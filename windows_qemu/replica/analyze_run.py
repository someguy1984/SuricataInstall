#!/usr/bin/env python3
"""Summarise one Sentinel-MM Windows replica run into RUN_DIR/SUMMARY.md (and print it).

    analyze_run.py RUN_DIR [--sentinel /home/j/sentinel-uefi]

Inputs (written by run_windows_sentinel_replica.sh / qmp_watch.py):
  outcome.json        how the run ended: guest reset / guest panic (+ Windows bugcheck) / timeout
  kvm-trace.txt       ftrace (trace_clock mono): kvm_smm_transition, kvm_pio on 0xB2/0xB3/0xCF9/0x64, kvm_exit for
                      OUTs to those ports and for SHUTDOWN (triple fault)
  firmware-debug.log  the firmware's DEBUG output (port 0x402), incl. Sentinel MM handlers at OS runtime
  vars-run.fd         the VM's NVRAM after the run (SentinelLastReset is NV)
What it answers:
  * Which SW SMIs were raised (value written to 0xB2), how often, from which code (RIP class), and when.
  * How long each vCPU stayed in SMM (a "stun lock" shows as a long residency or a vCPU still in SMM at the end).
  * Who wrote the reset (port, value, vCPU, RIP), or whether it was a triple fault or a bugcheck.
"""
import argparse, json, re, struct, sys
from collections import Counter, defaultdict
from pathlib import Path

LINE = re.compile(r"^\s*(?P<task>.+?)-(?P<tid>\d+)\s+\[(?P<hcpu>\d+)\]\s+\S+\s+(?P<ts>[\d.]+): (?P<ev>\w+): (?P<rest>.*)$")
EXIT = re.compile(r"vcpu (\d+) reason (\S+) rip (0x[0-9a-f]+) info1 (0x[0-9a-f]+)")
PIO = re.compile(r"pio_(read|write) at (0x[0-9a-f]+) size (\d+) count (\d+) val (0x[0-9a-f]+)")
SMM = re.compile(r"vcpu (\d+): (entering|leaving) SMM, smbase (0x[0-9a-f]+)")
EBS_GUID = "27ABF055-B1B8-4C26-8048-748F37BAA2DF"      # gEfiEventExitBootServicesGuid
RESET_TYPES = {0: "EfiResetCold", 1: "EfiResetWarm", 2: "EfiResetShutdown", 3: "EfiResetPlatformSpecific"}
PHASES = {0: "boot services", 1: "runtime (physical)", 2: "runtime (virtual)"}


def rip_class(rip: int) -> str:
    if rip >= 0xFFFF800000000000:
        return "kernel VA (Windows kernel/HAL/driver, or runtime services after SetVirtualAddressMap)"
    if rip < 0x100000000:
        return "below 4 GiB (firmware, bootmgr/winload identity map)"
    return "user/other VA"


def parse_trace(path: Path):
    exits, pios, smm = [], [], []
    last_exit_by_tid = {}
    if not path.exists():
        return exits, pios, smm
    for line in path.read_text(errors="replace").splitlines():
        m = LINE.match(line)
        if not m:
            continue
        ts, ev, rest, tid = float(m["ts"]), m["ev"], m["rest"], int(m["tid"])
        if ev == "kvm_exit" and (e := EXIT.search(rest)):
            rec = dict(ts=ts, tid=tid, vcpu=int(e[1]), reason=e[2], rip=int(e[3], 16), info1=int(e[4], 16))
            exits.append(rec)
            last_exit_by_tid[tid] = rec
        elif ev == "kvm_pio" and (p := PIO.search(rest)):
            ex = last_exit_by_tid.get(tid)
            pios.append(dict(ts=ts, tid=tid, rw=p[1], port=int(p[2], 16), size=int(p[3]), val=int(p[5], 16),
                             vcpu=ex["vcpu"] if ex else None, rip=ex["rip"] if ex else None))
        elif ev == "kvm_smm_transition" and (s := SMM.search(rest)):
            smm.append(dict(ts=ts, vcpu=int(s[1]), entering=s[2] == "entering"))
    return exits, pios, smm


def last_reset_trace(vars_fd: Path, sentinel: Path):
    sys.path.insert(0, str(sentinel / "smm_research/tools"))
    try:
        import nvar_dump  # noqa: E402
    except ImportError:
        return None
    img = vars_fd.read_bytes()
    best = None
    for bank_off in (0x1000, 0x20000):
        bank = img[bank_off:bank_off + 0x20000]
        i = bank.find(nvar_dump.NVRAM_FILE)
        if i < 0 or bank[0x28:0x2C] != b"_FVH":
            continue
        fsize = int.from_bytes(bank[i + 20:i + 23], "little")
        f = bank[i:i + fsize]
        gtab, e = [], len(f)
        while e - 16 >= 0 and f[e - 16:e] != b"\xff" * 16:
            gtab.append(nvar_dump.guid(f, e - 16)); e -= 16
        recs = []
        nvar_dump.walk(f, 24, e, gtab, 0, recs)
        top = {r["off"]: r for r in recs if r["depth"] == 0}
        for r in recs:
            if r["depth"] or r["attr"] & 0x08 or r["name"] != "SentinelLastReset":
                continue
            t = r
            while t["next"] != 0xFFFFFF and t["off"] + t["next"] in top:
                t = top[t["off"] + t["next"]]
            if not t["attr"] & 0x80:
                continue
            data = f[t["off"] + t["data"]:t["off"] + t["size"]]      # walk() sets "data" = header length
            if len(data) >= 40:
                ver, seq, rtype, phase, status, caller, dsize = struct.unpack_from("<IIIIQQQ", data)
                txt = data[40:40 + min(dsize, 64)]
                best = dict(version=ver, seq=seq, type=RESET_TYPES.get(rtype, rtype), phase=PHASES.get(phase, phase),
                            status=f"{status:#x}", caller=f"{caller:#x}",
                            data=txt.decode("utf-16-le", "replace").split("\0")[0] if txt else "")
    return best


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run", type=Path)
    ap.add_argument("--sentinel", type=Path, default=Path("/home/j/sentinel-uefi"))
    a = ap.parse_args()
    run = a.run
    out = []
    w = out.append
    oc = json.loads((run / "outcome.json").read_text()) if (run / "outcome.json").exists() else {}
    meta = json.loads((run / "run.json").read_text()) if (run / "run.json").exists() else {}
    exits, pios, smm = parse_trace(run / "kvm-trace.txt")

    w(f"# Sentinel MM Windows replica run: {run.name}\n")
    w(f"Firmware `{meta.get('firmware', '?')}` (SHA `{meta.get('firmware_sha256', '?')[:16]}…`), accel {meta.get('accel', '?')}, "
      f"{meta.get('cpus', '?')} vCPU, Secure Boot keys from `{meta.get('keys', '?')}`, disk overlay (base read-only).\n")
    w("## Outcome\n")
    w(f"- **{oc.get('outcome', 'unknown')}** after {oc.get('seconds_after_start', '?')} s")
    if "bugcheck" in oc:
        b = oc["bugcheck"]
        w(f"- **Windows bugcheck {b['code']} ({b['name']})**, parameters {', '.join(b['params'])}")
    if "reset_writer" in oc:
        r = oc["reset_writer"]
        w(f"- Reset written by **vCPU {r['vcpu']}**, {r['kind']}, RIP `{r['rip']}` ({rip_class(int(r['rip'], 16))}); "
          f"disassembly in `at-stop/disasm-vcpu{r['vcpu']}-at-reset-rip.txt`")
    resets = [p for p in pios if p["rw"] == "write" and p["port"] in (0xCF9, 0x64)]
    for p in resets[-3:]:
        w(f"- port {p['port']:#x} ← {p['val']:#x} from vCPU {p['vcpu']} RIP {p['rip']:#x}" if p["rip"] is not None
          else f"- port {p['port']:#x} ← {p['val']:#x}")
    if any(e["reason"] == "shutdown" for e in exits):
        w("- **SVM SHUTDOWN exit seen: a triple fault**")
    w(f"- Screen at stop: `at-stop/screen.png`; periodic screens in `screens/`.\n")

    lr = last_reset_trace(run / "vars-run.fd", a.sentinel) if (run / "vars-run.fd").exists() else None
    w("## SentinelLastReset (VM NVRAM after the run)\n")
    w(f"- {lr}\n" if lr else "- absent (no gRT->ResetSystem call was traced in this VM)\n")

    w("## SW SMIs (OUT to 0xB2)\n")
    sw = [p for p in pios if p["rw"] == "write" and p["port"] == 0xB2]
    if not sw:
        w("- none in the trace buffer" + ("" if (run / "kvm-trace.txt").exists() else " (no KVM trace: TCG run?)") + "\n")
    else:
        t0 = sw[0]["ts"]
        cnt = Counter(p["val"] for p in sw)
        w(f"{len(sw)} SW SMIs from {sw[0]['ts']:.3f} to {sw[-1]['ts']:.3f} (trace clock).\n")
        w("| value | count | first (s) | last (s) | RIP classes |")
        w("|---|---|---|---|---|")
        for val, n in cnt.most_common():
            ps = [p for p in sw if p["val"] == val]
            cls = Counter(rip_class(p["rip"]).split(" (")[0] for p in ps if p["rip"] is not None)
            w(f"| {val:#04x} | {n} | {ps[0]['ts'] - t0:.3f} | {ps[-1]['ts'] - t0:.3f} | "
              + ", ".join(f"{k} ×{v}" for k, v in cls.items()) + " |")
        w("")
        rips = Counter((p["val"], p["rip"]) for p in sw if p["rip"] is not None)
        w("Distinct (value, RIP) pairs, most frequent first:\n")
        for (val, rip), n in rips.most_common(15):
            w(f"- {val:#04x} from RIP `{rip:#x}` ×{n} ({rip_class(rip).split(' (')[0]})")
        w("")
        w("Last 15 SW SMIs before the end:\n")
        for p in sw[-15:]:
            w(f"- t={p['ts'] - t0:.6f} vCPU {p['vcpu']} value {p['val']:#04x} RIP `{p['rip']:#x}`" if p["rip"] is not None
              else f"- t={p['ts'] - t0:.6f} value {p['val']:#04x}")
        w("")

    w("## SMM residency (kvm_smm_transition)\n")
    if not smm:
        w("- no SMM transitions in the trace buffer\n")
    else:
        inside, dwell = {}, []
        for s in smm:
            if s["entering"]:
                inside[s["vcpu"]] = s["ts"]
            elif s["vcpu"] in inside:
                dwell.append((s["ts"] - inside.pop(s["vcpu"]), s["vcpu"], s["ts"]))
        end = max(x["ts"] for x in smm)
        per = defaultdict(int)
        for s in smm:
            per[s["vcpu"]] += s["entering"]
        w(f"- SMM entries per vCPU: {dict(sorted(per.items()))}")
        dwell.sort(reverse=True)
        w(f"- longest residencies: " + ", ".join(f"vCPU {v} {d * 1e3:.3f} ms (left at {t:.3f})" for d, v, t in dwell[:8]))
        if inside:
            w(f"- **still in SMM at the end of the trace: " + ", ".join(
                f"vCPU {v} since {ts:.3f} ({(end - ts) * 1e3:.1f} ms before the last transition)" for v, ts in inside.items())
              + "**")
        w("")

    log = run / "firmware-debug.log"
    w("## Firmware / MM debug output after ExitBootServices\n")
    if log.exists():
        lines = log.read_text(errors="replace").splitlines()
        idx = max((i for i, l in enumerate(lines) if EBS_GUID in l.upper() or "ExitBootServices" in l), default=None)
        bad = [l for l in lines if re.search(r"SentinelMmFatal|ASSERT|Exception|SentinelResetTrace|refus", l)]
        if bad:
            w("Notable lines anywhere in the log:\n\n```")
            out.extend(bad[-25:])
            w("```\n")
        if idx is not None:
            tail = lines[idx:]
            w(f"{len(tail)} lines from the last ExitBootServices marker (log line {idx + 1}); last 60:\n\n```")
            out.extend(tail[-60:])
            w("```\n")
        else:
            w("No ExitBootServices marker in the log (Windows never left boot services?). Last 40 lines:\n\n```")
            out.extend(lines[-40:])
            w("```\n")
    else:
        w("- no firmware-debug.log\n")
    text = "\n".join(out) + "\n"
    (run / "SUMMARY.md").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
