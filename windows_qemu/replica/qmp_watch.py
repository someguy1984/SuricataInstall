#!/usr/bin/env python3
"""Watch a QEMU run over QMP and freeze the evidence the moment the guest resets, panics or shuts down.

    qmp_watch.py RUN_DIR QMP_SOCKET [--trace-instance DIR] [--timeout SECONDS] [--hold] [--screens SECONDS]

QEMU must run with `-action reboot=shutdown,shutdown=pause,panic=pause`, so a guest reset (CF9, keyboard
controller, triple fault) or a Windows bugcheck reported through the Hyper-V crash MSRs (hv-crash) pauses the VM
instead of rebooting it. Then, in this order:
  1. the KVM ftrace instance is switched off (its ring buffer keeps the last SMI/port events);
  2. the last 0xCF9 / 0x64 port write in that buffer gives the resetting vCPU and RIP;
  3. QMP: query-status, `info registers -a`, `info cpus`, a screendump, and on the resetting vCPU a disassembly at
     that RIP plus the 160 bytes before it (`x/24i`, `x/160xb`), all to RUN_DIR;
  4. `quit`, unless --hold (the VM stays paused for a manual look through the same socket).
With no event for --timeout seconds the same snapshot is taken as outcome "timeout" (the guest survived).
Every QMP event goes to RUN_DIR/qmp-events.jsonl with host CLOCK_MONOTONIC (the ftrace instance uses trace_clock
mono, so both line up). A screendump goes to RUN_DIR/screens/ every --screens seconds.
"""
import argparse, json, os, re, socket, sys, time
from pathlib import Path

PANIC_HINT = {  # the usual suspects for an early-boot bugcheck on a firmware change
    0x0A: "IRQL_NOT_LESS_OR_EQUAL", 0x1E: "KMODE_EXCEPTION_NOT_HANDLED", 0x3B: "SYSTEM_SERVICE_EXCEPTION",
    0x50: "PAGE_FAULT_IN_NONPAGED_AREA", 0x7B: "INACCESSIBLE_BOOT_DEVICE", 0x7E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    0x7F: "UNEXPECTED_KERNEL_MODE_TRAP", 0x9F: "DRIVER_POWER_STATE_FAILURE", 0xA5: "ACPI_BIOS_ERROR",
    0xC4: "DRIVER_VERIFIER_DETECTED_VIOLATION", 0xD1: "DRIVER_IRQL_NOT_LESS_OR_EQUAL", 0xEF: "CRITICAL_PROCESS_DIED",
    0x101: "CLOCK_WATCHDOG_TIMEOUT", 0x109: "CRITICAL_STRUCTURE_CORRUPTION", 0x124: "WHEA_UNCORRECTABLE_ERROR",
    0x133: "DPC_WATCHDOG_VIOLATION", 0x139: "KERNEL_SECURITY_CHECK_FAILURE", 0x13A: "KERNEL_MODE_HEAP_CORRUPTION",
    0x15F: "CONNECTED_STANDBY_WATCHDOG_TIMEOUT_LIVEDUMP", 0x1C8: "MANUALLY_INITIATED_POWER_BUTTON_HOLD",
    0x5C: "HAL_INITIALIZATION_FAILED", 0x5D: "UNSUPPORTED_PROCESSOR", 0x78: "PHASE0_EXCEPTION",
    0x32: "PHASE1_INITIALIZATION_FAILED", 0xA0: "INTERNAL_POWER_ERROR", 0x116: "VIDEO_TDR_FAILURE",
    0x1D5: "DRIVER_PNP_WATCHDOG", 0xC0000001: "STATUS_UNSUCCESSFUL (boot manager)",
}
RESET_LINE = re.compile(r"^\s*\S+-(\d+)\s+\[\d+\].*?\s([\d.]+): kvm_exit: vcpu (\d+) reason (\S+) rip (0x[0-9a-f]+) "
                        r"info1 (0x[0-9a-f]+)")


class Qmp:
    def __init__(self, path: str, log):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        for _ in range(300):
            try:
                self.s.connect(path)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.1)
        else:
            raise SystemExit(f"QMP socket {path} never came up")
        self.f = self.s.makefile("rwb", buffering=0)
        self.log = log
        self.events = []
        json.loads(self.f.readline())                       # greeting
        self.cmd("qmp_capabilities")

    def _read(self):
        line = self.f.readline()
        if not line:
            raise EOFError
        msg = json.loads(line)
        if "event" in msg:
            msg["host_mono"] = time.monotonic()
            self.log.write(json.dumps(msg) + "\n")
            self.log.flush()
            self.events.append(msg)
        return msg

    def cmd(self, name, **args):
        self.f.write((json.dumps({"execute": name, "arguments": args} if args else {"execute": name}) + "\n").encode())
        while True:
            msg = self._read()
            if "return" in msg or "error" in msg:
                return msg

    def hmp(self, line, cpu=None):
        a = {"command-line": line}
        if cpu is not None:
            a["cpu-index"] = cpu
        r = self.cmd("human-monitor-command", **a)
        return r.get("return", json.dumps(r.get("error")))

    def wait_event(self, timeout):
        self.s.settimeout(timeout)
        try:
            return self._read()
        except (socket.timeout, TimeoutError):
            return None
        finally:
            self.s.settimeout(None)


def last_reset_write(trace_file: Path):
    """The last kvm_exit for an OUT to 0xCF9/0x64, or a SHUTDOWN exit (triple fault), in the ftrace buffer."""
    hit = None
    try:
        for line in trace_file.read_text(errors="replace").splitlines():
            m = RESET_LINE.match(line)
            if not m:
                continue
            tid, ts, vcpu, reason, rip, info1 = m.groups()
            port = (int(info1, 16) >> 16) & 0xFFFF
            if reason == "shutdown":
                hit = dict(kind="triple fault (SVM SHUTDOWN exit)", vcpu=int(vcpu), rip=int(rip, 16), ts=float(ts))
            elif reason == "io" and port in (0xCF9, 0x64) and not int(info1, 16) & 1:
                hit = dict(kind=f"OUT to port {port:#x}", vcpu=int(vcpu), rip=int(rip, 16), ts=float(ts), port=port)
    except FileNotFoundError:
        pass
    return hit


def snapshot(q: Qmp, run: Path, outcome: dict, trace_dir: Path | None):
    if trace_dir:
        try:
            (trace_dir / "tracing_on").write_text("0")
            outcome["ftrace_stopped_mono"] = time.monotonic()
        except OSError as e:
            outcome["ftrace_stop_error"] = str(e)
    (run / "at-stop").mkdir(exist_ok=True)
    out = run / "at-stop"
    outcome["query_status"] = q.cmd("query-status").get("return")
    (out / "registers-all.txt").write_text(q.hmp("info registers -a"))
    (out / "cpus.txt").write_text(q.hmp("info cpus"))
    r = q.cmd("screendump", filename=str(out / "screen.png"), format="png")
    if "error" in r:
        q.cmd("screendump", filename=str(out / "screen.ppm"))
    if trace_dir:
        hit = last_reset_write(trace_dir / "trace")
        if hit:
            outcome["reset_writer"] = {**hit, "rip": f"{hit['rip']:#x}"}
            cpu, rip = hit["vcpu"], hit["rip"]
            (out / f"disasm-vcpu{cpu}-at-reset-rip.txt").write_text(
                f"# {hit['kind']} on vCPU {cpu}, RIP {rip:#x} (the paused vCPU's address space; may have moved on)\n"
                + q.hmp(f"x/24i {rip:#x}", cpu) + "\n# 160 bytes before RIP\n" + q.hmp(f"x/160xb {rip - 160:#x}", cpu))
    for cpu in range(int(outcome.get("cpus", 1))):
        (out / f"disasm-vcpu{cpu}-pc.txt").write_text(q.hmp("x/16i $pc", cpu))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run", type=Path)
    ap.add_argument("sock")
    ap.add_argument("--trace-instance", type=Path)
    ap.add_argument("--timeout", type=float, default=1200)
    ap.add_argument("--screens", type=float, default=30)
    ap.add_argument("--cpus", type=int, default=1)
    ap.add_argument("--hold", action="store_true")
    a = ap.parse_args()
    (a.run / "screens").mkdir(parents=True, exist_ok=True)
    log = open(a.run / "qmp-events.jsonl", "a")
    q = Qmp(a.sock, log)
    start = time.monotonic()
    outcome = {"outcome": "timeout", "start_mono": start, "cpus": a.cpus}
    next_shot = start
    while True:
        now = time.monotonic()
        if now - start >= a.timeout:
            break
        if a.screens and now >= next_shot:
            q.cmd("screendump", filename=str(a.run / "screens" / f"{int(now - start):05d}s.png"), format="png")
            next_shot = now + a.screens
        try:
            ev = q.wait_event(max(0.5, min(next_shot, start + a.timeout) - time.monotonic()))
        except EOFError:
            outcome["outcome"] = "qemu exited"
            break
        if not ev or "event" not in ev:
            continue
        name = ev["event"]
        if name == "GUEST_PANICKED":
            info = ev.get("data", {}).get("info", {})
            outcome["outcome"] = "guest panic"
            outcome["panic"] = info
            if info.get("type") == "hyper-v":
                code = int(info.get("arg1", 0))
                outcome["bugcheck"] = {"code": f"{code:#x}", "name": PANIC_HINT.get(code, "?"),
                                       "params": [f"{int(info.get(k, 0)):#x}" for k in ("arg2", "arg3", "arg4", "arg5")]}
            break
        if name == "SHUTDOWN" and ev.get("data", {}).get("guest"):
            outcome["outcome"] = "guest " + ev["data"].get("reason", "shutdown")
            break
        if name == "RESET":
            outcome["outcome"] = "reset (not paused: check -action)"
            break
    outcome["event_mono"] = time.monotonic()
    outcome["seconds_after_start"] = round(outcome["event_mono"] - start, 1)
    try:
        snapshot(q, a.run, outcome, a.trace_instance)
    except EOFError:
        outcome["snapshot"] = "QEMU exited before the snapshot"
    (a.run / "outcome.json").write_text(json.dumps(outcome, indent=1) + "\n")
    print(f"qmp_watch: {outcome['outcome']} after {outcome['seconds_after_start']} s"
          + (f", bugcheck {outcome['bugcheck']['code']} {outcome['bugcheck']['name']}" if "bugcheck" in outcome else "")
          + (f", {outcome['reset_writer']['kind']} vCPU {outcome['reset_writer']['vcpu']} RIP "
             f"{outcome['reset_writer']['rip']}" if "reset_writer" in outcome else ""))
    if a.hold:
        print(f"qmp_watch: --hold: VM left paused; QMP socket {a.sock}. Close QEMU when done.")
        return 0
    try:
        q.cmd("quit")
    except EOFError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
