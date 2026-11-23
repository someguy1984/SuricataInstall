#!/bin/bash
# Remove the EDR client kit (client PLAN section 6). Driven by the install manifest: it removes what the kit wrote, puts
# back each prior value the manifest recorded, and purges only packages the kit installed.
#
#   sudo edr-uninstall                 asks first; shows what the manifest will remove
#   sudo edr-uninstall --yes --keep-logs
#   sudo edr-uninstall --purge         also forget this host's identity (host-id)
#   edr-uninstall --plan               prints every step and changes nothing (needs no root)
#   partial: --keep-suricata --keep-tetragon --keep-dns --keep-sctp-block --keep-config
#
# The manifest (/var/lib/edr-install/manifest.json, root only; else /var/lib/edr-agent/manifest.json, which the agent
# owns) is untrusted input: it is parsed by python3 -I, and a path outside the kit's own prefixes, a package or user
# that is not on the script's built-in list, or a prior value that is not a known sysctl key with an integer is refused
# (exit 3, nothing changed). The script copies itself and the manifest to a root-only directory under /run first,
# because the tree it deletes holds it.
#
# Exit codes (PLAN section 15): 0 final check PASS, 2 final check FAIL, 3 nothing to remove, declined, or manifest
# refused, 64 usage error.
# It never flushes nftables or iptables: it deletes the kit's own tables (inet edr, inet edr_dns, inet edr_isolate).
set -uo pipefail

SELF=$(readlink -f "$0")
R=${EDR_AGENT_ROOT:-}
LIB=/usr/local/lib/edr-agent
STATE_A=/var/lib/edr-agent
STATE_I=/var/lib/edr-install
ETC_A=/etc/edr-agent
ETC_DNS=/etc/edr-dns

ASSUME_YES=0 PURGE=0 PLAN=0 KEEP_LOGS=0 KEEP_SURICATA=0 KEEP_TETRAGON=0 KEEP_DNS=0 KEEP_SCTP=0 KEEP_CONFIG=0 IN_COPY='' 
ORIG_ARGS=("$@")

usage() {
    cat >&2 <<'USAGE'
usage: edr-uninstall [--yes] [--keep-logs] [--purge] [--plan]
                     [--keep-suricata] [--keep-tetragon] [--keep-dns] [--keep-sctp-block] [--keep-config]
  --yes            do not ask the first question (--purge still asks unless --yes is given too)
  --keep-logs      keep Tetragon's event logs and the edr journal namespace's data
  --purge          also forget this host's identity: delete /var/lib/edr-agent/host-id
  --plan           print every step and exit; changes nothing
  --keep-*         leave that part installed; a later full uninstall finishes the job
USAGE
}
while [[ $# -gt 0 ]]; do
    case $1 in
        --yes|-y) ASSUME_YES=1 ;;
        --purge) PURGE=1 ;;
        --plan) PLAN=1 ;;
        --keep-logs) KEEP_LOGS=1 ;;
        --keep-suricata) KEEP_SURICATA=1 ;;
        --keep-tetragon) KEEP_TETRAGON=1 ;;
        --keep-dns) KEEP_DNS=1 ;;
        --keep-sctp-block) KEEP_SCTP=1 ;;
        --keep-config) KEEP_CONFIG=1 ;;
        --in-copy) [[ $# -ge 2 ]] || { usage; exit 64; }; IN_COPY=$2; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 64 ;;
    esac
    shift
done
if [[ -n $R && $PLAN -eq 0 ]]; then
    echo "uninstall.sh: EDR_AGENT_ROOT is only for --plan and tests: a real run cannot work in a prefix." >&2
    exit 64
fi
KEEP_ANY=$((KEEP_SURICATA + KEEP_TETRAGON + KEEP_DNS + KEEP_SCTP + KEEP_CONFIG))

say() { printf '\n==> %s\n' "$*"; }

manifest_parse() {   # manifest_parse FILE
    python3 -I - "$1" "$R" all - <<'PY'
import hashlib, json, os, re, sys

# argv: MANIFEST ROOT MODE(all|last) STEP(-|N)
# Prints tab-separated lines for the shell. Every field of the manifest is untrusted input.
manifest, root, mode, step_arg = sys.argv[1], sys.argv[2].rstrip("/"), sys.argv[3], sys.argv[4]
only_step = int(step_arg) if step_arg.isdigit() else None
MAX_BYTES = 4 * 1024 * 1024
PATH_RE = re.compile(r"^/[A-Za-z0-9._@+:/-]+$")
NAME_RE = re.compile(r"^[A-Za-z0-9._@+:-]{1,80}$")
EXACT = {
    "/swapfile-edr", "/usr/sbin/policy-rc.d", "/etc/apt/preferences.d/suricata-8",
    "/etc/sysctl.d/90-edr-conntrack.conf", "/etc/modules-load.d/edr-conntrack.conf", "/etc/modprobe.d/edr-sctp-block.conf",
    "/etc/systemd/resolved.conf.d/zz-edr-doh.conf", "/etc/apt/apt.conf.d/zz-edr-inventory",
    "/etc/apt/apt.conf.d/zz-edr-policy-check", "/etc/needrestart/conf.d/50-edr.conf", "/etc/update-motd.d/90-edr",
    "/etc/systemd/journald@edr.conf", "/usr/local/bin/tetragon", "/usr/local/bin/tetra",
    "/etc/systemd/system/tetragon.service", "/var/lib/suricata/edr-rules-skipped",
}
SURICATA_ETC = {"suricata.yaml", "suricata.yaml.new", "drop.conf", "modify.conf", "disable.conf", "local.rules", "edr-dns.rules",
                "edr-home-net.yaml", "home-net.extra", "disable.conf.new", "drop.conf.new", "modify.conf.new"}
SURICATA_RULES = {"edr-ban-sids.txt", "edr-rules-status.json"}
TREES = ("/usr/local/lib/edr-agent", "/usr/local/lib/edr-agent.prev", "/usr/local/lib/tetragon", "/etc/tetragon", "/usr/libexec/edr",
         "/var/lib/suricata/cache", "/var/log/tetragon")
DROPIN_UNITS = ("suricata", "dnscrypt-proxy", "tetragon", "edr-agent")
UNITS_EXTRA = {"suricata.service", "dnscrypt-proxy.service", "dnscrypt-proxy.socket", "tetragon.service", "systemd-resolved.service"}
PACKAGES = {"suricata", "suricata-update", "dnscrypt-proxy", "nftables", "tetragon"}
USERS = {"edr-agent", "edr-notify"}
SYSCTLS = {"net.netfilter.nf_conntrack_max", "net.netfilter.nf_conntrack_acct"}
PPA = "ppa:oisf/suricata-stable"


def clean(text):
    return "".join(c if " " <= c <= "~" and c != "\t" else "?" for c in str(text))[:70]


def owned(path):
    if not isinstance(path, str) or len(path) > 400 or not PATH_RE.match(path) or path.endswith("/"):
        return False
    parts = path.split("/")[1:]
    if "" in parts or "." in parts or ".." in parts:
        return False
    if path in EXACT:
        return True
    if any(path == t or path.startswith(t + "/") for t in TREES):
        return True
    head = "/" + parts[0]
    if len(parts) >= 2 and ((head == "/etc" and parts[1].startswith("edr-")) or (head == "/var" and len(parts) >= 3 and parts[1] == "lib" and parts[2].startswith("edr-"))
                            or (head == "/run" and parts[1].startswith("edr-"))):
        return True
    if len(parts) == 4 and parts[:3] == ["usr", "local", "sbin"] and parts[3].startswith("edr-"):
        return True
    if parts[:2] == ["etc", "suricata"] and len(parts) == 3 and parts[2] in SURICATA_ETC:
        return True
    if parts[:4] == ["var", "lib", "suricata", "rules"] and len(parts) == 5 and parts[4] in SURICATA_RULES:
        return True
    if parts[:3] == ["etc", "systemd", "system"] and len(parts) >= 4:
        if parts[3].startswith("edr-") and re.match(r"^edr-[A-Za-z0-9@._-]+\.(service|timer|path)(\.d)?$", parts[3]):
            return len(parts) <= 5
        m = re.match(r"^([a-z-]+)\.service\.d$", parts[3])
        if m and m.group(1) in DROPIN_UNITS and len(parts) == 4:
            return True
        if m and m.group(1) in DROPIN_UNITS and len(parts) == 5 and re.match(r"^([0-9]{2}-[A-Za-z0-9._-]+|override)\.conf$", parts[4]):
            return True
    return False


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def out(*fields):
    print("\t".join(str(f) for f in fields))


try:
    size = os.path.getsize(manifest)
except FileNotFoundError:
    out("manifest", "missing")
    sys.exit(0)
except OSError:
    out("manifest", "unreadable")
    sys.exit(0)
if size > MAX_BYTES:
    out("manifest", "unreadable")
    out("refuse", "manifest", "larger than 4 MiB")
    sys.exit(0)
try:
    with open(manifest, encoding="utf-8") as f:
        doc = json.load(f)
    sessions = doc["sessions"]
    if doc.get("v") != 1 or not isinstance(sessions, list):
        raise ValueError("shape")
except (OSError, ValueError, KeyError, TypeError, RecursionError):
    out("manifest", "unreadable")
    out("refuse", "manifest", "not a manifest this script understands")
    sys.exit(0)
out("manifest", "ok")

STATES = ("running", "awaiting-confirm", "confirmed", "rolled-back", "failed")
good = []
for i, s in enumerate(sessions):
    if not isinstance(s, dict) or not re.match(r"^[0-9a-f-]{8,40}$", str(s.get("id", ""))) or s.get("state") not in STATES \
            or s.get("kind") not in ("install", "upgrade"):
        out("refuse", "session %d" % i, "not a session")
        continue
    good.append(s)
if not good:
    sys.exit(0)
chosen = good[-1:] if mode == "last" else good
for s in chosen:
    steps = [n for n in s.get("steps_done", []) if isinstance(n, int) and 0 < n < 20]
    cur = s.get("current_step")
    out("session", s["id"], s["kind"], s["state"], clean(s.get("from_version")), clean(s.get("to_version")),
        ",".join(str(n) for n in steps) or "-", cur if isinstance(cur, int) and not isinstance(cur, bool) else "-")
comps = chosen[-1].get("components") if isinstance(chosen[-1].get("components"), dict) else {}
for k in ("web", "tetragon", "suricata", "kernel", "dns_lockdown", "sctp_block", "enrolled"):
    out("comp", k, "1" if comps.get(k) is True else "0")
for k in ("conntrack_loaded_before", "policy_rc_d_ours"):
    out("flag", k, "1" if chosen[-1].get(k) is True else "0")
sw = chosen[-1].get("swapfile")
if isinstance(sw, dict) and sw.get("path") == "/swapfile-edr" and re.match(r"^[0-9]{1,4}[MG]$", str(sw.get("size", ""))):
    out("swap", sw["path"], sw["size"])
elif sw:
    out("refuse", "swapfile", "only /swapfile-edr is the kit's")

entries, first, last_sha = [], {}, {}


def refuse(where, why):
    out("refuse", where, why)


def step_of(item):
    st = item.get("step")
    return st if isinstance(st, int) and not isinstance(st, bool) else 0


for s in chosen:
    sid = s["id"]
    for item in s.get("files", []) if isinstance(s.get("files"), list) else []:
        if not isinstance(item, dict):
            refuse(sid, "file entry is not an object"); continue
        path, prior = item.get("path"), item.get("prior")
        if not owned(path):
            refuse(sid, "path outside what the kit owns: " + clean(path)); continue
        saved = "-"
        if prior == "absent":
            ps = "absent"
        elif isinstance(prior, dict) and isinstance(prior.get("saved"), str) and owned(prior["saved"]) \
                and prior["saved"].startswith("/var/lib/edr-install/prior/") and ".." not in prior["saved"]:
            ps, saved = "saved", prior["saved"]
        else:
            refuse(sid, "bad prior for " + clean(path)); continue
        sha = item.get("sha256")
        entries.append(("file", path, ps, saved, step_of(item), sha if isinstance(sha, str) and re.match(r"^[0-9a-f]{64}$", sha) else ""))
    for item in s.get("dirs", []) if isinstance(s.get("dirs"), list) else []:
        if not isinstance(item, dict) or not owned(item.get("path")) or item.get("prior") not in ("absent", "present"):
            refuse(sid, "bad directory entry: " + clean(item.get("path") if isinstance(item, dict) else item)); continue
        entries.append(("dir", item["path"], item["prior"], "-", step_of(item), ""))
    for item in s.get("units", []) if isinstance(s.get("units"), list) else []:
        n = item.get("name") if isinstance(item, dict) else None
        if not isinstance(n, str) or not NAME_RE.match(n) or not (re.match(r"^edr-[A-Za-z0-9@._-]+\.(service|timer|path)$", n) or n in UNITS_EXTRA):
            refuse(sid, "bad unit name: " + clean(n)); continue
        pe, pa = item.get("prior_enabled"), item.get("prior_active")
        if pe not in (None, True, False) or pa not in (None, True, False):
            refuse(sid, "bad unit state for " + n); continue
        entries.append(("unit", n, {None: "null", True: "true", False: "false"}[pe], {None: "null", True: "true", False: "false"}[pa], step_of(item), ""))
    for item in s.get("sysctls", []) if isinstance(s.get("sysctls"), list) else []:
        k = item.get("key") if isinstance(item, dict) else None
        pv, v = (item.get("prior"), item.get("value")) if isinstance(item, dict) else (None, None)
        if k not in SYSCTLS or not isinstance(pv, str) or not re.match(r"^[0-9]{1,12}$", pv) or not re.match(r"^[0-9]{1,12}$", str(v)):
            refuse(sid, "bad sysctl entry: " + clean(k)); continue
        entries.append(("sysctl", k, pv, str(v), step_of(item), ""))
    for kind, key, allowed in (("package", "packages", PACKAGES), ("user", "users", USERS)):
        for item in s.get(key, []) if isinstance(s.get(key), list) else []:
            n = item.get("name") if isinstance(item, dict) else None
            if n not in allowed or not isinstance(item.get("by_kit"), bool):
                refuse(sid, "%s not in the kit's list: %s" % (kind, clean(n))); continue
            entries.append((kind, n, "1" if item["by_kit"] else "0", "-", step_of(item), ""))
    ppa = s.get("ppa")
    if isinstance(ppa, dict):
        if ppa.get("name") == PPA and isinstance(ppa.get("by_kit"), bool):
            entries.append(("ppa", PPA, "1" if ppa["by_kit"] else "0", "-", 0, ""))
        else:
            refuse(sid, "ppa is not the kit's: " + clean(ppa.get("name")))

if mode == "all":
    merged, order = {}, []
    for e in entries:                       # oldest session first: the first prior is where to go back to, the last sha is what we wrote
        key = (e[0], e[1])
        if key not in merged:
            merged[key] = list(e)
            order.append(key)
        elif e[5]:
            merged[key][5] = e[5]
    entries = [tuple(merged[k]) for k in reversed(order)]
else:
    entries = [e for e in reversed(entries) if only_step is None or e[4] == only_step]

for kind, name, a, b, step, sha in entries:
    cond = "-"
    path = root + name
    if kind == "file":
        if not os.path.lexists(path):
            cond = "missing"
        elif os.path.islink(path) or not os.path.isfile(path):
            cond = "notfile"
        elif sha:
            try:
                cond = "ok" if sha256(path) == sha else "edited"
            except OSError:
                cond = "unknown"
        else:
            cond = "unknown"
    elif kind == "dir":
        cond = "ok" if os.path.isdir(path) and not os.path.islink(path) else "missing"
    out("entry", kind, name, a, b, cond, step)
PY
}

manifest_path() {
    if [[ -n $IN_COPY ]]; then echo "$IN_COPY/manifest.json"
    elif [[ -f $R$STATE_I/manifest.json ]]; then echo "$R$STATE_I/manifest.json"
    else echo "$R$STATE_A/manifest.json"; fi
}

# What to do with one entry; pure: the plan prints it, the run does it. kind path prior saved cond
classify() {
    local kind=$1 prior=$2 cond=$3
    case $kind in
        file)
            case $cond in
                notfile) echo LEAVE_NOTFILE ;;
                missing) [[ $prior == saved ]] && echo RESTORE || echo GONE ;;
                edited) [[ $prior == saved ]] && echo LEAVE_EDITED || echo REMOVE_EDITED ;;
                *) [[ $prior == saved ]] && echo RESTORE || echo REMOVE ;;
            esac ;;
        dir) if [[ $cond == missing ]]; then echo GONE; elif [[ $prior == present ]]; then echo LEAVE_PRESENT; else echo RMDIR; fi ;;
        unit) [[ $prior == true ]] && echo LEAVE_PRESENT || echo UNIT_OFF ;;
        sysctl) echo SYSCTL ;;
        package) [[ $prior == 1 ]] && echo PACKAGE_PURGE || echo PACKAGE_KEEP ;;
        ppa) [[ $prior == 1 ]] && echo PPA_REMOVE || echo PPA_KEEP ;;
        user) [[ $prior == 1 ]] && echo USER_DELETE || echo USER_KEEP ;;
        *) echo LEAVE_PRESENT ;;
    esac
}
describe() {   # action kind path prior
    case $1 in
        REMOVE) echo "remove $3" ;;
        REMOVE_EDITED) echo "remove $3 (changed since install; the manifest says it did not exist before)" ;;
        RESTORE) echo "put the saved prior copy back at $3" ;;
        RMDIR) echo "remove directory $3 (a kit tree with everything under it, any other only if empty)" ;;
        UNIT_OFF) echo "stop and disable unit $3, forget its failed state" ;;
        SYSCTL) echo "put $3 back to its prior value $4 (live)" ;;
        PACKAGE_PURGE) echo "purge package $3 (the kit installed it; no autoremove)" ;;
        PACKAGE_KEEP) echo "leave package $3 installed (it was there before the kit)" ;;
        PPA_REMOVE) echo "remove the apt source $3 (the kit added it)" ;;
        PPA_KEEP) echo "leave the apt source $3 (it was there before)" ;;
        USER_DELETE) echo "delete the user $3 (the kit created it)" ;;
        USER_KEEP) echo "keep the user $3 (it existed before the kit)" ;;
        GONE) echo "$3 is already gone" ;;
        LEAVE_EDITED) echo "leave $3: changed since install and a prior copy exists; check it by hand" ;;
        LEAVE_NOTFILE) echo "leave $3: it is not the file the kit wrote" ;;
        LEAVE_PRESENT) echo "leave $3: it existed before the kit" ;;
        *) echo "$1 $3" ;;
    esac
}

# the files and units a kit install leaves by name, for a machine with no manifest (the agent may have deleted it)
fallback_entries() {
    local p u
    for u in edr-agent edr-bans edr-inventory edr-diskguard edr-dns-watch edr-dnslock edr-home-net edr-policy-check edr-droplet-id edr-notify edr-rules-update; do
        for p in service timer path; do
            [[ -e $R/etc/systemd/system/$u.$p ]] && printf 'entry\tfile\t/etc/systemd/system/%s.%s\tabsent\t-\tok\t0\n' "$u" "$p"
        done
    done
    for p in /etc/sysctl.d/90-edr-conntrack.conf /etc/modules-load.d/edr-conntrack.conf /etc/modprobe.d/edr-sctp-block.conf \
        /etc/systemd/resolved.conf.d/zz-edr-doh.conf /etc/apt/apt.conf.d/zz-edr-inventory /etc/apt/apt.conf.d/zz-edr-policy-check \
        /etc/needrestart/conf.d/50-edr.conf /etc/update-motd.d/90-edr /etc/systemd/journald@edr.conf \
        /etc/systemd/system/dnscrypt-proxy.service.d/50-edr.conf /etc/systemd/system/suricata.service.d/override.conf \
        /etc/systemd/system/tetragon.service.d/50-edr-check.conf /etc/systemd/system/tetragon.service.d/10-edr.conf; do
        [[ -e $R$p ]] && printf 'entry\tfile\t%s\tabsent\t-\tok\t0\n' "$p"
    done
    for p in /usr/local/lib/edr-agent /usr/local/lib/edr-agent.prev /etc/edr-dns /usr/libexec/edr; do
        [[ -d $R$p ]] && printf 'entry\tdir\t%s\tabsent\t-\tok\t0\n' "$p"
    done
    return 0
}

installed_anything() {
    local p
    for p in "$LIB" "$LIB.prev" "$STATE_A" "$STATE_I" "$ETC_A" /usr/local/sbin/edr-agent; do
        [[ -e $R$p || -L $R$p ]] && return 0
    done
    compgen -G "$R/etc/systemd/system/edr-*" >/dev/null && return 0
    return 1
}

# ---- --plan ---------------------------------------------------------------------------------------------------------------------------
plan() {
    local mf out tag f1 f2 f3 f4 f5 action refused=0 enrolled=no
    mf=$(manifest_path)
    echo "uninstall.sh --plan: nothing is changed."
    installed_anything || echo "(nothing from the kit was found on this machine)"
    [[ -e $R$STATE_A/identity/current ]] && enrolled=yes
    say "Before anything: the hub"
    if [[ $enrolled == yes ]]; then echo "run edr-agent deregister --reason uninstall (the hub keeps the host and its history; the host-id stays); if the hub is unreachable, carry on"
    else echo "not enrolled: no deregister"; fi
    say "Step 1: stop everything that rebuilds or re-locks"
    echo "stop edr-install-rollback, edr-agent-pause-end, edr-agent-rehome-rollback if armed"
    echo "stop and disable edr-bans.path and edr-bans.timer, edr-policy-check.timer$([[ $KEEP_DNS -eq 1 ]] || echo ', edr-dns-watch.timer')$([[ $KEEP_SURICATA -eq 1 ]] || echo ', edr-home-net.timer')"
    echo "delete table inet edr_isolate if present"
    say "Step 2: delete table inet edr"
    echo "nft delete table inet edr: lifts every ban, feed, bigconn and egress rule at once (nothing else is touched, nothing is flushed)"
    say "Step 3: restore DNS"
    if [[ $KEEP_DNS -eq 1 ]]; then echo "skipped: --keep-dns (the lock, the proxy and the watchdog stay)"
    else
        echo "delete table inet edr_dns; remove edr-dnslock.service; remove zz-edr-doh.conf and /run/systemd/resolved.conf.d/zzz-edr-failopen.conf; restart systemd-resolved"
        echo "check that a lookup works through /etc/resolv.conf; only then stop dnscrypt-proxy, purge it if the kit installed it, remove its sandbox drop-in and /etc/edr-dns"
    fi
    say "Step 5: units, hooks and local alerts"
    echo "stop and remove edr-agent, edr-notify (and edr-notify.path), edr-bans, edr-inventory, edr-diskguard (with /etc/edr-agent/logrotate.conf), edr-policy-check, edr-home-net, edr-droplet-id, edr-rules-update"
    echo "remove the zz-edr-inventory and zz-edr-policy-check apt hooks, the needrestart file, the MOTD line, journald@edr.conf and the edr journal namespace$([[ $KEEP_LOGS -eq 1 ]] || echo ' with its data')"
    say "Step 6: kernel settings"
    echo "remove the conntrack sysctl drop-in and put back the prior values the kit changed (live)"
    if [[ $KEEP_SCTP -eq 1 ]]; then echo "keep /etc/modprobe.d/edr-sctp-block.conf (--keep-sctp-block)"
    else echo "remove /etc/modprobe.d/edr-sctp-block.conf: this re-opens both SCTP bugs behind NGINX2Root (Appendix A.2 says what is patched)"; fi
    say "Step 7: Tetragon"
    if [[ $KEEP_TETRAGON -eq 1 ]]; then echo "skipped: --keep-tetragon (enforcement stays on)"
    else echo "stop and remove tetragon, /usr/local/bin/tetragon and tetra, /usr/local/lib/tetragon, /etc/tetragon, the edr-canary policy and /usr/libexec/edr$([[ $KEEP_LOGS -eq 1 ]] || echo ', then /var/log/tetragon')"; fi
    say "Step 8: Suricata"
    if [[ $KEEP_SURICATA -eq 1 ]]; then echo "skipped: --keep-suricata (the kit's log rotation still goes in step 5)"
    else echo "stop Suricata, purge it if the kit installed it, remove the kit's rules, cache, home-net files, update units and apt pin; remove the OISF PPA only if the kit added it; then purge nftables if the kit installed it"; fi
    say "Step 4 to 11, the manifest, last entry first ($mf)"
    out=$(manifest_parse "$mf") || { echo "could not parse the manifest"; return 3; }
    if grep -q $'^manifest\tmissing' <<<"$out"; then
        echo "there is no manifest: the kit's files are removed by name (and this is said again when it runs):"
        out=$(fallback_entries)
    elif grep -q $'^manifest\tunreadable' <<<"$out"; then
        echo "the manifest cannot be read"
    fi
    while IFS=$'\t' read -r tag f1 f2 f3 f4 f5 _; do
        case $tag in
            refuse) refused=$((refused + 1)); echo "REFUSE $f1: $f2" ;;
            entry) action=$(classify "$f1" "$f3" "$f5"); describe "$action" "$f1" "$f2" "$f3"; : "$f4" ;;
        esac
    done <<<"$out"
    say "Step 9: the code, the state, the users"
    echo "remove /usr/local/lib/edr-agent and .prev, the /usr/local/sbin/edr-* links, /etc/edr-agent$([[ $KEEP_CONFIG -eq 0 ]] || echo ' except local.conf (--keep-config)')"
    echo "remove /var/lib/edr-agent except host-id$([[ $PURGE -eq 0 ]] || echo ' (--purge removes it too)'), /var/lib/edr-bans, -inventory, -restart, -diskguard, -notify, -policy-check, -dns-watch, every /run/edr-* and /run/edr-droplet-id"
    if [[ $KEEP_ANY -gt 0 ]]; then echo "/var/lib/edr-install stays: a partial run keeps it, and a later full uninstall finishes the job"
    else echo "remove /var/lib/edr-install (the manifest and the prior copies), then the users edr-agent and edr-notify the kit created"; fi
    say "Step 10: swap"
    echo "if the manifest says the kit made /swapfile-edr: swapoff it, remove its fstab line '/swapfile-edr none swap sw 0 0', delete the file"
    say "Step 11: final check"
    echo "no 'edr', 'edr_dns' or 'edr_isolate' table; no edr-* unit, kit drop-in or swapfile left; DNS resolves; sshd still listens; nginx answers on 127.0.0.1 when present; prior sysctl values restored"
    echo "(partial flags relax only the items they keep; each is printed as 'kept by --keep-...')"
    if [[ $refused -gt 0 ]]; then
        echo; echo "$refused manifest line(s) refused: a real run stops before changing anything (exit 3)."
        return 3
    fi
    return 0
}
if [[ $PLAN -eq 1 ]]; then
    plan
    exit $?
fi

# ---- from here on the script changes things -----------------------------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || { echo "ERROR: run as root (sudo $0)" >&2; exit 3; }

if [[ -z $IN_COPY ]]; then
    # run from a copy: this script lives in the tree it is about to delete
    installed_anything || { echo "Nothing to remove: no kit files, units or state found."; exit 3; }
    mf=$(manifest_path)
    if [[ -f $R$STATE_I/manifest.json && -f $R$STATE_A/manifest.json ]] && ! cmp -s "$R$STATE_I/manifest.json" "$R$STATE_A/manifest.json"; then
        echo "WARNING: the two copies of the manifest differ: the root-only one ($STATE_I) is used."
    fi
    COPY=$(mktemp -d /run/edr-uninstall.XXXXXX)
    chmod 0700 "$COPY"
    cp -- "$SELF" "$COPY/uninstall.sh"
    if [[ -f $mf ]]; then cp -- "$mf" "$COPY/manifest.json"; else printf '' > "$COPY/manifest.json"; : > "$COPY/no-manifest"; fi
    exec /bin/bash "$COPY/uninstall.sh" --in-copy "$COPY" "${ORIG_ARGS[@]}"
fi
COPY=$IN_COPY
trap 'rm -rf -- "$COPY"' EXIT

confirm() {   # prompt expected
    local answer
    if [[ $ASSUME_YES -eq 1 ]]; then echo "$1 $2 (--yes)"; return 0; fi
    [[ -t 0 ]] || { echo "No terminal to ask on; use --yes to go ahead." >&2; return 1; }
    read -rp "$1 " answer
    [[ $answer == "$2" ]]
}

MANIFEST_OUT=''
if [[ -f $COPY/no-manifest ]]; then
    echo "NOTE: there is no manifest: the kit's files are removed by name."
    MANIFEST_OUT=$(fallback_entries)
else
    MANIFEST_OUT=$(manifest_parse "$COPY/manifest.json") || { echo "ERROR: could not parse the manifest" >&2; exit 3; }
    if grep -q $'^manifest\tunreadable' <<<"$MANIFEST_OUT" || grep -q $'^refuse\t' <<<"$MANIFEST_OUT"; then
        echo "The manifest has content this script will not act on:" >&2
        grep $'^refuse\t' <<<"$MANIFEST_OUT" | cut -f2- | sed 's/^/  /' >&2
        echo "Nothing was changed. Fix the manifest ($STATE_I/manifest.json) or remove it to remove the kit by name." >&2
        exit 3
    fi
fi
SWAP_LINE=$(awk -F'\t' '$1 == "swap" { print $2 " " $3 }' <<<"$MANIFEST_OUT" | head -1)
LIB_ENTRIES=$MANIFEST_OUT

if [[ $PURGE -eq 0 && $ASSUME_YES -eq 0 ]]; then
    echo "This removes the EDR client kit from this machine: its bans, DNS lock, units, code and configuration."
    echo "Identity (host-id) stays unless --purge, so a reinstall with a token made --for this host continues its history on the hub."
    confirm "Continue? [y/N]" y || { echo "Aborted"; exit 3; }
fi
if [[ $PURGE -eq 1 ]]; then
    echo "--purge also deletes $STATE_A/host-id: a reinstall then needs a token made --for this host to continue its history."
    confirm "Type 'purge' to go on:" purge || { echo "Aborted"; exit 3; }
fi

FAIL=0
rm_tree() {   # only the kit's own trees
    case $1 in
        /usr/local/lib/edr-agent|/usr/local/lib/edr-agent.prev|/usr/local/lib/tetragon|/etc/tetragon|/usr/libexec/edr|/etc/edr-dns) rm -rf -- "$1" && echo "removed $1" ;;
    esac
}

# replay the entries of one kind for the given install steps: STEPS is a space-separated list, "*" is all
replay_kind() {   # replay_kind KIND "STEPS"
    local kind=$1 steps=$2 tag k name a b cond step action
    while IFS=$'\t' read -r tag k name a b cond step; do
        [[ $tag == entry && $k == "$kind" ]] || continue
        [[ $steps == '*' || " $steps " == *" $step "* ]] || continue
        [[ $KEEP_SCTP -eq 0 || $name != /etc/modprobe.d/edr-sctp-block.conf ]] || { echo "kept by --keep-sctp-block: $name"; continue; }
        action=$(classify "$k" "$a" "$cond")
        case $action in
            REMOVE|REMOVE_EDITED)
                [[ $action == REMOVE_EDITED ]] && echo "NOTE: $name was changed since install."
                rm -f -- "$name" && echo "removed $name" ;;
            RESTORE)
                if [[ -f $b ]]; then cp -p -- "$b" "$name" && echo "put the prior copy back at $name"; else echo "NOTE: the prior copy $b is missing; $name left"; fi ;;
            RMDIR) rm_tree "$name"; rmdir -- "$name" 2>/dev/null || true ;;
            UNIT_OFF) systemctl disable --now "$name" >/dev/null 2>&1 || true; systemctl reset-failed "$name" >/dev/null 2>&1 || true ;;
            SYSCTL) if sysctl -w "$name=$a" >/dev/null 2>&1; then echo "put $name back to $a"; fi ;;
            *) describe "$action" "$k" "$name" "$a" ;;
        esac
    done <<<"$LIB_ENTRIES"
}

purge_package() {   # purge_package NAME : only a package the manifest marks as the kit's, and only one on the built-in list
    case $1 in suricata|suricata-update|dnscrypt-proxy|nftables|tetragon) ;; *) return 0 ;; esac
    if grep -q -P "^entry\tpackage\t$1\t1\t" <<<"$MANIFEST_OUT"; then
        DEBIAN_FRONTEND=noninteractive apt-get -y purge "$1" && echo "purged $1"
    else
        echo "left package $1 (the kit did not install it)"
    fi
}

lookup_ok() { getent hosts example.com >/dev/null 2>&1 || getent hosts debian.org >/dev/null 2>&1; }

say "The hub"
if [[ -e $STATE_A/identity/current && -f $LIB/edr-agent.py ]]; then
    if timeout 20 python3 -I "$LIB/edr-agent.py" deregister --reason uninstall; then echo "deregistered"
    else echo "The hub could not be told (unreachable or refused): carrying on. The host stays listed there until it is retired."; fi
else
    echo "not enrolled: nothing to deregister"
fi

say "Step 1: stopping everything that rebuilds or re-locks"
systemctl stop edr-install-rollback.timer edr-install-rollback.service edr-install.service edr-agent-pause-end.timer edr-agent-pause-end.service \
    edr-agent-rehome-rollback.timer edr-agent-rehome-rollback.service >/dev/null 2>&1 || true
systemctl reset-failed edr-install-rollback.service edr-agent-pause-end.service >/dev/null 2>&1 || true
systemctl disable --now edr-bans.path edr-bans.timer edr-policy-check.timer >/dev/null 2>&1 || true
[[ $KEEP_DNS -eq 1 ]] || systemctl disable --now edr-dns-watch.timer >/dev/null 2>&1 || true
[[ $KEEP_SURICATA -eq 1 ]] || systemctl disable --now edr-home-net.timer >/dev/null 2>&1 || true
nft delete table inet edr_isolate >/dev/null 2>&1 || true

say "Step 2: the inet edr table"
if nft delete table inet edr >/dev/null 2>&1; then echo "deleted table inet edr (every ban, feed, bigconn and egress rule is gone)"; else echo "no inet edr table"; fi

say "Step 3: DNS"
if [[ $KEEP_DNS -eq 1 ]]; then
    echo "kept by --keep-dns"
else
    nft delete table inet edr_dns >/dev/null 2>&1 && echo "deleted table inet edr_dns"
    systemctl disable --now edr-dnslock.service >/dev/null 2>&1 || true
    rm -f -- /etc/systemd/resolved.conf.d/zz-edr-doh.conf /run/systemd/resolved.conf.d/zzz-edr-failopen.conf /etc/systemd/system/edr-dnslock.service
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl restart systemd-resolved.service >/dev/null 2>&1 || true
    sleep 2
    if lookup_ok; then
        echo "a lookup works through the system resolver"
        systemctl disable --now dnscrypt-proxy.socket dnscrypt-proxy.service >/dev/null 2>&1 || true
        rm -f -- /etc/systemd/system/dnscrypt-proxy.service.d/50-edr.conf
        rmdir /etc/systemd/system/dnscrypt-proxy.service.d 2>/dev/null || true
        systemctl daemon-reload >/dev/null 2>&1 || true
        purge_package dnscrypt-proxy
        rm_tree /etc/edr-dns
        replay_kind unit '8'
        replay_kind file '8'
    else
        echo "FAIL: no lookup works after the resolver was restored: the proxy is left in place (check resolvectl status)"
        FAIL=1
    fi
fi

say "Step 5: units, hooks and local alerts"
replay_kind unit '9'
replay_kind file '9'
systemctl disable --now edr-notify.path edr-notify.service edr-agent.service edr-inventory.timer edr-diskguard.timer edr-droplet-id.service \
    edr-rules-update.timer >/dev/null 2>&1 || true
rm -f -- /etc/systemd/system/edr-agent.service.d/*.conf
rmdir /etc/systemd/system/edr-agent.service.d 2>/dev/null || true
rm -f -- /etc/apt/apt.conf.d/zz-edr-inventory /etc/apt/apt.conf.d/zz-edr-policy-check /etc/needrestart/conf.d/50-edr.conf /etc/update-motd.d/90-edr
systemctl stop systemd-journald@edr.socket systemd-journald@edr.service systemd-journald-audit@edr.socket >/dev/null 2>&1 || true
rm -f -- /etc/systemd/journald@edr.conf
if [[ $KEEP_LOGS -eq 0 ]]; then
    for d in /var/log/journal/*.edr /run/log/journal/*.edr; do [[ -d $d ]] && rm -rf -- "$d"; done
fi
rm -rf -- /var/lib/edr-diskguard /var/lib/edr-notify /var/lib/edr-inventory /var/lib/edr-restart /var/lib/edr-policy-check /var/lib/edr-dns-watch
rm -rf -- /run/edr-bans /run/edr-inventory /run/edr-diskguard /run/edr-policy-check /run/edr-dns-watch /run/edr-droplet-id /run/edr-install.token
systemctl daemon-reload >/dev/null 2>&1 || true

say "Step 6: kernel settings"
replay_kind file '5'
replay_kind sysctl '*'
if [[ $KEEP_SCTP -eq 0 ]]; then
    rm -f -- /etc/modprobe.d/edr-sctp-block.conf
    echo "NOTE: the SCTP module block is gone: both SCTP bugs behind NGINX2Root are open again unless the kernel is patched (PLAN Appendix A.2)."
else echo "kept by --keep-sctp-block"; fi

say "Step 7: Tetragon"
if [[ $KEEP_TETRAGON -eq 1 ]]; then
    echo "kept by --keep-tetragon"
else
    systemctl disable --now tetragon.service >/dev/null 2>&1 || true
    rm -f -- /etc/systemd/system/tetragon.service /etc/systemd/system/tetragon.service.d/50-edr-check.conf /etc/systemd/system/tetragon.service.d/10-edr.conf
    rmdir /etc/systemd/system/tetragon.service.d 2>/dev/null || true
    rm -f -- /usr/local/bin/tetragon /usr/local/bin/tetra
    rm_tree /usr/local/lib/tetragon
    rm_tree /etc/tetragon
    rm_tree /usr/libexec/edr
    rm -rf /sys/fs/bpf/tetragon /run/tetragon/tetragon.sock 2>/dev/null || true
    if [[ $KEEP_LOGS -eq 0 ]]; then rm -rf -- /var/log/tetragon && echo "removed /var/log/tetragon"; else echo "kept the Tetragon event logs (--keep-logs)"; fi
    replay_kind file '7'
    replay_kind unit '7'
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

say "Step 8: Suricata"
if [[ $KEEP_SURICATA -eq 1 ]]; then
    echo "kept by --keep-suricata"
else
    systemctl disable --now suricata.service >/dev/null 2>&1 || true
    rm -f -- /etc/systemd/system/suricata.service.d/override.conf /etc/systemd/system/edr-rules-update.service /etc/systemd/system/edr-rules-update.timer \
        /etc/systemd/system/edr-home-net.service /etc/systemd/system/edr-home-net.timer /etc/apt/preferences.d/suricata-8
    rmdir /etc/systemd/system/suricata.service.d 2>/dev/null || true
    rm -f -- /etc/suricata/edr-home-net.yaml /etc/suricata/home-net.extra /etc/suricata/edr-dns.rules /etc/suricata/suricata.yaml.new \
        /var/lib/suricata/rules/edr-ban-sids.txt /var/lib/suricata/rules/edr-rules-status.json /var/lib/suricata/edr-rules-skipped
    replay_kind unit '4'
    replay_kind file '4'
    rm -rf /var/lib/suricata/cache/sgh
    systemctl daemon-reload >/dev/null 2>&1 || true
    purge_package suricata
    if grep -q -P $'^entry\tppa\t\\S+\t1\t' <<<"$MANIFEST_OUT"; then
        add-apt-repository -y -r ppa:oisf/suricata-stable && echo "removed the OISF PPA"
    else echo "left the OISF PPA (the kit did not add it, or it is not there)"; fi
fi
# nftables goes last, after the kit's tables are gone
if [[ $KEEP_DNS -eq 0 && $KEEP_SURICATA -eq 0 ]]; then purge_package nftables; else echo "left package nftables (a partial run)"; fi

say "Step 9: the code, the state, the users"
if [[ $KEEP_DNS -eq 1 ]]; then
    echo "kept by --keep-dns: $LIB (the watchdog's script), local.conf and $ETC_DNS"
else
    rm -f -- /usr/local/sbin/edr-agent /usr/local/sbin/edr-check /usr/local/sbin/edr-uninstall
    rm_tree /usr/local/lib/edr-agent.prev
    rm_tree /usr/local/lib/edr-agent
    if [[ $KEEP_CONFIG -eq 1 ]]; then
        find "$ETC_A" -mindepth 1 -maxdepth 1 ! -name local.conf -exec rm -rf -- {} + 2>/dev/null || true
        echo "kept $ETC_A/local.conf (--keep-config)"
    else
        rm -rf -- "$ETC_A"
    fi
fi
# the agent's state, but host-id stays unless --purge
if [[ -d $STATE_A ]]; then
    find "$STATE_A" -mindepth 1 -maxdepth 1 ! -name host-id -exec rm -rf -- {} + 2>/dev/null || true
    if [[ $PURGE -eq 1 ]]; then rm -rf -- "$STATE_A"; echo "removed $STATE_A including host-id"; else echo "kept $STATE_A/host-id (--purge removes it)"; fi
fi
rm -rf -- /run/edr-agent /run/edr-uninstall.keep
if [[ $KEEP_DNS -eq 0 ]]; then replay_kind dir '2'; fi
if [[ $KEEP_ANY -eq 0 ]]; then
    rm -rf -- "$STATE_I"
    for u in edr-notify edr-agent; do
        if grep -q -P "^entry\tuser\t$u\t1\t" <<<"$MANIFEST_OUT" && id -u "$u" >/dev/null 2>&1; then
            userdel "$u" && echo "deleted the user $u"
        elif id -u "$u" >/dev/null 2>&1; then echo "kept the user $u (it existed before the kit)"; fi
    done
else
    echo "kept $STATE_I and the users: a partial run keeps them for the later full uninstall"
fi

say "Step 10: swap"
if [[ -n $SWAP_LINE && ${SWAP_LINE%% *} == /swapfile-edr ]]; then
    swapoff /swapfile-edr 2>/dev/null || true
    if grep -qxF '/swapfile-edr none swap sw 0 0' /etc/fstab; then
        grep -vxF '/swapfile-edr none swap sw 0 0' /etc/fstab > /etc/fstab.edr-new && cat /etc/fstab.edr-new > /etc/fstab && echo "removed the fstab line"
        rm -f /etc/fstab.edr-new
    fi
    rm -f /swapfile-edr && echo "deleted /swapfile-edr"
else echo "the kit made no swapfile"; fi

say "Step 11: final check"
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAIL=1; }
kept() { echo "kept by $1: $2"; }
if nft list table inet edr >/dev/null 2>&1; then fail "table inet edr is still loaded"; else pass "no inet edr table"; fi
if [[ $KEEP_DNS -eq 1 ]]; then kept --keep-dns "inet edr_dns"
elif nft list table inet edr_dns >/dev/null 2>&1; then fail "table inet edr_dns is still loaded"; else pass "no inet edr_dns table"; fi
if nft list table inet edr_isolate >/dev/null 2>&1; then fail "table inet edr_isolate is still loaded"; else pass "no inet edr_isolate table"; fi
left=$({ systemctl list-unit-files --no-legend 'edr-*' 2>/dev/null; systemctl list-units --all --no-legend 'edr-*' 2>/dev/null; } | awk 'NF {print $1}' | sort -u \
    | grep -v -E '^(edr-install|edr-agent-pause-end|edr-agent-rehome-rollback)' || true)
if [[ $KEEP_DNS -eq 1 ]]; then left=$(grep -v -E '^edr-(dns-watch|dnslock)' <<<"$left" || true); fi
if [[ -n $left && $KEEP_ANY -eq 0 ]]; then fail "edr-* units remain:"; sed 's/^/  /' <<<"$left"; else pass "no edr-* unit left$([[ $KEEP_ANY -eq 0 ]] || echo ' (partial run: relaxed)')"; fi
dropins=$(ls /etc/systemd/system/*.service.d/*edr* /etc/systemd/system/edr-* 2>/dev/null || true)
if [[ -n $dropins && $KEEP_ANY -eq 0 ]]; then fail "kit unit files or drop-ins remain:"; sed 's/^/  /' <<<"$dropins"; else pass "no kit drop-in left"; fi
if [[ -e /swapfile-edr && -n $SWAP_LINE ]]; then fail "/swapfile-edr is still there"; else pass "no kit swapfile"; fi
if lookup_ok; then pass "DNS resolves"; else fail "DNS does not resolve"; fi
if [[ -n $(ss -Hltn 2>/dev/null | awk '$4 ~ /:22$/') || -n $(ss -Hltnp 2>/dev/null | grep sshd) ]]; then pass "sshd listens"; else fail "nothing listens on port 22 and no sshd was found"; fi
if systemctl is-active --quiet nginx.service 2>/dev/null; then
    if curl -s -o /dev/null --max-time 5 http://127.0.0.1/; then pass "nginx answers on 127.0.0.1"; else fail "nginx does not answer on 127.0.0.1"; fi
else echo "nginx is not running here: not checked"; fi
bad=0
while IFS=$'\t' read -r tag k name a b _; do
    [[ $tag == entry && $k == sysctl ]] || continue
    [[ $(sysctl -n "$name" 2>/dev/null) == "$a" ]] || { fail "$name is not back at $a"; bad=1; }
done <<<"$MANIFEST_OUT"
[[ $bad -eq 1 ]] || pass "prior sysctl values restored"
if [[ $KEEP_ANY -eq 0 ]]; then
    for p in "$LIB" "$LIB.prev" "$STATE_I" /etc/edr-dns /usr/libexec/edr /usr/local/sbin/edr-agent; do
        if [[ -e $p ]]; then fail "$p is still there"; fi
    done
fi
echo
if [[ $FAIL -eq 0 ]]; then echo "PASS"; exit 0; fi
echo "FAIL"
exit 2
