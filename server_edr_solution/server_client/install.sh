#!/bin/bash
# Install the EDR client kit on a DigitalOcean web server (client PLAN section 7).
#
#   sudo ./install.sh --plan  [flags]                  read-only: pre-flight and everything that would change
#   sudo ./install.sh [--hub IP:PORT --token-file PATH | --token -]  [--yes]
#       [--admin-ip CIDR ...] [--lite] [--no-dns-lockdown] [--no-sctp-block] [--bigconn-cap SIZE]
#       [--webroot PATH ...] [--allow-egress-port N ...] [--enforce | --observe-only] [--enroll-port N]
#       [--home-net CIDR ...] [--resolve-check NAME ...] [--vpc-dns auto] [--swapfile SIZE] [--no-web]
#       [--no-tetragon] [--no-suricata] [--no-kernel] [--droplet-id ID] [--force]
#   sudo /usr/local/lib/edr-agent/install.sh --confirm | --rollback | --plan      session control
#
# Run it from the unpacked, hash-checked kit tarball. It verifies the tree against MANIFEST.sha256 first and
# refuses to run from a tree without one unless --from-checkout is given (for the mock and for tests).
# It never flushes nftables or iptables, never edits UFW or nginx, and never restarts nginx, php-fpm or the
# database. The steps in order (PLAN section 7), each with its rollback:
#   1 pre-flight   2 stage   3 packages   4 Suricata   5 nftables   6 kernel   7 Tetragon   8 DNS
#   9 agent, inventory, local alerts   10 health and confirm   11 enroll (last)
# Steps 4 to 9 are the risky ones: the timer edr-install-rollback is (re)armed for 600 s before each of them
# and again after the last, and `install.sh --confirm` from a NEW session stops it. Over SSH the installer
# runs as the transient unit edr-install, so a dropped session cannot kill it.
# Every file it writes goes into the manifest /var/lib/edr-agent/manifest.json (a second copy in
# /var/lib/edr-install/), written before and after each step; uninstall and --rollback replay it.
#
# Exit codes (PLAN section 15): 0 done, 2 failed (the step was undone), 3 refused (nothing changed),
# 4 rolled back (nobody confirmed, or --rollback finished), 5 installed but not enrolled, 64 usage error.
set -uo pipefail

VERSION_NOW=0.1.0
PHASE=P2
SELF=$(readlink -f "$0")
SRC=$(dirname "$SELF")
if [[ -d $SRC/agent ]]; then AGENT_DIR=$SRC/agent; else AGENT_DIR=$SRC; fi
# EDR_AGENT_ROOT prefixes every path the pre-flight and --plan read, and replaces the programs they probe by
# files in $R/probe/. A real run refuses it: nothing here can install into a prefix.
R=${EDR_AGENT_ROOT:-}

LIB=/usr/local/lib/edr-agent
STATE_A=/var/lib/edr-agent
STATE_I=/var/lib/edr-install
ETC_A=/etc/edr-agent
ETC_DNS=/etc/edr-dns
TETRAGON_VERSION=v1.7.1
TETRAGON_SHA256_amd64=2f36a7bbb2b3d77a011383a01c8f804fe7761d934a76ff2fdf99ebad6f3e89ae
PPA=ppa:oisf/suricata-stable
MIN_RAM_KB=$((2000 * 1024))
MIN_RAM_LITE_KB=$((900 * 1024))
MIN_FREE_KB=$((5 * 1024 * 1024))
MIN_AVAIL_KB=$((1000 * 1024))

usage() {
    cat >&2 <<'USAGE'
usage: install.sh [--plan] [--hub IP:PORT (--token-file PATH | --token -)] [--yes] [--enroll-port N]
                  [--admin-ip CIDR]... [--lite] [--no-dns-lockdown] [--no-sctp-block] [--bigconn-cap SIZE]
                  [--webroot PATH]... [--allow-egress-port N]... [--enforce | --observe-only]
                  [--home-net CIDR]... [--resolve-check NAME]... [--vpc-dns auto] [--swapfile SIZE]
                  [--no-web] [--no-tetragon] [--no-suricata] [--no-kernel] [--droplet-id ID] [--force]
                  [--from-checkout]
       install.sh --confirm | --rollback
The token never goes on the command line: use --token-file PATH, --token - (stdin), EDR_TOKEN or the prompt.
USAGE
}
usage_error() { echo "install.sh: $*" >&2; usage; exit 64; }

PLAN=0 CONFIRM=0 ROLLBACK=0 ASSUME_YES=0 FORCE=0 FROM_CHECKOUT=0 IN_UNIT=0
HUB='' TOKEN_FILE='' TOKEN_STDIN=0 ENROLL_PORT='' DROPLET_ID_ARG='' SWAPFILE='' BIGCONN_CAP='' VPC_DNS=''
LITE=0 NO_DNS=0 NO_SCTP=0 NO_WEB=0 NO_TETRAGON=0 NO_SURICATA=0 NO_KERNEL=0 ENFORCE=0 OBSERVE=0
ADMIN_IPS=() WEBROOTS=() EGRESS_PORTS=() HOME_NETS=() RESOLVE_CHECKS=()
ORIG_ARGS=("$@")

valid_cidr() { python3 -I -c 'import ipaddress, sys; ipaddress.ip_network(sys.argv[1], strict=False)' "$1" 2>/dev/null; }
valid_name() { [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; }

while [[ $# -gt 0 ]]; do
    case $1 in
        --plan) PLAN=1 ;;
        --confirm) CONFIRM=1 ;;
        --rollback) ROLLBACK=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --force) FORCE=1 ;;
        --from-checkout) FROM_CHECKOUT=1 ;;
        --in-unit) IN_UNIT=1 ;;
        --lite) LITE=1 ;;
        --no-dns-lockdown) NO_DNS=1 ;;
        --no-sctp-block) NO_SCTP=1 ;;
        --no-web) NO_WEB=1 ;;
        --no-tetragon) NO_TETRAGON=1 ;;
        --no-suricata) NO_SURICATA=1 ;;
        --no-kernel) NO_KERNEL=1 ;;
        --enforce) ENFORCE=1 ;;
        --observe-only) OBSERVE=1 ;;
        --hub) [[ $# -ge 2 ]] || usage_error "--hub needs IP:PORT"; HUB=$2; shift ;;
        --token-file) [[ $# -ge 2 ]] || usage_error "--token-file needs a path"; TOKEN_FILE=$2; shift ;;
        --token)
            [[ $# -ge 2 && $2 == - ]] || usage_error "a token on the command line is refused (any local user can read process arguments). Use --token-file PATH, --token - (stdin), EDR_TOKEN or the prompt"
            TOKEN_STDIN=1; shift ;;
        --enroll-port) [[ $# -ge 2 && $2 =~ ^[0-9]+$ && $2 -ge 1 && $2 -le 65535 ]] || usage_error "--enroll-port needs a port number"; ENROLL_PORT=$2; shift ;;
        --droplet-id) [[ $# -ge 2 && $2 =~ ^[A-Za-z0-9._:-]{1,64}$ ]] || usage_error "--droplet-id needs an id of letters, digits and . _ : -"; DROPLET_ID_ARG=$2; shift ;;
        --swapfile) [[ $# -ge 2 && $2 =~ ^[0-9]{1,4}[MG]$ ]] || usage_error "--swapfile needs a size such as 1G"; SWAPFILE=$2; shift ;;
        --bigconn-cap) [[ $# -ge 2 && $2 =~ ^[0-9]{1,6}[KMGT]?$ ]] || usage_error "--bigconn-cap needs a size such as 8G"; BIGCONN_CAP=$2; shift ;;
        --vpc-dns) [[ $# -ge 2 && $2 == auto ]] || usage_error "--vpc-dns only takes: auto"; VPC_DNS=auto; shift ;;
        --admin-ip) [[ $# -ge 2 ]] && valid_cidr "$2" || usage_error "--admin-ip needs an address or CIDR"; ADMIN_IPS+=("$2"); shift ;;
        --home-net) [[ $# -ge 2 ]] && valid_cidr "$2" || usage_error "--home-net needs a CIDR"; HOME_NETS+=("$2"); shift ;;
        --webroot) [[ $# -ge 2 && $2 == /* && $2 != *..* && $2 != *,* ]] || usage_error "--webroot needs an absolute path"; WEBROOTS+=("$2"); shift ;;
        --allow-egress-port) [[ $# -ge 2 && $2 =~ ^[0-9]+$ && $2 -ge 1 && $2 -le 65535 ]] || usage_error "--allow-egress-port needs a port number"; EGRESS_PORTS+=("$2"); shift ;;
        --resolve-check) [[ $# -ge 2 ]] && valid_name "$2" || usage_error "--resolve-check needs a host name"; RESOLVE_CHECKS+=("$2"); shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage_error "unknown option: $1" ;;
    esac
    shift
done
[[ $ENFORCE -eq 0 || $OBSERVE -eq 0 ]] || usage_error "--enforce and --observe-only together make no sense"
if [[ -n $HUB ]]; then
    [[ $HUB =~ ^([0-9.]+|\[[0-9A-Fa-f:]+\]):[0-9]{1,5}$ ]] || usage_error "--hub needs IP:PORT (an IPv6 address in brackets)"
fi
[[ -z $TOKEN_FILE || $TOKEN_STDIN -eq 0 ]] || usage_error "give the token one way only"
[[ $((PLAN + CONFIRM + ROLLBACK)) -le 1 ]] || usage_error "--plan, --confirm and --rollback are separate commands"
if [[ $CONFIRM -eq 1 || $ROLLBACK -eq 1 ]] && [[ $# -gt 0 || -n $HUB || $ENFORCE -eq 1 || $OBSERVE -eq 1 ]]; then
    usage_error "--confirm and --rollback take no other option"
fi
if [[ -n $R && $PLAN -eq 0 ]]; then
    echo "install.sh: EDR_AGENT_ROOT is only for --plan and tests: a real install cannot go into a prefix." >&2
    exit 64
fi

say() { printf '\n==> %s\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 2; }
WARNS=() REFUSALS=() NOTES=()
warn() { WARNS+=("$*"); echo "WARN   $*"; }
refuse() { REFUSALS+=("$*"); echo "REFUSE $*"; }
note() { NOTES+=("$*"); echo "note   $*"; }

# A read-only program the pre-flight asks. With a test root only fixtures in $R/probe/ answer: nothing real runs.
probe() {
    if [[ -n $R ]]; then
        local p=$R/probe/$1
        [[ -x $p ]] || return 127
        shift
        "$p" "$@"
    else
        command -v "$1" >/dev/null 2>&1 || return 127
        "$@"
    fi
}

# ---- the manifest (shared reader, own writer) -------------------------------------------------------------------
# The reader is the same text as in uninstall.sh: every field of a manifest is untrusted input.
manifest_parse() {   # manifest_parse FILE MODE(all|last) [STEP]
    python3 -I - "$1" "$R" "$2" "${3:--}" <<'PY'
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

manifest_flush() {   # manifest_flush STATE FINISHED
    python3 -I - "$R" "$SESSION" "$SESSION_KIND" "$1" "${FROM_VERSION:--}" "$VERSION_NOW" "$STEPS_DONE" "${CURRENT_STEP:--}" \
        "$(components_json)" "$STATE_I/session-$SESSION.tsv" "${2:-0}" <<'PY'
import json, os, sys, time

# argv: ROOT ID KIND STATE FROM TO STEPS CURRENT COMPS_JSON JOURNAL FINISHED(0|1) SWAP(path size|-)
root, sid, kind, state, from_v, to_v, steps, cur, comps_json, journal, finished = sys.argv[1:12]
a_copy = root + "/var/lib/edr-agent/manifest.json"
b_copy = root + "/var/lib/edr-install/manifest.json"


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        if d.get("v") == 1 and isinstance(d.get("sessions"), list):
            return d
    except (OSError, ValueError, AttributeError):
        pass
    return None


doc = load(b_copy) or load(a_copy) or {"v": 1, "version": to_v, "phase": "P2", "components": {}, "sessions": []}
sess = None
for s in doc["sessions"]:
    if s.get("id") == sid:
        sess = s
if sess is None:
    sess = {"id": sid, "kind": kind, "started": int(time.time()), "finished": None, "from_version": from_v if from_v != "-" else None}
    doc["sessions"].append(sess)
sess["state"], sess["to_version"] = state, to_v
sess["steps_done"] = [int(n) for n in steps.split(",") if n.isdigit()]
sess["current_step"] = int(cur) if cur.isdigit() else None
if finished == "1":
    sess["finished"] = int(time.time())
lists = {"files": [], "dirs": [], "units": [], "sysctls": [], "packages": [], "users": [], "notes": [], "not_rolled_back": []}
sess.update({"ppa": None, "conntrack_loaded_before": False, "policy_rc_d_ours": False, "swapfile": None})
try:
    with open(journal, encoding="utf-8") as f:
        rows = [l.rstrip("\n").split("\t") for l in f if l.strip()]
except OSError:
    rows = []


def tri(v):
    return None if v == "null" else v == "true"


for r in rows:
    t = r[0]
    try:
        step = int(r[1]) if r[1].isdigit() else 0
        if t == "file":
            prior = "absent" if r[6] == "absent" else {"saved": r[7], "sha256": r[8]}
            lists["files"].append({"path": r[2], "sha256": r[3], "mode": r[4], "owner": r[5], "prior": prior, "step": step})
        elif t == "dir":
            lists["dirs"].append({"path": r[2], "prior": r[3], "step": step})
        elif t == "unit":
            lists["units"].append({"name": r[2], "prior_enabled": tri(r[3]), "prior_active": tri(r[4]), "step": step})
        elif t == "sysctl":
            lists["sysctls"].append({"key": r[2], "prior": r[3], "value": r[4], "step": step})
        elif t == "package":
            lists["packages"].append({"name": r[2], "by_kit": r[3] == "1", "step": step})
        elif t == "user":
            lists["users"].append({"name": r[2], "by_kit": r[3] == "1", "step": step})
        elif t == "ppa":
            sess["ppa"] = {"name": r[2], "by_kit": r[3] == "1"}
        elif t == "note":
            lists["notes"].append(r[2])
        elif t == "notrb":
            lists["not_rolled_back"].append(r[2])
        elif t == "flag":
            sess[r[2]] = r[3] == "1"
        elif t == "swap":
            sess["swapfile"] = {"path": r[2], "size": r[3]}
    except IndexError:
        continue
sess.update(lists)
try:
    doc["components"] = json.loads(comps_json)
except ValueError:
    pass
doc["version"], doc["phase"] = to_v, "P2"
text = json.dumps(doc, indent=1, sort_keys=True) + "\n"
for path in (a_copy, b_copy):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, text.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, path)
PY
}

manifest_file() {
    if [[ -f $R$STATE_I/manifest.json ]]; then echo "$R$STATE_I/manifest.json"; else echo "$R$STATE_A/manifest.json"; fi
}

installed_version() { cat "$R$LIB/VERSION" 2>/dev/null || true; }
is_enrolled() { [[ -e $R$STATE_A/identity/current ]]; }

# ---- what the flags mean ----------------------------------------------------------------------------------------
WANT_WEB=$((1 - NO_WEB)) WANT_TETRAGON=$((1 - NO_TETRAGON)) WANT_SURICATA=$((1 - NO_SURICATA)) WANT_KERNEL=$((1 - NO_KERNEL))
WANT_DNS=$((1 - NO_DNS)) WANT_SCTP=$((1 - NO_SCTP))
if [[ $WANT_KERNEL -eq 0 && $WANT_TETRAGON -eq 1 ]]; then
    # --no-kernel skips BPF too, and Tetragon is BPF: it is installed with --no-tetragon semantics
    WANT_TETRAGON=0
    TETRAGON_DROPPED_BY_NO_KERNEL=1
else
    TETRAGON_DROPPED_BY_NO_KERNEL=0
fi
components_json() {
    local enrolled=false
    is_enrolled && enrolled=true
    printf '{"web": %s, "tetragon": %s, "suricata": %s, "kernel": %s, "dns_lockdown": %s, "sctp_block": %s, "enrolled": %s}' \
        "$(tf $WANT_WEB)" "$(tf $WANT_TETRAGON)" "$(tf $WANT_SURICATA)" "$(tf $WANT_KERNEL)" "$(tf $WANT_DNS)" "$(tf $WANT_SCTP)" "$enrolled"
}
tf() { if [[ $1 -eq 1 ]]; then echo true; else echo false; fi; }
join_by() { local IFS=$1; shift; echo "$*"; }

# ---- small read-only helpers --------------------------------------------------------------------------------------
meminfo_kb() { awk -v k="$1:" '$1 == k { print $2 }' "$R/proc/meminfo" 2>/dev/null; }
os_field() { sed -n "s/^$1=//p" "$R/etc/os-release" 2>/dev/null | head -1 | tr -d '"'; }
free_kb() {
    python3 -I -c '
import os, sys
for p in sys.argv[1:]:
    try:
        s = os.statvfs(p)
        print(s.f_bavail * s.f_frsize // 1024)
        break
    except OSError:
        pass' "$R/var/lib" "$R/var" "$R/"
}
metadata_id() {   # the droplet id when the metadata service answers; nothing otherwise
    local url=${EDR_METADATA_URL:-http://169.254.169.254/metadata/v1/id}
    [[ -z $R || -n ${EDR_METADATA_URL:-} ]] || return 0
    curl -fsS --max-time 2 "$url" 2>/dev/null | head -c 64 | grep -E '^[0-9]{1,20}$' || true
}
vpc_has_default_route() { probe ip -o route show default 2>/dev/null; }

# The address this installer was started from over SSH: SSH_CONNECTION, else the peer of the sshd ancestor
admin_source() {
    local a
    if [[ -n ${SSH_CONNECTION:-} ]]; then
        a=${SSH_CONNECTION%% *}
        [[ $a =~ ^[0-9A-Fa-f.:]+$ ]] && { echo "$a"; return; }
    fi
    [[ -z $R ]] || return 0
    python3 -I - <<'PY' 2>/dev/null
import os, re, subprocess
pids, pid = [], os.getpid()
while pid > 1:
    pids.append(pid)
    try:
        with open("/proc/%d/stat" % pid) as f:
            stat = f.read()
        pid = int(stat.rsplit(")", 1)[1].split()[1])
    except (OSError, ValueError, IndexError):
        break
try:
    out = subprocess.run(["ss", "-Htnp", "state", "established"], capture_output=True, text=True, timeout=5).stdout
except (OSError, subprocess.TimeoutExpired):
    out = ""
for line in out.splitlines():
    m = re.search(r"pid=(\d+)", line)
    if m and int(m.group(1)) in pids:
        f = line.split()
        peer = f[-2] if "users:" in f[-1] else f[-1]
        print(peer.rsplit(":", 1)[0].strip("[]"))
        break
PY
}

read_token() {   # prints the token or nothing. Never from the command line.
    local t=''
    if [[ -n $TOKEN_FILE ]]; then
        [[ -f $TOKEN_FILE && ! -L $TOKEN_FILE ]] || return 1
        t=$(head -c 1024 -- "$TOKEN_FILE" | tr -d '[:space:]')
    elif [[ $TOKEN_STDIN -eq 1 ]]; then
        t=$(head -c 1024 | tr -d '[:space:]')
    elif [[ -n ${EDR_TOKEN:-} ]]; then
        t=$(printf '%s' "$EDR_TOKEN" | head -c 1024 | tr -d '[:space:]')
    elif [[ -t 0 && $PLAN -eq 0 && $ASSUME_YES -eq 0 ]]; then
        read -rsp "Enrollment token: " t; echo >&2
        t=$(printf '%s' "$t" | tr -d '[:space:]')
    fi
    [[ $t =~ ^[A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+\.[0-9a-f]{64}$ ]] || return 1
    printf '%s' "$t"
}

hub_probe() {   # hub_probe HOST ENROLL_PORT : prints "sha256-of-the-CA-DER skew-seconds", or nothing
    python3 -I - "$1" "$2" <<'PY' 2>/dev/null
import email.utils, hashlib, socket, ssl, sys, time
host, port = sys.argv[1].strip("[]"), int(sys.argv[2])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
try:
    with socket.create_connection((host, port), timeout=5) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
        s.sendall(b"GET /v1/ca HTTP/1.0\r\nHost: hub\r\nX-EDR-Proto: 1\r\n\r\n")
        data = b""
        while len(data) < 4096:
            b = s.recv(4096)
            if not b:
                break
            data += b
except (OSError, ssl.SSLError):
    sys.exit(0)
head, _, body = data.partition(b"\r\n\r\n")
try:
    der = ssl.PEM_cert_to_DER_cert(body.decode("ascii", "replace").strip())
except ValueError:
    sys.exit(0)
skew = 0
for line in head.decode("latin-1").splitlines():
    if line.lower().startswith("date:"):
        t = email.utils.parsedate_to_datetime(line.split(":", 1)[1].strip())
        skew = int(abs(t.timestamp() - time.time()))
print(hashlib.sha256(der).hexdigest(), skew)
PY
}

# ---- 1. pre-flight --------------------------------------------------------------------------------------------------
preflight() {
    local id ver arch ram avail swap free hub_host hub_port enroll token sha probe_out meta cur
    id=$(os_field ID); ver=$(os_field VERSION_ID)
    if [[ $id != ubuntu || ! $ver =~ ^(24\.04|26\.04)$ ]]; then
        refuse "this kit supports Ubuntu 24.04 and 26.04 (found: ${id:-unknown} ${ver:-})"
    fi
    [[ -d $R/run/systemd/system ]] || refuse "systemd is not running as PID 1"
    arch=$(probe uname -m 2>/dev/null || echo unknown)
    [[ $arch == x86_64 || ( -n $R && $arch == unknown ) ]] || refuse "amd64 only (found: $arch)"
    if [[ $PLAN -eq 0 && $EUID -ne 0 ]]; then refuse "run as root (sudo $0)"; fi
    if [[ $WANT_TETRAGON -eq 1 || $TETRAGON_DROPPED_BY_NO_KERNEL -eq 1 ]]; then
        [[ -r $R/sys/kernel/btf/vmlinux ]] || refuse "/sys/kernel/btf/vmlinux is missing (no BTF): use --no-tetragon, or a kernel with BTF"
    fi
    if probe systemd-detect-virt --container >/dev/null 2>&1; then
        if [[ $WANT_KERNEL -eq 1 ]]; then refuse "this is a container: the kernel steps would change the host's kernel. Use --no-kernel"
        else warn "this is a container: every kernel-wide step is skipped (--no-kernel)"; fi
    fi
    if [[ $TETRAGON_DROPPED_BY_NO_KERNEL -eq 1 ]]; then
        warn "--no-kernel skips BPF: Tetragon is not installed (same as --no-tetragon)"
    fi
    ram=$(meminfo_kb MemTotal); ram=${ram:-0}
    local need_ram=$MIN_RAM_KB
    if [[ $LITE -eq 1 || $WANT_SURICATA -eq 0 ]]; then need_ram=$MIN_RAM_LITE_KB; fi
    if [[ $ram -lt $need_ram ]]; then
        refuse "total RAM ${ram} kB is below the minimum $((need_ram / 1024)) MB (2 GB; 1 GB only with --lite or --no-suricata, unsupported until measured)"
    fi
    free=$(free_kb); free=${free:-0}
    [[ $free -ge $MIN_FREE_KB ]] || refuse "free disk $((free / 1024)) MB is below the kit's total plus 25% (at least 5 GB)"
    avail=$(meminfo_kb MemAvailable); avail=${avail:-0}
    [[ $avail -ge $MIN_AVAIL_KB ]] || warn "MemAvailable $((avail / 1024)) MB is below the kit's budget plus 25%"
    swap=$(meminfo_kb SwapTotal); swap=${swap:-0}
    if [[ $swap -eq 0 && -z $SWAPFILE ]]; then warn "no swap: --swapfile 1G offers a swapfile (opt-in)"; fi

    # someone else's Suricata, Tetragon or dnscrypt-proxy
    cur=$(manifest_file)
    local mout=''
    [[ ! -f $cur ]] || mout=$(manifest_parse "$cur" all)
    kit_has_package() { grep -q -P "^entry\tpackage\t$1\t1\t" <<<"$mout"; }
    if [[ -e $R/usr/bin/suricata && $WANT_SURICATA -eq 1 ]] && ! kit_has_package suricata; then
        refuse "a Suricata that this kit did not install is already here (/usr/bin/suricata): remove it or use --no-suricata"
    fi
    if [[ -e $R/usr/local/bin/tetragon && $WANT_TETRAGON -eq 1 && ! -d $R$LIB/tetragon ]]; then
        refuse "a Tetragon that this kit did not install is already here (/usr/local/bin/tetragon): use --no-tetragon"
    fi
    if [[ -e $R/usr/sbin/dnscrypt-proxy && $WANT_DNS -eq 1 && ! -d $R$ETC_DNS ]] && ! kit_has_package dnscrypt-proxy \
        && [[ -f $R/etc/dnscrypt-proxy/dnscrypt-proxy.toml ]] && ! grep -q 'edr' "$R/etc/systemd/system/dnscrypt-proxy.service.d/50-edr.conf" 2>/dev/null; then
        refuse "a dnscrypt-proxy that somebody else configured is already here: use --no-dns-lockdown"
    fi
    # things to know about
    for d in fail2ban crowdsec; do
        [[ -d $R/etc/$d ]] && warn "$d is installed: it also bans addresses; the two lists do not talk to each other"
    done
    if [[ -f $R/etc/nftables.conf ]] && grep -q '^flush ruleset' "$R/etc/nftables.conf"; then
        warn "/etc/nftables.conf starts with 'flush ruleset': a reload of nftables.service removes the kit's tables until edr-bans.timer repairs them (within a minute)"
    fi
    [[ -d $R/etc/ufw && -f $R/etc/ufw/ufw.conf ]] && grep -q '^ENABLED=yes' "$R/etc/ufw/ufw.conf" && warn "UFW is active: the kit never edits it; its rules and the kit's tables both apply"
    if [[ -e $R/proc/modules ]] && grep -q '^nf_conntrack ' "$R/proc/modules"; then CONNTRACK_BEFORE=1; else CONNTRACK_BEFORE=0; fi
    if [[ $CONNTRACK_BEFORE -eq 1 ]]; then note "nf_conntrack was already loaded (recorded in the manifest)"; else note "nf_conntrack is not loaded: the kit loads it and sizes it (recorded)"; fi
    local fwd
    fwd=$(cat "$R/proc/sys/net/ipv4/ip_forward" 2>/dev/null || echo 0)
    if [[ -S $R/var/run/docker.sock || -S $R/run/docker.sock || -d $R/var/lib/lxd || -d $R/var/lib/containers || $fwd == 1 ]]; then
        warn "Docker, LXD, podman, a bridge or ip_forward=1 was found: their DNS is not locked; bans still cover forwarded traffic"
    fi
    if [[ -d $R/etc/ploi || -d $R/home/forge || -d $R/etc/nginx/forge-conf || -d $R/etc/nginx/ploi ]]; then
        warn "a panel layout (Forge or Ploi style) was found: discovery handles /home/<user> sites; the panel owns nginx and the firewall"
    fi
    if [[ $WANT_WEB -eq 1 ]]; then
        if [[ ! -x $R/usr/sbin/nginx && ! -x $R/usr/local/sbin/nginx && ! -x $R/usr/bin/nginx && -z $(probe command -v nginx 2>/dev/null) ]] && ! compgen -G "$R/proc/[0-9]*/exe" >/dev/null; then
            refuse "no nginx was found: install it, or use --no-web for a host with no web server"
        fi
        note "the nginx exposure report (package against the advisory, HTTP/2, h2c, HTTP/3, resolver, stale binary) is printed after step 9; the kit never edits nginx"
        note "the enforcement gates (nginx master euid 0, CAP_SYS_ADMIN, no lua or njs) are evaluated by edr-policy-check; a failing gate keeps nginx-exec in monitor"
    fi
    note "install-time DNS pre-flight (.env host names, --resolve-check) runs in step 8, and does not lock if answers differ"
    # an unprivileged password check for the account that will own the box
    local who=${SUDO_USER:-}
    if [[ -n $who && -n $(admin_source) ]]; then
        local pw
        pw=$(getent shadow "$who" 2>/dev/null | cut -d: -f2)
        if [[ -z $pw || $pw == '!' || $pw == '*' || $pw == '!!' || $pw == '!*' ]]; then
            warn "the account $who has no local password: a Droplet Console login needs one"
        fi
        warn "the Droplet Console connects from addresses DigitalOcean does not publish: it cannot be allowlisted, and limiting SSH to admin addresses breaks it (the Recovery Console still works)"
    fi
    # the admin address
    local adm
    adm=$(admin_source)
    ADMIN_SRC=$adm
    if [[ -n $adm ]]; then
        note "admin address $adm will be kept out of every ban (never-ban list, [bans] admin_ip)"
    elif [[ ${#ADMIN_IPS[@]} -eq 0 && ( -n ${SSH_CONNECTION:-} || -n ${SSH_CLIENT:-} || -n ${SSH_TTY:-} ) ]]; then
        refuse "this looks like an SSH session but no source address could be found: pass --admin-ip CIDR"
    fi
    # metadata and the droplet id
    meta=$(metadata_id)
    if [[ -n $DROPLET_ID_ARG && -n $meta ]]; then
        refuse "--droplet-id is for hosts that are not droplets; the metadata service answers here (id $meta)"
    fi
    if [[ -n $HUB && -z $meta && -z $DROPLET_ID_ARG ]]; then
        refuse "--hub needs a droplet id: the metadata service does not answer and no --droplet-id was given"
    fi
    # an existing install: version, hub
    local have_v
    have_v=$(installed_version)
    if [[ -n $have_v ]]; then
        if [[ $have_v == "$VERSION_NOW" ]]; then note "version $have_v is installed: a re-run skips finished steps and never resets local.conf"
        elif [[ $(printf '%s\n%s\n' "$have_v" "$VERSION_NOW" | sort -V | head -1) == "$VERSION_NOW" ]]; then
            [[ $FORCE -eq 1 ]] && warn "installing $VERSION_NOW over the newer $have_v (--force)" \
                || refuse "version $have_v is installed and is newer than $VERSION_NOW: --force installs an older one"
        else note "upgrade from $have_v to $VERSION_NOW: the new tree is staged beside the old one, which stays as edr-agent.prev"; fi
    fi
    if [[ -n $HUB && -f $R$STATE_A/identity/current/hub.conf ]] && is_enrolled; then
        local cur_hub
        cur_hub=$(sed -n 's/^addresses *= *//p' "$R$STATE_A/identity/current/hub.conf" | head -1 | cut -d, -f1)
        if [[ -n $cur_hub && $cur_hub != "${HUB%:*}" ]]; then
            refuse "this host is enrolled to $cur_hub: a different --hub needs: edr-agent rehome --hub $HUB --token-file PATH"
        fi
    fi
    # the hub (P2): only read-only probes, and not at all under a test root
    if [[ -n $HUB ]]; then
        hub_host=${HUB%:*}; hub_port=${HUB##*:}
        enroll=${ENROLL_PORT:-8444}
        token=$(read_token 2>/dev/null || true)
        if [[ -n $token ]]; then note "token format looks right (only enrollment proves the token is valid)"
        elif [[ $PLAN -eq 0 ]]; then refuse "no usable token: use --token-file PATH, --token -, EDR_TOKEN or the prompt"
        else warn "no token was given to --plan: the hub probe is skipped"; fi
        if [[ -z $R && -n $token ]]; then
            probe_out=$(hub_probe "$hub_host" "$enroll" || true)
            if [[ -z $probe_out ]]; then
                warn "the hub does not answer on enrollment port $enroll (down, or no token is pending): the install ends in local mode (exit 5)"
            else
                sha=${probe_out%% *}
                if [[ $sha != "${token##*.}" ]]; then refuse "the CA the hub serves differs from the token's: wrong hub or wrong token"
                elif [[ ${probe_out##* } -gt 60 ]]; then warn "this host's clock differs from the hub's by ${probe_out##* } s"; fi
            fi
        fi
        : "$hub_port"
    fi
    # an install that nobody confirmed
    local last_state
    last_state=$([[ -f $(manifest_file) ]] && manifest_parse "$(manifest_file)" last | awk -F'\t' '$1 == "session" { print $4 }' | tail -1)
    if [[ $last_state == running || $last_state == awaiting-confirm ]]; then
        refuse "an earlier install session was not confirmed (state: $last_state): run install.sh --confirm, or install.sh --rollback"
    fi
    # rule sources and the PPA
    if [[ -z $R && $WANT_SURICATA -eq 1 ]]; then
        for u in https://rules.emergingthreats.net/ https://ppa.launchpadcontent.net/oisf/suricata-stable/ubuntu/; do
            probe curl -fsSI --max-time 8 "$u" >/dev/null 2>&1 || warn "$u is not reachable (the Suricata step may fail; it never falls back to the archive's old Suricata)"
        done
    fi
}

# ---- what each step writes: one table, used by --plan and by the steps ---------------------------------------------------
# step|component|mode|owner|source in the tree|destination
FILE_TABLE='
4|suricata|0644|root:root|files/suricata-drop.conf|/etc/suricata/drop.conf
4|suricata|0644|root:root|files/suricata-modify.conf|/etc/suricata/modify.conf
4|suricata|0644|root:root|files/suricata-disable.conf|/etc/suricata/disable.conf
4|suricata|0644|root:suricata|files/suricata-local.rules|/etc/suricata/local.rules
4|suricata|0644|root:root|files/suricata.apt-pin|/etc/apt/preferences.d/suricata-8
4|suricata|0644|root:root|files/suricata-edr-override.conf|/etc/systemd/system/suricata.service.d/override.conf
4|suricata|0644|root:root|files/edr-rules-update.service|/etc/systemd/system/edr-rules-update.service
4|suricata|0644|root:root|files/edr-rules-update.timer|/etc/systemd/system/edr-rules-update.timer
4|suricata|0644|root:root|files/edr-home-net.service|/etc/systemd/system/edr-home-net.service
4|suricata|0644|root:root|files/edr-home-net.timer|/etc/systemd/system/edr-home-net.timer
5|always|0644|root:root|files/edr-bans.service|/etc/systemd/system/edr-bans.service
5|always|0644|root:root|files/edr-bans.path|/etc/systemd/system/edr-bans.path
5|always|0644|root:root|files/edr-bans.timer|/etc/systemd/system/edr-bans.timer
5|kernel|0644|root:root|files/edr-conntrack.conf|/etc/sysctl.d/90-edr-conntrack.conf
5|kernel|0644|root:root|files/edr-modules-load.conf|/etc/modules-load.d/edr-conntrack.conf
6|sctp|0644|root:root|files/edr-sctp-block.conf|/etc/modprobe.d/edr-sctp-block.conf
7|tetragon|0644|root:root|files/tetragon-edr-check.conf|/etc/systemd/system/tetragon.service.d/50-edr-check.conf
7|tetragon|0644|root:root|files/edr-policy-check.service|/etc/systemd/system/edr-policy-check.service
7|tetragon|0644|root:root|files/edr-policy-check.timer|/etc/systemd/system/edr-policy-check.timer
7|tetragon|0644|root:root|files/zz-edr-policy-check|/etc/apt/apt.conf.d/zz-edr-policy-check
8|dns|0644|root:root|files/resolved-zz-edr-doh.conf|/etc/systemd/resolved.conf.d/zz-edr-doh.conf
8|dns|0644|root:root|files/doh-resolvers.conf|/etc/edr-dns/doh-resolvers.conf
8|dns|0644|root:root|files/edr-dnslock.service|/etc/systemd/system/edr-dnslock.service
8|dns|0644|root:root|files/edr-dns-watch.service|/etc/systemd/system/edr-dns-watch.service
8|dns|0644|root:root|files/edr-dns-watch.timer|/etc/systemd/system/edr-dns-watch.timer
9|always|0644|root:root|files/edr-agent.service|/etc/systemd/system/edr-agent.service
9|always|0644|root:root|files/edr-droplet-id.service|/etc/systemd/system/edr-droplet-id.service
9|always|0644|root:root|files/edr-inventory.service|/etc/systemd/system/edr-inventory.service
9|always|0644|root:root|files/edr-inventory.timer|/etc/systemd/system/edr-inventory.timer
9|always|0644|root:root|files/zz-edr-inventory|/etc/apt/apt.conf.d/zz-edr-inventory
9|always|0644|root:root|files/edr-diskguard.service|/etc/systemd/system/edr-diskguard.service
9|always|0644|root:root|files/edr-diskguard.timer|/etc/systemd/system/edr-diskguard.timer
9|always|0640|root:edr-agent|files/edr-logrotate.conf|/etc/edr-agent/logrotate.conf
9|notify|0644|root:root|files/edr-notify.service|/etc/systemd/system/edr-notify.service
9|notify|0644|root:root|files/edr-notify.path|/etc/systemd/system/edr-notify.path
9|always|0644|root:root|files/journald-edr.conf|/etc/systemd/journald@edr.conf
9|always|0755|root:root|files/motd-90-edr|/etc/update-motd.d/90-edr
9|needrestart|0644|root:root|files/needrestart-50-edr.conf|/etc/needrestart/conf.d/50-edr.conf
'
# also written, not in the table (they are generated or need a decision): the code tree, local.conf, the links,
# the Suricata candidate yaml, edr-home-net.yaml, the Tetragon release and its policies, the canary, the
# dnscrypt-proxy toml and its drop-in, the lock file, the swapfile.

component_wanted() {
    case $1 in
        always) return 0 ;;
        suricata) [[ $WANT_SURICATA -eq 1 ]] ;;
        tetragon) [[ $WANT_TETRAGON -eq 1 ]] ;;
        kernel) [[ $WANT_KERNEL -eq 1 ]] ;;
        sctp) [[ $WANT_SCTP -eq 1 ]] ;;
        dns) [[ $WANT_DNS -eq 1 ]] ;;
        notify) return 0 ;;
        needrestart) [[ -d $R/etc/needrestart ]] ;;
        *) return 1 ;;
    esac
}

step_title() {
    case $1 in
        1) echo "pre-flight" ;; 2) echo "stage the code, the users and local.conf" ;; 3) echo "packages" ;;
        4) echo "Suricata (candidate, test, commit)" ;; 5) echo "nftables bans and conntrack" ;; 6) echo "kernel: SCTP block" ;;
        7) echo "Tetragon, policies, canary, edr-policy-check" ;; 8) echo "DNS over HTTPS and the lock" ;;
        9) echo "agent, inventory, local alerts" ;; 10) echo "health check and confirmation" ;; 11) echo "enroll" ;;
    esac
}
step_phase() {
    case $1 in
        1|2|9|10) echo P1a ;;
        3|4|5|8) echo "P1a, P1b parts" ;;
        6|7) echo P1a ;;
        11) echo P2 ;;
    esac
}

local_conf_changes() {   # prints "section.key=value" for what the flags seed (first install only)
    local a
    if [[ ${#ADMIN_IPS[@]} -gt 0 || -n ${ADMIN_SRC:-} ]]; then
        a=("${ADMIN_IPS[@]}")
        [[ -z ${ADMIN_SRC:-} ]] || a+=("${ADMIN_SRC}")
        echo "bans.admin_ip=$(join_by , "${a[@]}")"
    fi
    [[ $ENFORCE -eq 0 ]] || echo "tetragon.enforce=nginx-exec,sctp-socket,web-exec"
    [[ $OBSERVE -eq 0 ]] || echo "tetragon.enforce="
    [[ ${#EGRESS_PORTS[@]} -eq 0 ]] || echo "tetragon.egress_ports=$(join_by , "${EGRESS_PORTS[@]}")"
    [[ ${#HOME_NETS[@]} -eq 0 ]] || echo "suricata.home_net=$(join_by , "${HOME_NETS[@]}")"
    [[ -z $BIGCONN_CAP ]] || echo "bans.bigconn_cap=$BIGCONN_CAP"
    [[ $LITE -eq 0 ]] || echo "suricata.lite=on"
    [[ $NO_DNS -eq 0 ]] || echo "dns.lockdown=off"
    [[ $NO_SCTP -eq 0 ]] || echo "kernel.sctp_block=off"
    [[ $NO_WEB -eq 0 ]] || echo "kit.web=off"
    [[ $NO_KERNEL -eq 0 ]] || echo "kit.kernel=off"
    [[ $NO_TETRAGON -eq 1 || $TETRAGON_DROPPED_BY_NO_KERNEL -eq 1 ]] && echo "kit.tetragon=off"
    [[ $NO_SURICATA -eq 0 ]] || echo "kit.suricata=off"
    [[ ${#RESOLVE_CHECKS[@]} -eq 0 ]] || echo "dns.resolve_check=$(join_by , "${RESOLVE_CHECKS[@]}")"
    [[ -z $VPC_DNS ]] || echo "dns.vpc_dns=auto"
    return 0
}

# ---- --plan: the pre-flight and the list of everything that would change. Nothing below this function runs before it exits.
plan_main() {
    local step spec comp mode owner src dest state have_v
    echo "install.sh --plan: nothing is changed."
    echo "Kit version $VERSION_NOW, phase $PHASE. Tree: $SRC$([[ $FROM_CHECKOUT -eq 1 ]] && echo ' (--from-checkout: not hash-checked)')"
    have_v=$(installed_version)
    if [[ -n $have_v ]]; then echo "Installed now: $have_v"; else echo "Installed now: nothing"; fi
    say "Step 1: pre-flight ($(step_phase 1))"
    preflight
    echo
    echo "Pre-flight: ${#REFUSALS[@]} refusal(s), ${#WARNS[@]} warning(s), ${#NOTES[@]} note(s)."
    say "Components"
    echo "web=$(tf $WANT_WEB) tetragon=$(tf $WANT_TETRAGON) suricata=$(tf $WANT_SURICATA) kernel=$(tf $WANT_KERNEL) dns_lockdown=$(tf $WANT_DNS) sctp_block=$(tf $WANT_SCTP)"
    say "Step 2: $(step_title 2) ($(step_phase 2))"
    state=new; [[ -d $R$LIB ]] && state="already there (the new tree is staged beside it; the old one becomes edr-agent.prev)"
    echo "tree    $LIB: the contents of agent/, files/, tetragon/, install.sh, uninstall.sh, check.sh, VERSION, MANIFEST.sha256, defaults.conf, tripwires.json, advisories.json: $state"
    for dest in /usr/local/sbin/edr-agent /usr/local/sbin/edr-check /usr/local/sbin/edr-uninstall; do
        state=new; [[ -e $R$dest || -L $R$dest ]] && state="already there"
        echo "link    $dest: $state"
    done
    for dest in edr-agent edr-notify; do
        state=new; getent passwd "$dest" >/dev/null 2>&1 && [[ -z $R ]] && state="already there"
        echo "user    $dest (system user, no login): $state"
    done
    state=new; [[ -f $R$ETC_A/local.conf ]] && state="already there (never rewritten)"
    echo "file    $ETC_A/local.conf (a commented reference of every key; seeded keys below; discovery fills [sites]): $state"
    if [[ ! -f $R$ETC_A/local.conf ]]; then
        local_conf_changes | sed 's/^/        seeds  [/; s/\./] /; s/=/ = /'
    fi
    echo "file    $ETC_A/notify.min_severity (HIGH unless local.conf says otherwise; root 0600): $([[ -f $R$ETC_A/notify.min_severity ]] && echo 'already there' || echo new)"
    echo "dir     $STATE_A, $STATE_I (manifest and prior copies), /run/edr-* by the units' RuntimeDirectory"
    echo "manifest $STATE_A/manifest.json and $STATE_I/manifest.json, written before and after each step"
    [[ -z $SWAPFILE ]] || echo "swap    /swapfile-edr $SWAPFILE (0600), swapon, one fstab line: $([[ -e $R/swapfile-edr ]] && echo 'already there' || echo new)"
    for step in 3 4 5 6 7 8 9 10 11; do
        say "Step $step: $(step_title "$step") ($(step_phase "$step"))"
        plan_step "$step"
        while IFS='|' read -r spec comp mode owner src dest; do
            [[ $spec == "$step" ]] || continue
            component_wanted "$comp" || continue
            state=new; [[ -e $R$dest ]] && state="already there"
            echo "file    $dest ($mode $owner) from $src: $state"
        done <<<"$FILE_TABLE"
    done
    say "Steps 4 to 9 are risky: before each the 600 s rollback timer edr-install-rollback is (re)armed"
    echo "An unconfirmed install is rolled back by that timer (exit 4); 'install.sh --confirm' from a new SSH session confirms it."
    echo
    echo "It never flushes nftables or iptables, never edits UFW or nginx, never restarts nginx, php-fpm or the database."
    if [[ ${#REFUSALS[@]} -gt 0 ]]; then
        echo; echo "REFUSED (exit 3): a real run would change nothing."
        return 3
    fi
    echo; echo "Would proceed (exit 0)."
    return 0
}

plan_step() {
    case $1 in
        3)
            echo "package python3, openssl (kept on uninstall)"
            [[ $WANT_SURICATA -eq 0 ]] || echo "package software-properties-common, the OISF PPA $PPA (never falls back to the archive's old Suricata), suricata (pinned 1:8.*), suricata-update"
            echo "package nftables"
            [[ $WANT_DNS -eq 0 ]] || echo "package dnscrypt-proxy"
            echo "file    /usr/sbin/policy-rc.d: written only if none exists (101 for suricata and dnscrypt-proxy), removed again at the end of the step"
            echo "apt-get with DPkg::Lock::Timeout=300; apt-get update in a bounded loop (10 x 30 s)" ;;
        4)
            if [[ $WANT_SURICATA -eq 0 ]]; then echo "skipped: --no-suricata"; return; fi
            echo "candidate /etc/suricata/suricata.yaml.new from files/suricata-server.yaml (interface, threads), tested with 'suricata -T' under systemd-run -p MemoryMax=900M, then moved over suricata.yaml"
            echo "file    /etc/suricata/edr-home-net.yaml and home-net.extra: written by edr-home-net"
            echo "file    /etc/suricata/edr-dns.rules: a stub until step 8 fills it"
            echo "rules   suricata-update with the sources of files/suricata-rule-sources.conf; /var/lib/suricata/rules/edr-ban-sids.txt"
            echo "units   suricata.service enabled and restarted once its test passed; edr-rules-update.timer, edr-home-net.timer enabled" ;;
        5)
            echo "table   inet edr: created by edr-bans (never a flush); edr-bans.path and edr-bans.timer enabled"
            if [[ $WANT_KERNEL -eq 1 ]]; then
                echo "kernel  modprobe nf_conntrack if needed; net.netfilter.nf_conntrack_max=262144 if still the default; nf_conntrack_acct=1 (each prior value recorded)"
            else echo "kernel  skipped: --no-kernel (no module, sysctl, conntrack or BPF step)"; fi ;;
        6)
            if [[ $WANT_SCTP -eq 0 ]]; then echo "skipped: --no-sctp-block"; return; fi
            echo "the modprobe.d file is written and its parse checked, even with --no-kernel"
            if [[ $WANT_KERNEL -eq 1 ]]; then echo "kernel  modprobe -r sctp only if it is loaded with no users (not rolled back); update-initramfs -u only if sctp is in the initrd"
            else echo "kernel  skipped: --no-kernel"; fi ;;
        7)
            if [[ $WANT_TETRAGON -eq 0 ]]; then echo "skipped: no Tetragon (--no-tetragon, or --no-kernel)"; return; fi
            echo "release Tetragon $TETRAGON_VERSION (amd64), the SHA-256 pinned in this script, into /usr/local/bin, /usr/local/lib/tetragon, /etc/tetragon"
            echo "config  no boot gate, no viewer; log 20 MB x 5 backups, mode 640; health server on 127.0.0.1:6789; export denylist from tetragon/export-denylist.jsonl"
            echo "policy  rendered by 'edr-agent render' into /etc/tetragon/tetragon.tp.d/edr-*.yaml: every killing policy starts in monitor mode"
            echo "canary  /usr/libexec/edr/canary: a copy of /bin/dash (root:root 0755), matched by the edr-canary policy"
            echo "log     /var/log/tetragon root:edr-agent 2750; tetragon.log group edr-agent mode 640"
            echo "units   tetragon.service enabled and started; edr-policy-check.timer enabled (it promotes a policy when its gate passes)" ;;
        8)
            if [[ $WANT_DNS -eq 0 ]]; then echo "skipped: --no-dns-lockdown"; return; fi
            echo "config  /etc/edr-dns/dnscrypt-proxy.toml for the installed series, checked with 'dnscrypt-proxy -check' before any restart"
            echo "files   /etc/edr-dns/doh-self.conf, doh-resolvers.filtered.conf, edr-dns.nft (generated by edr-dns-watch render), the proxy's sandbox drop-in"
            echo "check   .env host names, --resolve-check names and a lookup through the proxy: no lock if they differ"
            echo "units   dnscrypt-proxy restarted, systemd-resolved restarted (the drop-in), edr-dnslock.service and edr-dns-watch.timer enabled" ;;
        9)
            echo "units   edr-droplet-id, edr-agent (enabled and started), edr-inventory.timer, edr-diskguard.timer, edr-notify.path, apt hook, MOTD, journald@edr.conf"
            [[ $WANT_WEB -eq 0 ]] || echo "report  the nginx exposure findings of edr-inventory are printed as WARN" ;;
        10) echo "check   $LIB/check.sh --local; with no FAIL the unit waits for 'install.sh --confirm' from a new SSH session (--yes confirms itself after the automated checks, which include reaching sshd)" ;;
        11)
            if [[ -n $HUB ]]; then echo "run     edr-agent enroll --hub $HUB --token-file FILE${ENROLL_PORT:+ --enroll-port $ENROLL_PORT}: last, after the rollback timer is disarmed; a failure ends in local mode (exit 5)"
            else echo "skipped: no --hub (local mode; 'edr-agent enroll' joins a hub later)"; fi ;;
    esac
}

# ---- from here on the script changes things ---------------------------------------------------------------------------
# Everything below runs only after the --plan gate at the end of this file.

SESSION='' SESSION_KIND=install FROM_VERSION='' STEPS_DONE='' CURRENT_STEP='' JOURNAL=''
ADMIN_SRC=${ADMIN_SRC:-} CONNTRACK_BEFORE=${CONNTRACK_BEFORE:-0}
WORK=''

jr() { local IFS=$'\t'; printf '%s\n' "$*" >> "$JOURNAL"; }   # one manifest line: kind, step, fields

journaled() { grep -q -F -x -- "$1" <<<"$(cut -f1-3 "$JOURNAL" 2>/dev/null | tr '\t' ' ')"; }

ensure_dir() {   # ensure_dir PATH MODE OWNER
    local path=$1 mode=$2 owner=$3 prior=present
    if [[ ! -d $path ]]; then prior=absent; install -d -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$path"; fi
    journaled "dir $CURRENT_STEP $path" || jr dir "$CURRENT_STEP" "$path" "$prior"
}

# install_file SOURCE DEST MODE OWNER : the file goes in under a temporary name and is renamed; a file that was there is
# copied to /var/lib/edr-install/prior/ first, and the manifest says so.
install_file() {
    local src=$1 dest=$2 mode=$3 owner=$4 prior=absent saved=- psha=- n
    [[ ! -L $dest ]] || die "refusing to replace the symbolic link $dest"
    if [[ -e $dest ]]; then
        n=$(find "$STATE_I/prior/$SESSION" -type f 2>/dev/null | wc -l)
        saved=$STATE_I/prior/$SESSION/$((n + 1))
        install -D -m 0600 -o root -g root "$dest" "$saved"
        psha=$(sha256sum "$dest" | cut -c1-64)
        prior=saved
    fi
    [[ -d $(dirname "$dest") ]] || install -d -m 0755 "$(dirname "$dest")"
    install -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$src" "$dest.edr-new"
    mv -f "$dest.edr-new" "$dest"
    jr file "$CURRENT_STEP" "$dest" "$(sha256sum "$dest" | cut -c1-64)" "$mode" "$owner" "$prior" "$saved" "$psha"
}

write_file() {   # write_file DEST MODE OWNER, the text on stdin
    local tmp
    tmp=$(mktemp "$WORK/wf.XXXXXX")
    cat > "$tmp"
    install_file "$tmp" "$1" "$2" "$3"
    rm -f "$tmp"
}

# A file the operator may have edited since the kit wrote it is left, and the new copy goes beside it as .new
tuning_file() {   # tuning_file SOURCE DEST MODE OWNER SHIPPED-NAME
    local src=$1 dest=$2 old
    for old in "$LIB.prev/files/$5" "$LIB/files/$5"; do [[ -f $old ]] && break; old=''; done
    if [[ -e $dest && -n $old ]] && ! cmp -s "$dest" "$old" && ! cmp -s "$dest" "$src"; then
        echo "NOTE: $dest was edited: it is left as it is, and the new copy is $dest.new"
        jr note - "$dest was edited by the operator: the new shipped copy is $dest.new"
        install_file "$src" "$dest.new" "$3" "$4"
    else
        install_file "$src" "$dest" "$3" "$4"
    fi
}

install_table_step() {   # install_table_step N : every wanted file of the table for that step
    local spec comp mode owner src dest
    while IFS='|' read -r spec comp mode owner src dest; do
        [[ $spec == "$1" ]] || continue
        component_wanted "$comp" || continue
        install_file "$SRC/$src" "$dest" "$mode" "$owner"
    done <<<"$FILE_TABLE"
}

unit_prior() {   # record how a unit was before the kit touched it, once
    journaled "unit $CURRENT_STEP $1" && return 0
    local en e a
    en=$(systemctl is-enabled "$1" 2>/dev/null || true)
    case $en in enabled|enabled-runtime|static|alias) e=true ;; disabled) e=false ;; *) e=null ;; esac
    if [[ $e == null ]]; then a=null; elif systemctl is-active --quiet "$1" 2>/dev/null; then a=true; else a=false; fi
    jr unit "$CURRENT_STEP" "$1" "$e" "$a"
}
enable_units() {   # enable_units [--now] UNIT...
    local flags=() u
    if [[ $1 == --now ]]; then flags=(--now); shift; fi
    for u in "$@"; do unit_prior "$u"; systemctl enable "${flags[@]}" "$u" || die "cannot enable $u"; done
}

pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }
pkg_record() {   # a package: is it the kit that installs it?
    if pkg_installed "$1"; then jr package "$CURRENT_STEP" "$1" 0; else jr package "$CURRENT_STEP" "$1" 1; fi
}
apt_update() {
    local i
    for i in $(seq 10); do
        apt-get -o DPkg::Lock::Timeout=300 update && return 0
        echo "apt-get update failed (try $i of 10): waiting 30 s"; sleep 30
    done
    return 1
}
apt_install() { apt-get -o DPkg::Lock::Timeout=300 -y install "$@"; }

conf_edit() {   # conf_edit ROOT section.key=value... : through the agent's own validator and writer
    local root=$1; shift
    python3 -I - "$LIB" "$root" "$@" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from edragent import config, paths
changes = {}
for kv in sys.argv[3:]:
    key, _, value = kv.partition("=")
    section, _, name = key.partition(".")
    changes[(section, name)] = value
config.update_local_conf(paths.Paths(root=sys.argv[2]), changes)
PY
}
conf_value() { python3 -I "$LIB/edr-agent.py" checks value "conf:$1" 2>/dev/null || true; }

arm_timer() {
    systemctl stop edr-install-rollback.timer edr-install-rollback.service >/dev/null 2>&1 || true
    systemctl reset-failed edr-install-rollback.service >/dev/null 2>&1 || true
    systemd-run --quiet --on-active=600 --unit=edr-install-rollback --collect "$LIB/install.sh" --rollback \
        || echo "WARNING: could not arm the rollback timer"
}
disarm_timer() {
    systemctl stop edr-install-rollback.timer edr-install-rollback.service >/dev/null 2>&1 || true
    systemctl reset-failed edr-install-rollback.service >/dev/null 2>&1 || true
}

# ---- the shared replay of a session's entries (rollback of one step, or of the whole last session) -------------------------
SKIP_TREE_FILES=0
replay_step() {   # replay_step STEP|- : the manifest entries of the last session, newest first, as the manifest records them
    local out tag kind name a b cond step
    out=$(manifest_parse "$(manifest_file)" last "${1:--}")
    while IFS=$'\t' read -r tag kind name a b cond step; do
        [[ $tag == entry && $kind == unit ]] || continue
        if [[ $a != true ]]; then
            systemctl disable --now "$name" >/dev/null 2>&1 || true
            systemctl reset-failed "$name" >/dev/null 2>&1 || true
        fi
    done <<<"$out"
    while IFS=$'\t' read -r tag kind name a b cond step; do
        [[ $tag == entry && $kind == file ]] || continue
        case $name in "$LIB"/*|"$LIB.prev"/*) [[ $SKIP_TREE_FILES -eq 0 ]] || continue ;; esac
        if [[ $a == saved ]]; then
            [[ $cond == notfile ]] && continue
            if [[ -f $b ]]; then cp -p -- "$b" "$name" && echo "put the prior copy back at $name"; else echo "NOTE: the prior copy $b is missing; $name left"; fi
        elif [[ $cond != missing && $cond != notfile ]]; then
            rm -f -- "$name" && echo "removed $name"
        fi
    done <<<"$out"
    while IFS=$'\t' read -r tag kind name a b cond step; do
        [[ $tag == entry && $kind == dir && $a == absent ]] || continue
        case $name in
            "$LIB"|"$LIB.prev") [[ $SKIP_TREE_FILES -eq 1 ]] || rm -rf -- "$name" ;;
            /usr/local/lib/tetragon|/etc/tetragon|/usr/libexec/edr|/etc/edr-dns) rm -rf -- "$name" ;;
            "$STATE_I"|"$STATE_I"/*) ;;
            *) rmdir -- "$name" 2>/dev/null || true ;;
        esac
    done <<<"$out"
    while IFS=$'\t' read -r tag kind name a b cond step; do
        [[ $tag == entry && $kind == sysctl ]] || continue
        sysctl -w "$name=$a" >/dev/null 2>&1 && echo "put $name back to $a"
    done <<<"$out"
    while IFS=$'\t' read -r tag kind name a b cond step; do
        [[ $tag == entry ]] || continue
        case $kind in
            package) [[ $a == 1 ]] && { DEBIAN_FRONTEND=noninteractive apt-get -y purge "$name" || true; } ;;
            ppa) [[ $a == 1 ]] && { add-apt-repository -y -r "$name" || true; } ;;
            user) [[ $a == 1 ]] && { userdel "$name" 2>/dev/null || true; } ;;
        esac
    done <<<"$out"
    systemctl daemon-reload >/dev/null 2>&1 || true
}

undo_step() {   # undo_step N : what a step changed live, then the files, units and the rest it recorded
    local n=$1
    case $n in
        8)
            nft delete table inet edr_dns >/dev/null 2>&1 || true
            systemctl stop edr-dnslock.service edr-dns-watch.timer dnscrypt-proxy.socket dnscrypt-proxy.service >/dev/null 2>&1 || true ;;
        7)
            systemctl disable --now tetragon.service >/dev/null 2>&1 || true
            rm -rf /sys/fs/bpf/tetragon /run/tetragon/tetragon.sock 2>/dev/null || true ;;
        5)
            systemctl stop edr-bans.path edr-bans.timer edr-bans.service >/dev/null 2>&1 || true
            nft delete table inet edr >/dev/null 2>&1 || true ;;
        3) remove_policy_rc ;;
        2)
            if [[ $SESSION_KIND == upgrade && -d $LIB.prev ]]; then
                rm -rf "$LIB" && mv "$LIB.prev" "$LIB" && echo "the previous tree is back at $LIB"
                SKIP_TREE_FILES=1
            fi
            rm -f /usr/local/sbin/edr-agent /usr/local/sbin/edr-check /usr/local/sbin/edr-uninstall ;;
    esac
    replay_step "$n"
    case $n in
        8) rm -f /run/systemd/resolved.conf.d/zzz-edr-failopen.conf; systemctl restart systemd-resolved.service >/dev/null 2>&1 || true ;;
        4) systemctl restart suricata.service >/dev/null 2>&1 || true ;;
    esac
}

policy_rc_ours=0
install_policy_rc() {
    if [[ -e /usr/sbin/policy-rc.d ]]; then policy_rc_ours=0; return 0; fi
    cat > /usr/sbin/policy-rc.d <<'PRC'
#!/bin/sh
# Written by the EDR kit installer for the length of the package step: Suricata and dnscrypt-proxy must not
# start on their stock configuration. Removed again by the installer.
case "$1" in
    suricata|dnscrypt-proxy) exit 101 ;;
    *) exit 0 ;;
esac
PRC
    chmod 0755 /usr/sbin/policy-rc.d
    policy_rc_ours=1
    jr flag - policy_rc_d_ours 1
}
remove_policy_rc() {
    if [[ -f /usr/sbin/policy-rc.d ]] && grep -q 'EDR kit installer' /usr/sbin/policy-rc.d 2>/dev/null; then rm -f /usr/sbin/policy-rc.d; fi
    policy_rc_ours=0
}

# ---- the steps ---------------------------------------------------------------------------------------------------------------

tree_extras() {   # a checkout is not laid out like the tarball: add what make dist adds
    local dest=$1
    mkdir -p "$dest/tetragon/policies"
    local p
    for p in privilege-escalation setuid-files kernel-tampering tetragon-tamper boot-config monitor-kernel-modules; do
        [[ -e $dest/tetragon/policies/$p.yaml || ! -f $SRC/../../tetragon/policies/$p.yaml ]] || cp -a "$SRC/../../tetragon/policies/$p.yaml" "$dest/tetragon/policies/$p.yaml"
    done
    [[ -f $dest/files/dns-lockdown-rules.sh || ! -f $SRC/../../controld/files/dns-lockdown-rules.sh ]] || cp -a "$SRC/../../controld/files/dns-lockdown-rules.sh" "$dest/files/"
    [[ -f $dest/VERSION ]] || printf '%s\n' "$VERSION_NOW" > "$dest/VERSION"
}

stage_tree() {
    local new=$LIB.new f adv
    rm -rf "$new"
    mkdir -p "$new"
    cp -a "$AGENT_DIR/." "$new/"
    [[ $AGENT_DIR == "$SRC" ]] || cp -a "$SRC/files" "$SRC/tetragon" "$new/"
    for f in install.sh uninstall.sh check.sh VERSION MANIFEST.sha256 PLAN.md; do
        [[ ! -f $SRC/$f ]] || cp -a "$SRC/$f" "$new/$f"
    done
    [[ $FROM_CHECKOUT -eq 0 ]] || tree_extras "$new"
    cp -a "$new/files/defaults.conf" "$new/defaults.conf"
    # tripwires.json may have been edited: keep the operator's copy, and write the shipped one beside it
    cp -a "$new/files/tripwires.json" "$new/tripwires.json"
    if [[ -f $LIB/tripwires.json && -f $LIB/files/tripwires.json ]] && ! cmp -s "$LIB/tripwires.json" "$LIB/files/tripwires.json"; then
        cp -a "$new/tripwires.json" "$new/tripwires.json.new"
        cp -a "$LIB/tripwires.json" "$new/tripwires.json"
        echo "NOTE: tripwires.json was edited: it is kept, and the shipped one is $LIB/tripwires.json.new"
    fi
    # the advisory table: make dist puts it in the tarball, a checkout keeps it beside server_client
    for adv in ../common common files; do
        [[ -f $SRC/$adv/advisories.json ]] && { cp -a "$SRC/$adv/advisories.json" "$new/advisories.json"; break; }
    done
    [[ -f $new/advisories.json ]] || echo "WARNING: no advisories.json in the kit: edr-inventory cannot judge package fixes"
    find "$new" \( -name __pycache__ -o -name '*.pyc' \) -prune -exec rm -rf {} +
    chown -R root:root "$new"
    chmod -R go-w "$new"
    chmod 0755 "$new" "$new/install.sh" "$new/uninstall.sh" "$new/check.sh" 2>/dev/null || true
    if [[ -d $LIB ]]; then
        jr dir "$CURRENT_STEP" "$LIB" present
        rm -rf "$LIB.prev"
        mv "$LIB" "$LIB.prev"
        jr dir "$CURRENT_STEP" "$LIB.prev" absent
    else
        jr dir "$CURRENT_STEP" "$LIB" absent
    fi
    mv "$new" "$LIB"
    if [[ $SESSION_KIND == install ]]; then
        # every code file with its hash, for `edr-check --audit`
        (cd "$LIB" && find . -type f -print0 | sort -z | xargs -0 sha256sum) | while read -r sha path; do
            jr file "$CURRENT_STEP" "$LIB/${path#./}" "$sha" 0644 root:root absent - -
        done
    fi
    ln -sfn "$LIB/check.sh" /usr/local/sbin/edr-check
    ln -sfn "$LIB/uninstall.sh" /usr/local/sbin/edr-uninstall
    cat > /usr/local/sbin/edr-agent <<'WRAP'
#!/bin/sh
exec /usr/bin/python3 -I /usr/local/lib/edr-agent/edr-agent.py "$@"
WRAP
    chmod 0755 /usr/local/sbin/edr-agent
    for f in edr-agent edr-check edr-uninstall; do jr file "$CURRENT_STEP" "/usr/local/sbin/$f" "$(sha256sum "/usr/local/sbin/$f" | cut -c1-64)" 0755 root:root absent - -; done
}

seed_local_conf() {
    local lc=$ETC_A/local.conf tmp changes=()
    if [[ -f $lc ]]; then echo "local.conf exists: it is never rewritten"; return 0; fi
    tmp=$WORK/lc
    mkdir -p "$tmp$ETC_A"
    {
        echo "# /etc/edr-agent/local.conf: every choice that changes what the kit detects, bans, forwards or enforces."
        echo "# A commented reference of every key at its default (defaults.conf); the keys below it are set by the install flags and by"
        echo "# \`edr-agent discover\`. Edit as root, then run \`edr-agent apply-config\` (add --check to see the diff first)."
        awk '/^[A-Za-z_]+ *=/ { print "# " $0; next } { print }' "$LIB/defaults.conf"
    } > "$tmp$ETC_A/local.conf"
    mapfile -t changes < <(local_conf_changes)
    if [[ ${#changes[@]} -gt 0 ]]; then conf_edit "$tmp" "${changes[@]}" || die "a flag gave a value local.conf refuses"; fi
    install -m 0640 -o root -g edr-agent "$tmp$ETC_A/local.conf" "$lc"
}

step_2() {
    local u id ms
    install -d -m 0700 -o root -g root "$STATE_I" "$STATE_I/prior"
    for u in edr-agent edr-notify; do
        if getent passwd "$u" >/dev/null 2>&1; then jr user 2 "$u" 0
        else
            useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$u"
            jr user 2 "$u" 1
        fi
    done
    ensure_dir "$ETC_A" 0750 root:edr-agent
    ensure_dir "$STATE_A" 0700 edr-agent:edr-agent
    stage_tree
    seed_local_conf
    discover_args=(discover)
    for id in "${WEBROOTS[@]}"; do discover_args+=(--webroot "$id"); done
    python3 -I "$LIB/edr-agent.py" "${discover_args[@]}" || die "edr-agent discover refused (see above); use --no-web for a host with no nginx"
    if [[ -z $(conf_value sites.vpc_cidr) && -t 0 && $ASSUME_YES -eq 0 && $IN_UNIT -eq 0 ]]; then
        read -rp "The VPC range (CIDR, for example 10.116.0.0/20; empty to skip): " id
        if [[ -n $id ]] && valid_cidr "$id"; then conf_edit "" "sites.vpc_cidr=$id"; fi
    fi
    # the Reserved IP and a public IPv6 from the metadata service are kept in [sites] extra_addresses
    local extra='' m
    if [[ -n $(metadata_id) ]]; then
        for m in reserved_ip/ipv4/ip_address interfaces/public/0/ipv6/address; do
            id=$(curl -fsS --max-time 2 "http://169.254.169.254/metadata/v1/$m" 2>/dev/null | head -c 64 | grep -E '^[0-9A-Fa-f:.]+$' || true)
            [[ -z $id ]] || extra+="${extra:+,}$id"
        done
        [[ -z $extra ]] || conf_edit "" "sites.extra_addresses=$extra" || true
    fi
    ms=$(conf_value notify.min_severity); ms=${ms:-HIGH}
    printf '%s\n' "$ms" | write_file "$ETC_A/notify.min_severity" 0600 root:root
    if [[ -n ${SWAPFILE:-} ]]; then make_swap; fi
}

make_swap() {
    [[ ! -e /swapfile-edr ]] || { echo "/swapfile-edr exists: left as it is"; return 0; }
    fallocate -l "$SWAPFILE" /swapfile-edr || dd if=/dev/zero of=/swapfile-edr bs=1M count="$(( ${SWAPFILE%[MG]} * $([[ $SWAPFILE == *G ]] && echo 1024 || echo 1) ))"
    chmod 0600 /swapfile-edr
    mkswap /swapfile-edr >/dev/null
    swapon /swapfile-edr
    printf '%s\n' "/swapfile-edr none swap sw 0 0" >> /etc/fstab
    jr swap - /swapfile-edr "$SWAPFILE"
}

step_3() {
    local p pk=(python3 openssl nftables)
    export DEBIAN_FRONTEND=noninteractive
    install_policy_rc
    [[ $WANT_SURICATA -eq 0 ]] || pk+=(software-properties-common suricata)
    [[ $WANT_DNS -eq 0 ]] || pk+=(dnscrypt-proxy)
    apt_update || die "apt-get update did not succeed"
    if [[ $WANT_SURICATA -eq 1 ]]; then
        apt_install software-properties-common
        install_file "$SRC/files/suricata.apt-pin" /etc/apt/preferences.d/suricata-8 0644 root:root
        if grep -rqs 'oisf/suricata-stable' /etc/apt/sources.list /etc/apt/sources.list.d/; then
            jr ppa - "$PPA" 0
        else
            add-apt-repository -y "$PPA" || die "the OISF PPA could not be added: the installer stops (it never falls back to the archive's old Suricata)"
            jr ppa - "$PPA" 1
            apt_update || die "apt-get update after adding the PPA did not succeed"
        fi
    fi
    for p in "${pk[@]}"; do
        [[ $p == software-properties-common ]] && continue
        case $p in suricata|dnscrypt-proxy|nftables) pkg_record "$p" ;; esac
    done
    apt_install "${pk[@]}" || die "apt-get install failed"
    if [[ $WANT_SURICATA -eq 1 ]]; then
        local v
        v=$(suricata -V 2>/dev/null | grep -o '[0-9][0-9.]*' | head -1)
        echo "Suricata ${v:-?} installed"
        [[ ${v%%.*} -ge 8 ]] || die "Suricata ${v:-unknown} is not 8.x"
    fi
    remove_policy_rc
    jr flag - policy_rc_d_ours 0
}

step_4() {
    [[ $WANT_SURICATA -eq 1 ]] || { echo "skipped: --no-suricata"; return 0; }
    local iface cpus cand=/etc/suricata/suricata.yaml.new tdir avail rss need n
    command -v suricata >/dev/null || die "suricata is not installed"
    iface=$(ip -o route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
    iface=${iface:-eth0}
    cpus=$(nproc)
    sed -e "s/@PUBLIC_IFACE@/$iface/" "$SRC/files/suricata-server.yaml" > "$cand"
    if [[ $cpus -ge 4 ]]; then sed -i 's/^  threads: 1$/  threads: 2/' "$cand"; fi
    chown root:suricata "$cand"
    chmod 0644 "$cand"
    tuning_file "$SRC/files/suricata-drop.conf" /etc/suricata/drop.conf 0644 root:root suricata-drop.conf
    tuning_file "$SRC/files/suricata-modify.conf" /etc/suricata/modify.conf 0644 root:root suricata-modify.conf
    tuning_file "$SRC/files/suricata-disable.conf" /etc/suricata/disable.conf 0644 root:root suricata-disable.conf
    install_file "$SRC/files/suricata-local.rules" /etc/suricata/local.rules 0644 root:suricata
    [[ -e /etc/suricata/edr-dns.rules ]] || printf '# DoH SNI alerts: filled in by the DNS step\n' | write_file /etc/suricata/edr-dns.rules 0644 root:suricata
    # HOME_NET: written by edr-home-net from the interface addresses and local.conf
    python3 -I "$LIB/edr-home-net" --no-reload || die "edr-home-net failed"
    for n in /etc/suricata/edr-home-net.yaml /etc/suricata/home-net.extra; do
        jr file "$CURRENT_STEP" "$n" "$(sha256sum "$n" | cut -c1-64)" 0644 root:root absent - -
    done
    suricata-update update-sources
    mapfile -t sources < <(grep -vE '^\s*(#|$)' "$SRC/files/suricata-rule-sources.conf")
    [[ $(conf_value suricata.sslbl) =~ ^(on|true|yes|1)$ ]] && sources+=(abuse.ch/sslbl-blacklist)
    for n in "${sources[@]}"; do suricata-update enable-source "$n"; done
    # the memory guard: a candidate test loads the whole ruleset
    avail=$(meminfo_kb MemAvailable); avail=${avail:-0}; rss=0
    need=$((rss * 3 / 2)); [[ $need -ge $MIN_AVAIL_KB ]] || need=$((700 * 1024))
    if [[ $avail -lt $need ]]; then
        echo "WARNING: MemAvailable ${avail} kB is under the memory guard ($need kB): Suricata stays installed and stopped; a re-run finishes it"
        jr note - "Suricata was left stopped: memory was under the guard at install"
        rm -f "$cand"
        return 0
    fi
    suricata-update --no-reload --no-test || die "suricata-update failed"
    tdir=$(mktemp -d /var/lib/suricata/test.XXXXXX)
    cp "$cand" "$tdir/suricata.yaml"
    # a private copy of the config, its own log directory and no command socket: the test runs beside the live engine
    if ! systemd-run --quiet --wait --pipe --collect -p MemoryMax=900M -p Nice=19 \
        /usr/bin/suricata -T -c "$tdir/suricata.yaml" -l "$tdir" --set unix-command.enabled=no; then
        rm -rf "$tdir" "$cand"
        die "the Suricata configuration test failed (or was killed at 900 MB): the candidate is rejected"
    fi
    rm -rf "$tdir"
    install_file "$cand" /etc/suricata/suricata.yaml 0644 root:suricata
    rm -f "$cand"
    grep -oP "^drop .*sid:\K[0-9]+" /var/lib/suricata/rules/suricata.rules 2>/dev/null | sort -un > /var/lib/suricata/rules/edr-ban-sids.txt.new || true
    install_file /var/lib/suricata/rules/edr-ban-sids.txt.new /var/lib/suricata/rules/edr-ban-sids.txt 0640 root:suricata
    rm -f /var/lib/suricata/rules/edr-ban-sids.txt.new
    install_table_step 4
    systemctl daemon-reload
    unit_prior suricata.service
    systemctl enable suricata.service >/dev/null
    systemctl restart suricata.service
    enable_units --now edr-rules-update.timer edr-home-net.timer
    sleep 8
    systemctl is-active --quiet suricata.service || die "suricata.service did not stay up (systemctl status suricata)"
}

step_5() {
    local cur acct
    if [[ $WANT_KERNEL -eq 1 ]]; then
        if [[ $CONNTRACK_BEFORE -eq 0 ]]; then
            modprobe nf_conntrack || die "cannot load nf_conntrack"
            jr flag - conntrack_loaded_before 0
        else jr flag - conntrack_loaded_before 1; fi
        cur=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)
        acct=$(cat /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null || echo 0)
        [[ $cur -ge 262144 ]] || jr sysctl 5 net.netfilter.nf_conntrack_max "$cur" 262144
        [[ $acct -eq 1 ]] || jr sysctl 5 net.netfilter.nf_conntrack_acct "$acct" 1
    fi
    install_table_step 5
    if [[ $WANT_KERNEL -eq 1 ]]; then sysctl -p /etc/sysctl.d/90-edr-conntrack.conf >/dev/null || die "sysctl -p failed"; fi
    systemctl daemon-reload
    enable_units --now edr-bans.path edr-bans.timer
    systemctl start edr-bans.service || die "edr-bans.service did not run"
    nft -t list table inet edr >/dev/null 2>&1 || die "table inet edr is not loaded"
}

step_6() {
    [[ $WANT_SCTP -eq 1 ]] || { echo "skipped: --no-sctp-block"; return 0; }
    install_table_step 6
    modprobe -c 2>/dev/null | grep -q '^install sctp /bin/false' || die "/etc/modprobe.d/edr-sctp-block.conf does not parse as the sctp block"
    echo "modprobe.d file written and its parse checked"
    [[ $WANT_KERNEL -eq 1 ]] || return 0
    local rel
    rel=$(uname -r)
    if grep -qs '^CONFIG_IP_SCTP=y' "/boot/config-$rel"; then
        echo "WARNING: SCTP is built into this kernel: the module block does nothing; sctp-socket enforcement is the control"
        jr note - "CONFIG_IP_SCTP=y: the module block does nothing"
    fi
    if lsmod | awk '$1 == "sctp" { found = 1 } END { exit !found }'; then
        if [[ -z $(ss -H --sctp -a 2>/dev/null) && $(awk '$1 == "sctp" { print $3 }' /proc/modules) == 0 ]]; then
            modprobe -r sctp && echo "the sctp module was unloaded" && jr notrb - "modprobe -r sctp"
        else echo "WARNING: the sctp module is loaded and in use: it stays until the users stop or the host reboots"; fi
    fi
    if [[ -f /boot/initrd.img-$rel ]] && lsinitramfs "/boot/initrd.img-$rel" 2>/dev/null | grep -q 'sctp'; then
        update-initramfs -u && jr notrb - "update-initramfs -u (sctp was in the initrd)"
    fi
}

step_7() {
    [[ $WANT_TETRAGON -eq 1 ]] || { echo "skipped: no Tetragon"; return 0; }
    local name=tetragon-$TETRAGON_VERSION-amd64 url work t actual render cf want got i
    url=https://github.com/cilium/tetragon/releases/download/$TETRAGON_VERSION/$name.tar.gz
    work=$WORK/tetragon
    mkdir -p "$work"
    # policies are rendered first: a refusal stops here, before anything is stopped or replaced
    render=$work/render
    python3 -I "$LIB/edr-agent.py" render --out "$render" || die "edr-agent render refused (see the key it names)"
    want=$(find "$render/tetragon.tp.d" -name '*.yaml' 2>/dev/null | wc -l)
    [[ $want -ge 1 ]] || die "no policy was rendered"
    curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$name.tar.gz" "$url"
    actual=$(sha256sum "$work/$name.tar.gz" | cut -d' ' -f1)
    [[ $actual == "$TETRAGON_SHA256_amd64" ]] || die "the Tetragon tarball ($actual) is not the release pinned in this installer"
    tar -xzf "$work/$name.tar.gz" -C "$work"
    t=$work/$name
    [[ -x $t/usr/local/bin/tetragon ]] || die "unexpected Tetragon tarball layout"
    if systemctl is-active --quiet tetragon.service; then systemctl stop tetragon.service; fi
    unit_prior tetragon.service
    install_file "$t/usr/local/bin/tetragon" /usr/local/bin/tetragon 0755 root:root
    install_file "$t/usr/local/bin/tetra" /usr/local/bin/tetra 0755 root:root
    rm -rf /usr/local/lib/tetragon
    cp -a "$t/usr/local/lib/tetragon" /usr/local/lib/tetragon
    chown -R root:root /usr/local/lib/tetragon
    chmod -R go-w /usr/local/lib/tetragon
    jr dir "$CURRENT_STEP" /usr/local/lib/tetragon absent
    install_file "$t/usr/local/lib/tetragon/systemd/tetragon.service" /etc/systemd/system/tetragon.service 0644 root:root
    ensure_dir /etc/tetragon 0700 root:root
    ensure_dir /etc/tetragon/tetragon.conf.d 0700 root:root
    ensure_dir /etc/tetragon/tetragon.tp.d 0700 root:root
    # one file per option: the file name is the flag, the contents the value (the server values of PLAN 4.3 and 9)
    for cf in "enable-process-cred=true" "export-file-max-size-mb=20" "export-file-max-backups=5" "export-file-perm=640" \
        "health-server-address=127.0.0.1:6789" "enable-ancestors=base" "export-rate-limit=-1"; do
        printf '%s\n' "${cf#*=}" | write_file "/etc/tetragon/tetragon.conf.d/${cf%%=*}" 0600 root:root
    done
    grep -vE '^\s*(#|$)' "$SRC/tetragon/export-denylist.jsonl" | write_file /etc/tetragon/tetragon.conf.d/export-denylist 0600 root:root
    find /etc/tetragon/tetragon.tp.d -maxdepth 1 -type f -name 'edr-*.yaml' -delete
    for i in "$render"/tetragon.tp.d/*.yaml; do
        install_file "$i" "/etc/tetragon/tetragon.tp.d/${i##*/}" 0600 root:root
    done
    # no boot gate: Tetragon starts alongside everything and never delays sshd or nginx; it is killed by the OOM killer before the site
    cat <<'DROPIN' | write_file /etc/systemd/system/tetragon.service.d/10-edr.conf 0644 root:root
# Installed by the EDR kit. No boot gate. Tetragon is killed by the kernel before the site under memory pressure.
[Unit]
Conflicts=shutdown.target
Before=shutdown.target

[Service]
OOMScoreAdjust=700
TimeoutStopSec=30
DROPIN
    ensure_dir /usr/libexec/edr 0755 root:root
    install_file /bin/dash /usr/libexec/edr/canary 0755 root:root
    ensure_dir /var/log/tetragon 2750 root:edr-agent
    chown root:edr-agent /var/log/tetragon
    chmod 2750 /var/log/tetragon
    install_table_step 7
    systemctl daemon-reload
    systemctl reset-failed tetragon.service >/dev/null 2>&1 || true
    systemctl enable tetragon.service >/dev/null
    systemctl start tetragon.service || true
    got=0
    for i in $(seq 120); do
        systemctl is-active --quiet tetragon.service || die "tetragon.service stopped (journalctl -u tetragon)"
        got=$(tetra --server-address unix:///var/run/tetragon/tetragon.sock tracingpolicy list -o json 2>/dev/null | python3 -I -c 'import json, sys
try:
    print(len(json.load(sys.stdin).get("policies", [])))
except ValueError:
    print(0)' || echo 0)
        [[ ${got:-0} -ge $want ]] && break
        sleep 1
    done
    [[ ${got:-0} -ge $want ]] || echo "WARNING: only ${got:-0} of $want policies are loaded; edr-policy-check reports which"
    for i in $(seq 20); do [[ -f /var/log/tetragon/tetragon.log ]] && break; sleep 1; done
    if [[ -f /var/log/tetragon/tetragon.log ]]; then chgrp edr-agent /var/log/tetragon/tetragon.log; chmod 0640 /var/log/tetragon/tetragon.log; fi
    enable_units --now edr-policy-check.timer
    systemctl start --no-block edr-policy-check.service || true
}

dns_check() {   # dns_check NAME... : "name proxy=<addresses|NX|FAIL> system=<addresses|FAIL>" through the proxy and through the stub
    python3 -I - "$@" <<'PY'
import random, socket, struct, sys

def query(name, server="127.0.2.1"):
    qid = random.randrange(1, 65535)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1), (server, 53))
        d = s.recv(4096)
    except OSError:
        return "FAIL"
    finally:
        s.close()
    rc = struct.unpack("!H", d[2:4])[0] & 15
    if rc == 3:
        return "NX"
    if rc != 0:
        return "FAIL"
    an = struct.unpack("!H", d[6:8])[0]
    i = 12
    while d[i]:
        i += d[i] + 1
    i += 5
    out = []
    for _ in range(an):
        if d[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while d[i]:
                i += d[i] + 1
            i += 1
        t, _c, _ttl, ln = struct.unpack("!HHIH", d[i:i + 10])
        if t == 1 and ln == 4:
            out.append(socket.inet_ntoa(d[i + 10:i + 14]))
        i += 10 + ln
    return ",".join(sorted(out)) or "EMPTY"

for name in sys.argv[1:]:
    try:
        sysv = ",".join(sorted({a[4][0] for a in socket.getaddrinfo(name, None, socket.AF_INET)}))
    except OSError:
        sysv = "FAIL"
    print(name, "proxy=" + query(name), "system=" + sysv)
PY
}

web_env_hosts() {   # host names from the .env files of the web roots: text only, never executed
    local roots r app
    roots=$(conf_value sites.web_roots | tr ',' '\n')
    while read -r r; do
        [[ -n $r ]] || continue
        app=$r; [[ $(basename "$r") == public ]] && app=$(dirname "$r")
        [[ -f $app/.env && ! -L $app/.env ]] && grep -E '^[A-Z_]*HOST=' "$app/.env" 2>/dev/null | head -20 \
            | sed 's/^[A-Z_]*HOST=//; s/["'"'"']//g; s/[[:space:]#].*//' | grep -E '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' | grep -vE '^(localhost|127\.0\.0\.1)$' | grep -E '[A-Za-z]' || true
    done <<<"$roots"
}

step_8() {
    [[ $WANT_DNS -eq 1 ]] || { echo "skipped: --no-dns-lockdown"; return 0; }
    local series ver toml toml_src work=$WORK/dns lock_ok=1 names n line i ok=0
    command -v dnscrypt-proxy >/dev/null || die "dnscrypt-proxy is not installed"
    if [[ $(readlink -f /etc/resolv.conf) != /run/systemd/resolve/stub-resolv.conf ]]; then
        echo "WARNING: /etc/resolv.conf is not the systemd-resolved stub: the DNS step is skipped and nothing is locked"
        jr note - "DNS step skipped: /etc/resolv.conf is not the resolved stub"
        return 0
    fi
    mkdir -p "$work"
    ensure_dir "$ETC_DNS" 0755 root:root
    ver=$(dpkg-query -W -f='${Version}' dnscrypt-proxy 2>/dev/null)
    case $ver in
        2.0.*) series=2.0 ;;
        2.1.*|2.2.*) series=2.1 ;;
        *) if [[ $(os_field VERSION_ID) == 24.04 ]]; then series=2.0; else series=2.1; fi ;;
    esac
    toml=$ETC_DNS/dnscrypt-proxy.toml
    toml_src=files/dnscrypt-proxy-$series.toml
    install_file "$SRC/$toml_src" "$toml" 0644 root:root
    # a failing config aborts the DNS step before any restart
    dnscrypt-proxy -check -config "$toml" || die "dnscrypt-proxy -check refused the configuration (series $series)"
    python3 -I "$LIB/edr-dns-watch" decode-stamps "$toml" > "$work/self" || die "no resolver address in the stamps"
    install_file "$work/self" "$ETC_DNS/doh-self.conf" 0644 root:root
    install_file "$SRC/files/doh-resolvers.conf" "$ETC_DNS/doh-resolvers.conf" 0644 root:root
    if [[ -n $VPC_DNS ]]; then
        local cidr vpc
        cidr=$(conf_value sites.vpc_cidr | cut -d, -f1)
        vpc=$(python3 -I -c 'import ipaddress, sys
n = ipaddress.ip_network(sys.argv[1], strict=False)
print(n.broadcast_address - 1)' "${cidr:-10.0.0.0/8}" 2>/dev/null || true)
        if [[ -n $cidr && -n $vpc ]]; then
            printf '%s\n' "$vpc" | write_file "$ETC_DNS/vpc-resolver" 0644 root:root
            printf '# <zone> <vpc-resolver>, one per line (the zone list is yours): for example\n#internal.example %s\n' "$vpc" | write_file "$ETC_DNS/forwarding-rules.txt" 0644 root:root
            echo "NOTE: --vpc-dns auto wrote the VPC resolver $vpc; add your private zones to $ETC_DNS/forwarding-rules.txt"
        else echo "WARNING: --vpc-dns auto needs [sites] vpc_cidr: not set"; fi
    fi
    python3 -I "$LIB/edr-dns-watch" render --out-dir "$work/render" --proxy-user _dnscrypt-proxy || die "edr-dns-watch render refused"
    nft -c -f "$work/render/edr-dns.nft" || die "the lock file does not check with nft -c"
    install_file "$work/render/edr-dns.nft" "$ETC_DNS/edr-dns.nft" 0644 root:root
    install_file "$work/render/doh-resolvers.filtered.conf" "$ETC_DNS/doh-resolvers.filtered.conf" 0644 root:root
    ensure_dir /etc/systemd/system/dnscrypt-proxy.service.d 0755 root:root
    install_file "$work/render/50-edr.conf" /etc/systemd/system/dnscrypt-proxy.service.d/50-edr.conf 0644 root:root
    if [[ $WANT_SURICATA -eq 1 && -f $SRC/files/dns-lockdown-rules.sh ]]; then
        bash "$SRC/files/dns-lockdown-rules.sh" "$ETC_DNS/doh-resolvers.filtered.conf" \
            | sed -e 's/^drop /alert /' -e 's/classtype:policy-violation;/classtype:policy-violation; priority:3;/' > "$work/edr-dns.rules" || true
        [[ ! -s $work/edr-dns.rules ]] || install_file "$work/edr-dns.rules" /etc/suricata/edr-dns.rules 0644 root:suricata
    fi
    systemctl daemon-reload
    unit_prior dnscrypt-proxy.socket; unit_prior dnscrypt-proxy.service
    systemctl enable --now dnscrypt-proxy.socket >/dev/null
    for i in $(seq 15); do
        line=$(dns_check example.com | head -1)
        [[ $line == *proxy=[0-9]* ]] && { ok=1; break; }
        sleep 2
    done
    [[ $ok -eq 1 ]] || die "the DoH proxy does not answer on 127.0.2.1 (journalctl -u dnscrypt-proxy): nothing was locked"
    # names the public resolvers may not know: do not lock if the answers differ
    names=$( { web_env_hosts; printf '%s\n' "${RESOLVE_CHECKS[@]}"; conf_value dns.resolve_check | tr ',' '\n'; } | sort -u | grep -v '^$' || true)
    if [[ -n $names ]]; then
        # shellcheck disable=SC2086
        while read -r line; do
            n=${line%% *}
            if [[ $line == *proxy=NX* || $line == *proxy=FAIL* ]]; then
                echo "WARNING: $n does not resolve through the proxy (private name?): the DNS lock is not loaded"; lock_ok=0
            elif [[ $line != *"proxy=${line##*system=}"* ]]; then
                echo "WARNING: $n answers differently through the proxy and the link resolvers: the DNS lock is not loaded"; lock_ok=0
            fi
        done < <(dns_check $names)
    fi
    install_file "$SRC/files/resolved-zz-edr-doh.conf" /etc/systemd/resolved.conf.d/zz-edr-doh.conf 0644 root:root
    systemctl restart systemd-resolved.service
    sleep 2
    if ! getent hosts example.com >/dev/null; then
        rm -f /etc/systemd/resolved.conf.d/zz-edr-doh.conf
        systemctl restart systemd-resolved.service
        die "a lookup failed after the resolver switch: the drop-in was removed again"
    fi
    install_file "$SRC/files/edr-dns-watch.service" /etc/systemd/system/edr-dns-watch.service 0644 root:root
    install_file "$SRC/files/edr-dns-watch.timer" /etc/systemd/system/edr-dns-watch.timer 0644 root:root
    install_file "$SRC/files/edr-dnslock.service" /etc/systemd/system/edr-dnslock.service 0644 root:root
    systemctl daemon-reload
    if [[ $lock_ok -eq 1 ]]; then
        enable_units --now edr-dnslock.service
        nft -t list table inet edr_dns >/dev/null 2>&1 || die "table inet edr_dns is not loaded"
        getent hosts example.com >/dev/null || { nft delete table inet edr_dns; die "a lookup failed under the lock: the lock was removed"; }
        enable_units --now edr-dns-watch.timer
    else
        jr note - "the DNS lock was not loaded: names differ between the proxy and the link resolvers"
        echo "The proxy and the resolver switch are in place; the lock stays off. Fix the names, then: edr-dns-watch relock"
    fi
}

step_9() {
    local id f
    install_table_step 9
    id=$(metadata_id); id=${id:-$DROPLET_ID_ARG}
    if [[ -n $id ]]; then printf '%s\n' "$id" | write_file "$STATE_A/droplet-id" 0644 root:root; fi
    # SupplementaryGroups=suricata adm needs both groups: without Suricata there is no suricata group
    if ! getent group suricata >/dev/null 2>&1; then
        printf '[Service]\nSupplementaryGroups=\nSupplementaryGroups=adm\n' | write_file /etc/systemd/system/edr-agent.service.d/20-groups.conf 0644 root:root
    fi
    f=$WORK/render9
    if python3 -I "$LIB/edr-agent.py" render --out "$f" >/dev/null 2>&1 && [[ -f $f/systemd/edr-agent.service.d/10-hub.conf ]]; then
        install_file "$f/systemd/edr-agent.service.d/10-hub.conf" /etc/systemd/system/edr-agent.service.d/10-hub.conf 0644 root:root
    fi
    systemctl daemon-reload
    enable_units edr-droplet-id.service
    enable_units --now edr-agent.service edr-inventory.timer edr-diskguard.timer edr-notify.path
    for id in $(seq 20); do systemctl is-active --quiet edr-agent.service && break; sleep 1; done
    systemctl is-active --quiet edr-agent.service || die "edr-agent.service did not start (journalctl --namespace=edr -u edr-agent)"
    systemctl start edr-inventory.service || true
    python3 -I - <<'PY' || true
import json
try:
    with open("/run/edr-inventory/inventory.json") as f:
        doc = json.load(f)
except (OSError, ValueError):
    raise SystemExit(0)
for fi in doc.get("findings", []):
    if fi.get("check") in ("nginx_pkg", "nginx_exposure", "deleted_exe", "kernel_pending", "sctp"):
        print("WARN   %s %s: %s" % (fi.get("sev"), fi.get("check"), str(fi.get("summary", ""))[:160]))
PY
}

step_10() {
    local rc=0
    "$LIB/check.sh" --local || rc=$?
    [[ $rc -ne 2 ]] || die "check.sh reported a FAIL (see above)"
}

step_done() {
    case ",$STEPS_DONE," in *",$1,"*) return 0 ;; esac
    return 1
}

run_step() {   # run_step N
    local n=$1 rc
    CURRENT_STEP=$n
    if step_done "$n"; then say "Step $n: $(step_title "$n"): done in this session"; return 0; fi
    say "Step $n: $(step_title "$n") ($(step_phase "$n"))"
    if [[ $n -ge 4 && $n -le 10 ]]; then arm_timer; fi
    manifest_flush running
    ( set -e; "step_$n" )
    rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "Step $n failed (exit $rc): undoing it."
        manifest_flush running
        undo_step "$n" || true
        CURRENT_STEP=''
        manifest_flush failed 1
        disarm_timer
        remove_policy_rc
        exit 2
    fi
    STEPS_DONE=${STEPS_DONE:+$STEPS_DONE,}$n
    CURRENT_STEP=''
    manifest_flush running
}

# ---- confirm, rollback -----------------------------------------------------------------------------------------------------
session_state() {   # the state of the last session
    manifest_parse "$(manifest_file)" last | awk -F'\t' '$1 == "session" { print $4 }' | tail -1
}

do_confirm() {
    [[ $EUID -eq 0 ]] || { echo "install.sh --confirm: run as root" >&2; exit 3; }
    local st
    st=$(session_state)
    if [[ $st != awaiting-confirm ]]; then echo "Nothing is waiting for confirmation (the last session is: ${st:-none})."; exit 3; fi
    local rc=0
    "$LIB/check.sh" --local || rc=$?
    if [[ $rc -eq 2 ]]; then echo "check.sh reports a FAIL: not confirmed. The rollback timer is still armed."; exit 2; fi
    install -m 0600 /dev/null "$STATE_I/confirm"
    echo "Confirmed. The installer disarms the rollback timer and goes on."
    exit 0
}

do_rollback() {
    [[ $EUID -eq 0 ]] || { echo "install.sh --rollback: run as root" >&2; exit 3; }
    local out id kind state steps cur n list=()
    out=$(manifest_parse "$(manifest_file)" last)
    if ! grep -q $'^session\t' <<<"$out"; then echo "No install session to roll back."; exit 3; fi
    if grep -q $'^refuse\t' <<<"$out"; then
        echo "The manifest has entries this script will not act on; nothing was changed:" >&2
        grep $'^refuse\t' <<<"$out" | cut -f2- | sed 's/^/  /' >&2
        exit 3
    fi
    IFS=$'\t' read -r _ id kind state _ _ steps cur < <(grep $'^session\t' <<<"$out" | tail -1)
    if [[ $state == rolled-back ]]; then echo "The last session is already rolled back."; exit 3; fi
    SESSION=$id SESSION_KIND=$kind
    JOURNAL=$STATE_I/session-$id.tsv
    # the installer stops first, and so does the timer that called us
    systemctl stop edr-install.service >/dev/null 2>&1 || true
    systemctl stop edr-install-rollback.timer >/dev/null 2>&1 || true
    for n in ${steps//,/ } ${cur:+$cur}; do [[ $n =~ ^[0-9]+$ ]] && list+=("$n"); done
    if [[ ${#list[@]} -gt 0 ]]; then mapfile -t list < <(printf '%s\n' "${list[@]}" | sort -rnu); fi
    say "Rolling back session $id (steps: ${list[*]:-none})"
    for n in "${list[@]}"; do
        [[ $n =~ ^[0-9]+$ ]] || continue
        say "Undo step $n: $(step_title "$n")"
        undo_step "$n" || true
    done
    remove_policy_rc
    STEPS_DONE=''
    manifest_flush rolled-back 1 2>/dev/null || true
    echo
    echo "Rolled back. Not undone: anything a package's own scripts did, packages that were already there, and any 'modprobe -r sctp' (see the manifest)."
    exit 4
}

wait_confirm() {
    rm -f "$STATE_I/confirm"
    arm_timer
    manifest_flush awaiting-confirm
    if [[ $ASSUME_YES -eq 1 ]]; then
        # the automated checks include reaching sshd from the recorded admin address
        local port=22 adm=${ADMIN_SRC:-}
        sshd_port=$(ss -Hltn 2>/dev/null | awk '$4 ~ /:22$/ { print 22; exit }')
        [[ ${sshd_port:-} == "$port" ]] || { echo "sshd does not listen on port 22: not confirming by itself"; return 1; }
        if [[ -n $adm ]] && ! nft get element inet edr edr_never4 "{ $adm }" >/dev/null 2>&1 && ! nft get element inet edr edr_never6 "{ $adm }" >/dev/null 2>&1; then
            echo "the admin address $adm is not in the never-ban set: not confirming by itself"; return 1
        fi
        echo "--yes: confirmed by the installer after its automated checks"
        return 0
    fi
    echo
    echo "The install is in place. From a NEW SSH session run:   sudo $LIB/install.sh --confirm"
    echo "If nobody confirms within 600 s the whole install is rolled back (exit 4)."
    while [[ ! -f $STATE_I/confirm ]]; do sleep 2; done
    return 0
}

do_enroll() {
    local args
    args=(enroll --hub "$HUB" --token-file "$TOKEN_FILE")
    [[ -z $ENROLL_PORT ]] || args+=(--enroll-port "$ENROLL_PORT")
    [[ -n $DROPLET_ID_ARG ]] && args+=(--droplet-id "$DROPLET_ID_ARG")
    if python3 -I "$LIB/edr-agent.py" "${args[@]}"; then
        rm -f -- "$TOKEN_FILE"
        STEPS_DONE=${STEPS_DONE:+$STEPS_DONE,}11
        return 0
    fi
    echo
    echo "Enrollment failed: the host is installed and runs in local mode. To join the hub later:"
    echo "  sudo edr-agent enroll --hub $HUB --token-file PATH${ENROLL_PORT:+ --enroll-port $ENROLL_PORT}"
    return 1
}

# ---- a re-run: which finished steps are still true ----------------------------------------------------------------------------
step_satisfied() {   # step_satisfied N : only used for a re-run of the same version, whose last session was confirmed
    case $1 in
        2) [[ -f $SRC/MANIFEST.sha256 ]] && cmp -s "$SRC/MANIFEST.sha256" "$LIB/MANIFEST.sha256" && [[ -f $ETC_A/local.conf ]] ;;
        3) pkg_installed python3 && pkg_installed nftables && { [[ $WANT_SURICATA -eq 0 ]] || pkg_installed suricata; } && { [[ $WANT_DNS -eq 0 ]] || pkg_installed dnscrypt-proxy; } ;;
        4) [[ $WANT_SURICATA -eq 0 ]] || { systemctl is-active --quiet suricata.service && [[ -f /etc/systemd/system/suricata.service.d/override.conf ]]; } ;;
        5) nft -t list table inet edr >/dev/null 2>&1 && systemctl is-enabled --quiet edr-bans.path 2>/dev/null ;;
        6) [[ $WANT_SCTP -eq 0 ]] || [[ -f /etc/modprobe.d/edr-sctp-block.conf ]] ;;
        7) [[ $WANT_TETRAGON -eq 0 ]] || { systemctl is-active --quiet tetragon.service && [[ -x /usr/libexec/edr/canary ]]; } ;;
        8) [[ $WANT_DNS -eq 0 ]] || { [[ -f $ETC_DNS/edr-dns.nft ]] && systemctl is-enabled --quiet edr-dns-watch.timer 2>/dev/null; } ;;
        9) systemctl is-active --quiet edr-agent.service ;;
        *) return 1 ;;
    esac
}

verify_tree() {
    if [[ $FROM_CHECKOUT -eq 1 ]]; then echo "--from-checkout: the tree is not hash-checked (for the mock and for tests only)"; return 0; fi
    if [[ ! -f $SRC/MANIFEST.sha256 ]]; then
        echo "REFUSED: $SRC has no MANIFEST.sha256. Run from the unpacked, hash-checked kit tarball (--from-checkout is for the mock and tests)." >&2
        exit 3
    fi
    if ! (cd "$SRC" && sha256sum -c --quiet MANIFEST.sha256 >/dev/null 2>&1); then
        echo "REFUSED: the tree does not match its MANIFEST.sha256 (a damaged or changed copy)." >&2
        exit 3
    fi
    echo "The tree matches MANIFEST.sha256 (that catches damage, not a forged tarball: compare the tarball's hash with the one printed on the build machine)."
}

cleanup() {
    local s=$?
    trap - EXIT
    [[ -z $WORK ]] || rm -rf "$WORK"
    if [[ $policy_rc_ours -eq 1 ]]; then remove_policy_rc; fi
    exit "$s"
}

# ---- the gates: everything above only defines functions ------------------------------------------------------------------------
if [[ $CONFIRM -eq 1 ]]; then do_confirm; fi
if [[ $ROLLBACK -eq 1 ]]; then do_rollback; fi
if [[ $PLAN -eq 1 ]]; then
    verify_tree
    plan_main
    exit $?
fi

# ---- a real run -----------------------------------------------------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || { echo "ERROR: run as root (sudo $0)" >&2; exit 3; }
[[ -d /run/systemd/system ]] || { echo "ERROR: systemd is not running" >&2; exit 3; }

if [[ $IN_UNIT -eq 0 ]]; then
    verify_tree
    plan_main || exit $?
    if systemctl is-active --quiet edr-install.service 2>/dev/null; then
        echo "REFUSED: an install is already running (edr-install.service)." >&2; exit 3
    fi
    if [[ $ASSUME_YES -eq 0 ]]; then
        [[ -t 0 ]] || { echo "No terminal to ask on: use --yes to go ahead." >&2; exit 3; }
        read -rp "Go ahead with the changes listed above? [y/N] " answer
        [[ $answer == y || $answer == Y ]] || { echo "Aborted: nothing was changed."; exit 3; }
    fi
    # the token is read now (a prompt needs this terminal) and handed to the unit through a root-only file
    TOKEN_TMP=''
    if [[ -n $HUB ]]; then
        tok=$(read_token) || { echo "REFUSED: no usable token (--token-file PATH, --token -, EDR_TOKEN or the prompt)" >&2; exit 3; }
        if [[ -z $TOKEN_FILE ]]; then
            TOKEN_TMP=/run/edr-install.token
            (umask 077; printf '%s' "$tok" > "$TOKEN_TMP")
            TOKEN_FILE=$TOKEN_TMP
        fi
    fi
    # a dropped SSH session must not kill the install: it runs as the transient unit edr-install
    inner=() skip=0
    for a in "${ORIG_ARGS[@]}"; do
        if [[ $skip -eq 1 ]]; then skip=0; continue; fi
        case $a in --token|--token-file) skip=1; continue ;; esac
        inner+=("$a")
    done
    [[ -z $HUB ]] || inner+=(--token-file "$TOKEN_FILE")
    inner+=(--in-unit)
    setenv=()
    [[ -z ${SSH_CONNECTION:-} ]] || setenv+=("--setenv=SSH_CONNECTION=$SSH_CONNECTION")
    [[ -z ${SSH_TTY:-} ]] || setenv+=("--setenv=SSH_TTY=$SSH_TTY")
    echo
    echo "Starting the install as the transient unit edr-install (journalctl -fu edr-install)."
    systemd-run --unit=edr-install --collect --wait --pipe --quiet "${setenv[@]}" /bin/bash "$SELF" "${inner[@]}"
    rc=$?
    [[ -z $TOKEN_TMP ]] || rm -f "$TOKEN_TMP"
    if [[ $(session_state) == rolled-back ]]; then exit 4; fi
    exit "$rc"
fi

# ---- inside the unit edr-install ------------------------------------------------------------------------------------------------------
WORK=$(mktemp -d)
trap cleanup EXIT
verify_tree
say "Step 1: pre-flight ($(step_phase 1))"
preflight >/dev/null
[[ ${#REFUSALS[@]} -eq 0 ]] || { printf 'REFUSED: %s\n' "${REFUSALS[@]}" >&2; exit 3; }
last_state=$(session_state)
if [[ $last_state == running || $last_state == awaiting-confirm ]]; then
    echo "REFUSED: an earlier install session was not confirmed (state: $last_state). Run install.sh --confirm, or install.sh --rollback." >&2
    exit 3
fi
FROM_VERSION=$(installed_version)
RERUN_SAME=0
if [[ -n $FROM_VERSION ]]; then
    SESSION_KIND=upgrade
    [[ $FROM_VERSION != "$VERSION_NOW" || $last_state != confirmed ]] || RERUN_SAME=1
fi
SESSION=$(cat /proc/sys/kernel/random/uuid)
install -d -m 0700 -o root -g root "$STATE_I" "$STATE_I/prior" "$STATE_I/prior/$SESSION"
JOURNAL=$STATE_I/session-$SESSION.tsv
: > "$JOURNAL"
chmod 0600 "$JOURNAL"
CURRENT_STEP=1
jr flag - conntrack_loaded_before "$CONNTRACK_BEFORE"
for w in "${WARNS[@]}"; do jr note - "warn: $w"; done
for w in "${NOTES[@]}"; do jr note - "$w"; done
STEPS_DONE=1
mkdir -p "$STATE_A" 2>/dev/null || true
manifest_flush running

if [[ $RERUN_SAME -eq 1 ]]; then
    # a re-run of the same version skips the steps that are still true
    for n in 2 3 4 5 6 7 8 9; do
        if step_satisfied "$n"; then
            STEPS_DONE=$STEPS_DONE,$n
            echo "Step $n: $(step_title "$n"): finished earlier and still true: skipped"
        fi
    done
    manifest_flush running
fi

for n in 2 3 4 5 6 7 8 9; do run_step "$n"; done
run_step 10
manifest_flush awaiting-confirm
if ! wait_confirm; then
    echo "The install was not confirmed: rolling it back."
    do_rollback
fi
disarm_timer
STEPS_DONE=$STEPS_DONE
manifest_flush confirmed 1
echo
echo "The install is confirmed and the rollback timer is disarmed."
if [[ -n $HUB ]]; then
    say "Step 11: enroll ($(step_phase 11))"
    if ! do_enroll; then
        manifest_flush confirmed 1
        exit 5
    fi
    manifest_flush confirmed 1
else
    echo "No --hub: the agent runs in local mode. 'sudo edr-agent enroll --hub IP:PORT --token-file PATH' joins a hub later."
fi
echo
echo "Done. Health check: sudo edr-check. Break-glass, no agent: see PLAN section 4.7. Remove the kit: sudo edr-uninstall."
exit 0
