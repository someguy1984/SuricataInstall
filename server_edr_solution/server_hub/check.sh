#!/bin/bash
# Health check for the EDR hub. Read-only: it changes nothing. Run with: sudo server_hub/check.sh   (or the installed copy)
#
# Checks (hub PLAN section 10): the three services, the listening ports, the `inet edr_hub` table (FAIL if it is not
# loaded), edr-hub-nft.service and edr-hub-backup.timer enabled, no pending edr-hub-fw-rollback timer, `edr-hub health`,
# certificate expiry, database size against its cap, auto_vacuum, WAL size, disk use, backup age, hosts that went
# silent, alert delivery, advisory table age, and the owners and modes of PLAN section 8 step 2.
# The database is read through python3 -I with a read-only connection: the sqlite3 command is not guaranteed to be installed.
#
# Exit codes (PLAN section 17): 0 all pass, 1 warnings only, 2 any FAIL, 64 usage error (including: not run as root).
set -uo pipefail

STATE=/var/lib/edr-hub
OUT_STATE=/var/lib/edr-hub-out
BACKUPS=/var/backups/edr-hub
RUN=/run/edr-hub
ETC=/etc/edr-hub
LIB=/usr/local/lib/edr-hub
CLI=/usr/local/sbin/edr-hub

usage() {
    echo "usage: sudo $0        (read-only health check; exit 0 pass, 1 warnings, 2 failures, 64 usage)"
}
for arg in "$@"; do
    case $arg in
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; usage >&2; exit 64 ;;
    esac
done
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo $0)" >&2; exit 64; }

if [[ -t 1 ]]; then G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' B=$'\e[1m' N=$'\e[0m'; else G='' Y='' R='' B='' N=''; fi
PASS=0 WARN=0 FAIL=0
pass() { echo "  ${G}PASS${N} $*"; PASS=$((PASS + 1)); }
warn() { echo "  ${Y}WARN${N} $*"; WARN=$((WARN + 1)); }
fail() { echo "  ${R}FAIL${N} $*"; FAIL=$((FAIL + 1)); }
info() { echo "       $*"; }
section() { echo; echo "${B}== $* ==${N}"; }

# ---- What the database and settings say, read once -----------------------------------------------------
# Prints key=value lines; every text value is cut down to harmless characters.
db_report() {
    python3 -I - "$STATE" "$LIB" <<'PY'
import json, os, re, sqlite3, sys, time
state, lib = sys.argv[1], sys.argv[2]
now = int(time.time() * 1000)

def safe(v):
    return re.sub(r"[^A-Za-z0-9._:/| -]", "?", str(v))[:80]

def emit(k, v):
    print("%s=%s" % (k, safe(v)))

def size(text, default):
    m = re.match(r"^(\d+)([KMG])?$", str(text).strip().upper())
    return int(m.group(1)) * {None: 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}[m.group(2)] if m else default

settings = {}
try:
    with open(os.path.join(state, "settings.json"), encoding="utf-8") as f:
        settings = json.load(f)
except (OSError, ValueError):
    emit("settings", "unreadable")
for k, d in (("port", 8443), ("enroll_port", 8444), ("ui_port", 8450)):
    v = settings.get(k, d)
    emit(k, v if isinstance(v, int) else d)
for ip in settings.get("public_ip") or []:
    emit("public_ip", ip)
cap = size(settings.get("max_db_size", "2G"), 2 * 1024 ** 3)
emit("cap", cap)
try:
    with open(os.path.join(lib, "advisories.json"), encoding="utf-8") as f:
        emit("advisory_updated", json.load(f).get("updated", ""))
except (OSError, ValueError):
    emit("advisory_updated", "")
db = os.path.join(state, "hub.db")
try:
    conn = sqlite3.connect("file:%s?mode=ro" % db.replace("?", "%3f").replace("#", "%23"), uri=True, timeout=5)
    pc = conn.execute("PRAGMA page_count").fetchone()[0]
    fl = conn.execute("PRAGMA freelist_count").fetchone()[0]
    ps = conn.execute("PRAGMA page_size").fetchone()[0]
    emit("auto_vacuum", conn.execute("PRAGMA auto_vacuum").fetchone()[0])
    try:
        wal = os.path.getsize(db + "-wal")
    except OSError:
        wal = 0
    emit("db_bytes", (pc - fl) * ps + wal)
    emit("wal_bytes", wal)
    def meta(k):
        r = conn.execute("SELECT value FROM meta WHERE key=?", (k,)).fetchone()
        return r[0] if r else None
    lb = meta("last_backup")
    try:
        with open(os.path.join(state, "last-backup"), encoding="utf-8") as f:
            w = f.read().split()
        if w and w[0].isdigit():
            lb = max(int(lb or 0), int(w[0]))
    except OSError:
        pass
    if lb and str(lb).isdigit():
        emit("backup_age_s", max(0, (now - int(lb)) // 1000))
    first = meta("engine_first_tick")
    if first and str(first).isdigit():
        emit("hub_age_s", max(0, (now - int(first)) // 1000))
    for st, n in conn.execute("SELECT state, COUNT(*) FROM hosts GROUP BY state"):
        emit("hosts_" + st, n)
    for name, last in conn.execute("SELECT name, last_seen FROM hosts WHERE state='active' AND (last_seen IS NULL OR last_seen<?) ORDER BY name LIMIT 20", (now - 5 * 60 * 1000,)):
        emit("down", "%s|%s" % (name, "never" if last is None else (now - last) // 1000))
    for (name,) in conn.execute("SELECT name FROM hosts WHERE state='pending' AND last_seen IS NULL AND enrolled_at<? ORDER BY name LIMIT 20", (now - 3600 * 1000,)):
        emit("pending_silent", name)
    emit("open_critical", conn.execute("SELECT COUNT(*) FROM incidents WHERE state IN ('open','acknowledged') AND severity='CRITICAL'").fetchone()[0])
    emit("open_incidents", conn.execute("SELECT COUNT(*) FROM incidents WHERE state IN ('open','acknowledged')").fetchone()[0])
    for ch, n in conn.execute("SELECT channel, COUNT(*) FROM outbox WHERE channel!='none' AND state IN ('failed','dead') AND attempts>0 AND created>? GROUP BY channel", (now - 24 * 3600 * 1000,)):
        emit("outbox_bad", "%s|%s" % (ch, n))
    emit("engine_tick_age_s", max(0, (now - int(meta("engine_tick") or now)) // 1000))
    conn.close()
except sqlite3.Error as e:
    emit("db_error", type(e).__name__)
PY
}

section "Services"
for svc in edr-hub edr-hub-out edr-hub-ui; do
    if systemctl is-active --quiet "$svc.service"; then pass "$svc.service is active"; else fail "$svc.service is not active (journalctl --namespace edr-hub -u $svc -n 30)"; fi
    systemctl is-enabled --quiet "$svc.service" || warn "$svc.service is not enabled at boot"
done
if systemctl is-failed --quiet edr-hub-failed.service; then
    warn "edr-hub-failed.service failed: the failure message could not be sent (check edr-hub-out and the channel)"
fi
if command -v "$CLI" >/dev/null && [[ $(readlink -f "$CLI") == "$LIB/edr-hub" ]]; then
    pass "$CLI is the installed CLI"
else
    warn "$CLI is not a link to $LIB/edr-hub"
fi

# One read of the settings and the database for everything below
declare -A V
DOWN=() PSILENT=() OBAD=() PUBLIC=()
if report=$(db_report 2>/dev/null); then
    while IFS='=' read -r k v; do
        case $k in
            down) DOWN+=("$v") ;;
            pending_silent) PSILENT+=("$v") ;;
            outbox_bad) OBAD+=("$v") ;;
            public_ip) PUBLIC+=("$v") ;;
            *) V[$k]=$v ;;
        esac
    done <<<"$report"
else
    fail "could not read the settings and the database (python3 -I failed)"
fi
PORT=${V[port]:-8443} ENROLL=${V[enroll_port]:-8444} UIPORT=${V[ui_port]:-8450}
[[ -z ${V[settings]:-} ]] || fail "$STATE/settings.json is unreadable"

section "Listening ports"
listen=$(ss -ltnH 2>/dev/null || true)
if awk -v p=":$PORT" '$4 ~ p "$" { found = 1 } END { exit !found }' <<<"$listen"; then
    pass "fleet port $PORT is listening"
else
    fail "nothing listens on the fleet port $PORT"
fi
if awk -v p=":$ENROLL" '$4 ~ p "$" { found = 1 } END { exit !found }' <<<"$listen"; then
    pass "enrollment port $ENROLL is open (a token is pending)"
else
    pass "enrollment port $ENROLL is closed (no token is pending)"
fi
ui_addr=$(awk -v p=":$UIPORT" '$4 ~ p "$" { print $4 }' <<<"$listen")
if [[ -z $ui_addr ]]; then
    fail "nothing listens on the dashboard port $UIPORT"
elif [[ $(wc -l <<<"$ui_addr") -eq 1 && ( $ui_addr == "127.0.0.1:$UIPORT" || $ui_addr == "[::1]:$UIPORT" ) ]]; then
    pass "dashboard port $UIPORT listens on loopback only"
else
    fail "dashboard port $UIPORT listens on more than loopback: $(tr '\n' ' ' <<<"$ui_addr")"
fi

section "Firewall"
if tbl=$(nft -t list table inet edr_hub 2>/dev/null); then
    pass "table inet edr_hub is loaded"
    grep -q 'policy drop' <<<"$tbl" || fail "the input chain of inet edr_hub has no drop policy"
    grep -q 'skuid' <<<"$tbl" || fail "inet edr_hub does not stop the ingest user starting outbound connections (no meta skuid rule)"
    grep -q 'synmeter4' <<<"$tbl" && grep -q 'synmeter6' <<<"$tbl" || warn "inet edr_hub has no SYN meters"
    if grep -qE "tcp dport \{ ?($PORT, $ENROLL|$ENROLL, $PORT) ?\}" <<<"$tbl"; then
        pass "the table covers ports $PORT and $ENROLL"
    else
        warn "the loaded table does not name ports $PORT and $ENROLL (settings changed? re-run install.sh)"
    fi
else
    fail "table inet edr_hub is not loaded: the listeners are open without the firewall"
fi
rollback_pending=0
if systemctl is-active --quiet edr-hub-fw-rollback.timer || systemctl is-active --quiet edr-hub-fw-rollback.service; then
    rollback_pending=1
    fail "edr-hub-fw-rollback is pending: the firewall table will be deleted unless you run install.sh --confirm"
else
    pass "no firewall rollback timer is pending"
fi
if systemctl is-enabled --quiet edr-hub-nft.service; then
    pass "edr-hub-nft.service is enabled (the table survives a reboot)"
elif [[ $rollback_pending -eq 1 ]]; then
    info "edr-hub-nft.service is not enabled yet: install.sh --confirm does that"
else
    fail "edr-hub-nft.service is not enabled: the table will be gone after a reboot"
fi
[[ -f $ETC/edr-hub.nft ]] || warn "$ETC/edr-hub.nft is missing"

section "Hub health"
if [[ -x $CLI ]]; then
    if out=$("$CLI" health 2>&1); then pass "edr-hub health: ${out:-healthy}"; else fail "edr-hub health: ${out:-failed}"; fi
else
    fail "$CLI is missing"
fi
if [[ -n ${V[db_error]:-} ]]; then
    fail "the database could not be read: ${V[db_error]}"
fi
if [[ -n ${V[engine_tick_age_s]:-} && ${V[engine_tick_age_s]} -gt 60 ]]; then
    fail "the engine has not ticked for ${V[engine_tick_age_s]} s"
fi

section "Certificates"
check_cert() {   # file label warn-days fail-days
    local file=$1 label=$2 wd=$3 fd=$4 end
    if [[ ! -r $file ]]; then fail "$label not found: $file"; return; fi
    end=$(openssl x509 -in "$file" -noout -enddate 2>/dev/null | cut -d= -f2)
    if ! openssl x509 -in "$file" -noout -checkend 0 >/dev/null 2>&1; then fail "$label has expired ($end)"
    elif ! openssl x509 -in "$file" -noout -checkend $((fd * 86400)) >/dev/null 2>&1; then fail "$label expires within $fd days ($end)"
    elif ! openssl x509 -in "$file" -noout -checkend $((wd * 86400)) >/dev/null 2>&1; then warn "$label expires within $wd days ($end)"
    else pass "$label is valid until $end"; fi
}
check_cert "$STATE/tls/server.pem" "server certificate" 30 7
check_cert "$STATE/ca/ca.pem" "CA certificate" 730 90
if [[ -r $STATE/ca/ca.pem && -r $STATE/tls/server.pem ]]; then
    if openssl verify -CAfile "$STATE/ca/ca.pem" "$STATE/tls/server.pem" >/dev/null 2>&1; then
        pass "the server certificate chains to the CA"
    else
        fail "the server certificate does not chain to the CA (edr-hub reissue-cert)"
    fi
    sans=$(openssl x509 -in "$STATE/tls/server.pem" -noout -ext subjectAltName 2>/dev/null)
    for ip in "${PUBLIC[@]}"; do
        grep -qF "IP Address:$ip" <<<"$sans" || warn "the server certificate does not name $ip (edr-hub reissue-cert)"
    done
    info "CA SHA-256: $(openssl x509 -in "$STATE/ca/ca.pem" -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}')"
fi

section "Database and disk"
if [[ -n ${V[db_bytes]:-} && -n ${V[cap]:-} ]]; then
    pct=$((100 * ${V[db_bytes]} / ${V[cap]}))
    msg="the database uses $pct% of its $((${V[cap]} / 1048576)) MB cap"
    if [[ $pct -ge 95 ]]; then fail "$msg"; elif [[ $pct -ge 80 ]]; then warn "$msg"; else pass "$msg"; fi
    wal_mb=$((${V[wal_bytes]} / 1048576))
    if [[ $wal_mb -gt 256 ]]; then warn "the WAL is $wal_mb MB (a pinned reader keeps it growing)"; else pass "the WAL is $wal_mb MB"; fi
fi
if [[ -n ${V[auto_vacuum]:-} ]]; then
    if [[ ${V[auto_vacuum]} -eq 0 ]]; then fail "auto_vacuum is 0: pruning cannot give space back (PRAGMA auto_vacuum=INCREMENTAL; VACUUM)"; else pass "auto_vacuum is on (${V[auto_vacuum]})"; fi
fi
use=$(df --output=pcent "$STATE" 2>/dev/null | tail -1 | tr -dc '0-9')
if [[ -n $use ]]; then
    if [[ $use -ge 90 ]]; then fail "the disk under $STATE is $use% used"; elif [[ $use -ge 80 ]]; then warn "the disk under $STATE is $use% used"; else pass "the disk under $STATE is $use% used"; fi
fi

section "Backups"
if systemctl is-enabled --quiet edr-hub-backup.timer && systemctl is-active --quiet edr-hub-backup.timer; then
    pass "edr-hub-backup.timer is enabled and active (next: $(systemctl show -p NextElapseUSecRealtime --value edr-hub-backup.timer))"
else
    warn "edr-hub-backup.timer is not enabled and active: no scheduled backups"
fi
if systemctl is-failed --quiet edr-hub-backup.service; then fail "the last scheduled backup failed (journalctl --namespace edr-hub -u edr-hub-backup -n 30)"; fi
if [[ -n ${V[backup_age_s]:-} ]]; then
    days=$((${V[backup_age_s]} / 86400))
    if [[ $days -gt 7 ]]; then fail "the last good backup is $days days old (edr-hub backup)"
    elif [[ $days -ge 2 ]]; then warn "the last good backup is $days days old"
    else pass "the last good backup is $((${V[backup_age_s]} / 3600)) hours old"; fi
elif [[ -n ${V[hub_age_s]:-} && ${V[hub_age_s]} -gt $((7 * 86400)) ]]; then
    fail "no good backup was ever made and the hub is over 7 days old (edr-hub backup)"
else
    warn "no good backup yet"
fi
if [[ -d $BACKUPS ]]; then info "$(find "$BACKUPS" -maxdepth 1 -name '*.bak' 2>/dev/null | wc -l) backup file(s) in $BACKUPS"; fi
if [[ -r $ETC/backup.pass ]]; then pass "the backup passphrase file exists"; else fail "$ETC/backup.pass is missing: scheduled backups cannot encrypt"; fi

section "Fleet"
active=${V[hosts_active]:-0}
if [[ ${#DOWN[@]} -eq 0 ]]; then
    pass "$active active host(s), none silent"
else
    for d in "${DOWN[@]}"; do
        warn "host ${d%%|*} sent no heartbeat for ${d##*|} s (or never)"
    done
fi
for h in "${PSILENT[@]}"; do warn "host $h enrolled over an hour ago and never reported"; done
[[ ${V[hosts_orphan]:-0} -eq 0 ]] || warn "${V[hosts_orphan]} host(s) await adoption (edr-hub host UUID adopt)"
[[ ${V[open_critical]:-0} -eq 0 ]] || warn "${V[open_critical]} open CRITICAL incident(s): edr-hub incidents"
info "${V[open_incidents]:-0} open incident(s); IP feeds are not used before P3"
if [[ ${#OBAD[@]} -eq 0 ]]; then
    pass "alert delivery shows no failures in the last 24 hours"
else
    for o in "${OBAD[@]}"; do warn "alert channel ${o%%|*}: ${o##*|} message(s) failed or died in 24 hours (edr-hub alert test)"; done
fi
if [[ -n ${V[advisory_updated]:-} ]]; then
    age=$(( ( $(date +%s) - $(date -d "${V[advisory_updated]}" +%s 2>/dev/null || echo 0) ) / 86400 ))
    if [[ $age -gt 180 ]]; then warn "the advisory table is $age days old: nothing is reported as fixed (update the hub release)"
    elif [[ $age -gt 90 ]]; then warn "the advisory table is $age days old (update the hub release)"
    else pass "the advisory table is $age days old"; fi
else
    warn "the advisory table could not be read"
fi

section "Owners and modes"
check_mode() {   # path owner:group "modes" level(warn|fail)
    local path=$1 want=$2 modes=$3 level=$4 got
    if [[ ! -e $path ]]; then "$level" "$path is missing"; return; fi
    got=$(stat -c '%U:%G %a' "$path")
    if [[ ${got%% *} == "$want" && " $modes " == *" ${got##* } "* ]]; then pass "$path $got"; else "$level" "$path is $got (want $want ${modes%% *})"; fi
}
check_mode "$STATE" edr-hub:edr-hub-ui "2750" warn
check_mode "$STATE/ca" edr-hub:edr-hub "700" fail
check_mode "$STATE/tls" edr-hub:edr-hub "700" fail
check_mode "$STATE/tls/server.key" edr-hub:edr-hub "600" fail
check_mode "$STATE/ca/ca.key" edr-hub:edr-hub "600 400" fail
check_mode "$OUT_STATE" edr-hub-out:edr-hub-out "700" warn
check_mode "$BACKUPS" root:root "700" warn
check_mode "$RUN" edr-hub:edr-hub "711" fail
check_mode "$RUN/ctl.sock" edr-hub:edr-hub "600" fail
check_mode "$RUN/ui.sock" edr-hub:edr-hub-ui "660" fail
check_mode "$RUN/out.sock" edr-hub:edr-hub-out "660" fail
check_mode "$ETC" root:root "750" warn
check_mode "$ETC/secrets.json" root:root "600" fail
check_mode "$ETC/backup.pass" root:root "600" fail

section "Summary"
echo "  ${PASS} passed, ${WARN} warning(s), ${FAIL} failure(s)"
if [[ $FAIL -gt 0 ]]; then exit 2; fi
if [[ $WARN -gt 0 ]]; then exit 1; fi
exit 0
