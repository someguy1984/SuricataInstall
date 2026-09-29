#!/bin/bash
# Health check for the Suricata NFQUEUE (inline IPS) setup. Read-only: changes nothing.
# Run with: sudo ./check.sh [--config-test] [--live]
#   --config-test  also run 'suricata -T' (loads all rules, takes a minute)
#   --live         also send a harmless HTTP request that should trigger an alert-only rule
set -uo pipefail

SRC="$(dirname "$(readlink -f "$0")")/files"
CONF=/etc/suricata/suricata.yaml
LOGDIR=/var/log/suricata
EVE=$LOGDIR/eve.json
RULES=/var/lib/suricata/rules/suricata.rules
NFQ_SCRIPT=/usr/local/sbin/suricata-nfqueue-apply.sh

CONFIG_TEST=0 LIVE=0
for arg in "$@"; do
    case $arg in
        --config-test) CONFIG_TEST=1 ;;
        --live) LIVE=1 ;;
        *) echo "Unknown option: $arg"; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo $0)"; exit 1; }

if [[ -t 1 ]]; then G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' B=$'\e[1m' N=$'\e[0m'; else G= Y= R= B= N=; fi
PASS=0 WARN=0 FAIL=0
pass() { echo "  ${G}PASS${N} $*"; PASS=$((PASS + 1)); }
warn() { echo "  ${Y}WARN${N} $*"; WARN=$((WARN + 1)); }
fail() { echo "  ${R}FAIL${N} $*"; FAIL=$((FAIL + 1)); }
info() { echo "       $*"; }
section() { echo; echo "${B}== $* ==${N}"; }

section "Services"
for svc in suricata.service suricata-nfqueue.service; do
    if systemctl is-active --quiet "$svc"; then pass "$svc is active"; else fail "$svc is not active"; fi
    systemctl is-enabled --quiet "$svc" || warn "$svc is not enabled at boot"
done
if systemctl is-active --quiet suricata-rules-update.timer; then
    pass "Daily rule update timer is active (next: $(systemctl show -p NextElapseUSecRealtime --value suricata-rules-update.timer))"
else
    warn "suricata-rules-update.timer is not active: rules won't update automatically"
fi
since=$(systemctl show -p ActiveEnterTimestamp --value suricata.service)
info "Suricata running since: ${since:-unknown}"
if ps -o args= -C Suricata-Main 2>/dev/null | grep -q -- '-q 0'; then
    pass "Suricata is bound to NFQUEUE 0 (-q 0)"
else
    fail "No Suricata process found with '-q 0' (not running inline)"
fi

section "NFQUEUE firewall rules"
if cmp -s "$SRC/suricata-nfqueue-apply.sh" "$NFQ_SCRIPT"; then
    pass "$NFQ_SCRIPT matches the copy in $SRC"
else
    warn "$NFQ_SCRIPT differs from the copy in $SRC (re-run ./install.sh?)"
fi
for cmd in iptables ip6tables; do
    rules=$($cmd -t mangle -S 2>/dev/null)
    for chain in INPUT OUTPUT FORWARD; do
        n=$(grep -c -- "^-A $chain -j NFQUEUE --queue-num 0 --queue-bypass" <<<"$rules")
        if [[ $n -eq 1 ]]; then pass "$cmd mangle $chain -> NFQUEUE 0"
        elif [[ $n -eq 0 ]]; then fail "$cmd mangle $chain has no NFQUEUE rule (traffic not inspected)"
        else warn "$cmd mangle $chain has $n NFQUEUE rules (expected 1)"; fi
    done
    grep -q -- '^-A INPUT -i lo -j ACCEPT' <<<"$rules" && grep -q -- '^-A OUTPUT -o lo -j ACCEPT' <<<"$rules" \
        || warn "$cmd mangle loopback ACCEPT rules missing (loopback traffic will be queued)"
    if $cmd -S 2>/dev/null | grep -q NFQUEUE; then
        fail "$cmd filter table still has NFQUEUE rules (these bypass UFW)"
    else
        pass "$cmd filter table has no NFQUEUE rules"
    fi
done
if command -v ufw >/dev/null; then
    ufw status | head -1 | grep -q 'Status: active' && pass "UFW is active" || warn "UFW is not active"
fi

section "Kernel queue"
if [[ -r /proc/net/netfilter/nfnetlink_queue ]] && read -r q peer waiting _ _ qdrop udrop seq _ < <(awk '$1 == 0' /proc/net/netfilter/nfnetlink_queue); then
    info "queue 0: waiting=$waiting queue_dropped=$qdrop user_dropped=$udrop packets_seen=$seq"
    [[ $peer -ne 0 ]] && pass "Suricata is attached to queue 0 (portid $peer)" || fail "Nothing is attached to queue 0"
    if [[ $qdrop -gt 0 || $udrop -gt 0 ]]; then
        warn "Queue overflow since boot (queue_dropped=$qdrop user_dropped=$udrop): Suricata can't keep up at peaks"
    else
        pass "No queue overflows"
    fi
else
    fail "Queue 0 not listed in /proc/net/netfilter/nfnetlink_queue (no process bound)"
fi

section "Configuration"
grep -qx '  midstream: true' "$CONF" && pass "stream.midstream is enabled" || warn "stream.midstream is not enabled (re-run ./install.sh?)"
home=$(grep -m1 '^    HOME_NET:' "$CONF")
info "${home#    }"
grep -q 'fc00::/7' <<<"$home" && pass "HOME_NET includes IPv6 ranges" || warn "HOME_NET has no IPv6 ranges (re-run ./install.sh?)"
# Global IPv6 prefixes this machine routes (e.g. after an ISP prefix change) should be in HOME_NET
for prefix in $(ip -6 route show 2>/dev/null | awk '{print $1}' | grep -iE '^[23][0-9a-f]{0,3}:[0-9a-f:]*/[0-9]+$' | sort -u); do
    if grep -qF -- "$prefix" <<<"$home"; then
        pass "IPv6 prefix $prefix is in HOME_NET"
    else
        warn "IPv6 prefix $prefix is in use here but not in HOME_NET (re-run ./install.sh)"
    fi
done
if cmp -s "$SRC/drop.conf" /etc/suricata/drop.conf; then
    pass "drop.conf matches $SRC/drop.conf"
else
    warn "/etc/suricata/drop.conf differs from $SRC/drop.conf (re-run ./install.sh?)"
fi
grep -qx '  fail-open: no' "$CONF" && pass "NFQ fails closed under overload (fail-open: no)" \
    || warn "NFQ fail-open is not 'no': overload passes packets uninspected"
# Compare with the template, ignoring the lines install.sh fills in per machine
if diff -q <(grep -vE '^  - interface: |^    HOME_NET: ' "$SRC/suricata.yaml") \
           <(grep -vE '^  - interface: |^    HOME_NET: ' "$CONF") >/dev/null; then
    pass "suricata.yaml matches $SRC/suricata.yaml"
else
    warn "suricata.yaml differs from $SRC/suricata.yaml (local edits, or re-run ./install.sh)"
fi
want=$(grep -vE '^\s*(#|$)' "$SRC/rule-sources.conf" | sort)
have=$(suricata-update list-enabled-sources 2>/dev/null | sed -n 's/^  - //p' | sort)
if [[ $want == "$have" ]]; then
    pass "Rule sources enabled: $(echo $have)"
else
    warn "Enabled rule sources ($(echo $have)) don't match $SRC/rule-sources.conf ($(echo $want))"
fi
if [[ -f $RULES ]]; then
    total=$(grep -cE '^(alert|drop|reject|pass) ' "$RULES")
    drops=$(grep -c '^drop ' "$RULES")
    age=$(( ($(date +%s) - $(stat -c %Y "$RULES")) / 86400 ))
    info "$RULES: $total enabled rules, $drops set to drop, updated $age day(s) ago"
    [[ $drops -gt 0 ]] && pass "Drop rules are present" || warn "No drop rules: Suricata is only alerting"
    [[ $age -le 7 ]] && pass "Rules updated in the last week" || warn "Rules are $age days old (run suricata-update)"
else
    fail "Rules file $RULES not found"
fi
if [[ -f /etc/logrotate.d/suricata ]]; then
    cmp -s "$SRC/suricata.logrotate" /etc/logrotate.d/suricata \
        && pass "Logrotate config installed" || warn "/etc/logrotate.d/suricata differs from $SRC/suricata.logrotate"
else
    warn "No /etc/logrotate.d/suricata: logs will grow unbounded"
fi
if [[ $CONFIG_TEST -eq 1 ]]; then
    info "Running suricata -T (loads all rules)..."
    # -l to a temp dir so the test run doesn't append its own start-up lines to suricata.log
    tdir=$(mktemp -d)
    if out=$(suricata -T -c "$CONF" -l "$tdir" 2>&1); then pass "Configuration test passed"
    else fail "Configuration test failed:"; tail -10 <<<"$out" | sed 's/^/       /'; fi
    rm -rf "$tdir"
fi

section "Suricata log (since last start)"
if [[ -f $LOGDIR/suricata.log ]]; then
    # Only lines from the running process (suricata -T runs also log here, under their own PID)
    main_pid=$(systemctl show -p MainPID --value suricata.service)
    start_line=$(grep -n "^\[$main_pid - .*This is Suricata version" "$LOGDIR/suricata.log" | tail -1 | cut -d: -f1)
    [[ -n $start_line ]] || warn "Start-up of PID $main_pid not found in suricata.log (checking whole file)"
    errs=$(tail -n +"${start_line:-1}" "$LOGDIR/suricata.log" \
        | grep -E '^\[[^]]*\] [0-9-]+ [0-9:.]+ (Error|Warning|Critical|Alert|Emergency): ')
    if [[ -n $errs ]]; then
        warn "$(wc -l <<<"$errs") error/warning line(s):"
        tail -10 <<<"$errs" | sed 's/^/       /'
    else
        pass "No errors or warnings"
    fi
    grep -q 'Engine started' <(tail -n +"${start_line:-1}" "$LOGDIR/suricata.log") \
        && pass "Engine started" || fail "'Engine started' not logged since last start"
fi

section "Traffic and detection (eve.json)"
if [[ ! -s $EVE ]]; then
    fail "$EVE missing or empty"
else
    stale=$(( $(date +%s) - $(stat -c %Y "$EVE") ))
    [[ $stale -lt 120 ]] && pass "eve.json written ${stale}s ago" || fail "eve.json not written for ${stale}s"
    info "Size: $(du -h "$EVE" | cut -f1) (plus $(ls "$LOGDIR"/eve.json.* 2>/dev/null | wc -l) rotated file(s))"

    tail -n 200000 "$EVE" | python3 /dev/fd/3 3<<'PY'
import sys, json, collections

flows = both = v6 = 0
events = collections.Counter()
alerts = collections.Counter()
blocked = collections.Counter()
stats = None
for line in sys.stdin:
    try:
        e = json.loads(line)
    except ValueError:
        continue
    t = e.get("event_type")
    events[t] += 1
    if t == "stats":
        stats = e["stats"]
    elif t == "flow":
        if ":" in e.get("src_ip", ""):
            v6 += 1
        if e.get("proto") == "TCP":
            flows += 1
            f = e.get("flow", {})
            if f.get("pkts_toserver", 0) and f.get("pkts_toclient", 0):
                both += 1
    elif t == "alert":
        a = e["alert"]
        key = (a.get("signature_id"), a.get("signature"))
        (blocked if a.get("action") == "blocked" else alerts)[key] += 1

G, Y, R, N = ("\033[32m", "\033[33m", "\033[31m", "\033[0m") if sys.stdout.isatty() else ("",) * 4
def res(ok, msg, level="WARN"):
    tag = f"{G}PASS{N}" if ok else (f"{R}FAIL{N}" if level == "FAIL" else f"{Y}WARN{N}")
    print(f"  {tag} {msg}")
    return 0 if ok else (2 if level == "FAIL" else 1)
def info(msg):
    print(f"       {msg}")

worst = 0
info("Recent events: " + ", ".join(f"{k}={v}" for k, v in events.most_common(8)))
if flows:
    pct = 100 * both // flows
    worst = max(worst, res(pct >= 90, f"{pct}% of {flows} recent TCP flows seen in both directions",
                           "FAIL" if pct < 50 else "WARN"))
else:
    worst = max(worst, res(False, "No TCP flow records in recent eve.json", "FAIL"))
worst = max(worst, res(v6 > 0, f"{v6} recent IPv6 flows (any protocol) seen"))

if stats:
    ips = stats.get("ips", {})
    reasons = {k: v for k, v in ips.get("drop_reason", {}).items() if v}
    info(f"Since start ({stats.get('uptime', 0) // 60} min): accepted={ips.get('accepted', 0)} "
         f"blocked={ips.get('blocked', 0)} rejected={ips.get('rejected', 0)}")
    if reasons:
        info("Blocked by reason: " + ", ".join(f"{k}={v}" for k, v in sorted(reasons.items(), key=lambda x: -x[1])))
    worst = max(worst, res(ips.get("accepted", 0) > 0, "Suricata is issuing ACCEPT verdicts", "FAIL"))
    other = {k: v for k, v in reasons.items() if k not in ("rules", "stream_error")}
    if other:
        worst = max(worst, res(False, f"Packets dropped for engine reasons (not rules): {other}"))
    tcp, flow = stats.get("tcp", {}), stats.get("flow", {})
    memcap = {"tcp.ssn_memcap_drop": tcp.get("ssn_memcap_drop", 0),
              "tcp.segment_memcap_drop": tcp.get("segment_memcap_drop", 0),
              "flow.memcap": flow.get("memcap", 0)}
    hit = {k: v for k, v in memcap.items() if v}
    worst = max(worst, res(not hit, "No memcap exhaustion" if not hit else f"Memcap hits: {hit}"))
else:
    worst = max(worst, res(False, "No stats events in eve.json (is the stats output enabled?)"))

if blocked:
    print(f"  {Y}NOTE{N} Rule-based blocks in recent log (check these are not legitimate traffic):")
    for (sid, sig), n in blocked.most_common(10):
        info(f"{n:6}  [{sid}] {sig}")
else:
    info("No rule-based blocks in recent log")
if alerts:
    info("Top alerts (not blocked):")
    for (sid, sig), n in alerts.most_common(8):
        info(f"{n:6}  [{sid}] {sig}")
sys.exit(worst)
PY
    case $? in
        0) ;;
        1) WARN=$((WARN + 1)) ;;
        *) FAIL=$((FAIL + 1)) ;;
    esac
fi

if [[ $LIVE -eq 1 ]]; then
    section "Live detection test"
    # SID 2013504 alerts (never drops) on an outbound HTTP User-Agent containing "APT-HTTP/"
    marker=$(date +%Y-%m-%dT%H:%M:%S)  # eve.json timestamps are local time
    if curl -s -m 10 -o /dev/null -A 'APT-HTTP/1.3 (suricata check.sh)' http://archive.ubuntu.com/ubuntu/; then
        sleep 5
        if tail -n 20000 "$EVE" | grep '"event_type":"alert"' | grep '"signature_id":2013504' \
            | grep -o '"timestamp":"[^"]*"' | cut -d'"' -f4 | awk -v m="$marker" '$0 >= m' | grep -q .; then
            pass "Test request triggered SID 2013504"
        else
            fail "Test request did NOT trigger SID 2013504 (traffic isn't being inspected)"
        fi
    else
        warn "Could not reach archive.ubuntu.com, so the live test was skipped"
    fi
fi

section "Summary"
echo "  ${G}$PASS passed${N}, ${Y}$WARN warning(s)${N}, ${R}$FAIL failure(s)${N}"
[[ $FAIL -eq 0 ]] || exit 1
