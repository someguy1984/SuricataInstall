#!/bin/bash
# Smoke test for the alerting in watch/files/: ips-watch (its embedded activity de-duplication
# and its health state machine) and tetragon-notify.py --print. Everything runs against
# extracted parts or copies in a temp dir, with check scripts, systemctl, iptables, dig, ip and
# the notifier replaced by stubs, so nothing is notified, logged or changed on this machine.
#
#   A  the Python embedded in ips-watch (extracted at run time): de-duplication by "key",
#      severity levels, repeat window, bad input
#   B  the health state machine of a rewritten copy of ips-watch (needs root; skipped without)
#   C  tetragon-notify.py --print: summary lines, ignore list, malformed input
#
# Run with: sudo tests/watch-smoke.sh        (exit status 0 = every check passed)
# IPS_WATCH=path runs parts A and B against another copy of ips-watch (to prove the test can fail).
set -uo pipefail

ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
WATCH="${IPS_WATCH:-$ROOT/watch/files/ips-watch}"
TETRA="$ROOT/watch/files/tetragon-notify.py"

WORK=$(mktemp -d /var/tmp/watch-smoke.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

PASS=0 FAIL=0
ok() { echo "  PASS $*"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL $*"; FAIL=$((FAIL + 1)); }
# expect "description" ACTUAL EXPECTED
expect() { if [[ $2 == "$3" ]]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }
# contains "description" HAYSTACK NEEDLE
contains() { if [[ $2 == *"$3"* ]]; then ok "$1"; else bad "$1 (no '$3' in '$2')"; fi; }
lacks() { if [[ $2 != *"$3"* ]]; then ok "$1"; else bad "$1 ('$3' found in '$2')"; fi; }
die() { echo "  FAIL $*"; exit 1; }

[[ -r $WATCH ]] || die "cannot read $WATCH"
[[ -r $TETRA ]] || die "cannot read $TETRA"

# A stub notifier: one line per call, "LEVEL|TITLE|BODY" with the body's line breaks as "/"
mkdir -p "$WORK/bin"
cat > "$WORK/notify" <<'EOF'
#!/bin/bash
printf '%s|%s|%s\n' "$1" "$2" "$(printf '%s' "${3:-}" | tr '\n' '/')" >> "${NOTIFY_LOG:?}"
EOF
chmod +x "$WORK/notify"

# ---------------------------------------------------------------------------------------
echo "== ips-watch: embedded Python (activity de-duplication)"
PY="$WORK/embedded.py"
awk '
    found && $0 == "'\''" { exit }
    found { print }
    !found && index($0, "python3 -I -c '\''") { found = 1 }
' "$WATCH" > "$PY"
if [[ ! -s $PY ]]; then
    bad "extracting the embedded Python from $WATCH found nothing"
else
    ok "extracted the embedded Python ($(wc -l < "$PY") lines)"
    if python3 -B -I -c 'import sys; compile(open(sys.argv[1]).read(), "embedded", "exec")' "$PY" 2>"$WORK/compile.err"; then
        ok "it compiles"
    else
        bad "it compiles: $(tail -1 "$WORK/compile.err")"
    fi

    export NOTIFY_LOG="$WORK/calls"
    SEEN="$WORK/seen"
    # run_py JSON  (uses NOTIFY_MIN_T, REPEAT_T; calls are in $NOTIFY_LOG, output in $OUT, status in $RC)
    NOTIFY_MIN_T=HIGH REPEAT_T=60
    run_py() {
        : > "$NOTIFY_LOG"
        OUT=$(printf '%s' "$1" | NOTIFY="$WORK/notify" NOTIFY_MIN="$NOTIFY_MIN_T" REPEAT_MIN="$REPEAT_T" SEEN="$SEEN" \
            python3 -B -I "$PY" 2>&1)
        RC=$?
        CALLS=$(cat "$NOTIFY_LOG")
        NCALLS=$(grep -c . "$NOTIFY_LOG")
    }
    fnd() { printf '{"severity":"%s","title":"%s","key":"%s","details":["detail of %s"]}' "$1" "$2" "$3" "$3"; }
    rep() { local IFS=,; printf '{"findings":[%s]}' "$*"; }

    rm -f "$SEEN"
    HIGH_F=$(fnd HIGH "Scan from 10.0.0.9 (x5)" scan:10.0.0.9)
    MED_F=$(fnd MEDIUM "DNS tunnel to evil.test (x3)" dns:evil.test)
    run_py "$(rep "$HIGH_F" "$MED_F")"
    expect "first HIGH+MEDIUM report notifies once" "$NCALLS" 1
    contains "  ...with level critical" "$CALLS" "critical|"
    contains "  ...naming the HIGH finding" "$CALLS" "[HIGH] Scan from 10.0.0.9 (x5)"
    contains "  ...naming the MEDIUM finding" "$CALLS" "[MEDIUM] DNS tunnel to evil.test (x3)"
    contains "  ...title counts them" "$CALLS" "2 new finding(s), worst HIGH"

    run_py "$(rep "$(fnd HIGH "Scan from 10.0.0.9 (x9)" scan:10.0.0.9)" "$(fnd MEDIUM "DNS tunnel to evil.test (x12)" dns:evil.test)")"
    expect "same keys with other counts: no notification" "$NCALLS" 0
    contains "  ...says nothing new" "$OUT" "nothing new"

    run_py "$(rep "$(fnd HIGH "Scan from 10.0.0.9 (x9)" scan:10.0.0.9)" "$(fnd HIGH "Beacon to 203.0.113.5" beacon:203.0.113.5)")"
    expect "a new key is reported while the others stay suppressed" "$NCALLS" 1
    contains "  ...it is the new one" "$CALLS" "Beacon to 203.0.113.5"
    lacks "  ...and not the old one" "$CALLS" "Scan from"
    contains "  ...counted as one" "$CALLS" "1 new finding(s)"

    # No "key" (older analyse.py): the title without its trailing (xN)
    rm -f "$SEEN"
    run_py '{"findings":[{"severity":"HIGH","title":"Old style finding (x2)"}]}'
    expect "finding without a key is reported" "$NCALLS" 1
    run_py '{"findings":[{"severity":"HIGH","title":"Old style finding (x7)"}]}'
    expect "no key: same title with another count is suppressed" "$NCALLS" 0
    run_py '{"findings":[{"severity":"HIGH","title":"Old style finding (x7) elsewhere"}]}'
    expect "no key: a different title is reported" "$NCALLS" 1

    rm -f "$SEEN"
    run_py "$(rep "$(fnd LOW "Minor" low:1)" "$(fnd INFO "Fyi" info:1)")"
    expect "only LOW/INFO findings: no notification" "$NCALLS" 0
    expect "  ...exit status 0" "$RC" 0

    rm -f "$SEEN"
    NOTIFY_MIN_T=HIGH
    run_py "$(rep "$(fnd MEDIUM "Odd DNS" dns:odd)")"
    contains "MEDIUM with NOTIFY_MIN=HIGH goes to the journal only (log)" "$CALLS" "log|"
    rm -f "$SEEN"
    NOTIFY_MIN_T=MEDIUM
    run_py "$(rep "$(fnd MEDIUM "Odd DNS" dns:odd)")"
    contains "MEDIUM with NOTIFY_MIN=MEDIUM is normal" "$CALLS" "normal|"
    NOTIFY_MIN_T=HIGH

    # Age: entries are "EPOCH KEY"; one older than REPEAT_MIN is reported again, a fresh one is not
    now=$(date +%s)
    printf '%s old:key\n%s fresh:key\n' "$((now - 7200))" "$((now - 60))" > "$SEEN"
    run_py "$(rep "$(fnd HIGH "Old (x1)" old:key)" "$(fnd HIGH "Fresh (x1)" fresh:key)")"
    expect "entry older than REPEAT_MIN is reported again (and a fresh one is not)" "$NCALLS" 1
    contains "  ...the old one" "$CALLS" "Old (x1)"
    lacks "  ...not the fresh one" "$CALLS" "Fresh"

    rm -f "$SEEN"
    run_py ''
    expect "empty input: exit 0" "$RC" 0
    expect "  ...no notification" "$NCALLS" 0
    run_py 'this is { not json'
    expect "invalid JSON: exit 0" "$RC" 0
    expect "  ...no notification" "$NCALLS" 0
fi

# ---------------------------------------------------------------------------------------
echo "== ips-watch: health state machine"
if [[ $EUID -ne 0 ]]; then
    echo "  SKIP part B needs root (ips-watch insists on it): run with sudo"
else
    B="$WORK/b"
    mkdir -p "$B/bin" "$B/suri" "$B/tetra" "$B/ctl" "$B/state"
    W="$B/ips-watch"
    cp "$WATCH" "$W"
    rewrite() {  # rewrite VAR VALUE: point one of the fixed paths at the temp dir
        sed -i "s|^$1=.*|$1=$2|" "$W"
        grep -qxF "$1=$2" "$W" || die "sed found no $1= assignment to rewrite in $WATCH"
    }
    rewrite CONF "$B/ips-watch.conf"
    rewrite STATE "$B/state"
    rewrite SURICATA_TOOLS "$B/suri"
    rewrite TETRAGON_TOOLS "$B/tetra"
    rewrite NOTIFY "$WORK/notify"
    printf 'REMIND_HOURS=6\nDNS_TEST_DOMAIN=test.invalid\n' > "$B/ips-watch.conf"

    # Stub check scripts: print $dir/out and exit with $dir/rc
    for d in suri tetra; do
        printf '#!/bin/bash\ncat "%s/out"\nexit "$(cat "%s/rc")"\n' "$B/$d" "$B/$d" > "$B/$d/check.sh"
        chmod +x "$B/$d/check.sh"
    done
    # Stub tools, steered by files in ctl/: dns_enabled, ctrld_active, chain_ok (present = yes)
    cat > "$B/bin/systemctl" <<EOF
#!/bin/bash
case "\$1" in
    is-enabled) [[ -e "$B/ctl/dns_enabled" ]] ;;
    is-active) [[ -e "$B/ctl/ctrld_active" ]] ;;
    *) exit 0 ;;
esac
EOF
    cat > "$B/bin/iptables" <<EOF
#!/bin/bash
[[ -e "$B/ctl/chain_ok" ]] && echo "-A OUTPUT -j DNSLOCK"
exit 0
EOF
    printf '#!/bin/bash\necho "203.0.113.1"\n' > "$B/bin/dig"
    printf '#!/bin/bash\n[[ "$1" == route ]] && echo "default via 192.0.2.1 dev eth0"\nexit 0\n' > "$B/bin/ip"
    chmod +x "$B/bin/"*

    set_suri() { printf '%s' "$2" > "$B/suri/out"; echo "$1" > "$B/suri/rc"; }
    set_tetra() { printf '%s' "$2" > "$B/tetra/out"; echo "$1" > "$B/tetra/rc"; }
    run_watch() {
        : > "$NOTIFY_LOG"
        OUT=$(cd "$B" && PATH="$B/bin:$PATH" bash "$W" 2>&1)
        RC=$?
        CALLS=$(cat "$NOTIFY_LOG")
        NCALLS=$(grep -c . "$NOTIFY_LOG")
    }
    export NOTIFY_LOG="$WORK/calls"
    set_suri 0 ""; set_tetra 0 ""

    run_watch
    expect "healthy first run: exit 0, no notification" "$RC/$NCALLS" "0/0"
    contains "  ...says no problems" "$OUT" "Health: no problems"

    set_suri 1 $'  PASS fine\n  FAIL Suricata is not running\n'
    run_watch
    expect "new problem: one notification" "$NCALLS" 1
    contains "  ...critical, one problem" "$CALLS" "critical|Security setup: 1 problem(s)|"
    contains "  ...naming it with the kit's label" "$CALLS" "Suricata: Suricata is not running"

    run_watch
    expect "unchanged problem: silent" "$NCALLS" 0
    contains "  ...still listed on stdout" "$OUT" "Suricata: Suricata is not running"

    set_suri 1 $'  FAIL Suricata is not running\n  FAIL rules are stale\n'
    run_watch
    expect "changed set of problems: notified again" "$NCALLS" 1
    contains "  ...critical with 2 problems" "$CALLS" "critical|Security setup: 2 problem(s)|"

    touch -d '2 hours ago' "$B/state/health"
    run_watch
    expect "unchanged, 2 h old (REMIND_HOURS=6): silent" "$NCALLS" 0
    touch -d '7 hours ago' "$B/state/health"
    run_watch
    expect "unchanged, 7 h old: a reminder" "$NCALLS" 1
    contains "  ...critical, 'still'" "$CALLS" "critical|Security setup: still 2 problem(s)|"
    run_watch
    expect "right after the reminder: silent again" "$NCALLS" 0

    set_suri 0 ""
    run_watch
    expect "problems cleared: one notification" "$NCALLS" 1
    contains "  ...normal, all clear" "$CALLS" "normal|Security setup: all clear|"
    run_watch
    expect "still clear: silent" "$NCALLS" 0

    set_suri 3 "boom"
    run_watch
    contains "check that fails without a FAIL line is a problem" "$CALLS" "its health check could not run (boom)"
    set_suri 0 ""; run_watch

    set_tetra 1 $'  FAIL policy not loaded\n'
    run_watch
    contains "Tetragon's FAIL line is reported with its label" "$CALLS" "Tetragon: policy not loaded"
    set_tetra 0 ""; run_watch

    touch "$B/ctl/dns_enabled" "$B/ctl/chain_ok"
    run_watch
    expect "DNS lockdown enabled, ctrld stopped: notified" "$NCALLS" 1
    contains "  ...says ctrld is not running" "$CALLS" "DNS: ctrld is not running"
    touch "$B/ctl/ctrld_active"
    run_watch
    contains "ctrld running, chain present, lookup answers: all clear" "$CALLS" "all clear"
    rm "$B/ctl/chain_ok"
    run_watch
    contains "DNSLOCK chain missing: notified" "$CALLS" "DNSLOCK firewall chain is missing"
    contains "  ...as critical" "$CALLS" "critical|"
    touch "$B/ctl/chain_ok"
    run_watch

    # ctrld can be running and still not answer
    printf '#!/bin/bash\n[[ -e "%s/ctl/dig_silent" ]] || echo "203.0.113.1"\n' "$B" > "$B/bin/dig"
    touch "$B/ctl/dig_silent"
    run_watch
    contains "ctrld running but a lookup gets no answer: notified" "$CALLS" "got no answer"
    rm "$B/ctl/dig_silent"
    run_watch
    contains "  ...and cleared when it answers again" "$CALLS" "all clear"

    # An analyser that cannot run is a health problem, not silence
    printf '#!/bin/bash\nexit 3\n' > "$B/suri/analyse.py"
    chmod +x "$B/suri/analyse.py"
    run_watch
    contains "analyse.py failing: reported as a health problem" "$CALLS" "analyse.py could not run (exit status 3)"
    printf '#!/bin/bash\necho "{\\"findings\\": []}"\n' > "$B/suri/analyse.py"
    run_watch
    contains "  ...cleared when it runs again" "$CALLS" "all clear"
    contains "  ...and the activity half then runs" "$OUT" "Activity: nothing new"
    rm "$B/suri/analyse.py"
fi

# ---------------------------------------------------------------------------------------
echo "== tetragon-notify.py --print"
T="$WORK/t"
mkdir -p "$T"
cat > "$T/ignore.conf" <<'EOF'
# a comment, then a blank line

^sensitive-files security_file_permission /usr/bin/cat /tmp/harmless
EOF
cat > "$T/events" <<'EOF'
{"process_kprobe":{"policy_name":"sensitive-files","function_name":"security_file_permission","process":{"binary":"/usr/bin/cat","pid":7,"uid":1000},"parent":{"binary":"/usr/bin/bash"},"args":[{"file_arg":{"path":"/home/j/.ssh/id_ed25519"}}]}}
not json at all
{"process_kprobe":{"policy_name":"sensitive-files","function_name":"security_file_permission","process":{"binary":"/usr/bin/cat"},"args":[{"file_arg":{"path":"/tmp/harmless"}}]}}
{"process_kprobe":5}
[1,2,3]
{"something_else":{}}
{"process_exec":{"process":{"binary":"/memfd:x","arguments":"-a"},"parent":{"binary":"/usr/bin/sh"}}}
EOF
# --print never notifies, but point --notify at the stub anyway
tetra() { python3 -B -I "$TETRA" --notify "$WORK/notify" "$@"; }
OUT=$(tetra --print --ignore "$T/ignore.conf" < "$T/events" 2>"$T/err"); RC=$?
expect "exit status 0 despite malformed lines" "$RC" 0
contains "non-matching event is shown, unmarked, with parent" "$OUT" "  sensitive-files security_file_permission /usr/bin/cat /home/j/.ssh/id_ed25519 <- /usr/bin/bash"
contains "event matching the ignore list is marked '- '" "$OUT" "- sensitive-files security_file_permission /usr/bin/cat /tmp/harmless"
contains "process_exec event is summarised as fileless-exec" "$OUT" "fileless-exec exec /memfd:x -a <- /usr/bin/sh"
expect "three summary lines (the junk produced none)" "$(grep -c . <<<"$OUT")" 3
contains "the unreadable event was reported on stderr, not fatal" "$(cat "$T/err")" "skipped an event"
OUT=$(tetra --print --ignore "$T/missing.conf" < "$T/events" 2>"$T/err"); RC=$?
expect "missing ignore file: exit 0, nothing marked as dropped" "$RC/$(grep -c '^- ' <<<"$OUT")" "0/0"
contains "  ...and it says so on stderr" "$(cat "$T/err")" "no ignore list"
printf '(unclosed\n^fileless-exec\n' > "$T/badre.conf"
OUT=$(tetra --print --ignore "$T/badre.conf" < "$T/events" 2>"$T/err"); RC=$?
contains "bad regex is skipped, the good line still applies" "$OUT" "- fileless-exec exec"
contains "  ...and the bad one is reported" "$(cat "$T/err")" "bad pattern ignored"
expect "  ...exit 0" "$RC" 0

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
