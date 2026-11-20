#!/bin/bash
# Smoke test for analyse.py and the --json shape that watch/files/ips-watch reads. It builds a
# small synthetic log directory in a temp dir and never touches /var/log/suricata.
#
# Run with: tests/analyse-smoke.sh        (no root; exit status 0 = every check passed)
set -uo pipefail

ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
AN="$ROOT/suricata/analyse.py"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

PASS=0 FAIL=0
ok() { echo "  PASS $*"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL $*"; FAIL=$((FAIL + 1)); }
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi; }

# Synthetic logs: timestamps are relative to now so the test does not age out of its window.
# good/ is complete, trunc/ has its newest line cut off, empty/ has an empty eve.json.
python3 -I - "$WORK" <<'PY' || { echo "Cannot build the synthetic logs"; exit 1; }
import json, os, sys, time
from datetime import datetime, timezone

work = sys.argv[1]

def ts(ago):
    return datetime.fromtimestamp(time.time() - ago).astimezone().strftime('%Y-%m-%dT%H:%M:%S.%f%z')

def rec(ago, etype, **kw):
    return json.dumps({'timestamp': ts(ago), 'event_type': etype, **kw}, separators=(',', ':'))

def stats(ago, uptime, pkts):
    return rec(ago, 'stats', stats={'uptime': uptime, 'decoder': {'pkts': pkts, 'bytes': pkts * 100},
                                    'detect': {'alert': 2}, 'tcp': {'memcap': 0}})

def alert(ago, action, sid):
    return rec(ago, 'alert', src_ip='192.168.1.10', src_port=51000, dest_ip='203.0.113.7', dest_port=80,
               proto='TCP', flow_id=1000 + sid,
               alert={'action': action, 'gid': 1, 'signature_id': sid, 'rev': 1,
                      'signature': f'ET MALWARE Test Signature {sid}', 'category': 'Malware', 'severity': 1})

lines = [
    stats(240, 1000, 1000),
    alert(200, 'blocked', 2000001),
    alert(150, 'allowed', 2000002),
    rec(120, 'flow', src_ip='192.168.1.10', src_port=51000, dest_ip='203.0.113.7', dest_port=80, proto='TCP',
        flow_id=1001, flow={'pkts_toserver': 5, 'pkts_toclient': 4, 'bytes_toserver': 500, 'bytes_toclient': 900,
                            'start': ts(130)}),
    rec(100, 'dns', src_ip='192.168.1.10', src_port=40000, dest_ip='192.168.1.1', dest_port=53, proto='UDP',
        dns={'type': 'answer', 'id': 1, 'rrname': 'example.com', 'rrtype': 'A', 'rcode': 'NOERROR',
             'rdata': '203.0.113.7'}),
    stats(30, 1210, 5000),
    stats(5, 1235, 6000),
]
for name, body, tail in (('good', lines, ''), ('trunc', lines, '{"timestamp":"' + ts(1)[:17]), ('empty', [], '')):
    d = os.path.join(work, name)
    os.makedirs(d)
    with open(os.path.join(d, 'eve.json'), 'w') as f:
        f.write(''.join(l + '\n' for l in body) + tail)
# tls/: one certificate that ran out two hours ago and one with two hours left. Suricata writes
# these dates in UTC with no offset, so the answer must not depend on the machine's time zone.
def cert(ago, dest, hours_left):
    notafter = datetime.fromtimestamp(time.time() + hours_left * 3600, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
    return rec(ago, 'tls', src_ip='192.168.1.10', src_port=52000, dest_ip=dest, dest_port=443, proto='TCP',
               tls={'version': 'TLS 1.3', 'sni': 'tls.example', 'subject': 'CN=tls.example', 'issuerdn': 'CN=Some CA',
                    'notbefore': '2020-01-01T00:00:00', 'notafter': notafter})
os.makedirs(os.path.join(work, 'tls'))
with open(os.path.join(work, 'tls', 'eve.json'), 'w') as f:
    f.write(''.join(l + '\n' for l in [stats(240, 1000, 1000), cert(100, '203.0.113.8', 2), cert(90, '203.0.113.9', -2),
                                       stats(5, 1235, 6000)]))
os.makedirs(os.path.join(work, 'nolog'))
with open(os.path.join(work, 'suricata.yaml'), 'w') as f:
    f.write('vars:\n  address-groups:\n    HOME_NET: "[192.168.0.0/16,10.0.0.0/8]"\n')
PY

# run NAME DIR args... : stdout to $WORK/NAME.out, stderr to NAME.err, exit status in $RC
run() {
    local name=$1 dir=$2; shift 2
    python3 -B "$AN" --log-dir "$dir" --config "$WORK/suricata.yaml" --no-color "$@" \
        >"$WORK/$name.out" 2>"$WORK/$name.err"
    RC=$?
}
# in_range RC LOW HIGH
in_range() { [[ $1 -ge $2 && $1 -le $3 ]]; }
# jcheck FILE 'python expression on r' : the JSON file parses and the expression holds
jcheck() { python3 -I - "$1" "$2" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
sys.exit(0 if eval(sys.argv[2]) else 1)
PY
}

echo "analyse.py --json on a complete log"
run good "$WORK/good" --minutes 5 --json
check "exit status is 0, 1 or 2 (got $RC)" in_range "$RC" 0 2
check "output parses and has risk, findings, health, window, counts" \
    jcheck "$WORK/good.out" "all(k in r for k in ('risk', 'findings', 'health', 'window', 'counts'))"
check "risk is a severity name" \
    jcheck "$WORK/good.out" "r['risk'] in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')"
check "every finding has severity, title and details (list)" \
    jcheck "$WORK/good.out" "all(isinstance(f['severity'], str) and isinstance(f['title'], str) and isinstance(f['details'], list) for f in r['findings'])"
# ips-watch tells "the same finding again" by this; the count in an alert's title must not be in it
check "every finding has a key, and an alert's key carries no count" \
    jcheck "$WORK/good.out" "all(isinstance(f['key'], str) and f['key'] for f in r['findings']) and all('(x' not in f['key'] for f in r['findings'] if f['category'] == 'alert')"
check "the allowed alert shows up as a finding" \
    jcheck "$WORK/good.out" "any('2000002' in f['title'] for f in r['findings'])"
check "the blocked alert shows up as a finding" \
    jcheck "$WORK/good.out" "any('2000001' in f['title'] and 'blocked' in f['title'] for f in r['findings'])"
check "an allowed severity-1 alert makes the risk HIGH and the exit status 2" \
    bash -c "[[ $RC -eq 2 ]] && grep -q '\"risk\": \"HIGH\"' '$WORK/good.out'"
check "alert, flow, dns and stats events were counted" \
    jcheck "$WORK/good.out" "all(r['counts'].get(k, 0) >= 1 for k in ('alert', 'flow', 'dns', 'stats'))"

echo "analyse.py text report"
run text "$WORK/good" --minutes 5
check "exit status is 0, 1 or 2 (got $RC)" in_range "$RC" 0 2
check "report has the Findings section" grep -q '== Findings ==' "$WORK/text.out"

echo "--end latest with a truncated newest line"
run trunc "$WORK/trunc" --minutes 5 --end latest --json
check "exit status is 0, 1 or 2 (got $RC)" in_range "$RC" 0 2
check "output parses and has findings" jcheck "$WORK/trunc.out" "'findings' in r and 'risk' in r"
run truncnow "$WORK/trunc" --minutes 5 --json
check "default --end now also copes (exit status $RC)" in_range "$RC" 0 2

echo "certificate dates are UTC, whatever the machine's time zone"
for tz in UTC-5 UTC+5; do
    TZ=$tz run tls "$WORK/tls" --json
    check "TZ=$tz: one of the two certificates is expired, not both or neither" \
        jcheck "$WORK/tls.out" "[f['title'] for f in r['findings'] if 'expired' in f['title']] == ['1 TLS session(s) to servers with expired certificates']"
done

echo "missing or empty logs"
run missing "$WORK/does-not-exist" --json
check "missing log directory: exit status 3 (got $RC)" test "$RC" -eq 3
run nolog "$WORK/nolog" --json
check "directory without eve.json: exit status 3 (got $RC)" test "$RC" -eq 3
check "nothing but an error on stderr for the missing case" test -s "$WORK/nolog.err"
run emptylatest "$WORK/empty" --end latest --json
check "empty eve.json with --end latest: exit status 3 (got $RC)" test "$RC" -eq 3
# A sensor that logs nothing must not read as healthy
run emptynow "$WORK/empty" --json
check "empty eve.json, window ending now: exit status 2 (got $RC)" test "$RC" -eq 2
check "empty eve.json, window ending now: a HIGH finding says there are no records" \
    jcheck "$WORK/emptynow.out" "any(f['severity'] == 'HIGH' and 'no records' in f['title'] for f in r['findings'])"

echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
