#!/bin/bash
# L1 tests of the server kit's two firewalls (hub PLAN section 12, client PLAN section 11): the hub's `inet edr_hub`
# (rendered by server_hub/files/render-nft.sh), the client's `inet edr` (server_client/files/edr-base.nft applied by
# server_client/agent/edr-bans) and `inet edr_dns` (rendered by server_client/agent/edr-dns-watch).
#
# Run with: sudo tests/server-netns.sh          (exit 0: no case failed; SKIP is not a failure)
#
# SAFETY. This runs as root on machines with a live firewall, so:
#  - Its first act is to re-exec itself inside a fresh network namespace and a private mount namespace (unshare -n -m).
#    Before ANY nft, helper or test command the inner copy proves that it is inside: it is in a different network
#    namespace from the one that started it, its only link is `lo`, and `nft list ruleset` is empty. If any of the three
#    fails it exits 2 and has done nothing.
#  - Every later command runs in that namespace or in child namespaces made from it (unshare -n, entered with nsenter by
#    process id: no `ip netns`, so nothing is written under /run). The namespaces vanish when the script ends.
#  - It never flushes a ruleset and never names a table of the host: tables are deleted one by one, by name, in the
#    throwaway namespaces only. The helpers run with --root <temp dir>. Nothing is written under /etc, /run or /var.
#
# Topology (all inside the throwaway namespace):   c1 ---- srv ---- c2
#   srv  198.51.100.1  2001:db8:1::1 (to c1)   198.51.101.1  2001:db8:2::1 (to c2): the firewalls load here
#   c1   198.51.100.2  2001:db8:1::2 and ::3 (same /64)      c2   198.51.101.2  2001:db8:2::2
# 198.51.100/24 and 198.51.101/24 are not in the never-ban literals (10/8, 192.168/16, ... are), so they can be banned.
set -uo pipefail

ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
SE=$ROOT/server_edr_solution
RENDER=$SE/server_hub/files/render-nft.sh
BANS=$SE/server_client/agent/edr-bans
DNSWATCH=$SE/server_client/agent/edr-dns-watch
CLIENT_FILES=$SE/server_client/files

# ---- Stage 0: get into a throwaway namespace ---------------------------------------------------------------
if [[ ${EDR_NETNS_INNER:-} != 1 ]]; then
    [[ $EUID -eq 0 ]] || { echo "Run as root (sudo $0)"; exit 1; }
    for tool in unshare nsenter ip nft python3 setpriv; do
        command -v "$tool" >/dev/null || { echo "server-netns.sh needs $tool"; exit 1; }
    done
    EDR_NETNS_OUTER=$(readlink /proc/self/ns/net) || exit 2
    export EDR_NETNS_OUTER
    exec env EDR_NETNS_INNER=1 unshare --net --mount --propagation private "$0" "$@"
fi

# ---- Stage 1: prove it, before anything else runs ----------------------------------------------------------
refuse() { echo "server-netns.sh: REFUSING TO RUN: $*" >&2; exit 2; }
inner=$(readlink /proc/self/ns/net) || refuse "cannot read the network namespace"
[[ -n ${EDR_NETNS_OUTER:-} && $inner != "$EDR_NETNS_OUTER" ]] || refuse "not in a new network namespace (run it without EDR_NETNS_INNER)"
links=$(ip -o link show 2>/dev/null | awk -F': ' '{ sub(/@.*/, "", $2); print $2 }')
[[ $links == lo ]] || refuse "the namespace has links other than lo: $(echo "$links" | tr '\n' ' ')"
rs=$(nft list ruleset 2>&1) || refuse "nft list ruleset failed: $rs"
[[ -z $rs ]] || refuse "the namespace already has a ruleset"

WORK=$(mktemp -d) || exit 2
chmod 755 "$WORK"     # the test uids (nobody, daemon) read probe.py from here
PIDS=()
cleanup() {
    local p
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

PASS=0 FAIL=0 SKIP=0
pass() { echo "  PASS $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP $*"; SKIP=$((SKIP + 1)); }
# check "what" command...  : PASS when the command succeeds
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi; }
# expect "what" VALUE WANT
expect() { if [[ $2 == "$3" ]]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi; }
section() { echo; echo "== $* =="; }
note() { echo "       $*"; }

# ---- Child namespaces, links, addresses --------------------------------------------------------------------
declare -A NSPID
spawn_ns() {   # spawn_ns NAME
    local pid
    unshare --net sleep 100000 &
    pid=$!
    PIDS+=("$pid")
    local i
    for i in $(seq 100); do
        [[ $(readlink "/proc/$pid/ns/net" 2>/dev/null) != "$inner" && -e /proc/$pid/ns/net ]] && break
        sleep 0.05
    done
    [[ $(readlink "/proc/$pid/ns/net") != "$inner" ]] || refuse "a child namespace was not created"
    NSPID[$1]=$pid
}
nsx() { local n=$1; shift; nsenter --net="/proc/${NSPID[$n]}/ns/net" "$@"; }

for n in srv c1 c2; do spawn_ns "$n"; nsx "$n" ip link set lo up; done
ip link add vs1 type veth peer name vc1 && ip link add vs2 type veth peer name vc2 || refuse "cannot create veth pairs"
ip link set vs1 netns "${NSPID[srv]}"; ip link set vs2 netns "${NSPID[srv]}"
ip link set vc1 netns "${NSPID[c1]}"; ip link set vc2 netns "${NSPID[c2]}"
nsx srv ip addr add 198.51.100.1/24 dev vs1; nsx srv ip addr add 198.51.101.1/24 dev vs2
nsx c1 ip addr add 198.51.100.2/24 dev vc1; nsx c1 ip addr add 198.51.100.3/24 dev vc1
nsx c2 ip addr add 198.51.101.2/24 dev vc2
V6=1
if nsx srv ip -6 addr add 2001:db8:1::1/64 dev vs1 nodad 2>/dev/null; then
    nsx srv ip -6 addr add 2001:db8:2::1/64 dev vs2 nodad
    nsx c1 ip -6 addr add 2001:db8:1::2/64 dev vc1 nodad; nsx c1 ip -6 addr add 2001:db8:1::3/64 dev vc1 nodad
    nsx c2 ip -6 addr add 2001:db8:2::2/64 dev vc2 nodad
else
    V6=0
fi
for l in vs1 vs2; do nsx srv ip link set "$l" up; done
nsx c1 ip link set vc1 up; nsx c2 ip link set vc2 up
sleep 0.5
if ! nsx c1 ping -c1 -W2 198.51.100.1 >/dev/null 2>&1; then refuse "the test network does not work (c1 cannot reach srv)"; fi
[[ $V6 -eq 0 ]] || nsx c1 ping -6 -c1 -W2 2001:db8:1::1 >/dev/null 2>&1 || V6=0

# ---- Traffic helper ----------------------------------------------------------------------------------------
cat > "$WORK/probe.py" <<'PY'
import errno, selectors, socket, sys, time

def fam(host):
    return socket.AF_INET6 if ":" in host else socket.AF_INET

def tcp(host, port, timeout, src=None):
    s = socket.socket(fam(host))
    s.settimeout(timeout)
    try:
        if src:
            s.bind((src, 0))
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()

def udp(host, port, timeout, src=None):
    s = socket.socket(fam(host), socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        if src:
            s.bind((src, 0))
        s.connect((host, port))
        s.send(b"q")
        s.recv(64)
        return True
    except OSError:
        return False
    finally:
        s.close()

def burst(host, port, count, interval, timeout, src=None):
    """count connection attempts, one every `interval` seconds, none waiting for another."""
    sel = selectors.DefaultSelector()
    ok = bad = started = 0
    t0 = time.monotonic()
    live = {}
    while started < count or live:
        now = time.monotonic()
        while started < count and now >= t0 + started * interval:
            s = socket.socket(fam(host))
            s.setblocking(False)
            if src:
                s.bind((src, 0))
            e = s.connect_ex((host, port))
            if e not in (0, errno.EINPROGRESS):
                bad += 1
                s.close()
            else:
                sel.register(s, selectors.EVENT_WRITE)
                live[s] = now + timeout
            started += 1
        for key, _ in sel.select(0.01):
            s = key.fileobj
            if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                ok += 1
            else:
                bad += 1
            sel.unregister(s); s.close(); live.pop(s, None)
        now = time.monotonic()
        for s, dl in list(live.items()):
            if now >= dl:
                bad += 1
                sel.unregister(s); s.close(); del live[s]
    print("ok=%d fail=%d" % (ok, bad))

def listen(kind, ports):
    sel = selectors.DefaultSelector()
    for p in ports:
        for f, a in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
            s = socket.socket(f, socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if f == socket.AF_INET6:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                s.bind((a, int(p)))
            except OSError:
                s.close()
                continue
            if kind == "tcp":
                s.listen(128)
            s.setblocking(False)
            sel.register(s, selectors.EVENT_READ)
    print("listening", flush=True)
    while True:
        for key, _ in sel.select(1):
            s = key.fileobj
            if kind == "tcp":
                try:
                    c, _a = s.accept()
                    c.close()
                except OSError:
                    pass
            else:
                try:
                    d, a = s.recvfrom(64)
                    s.sendto(d, a)
                except OSError:
                    pass

cmd = sys.argv[1]
if cmd in ("tcp", "udp"):
    host, port, timeout = sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
    src = sys.argv[5] if len(sys.argv) > 5 else None
    sys.exit(0 if (tcp if cmd == "tcp" else udp)(host, port, timeout, src) else 1)
elif cmd == "burst":
    burst(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5]), float(sys.argv[6]), sys.argv[7] if len(sys.argv) > 7 else None)
elif cmd == "listen":
    listen(sys.argv[2], sys.argv[3:])
PY
PROBE="$WORK/probe.py"
chmod 644 "$PROBE"

LISTENERS=()
listen_in() {   # listen_in NS USERSPEC KIND PORT... : a listener in a namespace, as root or as a uid (setpriv); remembered for stop_listeners
    local n=$1 user=$2 kind=$3; shift 3
    local pre=()
    [[ $user == root ]] || pre=(setpriv --reuid "$user" --regid "$user" --clear-groups)
    nsx "$n" "${pre[@]}" python3 -I "$PROBE" listen "$kind" "$@" >"$WORK/listen.$$.$RANDOM" 2>&1 &
    local pid=$!
    PIDS+=("$pid"); LISTENERS+=("$pid")
    sleep 0.4
}
stop_listeners() {
    local p
    for p in "${LISTENERS[@]}"; do kill "$p" 2>/dev/null; done
    # wait for these only: a bare wait would also wait for the namespaces' sleep processes
    for p in "${LISTENERS[@]}"; do wait "$p" 2>/dev/null; done
    LISTENERS=()
}

reach() {   # reach NS KIND HOST PORT [TIMEOUT] [SRC] : succeeds when the connection works (or the UDP echo comes back)
    local n=$1 kind=$2 host=$3 port=$4 to=${5:-1} src=${6:-}
    nsx "$n" python3 -I "$PROBE" "$kind" "$host" "$port" "$to" ${src:+"$src"}
}
reaches() { if reach "$@"; then pass "$WHAT: reachable"; else fail "$WHAT: expected to be reachable"; fi; }
blocked() { if reach "$@"; then fail "$WHAT: expected to be blocked"; else pass "$WHAT: blocked"; fi; }
# case NAME : sets WHAT for reaches/blocked
case_() { WHAT=$1; }
burst() { nsx "$1" python3 -I "$PROBE" burst "${@:2}"; }   # burst NS HOST PORT COUNT INTERVAL TIMEOUT [SRC] -> "ok=N fail=M"
okcount() { sed -n 's/^ok=\([0-9]*\) .*/\1/p' <<<"$1"; }

tables() { nsx srv nft list tables; }
ntables() { tables | grep -c .; }
set_elems() {   # set_elems TABLE SET : one element per line, as nft prints them
    nsx srv nft -j list set inet "$1" "$2" 2>/dev/null | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
for item in d.get("nftables", []):
    s = item.get("set")
    for e in (s or {}).get("elem", []):
        if isinstance(e, dict) and "elem" in e:
            e = e["elem"]["val"]
        if isinstance(e, dict) and "prefix" in e:
            e = "%s/%s" % (e["prefix"]["addr"], e["prefix"]["len"])
        print(e)
'
}
drop_tables() { local t; for t in "$@"; do nsx srv nft delete table inet "$t" 2>/dev/null; done; return 0; }

TCPPORTS=(18443 18444 18022 18999)

###########################################################################################################
section "Hub: inet edr_hub (render-nft.sh)"
###########################################################################################################
listen_in srv root tcp "${TCPPORTS[@]}"
listen_in c1 root tcp 19001
NOBODY=$(id -u nobody 2>/dev/null || echo "")
render_hub() { bash "$RENDER" --port 18443 --enroll-port 18444 --ssh-port 18022 --hub-user nobody "$@" > "$WORK/hub.nft"; }
load_hub() { nsx srv nft -c -f "$WORK/hub.nft" && nsx srv nft -f "$WORK/hub.nft"; }

render_hub --admin4 198.51.100.2 --admin6 2001:db8:1::2 || fail "render-nft.sh failed"
case_ "before the table: a port with no rule is open (control)"; reaches c2 tcp 198.51.101.1 18999
check "the rendered file loads" load_hub
load_hub >/dev/null 2>&1
expect "loading it twice leaves one table" "$(tables | grep -c 'inet edr_hub')" 1
expect "loading it twice leaves one input chain" "$(nsx srv nft list table inet edr_hub | grep -c 'chain input')" 1
listing=$(nsx srv nft list table inet edr_hub)
if grep -q 'policy drop' <<<"$listing"; then pass "the input chain has policy drop"; else fail "the input chain has no drop policy"; fi

case_ "input policy drop: a port with no rule, from c1"; blocked c1 tcp 198.51.100.1 18999
case_ "input policy drop: a port with no rule, from c2"; blocked c2 tcp 198.51.101.1 18999
case_ "fleet port 18443 from c2 (no admin needed)"; reaches c2 tcp 198.51.101.1 18443
case_ "enrollment port 18444 from c2"; reaches c2 tcp 198.51.101.1 18444
case_ "SSH port from the admin address (IPv4)"; reaches c1 tcp 198.51.100.1 18022
case_ "SSH port from a non-admin address (IPv4)"; blocked c2 tcp 198.51.101.1 18022
if [[ $V6 -eq 1 ]]; then
    case_ "SSH port from the admin address (IPv6 ::2)"; reaches c1 tcp 2001:db8:1::1 18022 1 2001:db8:1::2
    case_ "SSH port from another address of the same /64 (IPv6 ::3, not listed)"; blocked c1 tcp 2001:db8:1::1 18022 1 2001:db8:1::3
    case_ "SSH port from a non-admin IPv6 source"; blocked c2 tcp 2001:db8:2::1 18022
else
    skip "IPv6 admin cases (no IPv6 in the test namespaces on this machine)"
fi
check "ICMP echo is answered (rate limited, not dropped)" nsx c2 ping -c1 -W2 198.51.101.1

# No admin address: SSH is open to everyone
render_hub || fail "render without an admin failed"
load_hub >/dev/null 2>&1
case_ "no admin: SSH from c1"; reaches c1 tcp 198.51.100.1 18022
case_ "no admin: SSH from c2"; reaches c2 tcp 198.51.101.1 18022
case_ "no admin: a port with no rule is still closed"; blocked c2 tcp 198.51.101.1 18999
render_hub --admin4 198.51.100.2 --admin6 2001:db8:1::2; load_hub >/dev/null 2>&1

# The per-source SYN meter: about 5 a second, burst 10. 60 attempts at 10 a second leave about 10 + 5 x 6 = 40.
sleep 3
out=$(burst c1 198.51.100.1 18443 60 0.1 0.5); ok=$(okcount "$out")
if [[ $ok -ge 25 && $ok -le 50 ]]; then pass "SYN meter, fleet port: 60 attempts at 10/s from one source, $out (some dropped)"; else fail "SYN meter, fleet port: $out (expected 25 to 50 connections)"; fi
out2=$(burst c2 198.51.101.1 18443 10 0.2 1); expect "SYN meter: a second source is unaffected ($out2)" "$(okcount "$out2")" 10
sleep 4
out=$(burst c1 198.51.100.1 18444 60 0.1 0.5); ok=$(okcount "$out")
if [[ $ok -ge 25 && $ok -le 50 ]]; then pass "SYN meter, enrollment port: $out (some dropped)"; else fail "SYN meter, enrollment port: $out (expected 25 to 50 connections)"; fi
check "SYN meter: counters show the drops" bash -c "nsx() { nsenter --net=/proc/${NSPID[srv]}/ns/net \"\$@\"; }; nsx nft list table inet edr_hub | grep -E 'counter packets [1-9]'"
sleep 4
if [[ $V6 -eq 1 ]]; then
    out=$(burst c1 2001:db8:1::1 18443 60 0.1 0.5 2001:db8:1::2); ok=$(okcount "$out")
    if [[ $ok -ge 25 && $ok -le 50 ]]; then pass "SYN meter, IPv6: $out (some dropped)"; else fail "SYN meter, IPv6: $out (expected 25 to 50 connections)"; fi
    out3=$(burst c1 2001:db8:1::1 18443 8 0.02 0.5 2001:db8:1::3)
    if [[ $(okcount "$out3") -le 3 ]]; then pass "SYN meter, IPv6 is keyed by /64: another address of the same /64 is held back too ($out3)"; else fail "SYN meter, IPv6 /64: a second address of the same /64 got through ($out3)"; fi
    out4=$(burst c2 2001:db8:2::1 18443 10 0.2 1); expect "SYN meter, IPv6: a different /64 is unaffected ($out4)" "$(okcount "$out4")" 10
else
    skip "IPv6 SYN meter cases (no IPv6 in the test namespaces on this machine)"
fi

# The ingest user can take an inbound connection but cannot start an outbound one
stop_listeners
if [[ -z $NOBODY ]]; then
    skip "meta skuid cases (no user 'nobody' here)"
else
    sleep 5
    listen_in srv "$NOBODY" tcp 18443
    listen_in c1 root tcp 19001
    case_ "skuid: a service running as the test uid accepts an inbound connection"; reaches c2 tcp 198.51.101.1 18443
    case_ "skuid: the test uid cannot start an outbound connection"
    if nsx srv setpriv --reuid "$NOBODY" --regid "$NOBODY" --clear-groups python3 -I "$PROBE" tcp 198.51.100.2 19001 1; then fail "$WHAT: it connected"; else pass "$WHAT: dropped"; fi
    case_ "skuid control: root in the same namespace can start the same outbound connection"; reaches srv tcp 198.51.100.2 19001
    stop_listeners
fi
drop_tables edr_hub
expect "deleting the table leaves no kit table" "$(ntables)" 0

###########################################################################################################
section "Client: inet edr (edr-base.nft applied by edr-bans)"
###########################################################################################################
CL=$WORK/cl
listen_in srv root tcp 18080
C1=198.51.100.2 C2=198.51.101.2
bans_run() { nsx srv python3 -I "$BANS" --root "$CL" --files-dir "$CLIENT_FILES" 2>&1; }
client_reset() { drop_tables edr; rm -rf "$CL"; mkdir -p "$CL/run/edr-agent" "$CL/etc/edr-agent"; }
bans_write() { printf '%s' "$1" > "$CL/run/edr-agent/bans.json.tmp" && mv "$CL/run/edr-agent/bans.json.tmp" "$CL/run/edr-agent/bans.json"; }
now() { date +%s; }
ban() { printf '{"cidr":"%s","expires":%d,"source":"%s","reason":"%s"}' "$1" $(($(now) + ${3:-3600})) "${2:-local}" "$([[ ${2:-local} == local ]] && echo ssh_fail || echo fleet_quorum)"; }
doc() {   # doc NEVER_JSON_LIST BAN...
    local never=$1 bans=""; shift
    local b; for b in "$@"; do bans+="${bans:+,}$b"; done
    printf '{"v":1,"written_at":%d,"empty":false,"never":%s,"bans":[%s],"feeds":{}}' "$(now)" "$never" "$bans"
}
empty_doc() { printf '{"v":1,"written_at":%d,"empty":true,"never":[],"bans":[],"feeds":{}}' "$(now)"; }
apply() { local out; out=$(bans_run); local rc=$?; [[ $rc -eq 0 ]] || note "edr-bans exit $rc: $out"; return $rc; }
counters() { python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(json.dumps(d))' "$CL/run/edr-bans/counters.json"; }

client_reset; bans_write "$(doc '[]' "$(ban $C1/32)")"
check "edr-bans applies a ban" apply
check "the table inet edr exists" bash -c "nsenter --net=/proc/${NSPID[srv]}/ns/net nft list table inet edr"
case_ "a banned source (IPv4 /32) is dropped"; blocked c1 tcp 198.51.100.1 18080
case_ "another source is not"; reaches c2 tcp 198.51.101.1 18080
case_ "the banned source's other address (198.51.100.3) is not banned"; reaches c1 tcp 198.51.100.1 18080 1 198.51.100.3

# never-ban first, in the kernel, even when a ban covers the address (loaded by hand: edr-bans refuses such a ban, below)
client_reset; apply
nsx srv nft add element inet edr edr_ban4 '{ 198.51.100.0/24 timeout 1h }'
nsx srv nft add element inet edr edr_never4 '{ 198.51.100.2 }'
case_ "kernel: an address in a banned /24 is dropped"; blocked c1 tcp 198.51.100.1 18080 1 198.51.100.3
case_ "kernel: the never-ban address inside that /24 is not dropped"; reaches c1 tcp 198.51.100.1 18080 1 198.51.100.2
# and edr-bans itself refuses a ban that overlaps the never-ban list
client_reset; bans_write "$(doc '["198.51.100.2/32"]' "$(ban 198.51.100.0/24)")"; apply
expect "edr-bans refuses a ban that covers a never-ban address" "$(set_elems edr edr_ban4 | wc -l)" 0
grep -q 'overlaps the never-ban list' "$CL/run/edr-bans/counters.json" && pass "the refusal is reported in counters.json" || fail "no refusal in counters.json"
case_ "the never-ban source is reachable"; reaches c1 tcp 198.51.100.1 18080
client_reset; bans_write "$(doc '[]' "$(ban 192.168.0.0/16)" "$(ban 10.1.0.0/16)")"; apply
expect "edr-bans refuses bans that sit inside the compiled-in literals (10/8, 192.168/16)" "$(set_elems edr edr_ban4 | wc -l)" 0

# IPv6
if [[ $V6 -eq 1 ]]; then
    client_reset; bans_write "$(doc '[]' "$(ban 2001:db8:1::/64)")"; apply
    case_ "IPv6: a banned /64 is dropped (::2)"; blocked c1 tcp 2001:db8:1::1 18080 1 2001:db8:1::2
    case_ "IPv6: a banned /64 is dropped (::3)"; blocked c1 tcp 2001:db8:1::1 18080 1 2001:db8:1::3
    case_ "IPv6: another /64 is not"; reaches c2 tcp 2001:db8:2::1 18080
    case_ "IPv6 ban leaves the same host's IPv4 alone"; reaches c1 tcp 198.51.100.1 18080
    nsx srv nft add element inet edr edr_never6 '{ 2001:db8:1::2 }'
    case_ "IPv6 kernel: the never-ban address inside a banned /64 is not dropped"; reaches c1 tcp 2001:db8:1::1 18080 1 2001:db8:1::2
    case_ "IPv6 kernel: its neighbour in the same /64 still is"; blocked c1 tcp 2001:db8:1::1 18080 1 2001:db8:1::3
    client_reset; bans_write "$(doc '[]' "$(ban 2001::/16)")"; apply
    expect "IPv6: a ban shorter than /32 is refused" "$(set_elems edr edr_ban6 | wc -l)" 0
else
    skip "IPv6 ban cases (no IPv6 in the test namespaces on this machine)"
fi

# Interval merge of overlapping bans
client_reset; bans_write "$(doc '[]' "$(ban 198.51.100.0/25 local 600)" "$(ban 198.51.100.0/24 local 3000)" "$(ban 198.51.100.128/25)" "$(ban 198.51.100.64/26)")"
check "overlapping bans load (no interval overlap error)" apply
expect "overlapping bans are merged into the widest CIDR" "$(set_elems edr edr_ban4 | tr '\n' ' ')" "198.51.100.0/24 "
case_ "the merged ban drops its source"; blocked c1 tcp 198.51.100.1 18080

# Atomic replace: the table never goes absent while the state changes
client_reset; bans_write "$(doc '[]' "$(ban $C1/32)")"; apply
nsx srv bash -c 'rm -f "$1"; while :; do if nft list table inet edr >/dev/null 2>&1; then echo . >> "$1.n"; else echo miss >> "$1.m"; fi; done' _ "$WORK/poll" &
POLLER=$!; PIDS+=("$POLLER")
sleep 0.3
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    if ((i % 2)); then bans_write "$(doc '[]' "$(ban $C2/32)" "$(ban 203.0.113.$i/32)")"; else bans_write "$(doc '[]' "$(ban $C1/32)" "$(ban 203.0.113.$i/32)")"; fi
    bans_run >/dev/null
done
kill "$POLLER" 2>/dev/null; wait "$POLLER" 2>/dev/null
polls=$(wc -l < "$WORK/poll.n" 2>/dev/null || echo 0); misses=$(wc -l < "$WORK/poll.m" 2>/dev/null || echo 0)
if [[ $misses -eq 0 && $polls -ge 50 ]]; then pass "atomic replace: the table was present in all $polls polls across 12 replacements"; else fail "atomic replace: $misses misses in $polls polls"; fi
rm -f "$WORK"/poll.*

# An expired entry is gone
client_reset; bans_write "$(doc '[]' "$(ban $C1/32 local 3)")"; apply
case_ "an entry with 3 s left is dropped while it lives"; blocked c1 tcp 198.51.100.1 18080
sleep 4.5
case_ "after its expiry the source is reachable again"; reaches c1 tcp 198.51.100.1 18080
expect "after its expiry the element is gone from the set" "$(set_elems edr edr_ban4 | wc -l)" 0
apply; expect "re-running edr-bans on the expired entry leaves the set empty" "$(set_elems edr edr_ban4 | wc -l)" 0
check "the table is still there" bash -c "nsenter --net=/proc/${NSPID[srv]}/ns/net nft list table inet edr"

# "empty": true empties the sets, keeps the table; an empty list without the flag does not
client_reset; bans_write "$(doc '[]' "$(ban $C1/32)")"; apply
bans_write "$(doc '[]')"; apply
expect "an empty list without \"empty\": true does not lift the bans" "$(set_elems edr edr_ban4 | wc -l)" 1
bans_write "$(empty_doc)"; apply
expect "\"empty\": true empties the ban set" "$(set_elems edr edr_ban4 | wc -l)" 0
check "\"empty\": true keeps the table" bash -c "nsenter --net=/proc/${NSPID[srv]}/ns/net nft list table inet edr"
case_ "after \"empty\": true the source is reachable"; reaches c1 tcp 198.51.100.1 18080

# pause.json
client_reset; bans_write "$(doc '[]' "$(ban $C1/32)")"; apply
printf '{"until": %d}' $(($(now) + 3600)) > "$CL/etc/edr-agent/pause.json"
bans_write "$(empty_doc)"; apply
expect "a valid pause applies the empty state (ban set)" "$(set_elems edr edr_ban4 | wc -l)" 0
check "a valid pause keeps the table" bash -c "nsenter --net=/proc/${NSPID[srv]}/ns/net nft list table inet edr"
case_ "during a pause the banned source is reachable"; reaches c1 tcp 198.51.100.1 18080
printf '{"until": %d}' $(($(now) - 100)) > "$CL/etc/edr-agent/pause.json"
bans_write "$(doc '[]' "$(ban $C2/32)")"; apply
case_ "an expired pause is ignored: the new ban applies"; blocked c2 tcp 198.51.101.1 18080
printf 'not json' > "$CL/etc/edr-agent/pause.json"; bans_write "$(doc '[]' "$(ban $C2/32)" "$(ban 203.0.113.9/32)")"; apply
expect "a pause.json that is not JSON is ignored" "$(set_elems edr edr_ban4 | wc -l)" 2

# The breaker on new hub bans
client_reset
args=("$(ban $C1/32 local)")
for i in $(seq 1 50); do args+=("$(ban 203.0.113.$i/32 fleet)"); done
bans_write "$(doc '[]' "${args[@]}")"; apply
n=$(set_elems edr edr_ban4 | wc -l)
hub=$((n - 1))
if [[ $hub -le 20 ]]; then pass "50 new hub bans in one update: at most 20 applied ($hub)"; else fail "50 new hub bans in one update: $hub applied (the limit is 20)"; fi
grep -q 'more than 20 new hub bans' "$CL/run/edr-bans/counters.json" && pass "the breaker's refusals are reported in counters.json" || fail "no breaker refusal in counters.json"
case_ "the local ban in the same update stays in force"; blocked c1 tcp 198.51.100.1 18080
note "the code applies the first 20 hub bans and refuses the rest; PLAN 4.2 says 'more than 20 new hub bans in one update ... is refused (hub part only)'"

# A burst of 20 bans.json writes in one second ends with the final state
client_reset; apply
( for _ in 1 2 3; do sleep 0.3; bans_run >/dev/null; done ) &
RUNNER=$!
for i in $(seq 1 20); do bans_write "$(doc '[]' "$(ban 203.0.113.$i/32)")"; sleep 0.04; done
wait "$RUNNER"
apply
expect "after 20 writes in about a second the final state is applied" "$(set_elems edr edr_ban4 | tr '\n' ' ')" "203.0.113.20 "

# Delete the table, run edr-bans again: rebuilt
client_reset; bans_write "$(doc '[]' "$(ban $C1/32)")"; apply
drop_tables edr
expect "the table is gone after delete" "$(ntables)" 0
apply
check "edr-bans rebuilds the table" bash -c "nsenter --net=/proc/${NSPID[srv]}/ns/net nft list table inet edr"
case_ "the rebuilt table holds the ban"; blocked c1 tcp 198.51.100.1 18080
stop_listeners

###########################################################################################################
section "Client: inet edr_dns (edr-dns-watch render)"
###########################################################################################################
DNSROOT=$WORK/dns
mkdir -p "$DNSROOT/etc/edr-dns"
printf '198.51.100.2\n' > "$DNSROOT/etc/edr-dns/doh-self.conf"
cp "$CLIENT_FILES/doh-resolvers.conf" "$DNSROOT/etc/edr-dns/doh-resolvers.conf"
PROXY_USER=nobody
ORD=$(id -u daemon 2>/dev/null || echo "")
if [[ -z $NOBODY || -z $ORD ]]; then
    skip "inet edr_dns cases (users 'nobody' and 'daemon' are needed)"
else
    out=$(nsx srv python3 -I "$DNSWATCH" render --root "$DNSROOT" --files-dir "$CLIENT_FILES" --proxy-user "$PROXY_USER" 2>&1) || fail "edr-dns-watch render failed: $out"
    LOCKFILE=$DNSROOT/etc/edr-dns/edr-dns.nft
    [[ -s $LOCKFILE ]] && pass "edr-dns-watch render wrote the lock file" || fail "edr-dns-watch render wrote no lock file"
    listen_in c1 root tcp 53 853 443
    listen_in c1 root udp 53 853
    as() { local uid=$1; shift; nsx srv setpriv --reuid "$uid" --regid "$uid" --clear-groups "$@"; }
    reach_as() { as "$1" python3 -I "$PROBE" "${@:2}"; }
    for spec in "tcp 53" "tcp 853" "udp 53" "udp 853"; do
        # shellcheck disable=SC2086
        set -- $spec
        if reach_as "$ORD" "$1" 198.51.100.2 "$2" 1; then pass "before the lock: plain DNS $1/$2 works for an ordinary uid (control)"; else fail "before the lock: $1/$2 does not work (the test setup is wrong)"; fi
    done
    nsx srv nft -f "$CLIENT_FILES/edr-base.nft" 2>/dev/null
    check "the lock file checks and loads" bash -c "nsenter --net=/proc/${NSPID[srv]}/ns/net nft -c -f '$LOCKFILE' && nsenter --net=/proc/${NSPID[srv]}/ns/net nft -f '$LOCKFILE'"
    for spec in "tcp 53" "tcp 853" "udp 53" "udp 853"; do
        # shellcheck disable=SC2086
        set -- $spec
        if reach_as "$ORD" "$1" 198.51.100.2 "$2" 1; then fail "ordinary uid: plain DNS $1/$2 is not refused"; else pass "ordinary uid: plain DNS $1/$2 is refused"; fi
    done
    if reach_as "$ORD" tcp 198.51.100.2 443 1; then pass "ordinary uid: TCP 443 is not touched"; else fail "ordinary uid: TCP 443 is blocked"; fi
    if reach_as "$NOBODY" tcp 198.51.100.2 443 1; then pass "proxy uid: DoH (TCP 443) to the resolver address in doh-self.conf is allowed"; else fail "proxy uid: DoH to its resolver is blocked"; fi
    if reach_as "$NOBODY" udp 198.51.100.2 53 1; then fail "proxy uid: plain UDP 53 is not refused (the lock lets it use DoH only)"; else pass "proxy uid: plain UDP 53 is refused (the lock lets it use DoH only)"; fi
    if reach_as "$NOBODY" tcp 198.51.100.2 53 1; then fail "proxy uid: plain TCP 53 is not refused"; else pass "proxy uid: plain TCP 53 is refused"; fi
    expect "the lock and the ban table are both loaded" "$(ntables)" 2
    nsx srv nft delete table inet edr_dns
    expect "the lock table can be deleted alone (the ban table stays)" "$(tables | grep -c 'inet edr$')" 1
    for spec in "tcp 53" "udp 53"; do
        # shellcheck disable=SC2086
        set -- $spec
        if reach_as "$ORD" "$1" 198.51.100.2 "$2" 1; then pass "after deleting the lock: plain DNS $1/$2 works again"; else fail "after deleting the lock: $1/$2 is still refused"; fi
    done
    stop_listeners
fi

###########################################################################################################
section "Uninstall leaves no kit table"
###########################################################################################################
drop_tables edr edr_dns edr_hub
expect "no table is left after deleting the kit's tables" "$(ntables)" 0

echo
echo "$PASS passed, $FAIL failed, $SKIP skipped"
[[ $FAIL -eq 0 ]]
