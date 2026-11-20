#!/bin/bash
# Exercise the two firewall scripts (files/suricata-nfqueue-apply.sh and
# controld/files/dns-lockdown.sh) in a throwaway network namespace. The namespace has its
# own, empty netfilter tables, so nothing here touches this machine's real firewall.
# systemctl, systemd-run and logger are replaced by stubs for the same reason.
#
# Run with: sudo tests/firewall-netns.sh        (exit status 0 = every check passed)
set -uo pipefail

ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
NFQ="$ROOT/files/suricata-nfqueue-apply.sh"
LOCK="$ROOT/controld/files/dns-lockdown.sh"

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo $0)"; exit 1; }

NS="ips-test-$$"
WORK=$(mktemp -d)
cleanup() { ip netns del "$NS" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

ip netns add "$NS" || { echo "Cannot create a network namespace"; exit 1; }
ip netns exec "$NS" ip link set lo up

# Stubs: record the call, change nothing on the host
mkdir -p "$WORK/bin" "$WORK/root/etc/dns-lockdown" "$WORK/root/etc/default" "$WORK/root/run"
for tool in systemctl systemd-run logger; do
    printf '#!/bin/sh\necho "%s $*" >> "%s/calls"\n' "$tool" "$WORK" > "$WORK/bin/$tool"
    chmod +x "$WORK/bin/$tool"
done
cp "$ROOT/controld/files/doh-resolvers.conf" "$WORK/root/etc/dns-lockdown/"

ns() { ip netns exec "$NS" env PATH="$WORK/bin:$PATH" DNS_LOCKDOWN_TEST_ROOT="$WORK/root" "$@"; }
rules() { ns "$1" ${3:+-t "$3"} -S ${2:-} 2>/dev/null; }

PASS=0 FAIL=0
ok() { echo "  PASS $*"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL $*"; FAIL=$((FAIL + 1)); }
# check "description" command...   (passes when the command succeeds)
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi; }
# has/hasnt CMD TABLE 'rule text' "description"
has() { check "$4" grep -qxF -- "$3" <(rules "$1" "" "$2"); }
hasnt() { if grep -qxF -- "$3" <(rules "$1" "" "$2"); then bad "$4"; else ok "$4"; fi; }
count() { grep -cF -- "$3" <(rules "$1" "" "$2"); }

echo "== suricata-nfqueue-apply.sh"
check "start succeeds" ns bash "$NFQ" start
for cmd in iptables ip6tables; do
    for hook in INPUT OUTPUT FORWARD; do
        has $cmd mangle "-A $hook -j SURICATA-NFQ" "$cmd: $hook jumps to SURICATA-NFQ"
    done
    has $cmd mangle "-A SURICATA-NFQ -i lo -j RETURN" "$cmd: loopback in returns before the queue"
    has $cmd mangle "-A SURICATA-NFQ -o lo -j RETURN" "$cmd: loopback out returns before the queue"
    has $cmd mangle "-A SURICATA-NFQ -j NFQUEUE --queue-num 0 --queue-bypass" "$cmd: everything else is queued with bypass"
done
ns bash "$NFQ" start
[[ $(count iptables mangle "-j SURICATA-NFQ") -eq 3 ]] && ok "start twice leaves one jump per hook" || bad "start twice duplicated rules"

# Loopback must not reach the queue; anything else must (nothing listens, so bypass accepts it)
ns ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1
queued=$(ns iptables -t mangle -L SURICATA-NFQ -v -n -x | awk '/NFQUEUE/ { print $1 }')
[[ $queued -eq 0 ]] && ok "loopback traffic is not queued" || bad "loopback traffic reached the queue ($queued packets)"
ns ip link add dummy0 type dummy && ns ip addr add 192.0.2.1/24 dev dummy0 && ns ip link set dummy0 up
ns ping -c 1 -W 1 192.0.2.2 >/dev/null 2>&1
queued=$(ns iptables -t mangle -L SURICATA-NFQ -v -n -x | awk '/NFQUEUE/ { print $1 }')
[[ $queued -gt 0 ]] && ok "other traffic is queued" || bad "non-loopback traffic was not queued"

# A rule that isn't ours must survive stop/start
ns iptables -t mangle -A OUTPUT -o lo -j ACCEPT
check "stop succeeds" ns bash "$NFQ" stop
hasnt iptables mangle "-N SURICATA-NFQ" "stop removes the chain"
has iptables mangle "-A OUTPUT -o lo -j ACCEPT" "stop leaves someone else's loopback rule alone"
ns iptables -t mangle -D OUTPUT -o lo -j ACCEPT

# Upgrade from the layout before the chain existed
for cmd in iptables ip6tables; do
    ns $cmd -t mangle -I INPUT 1 -i lo -j ACCEPT
    ns $cmd -t mangle -I INPUT 2 -j NFQUEUE --queue-num 0 --queue-bypass
    ns $cmd -t mangle -I OUTPUT 1 -o lo -j ACCEPT
    ns $cmd -t mangle -I OUTPUT 2 -j NFQUEUE --queue-num 0 --queue-bypass
    ns $cmd -t mangle -I FORWARD 1 -j NFQUEUE --queue-num 0 --queue-bypass
done
ns bash "$NFQ" start
for cmd in iptables ip6tables; do
    hasnt $cmd mangle "-A INPUT -j NFQUEUE --queue-num 0 --queue-bypass" "$cmd: old-layout queue rule is replaced"
    hasnt $cmd mangle "-A INPUT -i lo -j ACCEPT" "$cmd: old-layout loopback rule is removed"
    has $cmd mangle "-A INPUT -j SURICATA-NFQ" "$cmd: new chain in place after the upgrade"
done

echo "== dns-lockdown.sh"
check "start succeeds" ns bash "$LOCK" start
for cmd in iptables ip6tables; do
    has $cmd "" "-A OUTPUT -j DNSLOCK" "$cmd: OUTPUT jumps to DNSLOCK"
    has $cmd "" "-A FORWARD -j DNSLOCK-FWD" "$cmd: FORWARD jumps to DNSLOCK-FWD"
    has $cmd "" "-A DNSLOCK-FWD -p udp -m udp --dport 853 -j REJECT --reject-with $([[ $cmd == iptables ]] && echo icmp-port-unreachable || echo icmp6-port-unreachable)" "$cmd: forwarded DoT is rejected"
    has $cmd "" "-A DNSLOCK -o lo -j RETURN" "$cmd: loopback is exempt"
done
has iptables "" "-A DNSLOCK -p udp -m udp --dport 53 -j REJECT --reject-with icmp-port-unreachable" "plain DNS is rejected"
want4=$(grep -cE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$ROOT/controld/files/doh-resolvers.conf")
want6=$(grep -cE '^[0-9A-Fa-f:]+:[0-9A-Fa-f:]*$' "$ROOT/controld/files/doh-resolvers.conf")
# Once for this machine's own traffic and once for what it forwards
for chain in DNSLOCK DNSLOCK-FWD; do
    [[ $(rules iptables $chain | grep -c -- "--dport 443 -j REJECT --reject-with tcp-reset") -eq $want4 ]] \
        && ok "$chain: every IPv4 resolver in the list is blocked on 443 ($want4)" || bad "$chain: IPv4 DoH rules don't match the list ($want4 expected)"
    [[ $(rules ip6tables $chain | grep -c -- "--dport 443 -j REJECT --reject-with tcp-reset") -eq $want6 ]] \
        && ok "$chain: every IPv6 resolver in the list is blocked on 443 ($want6)" || bad "$chain: IPv6 DoH rules don't match the list ($want6 expected)"
done
ns bash "$LOCK" start
[[ $(count iptables "" "-A OUTPUT -j DNSLOCK") -eq 1 ]] && ok "start twice leaves one jump" || bad "start twice duplicated the jump"

# With the resolver's cgroup present, as on a real machine. The cgroup match cannot be
# reached from FORWARD (the kernel refuses the jump), which is why forwarded traffic has a
# chain of its own; without this the whole lockdown failed to load wherever ctrld was running.
# `ip netns exec` gives each command a /sys without the cgroup tree, so mount it first.
echo "CGROUP=system.slice" > "$WORK/root/etc/default/dns-lockdown"
nscg() { ns bash -c 'mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null; exec "$@"' _ "$@"; }
if nscg test -d /sys/fs/cgroup/system.slice; then
    check "start succeeds with the resolver's cgroup exempted" nscg bash "$LOCK" start
    for cmd in iptables ip6tables; do
        has $cmd "" '-A DNSLOCK -m cgroup --path "system.slice" -j RETURN' "$cmd: the resolver's cgroup is exempt in OUTPUT"
        has $cmd "" "-A FORWARD -j DNSLOCK-FWD" "$cmd: FORWARD is still covered with the exemption in place"
        if rules $cmd DNSLOCK-FWD | grep -q -- '-m cgroup'; then bad "$cmd: the forward chain holds a cgroup match"; else ok "$cmd: the forward chain holds no cgroup match"; fi
    done
else
    echo "  SKIP the cgroup exemption (no system.slice cgroup here)"
fi
rm -f "$WORK/root/etc/default/dns-lockdown"
ns bash "$LOCK" start

ns bash "$NFQ" start
# Another firewall's own "deny out 53" (what `ufw deny out 53` adds): the pause has to get past it
for cmd in iptables ip6tables; do ns $cmd -A OUTPUT -p udp --dport 53 -j DROP; done
check "pause succeeds" ns bash "$LOCK" pause 5
has iptables "" "-A OUTPUT -j DNSLOCK" "pause leaves the rest of the lockdown in place"
has iptables "" "-A DNSLOCK -p udp -m udp --dport 853 -j REJECT --reject-with icmp-port-unreachable" "pause: DoT stays rejected"
[[ $(rules iptables OUTPUT mangle | sed -n 2p) == "-A OUTPUT -j DNSLOCK-PAUSE" ]] \
    && ok "pause: port 53 is accepted ahead of Suricata's queue" || bad "pause chain is not first in mangle OUTPUT"
has iptables mangle "-A DNSLOCK-PAUSE -p udp -m udp --dport 53 -j ACCEPT" "pause accepts UDP 53 only by port"
for cmd in iptables ip6tables; do
    [[ $(rules $cmd OUTPUT | sed -n 2p) == "-A OUTPUT -j DNSLOCK-PAUSE" ]] \
        && ok "$cmd pause: port 53 is accepted ahead of every other filter rule" || bad "$cmd: pause chain is not first in filter OUTPUT"
    has $cmd "" "-A DNSLOCK-PAUSE -p tcp -m tcp --dport 53 -j ACCEPT" "$cmd pause: the filter chain accepts TCP 53 only by port"
done
# In practice: a lookup sent while paused is counted by the pause chain, not by the other firewall's DROP
ns bash -c 'echo -n x > /dev/udp/192.0.2.53/53' 2>/dev/null
passed=$(ns iptables -L DNSLOCK-PAUSE -v -n -x | awk '$3 == "ACCEPT" && /udp dpt:53/ { print $1 }')
dropped=$(ns iptables -L OUTPUT -v -n -x | awk '$3 == "DROP" && /udp dpt:53/ { print $1 }')
[[ ${passed:-0} -gt 0 && ${dropped:-1} -eq 0 ]] && ok "pause: a lookup gets past another firewall's deny-out-53" \
    || bad "pause: a lookup was still stopped by the other firewall's rule (accepted=${passed:-?} dropped=${dropped:-?})"
check "pause schedules the re-lock" grep -q "systemd-run .*--unit=dns-lockdown-rearm .*dns-lockdown.sh start" "$WORK/calls"
check "pause leaves a marker for status/verify" test -s "$WORK/root/run/dns-lockdown.paused"
ns bash "$LOCK" refresh
for cmd in iptables ip6tables; do
    [[ $(rules $cmd OUTPUT | sed -n 2p) == "-A OUTPUT -j DNSLOCK-PAUSE" && $(rules $cmd OUTPUT | sed -n 3p) == "-A OUTPUT -j DNSLOCK" ]] \
        && ok "$cmd: a ctrld restart during a pause rebuilds the chain behind the pause" || bad "$cmd: a ctrld restart during a pause re-locked early"
done
# Restarting Suricata's rules during a pause must keep the pause chain first in mangle OUTPUT
check "nfqueue start succeeds during a pause" ns bash "$NFQ" start
for cmd in iptables ip6tables; do
    [[ $(rules $cmd OUTPUT mangle | sed -n 2p) == "-A OUTPUT -j DNSLOCK-PAUSE" && $(rules $cmd OUTPUT mangle | sed -n 3p) == "-A OUTPUT -j SURICATA-NFQ" ]] \
        && ok "$cmd: restarting the nfqueue rules during a pause keeps the pause chain ahead of Suricata" || bad "$cmd: an nfqueue restart during a pause put Suricata ahead of the pause chain"
done
check "resume succeeds" ns bash "$LOCK" resume
[[ $(rules iptables OUTPUT | sed -n 2p) == "-A OUTPUT -j DNSLOCK" ]] && ok "resume re-locks" || bad "resume: DNSLOCK is not first in OUTPUT"
hasnt iptables mangle "-N DNSLOCK-PAUSE" "resume removes the pause chain"
for cmd in iptables ip6tables; do
    hasnt $cmd "" "-N DNSLOCK-PAUSE" "$cmd: resume removes the filter pause chain"
    has $cmd "" "-A OUTPUT -p udp -m udp --dport 53 -j DROP" "$cmd: resume leaves the other firewall's rule alone"
    ns $cmd -D OUTPUT -p udp --dport 53 -j DROP
done
check "resume clears the marker" test ! -e "$WORK/root/run/dns-lockdown.paused"
if ns bash "$LOCK" pause 600 >/dev/null 2>&1; then bad "pause accepts more than 60 minutes"; else ok "pause refuses more than 60 minutes"; fi
has iptables "" "-A OUTPUT -j DNSLOCK" "a refused pause leaves the lockdown in place"
if ns bash "$LOCK" pause 0 >/dev/null 2>&1; then bad "pause accepts 0 minutes"; else ok "pause refuses 0 minutes"; fi
has iptables "" "-A DNSLOCK -p udp -m udp --dport 5353 -j DROP" "mDNS is dropped"
has iptables "" "-A DNSLOCK -p udp -m udp --dport 5355 -j DROP" "LLMNR is dropped"

echo "MODE=redirect" > "$WORK/root/etc/default/dns-lockdown"
ns bash "$LOCK" start
has iptables nat "-A OUTPUT -j DNSLOCK" "redirect mode adds the nat chain"
ns bash "$LOCK" pause 5
hasnt iptables nat "-A OUTPUT -j DNSLOCK" "redirect mode: pause lifts the redirect (it would send the lookups back to ctrld)"
ns bash "$LOCK" refresh
hasnt iptables nat "-A OUTPUT -j DNSLOCK" "redirect mode: a ctrld restart during a pause does not bring the redirect back"
ns bash "$LOCK" resume
has iptables nat "-A OUTPUT -j DNSLOCK" "redirect mode: resume puts the redirect back"
rm -f "$WORK/root/etc/default/dns-lockdown"

rm -f "$WORK/root/etc/dns-lockdown/doh-resolvers.conf"
check "start still works without the resolver list" ns bash "$LOCK" start
has iptables "" "-A DNSLOCK -p udp -m udp --dport 53 -j REJECT --reject-with icmp-port-unreachable" "DNS is still locked without the list"

check "stop succeeds" ns bash "$LOCK" stop
hasnt iptables "" "-N DNSLOCK" "stop removes the chain"
hasnt iptables "" "-N DNSLOCK-FWD" "stop removes the forward chain"
hasnt iptables nat "-N DNSLOCK" "stop removes the nat chain"
has iptables mangle "-A OUTPUT -j SURICATA-NFQ" "stop leaves Suricata's chain alone"

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
