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
    has $cmd "" "-A FORWARD -j DNSLOCK" "$cmd: FORWARD jumps to DNSLOCK"
    has $cmd "" "-A DNSLOCK -o lo -j RETURN" "$cmd: loopback is exempt"
done
has iptables "" "-A DNSLOCK -p udp -m udp --dport 53 -j REJECT --reject-with icmp-port-unreachable" "plain DNS is rejected"
want4=$(grep -cE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$ROOT/controld/files/doh-resolvers.conf")
want6=$(grep -cE '^[0-9A-Fa-f:]+:[0-9A-Fa-f:]*$' "$ROOT/controld/files/doh-resolvers.conf")
[[ $(count iptables "" "--dport 443 -j REJECT --reject-with tcp-reset") -eq $want4 ]] \
    && ok "every IPv4 resolver in the list is blocked on 443 ($want4)" || bad "IPv4 DoH rules don't match the list ($want4 expected)"
[[ $(count ip6tables "" "--dport 443 -j REJECT --reject-with tcp-reset") -eq $want6 ]] \
    && ok "every IPv6 resolver in the list is blocked on 443 ($want6)" || bad "IPv6 DoH rules don't match the list ($want6 expected)"
ns bash "$LOCK" start
[[ $(count iptables "" "-A OUTPUT -j DNSLOCK") -eq 1 ]] && ok "start twice leaves one jump" || bad "start twice duplicated the jump"

ns bash "$NFQ" start
check "pause succeeds" ns bash "$LOCK" pause 5
hasnt iptables "" "-A OUTPUT -j DNSLOCK" "pause lifts the firewall chain"
[[ $(rules iptables OUTPUT mangle | sed -n 2p) == "-A OUTPUT -j DNSLOCK-PAUSE" ]] \
    && ok "pause: port 53 is accepted ahead of Suricata's queue" || bad "pause chain is not first in mangle OUTPUT"
has iptables mangle "-A DNSLOCK-PAUSE -p udp -m udp --dport 53 -j ACCEPT" "pause accepts UDP 53 only by port"
check "pause schedules the re-lock" grep -q "systemd-run .*--unit=dns-lockdown-rearm .*dns-lockdown.sh start" "$WORK/calls"
check "pause leaves a marker for status/verify" test -s "$WORK/root/run/dns-lockdown.paused"
ns bash "$LOCK" refresh
hasnt iptables "" "-A OUTPUT -j DNSLOCK" "a ctrld restart during a pause does not re-lock early"
check "resume succeeds" ns bash "$LOCK" resume
has iptables "" "-A OUTPUT -j DNSLOCK" "resume re-locks"
hasnt iptables mangle "-N DNSLOCK-PAUSE" "resume removes the pause chain"
check "resume clears the marker" test ! -e "$WORK/root/run/dns-lockdown.paused"
if ns bash "$LOCK" pause 600 >/dev/null 2>&1; then bad "pause accepts more than 60 minutes"; else ok "pause refuses more than 60 minutes"; fi
has iptables "" "-A OUTPUT -j DNSLOCK" "a refused pause leaves the lockdown in place"

echo "MODE=redirect" > "$WORK/root/etc/default/dns-lockdown"
ns bash "$LOCK" start
has iptables nat "-A OUTPUT -j DNSLOCK" "redirect mode adds the nat chain"
rm -f "$WORK/root/etc/default/dns-lockdown"

rm -f "$WORK/root/etc/dns-lockdown/doh-resolvers.conf"
check "start still works without the resolver list" ns bash "$LOCK" start
has iptables "" "-A DNSLOCK -p udp -m udp --dport 53 -j REJECT --reject-with icmp-port-unreachable" "DNS is still locked without the list"

check "stop succeeds" ns bash "$LOCK" stop
hasnt iptables "" "-N DNSLOCK" "stop removes the chain"
hasnt iptables nat "-N DNSLOCK" "stop removes the nat chain"
has iptables mangle "-A OUTPUT -j SURICATA-NFQ" "stop leaves Suricata's chain alone"

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
