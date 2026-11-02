#!/bin/bash
# Check that DNS goes through ctrld and direct DNS egress is refused.
# Doesn't need root. Exit status is the number of failed checks.

MODE=block
[ -r /etc/default/dns-lockdown ] && . /etc/default/dns-lockdown
Q="+time=2 +tries=1 +short"
TEST_DOMAIN=${TEST_DOMAIN:-controld.com}   # example.com is blocked by the Control D profile
fails=0

pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }

answers() { [ -n "$(dig $Q "$@" 2>/dev/null | grep -vE '^;|timed out|refused|error')" ]; }

echo "DNS lockdown checks (mode=$MODE)"

systemctl is-active --quiet ctrld && pass "ctrld is running" || fail "ctrld is not running"
# A failed ufw.service leaves its DROP policies without the before.rules accepts
# (replies, loopback), which silently breaks ctrld
if systemctl is-enabled --quiet ufw 2>/dev/null; then
    systemctl is-failed --quiet ufw && fail "ufw.service failed to load (journalctl -b -u ufw)" \
        || pass "ufw.service loaded"
fi
systemctl is-active --quiet dns-lockdown && pass "dns-lockdown service is active" \
    || fail "dns-lockdown service is not active"

answers @127.0.0.1 "$TEST_DOMAIN" && pass "ctrld answers on 127.0.0.1:53" \
    || fail "ctrld does not answer on 127.0.0.1:53"
answers "$TEST_DOMAIN" && pass "system resolver works (via resolv.conf)" \
    || fail "system resolver does not work"

if [ "$MODE" = "redirect" ]; then
    answers @8.8.8.8 "$TEST_DOMAIN" && pass "IPv4 plain DNS to 8.8.8.8 is redirected to ctrld" \
        || fail "IPv4 plain DNS to 8.8.8.8 got no answer (redirect not working)"
else
    answers @8.8.8.8 "$TEST_DOMAIN" && fail "IPv4 plain DNS to 8.8.8.8 still works" \
        || pass "IPv4 plain DNS to 8.8.8.8 is refused"
    answers +tcp @1.1.1.1 "$TEST_DOMAIN" && fail "IPv4 DNS over TCP to 1.1.1.1 still works" \
        || pass "IPv4 DNS over TCP to 1.1.1.1 is refused"
fi
answers +tls @1.1.1.1 "$TEST_DOMAIN" && fail "DNS-over-TLS (853) to 1.1.1.1 still works" \
    || pass "DNS-over-TLS (853) to 1.1.1.1 is refused"
answers @2001:4860:4860::8888 "$TEST_DOMAIN" && fail "IPv6 plain DNS to Google still works" \
    || pass "IPv6 plain DNS to Google is refused (or no IPv6 route)"

# DoH bypass: any HTTPS answer at all from a public resolver means it's reachable
doh_reachable() { [ "$(curl -s -o /dev/null -m 5 -w '%{http_code}' $1 2>/dev/null)" != 000 ]; }
if command -v curl >/dev/null; then
    doh_reachable "https://1.1.1.1/dns-query?name=$TEST_DOMAIN" \
        && fail "DoH to 1.1.1.1 still works (firewall IP block)" || pass "DoH to 1.1.1.1 is refused (firewall IP block)"
    # Name-based layer (Suricata SNI rules): send the SNI "dns.google" to an ordinary Google web
    # front end, so neither DNS filtering nor the firewall IP block is what stops it
    gip=$(dig +short www.google.com A 2>/dev/null | grep -m1 -E '^[0-9.]+$')
    if [ -n "$gip" ]; then
        doh_reachable "-k --resolve dns.google:443:$gip https://dns.google/" \
            && fail "TLS with SNI dns.google still connects (Suricata SNI rule)" \
            || pass "TLS with SNI dns.google is dropped (Suricata SNI rule)"
    fi
else
    printf '  INFO  curl not installed: DoH bypass not tested\n'
fi

# Config and logs: ctrld runs as root, nobody else needs them
[ "$(stat -c '%U:%a' /etc/controld 2>/dev/null)" = root:700 ] && pass "/etc/controld is root-only (700)" \
    || fail "/etc/controld is $(stat -c '%U:%G %a' /etc/controld 2>/dev/null), expected root 700"
for f in /var/log/ctrld.log /var/log/ctrld.err.log; do
    [ -e "$f" ] || continue
    case $(stat -c %a "$f") in
        *0) pass "$f is not world-readable" ;;
        *) fail "$f is world-readable (it lists every domain looked up)" ;;
    esac
done
[ "$(systemctl show -p MemoryDenyWriteExecute --value ctrld)" = yes ] \
    && pass "ctrld runs sandboxed (exposure $(systemd-analyze security ctrld.service 2>/dev/null | awk '/Overall exposure/ {print $(NF-2)}'))" \
    || fail "ctrld's sandbox (60-hardening.conf) is not active"

for f in /etc/firefox/policies/policies.json /etc/chromium-browser/policies/managed/dns-lockdown.json; do
    [ -r "$f" ] && pass "policy present: $f" || printf '  INFO  policy not installed: %s\n' "$f"
done

echo
[ $fails -eq 0 ] && echo "All checks passed." || echo "$fails check(s) failed."
echo "Also check about:policies in Firefox and chrome://policy in Chromium."
exit $fails
