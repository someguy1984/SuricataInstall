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

for f in /etc/firefox/policies/policies.json /etc/chromium-browser/policies/managed/dns-lockdown.json; do
    [ -r "$f" ] && pass "policy present: $f" || printf '  INFO  policy not installed: %s\n' "$f"
done

echo
[ $fails -eq 0 ] && echo "All checks passed." || echo "$fails check(s) failed."
echo "Also check about:policies in Firefox and chrome://policy in Chromium."
exit $fails
