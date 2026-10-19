#!/bin/bash
# Install the ctrld DNS lockdown. Run as root from this folder.
#
#   ./install.sh                  block direct DNS, sandbox ctrld, lock browser DoH
#   MODE=redirect ./install.sh    redirect hard-coded IPv4 resolvers to ctrld instead of refusing
#   HARDEN=0 ./install.sh         skip the ctrld sandbox drop-in
#   BROWSERS=0 ./install.sh       skip the Firefox/Chromium policies
#
# Safe to re-run. Undo everything with ./uninstall.sh.
set -euo pipefail

MODE=${MODE:-block}
HARDEN=${HARDEN:-1}
BROWSERS=${BROWSERS:-1}
TEST_DOMAIN=${TEST_DOMAIN:-controld.com}   # example.com is blocked by the Control D profile

HERE=$(cd "$(dirname "$0")" && pwd)
STATE=/var/lib/dns-lockdown
CTRLD_DROPIN=/etc/systemd/system/ctrld.service.d
FF_POLICY=/etc/firefox/policies/policies.json
CR_POLICY=/etc/chromium-browser/policies/managed/dns-lockdown.json

say()  { printf '\n==> %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
resolves() { [ -n "$(dig +time=3 +tries=2 +short @127.0.0.1 "$TEST_DOMAIN" 2>/dev/null | grep -v '^;')" ]; }

[ "$(id -u)" -eq 0 ] || die "run as root"
[ "$MODE" = block ] || [ "$MODE" = redirect ] || die "MODE must be 'block' or 'redirect'"
command -v dig >/dev/null || die "dig not found (apt install bind9-dnsutils)"

say "Pre-flight"
systemctl is-failed --quiet ufw && die "ufw.service is in a failed state; fix /etc/ufw/*.rules first (journalctl -b -u ufw)"
if grep -qs -- '-m cgroup' /etc/ufw/before.rules /etc/ufw/before6.rules; then
    die "/etc/ufw/before*.rules has a cgroup match, which fails at boot before ctrld exists; remove it (DNSLOCK handles the exemption)"
fi
systemctl is-active --quiet ctrld || die "ctrld is not running; fix that first so DNS isn't locked to a dead resolver"
resolves || die "ctrld is running but not answering on 127.0.0.1:53; not locking DNS to it"
echo "ctrld is up and answering"
mkdir -p "$STATE"

say "Firewall lockdown (mode=$MODE)"
install -m 0755 -o root -g root "$HERE/files/dns-lockdown.sh" /usr/local/sbin/dns-lockdown.sh
install -m 0644 -o root -g root "$HERE/files/dns-lockdown.service" /etc/systemd/system/dns-lockdown.service
echo "MODE=$MODE" > /etc/default/dns-lockdown
mkdir -p "$CTRLD_DROPIN"
install -m 0644 -o root -g root "$HERE/files/ctrld-50-dns-lockdown.conf" "$CTRLD_DROPIN/50-dns-lockdown.conf"
systemctl daemon-reload
systemctl enable dns-lockdown.service
systemctl restart dns-lockdown.service
/usr/local/sbin/dns-lockdown.sh status

if [ "$HARDEN" = 1 ]; then
    say "Sandboxing ctrld"
    install -m 0644 -o root -g root "$HERE/files/ctrld-60-hardening.conf" "$CTRLD_DROPIN/60-hardening.conf"
    systemctl daemon-reload
    systemctl restart ctrld || true
    sleep 3
    if systemctl is-active --quiet ctrld && resolves; then
        echo "ctrld restarted under the sandbox and is resolving"
    else
        echo "ctrld failed under the sandbox; removing it and restarting ctrld without it"
        journalctl -u ctrld -n 20 --no-pager || true
        tail -n 20 /var/log/ctrld.err.log 2>/dev/null || true
        rm -f "$CTRLD_DROPIN/60-hardening.conf"
        systemctl daemon-reload
        systemctl restart ctrld || true
        sleep 3
        resolves || die "ctrld still not resolving after removing the sandbox; run ./uninstall.sh"
        echo "Sandbox skipped; everything else is in place"
    fi
fi

if [ "$BROWSERS" = 1 ]; then
    say "Browser policies"
    # Profile URL comes from your ctrld config rather than being stored in this folder
    DOH_URL=$(grep -m1 -oP "^\s*endpoint\s*=\s*['\"]\Khttps://[^'\"]+" /etc/controld/local.toml || true)
    [ -n "$DOH_URL" ] || die "couldn't read the https:// endpoint from /etc/controld/local.toml"
    echo "Control D profile: $DOH_URL"

    # Firefox: merge into any existing policies.json rather than overwrite it
    mkdir -p "$(dirname "$FF_POLICY")"
    # Record the pre-install state once, so a re-run never mistakes our own file for the original
    if [ ! -e "$STATE/firefox-policies.json.orig" ] && [ ! -e "$STATE/firefox-created" ]; then
        if [ -e "$FF_POLICY" ]; then
            cp -a "$FF_POLICY" "$STATE/firefox-policies.json.orig"
        else
            touch "$STATE/firefox-created"
        fi
    fi
    DOH_URL="$DOH_URL" FF_POLICY="$FF_POLICY" python3 - <<'PY'
import json, os
path = os.environ["FF_POLICY"]
data = {}
if os.path.exists(path) and os.path.getsize(path) > 0:
    with open(path) as f:
        data = json.load(f)
data.setdefault("policies", {})["DNSOverHTTPS"] = {
    "Enabled": True,
    "ProviderURL": os.environ["DOH_URL"],
    "Locked": True,
    "Fallback": False,
}
with open(path + ".tmp", "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
os.chmod(path + ".tmp", 0o644)
os.replace(path + ".tmp", path)
PY
    echo "Firefox: $FF_POLICY (restart Firefox, then check about:policies)"

    # Chromium snap reads /etc/chromium-browser/policies via its system-files plug
    mkdir -p "$(dirname "$CR_POLICY")"
    install -m 0644 -o root -g root "$HERE/files/chromium-dns-lockdown.json" "$CR_POLICY"
    echo "Chromium: $CR_POLICY (restart Chromium, then check chrome://policy)"
fi

say "Verifying"
sudo -u "${SUDO_USER:-j}" "$HERE/verify.sh" || true
