#!/bin/bash
# Remove everything install.sh added and put the Firefox policy file back as it was.
# Run as root. Safe to run more than once, or after a partial install.
set -uo pipefail

STATE=/var/lib/dns-lockdown
CTRLD_DROPIN=/etc/systemd/system/ctrld.service.d
FF_POLICY=/etc/firefox/policies/policies.json
CR_POLICY=/etc/chromium-browser/policies/managed/dns-lockdown.json

say() { printf '\n==> %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root" >&2; exit 1; }

say "Firewall lockdown"
systemctl disable --now dns-lockdown.service 2>/dev/null || true
# In case the service was already gone but rules were left behind
if [ -x /usr/local/sbin/dns-lockdown.sh ]; then
    /usr/local/sbin/dns-lockdown.sh stop
fi
rm -f /etc/systemd/system/dns-lockdown.service /usr/local/sbin/dns-lockdown.sh /etc/default/dns-lockdown
echo "Removed"

say "ctrld drop-ins"
restart_ctrld=0
[ -e "$CTRLD_DROPIN/60-hardening.conf" ] && restart_ctrld=1
rm -f "$CTRLD_DROPIN/50-dns-lockdown.conf" "$CTRLD_DROPIN/60-hardening.conf"
systemctl daemon-reload
if [ $restart_ctrld = 1 ]; then
    systemctl restart ctrld
    echo "Removed sandbox and restarted ctrld"
else
    echo "Removed"
fi

say "Browser policies"
if [ -e "$STATE/firefox-policies.json.orig" ]; then
    cp -a "$STATE/firefox-policies.json.orig" "$FF_POLICY"
    echo "Firefox: restored original $FF_POLICY"
elif [ -e "$STATE/firefox-created" ]; then
    rm -f "$FF_POLICY"
    rmdir "$(dirname "$FF_POLICY")" 2>/dev/null || true
    echo "Firefox: removed $FF_POLICY (install.sh created it)"
else
    echo "Firefox: nothing recorded, left alone"
fi
rm -f "$CR_POLICY"
echo "Chromium: removed $CR_POLICY"

rm -rf "$STATE"

say "Done"
echo "ctrld is untouched apart from the drop-ins above. Restart the browsers to drop their policies."
