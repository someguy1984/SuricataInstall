#!/bin/bash
# Remove everything install.sh added and put the Firefox policy file back as it was.
# Run as root. Safe to run more than once, or after a partial install.
set -uo pipefail

STATE=/var/lib/dns-lockdown
CTRLD_DROPIN=/etc/systemd/system/ctrld.service.d
FF_POLICY=/etc/firefox/policies/policies.json
CR_POLICY_NAME=dns-lockdown.json
CR_POLICY_DIRS="/etc/chromium-browser/policies/managed /etc/chromium/policies/managed
    /etc/opt/chrome/policies/managed /etc/brave/policies/managed /etc/opt/edge/policies/managed"
SURICATA_RULES=/etc/suricata/dns-lockdown.rules
HERE=$(cd "$(dirname "$0")" && pwd)

say() { printf '\n==> %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root" >&2; exit 1; }

say "Firewall lockdown"
systemctl disable --now dns-lockdown.service 2>/dev/null || true
# In case the service was already gone but rules were left behind
if [ -x /usr/local/sbin/dns-lockdown.sh ]; then
    /usr/local/sbin/dns-lockdown.sh stop
fi
rm -f /etc/systemd/system/dns-lockdown.service /usr/local/sbin/dns-lockdown.sh /etc/default/dns-lockdown
rm -rf /etc/dns-lockdown
# Log rotation and the boot-time permission fix; the root-only permissions themselves are kept
rm -f /etc/logrotate.d/ctrld /etc/tmpfiles.d/ctrld-logs.conf
echo "Removed"

say "Suricata DNS rules"
# Back to the placeholder, so Suricata stops dropping DNS now that nothing forces it through ctrld
if [ -f "$SURICATA_RULES" ] && grep -q '^drop ' "$SURICATA_RULES"; then
    bash "$HERE/files/dns-lockdown-rules.sh" --stub > "$SURICATA_RULES"
    if systemctl is-active --quiet suricata; then
        systemctl reload suricata
        echo "Removed; reloading Suricata's rules (takes about a minute to take effect)"
    else
        echo "Removed"
    fi
else
    echo "None installed"
fi

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
# Take back only the DNSOverHTTPS setting, so policies added since the install are kept:
# put the original value back if there was one, otherwise drop the key
if [ -e "$FF_POLICY" ] && { [ -e "$STATE/firefox-policies.json.orig" ] || [ -e "$STATE/firefox-created" ]; }; then
    FF_POLICY="$FF_POLICY" ORIG="$STATE/firefox-policies.json.orig" python3 - <<'PY'
import json, os
path, orig_path = os.environ["FF_POLICY"], os.environ["ORIG"]
def load(p):
    try:
        with open(p) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}
data, orig = load(path), load(orig_path)
policies = data.get("policies", {})
if "DNSOverHTTPS" in orig.get("policies", {}):
    policies["DNSOverHTTPS"] = orig["policies"]["DNSOverHTTPS"]
    print("Firefox: put the original DNSOverHTTPS policy back")
else:
    policies.pop("DNSOverHTTPS", None)
    print("Firefox: removed the DNSOverHTTPS policy")
if not policies and not os.path.exists(orig_path):
    os.remove(path)                       # install.sh created the file and nothing else is in it
    print(f"Firefox: removed {path} (install.sh created it)")
else:
    data["policies"] = policies
    with open(path + ".tmp", "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.chmod(path + ".tmp", 0o644)
    os.replace(path + ".tmp", path)
PY
    rmdir "$(dirname "$FF_POLICY")" 2>/dev/null || true
else
    echo "Firefox: nothing recorded, left alone"
fi
for dir in $CR_POLICY_DIRS; do
    [ -e "$dir/$CR_POLICY_NAME" ] || continue
    rm -f "$dir/$CR_POLICY_NAME"
    echo "Chromium family: removed $dir/$CR_POLICY_NAME"
done

rm -rf "$STATE"

say "Done"
echo "ctrld is untouched apart from the drop-ins above. Restart the browsers to drop their policies."
