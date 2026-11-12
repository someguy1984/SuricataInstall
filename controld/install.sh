#!/bin/bash
# Install the ctrld DNS lockdown. Run as root from this folder.
#
#   ./install.sh                  block direct DNS and public DoH resolvers, sandbox ctrld,
#                                 turn off the browsers' own DoH, make ctrld's config and
#                                 logs root-only, add the DNS rules to Suricata if it is installed
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
SURICATA_RULES=/etc/suricata/dns-lockdown.rules
# Managed-policy directories of the Chromium family. The first is always written (the
# Chromium snap reads it); the others only if that browser is installed.
CR_POLICY_NAME=dns-lockdown.json
CR_POLICY_DIRS=(
    "/etc/chromium-browser/policies/managed:always"
    "/etc/chromium/policies/managed:chromium"
    "/etc/opt/chrome/policies/managed:google-chrome google-chrome-stable"
    "/etc/brave/policies/managed:brave-browser"
    "/etc/opt/edge/policies/managed:microsoft-edge microsoft-edge-stable"
)

say()  { printf '\n==> %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
resolves() { [ -n "$(dig +time=3 +tries=2 +short @127.0.0.1 "$TEST_DOMAIN" 2>/dev/null | grep -v '^;')" ]; }
# The same through /etc/resolv.conf, i.e. what every program on the machine actually uses
system_resolves() { [ -n "$(dig +time=3 +tries=2 +short "$TEST_DOMAIN" 2>/dev/null | grep -v '^;')" ]; }

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

say "Securing ctrld's binary, config and logs"
# ctrld runs as root, so nothing else needs to read its config (it holds the profile ID) or
# be able to replace its binary; the logs hold every domain looked up
chown root:root /usr/local/bin/ctrld
chmod 0755 /usr/local/bin/ctrld
chown -R root:root /etc/controld
chmod 0700 /etc/controld
find /etc/controld -type f -exec chmod 0600 {} +
for f in /var/log/ctrld.log /var/log/ctrld.err.log; do
    [ -e "$f" ] && chown root:adm "$f" && chmod 0640 "$f"
done
install -m 0644 -o root -g root "$HERE/files/ctrld.logrotate" /etc/logrotate.d/ctrld
# Re-applies those permissions at every boot, in case something resets them
install -m 0644 -o root -g root "$HERE/files/ctrld-logs.tmpfiles" /etc/tmpfiles.d/ctrld-logs.conf
systemd-tmpfiles --create /etc/tmpfiles.d/ctrld-logs.conf
ls -ld /etc/controld /var/log/ctrld*.log

say "Firewall lockdown (mode=$MODE)"
install -m 0755 -o root -g root "$HERE/files/dns-lockdown.sh" /usr/local/sbin/dns-lockdown.sh
install -m 0644 -o root -g root "$HERE/files/dns-lockdown.service" /etc/systemd/system/dns-lockdown.service
# The public DoH resolvers to block: IPs here in the firewall, hostnames in Suricata below
install -d -m 0755 -o root -g root /etc/dns-lockdown
install -m 0644 -o root -g root "$HERE/files/doh-resolvers.conf" /etc/dns-lockdown/doh-resolvers.conf
echo "MODE=$MODE" > /etc/default/dns-lockdown
mkdir -p "$CTRLD_DROPIN"
install -m 0644 -o root -g root "$HERE/files/ctrld-50-dns-lockdown.conf" "$CTRLD_DROPIN/50-dns-lockdown.conf"
systemctl daemon-reload
systemctl enable dns-lockdown.service
systemctl restart dns-lockdown.service
/usr/local/sbin/dns-lockdown.sh status

say "Suricata DNS rules"
# Second layer, by name: drops plain DNS/DoT that slips past the firewall (ctrld's own
# fallback, which DNSLOCK exempts) and TLS/QUIC to the listed resolvers' hostnames.
if [ -d /etc/suricata ] && getent group suricata >/dev/null; then
    bash "$HERE/files/dns-lockdown-rules.sh" "$HERE/files/doh-resolvers.conf" > "$STATE/dns-lockdown.rules"
    if cmp -s "$STATE/dns-lockdown.rules" "$SURICATA_RULES"; then
        echo "$SURICATA_RULES is up to date"
    else
        install -m 0644 -o root -g suricata "$STATE/dns-lockdown.rules" "$SURICATA_RULES"
        echo "Installed $SURICATA_RULES ($(grep -c '^drop ' "$SURICATA_RULES") rules)"
        if ! grep -qs "^  - $SURICATA_RULES" /etc/suricata/suricata.yaml; then
            echo "NOTE: Suricata's config doesn't load this file yet; run ../install.sh so it does"
        elif systemctl is-active --quiet suricata; then
            systemctl reload suricata
            echo "Reloading Suricata's rules (takes about a minute to take effect)"
        fi
    fi
    rm -f "$STATE/dns-lockdown.rules"
else
    echo "Suricata is not installed: only the firewall layer is in place."
    echo "../install.sh adds these rules when it is run after this script."
fi

if [ "$HARDEN" = 1 ]; then
    say "Sandboxing ctrld"
    SANDBOX="$CTRLD_DROPIN/60-hardening.conf"
    # PrivateIPC is one of this drop-in's settings: "yes" means systemd has it loaded
    if cmp -s "$HERE/files/ctrld-60-hardening.conf" "$SANDBOX" && systemctl is-active --quiet ctrld \
        && [ "$(systemctl show -p PrivateIPC --value ctrld)" = yes ]; then
        # Restarting ctrld means a few seconds without DNS; don't when nothing would change
        echo "The sandbox is already in place and unchanged: ctrld is not restarted"
    else
        # Keep whatever sandbox was there, so a new one that doesn't work is replaced by the
        # old one that did rather than by nothing
        rm -f "$STATE/60-hardening.conf.prev"
        if [ -f "$SANDBOX" ]; then cp -p "$SANDBOX" "$STATE/60-hardening.conf.prev"; fi
        install -m 0644 -o root -g root "$HERE/files/ctrld-60-hardening.conf" "$SANDBOX"
        systemctl daemon-reload
        echo "Restarting ctrld (DNS lookups fail for a few seconds)"
        systemctl restart ctrld || true
        sleep 3
        if systemctl is-active --quiet ctrld && resolves && system_resolves; then
            echo "ctrld restarted under the sandbox and is resolving"
        else
            echo "ctrld failed under the new sandbox:"
            journalctl -u ctrld -n 20 --no-pager || true
            tail -n 20 /var/log/ctrld.err.log 2>/dev/null || true
            if [ -f "$STATE/60-hardening.conf.prev" ]; then
                echo "Putting the previous sandbox back and restarting ctrld"
                install -m 0644 -o root -g root "$STATE/60-hardening.conf.prev" "$SANDBOX"
            else
                echo "Removing it and restarting ctrld without a sandbox"
                rm -f "$SANDBOX"
            fi
            systemctl daemon-reload
            systemctl restart ctrld || true
            sleep 3
            if ! { resolves && system_resolves; } && [ -f "$SANDBOX" ]; then
                echo "Still not resolving; removing the sandbox altogether"
                rm -f "$SANDBOX"
                systemctl daemon-reload
                systemctl restart ctrld || true
                sleep 3
            fi
            resolves || die "ctrld still not resolving without the sandbox; run ./uninstall.sh"
            echo "New sandbox skipped; everything else is in place"
        fi
        rm -f "$STATE/60-hardening.conf.prev"
    fi
fi

if [ "$BROWSERS" = 1 ]; then
    say "Browser policies"
    # Every browser gets its own DoH switched off and locked, so it uses the system
    # resolver, i.e. ctrld. Firefox is not pointed at the Control D profile URL directly:
    # this file has to be world-readable, and that URL holds the profile ID that
    # /etc/controld is kept root-only to protect. It also keeps Firefox's lookups in
    # ctrld's log and under its rules, like everything else.

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
    FF_POLICY="$FF_POLICY" python3 - <<'PY'
import json, os
path = os.environ["FF_POLICY"]
data = {}
if os.path.exists(path) and os.path.getsize(path) > 0:
    with open(path) as f:
        data = json.load(f)
data.setdefault("policies", {})["DNSOverHTTPS"] = {
    "Enabled": False,
    "Locked": True,
}
with open(path + ".tmp", "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
os.chmod(path + ".tmp", 0o644)
os.replace(path + ".tmp", path)
PY
    echo "Firefox: $FF_POLICY (restart Firefox, then check about:policies)"

    # Chromium snap reads /etc/chromium-browser/policies via its system-files plug
    for entry in "${CR_POLICY_DIRS[@]}"; do
        dir=${entry%%:*} found=0
        for bin in ${entry#*:}; do
            if [ "$bin" = always ] || command -v "$bin" >/dev/null; then found=1; fi
        done
        [ $found = 1 ] || continue
        mkdir -p "$dir"
        install -m 0644 -o root -g root "$HERE/files/chromium-dns-lockdown.json" "$dir/$CR_POLICY_NAME"
        echo "Chromium family: $dir/$CR_POLICY_NAME (restart the browser, then check chrome://policy)"
    done
    echo "A browser installed later is covered by re-running this script."
fi

say "Verifying"
# verify.sh doesn't need root; run it as the person who called sudo when there is one
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    sudo -u "$SUDO_USER" "$HERE/verify.sh" || true
else
    "$HERE/verify.sh" || true
fi
