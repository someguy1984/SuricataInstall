#!/bin/bash
# Install the alerting for the whole setup: without it, nothing tells you when Suricata
# blocks something, a service dies or Tetragon sees something. Run as root from this folder.
#
#   ./install.sh
#
# Installs two things, each only for the kits that are present:
#   ips-watch.timer        every 15 minutes: Suricata's and Tetragon's health checks, the DNS
#                          lockdown's state, and analyse.py over the last 15 minutes of logs
#   tetragon-notify        a desktop notification for each Tetragon policy hit that isn't on
#                          the ignore list (files/tetragon-ignore.conf)
# Alerts always go to the journal (journalctl -t ips-alert) and, when someone is logged in
# to a desktop, to a notification as well. Settings: files/ips-watch.conf.
#
# Run this after the other installers: it uses the root-owned copies of their check scripts
# (/usr/local/lib/suricata-ips, /usr/local/lib/tetragon-tools), never this checkout.
# Safe to re-run. Undo with ./uninstall.sh
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
LIB=/usr/local/lib/ips-watch
ETC=/etc/ips-watch

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"

say "Pre-flight"
have_suricata=0 have_tetragon=0
[ -x /usr/local/lib/suricata-ips/check.sh ] && have_suricata=1
[ -x /usr/local/lib/tetragon-tools/check.sh ] && have_tetragon=1
[ $have_suricata = 1 ] && echo "Suricata kit found" || echo "Suricata kit not found (run ../install.sh first to have it watched)"
[ $have_tetragon = 1 ] && echo "Tetragon kit found" || echo "Tetragon kit not found (run ../tetragon/local_install.sh first to have it watched)"
[ $have_suricata = 1 ] || [ $have_tetragon = 1 ] || die "nothing to watch yet: install Suricata and/or Tetragon first"
command -v notify-send >/dev/null \
    || echo "NOTE: notify-send is not installed (apt install libnotify-bin): alerts will go to the journal only"

say "Installing scripts and settings"
install -m 0755 -o root -g root "$HERE/files/ips-notify" /usr/local/sbin/ips-notify
install -m 0755 -o root -g root "$HERE/files/ips-watch" /usr/local/sbin/ips-watch
install -d -m 0755 -o root -g root "$LIB"
install -m 0755 -o root -g root "$HERE/files/tetragon-notify.py" "$LIB/tetragon-notify.py"
# The ignore list says which alerts never reach the screen: root-only, like Tetragon's policies
install -d -m 0700 -o root -g root "$ETC"
# Settings are kept in this folder; a copy edited in place is saved rather than lost
for pair in "ips-watch.conf:/etc/ips-watch.conf:0644" "tetragon-ignore.conf:$ETC/tetragon-ignore.conf:0600"; do
    IFS=: read -r src dest mode <<<"$pair"
    if [ -f "$dest" ] && ! cmp -s "$HERE/files/$src" "$dest"; then
        cp -p "$dest" "$dest.bak"
        echo "NOTE: $dest differed from files/$src; the old one is saved as $dest.bak"
    fi
    install -m "$mode" -o root -g root "$HERE/files/$src" "$dest"
done

say "Services"
install -m 0644 -o root -g root "$HERE/files/ips-watch.service" /etc/systemd/system/ips-watch.service
install -m 0644 -o root -g root "$HERE/files/ips-watch.timer" /etc/systemd/system/ips-watch.timer
if [ $have_tetragon = 1 ] && [ -f /etc/systemd/system/tetragon-alerts.service ]; then
    install -m 0644 -o root -g root "$HERE/files/tetragon-notify.service" /etc/systemd/system/tetragon-notify.service
    systemctl daemon-reload
    systemctl enable --quiet tetragon-notify.service
    systemctl restart tetragon-notify.service
    echo "tetragon-notify.service started"
else
    systemctl disable --now --quiet tetragon-notify.service 2>/dev/null || true
    rm -f /etc/systemd/system/tetragon-notify.service
    systemctl daemon-reload
    echo "tetragon-notify not installed (no tetragon-alerts.service to read from)"
fi
systemctl enable --now --quiet ips-watch.timer
echo "ips-watch.timer started (next run: $(systemctl show -p NextElapseUSecMonotonic --value ips-watch.timer))"

say "First run"
# Shows what it finds, and sets the baseline that later runs compare against
systemctl start ips-watch.service || true
journalctl -u ips-watch.service -n 12 --no-pager -o cat 2>/dev/null | sed 's/^/  /' || true

/usr/local/sbin/ips-notify normal "Security alerts are set up" \
    "This is what an alert looks like. They are also in the journal: journalctl -t ips-alert"
echo
echo "A test notification was sent. If nothing appeared on screen, check: journalctl -t ips-alert -n 3"
[ $have_tetragon = 1 ] && echo "End-to-end test of the Tetragon side: sudo $(dirname "$HERE")/tetragon/check.sh --canary"
echo "Tune what notifies: files/tetragon-ignore.conf and files/ips-watch.conf, then re-run this script."
