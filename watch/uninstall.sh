#!/bin/bash
# Remove everything watch/install.sh added. Run as root. Safe to run more than once.
# The other kits and their logs are not touched; alerts already in the journal stay there.
set -uo pipefail

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root" >&2; exit 1; }

systemctl disable --now ips-watch.timer tetragon-notify.service 2>/dev/null || true
systemctl stop ips-watch.service 2>/dev/null || true
rm -f /etc/systemd/system/ips-watch.service /etc/systemd/system/ips-watch.timer \
    /etc/systemd/system/tetragon-notify.service \
    /usr/local/sbin/ips-watch /usr/local/sbin/ips-notify \
    /etc/ips-watch.conf /etc/ips-watch.conf.bak
rm -rf /usr/local/lib/ips-watch /etc/ips-watch /var/lib/ips-watch
systemctl daemon-reload
systemctl reset-failed ips-watch.service tetragon-notify.service 2>/dev/null || true
echo "Alerting removed. Nothing will notify you about Suricata, the DNS lockdown or Tetragon any more."
