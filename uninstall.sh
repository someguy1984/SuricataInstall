#!/bin/bash
# Remove everything install.sh set up: NFQUEUE firewall rules, services, config, rules and the package.
# Run with: sudo ./uninstall.sh [--yes] [--keep-logs]
#   --yes        don't ask for confirmation
#   --keep-logs  keep /var/log/suricata (eve.json, fast.log, extracted files)
set -uo pipefail

STATE_DIR=/var/lib/suricata-installer
ASSUME_YES=0 KEEP_LOGS=0
for arg in "$@"; do
    case $arg in
        --yes|-y) ASSUME_YES=1 ;;
        --keep-logs) KEEP_LOGS=1 ;;
        *) echo "Unknown option: $arg"; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo $0)"; exit 1; }

if [[ $ASSUME_YES -eq 0 ]]; then
    echo "This will remove Suricata, its firewall rules, config and rules from this machine."
    [[ $KEEP_LOGS -eq 1 ]] && echo "/var/log/suricata will be kept." || echo "/var/log/suricata will be deleted too (use --keep-logs to keep it)."
    read -rp "Continue? [y/N] " answer
    [[ $answer == [yY]* ]] || { echo "Aborted"; exit 1; }
fi

step() { echo; echo "==> $*"; }

# Firewall rules first, so traffic is never queued to a stopped Suricata
step "Removing NFQUEUE firewall rules"
systemctl disable --now suricata-rules-update.timer 2>/dev/null
systemctl disable --now suricata-nfqueue.service 2>/dev/null
for cmd in iptables ip6tables; do
    command -v $cmd >/dev/null || continue
    while $cmd -D OUTPUT -o lo -j ACCEPT 2>/dev/null; do :; done
    for chain in OUTPUT FORWARD; do
        while $cmd -D $chain -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null; do :; done
    done
    while $cmd -t mangle -D INPUT -i lo -j ACCEPT 2>/dev/null; do :; done
    while $cmd -t mangle -D OUTPUT -o lo -j ACCEPT 2>/dev/null; do :; done
    for chain in INPUT OUTPUT FORWARD; do
        while $cmd -t mangle -D $chain -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null; do :; done
    done
done

step "Stopping Suricata"
systemctl disable --now suricata.service 2>/dev/null

step "Removing services and config"
rm -f /etc/systemd/system/suricata-nfqueue.service \
      /etc/systemd/system/suricata-rules-update.service \
      /etc/systemd/system/suricata-rules-update.timer \
      /etc/systemd/system/suricata.service.d/override.conf \
      /etc/systemd/system/suricata.service.d/network-ordering.conf \
      /usr/local/sbin/suricata-nfqueue-apply.sh \
      /usr/local/sbin/suricata-nfqueue-apply.sh.orig \
      /etc/logrotate.d/suricata
rmdir /etc/systemd/system/suricata.service.d 2>/dev/null
systemctl daemon-reload
systemctl reset-failed suricata.service suricata-nfqueue.service suricata-rules-update.service 2>/dev/null

step "Removing the Suricata package"
export DEBIAN_FRONTEND=noninteractive
dpkg -s suricata >/dev/null 2>&1 && apt-get purge -y suricata
if [[ -f $STATE_DIR/added-ppa ]]; then
    add-apt-repository -r -y ppa:oisf/suricata-stable && echo "Removed the OISF PPA (added by install.sh)"
fi
rm -rf /etc/suricata /var/lib/suricata /run/suricata
if [[ $KEEP_LOGS -eq 1 ]]; then
    echo "Kept /var/log/suricata"
else
    rm -rf /var/log/suricata
fi
rm -rf "$STATE_DIR"

step "Verifying"
left=0
for cmd in iptables ip6tables; do
    command -v $cmd >/dev/null || continue
    if { $cmd -S; $cmd -t mangle -S; } 2>/dev/null | grep -q NFQUEUE; then
        echo "WARNING: $cmd still has NFQUEUE rules:"; { $cmd -S; $cmd -t mangle -S; } | grep NFQUEUE
        left=1
    fi
done
[[ $left -eq 0 ]] && echo "No NFQUEUE rules remain"
command -v suricata >/dev/null && echo "WARNING: suricata binary still present" || echo "Suricata removed"
echo
echo "Uninstall complete. Packages pulled in as dependencies can be removed with: sudo apt autoremove"
