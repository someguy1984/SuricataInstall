#!/bin/bash
# One-shot install of Suricata as an inline IPS (NFQUEUE) on Ubuntu.
#   - installs Suricata 8.x from the OISF PPA
#   - pulls ET Open + abuse.ch SSLBL/Feodo Tracker/URLhaus rules (files/rule-sources.conf)
#   - installs the tuned suricata.yaml from files/ (midstream, IPv6 HOME_NET, rich eve.json)
#   - converts high-confidence rules to drop (files/drop.conf)
#   - diverts all traffic (IPv4 + IPv6) through Suricata via iptables mangle NFQUEUE rules
#   - daily rule updates, size-based log rotation
# Safe to re-run. Undo with ./uninstall.sh
#
# Run with: sudo ./install.sh [IPv6 prefix ...]
#   Pass any fixed global IPv6 prefixes from your ISP to add them to HOME_NET, e.g.
#   sudo ./install.sh 2a02:c7c:1234::/48
set -euo pipefail

SRC="$(dirname "$(readlink -f "$0")")/files"
CONF=/etc/suricata/suricata.yaml
STATE_DIR=/var/lib/suricata-installer
PPA=ppa:oisf/suricata-stable

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo $0)"; exit 1; }
[[ -d $SRC ]] || { echo "Missing $SRC"; exit 1; }
. /etc/os-release
[[ ${ID:-} == ubuntu ]] || { echo "This installer supports Ubuntu only (found: ${ID:-unknown})"; exit 1; }

V6_EXTRA=""
for prefix in "$@"; do
    [[ $prefix == *:*/* ]] || { echo "Not an IPv6 prefix (expected e.g. 2a02:c7c:1234::/48): $prefix"; exit 1; }
    V6_EXTRA="$V6_EXTRA,$prefix"
done

step() { echo; echo "==> $*"; }
mkdir -p "$STATE_DIR"

step "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y software-properties-common
if ! grep -rqs 'oisf/suricata-stable' /etc/apt/sources.list /etc/apt/sources.list.d/; then
    add-apt-repository -y "$PPA"
    touch "$STATE_DIR/added-ppa"   # so uninstall.sh only removes the PPA if we added it
fi
apt-get update
apt-get install -y suricata iptables curl python3
version=$(suricata -V | grep -o '[0-9][0-9.]*' | head -1)
echo "Suricata $version installed"
[[ ${version%%.*} -ge 8 ]] || echo "WARNING: files/suricata.yaml was written for Suricata 8.x; the config test below will tell us if $version accepts it"

# The package starts Suricata in af-packet (IDS) mode; stop it while we reconfigure
systemctl stop suricata.service || true

step "Installing configuration"
if [[ -f $CONF && ! -f $STATE_DIR/suricata.yaml.orig ]]; then
    cp -p "$CONF" "$STATE_DIR/suricata.yaml.orig"
    echo "Saved the previous config to $STATE_DIR/suricata.yaml.orig"
fi
PREV=$(mktemp)
[[ -f $CONF ]] && cp -p "$CONF" "$PREV"

# af-packet isn't used in NFQUEUE mode, but point it at a real interface so the config stays valid
iface=$(ip route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
iface=${iface:-eth0}
sed -e "s/@DEFAULT_IFACE@/$iface/" \
    -e "s|^\(    HOME_NET: \"\[.*fe80::/10\)\]\"|\1$V6_EXTRA]\"|" \
    "$SRC/suricata.yaml" > "$CONF.new"
install -m 0644 -o root -g suricata "$CONF.new" "$CONF"
rm -f "$CONF.new"
grep '^    HOME_NET:' "$CONF"
install -m 0644 -o root -g root "$SRC/drop.conf" /etc/suricata/drop.conf
install -m 0644 -o root -g root "$SRC/modify.conf" /etc/suricata/modify.conf

step "Enabling rule sources (files/rule-sources.conf)"
suricata-update update-sources
mapfile -t sources < <(grep -vE '^\s*(#|$)' "$SRC/rule-sources.conf")
for src in "${sources[@]}"; do
    suricata-update enable-source "$src"
done
# Disable anything enabled earlier that's no longer listed
for src in $(suricata-update list-enabled-sources 2>/dev/null | sed -n 's/^  - //p'); do
    printf '%s\n' "${sources[@]}" | grep -qxF -- "$src" || suricata-update disable-source "$src"
done

step "Downloading rules (suricata-update, loads the full ruleset to test it: about a minute)"
suricata-update
echo "$(grep -c '^drop ' /var/lib/suricata/rules/suricata.rules) of $(grep -cE '^(alert|drop) ' /var/lib/suricata/rules/suricata.rules) rules set to drop"

step "Testing configuration (loads all rules, can take a minute)"
tdir=$(mktemp -d)
if ! out=$(suricata -T -c "$CONF" -l "$tdir" 2>&1); then
    echo "Configuration test FAILED:"
    tail -20 <<<"$out"
    if [[ -s $PREV ]]; then cp -p "$PREV" "$CONF"; echo "Restored the previous $CONF"; fi
    echo "Nothing else was changed; traffic is not being diverted to Suricata."
    rm -rf "$tdir" "$PREV"
    exit 1
fi
rm -rf "$tdir" "$PREV"
echo "Configuration test passed"

step "Installing NFQUEUE firewall rules and services"
install -m 0755 -o root -g root "$SRC/suricata-nfqueue-apply.sh" /usr/local/sbin/suricata-nfqueue-apply.sh
install -m 0644 -o root -g root "$SRC/suricata-nfqueue.service" /etc/systemd/system/suricata-nfqueue.service
install -m 0644 -o root -g root "$SRC/suricata-rules-update.service" /etc/systemd/system/suricata-rules-update.service
install -m 0644 -o root -g root "$SRC/suricata-rules-update.timer" /etc/systemd/system/suricata-rules-update.timer
mkdir -p /etc/systemd/system/suricata.service.d
install -m 0644 -o root -g root "$SRC/suricata-override.conf" /etc/systemd/system/suricata.service.d/override.conf
# Left over from earlier manual setups; its settings are already in the packaged unit
rm -f /etc/systemd/system/suricata.service.d/network-ordering.conf /usr/local/sbin/suricata-nfqueue-apply.sh.orig
install -m 0644 -o root -g root "$SRC/suricata.logrotate" /etc/logrotate.d/suricata
systemctl daemon-reload

# Rules use --queue-bypass, so traffic keeps flowing even before Suricata binds the queue
systemctl enable suricata-nfqueue.service suricata.service
systemctl restart suricata-nfqueue.service
systemctl restart suricata.service
systemctl enable --now suricata-rules-update.timer

step "Waiting for Suricata to bind NFQUEUE 0"
for _ in $(seq 90); do
    if awk '$1 == 0 && $2 != 0 { found = 1 } END { exit !found }' /proc/net/netfilter/nfnetlink_queue 2>/dev/null; then
        echo "Suricata is inspecting traffic inline."
        echo
        echo "Run a full health check with:  sudo $(dirname "$(readlink -f "$0")")/check.sh --live"
        echo "Watch blocks with:             grep '\"event_type\":\"drop\"' /var/log/suricata/eve.json | tail"
        echo "If something legitimate is blocked, add its SID to /etc/suricata/disable.conf, then run:"
        echo "  suricata-update && systemctl reload suricata"
        exit 0
    fi
    sleep 2
done
echo "Suricata did not bind NFQUEUE 0 within 3 minutes (traffic is passing uninspected). Check:"
echo "  systemctl status suricata; tail -30 /var/log/suricata/suricata.log"
exit 1
