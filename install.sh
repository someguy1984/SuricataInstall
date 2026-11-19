#!/bin/bash
# One-shot install of Suricata as an inline IPS (NFQUEUE) on Ubuntu.
#   - installs Suricata 8.x from the OISF PPA
#   - pulls ET Open + abuse.ch SSLBL/Feodo Tracker/URLhaus rules (files/rule-sources.conf)
#   - installs the tuned suricata.yaml from files/ (midstream, rich eve.json)
#   - converts high-confidence rules to drop (files/drop.conf), leaves out the categories
#     that can't apply here (files/disable.conf)
#   - diverts all traffic (IPv4 + IPv6) through Suricata via iptables mangle NFQUEUE rules
#   - daily rule updates (sandboxed), size-based log rotation, weekly filestore clean-up
#   - keeps HOME_NET set to this machine's own addresses as networks change (NetworkManager hook)
#   - pins Suricata to 8.x, and runs it sandboxed (systemd + Landlock)
#   - copies check.sh, analyse.py and files/ to /usr/local/lib/suricata-ips (root-owned)
# Safe to re-run: Suricata keeps inspecting traffic while the new configuration is prepared
# and tested, and is only restarted (or just reloaded) once the test has passed. If anything
# fails before that point the previous files are put back. Undo with ./uninstall.sh
#
# The rules that stop DNS leaving the machine belong to the Control D lockdown (controld/).
# They are installed here only if that lockdown is already in place; otherwise
# controld/install.sh adds them later.
#
# Run with: sudo ./install.sh [CIDR ...]
#   HOME_NET follows this machine's own addresses automatically. CIDRs given here are kept
#   in HOME_NET permanently (written to /etc/suricata/home-net.extra, replacing its contents),
#   e.g. a NAS you trust:  sudo ./install.sh 192.168.1.20/32
set -euo pipefail

ROOT="$(dirname "$(readlink -f "$0")")"
SRC="$ROOT/files"
ETC=/etc/suricata
CONF=$ETC/suricata.yaml
CAND=$ETC/suricata.yaml.new        # the new config, tested here before it replaces $CONF
STATE_DIR=/var/lib/suricata-installer
TOOLS=/usr/local/lib/suricata-ips
OVERRIDE=/etc/systemd/system/suricata.service.d/override.conf
NFQ_SCRIPT=/usr/local/sbin/suricata-nfqueue-apply.sh
PPA=ppa:oisf/suricata-stable
# Everything in /etc/suricata this script writes, for putting back if the install fails
MANAGED=(suricata.yaml drop.conf modify.conf disable.conf local.rules dns-lockdown.rules)

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo $0)"; exit 1; }
[[ -d $SRC ]] || { echo "Missing $SRC"; exit 1; }
. /etc/os-release
[[ ${ID:-} == ubuntu ]] || { echo "This installer supports Ubuntu only (found: ${ID:-unknown})"; exit 1; }

EXTRA_NETS=()
for arg in "$@"; do
    case $arg in
        -*) echo "Unknown option: $arg"; exit 2 ;;
        */*) EXTRA_NETS+=("$arg") ;;
        *) echo "Not a CIDR (expected e.g. 192.168.1.20/32 or 2a02:c7c:1234::/48): $arg"; exit 1 ;;
    esac
done

step() { echo; echo "==> $*"; }
mkdir -p "$STATE_DIR"

# Already running inline from an earlier install? Then it stays up until the new config is tested.
was_inline=0
if [[ -f $OVERRIDE ]] && systemctl is-active --quiet suricata.service; then was_inline=1; fi

committed=0 rules_regenerated=0 BACKUP='' tdir=''
on_exit() {
    local status=$? f
    trap - EXIT
    if [[ $status -ne 0 && $committed -eq 0 && -n $BACKUP ]]; then
        echo
        echo "Install failed before the new configuration went live: putting the previous files back."
        for f in "${MANAGED[@]}"; do
            if [[ -f $BACKUP/$f ]]; then
                cp -p "$BACKUP/$f" "$ETC/$f"
            elif [[ $f != suricata.yaml ]]; then
                rm -f "$ETC/$f"
            fi
        done
        rm -f "$CAND"
        if [[ $rules_regenerated -eq 1 ]]; then
            echo "The downloaded ruleset was already rebuilt with the new drop/disable settings;"
            echo "run 'suricata-update' to rebuild it from the restored files."
        fi
        if [[ $was_inline -eq 1 ]]; then
            echo "Suricata was not restarted and is still inspecting traffic with its previous configuration."
        else
            echo "Traffic is not being diverted to Suricata."
        fi
    fi
    # Whatever went wrong, don't leave a previously working IPS switched off
    if [[ $status -ne 0 && $was_inline -eq 1 ]] && ! systemctl is-active --quiet suricata.service; then
        echo "Starting Suricata again."
        systemctl start suricata.service || echo "WARNING: Suricata did not start; traffic is passing uninspected (systemctl status suricata)"
    fi
    [[ -n $BACKUP ]] && rm -rf "$BACKUP"
    [[ -n $tdir ]] && rm -rf "$tdir"
    exit "$status"
}
trap on_exit EXIT

step "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y software-properties-common
if ! grep -rqs 'oisf/suricata-stable' /etc/apt/sources.list /etc/apt/sources.list.d/; then
    add-apt-repository -y "$PPA"
    touch "$STATE_DIR/added-ppa"   # so uninstall.sh only removes the PPA if we added it
fi
apt-get update
install -m 0644 -o root -g root "$SRC/suricata.apt-pin" /etc/apt/preferences.d/suricata-8
apt-get install -y suricata iptables curl python3
version=$(suricata -V | grep -o '[0-9][0-9.]*' | head -1)
echo "Suricata $version installed"
[[ ${version%%.*} -ge 8 ]] || echo "WARNING: files/suricata.yaml was written for Suricata 8.x; the config test below will tell us if $version accepts it"

if [[ $was_inline -eq 0 ]]; then
    # The package starts Suricata in af-packet (IDS) mode; stop it while we configure
    systemctl stop suricata.service || true
fi

step "Preparing configuration"
if [[ -f $CONF && ! -f $STATE_DIR/suricata.yaml.orig ]]; then
    cp -p "$CONF" "$STATE_DIR/suricata.yaml.orig"
    echo "Saved the previous config to $STATE_DIR/suricata.yaml.orig"
fi
BACKUP=$(mktemp -d)
for f in "${MANAGED[@]}"; do
    if [[ -f $ETC/$f ]]; then cp -p "$ETC/$f" "$BACKUP/$f"; fi
done

iface=$(ip route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')

# af-packet isn't used in NFQUEUE mode, but point it at a real interface so the config stays valid
sed -e "s/@DEFAULT_IFACE@/${iface:-eth0}/" "$SRC/suricata.yaml" > "$CAND"
chown root:suricata "$CAND"
chmod 0644 "$CAND"
if [[ ${#EXTRA_NETS[@]} -gt 0 ]]; then
    printf '%s\n' "# Always in HOME_NET (written by install.sh)" "${EXTRA_NETS[@]}" > $ETC/home-net.extra
fi
install -m 0755 -o root -g root "$SRC/suricata-home-net.sh" /usr/local/sbin/suricata-home-net
SURICATA_CONF=$CAND /usr/local/sbin/suricata-home-net --no-reload
grep '^    HOME_NET:' "$CAND"

install -m 0644 -o root -g root "$SRC/drop.conf" $ETC/drop.conf
install -m 0644 -o root -g root "$SRC/modify.conf" $ETC/modify.conf
# disable.conf used to be edited in place; don't lose that if it differs from anything we installed
if [[ -f $ETC/disable.conf ]] && ! cmp -s $ETC/disable.conf "$SRC/disable.conf" \
    && ! cmp -s $ETC/disable.conf "$TOOLS/files/disable.conf"; then
    cp -p $ETC/disable.conf $ETC/disable.conf.local
    echo "NOTE: $ETC/disable.conf had local edits. They are saved as disable.conf.local;"
    echo "      move them into files/disable.conf and re-run to keep them."
fi
install -m 0644 -o root -g root "$SRC/disable.conf" $ETC/disable.conf
install -m 0644 -o root -g suricata "$SRC/local.rules" $ETC/local.rules

# The DNS rules drop all plain DNS leaving the machine, so they only go in where ctrld and
# the lockdown are already installed. controld/install.sh fills the file in otherwise.
dns_gen="$ROOT/controld/files/dns-lockdown-rules.sh"
if systemctl is-enabled --quiet dns-lockdown.service 2>/dev/null && [[ -f $dns_gen ]]; then
    bash "$dns_gen" > $ETC/dns-lockdown.rules.new
    echo "DNS lockdown is installed: adding its rules ($(grep -c '^drop ' $ETC/dns-lockdown.rules.new) rules)"
elif [[ -f $dns_gen ]]; then
    bash "$dns_gen" --stub > $ETC/dns-lockdown.rules.new
    echo "DNS lockdown (controld/) is not installed: no DNS rules added. controld/install.sh adds them."
else
    echo "# Placeholder: controld/ was not found next to install.sh, so no DNS lockdown rules." > $ETC/dns-lockdown.rules.new
fi
install -m 0644 -o root -g suricata $ETC/dns-lockdown.rules.new $ETC/dns-lockdown.rules
rm -f $ETC/dns-lockdown.rules.new

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
rules_regenerated=1
# --no-reload: the running Suricata is reloaded or restarted below, once everything has passed
suricata-update --suricata-conf "$CAND" --no-reload
echo "$(grep -c '^drop ' /var/lib/suricata/rules/suricata.rules) of $(grep -cE '^(alert|drop) ' /var/lib/suricata/rules/suricata.rules) rules set to drop"

step "Testing configuration (loads all rules, can take a minute)"
tdir=$(mktemp -d)
if ! out=$(suricata -T -c "$CAND" -l "$tdir" 2>&1); then
    echo "Configuration test FAILED:"
    tail -20 <<<"$out"
    exit 1
fi
echo "Configuration test passed"

# From here the new configuration is live. Suricata only needs a restart if something it
# reads at start-up changed; new rules alone are picked up by a reload.
need_restart=1
if [[ $was_inline -eq 1 ]] && cmp -s "$CAND" "$CONF" && cmp -s "$SRC/suricata-override.conf" "$OVERRIDE"; then
    need_restart=0
fi
nfq_changed=1
if cmp -s "$SRC/suricata-nfqueue-apply.sh" "$NFQ_SCRIPT" && systemctl is-active --quiet suricata-nfqueue.service; then
    nfq_changed=0
fi
mv "$CAND" "$CONF"
committed=1

step "Installing NFQUEUE firewall rules and services"
install -m 0755 -o root -g root "$SRC/suricata-nfqueue-apply.sh" "$NFQ_SCRIPT"
for unit in suricata-nfqueue.service suricata-rules-update.service suricata-rules-update.timer \
    suricata-home-net.service suricata-home-net.timer \
    suricata-filestore-prune.service suricata-filestore-prune.timer; do
    install -m 0644 -o root -g root "$SRC/$unit" "/etc/systemd/system/$unit"
done
if [[ -d /etc/NetworkManager/dispatcher.d ]]; then
    install -m 0755 -o root -g root "$SRC/90-suricata-home-net" /etc/NetworkManager/dispatcher.d/90-suricata-home-net
else
    echo "NetworkManager not found: HOME_NET is refreshed by the 15-minute timer only"
fi
mkdir -p "$(dirname "$OVERRIDE")"
install -m 0644 -o root -g root "$SRC/suricata-override.conf" "$OVERRIDE"
# Left over from earlier manual setups; its settings are already in the packaged unit
rm -f /etc/systemd/system/suricata.service.d/network-ordering.conf /usr/local/sbin/suricata-nfqueue-apply.sh.orig
install -m 0644 -o root -g root "$SRC/suricata.logrotate" /etc/logrotate.d/suricata

# Root-owned copies of the health check, the analyser and the reference files they compare
# against, so scheduled jobs (watch/) never run anything from a user-writable checkout
rm -rf "$TOOLS"
install -d -m 0755 -o root -g root "$TOOLS" "$TOOLS/files"
install -m 0755 -o root -g root "$ROOT/check.sh" "$ROOT/analyse.py" "$TOOLS/"
install -m 0644 -o root -g root "$SRC"/* "$TOOLS/files/"
systemctl daemon-reload

# Rules use --queue-bypass, so traffic keeps flowing even before Suricata binds the queue
systemctl enable suricata-nfqueue.service suricata.service
if [[ $nfq_changed -eq 1 ]]; then systemctl restart suricata-nfqueue.service; fi
if [[ $need_restart -eq 1 ]]; then
    systemctl restart suricata.service
else
    echo "suricata.yaml and the service settings are unchanged: reloading rules without a restart"
    systemctl reload suricata.service
fi
systemctl enable --now suricata-rules-update.timer suricata-home-net.timer suricata-filestore-prune.timer

step "Waiting for Suricata to bind NFQUEUE 0"
for _ in $(seq 90); do
    if awk '$1 == 0 && $2 != 0 { found = 1 } END { exit !found }' /proc/net/netfilter/nfnetlink_queue 2>/dev/null; then
        echo "Suricata is inspecting traffic inline."
        echo
        echo "Run a full health check with:  sudo $ROOT/check.sh --live"
        echo "Watch blocks with:             grep '\"event_type\":\"drop\"' /var/log/suricata/eve.json | tail"
        echo "If something legitimate is blocked, add its SID to files/disable.conf and re-run this script."
        exit 0
    fi
    sleep 2
done
echo "Suricata did not bind NFQUEUE 0 within 3 minutes (traffic is passing uninspected). Check:"
echo "  systemctl status suricata; tail -30 /var/log/suricata/suricata.log"
exit 1
