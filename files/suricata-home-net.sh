#!/bin/bash
# Keep HOME_NET in /etc/suricata/suricata.yaml set to this machine's own addresses, so that
# other hosts on whatever network the laptop is on (café or hotel Wi-Fi included) count as
# EXTERNAL_NET and the inbound-attack rules fire for them.
#   IPv4: this machine's exact addresses, on every interface
#   IPv6: the /64 of each global or ULA address (temporary privacy addresses rotate inside
#         it, so it can't be narrower), plus this machine's exact link-local addresses
#   Guests: the whole subnet of each bridge this machine routes for (libvirt, Docker), so
#         VMs and containers behind it are "home" too and the outbound rules cover their
#         traffic. A bridge that carries the default route is the uplink, not a guest network,
#         and is treated like any other interface.
#   Always: loopback, and any CIDRs listed in /etc/suricata/home-net.extra (one per line)
# Run by suricata-home-net.service (NetworkManager hook + timer) and before Suricata starts.
# Usage: suricata-home-net [--no-reload | --check]
#   (none)       update the config if it changed, then reload the rules (USR2, traffic keeps flowing)
#   --no-reload  update the config only
#   --check      print the expected value; exit 1 if the config is out of date. Changes nothing
# SURICATA_CONF=<file> works on another copy of the config (install.sh uses it for the
# candidate it tests before going live); that never reloads Suricata.
set -euo pipefail

LIVE_CONF=/etc/suricata/suricata.yaml
CONF=${SURICATA_CONF:-$LIVE_CONF}
EXTRA=/etc/suricata/home-net.extra
MODE=${1:-update}

expected() {
    local bridges uplinks
    bridges=$(ip -o link show type bridge 2>/dev/null | awk -F': ' '{ sub(/@.*/, "", $2); print $2 }')
    uplinks=$({ ip -4 route show default; ip -6 route show default; } 2>/dev/null \
        | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1) }')
    {
        echo 127.0.0.0/8
        echo ::1/128
        ip -o addr show 2>/dev/null | awk -v bridges="$bridges" -v uplinks="$uplinks" '
            BEGIN {
                n = split(bridges, b, "\n"); for (i = 1; i <= n; i++) guest[b[i]] = 1
                n = split(uplinks, u, "\n"); for (i = 1; i <= n; i++) delete guest[u[i]]
            }
            $3 == "inet" || $3 == "inet6" { print $3, $4, (($2 in guest) ? "net" : "host") }'
        if [[ -f $EXTRA ]]; then sed -e 's/#.*//' -e 's/[[:space:]]//g' "$EXTRA" | awk 'NF { print "extra", $1 }'; fi
    } | python3 -I -c '
import ipaddress, sys
nets = set()
for line in sys.stdin:
    f = line.split()
    try:
        if len(f) == 1:                                   # fixed entries
            nets.add(ipaddress.ip_network(f[0]))
        elif f[0] == "extra":
            nets.add(ipaddress.ip_network(f[1], strict=False))
        elif f[0] == "inet":
            iface = ipaddress.ip_interface(f[1])
            if iface.ip.is_loopback:
                continue
            if f[2] == "net":                             # bridge we route for: its guests too
                nets.add(iface.network)
            else:
                nets.add(ipaddress.ip_network(f"{iface.ip}/32"))
        elif f[0] == "inet6":
            addr = ipaddress.ip_address(f[1].split("/")[0])
            if addr.is_loopback:
                continue
            prefix = 128 if addr.is_link_local else 64
            nets.add(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))
    except ValueError as e:
        print(f"ignoring {line.strip()!r}: {e}", file=sys.stderr)
print(",".join(str(n) for n in sorted(nets, key=lambda n: (n.version, n))))
'
}

current() { grep -m1 '^    HOME_NET: ' "$CONF"; }

want="    HOME_NET: \"[$(expected)]\""

if [[ $MODE == --check ]]; then
    echo "$want"
    [[ $(current) == "$want" ]]
    exit
fi
[[ $MODE == update || $MODE == --no-reload ]] || { echo "Usage: $0 [--no-reload | --check]"; exit 2; }

# Read the current value only once we hold the lock: two runs started together (hook + timer)
# would otherwise both see the old value, and both rewrite the file and reload the rules
exec 9>/run/suricata-home-net.lock
flock 9
[[ $(current) == "$want" ]] && exit 0

tmp=$(mktemp "$CONF.XXXXXX")
trap 'rm -f "$tmp"' EXIT
awk -v line="$want" '!done && /^    HOME_NET: / { print line; done = 1; next } { print }' "$CONF" > "$tmp"
chown root:suricata "$tmp"
chmod 0644 "$tmp"
mv "$tmp" "$CONF"
echo "HOME_NET is now ${want#    HOME_NET: }"

if [[ $MODE == update && $CONF == "$LIVE_CONF" ]] && systemctl is-active --quiet suricata.service; then
    systemctl reload suricata.service
    echo "Reloaded Suricata's rules"
fi
