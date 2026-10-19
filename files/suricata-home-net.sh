#!/bin/bash
# Keep HOME_NET in /etc/suricata/suricata.yaml set to this machine's own addresses, so that
# other hosts on whatever network the laptop is on (café or hotel Wi-Fi included) count as
# EXTERNAL_NET and the inbound-attack rules fire for them.
#   IPv4: this machine's exact addresses, on every interface (libvirt/docker bridges included)
#   IPv6: the /64 of each global or ULA address (temporary privacy addresses rotate inside
#         it, so it can't be narrower), plus this machine's exact link-local addresses
#   Always: loopback, and any CIDRs listed in /etc/suricata/home-net.extra (one per line)
# Run by suricata-home-net.service (NetworkManager hook + timer) and before Suricata starts.
# Usage: suricata-home-net [--no-reload | --check]
#   (none)       update the config if it changed, then reload the rules (USR2, traffic keeps flowing)
#   --no-reload  update the config only
#   --check      print the expected value; exit 1 if the config is out of date. Changes nothing
set -euo pipefail

CONF=/etc/suricata/suricata.yaml
EXTRA=/etc/suricata/home-net.extra
MODE=${1:-update}

expected() {
    {
        echo 127.0.0.0/8
        echo ::1/128
        ip -o addr show 2>/dev/null | awk '$3 == "inet" || $3 == "inet6" { print $3, $4 }'
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
            addr = ipaddress.ip_address(f[1].split("/")[0])
            if not addr.is_loopback:
                nets.add(ipaddress.ip_network(f"{addr}/32"))
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

want="    HOME_NET: \"[$(expected)]\""
have=$(grep -m1 '^    HOME_NET: ' "$CONF")

if [[ $MODE == --check ]]; then
    echo "$want"
    [[ $have == "$want" ]]
    exit
fi
[[ $MODE == update || $MODE == --no-reload ]] || { echo "Usage: $0 [--no-reload | --check]"; exit 2; }

exec 9>/run/suricata-home-net.lock
flock 9
[[ $have == "$want" ]] && exit 0

tmp=$(mktemp "$CONF.XXXXXX")
trap 'rm -f "$tmp"' EXIT
awk -v line="$want" '!done && /^    HOME_NET: / { print line; done = 1; next } { print }' "$CONF" > "$tmp"
chown root:suricata "$tmp"
chmod 0644 "$tmp"
mv "$tmp" "$CONF"
echo "HOME_NET is now ${want#    HOME_NET: }"

if [[ $MODE == update ]] && systemctl is-active --quiet suricata.service; then
    systemctl reload suricata.service
    echo "Reloaded Suricata's rules"
fi
