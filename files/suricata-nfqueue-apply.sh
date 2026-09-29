#!/bin/bash
# Divert traffic to Suricata (NFQUEUE 0) from the mangle table, so that an ACCEPT
# verdict from Suricata still passes through UFW's rules in the filter table.
# INPUT is queued as well as OUTPUT/FORWARD so Suricata sees both directions of each flow.
# --queue-bypass: if Suricata isn't running, packets are accepted rather than dropped.
# Usage: suricata-nfqueue-apply.sh start|stop   (idempotent; start purges old copies first)

remove_rules() {
    local cmd=$1
    # Old filter-table rules from earlier setups (these bypassed UFW)
    while $cmd -D OUTPUT -o lo -j ACCEPT 2>/dev/null; do :; done
    while $cmd -D OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null; do :; done
    while $cmd -D FORWARD -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null; do :; done

    while $cmd -t mangle -D INPUT -i lo -j ACCEPT 2>/dev/null; do :; done
    while $cmd -t mangle -D OUTPUT -o lo -j ACCEPT 2>/dev/null; do :; done
    for chain in INPUT OUTPUT FORWARD; do
        while $cmd -t mangle -D $chain -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null; do :; done
    done
}

case ${1:-start} in
    start)
        for cmd in iptables ip6tables; do
            remove_rules $cmd
            $cmd -t mangle -I INPUT 1 -i lo -j ACCEPT
            $cmd -t mangle -I INPUT 2 -j NFQUEUE --queue-num 0 --queue-bypass
            $cmd -t mangle -I OUTPUT 1 -o lo -j ACCEPT
            $cmd -t mangle -I OUTPUT 2 -j NFQUEUE --queue-num 0 --queue-bypass
            $cmd -t mangle -I FORWARD 1 -j NFQUEUE --queue-num 0 --queue-bypass
        done
        ;;
    stop)
        for cmd in iptables ip6tables; do remove_rules $cmd; done
        ;;
    *)
        echo "Usage: $0 start|stop"; exit 2 ;;
esac
