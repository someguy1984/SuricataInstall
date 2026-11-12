#!/bin/bash
# Divert traffic to Suricata (NFQUEUE 0) from the mangle table, so that an ACCEPT
# verdict from Suricata still passes through UFW's rules in the filter table.
#
# Everything lives in one chain of our own, SURICATA-NFQ (IPv4 + IPv6), jumped to from
# position 1 of mangle INPUT, OUTPUT and FORWARD. INPUT is queued as well as OUTPUT/FORWARD
# so Suricata sees both directions of each flow. Loopback returns before the queue.
# --queue-bypass: if Suricata isn't running, packets are accepted rather than dropped.
#
# Owning a chain means stop/start only ever touch rules this script created.
#
# Usage: suricata-nfqueue-apply.sh start|stop   (idempotent; start rebuilds from scratch)

CHAIN=SURICATA-NFQ
HOOKS="INPUT OUTPUT FORWARD"
QUEUE=(-j NFQUEUE --queue-num 0 --queue-bypass)

# Rules that versions before the SURICATA-NFQ chain put straight into the built-in chains.
# Only touched where the old NFQUEUE rule is actually present, so a loopback ACCEPT that
# belongs to something else is left alone. Safe to delete once no machine has the old layout.
remove_legacy() {
    local cmd=$1 hook
    for hook in $HOOKS; do
        $cmd -t mangle -C "$hook" "${QUEUE[@]}" 2>/dev/null || continue
        while $cmd -t mangle -D "$hook" "${QUEUE[@]}" 2>/dev/null; do :; done
        case $hook in
            INPUT) while $cmd -t mangle -D INPUT -i lo -j ACCEPT 2>/dev/null; do :; done ;;
            OUTPUT) while $cmd -t mangle -D OUTPUT -o lo -j ACCEPT 2>/dev/null; do :; done ;;
        esac
    done
    # Older still: NFQUEUE rules in the filter table, where they bypassed UFW
    for hook in OUTPUT FORWARD; do
        while $cmd -D "$hook" "${QUEUE[@]}" 2>/dev/null; do :; done
    done
}

remove_rules() {
    local cmd=$1 hook
    for hook in $HOOKS; do
        while $cmd -t mangle -D "$hook" -j $CHAIN 2>/dev/null; do :; done
    done
    $cmd -t mangle -F $CHAIN 2>/dev/null
    $cmd -t mangle -X $CHAIN 2>/dev/null
    remove_legacy "$cmd"
    return 0
}

build_rules() {
    local cmd=$1 hook
    $cmd -t mangle -N $CHAIN || return 1
    $cmd -t mangle -A $CHAIN -i lo -j RETURN || return 1
    $cmd -t mangle -A $CHAIN -o lo -j RETURN || return 1
    $cmd -t mangle -A $CHAIN "${QUEUE[@]}" || return 1
    for hook in $HOOKS; do
        $cmd -t mangle -I "$hook" 1 -j $CHAIN || return 1
    done
}

case ${1:-start} in
    start)
        for cmd in iptables ip6tables; do
            remove_rules $cmd
            if ! build_rules $cmd; then
                # All-or-nothing: with only one family queued, the other would go uninspected
                # while everything looks active
                echo "suricata-nfqueue: failed to build the $cmd rules; removing all of them" >&2
                for c in iptables ip6tables; do remove_rules $c; done
                exit 1
            fi
        done
        ;;
    stop)
        for cmd in iptables ip6tables; do remove_rules $cmd; done
        ;;
    *)
        echo "Usage: $0 start|stop"; exit 2 ;;
esac
