#!/bin/bash
# Force all DNS through ctrld.
#
# Builds a DNSLOCK chain in the filter table (IPv4 + IPv6), jumped to from OUTPUT
# position 1, that refuses plain DNS (53), DoT/DoQ (853), mDNS (5353) and LLMNR (5355)
# to anything off-box. Loopback (i.e. ctrld on 127.0.0.1:53) and ctrld's own
# cgroup are exempt.
#
# MODE=redirect (in /etc/default/dns-lockdown) additionally rewrites IPv4 port-53
# traffic to 127.0.0.1:53 in the nat table, so apps with hard-coded resolvers
# get answered by ctrld instead of failing. IPv6 is always rejected, since ctrld
# only listens on 127.0.0.1.
#
# This lives in its own chain rather than /etc/ufw/before.rules because an
# iptables cgroup match fails to load if the cgroup doesn't exist yet, and a
# failed line in before.rules stops UFW loading at all. UFW (MANAGE_BUILTINS=no)
# never flushes chains it doesn't own, so this survives `ufw reload`.
#
# Usage: dns-lockdown.sh start|stop|refresh|status

CHAIN=DNSLOCK
CGROUP=system.slice/ctrld.service
MODE=block
[ -r /etc/default/dns-lockdown ] && . /etc/default/dns-lockdown

log() { echo "dns-lockdown: $*"; logger -t dns-lockdown -- "$*" 2>/dev/null || true; }

remove_rules() {
    for cmd in iptables ip6tables; do
        while $cmd -D OUTPUT -j $CHAIN 2>/dev/null; do :; done
        $cmd -F $CHAIN 2>/dev/null
        $cmd -X $CHAIN 2>/dev/null
    done
    while iptables -t nat -D OUTPUT -j $CHAIN 2>/dev/null; do :; done
    iptables -t nat -F $CHAIN 2>/dev/null
    iptables -t nat -X $CHAIN 2>/dev/null
    return 0
}

have_ctrld_cgroup() { [ -d "/sys/fs/cgroup/$CGROUP" ]; }

build_filter() {
    local cmd=$1
    $cmd -N $CHAIN || return 1
    $cmd -A $CHAIN -o lo -j RETURN || return 1
    if have_ctrld_cgroup; then
        $cmd -A $CHAIN -m cgroup --path $CGROUP -j RETURN || return 1
    fi
    for proto in udp tcp; do
        $cmd -A $CHAIN -p $proto --dport 53 -j REJECT || return 1
        $cmd -A $CHAIN -p $proto --dport 853 -j REJECT || return 1
        $cmd -A $CHAIN -p $proto --dport 5355 -j DROP || return 1
    done
    $cmd -A $CHAIN -p udp --dport 5353 -j DROP || return 1
    $cmd -I OUTPUT 1 -j $CHAIN || return 1
}

build_nat() {
    iptables -t nat -N $CHAIN || return 1
    iptables -t nat -A $CHAIN -d 127.0.0.0/8 -j RETURN || return 1
    if have_ctrld_cgroup; then
        iptables -t nat -A $CHAIN -m cgroup --path $CGROUP -j RETURN || return 1
    fi
    for proto in udp tcp; do
        iptables -t nat -A $CHAIN -p $proto --dport 53 -j REDIRECT --to-ports 53 || return 1
    done
    iptables -t nat -I OUTPUT 1 -j $CHAIN || return 1
}

apply_rules() {
    remove_rules
    if ! have_ctrld_cgroup; then
        log "ctrld is not running; it will be exempted when it starts (ExecStartPost refresh)"
    fi
    # All-or-nothing: a half-built chain is worse than none
    if ! { build_filter iptables && build_filter ip6tables; }; then
        log "failed to build filter rules; removing partial rules"
        remove_rules
        return 1
    fi
    if [ "$MODE" = "redirect" ] && ! build_nat; then
        log "failed to build nat redirect; removing all rules"
        remove_rules
        return 1
    fi
    log "active (mode=$MODE, ctrld exempt=$(have_ctrld_cgroup && echo yes || echo no))"
}

case ${1:-start} in
    start)
        apply_rules
        ;;
    stop)
        remove_rules
        log "removed"
        ;;
    refresh)
        # Called from ctrld's ExecStartPost: a restarted ctrld gets a new cgroup,
        # so the exemption has to be rebuilt. No-op if the lockdown isn't active.
        if iptables -n -L $CHAIN >/dev/null 2>&1; then
            apply_rules
        fi
        ;;
    status)
        for cmd in iptables ip6tables; do
            echo "== $cmd filter"
            $cmd -n -v -L $CHAIN 2>/dev/null || echo "(not active)"
        done
        echo "== iptables nat"
        iptables -t nat -n -v -L $CHAIN 2>/dev/null || echo "(not active)"
        ;;
    *)
        echo "Usage: $0 start|stop|refresh|status"; exit 2 ;;
esac
