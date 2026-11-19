#!/bin/bash
# Force all DNS through ctrld.
#
# Builds a DNSLOCK chain in the filter table (IPv4 + IPv6), jumped to from position 1 of
# OUTPUT and FORWARD, that refuses plain DNS (53), DoT/DoQ (853), mDNS (5353) and LLMNR
# (5355) to anything off-box, plus HTTPS/QUIC (443) to the fixed IPs of well-known public
# DoH resolvers, so apps can't bypass ctrld with their own DNS-over-HTTPS. Loopback
# (i.e. ctrld on 127.0.0.1:53) and ctrld's own cgroup are exempt. The resolver IPs come
# from /etc/dns-lockdown/doh-resolvers.conf; Suricata's dns-lockdown.rules block the
# hostnames in the same list by name (SNI), for the resolvers without fixed IPs.
#
# FORWARD covers VMs and containers routed through this machine. Something that manages
# FORWARD itself and starts later (rootful Docker) can put its own accepts above this jump;
# Suricata's rules sit in the mangle table ahead of all of it and still drop that traffic.
#
# MODE=redirect (in /etc/default/dns-lockdown) additionally rewrites this machine's own IPv4
# port-53 traffic to 127.0.0.1:53 in the nat table, so apps with hard-coded resolvers
# get answered by ctrld instead of failing. IPv6 and forwarded traffic are always rejected,
# since ctrld only listens on 127.0.0.1.
#
# This lives in its own chain rather than /etc/ufw/before.rules because an
# iptables cgroup match fails to load if the cgroup doesn't exist yet, and a
# failed line in before.rules stops UFW loading at all. UFW (MANAGE_BUILTINS=no)
# never flushes chains it doesn't own, so this survives `ufw reload`.
#
# pause: a captive portal (hotel, café) only works if its own DNS can be reached. `pause`
# lifts the lockdown for a few minutes (plain DNS on port 53 only: the firewall chain is
# removed and port 53 skips Suricata), then puts it back by itself. A reboot, `start` or
# `resume` re-locks at once.
#
# Usage: dns-lockdown.sh start|stop|refresh|status|resume
#        dns-lockdown.sh pause [MINUTES]     (default 10, at most 60)

CHAIN=DNSLOCK
PAUSE_CHAIN=DNSLOCK-PAUSE
REARM_UNIT=dns-lockdown-rearm
CGROUP=system.slice/ctrld.service
# tests/firewall-netns.sh points this at a scratch directory; it is empty in normal use
R=${DNS_LOCKDOWN_TEST_ROOT:-}
PAUSE_MARK=$R/run/dns-lockdown.paused
DOH_LIST=$R/etc/dns-lockdown/doh-resolvers.conf
MODE=block
[ -r "$R/etc/default/dns-lockdown" ] && . "$R/etc/default/dns-lockdown"

log() { echo "dns-lockdown: $*"; logger -t dns-lockdown -- "$*" 2>/dev/null || true; }

# The IPs in the resolver list for one family (4 or 6), comma-separated
doh_ips() {
    [ -r "$DOH_LIST" ] || return 0
    sed -e 's/#.*//' -e 's/[[:space:]]//g' "$DOH_LIST" | awk -v fam="$1" '
        fam == 4 && /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print }
        fam == 6 && /:/ && /^[0-9A-Fa-f:]+$/ { print }' | paste -sd, -
}

remove_rules() {
    for cmd in iptables ip6tables; do
        for hook in OUTPUT FORWARD; do
            while $cmd -D $hook -j $CHAIN 2>/dev/null; do :; done
        done
        $cmd -F $CHAIN 2>/dev/null
        $cmd -X $CHAIN 2>/dev/null
    done
    while iptables -t nat -D OUTPUT -j $CHAIN 2>/dev/null; do :; done
    iptables -t nat -F $CHAIN 2>/dev/null
    iptables -t nat -X $CHAIN 2>/dev/null
    return 0
}

is_paused() { iptables -t mangle -n -L $PAUSE_CHAIN >/dev/null 2>&1; }

remove_pause() {
    for cmd in iptables ip6tables; do
        while $cmd -t mangle -D OUTPUT -j $PAUSE_CHAIN 2>/dev/null; do :; done
        $cmd -t mangle -F $PAUSE_CHAIN 2>/dev/null
        $cmd -t mangle -X $PAUSE_CHAIN 2>/dev/null
    done
    rm -f "$PAUSE_MARK"
    # Only the timer: when the timer is what called us, its service is this very process
    systemctl stop "$REARM_UNIT.timer" 2>/dev/null
    return 0
}

have_ctrld_cgroup() { [ -d "/sys/fs/cgroup/$CGROUP" ]; }

build_filter() {
    local cmd=$1 doh
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
    if [ "$cmd" = ip6tables ]; then doh=$(doh_ips 6); else doh=$(doh_ips 4); fi
    if [ -n "$doh" ]; then
        # tcp-reset / port-unreachable so a blocked DoH client fails over at once instead of hanging
        $cmd -A $CHAIN -p tcp --dport 443 -d "$doh" -j REJECT --reject-with tcp-reset || return 1
        $cmd -A $CHAIN -p udp --dport 443 -d "$doh" -j REJECT || return 1
    fi
    $cmd -I OUTPUT 1 -j $CHAIN || return 1
    $cmd -I FORWARD 1 -j $CHAIN || return 1
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
    if [ -z "$(doh_ips 4)$(doh_ips 6)" ]; then
        log "no resolver IPs in $DOH_LIST: public DoH resolvers are not blocked by IP (re-run controld/install.sh)"
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

# Port 53 leaves the machine untouched while paused: ACCEPT in the mangle table ends that
# table for the packet, so it never reaches Suricata's queue (and its drop rules) below
build_pause() {
    local cmd=$1
    $cmd -t mangle -N $PAUSE_CHAIN || return 1
    for proto in udp tcp; do
        $cmd -t mangle -A $PAUSE_CHAIN -p $proto --dport 53 -j ACCEPT || return 1
    done
    $cmd -t mangle -I OUTPUT 1 -j $PAUSE_CHAIN || return 1
}

pause_rules() {
    local mins=${1:-10} until
    case $mins in
        '' | *[!0-9]*) echo "Usage: $0 pause [MINUTES]"; return 2 ;;
    esac
    if [ "$mins" -lt 1 ] || [ "$mins" -gt 60 ]; then
        echo "MINUTES must be between 1 and 60"; return 2
    fi
    if ! iptables -n -L $CHAIN >/dev/null 2>&1 && ! is_paused; then
        echo "The DNS lockdown isn't active, so there is nothing to pause"; return 1
    fi
    remove_pause
    until=$(date -d "+$mins min" '+%Y-%m-%d %H:%M:%S')
    # Schedule the re-lock before lifting anything: if this fails, stay locked.
    # A calendar time rather than a delay, so a suspended laptop re-locks as soon as it wakes.
    if ! systemd-run --quiet --collect --unit="$REARM_UNIT" --on-calendar="$until" \
        --timer-property=AccuracySec=1s /usr/local/sbin/dns-lockdown.sh start; then
        log "could not schedule the re-lock; not pausing"
        return 1
    fi
    remove_rules
    if ! { build_pause iptables && build_pause ip6tables; }; then
        log "failed to build the pause rules; re-locking"
        remove_pause
        apply_rules
        return 1
    fi
    echo "$until" > "$PAUSE_MARK"
    log "PAUSED until $until: plain DNS (port 53) may leave this machine. Re-lock now with: $0 resume"
}

case ${1:-start} in
    start | resume)
        remove_pause
        apply_rules
        ;;
    stop)
        remove_pause
        remove_rules
        log "removed"
        ;;
    refresh)
        # Called from ctrld's ExecStartPost: a restarted ctrld gets a new cgroup,
        # so the exemption has to be rebuilt. No-op if the lockdown isn't active
        # (or is paused: the re-lock builds it for the current cgroup anyway).
        if iptables -n -L $CHAIN >/dev/null 2>&1; then
            apply_rules
        fi
        ;;
    pause)
        pause_rules "${2:-}"
        ;;
    status)
        if is_paused; then
            echo "== PAUSED until $(cat "$PAUSE_MARK" 2>/dev/null || echo unknown) (re-lock now with: $0 resume)"
        fi
        for cmd in iptables ip6tables; do
            echo "== $cmd filter"
            $cmd -n -v -L $CHAIN 2>/dev/null || echo "(not active)"
        done
        echo "== iptables nat"
        iptables -t nat -n -v -L $CHAIN 2>/dev/null || echo "(not active)"
        ;;
    *)
        echo "Usage: $0 start|stop|refresh|status|resume|pause [MINUTES]"; exit 2 ;;
esac
