#!/bin/bash
# Render edr-hub.nft.in into the firewall file: the values come as arguments, the file goes to stdout.
# install.sh and the unit tests use this one script, so the file that is tested is the file that is installed.
#
#   render-nft.sh --port 8443 --enroll-port 8444 --ssh-port 22 [--admin4 CIDR,CIDR] [--admin6 CIDR,CIDR]
#                 [--hub-user edr-hub] [--template FILE]
#
# Every value is checked before it goes into the file (digits for ports, address characters for the admin
# lists, a plain user name), so an argument cannot add a rule. Exit codes: 0 done, 64 usage error.
set -euo pipefail

HERE="$(dirname "$(readlink -f "$0")")"
TEMPLATE="$HERE/edr-hub.nft.in"
PORT="" ENROLL_PORT="" SSH_PORT="" ADMIN4="" ADMIN6="" HUB_USER="edr-hub"

usage() {
    echo "usage: $0 --port N --enroll-port N --ssh-port N [--admin4 CIDR,...] [--admin6 CIDR,...] [--hub-user NAME] [--template FILE]" >&2
    exit 64
}
die() { echo "render-nft.sh: $*" >&2; exit 64; }

while [[ $# -gt 0 ]]; do
    [[ $# -ge 2 ]] || usage
    case $1 in
        --port) PORT=$2 ;;
        --enroll-port) ENROLL_PORT=$2 ;;
        --ssh-port) SSH_PORT=$2 ;;
        --admin4) ADMIN4=$2 ;;
        --admin6) ADMIN6=$2 ;;
        --hub-user) HUB_USER=$2 ;;
        --template) TEMPLATE=$2 ;;
        *) usage ;;
    esac
    shift 2
done
[[ -n $PORT && -n $ENROLL_PORT && -n $SSH_PORT ]] || usage
[[ -f $TEMPLATE ]] || die "template not found: $TEMPLATE"

check_port() {
    [[ $2 =~ ^[0-9]{1,5}$ ]] && ((10#$2 >= 1 && 10#$2 <= 65535)) || die "$1 is not a port number"
}
check_port --port "$PORT"
check_port --enroll-port "$ENROLL_PORT"
check_port --ssh-port "$SSH_PORT"
[[ $PORT != "$ENROLL_PORT" ]] || die "the fleet and enrollment ports must differ"
[[ $HUB_USER =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "--hub-user is not a plain user name"

# A comma list of CIDRs becomes `elements = { a, b }`; an empty list becomes nothing.
elements() {   # $1 = option name, $2 = list, $3 = character class for one element
    local list=$2 item out="" n=0
    [[ -n $list ]] || return 0
    local IFS=,
    for item in $list; do
        [[ $item =~ $3 ]] || die "$1 holds something that is not an address: $item"
        out+="${out:+, }$item"
        n=$((n + 1))
    done
    ((n <= 4096)) || die "$1 holds too many entries"
    printf 'elements = { %s }' "$out"
}
E4=$(elements --admin4 "$ADMIN4" '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$')
E6=$(elements --admin6 "$ADMIN6" '^[0-9A-Fa-f:]{2,39}(/[0-9]{1,3})?$')

in_block=0
while IFS= read -r line || [[ -n $line ]]; do
    squeezed=${line//[[:space:]]/}
    if [[ $squeezed == "#BEGINssh-admin" ]]; then
        in_block=1
        if [[ -z $E4 && -z $E6 ]]; then
            printf '        tcp dport %s accept\n' "$SSH_PORT"
            continue
        fi
    elif [[ $squeezed == "#ENDssh-admin" ]]; then
        in_block=0
        [[ -n $E4 || -n $E6 ]] || continue
    elif [[ $in_block -eq 1 && -z $E4 && -z $E6 ]]; then
        continue                          # no admin address: the admin lines go
    fi
    if [[ $squeezed == "#"* ]]; then      # comments are copied as they are
        printf '%s\n' "$line"
        continue
    fi
    line=${line//@ADMIN4_ELEMENTS@/$E4}
    line=${line//@ADMIN6_ELEMENTS@/$E6}
    line=${line//@SSH_PORT@/$SSH_PORT}
    line=${line//@ENROLL_PORT@/$ENROLL_PORT}
    line=${line//@PORT@/$PORT}
    line=${line//@HUB_USER@/$HUB_USER}
    printf '%s\n' "$line"
done < "$TEMPLATE"
