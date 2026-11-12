#!/bin/bash
# One look at the whole setup: runs each kit's own check and sums up.
#
#   sudo ./status.sh           Suricata's check.sh, the DNS lockdown's verify.sh, Tetragon's check.sh
#   sudo ./status.sh --quiet   only the problems and the summary
#
# Each check is skipped if that kit isn't installed. verify.sh probes public resolvers to
# prove they are blocked, so expect a few of Suricata's own DNS drops in its log afterwards.
# Exit status is non-zero if any kit reports a failure.
set -uo pipefail

ROOT="$(dirname "$(readlink -f "$0")")"
QUIET=0
for arg in "$@"; do
    case $arg in
        --quiet | -q) QUIET=1 ;;
        *) echo "Unknown option: $arg"; exit 2 ;;
    esac
done
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo $0)"; exit 1; }

if [[ -t 1 ]]; then G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' B=$'\e[1m' N=$'\e[0m'; else G='' Y='' R='' B='' N=''; fi
results=()
bad=0

# run NAME INSTALLED-TEST COMMAND...
run() {
    local name=$1 installed=$2 out rc
    shift 2
    if ! eval "$installed"; then
        results+=("${Y}not installed${N}  $name")
        return
    fi
    echo
    echo "${B}######## $name ########${N}"
    out=$("$@" 2>&1)
    rc=$?
    if [[ $QUIET -eq 1 ]]; then
        grep -E 'FAIL|WARN' <<<"$out" || echo "  (nothing to report)"
    else
        echo "$out"
    fi
    if [[ $rc -eq 0 ]]; then
        results+=("${G}ok${N}             $name")
    else
        results+=("${R}PROBLEMS${N}       $name")
        bad=1
    fi
}

run "Suricata IPS" '[[ -f /etc/systemd/system/suricata.service.d/override.conf ]]' "$ROOT/check.sh"
run "Control D DNS lockdown" '[[ -f /etc/systemd/system/dns-lockdown.service ]]' "$ROOT/controld/verify.sh"
run "Tetragon" '[[ -f /etc/systemd/system/tetragon.service ]]' "$ROOT/tetragon/check.sh"

echo
echo "${B}######## Summary ########${N}"
printf '  %s\n' "${results[@]}"
if systemctl is-active --quiet ips-watch.timer; then
    echo "  ${G}ok${N}             Alerting (ips-watch.timer; recent alerts: journalctl -t ips-alert -n 20)"
else
    echo "  ${Y}not installed${N}  Alerting: nothing notifies you of problems (sudo $ROOT/watch/install.sh)"
fi
exit $bad
