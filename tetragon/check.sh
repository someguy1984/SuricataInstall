#!/usr/bin/env bash
# Health check for the native Tetragon install (local_install.sh). Read-only: changes nothing.
#
#   sudo ./check.sh            standard checks, takes a couple of seconds
#   sudo ./check.sh --canary   also reads one byte of /etc/shadow and confirms the alert
#                              travels the whole way: policy -> Tetragon -> journal copy.
#                              This leaves one real "sensitive-files" entry behind
#                              (binary /usr/bin/head), which is the point of the test.
#
# Exit status is non-zero if anything fails. Warnings don't affect it.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "$DIR/config.sh"

ETC=/etc/tetragon
CANARY=0
for arg in "$@"; do
	case $arg in
	--canary) CANARY=1 ;;
	*)
		echo "Unknown option: $arg"
		exit 2
		;;
	esac
done

[[ $EUID -eq 0 ]] || {
	echo "Run as root (sudo $0)"
	exit 1
}

if [[ -t 1 ]]; then G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' B=$'\e[1m' N=$'\e[0m'; else G='' Y='' R='' B='' N=''; fi
PASS=0 WARN=0 FAIL=0
pass() {
	echo "  ${G}PASS${N} $*"
	PASS=$((PASS + 1))
}
warn() {
	echo "  ${Y}WARN${N} $*"
	WARN=$((WARN + 1))
}
fail() {
	echo "  ${R}FAIL${N} $*"
	FAIL=$((FAIL + 1))
}
info() { echo "       $*"; }
section() {
	echo
	echo "${B}== $* ==${N}"
}

section "Services"
if systemctl is-active --quiet tetragon; then pass "tetragon.service is active"; else fail "tetragon.service is not active: nothing is being recorded"; fi
systemctl is-enabled --quiet tetragon 2>/dev/null || warn "tetragon.service is not enabled at boot"
if tetra status 2>/dev/null | grep -q 'running'; then
	pass "Tetragon answers on its socket"
else
	fail "Tetragon does not answer on its socket (tetra status)"
fi
if [[ -f /etc/systemd/system/tetragon.service.d/boot-gate.conf ]]; then
	pass "Boot gate installed (services wait until Tetragon is recording)"
else
	warn "No boot gate: whatever starts before Tetragon at boot goes unrecorded (local_install.sh without --no-boot-gate)"
fi
if systemctl is-active --quiet tetragon-alerts; then
	pass "tetragon-alerts.service is copying policy hits into the journal"
else
	fail "tetragon-alerts.service is not active: policy hits exist only in $TETRAGON_LOG_DIR"
fi

section "Policies"
mapfile -t want < <(sed -n 's/^  name: *"\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$ETC"/tetragon.tp.d/*.yaml 2>/dev/null | sort -u)
loaded=$(tetra tracingpolicy list 2>/dev/null | awk 'NR > 1 { print $2, $3 }')
if [[ ${#want[@]} -eq 0 ]]; then
	fail "No policies in $ETC/tetragon.tp.d"
fi
bad=0
for name in "${want[@]}"; do
	state=$(awk -v n="$name" '$1 == n { print $2 }' <<<"$loaded")
	if [[ $state != enabled ]]; then
		fail "Policy '$name' is ${state:-not loaded}"
		bad=1
	fi
done
[[ ${#want[@]} -gt 0 && $bad -eq 0 ]] && pass "All ${#want[@]} policies are loaded and enabled"
while read -r name _; do
	[[ -n $name ]] || continue
	printf '%s\n' "${want[@]}" | grep -qxF -- "$name" || warn "Policy '$name' is loaded but is not in $ETC/tetragon.tp.d (added by hand?)"
done <<<"$loaded"

section "Configuration"
[[ $(stat -c '%U:%a' "$ETC" 2>/dev/null) == root:700 ]] && pass "$ETC is root-only (what is watched can't be read by other users)" ||
	warn "$ETC is $(stat -c '%U %a' "$ETC" 2>/dev/null): the policies and denylist are readable by others (re-run local_install.sh)"

# Installed copies against the ones next to this script (the checkout, or the root-owned reference copy)
if [[ -d $DIR/policies && -r $ETC/watch-user ]]; then
	tmp=$(mktemp -d)
	if WATCH_USER=$(cat "$ETC/watch-user") render_policies "$tmp" 2>/dev/null; then
		if diff -rq "$tmp" "$ETC/tetragon.tp.d" >/dev/null 2>&1; then
			pass "Installed policies match $DIR/policies (watching $(cat "$ETC/watch-user")'s home)"
		else
			warn "Installed policies differ from $DIR/policies (re-run local_install.sh?)"
		fi
	else
		warn "Could not fill in the policies for user '$(cat "$ETC/watch-user")' to compare them"
	fi
	rm -rf "$tmp"
else
	warn "$ETC/watch-user is missing: installed before the policies were per-user (re-run local_install.sh)"
fi
if [[ -r $DIR/export-denylist.jsonl ]]; then
	if diff -q <(grep -vE '^\s*(#|$)' "$DIR/export-denylist.jsonl") "$ETC/tetragon.conf.d/export-denylist" >/dev/null 2>&1; then
		pass "Export denylist matches $DIR/export-denylist.jsonl"
	else
		warn "Export denylist differs from $DIR/export-denylist.jsonl (re-run local_install.sh?)"
	fi
fi
# A denylist line without an event type or policy also hides that process's policy hits
if [[ -r $ETC/tetragon.conf.d/export-denylist ]]; then
	loose=$(python3 -I -c '
import json, sys
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    try:
        f = json.loads(line)
    except ValueError:
        print("unparsable: " + line[:80]); continue
    if not f.get("event_set") and not f.get("policy_names"):
        print(line[:100])
' "$ETC/tetragon.conf.d/export-denylist")
	if [[ -z $loose ]]; then
		pass "Every denylist line is limited to an event type or one policy"
	else
		warn "Denylist lines that hide everything a matching process does, policy hits included:"
		sed 's/^/       /' <<<"$loose"
	fi
fi

section "Event log"
LOG=$TETRAGON_LOG_DIR/tetragon.log
if [[ -s $LOG ]]; then
	age=$(($(date +%s) - $(stat -c %Y "$LOG")))
	[[ $age -lt 600 ]] && pass "tetragon.log written ${age}s ago" || warn "tetragon.log not written for ${age}s"
	[[ $(stat -c %a "$LOG") == 600 ]] && pass "tetragon.log is root-only (600)" || warn "tetragon.log is mode $(stat -c %a "$LOG"), expected 600"
	info "Size: $(du -sh "$TETRAGON_LOG_DIR" | cut -f1) in $TETRAGON_LOG_DIR ($(find "$TETRAGON_LOG_DIR" -maxdepth 1 -name 'tetragon*' | wc -l) file(s))"
else
	fail "$LOG is missing or empty"
fi

if [[ -f /etc/systemd/system/tetragon-viewer.service ]]; then
	section "Web viewer"
	if systemctl is-active --quiet tetragon-viewer; then pass "tetragon-viewer.service is active"; else warn "tetragon-viewer.service is not active"; fi
	if command -v curl >/dev/null && systemctl is-active --quiet tetragon-viewer; then
		code=$(curl -s -o /dev/null -m 3 -w '%{http_code}' "http://127.0.0.1:$VIEWER_PORT/auth")
		case $code in
		403) pass "The viewer refuses the event stream without its token" ;;
		204) warn "The viewer serves the event log to any local program (no token; re-run local_install.sh)" ;;
		404) warn "The viewer is an older version that serves the event log to any local program (re-run local_install.sh)" ;;
		*) warn "The viewer did not answer on 127.0.0.1:$VIEWER_PORT (HTTP $code)" ;;
		esac
	fi
fi

if [[ $CANARY -eq 1 ]]; then
	section "Canary"
	since=$(date '+%Y-%m-%d %H:%M:%S')
	head -c 1 /etc/shadow >/dev/null
	found=0
	for _ in $(seq 20); do
		if journalctl -t tetragon-alerts --since "$since" -o cat --no-pager 2>/dev/null |
			grep '"policy_name":"sensitive-files"' | grep -q '"binary":"/usr/bin/head"'; then
			found=1
			break
		fi
		sleep 0.5
	done
	if [[ $found -eq 1 ]]; then
		pass "Reading /etc/shadow raised a sensitive-files alert that reached the journal"
	else
		fail "Reading /etc/shadow did not produce an alert in the journal within 10 s (journalctl -t tetragon-alerts)"
	fi
fi

section "Summary"
echo "  ${G}$PASS passed${N}, ${Y}$WARN warning(s)${N}, ${R}$FAIL failure(s)${N}"
[[ $FAIL -eq 0 ]] || exit 1
