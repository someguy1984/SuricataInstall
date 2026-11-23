#!/bin/bash
# Health check for the EDR client kit (client PLAN section 8). Installed as /usr/local/sbin/edr-check.
# Read-only: it changes nothing, except that --live runs the canaries (they say what they do first).
#
#   sudo edr-check             all the checks of the installed phase
#   sudo edr-check --audit     also compare every installed file with the install manifest
#   sudo edr-check --local     skip the hub checks (certificate, heartbeat, hub liveness)
#   sudo edr-check --live      also run the enforcement and SCTP canaries (they can page the hub: read the warning)
#   sudo edr-check --live --yes   run the SCTP canaries on an enrolled or notifying host too
#
# Exit status: 0 all PASS, 1 WARN only, 2 any FAIL, 64 usage error (client PLAN section 15). Hub liveness is its own WARN,
# so a hub outage is never an agent FAIL. A component switched off in local.conf ([kit]) is skipped, never a FAIL.
# On a paused host (pause.json with an `until` in the future) the DNS lock, the ban counts and the policy modes are WARN.
#
# What only reads files is done by `edr-agent checks SECTION` (unit-tested); this script holds the checks that
# need the live system: systemctl, nft, ss, tetra, dnscrypt-proxy, setpriv.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f $DIR/edr-agent.py ]]; then
	AGENT_PY="$DIR/edr-agent.py"
else
	AGENT_PY="$DIR/agent/edr-agent.py"
fi
ROOT_PREFIX="${EDR_AGENT_ROOT:-}"
SURICATA_YAML="${EDR_SURICATA_YAML:-/etc/suricata/suricata.yaml}"
LIVE=0 AUDIT=0 LOCAL=0 YES=0

usage() {
	cat >&2 <<'EOF'
usage: edr-check [--live [--yes]] [--audit] [--local]
  --live    also run the canaries (read one byte of /etc/shadow; an exec the policy must kill; SCTP sockets it must kill)
  --yes     with --live: run the SCTP canaries even when the host is enrolled or edr-notify is configured (they page)
  --audit   compare installed files with the install manifest (WARN on a difference)
  --local   skip the hub checks
EOF
}

for arg in "$@"; do
	case $arg in
	--live) LIVE=1 ;;
	--audit) AUDIT=1 ;;
	--local) LOCAL=1 ;;
	--yes) YES=1 ;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "edr-check: unknown option: $arg" >&2
		usage
		exit 64
		;;
	esac
done
if ((YES && !LIVE)); then
	echo "edr-check: --yes only means something with --live" >&2
	usage
	exit 64
fi

if [[ -z $ROOT_PREFIX && $EUID -ne 0 ]]; then
	echo "edr-check: run as root (sudo edr-check)" >&2
	exit 2
fi

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
skip() { echo "  SKIP $*"; }
section() {
	echo
	echo "${B}== $* ==${N}"
}

have() { command -v "$1" >/dev/null 2>&1; }
active() { systemctl is-active --quiet "$1" 2>/dev/null; }
agent() { /usr/bin/python3 -I "$AGENT_PY" "$@"; }

# Print the LEVEL<TAB>text lines of `edr-agent checks SECTION` through pass, warn and fail.
py_section() {
	local out level text
	local -a extra=()
	((LOCAL)) && extra=(--local)
	if ! out=$(agent checks "$1" "${extra[@]}" 2>&1); then
		warn "the $1 checks could not run: ${out:0:120}"
		return
	fi
	while IFS=$'\t' read -r level text; do
		case $level in
		PASS) pass "$text" ;;
		WARN) warn "$text" ;;
		FAIL) fail "$text" ;;
		INFO) info "$text" ;;
		"") ;;
		*) warn "unexpected output from the $1 checks: ${level:0:40}" ;;
		esac
	done <<<"$out"
}

value() { agent checks value "$1" 2>/dev/null || true; }
conf() { value "conf:$1"; }
is_on() { [[ $(conf "$1") =~ ^(on|true|yes|1)$ ]]; }

PHASE="$(value phase)"
[[ $PHASE =~ ^P(1a|1b|2)$ ]] || PHASE=P2
phase_ge() {
	local order="P1a P1b P2" have_i=0 need_i=0 i=0 p
	for p in $order; do
		[[ $p == "$PHASE" ]] && have_i=$i
		[[ $p == "$1" ]] && need_i=$i
		i=$((i + 1))
	done
	((have_i >= need_i))
}

PAUSE_UNTIL="$(value pause)"
PAUSED=0
[[ -n $PAUSE_UNTIL ]] && PAUSED=1
paused_text() { printf 'paused until %s' "$(date -u -d "@$PAUSE_UNTIL" '+%Y-%m-%d %H:%M:%SZ' 2>/dev/null || echo "$PAUSE_UNTIL")"; }

KIT_WEB=1 KIT_TETRAGON=1 KIT_SURICATA=1 DNS_LOCK=1 LITE=0
is_on kit.web || KIT_WEB=0
is_on kit.tetragon || KIT_TETRAGON=0
is_on kit.suricata || KIT_SURICATA=0
is_on dns.lockdown || DNS_LOCK=0
is_on suricata.lite && LITE=1

echo "${B}edr-check${N}: phase $PHASE installed, $([[ $(value enrolled) == yes ]] && echo enrolled || echo 'local mode')"
if ((PAUSED)); then
	warn "this host is $(paused_text): the DNS lock, the ban counts and the policy modes are expected to differ"
fi

# ---- Kit and install (P1a) -----------------------------------------------------------------------------
section "Kit and install"
py_section kit
if ((AUDIT)); then py_section audit; fi
if active edr-agent.service; then pass "edr-agent.service is active"; else fail "edr-agent.service is not active: nothing is read or reported"; fi
systemctl is-enabled --quiet edr-agent.service 2>/dev/null || warn "edr-agent.service is not enabled at boot"
if active edr-install-rollback.timer || active edr-install-rollback.service; then
	warn "an install rollback timer is armed (edr-install-rollback): confirm with install.sh --confirm from a new SSH session, or let it roll back"
else
	pass "no install rollback timer is armed"
fi
for unit in edr-agent suricata tetragon dnscrypt-proxy; do
	pid=$(systemctl show -p MainPID --value "$unit.service" 2>/dev/null || true)
	[[ $pid =~ ^[0-9]+$ && $pid -gt 1 ]] || continue
	if grep -q 'edr-agent.* (deleted)' "/proc/$pid/maps" 2>/dev/null; then
		warn "$unit.service runs on a library that was deleted by an upgrade: restart it"
	fi
done

# ---- Suricata (P1b) -------------------------------------------------------------------------------------
if phase_ge P1b; then
	section "Suricata"
	if ((!KIT_SURICATA)); then
		skip "Suricata is switched off in local.conf ([kit] suricata = off)"
	else
		if active suricata.service; then pass "suricata.service is active"; else fail "suricata.service is not active: no network detection"; fi
		if [[ -r $SURICATA_YAML ]]; then
			if grep -Eq '^af-packet:' "$SURICATA_YAML"; then pass "Suricata runs in af-packet mode (IDS, no packet queued)"; else fail "no af-packet section in $SURICATA_YAML"; fi
			if grep -Eq '^[[:space:]]*midstream:[[:space:]]*(false|no)\b' "$SURICATA_YAML"; then
				pass "stream.midstream is false"
			else
				fail "stream.midstream is not false: Suricata bans stay off until it is"
			fi
			if grep -Eqi '^[[:space:]]*dump-all-headers:[[:space:]]*(both|request|response|yes)' "$SURICATA_YAML" ||
				grep -Eqi '^[[:space:]]*custom:.*(cookie|authorization)' "$SURICATA_YAML"; then
				fail "dump-all-headers or a custom cookie or authorization field is set in $SURICATA_YAML: secrets would be logged"
			else
				pass "no dump-all-headers and no cookie or authorization field"
			fi
		else
			warn "$SURICATA_YAML is not readable"
		fi
		py_section suricata
		rules=/var/lib/suricata/rules/suricata.rules
		if [[ -f $ROOT_PREFIX$rules ]]; then
			age=$(($(date +%s) - $(stat -c %Y "$ROOT_PREFIX$rules")))
			if ((age > 7 * 86400)); then warn "the rules are $((age / 86400)) days old"; else pass "the rules are $((age / 3600)) hours old"; fi
		else
			warn "$rules is missing"
		fi
		old_src=0
		for f in "$ROOT_PREFIX"/var/lib/suricata/update/cache/*; do
			[[ -f $f ]] || continue
			(($(date +%s) - $(stat -c %Y "$f") > 7 * 86400)) && old_src=$((old_src + 1))
		done
		if ((old_src)); then warn "$old_src rule source(s) were not refreshed in 7 days"; fi
		result=$(systemctl show edr-rules-update.service -p Result --value 2>/dev/null || true)
		case $result in
		success) pass "the last rule update succeeded" ;;
		"") info "no rule update has run yet" ;;
		*) warn "the last rule update ended with: $result" ;;
		esac
		skipped=$(journalctl --namespace=edr -u edr-rules-update.service --since '-3 days' -o cat --no-pager 2>/dev/null | grep -ci 'skip' || true)
		if ((${skipped:-0} >= 3)); then warn "the rule update was skipped $skipped times in 3 days (memory short): the rules are going stale"; fi
		sids=/var/lib/suricata/rules/edr-ban-sids.txt
		if [[ -f $ROOT_PREFIX$sids ]]; then
			if [[ $(stat -c '%U:%G %a' "$ROOT_PREFIX$sids") == "root:suricata 640" ]]; then pass "edr-ban-sids.txt is root:suricata 0640"; else warn "edr-ban-sids.txt is not root:suricata 0640"; fi
		else
			warn "edr-ban-sids.txt is missing: Suricata bans have no signature list"
		fi
		if [[ -r /var/log/suricata/suricata.log ]] && tail -n 400 /var/log/suricata/suricata.log 2>/dev/null | grep -qi 'offloading'; then
			warn "Suricata logged an offloading warning: check ethtool -k on the capture interface"
		fi
		if have suricata; then
			if "$DIR/files/edr-rules-update" guard >/dev/null 2>&1 || [[ ! -x $DIR/files/edr-rules-update ]]; then
				if have systemd-run && systemd-run --quiet --wait --pipe --collect -p MemoryMax=900M -p Nice=19 -- suricata -T -c "$SURICATA_YAML" >/dev/null 2>&1; then
					pass "the kit's Suricata configuration passes suricata -T (under a 900 MB memory limit)"
				else
					fail "suricata -T rejects the kit's configuration (or ran out of its 900 MB limit)"
				fi
			else
				warn "suricata -T was not run: memory is short (the update guard refused)"
			fi
			hs=$(suricata --build-info 2>/dev/null | grep -i hyperscan | head -n 1 || true)
			[[ -n $hs ]] && info "$hs"
		fi
		addr_text=$(ip -o addr 2>/dev/null || true)
		route_text=$(ip route show 2>/dev/null || true)
		yaml_text=$(cat /etc/suricata/edr-home-net.yaml 2>/dev/null || true)
		while IFS=$'\t' read -r level text; do
			case $level in
			PASS) pass "$text" ;;
			WARN) warn "$text" ;;
			FAIL) fail "$text" ;;
			esac
		done < <(printf '%s\n---\n%s\n---\n%s\n' "$addr_text" "$route_text" "$yaml_text" | agent checks netcheck 2>/dev/null)
	fi
fi

# ---- Bans and conntrack (P1b) ---------------------------------------------------------------------------
if phase_ge P1b; then
	section "Bans and conntrack"
	if have nft; then
		if nft -t list table inet edr >/dev/null 2>&1; then
			pass "nft table inet edr is present"
		elif ((PAUSED)); then
			warn "nft table inet edr is not present: $(paused_text)"
		else
			fail "nft table inet edr is absent: no ban is in force"
		fi
		if nft -t get element inet edr edr_ban4 '{ 169.254.169.254 }' >/dev/null 2>&1 || nft -t get element inet edr edr_feed4 '{ 169.254.169.254 }' >/dev/null 2>&1; then
			fail "169.254.169.254 is in a ban or feed set"
		fi
	else
		warn "nft is not installed"
	fi
	if active edr-bans.path; then pass "edr-bans.path is active"; else fail "edr-bans.path is not active: a new ban waits for the timer (a minute)"; fi
	if active edr-bans.timer; then pass "edr-bans.timer is running"; else warn "edr-bans.timer is not running: a flushed table is not repaired"; fi
	py_section bans
	if have systemd-analyze; then
		slow=$(systemd-analyze critical-chain network-pre.target --no-pager 2>/dev/null | awk '/edr-/ { for (i = 1; i <= NF; i++) if ($i ~ /^\+[0-9.]+(ms|s)$/) { v = $i; sub(/^\+/, "", v); if (v ~ /ms$/) { sub(/ms$/, "", v); v = v / 1000 } else sub(/s$/, "", v); if (v + 0 > 5) print $0 } }' || true)
		if [[ -n $slow ]]; then fail "a kit unit took over 5 s before network-pre.target: ${slow:0:100}"; else pass "no kit unit holds network-pre.target for over 5 s"; fi
	fi
fi

# ---- Tetragon (P1a) -------------------------------------------------------------------------------------
section "Tetragon"
if ((!KIT_TETRAGON)); then
	skip "Tetragon is switched off in local.conf ([kit] tetragon = off)"
else
	if active tetragon.service; then pass "tetragon.service is active"; else fail "tetragon.service is not active: no process events, no enforcement"; fi
	pin=${EDR_TETRAGON_PIN:-}
	if [[ -z $pin && -r $DIR/tetragon/config.sh ]]; then
		pin=$(sed -n 's/^[[:space:]]*TETRAGON_VERSION=\(.*\)$/\1/p;s/^[[:space:]]*: "\${TETRAGON_VERSION:=\(.*\)}"$/\1/p' "$DIR/tetragon/config.sh" | head -n 1 | tr -d '"v')
	fi
	if have tetra; then
		running=$(tetra version 2>/dev/null | grep -i 'server' | head -n 1 || true)
		if [[ -n $pin ]]; then
			if [[ $running == *"$pin"* ]]; then pass "Tetragon runs the pinned version $pin"; else warn "Tetragon is not at the pinned version $pin (${running:-unknown})"; fi
		fi
		list=$(tetra tracingpolicy list 2>/dev/null || true)
		for name in $(value tp_names); do
			if grep -Eq "(^|[[:space:]])$name([[:space:]]|\$)" <<<"$list"; then
				pass "policy $name is loaded"
			else
				fail "policy $name is rendered but not loaded"
			fi
		done
		if ((LITE)); then
			mb=$(awk '/MB/ { for (i = 1; i < NF; i++) if ($(i + 1) == "MB") s += $i } END { print int(s) }' <<<"$list")
			if ((${mb:-0} > 150)); then warn "kernel memory of the policies is ${mb} MB, over 150 MB on --lite"; fi
		fi
	else
		warn "tetra is not installed: policy state could not be listed"
	fi
	if have ss; then
		bad=$(ss -ltnpH 2>/dev/null | awk '/tetragon/ && $4 !~ /^(127\.0\.0\.1|\[::1\]):/ { print $4 }' | head -n 3 | tr '\n' ' ')
		if [[ -n $bad ]]; then fail "Tetragon listens on a non-loopback address: ${bad}(health-server-address must be 127.0.0.1)"; else pass "Tetragon listens on loopback only"; fi
	fi
	py_section tetragon
fi

# ---- DNS (P1b) ------------------------------------------------------------------------------------------
if phase_ge P1b; then
	section "DNS"
	if ((!DNS_LOCK)); then
		skip "[dns] lockdown = off: the DNS lock checks are skipped"
	else
		if have dnscrypt-proxy; then
			if dnscrypt-proxy -check -config /etc/dnscrypt-proxy/dnscrypt-proxy.toml >/dev/null 2>&1; then pass "dnscrypt-proxy -check passes"; else fail "dnscrypt-proxy -check fails"; fi
		else
			fail "dnscrypt-proxy is not installed"
		fi
		names=$(conf dns.resolve_check | tr ',' ' ')
		[[ -n ${names// /} ]] || names=example.com
		for n in $names; do
			if getent ahosts "$n" >/dev/null 2>&1; then pass "lookup of $n works"; else fail "lookup of $n fails"; fi
		done
		if have resolvectl; then
			status=$(resolvectl status 2>/dev/null || true)
			glob=$(awk '/^Global/ { g = 1; next } /^(Link|$)/ { g = 0 } g && /DNS Servers:|Current DNS Server:/ { print }' <<<"$status")
			if [[ -n $glob && $glob != *127.0.2.1* ]]; then warn "resolved's Global scope lists a server other than 127.0.2.1"; fi
			if awk '/^Link/ { l = $0 } /Domains:.*~\./ { print l }' <<<"$status" | grep -q .; then
				warn "a link has Domains=~. pointing queries away from the proxy"
			fi
		fi
		if have nft; then
			if nft -t list table inet edr_dns >/dev/null 2>&1; then
				pass "nft table inet edr_dns (the lock) is present"
				stamp=$(nft -t list set inet edr_dns stamp4 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
				doh=$(nft -t list set inet edr_dns doh4 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
				both=$(comm -12 <(printf '%s\n' "$stamp") <(printf '%s\n' "$doh") | tr '\n' ' ')
				if [[ -n ${both// /} ]]; then fail "the stamp and block-list sets overlap: ${both}(the kit would block its own resolver)"; else pass "stamp and block-list sets are disjoint"; fi
			elif ((PAUSED)); then
				warn "nft table inet edr_dns is not present: $(paused_text)"
			else
				fail "nft table inet edr_dns is absent: plain DNS is not locked"
			fi
		fi
		if ((!PAUSED)); then
			if active edr-dns-watch.timer; then pass "edr-dns-watch.timer is active"; else fail "edr-dns-watch.timer is not active: a failing proxy is not worked around"; fi
		fi
		if id _dnscrypt-proxy >/dev/null 2>&1; then pass "the exempt uid _dnscrypt-proxy exists"; else fail "user _dnscrypt-proxy does not exist: the lock cannot load"; fi
		if have setpriv && have python3; then
			probe='import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
q=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
try:
    s.sendto(q,("9.9.9.9",53)); s.recvfrom(512)
except OSError:
    sys.exit(1)
sys.exit(0)'
			if timeout 6 setpriv --reuid 65534 --regid 65534 --clear-groups /usr/bin/python3 -I -c "$probe" >/dev/null 2>&1; then
				if ((PAUSED)); then warn "a plain query to 9.9.9.9:53 succeeds: expected, $(paused_text)"; else fail "a plain query to 9.9.9.9:53 as uid 65534 succeeded: the lock does not hold"; fi
			else
				pass "a plain query to 9.9.9.9:53 as a non-proxy uid fails, as it should"
			fi
		fi
		links=$(ip -o link 2>/dev/null | awk -F': ' '$2 ~ /^(docker|br-|veth|tailscale|wg|tun|tap|zt)/ { sub(/@.*/, "", $2); print $2 }' | sort -u | tr '\n' ' ')
		[[ -n $links ]] && info "containers and tunnels detected: $links(their DNS may not follow the lock)"
		py_section dns
	fi
fi

# ---- Agent and local alerts (P1a; hub checks P2) --------------------------------------------------------
section "Agent and local alerts"
py_section agent

# ---- Disk (P1a; Suricata paths P1b) ---------------------------------------------------------------------
section "Disk"
py_section disk
if active edr-diskguard.timer; then pass "edr-diskguard.timer is active"; else warn "edr-diskguard.timer is not active: log caps are not enforced"; fi

# ---- nginx, packages and kernel (P1a; posture lines from P1b) -------------------------------------------
section "nginx, packages and kernel"
if ((!KIT_WEB)); then
	skip "the web part is switched off in local.conf ([kit] web = off)"
else
	py_section nginx
	if have modprobe; then
		if modprobe -n -v sctp 2>/dev/null | grep -q 'install /bin/false'; then
			pass "the sctp module is blocked (modprobe shows install /bin/false)"
		else
			warn "the sctp module is not blocked"
		fi
	fi
	if grep -q '^sctp ' /proc/modules 2>/dev/null; then warn "the sctp module is loaded"; else pass "the sctp module is not loaded"; fi
fi

# ---- --live canaries (P1a) --------------------------------------------------------------------------------
sctp_safe() {
	# the gate of client PLAN section 4.3: enforcing (or blocked), ss --sctp empty, no SCTP user installed
	local mode
	mode=$(value policy_mode:sctp-socket)
	[[ $mode == enforce/loaded ]] || { modprobe -n -v sctp 2>/dev/null | grep -q 'install /bin/false' || return 1; }
	if have ss && [[ -n $(ss -H --sctp -a 2>/dev/null) ]]; then return 2; fi
	if dpkg-query -W -f '${Package}\n' 'lksctp-tools' 'libsctp1' 'libusrsctp*' 2>/dev/null | grep -q .; then return 3; fi
	return 0
}

wait_for_alert() {
	# wait_for_alert PATTERN: the agent's journal copy shows it within 10 s
	local i
	for i in 1 2 3 4 5 6 7 8 9 10; do
		if journalctl --namespace=edr -u edr-agent.service --since '-1 min' -o cat --no-pager 2>/dev/null | grep -q -- "$1"; then return 0; fi
		sleep 1
	done
	return 1
}

wait_for_log() {
	# wait_for_log PATTERN: Tetragon's log shows it within 10 s
	local i
	for i in 1 2 3 4 5 6 7 8 9 10; do
		if tail -n 400 "$ROOT_PREFIX/var/log/tetragon/tetragon.log" 2>/dev/null | grep -q -- "$1"; then return 0; fi
		sleep 1
	done
	return 1
}

if ((LIVE)); then
	section "Canaries (--live)"
	cat <<'EOF'
  These canaries run real events through the live policies. They change nothing durable, but:
    - one reads a single byte of /etc/shadow (a "sensitive-files" entry for /usr/bin/head stays in the Tetragon log);
    - one starts a program the policy must kill (an INFO "edr-canary" event, which never pages);
    - the SCTP canaries open SCTP sockets that the "sctp-socket" policy must kill. That is an ordinary CRITICAL
      event, with NO test marker (an intruder could set one): on an enrolled host it PAGES THE HUB on every
      channel, and next to a recent crash or bigconn signal it can complete the hub's "attempt contained" chain.
      Open a maintenance window for this host on the hub first (edr-hub host NAME maintenance --for 30m).
EOF
	if ((!KIT_TETRAGON)); then
		skip "Tetragon is switched off in local.conf: no canary can run"
	else
		web_user=$(value web_user)
		if ((KIT_WEB)) && [[ -n $web_user ]] && id "$web_user" >/dev/null 2>&1; then
			run_uid=$(id -u "$web_user")
			run_gid=$(id -g "$web_user")
		else
			run_uid=65534 run_gid=65534
			web_user=nobody
		fi
		info "canaries run as $web_user (uid $run_uid)"
		# 1. the shadow canary: the same idea as tetragon/check.sh --canary
		if head -c 1 /etc/shadow >/dev/null 2>&1; then
			if wait_for_log '/etc/shadow'; then pass "canary: reading /etc/shadow was recorded by Tetragon"; else fail "canary: Tetragon did not record a read of /etc/shadow within 10 s"; fi
		else
			warn "canary: /etc/shadow could not be read"
		fi
		# 2. the enforcement canary: must die by SIGKILL, and an event must follow
		canary=/usr/libexec/edr/canary
		if [[ -x $canary ]] && have setpriv; then
			setpriv --reuid "$run_uid" --regid "$run_gid" --clear-groups "$canary" -c 'exec /bin/true' >/dev/null 2>&1
			rc=$?
			if ((rc == 137)); then
				pass "canary: the enforcement canary was killed by SIGKILL"
				if wait_for_log 'edr-canary'; then pass "canary: its event reached the Tetragon log"; else fail "canary: no edr-canary event followed the kill"; fi
			else
				fail "canary: the enforcement canary was NOT killed (exit $rc): enforcement does not work on this kernel"
			fi
		else
			warn "canary: $canary or setpriv is missing"
		fi
		# 3. the SCTP canaries
		notify=$(value notify)
		sctp_safe
		gate=$?
		if ((gate != 0)); then
			case $gate in
			1) skip "SCTP canaries: sctp-socket is not enforcing and the module is not blocked" ;;
			2) skip "SCTP canaries: an SCTP socket is in use on this host (ss --sctp is not empty)" ;;
			*) skip "SCTP canaries: an SCTP user (lksctp-tools or similar) is installed" ;;
			esac
		elif [[ $(value enrolled) == yes || $notify == yes ]] && ((!YES)); then
			warn "SCTP canaries not run: this host is enrolled or notifies, so they would page. Open a hub maintenance window and run again with --yes"
		else
			for form in "socket.SOCK_STREAM, 132" "socket.SOCK_SEQPACKET, 0"; do
				setpriv --reuid "$run_uid" --regid "$run_gid" --clear-groups /usr/bin/python3 -I -c "import socket; socket.socket(socket.AF_INET, $form)" >/dev/null 2>&1
				rc=$?
				if ((rc == 137)); then
					if wait_for_alert 'tetragon.sctp-socket'; then pass "canary: SCTP socket ($form) was killed and the agent's journal shows the event"; else fail "canary: SCTP socket ($form) was killed but no event reached the agent's journal within 10 s"; fi
				else
					fail "canary: SCTP socket ($form) was NOT killed (exit $rc)"
				fi
			done
			if [[ $(value enrolled) == yes ]]; then info "confirm on the hub within 2 minutes that the two CRITICAL events arrived"; fi
		fi
		# 4. nothing fires on the root helpers
		logf=$ROOT_PREFIX/var/log/tetragon/tetragon.log
		before=$(wc -l <"$logf" 2>/dev/null || echo 0)
		systemctl start --wait edr-inventory.service >/dev/null 2>&1 || true
		sleep 3
		fired=$(tail -n +"$((before + 1))" "$logf" 2>/dev/null | grep -F '"policy_name"' | grep -F '/usr/local/lib/edr-agent/' | head -n 1 || true)
		if [[ -n $fired ]]; then fail "a Tetragon policy fired on a root helper (edr-inventory): ${fired:0:120}"; else pass "no policy fired on the root helpers"; fi
	fi
fi

# ---- Result -------------------------------------------------------------------------------------------------
echo
echo "${B}Result:${N} $PASS passed, $WARN warning(s), $FAIL failure(s)"
if ((FAIL > 0)); then exit 2; fi
if ((WARN > 0)); then exit 1; fi
exit 0
