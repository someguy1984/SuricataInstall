#!/bin/bash
# Drive the server_edr_solution mock environment (two Ubuntu 26.04 "droplets" on a private network).
#
#   ./mock.sh up            build images and start; waits until both boxes are healthy
#   ./mock.sh test          smoke test; exits non-zero if anything fails
#   ./mock.sh status        containers, health, addresses
#   ./mock.sh shell hub|web a root shell inside a box
#   ./mock.sh logs hub|web  follow that box's journal
#   ./mock.sh down [--volumes]   stop and remove (--volumes also forgets the mock certificates)
#
# With the real installers (first run 2026-11-24: see README.md, "First run"), in this order:
#   ./mock.sh dist          make dist on this machine; copy the tarballs and their hashes into the boxes
#   ./mock.sh install-hub   disable the placeholder; unpack, check the hash, install.sh --plan, install.sh --yes
#   ./mock.sh install-web   the client in local mode (MOCK_SURICATA=1 adds Suricata; MOCK_WEB_FLAGS="..." adds flags)
#   ./mock.sh enroll        token on the hub box, carried in a file to the web box, edr-agent enroll
#   ./mock.sh e2e           the end-to-end checks, each PASS or FAIL; exits non-zero on any FAIL
#   ./mock.sh uninstall     both uninstallers, then the residue checks; puts the placeholder back
#
#   MOCK_CAPS=1 ./mock.sh ...    the boxes without `privileged` (compose.caps.yaml; not boot-tested yet)
#   MOCK_HTTP_PORT=18080 MOCK_HTTPS_PORT=18443 ./mock.sh ...   publish the site on other loopback ports
#                                (when 80 or 443 is taken here; give the same values to every subcommand)
#
# Use rootless Docker only (see README.md; the boxes run privileged): a rootful daemon is refused
# unless MOCK_ALLOW_ROOTFUL=1 is set. If DOCKER_HOST is unset and the system socket is missing, the
# current user's rootless socket ($XDG_RUNTIME_DIR/docker.sock) is used.
set -euo pipefail

SELF=$(readlink -f "$0")
cd "$(dirname "$SELF")"

if [[ -z ${DOCKER_HOST:-} && ! -S /var/run/docker.sock ]]; then
    rt=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
    [[ -S $rt/docker.sock ]] && export DOCKER_HOST=unix://$rt/docker.sock
fi

COMPOSE=(-f compose.yaml)
if [[ ${MOCK_CAPS:-0} == 1 ]]; then COMPOSE+=(-f compose.caps.yaml); fi
dc() { docker compose "${COMPOSE[@]}" "$@"; }

export MOCK_HTTP_PORT=${MOCK_HTTP_PORT:-80} MOCK_HTTPS_PORT=${MOCK_HTTPS_PORT:-443}   # compose.yaml reads them
REPO=$(cd ../.. && pwd)          # the repository root: `make dist` runs there, on this machine
HUB_IP=10.77.0.10
HUB_PORT=8443
DIST=/root/mock-dist             # inside each box: the tarballs, their hashes, the unpacked trees

# The boxes run privileged. On a rootful daemon that is root on this machine: the installers
# tried in them would change the host's modules and sysctls, not the box's.
refuse_rootful() {
    local opts
    [[ ${MOCK_ALLOW_ROOTFUL:-0} == 1 ]] && return 0
    # No answer from the daemon: docker compose reports that better than this could
    opts=$(docker info -f '{{.SecurityOptions}}' 2>/dev/null) || return 0
    [[ $opts == *rootless* ]] && return 0
    echo "mock: this Docker daemon is not rootless, and the boxes run privileged (see README.md)." >&2
    echo "      Use rootless Docker. In a throwaway VM only: MOCK_ALLOW_ROOTFUL=1 $0 ${1:-}" >&2
    exit 1
}

# A published port that something else on this machine holds: say so before docker does, with the way round it.
# The mock's own web box holding it (a second `up`) is fine.
port_free() {   # port_free PORT VARIABLE
    ss -Hltn "sport = :$1" 2>/dev/null | grep -q "127.0.0.1:$1\|0.0.0.0:$1\|\*:$1" || return 0
    [[ -n $(docker port edr-mock-web-1 2>/dev/null) ]] && return 0
    echo "mock: 127.0.0.1:$1 is taken on this machine. Publish the site elsewhere: $2=<port> $0 up" >&2
    exit 1
}

wait_healthy() {
    local svc state i
    for svc in hub web; do
        for ((i = 0; i < 60; i++)); do
            state=$(docker inspect -f '{{.State.Health.Status}}' "edr-mock-$svc-1" 2>/dev/null || echo missing)
            [[ $state == healthy ]] && break
            sleep 2
        done
        if [[ $state != healthy ]]; then
            echo "mock: $svc is $state after 120 s; last journal lines:" >&2
            dc exec -T "$svc" journalctl -b --no-pager -n 40 >&2 || true
            return 1
        fi
        echo "mock: $svc healthy"
    done
}

pass=0 fail=0
check() {   # check DESCRIPTION COMMAND...
    local what=$1; shift
    if out=$("$@" 2>&1); then
        printf '  PASS  %s\n' "$what"; pass=$((pass + 1))
    else
        printf '  FAIL  %s\n' "$what"; printf '        %s\n' "${out//$'\n'/$'\n'        }" | head -8
        fail=$((fail + 1))
    fi
}

run_tests() {
    echo "== web.dev.local from this machine (loopback-published ports $MOCK_HTTP_PORT and $MOCK_HTTPS_PORT)"
    local http="http://web.dev.local:$MOCK_HTTP_PORT" https="https://web.dev.local:$MOCK_HTTPS_PORT"
    local rh="web.dev.local:$MOCK_HTTP_PORT:127.0.0.1" rs="web.dev.local:$MOCK_HTTPS_PORT:127.0.0.1"
    check "$http serves the PHP 8.5 hello page" \
        bash -c 'p=$(curl -fsS --max-time 10 --resolve "$1" "$2/") &&
                 grep -q "Hello, world" <<<"$p" && grep -q "PHP 8\.5\." <<<"$p" && grep -q "plain HTTP" <<<"$p"' _ "$rh" "$http"
    check "$https serves it over TLS with HTTP/2" \
        bash -c 'p=$(curl -fsSk --http2 --max-time 10 --resolve "$1" "$2/") &&
                 grep -q "HTTPS, HTTP/2.0" <<<"$p"' _ "$rs" "$https"
    check "the certificate names web.dev.local" \
        bash -c 'openssl s_client -connect "127.0.0.1:$1" -servername web.dev.local </dev/null 2>/dev/null |
                 openssl x509 -noout -ext subjectAltName | grep -q "DNS:web.dev.local"' _ "$MOCK_HTTPS_PORT"
    check "dotfiles are refused (/.env -> 403)" \
        bash -c '[[ $(curl -s -o /dev/null -w "%{http_code}" --resolve "$1" "$2/.env") == 403 ]]' _ "$rh" "$http"

    echo "== inside the web box"
    check "Ubuntu 26.04" dc exec -T web grep -q 'VERSION_ID="26.04"' /etc/os-release
    check "systemd is PID 1 and the system is running" \
        dc exec -T web bash -c '[[ $(ps -o comm= -p 1) == systemd ]] && [[ $(systemctl is-system-running --wait) == running ]]'
    check "php-fpm 8.5 and nginx active" dc exec -T web systemctl is-active --quiet php8.5-fpm nginx
    check "nginx package is the USN-9159-1 fixed build or newer (NGINX2Root)" \
        dc exec -T web bash -c 'v=$(dpkg-query -W -f="\${Version}" nginx) && dpkg --compare-versions "$v" ge 1.28.3-2ubuntu1.13'

    echo "== private network (edr_vpc, 10.77.0.0/24)"
    check "web reaches the hub placeholder at 10.77.0.10:8443 over TLS 1.3" \
        dc exec -T web bash -c 'openssl s_client -connect 10.77.0.10:8443 -tls1_3 </dev/null 2>/dev/null | grep -q "TLSv1.3"'
    check "web resolves hub.dev.local to 10.77.0.10" \
        dc exec -T web bash -c '[[ $(getent hosts hub.dev.local | cut -d" " -f1) == 10.77.0.10 ]]'
    check "hub reaches https://web.dev.local over the private network" \
        dc exec -T hub bash -c 'curl -fsSk --max-time 10 https://web.dev.local/ | grep -q "Hello, world"'
    check "the hub publishes no ports to this machine" \
        bash -c '[[ -z $(docker port edr-mock-hub-1) ]]'

    echo
    echo "mock: $pass passed, $fail failed"
    ((fail == 0))
}

# ---- the real installers ------------------------------------------------------------------------------------
die() { echo "mock: $*" >&2; exit 1; }
hubx() { dc exec -T hub "$@"; }
webx() { dc exec -T web "$@"; }

# Poll a command for LIMIT seconds; the last try's output is what a failing check shows.
wait_ok() {   # wait_ok LIMIT COMMAND...
    local limit=$1 i
    shift
    for ((i = 0; i < limit; i += 3)); do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 3
    done
    "$@"
}

# The newest tarball of one kind built by `make dist`
dist_tarball() {   # dist_tarball client|hub
    local f
    f=$(ls "$REPO/dist/$1/edr-$1-"*.tar.gz 2>/dev/null | sort | tail -n 1)
    [[ -n $f ]] || die "no $1 tarball in $REPO/dist/$1: run ./mock.sh dist"
    printf '%s\n' "$f"
}

# What the box holds: the tarball and a hash made here, on this machine, from the file that is copied.
# (A hash that travelled beside the tarball proves nothing: client plan section 7.)
copy_into_box() {   # copy_into_box hub|web TARBALL
    local box=$1 tb=$2 name
    name=$(basename "$tb")
    dc exec -T "$box" mkdir -p "$DIST"
    dc cp "$tb" "$box:$DIST/$name"
    (cd "$(dirname "$tb")" && sha256sum "$name") | dc exec -T "$box" tee "$DIST/$name.sha256" >/dev/null
    echo "mock: $name -> $box:$DIST/ (sha256 $(cut -c1-16 <<<"$(sha256sum "$tb")")...)"
}

cmd_dist() {
    command -v make >/dev/null || die "make is needed on this machine"
    make -C "$REPO" dist
    copy_into_box hub "$(dist_tarball hub)"
    copy_into_box web "$(dist_tarball client)"
}

# The hub: the placeholder holds :8443, so it goes first. The mock's addresses: the hub is 10.77.0.10 on the
# private network, the web box 10.77.0.20 is its one admin address (nothing in the mock runs ssh to the hub).
# --max-db-size keeps the disk pre-flight small for a container.
HUB_INSTALL_FLAGS=(--public-ip "$HUB_IP" --admin-ip 10.77.0.20/32 --port "$HUB_PORT" --enroll-port 8444 --ui-port 8450
                   --max-db-size 256M)

cmd_install_hub() {
    hubx systemctl disable --now mock-hub-placeholder
    hubx bash -s -- "${HUB_INSTALL_FLAGS[@]}" <<'BOX'
set -euo pipefail
cd /root/mock-dist
sha256sum -c --quiet edr-hub-*.tar.gz.sha256
rm -rf hub-tree
mkdir hub-tree
tar -xzf edr-hub-*.tar.gz -C hub-tree
cd hub-tree/edr-hub-*/
echo "== install.sh --plan"
./install.sh --plan "$@"
echo "== install.sh --yes"
./install.sh --yes "$@"
BOX
}

cmd_install_web() {
    local flags=(--no-kernel --no-tetragon --droplet-id mock-web --yes)
    [[ ${MOCK_SURICATA:-0} == 1 ]] || flags+=(--no-suricata)
    # shellcheck disable=SC2206   # extra flags, split on spaces on purpose
    flags+=(${MOCK_WEB_FLAGS:-})
    webx bash -s -- "${flags[@]}" <<'BOX'
set -euo pipefail
cd /root/mock-dist
sha256sum -c --quiet edr-client-*.tar.gz.sha256
rm -rf client-tree
mkdir client-tree
tar -xzf edr-client-*.tar.gz -C client-tree
cd client-tree/edr-client-*/
echo "== install.sh --plan"
./install.sh --plan "$@"
echo "== install.sh (local mode: no --hub)"
./install.sh "$@"
BOX
}

PENDING_TOKEN_PY='
import json, sys
for line in sys.stdin:
    try:
        t = json.loads(line)
    except ValueError:
        continue
    if t.get("name") == "web" and t.get("state") == "pending":
        print(t.get("id", ""))'

# The token goes from the hub box to the web box through two pipes and a file: it is never an argument
# and never on this machine's disk.
cmd_enroll() {
    local py='import json, sys; print(json.load(sys.stdin)["tokens"][0]["token"])' id
    # a second run: the hub refuses a new token while one for the same name is pending, so that one is revoked first
    for id in $(hubx bash -c 'edr-hub token list --json | python3 -I -c "$1"' _ "$PENDING_TOKEN_PY"); do
        hubx edr-hub token revoke "$id" >/dev/null && echo "mock: revoked the pending token $id left by an earlier run"
    done
    hubx edr-hub token create --name web --ttl 1h --json | python3 -I -c "$py" |
        webx sh -c 'umask 077; cat > /root/mock-dist/web.token'
    # no --droplet-id here: install-web gave it, edr-droplet-id.service wrote it, and enroll refuses a second one
    webx edr-agent enroll --hub "$HUB_IP:$HUB_PORT" --token-file "$DIST/web.token"
    webx rm -f "$DIST/web.token"
    # what the hub says right after: pending until the first heartbeat (the e2e check reads this note)
    host_state | hubx tee "$DIST/web.state-after-enroll" >/dev/null || true
    echo "mock: web enrolled; the hub shows it as $(hubx cat "$DIST/web.state-after-enroll" 2>/dev/null || echo unknown)"
}

HOST_STATE_PY='
import json, sys
for line in sys.stdin:
    try:
        h = json.loads(line)
    except ValueError:
        continue
    if h.get("name") == "web":
        print(h.get("state", "unknown"))
        sys.exit(0)
sys.exit(1)'
host_state() { hubx bash -c 'edr-hub host list --all --json | python3 -I -c "$1"' _ "$HOST_STATE_PY"; }

EVENT_PY='
import json, sys
kind, sev, marker = sys.argv[1:4]
for line in sys.stdin:
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if e.get("kind") == kind and (not sev or e.get("hub_severity") == sev) and marker in (e.get("summary") or ""):
        sys.exit(0)
sys.exit(1)'
hub_has_event() {   # hub_has_event KIND SEVERITY|"" MARKER|""
    hubx bash -c 'edr-hub events --host web --since 30m --limit 1000 --json | python3 -I -c "$1" "$2" "$3" "$4"' _ "$EVENT_PY" "$1" "$2" "$3"
}

# One recorded Tetragon line, as the agent's reader expects it (the same shape tests/e2e_local.py writes)
TETRAGON_PY='
import json, sys, time
binary = sys.argv[1]
proc = {"exec_id": "mock-e2e", "pid": 4242, "uid": 33, "cwd": "/", "binary": binary, "arguments": "-c id"}
kp = {"process": proc, "parent": {"binary": "/usr/sbin/nginx", "arguments": ""}, "function_name": "security_bprm_check",
      "args": [{"linux_binprm_arg": {"path": binary}}], "policy_name": "nginx-exec", "action": "KPROBE_ACTION_SIGKILL"}
ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000000000Z"
with open("/var/log/tetragon/tetragon.log", "a") as f:
    f.write(json.dumps({"process_kprobe": kp, "node_name": "web", "time": ts}) + "\n")'
append_tetragon_line() {   # append_tetragon_line BINARY
    webx python3 -I -c "$TETRAGON_PY" "$1"
}

# Tetragon cannot run in a box, so install-web passes --no-tetragon and the agent's Tetragon reader is off.
# For the replay it is switched on by hand: the log directory as the installer's step 7 makes it, the key in
# local.conf, and a restart (the agent's unit binds /var/log/tetragon when it starts, and the reader begins at
# the end of the log). tetragon_replay off puts the key back, so edr-check has no Tetragon to miss.
tetragon_replay() {   # tetragon_replay on|off
    local from=off to=on
    [[ $1 == on ]] || { from=on; to=off; }
    webx bash -c 'set -e
        install -d -m 2750 -o root -g edr-agent /var/log/tetragon
        [[ -e /var/log/tetragon/tetragon.log ]] || install -m 0640 -o root -g edr-agent /dev/null /var/log/tetragon/tetragon.log
        sed -i "s/^tetragon = $1\$/tetragon = $2/" /etc/edr-agent/local.conf
        grep -qx "tetragon = $2" /etc/edr-agent/local.conf
        edr-agent apply-config >/dev/null
        systemctl restart edr-agent
        for i in $(seq 30); do systemctl is-active --quiet edr-agent && break; sleep 1; done
        systemctl is-active --quiet edr-agent' _ "$from" "$to"
    sleep 5   # the reader opens the log a moment after the unit is active
}
tripwire_request() { hubx curl -s -o /dev/null --max-time 10 http://web.dev.local/.env || true; }

exit_0_or_1() { local rc=0; "$@" >/dev/null 2>&1 || rc=$?; ((rc <= 1)); }

# The checks are functions, not `bash -c` strings: check() and wait_ok() run them in this shell, where hubx and webx exist.
hub_publishes_nothing() { [[ -z $(docker port edr-mock-hub-1) ]]; }
state_after_enroll_ok() { local s; s=$(hubx cat "$DIST/web.state-after-enroll") && [[ $s == pending || $s == active ]]; }
host_is_active() { [[ $(host_state) == active ]]; }
agent_revoked_and_spooling() {
    local s
    s=$(webx edr-agent status 2>&1 || true)
    grep -q host_revoked <<<"$s" && grep -Eq 'spool: depth [1-9]' <<<"$s"
}

run_e2e() {
    local marker="/tmp/mock-e2e-$$"

    echo "== the hub box"
    check "edr-hub, edr-hub-out and edr-hub-ui are active" hubx systemctl is-active --quiet edr-hub edr-hub-out edr-hub-ui
    check "edr-hub health exits 0 (writer and engine alive)" wait_ok 90 hubx edr-hub health
    check "the table inet edr_hub is loaded" hubx nft list table inet edr_hub
    check "the hub publishes no port to this machine" hub_publishes_nothing

    echo "== the web box"
    check "edr-agent is active" webx systemctl is-active --quiet edr-agent
    check "the host web was pending right after enrollment (or already active)" state_after_enroll_ok
    check "the host web is active at the hub within 2 minutes" wait_ok 120 host_is_active

    echo "== health checks (before the replay switches the Tetragon reader on)"
    check "edr-check on the web box exits 0 or 1" exit_0_or_1 webx edr-check
    check "the hub's check.sh exits 0 or 1" exit_0_or_1 hubx /usr/local/lib/edr-hub/check.sh

    echo "== events reach the hub (within 2 minutes each)"
    tripwire_request
    check "the tripwire request for /.env is a canary.tripwire event in edr-hub events --json" \
        wait_ok 120 hub_has_event canary.tripwire "" ".env"
    check "the agent's Tetragon reader is switched on for the replay" tetragon_replay on
    append_tetragon_line "$marker"
    check "the recorded Tetragon line is a CRITICAL tetragon.nginx-exec event" \
        wait_ok 120 hub_has_event tetragon.nginx-exec CRITICAL "$marker"

    echo "== revoke: the agent gets 403 and keeps spooling"
    check "edr-hub host web revoke succeeds" hubx edr-hub host web revoke
    append_tetragon_line "$marker-after-revoke"
    tripwire_request
    check "edr-agent status shows host_revoked and a spool with at least one event" wait_ok 150 agent_revoked_and_spooling
    check "the Tetragon reader is switched off again" tetragon_replay off

    echo
    echo "mock: $pass passed, $fail failed"
    ((fail == 0))
}

# Nothing of either kit may remain: no table, unit, listening port or process. The placeholder is switched
# on again only after the port check, so :8443 is the hub's to answer for until then.
no_table() {   # no_table BOX TABLE
    ! dc exec -T "$1" nft list table inet "$2" >/dev/null 2>&1
}
no_units() {   # no_units BOX GLOB
    local left
    # systemctl exits 1 when the pattern matches nothing, which is the good case here: only the text counts
    left=$(dc exec -T "$1" bash -c 'systemctl list-unit-files "$1" --no-legend; systemctl list-units --all "$1" --no-legend; true' _ "$2") || return 1
    [[ -z $left ]] || { printf '%s\n' "$left"; return 1; }
}
no_path() {   # no_path BOX PATH...
    local box=$1 left
    shift
    left=$(dc exec -T "$box" bash -c 'for p in "$@"; do [[ -e $p || -L $p ]] && echo "$p"; done; true' _ "$@") || return 1
    [[ -z $left ]] || { printf '%s\n' "$left"; return 1; }
}
no_kit_user_on_web() { ! webx getent passwd edr-agent edr-notify >/dev/null; }
no_listener() {   # no_listener BOX EXTENDED-REGEX-OF-PORTS
    local sockets
    sockets=$(dc exec -T "$1" ss -Hltn) || return 1
    ! awk '{print $4}' <<<"$sockets" | grep -Eq ":($2)\$"
}
no_process() {   # no_process BOX BRACKETED-PATTERN
    ! dc exec -T "$1" pgrep -f "$2" >/dev/null 2>&1
}
nothing_of_the_kit_listens_on_web() {
    local sockets
    sockets=$(webx ss -Hltnp) || return 1
    ! grep -Eq 'edr|dnscrypt' <<<"$sockets"
}

run_residue() {
    echo "== residue in the hub box"
    check "no table inet edr_hub" no_table hub edr_hub
    check "no edr-hub unit file or unit" no_units hub 'edr-hub*'
    check "nothing listens on 8443, 8444 or 8450" no_listener hub '8443|8444|8450'
    check "no edr-hub process" no_process hub '[e]dr_hub'
    check "no code, CLI, firewall file or journal file of the hub is left (the data and the users are kept by a plain uninstall)" no_path hub \
        /usr/local/lib/edr-hub /usr/local/sbin/edr-hub /etc/edr-hub/edr-hub.nft /etc/systemd/journald@edr-hub.conf /etc/apt/apt.conf.d/52edr-hub
    echo "== residue in the web box"
    check "no table inet edr" no_table web edr
    check "no table inet edr_dns" no_table web edr_dns
    check "no table inet edr_isolate" no_table web edr_isolate
    check "no edr unit file or unit" no_units web 'edr-*'
    check "no edr-agent process" no_process web '[e]dr-agent'
    check "no code, configuration or state of the client is left (host-id alone is kept)" no_path web \
        /usr/local/lib/edr-agent /usr/local/sbin/edr-agent /usr/local/sbin/edr-check /usr/local/sbin/edr-uninstall /etc/edr-agent /etc/edr-dns \
        /var/lib/edr-install /var/lib/edr-bans /var/lib/edr-inventory /var/lib/edr-diskguard /var/lib/edr-notify /var/lib/edr-agent/spool \
        /var/lib/edr-agent/identity /etc/modprobe.d/edr-sctp-block.conf /etc/systemd/journald@edr.conf
    check "the users edr-agent and edr-notify are gone" no_kit_user_on_web
    check "nothing of the kit listens in the web box (nginx keeps 80 and 443)" nothing_of_the_kit_listens_on_web
}

cmd_uninstall() {
    echo "== web box: edr-uninstall"
    webx edr-uninstall --plan
    webx edr-uninstall --yes
    echo "== hub box: uninstall.sh"
    hubx bash -s <<'BOX'
set -euo pipefail
cd /root/mock-dist/hub-tree/edr-hub-*/
./uninstall.sh --plan
./uninstall.sh --yes
BOX
    run_residue || true
    hubx systemctl enable --now mock-hub-placeholder
    echo
    echo "mock: $pass passed, $fail failed (the placeholder is back on :$HUB_PORT)"
    ((fail == 0))
}

case ${1:-help} in
    up)
        refuse_rootful up
        port_free "$MOCK_HTTP_PORT" MOCK_HTTP_PORT
        port_free "$MOCK_HTTPS_PORT" MOCK_HTTPS_PORT
        dc up -d --build
        wait_healthy
        echo "mock: up. Add '127.0.0.1 web.dev.local' to /etc/hosts to browse http://web.dev.local:$MOCK_HTTP_PORT and https://web.dev.local:$MOCK_HTTPS_PORT"
        ;;
    test) refuse_rootful test; run_tests ;;
    status)
        refuse_rootful status
        dc ps
        for svc in hub web; do
            echo "-- $svc"; dc exec -T "$svc" ip -br -4 addr show scope global 2>/dev/null || true
        done
        ;;
    shell) refuse_rootful shell; dc exec "${2:?shell hub|web}" bash ;;
    logs) refuse_rootful logs; dc exec "${2:?logs hub|web}" journalctl -f ;;
    dist) refuse_rootful dist; cmd_dist ;;
    install-hub) refuse_rootful install-hub; cmd_install_hub ;;
    install-web) refuse_rootful install-web; cmd_install_web ;;
    enroll) refuse_rootful enroll; cmd_enroll ;;
    e2e) refuse_rootful e2e; run_e2e ;;
    uninstall) refuse_rootful uninstall; cmd_uninstall ;;
    down) shift; dc down "$@" ;;
    *) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$SELF"; exit 2 ;;
esac
