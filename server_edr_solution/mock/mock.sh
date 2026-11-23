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
# With the real installers (WRITTEN BUT NOT YET RUN: see README.md), in this order:
#   ./mock.sh dist          make dist on this machine; copy the tarballs and their hashes into the boxes
#   ./mock.sh install-hub   disable the placeholder; unpack, check the hash, install.sh --plan, install.sh --yes
#   ./mock.sh install-web   the client in local mode (MOCK_SURICATA=1 adds Suricata; MOCK_WEB_FLAGS="..." adds flags)
#   ./mock.sh enroll        token on the hub box, carried in a file to the web box, edr-agent enroll
#   ./mock.sh e2e           the end-to-end checks, each PASS or FAIL; exits non-zero on any FAIL
#   ./mock.sh uninstall     both uninstallers, then the residue checks; puts the placeholder back
#
#   MOCK_CAPS=1 ./mock.sh ...    the boxes without `privileged` (compose.caps.yaml; not boot-tested yet)
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
    echo "== web.dev.local from this machine (loopback-published ports)"
    check "http://web.dev.local:80 serves the PHP 8.5 hello page" \
        bash -c 'p=$(curl -fsS --max-time 10 --resolve web.dev.local:80:127.0.0.1 http://web.dev.local/) &&
                 grep -q "Hello, world" <<<"$p" && grep -q "PHP 8\.5\." <<<"$p" && grep -q "plain HTTP" <<<"$p"'
    check "https://web.dev.local:443 serves it over TLS with HTTP/2" \
        bash -c 'p=$(curl -fsSk --http2 --max-time 10 --resolve web.dev.local:443:127.0.0.1 https://web.dev.local/) &&
                 grep -q "HTTPS, HTTP/2.0" <<<"$p"'
    check "the certificate names web.dev.local" \
        bash -c 'openssl s_client -connect 127.0.0.1:443 -servername web.dev.local </dev/null 2>/dev/null |
                 openssl x509 -noout -ext subjectAltName | grep -q "DNS:web.dev.local"'
    check "dotfiles are refused (/.env -> 403)" \
        bash -c '[[ $(curl -s -o /dev/null -w "%{http_code}" --resolve web.dev.local:80:127.0.0.1 http://web.dev.local/.env) == 403 ]]'

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

# ---- the real installers (written, not yet run) -------------------------------------------------------------
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

# The token goes from the hub box to the web box through two pipes and a file: it is never an argument
# and never on this machine's disk.
cmd_enroll() {
    local py='import json, sys; print(json.load(sys.stdin)["tokens"][0]["token"])'
    hubx edr-hub token create --name web --ttl 1h --json | python3 -I -c "$py" |
        webx sh -c 'umask 077; cat > /root/mock-dist/web.token'
    webx edr-agent enroll --hub "$HUB_IP:$HUB_PORT" --token-file "$DIST/web.token" --droplet-id mock-web
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
    webx bash -c 'mkdir -p /var/log/tetragon && python3 -I -c "$1" "$2"' _ "$TETRAGON_PY" "$1"
}

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

    echo "== events reach the hub (within 2 minutes each)"
    hubx curl -s -o /dev/null --max-time 10 http://web.dev.local/.env || true
    append_tetragon_line "$marker"
    check "the tripwire request for /.env is a canary.tripwire event in edr-hub events --json" \
        wait_ok 120 hub_has_event canary.tripwire "" ".env"
    check "the recorded Tetragon line is a CRITICAL tetragon.nginx-exec event" \
        wait_ok 120 hub_has_event tetragon.nginx-exec CRITICAL "$marker"

    echo "== health checks"
    check "edr-check on the web box exits 0 or 1" exit_0_or_1 webx edr-check
    check "the hub's check.sh exits 0 or 1" exit_0_or_1 hubx /usr/local/lib/edr-hub/check.sh

    echo "== revoke: the agent gets 403 and keeps spooling"
    check "edr-hub host web revoke succeeds" hubx edr-hub host web revoke
    append_tetragon_line "$marker-after-revoke"
    check "edr-agent status shows host_revoked and a spool with at least one event" wait_ok 150 agent_revoked_and_spooling

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
    local a b
    a=$(dc exec -T "$1" systemctl list-unit-files "$2" --no-legend) || return 1
    b=$(dc exec -T "$1" systemctl list-units --all "$2" --no-legend) || return 1
    [[ -z $a && -z $b ]]
}
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
    echo "== residue in the web box"
    check "no table inet edr" no_table web edr
    check "no table inet edr_dns" no_table web edr_dns
    check "no table inet edr_isolate" no_table web edr_isolate
    check "no edr unit file or unit" no_units web 'edr-*'
    check "no edr-agent process" no_process web '[e]dr-agent'
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
        dc up -d --build
        wait_healthy
        echo "mock: up. Add '127.0.0.1 web.dev.local' to /etc/hosts to browse http(s)://web.dev.local"
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
