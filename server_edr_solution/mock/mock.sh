#!/bin/bash
# Drive the server_edr_solution mock environment (two Ubuntu 26.04 "droplets" on a private network).
#
#   ./mock.sh up            build images and start; waits until both boxes are healthy
#   ./mock.sh test          smoke test; exits non-zero if anything fails
#   ./mock.sh status        containers, health, addresses
#   ./mock.sh shell hub|web a root shell inside a box
#   ./mock.sh logs hub|web  follow that box's journal
#   ./mock.sh down [--volumes]   stop and remove (--volumes also forgets the mock certificates)
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
    down) shift; dc down "$@" ;;
    *) sed -n '2,14p' "$SELF" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
