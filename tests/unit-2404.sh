#!/bin/bash
# The unit tests of server_edr_solution and its loopback end-to-end test under Python 3.12 (Ubuntu 24.04, OpenSSL 3.0),
# in a throwaway container. Development is on 3.14; the droplets run 24.04 and 26.04. One summary line per suite;
# the output of a suite that failed follows it. Exit status: 0 when every suite passed, 1 otherwise.
#
# The image is ubuntu:24.04 plus python3, openssl and the tools some tests shell out to (built once, tagged
# edr-py312:HASH of the recipe below). The repository is mounted read-only and copied inside the container; the tests run
# there as an unprivileged user (the suites are written for "no root") with umask 022, and /tmp is a tmpfs as on a
# development machine (on an overlay or ext4 /tmp a deleted file's inode is reused at once, which two tail tests do not expect).
# Rootless Docker is found the way server_edr_solution/mock/mock.sh finds it.
#
# Usage: tests/unit-2404.sh        (normally via: make unit-2404)
#   UNIT_TIMEOUT=SECONDS           limit per suite (default 600)
set -uo pipefail

ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
LIMIT=${UNIT_TIMEOUT:-600}

# /run/systemd/system: the hub installer's dry run refuses a host that is not running systemd
DOCKERFILE='FROM ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends python3 python3-yaml openssl shellcheck systemd nftables curl logrotate && mkdir -p /run/systemd/system && rm -rf /var/lib/apt/lists/* && useradd -m tester'
IMAGE=edr-py312:$(printf '%s' "$DOCKERFILE" | sha256sum | cut -c1-8)

if [[ -z ${DOCKER_HOST:-} && ! -S /var/run/docker.sock ]]; then
    rt=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
    [[ -S $rt/docker.sock ]] && export DOCKER_HOST=unix://$rt/docker.sock
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "building $IMAGE (ubuntu:24.04 with python3, openssl, shellcheck, systemd-analyze, PyYAML)"
    printf '%s\n' "$DOCKERFILE" | docker build -q -t "$IMAGE" - >/dev/null || { echo "  FAIL  could not build $IMAGE"; exit 1; }
fi

# What runs inside the container, as user tester: one RESULT line per suite, then the tail of each log.
INNER='
umask 022
cp -a /repo /work/repo && cd /work/repo || exit 1
python3 --version; openssl version
S=server_edr_solution
run() {
    name=$1; shift; start=$SECONDS
    timeout --kill-after=10 '"$LIMIT"' "$@" >/work/$name.log 2>&1; rc=$?
    ran=$(sed -n "s/^Ran \([0-9]*\) tests\? in .*/\1/p" /work/$name.log | tail -1)
    detail=$(grep -E "^(OK|FAILED|[0-9]+ steps)" /work/$name.log | tail -1)
    echo "RESULT $rc $name ${ran:-?} tests, ${detail:-exit $rc}, $((SECONDS - start))s"
}
run hub    python3 -B -m unittest discover -s $S/server_hub/tests -t $S/server_hub/tests
run client python3 -B -m unittest discover -s $S/server_client/tests -t $S/server_client/tests
run e2e    python3 -I $S/tests/e2e_local.py
for n in hub client e2e; do echo "=== $n"; tail -n 40 /work/$n.log; done
'

out=$(docker run --rm --name edr-py312-run --user tester -v "$ROOT:/repo:ro" --tmpfs /work:exec,mode=1777,size=512m \
    --tmpfs /tmp:exec,mode=1777 "$IMAGE" bash -c "$INNER" 2>&1) || { echo "  FAIL  the container did not run"; echo "$out" | tail -n 20; exit 1; }

echo "$out" | sed -n '1,2p' | sed 's/^/  /'
FAIL=0
while read -r _ rc name rest; do
    if [[ $rc -eq 0 ]]; then echo "  ok    py3.12 $name: $rest"
    else echo "  FAIL  py3.12 $name: $rest"; FAIL=1; fi
done < <(echo "$out" | grep '^RESULT ')
[[ $(echo "$out" | grep -c '^RESULT ') -eq 3 ]] || { echo "  FAIL  not all suites ran"; FAIL=1; }
if [[ $FAIL -ne 0 ]]; then echo "$out" | sed -n '/^=== /,$p' | sed 's/^/        /'; fi

echo
if [[ $FAIL -eq 0 ]]; then echo "Python 3.12 tests passed"; else echo "Python 3.12 tests FAILED"; fi
exit $FAIL
