#!/bin/bash
# Unit tests of server_edr_solution: the hub and the client agent. Needs no root, no network and nothing installed.
# Each suite runs under its own wall-clock limit, so one hung test cannot hang make. One summary line per suite;
# the output of a suite that failed follows it. Exit status: 0 when every suite passed, 1 otherwise.
#
# Usage: tests/unit.sh        (normally via: make unit)
#   UNIT_TIMEOUT=SECONDS      limit per suite (default 600)
set -uo pipefail

ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
cd "$ROOT" || exit 1
LIMIT=${UNIT_TIMEOUT:-600}
OUT=$(mktemp -d) || exit 1
trap 'rm -rf "$OUT"' EXIT

FAIL=0
suites=(server_edr_solution/server_hub/tests server_edr_solution/server_client/tests)
for dir in "${suites[@]}"; do
    name=${dir#server_edr_solution/}
    log="$OUT/$(basename "$(dirname "$dir")").log"
    if [[ ! -d $dir ]]; then
        echo "  FAIL  $name: no such directory"; FAIL=1; continue
    fi
    start=$SECONDS
    # -B: no .pyc files next to the sources. The tests insert the code directories into sys.path themselves.
    timeout --kill-after=10 "$LIMIT" python3 -B -m unittest discover -s "$dir" -t "$dir" >"$log" 2>&1
    rc=$?
    took=$((SECONDS - start))
    ran=$(sed -n 's/^Ran \([0-9]*\) tests\? in .*/\1/p' "$log" | tail -1)
    detail=$(grep -E '^(OK|FAILED)' "$log" | tail -1)
    if [[ $rc -eq 124 || $rc -eq 137 ]]; then
        echo "  FAIL  $name: timed out after ${LIMIT}s (a test hangs; UNIT_TIMEOUT changes the limit)"; FAIL=1
        tail -n 15 "$log" | sed 's/^/        /'
    elif [[ $rc -eq 0 ]]; then
        echo "  ok    $name: ${ran:-?} tests, ${detail:-OK}, ${took}s"
    else
        echo "  FAIL  $name: ${ran:-no} tests ran, ${detail:-exit $rc}, ${took}s"; FAIL=1
        # the failures only: the headers and messages of the failing tests, then the tail
        grep -E '^(ERROR|FAIL):' "$log" | sed 's/^/        /'
        tail -n 25 "$log" | sed 's/^/        | /'
    fi
done

echo
if [[ $FAIL -eq 0 ]]; then echo "Unit tests passed"; else echo "Unit tests FAILED"; fi
exit $FAIL
