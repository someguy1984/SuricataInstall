#!/bin/bash
set -euo pipefail
exec python3 -I "$(dirname "$(readlink -f "$0")")/e2e_local.py" "$@"
