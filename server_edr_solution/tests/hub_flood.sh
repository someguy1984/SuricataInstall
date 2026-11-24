#!/bin/bash
set -euo pipefail
exec python3 -I "$(dirname "$(readlink -f "$0")")/hub_flood.py" "$@"
