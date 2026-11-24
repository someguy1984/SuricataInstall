#!/bin/bash
set -euo pipefail
exec python3 -I "$(dirname "$(readlink -f "$0")")/outage_local.py" "$@"
