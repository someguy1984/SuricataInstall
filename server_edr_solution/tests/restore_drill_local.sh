#!/bin/bash
set -euo pipefail
exec python3 -I "$(dirname "$(readlink -f "$0")")/restore_drill_local.py" "$@"
