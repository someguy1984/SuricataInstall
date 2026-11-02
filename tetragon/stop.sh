#!/usr/bin/env bash
# Stop Tetragon, the web viewer and the private dockerd started by run.sh.
#   ./stop.sh          stop everything (keeps image cache and event logs)
#   ./stop.sh --purge  also delete the image cache and event logs
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/config.sh"

if sudo systemctl is-active --quiet "$DOCKERD_UNIT"; then
	echo "==> Stopping containers"
	d stop -t 20 tetragon-viewer tetragon >/dev/null 2>&1 || true
	d rm -f tetragon-viewer tetragon >/dev/null 2>&1 || true
	echo "==> Stopping private dockerd ($DOCKERD_UNIT)"
	sudo systemctl stop "$DOCKERD_UNIT"
else
	echo "==> Private dockerd is not running"
fi
sudo rm -f "$TETRAGON_RUN_DIR/tetragon.sock"

if [[ "${1:-}" == "--purge" ]]; then
	echo "==> Removing $DOCKERD_DATA, $DOCKERD_RUN and $TETRAGON_LOG_DIR"
	sudo rm -rf "$DOCKERD_DATA" "$DOCKERD_RUN" "$TETRAGON_LOG_DIR"
else
	echo "Event logs kept in $TETRAGON_LOG_DIR (use --purge to delete them and the image cache)."
fi
echo "Stopped."
