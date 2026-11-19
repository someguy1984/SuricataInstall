#!/usr/bin/env bash
# Remove the native Tetragon install created by local_install.sh.
#   ./local_uninstall.sh          remove everything except the event logs
#   ./local_uninstall.sh --purge  also delete the event logs in /var/log/tetragon
#
# The Docker setup (run.sh / stop.sh) is not touched.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
	echo "==> Root is needed to remove a system service; re-running with sudo."
	exec sudo -- "$0" "$@"
fi

PURGE=0
case "${1:-}" in
"") ;;
--purge) PURGE=1 ;;
*)
	echo "usage: $0 [--purge]" >&2
	exit 2
	;;
esac

# shellcheck source=config.sh
source "$DIR/config.sh"

echo "==> Stopping and disabling tetragon-viewer, tetragon-alerts and tetragon"
systemctl disable --now --quiet tetragon-viewer 2>/dev/null || true
systemctl disable --now --quiet tetragon-alerts 2>/dev/null || true
systemctl disable --now --quiet tetragon 2>/dev/null || true

echo "==> Removing unit files"
rm -f /etc/systemd/system/tetragon-viewer.service \
	/etc/systemd/system/tetragon-alerts.service \
	/etc/systemd/system/tetragon.service \
	/etc/systemd/system/tetragon.service.d/boot-gate.conf \
	/etc/systemd/system/tetragon.service.d/shutdown.conf \
	/usr/local/libexec/tetragon-wait-ready \
	/usr/lib/systemd/system/tetragon.service \
	/etc/systemd/system/multi-user.target.wants/tetragon.service \
	/etc/systemd/system/multi-user.target.wants/tetragon-viewer.service \
	/etc/systemd/system/multi-user.target.wants/tetragon-alerts.service
rmdir /etc/systemd/system/tetragon.service.d 2>/dev/null || true
systemctl daemon-reload
systemctl reset-failed tetragon tetragon-viewer tetragon-alerts 2>/dev/null || true

echo "==> Removing binaries, BPF objects, viewer and configuration"
rm -f /usr/local/bin/tetragon /usr/local/bin/tetra
rm -rf /usr/local/lib/tetragon /usr/local/lib/tetragon-viewer /usr/local/lib/tetragon-tools /etc/tetragon

# Tetragon unpins its BPF maps/programs on a clean stop; clear leftovers from
# a crash. Only when the Docker setup isn't running, since it shares these.
if ! systemctl is-active --quiet "$DOCKERD_UNIT"; then
	rm -rf /sys/fs/bpf/tetragon
	rm -f "$TETRAGON_RUN_DIR/tetragon.sock"
fi

if ((PURGE)); then
	echo "==> Removing event logs in $TETRAGON_LOG_DIR"
	rm -rf "$TETRAGON_LOG_DIR"
else
	echo "Event logs kept in $TETRAGON_LOG_DIR (use --purge to delete them)."
fi
echo "Tetragon removed."
