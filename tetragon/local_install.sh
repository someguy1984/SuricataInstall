#!/usr/bin/env bash
# Install Tetragon natively on this host as a systemd service, using the same
# policies, export denylist and web viewer as the Docker setup (run.sh).
#
#   ./local_install.sh               install or upgrade, enable at boot, start
#   ./local_install.sh --no-viewer   skip the web viewer service
#   ./local_install.sh --no-boot-gate  don't hold boot until Tetragon is ready
#
# What gets installed (all removed again by local_uninstall.sh):
#   /usr/local/bin/{tetragon,tetra}         official release binaries
#   /usr/local/lib/tetragon/                BPF objects, bpftool, default config
#   /etc/systemd/system/tetragon.service    upstream unit, enabled at boot
#                                           (boot gate drops After=network.target)
#   /etc/systemd/system/tetragon.service.d/boot-gate.conf
#                                           starts Tetragon early and holds
#                                           normal services back until it is
#                                           recording (see "Boot gate" below)
#   /etc/systemd/system/tetragon.service.d/shutdown.conf
#                                           clean stop late in shutdown
#   /usr/local/libexec/tetragon-wait-ready  readiness check used by the gate
#   /etc/tetragon/tetragon.conf.d/          our option overrides
#   /etc/tetragon/tetragon.tp.d/            mirror of ./policies (managed by this
#                                           script: stray *.yaml there are removed)
#   /usr/local/lib/tetragon-viewer/         copy of ./viewer
#   /etc/systemd/system/tetragon-viewer.service   sandboxed, localhost only
#   /etc/systemd/system/tetragon-alerts.service   copies policy hits into the
#                                           journal (second, separate record)
#
# Upgrading: set TETRAGON_VERSION in config.sh and replace the pinned
# checksums/digests next to it with the values published for that release.
#
# Re-run after editing ./policies or export-denylist.jsonl to apply changes.
# The Docker setup (run.sh) must be stopped first: both use the same socket
# and log file.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WITH_VIEWER=1
WITH_BOOT_GATE=1
for arg in "$@"; do
	case "$arg" in
	--no-viewer) WITH_VIEWER=0 ;;
	--no-boot-gate) WITH_BOOT_GATE=0 ;;
	-h | --help)
		sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "error: unknown option: $arg" >&2
		exit 2
		;;
	esac
done

if [[ $EUID -ne 0 ]]; then
	echo "==> Root is needed to install a system service; re-running with sudo."
	exec sudo -- "$0" "$@"
fi

# shellcheck source=config.sh
source "$DIR/config.sh"

ETC=/etc/tetragon
UNIT_DIR=/etc/systemd/system
VIEWER_DIR=/usr/local/lib/tetragon-viewer

die() {
	echo "error: $*" >&2
	exit 1
}

# --- Pre-flight -------------------------------------------------------------
[[ -d /run/systemd/system ]] || die "systemd is not running on this host"
[[ -r /sys/kernel/btf/vmlinux ]] || die "/sys/kernel/btf/vmlinux missing; kernel lacks BTF support"
for cmd in curl sha256sum tar install; do
	command -v "$cmd" >/dev/null || die "'$cmd' is required"
done
if ((WITH_VIEWER)) && ! command -v python3 >/dev/null; then
	die "python3 is required for the viewer (or pass --no-viewer)"
fi

case "$(uname -m)" in
x86_64) ARCH=amd64 ;;
aarch64) ARCH=arm64 ;;
*) die "unsupported architecture: $(uname -m)" ;;
esac

if systemctl is-active --quiet "$DOCKERD_UNIT"; then
	die "the Docker setup is running; stop it first with: $DIR/stop.sh"
fi

# --- Download and verify the official release tarball ------------------------
NAME="tetragon-${TETRAGON_VERSION}-${ARCH}"
URL="https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/${NAME}.tar.gz"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Downloading $NAME"
curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/$NAME.tar.gz" "$URL"
curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/$NAME.tar.gz.sha256sum" "$URL.sha256sum"
# The .sha256sum file comes from the same place as the tarball, so it only
# proves the download wasn't corrupted. The checksum pinned in config.sh is
# what proves it is the same release that was reviewed.
echo "==> Verifying checksum"
pinned_var="TETRAGON_TARBALL_SHA256_${ARCH}"
pinned="${!pinned_var:-}"
[[ -n "$pinned" ]] || die "no pinned checksum $pinned_var in config.sh"
actual="$(sha256sum "$WORK/$NAME.tar.gz" | cut -d' ' -f1)"
[[ "$actual" == "$pinned" ]] ||
	die "checksum of $NAME.tar.gz ($actual) does not match the one pinned in config.sh; refusing to install"
(cd "$WORK" && sha256sum --check --strict --quiet "$NAME.tar.gz.sha256sum") ||
	die "checksum mismatch against the published $NAME.tar.gz.sha256sum; refusing to install"
tar -xzf "$WORK/$NAME.tar.gz" -C "$WORK"
SRC="$WORK/$NAME"
[[ -x "$SRC/usr/local/bin/tetragon" ]] || die "unexpected tarball layout in $NAME.tar.gz"

# Stop a previous native install before swapping binaries underneath it.
if systemctl is-active --quiet tetragon; then
	echo "==> Stopping running tetragon service for upgrade"
	systemctl stop tetragon-viewer tetragon-alerts 2>/dev/null || true
	systemctl stop tetragon
fi

# --- Install binaries and BPF objects ---------------------------------------
echo "==> Installing Tetragon $TETRAGON_VERSION into /usr/local"
install -D -m 0755 "$SRC/usr/local/bin/tetragon" /usr/local/bin/tetragon
install -D -m 0755 "$SRC/usr/local/bin/tetra" /usr/local/bin/tetra
rm -rf /usr/local/lib/tetragon
cp -a "$SRC/usr/local/lib/tetragon" /usr/local/lib/tetragon
chown -R root:root /usr/local/lib/tetragon /usr/local/bin/tetragon /usr/local/bin/tetra
chmod -R go-w /usr/local/lib/tetragon
install -m 0644 "$SRC/usr/local/lib/tetragon/systemd/tetragon.service" "$UNIT_DIR/tetragon.service"

# --- Configuration ----------------------------------------------------------
# Each file in tetragon.conf.d is one command-line option (file name = flag,
# contents = value). These sit on top of the defaults shipped in
# /usr/local/lib/tetragon/tetragon.conf.d (socket, log file, compression ...).
echo "==> Writing configuration to $ETC"
install -d -m 0755 "$ETC" "$ETC/tetragon.conf.d" "$ETC/tetragon.tp.d"
echo true >"$ETC/tetragon.conf.d/enable-process-cred"
echo "$TETRAGON_LOG_MAX_SIZE_MB" >"$ETC/tetragon.conf.d/export-file-max-size-mb"
echo "$TETRAGON_LOG_MAX_BACKUPS" >"$ETC/tetragon.conf.d/export-file-max-backups"
echo 600 >"$ETC/tetragon.conf.d/export-file-perm"
grep -vE '^\s*(#|$)' "$DIR/export-denylist.jsonl" >"$ETC/tetragon.conf.d/export-denylist" || true
chmod 0644 "$ETC/tetragon.conf.d/"*

echo "==> Syncing policies to $ETC/tetragon.tp.d"
find "$ETC/tetragon.tp.d" -maxdepth 1 -type f -name '*.yaml' -delete
install -m 0644 "$DIR"/policies/*.yaml "$ETC/tetragon.tp.d/"
want=$(find "$ETC/tetragon.tp.d" -maxdepth 1 -name '*.yaml' | wc -l)

# --- Boot gate --------------------------------------------------------------
# Upstream's unit waits for network.target (not needed without Kubernetes) and
# nothing waits for it, so ordinary services, logins and the desktop start
# while Tetragon is still loading policies (~9 s here) and go unrecorded.
# This drop-in starts it as soon as local filesystems are mounted and orders
# it before basic.target, which every normal service comes after. Tetragon
# has no sd_notify support, so systemd would treat it as started the instant
# the process launches; ExecStartPost holds startup until it logs
# "Listening for events", i.e. all policies are loaded and events flow.
# If it is not ready within 90 s boot carries on regardless (the service is
# left running); if it exits, the unit fails and Restart=on-failure applies.
#
# The network.target ordering has to be removed from the unit file itself. A
# drop-in cannot clear After= (systemd ignores an empty "After=" for
# dependency settings), and with it left in place, Before=basic.target forms
# an ordering cycle (basic.target -> tetragon -> network.target ->
# wpa_supplicant -> dbus -> basic.target). systemd breaks that cycle by
# deleting Tetragon's start job, so Tetragon did not start at boot at all.
GATE_DIR="$UNIT_DIR/tetragon.service.d"
WAIT_READY=/usr/local/libexec/tetragon-wait-ready
install -d -m 0755 "$GATE_DIR"
if ((WITH_BOOT_GATE)); then
	echo "==> Installing boot gate ($GATE_DIR/boot-gate.conf)"
	grep -qx 'After=network.target local-fs.target' "$UNIT_DIR/tetragon.service" ||
		die "upstream tetragon.service no longer has the expected After= line; review the boot gate before installing (or pass --no-boot-gate)"
	sed -i 's/^After=network.target local-fs.target$/After=local-fs.target systemd-journald.socket/' \
		"$UNIT_DIR/tetragon.service"
	install -d -m 0755 /usr/local/libexec
	cat >"$WAIT_READY" <<'EOF'
#!/bin/sh
# Installed by local_install.sh. Run as ExecStartPost of tetragon.service:
# wait until the Tetragon process with PID $1 logs "Listening for events".
pid="$1"
timeout="${2:-90}"
[ -n "$pid" ] || { echo "usage: $0 PID [TIMEOUT_SECONDS]" >&2; exit 2; }
n=0
while [ "$n" -lt $((timeout * 4)) ]; do
	if [ ! -d "/proc/$pid" ]; then
		echo "tetragon (pid $pid) exited before it was ready" >&2
		exit 1
	fi
	if journalctl -b _PID="$pid" -o cat --no-pager 2>/dev/null |
		grep -q 'Listening for events'; then
		exit 0
	fi
	sleep 0.25
	n=$((n + 1))
done
echo "tetragon not ready after ${timeout}s; letting boot continue" >&2
exit 0
EOF
	chmod 0755 "$WAIT_READY"
	cat >"$GATE_DIR/boot-gate.conf" <<EOF
# Installed by $DIR/local_install.sh (remove with --no-boot-gate)
[Unit]
# tetragon.service itself was edited to drop After=network.target; see
# local_install.sh. Without that, this Before= creates a boot ordering cycle.
Before=basic.target

[Service]
ExecStartPost=$WAIT_READY \$MAINPID 90
TimeoutStartSec=120
EOF
	chmod 0644 "$GATE_DIR/boot-gate.conf"
else
	rm -f "$GATE_DIR/boot-gate.conf" "$WAIT_READY"
fi

# --- Clean shutdown -----------------------------------------------------------
# With DefaultDependencies=no and nothing else, systemd never stops Tetragon:
# it is still running when filesystems (including /run/tetragon/cgroup2) are
# unmounted, then is SIGTERMed together with journald by systemd-shutdown, so
# its exit is never logged and the event log isn't flushed and closed. Stopping
# it as part of the shutdown transaction fixes that. Stop order is the reverse
# of start order, so with the boot gate (Before=basic.target) it still stops
# only after every normal service has stopped, and before local filesystems
# and journald go away.
echo "==> Installing shutdown ordering ($GATE_DIR/shutdown.conf)"
cat >"$GATE_DIR/shutdown.conf" <<EOF
# Installed by $DIR/local_install.sh
[Unit]
Conflicts=shutdown.target
Before=shutdown.target

[Service]
TimeoutStopSec=30
EOF
chmod 0644 "$GATE_DIR/shutdown.conf"

# --- Start Tetragon ---------------------------------------------------------
systemctl daemon-reload
if ((WITH_BOOT_GATE)) &&
	systemctl show -p After --value tetragon | tr ' ' '\n' | grep -qx 'network.target'; then
	die "tetragon.service is still ordered after network.target; with the boot gate this is a boot ordering cycle and Tetragon would not start at boot"
fi
systemctl reset-failed tetragon 2>/dev/null || true
since="$(date '+%Y-%m-%d %H:%M:%S')"
echo "==> Enabling and starting tetragon.service"
systemctl enable --quiet tetragon
# With the boot gate this blocks until Tetragon is listening. A failure is
# reported (with logs) by the wait loop below rather than aborting here.
systemctl start tetragon || true

echo -n "==> Waiting for Tetragon to load $want tracing policies "
got=0
for _ in $(seq 1 120); do
	if ! systemctl is-active --quiet tetragon; then
		echo
		echo "error: tetragon.service stopped. Last log lines:" >&2
		journalctl -u tetragon --since "$since" --no-pager | tail -20 >&2
		exit 1
	fi
	got=$(journalctl -u tetragon --since "$since" --no-pager -o cat 2>/dev/null |
		grep -c 'Added TracingPolicy with success' || true)
	((got >= want)) && break
	echo -n "."
	sleep 1
done
echo
if ((got < want)); then
	echo "warning: only $got of $want policies reported loaded; check: journalctl -u tetragon" >&2
fi

# --- Second copy of policy hits in the journal --------------------------------
# /var/log/tetragon is one directory an intruder with root can simply delete.
# This streams every policy hit (not process exec/exit, so it stays small)
# into journald as well: a separate store with its own retention, which can be
# sealed (journalctl --setup-keys) or forwarded off the machine. tcp-connect is
# left out: it is high-volume and not an alert on its own.
echo "==> Installing tetragon-alerts.service (policy hits -> journal)"
alert_policies="$(find "$ETC/tetragon.tp.d" -maxdepth 1 -name '*.yaml' -exec \
	sed -n 's/^  name: *"\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' {} + |
	grep -vx 'tcp-connect' | sort -u | paste -sd, -)"
cat >"$UNIT_DIR/tetragon-alerts.service" <<EOF
# Installed by $DIR/local_install.sh
[Unit]
Description=Copy Tetragon policy hits into the systemd journal
After=tetragon.service
PartOf=tetragon.service

[Service]
ExecStart=/usr/local/bin/tetra --server-address unix://$TETRAGON_RUN_DIR/tetragon.sock getevents -o json --event-types PROCESS_KPROBE --policy-names $alert_policies
StandardOutput=journal
SyslogIdentifier=tetragon-alerts
Restart=always
RestartSec=2

# Root only to open Tetragon's 0660 root:root socket; nothing else is needed.
User=root
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
# tetra is a Go binary, and the Go runtime raises RLIMIT_NOFILE at startup with
# prlimit64 (in @resources). The default filter action kills the process with
# SIGSYS (status=31/SYS crash loop); return EPERM instead, which Go ignores.
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --quiet tetragon-alerts
systemctl restart tetragon-alerts

# --- Web viewer (optional) --------------------------------------------------
if ((WITH_VIEWER)); then
	echo "==> Installing web viewer service"
	install -d -m 0755 "$VIEWER_DIR"
	install -m 0644 "$DIR/viewer/server.py" "$DIR/viewer/index.html" "$VIEWER_DIR/"
	cat >"$UNIT_DIR/tetragon-viewer.service" <<EOF
# Installed by $DIR/local_install.sh
[Unit]
Description=Read-only web viewer for Tetragon events (localhost only)
After=tetragon.service
Wants=tetragon.service

[Service]
ExecStart=/usr/bin/python3 -I $VIEWER_DIR/server.py --log $TETRAGON_LOG_DIR/tetragon.log --bind 127.0.0.1 --port $VIEWER_PORT
Restart=on-failure
RestartSec=5

# Runs as root only because Tetragon writes its log 0600 root:root. Every
# capability is dropped and the filesystem view is reduced to what the viewer
# needs, so it can read the event log and little else.
User=root
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
TemporaryFileSystem=/var:ro
BindReadOnlyPaths=$TETRAGON_LOG_DIR
InaccessiblePaths=-/etc/shadow -/etc/gshadow -/etc/sudoers -/etc/sudoers.d -/etc/ssh -/etc/ssl/private -/etc/tetragon -/run/tetragon -/var/run/tetragon
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
	systemctl enable --quiet tetragon-viewer
	systemctl restart tetragon-viewer
	sleep 1
	systemctl is-active --quiet tetragon-viewer ||
		echo "warning: viewer failed to start; check: journalctl -u tetragon-viewer" >&2
fi

cat <<EOF

Tetragon $TETRAGON_VERSION is installed and enabled at boot.

  Status:        systemctl status tetragon
  Agent logs:    journalctl -u tetragon -f
  Live events:   sudo tetra getevents -o compact
  Raw JSON log:  sudo tail -f $TETRAGON_LOG_DIR/tetragon.log
  Alerts copy:   journalctl -t tetragon-alerts -f
  Policies:      sudo tetra tracingpolicy list
EOF
((WITH_VIEWER)) && echo "  Web viewer:    http://127.0.0.1:$VIEWER_PORT"
cat <<EOF

  Change policies or the denylist: edit them in $DIR, then re-run this script.
  Remove:        $DIR/local_uninstall.sh   (--purge also deletes event logs)
EOF
