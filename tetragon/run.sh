#!/usr/bin/env bash
# Start Tetragon in Docker plus a small web viewer for its events.
#
# This is the try-it-out path: nothing is installed or enabled at boot, which
# makes it handy for testing a policy change. For a machine you rely on, use
# local_install.sh instead. Compared with it, this has no boot gate (nothing
# before you run it is recorded), no clean shutdown ordering, no second copy of
# policy hits in the journal and no health check.
#
# Tetragon has to load eBPF programs into the host kernel, which rootless
# Docker cannot do. So this starts a *private* rootful dockerd (as a transient
# systemd unit) that is isolated from your everyday rootless Docker:
#   - own socket, data dir and containerd namespace
#   - no iptables rules, no docker0 bridge, no ip_forward change
#   - ignores /etc/docker/daemon.json
# stop.sh shuts it all down again; nothing is enabled at boot.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/config.sh"

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
	echo "error: /sys/kernel/btf/vmlinux missing; kernel lacks BTF support" >&2
	exit 1
fi

echo "==> Tetragon needs root to load eBPF programs; sudo may ask for your password."
sudo -v

# 1. Private dockerd
if ! sudo systemctl is-active --quiet "$DOCKERD_UNIT"; then
	echo "==> Starting private dockerd ($DOCKERD_UNIT)"
	sudo systemctl reset-failed "$DOCKERD_UNIT" >/dev/null 2>&1 || true
	sudo mkdir -p "$DOCKERD_RUN"
	sudo systemd-run --quiet --collect \
		--unit="$DOCKERD_UNIT" \
		--description="Private dockerd for Tetragon (local/run.sh)" \
		/usr/bin/dockerd \
		--config-file "$DIR/dockerd.json" \
		--host "unix://$DOCKERD_SOCK" \
		--data-root "$DOCKERD_DATA" \
		--exec-root "$DOCKERD_RUN/exec" \
		--pidfile "$DOCKERD_RUN/dockerd.pid" \
		--iptables=false --ip6tables=false --ip-forward=false \
		--bridge=none \
		--containerd-namespace tetragon \
		--containerd-plugins-namespace tetragon-plugins
fi

for _ in $(seq 1 30); do
	d info >/dev/null 2>&1 && break
	sleep 1
done
if ! d info >/dev/null 2>&1; then
	echo "error: private dockerd did not come up; see: sudo journalctl -u $DOCKERD_UNIT" >&2
	exit 1
fi

# 2. Tetragon (no network at all; talks to the host only via mounted paths)
d rm -f tetragon tetragon-viewer >/dev/null 2>&1 || true
sudo mkdir -p "$TETRAGON_LOG_DIR" "$TETRAGON_RUN_DIR"
sudo rm -f "$TETRAGON_RUN_DIR/tetragon.sock"

# The policies with @HOME@ filled in, and the viewer's token, in a root-only
# directory: both are mounted into the containers from there, not from this checkout.
POLICY_DIR="$DOCKERD_RUN/policies"
TOKEN_FILE="$DOCKERD_RUN/viewer-token"
rendered="$(mktemp -d)"
render_policies "$rendered" || { rm -rf "$rendered"; exit 1; }
sudo rm -rf "$POLICY_DIR"
sudo install -d -m 0700 -o root -g root "$POLICY_DIR"
sudo install -m 0600 -o root -g root "$rendered"/*.yaml "$POLICY_DIR/"
rm -rf "$rendered"
if ! sudo test -s "$TOKEN_FILE"; then
	head -c 24 /dev/urandom | base64 | tr '+/' '-_' | sudo install -m 0600 -o root -g root /dev/stdin "$TOKEN_FILE"
fi

denylist="$(grep -vE '^\s*(#|$)' "$DIR/export-denylist.jsonl" || true)"

echo "==> Starting Tetragon ($TETRAGON_IMAGE)"
d run -d --name tetragon \
	--pid=host --cgroupns=host --privileged --network none \
	-v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf:ro \
	-v "$TETRAGON_LOG_DIR:/var/log/tetragon" \
	-v "$TETRAGON_RUN_DIR:/var/run/tetragon" \
	-v "$POLICY_DIR:/etc/tetragon/tetragon.tp.d:ro" \
	"$TETRAGON_IMAGE" \
	--server-address unix:///var/run/tetragon/tetragon.sock \
	--export-filename /var/log/tetragon/tetragon.log \
	--export-file-max-size-mb "$TETRAGON_LOG_MAX_SIZE_MB" \
	--export-file-max-backups "$TETRAGON_LOG_MAX_BACKUPS" \
	--export-file-compress \
	--export-file-perm 600 \
	--tracing-policy-dir /etc/tetragon/tetragon.tp.d \
	--enable-process-cred \
	--export-denylist "$denylist" >/dev/null

echo -n "==> Waiting for Tetragon to load its eBPF programs "
for _ in $(seq 1 90); do
	if [[ "$(d inspect -f '{{.State.Running}}' tetragon 2>/dev/null)" != "true" ]]; then
		echo
		echo "error: Tetragon exited. Last log lines:" >&2
		d logs --tail 40 tetragon >&2 || true
		exit 1
	fi
	sudo test -S "$TETRAGON_RUN_DIR/tetragon.sock" && break
	echo -n "."
	sleep 1
done
echo
if ! sudo test -S "$TETRAGON_RUN_DIR/tetragon.sock"; then
	echo "error: Tetragon did not become ready; check: sudo docker -H unix://$DOCKERD_SOCK logs tetragon" >&2
	exit 1
fi

# The socket appears before policies are loaded, and Tetragon exits if any
# policy fails, so wait until every policy file is reported as added.
want=$(find "$DIR/policies" -maxdepth 1 -name '*.yaml' | wc -l)
echo -n "==> Loading $want tracing policies "
for _ in $(seq 1 60); do
	if [[ "$(d inspect -f '{{.State.Running}}' tetragon 2>/dev/null)" != "true" ]]; then
		echo
		echo "error: Tetragon exited while loading policies:" >&2
		d logs tetragon 2>&1 | grep -E 'level=(error|fatal)' | tail -5 >&2 || true
		exit 1
	fi
	got=$(d logs tetragon 2>&1 | grep -c 'Added TracingPolicy with success' || true)
	((got >= want)) && break
	echo -n "."
	sleep 1
done
echo
if ((got < want)); then
	echo "warning: only $got of $want policies reported loaded; check: sudo docker -H unix://$DOCKERD_SOCK logs tetragon" >&2
fi

# 3. Web viewer (localhost only, read-only access to the event log)
echo "==> Starting web viewer"
d run -d --name tetragon-viewer \
	--network host --read-only --cap-drop ALL \
	--security-opt no-new-privileges \
	-v "$TETRAGON_LOG_DIR:/logs:ro" \
	-v "$DIR/viewer:/app:ro" \
	-v "$TOKEN_FILE:/run/viewer-token:ro" \
	"$VIEWER_IMAGE" \
	python /app/server.py --log /logs/tetragon.log \
	--bind 127.0.0.1 --port "$VIEWER_PORT" --token-file /run/viewer-token >/dev/null

cat <<EOF

Tetragon is running.

  Live report:  http://127.0.0.1:$VIEWER_PORT/#token=$(sudo cat "$TOKEN_FILE")

  Terminal view:
    sudo docker -H unix://$DOCKERD_SOCK exec -it tetragon \\
      tetra --server-address unix:///var/run/tetragon/tetragon.sock getevents -o compact
  Raw JSON log: sudo tail -f $TETRAGON_LOG_DIR/tetragon.log
  Policies:     $DIR/policies (re-run ./run.sh after changing)
  Stop:         $DIR/stop.sh
EOF
