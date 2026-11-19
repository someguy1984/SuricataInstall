# Shared settings for run.sh / stop.sh. Sourced, not executed.

# Pinned versions. Tags can be moved to point at different content, so the
# image digests and tarball checksums below are what is actually trusted.
# When upgrading, update all of them together (see local_install.sh header).
TETRAGON_VERSION="v1.7.1"
TETRAGON_IMAGE="quay.io/cilium/tetragon:${TETRAGON_VERSION}@sha256:afc9458ba4bc3f2795da3df6b03d88ce50e175ac3903027de8036e2046b84a02"
TETRAGON_TARBALL_SHA256_amd64="2f36a7bbb2b3d77a011383a01c8f804fe7761d934a76ff2fdf99ebad6f3e89ae"
TETRAGON_TARBALL_SHA256_arm64="aa71d12eddd962003e9fd78e3b3534185af5b2728c7d21ab3cb0f7fe2dc87702"
VIEWER_IMAGE="python:3.13-alpine@sha256:7984cf56ceaddebe4fefeb75d64000b9f45d8b77b11a09b24524da6cdc3af0c8"

# Event log retention. Tetragon's default (5 x 10 MB) only held a few hours
# of history here, which also makes it easy to push evidence out by
# generating noise. 40 x 50 MB, gzip-compressed once rotated (~10:1 for this
# JSON), keeps days to weeks in a few hundred MB.
TETRAGON_LOG_MAX_SIZE_MB=50
TETRAGON_LOG_MAX_BACKUPS=40
VIEWER_PORT="${VIEWER_PORT:-8099}"

# Whose home directory the policies watch (shell start-up files, SSH keys, browser
# and credential stores): the person running the installer, unless set here or in
# the environment. Policy files say @HOME@ where that directory goes.
WATCH_USER="${WATCH_USER:-${SUDO_USER:-$(id -un)}}"

# Write ./policies into the directory $1 with @HOME@ filled in.
render_policies() {
	local dest="$1" home f
	if [[ $WATCH_USER == root ]]; then
		echo "error: can't tell whose home directory to watch when run as root without sudo;" >&2
		echo "       set WATCH_USER=<your login name>" >&2
		return 1
	fi
	home="$(getent passwd "$WATCH_USER" | cut -d: -f6)"
	if [[ -z $home || ! -d $home ]]; then
		echo "error: user '$WATCH_USER' has no home directory" >&2
		return 1
	fi
	for f in "$DIR"/policies/*.yaml; do
		sed "s|@HOME@|$home|g" "$f" >"$dest/$(basename "$f")" || return 1
	done
}

# Private rootful dockerd, completely separate from your rootless Docker
# (which lives at /run/user/$UID/docker.sock and is never touched).
DOCKERD_UNIT="tetragon-dockerd"
DOCKERD_RUN="/run/tetragon-docker"
DOCKERD_SOCK="$DOCKERD_RUN/docker.sock"
DOCKERD_DATA="/var/lib/tetragon-docker"

# Host paths shared with the Tetragon container.
TETRAGON_LOG_DIR="/var/log/tetragon"
TETRAGON_RUN_DIR="/var/run/tetragon"

# docker CLI pointed only at the private daemon (-H overrides any context).
d() { sudo docker -H "unix://$DOCKERD_SOCK" "$@"; }
