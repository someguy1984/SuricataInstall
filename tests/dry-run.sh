#!/bin/bash
# Rehearse an installer without changing this machine.
#
#   sudo tests/dry-run.sh ./install.sh
#   sudo tests/dry-run.sh controld/install.sh
#   sudo tests/dry-run.sh tetragon/local_install.sh
#   sudo tests/dry-run.sh watch/install.sh
#   sudo KEEP=1 tests/dry-run.sh ./install.sh      keep the files it wrote, to look at them
#
# The installer really runs: it downloads what it downloads, generates its files, and (for
# Suricata) loads the whole ruleset into the new config to test it. But it runs in a private
# mount namespace in which /etc, /usr/local, /var/lib and /var/log are copy-on-write
# overlays, so every file it writes lands in a scratch directory and the real ones are never
# touched. Commands that would change the running system are replaced by stubs that only
# record the call:
#   systemctl   anything other than a query (start, stop, restart, reload, enable, ...)
#   apt-get, add-apt-repository
#   logger, runuser                  so no alert is logged or shown
#   journalctl                       only "has Tetragon loaded its policies yet", answered yes
# At the end it lists the service changes the installer would have made and the files it
# would have written.
#
# What this proves: the installer's own logic, downloads, generated files and config test.
# What it cannot: that the services come back after the restarts it skipped, or what the
# firewall looks like afterwards. For the firewall scripts, see tests/firewall-netns.sh.
# Anything an installer does to the network directly still happens for real: controld's
# verify.sh sends its probes, and reports on the lockdown as it is now, not as it would be.
set -uo pipefail

ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo $0 ...)"; exit 1; }
[[ $# -ge 1 ]] || { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
target=$1; shift
[[ $target == /* ]] || target="$PWD/$target"
[[ -x $target ]] || { echo "Not an executable script: $target"; exit 2; }

WORK=$(mktemp -d)
cleanup() {
    if [[ ${KEEP:-0} == 1 ]]; then echo "Kept: $WORK (the files are under */upper)"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT
mkdir -p "$WORK/stubs"

cat > "$WORK/stubs/systemctl" <<'EOF'
#!/bin/bash
# Queries go to the real systemctl; anything that changes state is only recorded
case "${1:-}" in
    is-active | is-enabled | is-failed | show | list-timers | list-units | status | cat) exec /usr/bin/systemctl "$@" ;;
esac
echo "systemctl $*" >> "$STUBLOG"
exit 0
EOF
for tool in apt-get add-apt-repository logger runuser; do
    printf '#!/bin/bash\necho "%s $*" | cut -c1-200 >> "$STUBLOG"\nexit 0\n' "$tool" > "$WORK/stubs/$tool"
done
cat > "$WORK/stubs/journalctl" <<'EOF'
#!/bin/bash
# Tetragon isn't restarted in a dry run, so it can't report its policies as loaded: say it did
case " $* " in
    *" -u tetragon "*"--since"*)
        n=$(find /etc/tetragon/tetragon.tp.d -maxdepth 1 -name '*.yaml' 2>/dev/null | wc -l)
        for _ in $(seq "$n"); do echo "Added TracingPolicy with success"; done
        exit 0 ;;
esac
exec /usr/bin/journalctl "$@"
EOF
chmod +x "$WORK/stubs/"*

cat > "$WORK/enter.sh" <<'EOF'
#!/bin/bash
set -euo pipefail
mount --make-rprivate /
for d in etc usr/local var/lib var/log; do
    k=${d//\//-}
    mkdir -p "$OVL/$k/upper" "$OVL/$k/work"
    mount -t overlay overlay -o "lowerdir=/$d,upperdir=$OVL/$k/upper,workdir=$OVL/$k/work" "/$d"
done
cd "$(dirname "$1")"
exec "$@"
EOF

echo "### Dry run of $target: nothing on this machine is changed"
echo
OVL=$WORK STUBLOG=$WORK/calls.log PATH="$WORK/stubs:$PATH" \
    unshare -m --propagation private bash "$WORK/enter.sh" "$target" "$@"
rc=$?

echo
echo "### Exit status: $rc"
echo "### What it would have done to the running system, in order:"
if [[ -s $WORK/calls.log ]]; then sed 's/^/    /' "$WORK/calls.log"; else echo "    (nothing)"; fi
echo "### Files it would have written or changed:"
( cd "$WORK" && find etc usr-local var-lib var-log -path '*/upper/*' \( -type f -o -type l \) 2>/dev/null \
    | sed -e 's|^etc/upper|/etc|' -e 's|^usr-local/upper|/usr/local|' -e 's|^var-lib/upper|/var/lib|' -e 's|^var-log/upper|/var/log|' \
    | grep -vE '^/var/lib/suricata/(update|cache)/|^/var/lib/(apt|dpkg|systemd|logrotate|snapd|NetworkManager|docker|containerd)/|^/var/log/' \
    | sort | sed 's/^/    /' | head -80 )
exit $rc
