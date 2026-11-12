#!/bin/bash
# The "full install -> check -> uninstall cycle on a fresh Ubuntu VM" from the README, as one
# command. Covers the Suricata kit on a machine with nothing else on it, which is exactly
# the case that is easy to break without noticing: no ctrld, no earlier install, stock config.
#
#   tests/vm-smoke.sh            launch a VM, run the cycle, delete the VM
#   KEEP=1 tests/vm-smoke.sh     keep the VM afterwards (multipass shell <name>) to look around
#   RELEASE=24.04 tests/vm-smoke.sh   another Ubuntu release (default: the current LTS)
#
# Needs multipass (sudo snap install multipass). Nothing is changed on this machine apart
# from the VM. The VM gets 4 GB of memory because loading the full ruleset needs over 1 GB.
#
# NOTE: written without multipass at hand, so this script itself has not been run yet.
# Treat its first run as a test of the script as much as of the installer.
set -euo pipefail

ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
NAME="ips-smoke-$$"
RELEASE=${RELEASE:-lts}

command -v multipass >/dev/null || { echo "multipass is not installed (sudo snap install multipass)"; exit 1; }

cleanup() {
    if [[ ${KEEP:-0} == 1 ]]; then
        echo "Keeping the VM: multipass shell $NAME   (remove with: multipass delete --purge $NAME)"
    else
        multipass delete --purge "$NAME" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

step() { echo; echo "==> $*"; }
vm() { multipass exec "$NAME" -- "$@"; }

step "Launching Ubuntu $RELEASE as $NAME"
multipass launch "$RELEASE" --name "$NAME" --cpus 2 --memory 4G --disk 15G

step "Copying the repo into the VM"
vm mkdir -p /home/ubuntu/ips
tar -C "$ROOT" --exclude=.git -cf - . | vm tar -C /home/ubuntu/ips -xf -

step "DNS works before the install"
vm getent hosts archive.ubuntu.com >/dev/null

step "install.sh"
vm sudo /home/ubuntu/ips/install.sh

step "DNS still works with Suricata inline (no ctrld here, so no DNS rules may be loaded)"
vm getent hosts archive.ubuntu.com >/dev/null
vm sudo grep -c '^drop ' /etc/suricata/dns-lockdown.rules | grep -qx 0

step "check.sh --live"
vm sudo /home/ubuntu/ips/check.sh --live

step "install.sh again (a re-run must keep Suricata up and end healthy)"
vm sudo /home/ubuntu/ips/install.sh
vm sudo /home/ubuntu/ips/check.sh

step "A broken config must be refused and leave the working one in place"
vm sudo cp /home/ubuntu/ips/files/suricata.yaml /home/ubuntu/suricata.yaml.good
vm sudo sh -c 'echo "this-is: [not valid" >> /home/ubuntu/ips/files/suricata.yaml'
if vm sudo /home/ubuntu/ips/install.sh; then
    echo "FAIL: install.sh accepted a broken suricata.yaml"; exit 1
fi
vm sudo cp /home/ubuntu/suricata.yaml.good /home/ubuntu/ips/files/suricata.yaml
vm sudo systemctl is-active --quiet suricata
vm sudo /home/ubuntu/ips/check.sh

step "uninstall.sh"
vm sudo /home/ubuntu/ips/uninstall.sh --yes
if vm sudo sh -c 'iptables -t mangle -S; ip6tables -t mangle -S' | grep -qE 'NFQUEUE|SURICATA-NFQ'; then
    echo "FAIL: firewall rules left behind after uninstall"; exit 1
fi
vm getent hosts archive.ubuntu.com >/dev/null

echo
echo "VM smoke test passed"
