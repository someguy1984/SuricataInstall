# Checks that need nothing installed and change nothing on this machine.
#
#   make lint            syntax of the scripts, Python, Tetragon policies, export denylist, generated DNS rules, JSON, the kits' systemd units
#                        and the server_edr_solution release tarballs (CI=1: a missing shellcheck, PyYAML or systemd-analyze fails)
#   make unit            unit tests of the hub and the client agent (no root, no network)
#   make unit-2404       the same suites and the loopback end-to-end test on Python 3.12 (Ubuntu 24.04) in a throwaway rootless Docker container
#   make dist            release tarballs of the server client and the hub, with MANIFEST.sha256, VERSION and .sha256, in dist/
#   sudo make test       the firewall scripts and the server kit's three nft tables in throwaway network namespaces; analyse.py and the alerting on synthetic input
#   sudo tests/dry-run.sh <installer>   rehearse an installer without changing this machine
#   make vm-test         Suricata kit install -> check -> uninstall cycle in a fresh Ubuntu VM (needs multipass)

SHELL := /bin/bash
SH_FILES := status.sh suricata/install.sh suricata/uninstall.sh suricata/check.sh \
	suricata/files/suricata-home-net.sh suricata/files/suricata-nfqueue-apply.sh suricata/files/90-suricata-home-net \
	controld/install.sh controld/uninstall.sh controld/verify.sh \
	controld/files/dns-lockdown.sh controld/files/dns-lockdown-rules.sh \
	tetragon/config.sh tetragon/local_install.sh tetragon/local_uninstall.sh \
	tetragon/run.sh tetragon/stop.sh tetragon/check.sh \
	watch/install.sh watch/uninstall.sh watch/files/ips-watch watch/files/ips-notify \
	tests/firewall-netns.sh tests/analyse-smoke.sh tests/watch-smoke.sh tests/dry-run.sh tests/vm-smoke.sh tests/lint.sh \
	tests/unit.sh tests/unit-2404.sh tests/dist.sh tests/server-netns.sh \
	server_edr_solution/mock/mock.sh server_edr_solution/mock/common/mock-tls.sh \
	windows_qemu/inspect.sh windows_qemu/run_windows_qemu.sh windows_qemu/run_windows_sentinel_replica.sh
# Everything under server_edr_solution/ is found by its shebang, so a new script is checked the day it is written
# ([#] is a # that make does not take for a comment)
SERVER_SH := $(shell grep -rlIE '^[#]!.*\b(ba)?sh\b' server_edr_solution --exclude-dir=__pycache__ --exclude-dir=.git 2>/dev/null)
SH_FILES := $(sort $(SH_FILES) $(SERVER_SH))
PY_FILES := suricata/analyse.py tetragon/viewer/server.py watch/files/tetragon-notify.py \
	windows_qemu/monitor.py windows_qemu/replica/analyze_run.py windows_qemu/replica/make_key_dmpstore.py \
	windows_qemu/replica/qmp_watch.py
# The server code: every .py file, and the Python scripts with no .py name (server_hub/hub/edr-hub, the client helpers)
SERVER_PY := $(shell find server_edr_solution -name '*.py' -type f -not -path '*/__pycache__/*' 2>/dev/null) \
	$(shell grep -rlIE '^[#]!.*python3' server_edr_solution --exclude-dir=__pycache__ --exclude-dir=.git 2>/dev/null)
PY_FILES := $(sort $(PY_FILES) $(SERVER_PY))

.PHONY: lint test vm-test unit unit-2404 dist

lint:
	@tests/lint.sh $(SH_FILES) -- $(PY_FILES)

unit:
	@tests/unit.sh

unit-2404:
	@tests/unit-2404.sh

dist:
	@tests/dist.sh

test:
	tests/firewall-netns.sh
	tests/analyse-smoke.sh
	tests/watch-smoke.sh
	tests/server-netns.sh

vm-test:
	tests/vm-smoke.sh
