# Checks that need nothing installed and change nothing on this machine.
#
#   make lint            syntax of every script, unit, policy and config in the repo
#   sudo make test       the firewall scripts, in a throwaway network namespace
#   sudo tests/dry-run.sh <installer>   rehearse an installer without changing this machine
#   make vm-test         full install -> check -> uninstall cycle in a fresh Ubuntu VM (needs multipass)

SHELL := /bin/bash
SH_FILES := install.sh uninstall.sh check.sh status.sh \
	files/suricata-home-net.sh files/suricata-nfqueue-apply.sh files/90-suricata-home-net \
	controld/install.sh controld/uninstall.sh controld/verify.sh \
	controld/files/dns-lockdown.sh controld/files/dns-lockdown-rules.sh \
	tetragon/config.sh tetragon/local_install.sh tetragon/local_uninstall.sh \
	tetragon/run.sh tetragon/stop.sh tetragon/check.sh \
	watch/install.sh watch/uninstall.sh watch/files/ips-watch watch/files/ips-notify \
	tests/firewall-netns.sh tests/dry-run.sh tests/vm-smoke.sh tests/lint.sh
PY_FILES := analyse.py tetragon/viewer/server.py watch/files/tetragon-notify.py

.PHONY: lint test vm-test

lint:
	@tests/lint.sh $(SH_FILES) -- $(PY_FILES)

test:
	tests/firewall-netns.sh

vm-test:
	tests/vm-smoke.sh
