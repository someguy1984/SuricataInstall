"""Every path the agent uses (contract 7.1).

Set EDR_AGENT_ROOT=<dir> and every installed path is prefixed with it, so the agent runs without root
from a checkout and the tests stay inside a temporary directory. The code directory is never prefixed.
"""
import os

ENV_ROOT = "EDR_AGENT_ROOT"

# Where the real files live. The log names are the ones the plan gives (section 4.5, Inputs).
_ETC = "/etc/edr-agent"
_STATE = "/var/lib/edr-agent"
_RUN = "/run/edr-agent"
_LIB = "/usr/local/lib/edr-agent"
_LOGS = {
    "tetragon_log": "/var/log/tetragon/tetragon.log",
    "nginx_error_log": "/var/log/nginx/error.log",
    "nginx_access_log": "/var/log/nginx/access.log",
    "nginx_info_log": "/var/log/nginx/edr.log",
    "eve_json": "/var/log/suricata/eve.json",
    "eve_bulk_json": "/var/log/suricata/eve-bulk.json",
}


class Paths:
    def __init__(self, root=None, lib_dir=None):
        self.root = root if root is not None else os.environ.get(ENV_ROOT, "")
        self.dev = bool(self.root)          # a checkout or test run: "must be root" checks are skipped
        code_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        self.lib_dir = lib_dir or code_dir
        # Kernel interfaces. Instances may be pointed elsewhere by tests.
        self.proc_dir = self._maybe_rooted("/proc")
        self.sys_dir = self._maybe_rooted("/sys")

    def _maybe_rooted(self, path):
        """/proc and /sys are the kernel's, unless a test or dev root brings its own copy."""
        if self.root:
            rooted = os.path.join(self.root, path.lstrip("/"))
            if os.path.isdir(rooted):
                return rooted
        return path

    def _p(self, path):
        if not self.root:
            return path
        return os.path.join(self.root, path.lstrip("/"))

    # configuration
    etc_dir = property(lambda s: s._p(_ETC))
    local_conf = property(lambda s: os.path.join(s.etc_dir, "local.conf"))
    pause_json = property(lambda s: os.path.join(s.etc_dir, "pause.json"))
    notify_url = property(lambda s: os.path.join(s.etc_dir, "notify.url"))
    notify_min_severity = property(lambda s: os.path.join(s.etc_dir, "notify.min_severity"))
    tetragon_ignore = property(lambda s: os.path.join(s.etc_dir, "tetragon-ignore.conf"))

    # shipped files: beside the code first, then in ../files/ (a checkout)
    def _shipped(self, name):
        beside = os.path.join(self.lib_dir, name)
        if os.path.exists(beside):
            return beside
        return os.path.join(os.path.dirname(self.lib_dir), "files", name)

    def _shipped_dir(self, *parts):
        beside = os.path.join(self.lib_dir, *parts)
        if os.path.isdir(beside):
            return beside
        return os.path.join(os.path.dirname(self.lib_dir), *parts)

    policy_templates = property(lambda s: s._shipped_dir("tetragon", "policies"))
    tetragon_tp_dir = property(lambda s: s._p("/etc/tetragon/tetragon.tp.d"))
    dropin_path = property(lambda s: s._p("/etc/systemd/system/edr-agent.service.d/10-hub.conf"))
    manifest_json = property(lambda s: os.path.join(s.state_dir, "manifest.json"))
    install_manifest = property(lambda s: s._p("/var/lib/edr-install/manifest.json"))

    defaults_conf = property(lambda s: s._shipped("defaults.conf"))
    tripwires = property(lambda s: s._shipped("tripwires.json"))

    # state
    state_dir = property(lambda s: s._p(_STATE))
    identity_dir = property(lambda s: os.path.join(s.state_dir, "identity"))
    spool_dir = property(lambda s: os.path.join(s.state_dir, "spool"))
    cursors_dir = property(lambda s: os.path.join(s.state_dir, "cursors"))
    host_id = property(lambda s: os.path.join(s.state_dir, "host-id"))
    alerts_jsonl = property(lambda s: os.path.join(s.state_dir, "alerts.jsonl"))
    seen_json = property(lambda s: os.path.join(s.state_dir, "seen.json"))
    ban_state = property(lambda s: os.path.join(s.state_dir, "ban-state.json"))
    learn_json = property(lambda s: os.path.join(s.state_dir, "learn.json"))
    ids_json = property(lambda s: os.path.join(s.state_dir, "ids.json"))
    clean_marker = property(lambda s: os.path.join(s.state_dir, "clean-shutdown"))
    config_good = property(lambda s: os.path.join(s.state_dir, "local.conf.good"))
    agent_state_json = property(lambda s: os.path.join(s.state_dir, "agent-state.json"))

    # runtime
    run_dir = property(lambda s: s._p(_RUN))
    bans_json = property(lambda s: os.path.join(s.run_dir, "bans.json"))
    summary_json = property(lambda s: os.path.join(s.run_dir, "summary.json"))
    pid_file = property(lambda s: os.path.join(s.run_dir, "agent.pid"))
    droplet_id = property(lambda s: s._p("/run/edr-droplet-id"))
    inventory_json = property(lambda s: s._p("/run/edr-inventory/inventory.json"))
    bans_counters = property(lambda s: s._p("/run/edr-bans/counters.json"))
    diskguard_status = property(lambda s: s._p("/run/edr-diskguard/status.json"))
    policy_check_status = property(lambda s: s._p("/run/edr-policy-check/status.json"))
    dns_watch_status = property(lambda s: s._p("/run/edr-dns-watch/status.json"))
    rules_status = property(lambda s: s._p("/var/lib/suricata/rules/edr-rules-status.json"))
    nginx_pid = property(lambda s: s._p("/run/nginx.pid"))

    # logs that are read
    tetragon_log = property(lambda s: s._p(_LOGS["tetragon_log"]))
    nginx_error_log = property(lambda s: s._p(_LOGS["nginx_error_log"]))
    nginx_access_log = property(lambda s: s._p(_LOGS["nginx_access_log"]))
    nginx_info_log = property(lambda s: s._p(_LOGS["nginx_info_log"]))
    eve_json = property(lambda s: s._p(_LOGS["eve_json"]))
    eve_bulk_json = property(lambda s: s._p(_LOGS["eve_bulk_json"]))

    def log(self, name):
        """The path of one log by name: tetragon_log, nginx_error_log, nginx_access_log, eve_json, eve_bulk_json."""
        if name not in _LOGS:
            raise KeyError(name)
        return self._p(_LOGS[name])

    # kernel files read for the heartbeat
    def proc(self, *parts):
        return os.path.join(self.proc_dir, *parts)

    def sys(self, *parts):
        return os.path.join(self.sys_dir, *parts)

    def cgroup_system_slice(self):
        return self.sys("fs", "cgroup", "system.slice")
