"""check.sh (client PLAN section 8): the shell is checked statically and for its usage errors only (it is never run
for real here); the file-reading checks behind `edr-agent checks` run against fixtures in temporary directories."""
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_daemon_support import Tmp, cfgmod, evmod, CODE                   # noqa: E402
from edragent import checks, cli                                            # noqa: E402

CHECK_SH = os.path.normpath(os.path.join(CODE, "..", "check.sh"))
NOW = 1_795_000_000.0


class TestShell(unittest.TestCase):
    def run_sh(self, *args):
        p = subprocess.run(["/bin/bash", CHECK_SH] + list(args), capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout, p.stderr

    def test_syntax(self):
        p = subprocess.run(["bash", "-n", CHECK_SH], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_shellcheck(self):
        if shutil.which("shellcheck") is None:
            self.fail("shellcheck is missing (CI fails, never skips)")
        p = subprocess.run(["shellcheck", "-S", "warning", "-x", CHECK_SH], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_usage_errors_exit_64_before_anything_runs(self):
        for args in (["--bogus"], ["--yes"], ["--live", "--nope"], ["live"]):
            code, out, err = self.run_sh(*args)
            self.assertEqual(code, 64, args)
            self.assertIn("usage:", err)
            self.assertEqual(out, "")

    def test_help_exits_0(self):
        code, out, err = self.run_sh("--help")
        self.assertEqual(code, 0)
        for opt in ("--live", "--audit", "--local", "--yes"):
            self.assertIn(opt, err)

    def test_the_script_follows_the_plan_literally(self):
        with open(CHECK_SH) as f:
            text = f.read()
        self.assertIn("nft -t list table", text)
        self.assertNotIn("nft list ruleset", text)
        self.assertNotRegex(text, r"nft\s+list\b")
        self.assertTrue(text.startswith("#!/bin/bash\n"))
        self.assertIn("set -uo pipefail", text)
        for needle in ("--live", "--audit", "--local", "--yes", "SCTP canaries not run", "/usr/libexec/edr/canary", "edr-install-rollback",
                       "systemd-analyze critical-chain network-pre.target", "setpriv", "9.9.9.9", "dnscrypt-proxy -check", "suricata -T",
                       "midstream", "dump-all-headers", "edr-ban-sids.txt", "inet edr_dns", "edr-dns-watch.timer", "edr-bans.path"):
            self.assertIn(needle, text, needle)
        # the exit codes of section 15
        self.assertIn("exit 64", text)
        self.assertIn("exit 2", text)
        self.assertIn("exit 1", text)

    def test_the_live_warning_comes_before_the_canaries(self):
        with open(CHECK_SH) as f:
            text = f.read()
        self.assertLess(text.index("PAGES THE HUB"), text.index("head -c 1 /etc/shadow"))
        self.assertLess(text.index("PAGES THE HUB"), text.index("setpriv --reuid \"$run_uid\""))
        # the SCTP canaries run only with --yes on an enrolled or notifying host
        self.assertRegex(text, r"enrolled.*notify.*\(\(!YES\)\)")

    def test_it_is_in_the_installed_name_notes(self):
        with open(CHECK_SH) as f:
            self.assertIn("edr-check", f.read())


class CheckCase(Tmp):
    def setUp(self):
        super().setUp()
        self.uid = os.getuid()
        self.lib = os.path.join(self.root, "lib")
        os.makedirs(self.lib)
        self.paths.lib_dir = self.lib
        self.write(os.path.join(self.lib, "edr-agent.py"), "x = 1\n", 0o644)

    def run_(self, section, now=NOW, local=False, phase=None, text=None):
        cfg = self.conf(text) if text is not None else cfgmod.load(self.paths)
        return checks.run_section(section, self.paths, cfg, now=now, local=local, owner_uid=self.uid, phase=phase)

    def levels(self, out):
        return [lvl for lvl, _ in out]

    def has(self, out, level, needle):
        return any(l == level and needle in t for l, t in out)

    def put(self, path, obj):
        self.write(path, json.dumps(obj))

    def manifest(self, **kw):
        m = {"v": 1, "version": "0.1.0", "phase": "P2", "components": {}, "sessions": [
            {"id": "a", "kind": "install", "started": 1, "finished": 2, "state": "confirmed", "files": []}]}
        m.update(kw)
        self.put(self.paths.manifest_json, m)
        return m


class TestKit(CheckCase):
    def test_a_clean_install(self):
        self.manifest()
        self.write(self.paths.local_conf, "[bans]\nauto_ban = on\n", 0o640)
        out = self.run_("kit")
        self.assertTrue(self.has(out, "PASS", "version 0.1.0 matches the manifest"))
        self.assertTrue(self.has(out, "PASS", "root-owned and not group or other writable"))
        self.assertTrue(self.has(out, "PASS", "no unconfirmed install session"))
        self.assertTrue(self.has(out, "PASS", "parses with no unknown key"))
        self.assertNotIn("FAIL", self.levels(out))

    def test_version_mismatch_is_a_fail(self):
        self.manifest(version="0.0.9")
        self.assertTrue(self.has(self.run_("kit"), "FAIL", "manifest says 0.0.9"))
        self.write(os.path.join(self.lib, "VERSION"), "9.9.9\n")
        self.manifest()
        self.assertTrue(self.has(self.run_("kit"), "FAIL", "VERSION file says 9.9.9"))

    def test_no_manifest_is_a_warn(self):
        out = self.run_("kit")
        self.assertTrue(self.has(out, "WARN", "no install manifest"))

    def test_an_unknown_local_conf_key_is_a_fail(self):
        self.manifest()
        self.write(self.paths.local_conf, "[bans]\nauto_bann = on\n", 0o640)
        out = self.run_("kit")
        self.assertTrue(self.has(out, "FAIL", "local.conf is not valid"))
        self.assertTrue(self.has(out, "FAIL", "auto_bann"))

    def test_local_conf_mode(self):
        self.manifest()
        self.write(self.paths.local_conf, "", 0o666)
        self.assertTrue(self.has(self.run_("kit"), "FAIL", "only root may write it"))
        self.write(self.paths.local_conf, "", 0o644)
        os.chmod(self.paths.local_conf, 0o644)
        out = self.run_("kit")
        self.assertTrue(self.has(out, "WARN", "expected root:edr-agent 0640"))
        self.assertFalse(self.has(out, "FAIL", "local.conf"))

    def test_code_that_others_can_write_is_a_fail(self):
        self.manifest()
        os.chmod(os.path.join(self.lib, "edr-agent.py"), 0o666)
        self.assertTrue(self.has(self.run_("kit"), "FAIL", "group or other writable"))
        os.chmod(os.path.join(self.lib, "edr-agent.py"), 0o644)
        out = checks.run_section("kit", self.paths, cfgmod.load(self.paths), now=NOW, owner_uid=self.uid + 1)
        self.assertTrue(self.has(out, "FAIL", "owned by uid"))

    def test_an_unconfirmed_session_is_a_warn(self):
        m = self.manifest()
        m["sessions"].append({"id": "b", "kind": "upgrade", "state": "awaiting-confirm", "files": []})
        self.put(self.paths.manifest_json, m)
        self.assertTrue(self.has(self.run_("kit"), "WARN", "not confirmed"))

    def test_a_left_over_policy_rc_d(self):
        m = self.manifest()
        m["sessions"][0]["policy_rc_d_ours"] = True
        self.put(self.paths.manifest_json, m)
        self.write(self.paths._p("/usr/sbin/policy-rc.d"), "#!/bin/sh\n")
        self.assertTrue(self.has(self.run_("kit"), "WARN", "policy-rc.d"))

    def test_apparmor_userns_sysctl(self):
        self.manifest()
        self.paths.proc_dir = os.path.join(self.root, "proc")
        self.write(os.path.join(self.root, "proc", "sys", "kernel", "apparmor_restrict_unprivileged_userns"), "0\n")
        self.assertTrue(self.has(self.run_("kit"), "WARN", "apparmor_restrict_unprivileged_userns is 0"))
        self.write(os.path.join(self.root, "proc", "sys", "kernel", "apparmor_restrict_unprivileged_userns"), "1\n")
        self.assertTrue(self.has(self.run_("kit"), "PASS", "apparmor_restrict_unprivileged_userns is 1"))

    def test_an_agent_older_than_its_code(self):
        self.manifest()
        proc = os.path.join(self.root, "proc")
        self.paths.proc_dir = proc
        self.write(os.path.join(proc, "stat"), "cpu 1 2 3\nbtime 1000\n")
        os.makedirs(os.path.join(proc, "321"))
        self.write(os.path.join(proc, "321", "cmdline"), "/usr/bin/python3\0-I\0%s/edr-agent.py\0" % self.lib)
        hz = os.sysconf("SC_CLK_TCK")
        fields = ["S"] + ["0"] * 18 + [str(int(500 * hz))] + ["0"] * 5      # started 500 s after boot: epoch 1500
        self.write(os.path.join(proc, "321", "stat"), "321 (python3) " + " ".join(fields) + "\n")
        os.utime(os.path.join(self.lib, "edr-agent.py"), (4000, 4000))
        self.assertTrue(self.has(self.run_("kit"), "WARN", "started before its code was last changed"))
        os.utime(os.path.join(self.lib, "edr-agent.py"), (1000, 1000))
        self.assertFalse(self.has(self.run_("kit"), "WARN", "started before"))


class TestAudit(CheckCase):
    def sha(self, text):
        return hashlib.sha256(text.encode()).hexdigest()

    def test_a_changed_file_is_a_warn_a_matching_one_a_pass_and_a_missing_one_a_warn(self):
        good = self.write(os.path.join(self.root, "etc", "a.conf"), "one\n")
        bad = self.write(os.path.join(self.root, "etc", "b.conf"), "tampered\n")
        m = self.manifest()
        m["sessions"][0]["files"] = [{"path": "/etc/a.conf", "sha256": self.sha("one\n")}, {"path": "/etc/b.conf", "sha256": self.sha("original\n")},
                                     {"path": "/etc/gone.conf", "sha256": self.sha("x")}]
        self.put(self.paths.manifest_json, m)
        self.paths.root = self.root
        out = self.run_("audit")
        self.assertTrue(self.has(out, "WARN", "/etc/b.conf differs"))
        self.assertTrue(self.has(out, "WARN", "/etc/gone.conf is listed in the manifest and is missing"))
        self.assertFalse(self.has(out, "WARN", "/etc/a.conf"))
        self.assertFalse(self.has(out, "PASS", "match the manifest"))

    def test_all_matching_is_a_pass_and_the_latest_record_of_a_path_wins(self):
        self.write(os.path.join(self.root, "etc", "a.conf"), "two\n")
        m = self.manifest()
        m["sessions"][0]["files"] = [{"path": "/etc/a.conf", "sha256": self.sha("one\n")}]
        m["sessions"].append({"id": "b", "kind": "upgrade", "state": "confirmed", "files": [{"path": "/etc/a.conf", "sha256": self.sha("two\n")}]})
        self.put(self.paths.manifest_json, m)
        out = self.run_("audit")
        self.assertTrue(self.has(out, "PASS", "1 files match the manifest"))

    def test_hostile_manifest_entries_are_ignored(self):
        m = self.manifest()
        m["sessions"][0]["files"] = [{"path": "../etc/shadow", "sha256": "0" * 64}, {"path": "relative", "sha256": "0" * 64}, "junk",
                                     {"path": "/etc/a\x00b", "sha256": "0" * 64}, {"path": "/x", "sha256": 5}]
        self.put(self.paths.manifest_json, m)
        out = self.run_("audit")
        self.assertEqual(self.levels(out), ["WARN"])
        self.assertIn("lists no files", out[0][1])

    def test_a_symlink_in_place_of_a_listed_file_is_a_warn(self):
        self.write(os.path.join(self.root, "target"), "x")
        os.makedirs(os.path.join(self.root, "etc"), exist_ok=True)
        os.symlink(os.path.join(self.root, "target"), os.path.join(self.root, "etc", "a.conf"))
        m = self.manifest()
        m["sessions"][0]["files"] = [{"path": "/etc/a.conf", "sha256": self.sha("x")}]
        self.put(self.paths.manifest_json, m)
        self.assertTrue(self.has(self.run_("audit"), "WARN", "a.conf"))


def make_cert(path, key, days=1):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key,
                    "-out", path, "-days", str(days), "-subj", "/CN=test"], check=True, capture_output=True)


class TestAgent(CheckCase):
    def summary(self, hub=None, **ag):
        agent = {"pid": os.getpid(), "version": "0.1.0", "config": "local", "config_errors": [], "started": NOW - 3600}
        agent.update(ag)
        self.put(self.paths.summary_json, {"v": 1, "written_at": int(NOW) - 5, "counts": {}, "alerts": [], "hub": hub or {"mode": "local"}, "agent": agent})

    def enroll(self, not_after_days=100):
        d = os.path.join(self.paths.identity_dir, "gen-1")
        if os.path.isdir(d):
            return os.path.join(d, "client.pem")
        os.makedirs(d)
        self.write(os.path.join(d, "hub.conf"), "[hub]\naddresses = 203.0.113.5\nport = 8443\nenroll_port = 8444\nhost_uuid = x\nca_sha256 = %s\n" % ("a" * 64))
        make_cert(os.path.join(d, "client.pem"), os.path.join(self.root, "k.pem"), days=1)
        os.symlink("gen-1", os.path.join(self.paths.identity_dir, "current"))
        return os.path.join(d, "client.pem")

    def test_not_running_is_a_fail(self):
        self.assertTrue(self.has(self.run_("agent"), "FAIL", "the agent is not running: no "))
        self.put(self.paths.summary_json, {"written_at": int(NOW) - 1000, "agent": {"pid": os.getpid()}, "hub": {}})
        self.assertTrue(self.has(self.run_("agent"), "FAIL", "its summary is 1000 s old"))

    def test_running_in_local_mode(self):
        self.summary()
        self.put(self.paths.agent_state_json, {"last_seen": int(NOW) - 30})
        self.put(self.paths.inventory_json, {"checks": {}, "findings": []})
        os.utime(self.paths.inventory_json, (NOW - 600, NOW - 600))
        out = self.run_("agent")
        self.assertTrue(self.has(out, "PASS", "the agent is running"))
        self.assertTrue(self.has(out, "PASS", "sandbox self-test"))
        self.assertTrue(self.has(out, "PASS", "inventory.json is 10 minutes old"))
        self.assertTrue(self.has(out, "PASS", "no CRITICAL alert in the last 24 hours"))
        self.assertTrue(self.has(out, "PASS", "local mode: heartbeat n/a"))
        self.assertNotIn("FAIL", self.levels(out))

    def test_stale_inventory_is_a_warn(self):
        self.summary()
        self.put(self.paths.inventory_json, {"checks": {}, "findings": []})
        os.utime(self.paths.inventory_json, (NOW - 3 * 3600, NOW - 3 * 3600))
        self.assertTrue(self.has(self.run_("agent"), "WARN", "inventory.json is 180 minutes old"))
        os.unlink(self.paths.inventory_json)
        self.assertTrue(self.has(self.run_("agent"), "WARN", "inventory.json is missing"))

    def test_sandbox_failure_critical_alert_and_spool(self):
        self.summary()
        from edragent import alertlog
        a = alertlog.AlertLog(self.paths.alerts_jsonl, lambda: NOW)
        ts = int((NOW - 3600) * 1000)
        a.add(evmod.make_event("health.sandbox_ineffective", "agent", "HIGH", "x", ts_ms=ts), NOW - 3600)
        a.add(evmod.make_event("tetragon.nginx-exec", "tetragon", "CRITICAL", "a worker exec", ts_ms=ts), NOW - 3600)
        a.close()
        os.makedirs(self.paths.spool_dir)
        with open(os.path.join(self.paths.spool_dir, "seg"), "wb") as f:
            f.truncate(60 * 1024 * 1024)
        out = self.run_("agent")
        self.assertTrue(self.has(out, "FAIL", "sandbox self-test failed"))
        self.assertTrue(self.has(out, "WARN", "1 CRITICAL alert(s) in the last 24 hours"))
        self.assertTrue(self.has(out, "WARN", "the spool is 60 MB"))
        a2 = alertlog.AlertLog(self.paths.alerts_jsonl, lambda: NOW)
        self.assertEqual(len(alertlog.read_alerts(self.paths.alerts_jsonl, NOW - 86400 * 2)), 2)

    def test_sandbox_failure_is_a_warn_where_the_kit_was_installed_with_no_kernel(self):
        # Found on the first install in the mock: under rootless Docker systemd has no BPF firewall, the agent's
        # self-test fails every start, and a FAIL here rolled the whole install back.
        self.put(self.paths.summary_json, {"v": 1, "written_at": int(NOW) - 5, "counts": {}, "hub": {"mode": "local"},
                                           "alerts": [{"sev": "HIGH", "kind": "health.sandbox_ineffective", "summary": "x"}],
                                           "agent": {"pid": os.getpid(), "version": "0.1.0", "config": "local", "config_errors": []}})
        self.assertTrue(self.has(self.run_("agent"), "FAIL", "sandbox self-test failed"))
        self.write(self.paths.local_conf, "[kit]\nkernel = off\n")
        out = self.run_("agent")
        self.assertTrue(self.has(out, "WARN", "sandbox self-test failed"))
        self.assertFalse(self.has(out, "FAIL", "sandbox self-test failed"))
        self.assertFalse(self.has(out, "PASS", "sandbox self-test"))

    def test_gaps_and_drops_in_24_hours(self):
        self.summary(health_24h={"gap": 2, "spool_dropped": 1})
        out = self.run_("agent")
        self.assertTrue(self.has(out, "WARN", "2 log gaps in the last 24 hours"))
        self.assertTrue(self.has(out, "WARN", "1 events dropped from the spool"))

    def test_config_errors_in_the_summary(self):
        self.summary(config="last-good", config_errors=["[bans] auto_ban: bad"])
        self.assertTrue(self.has(self.run_("agent"), "WARN", "last-good because local.conf is invalid"))

    def test_certificate_expiry(self):
        self.summary(hub={"mode": "enrolled", "last_heartbeat_ok": NOW - 10})
        cert = self.enroll()
        from edragent import identity
        na = identity.cert_not_after(cert)
        for days, level, needle in ((100, "PASS", "valid for 100 more days"), (20, "WARN", "expires in 20 days"), (10, "WARN", "expires in 10 days"),
                                    (5, "WARN", "expires in 5 days"), (-1, "FAIL", "expired on")):
            out = self.run_("agent", now=na - days * 86400 - 3600 if days >= 0 else na + 3600)
            self.assertTrue(self.has(out, level, needle), (days, out))
        # a P1 install does not check it, and a host in local mode has none
        self.assertFalse(self.has(self.run_("agent", phase="P1b", now=na + 3600), "FAIL", "certificate"))

    def test_droplet_id(self):
        self.summary(hub={"mode": "enrolled", "last_heartbeat_ok": NOW - 10})
        self.enroll()
        self.assertTrue(self.has(self.run_("agent"), "WARN", "droplet-id is missing"))
        self.write(self.paths.droplet_id, "12345\n", 0o640)
        out = self.run_("agent")
        self.assertTrue(self.has(out, "PASS", "droplet id is present") or self.has(out, "WARN", "expected root:edr-agent 0640"))
        self.write(self.paths.droplet_id, "\n", 0o640)
        self.assertTrue(self.has(self.run_("agent"), "WARN", "missing or empty"))

    def hub(self, **kw):
        h = {"mode": "enrolled", "hub": "203.0.113.5:8443", "last_heartbeat_ok": NOW - 30, "last_error": "", "unreachable_s": 0}
        h.update(kw)
        self.summary(hub=h)
        self.enroll()
        return self.run_("agent")

    def test_heartbeat_thresholds(self):
        self.assertTrue(self.has(self.hub(last_heartbeat_ok=NOW - 30), "PASS", "last accepted heartbeat was 30 s ago"))
        self.assertTrue(self.has(self.hub(last_heartbeat_ok=NOW - 150), "WARN", "last accepted heartbeat was 150 s ago"))
        out = self.hub(last_heartbeat_ok=NOW - 400)
        self.assertTrue(self.has(out, "FAIL", "the uplink is stuck"))
        out = self.hub(last_heartbeat_ok=NOW - 400, last_error="timeout", unreachable_s=400)
        self.assertFalse(self.has(out, "FAIL", "heartbeat"))                                  # a hub outage is never an agent FAIL
        self.assertTrue(self.has(out, "WARN", "the hub has been unreachable for 6 minutes (last error: timeout)"))
        self.assertTrue(self.has(out, "WARN", "last accepted heartbeat was 6 minutes ago"))

    def test_hub_statuses(self):
        self.assertTrue(self.has(self.hub(orphan=True, blocked="host_orphan"), "WARN", "adopt this host on the hub"))
        out = self.hub(blocked="host_revoked")
        self.assertTrue(self.has(out, "FAIL", "refuses this host: host_revoked"))
        self.assertTrue(self.has(self.hub(held={"events": 426}), "WARN", "426"))
        self.assertTrue(self.has(self.hub(held={"events": "schema_too_old"}), "WARN", "422"))
        self.assertTrue(self.has(self.hub(min_client_schema=5), "WARN", "below the hub's minimum 5"))
        self.assertFalse(self.has(self.hub(min_client_schema=1), "WARN", "minimum"))

    def test_local_skips_the_hub_checks(self):
        self.summary(hub={"mode": "enrolled", "last_heartbeat_ok": NOW - 4000, "last_error": "", "blocked": "host_revoked"})
        self.enroll()
        out = self.run_("agent", local=True)
        self.assertTrue(self.has(out, "INFO", "hub checks skipped (--local)"))
        self.assertFalse(self.has(out, "FAIL", "refuses"))
        self.assertFalse(self.has(out, "FAIL", "heartbeat"))

    def test_local_mode_last_event_age(self):
        self.summary()
        self.put(self.paths.agent_state_json, {"last_seen": int(NOW) - 400})
        self.assertTrue(self.has(self.run_("agent"), "FAIL", "last event processed was 6 minutes ago"))
        self.put(self.paths.agent_state_json, {"last_seen": int(NOW) - 150})
        self.assertTrue(self.has(self.run_("agent"), "WARN", "last event processed was 150 s ago"))


class TestStatusFiles(CheckCase):
    def put(self, path, obj, age=0):
        obj = dict(obj)
        obj.setdefault("written_at", int(NOW - age))
        self.write(path, json.dumps(obj))
        os.utime(path, (NOW - age, NOW - age))

    def pause(self, delta):
        self.write(self.paths.pause_json, json.dumps({"until": int(NOW + delta)}))

    def test_policy_check_fresh_stale_and_enforcement_gone(self):
        pol = [{"name": "nginx-exec", "mode": "enforce", "state": "loaded", "want": "enforce"},
               {"name": "sctp-socket", "mode": "monitor", "state": "loaded", "want": "enforce", "gate": "ss --sctp is not empty"}]
        self.put(self.paths.policy_check_status, {"policies": pol, "enforcement_gone": [], "canary": {"ok": True}}, age=30)
        out = self.run_("tetragon")
        self.assertTrue(self.has(out, "PASS", "the policy check is 30 s old"))
        self.assertTrue(self.has(out, "PASS", "policy nginx-exec is loaded and enforcing"))
        self.assertTrue(self.has(out, "WARN", "policy sctp-socket stays in monitor: ss --sctp is not empty"))
        self.assertTrue(self.has(out, "PASS", "no policy has lost enforcement"))
        self.put(self.paths.policy_check_status, {"policies": pol, "enforcement_gone": ["nginx-exec"]}, age=900)
        out = self.run_("tetragon")
        self.assertTrue(self.has(out, "WARN", "the policy check is 15 minutes old"))
        self.assertTrue(self.has(out, "FAIL", "enforcement is gone for: nginx-exec"))

    def test_a_missing_policy_status_is_unknown_not_clean(self):
        self.assertTrue(self.has(self.run_("tetragon"), "WARN", "status.json is missing: policy state unknown"))
        self.write(self.paths.policy_check_status, "{broken")
        self.assertTrue(self.has(self.run_("tetragon"), "WARN", "not valid JSON"))

    def test_a_policy_set_to_enforce_that_is_not_loaded_is_a_fail_unless_paused(self):
        self.put(self.paths.policy_check_status, {"policies": [{"name": "nginx-exec", "mode": "monitor", "state": "loaded"}]}, age=10)
        out = self.run_("tetragon")
        self.assertTrue(self.has(out, "FAIL", "policy sctp-socket is set to enforce and is not loaded"))
        self.pause(3600)
        out = self.run_("tetragon")
        self.assertTrue(self.has(out, "WARN", "policy sctp-socket is set to enforce and is not loaded (paused until"))
        self.assertTrue(self.has(out, "WARN", "policy nginx-exec is held in monitor: paused until"))
        self.assertFalse(self.has(out, "FAIL", "policy"))

    def test_an_expired_pause_file_is_ignored(self):
        self.put(self.paths.policy_check_status, {"policies": [{"name": "nginx-exec", "mode": "monitor", "state": "loaded"}]}, age=10)
        self.pause(-10)
        out = self.run_("tetragon")
        self.assertTrue(self.has(out, "FAIL", "policy sctp-socket is set to enforce and is not loaded"))
        self.assertFalse(self.has(out, "WARN", "paused"))
        self.put(self.paths.bans_counters, {"table_present": False}, age=5)
        self.assertTrue(self.has(self.run_("bans"), "FAIL", "table inet edr is absent"))
        self.assertEqual(checks.helper_value("pause", self.paths, cfgmod.load(self.paths), NOW), "")
        self.pause(100)
        self.assertEqual(checks.helper_value("pause", self.paths, cfgmod.load(self.paths), NOW), str(int(NOW + 100)))

    def test_ban_state_and_pause(self):
        self.put(self.paths.bans_counters, {"table_present": True, "sets": {"edr_ban4": 3}, "last_apply": {"ok": True, "error": ""},
                                            "conntrack": {"count": 10, "max": 100, "drop": 0, "early_drop": 0}}, age=20)
        out = self.run_("bans")
        self.assertTrue(self.has(out, "PASS", "table inet edr is present (edr_ban4=3)"))
        self.assertTrue(self.has(out, "PASS", "edr-bans last apply is clean"))
        self.assertTrue(self.has(out, "PASS", "conntrack is 10% full"))
        self.put(self.paths.bans_counters, {"table_present": False}, age=20)
        self.pause(600)
        out = self.run_("bans")
        self.assertTrue(self.has(out, "WARN", "paused until"))
        self.assertFalse(self.has(out, "FAIL", "table inet edr"))

    def test_conntrack_thresholds_and_rising_drops(self):
        for count, level in ((50, "PASS"), (75, "WARN"), (95, "FAIL")):
            self.put(self.paths.bans_counters, {"table_present": True, "conntrack": {"count": count, "max": 100, "drop": 0, "early_drop": 0}}, age=5)
            self.assertTrue(self.has(self.run_("bans"), level, "conntrack is %d%% full" % count), count)
        self.put(self.paths.bans_counters, {"table_present": True, "conntrack": {"count": 1, "max": 100, "drop": 7, "early_drop": 0}}, age=5)
        self.assertTrue(self.has(self.run_("bans"), "WARN", "drop counters are rising"))
        self.assertFalse(self.has(self.run_("bans"), "WARN", "rising"))

    def test_stale_ban_counters_and_a_ban_on_the_metadata_address(self):
        self.put(self.paths.bans_counters, {"table_present": True}, age=1200)
        self.assertTrue(self.has(self.run_("bans"), "WARN", "20 minutes old"))
        self.put(self.paths.bans_json, {"never": ["10.0.0.0/8"], "bans": [{"cidr": "169.254.0.0/16"}]})
        self.assertTrue(self.has(self.run_("bans"), "FAIL", "169.254.169.254 is covered by a ban"))

    def test_dns_lock_states(self):
        def state(s, age=10):
            self.put(self.paths.dns_watch_status, {"state": s, "since": 1, "relocks": 0}, age=age)
            return self.run_("dns")
        self.assertTrue(self.has(state("locked"), "PASS", "the DNS lock is locked"))
        self.assertTrue(self.has(state("open"), "FAIL", "OPEN"))
        self.assertTrue(self.has(state("flapping"), "WARN", "flapping"))
        self.assertTrue(self.has(state("paused"), "WARN", "not in force"))
        self.assertTrue(self.has(state("locked", age=300), "WARN", "5 minutes old"))
        self.pause(3600)
        out = state("paused", age=500)
        self.assertTrue(self.has(out, "WARN", "paused until"))
        self.assertFalse(self.has(out, "FAIL", "DNS"))
        self.assertFalse(self.has(out, "WARN", "minutes old"))                              # a paused host's status may be old

    def test_dns_lockdown_off_is_skipped_never_a_fail(self):
        out = self.run_("dns", text="[dns]\nlockdown = off\n")
        self.assertEqual(self.levels(out), ["INFO"])

    def test_missing_dns_status_is_a_warn(self):
        self.assertTrue(self.has(self.run_("dns"), "WARN", "is missing"))

    def test_components_switched_off_are_skipped(self):
        out = self.run_("tetragon", text="[kit]\ntetragon = off\n")
        self.assertEqual(self.levels(out), ["INFO"])
        out = self.run_("suricata", text="[kit]\nsuricata = off\n")
        self.assertEqual(self.levels(out), ["INFO"])

    def test_tetragon_log_perms_and_home_placeholder(self):
        self.put(self.paths.policy_check_status, {"policies": []}, age=10)
        self.write(self.paths.tetragon_log, "", 0o640)
        os.makedirs(self.paths.tetragon_tp_dir)
        self.write(os.path.join(self.paths.tetragon_tp_dir, "edr-x.yaml"), "path: @HOME@/x\n")
        out = self.run_("tetragon", text="[tetragon]\nenforce =\n")
        self.assertTrue(self.has(out, "FAIL", "@HOME@ is left in a rendered policy"))
        self.assertTrue(self.has(out, "WARN", "group edr-agent") or self.has(out, "FAIL", "expected group edr-agent") or self.has(out, "PASS", "tetragon.log"))
        os.chmod(self.paths.tetragon_log, 0o644)
        self.assertTrue(self.has(self.run_("tetragon", text="[tetragon]\nenforce =\n"), "FAIL", "0640"))

    def test_coverage_drift_from_p1b(self):
        self.put(self.paths.policy_check_status, {"policies": []}, age=10)
        inv = {"checks": {"uncovered_webroots": {"status": True, "paths": ["/srv/new"]}, "uncovered_fpm_binaries": {"status": False}}, "findings": []}
        self.put(self.paths.inventory_json, inv, age=10)
        self.assertTrue(self.has(self.run_("tetragon", phase="P1b", text="[tetragon]\nenforce =\n"), "WARN", "coverage drift (uncovered_webroots): /srv/new"))
        self.assertFalse(self.has(self.run_("tetragon", phase="P1a", text="[tetragon]\nenforce =\n"), "WARN", "coverage drift"))

    def test_disk_status_and_budgets(self):
        self.put(self.paths.diskguard_status, {"free_pct": 40, "stage": 0, "freed_mb": 0}, age=60)
        out = self.run_("disk")
        self.assertTrue(self.has(out, "PASS", "the disk guard ran 60 s ago"))
        self.assertTrue(self.has(out, "PASS", "free disk space is 40%"))
        self.put(self.paths.diskguard_status, {"free_pct": 4, "stage": 2}, age=900)
        out = self.run_("disk")
        self.assertTrue(self.has(out, "WARN", "15 minutes"))
        self.assertTrue(self.has(out, "FAIL", "stage 2"))
        os.makedirs(os.path.dirname(self.paths.tetragon_log), exist_ok=True)
        with open(self.paths.tetragon_log, "wb") as f:
            f.truncate(130 * 1024 * 1024)
        self.assertTrue(self.has(self.run_("disk"), "WARN", "Tetragon log uses 130 MB, over its 100 MB budget"))
        self.assertFalse(self.has(self.run_("disk", text="[kit]\ntetragon = off\n"), "WARN", "Tetragon log"))

    def test_findings_of_the_inventory(self):
        inv = {"checks": {"security_pending": {"lists_age_hours": 60}}, "findings": [
            {"check": "nginx_pkg", "sev": "HIGH", "summary": "nginx 1.24.0-2ubuntu7 is below its fix"},
            {"check": "deleted_exe", "sev": "HIGH", "summary": "nginx runs a deleted binary"},
            {"check": "security_pending", "sev": "MEDIUM", "summary": "3 security updates pending"},
            {"check": "posture", "sev": "HIGH", "summary": "APP_DEBUG is true"}]}
        self.put(self.paths.inventory_json, inv, age=10)
        out = self.run_("nginx")
        self.assertTrue(self.has(out, "FAIL", "nginx_pkg: nginx 1.24.0-2ubuntu7 is below its fix"))
        self.assertTrue(self.has(out, "FAIL", "restart nginx, a reload is not enough"))
        self.assertTrue(self.has(out, "WARN", "security_pending: 3 security updates pending"))
        self.assertTrue(self.has(out, "WARN", "posture: APP_DEBUG is true"))
        self.assertTrue(self.has(out, "WARN", "the apt lists are 60 hours old"))
        self.assertTrue(self.has(self.run_("nginx", text="[sites]\nweb_users = x\n"), "FAIL", "nginx_pkg"))

    def test_nginx_log_levels_and_formats(self):
        inv = {"checks": {"nginx_logs": {"error_logs": [{"path": "/var/log/nginx/error.log", "level": "error"}],
                                         "access_logs": [{"path": "a", "format": "vhost"}],
                                         "log_formats": {"vhost": {"starts_remote_addr": False}}},
                          "real_ip": {"status": True}}, "findings": []}
        self.put(self.paths.inventory_json, inv, age=10)
        out = self.run_("nginx")
        self.assertTrue(self.has(out, "INFO", "window_update (info)"))
        self.assertTrue(self.has(out, "WARN", "log_format vhost does not start with $remote_addr"))
        self.assertTrue(self.has(out, "INFO", "web-sourced bans are off"))
        self.assertFalse(self.has(out, "FAIL", ""))

    def test_missing_inventory_is_unknown_not_clean(self):
        out = self.run_("nginx")
        self.assertEqual(self.levels(out), ["WARN"])

    def test_suricata_drop_share(self):
        self.put(self.paths.summary_json, {"written_at": int(NOW), "agent": {"suricata_drops": {"packets": 1000, "drops": 50, "window_s": 60}}})
        self.assertTrue(self.has(self.run_("suricata"), "WARN", "dropped 5.0% of packets"))
        self.put(self.paths.summary_json, {"written_at": int(NOW), "agent": {"suricata_drops": {"packets": 1000, "drops": 1, "window_s": 60}}})
        self.assertTrue(self.has(self.run_("suricata"), "PASS", "dropped 0.10%"))

    def test_the_rule_update_status(self):
        self.put(self.paths.rules_status, {"written_at": int(NOW) - 7200, "ok": True, "skipped_days": 0, "message": "rules updated"})
        self.assertTrue(self.has(self.run_("suricata"), "PASS", "last rule update succeeded 2 hours ago"))
        self.put(self.paths.rules_status, {"written_at": int(NOW) - 4 * 86400, "ok": True, "skipped_days": 0, "message": "rules updated"})
        self.assertTrue(self.has(self.run_("suricata"), "WARN", "succeeded 4 days ago"))
        self.put(self.paths.rules_status, {"written_at": int(NOW), "ok": False, "skipped_days": 3, "message": "rules_stale: memory too short for 3 days"})
        out = self.run_("suricata")
        self.assertTrue(self.has(out, "WARN", "did not succeed (rules_stale: memory too short for 3 days), 3 day(s) skipped"))

    def test_netcheck(self):
        self.manifest = None
        addr = "2: eth0    inet 203.0.113.9/24 brd 203.0.113.255 scope global eth0\n3: eth1    inet 10.116.0.2/20 scope global eth1\n1: lo    inet 127.0.0.1/8 scope host lo"
        route = "default via 203.0.113.1 dev eth0\n"
        good = "HOME_NET: '[203.0.113.0/24,10.116.0.0/20]'\n"
        self.put(self.paths.bans_json, {"never": ["203.0.113.9/32", "10.116.0.2/32", "203.0.113.1/32", "198.51.100.7/32"]})
        cfg = self.conf("[bans]\nadmin_ip = 198.51.100.7\n")
        out = checks.run_section("netcheck", self.paths, cfg, now=NOW, stdin="%s\n---\n%s\n---\n%s" % (addr, route, good), phase="P1b")
        self.assertTrue(self.has(out, "PASS", "HOME_NET covers every address"))
        self.assertTrue(self.has(out, "PASS", "never-ban list holds"))
        out = checks.run_section("netcheck", self.paths, cfg, now=NOW, phase="P1b",
                                 stdin="%s\n---\n%s\n---\n%s" % (addr, route, "HOME_NET: '[10.116.0.0/20]'\n"))
        self.assertTrue(self.has(out, "FAIL", "HOME_NET lacks 203.0.113.9"))
        self.put(self.paths.bans_json, {"never": ["203.0.113.9/32"]})
        out = checks.run_section("netcheck", self.paths, cfg, now=NOW, phase="P1b", stdin="%s\n---\n%s\n---\n%s" % (addr, route, good))
        self.assertTrue(self.has(out, "WARN", "never-ban list lacks"))
        self.assertTrue(self.has(out, "WARN", "gateway 203.0.113.1"))
        out = checks.run_section("netcheck", self.paths, cfg, now=NOW, phase="P1a", stdin="x")
        self.assertEqual(out, [])


class TestCommand(CheckCase):
    def main(self, *argv):
        old = os.environ.get("EDR_AGENT_ROOT")
        os.environ["EDR_AGENT_ROOT"] = self.root
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(list(argv))
        finally:
            os.environ.pop("EDR_AGENT_ROOT", None) if old is None else os.environ.__setitem__("EDR_AGENT_ROOT", old)
        return code, out.getvalue(), err.getvalue()

    def test_checks_prints_level_tab_text(self):
        code, out, _ = self.main("checks", "kit")
        self.assertEqual(code, 0)
        for line in out.splitlines():
            level, _, text = line.partition("\t")
            self.assertIn(level, ("PASS", "WARN", "FAIL", "INFO"))
            self.assertTrue(text)
        self.assertEqual(self.main("checks", "nonsense")[0], 64)

    def test_values_for_the_shell(self):
        self.manifest(phase="P1b")
        self.write(self.paths.local_conf, "[kit]\nweb = off\n[sites]\nweb_users = forge, www-data\nnginx_bin = /usr/sbin/nginx\n[dns]\nresolve_check = a.test, b.test\n")
        self.assertEqual(self.main("checks", "value", "phase")[1].strip(), "P1b")
        self.assertEqual(self.main("checks", "value", "conf:kit.web")[1].strip(), "off")
        self.assertEqual(self.main("checks", "value", "conf:kit.tetragon")[1].strip(), "on")
        self.assertEqual(self.main("checks", "value", "web_user")[1].strip(), "forge")
        self.assertEqual(self.main("checks", "value", "conf:dns.resolve_check")[1].strip(), "a.test, b.test")
        self.assertEqual(self.main("checks", "value", "enrolled")[1].strip(), "no")
        self.assertEqual(self.main("checks", "value", "notify")[1].strip(), "no")
        self.assertEqual(self.main("checks", "value", "phase_nonsense")[1].strip(), "")
        self.put(self.paths.policy_check_status, {"policies": [{"name": "sctp-socket", "mode": "enforce", "state": "loaded"}]})
        self.assertEqual(self.main("checks", "value", "policy_mode:sctp-socket")[1].strip(), "enforce/loaded")
        self.assertEqual(self.main("checks", "value", "policy_mode:other")[1].strip(), "missing")

    def test_phase_defaults_to_p2_and_ignores_junk(self):
        self.assertEqual(self.main("checks", "value", "phase")[1].strip(), "P2")
        self.manifest(phase="P9")
        self.assertEqual(self.main("checks", "value", "phase")[1].strip(), "P2")

    def test_tp_names_lists_the_rendered_policy_names(self):
        os.makedirs(self.paths.tetragon_tp_dir)
        self.write(os.path.join(self.paths.tetragon_tp_dir, "edr-web-exec.yaml"), 'metadata:\n  name: "web-exec"\n')
        self.write(os.path.join(self.paths.tetragon_tp_dir, "privilege-escalation.yaml"), 'metadata:\n  name: "privilege-escalation"\n')
        self.assertEqual(self.main("checks", "value", "tp_names")[1].strip(), "web-exec")

    def test_status_json(self):
        import time
        self.put(self.paths.summary_json, {"v": 1, "written_at": int(time.time()), "counts": {}, "alerts": [], "hub": {"mode": "local"},
                                           "agent": {"pid": os.getpid(), "version": "0.1.0"}})
        self.put(self.paths.agent_state_json, {"last_seen": 12345})
        code, out, _ = self.main("status", "--json")
        doc = json.loads(out)
        self.assertEqual(code, 0)
        self.assertIs(doc["running"], True)
        self.assertEqual(doc["last_seen"], 12345)
        self.assertEqual(doc["hub"], {"mode": "local"})
        os.unlink(self.paths.summary_json)
        code, out, _ = self.main("status", "--json")
        self.assertEqual(code, 2)
        self.assertIs(json.loads(out)["running"], False)

    def test_a_crashing_section_becomes_a_warn(self):
        real = checks.SECTIONS["disk"]
        checks.SECTIONS["disk"] = lambda ctx: 1 / 0
        try:
            out = checks.run_section("disk", self.paths, cfgmod.load(self.paths), now=NOW)
        finally:
            checks.SECTIONS["disk"] = real
        self.assertEqual(self.levels(out), ["WARN"])
        self.assertIn("failed to run", out[0][1])


if __name__ == "__main__":
    unittest.main()
