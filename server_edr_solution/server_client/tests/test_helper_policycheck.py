"""L0 tests of agent/edr-policy-check (client PLAN section 4.3): gates, promotion, the pause, the
canary, enforcement_gone and the status file. tetra, setpriv and the other programs are fixtures."""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from test_helper_common import TmpCase, load_helper, run_helper  # noqa: E402

P = load_helper("edr-policy-check")
NOW = 1795000000
TETRA = "tetra --server-address unix:///var/run/tetragon/tetragon.sock "


class Recorder(dict):
    """A fixtures dict that records every program run."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.calls = []

    def get(self, key, default=None):
        self.calls.append(key)
        return dict.get(self, key, default)


def tp_list(items):
    return {"rc": 0, "out": json.dumps({"policies": items})}


class PolicyCase(TmpCase):
    def setUp(self):
        super().setUp()
        for name in ("nginx-exec", "sctp-socket", "web-exec", "edr-canary", "persistence"):
            self.put("/etc/tetragon/tetragon.tp.d/%s.yaml" % name, 'apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: "%s"\nspec:\n  kprobes: []\n' % name)
        self.put("/proc/sys/kernel/osrelease", "6.8.0-45-generic\n")
        self.put("/proc/uptime", "9000.00 8000.00\n")
        self.put("/proc/stat", "btime 1794000000\n")
        self.put("/run/nginx.pid", "321\n")
        self.put("/proc/321/status", "Name:\tnginx\nUid:\t0\t0\t0\t0\nCapBnd:\t000001ffffffffff\n")
        self.put("/etc/nginx/nginx.conf", "http { server { listen 80; } }")
        self.put("/etc/edr-agent/local.conf", "[tetragon]\nenforce = nginx-exec,sctp-socket\n")
        self.put("/usr/libexec/edr/canary", "x")
        self.fx = Recorder({
            "systemd-detect-virt --container": {"rc": 1, "out": "none\n"},
            "nginx -V": {"rc": 0, "err": "nginx version: nginx/1.24.0\nconfigure arguments: --with-http_ssl_module\n"},
            "ss -H --sctp -a": {"rc": 0, "out": ""},
            "setpriv --reuid 65534 --regid 65534 --clear-groups /usr/libexec/edr/canary -c exec /bin/true": {"rc": -9},
        })

    def loaded(self, modes, kills=None, state="enabled"):
        kills = kills or {}
        return tp_list([{"name": n, "mode": m, "state": state, "nmonitor": kills.get(n, 0)} for n, m in modes.items()])

    def state_file(self, **policies):
        self.put("/var/lib/edr-policy-check/state.json", json.dumps({"policies": policies, "kernel": "6.8.0-45-generic", "tetragon_seen": True,
                                                                     "canary": {"at": NOW - 3600, "ok": True, "detail": "x"},
                                                                     "canary_ok_kernel": "6.8.0-45-generic"}))

    def run_check(self, *extra, now=NOW):
        env = P.Env(self.root, dry=False, fixtures=self.fx, now=now)
        env.writes = True
        orig = P.parse_common
        P.parse_common = lambda argv: (env, "", list(extra))
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                rc = P.main([])
        finally:
            P.parse_common = orig
        self.assertEqual(rc, 0)
        return self.read_json("/run/edr-policy-check/status.json")

    def by_name(self, doc):
        return {p["name"]: p for p in doc["policies"]}


class TestGates(PolicyCase):
    def test_nginx_exec_stays_in_monitor_before_24_hours(self):
        self.fx[TETRA + "tracingpolicy list -o json"] = self.loaded({"nginx-exec": "monitor", "sctp-socket": "monitor", "web-exec": "monitor",
                                                                    "edr-canary": "enforce", "persistence": "enforce"})
        doc = self.run_check()
        p = self.by_name(doc)
        self.assertEqual(p["nginx-exec"]["want"], "monitor")
        self.assertIn("monitor period", p["nginx-exec"]["gate"])
        self.assertEqual(p["edr-canary"]["want"], "enforce")
        self.assertFalse([c for c in self.fx.calls if "set-mode" in c])
        self.assertEqual(doc["enforcement_gone"], [])

    def test_nginx_exec_is_promoted_after_its_gate(self):
        self.state_file(**{"nginx-exec": {"monitor_since": NOW - 25 * 3600, "loaded_at": NOW - 25 * 3600}})
        self.fx[TETRA + "tracingpolicy list -o json"] = self.loaded({"nginx-exec": "monitor", "edr-canary": "enforce"})
        self.fx[TETRA + "tracingpolicy set-mode nginx-exec enforce"] = {"rc": 0}
        doc = self.run_check()
        p = self.by_name(doc)["nginx-exec"]
        self.assertEqual((p["want"], p["gate"]), ("enforce", ""))
        self.assertIn(TETRA + "tracingpolicy set-mode nginx-exec enforce", self.fx.calls)
        self.assertEqual(p["mode"], "enforce")

    def test_a_would_be_kill_restarts_the_clock(self):
        self.state_file(**{"nginx-exec": {"monitor_since": NOW - 25 * 3600, "loaded_at": NOW - 25 * 3600}})
        self.fx[TETRA + "tracingpolicy list -o json"] = self.loaded({"nginx-exec": "monitor", "edr-canary": "enforce"}, kills={"nginx-exec": 2})
        doc = self.run_check()
        p = self.by_name(doc)["nginx-exec"]
        self.assertEqual(p["want"], "monitor")
        self.assertEqual(p["would_be_kills"], 2)
        self.assertEqual(self.read_json("/var/lib/edr-policy-check/state.json")["policies"]["nginx-exec"]["monitor_since"], NOW)

    def test_nginx_gate_failures(self):
        self.state_file(**{"nginx-exec": {"monitor_since": NOW - 25 * 3600, "loaded_at": NOW - 25 * 3600}})
        self.fx[TETRA + "tracingpolicy list -o json"] = self.loaded({"nginx-exec": "monitor", "edr-canary": "enforce"})
        cases = {
            "euid": lambda: self.put("/proc/321/status", "Uid:\t33\t33\t33\t33\nCapBnd:\t000001ffffffffff\n"),
            "capability": lambda: self.put("/proc/321/status", "Uid:\t0\t0\t0\t0\nCapBnd:\t00000000000000c0\n"),
            "lua": lambda: self.put("/etc/nginx/nginx.conf", "http { server { location / { content_by_lua_block { } } } }"),
            "njs": lambda: self.put("/etc/nginx/nginx.conf", "load_module modules/ngx_http_js_module.so;\nhttp { }"),
            "container": lambda: self.fx.update({"systemd-detect-virt --container": {"rc": 0, "out": "docker\n"}}),
        }
        for name, break_it in cases.items():
            self.setUp()
            self.state_file(**{"nginx-exec": {"monitor_since": NOW - 25 * 3600, "loaded_at": NOW - 25 * 3600}})
            self.fx[TETRA + "tracingpolicy list -o json"] = self.loaded({"nginx-exec": "monitor", "edr-canary": "enforce"})
            break_it()
            doc = self.run_check()
            p = self.by_name(doc)["nginx-exec"]
            self.assertEqual(p["want"], "monitor", name)
            self.assertTrue(p["gate"], name)

    def test_sctp_socket_needs_the_monitor_canary_and_no_sctp_user(self):
        self.state_file(**{"sctp-socket": {"loaded_at": NOW - 100, "monitor_since": NOW - 100}})
        self.fx[TETRA + "tracingpolicy list -o json"] = self.loaded({"sctp-socket": "monitor", "edr-canary": "enforce"})
        p = self.by_name(self.run_check())["sctp-socket"]
        self.assertEqual(p["want"], "monitor")
        self.assertIn("NMONITOR", p["gate"])
        # the hook raised NMONITOR (it counted a would-be kill): promote
        self.state_file(**{"sctp-socket": {"loaded_at": NOW - 100, "monitor_since": NOW - 100, "hook_seen": True}})
        self.fx[TETRA + "tracingpolicy set-mode sctp-socket enforce"] = {"rc": 0}
        p = self.by_name(self.run_check())["sctp-socket"]
        self.assertEqual((p["want"], p["gate"]), ("enforce", ""))
        # an SCTP socket exists: stay in monitor
        self.state_file(**{"sctp-socket": {"loaded_at": NOW - 100, "monitor_since": NOW - 100, "hook_seen": True}})
        self.fx["ss -H --sctp -a"] = {"rc": 0, "out": "ESTAB 0 0 10.0.0.1:1 10.0.0.2:2\n"}
        p = self.by_name(self.run_check())["sctp-socket"]
        self.assertEqual(p["want"], "monitor")
        self.assertIn("SCTP", p["gate"])

    def test_only_policies_in_the_enforce_list_are_promoted(self):
        self.put("/etc/edr-agent/local.conf", "[tetragon]\nenforce =\n")
        self.state_file(**{"nginx-exec": {"monitor_since": NOW - 25 * 3600, "loaded_at": NOW - 25 * 3600}})
        self.fx[TETRA + "tracingpolicy list -o json"] = self.loaded({"nginx-exec": "monitor", "edr-canary": "enforce"})
        p = self.by_name(self.run_check())["nginx-exec"]
        self.assertEqual(p["want"], "monitor")
        self.assertIn("enforce", p["gate"])

    def test_web_exec_needs_learning_accepted_and_a_php_restart(self):
        self.put("/etc/edr-agent/local.conf", "[tetragon]\nenforce = nginx-exec,sctp-socket,web-exec\n")
        self.state_file(**{"web-exec": {"monitor_since": NOW - 99999, "loaded_at": NOW - 5000}})
        self.fx[TETRA + "tracingpolicy list -o json"] = self.loaded({"web-exec": "monitor", "edr-canary": "enforce"})
        p = self.by_name(self.run_check())["web-exec"]
        self.assertIn("learning not accepted", p["gate"])
        self.put("/etc/edr-agent/local.conf", "[tetragon]\nenforce = nginx-exec,sctp-socket,web-exec\nweb_exec_allow = /usr/bin/convert\n")
        self.put("/var/lib/edr-agent/learn.json", json.dumps({"accepted_at": NOW - 90000, "tuples": {"a": {"policy": "web-exec", "first": NOW - 3600}}}))
        self.assertIn("72 hours", self.by_name(self.run_check())["web-exec"]["gate"])
        self.put("/var/lib/edr-agent/learn.json", json.dumps({"accepted_at": NOW - 90000, "tuples": {"a": {"policy": "web-exec", "first": NOW - 300000}}}))
        self.assertIn("php-fpm was not restarted", self.by_name(self.run_check())["web-exec"]["gate"])


class TestPauseAndCanary(PolicyCase):
    def test_pause_demotes_an_enforcing_policy_but_not_the_canary(self):
        self.state_file(**{"nginx-exec": {"monitor_since": NOW - 99999, "loaded_at": NOW - 99999}})
        self.put("/etc/edr-agent/pause.json", json.dumps({"until": NOW + 600}))
        self.fx[TETRA + "tracingpolicy list -o json"] = self.loaded({"nginx-exec": "enforce", "sctp-socket": "enforce", "edr-canary": "enforce"})
        self.fx[TETRA + "tracingpolicy set-mode nginx-exec monitor"] = {"rc": 0}
        self.fx[TETRA + "tracingpolicy set-mode sctp-socket monitor"] = {"rc": 0}
        doc = self.run_check()
        p = self.by_name(doc)
        self.assertEqual(p["nginx-exec"]["want"], "monitor")
        self.assertEqual(p["nginx-exec"]["gate"], "paused")
        self.assertEqual(p["edr-canary"]["want"], "enforce")
        self.assertIn(TETRA + "tracingpolicy set-mode nginx-exec monitor", self.fx.calls)
        self.assertNotIn(TETRA + "tracingpolicy set-mode edr-canary monitor", self.fx.calls)

    def test_expired_pause_is_ignored(self):
        self.state_file(**{"nginx-exec": {"monitor_since": NOW - 99999, "loaded_at": NOW - 99999}})
        self.put("/etc/edr-agent/pause.json", json.dumps({"until": NOW - 1}))
        self.fx[TETRA + "tracingpolicy list -o json"] = self.loaded({"nginx-exec": "enforce", "edr-canary": "enforce"})
        p = self.by_name(self.run_check())["nginx-exec"]
        self.assertEqual(p["want"], "enforce")

    def test_canary_must_die_by_sigkill(self):
        self.fx[TETRA + "tracingpolicy list -o json"] = self.loaded({"edr-canary": "enforce"})
        doc = self.run_check()
        self.assertTrue(doc["canary"]["ok"])
        self.assertEqual(doc["canary"]["at"], NOW)
        self.fx["setpriv --reuid 65534 --regid 65534 --clear-groups /usr/libexec/edr/canary -c exec /bin/true"] = {"rc": 0}
        doc = self.run_check(now=NOW + 90000)
        self.assertFalse(doc["canary"]["ok"])
        self.assertIn("not killed", doc["canary"]["detail"])
        self.assertIn("edr-canary", doc["enforcement_gone"])

    def test_the_canary_runs_once_a_day(self):
        self.fx[TETRA + "tracingpolicy list -o json"] = self.loaded({"edr-canary": "enforce"})
        self.run_check()
        n = len([c for c in self.fx.calls if c.startswith("setpriv")])
        self.run_check(now=NOW + 3600)
        self.assertEqual(len([c for c in self.fx.calls if c.startswith("setpriv")]), n)
        self.run_check(now=NOW + 90000)
        self.assertEqual(len([c for c in self.fx.calls if c.startswith("setpriv")]), n + 1)

    def test_a_kernel_change_forces_a_canary_run(self):
        self.fx[TETRA + "tracingpolicy list -o json"] = self.loaded({"edr-canary": "enforce"})
        self.run_check()
        n = len([c for c in self.fx.calls if c.startswith("setpriv")])
        self.put("/proc/sys/kernel/osrelease", "6.8.0-50-generic\n")
        self.run_check(now=NOW + 60)
        self.assertEqual(len([c for c in self.fx.calls if c.startswith("setpriv")]), n + 1)


class TestEnforcementGone(PolicyCase):
    def test_a_missing_or_failed_policy_in_the_enforce_list_is_gone(self):
        self.state_file()
        self.fx[TETRA + "tracingpolicy list -o json"] = self.loaded({"edr-canary": "enforce", "persistence": "enforce"})
        doc = self.run_check()
        p = self.by_name(doc)
        self.assertEqual(p["nginx-exec"]["state"], "missing")
        self.assertEqual(sorted(doc["enforcement_gone"]), ["nginx-exec", "sctp-socket"])
        self.fx[TETRA + "tracingpolicy list -o json"] = tp_list([{"name": "nginx-exec", "mode": "monitor", "state": "load_error"},
                                                                {"name": "sctp-socket", "mode": "monitor", "state": "enabled"},
                                                                {"name": "edr-canary", "mode": "enforce", "state": "enabled"}])
        doc = self.run_check()
        self.assertEqual(self.by_name(doc)["nginx-exec"]["state"], "error")
        self.assertIn("nginx-exec", doc["enforcement_gone"])
        self.assertNotIn("sctp-socket", doc["enforcement_gone"])

    def test_nothing_is_gone_right_after_boot(self):
        self.put("/proc/uptime", "60.0 50.0\n")
        self.fx[TETRA + "tracingpolicy list -o json"] = tp_list([])
        self.assertEqual(self.run_check()["enforcement_gone"], [])

    def test_tetra_down_means_missing_not_a_crash(self):
        doc = self.run_check()
        self.assertTrue(all(p["state"] == "missing" for p in doc["policies"]))
        self.assertTrue(doc["btf"] is False)

    def test_status_file_shape_and_mode(self):
        self.fx[TETRA + "tracingpolicy list -o json"] = self.loaded({"edr-canary": "enforce"})
        doc = self.run_check()
        self.assertEqual(os.stat(self.root + "/run/edr-policy-check/status.json").st_mode & 0o777, 0o640)
        self.assertEqual(set(doc), {"written_at", "kernel", "btf", "policies", "canary", "enforcement_gone"})
        for p in doc["policies"]:
            self.assertEqual(set(p), {"name", "mode", "state", "want", "would_be_kills", "gate"})
            self.assertIn(p["mode"], ("monitor", "enforce"))
            self.assertIn(p["state"], ("loaded", "missing", "error"))
        self.assertEqual(set(doc["canary"]), {"at", "ok", "detail"})

    def test_dry_run_runs_nothing(self):
        rc, out, err = run_helper("edr-policy-check", ["--root", self.root, "--dry-run", "--now", str(NOW)])
        self.assertEqual(rc, 0, err)
        self.assertIn("enforcement_gone", out)


if __name__ == "__main__":
    unittest.main()
