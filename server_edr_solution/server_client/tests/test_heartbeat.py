import hashlib
import json
import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_daemon_support import Tmp, cfgmod, evmod, hub_modules, CODE                         # noqa: E402
from edragent import heartbeat, sources as src                                                  # noqa: E402
from edragent.pipeline import Pipeline                                                          # noqa: E402


class HbCase(Tmp):
    def setUp(self):
        super().setUp()
        self.proc = os.path.join(self.root, "proc")
        self.sysd = os.path.join(self.root, "sys")
        self.write(os.path.join(self.proc, "uptime"), "12345.67 9999.9\n")
        self.write(os.path.join(self.proc, "loadavg"), "0.52 0.40 0.31 1/200 1234\n")
        self.write(os.path.join(self.proc, "version_signature"), "Ubuntu 7.0.0-43.43-generic 7.0.14\n")
        self.write(os.path.join(self.proc, "sys", "kernel", "random", "boot_id"), "5b1c0000-1111-2222-3333-444444444444\n")
        self.write(os.path.join(self.proc, "meminfo"), "MemTotal:  2048000 kB\nMemFree: 100000 kB\nMemAvailable: 1024000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")
        os.makedirs(os.path.join(self.sysd, "fs", "cgroup", "system.slice"))
        self.paths.proc_dir, self.paths.sys_dir = self.proc, self.sysd
        self.reload()

    def reload(self, text=None):
        self.cfg = self.conf(text) if text is not None else cfgmod.load(self.paths)
        self.ctx = src.Context(self.cfg, self.paths, self.clock)
        self.helpers = src.HelperWatcher(self.ctx, uptime=lambda: 10_000.0)
        self.state = heartbeat.HeartbeatState(self.cfg, self.paths, self.ctx, self.helpers, None, self.clock)

    def unit(self, name):
        os.makedirs(os.path.join(self.sysd, "fs", "cgroup", "system.slice", name + ".service"), exist_ok=True)

    def put(self, path, obj):
        obj = dict(obj)
        obj.setdefault("written_at", int(self.clock()))
        self.write(path, json.dumps(obj))

    def build(self):
        self.clock.advance(61)
        self.helpers.next_poll = 0
        self.helpers.poll(self.clock())
        return heartbeat.build(self.state)


class TestBuild(HbCase):
    def test_keys_and_values(self):
        for u in ("tetragon", "suricata", "nginx"):
            self.unit(u)
        hb = self.build()
        self.assertEqual((hb["schema"], hb["proto"], hb["agent_version"]), (1, 1, "0.1.0"))
        self.assertRegex(hb["agent_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(hb["boot_id"], "5b1c0000-1111-2222-3333-444444444444")
        self.assertEqual(hb["uptime_s"], 12345)
        self.assertEqual(hb["kernel"], "Ubuntu 7.0.0-43.43-generic 7.0.14")
        self.assertEqual(hb["load"], {"1m": 0.52, "5m": 0.40, "15m": 0.31})
        self.assertEqual(hb["mem"]["total_mb"], 2000)
        self.assertEqual(hb["mem"]["used_pct"], 50.0)
        self.assertEqual(len(hb["local_conf_sha256"]), 64)
        self.assertGreaterEqual(hb["disk"]["free_pct"], 0)
        self.assertLessEqual(hb["disk"]["free_pct"], 100)
        json.dumps(hb)

    def test_the_uplinks_keys_are_left_to_it(self):
        hb = self.build()
        for k in ("sent_at", "seq", "epoch", "policy_rev_applied", "last_apply_error", "ban_counts", "cert_not_after", "droplet_id", "maintenance_until"):
            self.assertNotIn(k, hb)

    def test_units_by_cgroup_and_by_status_file_age(self):
        self.unit("nginx")
        self.put(self.paths.diskguard_status, {"stage": 0, "free_pct": 60})
        hb = self.build()
        u = hb["units"]
        self.assertEqual(u["edr-agent"], "running")
        self.assertEqual((u["nginx"], u["suricata"], u["tetragon"], u["dnscrypt-proxy"]), ("running", "absent", "absent", "absent"))
        self.assertEqual(u["edr-diskguard"], "fresh")
        self.assertEqual(u["edr-bans"], "stale")
        for v in u.values():
            self.assertIn(v, ("running", "absent", "fresh", "stale"))

    def test_a_component_switched_off_is_not_reported_absent(self):
        self.reload("[kit]\ntetragon = off\nsuricata = off\nweb = off\n")
        u = self.build()["units"]
        for name in ("tetragon", "suricata", "nginx"):
            self.assertNotIn(name, u)
        self.assertIn("dnscrypt-proxy", u)

    def test_no_systemctl_is_run(self):
        import subprocess
        real = subprocess.Popen
        subprocess.Popen = lambda *a, **k: (_ for _ in ()).throw(AssertionError("a process was started"))
        try:
            self.build()
        finally:
            subprocess.Popen = real

    def test_tetragon_list_only_when_the_policy_check_is_fresh(self):
        hb = self.build()
        self.assertNotIn("tetragon", hb)                      # unknown, not an empty list: the hub reads [] as "Tetragon unhealthy"
        self.put(self.paths.policy_check_status, {"policies": [{"name": "nginx-exec", "mode": "enforce", "state": "loaded", "would_be_kills": 0}]})
        self.assertEqual(self.build()["tetragon"], [{"name": "nginx-exec", "mode": "enforce", "would_be_kills": 0}])
        self.put(self.paths.policy_check_status, {"policies": []})
        self.assertEqual(self.build()["tetragon"], [])

    def test_nft_conntrack_dns_lock_and_suricata_drops(self):
        self.put(self.paths.bans_counters, {"table_present": True, "sets": {"edr_ban4": 1}, "counters": {"ban_drop": 2},
                                            "conntrack": {"count": 5, "max": 10, "drop": 0, "early_drop": 0}})
        self.put(self.paths.dns_watch_status, {"state": "locked", "since": 99, "relocks": 0})
        self.ctx.suricata_drops = {"packets": 100, "drops": 1, "window_s": 60}
        hb = self.build()
        self.assertEqual(hb["nft"]["table_present"], True)
        self.assertEqual(hb["conntrack"], {"count": 5, "max": 10, "drop": 0, "early_drop": 0})
        self.assertEqual(hb["dns_lock"], {"state": "locked", "since": 99, "relocks": 0})
        self.assertEqual(hb["suricata_drops"], {"packets": 100, "drops": 1, "window_s": 60})

    def test_unknown_things_are_left_out_not_guessed(self):
        hb = self.build()
        for k in ("nft", "dns_lock", "suricata_drops", "tetragon", "paused_until"):
            self.assertNotIn(k, hb)

    def test_paused_until_is_rfc3339_and_an_expired_pause_is_ignored(self):
        self.write(self.paths.pause_json, json.dumps({"until": int(self.clock()) + 3600}))
        hb = self.build()
        self.assertRegex(hb["paused_until"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.000Z$")
        self.write(self.paths.pause_json, json.dumps({"until": int(self.clock()) - 10}))
        self.assertNotIn("paused_until", self.build())
        self.write(self.paths.pause_json, "garbage")
        self.assertNotIn("paused_until", self.build())

    def test_over_budget_counts_ride_in_spool(self):
        pipe = Pipeline(self.cfg, self.paths, None, None, self.ctx, self.clock)
        self.addCleanup(pipe.alerts.close)
        pipe.dropped["nginx"] = 5
        self.state.pipeline = pipe
        self.assertEqual(self.build()["spool"], {"over_budget": {"nginx": 5}})

    def test_the_hub_accepts_the_body(self):
        mods = hub_modules()
        if mods is None:
            self.skipTest("the hub code is not importable here")
        hub_common, hub_ingest = mods
        self.put(self.paths.policy_check_status, {"policies": [{"name": "nginx-exec", "mode": "enforce", "state": "loaded", "would_be_kills": 3}]})
        self.put(self.paths.bans_counters, {"table_present": True, "sets": {"edr_ban4": 1}, "counters": {}, "conntrack": {"count": 1, "max": 2, "drop": 0, "early_drop": 0}})
        self.put(self.paths.dns_watch_status, {"state": "locked", "since": 1, "relocks": 0})
        self.put(self.paths.inventory_json, {"v": 1, "checks": {"nginx_pkg": {"status": False}}, "findings": []})
        hb = self.build()
        hb["sent_at"] = "2026-11-19T10:15:03.120Z"
        hb["droplet_id"] = "1234"
        clean, sent_ms = hub_ingest.validate_heartbeat(hb)
        for k in ("units", "tetragon", "nft", "conntrack", "dns_lock", "disk", "load", "mem", "inventory", "agent_sha256", "kernel", "boot_id", "uptime_s"):
            self.assertIn(k, clean, k)


class TestInventoryResend(HbCase):
    def test_inventory_is_sent_when_it_changes_and_hourly_otherwise(self):
        self.put(self.paths.inventory_json, {"v": 1, "checks": {"a": {"status": True}}, "findings": []})
        self.assertIn("inventory", self.build())
        self.put(self.paths.inventory_json, {"v": 1, "checks": {"a": {"status": True}}, "findings": []})
        self.assertNotIn("inventory", self.build())
        self.put(self.paths.inventory_json, {"v": 1, "checks": {"a": {"status": False}}, "findings": []})
        self.assertEqual(self.build()["inventory"]["checks"]["a"]["status"], False)
        self.assertNotIn("inventory", self.build())
        self.clock.advance(3600)
        self.put(self.paths.inventory_json, {"v": 1, "checks": {"a": {"status": False}}, "findings": []})
        self.assertIn("inventory", self.build())

    def test_a_missing_or_stale_inventory_is_sent_as_unknown(self):
        self.clock.advance(700)
        hb = self.build()
        self.assertEqual(hb["inventory"], {"status": "unknown", "reason": "missing"})
        self.put(self.paths.inventory_json, {"checks": {}, "findings": [], "written_at": int(self.clock()) - 3 * 3600})
        self.assertEqual(self.build()["inventory"]["status"], "unknown")

    def test_an_oversize_inventory_is_unknown(self):
        self.put(self.paths.inventory_json, {"checks": {"x": {"blob": "a" * 300000}}, "findings": []})
        # the file stays under the 1 MiB read cap but over what one heartbeat may carry
        self.assertEqual(self.build()["inventory"], {"status": "unknown", "reason": "oversize"})


class TestAgentHash(Tmp):
    def test_hash_covers_the_code_and_follows_changes(self):
        d = os.path.join(self.root, "lib")
        os.makedirs(os.path.join(d, "edragent", "__pycache__"))
        self.write(os.path.join(d, "edr-agent.py"), "print(1)\n")
        self.write(os.path.join(d, "edragent", "a.py"), "A=1\n")
        self.write(os.path.join(d, "edragent", "__pycache__", "a.pyc"), "junk")
        self.write(os.path.join(d, "edragent", "notes.txt"), "not code")
        heartbeat._hash_cache.clear()
        h1 = heartbeat.agent_sha256(d)
        manual = hashlib.sha256()
        for rel, data in (("edr-agent.py", b"print(1)\n"), (os.path.join("edragent", "a.py"), b"A=1\n")):
            manual.update(rel.encode() + b"\0" + data + b"\0")
        self.assertEqual(h1, manual.hexdigest())
        self.write(os.path.join(d, "edragent", "a.py"), "A=2\n")
        heartbeat._hash_cache.clear()
        self.assertNotEqual(heartbeat.agent_sha256(d), h1)

    def test_the_real_code_has_a_hash_and_version_prints_it(self):
        heartbeat._hash_cache.clear()
        h = heartbeat.agent_sha256(CODE)
        self.assertRegex(h, r"^[0-9a-f]{64}$")
        from edragent import cli
        lines = []
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["version", "--hash"])
        self.assertEqual(code, 0)
        self.assertEqual(buf.getvalue().split(), ["0.1.0", h])


if __name__ == "__main__":
    unittest.main()
