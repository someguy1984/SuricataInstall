import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_daemon_support import Tmp, cfgmod                              # noqa: E402
from edragent import sources as src                                      # noqa: E402
from edragent.sources import helpers                                     # noqa: E402


class HelperCase(Tmp):
    def setUp(self):
        super().setUp()
        self.reload()

    def reload(self, text=None):
        self.cfg = self.conf(text) if text is not None else cfgmod.load(self.paths)
        self.ctx = src.Context(self.cfg, self.paths, self.clock)
        self.h = src.HelperWatcher(self.ctx, uptime=lambda: 10_000.0)

    def put(self, path, obj, **kw):
        obj = dict(obj)
        obj.setdefault("written_at", int(self.clock()))
        self.write(path, json.dumps(obj), **kw)

    def poll(self):
        self.clock.advance(61)
        return self.h.poll(self.clock())


class TestReadStatusFile(HelperCase):
    def test_missing_oversized_invalid_symlink_fifo_are_unknown(self):
        p = os.path.join(self.root, "s.json")
        self.assertEqual(helpers.read_status_file(p, 100)[2], "missing")
        self.write(p, "{" + "x" * 500)
        self.assertEqual(helpers.read_status_file(p, 100)[2], "oversize")
        self.write(p, "{not json")
        self.assertEqual(helpers.read_status_file(p, 1000)[2], "invalid")
        self.write(p, "[1, 2]")
        self.assertEqual(helpers.read_status_file(p, 1000)[2], "invalid")
        q = os.path.join(self.root, "link.json")
        os.symlink(p, q)
        self.assertEqual(helpers.read_status_file(q, 1000)[2], "unreadable")
        f = os.path.join(self.root, "fifo.json")
        os.mkfifo(f)
        self.assertEqual(helpers.read_status_file(f, 1000)[2], "not a regular file")        # no hang
        self.write(p, '{"a": 1}')
        obj, written, reason = helpers.read_status_file(p, 1000)
        self.assertEqual((obj, reason), ({"a": 1}, ""))
        self.assertAlmostEqual(written, os.stat(p).st_mtime, delta=2)             # no written_at: the file time

    def test_a_hostile_status_file_never_raises(self):
        for text in ('{"stage": "9"}', '{"policies": 5}', '{"state": ["x"]}', '{"findings": {"a": 1}}', '{"checks": 3, "findings": [1, "x", null]}',
                     '{"canary": []}', "{}"):
            for p in (self.paths.diskguard_status, self.paths.dns_watch_status, self.paths.policy_check_status, self.paths.inventory_json,
                      self.paths.bans_counters):
                self.write(p, text)
            self.poll()
            self.h.tetragon_list()
            self.h.nft()
            self.h.conntrack()
            self.h.dns_lock()
            self.h.inventory_for_heartbeat()
            self.h.next_poll = 0


class TestInventory(HelperCase):
    def test_findings_become_events_once_and_again_after_a_day(self):
        inv = {"v": 1, "checks": {"real_ip": {"status": False}}, "findings": [
            {"check": "nginx_pkg", "sev": "HIGH", "summary": "nginx 1.24.0-2ubuntu7 is below its fix", "details": {"pkg": "nginx"}},
            {"check": "deleted_exe", "sev": "BOGUS", "summary": "x"}]}
        self.put(self.paths.inventory_json, inv)
        events = self.poll()
        self.assertEqual([(e["kind"], e["sev"], e["source"]) for e in events],
                         [("inventory.nginx_pkg", "HIGH", "inventory"), ("inventory.deleted_exe", "MEDIUM", "inventory")])
        self.assertEqual(events[0]["details"], {"pkg": "nginx"})
        self.put(self.paths.inventory_json, inv)
        self.assertEqual(self.poll(), [])                                           # unchanged: not again
        self.clock.advance(86400)
        self.put(self.paths.inventory_json, inv)
        self.assertEqual(len(self.poll()), 2)                                       # still there a day later
        inv["findings"][0]["summary"] = "different"
        self.put(self.paths.inventory_json, inv)
        self.assertEqual(len(self.poll()), 1)                                       # a changed finding is new

    def test_checks_feed_the_context(self):
        self.put(self.paths.inventory_json, {"checks": {"real_ip": {"status": True}}, "findings": []})
        self.poll()
        self.assertTrue(self.ctx.real_ip())
        self.assertEqual(self.ctx.web_src_trust(), "claimed")

    def test_missing_file_is_stale_after_the_grace_and_reminds_every_six_hours(self):
        self.assertEqual(self.h.poll(self.clock()), [])                             # right after start: not stale yet
        self.clock.advance(11 * 60)
        events = self.h.poll(self.clock())
        self.assertEqual([(e["kind"], e["sev"]) for e in events], [("inventory.stale", "MEDIUM")])
        self.assertEqual(self.poll(), [])
        self.clock.advance(6 * 3600)
        self.assertEqual(len(self.poll()), 1)
        self.assertEqual(self.h.inventory_for_heartbeat(), {"status": "unknown", "reason": "missing"})

    def test_old_file_is_stale(self):
        self.put(self.paths.inventory_json, {"checks": {}, "findings": [], "written_at": int(self.clock()) - 3 * 3600})
        events = self.poll()
        self.assertEqual([e["kind"] for e in events], ["inventory.stale"])
        self.assertEqual(self.h.inventory_for_heartbeat()["status"], "unknown")
        self.assertEqual(self.ctx.inventory_checks, {})

    def test_fresh_inventory_is_forwarded_as_it_is(self):
        inv = {"v": 1, "checks": {"nginx_pkg": {"status": False}}, "posture": {"a": True}, "findings": []}
        self.put(self.paths.inventory_json, inv)
        self.poll()
        got = self.h.inventory_for_heartbeat()
        self.assertEqual(got["checks"], inv["checks"])
        self.assertEqual(got["posture"], inv["posture"])


class TestPolicyCheck(HelperCase):
    def setUp(self):
        super().setUp()
        self.at = int(self.clock())

    def status(self, **kw):
        d = {"kernel": "7.0.0-43-generic", "btf": True, "policies": [
            {"name": "nginx-exec", "mode": "enforce", "state": "loaded", "want": "enforce", "would_be_kills": 0, "gate": ""},
            {"name": "sctp-socket", "mode": "monitor", "state": "loaded", "want": "enforce", "would_be_kills": 2, "gate": "waiting"}],
             "canary": {"at": self.at, "ok": True, "detail": "died by SIGKILL"}, "enforcement_gone": []}
        d.update(kw)
        self.put(self.paths.policy_check_status, d)

    def test_heartbeat_list(self):
        self.status()
        self.poll()
        self.assertEqual(self.h.tetragon_list(), [{"name": "nginx-exec", "mode": "enforce", "would_be_kills": 0},
                                                  {"name": "sctp-socket", "mode": "monitor", "would_be_kills": 2}])

    def test_healthy_set_raises_only_the_canary_result(self):
        self.status()
        events = self.poll()
        self.assertEqual([(e["kind"], e["sev"], e["source"]) for e in events], [("canary.policy_check", "INFO", "canary")])
        self.status()
        self.assertEqual(self.poll(), [])                                            # the same canary is not repeated
        self.status(canary={"at": self.at + 5, "ok": True, "detail": "again"})
        self.assertEqual([e["kind"] for e in self.poll()], ["canary.policy_check"])

    def test_a_policy_set_to_enforce_that_is_not_loaded_is_high(self):
        pol = [{"name": "nginx-exec", "mode": "monitor", "state": "missing", "want": "enforce", "would_be_kills": 0, "gate": ""}]
        self.status(policies=pol)
        events = self.poll()
        gone = [e for e in events if e["kind"] == "health.enforcement_gone"]
        self.assertEqual(len(gone), 1)
        self.assertEqual((gone[0]["sev"], gone[0]["details"]["policies"]), ("HIGH", ["nginx-exec"]))
        self.status(policies=pol)
        self.assertEqual([e for e in self.poll() if e["kind"] == "health.enforcement_gone"], [])      # once
        self.clock.advance(6 * 3600)
        self.status(policies=pol)
        self.assertEqual(len([e for e in self.poll() if e["kind"] == "health.enforcement_gone"]), 1)   # reminded

    def test_monitor_mode_before_the_gate_is_not_gone(self):
        pol = [{"name": "nginx-exec", "mode": "monitor", "state": "loaded", "want": "enforce", "would_be_kills": 0, "gate": "24h in monitor"}]
        self.status(policies=pol)
        self.assertEqual([e for e in self.poll() if e["kind"] == "health.enforcement_gone"], [])

    def test_the_helper_can_name_policies_that_lost_enforcement(self):
        self.status(enforcement_gone=["web-exec"])
        events = [e for e in self.poll() if e["kind"] == "health.enforcement_gone"]
        self.assertEqual(events[0]["details"]["policies"], ["web-exec"])

    def test_not_in_the_first_5_minutes_after_boot(self):
        self.h.uptime = lambda: 60.0
        self.status(enforcement_gone=["web-exec"])
        self.assertEqual([e for e in self.poll() if e["kind"] == "health.enforcement_gone"], [])
        self.h.uptime = lambda: 400.0
        self.status(enforcement_gone=["web-exec"])
        self.assertEqual(len([e for e in self.poll() if e["kind"] == "health.enforcement_gone"]), 1)

    def test_a_new_kernel_without_a_passed_canary_is_gone_after_5_minutes(self):
        self.status()
        self.poll()
        self.clock.advance(100)
        self.status(kernel="7.0.0-44-generic", canary={"at": self.at, "ok": True, "detail": "old"})
        self.assertEqual([e for e in self.poll() if e["kind"] == "health.enforcement_gone"], [])      # just changed
        self.clock.advance(400)
        self.status(kernel="7.0.0-44-generic", canary={"at": self.at, "ok": True, "detail": "old"})
        events = [e for e in self.poll() if e["kind"] == "health.enforcement_gone"]
        self.assertEqual(len(events), 1)
        self.assertIn("kernel", events[0]["details"]["reasons"])
        self.clock.advance(61)
        self.status(kernel="7.0.0-44-generic", canary={"at": int(self.clock()) + 1000, "ok": True, "detail": "new"})
        self.assertEqual([e for e in self.poll() if e["kind"] == "health.enforcement_gone"], [])      # the canary passed

    def test_a_failed_canary_is_reported(self):
        self.status(canary={"at": self.at + 1, "ok": False, "detail": "survived"})
        kinds = [(e["kind"], e["sev"]) for e in self.poll()]
        self.assertIn(("canary.policy_check", "INFO"), kinds)
        self.assertIn(("health.enforcement_gone", "HIGH"), kinds)

    def test_with_nothing_to_enforce_there_is_no_alarm(self):
        self.reload("[tetragon]\nenforce =\n")
        self.status(policies=[{"name": "nginx-exec", "mode": "monitor", "state": "missing", "want": "monitor"}])
        self.assertEqual([e for e in self.poll() if e["kind"] == "health.enforcement_gone"], [])


class TestDnsAndDisk(HelperCase):
    def dns(self, state, since=1, relocks=0):
        self.put(self.paths.dns_watch_status, {"state": state, "since": since, "relocks": relocks})
        return self.poll()

    def test_dns_lock_events_on_a_change_of_state(self):
        self.assertEqual(self.dns("locked"), [])                                    # the first reading is not a change
        e = self.dns("open")[0]
        self.assertEqual((e["kind"], e["sev"], e["source"], e["details"]["what"]), ("edr.dnslock", "CRITICAL", "agent", "failopen"))
        self.assertEqual(self.dns("open"), [])
        e = self.dns("locked", relocks=1)[0]
        self.assertEqual((e["sev"], e["details"]["what"]), ("INFO", "relock"))
        e = self.dns("flapping", relocks=3)[0]
        self.assertEqual((e["sev"], e["details"]["what"]), ("HIGH", "flapping"))
        self.assertEqual(self.dns("paused", relocks=3), [])
        self.assertEqual(self.h.dns_lock(), {"state": "paused", "since": 1, "relocks": 3})

    def test_dns_open_at_start_is_reported(self):
        self.assertEqual(self.dns("open")[0]["details"]["what"], "failopen")

    def test_unknown_state_is_ignored(self):
        self.assertEqual(self.dns("weird"), [])
        self.assertIsNone(self.h.dns_lock())

    def test_diskguard_stage_is_critical(self):
        def disk(stage, free=8.0):
            self.put(self.paths.diskguard_status, {"free_pct": free, "stage": stage, "freed_mb": 12})
            return [e for e in self.poll() if e["kind"] == "health.diskguard"]
        self.assertEqual(disk(0, 40), [])
        e = disk(1)[0]
        self.assertEqual((e["kind"], e["sev"], e["details"]["stage"]), ("health.diskguard", "CRITICAL", 1))
        self.assertEqual(disk(1), [])
        self.assertEqual(disk(2, 4)[0]["details"]["stage"], 2)
        self.clock.advance(1800)
        self.assertEqual(len(disk(2, 4)), 1)                                         # still bad half an hour later


class TestDiskLow(HelperCase):
    def test_under_10_percent_free_is_critical_and_repeats_every_half_hour(self):
        import types
        calls = []

        def fake(path):
            calls.append(path)
            return types.SimpleNamespace(f_blocks=1000, f_bavail=50, f_frsize=4096)
        real = os.statvfs
        os.statvfs = fake
        try:
            e = [x for x in self.poll() if x["kind"] == "health.disk_low"]
            self.assertEqual((e[0]["sev"], e[0]["source"], e[0]["details"]["free_pct"]), ("CRITICAL", "agent", 5.0))
            self.assertEqual([x for x in self.poll() if x["kind"] == "health.disk_low"], [])
            self.clock.advance(1800)
            self.assertEqual(len([x for x in self.poll() if x["kind"] == "health.disk_low"]), 1)
            os.statvfs = lambda p: types.SimpleNamespace(f_blocks=1000, f_bavail=500, f_frsize=4096)
            self.assertEqual([x for x in self.poll() if x["kind"] == "health.disk_low"], [])
        finally:
            os.statvfs = real


class TestRulesStale(HelperCase):
    def status(self, ok, skipped=0, age=0, message="x"):
        self.put(self.paths.rules_status, {"written_at": int(self.clock()) - age, "ok": ok, "skipped_days": skipped, "message": message})

    def stale(self):
        return [e for e in self.poll() if e["kind"] == "health.rules_stale"]

    def test_three_skipped_days_raise_a_medium_event_once_then_every_6_hours(self):
        self.status(False, skipped=2)
        self.assertEqual(self.stale(), [])
        self.status(False, skipped=3, message="rules_stale: memory too short for 3 days")
        e = self.stale()
        self.assertEqual((e[0]["sev"], e[0]["source"], e[0]["details"]["skipped_days"]), ("MEDIUM", "agent", 3))
        self.status(False, skipped=4)
        self.assertEqual(self.stale(), [])
        self.clock.advance(6 * 3600)
        self.status(False, skipped=5)
        self.assertEqual(len(self.stale()), 1)
        self.status(True, skipped=0)
        self.assertEqual(self.stale(), [])

    def test_the_last_success_over_3_days_old(self):
        self.status(True)
        self.assertEqual(self.stale(), [])
        self.clock.advance(3 * 86400 + 600)
        self.status(False, skipped=1, message="candidate rejected")
        e = self.stale()
        self.assertEqual(len(e), 1)
        self.assertIn("3 days ago", e[0]["summary"])

    def test_a_first_failure_or_a_missing_file_says_nothing(self):
        self.assertEqual(self.stale(), [])
        self.status(False, skipped=0, message="no rules produced")
        self.assertEqual(self.stale(), [])

    def test_off_when_suricata_is_off_and_hostile_content_is_harmless(self):
        self.reload("[kit]\nsuricata = off\n")
        self.status(False, skipped=9)
        self.assertEqual(self.stale(), [])
        self.reload()
        self.write(self.paths.rules_status, '{"ok": "yes", "skipped_days": "many", "written_at": "now"}')
        self.assertEqual(self.stale(), [])


class TestHeartbeatPieces(HelperCase):
    def test_nft_and_conntrack_from_counters(self):
        self.put(self.paths.bans_counters, {"table_present": True, "sets": {"edr_ban4": 3}, "counters": {"ban_drop": 9},
                                            "conntrack": {"count": 10, "max": 100, "drop": 1, "early_drop": 2}})
        self.poll()
        self.assertEqual(self.h.nft(), {"table_present": True, "sets": {"edr_ban4": 3}, "counters": {"ban_drop": 9}})
        self.assertEqual(self.h.conntrack(), {"count": 10, "max": 100, "drop": 1, "early_drop": 2})

    def test_nft_is_unknown_not_false_without_the_helper(self):
        self.poll()
        self.assertIsNone(self.h.nft())                       # the hub reads table_present False as "the table is gone"

    def test_conntrack_falls_back_to_proc(self):
        d = os.path.join(self.root, "proc", "sys", "net", "netfilter")
        self.write(os.path.join(d, "nf_conntrack_count"), "42\n")
        self.write(os.path.join(d, "nf_conntrack_max"), "262144\n")
        self.paths.proc_dir = os.path.join(self.root, "proc")
        self.poll()
        self.assertEqual(self.h.conntrack(), {"count": 42, "max": 262144, "drop": 0, "early_drop": 0})

    def test_fresh_and_stale_by_age(self):
        self.put(self.paths.diskguard_status, {"stage": 0, "free_pct": 50})
        self.poll()
        self.assertTrue(self.h.fresh("edr-diskguard", self.clock()))
        self.assertFalse(self.h.fresh("edr-diskguard", self.clock() + 700))
        self.assertFalse(self.h.fresh("edr-dns-watch", self.clock()))


if __name__ == "__main__":
    unittest.main()
