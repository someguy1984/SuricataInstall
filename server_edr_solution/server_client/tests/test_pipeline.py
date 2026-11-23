import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_daemon_support import Tmp, FakeBanEngine, FakeUplink, cfgmod, evmod, ids          # noqa: E402
from edragent import alertlog, sources as src                                                  # noqa: E402
from edragent.pipeline import Pipeline                                                          # noqa: E402


def mk(kind="nginx.marker.window_update", source="nginx", sev="LOW", summary="s", **kw):
    return evmod.make_event(kind, source, sev, summary, **kw)


class PipeCase(Tmp):
    def setUp(self):
        super().setUp()
        self.build()

    def build(self, text=None):
        self.cfg = self.conf(text) if text is not None else cfgmod.load(self.paths)
        self.bans = FakeBanEngine()
        self.up = FakeUplink()
        self.ctx = src.Context(self.cfg, self.paths, self.clock)
        self.logs = []
        self.p = Pipeline(self.cfg, self.paths, self.bans, self.up, self.ctx, self.clock, lambda lvl, msg: self.logs.append((lvl, msg)))
        self.addCleanup(self.p.alerts.close)

    def feed(self, e, advance=0):
        self.clock.advance(advance)
        self.p.process(e, self.clock())

    def alert_lines(self):
        try:
            with open(self.paths.alerts_jsonl) as f:
                return [json.loads(x) for x in f]
        except FileNotFoundError:
            return []


class TestBanEngineHook(PipeCase):
    def test_ban_engine_sees_every_event_before_collapsing(self):
        for _ in range(5):
            self.feed(mk(src_ip="203.0.113.9", src_trust="tcp"))
        self.assertEqual(len(self.bans.observed), 5)
        self.assertEqual(len(self.up.submitted), 1)                      # the first goes out at once, the repeats are held

    def test_events_the_ban_engine_returns_are_processed_but_not_observed_again(self):
        ban = evmod.make_event("ban.local", "agent", "HIGH", "banned 203.0.113.9", details={"cidr": "203.0.113.9/32", "trigger": "ssh_fail"},
                               src_ip="203.0.113.9", src_trust="tcp")
        self.bans.to_return = [ban]
        self.feed(mk(kind="ssh.fail", source="journal", src_ip="203.0.113.9", src_trust="tcp"))
        self.assertEqual([e["kind"] for e in self.up.submitted], ["ssh.fail", "ban.local"])
        self.assertEqual([e["kind"] for e in self.bans.observed], ["ssh.fail"])
        self.assertIn("ban.local", [a["kind"] for a in self.alert_lines()])      # a HIGH event reaches alerts.jsonl

    def test_a_failing_ban_engine_does_not_stop_the_stream(self):
        def boom(event, now):
            raise RuntimeError("bug")
        self.bans.observe = boom
        self.feed(mk())
        self.assertEqual(len(self.up.submitted), 1)

    def test_a_failing_uplink_does_not_stop_the_stream(self):
        def boom(event):
            raise OSError("spool full")
        self.up.submit = boom
        self.feed(mk(sev="HIGH", kind="x.y"))
        self.assertEqual(len(self.alert_lines()), 1)

    def test_tick_calls_the_ban_engine_and_processes_what_it_returns(self):
        self.bans.tick = lambda now: [evmod.make_event("health.x", "agent", "MEDIUM", "from tick")]
        self.p.tick(self.clock())
        self.assertEqual([e["kind"] for e in self.up.submitted], ["health.x"])


class TestIds(PipeCase):
    def test_only_forwarded_events_take_an_id_and_there_are_no_gaps(self):
        for i in range(30):
            self.feed(mk(summary="a"))                                          # 29 are collapsed
            self.feed(mk(kind="x.%d" % i, summary="b"))
        seqs = [e["seq"] for e in self.up.submitted]
        self.assertEqual(seqs, list(range(seqs[0], seqs[0] + len(seqs))))
        for e in self.up.submitted:
            self.assertEqual(e["id"], "%08x:%d" % (e["epoch"], e["seq"]))
        self.assertEqual(len(seqs), 31)

    def test_the_epoch_is_the_one_ids_handed_out(self):
        self.feed(mk())
        self.assertEqual(self.up.submitted[0]["epoch"], ids.current()[0])


class TestCollapse(PipeCase):
    def test_repeats_collapse_into_one_event_with_a_count(self):
        for i in range(10):
            self.feed(mk(src_ip="203.0.113.9", src_trust="tcp"), advance=10)
        self.assertEqual(len(self.up.submitted), 1)
        self.feed(mk(kind="other.kind"), advance=300)                           # time passes, the window ends
        self.p.tick(self.clock())
        kinds = [(e["kind"], e.get("count")) for e in self.up.submitted]
        self.assertEqual(kinds[0], ("nginx.marker.window_update", None))
        self.assertIn(("nginx.marker.window_update", 9), kinds)
        rep = [e for e in self.up.submitted if e.get("count")][0]
        self.assertTrue(rep["first_ts"] <= rep["last_ts"])
        self.assertNotEqual(rep["id"], self.up.submitted[0]["id"])

    def test_distinct_events_are_never_collapsed_together(self):
        self.feed(mk(src_ip="203.0.113.9", src_trust="tcp"))
        self.feed(mk(src_ip="198.51.100.1", src_trust="tcp"))                   # a second attacker stays visible
        self.feed(mk(kind="nginx.marker.conn_pressure"))
        self.feed(mk(details={"sid": 2}, kind="suricata.alert", source="suricata", src_ip="203.0.113.9", src_trust="tcp"))
        self.feed(mk(details={"sid": 3}, kind="suricata.alert", source="suricata", src_ip="203.0.113.9", src_trust="tcp"))
        self.assertEqual(len(self.up.submitted), 5)

    def test_tetragon_key_is_policy_binary_argv_and_parent(self):
        def t(binary="/bin/sh", args="-c id", parent="/usr/sbin/nginx", kind="tetragon.web-exec"):
            return mk(kind=kind, source="tetragon", sev="MEDIUM", proc={"binary": binary, "args": args, "parent": parent})
        self.feed(t())
        self.feed(t())
        self.feed(t(args="-c id extra words beyond three"))
        self.feed(t(args="-c id extra words beyond three again"))                # the same first three arguments
        self.feed(t(binary="/bin/bash"))
        self.feed(t(parent="/usr/sbin/php-fpm"))
        self.feed(t(kind="tetragon.env-read"))
        self.assertEqual(len(self.up.submitted), 5)

    def test_high_repeats_with_the_same_source_and_path_collapse_too(self):
        for i in range(5):
            self.feed(mk(kind="canary.tripwire", sev="HIGH", details={"path": "/.env"}, src_ip="203.0.113.9", src_trust="tcp"), advance=1)
        self.feed(mk(kind="canary.tripwire", sev="HIGH", details={"path": "/.git/config"}, src_ip="203.0.113.9", src_trust="tcp"))
        self.assertEqual(len(self.up.submitted), 2)

    def test_critical_is_never_collapsed_capped_or_budgeted(self):
        self.build("[agent]\nevent_budget_per_hour = 1\n")
        for i in range(500):
            self.feed(mk(kind="tetragon.nginx-exec", source="tetragon", sev="CRITICAL", proc={"binary": "/bin/sh", "args": "-c id", "parent": "/x"}))
        self.assertEqual(len(self.up.submitted), 500)

    def test_a_collapsed_window_that_ends_with_no_repeats_sends_nothing_extra(self):
        self.feed(mk())
        self.clock.advance(400)
        self.p.tick(self.clock())
        self.assertEqual(len(self.up.submitted), 1)

    def test_state_is_bounded(self):
        for i in range(10500):
            self.p.process(mk(kind="k.%d" % (i % 9999), source="agent", summary="s"), self.clock())
            self.clock.advance(0.001)
        self.assertLessEqual(len(self.p.collapse), 10000)

    def test_flush_sends_what_the_windows_hold(self):
        for _ in range(4):
            self.feed(mk())
        self.p.flush()
        self.assertEqual([e.get("count") for e in self.up.submitted], [None, 3])


class TestBudget(PipeCase):
    def test_low_and_medium_are_budgeted_per_source(self):
        self.build("[agent]\nevent_budget_per_hour = 5\n")
        for i in range(12):
            self.feed(mk(kind="a.%d" % i, source="nginx", sev="LOW"))
            self.feed(mk(kind="b.%d" % i, source="journal", sev="MEDIUM"))
        by = {}
        for e in self.up.submitted:
            by[e["source"]] = by.get(e["source"], 0) + 1
        self.assertEqual(by, {"nginx": 5, "journal": 5})
        self.assertEqual(self.p.stats()["dropped"], {"nginx": 7, "journal": 7})
        self.feed(mk(kind="a.next", source="nginx"), advance=3600)               # a new hour
        self.assertEqual(sum(1 for e in self.up.submitted if e["source"] == "nginx"), 6)

    def test_high_and_critical_bypass_the_budget(self):
        self.build("[agent]\nevent_budget_per_hour = 1\n")
        for i in range(20):
            self.feed(mk(kind="a.%d" % i, source="tetragon", sev="HIGH", src_ip="198.51.100.%d" % (i + 1), src_trust="tcp"))
        self.assertEqual(len(self.up.submitted), 20)

    def test_agent_and_canary_events_are_not_budgeted(self):
        self.build("[agent]\nevent_budget_per_hour = 1\n")
        for i in range(10):
            self.feed(mk(kind="health.a%d" % i, source="agent", sev="MEDIUM"))
            self.feed(mk(kind="canary.b%d" % i, source="canary", sev="INFO"))
        self.assertEqual(len(self.up.submitted), 20)

    def test_the_default_is_2000_a_source(self):
        for i in range(2100):
            self.p.process(mk(kind="k.%d" % i, source="inventory", sev="LOW"), self.clock())
        self.assertEqual(len(self.up.submitted), 2000)

    def test_six_sources_are_budgeted(self):
        from edragent import pipeline
        self.assertEqual(set(pipeline.BUDGETED), {"tetragon", "suricata", "nginx", "journal", "kernel", "inventory"})


class TestHighFlood(PipeCase):
    def test_more_than_200_high_an_hour_from_one_address_raises_one_flood_event(self):
        for i in range(260):
            self.feed(mk(kind="k.%d" % i, sev="HIGH", src_ip="203.0.113.9", src_trust="tcp"))
        high = [e for e in self.up.submitted if e["kind"] != "health.high_flood"]
        flood = [e for e in self.up.submitted if e["kind"] == "health.high_flood"]
        self.assertEqual(len(high), 200)
        self.assertEqual(len(flood), 1)
        self.assertEqual(flood[0]["sev"], "HIGH")
        self.feed(mk(kind="k.other", sev="HIGH", src_ip="198.51.100.2", src_trust="tcp"))              # another source is unaffected
        self.assertEqual(self.up.submitted[-1]["kind"], "k.other")
        self.feed(mk(kind="k.again", sev="HIGH", src_ip="203.0.113.9", src_trust="tcp"), advance=3600)  # next hour
        self.assertEqual(self.up.submitted[-1]["kind"], "k.again")

    def test_critical_is_not_counted(self):
        for i in range(300):
            self.feed(mk(kind="k.%d" % i, sev="CRITICAL", src_ip="203.0.113.9", src_trust="tcp"))
        self.assertEqual(len(self.up.submitted), 300)


class TestContext(PipeCase):
    def test_high_events_with_an_address_get_the_access_ring_slice(self):
        for i in range(30):
            self.ctx.ring.add(int(self.clock()), "203.0.113.9", "GET", "/p%d" % i, "token=SECRET%d" % i, 404, 5, "UA")
        self.ctx.ring.add(int(self.clock()), "198.51.100.1", "GET", "/other", "", 200, 5, "UA")
        self.feed(mk(kind="tetragon.nginx-exec", sev="HIGH", src_ip="203.0.113.9", src_trust="tcp"))
        ctx = self.up.submitted[0]["context"]
        self.assertEqual(len(ctx), 20)
        self.assertEqual({c["ip"] for c in ctx}, {"203.0.113.9"})
        self.assertEqual(ctx[-1]["path"], "/p29")
        self.assertNotIn("SECRET", json.dumps(self.up.submitted[0]))
        self.assertLessEqual(len(json.dumps(ctx)), 4096)
        self.assertLessEqual(evmod.size_of(self.up.submitted[0]), 5120)

    def test_low_events_and_events_without_an_address_get_none(self):
        self.ctx.ring.add(int(self.clock()), "203.0.113.9", "GET", "/p", "", 404, 5, "UA")
        self.feed(mk(sev="LOW", src_ip="203.0.113.9", src_trust="tcp"))
        self.feed(mk(kind="k.no_ip", sev="HIGH"))
        self.assertNotIn("context", self.up.submitted[0])
        self.assertNotIn("context", self.up.submitted[1])


class TestAlertFile(PipeCase):
    def test_every_high_and_critical_event_is_written_and_lower_ones_are_not(self):
        self.feed(mk(kind="a.low", sev="LOW"))
        self.feed(mk(kind="a.med", sev="MEDIUM"))
        self.feed(mk(kind="a.high", sev="HIGH"))
        self.feed(mk(kind="a.crit", sev="CRITICAL"))
        self.assertEqual([a["kind"] for a in self.alert_lines()], ["a.high", "a.crit"])
        self.assertEqual(oct(os.stat(self.paths.alerts_jsonl).st_mode & 0o777), "0o600")

    def test_forwarded_events_keep_their_id_in_the_file(self):
        self.feed(mk(kind="a.high", sev="HIGH"))
        self.assertEqual(self.alert_lines()[0]["id"], self.up.submitted[0]["id"])
        self.assertNotIn("context", self.alert_lines()[0])

    def test_repeats_are_collapsed_into_one_line_with_a_count_and_the_first_is_immediate(self):
        for _ in range(50):
            self.feed(mk(kind="a.high", sev="HIGH", summary="same", src_ip="203.0.113.9", src_trust="tcp"), advance=1)
        self.assertEqual(len(self.alert_lines()), 1)
        self.clock.advance(400)
        self.p.tick(self.clock())
        lines = self.alert_lines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[1]["count"], 49)
        self.assertLessEqual(lines[1]["first_ts"], lines[1]["last_ts"])
        self.assertNotEqual(lines[0]["id"], lines[1]["id"])

    def test_collapsed_lines_do_not_depend_on_the_event_streams_own_collapse(self):
        for _ in range(5):
            self.feed(mk(kind="canary.tripwire", sev="HIGH", summary="x", details={"path": "/.env"}, src_ip="203.0.113.9", src_trust="tcp"))
        self.clock.advance(400)
        self.p.tick(self.clock())
        self.assertEqual([a.get("count") for a in self.alert_lines()], [None, 4])

    def test_per_minute_cap_one_suppressed_line_and_first_occurrences_are_never_dropped(self):
        a = alertlog.AlertLog(os.path.join(self.root, "x", "alerts.jsonl"), self.clock, window=1, cap=60)
        self.addCleanup(a.close)
        t = self.clock()
        # 100 different alerts, each twice: the 100 first occurrences all get a line, the 100 collapsed lines are capped
        for i in range(100):
            a.add(mk(kind="k.%d" % i, sev="HIGH", summary="s"), t)
            a.add(mk(kind="k.%d" % i, sev="HIGH", summary="s"), t + 0.1)
        a.tick(t + 2)
        a.tick(t + 90)
        with open(a.path) as f:
            lines = [json.loads(x) for x in f]
        firsts = [x for x in lines if "count" not in x]
        counted = [x for x in lines if x.get("count") and x["kind"] != "health.alerts_suppressed"]
        suppressed = [x for x in lines if x["kind"] == "health.alerts_suppressed"]
        self.assertEqual(len(firsts), 100)                                      # never dropped
        self.assertEqual(len(suppressed), 1)                                    # one line for the rest of the minute
        self.assertEqual(len(counted) + suppressed[0]["count"], 100)
        self.assertLessEqual(len(counted), 60)
        self.assertIn("suppressed", suppressed[0]["summary"])
        self.assertEqual(suppressed[0]["sev"], "HIGH")

    def test_a_flood_of_one_alert_cannot_push_out_others(self):
        a = alertlog.AlertLog(os.path.join(self.root, "y", "alerts.jsonl"), self.clock)
        self.addCleanup(a.close)
        t = self.clock()
        a.add(mk(kind="old.alert", sev="HIGH"), t)
        for i in range(100000):
            a.add(mk(kind="flood", sev="HIGH", summary="same"), t + i * 0.001)
        a.tick(t + 1000)
        self.assertLess(a.written, 10)
        a.close()
        with open(a.path) as f:
            kinds = [json.loads(x)["kind"] for x in f]
        self.assertEqual(kinds[0], "old.alert")

    def test_rotation_at_5_mib_keeps_two_files(self):
        a = alertlog.AlertLog(os.path.join(self.root, "z", "alerts.jsonl"), self.clock, max_bytes=20000)
        self.addCleanup(a.close)
        for i in range(300):
            a.add(mk(kind="k.%d" % i, sev="HIGH", summary="s" * 100), self.clock())
        a.close()
        d = os.path.dirname(a.path)
        self.assertEqual(sorted(os.listdir(d)), ["alerts.jsonl", "alerts.jsonl.1"])
        for n in os.listdir(d):
            self.assertLessEqual(os.path.getsize(os.path.join(d, n)), 20000)
        self.assertEqual(alertlog.MAX_BYTES, 5 * 1024 * 1024)

    def test_fsync_on_critical_only(self):
        calls = []
        real = os.fsync
        os.fsync = lambda fd: calls.append(fd) or real(fd)
        try:
            self.feed(mk(kind="a.high", sev="HIGH"))
            n = len(calls)
            self.feed(mk(kind="a.crit", sev="CRITICAL"))
        finally:
            os.fsync = real
        self.assertEqual(n, 0)                                                  # no fsync for a HIGH line
        self.assertGreater(len(calls), 0)                                       # one for the CRITICAL line

    def test_read_alerts_since(self):
        self.feed(mk(kind="old.alert", sev="HIGH", ts_ms=int((self.clock() - 8 * 86400) * 1000)))
        self.feed(mk(kind="new.alert", sev="HIGH", ts_ms=int(self.clock() * 1000)))
        self.p.alerts.close()
        rows = alertlog.read_alerts(self.paths.alerts_jsonl, self.clock() - 7 * 86400)
        self.assertEqual([r["kind"] for r in rows], ["new.alert"])
        self.assertEqual(len(alertlog.read_alerts(self.paths.alerts_jsonl, 0)), 2)

    def test_journal_copy_levels(self):
        self.feed(mk(kind="a.high", sev="HIGH"))
        self.feed(mk(kind="a.crit", sev="CRITICAL"))
        self.assertEqual([lvl for lvl, _ in self.logs], ["err", "crit"])
        self.p.hub_down = True
        self.feed(mk(kind="b.high", sev="HIGH"))
        self.assertEqual(self.logs[-1][0], "crit")

    def test_summary_json(self):
        self.feed(mk(kind="a.high", sev="HIGH", summary="one"))
        self.feed(mk(kind="a.crit", sev="CRITICAL", summary="two"))
        self.p.tick(self.clock() + 20, {"mode": "local"}, {"agent": {"pid": 1}})
        with open(self.paths.summary_json) as f:
            s = json.load(f)
        self.assertEqual(s["counts"], {"CRITICAL": 1, "HIGH": 1})
        self.assertEqual([a["kind"] for a in s["alerts"]], ["a.crit", "a.high"])
        self.assertEqual(s["hub"], {"mode": "local"})
        self.assertEqual(s["agent"], {"pid": 1})
        self.assertEqual(oct(os.stat(self.paths.summary_json).st_mode & 0o777), "0o644")


class TestLearning(PipeCase):
    def test_web_policy_hits_are_recorded_without_arguments_beyond_the_first_basename(self):
        e = mk(kind="tetragon.web-exec", source="tetragon", sev="HIGH",
               proc={"binary": "/usr/bin/convert", "args": "/tmp/in.png out.png", "parent": "/usr/sbin/php-fpm8.3", "uid": 0})
        self.feed(e)
        self.feed(mk(kind="tetragon.nginx-exec", source="tetragon", sev="HIGH", proc={"binary": "/bin/sh", "args": "-c", "parent": "/x"}))
        tuples = self.p.learn.data["tuples"]
        self.assertEqual(len(tuples), 1)
        t = next(iter(tuples.values()))
        self.assertEqual((t["policy"], t["binary"], t["parent"], t["arg0"]), ("web-exec", "/usr/bin/convert", "/usr/sbin/php-fpm8.3", "in.png"))
        self.assertNotIn("out.png", json.dumps(t))
        self.assertEqual(list(t["days"].values()), [1])


if __name__ == "__main__":
    unittest.main()
