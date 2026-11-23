"""hub_engine, event side: after_insert, the cursor, incidents, sum(count) windows, the three NGINX2Root chains."""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "hub"))

import hub_engine    # noqa: E402
from test_engine_support import HubTestCase, T0, MIN, HOUR   # noqa: E402


class EngineCase(HubTestCase):
    def setUp(self):
        super().setUp()
        self.host = self.hub.add_host("web1", last_seen=T0 + 3 * HOUR)
        self.hub.settings["digest_time"] = "23:59"            # the digest and the self-health checks have their own tests
        self.engine = hub_engine.Engine(self.hub)
        self.engine._t_health = float("inf")

    def tick(self, now):
        self.engine.tick(now)

    def after_insert(self, *events, host=None):
        self.hub.writer.call(lambda c: hub_engine.after_insert(c, self.hub, host or self.host, list(events)))

    def alerts(self, kind=None):
        out = self.hub.outbox()
        return [o for o in out if o["channel"] == "webhook" and (kind is None or o["payload"]["kind"] == kind)]

    def incident_signals(self):
        return [(i["chain"], i["severity"], i["state"], i["signals"], json.loads(i["kinds"])) for i in self.hub.incidents()]


class AfterInsertTests(EngineCase):
    def test_critical_event_is_in_the_outbox_at_once_with_its_incident(self):
        e = self.hub.add_event(self.host, "tetragon.nginx-exec", "CRITICAL", count=3, src_ip="198.51.100.7", summary="nginx worker tried to exec /bin/sh",
                               details={"proc": {"binary": "/bin/sh", "args": "-c id", "uid": 33}})
        self.after_insert(e)
        (a,) = self.alerts()
        self.assertEqual(a["severity"], "CRITICAL")
        p = a["payload"]
        self.assertEqual((p["kind"], p["host"], p["incident_id"]), ("tetragon.nginx-exec", "web1", 1))
        self.assertEqual(p["fields"]["source ip"], "198.51.100.7")
        self.assertEqual(p["fields"]["process"], "/bin/sh -c id")
        self.assertEqual(p["fields"]["repeats"], "3")
        self.assertIn("edr-hub incident 1", p["commands"])
        self.assertEqual(self.incident_signals(), [("exploit", "CRITICAL", "open", 3, ["tetragon.nginx-exec"])])

    def test_the_tick_does_not_count_or_alert_the_same_event_again(self):
        e = self.hub.add_event(self.host, "tetragon.nginx-exec", "CRITICAL", count=3)
        self.after_insert(e)
        self.tick(T0 + 10_000)
        self.tick(T0 + 20_000)
        self.assertEqual(len(self.alerts()), 1)
        self.assertEqual(self.incident_signals()[0][3], 3)                       # sum(count), once
        self.assertEqual(self.hub.meta("engine_cursor"), "1")

    def test_a_critical_event_that_after_insert_never_saw_is_alerted_by_the_tick(self):
        self.hub.add_event(self.host, "tetragon.web-exec", "CRITICAL")
        self.tick(T0 + 10_000)
        self.assertEqual(len(self.alerts()), 1)

    def test_only_critical_events_are_handled(self):
        e = self.hub.add_event(self.host, "tamper.x", "HIGH")
        self.after_insert(e)
        self.assertEqual(self.alerts(), [])

    def test_never_raises_and_keeps_the_rest_of_the_transaction(self):
        good = self.hub.add_event(self.host, "tetragon.web-exec", "CRITICAL")

        def work(c):
            c.execute("INSERT INTO meta (key, value) VALUES ('marker', '1')")
            hub_engine.after_insert(c, self.hub, self.host, [{"hub_severity": "CRITICAL"}, "junk", None,
                                                             {"hub_severity": "CRITICAL", "kind": None, "rowid": "x"}, good])
        self.hub.writer.call(work)
        self.assertEqual(self.hub.meta("marker"), "1")
        self.assertEqual(len(self.alerts()), 1)                                   # the good event still alerted
        self.assertTrue(any("after_insert failed" in m for _l, m in self.hub.logs))

    def test_replayed_critical_is_labelled_with_its_delay(self):
        e = self.hub.add_event(self.host, "tetragon.nginx-exec", "CRITICAL", ts=T0 - (3 * HOUR + 12 * MIN), received_at=T0, replayed=1)
        self.after_insert(e)
        (a,) = self.alerts()
        self.assertEqual(a["payload"]["fields"]["late"], "delayed 3h12m")

    def test_hostile_event_fields_are_sanitised_before_they_reach_the_outbox(self):
        evil = "\x1b]8;;http://evil.example/\x07click\x1b]8;;\x07 \u202e <!channel> `x` \x00"
        e = self.hub.add_event(self.host, "tetragon.nginx-exec", "CRITICAL", summary=evil, src_ip="198.51.100.7",
                               details={"proc": {"binary": evil, "args": evil * 3, "uid": 33}, "path": evil, "what": evil})
        self.after_insert(e)
        (a,) = self.alerts()
        blob = json.dumps(a["payload"], ensure_ascii=False)
        for bad in ("\x1b", "\x07", "\x00", "\u202e"):
            self.assertNotIn(bad, blob)
        self.assertTrue(all(len(v) <= 200 for v in a["payload"]["fields"].values()))
        import hub_alerts
        text = json.loads(hub_alerts.render("webhook", a["payload"])["body"])["text"]
        self.assertNotIn("<", text)
        self.assertIn("&lt;!channel&gt;", text)

    def test_dedup_five_minutes_per_host_and_kind(self):
        for i in range(3):
            e = self.hub.add_event(self.host, "tetragon.web-exec", "CRITICAL", received_at=T0 + i * MIN)
            self.after_insert(e)
        self.assertEqual(len(self.alerts()), 1)
        self.assertEqual(self.incident_signals()[0][3], 3)


class IncidentTests(EngineCase):
    def test_high_event_opens_one_incident_and_alerts_once(self):
        self.hub.add_event(self.host, "tetragon.env-read", "HIGH", received_at=T0, src_ip="198.51.100.7")
        self.tick(T0 + 10_000)
        self.assertEqual(self.incident_signals(), [("secrets", "HIGH", "open", 1, ["tetragon.env-read"])])
        self.assertEqual(len(self.alerts()), 1)
        self.hub.add_event(self.host, "tetragon.env-read", "HIGH", received_at=T0 + 5 * MIN, count=4)
        self.tick(T0 + 5 * MIN + 1000)
        self.assertEqual(self.incident_signals(), [("secrets", "HIGH", "open", 5, ["tetragon.env-read"])])      # a repeat only counts
        self.assertEqual(len(self.alerts()), 1)

    def test_medium_and_low_events_never_open_incidents(self):
        self.hub.add_event(self.host, "ssh.fail", "LOW")
        self.hub.add_event(self.host, "inventory.stale", "MEDIUM")
        self.tick(T0 + 10_000)
        self.assertEqual(self.hub.incidents(), [])
        self.assertEqual(self.alerts(), [])

    def test_two_distinct_kinds_raise_it_one_level_and_alert(self):
        self.hub.add_event(self.host, "tetragon.env-read", "HIGH", received_at=T0)
        self.tick(T0 + 10_000)
        self.hub.add_event(self.host, "canary.file", "HIGH", received_at=T0 + 10 * MIN)
        self.tick(T0 + 10 * MIN + 1000)
        self.assertEqual(self.incident_signals()[0][:3], ("secrets", "CRITICAL", "open"))
        self.assertEqual([a["severity"] for a in self.alerts()], ["HIGH", "CRITICAL"])
        self.hub.add_event(self.host, "tamper.x", "HIGH", received_at=T0 + 11 * MIN)             # another chain: its own incident
        self.hub.add_event(self.host, "tamper.y", "HIGH", received_at=T0 + 12 * MIN)
        self.tick(T0 + 13 * MIN)
        self.assertEqual(sorted((c, s) for c, s, *_ in self.incident_signals()), [("secrets", "CRITICAL"), ("tamper", "CRITICAL")])

    def test_critical_stays_critical(self):
        for i, k in enumerate(("tetragon.web-exec", "tetragon.nginx-exec", "tetragon.web-write-code")):
            self.hub.add_event(self.host, k, "CRITICAL", received_at=T0 + i * MIN)
        self.tick(T0 + 5 * MIN)
        self.assertEqual(self.incident_signals()[0][1], "CRITICAL")

    def test_a_signal_after_a_30_minute_gap_opens_a_new_incident(self):
        self.hub.add_event(self.host, "tetragon.env-read", "HIGH", received_at=T0)
        self.tick(T0 + 10_000)
        self.hub.add_event(self.host, "tetragon.env-read", "HIGH", received_at=T0 + 40 * MIN)
        self.tick(T0 + 40 * MIN + 1000)
        inc = self.hub.incidents()
        self.assertEqual([(i["state"]) for i in inc], ["resolved", "open"])
        self.assertEqual(len(self.alerts()), 2)

    def test_resolved_after_60_minutes_with_no_signal(self):
        self.hub.add_event(self.host, "tetragon.env-read", "HIGH", received_at=T0)
        self.tick(T0 + 10_000)
        self.tick(T0 + 59 * MIN)
        self.assertEqual(self.hub.incidents()[0]["state"], "open")
        self.tick(T0 + 61 * MIN)
        self.assertEqual(self.hub.incidents()[0]["state"], "resolved")
        row = self.hub.q("SELECT closed_by, closed_at FROM incidents")[0]
        self.assertEqual(row[0], "system")

    def test_a_signal_after_an_operator_resolved_the_incident_opens_a_new_one(self):
        self.hub.add_event(self.host, "tetragon.env-read", "HIGH", received_at=T0)
        self.tick(T0 + 10_000)
        self.hub.writer.call(lambda c: c.execute("UPDATE incidents SET state='resolved', closed_by='uid=0'"))
        self.hub.add_event(self.host, "tetragon.env-read", "HIGH", received_at=T0 + 5 * MIN)
        self.tick(T0 + 5 * MIN + 1000)
        self.assertEqual([i["state"] for i in self.hub.incidents()], ["resolved", "open"])

    def test_events_are_pinned_to_their_incident(self):
        e = self.hub.add_event(self.host, "tetragon.env-read", "HIGH")
        self.tick(T0 + 10_000)
        self.assertEqual(self.hub.q("SELECT incident_id, event_rowid FROM incident_events"), [(1, e["rowid"])])

    def test_incident_note_names_an_operator_window(self):
        self.hub.writer.call(lambda c: c.execute("INSERT INTO maintenance (host, until, set_by, set_at) VALUES (?,?,?,?)",
                                                 (self.host["uuid"], T0 + HOUR, "uid=1000", T0)))
        self.hub.add_event(self.host, "tetragon.env-read", "HIGH")
        self.tick(T0 + 10_000)
        note = self.hub.q("SELECT note FROM incidents")[0][0]
        self.assertIn("maintenance window set on the hub by uid=1000", note)
        self.assertIn("maintenance window", self.alerts()[0]["payload"]["fields"])

    def test_retired_and_moved_hosts_are_out_of_correlation(self):
        gone = self.hub.add_host("old1", state="retired")
        self.hub.add_event(gone, "tetragon.env-read", "HIGH")
        self.tick(T0 + 10_000)
        self.assertEqual(self.hub.incidents(), [])
        self.assertEqual(self.hub.meta("engine_cursor"), "1")

    def test_replayed_high_makes_an_incident_but_does_not_page(self):
        self.hub.add_event(self.host, "tetragon.env-read", "HIGH", ts=T0 - 3 * HOUR, received_at=T0, replayed=1)
        self.tick(T0 + 10_000)
        self.assertEqual(len(self.hub.incidents()), 1)
        self.assertEqual(self.alerts(), [])

    def test_event_time_window_rules(self):
        h = self.host
        self.assertEqual(hub_engine.event_time({"ts": T0 - MIN, "received_at": T0}, 0), T0 - MIN)
        self.assertEqual(hub_engine.event_time({"ts": T0 + MIN, "received_at": T0}, 0), T0)          # in the future
        self.assertEqual(hub_engine.event_time({"ts": T0 - MIN, "received_at": T0}, 6 * MIN), T0)     # skew over 5 minutes
        self.assertEqual(hub_engine.event_time({"ts": T0 - MIN, "received_at": T0}, 4 * MIN), T0 - MIN)
        self.assertEqual(h["name"], "web1")


class SumCountTests(EngineCase):
    def crash_alerts(self):
        return [a for a in self.alerts("nginx.crash")]

    def test_three_crashes_in_ten_minutes_by_sum_of_count_not_rows(self):
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0, count=2)
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0 + 4 * MIN, count=1)
        self.tick(T0 + 5 * MIN)
        (a,) = self.crash_alerts()
        self.assertIn("crashed 3 times", a["payload"]["title"])
        self.assertEqual(self.incident_signals()[0][:3], ("exploit", "HIGH", "open"))

    def test_two_rows_of_one_crash_each_are_not_enough(self):
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0)
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0 + MIN)
        self.tick(T0 + 2 * MIN)
        self.assertEqual(self.crash_alerts(), [])

    def test_crashes_more_than_ten_minutes_apart_do_not_add_up(self):
        for i in range(3):
            self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0 + i * 11 * MIN)
        self.tick(T0 + HOUR)
        self.assertEqual(self.crash_alerts(), [])

    def test_a_late_batch_lands_in_the_window(self):
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0 + 20 * MIN, ts=T0 + 20 * MIN)
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0 + 20 * MIN, ts=T0 + 20 * MIN)
        self.tick(T0 + 21 * MIN)
        self.assertEqual(self.crash_alerts(), [])
        # a replay from before arrives later with old event times; its flag keeps it out of the live window
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0 + 22 * MIN, ts=T0 + 19 * MIN)
        self.tick(T0 + 23 * MIN)
        self.assertEqual(len(self.crash_alerts()), 1)

    def test_replayed_crashes_do_not_page(self):
        for i in range(3):
            self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0 + HOUR, ts=T0 + i * MIN, replayed=1)
        self.tick(T0 + HOUR + MIN)
        self.assertEqual(self.crash_alerts(), [])
        self.assertEqual(len(self.hub.incidents()), 1)

    def test_bigconn_followed_by_a_crash_is_high(self):
        big = self.hub.add_event(self.host, "edr.bigconn", "MEDIUM", received_at=T0)
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0 + 10 * MIN)
        self.tick(T0 + 11 * MIN)
        row = self.hub.q("SELECT hub_severity, rated_by, severity FROM events WHERE id=?", (big["rowid"],))[0]
        self.assertEqual(row, ("HIGH", "bigconn", "MEDIUM"))                            # the client's sev is never rewritten
        self.assertEqual(len(self.alerts("edr.bigconn")), 1)

    def test_bigconn_alone_or_with_a_late_crash_stays_medium(self):
        big = self.hub.add_event(self.host, "edr.bigconn", "MEDIUM", received_at=T0)
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0 + 40 * MIN)
        self.tick(T0 + 41 * MIN)
        self.assertEqual(self.hub.q("SELECT hub_severity FROM events WHERE id=?", (big["rowid"],))[0][0], "MEDIUM")

    def test_window_update_three_in_ten_minutes_by_sum_of_count(self):
        a = self.hub.add_event(self.host, "nginx.marker.window_update", "LOW", received_at=T0, src_ip="198.51.100.7", count=1)
        self.hub.add_event(self.host, "nginx.marker.window_update", "LOW", received_at=T0 + MIN, src_ip="198.51.100.7", count=1)
        self.tick(T0 + 2 * MIN)
        self.assertEqual(self.hub.q("SELECT hub_severity FROM events WHERE id=?", (a["rowid"],))[0][0], "LOW")
        self.hub.add_event(self.host, "nginx.marker.window_update", "LOW", received_at=T0 + 2 * MIN, src_ip="198.51.100.7", count=2)
        self.tick(T0 + 3 * MIN)
        self.assertEqual({r[0] for r in self.hub.q("SELECT hub_severity FROM events")}, {"MEDIUM"})
        self.assertEqual(self.hub.q("SELECT rated_by FROM events WHERE id=?", (a["rowid"],))[0][0], "window_update")

    def test_window_update_from_different_addresses_is_not_summed(self):
        for i, ip in enumerate(("198.51.100.1", "198.51.100.2", "198.51.100.3")):
            self.hub.add_event(self.host, "nginx.marker.window_update", "LOW", received_at=T0 + i * MIN, src_ip=ip)
        self.tick(T0 + 5 * MIN)
        self.assertEqual({r[0] for r in self.hub.q("SELECT hub_severity FROM events")}, {"LOW"})


class ChainTests(EngineCase):
    def chain_alerts(self, kind):
        return [a for a in self.alerts(kind)]

    def test_attempt_contained(self):
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0)
        self.hub.add_event(self.host, "tetragon.nginx-exec", "CRITICAL", received_at=T0 + 10 * MIN, details={"proc": {"binary": "/bin/sh", "uid": 33}})
        self.tick(T0 + 11 * MIN)
        (a,) = self.chain_alerts("hub.contained")
        self.assertEqual(a["severity"], "CRITICAL")
        self.assertIn("Attempt contained", a["payload"]["title"])
        inc = self.incident_signals()[0]
        self.assertEqual(inc[:3], ("exploit", "CRITICAL", "open"))
        self.assertIn("chain.contained", inc[4])
        self.tick(T0 + 12 * MIN)
        self.assertEqual(len(self.chain_alerts("hub.contained")), 1)              # once per pair of events

    def test_contained_for_each_first_signal_and_sctp(self):
        for first in ("edr.bigconn", "nginx.marker.window_update"):
            h = self.hub.add_host("h-" + first[-4:])
            self.hub.add_event(h, first, "MEDIUM", received_at=T0)
            self.hub.add_event(h, "tetragon.sctp-socket", "CRITICAL", received_at=T0 + MIN)
        self.tick(T0 + 5 * MIN)
        self.assertEqual(len(self.chain_alerts("hub.contained")), 2)

    def test_contained_needs_the_second_signal_within_30_minutes_and_in_order(self):
        self.hub.add_event(self.host, "tetragon.nginx-exec", "CRITICAL", received_at=T0)               # exec first, crash after: not this chain
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0 + 5 * MIN)
        late = self.hub.add_host("web2")
        self.hub.add_event(late, "nginx.crash", "MEDIUM", received_at=T0)
        self.hub.add_event(late, "tetragon.nginx-exec", "CRITICAL", received_at=T0 + 31 * MIN)
        self.tick(T0 + HOUR)
        self.assertEqual(self.chain_alerts("hub.contained"), [])

    def test_contained_found_when_the_signals_arrive_out_of_order(self):
        # the exec reaches the hub first (higher priority lane), the crash comes later from the spool with its old time
        self.hub.add_event(self.host, "tetragon.nginx-exec", "CRITICAL", received_at=T0 + 10 * MIN, ts=T0 + 10 * MIN)
        self.tick(T0 + 11 * MIN)
        self.assertEqual(self.chain_alerts("hub.contained"), [])
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0 + 12 * MIN, ts=T0 + 2 * MIN)
        self.tick(T0 + 13 * MIN)
        self.assertEqual(len(self.chain_alerts("hub.contained")), 1)

    def test_chains_use_the_hosts_own_events_only(self):
        other = self.hub.add_host("web2")
        self.hub.add_event(other, "nginx.crash", "MEDIUM", received_at=T0)
        self.hub.add_event(self.host, "tetragon.nginx-exec", "CRITICAL", received_at=T0 + MIN)
        self.tick(T0 + 5 * MIN)
        self.assertEqual(self.chain_alerts("hub.contained"), [])

    def test_worker_survived_the_kill_and_the_open_task(self):
        self.hub.add_event(self.host, "tetragon.fork-watch", "HIGH", received_at=T0)
        self.hub.add_event(self.host, "tetragon.web-connect", "HIGH", received_at=T0 + 9 * MIN)
        self.tick(T0 + 10 * MIN)
        (a,) = self.chain_alerts("hub.survived")
        self.assertEqual(a["severity"], "CRITICAL")
        self.assertIn("restart nginx", a["payload"]["next_step"].lower())
        task = self.hub.q("SELECT data FROM alert_state WHERE key LIKE 'task|survived|%'")
        self.assertEqual(len(task), 1)

    def test_survived_needs_a_web_event_within_ten_minutes(self):
        self.hub.add_event(self.host, "tetragon.fork-watch", "HIGH", received_at=T0)
        self.hub.add_event(self.host, "tetragon.web-exec", "HIGH", received_at=T0 + 11 * MIN)
        self.tick(T0 + 12 * MIN)
        self.assertEqual(self.chain_alerts("hub.survived"), [])

    def test_possible_success_after_tamper(self):
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0)
        self.hub.add_event(self.host, "tamper.log_truncated", "HIGH", received_at=T0 + 20 * MIN)
        self.tick(T0 + 21 * MIN)
        (a,) = self.chain_alerts("hub.possible_success")
        self.assertEqual(a["severity"], "CRITICAL")
        self.assertIn("treat the host as lost", a["payload"]["next_step"].lower())

    def test_tamper_before_the_first_signal_is_not_possible_success(self):
        self.hub.add_event(self.host, "tamper.log_truncated", "HIGH", received_at=T0)
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0 + 5 * MIN)
        self.tick(T0 + 10 * MIN)
        self.assertEqual(self.chain_alerts("hub.possible_success"), [])

    def test_replayed_events_chain_only_with_replayed_events(self):
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0 + 5 * HOUR, ts=T0, replayed=1)
        self.hub.add_event(self.host, "tetragon.nginx-exec", "CRITICAL", received_at=T0 + 5 * HOUR, ts=T0 + MIN, replayed=0)
        self.tick(T0 + 5 * HOUR + MIN)
        self.assertEqual(self.chain_alerts("hub.contained"), [])
        h2 = self.hub.add_host("web2")
        self.hub.add_event(h2, "nginx.crash", "MEDIUM", received_at=T0 + 5 * HOUR, ts=T0, replayed=1)
        self.hub.add_event(h2, "tetragon.nginx-exec", "CRITICAL", received_at=T0 + 5 * HOUR, ts=T0 + MIN, replayed=1)
        self.tick(T0 + 5 * HOUR + 2 * MIN)
        self.assertEqual(len(self.chain_alerts("hub.contained")), 1)


if __name__ == "__main__":
    unittest.main()
