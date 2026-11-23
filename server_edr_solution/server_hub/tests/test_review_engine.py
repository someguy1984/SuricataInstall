"""Findings of the independent review of the engine, rules, alerts, advisory and outbound code.

Each test pins a defect the review found and that has since been fixed, or behaviour the review found right.
Reuses test_engine_support.py (a FakeHub on a real SQLite file) and test_ingest_fixture.py (the real server), read only.
"""

import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_engine_support as E  # noqa: E402
import test_ingest_fixture as F  # noqa: E402

import edr_hub_out  # noqa: E402
import hub_advisory  # noqa: E402
import hub_alerts  # noqa: E402
import hub_common  # noqa: E402
import hub_engine  # noqa: E402

T0, MIN, HOUR = E.T0, E.MIN, E.HOUR


class EngineCase(E.HubTestCase):
    def tick(self, now=T0 + 1):
        hub_engine.Engine(self.hub).tick(now)


class ConfirmedDefects(EngineCase):
    # was a confirmed defect, fixed: hub_alerts.py:195-216 and hub_rules.py (rate): the 5-minute CRITICAL dedup key is (host, client-chosen kind)
    def test_one_host_cannot_page_every_channel_dozens_of_times_with_invented_kinds(self):
        fx = F.HubFixture()
        self.addCleanup(fx.stop)
        c = fx.enroll("web1")
        events = [F.make_event(seq=i + 1, sev="CRITICAL", kind="x.invented%d" % i) for i in range(30)]
        self.assertEqual(c.send_events(events)[0], 200)
        pages = fx.sql("SELECT COUNT(*) AS n FROM outbox WHERE severity='CRITICAL'")[0]["n"]
        self.assertLessEqual(pages, 5)                                    # today 30: CRITICAL is exempt from storm control

    # was a confirmed defect, fixed: hub_engine.py:646 _track key "dup|droplet|<uuid>|<claimed id>": one alert_state row per claimed id, never pruned
    def test_claimed_droplet_ids_cannot_grow_alert_state_without_bound(self):
        fx = F.HubFixture()
        self.addCleanup(fx.stop)
        c = fx.enroll("web1")
        for i in range(40):
            self.assertEqual(c.heartbeat(droplet_id="evil-%d" % i)[0], 200)
        rows = fx.sql("SELECT COUNT(*) AS n FROM alert_state WHERE key LIKE 'dup|droplet|%'")[0]["n"]
        self.assertLessEqual(rows, 3)                                     # today 40 (and 40 HIGH findings)

    # was a confirmed defect, fixed: hub_engine.py:869-883 (_advisory_eval): a look with no finding clears first-seen, so "HIGH after 24 h" never comes
    def test_an_unknown_inventory_result_does_not_reset_the_24_hour_exposure_clock(self):
        host = self.hub.add_host("web1")
        vulnerable = {"os_release": "Ubuntu 24.04", "checks": {
            "nginx_pkg": {"status": True, "packages": [{"name": "nginx", "version": "1.24.0-2ubuntu7.1", "origin": "ubuntu"}]},
            "nginx_exposure": {"tls": True}}}
        unknown = {"os_release": "Ubuntu 24.04", "checks": {"nginx_pkg": {"status": "unknown"}}}
        for when, inv in ((T0, vulnerable), (T0 + 23 * HOUR, unknown), (T0 + 25 * HOUR, vulnerable)):
            self.hub.writer.call(lambda c, w=when, i=inv: hub_engine._advisory_eval(c, self.hub, self.hub.host(host["uuid"]), i, w, daily=False))
        self.assertTrue([o for o in self.hub.outbox() if o["severity"] == "HIGH"])    # 25 h after the first sighting

    # was a confirmed defect, fixed: hub_engine.py:714 and 748-749: ms_to_rfc3339 / int() on a client number raises, the rule is skipped
    def test_odd_client_numbers_do_not_make_heartbeat_rules_fail(self):
        host = self.hub.add_host("web1")
        hb = {"paused_until": 10 ** 18, "conntrack": {"count": 1e308, "max": 1}}
        self.hub.writer.call(lambda c: hub_engine.on_heartbeat(c, self.hub, host, hb, T0, "203.0.113.9"))
        self.assertEqual([m for lvl, m in self.hub.logs if "failed" in m], [])

    # was a confirmed defect, fixed: hub_advisory.py:35-48 and 244-258: a version that is not a dpkg version (none, unknown, NUL) compares as newer, so "fixed"
    def test_a_version_string_that_is_not_a_version_is_unknown_not_fixed(self):
        adv = hub_advisory.load(self.hub.paths)
        for version in ("none", "unknown", "(none)", "n/a", "\x00"):
            out = hub_advisory.evaluate_package(adv, origin="ubuntu", release="noble", package="nginx", version=version, now_ms=T0)
            self.assertNotIn("fixed", [v["status"] for v in out], version)

    # was a confirmed defect, fixed: hub_advisory.py:208-216 (load): advisories.d/*.json symlinks are followed, size is taken from the link target
    def test_an_advisory_override_that_is_a_symlink_is_not_loaded(self):
        paths = self.hub.paths
        os.makedirs(paths.advisories_d, exist_ok=True)
        outside = os.path.join(self.tmp, "outside.json")
        with open(outside, "w") as f:
            json.dump({"rows": [{"id": "planted", "origin": "ubuntu", "release": "noble", "packages": ["nginx"], "compare": "dpkg",
                                 "fixed_in": "0:0", "cves": [], "needs_feature": None, "ref": "https://example.org"}]}, f)
        os.symlink(outside, os.path.join(paths.advisories_d, "planted.json"))
        adv = hub_advisory.load(paths)
        self.assertNotIn("planted", [r["id"] for r in adv.rows])

    # was a confirmed defect, fixed: edr_hub_out.py:152-157: 5 s is a per-read timeout, so a slow-dripping reply holds the one worker for ever
    def test_a_slow_dripping_webhook_reply_cannot_hold_the_worker(self):
        fx = F.HubFixture()
        self.addCleanup(fx.stop)
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(fx.paths.server_cert, fx.paths.server_key)

        def serve():
            tls = None
            try:
                conn, _ = srv.accept()
                tls = sctx.wrap_socket(conn, server_side=True)
                tls.settimeout(5)
                data = b""
                while b"\r\n\r\n" not in data:
                    data += tls.recv(4096)
                tls.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 1000000\r\n\r\n")
                for _ in range(12):                                      # one byte every second, longer than any sane wall clock
                    time.sleep(1)
                    tls.sendall(b"x")
            except OSError:
                pass
            finally:
                if tls is not None:
                    tls.close()
        threading.Thread(target=serve, daemon=True).start()
        self.addCleanup(srv.close)
        ctx = edr_hub_out.make_context(fx.hub.pki.ca_pem())
        done = []
        t = threading.Thread(target=lambda: done.append(edr_hub_out.http_send(
            "POST", "https://127.0.0.1:%d/hook" % srv.getsockname()[1], {}, b"{}", ctx, allow_private=True)), daemon=True)
        t.start()
        t.join(7)
        self.assertFalse(t.is_alive())                                    # a send must be over after a few seconds in all


class ReplayedEventsFollowThePlan(unittest.TestCase):
    """What PLAN section 2 (Clock skew and old events) and section 4 (Late and out-of-order events) specify.

    The replayed flag comes from the event's own time, so a client can back-date an event. The plan accepts that:
    a replayed event is stored and shown as late, pages only if CRITICAL (once, labelled "delayed"), and may chain
    only with other replayed events. A client that controls its agent can simply not send an event, so back-dating
    gives it nothing new. These tests pin the plan's behaviour; they are not defects.
    """

    def setUp(self):
        self.fx = F.HubFixture()
        self.addCleanup(self.fx.stop)
        self.client = self.fx.enroll("web1")

    def run_engine(self):
        hub_engine.Engine(self.fx.hub).tick()

    def alerts(self):
        return [json.loads(r["payload"]) for r in self.fx.sql("SELECT payload FROM outbox")]

    def test_a_replayed_high_is_stored_shown_as_late_and_does_not_page(self):
        old = hub_common.ms_to_rfc3339(hub_common.now_ms() - 15 * MIN)
        self.assertEqual(self.client.send_events([F.make_event(sev="HIGH", kind="tamper.log_changed", ts=old)])[0], 200)
        row = self.fx.sql("SELECT replayed, hub_severity FROM events")[0]
        self.assertEqual((row["replayed"], row["hub_severity"]), (1, "HIGH"))       # stored, flagged late, still rated HIGH
        self.run_engine()
        self.assertEqual([a for a in self.alerts() if a["kind"] == "tamper.log_changed"], [])
        ro = self.fx.hub.ro()
        try:
            digest = hub_engine.build_digest(ro, self.fx.hub, hub_common.now_ms() - HOUR, hub_common.now_ms())[0]
        finally:
            ro.close()
        self.assertTrue([line for line in digest if line.startswith("Late events: 1")])    # the digest names it

    def test_a_replayed_critical_pages_once_and_says_it_was_delayed(self):
        old = hub_common.ms_to_rfc3339(hub_common.now_ms() - 15 * MIN)
        self.assertEqual(self.client.send_events([F.make_event(sev="CRITICAL", kind="tetragon.nginx-exec", ts=old)])[0], 200)
        self.run_engine()
        self.run_engine()                                                           # the tick does not page it a second time
        pages = [a for a in self.alerts() if a["kind"] == "tetragon.nginx-exec"]
        self.assertEqual(len(pages), 1)
        self.assertTrue(pages[0]["fields"].get("late", "").startswith("delayed "))

    def test_a_replayed_signal_does_not_complete_a_chain_with_a_live_one(self):
        old = hub_common.ms_to_rfc3339(hub_common.now_ms() - 12 * MIN)
        self.client.send_events([F.make_event(seq=1, sev="MEDIUM", kind="nginx.crash", ts=old, source="nginx")])
        self.client.send_events([F.make_event(seq=2, sev="CRITICAL", kind="tetragon.nginx-exec", source="tetragon")], batch_id="b2")
        self.run_engine()
        self.assertEqual([a for a in self.alerts() if a["kind"] == "hub.contained"], [])      # replayed chains only with replayed
        self.assertTrue([a for a in self.alerts() if a["kind"] == "tetragon.nginx-exec"])     # the live CRITICAL still pages on its own

    def test_two_replayed_signals_of_one_replayed_batch_do_chain(self):
        old1 = hub_common.ms_to_rfc3339(hub_common.now_ms() - 14 * MIN)
        old2 = hub_common.ms_to_rfc3339(hub_common.now_ms() - 12 * MIN)
        self.client.send_events([F.make_event(seq=1, sev="MEDIUM", kind="nginx.crash", ts=old1, source="nginx"),
                                 F.make_event(seq=2, sev="CRITICAL", kind="tetragon.nginx-exec", ts=old2, source="tetragon")])
        self.run_engine()
        self.assertTrue([a for a in self.alerts() if a["kind"] == "hub.contained"])


class VerifiedGood(EngineCase):
    """What the review tried to break and could not."""

    def test_a_clients_own_maintenance_pause_and_shutdown_fields_never_silence_agent_silent(self):
        host = self.hub.add_host("web1", last_seen=T0 - 10 * MIN, shutdown_notice_at=None)
        hb = {"maintenance_until": T0 + 3600 * 1000, "paused_until": T0 + 3600 * 1000}
        self.hub.writer.call(lambda c: hub_engine.on_heartbeat(c, self.hub, host, hb, T0 - 10 * MIN, "203.0.113.9"))
        engine = hub_engine.Engine(self.hub)
        engine.grace_until = 0
        engine.tick(T0)
        self.assertTrue([o for o in self.hub.outbox() if "no heartbeat" in o["payload"]["title"]])

    def test_only_a_window_set_on_the_hub_silences_agent_silent(self):
        host = self.hub.add_host("web1", last_seen=T0 - 10 * MIN)
        self.hub.writer.call(lambda c: c.execute("INSERT INTO maintenance (host, until, set_by, set_at) VALUES (?,?,?,?)",
                                                 (host["uuid"], T0 + HOUR, "uid=0 sudo=j", T0)))
        engine = hub_engine.Engine(self.hub)
        engine.grace_until = 0
        engine.tick(T0)
        self.assertEqual([o for o in self.hub.outbox() if "no heartbeat" in o["payload"]["title"]], [])

    def test_exactly_the_same_exposure_clock_reaches_high_at_24_hours_without_a_gap(self):
        host = self.hub.add_host("web1")
        vulnerable = {"os_release": "Ubuntu 24.04", "checks": {
            "nginx_pkg": {"status": True, "packages": [{"name": "nginx", "version": "1.24.0-2ubuntu7.1", "origin": "ubuntu"}]},
            "nginx_exposure": {"tls": True}}}
        for when in (T0, T0 + 25 * HOUR):
            self.hub.writer.call(lambda c, w=when: hub_engine._advisory_eval(c, self.hub, self.hub.host(host["uuid"]), vulnerable, w, daily=False))
        self.assertTrue([o for o in self.hub.outbox() if o["severity"] == "HIGH"])

    def test_hostile_text_reaches_slack_and_ntfy_as_one_escaped_code_span(self):
        nasty = "evil `x` <!channel> <@U123> <https://x.example|click> \x1b[31m\nsecond line https://hooks.example.com/services/T/B/SECRET"
        payload = hub_alerts.build_payload(None, severity="HIGH", kind="x.y", summary=nasty, host={"name": "web1"},
                                           fields={"process": nasty, "k`ey": nasty})
        for channel in ("webhook", "ntfy"):
            req = hub_alerts.render(channel, payload)
            body = json.loads(req["body"].decode("ascii"))
            text = body["text"] if channel == "webhook" else body["message"]
            for bad in ("\x1b", "SECRET"):
                self.assertNotIn(bad, text, (channel, bad))
            if channel == "webhook":                                       # Slack: every < and > is escaped, so no mention or link forms
                for bad in ("<!channel>", "<@U123>", "<https"):
                    self.assertNotIn(bad, text, bad)
            self.assertNotIn("\n`", text.replace("\n", "\n").split("Kind:")[0].replace("[HIGH] `", ""))
            self.assertLessEqual(max(len(line) for line in text.splitlines()), 260)
            if channel == "ntfy":
                self.assertEqual(set(body), {"title", "message", "priority", "tags"})      # no Click, Actions, Attach, Email
                self.assertEqual(body["title"], "EDR HIGH")

    def test_the_worker_refuses_private_hosts_and_redirects_and_caps_retry_after(self):
        for url in ("https://127.0.0.1/x", "https://localhost/x", "https://169.254.169.254/x", "https://2130706433/x",
                    "https://[::1]/x", "https://10.0.0.5/x", "http://example.org/x", "https://user:pw@example.org/x"):
            ok, err, _ra = edr_hub_out.http_send("POST", url, {}, b"{}", edr_hub_out.make_context(None))
            self.assertFalse(ok, url)
            self.assertNotIn("pw", err)
        self.assertEqual(edr_hub_out._retry_after("999999"), 3600)
        self.assertIsNone(edr_hub_out._retry_after("Wed, 21 Oct 2026 07:28:00 GMT"))

    def test_no_secret_reaches_channels_json(self):
        paths = self.hub.paths
        os.makedirs(paths.out_state_dir, exist_ok=True)
        worker = edr_hub_out.Worker(paths)
        secrets = {"webhook_url": "https://hooks.example.com/services/T/B/TOPSECRET", "ntfy_topic": "TOPICSECRET", "ntfy_token": "TOKENSECRET"}
        worker.write_channels(secrets, {"ntfy_url": "https://ntfy.example.org", "webhook_ca_pem": None})
        with open(paths.channels) as f:
            text = f.read()
        for word in ("TOPSECRET", "TOPICSECRET", "TOKENSECRET"):
            self.assertNotIn(word, text)
        self.assertEqual(os.stat(paths.channels).st_mode & 0o777, 0o600)

    def test_a_critical_is_not_lost_to_a_high_of_the_same_kind_and_passes_the_storm_budget(self):
        host = self.hub.add_host("web1")
        for i in range(25):
            self.hub.writer.call(lambda c, n=i: hub_alerts.notify(c, self.hub, severity="HIGH", kind="k.%d" % n, summary="s", host=host, now=T0))
        self.hub.writer.call(lambda c: hub_alerts.notify(c, self.hub, severity="HIGH", kind="tetragon.web-exec", summary="h", host=host, now=T0))
        before = len(self.hub.outbox())
        self.hub.writer.call(lambda c: hub_alerts.notify(c, self.hub, severity="CRITICAL", kind="tetragon.web-exec", summary="c", host=host, now=T0 + 1))
        self.assertEqual(len(self.hub.outbox()), before + 1)

    def test_bad_advisory_overrides_are_skipped_and_named(self):
        paths = self.hub.paths
        os.makedirs(paths.advisories_d, exist_ok=True)
        with open(os.path.join(paths.advisories_d, "bad.json"), "w") as f:
            f.write("{not json")
        with open(os.path.join(paths.advisories_d, "huge.json"), "w") as f:
            f.write(" " * (hub_advisory.FILE_MAX_BYTES + 10))
        adv = hub_advisory.load(paths)
        self.assertTrue(any("bad.json skipped" in p for p in adv.problems))
        self.assertTrue(any("huge.json skipped" in p for p in adv.problems))
        self.assertTrue(adv.rows)                                          # the shipped table is still there

    def test_odd_versions_never_crash_or_turn_unknown_into_fixed(self):
        adv = hub_advisory.load(self.hub.paths)
        for version in ("", ":", "1:", "x" * 4000, "9" * 4000, "1.2.3-", "~~~", "1:1:1", "-1"):
            out = hub_advisory.evaluate_package(adv, origin="ubuntu", release="noble", package="nginx", version=version, now_ms=T0)
            self.assertTrue(all(v["status"] in ("vulnerable", "unknown", "fixed") for v in out))
            if version in ("", ":", "1:", "-1"):
                self.assertNotIn("fixed", [v["status"] for v in out], version)
        out = hub_advisory.evaluate_package(adv, origin="ondrej", release="noble", package="nginx", version="1.24.0", now_ms=T0)
        self.assertEqual([v["status"] for v in out], ["unknown"])
        self.assertEqual([v["status"] for v in hub_advisory.evaluate_package(adv, origin="ubuntu", release="noble", package="nginx",
                                                                             version="1.24.0-2ubuntu7.20", now_ms=T0)], ["fixed"])


if __name__ == "__main__":
    unittest.main()
