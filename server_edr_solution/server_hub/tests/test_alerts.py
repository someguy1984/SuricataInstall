"""hub_alerts: payloads, dedup, storm control, outbox rows, escaping per channel, the sanitiser on hostile fields."""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "hub"))

import hub_alerts    # noqa: E402
from test_engine_support import HubTestCase, T0, MIN, HOUR   # noqa: E402

HOSTILE = "\x1b]8;;http://evil.example/\x07click\x1b]8;;\x07 ‮drowssap <!channel> <@U123> <https://evil.example|safe> & `rm -rf` @here \x00\x9b2J"


class NotifyTests(HubTestCase):
    def setUp(self):
        super().setUp()
        self.host = self.hub.add_host("web1")

    def notify(self, **kw):
        args = dict(severity="HIGH", kind="tetragon.env-read", summary="env read", host=self.host, now=T0)
        args.update(kw)
        return self.hub.writer.call(lambda c: hub_alerts.notify(c, self.hub, **args))

    def test_payload_shape_and_commands(self):
        self.assertEqual(self.notify(incident_id=41, fields={"source ip": "198.51.100.7"}), 1)
        row = self.hub.outbox()[0]
        self.assertEqual((row["channel"], row["severity"], row["state"]), ("webhook", "HIGH", "pending"))
        p = row["payload"]
        for key in ("title", "severity", "host", "host_ip", "kind", "meaning", "next_step", "incident_id", "commands", "fields", "ts", "test"):
            self.assertIn(key, p)
        self.assertEqual((p["host"], p["host_ip"], p["incident_id"], p["test"]), ("web1", "203.0.113.9", 41, False))
        self.assertIn("rotate", p["next_step"])
        self.assertIn("edr-hub incident 41", p["commands"])
        self.assertTrue(any(c.startswith("edr-hub events --host web1") for c in p["commands"]))
        self.assertEqual(p["fields"], {"source ip": "198.51.100.7"})

    def test_minimum_severity(self):
        self.assertEqual(self.notify(severity="MEDIUM"), 0)
        self.assertEqual(self.notify(severity="LOW", kind="a.b"), 0)
        self.assertEqual(self.notify(severity="INFO", kind="a.c", always=True), 1)
        self.hub.settings["alert_min_severity"] = "CRITICAL"
        self.assertEqual(self.notify(severity="HIGH", kind="a.d"), 0)
        self.assertEqual(self.notify(severity="CRITICAL", kind="a.e"), 1)
        self.hub.settings["alert_min_severity"] = "MEDIUM"
        self.assertEqual(self.notify(severity="MEDIUM", kind="a.f"), 1)

    def test_one_row_per_enabled_channel(self):
        self.hub.settings["ntfy_url"] = "https://ntfy.example.com"
        self.hub.settings["secrets_set"]["ntfy_topic"] = "ntfy.example.com ...zzzz"
        self.assertEqual(self.notify(), 2)
        self.assertEqual(sorted(o["channel"] for o in self.hub.outbox()), ["ntfy", "webhook"])

    def test_no_channel_writes_one_dead_row(self):
        self.hub.settings["secrets_set"] = {}
        self.assertEqual(self.notify(), 1)
        row = self.hub.outbox()[0]
        self.assertEqual((row["channel"], row["state"]), ("none", "dead"))

    def test_dedup_per_host_and_kind(self):
        self.assertEqual(self.notify(now=T0), 1)
        self.assertEqual(self.notify(now=T0 + 10 * MIN), 0)                      # same host and kind within 30 minutes
        self.assertEqual(self.notify(now=T0 + 10 * MIN, kind="tamper.x"), 1)        # another kind
        other = self.hub.add_host("web2")
        self.assertEqual(self.notify(now=T0 + 10 * MIN, host=other), 1)             # another host
        self.assertEqual(self.notify(now=T0 + 31 * MIN), 1)                      # window over
        row = self.hub.q("SELECT suppressed FROM alert_state WHERE key=?", (self.host["uuid"] + "|tetragon.env-read",))[0]
        self.assertEqual(row[0], 1)

    def test_severity_increase_bypasses_dedup(self):
        self.assertEqual(self.notify(severity="HIGH"), 1)
        self.assertEqual(self.notify(severity="CRITICAL", now=T0 + MIN), 1)
        self.assertEqual(self.notify(severity="HIGH", now=T0 + 2 * MIN), 0)

    def test_critical_is_limited_to_one_per_host_kind_per_five_minutes(self):
        self.assertEqual(self.notify(severity="CRITICAL"), 1)
        self.assertEqual(self.notify(severity="CRITICAL", now=T0 + 4 * MIN), 0)
        self.assertEqual(self.notify(severity="CRITICAL", now=T0 + 6 * MIN), 1)

    def test_always_bypasses_minimum_dedup_and_storm(self):
        for i in range(3):
            self.assertEqual(self.notify(severity="LOW", always=True, kind="hub.admin", now=T0 + i), 1)
        self.assertEqual(len(self.hub.outbox()), 3)

    def test_storm_control_twenty_per_ten_minutes_then_one_summary(self):
        sent = 0
        for i in range(30):
            sent += self.notify(kind="k.%d" % i, now=T0 + i * 1000)
        self.assertEqual(sent, 20)
        self.assertEqual(self.notify(severity="CRITICAL", kind="k.crit", now=T0 + 40 * 1000), 1)       # CRITICAL is exempt
        self.assertEqual(self.notify(kind="k.late", now=T0 + 5 * MIN), 0)
        before = len(self.hub.outbox())
        # the window is over: the next message first sends one "N alerts suppressed" summary
        n = self.notify(kind="k.after", now=T0 + 11 * MIN)
        self.assertEqual(n, 2)
        titles = self.hub.titles()
        self.assertEqual(len(titles), before + 2)
        self.assertIn("11 alerts suppressed by storm control", titles)
        self.assertEqual(self.hub.q("SELECT suppressed FROM alert_state WHERE key='storm'")[0][0], 0)

    def test_flush_storm_from_the_tick(self):
        for i in range(25):
            self.notify(kind="k.%d" % i, now=T0 + i)
        n = self.hub.writer.call(lambda c: hub_alerts.flush_storm(c, self.hub, T0 + 11 * MIN))
        self.assertEqual(n, 1)
        self.assertTrue(any("alerts suppressed" in t for t in self.hub.titles()))
        self.assertEqual(self.hub.writer.call(lambda c: hub_alerts.flush_storm(c, self.hub, T0 + 12 * MIN)), 0)

    def test_maintenance_line_only_for_operator_windows(self):
        self.hub.writer.call(lambda c: c.execute("INSERT INTO maintenance (host, until, set_by, set_at) VALUES (?,?,?,?)",
                                                 (self.host["uuid"], T0 + HOUR, "uid=1000 ops", T0)))
        self.notify()
        self.assertIn("set on the hub by uid=1000 ops until", self.hub.outbox()[-1]["payload"]["fields"]["maintenance window"])
        self.hub.writer.call(lambda c: c.execute("UPDATE maintenance SET until=?", (T0 - 1,)))
        self.notify(kind="x.y")
        self.assertNotIn("maintenance window", self.hub.outbox()[-1]["payload"]["fields"])

    def test_hostile_fields_are_sanitised_in_the_payload(self):
        evil_host = self.hub.add_host("web9", reported_name=HOSTILE)
        self.notify(summary=HOSTILE, fields={HOSTILE: HOSTILE}, host=evil_host, kind="x.hostile")
        p = self.hub.outbox()[-1]["payload"]
        blob = json.dumps(p, ensure_ascii=False)
        for bad in ("\x1b", "\x07", "\x00", "\x9b", "‮"):
            self.assertNotIn(bad, blob)
        self.assertLessEqual(len(p["title"]), 200)
        for k, v in p["fields"].items():
            self.assertLessEqual(len(k), 40)
            self.assertLessEqual(len(v), 200)

    def test_secrets_are_scrubbed(self):
        token = "tkn12345.%s.%s" % ("A" * 22, "ab" * 32)
        self.notify(summary="made token %s for host" % token, fields={"url": "https://hooks.example.com/services/T000/B000/SECRETSECRET"}, kind="x.s")
        blob = json.dumps(self.hub.outbox()[-1]["payload"])
        self.assertNotIn("A" * 22, blob)
        self.assertNotIn("SECRETSECRET", blob)
        self.assertIn("hooks.example.com", blob)

    def test_admin_notice(self):
        self.hub.settings["alert_min_severity"] = "CRITICAL"
        n = self.hub.writer.call(lambda c: hub_alerts.admin_notice(c, self.hub, "token created", "name web3, 15m", "uid=0 loginuid=1000 sudo=j", now=T0))
        self.assertEqual(n, 1)
        row = self.hub.outbox()[0]
        self.assertEqual(row["severity"], "HIGH")
        self.assertEqual(row["payload"]["kind"], "hub.admin")
        self.assertIn("token created", row["payload"]["title"])
        self.assertEqual(row["payload"]["fields"]["by"], "uid=0 loginuid=1000 sudo=j")
        again = self.hub.writer.call(lambda c: hub_alerts.admin_notice(c, self.hub, "token created", "name web3, 15m", "x", now=T0 + 1))
        self.assertEqual(again, 1)                       # never deduplicated


class TestAlertTests(HubTestCase):
    def test_enqueue_test(self):
        ids = self.hub.writer.call(lambda c: hub_alerts.enqueue_test(c, self.hub, None, now=T0))
        self.assertEqual(len(ids), 1)
        row = self.hub.outbox()[0]
        self.assertEqual((row["channel"], row["payload"]["test"], row["id"]), ("webhook", True, ids[0]))
        self.hub.settings["ntfy_url"] = "https://ntfy.example.com"
        self.hub.settings["secrets_set"]["ntfy_topic"] = "x"
        ids = self.hub.writer.call(lambda c: hub_alerts.enqueue_test(c, self.hub, "ntfy", now=T0))
        self.assertEqual([o["channel"] for o in self.hub.outbox()][-1], "ntfy")
        with self.assertRaises(ValueError):
            self.hub.writer.call(lambda c: hub_alerts.enqueue_test(c, self.hub, "discord"))
        with self.assertRaises(ValueError):
            self.hub.writer.call(lambda c: hub_alerts.enqueue_test(c, self.hub, "carrier-pigeon"))

    def test_enqueue_test_with_no_channel(self):
        self.hub.settings["secrets_set"] = {}
        ids = self.hub.writer.call(lambda c: hub_alerts.enqueue_test(c, self.hub, None))
        self.assertEqual(self.hub.outbox()[0]["state"], "dead")
        self.assertEqual(len(ids), 1)


class ChannelHealthTests(HubTestCase):
    def add(self, state, attempts, created, err=""):
        self.hub.writer.call(lambda c: c.execute(
            "INSERT INTO outbox (created, channel, severity, payload, attempts, next_try, state, last_error) VALUES (?,?,?,?,?,?,?,?)",
            (created, "webhook", "HIGH", "{}", attempts, created, state, err)))

    def health(self, now):
        return self.hub.writer.call(lambda c: hub_alerts.channel_health(c, now))

    def test_a_failing_channel_is_flagged_and_clears_after_a_success(self):
        self.assertEqual(self.health(T0), [])
        self.add("sent", 1, T0)
        self.assertFalse(self.health(T0 + MIN)[0]["failing"])
        self.add("failed", 2, T0 + MIN, "HTTP 500")
        h = self.health(T0 + 2 * MIN)[0]
        self.assertTrue(h["failing"])
        self.assertEqual((h["bad_rows"], h["last_error"], h["over_1h"]), (1, "HTTP 500", False))
        self.assertTrue(self.health(T0 + 3 * HOUR)[0]["over_1h"])
        self.add("sent", 1, T0 + 4 * HOUR)
        self.assertFalse(self.health(T0 + 5 * HOUR)[0]["failing"])

    def test_dead_rows_count(self):
        self.add("dead", 6, T0, "timeout")
        self.assertTrue(self.health(T0)[0]["failing"])


class RenderTests(unittest.TestCase):
    PAYLOAD = {"title": HOSTILE, "severity": "CRITICAL", "host": "web1", "host_ip": "203.0.113.9", "kind": "tetragon.nginx-exec",
               "meaning": "m", "next_step": "n", "incident_id": 41, "commands": ["edr-hub incident 41"],
               "fields": {"process": HOSTILE, "source ip": "198.51.100.7"}, "ts": T0, "test": False}

    def test_webhook_escapes_and_does_not_unfurl(self):
        req = hub_alerts.render("webhook", self.PAYLOAD)
        self.assertEqual(req["url_key"], "webhook_url")
        doc = json.loads(req["body"])
        self.assertIs(doc["unfurl_links"], False)
        self.assertIs(doc["unfurl_media"], False)
        self.assertNotIn("link_names", doc)
        text = doc["text"]
        self.assertNotIn("<", text)
        self.assertNotIn(">", text)
        self.assertIn("&lt;!channel&gt;", text)
        self.assertIn("&lt;@U123&gt;", text)
        self.assertIn("&amp;", text)
        self.assertNotIn("&amp;lt;", text)                       # escaped once
        for bad in ("\x1b", "\x07", "\x00", "‮"):
            self.assertNotIn(bad, text)
        self.assertNotIn("`rm -rf`", text)                       # the backticks inside a value became quotes
        self.assertIn("'rm -rf'", text)
        self.assertIn("`web1`", text)
        self.assertEqual(req["headers"], {"Content-Type": "application/json"})
        self.assertIsInstance(req["body"], bytes)

    def test_every_attacker_value_is_a_code_span_of_at_most_200_characters(self):
        payload = dict(self.PAYLOAD, title="x" * 5000)
        text = json.loads(hub_alerts.render("webhook", payload)["body"])["text"]
        first = text.split("\n")[0]
        self.assertTrue(first.startswith("[CRITICAL] `"))
        self.assertLessEqual(len(first), len("[CRITICAL] ``") + 200)

    def test_ntfy_json_publish_with_fixed_title(self):
        req = hub_alerts.render("ntfy", self.PAYLOAD)
        self.assertEqual(req["url_key"], "ntfy_url")
        doc = json.loads(req["body"])
        self.assertEqual(doc["title"], "EDR CRITICAL")
        self.assertEqual(doc["priority"], 5)
        self.assertNotIn("topic", doc)                             # a secret: the worker adds it
        for forbidden in ("click", "actions", "Click", "Actions", "attach", "icon", "email", "call"):
            self.assertNotIn(forbidden, doc)
        self.assertNotIn("\x1b", doc["message"])
        self.assertNotIn("‮", doc["message"])
        for k in req["headers"]:
            self.assertNotIn(k.lower(), ("click", "actions", "authorization"))
        evil = dict(self.PAYLOAD, severity="CRITICAL\r\nX-Evil: 1")
        self.assertEqual(json.loads(hub_alerts.render("ntfy", evil)["body"])["title"], "EDR HIGH")

    def test_test_marker(self):
        t = dict(self.PAYLOAD, test=True)
        self.assertEqual(json.loads(hub_alerts.render("ntfy", t)["body"])["title"], "EDR TEST")
        self.assertIn("TEST", json.loads(hub_alerts.render("webhook", t)["body"])["text"])

    def test_digest_lines(self):
        p = dict(self.PAYLOAD, lines=["Open incidents: 0", "line <b>2</b>"])
        text = json.loads(hub_alerts.render("webhook", p)["body"])["text"]
        self.assertIn("Open incidents: 0", text)
        self.assertIn("&lt;b&gt;2&lt;/b&gt;", text)

    def test_unsupported_channels_and_odd_payloads(self):
        for ch in ("discord", "email", "nope", None):
            with self.assertRaises(ValueError):
                hub_alerts.render(ch, self.PAYLOAD)
        for odd in (None, {}, "x", {"fields": "x", "commands": 5, "severity": 7}):
            self.assertIsInstance(hub_alerts.render("webhook", odd)["body"], bytes)
            self.assertIsInstance(hub_alerts.render("ntfy", odd)["body"], bytes)


if __name__ == "__main__":
    unittest.main()
