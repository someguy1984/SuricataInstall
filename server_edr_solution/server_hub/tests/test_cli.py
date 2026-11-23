"""The edr-hub command line against a live set of sockets and a real database file (PLAN sections 6 and 17)."""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_ctl_support as S  # noqa: E402

import hub_common  # noqa: E402
import hub_ctl  # noqa: E402
import hub_audit  # noqa: E402



def R(path):
    with open(path) as f:
        return f.read()


def W(path, data):
    with open(path, "w") as f:
        f.write(data)


def J(path):
    with open(path) as f:
        return json.load(f)


NASTY = "evil \x1b[31mred\x1b]8;;http://x\x07link\x1b]8;;\x07 ‮drow ​zw \x7f end"


class CliCase(S.HubTestCase):
    sockets = True

    def setUp(self):
        super().setUp()
        if self.sockets:
            self.socks = hub_ctl.Sockets(self.hub)
            self.socks.start()
            self.addCleanup(self.socks.stop)
        self.uuid = S.add_host(self.hub.db, "web-1")
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("EDR_HUB_") and k != "SUDO_USER" and k != "NO_COLOR"}
        self.env.update({"EDR_HUB_STATE_DIR": self.paths.state_dir, "EDR_HUB_RUN_DIR": self.paths.run_dir,
                         "EDR_HUB_ETC_DIR": self.paths.etc_dir, "EDR_HUB_BACKUP_DIR": self.paths.backup_dir,
                         "SUDO_USER": "j", "PYTHONDONTWRITEBYTECODE": "1"})

    def run_cli(self, *args, stdin=None, env=None):
        r = subprocess.run([sys.executable, "-I", S.EDR_HUB, *args], input=stdin, capture_output=True, text=True,
                           env=env or self.env, timeout=60)
        return r

    def ok(self, *args, **kw):
        r = self.run_cli(*args, **kw)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r.stdout

    def code(self, expected, *args, **kw):
        r = self.run_cli(*args, **kw)
        self.assertEqual(r.returncode, expected, r.stdout + r.stderr)
        return r

    def event(self, kind="ssh.fail", sev="HIGH", summary="s", count=1, received=None, host=None):
        self.hub.db.execute(
            "INSERT INTO events (host, event_id, received_at, ts, source, severity, hub_severity, kind, summary, details, epoch, seq, count) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (host or self.uuid, "%08x:%d" % (1, self.hub.db.execute("SELECT COALESCE(MAX(id),0)+1 FROM events").fetchone()[0]),
             received or hub_common.now_ms(), 1, "journal", sev, sev, kind, summary, json.dumps({"k": summary}), 1, 1, count))


class ReadCommandTests(CliCase):
    def test_host_list_show_and_json(self):
        S.add_host(self.hub.db, "gone", state="retired")
        out = self.ok("host", "list")
        self.assertIn("web-1", out)
        self.assertNotIn("gone", out)
        self.assertIn("gone", self.ok("host", "list", "--all"))
        rows = [json.loads(x) for x in self.ok("host", "list", "--json").splitlines()]
        self.assertEqual([r["name"] for r in rows], ["web-1"])
        shown = self.ok("host", "web-1", "show")
        self.assertIn(self.uuid, shown)
        self.assertIn("reported (untrusted)", shown)
        self.assertEqual(json.loads(self.ok("host", self.uuid, "show", "--json"))["name"], "web-1")
        self.code(3, "host", "nobody", "show")

    def test_host_list_notes_a_maintenance_window(self):
        self.hub.db.execute("INSERT INTO maintenance (host, until, set_by, set_at) VALUES (?,?,?,?)",
                            (self.uuid, hub_common.now_ms() + 600_000, "x", 1))
        self.assertIn("maintenance until", self.ok("host", "list"))

    def test_a_host_is_late_between_four_and_five_minutes_without_a_heartbeat(self):
        now = hub_common.now_ms()
        for seen, label in ((now - 3 * 60_000, "ok"), (now - 4 * 60_000 - 5000, "late"), (now - 6 * 60_000, "silent")):
            self.hub.db.execute("UPDATE hosts SET last_seen=? WHERE uuid=?", (seen, self.uuid))
            out = self.ok("host", "list")
            self.assertEqual("(late)" in out, label == "late", (label, out))
            self.assertEqual(json.loads(self.ok("host", "list", "--json").splitlines()[0])["late"], label == "late")

    def test_late_is_not_shown_in_a_maintenance_window_or_for_a_retired_host(self):
        now = hub_common.now_ms()
        self.hub.db.execute("UPDATE hosts SET last_seen=? WHERE uuid=?", (now - 270_000, self.uuid))
        self.hub.db.execute("INSERT INTO maintenance (host, until, set_by, set_at) VALUES (?,?,?,?)", (self.uuid, now + 600_000, "x", 1))
        self.assertNotIn("(late)", self.ok("host", "list"))
        self.hub.db.execute("DELETE FROM maintenance")
        self.assertIn("(late)", self.ok("host", "list"))
        self.hub.db.execute("UPDATE hosts SET state='retired' WHERE uuid=?", (self.uuid,))
        self.assertNotIn("(late)", self.ok("host", "list", "--all"))

    def test_host_show_cleans_every_field_including_the_applied_policy_revision(self):
        self.hub.db.execute("UPDATE hosts SET policy_rev_applied=?, policy_rev=?, state_since=? WHERE uuid=?",
                            ("abcd\x1b[31mred\x1b]8;;x\x07", "12\u202e34", hub_common.now_ms(), self.uuid))
        out = self.ok("host", "web-1", "show")
        for bad in ("\x1b", "\x07", "\u202e"):
            self.assertNotIn(bad, out)
        self.assertIn("\\u001b", out)

    def test_events_filters(self):
        h2 = S.add_host(self.hub.db, "web-2")
        now = hub_common.now_ms()
        self.event(kind="a.low", sev="LOW", summary="lowone")
        self.event(kind="b.high", sev="HIGH", summary="highone")
        self.event(kind="c.crit", sev="CRITICAL", summary="critone", host=h2)
        self.event(kind="d.old", sev="HIGH", summary="oldone", received=now - 3 * 3600_000)
        out = self.ok("events")
        for word in ("lowone", "highone", "critone", "oldone"):
            self.assertIn(word, out)
        self.assertNotIn("oldone", self.ok("events", "--since", "1h"))
        hi = self.ok("events", "--min-sev", "high")
        self.assertIn("highone", hi)
        self.assertIn("critone", hi)
        self.assertNotIn("lowone", hi)
        only = self.ok("events", "--host", "web-2")
        self.assertIn("critone", only)
        self.assertNotIn("highone", only)
        self.assertEqual(len(self.ok("events", "--limit", "2").splitlines()), 2)
        self.code(3, "events", "--min-sev", "loud")
        self.code(3, "events", "--host", "ghost")
        self.code(3, "events", "--since", "yesterday")

    def test_events_json_keeps_ascii_and_parsed_details(self):
        self.event(summary=NASTY)
        raw = self.ok("events", "--json")
        raw.encode("ascii")                                        # ensure_ascii: nothing outside ASCII
        self.assertNotIn("\x1b", raw)
        d = json.loads(raw.splitlines()[0])
        self.assertEqual(d["summary"], NASTY)
        self.assertEqual(d["details"], {"k": NASTY})
        self.assertEqual(d["host_name"], "web-1")

    def test_text_output_is_terminal_safe(self):
        self.event(summary=NASTY)
        S.add_host(self.hub.db, "x")
        self.hub.db.execute("UPDATE hosts SET reported_name=?, os=? WHERE name='web-1'", (NASTY, NASTY))
        now = hub_common.now_ms()
        self.hub.db.execute("INSERT INTO incidents (host, chain, opened, updated, severity, title, kinds) VALUES (?,?,?,?,?,?,?)",
                            (self.uuid, "c", now, now, "HIGH", NASTY, json.dumps([NASTY])))
        hub_audit.append(self.hub.db, actor_kind="cli", actor_detail=NASTY, action="a", target=NASTY)
        for args in (("events",), ("host", "web-1", "show"), ("host", "list"), ("incidents",), ("incident", "1"),
                     ("audit",), ("never-ban", "list")):
            out = self.ok(*args)
            for bad in ("\x1b", "\x07", "‮", "​", "\x7f"):
                self.assertNotIn(bad, out, args)
        self.assertIn("\\u001b", self.ok("events"))

    def test_no_colour_when_stdout_is_not_a_terminal(self):
        self.event(sev="CRITICAL")
        self.assertNotIn("\x1b[", self.ok("events"))

    def test_incidents_and_incident_detail(self):
        now = hub_common.now_ms()
        self.event(summary="first")
        self.event(summary="second")
        self.hub.db.execute("INSERT INTO incidents (host, chain, opened, updated, severity, title, kinds, signals) VALUES (?,?,?,?,?,?,?,?)",
                            (self.uuid, "ssh-brute", now, now, "HIGH", "SSH brute force", '["ssh.fail"]', 2))
        self.hub.db.execute("INSERT INTO incidents (host, chain, opened, updated, severity, title, state) VALUES (?,?,?,?,?,?,?)",
                            (self.uuid, "old", now - 5, now - 5, "LOW", "Closed one", "resolved"))
        self.hub.db.execute("INSERT INTO incident_events (incident_id, event_rowid) VALUES (1,1),(1,2)")
        out = self.ok("incidents")
        self.assertIn("SSH brute force", out)
        self.assertIn("Closed one", out)
        self.assertNotIn("Closed one", self.ok("incidents", "--open"))
        detail = self.ok("incident", "1")
        self.assertIn("first", detail)
        self.assertIn("second", detail)
        self.assertIn("edr-hub resolve 1", detail)
        d = json.loads(self.ok("incident", "1", "--json"))
        self.assertEqual(len(d["events"]), 2)
        self.code(3, "incident", "99")

    def test_token_list_and_audit(self):
        self.ok("token", "create", "--name", "web-9")
        out = self.ok("token", "list")
        self.assertIn("web-9", out)
        self.assertIn("pending", out)
        self.assertNotIn("SECRETVALUE", out)
        self.assertEqual(json.loads(self.ok("token", "list", "--json").splitlines()[0])["state"], "pending")
        audit = self.ok("audit")
        self.assertIn("token.create", audit)
        self.assertNotIn("SECRETVALUE", audit)
        self.assertEqual(json.loads(self.ok("audit", "--json").splitlines()[0])["action"], "token.create")
        self.assertEqual(self.ok("audit", "--since", "1s").strip() in ("", audit.strip()), True)

    def test_settings_get_masks_secrets(self):
        masked = hub_common.mask_secret("https://hooks.example.com/services/XXXXYYYY")
        self.hub.update_settings(dict(self.hub.settings, secrets_set={"webhook_url": masked}))
        out = self.ok("settings", "get")
        self.assertIn("webhook_url = %s" % masked, out)
        self.assertIn("deadman_url = (not set)", out)
        self.assertIn("port = 8443  (installer-owned)", out)
        self.assertNotIn("XXXXYYYY/", out)
        self.assertEqual(self.ok("settings", "get", "retention_days").strip(), "retention_days = 30")
        self.code(3, "settings", "get", "nonsense")

    def test_status_reports_and_exit_codes(self):
        r = self.code(1, "status")                                  # no channel, no backup: warnings only
        self.assertIn("hub:        running", r.stdout)
        self.assertIn("hosts:", r.stdout)
        self.assertIn("backup:     never", r.stdout)
        self.assertIn("edr-hub ui-login", r.stdout)
        self.assertIn("NONE", r.stdout)
        # healthy: a channel, a fresh backup marker
        self.hub.update_settings(dict(self.hub.settings, secrets_set={"webhook_url": "h …abcd"}))
        with open(self.paths.last_backup, "w") as f:
            f.write(str(hub_common.now_ms()))
        self.code(0, "status")
        # an orphan or a stale backup is a warning
        S.add_host(self.hub.db, "orph", state="orphan")
        self.assertIn("orphan", self.code(1, "status").stdout)

    def test_status_with_the_hub_down_exits_2_and_still_prints(self):
        self.socks.stop()
        r = self.code(2, "status")
        self.assertIn("NOT RUNNING", r.stdout)
        self.assertIn("hosts:", r.stdout)


class HealthTests(CliCase):
    def set_meta(self, **kw):
        for k, v in kw.items():
            self.hub.db.execute("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                                (k, str(v)))

    def fresh(self, **kw):
        now = hub_common.now_ms()
        values = {"writer_tick": now - 5000, "engine_tick": now - 5000, "engine_cursor": 0}
        values.update(kw)
        self.set_meta(**values)

    def test_healthy_when_both_ticks_are_recent_and_the_engine_is_current(self):
        self.fresh()
        self.assertEqual(self.ok("health").strip(), "healthy")

    def test_unhealthy_when_the_writer_is_silent_for_over_30_seconds(self):
        self.fresh(writer_tick=hub_common.now_ms() - 31_000)
        self.assertIn("writer", self.code(2, "health").stdout)
        self.set_meta(writer_tick=hub_common.now_ms() - 29_000)
        self.code(0, "health")

    def test_unhealthy_when_there_is_no_writer_tick(self):
        self.set_meta(engine_tick=hub_common.now_ms())
        self.assertIn("writer has never reported", self.code(2, "health").stdout)

    def test_the_engine_tick_must_be_within_60_seconds(self):
        self.fresh(engine_tick=hub_common.now_ms() - 61_000)
        self.assertIn("engine has not ticked", self.code(2, "health").stdout)
        self.set_meta(engine_tick=hub_common.now_ms() - 59_000)
        self.code(0, "health")

    def test_unhealthy_when_the_engine_has_never_ticked(self):
        self.set_meta(writer_tick=hub_common.now_ms(), engine_cursor=0)
        self.assertIn("engine has never ticked", self.code(2, "health").stdout)

    def test_the_engine_cursor_must_be_current(self):
        self.fresh()
        self.event(received=hub_common.now_ms() - 10_000)           # 10 s behind: a normal tick gap
        self.code(0, "health")
        self.event(received=hub_common.now_ms() - 120_000)
        self.hub.db.execute("UPDATE events SET received_at=? WHERE id=1", (hub_common.now_ms() - 120_000,))
        r = self.code(2, "health")
        self.assertIn("engine cursor", r.stdout)
        self.set_meta(engine_cursor=2)
        self.code(0, "health")

    def test_an_unprocessed_event_exactly_at_the_edge(self):
        self.fresh()
        self.event(received=hub_common.now_ms() - 59_000)
        self.code(0, "health")
        self.hub.db.execute("UPDATE events SET received_at=? WHERE id=1", (hub_common.now_ms() - 61_000,))
        self.code(2, "health")

    def test_all_three_problems_are_reported_together(self):
        now = hub_common.now_ms()
        self.set_meta(writer_tick=now - 90_000, engine_tick=now - 90_000, engine_cursor=0)
        self.event(received=now - 120_000)
        self.hub.db.execute("UPDATE events SET received_at=? WHERE id=1", (now - 120_000,))
        out = self.code(2, "health").stdout
        for word in ("writer", "engine has not ticked", "engine cursor"):
            self.assertIn(word, out)

    def test_unhealthy_when_the_database_cannot_be_opened(self):
        os.unlink(self.paths.db)
        self.code(2, "health")


class WriteCommandTests(CliCase):
    def test_host_actions_go_through_the_socket_with_the_callers_login_uid(self):
        self.ok("host", "web-1", "maintenance", "--for", "30m")
        row = self.rows("SELECT * FROM maintenance")[0]
        self.assertIn("sudo=j", row["set_by"])
        self.assertRegex(row["set_by"], r"loginuid=(\d+|unknown)")
        self.assertIn("ended", self.ok("host", "web-1", "maintenance", "--end"))
        self.ok("host", "web-1", "revoke")
        self.assertEqual(self.rows("SELECT state FROM hosts")[0]["state"], "revoked")
        r = self.code(3, "host", "web-1", "retire")
        self.assertIn("transition not allowed", r.stderr)
        self.code(3, "host", "web-1", "maintenance", "--for", "5h")
        self.code(64, "host", "web-1", "maintenance")
        self.code(64, "host", "web-1")
        self.code(64, "host")
        self.code(64, "host", "web-1", "explode")

    def test_token_create_prints_the_install_line_once_per_token(self):
        out = self.ok("token", "create", "--names", "web-5,web-6", "--ttl", "4h", "--source", "198.51.100.0/24")
        self.assertEqual(out.count("Token for"), 2)
        self.assertIn("tok1.SECRETVALUE1XYZ.", out)
        self.assertIn("sudo ./install.sh --hub 203.0.113.10:8443 --token-file FILE", out)
        self.assertIn("--ttl 1h", out)
        j = json.loads(self.ok("token", "create", "--name", "web-7", "--json"))
        self.assertEqual(j["tokens"][0]["label"], "web-7")
        self.code(3, "token", "create", "--name", "Bad_Name")
        self.code(3, "token", "create", "--name", "x", "--ttl", "48h")
        self.code(64, "token", "create")
        self.code(64, "token", "create", "--name", "a", "--names", "b")
        self.ok("token", "revoke", "tok1")
        self.code(3, "token", "revoke", "tok1")

    def test_never_ban(self):
        self.ok("never-ban", "add", "198.51.100.0/24", "--reason", "monitoring")
        self.assertIn("monitoring", self.ok("never-ban", "list"))
        self.code(3, "never-ban", "add", "10.0.0.0/8")
        self.code(3, "never-ban", "add", "198.51.100.0/25")
        self.code(64, "never-ban", "add")
        self.ok("never-ban", "remove", "198.51.100.0/24")
        self.code(3, "never-ban", "remove", "198.51.100.0/24")

    def test_plain_setting_over_the_socket_and_value_from_stdin(self):
        self.ok("settings", "set", "retention_days", "60")
        self.assertEqual(hub_common.load_settings(self.paths)["retention_days"], 60)
        self.ok("settings", "set", "digest_time", "-", stdin="08:30\n")
        self.assertEqual(hub_common.load_settings(self.paths)["digest_time"], "08:30")
        self.code(3, "settings", "set", "retention_days", "0")
        self.code(3, "settings", "set", "port", "9")
        self.code(64, "settings", "set", "retention_days")

    def test_secret_from_stdin_goes_to_secrets_json_and_the_hub_hears_only_that_it_changed(self):
        url = "https://hooks.example.com/services/T0/B0/TOPSECRETTOKEN"
        out = self.ok("settings", "set", "webhook_url", "-", stdin=url + "\n")
        self.assertNotIn("TOPSECRETTOKEN", out)
        self.assertEqual(J(self.paths.secrets)["webhook_url"], url)
        self.assertEqual(os.stat(self.paths.secrets).st_mode & 0o777, 0o600)
        masked = hub_common.mask_secret(url)
        self.assertEqual(hub_common.load_settings(self.paths)["secrets_set"], {"webhook_url": masked})
        self.assertEqual(self.rows("SELECT old, new FROM settings_history")[0], {"old": "changed", "new": "changed"})
        everything = json.dumps(self.rows("SELECT * FROM audit")) + json.dumps(self.alerts.notices) + \
            json.dumps(self.rows("SELECT * FROM settings_history")) + R(self.paths.settings)
        self.assertNotIn("TOPSECRETTOKEN", everything)
        self.assertNotIn("TOPSECRETTOKEN", R(self.paths.pending_audit))
        lines = [json.loads(x) for x in R(self.paths.pending_audit).splitlines()]
        self.assertEqual([(x["op"], x["outcome"]) for x in lines], [("secrets.write", "started"), ("secrets.write", "ok")])
        # an empty value switches the channel off and removes the key
        self.ok("settings", "set", "webhook_url", "-", stdin="\n")
        self.assertEqual(J(self.paths.secrets), {})
        self.assertEqual(hub_common.load_settings(self.paths)["secrets_set"], {})

    def test_the_old_channel_is_told_before_the_secret_is_replaced(self):
        self.hub.update_settings(dict(self.hub.settings, secrets_set={"webhook_url": "old …1234"}))
        self.ok("settings", "set", "webhook_url", "-", stdin="https://hooks.example.com/new\n")
        self.assertEqual([n[0] for n in self.alerts.notices], ["secret about to change", "secret changed"])

    def test_a_secret_is_never_taken_from_argv(self):
        r = self.code(3, "settings", "set", "webhook_url", "https://hooks.example.com/x")
        self.assertNotIn("hooks.example.com", r.stdout + r.stderr.replace("settings set webhook_url", ""))
        self.assertFalse(os.path.exists(self.paths.secrets))
        self.assertEqual(self.rows("SELECT * FROM settings_history"), [])

    def test_secret_values_are_checked_and_a_down_hub_changes_nothing(self):
        self.code(3, "settings", "set", "webhook_url", "-", stdin="http://not-https.example\n")
        self.code(3, "settings", "set", "ntfy_topic", "-", stdin="has space\n")
        self.assertFalse(os.path.exists(self.paths.secrets))
        self.socks.stop()
        self.code(2, "settings", "set", "webhook_url", "-", stdin="https://hooks.example.com/x\n")
        self.assertFalse(os.path.exists(self.paths.secrets))

    def test_alert_test_with_no_channel_exits_1(self):
        r = self.code(1, "alert", "test")
        self.assertIn("no channel is enabled", r.stdout)
        self.code(64, "alert", "test", "--bogus")
        self.code(3, "alert", "test", "--channel", "pigeon")

    def test_alert_test_reports_per_channel(self):
        self.hub.update_settings(dict(self.hub.settings, secrets_set={"webhook_url": "h …abcd"}))

        def deliver(*_a):
            self.hub.db.execute("UPDATE outbox SET state='sent'")
        original = self.alerts.enqueue_test

        def enqueue(conn, hub, channel):
            ids = original(conn, hub, channel)
            conn.execute("UPDATE outbox SET state='sent'")
            return ids
        self.alerts.enqueue_test = enqueue
        self.assertIn("webhook: sent", self.code(0, "alert", "test").stdout)

    def test_ui_login_prints_a_one_time_url(self):
        W(self.paths.ui_url, "http://127.0.0.1:8450/\n")
        out = self.ok("ui-login")
        line = out.splitlines()[0]
        self.assertTrue(line.startswith("http://127.0.0.1:8450/#code="), line)
        code = line.split("#code=")[1]
        self.assertGreaterEqual(len(code), 20)
        self.assertEqual(len(self.rows("SELECT * FROM login_codes")), 1)

    def test_ui_login_without_the_url_file_falls_back_to_the_loopback_port(self):
        self.assertIn("http://127.0.0.1:8450/#code=", self.ok("ui-login"))

    def test_resolve_ack_reissue_agent_hash_audit_verify(self):
        now = hub_common.now_ms()
        self.hub.db.execute("INSERT INTO incidents (host, chain, opened, updated, severity) VALUES (?,?,?,?,?)",
                            (self.uuid, "c", now, now, "HIGH"))
        self.ok("resolve", "1")
        self.code(3, "resolve", "1")
        self.assertIn("P3", self.code(3, "ack", "1").stderr)
        self.assertIn("reissued", self.ok("reissue-cert"))
        self.assertIn("added", self.ok("agent-hash", "add", "ab" * 32, "--note", "patched"))
        self.code(3, "agent-hash", "add", "nothex")
        self.assertIn("intact", self.ok("audit", "verify"))
        self.hub.db.execute("UPDATE audit SET target='tampered' WHERE id=1")
        r = self.code(2, "audit", "verify")
        self.assertIn("BROKEN", r.stdout)

    def test_hub_down_is_exit_2(self):
        self.socks.stop()
        r = self.code(2, "token", "create", "--name", "x")
        self.assertIn("not running", r.stderr)


class UsageTests(CliCase):
    sockets = False

    def test_usage_errors_exit_64(self):
        self.code(64)
        self.code(64, "frobnicate")
        self.code(64, "events", "--nonsense")
        self.code(64, "events", "--limit", "many")
        self.code(64, "settings")
        self.code(64, "token")
        self.code(64, "audit", "--bogus")

    def test_help_and_version(self):
        self.assertIn("usage: edr-hub", self.ok("--help"))
        self.assertIn(hub_common.VERSION, self.ok("--version"))

    def test_root_checks_apply_only_to_the_installed_paths(self):
        env = {k: v for k, v in self.env.items() if not k.startswith("EDR_HUB_")}
        r = subprocess.run([sys.executable, "-I", S.EDR_HUB, "reissue-cert"], capture_output=True, text=True, env=env, timeout=30)
        if os.geteuid() != 0:
            self.assertEqual(r.returncode, 3)
            self.assertIn("root", r.stderr)
        else:
            self.assertIn(r.returncode, (2, 3))                     # root, no hub at the real path: unreachable
        # With the dev paths set, no root is needed (this test itself runs as whoever runs the suite).
        self.assertEqual(self.run_cli("reissue-cert").returncode, 2)


if __name__ == "__main__":
    unittest.main()
