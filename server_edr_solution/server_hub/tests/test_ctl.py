"""The three sockets and every verb on them, over real AF_UNIX sockets (PLAN sections 5, 6; section 12 L0)."""

import hashlib
import json
import os
import socket
import stat
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_ctl_support as S  # noqa: E402

import hub_common  # noqa: E402
import hub_ctl  # noqa: E402

UI_ACTOR = {"session": "0a1b2c3d", "addr": "127.0.0.1"}


class SocketCase(S.HubTestCase):
    def setUp(self):
        super().setUp()
        self.socks = hub_ctl.Sockets(self.hub)
        self.socks.start()
        self.addCleanup(self.socks.stop)

    def ctl(self, cmd, args=None):
        return S.ctl(self.paths, cmd, args)

    def flush_folds(self):
        """Folded refusals are written when their minute is over: make it over."""
        import hub_audit
        self.hub.writer.call(lambda conn: hub_audit.flush_folds(conn, hub_common.now_ms() + 120000))

    def ui(self, cmd, args=None, actor=UI_ACTOR):
        return S.send(self.paths.ui_sock, {"cmd": cmd, "args": args or {}, "actor": actor})

    def out(self, cmd, args=None):
        return S.send(self.paths.out_sock, {"cmd": cmd, "args": args or {}})

    def ok(self, reply):
        self.assertTrue(reply and reply["ok"], reply)
        return reply["result"]

    def bad(self, reply, code, exit_):
        self.assertTrue(reply and not reply["ok"], reply)
        self.assertEqual((reply["code"], reply["exit"]), (code, exit_), reply)
        return reply


class TransportTests(SocketCase):
    def test_socket_modes_follow_umask_0117(self):
        modes = {n: stat.S_IMODE(os.stat(p).st_mode) for n, p in
                 (("ctl", self.paths.ctl_sock), ("ui", self.paths.ui_sock), ("out", self.paths.out_sock))}
        self.assertEqual(modes["ctl"], 0o600)
        self.assertEqual(modes["ui"], 0o660)
        self.assertEqual(modes["out"], 0o660)

    def test_unknown_verb_is_refused_and_audited(self):
        r = self.bad(self.ctl("rm-rf", {}), "denied", 3)
        self.assertEqual(r["error"], "command not allowed")
        self.assertIn(("cli", "socket.refused", "denied"), self.audit_actions())

    def test_ui_takes_only_its_whitelist(self):
        for verb in ("token.create", "host.revoke", "host.retire", "host.adopt", "settings.set", "never-ban.add",
                     "alert.test", "ui-login.mint", "audit.verify", "reissue-cert", "agent-hash.add", "status",
                     "incident.resolve", "outbox.take"):
            self.bad(self.ui(verb), "denied", 3)
        self.flush_folds()
        rows = self.rows("SELECT actor_detail, action, target, details FROM audit WHERE action='socket.refused'")
        self.assertEqual(len(rows), 14)                                    # one folded row per verb, with a count
        self.assertEqual({r["actor_detail"] for r in rows}, {"socket=ui verb=%s" % v for v in
                                                              ("token.create", "host.revoke", "host.retire", "host.adopt", "settings.set",
                                                               "never-ban.add", "alert.test", "ui-login.mint", "audit.verify", "reissue-cert",
                                                               "agent-hash.add", "status", "incident.resolve", "outbox.take")})
        self.assertTrue(all(json.loads(r["details"])["count"] == 1 for r in rows))

    def test_ctl_does_not_take_login_redeem_or_out_verbs(self):
        self.bad(self.ctl("login.redeem", {"code": "x"}), "denied", 3)
        self.bad(self.ctl("outbox.take"), "denied", 3)

    def test_out_takes_only_outbox_and_feed_verbs(self):
        for verb in ("host.revoke", "token.create", "status", "settings.set", "login.redeem"):
            self.bad(self.out(verb), "denied", 3)
        self.ok(self.out("feed.job"))

    def test_peer_uid_check_denies_and_audits(self):
        self.socks.allowed["ctl"] = {12345}
        self.bad(self.ctl("status"), "denied", 3)
        self.assertIn(("cli", "socket.denied", "denied"), self.audit_actions())

    def test_oversize_line_is_refused(self):
        r = S.send(self.paths.ctl_sock, None, raw=b'{"cmd":"status","pad":"' + b"x" * 70000 + b'"}\n')
        self.bad(r, "invalid", 3)

    def test_line_at_the_limit_still_works(self):
        pad = "x" * (hub_common.SOCK_LINE_MAX - len('{"cmd":"status","args":{},"pad":""}'))
        line = ('{"cmd":"status","args":{},"pad":"%s"}' % pad).encode() + b"\n"
        self.assertLessEqual(len(line) - 1, hub_common.SOCK_LINE_MAX)
        self.ok(S.send(self.paths.ctl_sock, None, raw=line))

    def test_malformed_json_and_wrong_shapes(self):
        for raw in (b"not json\n", b"[1,2]\n", b'{"cmd":5}\n', b'{"cmd":"status","args":[1]}\n', b"\xff\xfe\n"):
            self.bad(S.send(self.paths.ctl_sock, None, raw=raw), "invalid", 3)
        self.assertIn(("cli", "socket.bad-request", "invalid"), self.audit_actions())

    def test_a_silent_client_is_cut_after_the_timeout(self):
        with mock.patch("hub_ctl.TIMEOUT_S", 0.5):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(self.paths.ctl_sock)
            s.sendall(b'{"cmd":"sta')
            t0 = time.monotonic()
            data = s.recv(100)
            s.close()
        self.assertEqual(data, b"")
        self.assertLess(time.monotonic() - t0, 2.5)

    def test_a_ninth_connection_is_dropped_at_once(self):
        with mock.patch("hub_ctl.TIMEOUT_S", 4):
            held = []
            for _ in range(8):
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(self.paths.ctl_sock)
                held.append(s)
            time.sleep(0.4)
            ninth = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            ninth.settimeout(2)
            ninth.connect(self.paths.ctl_sock)
            t0 = time.monotonic()
            self.assertEqual(ninth.recv(10), b"")
            self.assertLess(time.monotonic() - t0, 1.5)
            ninth.close()
            for s in held:
                s.close()
        time.sleep(0.3)
        self.ok(self.ctl("status"))                       # the slots come back

    def test_status_verb(self):
        r = self.ok(self.ctl("status"))
        self.assertEqual(r["version"], hub_common.VERSION)
        self.assertEqual(r["pid"], os.getpid())

    def test_stop_removes_the_sockets(self):
        self.socks.stop()
        for p in (self.paths.ctl_sock, self.paths.ui_sock, self.paths.out_sock):
            self.assertFalse(os.path.exists(p))

    def test_busy_writer_gives_a_clean_error(self):
        class Busy(Exception):
            pass
        self.hub.writer.fail_next = Busy()
        self.bad(self.ctl("never-ban.list"), "error", 2)

    def test_unexpected_exception_is_not_leaked(self):
        self.hub.writer.fail_next = RuntimeError("secret internals")
        r = self.bad(self.ctl("never-ban.list"), "error", 2)
        self.assertNotIn("secret", r["error"])


class HostVerbTests(SocketCase):
    def setUp(self):
        super().setUp()
        self.uuid = S.add_host(self.hub.db, "web-1")

    def state(self):
        return self.rows("SELECT state FROM hosts WHERE name='web-1'")[0]["state"]

    def test_revoke_audits_notifies_and_changes_state(self):
        r = self.ok(self.ctl("host.revoke", {"host": "web-1"}))
        self.assertEqual((r["state"], r["uuid"]), ("revoked", self.uuid))
        self.assertEqual(self.state(), "revoked")
        self.assertIn(("cli", "host.revoke", "ok"), self.audit_actions())
        self.assertEqual(self.alerts.notices[0][0], "host revoked")
        self.assertIn("web-1", self.alerts.notices[0][1])
        self.assertIn("loginuid=1000", self.alerts.notices[0][2])
        self.assertIn("sudo=j", self.alerts.notices[0][2])

    def test_by_uuid_retire_and_adopt(self):
        self.ok(self.ctl("host.retire", {"host": self.uuid}))
        self.assertEqual(self.state(), "retired")
        orphan = S.add_host(self.hub.db, "web-2", state="orphan")
        self.ok(self.ctl("host.adopt", {"host": orphan}))
        self.assertEqual(self.rows("SELECT state FROM hosts WHERE name='web-2'")[0]["state"], "active")
        self.assertEqual([n[0] for n in self.alerts.notices], ["host retired", "host adopted"])

    def test_adopt_refuses_a_host_that_is_not_an_orphan(self):
        self.bad(self.ctl("host.adopt", {"host": "web-1"}), "invalid", 3)
        self.assertEqual(self.state(), "active")

    def test_unknown_host_and_disallowed_transition(self):
        self.bad(self.ctl("host.revoke", {"host": "nope"}), "invalid", 3)
        self.ok(self.ctl("host.revoke", {"host": "web-1"}))
        self.bad(self.ctl("host.retire", {"host": "web-1"}), "invalid", 3)
        self.assertIn(("cli", "host.retire", "invalid"), self.audit_actions())
        self.bad(self.ctl("host.revoke", {}), "invalid", 3)

    def test_mark_moved_raises_an_admin_notice_because_it_revokes_the_certificate(self):
        self.ok(self.ctl("host.mark-moved", {"host": "web-1"}))
        self.assertEqual(self.state(), "moved")
        self.assertEqual([n[0] for n in self.alerts.notices], ["host marked moved"])     # HIGH, always sent (admin_notice)
        self.assertIn("web-1", self.alerts.notices[0][1])
        self.assertEqual(self.enroll.revoked_certs, [self.uuid])

    def test_the_dashboards_mark_moved_is_announced_too(self):
        self.ok(self.ui("host.mark-moved", {"host": "web-1"}))
        self.assertEqual([n[0] for n in self.alerts.notices], ["host marked moved"])
        self.assertIn("ui session=0a1b2c3d", self.alerts.notices[0][2])

    def test_maintenance_stays_an_info_notice(self):
        self.ok(self.ctl("host.maintenance", {"host": "web-1", "for": "30m"}))
        self.assertEqual(self.alerts.notices, [])
        self.assertEqual(self.alerts.notifies[-1]["severity"], "INFO")

    def test_ui_may_mark_moved_and_is_named_in_the_audit(self):
        self.ok(self.ui("host.mark-moved", {"host": "web-1"}))
        self.assertEqual(self.state(), "moved")
        row = self.rows("SELECT * FROM audit WHERE action='host.mark-moved'")[0]
        self.assertEqual(row["actor_kind"], "ui")
        self.assertEqual(row["actor_detail"], "ui session=0a1b2c3d addr=127.0.0.1")

    def test_ui_actor_is_validated(self):
        self.ok(self.ui("host.mark-moved", {"host": "web-1"}, actor={"session": "<script>", "addr": "not an ip"}))
        row = self.rows("SELECT * FROM audit WHERE action='host.mark-moved'")[0]
        self.assertEqual(row["actor_detail"], "ui session=unknown addr=unknown")

    def test_maintenance_window_set_and_end(self):
        r = self.ok(self.ctl("host.maintenance", {"host": "web-1", "for": "30m"}))
        w = self.rows("SELECT * FROM maintenance")[0]
        self.assertEqual(w["host"], self.uuid)
        self.assertAlmostEqual(w["until"], hub_common.now_ms() + 30 * 60_000, delta=5000)
        self.assertEqual(r["until"], w["until"])
        self.assertIn("loginuid=1000", w["set_by"])
        self.assertEqual(self.alerts.notifies[-1]["severity"], "INFO")
        self.ok(self.ctl("host.maintenance", {"host": "web-1", "end": True}))
        self.assertEqual(self.rows("SELECT * FROM maintenance"), [])
        self.bad(self.ctl("host.maintenance", {"host": "web-1", "end": True}), "invalid", 3)
        self.assertIn(("cli", "host.maintenance-end", "ok"), self.audit_actions())

    def test_maintenance_limits(self):
        self.ok(self.ctl("host.maintenance", {"host": "web-1", "for": "2h"}))
        self.bad(self.ctl("host.maintenance", {"host": "web-1", "for": "3h"}), "invalid", 3)
        self.bad(self.ctl("host.maintenance", {"host": "web-1", "for": "10s"}), "invalid", 3)
        self.bad(self.ctl("host.maintenance", {"host": "web-1", "for": "forever"}), "invalid", 3)
        self.bad(self.ctl("host.maintenance", {"host": "web-1"}), "invalid", 3)

    def test_maintenance_from_the_ui_has_the_same_limit(self):
        self.ok(self.ui("host.maintenance", {"host": "web-1", "for": "1h"}))
        self.bad(self.ui("host.maintenance", {"host": "web-1", "for": "5h"}), "invalid", 3)
        self.ok(self.ui("host.maintenance", {"host": "web-1", "end": True}))

    def test_maintenance_needs_a_host_in_service(self):
        S.add_host(self.hub.db, "gone", state="retired")
        self.bad(self.ctl("host.maintenance", {"host": "gone", "for": "30m"}), "invalid", 3)

    def test_incident_resolve(self):
        now = hub_common.now_ms()
        self.hub.db.execute("INSERT INTO incidents (host, chain, opened, updated, severity) VALUES (?,?,?,?,?)",
                            (self.uuid, "c", now, now, "HIGH"))
        r = self.ok(self.ctl("incident.resolve", {"id": 1}))
        self.assertEqual(r["state"], "resolved")
        row = self.rows("SELECT * FROM incidents")[0]
        self.assertEqual((row["state"], row["closed_by"]), ("resolved", "j"))
        self.bad(self.ctl("incident.resolve", {"id": 1}), "invalid", 3)
        self.bad(self.ctl("incident.resolve", {"id": "x"}), "invalid", 3)


class TokenTests(SocketCase):
    def all_text(self):
        parts = [json.dumps(self.rows("SELECT * FROM audit")), json.dumps(self.alerts.notices),
                 json.dumps(self.rows("SELECT * FROM settings_history")), json.dumps(self.hub.logs)]
        return " ".join(parts)

    def test_single_token_and_secret_stays_out_of_audit_and_notices(self):
        r = self.ok(self.ctl("token.create", {"name": "web-1", "ttl": "1h", "source": "198.51.100.0/24"}))
        tok = r["tokens"][0]
        self.assertTrue(tok["token"].startswith("tok1.SECRETVALUE1XYZ."))
        self.assertEqual(tok["label"], "web-1")
        row = self.rows("SELECT * FROM tokens")[0]
        self.assertEqual((row["name"], row["source_cidr"]), ("web-1", "198.51.100.0/24"))
        self.assertEqual(row["created_by"], "j")
        self.assertAlmostEqual(row["expires_at"], hub_common.now_ms() + 3600_000, delta=5000)
        self.assertEqual(self.hub.listener_refreshes, 1)
        self.assertNotIn("SECRETVALUE", self.all_text())
        self.assertNotIn("ab" * 32, self.all_text())
        self.assertEqual(self.alerts.notices[0][0], "token created")
        self.assertIn(("cli", "token.create", "ok"), self.audit_actions())

    def test_default_ttl_is_15_minutes(self):
        self.ok(self.ctl("token.create", {"name": "web-1"}))
        self.assertAlmostEqual(self.rows("SELECT expires_at FROM tokens")[0]["expires_at"],
                               hub_common.now_ms() + 900_000, delta=5000)

    def test_bulk_names_are_all_or_nothing(self):
        r = self.ok(self.ctl("token.create", {"names": ["web-1", "web-2", "web-3"], "ttl": "4h"}))
        self.assertEqual([t["label"] for t in r["tokens"]], ["web-1", "web-2", "web-3"])
        self.assertEqual(len(self.rows("SELECT * FROM tokens")), 3)
        S.add_host(self.hub.db, "taken")
        self.bad(self.ctl("token.create", {"names": ["fresh", "taken"]}), "invalid", 3)
        self.assertEqual(len(self.rows("SELECT * FROM tokens")), 3)           # "fresh" was rolled back too
        self.assertEqual(len(self.alerts.notices), 1)

    def test_for_takes_a_comma_list_of_names_and_uuids(self):
        u1 = S.add_host(self.hub.db, "web-1")
        S.add_host(self.hub.db, "web-2")
        r = self.ok(self.ctl("token.create", {"for": ["web-1", "web-2"]}))
        self.assertEqual([t["label"] for t in r["tokens"]], ["web-1", "web-2"])
        self.assertEqual(self.rows("SELECT bound_host FROM tokens ORDER BY id")[0]["bound_host"], u1)
        self.ok(self.ctl("token.create", {"for": u1}))
        self.bad(self.ctl("token.create", {"for": ["ghost"]}), "invalid", 3)

    def test_validation(self):
        self.bad(self.ctl("token.create", {}), "invalid", 3)
        self.bad(self.ctl("token.create", {"name": "a", "names": ["b"]}), "invalid", 3)
        self.bad(self.ctl("token.create", {"name": "Bad_Name"}), "invalid", 3)
        self.bad(self.ctl("token.create", {"names": ["a", "a"]}), "invalid", 3)
        self.bad(self.ctl("token.create", {"name": "a", "ttl": "25h"}), "invalid", 3)
        self.bad(self.ctl("token.create", {"name": "a", "ttl": "soon"}), "invalid", 3)
        self.bad(self.ctl("token.create", {"name": "a", "source": "999.1.1.1/8"}), "invalid", 3)
        self.bad(self.ctl("token.create", {"name": "a", "source": "10.0.0.1/8"}), "invalid", 3)   # host bits set
        self.assertEqual(self.rows("SELECT * FROM tokens"), [])
        self.assertEqual(self.hub.listener_refreshes, 0)

    def test_source_is_required_while_clients_only_is_on(self):
        self.hub.update_settings(dict(self.hub.settings, clients_only=True))
        self.bad(self.ctl("token.create", {"name": "a"}), "invalid", 3)
        self.ok(self.ctl("token.create", {"name": "a", "source": "198.51.100.7"}))

    def test_list_and_revoke(self):
        r = self.ok(self.ctl("token.create", {"names": ["a", "b"]}))
        listed = self.ok(self.ctl("token.list"))["tokens"]
        self.assertEqual([t["name"] for t in listed], ["a", "b"])
        self.assertNotIn("token", json.dumps(listed))
        self.ok(self.ctl("token.revoke", {"id": r["tokens"][0]["id"]}))
        self.assertEqual(self.hub.listener_refreshes, 2)
        self.bad(self.ctl("token.revoke", {"id": r["tokens"][0]["id"]}), "invalid", 3)
        self.bad(self.ctl("token.revoke", {"id": "nope"}), "invalid", 3)
        self.assertIn(("cli", "token.revoke", "ok"), self.audit_actions())


class NeverBanTests(SocketCase):
    def test_add_list_remove_with_notices(self):
        self.ok(self.ctl("never-ban.add", {"cidr": "198.51.100.0/24", "reason": "monitor"}))
        self.ok(self.ctl("never-ban.add", {"cidr": "203.0.113.5"}))
        entries = self.ok(self.ctl("never-ban.list"))["entries"]
        self.assertEqual([e["cidr"] for e in entries], ["198.51.100.0/24", "203.0.113.5/32"])
        self.assertEqual(entries[0]["reason"], "monitor")
        self.assertEqual(entries[0]["added_by"], "j")
        self.ok(self.ctl("never-ban.remove", {"cidr": "203.0.113.5"}))
        self.assertEqual([n[0] for n in self.alerts.notices], ["never-ban added", "never-ban added", "never-ban removed"])
        self.bad(self.ctl("never-ban.remove", {"cidr": "203.0.113.5"}), "invalid", 3)

    def test_minimum_prefix_and_validation(self):
        for cidr in ("0.0.0.0/0", "10.0.0.0/8", "198.0.0.0/15", "2001:db8::/16", "::/0"):
            self.bad(self.ctl("never-ban.add", {"cidr": cidr}), "invalid", 3)
        self.ok(self.ctl("never-ban.add", {"cidr": "198.51.0.0/16"}))
        self.ok(self.ctl("never-ban.add", {"cidr": "2001:db8::/32"}))
        for cidr in ("garbage", "198.51.100.1/24", "", "198.51.100.0/33"):
            self.bad(self.ctl("never-ban.add", {"cidr": cidr}), "invalid", 3)

    def test_overlap_with_an_existing_entry_is_refused(self):
        self.ok(self.ctl("never-ban.add", {"cidr": "198.51.0.0/16"}))
        self.bad(self.ctl("never-ban.add", {"cidr": "198.51.100.0/24"}), "refused", 3)
        self.bad(self.ctl("never-ban.add", {"cidr": "198.51.0.0/16"}), "refused", 3)
        self.assertEqual(len(self.rows("SELECT * FROM never_ban")), 1)

    def test_overlap_with_an_active_ban_is_refused(self):
        now = int(time.time())
        self.hub.db.execute("INSERT INTO bans (cidr, source, created, expires) VALUES ('198.51.100.7/32','operator',?,?)",
                            (now, now + 3600))
        self.bad(self.ctl("never-ban.add", {"cidr": "198.51.100.0/24"}), "refused", 3)

    def test_the_ui_cannot_touch_it(self):
        self.bad(self.ui("never-ban.add", {"cidr": "198.51.100.0/24"}), "denied", 3)


class SettingsTests(SocketCase):
    def test_plain_key_is_validated_saved_recorded_and_announced(self):
        r = self.ok(self.ctl("settings.set", {"key": "alert_min_severity", "value": "MEDIUM"}))
        self.assertEqual(r["value"], "MEDIUM")
        self.assertEqual(hub_common.load_settings(self.paths)["alert_min_severity"], "MEDIUM")
        self.assertEqual(self.hub.settings["alert_min_severity"], "MEDIUM")
        h = self.rows("SELECT * FROM settings_history")[0]
        self.assertEqual((h["key"], h["old"], h["new"]), ("alert_min_severity", "HIGH", "MEDIUM"))
        self.assertIn("loginuid=1000", h["actor"])
        self.assertEqual(self.alerts.notices[0][0], "setting changed")
        self.assertIn(("cli", "settings.set", "ok"), self.audit_actions())

    def test_typed_keys_are_converted(self):
        self.ok(self.ctl("settings.set", {"key": "retention_days", "value": "45"}))
        self.assertEqual(self.hub.settings["retention_days"], 45)
        self.ok(self.ctl("settings.set", {"key": "max_db_size", "value": "512m"}))
        self.assertEqual(self.hub.settings["max_db_size"], "512M")
        self.ok(self.ctl("settings.set", {"key": "ui_host", "value": "127.0.0.1:9000,localhost:9000"}))
        self.assertEqual(self.hub.settings["ui_host"], ["127.0.0.1:9000", "localhost:9000"])

    def test_bad_values_and_keys(self):
        for key, value in (("alert_min_severity", "LOUD"), ("retention_days", "0"), ("retention_days", "x"),
                           ("digest_time", "25:00"), ("ntfy_url", "http://insecure.example"), ("max_db_size", "big"),
                           ("ui_host", "nocolon")):
            self.bad(self.ctl("settings.set", {"key": key, "value": value}), "invalid", 3)
        self.bad(self.ctl("settings.set", {"key": "nonsense", "value": "x"}), "invalid", 3)
        self.assertEqual(self.rows("SELECT * FROM settings_history"), [])

    def test_a_secret_key_is_refused_over_the_socket(self):
        for key in hub_common.SECRET_SETTINGS:
            self.bad(self.ctl("settings.set", {"key": key, "value": "https://hooks.example/x"}), "refused", 3)
        self.assertEqual(self.hub.settings["secrets_set"], {})
        self.assertNotIn("hooks.example", json.dumps(self.rows("SELECT * FROM audit")))

    def test_installer_keys_are_refused(self):
        self.bad(self.ctl("settings.set", {"key": "port", "value": "9"}), "refused", 3)
        self.bad(self.ctl("settings.set", {"key": "public_ip", "value": "1.2.3.4"}), "refused", 3)

    def test_secret_changed_records_only_that_it_changed(self):
        masked = hub_common.mask_secret("https://hooks.example.com/services/T000/B000/XXXXsecretYYYY")
        self.ok(self.ctl("settings.secret-changed", {"key": "webhook_url", "masked": masked}))
        self.assertEqual(self.hub.settings["secrets_set"], {"webhook_url": masked})
        self.assertEqual(hub_common.load_settings(self.paths)["secrets_set"], {"webhook_url": masked})
        self.assertEqual(hub_common.enabled_channels(self.hub.settings), ["webhook"])
        h = self.rows("SELECT * FROM settings_history")[0]
        self.assertEqual((h["key"], h["old"], h["new"]), ("webhook_url", "changed", "changed"))
        self.assertNotIn("XXXXsecret", json.dumps(self.rows("SELECT * FROM audit")) + json.dumps(self.alerts.notices))
        self.assertEqual(self.alerts.notices[0][0], "secret changed")
        self.ok(self.ctl("settings.secret-changed", {"key": "webhook_url", "masked": ""}))
        self.assertEqual(self.hub.settings["secrets_set"], {})
        self.assertEqual(self.rows("SELECT new FROM settings_history ORDER BY id")[-1]["new"], "cleared")

    def test_secret_changed_pre_phase_only_queues_a_notice(self):
        self.ok(self.ctl("settings.secret-changed", {"key": "webhook_url", "phase": "pre"}))
        self.assertEqual(self.alerts.notices[0][0], "secret about to change")
        self.assertEqual(self.rows("SELECT * FROM settings_history"), [])
        self.assertEqual(self.hub.settings["secrets_set"], {})

    def test_secret_changed_validation(self):
        self.bad(self.ctl("settings.secret-changed", {"key": "retention_days", "masked": "x"}), "invalid", 3)
        self.bad(self.ctl("settings.secret-changed", {"key": "webhook_url", "phase": "later"}), "invalid", 3)

    def test_a_failure_while_saving_rolls_the_rows_back(self):
        with mock.patch.object(self.hub, "update_settings", side_effect=OSError("disk full")):
            self.bad(self.ctl("settings.set", {"key": "retention_days", "value": "40"}), "error", 2)
        self.assertEqual(self.rows("SELECT * FROM settings_history"), [])
        self.assertIn(("cli", "settings.set", "error"), self.audit_actions())

    def test_alert_test_goes_through_the_outbox(self):
        r = self.ok(self.ctl("alert.test", {}))
        self.assertEqual(len(r["ids"]), 1)
        self.assertEqual(self.rows("SELECT channel, state FROM outbox")[0], {"channel": "none", "state": "dead"})
        self.bad(self.ctl("alert.test", {"channel": "pigeon"}), "invalid", 3)
        self.ok(self.ctl("alert.test", {"channel": "ntfy"}))
        self.assertIn(("cli", "alert.test", "ok"), self.audit_actions())

    def test_agent_hash_add(self):
        sha = "ab" * 32
        r = self.ok(self.ctl("agent-hash.add", {"sha256": sha.upper(), "note": "patched build"}))
        self.assertEqual((r["sha256"], r["added"]), (sha, True))
        self.assertEqual(self.rows("SELECT * FROM agent_hashes")[0]["note"], "patched build")
        self.assertFalse(self.ok(self.ctl("agent-hash.add", {"sha256": sha}))["added"])
        self.bad(self.ctl("agent-hash.add", {"sha256": "xyz"}), "invalid", 3)
        self.assertEqual(sum(1 for n in self.alerts.notices if n[0] == "agent hash added"), 1)

    def test_reissue_cert(self):
        r = self.ok(self.ctl("reissue-cert"))
        self.assertEqual(self.hub.pki.issued, [["203.0.113.10"]])
        self.assertEqual(self.hub.cert_reloads, 1)
        self.assertEqual(r["serial"], "0abc")
        self.assertEqual(self.alerts.notices[0][0], "server certificate reissued")

    def test_reissue_cert_failure_is_audited(self):
        self.hub.pki.issue_server_cert = mock.Mock(side_effect=RuntimeError("openssl died"))
        self.bad(self.ctl("reissue-cert"), "error", 2)
        self.assertIn(("cli", "reissue-cert", "error"), self.audit_actions())


class LoginTests(SocketCase):
    def mint(self):
        return self.ok(self.ctl("ui-login.mint"))["code"]

    def test_mint_stores_only_a_hash_and_redeem_is_single_use(self):
        code = self.mint()
        row = self.rows("SELECT * FROM login_codes")[0]
        self.assertEqual(row["code_sha256"], hashlib.sha256(code.encode()).hexdigest())
        self.assertNotIn(code, json.dumps(self.rows("SELECT * FROM audit")))
        self.assertAlmostEqual(row["expires"] - row["created"], 600_000, delta=1)
        self.assertEqual(self.ok(self.ui("login.redeem", {"code": code})), {"valid": True})
        self.assertEqual(self.alerts.notices[-1][0], "dashboard session")
        self.assertIn("127.0.0.1", self.alerts.notices[-1][1])
        self.assertIn(("ui", "login.redeem", "ok"), self.audit_actions())
        r = self.bad(self.ui("login.redeem", {"code": code}), "denied", 3)
        self.assertEqual(r["failures"], 1)

    def test_an_expired_code_fails(self):
        code = self.mint()
        self.hub.db.execute("UPDATE login_codes SET expires=?", (hub_common.now_ms() - 1,))
        self.bad(self.ui("login.redeem", {"code": code}), "denied", 3)

    def test_wrong_and_malformed_codes_fail_and_are_audited(self):
        self.mint()
        for code in ("wrong", "", None, 5, "x" * 500):
            self.bad(self.ui("login.redeem", {"code": code}), "denied", 3)
        self.flush_folds()
        rows = self.rows("SELECT details FROM audit WHERE action='login.redeem' AND outcome='denied'")
        self.assertEqual([json.loads(r["details"])["count"] for r in rows], [5])      # folded: one row, a count of five

    def test_more_than_five_failures_a_minute_raises_one_notice(self):
        for _ in range(5):
            self.bad(self.ui("login.redeem", {"code": "bad"}), "denied", 3)
        self.assertEqual([n for n in self.alerts.notices if n[0] == "failed dashboard logins"], [])
        r = self.bad(self.ui("login.redeem", {"code": "bad"}), "denied", 3)
        self.assertEqual(r["failures"], 6)
        self.bad(self.ui("login.redeem", {"code": "bad"}), "denied", 3)
        self.assertEqual(len([n for n in self.alerts.notices if n[0] == "failed dashboard logins"]), 1)

    def test_login_redeem_is_not_on_ctl(self):
        code = self.mint()
        self.bad(self.ctl("login.redeem", {"code": code}), "denied", 3)
        self.ok(self.ui("login.redeem", {"code": code}))


class AuditVerifyTests(SocketCase):
    def test_verify_ok_and_broken(self):
        r = self.ok(self.ctl("audit.verify"))
        self.assertTrue(r["ok"])
        self.assertIsNone(r["first_bad_id"])
        self.hub.db.execute("UPDATE audit SET target='tampered' WHERE id=1")
        r = self.ok(self.ctl("audit.verify"))
        self.assertFalse(r["ok"])
        self.assertEqual(r["first_bad_id"], 1)
        self.assertEqual(self.alerts.notices[-1][0], "audit chain broken")
        self.bad(self.ui("audit.verify"), "denied", 3)


class OutboxTests(SocketCase):
    def seed(self, channel="webhook", state="pending", next_try=None, created=None, attempts=0):
        now = hub_common.now_ms()
        cur = self.hub.db.execute(
            "INSERT INTO outbox (created, channel, severity, payload, next_try, state, attempts) VALUES (?,?,?,?,?,?,?)",
            (created or now, channel, "HIGH", json.dumps({"title": "t", "severity": "HIGH"}),
             now - 10 if next_try is None else next_try, state, attempts))
        return cur.lastrowid

    def test_take_returns_due_rows_and_marks_them_sending(self):
        a = self.seed()
        b = self.seed(channel="ntfy")
        self.seed(channel="none", state="dead")
        self.seed(next_try=hub_common.now_ms() + 600_000)          # not due
        self.seed(state="sent")
        r = self.ok(self.out("outbox.take", {"max": 20}))
        self.assertEqual([i["id"] for i in r["items"]], [a, b])
        self.assertEqual(r["items"][0]["payload"]["title"], "t")
        self.assertEqual(set(r["items"][0]), {"id", "channel", "severity", "payload", "attempts"})
        self.assertEqual(r["options"], {"ntfy_url": "", "webhook_ca_pem": None})
        self.assertFalse(r["deadman"])
        states = {x["id"]: x["state"] for x in self.rows("SELECT id, state FROM outbox")}
        self.assertEqual((states[a], states[b]), ("sending", "sending"))
        self.assertEqual(self.ok(self.out("outbox.take"))["items"], [])        # leased: not handed out twice

    def test_take_respects_max_and_options_and_deadman(self):
        for _ in range(5):
            self.seed()
        self.hub.update_settings(dict(self.hub.settings, ntfy_url="https://ntfy.example.org",
                                      secrets_set={"deadman_url": "x"}))
        with open(self.paths.webhook_ca, "w") as f:
            f.write("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
        r = self.ok(self.out("outbox.take", {"max": 2}))
        self.assertEqual(len(r["items"]), 2)
        self.assertEqual(r["options"]["ntfy_url"], "https://ntfy.example.org")
        self.assertIn("BEGIN CERTIFICATE", r["options"]["webhook_ca_pem"])
        self.assertTrue(r["deadman"])

    def test_a_lease_that_ran_out_is_taken_again(self):
        a = self.seed()
        self.ok(self.out("outbox.take"))
        self.hub.db.execute("UPDATE outbox SET next_try=? WHERE id=?", (hub_common.now_ms() - 1, a))
        self.assertEqual([i["id"] for i in self.ok(self.out("outbox.take"))["items"]], [a])

    def test_result_ok_marks_sent(self):
        a = self.seed()
        self.ok(self.out("outbox.take"))
        self.ok(self.out("outbox.result", {"id": a, "ok": True}))
        row = self.rows("SELECT * FROM outbox WHERE id=?", (a,))[0]
        self.assertEqual(row["state"], "sent")
        self.assertIsNotNone(row["sent_at"])

    def test_failure_ladder_1_5_15_60_minutes_then_stays_at_60(self):
        a = self.seed()
        expected = [1, 5, 15, 60, 60]
        for n, minutes in enumerate(expected, start=1):
            self.hub.db.execute("UPDATE outbox SET state='sending' WHERE id=?", (a,))
            t = hub_common.now_ms()
            self.ok(self.out("outbox.result", {"id": a, "ok": False, "error": "HTTP 500"}))
            row = self.rows("SELECT * FROM outbox WHERE id=?", (a,))[0]
            self.assertEqual((row["state"], row["attempts"]), ("failed", n))
            self.assertAlmostEqual(row["next_try"] - t, minutes * 60_000, delta=3000)
            self.assertEqual(row["last_error"], "HTTP 500")

    def test_retry_after_is_honoured_up_to_an_hour(self):
        a = self.seed()
        t = hub_common.now_ms()
        self.ok(self.out("outbox.result", {"id": a, "ok": False, "error": "429", "retry_after": 600}))
        self.assertAlmostEqual(self.rows("SELECT next_try FROM outbox")[0]["next_try"] - t, 600_000, delta=3000)
        self.ok(self.out("outbox.result", {"id": a, "ok": False, "error": "429", "retry_after": 999999}))
        self.assertAlmostEqual(self.rows("SELECT next_try FROM outbox")[0]["next_try"] - t, 3_600_000, delta=3000)

    def test_dead_after_24_hours(self):
        a = self.seed(created=hub_common.now_ms() - 24 * 3600_000 - 1000)
        self.ok(self.out("outbox.result", {"id": a, "ok": False, "error": "gone"}))
        self.assertEqual(self.rows("SELECT state FROM outbox")[0]["state"], "dead")

    def test_result_for_an_unknown_or_finished_row_is_not_accepted(self):
        a = self.seed(state="sent")
        self.assertFalse(self.ok(self.out("outbox.result", {"id": a, "ok": False}))["accepted"])
        self.assertFalse(self.ok(self.out("outbox.result", {"id": 999, "ok": True}))["accepted"])
        self.bad(self.out("outbox.result", {"id": "x"}), "invalid", 3)

    def test_feed_verbs_are_empty_p3_slots(self):
        self.assertEqual(self.ok(self.out("feed.job")), {"jobs": []})
        self.assertTrue(self.ok(self.out("feed.result", {"anything": 1}))["accepted"])

    def test_out_sock_traffic_is_not_audited_except_refusals(self):
        self.seed()
        self.ok(self.out("outbox.take"))
        self.assertEqual(self.audit_actions(), [])


class FoldedRefusalTests(SocketCase):
    def test_refusals_on_ui_and_out_are_one_row_per_socket_verb_and_minute(self):
        for i in range(60):
            self.ui("token.create", {"name": "x%d" % i})
            self.ui("made.up.%d" % i)
            self.out("host.revoke")
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM audit")[0]["n"], 0)       # nothing yet: the minute is not over
        self.flush_folds()
        rows = {r["actor_detail"]: json.loads(r["details"])["count"] for r in
                self.rows("SELECT actor_detail, details FROM audit ORDER BY id")}
        self.assertEqual(rows, {"socket=ui verb=token.create": 60, "socket=ui verb=unknown": 60, "socket=out verb=host.revoke": 60})

    def test_the_daily_cap_and_summary_row_apply(self):
        import hub_audit
        from unittest import mock
        with mock.patch("hub_audit.FOLD_ROWS_PER_DAY", 2):
            for verb in ("token.create", "host.revoke", "settings.set", "status"):
                self.ui(verb)
            self.flush_folds()
            self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM audit WHERE action='socket.refused'")[0]["n"], 2)
            self.hub.writer.call(lambda conn: hub_audit.flush_folds(conn, hub_common.now_ms() + 2 * 86400 * 1000))
        self.assertEqual(len(self.rows("SELECT * FROM audit WHERE action='client-failures.capped'")), 1)

    def test_ctl_refusals_keep_one_row_each(self):
        for _ in range(3):
            self.ctl("no.such.verb")
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM audit WHERE action='socket.refused'")[0]["n"], 3)


class IngestLoopTests(S.HubTestCase):
    def test_pending_audit_lines_are_taken_in_without_waiting_for_a_writer_idle_tick(self):
        import hub_audit
        with mock.patch("hub_ctl.INGEST_TICK_S", 0.1):
            socks = hub_ctl.Sockets(self.hub)
            socks.start()
            self.addCleanup(socks.stop)
            hub_audit.append_pending(self.paths, "restore", "/x/f.bak", "started")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not self.alerts.notices:
                time.sleep(0.05)
        self.assertEqual([n[0] for n in self.alerts.notices], ["restore"])
        self.assertEqual(self.rows("SELECT action FROM audit")[0]["action"], "file-op.restore")


class ConcurrencyTests(SocketCase):
    def test_parallel_requests_all_get_answers(self):
        S.add_host(self.hub.db, "web-1")
        results = []

        def go():
            results.append(self.ctl("never-ban.list"))
        threads = [threading.Thread(target=go) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        self.assertEqual(len(results), 6)
        self.assertTrue(all(r and r["ok"] for r in results))


if __name__ == "__main__":
    unittest.main()
