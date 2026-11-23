"""Independent security review of the hub's admin plane (hub_ctl, hub_audit, hub_backup, the edr-hub CLI, the
dashboard server and page, uninstall.sh), measured against server_hub/PLAN.md sections 1, 5, 6, 7, 9, 14 and 17.

Each test either records something the review checked and found right, or pins a defect the review found and
that has since been fixed: it asserts the behaviour the plan requires, so the defect cannot come back unnoticed.
Nothing here touches the real system: temp directories, 127.0.0.1 ports of 18000 and up, throwaway sockets.
"""

import hashlib
import http.client
import json
import os
import random
import re
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
HUB_DIR = os.path.normpath(os.path.join(HERE, "..", "hub"))
SERVER_HUB = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, HUB_DIR)

import hub_audit      # noqa: E402
import hub_common     # noqa: E402
import hub_ctl        # noqa: E402
import hub_schema     # noqa: E402
from test_engine_support import HubTestCase, T0   # noqa: E402

EDR_HUB = os.path.join(HUB_DIR, "edr-hub")
UNINSTALL = os.path.join(SERVER_HUB, "uninstall.sh")
HOSTILE = "\x1b]8;;http://evil.example/\x07link\x1b]8;;\x07 \x1b[31mred\x9b2J \u202edrowssap \u200b\x00\x7f"


def use_row_factory(hub):
    """hub_enroll reads rows by name, as the real writer connection allows; hub.q still gives plain tuples."""
    hub.writer.conn.row_factory = sqlite3.Row
    hub.q = lambda sql, args=(): [tuple(r) for r in hub.writer.conn.execute(sql, args).fetchall()]


class CtlCase(HubTestCase):
    def setUp(self):
        super().setUp()
        use_row_factory(self.hub)
        self.socks = hub_ctl.Sockets(self.hub)

    def ask(self, sock, cmd, args=None, uid=0, actor=None):
        line = json.dumps({"cmd": cmd, "args": args or {}, "actor": actor or {}}).encode()
        return self.socks.handle_line(sock, 4242, uid, line)

    def audit_rows(self):
        return self.hub.q("SELECT actor_kind, action, outcome FROM audit ORDER BY id")


# =============================================================================================================
# Sockets
# =============================================================================================================
class SocketVerbTests(CtlCase):
    def test_ui_socket_refuses_every_verb_the_plan_reserves_for_ctl_whatever_the_peer_uid(self):
        reserved = sorted(hub_ctl.CTL_VERBS - hub_ctl.UI_VERBS)
        self.assertIn("token.create", reserved)
        self.assertIn("never-ban.add", reserved)
        self.assertIn("settings.set", reserved)
        self.assertIn("ui-login.mint", reserved)
        for uid in (0, os.getuid(), 12345):
            for verb in reserved + ["outbox.take", "outbox.result", "feed.job", "no.such.verb"]:
                reply = self.ask("ui", verb, {"name": "web9", "cidr": "198.51.100.0/24", "key": "alert_min_severity", "value": "LOW"}, uid=uid)
                self.assertEqual((reply["ok"], reply["code"]), (False, "denied"), "%s on ui.sock as uid %d" % (verb, uid))
        self.assertEqual(self.hub.q("SELECT COUNT(*) FROM tokens")[0][0], 0)
        self.assertEqual(self.hub.q("SELECT COUNT(*) FROM never_ban")[0][0], 0)
        self.assertEqual(self.hub.q("SELECT COUNT(*) FROM login_codes")[0][0], 0)

    def test_ui_verbs_are_exactly_the_plans_table(self):
        self.assertEqual(set(hub_ctl.UI_VERBS), {"login.redeem", "host.mark-moved", "host.maintenance"})
        self.assertEqual(set(hub_ctl.OUT_VERBS), {"outbox.take", "outbox.result", "feed.job", "feed.result"})
        self.assertFalse(hub_ctl.OUT_VERBS & hub_ctl.CTL_VERBS)

    def test_out_socket_refuses_every_admin_verb(self):
        for verb in sorted(hub_ctl.CTL_VERBS | hub_ctl.UI_VERBS):
            reply = self.ask("out", verb, {}, uid=0)
            self.assertEqual((reply["ok"], reply["code"]), (False, "denied"), verb)

    def test_ctl_socket_refuses_the_out_verbs_it_does_not_list(self):
        self.assertEqual(self.ask("ctl", "outbox.take")["code"], "denied")
        self.assertEqual(self.ask("ctl", "login.redeem", {"code": "x"})["code"], "denied")

    def test_every_refusal_is_audited_with_the_socket_named(self):
        self.ask("ui", "token.create", {"name": "web9"})
        # a refusal on ui.sock is folded (one row per socket, verb and minute): it appears when the minute is over
        self.hub.writer.call(lambda c: hub_audit.flush_folds(c, hub_common.now_ms() + 120000))
        rows = self.hub.q("SELECT actor_kind, action, outcome, actor_detail, target FROM audit ORDER BY id")
        self.assertEqual(rows[-1], ("ui", "socket.refused", "denied", "socket=ui verb=token.create", "token.create"))

    def test_malformed_requests_are_refused_and_audited(self):
        for line in (b"not json", b"[1,2]", b'{"cmd": 5}', b'{"cmd": "status", "args": 7}', b"\xff\xfe", b"[" * 100000):
            reply = self.socks.handle_line("ctl", 1, 0, line)
            self.assertFalse(reply["ok"])
            self.assertEqual(reply["code"], "invalid")

    def test_a_secret_never_crosses_ctl_sock(self):
        for key in hub_common.SECRET_SETTINGS:
            reply = self.ask("ctl", "settings.set", {"key": key, "value": "https://hooks.example.com/SECRET"})
            self.assertEqual(reply["code"], "refused", key)
        self.assertNotIn("SECRET", json.dumps(self.audit_rows()))


class SocketLimitTests(CtlCase):
    """Real sockets, in a temp directory: size, speed and connection caps."""

    def setUp(self):
        super().setUp()
        self.socks.start()
        self.addCleanup(self.socks.stop)
        self.path = self.hub.paths.ui_sock

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect(self.path)
        return s

    def read_reply(self, s):
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf) if buf else None

    def test_socket_modes_and_the_peer_check_runs_first(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.hub.paths.ctl_sock).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.hub.paths.ui_sock).st_mode), 0o660)
        self.assertEqual(self.socks.allowed["ctl"], {os.getuid(), 0})
        self.assertIn(os.getuid(), self.socks.allowed["ui"])

    def test_request_over_64_kib_is_refused(self):
        s = self.connect()
        s.sendall(b'{"cmd":"login.redeem","args":{"code":"' + b"a" * 70000 + b'"}}\n')
        reply = self.read_reply(s)
        s.close()
        self.assertEqual((reply["ok"], reply["code"]), (False, "invalid"))

    def test_a_request_with_no_newline_and_70_kib_is_refused_too(self):
        s = self.connect()
        s.sendall(b"x" * 70000)
        reply = self.read_reply(s)
        s.close()
        self.assertEqual(reply["code"], "invalid")

    def test_slow_sender_is_cut_at_the_deadline(self):
        old = hub_ctl.TIMEOUT_S
        hub_ctl.TIMEOUT_S = 1
        try:
            s = self.connect()
            started = time.monotonic()
            for _ in range(10):
                try:
                    s.sendall(b" ")
                except OSError:
                    break
                time.sleep(0.3)
            took = time.monotonic() - started
            s.close()
        finally:
            hub_ctl.TIMEOUT_S = old
        self.assertLess(took, 3.5)

    def test_the_ninth_connection_is_dropped_at_once(self):
        held = [self.connect() for _ in range(hub_ctl.MAX_CONN)]
        time.sleep(0.3)
        try:
            ninth = self.connect()
            ninth.settimeout(2)
            try:
                data = ninth.recv(10)
            except socket.timeout:
                self.fail("the ninth connection was held open")
            self.assertEqual(data, b"")
            ninth.close()
        finally:
            for s in held:
                s.close()


# =============================================================================================================
# Login codes
# =============================================================================================================
class LoginTests(CtlCase):
    def mint(self):
        return self.ask("ctl", "ui-login.mint")["result"]["code"]

    def redeem(self, code, uid=0):
        return self.ask("ui", "login.redeem", {"code": code}, uid=uid, actor={"session": "abcd1234", "addr": "127.0.0.1"})

    def test_code_has_128_bits_and_is_stored_hashed(self):
        code = self.mint()
        self.assertGreaterEqual(len(code), 22)
        self.assertRegex(code, r"^[A-Za-z0-9_-]+$")
        stored = self.hub.q("SELECT code_sha256 FROM login_codes")[0][0]
        self.assertEqual(stored, hashlib.sha256(code.encode()).hexdigest())
        self.assertNotIn(code, json.dumps(self.hub.q("SELECT * FROM audit")))
        self.assertEqual(len({self.mint() for _ in range(20)}), 20)

    def test_a_code_works_once(self):
        code = self.mint()
        self.assertTrue(self.redeem(code)["ok"])
        second = self.redeem(code)
        self.assertEqual((second["ok"], second["code"]), (False, "denied"))

    def test_two_concurrent_redeems_of_one_code_give_one_session(self):
        code = self.mint()
        results = []
        barrier = threading.Barrier(8)

        def go():
            barrier.wait()
            results.append(self.redeem(code)["ok"])
        threads = [threading.Thread(target=go) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(True), 1)

    def test_an_expired_code_is_refused(self):
        code = self.mint()
        self.hub.writer.call(lambda c: c.execute("UPDATE login_codes SET expires=?", (1,)))
        self.assertFalse(self.redeem(code)["ok"])

    def test_neither_the_code_nor_the_session_reaches_the_audit_or_the_outbox(self):
        code = self.mint()
        self.redeem(code)
        self.redeem(code + "x")
        blob = json.dumps(self.hub.q("SELECT * FROM audit")) + json.dumps(self.hub.outbox())
        self.assertNotIn(code, blob)

    def test_a_successful_login_is_audited_and_notified(self):
        self.redeem(self.mint())
        self.assertIn(("ui", "login.redeem", "ok"), self.audit_rows())
        self.assertTrue(any(o["payload"]["kind"] == "hub.admin" and "dashboard session" in o["payload"]["title"] for o in self.hub.outbox()))


# =============================================================================================================
# Audit
# =============================================================================================================
class AuditChainTests(HubTestCase):
    def fill(self, n=6):
        for i in range(n):
            self.hub.writer.call(lambda c, i=i: hub_audit.append(c, actor_kind="cli", actor_detail="uid=0", action="a%d" % i, target="t"))

    def verify(self):
        return self.hub.writer.call(hub_audit.verify)

    def test_an_edited_dropped_or_reordered_row_is_found(self):
        self.fill()
        self.assertEqual(self.verify(), (True, None))
        self.hub.writer.call(lambda c: c.execute("UPDATE audit SET target='x' WHERE id=3"))
        self.assertEqual(self.verify(), (False, 3))
        self.hub.writer.call(lambda c: c.execute("UPDATE audit SET target='t' WHERE id=3"))
        self.assertEqual(self.verify(), (True, None))
        self.hub.writer.call(lambda c: c.execute("DELETE FROM audit WHERE id=4"))
        self.assertFalse(self.verify()[0])

    def test_truncating_the_tail_is_found_by_the_head_in_meta(self):
        self.fill()
        self.hub.writer.call(lambda c: c.execute("DELETE FROM audit WHERE id>4"))
        self.assertFalse(self.verify()[0])

    def test_swapping_two_rows_is_found(self):
        self.fill()
        def swap(c):
            c.execute("UPDATE audit SET id=100 WHERE id=3")
            c.execute("UPDATE audit SET id=3 WHERE id=4")
            c.execute("UPDATE audit SET id=4 WHERE id=100")
        self.hub.writer.call(swap)
        self.assertFalse(self.verify()[0])

    def test_a_gap_is_accepted_only_with_its_prune_row(self):
        self.fill(8)
        self.hub.writer.call(lambda c: c.execute("UPDATE audit SET ts=1 WHERE id IN (1,2)"))
        # the ts edit changed the rows, so rebuild honestly: delete through prune() instead
        self.hub.writer.call(lambda c: c.execute("DELETE FROM audit"))
        self.hub.writer.call(lambda c: c.execute("DELETE FROM meta WHERE key='audit_head'"))
        self.fill(8)
        old = hub_common.now_ms() - hub_audit.PRUNE_MAIN_MS - 1000
        # make the first two rows old by rebuilding the chain with old timestamps
        self.hub.writer.call(lambda c: c.execute("DELETE FROM audit"))
        self.hub.writer.call(lambda c: c.execute("DELETE FROM meta WHERE key='audit_head'"))
        for i in range(8):
            ts = old if i < 2 else hub_common.now_ms()
            self.hub.writer.call(lambda c, i=i, ts=ts: hub_audit._insert(c, ts, "cli", "d", "a%d" % i, "t", "ok", "{}"))
        self.assertEqual(self.verify(), (True, None))
        self.assertEqual(self.hub.writer.call(hub_audit.prune), 2)
        self.assertEqual(self.verify(), (True, None))
        self.assertEqual(self.hub.q("SELECT action FROM audit WHERE action='prune'")[0][0], "prune")

    def test_an_unauthenticated_failure_is_folded_but_an_operator_failure_is_not(self):
        for _ in range(50):
            self.hub.writer.call(lambda c: hub_audit.append(c, actor_kind="client", actor_detail="addr=198.51.100.1", action="enroll", outcome="denied"))
        self.hub.writer.call(lambda c: hub_audit.flush_folds(c, hub_common.now_ms() + 120000))
        self.assertLessEqual(self.hub.q("SELECT COUNT(*) FROM audit")[0][0], 2)


class AuditFloodTests(CtlCase):
    """PLAN 5 Audit: 'Denied socket commands, bad UI logins ... are recorded. Unauthenticated-failure rows are one
    row per source per minute with a count ... capped at 10,000 a day.'"""

    def test_a_dashboard_process_cannot_fill_the_audit_table_with_refusals(self):
        # hub_ctl._audit_quiet writes every refusal as its own row (actor_kind ui, so hub_audit.append never folds it)
        for i in range(300):
            self.ask("ui", "token.create", {"name": "x%d" % i}, actor={"session": "abcd1234", "addr": "127.0.0.1"})
            self.ask("ui", "login.redeem", {"code": "wrong%d" % i}, actor={"session": "abcd1234", "addr": "127.0.0.1"})
        rows = self.hub.q("SELECT COUNT(*) FROM audit")[0][0]
        self.assertLess(rows, 100, "%d audit rows from 600 refused requests in one minute" % rows)

    def test_a_junk_pending_audit_file_cannot_flood_the_audit_table_or_the_alerts(self):
        # hub_audit.ingest_pending adds a row per bad line and a HIGH notice (always=True, so no storm control) per line
        lines = [b"{}\n"] * 3000
        for i in range(3000):
            lines.append(json.dumps({"id": "id%d" % i, "op": "backup", "outcome": "started", "ts": T0, "target": "x"}).encode() + b"\n")
        with open(self.hub.paths.pending_audit, "wb") as f:
            f.write(b"".join(lines))
        self.hub.writer.call(lambda c: hub_audit.ingest_pending(c, self.hub))
        rows = self.hub.q("SELECT COUNT(*) FROM audit")[0][0]
        notices = self.hub.q("SELECT COUNT(*) FROM outbox")[0][0]
        self.assertLess(rows, 500, "%d audit rows from one ingest" % rows)
        self.assertLess(notices, 100, "%d admin notices from one ingest" % notices)

    def test_ingest_refuses_a_pending_audit_file_the_edr_hub_user_could_have_written(self):
        # PLAN 5: root:edr-hub 0640, only root appends. The code never checks owner or mode; the file sits in a
        # directory that edr-hub owns (so it can unlink and recreate it).
        with open(self.hub.paths.pending_audit, "w") as f:
            f.write(json.dumps({"id": "forged1", "op": "restore", "outcome": "ok", "ts": T0, "target": "x", "uid": 0}) + "\n")
        os.chmod(self.hub.paths.pending_audit, 0o666)
        n = self.hub.writer.call(lambda c: hub_audit.ingest_pending(c, self.hub))
        self.assertEqual(n, 0, "a world-writable pending-audit.jsonl was ingested")

    def test_a_repeated_line_id_and_a_huge_line_and_bad_json_are_handled(self):
        good = json.dumps({"id": "same", "op": "backup", "outcome": "ok", "ts": T0, "target": "x", "scheduled": True}).encode() + b"\n"
        with open(self.hub.paths.pending_audit, "wb") as f:
            f.write(good + good + b"{not json}\n" + b"y" * 20000 + b"\n" + good)
        n = self.hub.writer.call(lambda c: hub_audit.ingest_pending(c, self.hub))
        self.assertEqual(n, 1)
        ops = [r[1] for r in self.audit_rows()]
        self.assertEqual(ops.count("file-op.backup"), 1)
        self.assertEqual(ops.count("pending-audit.bad-line"), 1)         # one summary row for the bad lines of the ingest
        summary = self.hub.q("SELECT details FROM audit WHERE action='pending-audit.bad-line'")[0][0]
        self.assertEqual(json.loads(summary)["count"], 2)

    def test_the_first_scheduled_backup_of_a_day_is_quiet_and_a_second_one_is_not(self):
        def line(i, ts):
            return json.dumps({"id": "s%d" % i, "op": "backup", "outcome": "started", "ts": ts, "target": "x", "scheduled": True}) + "\n"
        now = hub_common.now_ms()
        with open(self.hub.paths.pending_audit, "w") as f:
            f.write(line(1, now - 3600_000) + line(2, now - 1800_000))
        self.hub.writer.call(lambda c: hub_audit.ingest_pending(c, self.hub))
        self.assertEqual(len(self.hub.outbox()), 1)


# =============================================================================================================
# The dashboard server
# =============================================================================================================
def free_port():
    for _ in range(100):
        port = random.randint(18000, 18999)
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
            s.close()
            return port
        except OSError:
            s.close()
    raise RuntimeError("no free port")


class FakeUiSock:
    """The hub's ui.sock for the dashboard tests: login.redeem accepts the code 'good', verbs are recorded."""

    def __init__(self, path):
        self.path = path
        self.calls = []
        self.stop = False
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path)
        self.srv.listen(8)
        self.srv.settimeout(0.1)
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop:
            try:
                conn, _ = self.srv.accept()
            except (socket.timeout, OSError):
                continue
            with conn:
                buf = b""
                while b"\n" not in buf:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                req = json.loads(buf.split(b"\n")[0])
                self.calls.append(req)
                if req["cmd"] == "login.redeem":
                    ok = req["args"].get("code") == "good"
                    reply = {"ok": True, "result": {"valid": True}} if ok else {"ok": False, "code": "denied", "error": "login refused", "exit": 3}
                else:
                    reply = {"ok": True, "result": {"done": req["cmd"]}}
                conn.sendall(json.dumps(reply).encode() + b"\n")

    def close(self):
        self.stop = True
        self.thread.join(2)
        self.srv.close()


class UiCase(HubTestCase):
    def setUp(self):
        super().setUp()
        import edr_hub_ui
        self.ui_mod = edr_hub_ui
        self.page_path = os.path.join(self.tmp, "index.html")
        shutil.copy(os.path.join(HUB_DIR, "ui", "index.html"), self.page_path)

        class P(hub_common.Paths):
            ui_index = property(lambda s, p=self.page_path: p)
        self.paths = P(state_dir=self.hub.paths.state_dir, run_dir=self.hub.paths.run_dir, etc_dir=self.hub.paths.etc_dir,
                       out_state_dir=self.hub.paths.out_state_dir, lib_dir=HUB_DIR)
        hub_common.save_settings(self.paths, hub_common.default_settings())
        self.fake = FakeUiSock(self.paths.ui_sock)
        self.addCleanup(self.fake.close)
        self.now = [1000.0]
        self.server = edr_hub_ui.UiServer(self.paths, free_port(), clock=lambda: self.now[0]).start()
        self.addCleanup(self.server.stop)
        self.port = self.server.port

    def req(self, method, path, body=None, headers=None, host=None, raw_body=None):
        h = {"Host": host if host is not None else "127.0.0.1:%d" % self.port}
        h.update(headers or {})
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=8)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for k, v in h.items():
                conn.putheader(k, v)
            data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
            if data is not None:
                conn.putheader("Content-Length", str(len(data)))
            conn.endheaders(data)
            resp = conn.getresponse()
            payload = resp.read()
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, payload
        finally:
            conn.close()

    def origin(self):
        return {"Origin": "http://127.0.0.1:%d" % self.port, "Content-Type": "application/json"}

    def login(self, code="good"):
        status, _h, body = self.req("POST", "/api/login", {"code": code}, self.origin())
        return status, (json.loads(body) if body else {})

    def auth(self, token):
        return {"Authorization": "Bearer " + token}


FIXED_HEADERS = ("content-security-policy", "x-content-type-options", "referrer-policy", "cross-origin-opener-policy",
                 "cross-origin-resource-policy", "permissions-policy")


class DashboardHttpTests(UiCase):
    def test_host_allowlist_covers_every_route_including_the_stream_and_the_page(self):
        status, body = self.login()
        token = body["token"]
        for host in ("evil.example", "evil.example:%d" % self.port, "127.0.0.1", "127.0.0.1:1", "", "localhost.evil.example:%d" % self.port):
            for method, path, extra in (("GET", "/", {}), ("GET", "/index.html", {}), ("GET", "/api/status", self.auth(token)),
                                        ("GET", "/api/stream", self.auth(token)), ("GET", "/nothing", {}),
                                        ("POST", "/api/login", self.origin())):
                status, _h, _b = self.req(method, path, {"code": "good"} if method == "POST" else None, extra, host=host)
                self.assertEqual(status, 403, "%s %s with Host %r" % (method, path, host))
        for host in ("127.0.0.1:%d" % self.port, "localhost:%d" % self.port):
            self.assertEqual(self.req("GET", "/", host=host)[0], 200)

    def test_post_needs_the_right_origin(self):
        for origin in ("http://evil.example", "http://127.0.0.1", "null", "", "https://127.0.0.1:%d" % self.port):
            status, _h, _b = self.req("POST", "/api/login", {"code": "good"}, {"Origin": origin, "Content-Type": "application/json"})
            self.assertEqual(status, 403, origin)
        status, _h, _b = self.req("POST", "/api/login", {"code": "good"}, dict(self.origin(), **{"Sec-Fetch-Site": "cross-site"}))
        self.assertEqual(status, 403)
        self.assertEqual(self.req("POST", "/api/login", {"code": "good"}, self.origin())[0], 200)

    def test_every_response_has_the_fixed_headers_and_the_csp_is_the_hash_of_the_page(self):
        status, token = self.login()
        token = token["token"]
        responses = [self.req("GET", "/"), self.req("GET", "/api/status", headers=self.auth(token)), self.req("GET", "/api/status"),
                     self.req("GET", "/missing"), self.req("GET", "/", host="evil.example"), self.req("PUT", "/api/status"),
                     self.req("POST", "/api/login", {"code": "bad"}, self.origin()), self.req("GET", "/api/event/999999", headers=self.auth(token))]
        csp = None
        for status, headers, body in responses:
            for name in FIXED_HEADERS:
                self.assertIn(name, headers, "%d response lacks %s" % (status, name))
            csp = csp or headers["content-security-policy"]
            self.assertEqual(headers["content-security-policy"], csp)
        with open(self.page_path, "rb") as f:
            self.assertEqual(csp, self.ui_mod.csp_for(f.read()))
        for status, headers, body in responses[1:]:
            if status != 200:
                self.assertEqual(headers["content-type"], "application/json")
                self.assertEqual(headers.get("cache-control"), "no-store")

    def test_the_csp_and_the_page_are_not_re_read_from_disk_after_start(self):
        status, headers, body = self.req("GET", "/")
        with open(self.page_path, "a") as f:
            f.write("<script>alert(1)</script>")
        status2, headers2, body2 = self.req("GET", "/")
        self.assertEqual(body, body2)
        self.assertEqual(headers["content-security-policy"], headers2["content-security-policy"])

    def test_no_api_route_without_a_bearer_and_no_token_in_a_query(self):
        token = self.login()[1]["token"]
        for path in ("/api/status", "/api/fleet", "/api/events", "/api/audit", "/api/settings", "/api/tokens", "/api/stream"):
            self.assertEqual(self.req("GET", path)[0], 401, path)
            self.assertEqual(self.req("GET", path + "?token=" + token)[0], 401, path)
            self.assertEqual(self.req("GET", path + "?access_token=" + token, headers={"Authorization": "Bearer short"})[0], 401)
        self.assertEqual(self.req("GET", "/api/status", headers=self.auth(token))[0], 200)

    def test_get_never_changes_state_and_unknown_methods_are_refused(self):
        token = self.login()[1]["token"]
        before = len(self.fake.calls)
        for path in ("/api/host/mark-moved", "/api/host/maintenance", "/api/logout", "/api/login"):
            self.assertIn(self.req("GET", path, headers=self.auth(token))[0], (404, 400))
        for method in ("PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            self.assertEqual(self.req(method, "/api/status", headers=self.auth(token))[0], 405)
        self.assertEqual(len(self.fake.calls), before)

    def test_only_the_three_writes_exist_and_they_need_a_session(self):
        token = self.login()[1]["token"]
        for path in ("/api/token/create", "/api/never-ban", "/api/settings", "/api/ui-login", "/api/host/revoke", "/api/host/adopt"):
            self.assertIn(self.req("POST", path, {"host": "web1"}, dict(self.origin(), **self.auth(token)))[0], (404,), path)
        self.assertEqual(self.req("POST", "/api/host/mark-moved", {"host": "web1"}, self.origin())[0], 401)
        ok = self.req("POST", "/api/host/mark-moved", {"host": "web1"}, dict(self.origin(), **self.auth(token)))
        self.assertEqual(ok[0], 200)
        self.assertEqual(self.fake.calls[-1]["cmd"], "host.mark-moved")
        self.assertEqual(self.fake.calls[-1]["args"], {"host": "web1"})

    def test_path_traversal_and_odd_paths(self):
        token = self.login()[1]["token"]
        for path in ("/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/api/host/..%2f..%2fetc", "/api/host/web1/../../x", "//etc/passwd",
                     "/static/../index.html", "/api/event/1%00", "/api/host/%0d%0aX-Evil:1"):
            status, headers, body = self.req("GET", path, headers=self.auth(token))
            self.assertIn(status, (400, 404), path)
            self.assertNotIn(b"root:", body)
            self.assertNotIn("x-evil", headers)

    def test_a_get_with_a_body_and_a_request_line_with_crlf_are_refused(self):
        token = self.login()[1]["token"]
        self.assertEqual(self.req("GET", "/api/status", headers=dict(self.auth(token), **{"Content-Length": "5"}), raw_body=b"hello")[0], 400)
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(b"GET /api/status HTTP/1.0\r\nHost: 127.0.0.1:%d\r\nX-A: 1\r\nX-A:\x00\r\n\r\n" % self.port)
        data = s.recv(65536)
        s.close()
        self.assertNotIn(b"X-A", data)

    def test_login_flow_session_and_logout(self):
        status, body = self.login("wrong")
        self.assertEqual(status, 401)
        self.assertNotIn("token", body)
        status, body = self.login()
        self.assertEqual(status, 200)
        token = body["token"]
        self.assertGreaterEqual(len(token), 43)
        self.assertEqual(self.fake.calls[-1]["actor"]["addr"], "127.0.0.1")
        self.assertNotIn(token, json.dumps(self.fake.calls))
        self.assertEqual(self.req("GET", "/api/status", headers=self.auth(token))[0], 200)
        self.assertEqual(self.req("POST", "/api/logout", {}, dict(self.origin(), **self.auth(token)))[0], 200)
        self.assertEqual(self.req("GET", "/api/status", headers=self.auth(token))[0], 401)

    def test_session_idle_and_absolute_expiry(self):
        token = self.login()[1]["token"]
        self.now[0] += 29 * 60
        self.assertEqual(self.req("GET", "/api/status", headers=self.auth(token))[0], 200)       # touched
        self.now[0] += 29 * 60
        self.assertEqual(self.req("GET", "/api/status", headers=self.auth(token))[0], 200)
        self.now[0] += 31 * 60
        self.assertEqual(self.req("GET", "/api/status", headers=self.auth(token))[0], 401)       # idle over 30 minutes
        token = self.login()[1]["token"]
        for _ in range(25):                                                                        # keep it busy past 12 hours
            self.now[0] += 29 * 60
            status = self.req("GET", "/api/status", headers=self.auth(token))[0]
            if status == 401:
                break
        self.assertEqual(status, 401)
        self.assertLess(self.now[0] - 1000.0 - 31 * 60 - 58 * 60, 13 * 3600)

    def test_streams_are_capped_per_session_and_in_all(self):
        token = self.login()[1]["token"]
        socks = []
        try:
            for _ in range(2):
                s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
                s.sendall(("GET /api/stream HTTP/1.0\r\nHost: 127.0.0.1:%d\r\nAuthorization: Bearer %s\r\n\r\n" % (self.port, token)).encode())
                self.assertIn(b"200", s.recv(200))
                socks.append(s)
            self.assertEqual(self.req("GET", "/api/stream", headers=self.auth(token))[0], 429)
            self.assertEqual(self.req("GET", "/api/status", headers=self.auth(token))[0], 200)
        finally:
            for s in socks:
                s.close()

    def test_a_login_flood_is_limited_to_five_failures_a_minute(self):
        for _ in range(5):
            self.assertEqual(self.login("wrong")[0], 401)
        self.assertEqual(self.login("wrong")[0], 429)
        self.now[0] += 61
        self.assertEqual(self.login()[0], 200)


class IndexHtmlTests(unittest.TestCase):
    """PLAN 5 Rendering rules: data enters the page only through textContent or createElement."""

    def setUp(self):
        with open(os.path.join(HUB_DIR, "ui", "index.html"), encoding="utf-8") as f:
            self.text = f.read()

    def test_no_dangerous_sink_exists(self):
        script = re.search(r"<script>(.*?)</script>", self.text, re.S).group(1)
        for sink in (r"\.innerHTML", r"insertAdjacentHTML", r"\.outerHTML", r"document\.write", r"\.setAttribute\(", r"\beval\(",
                     r"\bnew Function", r"setTimeout\(\s*['\"`]", r"setInterval\(\s*['\"`]", r"createContextualFragment", r"DOMParser",
                     r"\.srcdoc", r"\.href\s*=", r"\.src\s*=", r"localStorage", r"\.cookie", r"postMessage", r"\bimport\(", r"\.location\s*=",
                     r"window\.open", r"`"):
            self.assertIsNone(re.search(sink, script), sink)

    def test_no_inline_handlers_style_attributes_or_external_resources(self):
        body = re.sub(r"<script>.*?</script>|<style>.*?</style>", "", self.text, flags=re.S)
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", body, re.I))
        self.assertIsNone(re.search(r"\sstyle\s*=", body, re.I))
        self.assertIsNone(re.search(r"(src|href)\s*=", body, re.I))
        self.assertEqual(len(re.findall(r"<script", self.text)), 1)

    def test_the_login_code_leaves_the_url_at_once_and_the_token_lives_in_session_storage(self):
        script = re.search(r"<script>(.*?)</script>", self.text, re.S).group(1)
        self.assertLess(script.index("replaceState"), script.index("redeem(m[1])"))
        self.assertIn("sessionStorage.setItem('edr_token'", script)
        self.assertNotIn("EventSource", script)
        self.assertNotIn("?token=", script)


# =============================================================================================================
# The CLI
# =============================================================================================================
class CliCase(HubTestCase):
    def cli(self, *args, stdin=None, extra_env=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith("EDR_HUB")}
        env.update({"EDR_HUB_STATE_DIR": self.hub.paths.state_dir, "EDR_HUB_RUN_DIR": self.hub.paths.run_dir,
                    "EDR_HUB_ETC_DIR": self.hub.paths.etc_dir, "EDR_HUB_OUT_STATE_DIR": self.hub.paths.out_state_dir})
        env.update(extra_env or {})
        return subprocess.run([sys.executable, "-I", EDR_HUB, *args], input=stdin, capture_output=True, text=True, env=env, timeout=60)


class CliSafetyTests(CliCase):
    def setUp(self):
        super().setUp()
        self.host = self.hub.add_host("web1", reported_name=HOSTILE, os=HOSTILE, kernel=HOSTILE, agent_version=HOSTILE,
                                      agent_sha256=HOSTILE, enrolled_from=HOSTILE, cert_serial=HOSTILE,
                                      peer_ips=json.dumps([HOSTILE]), ips=json.dumps([HOSTILE]))
        self.hub.add_event(self.host, HOSTILE.replace("\x00", "")[:60].lower() and "tetragon.nginx-exec", "CRITICAL", summary=HOSTILE,
                           src_ip=HOSTILE, details={"proc": {"binary": HOSTILE, "args": HOSTILE}})
        self.hub.writer.call(lambda c: c.execute(
            "INSERT INTO incidents (host, chain, opened, updated, state, severity, kinds, signals, title) VALUES (?,?,?,?,?,?,?,?,?)",
            (self.host["uuid"], HOSTILE, T0, T0, "open", "HIGH", json.dumps([HOSTILE]), 1, HOSTILE)))
        self.hub.writer.call(lambda c: hub_audit.append(c, actor_kind="ui", actor_detail=HOSTILE, action=HOSTILE, target=HOSTILE,
                                                        details={"x": HOSTILE}))
        self.hub.writer.call(lambda c: c.execute("INSERT INTO never_ban (cidr, reason, added_by, ts) VALUES ('198.51.100.0/24', ?, ?, ?)", (HOSTILE, HOSTILE, T0)))
        self.hub.writer.call(lambda c: c.execute(
            "INSERT INTO tokens (id, secret_sha256, name, created_at, created_by, expires_at) VALUES (?,?,?,?,?,?)",
            (HOSTILE, "0" * 64, HOSTILE, T0, HOSTILE, T0 + 10 ** 9)))
        self.hub.writer.call(lambda c: c.execute("INSERT INTO outbox (created, channel, severity, payload, attempts, next_try, state, last_error) VALUES (?,?,?,?,?,?,?,?)",
                                                 (T0, "webhook", "HIGH", "{}", 2, T0, "failed", HOSTILE)))
        s = hub_common.default_settings()
        s["secrets_set"] = {"webhook_url": HOSTILE}
        hub_common.save_settings(self.hub.paths, s)

    def assertSafe(self, text, what):
        for ch in text:
            cp = ord(ch)
            self.assertFalse(cp < 32 and ch not in "\n" or 0x7F <= cp <= 0x9F or cp in (0x202E, 0x200B, 0x2028, 0x2029),
                             "%s: raw U+%04X on the terminal" % (what, cp))

    def test_no_escape_sequence_from_a_field_reaches_the_terminal_on_any_command(self):
        for args in (("events",), ("events", "--json"), ("events", "--host", "web1"), ("incidents",), ("incidents", "--json"),
                     ("incident", "1"), ("incident", "1", "--json"), ("host", "list"), ("host", "list", "--json"), ("host", "web1", "show"),
                     ("host", "web1", "show", "--json"), ("audit",), ("audit", "--json"), ("never-ban", "list"), ("token", "list"),
                     ("token", "list", "--json"), ("settings", "get"), ("status",)):
            r = self.cli(*args)
            self.assertSafe(r.stdout, " ".join(args))
            self.assertSafe(r.stderr, " ".join(args))
        r = self.cli("events", "--json")
        self.assertEqual(r.returncode, 0)
        json.loads(r.stdout.splitlines()[0])

    def test_a_secret_is_never_taken_from_argv_and_never_echoed(self):
        r = self.cli("settings", "set", "webhook_url", "https://hooks.example.com/SECRETPATH")
        self.assertEqual(r.returncode, hub_common.EXIT_REFUSED)
        self.assertNotIn("SECRETPATH", r.stdout + r.stderr)
        self.assertFalse(os.path.exists(self.hub.paths.secrets))

    def test_a_secret_written_from_stdin_stays_out_of_settings_and_audit(self):
        # no hub runs here, so the write is refused early; nothing may have been written
        r = self.cli("settings", "set", "ntfy_topic", "-", stdin="topic-SECRET-123\n")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("topic-SECRET-123", r.stdout + r.stderr)
        self.assertFalse(os.path.exists(self.hub.paths.secrets))

    def test_exit_codes(self):
        self.assertEqual(self.cli().returncode, hub_common.EXIT_USAGE)
        self.assertEqual(self.cli("nonsense").returncode, hub_common.EXIT_USAGE)
        self.assertEqual(self.cli("events", "--bogus").returncode, hub_common.EXIT_USAGE)
        self.assertEqual(self.cli("host", "nosuchhost", "show").returncode, hub_common.EXIT_REFUSED)
        self.assertEqual(self.cli("health").returncode, hub_common.EXIT_FAIL)         # the writer never reported
        self.assertEqual(self.cli("resolve", "1").returncode, hub_common.EXIT_FAIL)   # no hub on ctl.sock

    def test_must_be_root_applies_to_the_installed_paths_only(self):
        if os.geteuid() == 0:
            self.skipTest("this test runs as root")
        r = self.cli("backup", extra_env={"EDR_HUB_STATE_DIR": "", "EDR_HUB_RUN_DIR": "", "EDR_HUB_ETC_DIR": ""})
        self.assertEqual(r.returncode, hub_common.EXIT_REFUSED)
        self.assertIn("root", r.stderr)


# =============================================================================================================
# Backup and restore (real openssl, real hub_pki, temp directories)
# =============================================================================================================
class BackupCase(unittest.TestCase):
    PASSPHRASE = "the backup passphrase of this test, long enough\n"

    def setUp(self):
        import hub_backup
        import hub_pki
        self.hub_backup, self.hub_pki = hub_backup, hub_pki
        self.tmp = tempfile.mkdtemp(prefix="edr-review-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        t = self.tmp
        for sub in ("state", "run", "etc", "bk", "out"):
            os.makedirs(os.path.join(t, sub), mode=0o750)
        self.paths = hub_common.Paths(state_dir=t + "/state", run_dir=t + "/run", etc_dir=t + "/etc", backup_dir=t + "/bk",
                                      out_state_dir=t + "/out", lib_dir=HUB_DIR)
        hub_pki.init_ca(self.paths)
        db = sqlite3.connect(self.paths.db)
        db.executescript(hub_schema.DDL)
        db.execute("INSERT INTO meta (key, value) VALUES ('schema_version', ?)", (str(hub_schema.SCHEMA_VERSION),))
        db.execute("INSERT INTO tokens (id, secret_sha256, name, created_at, expires_at) VALUES ('tok1', ?, 'web9', ?, ?)", ("0" * 64, T0, T0 + 10 ** 12))
        db.execute("INSERT INTO login_codes (code_sha256, created, expires) VALUES (?,?,?)", ("1" * 64, T0, T0 + 10 ** 12))
        db.commit()
        db.close()
        settings = hub_common.default_settings()
        settings["public_ip"] = ["127.0.0.1"]
        settings["secrets_set"] = {"webhook_url": "hooks.example.com ...abcd"}
        hub_common.save_settings(self.paths, settings)
        with open(self.paths.backup_pass, "w") as f:
            f.write(self.PASSPHRASE)
        os.chmod(self.paths.backup_pass, 0o600)
        with open(self.paths.secrets, "w") as f:
            json.dump({"webhook_url": "https://hooks.example.com/SECRETPATH"}, f)
        os.chmod(self.paths.secrets, 0o600)
        self.logs = []
        self.log = self.logs.append

    def backup(self, name="one.bak"):
        out = os.path.join(self.tmp, "bk", name)
        self.assertEqual(self.hub_backup.backup(self.paths, out=out, scheduled=False, log=self.log), 0, self.logs)
        return out

    def restore(self, file, **kw):
        return self.hub_backup.restore(self.paths, file, log=self.log, **kw)


class BackupTests(BackupCase):
    def test_backup_file_is_private_encrypted_and_holds_no_ca_or_server_key(self):
        out = self.backup()
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)
        with open(out, "rb") as f:
            raw = f.read()
        self.assertNotIn(b"SECRETPATH", raw)
        self.assertNotIn(b"BEGIN", raw)
        stage = os.path.join(self.tmp, "peek")
        os.makedirs(stage)
        manifest = self.hub_backup._unpack(out, self.paths.backup_pass, stage)
        names = set(manifest["files"])
        self.assertEqual(names, {"hub.db", "settings.json", "secrets.json", "never-ban.json", "hub-addresses.json", "ca/ca.pem", "ca/revoked.txt"})
        for root, _d, files in os.walk(stage):
            for fn in files:
                with open(os.path.join(root, fn), "rb") as f:
                    self.assertNotIn(b"PRIVATE KEY", f.read(), fn)
        self.assertEqual(os.listdir(os.path.join(self.tmp, "bk")), ["one.bak"])       # no temp left behind

    def test_the_passphrase_is_on_no_command_line(self):
        calls = []
        real = subprocess.Popen

        def spy(args, *a, **kw):
            calls.append(list(args))
            return real(args, *a, **kw)
        old = subprocess.Popen
        subprocess.Popen = spy
        try:
            self.backup()
        finally:
            subprocess.Popen = old
        self.assertTrue(calls)
        for args in calls:
            self.assertNotIn(self.PASSPHRASE.strip(), " ".join(args))
            self.assertIn("file:" + self.paths.backup_pass, args)

    def test_ca_export_passphrase_goes_over_a_pipe_and_the_file_is_private(self):
        out = os.path.join(self.tmp, "bk", "ca.enc")
        seen = []
        real = subprocess.run

        def spy(args, *a, **kw):
            seen.append(list(args))
            return real(args, *a, **kw)
        old = subprocess.run
        subprocess.run = spy
        try:
            code = self.hub_backup.ca_export(self.paths, "correct horse battery staple", out=out, log=self.log)
        finally:
            subprocess.run = old
        self.assertEqual(code, 0, self.logs)
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)
        self.assertIn(b"ENCRYPTED PRIVATE KEY", open(out, "rb").read())
        for args in seen:
            self.assertNotIn("correct horse battery staple", " ".join(args))
        self.assertEqual(self.hub_backup.ca_export(self.paths, "short", out=out + "2", log=self.log), 3)
        self.assertEqual(self.hub_backup.ca_export(self.paths, "correct horse battery staple", out=out, log=self.log), 3)   # exists

    def test_restore_marks_tokens_invalid_clears_login_codes_and_reissues_the_server_certificate(self):
        out = self.backup()
        os.unlink(self.paths.db)
        self.assertEqual(self.restore(out), 0, self.logs)
        db = sqlite3.connect(self.paths.db)
        self.assertIsNotNone(db.execute("SELECT revoked_at FROM tokens WHERE id='tok1'").fetchone()[0])
        self.assertEqual(db.execute("SELECT COUNT(*) FROM login_codes").fetchone()[0], 0)
        self.assertIsNotNone(db.execute("SELECT value FROM meta WHERE key='restored_at'").fetchone())
        db.close()
        self.assertTrue(os.path.exists(self.paths.server_cert))

    def test_drill_does_not_write_secrets(self):
        out = self.backup()
        os.unlink(self.paths.secrets)
        self.assertEqual(self.restore(out, drill=True), 0, self.logs)
        self.assertFalse(os.path.exists(self.paths.secrets))
        self.assertEqual(hub_common.load_settings(self.paths)["secrets_set"], {})
        self.assertEqual(self.restore(out), 0, self.logs)
        self.assertTrue(os.path.exists(self.paths.secrets))
        self.assertEqual(stat.S_IMODE(os.stat(self.paths.secrets).st_mode), 0o600)

    def test_restore_refuses_while_the_hub_runs(self):
        out = self.backup()
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.paths.ctl_sock)
        srv.listen(1)
        self.addCleanup(srv.close)
        before = open(self.paths.settings).read()
        self.assertEqual(self.restore(out), 3)
        self.assertEqual(open(self.paths.settings).read(), before)

    def test_restore_refuses_a_mismatched_ca_key_and_changes_nothing(self):
        out = self.backup()
        shutil.rmtree(self.paths.ca_dir)
        other = hub_common.Paths(state_dir=self.tmp + "/other", run_dir=self.tmp + "/run", etc_dir=self.tmp + "/etc", lib_dir=HUB_DIR)
        os.makedirs(other.state_dir)
        self.hub_pki.init_ca(other)
        shutil.copytree(other.ca_dir, self.paths.ca_dir)
        db_before = open(self.paths.db, "rb").read()
        self.assertEqual(self.restore(out), 3, self.logs)
        self.assertEqual(open(self.paths.db, "rb").read(), db_before)
        self.assertTrue(any("CA" in line for line in self.logs))

    def test_a_hostile_archive_is_refused_before_anything_is_written(self):
        # a valid container (right passphrase) holding a symlink, a traversal name, a device node or a surprise member
        import io
        import tarfile
        for label, build in (("symlink", lambda t: self._add(t, "hub.db", link="/etc/passwd")),
                             ("traversal", lambda t: self._add(t, "../evil", data=b"x")),
                             ("absolute", lambda t: self._add(t, "/etc/evil", data=b"x")),
                             ("device", lambda t: self._add(t, "hub.db", dev=True)),
                             ("surprise", lambda t: self._add(t, "extra.txt", data=b"x"))):
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w") as tar:
                self._add(tar, "MANIFEST.json", data=json.dumps({"format": 1, "files": {}}).encode())
                build(tar)
            enc = subprocess.run(["openssl", *self.hub_backup.CIPHER, "-pass", "file:" + self.paths.backup_pass], input=raw.getvalue(),
                                 capture_output=True, check=True).stdout
            path = os.path.join(self.tmp, "evil-%s.bak" % label)
            with open(path, "wb") as f:
                f.write(enc + self.hub_backup.TRAILER + hashlib.sha256(enc).hexdigest().encode() + b"\n")
            keep = lambda: sorted(n for n in os.listdir(self.paths.state_dir) if n != "pending-audit.jsonl")
            state_before = keep()
            self.assertEqual(self.restore(path), 2, label)
            self.assertEqual(keep(), state_before, label)
            self.assertFalse(os.path.exists("/etc/evil"), label)
            self.assertFalse(os.path.exists(os.path.join(self.tmp, "evil")), label)

    @staticmethod
    def _add(tar, name, data=None, link=None, dev=False):
        import io
        import tarfile
        info = tarfile.TarInfo(name)
        if link:
            info.type, info.linkname = tarfile.SYMTYPE, link
            tar.addfile(info)
        elif dev:
            info.type, info.devmajor, info.devminor = tarfile.CHRTYPE, 1, 3
            tar.addfile(info)
        else:
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

    def test_damaged_and_wrong_passphrase_backups_are_refused(self):
        out = self.backup()
        raw = bytearray(open(out, "rb").read())
        raw[100] ^= 1
        bad = os.path.join(self.tmp, "bad.bak")
        open(bad, "wb").write(raw)
        self.assertEqual(self.restore(bad), 2)
        with open(self.paths.backup_pass, "w") as f:
            f.write("a different passphrase entirely\n")
        self.assertEqual(self.restore(out), 2)


class BackupSymlinkDefects(BackupCase):
    """Root works inside /var/lib/edr-hub, a directory the edr-hub user owns. The names root creates there are predictable
    and are opened without O_EXCL or O_NOFOLLOW, and chown/chmod follow links."""

    def test_restore_does_not_follow_a_symlink_planted_at_its_temp_name(self):
        out = self.backup()
        victim = os.path.join(self.tmp, "victim.txt")
        with open(victim, "w") as f:
            f.write("VICTIM")
        for name in ("settings.json.restore-new", "hub.db.restore-new", "ca/ca.pem.restore-new", "ca/revoked.txt.restore-new"):
            os.symlink(victim, os.path.join(self.paths.state_dir, name))
        self.restore(out)
        with open(victim) as f:
            self.assertEqual(f.read(), "VICTIM", "root wrote through a symlink an attacker planted in the state directory")

    def test_backup_does_not_read_through_a_symlinked_settings_file(self):
        # settings.json, ca/ca.pem and ca/revoked.txt are read with open(): a link in the edr-hub-owned directory
        # makes root copy any file into the (encrypted, but operator-readable) backup
        secret = os.path.join(self.tmp, "shadow.txt")
        with open(secret, "w") as f:
            f.write("ROOTONLY-CONTENT")
        os.unlink(self.paths.revoked) if os.path.exists(self.paths.revoked) else None
        os.symlink(secret, self.paths.revoked)
        out = self.backup()
        stage = os.path.join(self.tmp, "peek")
        os.makedirs(stage)
        self.hub_backup._unpack(out, self.paths.backup_pass, stage)
        with open(os.path.join(stage, "ca", "revoked.txt")) as f:
            self.assertNotIn("ROOTONLY-CONTENT", f.read())


# =============================================================================================================
# uninstall.sh (only --plan is ever run; the confirmation logic is read, not executed)
# =============================================================================================================
class UninstallCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="edr-review-un-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.dirs = {k: os.path.join(self.tmp, k) for k in ("state", "run", "etc", "bk", "out")}
        for d in self.dirs.values():
            os.makedirs(d)

    def plan(self, *flags):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "EDR_HUB_STATE_DIR": self.dirs["state"], "EDR_HUB_RUN_DIR": self.dirs["run"],
               "EDR_HUB_ETC_DIR": self.dirs["etc"], "EDR_HUB_BACKUP_DIR": self.dirs["bk"], "EDR_HUB_OUT_STATE_DIR": self.dirs["out"]}
        return subprocess.run(["bash", UNINSTALL, "--plan", *flags], capture_output=True, text=True, env=env, timeout=60)

    def manifest(self, *items):
        with open(os.path.join(self.dirs["etc"], "manifest.jsonl"), "w") as f:
            for item in items:
                f.write(json.dumps(item) + "\n")

    def test_plan_changes_nothing_and_needs_no_root(self):
        self.manifest({"kind": "file", "path": self.dirs["etc"] + "/edr-hub.nft", "prior": "absent"})
        open(self.dirs["etc"] + "/edr-hub.nft", "w").write("x")
        r = self.plan("--purge", "--yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(self.dirs["etc"] + "/edr-hub.nft"))
        self.assertIn("ask twice", r.stdout)

    def test_a_manifest_line_outside_the_owned_set_is_refused(self):
        for path in ("/etc/passwd", "/etc/edr-hub/../passwd", "/usr/local/lib/edr-hub/../../../etc/passwd", "/etc/systemd/system/other.service",
                     "/usr/local/lib/edr-hubx/f", self.dirs["etc"] + "/dir/", self.dirs["etc"] + "//x", "/etc/edr\u2024\u2024hub/x",
                     "relative/path", self.dirs["etc"] + "/a b", self.dirs["etc"] + "/x\u2025y"):
            self.manifest({"kind": "file", "path": path, "prior": "absent"})
            r = self.plan()
            self.assertEqual(r.returncode, 3, "%r: %s" % (path, r.stdout))
            self.assertIn("REFUSE", r.stdout)

    def test_a_path_through_a_symlinked_parent_directory_is_not_treated_as_owned(self):
        # owned() in uninstall.sh is lexical: a link inside the owned tree makes `rm -f` reach outside it
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        open(os.path.join(outside, "precious"), "w").write("keep")
        os.symlink(outside, self.dirs["etc"] + "/lnk")
        self.manifest({"kind": "file", "path": self.dirs["etc"] + "/lnk/precious", "prior": "absent"})
        r = self.plan()
        self.assertNotIn("remove %s" % (self.dirs["etc"] + "/lnk/precious"), r.stdout)

    def test_the_final_file_being_a_symlink_is_left_alone(self):
        open(self.tmp + "/target", "w").write("x")
        os.symlink(self.tmp + "/target", self.dirs["etc"] + "/edr-hub.nft")
        self.manifest({"kind": "file", "path": self.dirs["etc"] + "/edr-hub.nft", "prior": "absent"})
        r = self.plan()
        self.assertIn("leave %s: it is not the file the kit wrote" % (self.dirs["etc"] + "/edr-hub.nft"), r.stdout)

    def test_system_directories_are_never_accepted_as_the_state_directory(self):
        for bad in ("/", "/etc", "/var/lib", "/usr/local/lib", "relative", "/var/lib/edr hub", "/var/lib/../etc"):
            env = {"PATH": os.environ["PATH"], "EDR_HUB_STATE_DIR": bad}
            r = subprocess.run(["bash", UNINSTALL, "--plan"], capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(r.returncode, 3, bad)

    def test_purge_with_yes_still_asks_the_two_purge_questions(self):
        # PLAN 9: '--purge ... It asks twice.' confirm() answers every question under --yes, the purge ones included.
        # Only the function is run, with the two purge prompts and no terminal: it must not agree by itself.
        text = open(UNINSTALL).read()
        func = re.search(r"^confirm\(\) \{.*?^\}", text, re.S | re.M).group(0)
        calls = re.findall(r"^\s*confirm (\"Type 'purge' to go on:\" purge|\"Last chance[^\"]*\" \"delete everything\")", text, re.M)
        self.assertEqual(len(calls), 2)
        for call in calls:
            r = subprocess.run(["bash", "-c", "ASSUME_YES=1\n%s\nconfirm %s" % (func, call)], capture_output=True, text=True,
                               stdin=subprocess.DEVNULL, timeout=20)
            self.assertNotEqual(r.returncode, 0, "--yes answered a purge question: " + call)

    def test_nothing_destructive_happens_before_the_confirmations(self):
        text = open(UNINSTALL).read()
        first_change = min(text.index(m) for m in ('say "Step 1: final backup"', 'rm -rf', 'systemctl disable', 'userdel', 'nft delete')
                           if m in text.split("# ---- from here on the script changes things")[1])
        before = text.split("# ---- from here on the script changes things")[1][:text.split("# ---- from here on the script changes things")[1].index('say "Step 1: final backup"')]
        for word in ("rm -rf", "rm -f", "systemctl", "userdel", "groupdel", "nft delete", "cp -p"):
            self.assertNotIn(word, before, word)
        self.assertIn("confirm \"Continue?", before)


if __name__ == "__main__":
    unittest.main()
