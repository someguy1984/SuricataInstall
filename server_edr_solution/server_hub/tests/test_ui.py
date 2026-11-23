"""The dashboard server against a real database file and a real ui.sock served by hub_ctl (PLAN section 5; 12 L0)."""

import base64
import hashlib
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_ctl_support as S  # noqa: E402

import edr_hub_ui  # noqa: E402
import hub_common  # noqa: E402
import hub_ctl  # noqa: E402

NASTY = "evil \x1b[31mred\x1b]8;;http://x\x07link ‮drow ​zw \x7f <img src=x onerror=alert(1)> end"
PAGE_PATH = os.path.join(S.HUB_DIR, "ui", "index.html")


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


class UiCase(S.HubTestCase):
    def setUp(self):
        super().setUp()
        self.socks = hub_ctl.Sockets(self.hub)
        self.socks.start()
        self.addCleanup(self.socks.stop)
        self.clock = Clock()
        self.start_ui()
        self.uuid = S.add_host(self.hub.db, "web-1")

    def start_ui(self):
        self.ui = edr_hub_ui.UiServer(self.paths, 0, clock=self.clock)
        self.ui.start()
        self.addCleanup(self.ui.stop)
        self.port = self.ui.port

    def conn(self, timeout=5):
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)

    def req(self, method, path, token=None, body=None, headers=None, post_ok=True):
        h = {}
        if method == "POST" and post_ok:
            h["Origin"] = "http://127.0.0.1:%d" % self.port
            h["Content-Type"] = "application/json"
        if token:
            h["Authorization"] = "Bearer " + token
        h.update(headers or {})
        c = self.conn()
        try:
            data = None
            if body is not None:
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
            c.request(method, path, body=data, headers=h)
            r = c.getresponse()
            raw = r.read()
            return r.status, r, raw
        finally:
            c.close()

    def jreq(self, *a, **kw):
        status, r, raw = self.req(*a, **kw)
        return status, (json.loads(raw) if raw else None)

    def mint(self):
        reply = S.ctl(self.paths, "ui-login.mint")
        return reply["result"]["code"]

    def login(self):
        status, body = self.jreq("POST", "/api/login", body={"code": self.mint()})
        self.assertEqual(status, 200, body)
        return body["token"]

    def event(self, kind="ssh.fail", sev="HIGH", summary="s", host=None, source="journal", count=1, details=None):
        cur = self.hub.db.execute(
            "INSERT INTO events (host, event_id, received_at, ts, source, severity, hub_severity, kind, summary, details, epoch, seq, count, src_ip) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (host or self.uuid, "%08x:%d" % (1, self.hub.db.execute("SELECT COALESCE(MAX(id),0)+1 FROM events").fetchone()[0]),
             hub_common.now_ms(), 1, source, sev, sev, kind, summary, json.dumps(details or {"k": summary}), 1, 1, count, "198.51.100.9"))
        return cur.lastrowid


class RequestCheckTests(UiCase):
    def test_wrong_or_missing_host_is_403(self):
        token = self.login()
        for host in ("evil.example", "127.0.0.1", "127.0.0.1:1", "localhost", "127.0.0.1:%d.evil.example" % self.port, ""):
            status, body = self.jreq("GET", "/api/status", token=token, headers={"Host": host})
            self.assertEqual(status, 403, host)
            self.assertEqual(body, {"error": "forbidden"})
        status, _ = self.jreq("GET", "/", headers={"Host": "evil.example"})
        self.assertEqual(status, 403)
        status, _ = self.jreq("GET", "/api/status", token=token, headers={"Host": "localhost:%d" % self.port})
        self.assertEqual(status, 200)

    def test_host_allowlist_follows_ui_host_setting(self):
        self.hub.update_settings(dict(self.hub.settings, ui_host=["127.0.0.1:9999"]))
        self.ui.stop()
        self.start_ui()
        status, _ = self.jreq("GET", "/", headers={"Host": "127.0.0.1:%d" % self.port})
        self.assertEqual(status, 403)
        status, _, _ = self.req("GET", "/", headers={"Host": "127.0.0.1:9999"})
        self.assertEqual(status, 200)

    def test_wrong_origin_on_post_is_403(self):
        token = self.login()
        for origin in ("http://evil.example", "http://127.0.0.1:1", "https://127.0.0.1:%d" % self.port, "null", "http://localhost"):
            status, _ = self.jreq("POST", "/api/logout", token=token, body={}, headers={"Origin": origin})
            self.assertEqual(status, 403, origin)
        status, _ = self.jreq("POST", "/api/logout", token=token, body={}, headers={"Origin": ""})
        self.assertEqual(status, 403)
        c = self.conn()
        c.request("POST", "/api/logout", body=b"{}", headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        self.assertEqual(c.getresponse().status, 403)                      # no Origin at all
        c.close()
        status, _ = self.jreq("POST", "/api/login", body={"code": "x"}, headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 403)

    def test_sec_fetch_site_cross_site_is_refused(self):
        token = self.login()
        for value in ("cross-site", "same-site"):
            status, _ = self.jreq("POST", "/api/logout", token=token, body={}, headers={"Sec-Fetch-Site": value})
            self.assertEqual(status, 403, value)
        status, _ = self.jreq("POST", "/api/logout", token=token, body={}, headers={"Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 200)

    def test_missing_or_bad_bearer_is_401(self):
        for path in ("/api/status", "/api/fleet", "/api/events", "/api/stream", "/api/settings", "/api/event/1"):
            status, body = self.jreq("GET", path)
            self.assertEqual((status, body), (401, {"error": "login required"}), path)
        for bad in ("nope", "x" * 40, "Basic abc", "a b"):
            status, _ = self.jreq("GET", "/api/status", headers={"Authorization": bad})
            self.assertEqual(status, 401, bad)
        status, _ = self.jreq("GET", "/api/status", token="A" * 43)
        self.assertEqual(status, 401)
        status, _ = self.jreq("POST", "/api/logout", body={})
        self.assertEqual(status, 401)
        status, _ = self.jreq("POST", "/api/host/mark-moved", body={"host": "web-1"})
        self.assertEqual(status, 401)
        self.assertEqual(self.rows("SELECT state FROM hosts")[0]["state"], "active")

    def test_post_content_type_length_and_body_checks(self):
        token = self.login()
        status, _ = self.jreq("POST", "/api/logout", token=token, body={}, headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 415)
        status, _ = self.jreq("POST", "/api/host/maintenance", token=token, body=b"x" * (16 * 1024 + 1))
        self.assertEqual(status, 413)
        status, _ = self.jreq("POST", "/api/host/maintenance", token=token, body=b"{not json")
        self.assertEqual(status, 400)
        status, _ = self.jreq("POST", "/api/host/maintenance", token=token, body=b"[1]")
        self.assertEqual(status, 400)
        status, _ = self.jreq("POST", "/api/host/maintenance", token=token, body=b"\xff\xfe")
        self.assertEqual(status, 400)
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)         # no Content-Length at all
        s.sendall(("POST /api/logout HTTP/1.0\r\nHost: 127.0.0.1:%d\r\nOrigin: http://127.0.0.1:%d\r\n"
                   "Content-Type: application/json\r\nAuthorization: Bearer %s\r\n\r\n" % (self.port, self.port, token)).encode())
        self.assertIn(b" 411 ", s.recv(4096).split(b"\r\n")[0])
        s.close()

    def test_a_get_with_a_body_is_refused(self):
        token = self.login()
        status, _ = self.jreq("GET", "/api/status", token=token, body=b"{}")
        self.assertEqual(status, 400)

    def test_other_methods_and_unknown_paths(self):
        token = self.login()
        for method in ("PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
            status, _, _ = self.req(method, "/api/status", token=token)
            self.assertEqual(status, 405, method)
        status, body = self.jreq("GET", "/api/<script>alert(1)</script>", token=token)
        self.assertEqual((status, body), (404, {"error": "not found"}))
        self.assertNotIn(b"script", self.req("GET", "/api/<script>x</script>", token=token)[2])
        self.assertEqual(self.jreq("GET", "/nothing", token=token)[0], 404)
        self.assertEqual(self.jreq("GET", "/api/event/abc", token=token)[0], 404)
        self.assertEqual(self.jreq("GET", "/api/host/a%20b", token=token)[0], 404)
        self.assertEqual(self.jreq("POST", "/api/tokens", token=token, body={"name": "x"})[0], 404)   # creating is CLI only

    def test_garbage_request_line_gets_fixed_json(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(b"EVIL <b>x</b>\r\n\r\n")
        data = s.recv(4096)
        s.close()
        self.assertIn(b"bad request", data)                                # a fixed JSON body, whatever the request said
        self.assertNotIn(b"<b>", data)
        self.assertNotIn(b"EVIL", data)

    def test_a_trickling_client_is_cut_by_the_wall_clock_deadline(self):
        with mock.patch("edr_hub_ui.HANDLER_DEADLINE_S", 1), mock.patch.object(edr_hub_ui.Handler, "timeout", 30):
            s = socket.create_connection(("127.0.0.1", self.port), timeout=6)
            t0 = time.monotonic()
            try:
                for ch in b"GET / HTTP/1.0\r\nX-A: ":                  # one byte every 0.2 s keeps every read alive
                    s.send(bytes([ch]))
                    time.sleep(0.2)
                data = s.recv(100)                                      # the deadline timer has shut the socket down
            except OSError:
                data = b""
            finally:
                s.close()
        self.assertEqual(data, b"")
        self.assertLess(time.monotonic() - t0, 4)

    def test_connection_cap(self):
        self.ui.stop()
        with mock.patch("edr_hub_ui.CONNECTIONS_MAX", 2):
            self.start_ui()
        held = [socket.create_connection(("127.0.0.1", self.port), timeout=5) for _ in range(2)]
        time.sleep(0.3)
        third = socket.create_connection(("127.0.0.1", self.port), timeout=3)
        third.settimeout(3)
        try:
            data = third.recv(10)
        except OSError:
            data = b""
        self.assertEqual(data, b"")
        third.close()
        for s in held:
            s.close()


class HeaderTests(UiCase):
    def inline_hashes(self):
        with open(PAGE_PATH, encoding="utf-8") as f:
            page = f.read()
        js = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
        css = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
        h = lambda text: "'sha256-%s'" % base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()
        return h(js), h(css)

    def test_csp_matches_the_inline_blocks_of_the_page(self):
        js, css = self.inline_hashes()
        status, r, body = self.req("GET", "/")
        self.assertEqual(status, 200)
        csp = r.getheader("Content-Security-Policy")
        self.assertEqual(csp, "default-src 'none'; script-src %s; style-src %s; connect-src 'self'; img-src 'self'; base-uri 'none'; "
                              "form-action 'none'; frame-ancestors 'none'; object-src 'none'" % (js, css))
        with open(PAGE_PATH, "rb") as f:
            self.assertEqual(body, f.read())
        self.assertEqual(r.getheader("Content-Type"), "text/html; charset=utf-8")

    def test_csp_follows_the_page_content(self):
        a = edr_hub_ui.csp_for(b"<style>a{}</style><script>1</script>")
        b = edr_hub_ui.csp_for(b"<style>a{}</style><script>2</script>")
        self.assertNotEqual(a, b)
        for bad in (b"<script>1</script>", b"<style>a{}</style><script>1</script><script>2</script>",
                    b"<style>a{}</style><script src=x></script>", b"<style>a{}</style><style>b{}</style><script>1</script>"):
            with self.assertRaises(SystemExit):
                edr_hub_ui.csp_for(bad)

    def test_fixed_headers_on_every_kind_of_response(self):
        token = self.login()
        for status, r, _ in (self.req("GET", "/"), self.req("GET", "/api/status", token=token), self.req("GET", "/api/status"),
                             self.req("GET", "/nothing", token=token), self.req("GET", "/", headers={"Host": "evil.example"})):
            self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
            self.assertEqual(r.getheader("Referrer-Policy"), "no-referrer")
            self.assertEqual(r.getheader("Cross-Origin-Opener-Policy"), "same-origin")
            self.assertEqual(r.getheader("Cross-Origin-Resource-Policy"), "same-origin")
            self.assertIn("camera=()", r.getheader("Permissions-Policy"))
            self.assertIn("script-src 'sha256-", r.getheader("Content-Security-Policy"))
            self.assertIsNone(r.getheader("Access-Control-Allow-Origin"))
            self.assertIsNone(r.getheader("Strict-Transport-Security"))
            self.assertIsNone(r.getheader("Set-Cookie"))
        status, r, _ = self.req("GET", "/api/status", token=token)
        self.assertEqual(r.getheader("Cache-Control"), "no-store")
        self.assertEqual(r.getheader("Content-Type"), "application/json")
        self.assertNotIn("Python", r.getheader("Server") or "")

    def test_the_server_binds_loopback_only(self):
        self.assertEqual(self.ui.httpd.server_address[0], "127.0.0.1")


class StaticPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(PAGE_PATH, encoding="utf-8") as f:
            cls.page = f.read()
        cls.markup = re.sub(r"<script>.*?</script>", "<script></script>", cls.page, flags=re.S)
        cls.markup = re.sub(r"<style>.*?</style>", "<style></style>", cls.markup, flags=re.S)

    def test_exactly_one_inline_script_and_one_inline_style(self):
        self.assertEqual(len(re.findall(r"<script\b", self.page, re.I)), 1)
        self.assertEqual(len(re.findall(r"<style\b", self.page, re.I)), 1)
        self.assertIsNotNone(re.search(r"<script>", self.page))
        self.assertIsNotNone(re.search(r"<style>", self.page))
        self.assertNotIn("<link", self.page.lower())
        self.assertNotIn("<iframe", self.page.lower())

    def test_no_style_attributes_and_no_inline_handlers(self):
        self.assertIsNone(re.search(r"\sstyle\s*=", self.markup, re.I))
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", self.markup, re.I))
        self.assertIsNone(re.search(r"\.style\b|setAttribute\s*\(\s*['\"](style|on)", self.page))
        self.assertIsNone(re.search(r"\bon[a-z]+\s*=", self.page))                 # not in the script either

    def test_no_markup_injection_apis(self):
        for word in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "EventSource",
                     "localStorage", "createContextualFragment", "srcdoc", "javascript:"):
            self.assertNotIn(word, self.page, word)
        self.assertIn("textContent", self.page)
        self.assertIn("createElement", self.page)

    def test_no_external_urls_no_data_in_href_or_src(self):
        self.assertIsNone(re.search(r"https?://", self.page))
        self.assertIsNone(re.search(r"//[a-z0-9.-]+\.[a-z]{2,}", self.markup, re.I))
        self.assertIsNone(re.search(r"\b(href|src|action)\s*=", self.markup, re.I))
        self.assertIsNone(re.search(r"setAttribute", self.page))

    def test_the_login_code_leaves_the_url_at_once(self):
        self.assertLess(self.page.index("replaceState"), self.page.index("redeem(m[1])"))
        self.assertIn("window.location.hash", self.page)
        self.assertIn("fetch('/api/login'", self.page)
        self.assertIn("Authorization", self.page)
        self.assertNotIn("document.cookie", self.page)
        self.assertNotIn("?token", self.page)

    def test_the_page_has_the_banners_and_the_p2_pages_only(self):
        for text in ("Hub down", "Alert delivery is failing", "Fleet", "Events", "Incidents", "Host", "Enroll", "Audit", "Settings"):
            self.assertIn(text, self.page)
        self.assertNotIn("Bans", self.page)
        self.assertNotIn("acknowledge", self.page.lower())
        self.assertIsNone(re.search(r"token/create", self.page))


class LoginTests(UiCase):
    def test_a_code_works_once(self):
        code = self.mint()
        status, body = self.jreq("POST", "/api/login", body={"code": code})
        self.assertEqual(status, 200)
        token = body["token"]
        self.assertEqual(body["idle_s"], 1800)
        self.assertEqual(body["absolute_s"], 12 * 3600)
        self.assertGreaterEqual(len(token), 43)                                     # 256 bits, base64url
        self.assertEqual(self.jreq("POST", "/api/login", body={"code": code})[0], 401)
        self.assertEqual(self.jreq("GET", "/api/status", token=token)[0], 200)
        self.assertEqual(self.alerts.notices[-1][0], "dashboard session")
        self.assertIn("127.0.0.1", self.alerts.notices[-1][1])
        self.assertIn(("ui", "login.redeem", "ok"), self.audit_actions())

    def test_the_session_is_held_hashed_in_memory_and_never_in_the_database_or_a_cookie(self):
        status, r, raw = self.req("POST", "/api/login", body={"code": self.mint()})
        token = json.loads(raw)["token"]
        self.assertIsNone(r.getheader("Set-Cookie"))
        self.assertIn(hashlib.sha256(token.encode()).hexdigest(), self.ui.app.sessions.items)
        self.assertNotIn(token, str(self.ui.app.sessions.items))
        dump = json.dumps(self.rows("SELECT * FROM audit")) + json.dumps(self.rows("SELECT * FROM login_codes")) + json.dumps(self.alerts.notices)
        self.assertNotIn(token, dump)
        row = self.rows("SELECT * FROM audit WHERE action='login.redeem'")[0]
        self.assertEqual(row["actor_detail"], "ui session=%s addr=127.0.0.1" % hashlib.sha256(token.encode()).hexdigest()[:8])

    def test_a_wrong_code_is_401_and_malformed_bodies_400(self):
        self.assertEqual(self.jreq("POST", "/api/login", body={"code": "wrong"})[0], 401)
        for body in ({}, {"code": 5}, {"code": ""}, {"code": "x" * 200}, {"code": None}):
            self.assertEqual(self.jreq("POST", "/api/login", body=body)[0], 400, body)

    def test_an_expired_code_is_refused(self):
        code = self.mint()
        self.hub.db.execute("UPDATE login_codes SET expires=?", (hub_common.now_ms() - 1,))
        self.assertEqual(self.jreq("POST", "/api/login", body={"code": code})[0], 401)

    def test_at_most_5_failed_logins_a_minute_then_429(self):
        for _ in range(5):
            self.assertEqual(self.jreq("POST", "/api/login", body={"code": "bad"})[0], 401)
        good = self.mint()
        status, body = self.jreq("POST", "/api/login", body={"code": good})
        self.assertEqual((status, body), (429, {"error": "too many requests"}))
        self.assertEqual(self.jreq("POST", "/api/login", body={"code": "bad"})[0], 429)
        self.clock.advance(61)
        self.assertEqual(self.jreq("POST", "/api/login", body={"code": good})[0], 200)       # the good code was not spent by the 429

    def test_failed_logins_are_counted_in_the_status(self):
        token = self.login()
        for _ in range(3):
            self.jreq("POST", "/api/login", body={"code": "bad"})
        self.assertEqual(self.jreq("GET", "/api/status", token=token)[1]["failed_logins_last_minute"], 3)
        self.clock.advance(61)
        self.assertEqual(self.jreq("GET", "/api/status", token=token)[1]["failed_logins_last_minute"], 0)

    def test_logout_ends_the_session(self):
        token = self.login()
        self.assertEqual(self.jreq("POST", "/api/logout", token=token, body={})[0], 200)
        self.assertEqual(self.jreq("GET", "/api/status", token=token)[0], 401)

    def test_idle_expiry_after_30_minutes_and_activity_keeps_it_alive(self):
        token = self.login()
        for _ in range(4):
            self.clock.advance(25 * 60)
            self.assertEqual(self.jreq("GET", "/api/status", token=token)[0], 200)        # 100 minutes in all, never idle 30
        self.clock.advance(30 * 60 + 1)
        self.assertEqual(self.jreq("GET", "/api/status", token=token)[0], 401)

    def test_absolute_expiry_after_12_hours(self):
        token = self.login()
        for _ in range(23):
            self.clock.advance(29 * 60)
            self.assertEqual(self.jreq("GET", "/api/status", token=token)[0], 200)        # 11 h 7 min, always active
        self.clock.advance(29 * 60 * 2)                                                    # past 12 h in total
        self.assertEqual(self.jreq("GET", "/api/status", token=token)[0], 401)

    def test_a_restart_logs_everyone_out(self):
        token = self.login()
        self.ui.stop()
        self.start_ui()
        self.assertEqual(self.jreq("GET", "/api/status", token=token)[0], 401)

    def test_login_with_the_hub_down_is_503(self):
        code = self.mint()
        self.socks.stop()
        self.assertEqual(self.jreq("POST", "/api/login", body={"code": code})[0], 503)

    def test_session_cap_evicts_the_oldest(self):
        tokens = []
        for _ in range(edr_hub_ui.SESSIONS_MAX + 1):
            tokens.append(self.login())
            self.clock.advance(1)
        self.assertEqual(self.jreq("GET", "/api/status", token=tokens[0])[0], 401)
        self.assertEqual(self.jreq("GET", "/api/status", token=tokens[-1])[0], 200)


class ReadTests(UiCase):
    def setUp(self):
        super().setUp()
        self.token = self.login()

    def get(self, path):
        status, body = self.jreq("GET", path, token=self.token)
        return status, body

    def ok(self, path):
        status, body = self.get(path)
        self.assertEqual(status, 200, body)
        return body

    def test_status_and_banners(self):
        s = self.ok("/api/status")
        self.assertEqual(s["version"], hub_common.VERSION)
        self.assertTrue(s["hub_down"])                                     # the fake writer never stamped writer_tick
        self.assertFalse(s["alerts_failing"])
        self.hub.db.execute("INSERT INTO meta (key, value) VALUES ('writer_tick', ?)", (str(hub_common.now_ms()),))
        self.assertFalse(self.ok("/api/status")["hub_down"])
        self.hub.db.execute("UPDATE meta SET value=? WHERE key='writer_tick'", (str(hub_common.now_ms() - 40_000),))
        self.assertTrue(self.ok("/api/status")["hub_down"])
        old = hub_common.now_ms() - 2 * 3600 * 1000
        self.hub.db.execute("INSERT INTO outbox (created, channel, severity, payload, next_try, state) VALUES (?,?,?,?,?,?)",
                            (old, "webhook", "HIGH", "{}", old, "failed"))
        self.assertTrue(self.ok("/api/status")["alerts_failing"])

    def test_the_fleet_page_marks_a_host_late_between_four_and_five_minutes(self):
        now = hub_common.now_ms()
        for seen, state, window, late in ((now - 3 * 60_000, "active", False, False), (now - 270_000, "active", False, True),
                                          (now - 270_000, "active", True, False), (now - 270_000, "retired", False, False),
                                          (now - 6 * 60_000, "active", False, False)):
            self.hub.db.execute("UPDATE hosts SET last_seen=?, state=? WHERE uuid=?", (seen, state, self.uuid))
            self.hub.db.execute("DELETE FROM maintenance")
            if window:
                self.hub.db.execute("INSERT INTO maintenance (host, until, set_by, set_at) VALUES (?,?,?,?)", (self.uuid, now + 600_000, "x", 1))
            hosts = {h["name"]: h for h in self.ok("/api/fleet")["hosts"]}
            self.assertEqual(hosts["web-1"]["late"] if "web-1" in hosts else False, late, (state, window))

    def test_fleet_lists_hosts_with_health_and_notes(self):
        S.add_host(self.hub.db, "gone", state="retired")
        now = hub_common.now_ms()
        hb = {"dns_lock": {"state": "locked"}, "tetragon": [{"name": "p", "mode": "monitor", "would_be_kills": 0}],
              "maintenance_until": 5, "secret": "dropped"}
        self.hub.db.execute("INSERT INTO heartbeats (host, received_at, body) VALUES (?,?,?)", (self.uuid, now, json.dumps(hb)))
        self.hub.db.execute("INSERT INTO inventory (host, received_at, body) VALUES (?,?,?)",
                            (self.uuid, now, json.dumps({"checks": {"sctp": {"status": False}, "ufw": {"status": True}}})))
        self.hub.db.execute("INSERT INTO maintenance (host, until, set_by, set_at) VALUES (?,?,?,?)", (self.uuid, now + 600_000, "uid=0 x", now))
        self.hub.db.execute("INSERT INTO incidents (host, chain, opened, updated, severity) VALUES (?,?,?,?,?)", (self.uuid, "c", now, now, "HIGH"))
        hosts = self.ok("/api/fleet")["hosts"]
        self.assertEqual([h["name"] for h in hosts], ["web-1"])
        h = hosts[0]
        self.assertEqual(h["open_incidents"], 1)
        self.assertEqual(h["health"]["dns_lock"], {"state": "locked"})
        self.assertNotIn("secret", h["health"])
        self.assertEqual(h["exposure"], "ok")                              # a false status alone is not a HIGH finding
        self.assertEqual(h["maintenance_by"], "uid=0 x")
        self.assertNotIn("cert_sha256", h)

    def fleet_exposure(self, inv, name="web-1"):
        uuid = self.uuid if name == "web-1" else S.add_host(self.hub.db, name)
        if inv is not None:
            self.hub.db.execute("INSERT OR REPLACE INTO inventory (host, received_at, body) VALUES (?,?,?)",
                                (uuid, hub_common.now_ms(), json.dumps(inv)))
        hosts = {h["name"]: h for h in self.ok("/api/fleet")["hosts"]}
        return hosts[name]["exposure"], hosts[name]["exposure_checks"]

    def test_exposure_column_exposed_unknown_ok(self):
        ok_checks = {n: {"status": True} for n in edr_hub_ui.EXPOSURE_CHECKS}
        # no inventory at all
        self.assertEqual(self.fleet_exposure(None), ("unknown", []))
        # clean
        self.assertEqual(self.fleet_exposure({"checks": ok_checks, "findings": []}), ("ok", []))
        # a HIGH finding on one of the five checks
        for sev in ("HIGH", "CRITICAL"):
            inv = {"checks": ok_checks, "findings": [{"check": "sctp", "sev": sev, "summary": "x"}]}
            self.assertEqual(self.fleet_exposure(inv), ("exposed", ["sctp"]), sev)
        # MEDIUM or LOW findings, or a finding of another check, do not expose
        for finding in ({"check": "sctp", "sev": "MEDIUM"}, {"check": "nginx_pkg", "sev": "LOW"}, {"check": "ufw", "sev": "CRITICAL"},
                        {"check": "app_key_in_public", "sev": "HIGH"}):
            self.assertEqual(self.fleet_exposure({"checks": ok_checks, "findings": [finding]}), ("ok", []), finding)
        # each of the five names counts
        for name in edr_hub_ui.EXPOSURE_CHECKS:
            inv = {"checks": ok_checks, "findings": [{"check": name, "sev": "HIGH"}]}
            self.assertEqual(self.fleet_exposure(inv), ("exposed", [name]), name)
        # unknown status on any of the five
        for name in edr_hub_ui.EXPOSURE_CHECKS:
            checks = dict(ok_checks, **{name: {"status": "unknown"}})
            self.assertEqual(self.fleet_exposure({"checks": checks, "findings": []}), ("unknown", [name]), name)
        # unknown on a check outside the five does not matter
        self.assertEqual(self.fleet_exposure({"checks": dict(ok_checks, ufw={"status": "unknown"}), "findings": []}), ("ok", []))
        # exposed wins over unknown
        inv = {"checks": dict(ok_checks, sctp={"status": "unknown"}), "findings": [{"check": "deleted_exe", "sev": "HIGH"}]}
        self.assertEqual(self.fleet_exposure(inv), ("exposed", ["deleted_exe"]))
        # odd shapes never crash and read as unknown
        for odd in ({}, {"checks": []}, {"checks": ok_checks, "findings": "x"}, {"checks": ok_checks, "findings": [5, None, {"check": 3}]}):
            state = self.fleet_exposure(odd)[0]
            self.assertIn(state, ("unknown", "ok"), odd)

    def test_exposure_state_function_directly(self):
        self.assertEqual(edr_hub_ui.exposure_state(None), ("unknown", []))
        self.assertEqual(edr_hub_ui.exposure_state({"checks": {}, "findings": [{"check": "inventory.sctp", "sev": "high"}]}), ("exposed", ["sctp"]))

    def test_events_filters_and_paging(self):
        h2 = S.add_host(self.hub.db, "web-2")
        ids = [self.event(kind="a.low", sev="LOW"), self.event(kind="ssh.fail", sev="HIGH"), self.event(kind="ssh.ok", sev="MEDIUM"),
               self.event(kind="x.crit", sev="CRITICAL", host=h2, source="tetragon")]
        r = self.ok("/api/events")
        self.assertEqual([e["id"] for e in r["events"]], ids[::-1])
        self.assertEqual(r["head_event_id"], ids[-1])
        self.assertEqual(r["events"][0]["host_name"], "web-2")
        self.assertEqual([e["kind"] for e in self.ok("/api/events?min_sev=high")["events"]], ["x.crit", "ssh.fail"])
        self.assertEqual([e["kind"] for e in self.ok("/api/events?host=web-2")["events"]], ["x.crit"])
        self.assertEqual([e["kind"] for e in self.ok("/api/events?host=" + h2)["events"]], ["x.crit"])
        self.assertEqual([e["kind"] for e in self.ok("/api/events?source=tetragon")["events"]], ["x.crit"])
        self.assertEqual([e["kind"] for e in self.ok("/api/events?kind=ssh.fail")["events"]], ["ssh.fail"])
        self.assertEqual([e["kind"] for e in self.ok("/api/events?kind=ssh.*")["events"]], ["ssh.ok", "ssh.fail"])
        self.assertEqual(len(self.ok("/api/events?limit=2")["events"]), 2)
        self.assertEqual([e["id"] for e in self.ok("/api/events?before_id=%d&limit=1" % ids[2])["events"]], [ids[1]])
        self.assertEqual(self.ok("/api/events?since=1h")["events"][0]["id"], ids[-1])
        for bad in ("min_sev=loud", "source=nope", "kind=%27%3B--", "limit=0", "limit=99999", "since=never", "before_id=x", "host=a%20b"):
            self.assertEqual(self.get("/api/events?" + bad)[0], 400, bad)

    def test_event_detail_has_details_and_the_rules_text(self):
        eid = self.event(kind="tetragon.sctp-socket", sev="CRITICAL", details={"proc": {"binary": "/usr/bin/x"}})
        e = self.ok("/api/event/%d" % eid)["event"]
        self.assertEqual(e["details"], {"proc": {"binary": "/usr/bin/x"}})
        self.assertEqual(e["host_name"], "web-1")
        import hub_rules
        self.assertEqual(e["describe"], hub_rules.describe("tetragon.sctp-socket"))
        self.assertEqual(self.get("/api/event/99999")[0], 404)

    def test_describe_endpoint_uses_hub_rules(self):
        import hub_rules
        self.assertEqual(self.ok("/api/describe?kind=tetragon.sctp-socket"), hub_rules.describe("tetragon.sctp-socket"))
        self.assertIn("meaning", self.ok("/api/describe?kind=totally.unknown"))
        self.assertEqual(self.get("/api/describe?kind=Bad%20Kind")[0], 400)

    def test_incidents_and_timeline(self):
        now = hub_common.now_ms()
        e1, e2 = self.event(summary="first"), self.event(summary="second")
        self.hub.db.execute("INSERT INTO incidents (host, chain, opened, updated, severity, title, kinds, signals) VALUES (?,?,?,?,?,?,?,?)",
                            (self.uuid, "auth", now, now, "HIGH", "SSH brute force", '["ssh.fail"]', 2))
        self.hub.db.execute("INSERT INTO incidents (host, chain, opened, updated, severity, title, state) VALUES (?,?,?,?,?,?,?)",
                            (self.uuid, "old", now - 5, now - 5, "LOW", "Closed", "resolved"))
        self.hub.db.execute("INSERT INTO incident_events (incident_id, event_rowid) VALUES (1,?),(1,?)", (e1, e2))
        self.assertEqual(len(self.ok("/api/incidents")["incidents"]), 2)
        self.assertEqual([i["title"] for i in self.ok("/api/incidents?state=open")["incidents"]], ["SSH brute force"])
        inc = self.ok("/api/incident/1")["incident"]
        self.assertEqual([e["summary"] for e in inc["events"]], ["first", "second"])
        self.assertEqual(inc["kinds"], ["ssh.fail"])
        self.assertIn("ssh.fail", inc["describe"])
        self.assertEqual(self.get("/api/incident/99")[0], 404)
        self.assertEqual(self.get("/api/incidents?state=x")[0], 400)

    def test_host_page_data(self):
        now = hub_common.now_ms()
        self.event(summary="one")
        self.hub.db.execute("INSERT INTO heartbeats (host, received_at, body) VALUES (?,?,?)",
                            (self.uuid, now, json.dumps({"local_conf_sha256": "ab" * 32, "ban_counts": {"local": 2}})))
        d = self.ok("/api/host/web-1")
        self.assertEqual(d["host"]["uuid"], self.uuid)
        self.assertEqual(d["health"]["local_conf_sha256"], "ab" * 32)
        self.assertEqual(d["ban_counts"], {"local": 2})
        self.assertEqual(len(d["events"]), 1)
        self.assertEqual(self.ok("/api/host/" + self.uuid)["host"]["name"], "web-1")
        self.assertNotIn("cert_sha256", d["host"])
        self.assertEqual(self.get("/api/host/ghost")[0], 404)

    def test_enroll_page_lists_tokens_and_the_cli_command_but_cannot_create(self):
        S.ctl(self.paths, "token.create", {"name": "web-9", "source": "198.51.100.0/24"})
        d = self.ok("/api/tokens")
        self.assertEqual(d["tokens"][0]["name"], "web-9")
        self.assertEqual(d["tokens"][0]["state"], "pending")
        self.assertEqual(d["tokens"][0]["source_cidr"], "198.51.100.0/24")
        self.assertIn("sudo edr-hub token create", d["command"])
        self.assertNotIn("SECRETVALUE", json.dumps(d))
        self.assertNotIn("secret", json.dumps(d).lower().replace("secret_", ""))

    def test_audit_pages(self):
        for i in range(5):
            S.ctl(self.paths, "never-ban.list")
        S.ctl(self.paths, "settings.set", {"key": "retention_days", "value": "40"})
        rows = self.ok("/api/audit?limit=100")["audit"]
        self.assertEqual(rows[0]["action"], "settings.set")
        self.assertEqual(rows[0]["details"], {"old": 30, "new": 40})
        older = self.ok("/api/audit?limit=1&before_id=%d" % rows[0]["id"])["audit"]
        self.assertEqual(len(older), 1)
        self.assertLess(older[0]["id"], rows[0]["id"])

    def test_settings_are_read_only_and_secrets_are_masked(self):
        masked = hub_common.mask_secret("https://hooks.example.com/services/AAAA/BBBB/TOPSECRETXYZ")
        self.hub.update_settings(dict(self.hub.settings, secrets_set={"webhook_url": masked}))
        with open(self.paths.secrets, "w") as f:
            json.dump({"webhook_url": "https://hooks.example.com/services/AAAA/BBBB/TOPSECRETXYZ"}, f)
        S.ctl(self.paths, "never-ban.add", {"cidr": "198.51.100.0/24", "reason": "mon"})
        d = self.ok("/api/settings")
        self.assertEqual(d["secrets"]["webhook_url"], masked)
        self.assertEqual(d["secrets"]["deadman_url"], "")
        self.assertEqual(d["plain"]["alert_min_severity"], "HIGH")
        self.assertEqual(d["installer"]["port"], 8443)
        self.assertEqual(d["never_ban"][0]["cidr"], "198.51.100.0/24")
        self.assertNotIn("TOPSECRET", json.dumps(d))
        self.assertEqual(self.jreq("POST", "/api/settings", token=self.token, body={"key": "x"})[0], 404)

    def test_hub_down_when_the_database_cannot_be_opened_but_the_page_still_loads(self):
        os.rename(self.paths.db, self.paths.db + ".away")
        try:
            for path in ("/api/fleet", "/api/events", "/api/status", "/api/audit", "/api/settings", "/api/host/web-1"):
                status, body = self.get(path)
                self.assertEqual((status, body), (503, {"error": "hub down"}), path)
            self.assertEqual(self.req("GET", "/")[0], 200)
        finally:
            os.rename(self.paths.db + ".away", self.paths.db)
        self.assertEqual(self.get("/api/fleet")[0], 200)

    def test_no_read_transaction_is_left_open_between_requests(self):
        for _ in range(5):
            self.ok("/api/fleet")
            self.ok("/api/events")
        self.hub.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        res = self.hub.db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        self.assertEqual(res[0], 0)                                         # not blocked by a pinned reader

    def test_hostile_fields_come_back_json_escaped(self):
        self.hub.db.execute("UPDATE hosts SET reported_name=?, os=? WHERE uuid=?", (NASTY, NASTY, self.uuid))
        eid = self.event(summary=NASTY, details={"url": NASTY, NASTY: NASTY})
        now = hub_common.now_ms()
        self.hub.db.execute("INSERT INTO incidents (host, chain, opened, updated, severity, title, kinds) VALUES (?,?,?,?,?,?,?)",
                            (self.uuid, "c", now, now, "HIGH", NASTY, json.dumps([NASTY])))
        hub_ctl_audit = __import__("hub_audit")
        hub_ctl_audit.append(self.hub.db, actor_kind="cli", actor_detail=NASTY, action="a", target=NASTY, details={"k": NASTY})
        for path in ("/api/events", "/api/event/%d" % eid, "/api/fleet", "/api/incidents", "/api/incident/1", "/api/host/web-1", "/api/audit"):
            status, r, raw = self.req("GET", path, token=self.token)
            self.assertEqual(status, 200, path)
            raw.decode("ascii")                                            # pure ASCII: ensure_ascii escaped everything
            for bad in (b"\x1b", b"\x07", b"\x7f", b"<img", b"\xe2\x80"):
                self.assertNotIn(bad, raw, path)
            self.assertIn(b"\\u001b", raw)
            self.assertEqual(r.getheader("Content-Type"), "application/json")
            self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(self.ok("/api/event/%d" % eid)["event"]["summary"], NASTY)       # and it round-trips intact

    def test_list_rows_cap_strings_at_2_kib(self):
        self.event(summary="x" * 5000)
        self.assertEqual(len(self.ok("/api/events")["events"][0]["summary"]), 2048)


class WriteTests(UiCase):
    def setUp(self):
        super().setUp()
        self.token = self.login()
        self.session8 = hashlib.sha256(self.token.encode()).hexdigest()[:8]

    def post(self, path, body):
        return self.jreq("POST", path, token=self.token, body=body)

    def test_mark_moved_goes_through_ui_sock_and_is_audited_as_the_session(self):
        status, body = self.post("/api/host/mark-moved", {"host": "web-1"})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["result"]["state"], "moved")
        self.assertEqual(self.rows("SELECT state FROM hosts")[0]["state"], "moved")
        row = self.rows("SELECT * FROM audit WHERE action='host.mark-moved'")[0]
        self.assertEqual((row["actor_kind"], row["actor_detail"]), ("ui", "ui session=%s addr=127.0.0.1" % self.session8))
        self.assertEqual(self.post("/api/host/mark-moved", {"host": "web-1"})[0], 400)            # already moved

    def test_maintenance_set_and_end(self):
        status, body = self.post("/api/host/maintenance", {"host": "web-1", "for": "30m"})
        self.assertEqual(status, 200, body)
        w = self.rows("SELECT * FROM maintenance")[0]
        self.assertEqual(w["host"], self.uuid)
        self.assertIn("ui session=" + self.session8, w["set_by"])
        self.assertAlmostEqual(w["until"], hub_common.now_ms() + 30 * 60_000, delta=5000)
        self.assertEqual(self.post("/api/host/maintenance", {"host": "web-1", "end": True})[0], 200)
        self.assertEqual(self.rows("SELECT * FROM maintenance"), [])

    def test_maintenance_limits_are_enforced_by_the_hub(self):
        self.assertEqual(self.post("/api/host/maintenance", {"host": "web-1", "for": "5h"})[0], 400)
        self.assertEqual(self.post("/api/host/maintenance", {"host": "web-1", "for": "2h"})[0], 200)

    def test_bad_arguments(self):
        for body in ({}, {"host": 5}, {"host": "a b"}, {"host": "web-1"}, {"host": "web-1", "for": "forever"},
                     {"host": "web-1", "for": "30"}, {"host": "web-1", "for": 30}, {"host": "x" * 70, "for": "5m"}):
            self.assertEqual(self.post("/api/host/maintenance", body)[0], 400, body)
        self.assertEqual(self.post("/api/host/maintenance", {"host": "ghost", "for": "5m"})[0], 400)
        self.assertEqual(self.rows("SELECT * FROM maintenance"), [])

    def test_only_the_whitelisted_writes_exist(self):
        for path in ("/api/host/revoke", "/api/host/retire", "/api/host/adopt", "/api/token/create", "/api/settings",
                     "/api/never-ban", "/api/incident/resolve", "/api/ban"):
            self.assertEqual(self.post(path, {"host": "web-1"})[0], 404, path)
        self.assertEqual(self.rows("SELECT state FROM hosts")[0]["state"], "active")

    def test_hub_down_is_503(self):
        self.socks.stop()
        self.assertEqual(self.post("/api/host/mark-moved", {"host": "web-1"})[0], 503)


class StreamTests(UiCase):
    def setUp(self):
        self._patch = mock.patch("edr_hub_ui.POLL_S", 0.1)
        self._patch.start()
        super().setUp()
        self.addCleanup(self._patch.stop)
        self.token = self.login()

    def open_stream(self, token=None, last_id=None, timeout=5):
        c = self.conn(timeout)
        headers = {"Authorization": "Bearer " + (token or self.token)}
        if last_id is not None:
            headers["Last-Event-ID"] = str(last_id)
        c.request("GET", "/api/stream", headers=headers)
        r = c.getresponse()
        self.addCleanup(c.close)
        return c, r

    @staticmethod
    def read_frame(r):
        lines = []
        while True:
            line = r.fp.readline().decode()
            if line == "":
                return None
            if line == "\n":
                if lines:
                    return lines
                continue
            lines.append(line.rstrip("\n"))

    def frames_until(self, r, name, limit=20):
        for _ in range(limit):
            f = self.read_frame(r)
            if f is None:
                return None
            if "event: " + name in f:
                return f
        return None

    def test_stream_headers_and_live_events_with_ids(self):
        c, r = self.open_stream()
        self.assertEqual(r.status, 200)
        self.assertEqual(r.getheader("Content-Type"), "text/event-stream")
        self.assertEqual(r.getheader("Cache-Control"), "no-store")
        time.sleep(0.4)
        eid = self.event(summary="live one")
        f = self.frames_until(r, "event")
        self.assertIsNotNone(f)
        self.assertEqual(f[0], "id: %d" % eid)
        data = json.loads(f[2][len("data: "):])
        self.assertEqual((data["id"], data["summary"], data["host_name"]), (eid, "live one", "web-1"))
        self.assertEqual(len(f), 3)                                        # id, event, one-line data

    def test_hostile_text_in_a_frame_is_escaped_on_one_line(self):
        c, r = self.open_stream()
        time.sleep(0.4)
        self.event(summary=NASTY)
        f = self.frames_until(r, "event")
        self.assertEqual(len(f), 3)
        f[2].encode("ascii")
        self.assertNotIn("\x1b", "".join(f))
        self.assertEqual(json.loads(f[2][6:])["summary"], NASTY)

    def test_last_event_id_resumes_from_the_database(self):
        ids = [self.event(summary="e%d" % i) for i in range(3)]
        c, r = self.open_stream(last_id=ids[0])
        got = [self.frames_until(r, "event") for _ in range(2)]
        self.assertEqual([f[0] for f in got], ["id: %d" % ids[1], "id: %d" % ids[2]])
        c2, r2 = self.open_stream(last_id=ids[2])
        time.sleep(0.4)
        later = self.event(summary="later")
        self.assertEqual(self.frames_until(r2, "event")[0], "id: %d" % later)             # nothing repeated

    def test_without_last_event_id_the_stream_starts_at_the_head(self):
        self.event(summary="old")
        c, r = self.open_stream()
        time.sleep(0.4)
        new = self.event(summary="new")
        self.assertEqual(self.frames_until(r, "event")[0], "id: %d" % new)

    def test_two_streams_per_session_and_eight_in_all(self):
        opened = []
        for _ in range(2):
            opened.append(self.open_stream())
        status, r, _ = self.req("GET", "/api/stream", token=self.token)
        self.assertEqual(status, 429)
        tokens = [self.login() for _ in range(3)]
        for t in tokens:
            for _ in range(2):
                c, r = self.open_stream(token=t)
                self.assertEqual(r.status, 200)
                opened.append((c, r))
        self.assertEqual(len(opened), 8)
        self.assertEqual(self.ui.app.feed.counts(), 8)
        extra = self.login()
        self.assertEqual(self.req("GET", "/api/stream", token=extra)[0], 429)
        c, r = opened.pop()
        r.close()
        c.close()
        deadline = time.monotonic() + 5
        while self.ui.app.feed.counts() > 7 and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertEqual(self.open_stream(token=extra)[1].status, 200)                      # a slot came back

    def test_a_slow_client_gets_reset_and_is_dropped(self):
        feed = self.ui.app.feed
        c, r = self.open_stream()
        deadline = time.monotonic() + 3
        while not feed.clients and time.monotonic() < deadline:
            time.sleep(0.05)
        (client,) = list(feed.clients)
        client.dropped = True
        client.q.put({"id": 10 ** 9})
        f = self.frames_until(r, "reset")
        self.assertIsNotNone(f)
        self.assertEqual(self.read_frame(r), None)                          # and the stream ends
        self.assertEqual(feed.counts(), 0)

    def test_feed_drops_a_client_whose_queue_is_full(self):
        with mock.patch("edr_hub_ui.STREAM_QUEUE_MAX", 3):
            client = self.ui.app.feed.register("d" * 64)
        self.ui.app.feed._broadcast([{"id": i} for i in range(10)])
        self.assertTrue(client.dropped)
        self.assertEqual(self.ui.app.feed.counts(), 0)

    def test_a_ping_rechecks_the_session_and_ends_the_stream_when_it_is_gone(self):
        with mock.patch("edr_hub_ui.STREAM_PING_S", 0.3):
            c, r = self.open_stream()
            f = self.frames_until(r, "ping")
            self.assertIsNotNone(f)
            self.assertEqual(json.loads(f[1][6:]), {"hub_down": False})
            self.ui.app.sessions.drop(hashlib.sha256(self.token.encode()).hexdigest())
            f = self.frames_until(r, "end")
        self.assertIsNotNone(f)
        self.assertEqual(json.loads(f[1][6:]), {"reason": "session"})
        self.assertIsNone(self.read_frame(r))

    def test_a_stream_ends_after_15_minutes(self):
        with mock.patch("edr_hub_ui.STREAM_MAX_S", 0.5):
            c, r = self.open_stream()
            f = self.frames_until(r, "end")
        self.assertEqual(json.loads(f[1][6:]), {"reason": "time"})
        self.assertEqual(edr_hub_ui.STREAM_MAX_S, 15 * 60)
        self.assertEqual((edr_hub_ui.STREAMS_MAX, edr_hub_ui.STREAMS_PER_SESSION, edr_hub_ui.STREAM_PING_S), (8, 2, 15))

    def test_the_poller_holds_no_read_transaction(self):
        self.event(summary="x")
        time.sleep(0.5)
        res = self.hub.db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        self.assertEqual(res[0], 0)

    def test_the_stream_needs_a_session(self):
        self.assertEqual(self.req("GET", "/api/stream")[0], 401)
        self.assertEqual(self.req("GET", "/api/stream", token="Z" * 43)[0], 401)


class EntryScriptTests(unittest.TestCase):
    def test_the_script_serves_the_page_on_loopback_and_stops_on_sigterm(self):
        root, paths = S.make_dirs()
        self.addCleanup(__import__("shutil").rmtree, root, True)
        db = S.new_db(paths.db)
        db.close()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        self.assertGreaterEqual(port, 18000)
        env = dict(os.environ, EDR_HUB_STATE_DIR=paths.state_dir, EDR_HUB_RUN_DIR=paths.run_dir, EDR_HUB_ETC_DIR=paths.etc_dir,
                   PYTHONDONTWRITEBYTECODE="1")
        proc = subprocess.Popen([sys.executable, "-I", os.path.join(S.HUB_DIR, "edr_hub_ui.py"), "--port", str(port)],
                                env=env, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            status = None
            while time.monotonic() < deadline:
                try:
                    c = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                    c.request("GET", "/")
                    resp = c.getresponse()
                    status, body = resp.status, resp.read()
                    c.close()
                    break
                except OSError:
                    time.sleep(0.2)
            self.assertEqual(status, 200)
            self.assertIn(b"<title>edr-hub</title>", body)
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            c.request("GET", "/", headers={"Host": "evil.example"})
            self.assertEqual(c.getresponse().status, 403)
            c.close()
        finally:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            proc.stderr.close()
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
