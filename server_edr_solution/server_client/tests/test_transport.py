import gzip
import json
import os
import random
import ssl
import time
import unittest

import test_transport_pki as support
from test_transport_pki import FakeHub, PKI, Raw, Reset, Stream, err, reply
from edragent import transport as tr


class TransportCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = PKI()
        cls.cert, cls.key = cls.pki.client()

    @classmethod
    def tearDownClass(cls):
        cls.pki.cleanup()

    def ctx(self):
        return tr.make_context(self.pki.ca_pem, self.cert, self.key)

    def hub(self, handler, **kw):
        h = FakeHub(self.pki, handler, **kw).start()
        self.addCleanup(h.stop)
        return h

    def get(self, hub, path="/v1/policy", **kw):
        kw.setdefault("ctx", self.ctx())
        return tr.request("127.0.0.1", hub.port, "GET", path, **kw)


class TestOneRequest(TransportCase):
    def test_http10_tls13_proto_header_and_identity(self):
        hub = self.hub(lambda r: reply(200, {"hub_time": 1, "policy_rev": "a" * 16, "min_client_schema": 0}))
        r = tr.request("127.0.0.1", hub.port, "POST", "/v1/heartbeat", ctx=self.ctx(), body=b'{"a":1}',
                       headers={"Content-Type": "application/json"})
        self.assertEqual(r.status, 200)
        self.assertEqual(r.json()["policy_rev"], "a" * 16)
        q = hub.requests[0]
        self.assertEqual(q.version, "HTTP/1.0")
        self.assertEqual(q.tls_version, "TLSv1.3")
        self.assertEqual(q.headers["x-edr-proto"], "1")
        self.assertEqual(q.headers["content-length"], "7")
        self.assertEqual(q.headers["content-type"], "application/json")
        self.assertEqual(q.headers["connection"], "close")
        self.assertEqual(q.headers["host"], "127.0.0.1:%d" % hub.port)
        self.assertEqual(q.peer_cn, "11111111-2222-4333-8444-555555555555")
        self.assertEqual(q.body, b'{"a":1}')

    def test_get_sends_no_content_length(self):
        hub = self.hub(lambda r: reply(200))
        self.get(hub)
        self.assertNotIn("content-length", hub.requests[0].headers)

    def test_headers_with_newlines_are_refused(self):
        hub = self.hub(lambda r: reply(200))
        with self.assertRaises(ValueError):
            self.get(hub, headers={"X-A": "b\r\nX-Evil: 1"})

    def test_ipv6_literal_hub(self):
        try:
            hub = FakeHub(self.pki, lambda r: reply(200, {"ok": 1}), host="::1").start()
        except OSError:
            self.skipTest("no IPv6 loopback")
        self.addCleanup(hub.stop)
        r = tr.request("::1", hub.port, "GET", "/v1/policy", ctx=self.ctx())
        self.assertEqual(r.status, 200)
        self.assertEqual(hub.requests[0].headers["host"], "[::1]:%d" % hub.port)

    def test_pinned_ca_only(self):
        other = PKI(cn="Other CA")
        self.addCleanup(other.cleanup)
        hub = FakeHub(other, lambda r: reply(200), mtls=False).start()
        self.addCleanup(hub.stop)
        with self.assertRaises(tr.TransportError) as cm:
            self.get(hub)
        self.assertEqual(cm.exception.kind, "tls")

    def test_ip_san_is_checked(self):
        cert, key = self.pki.server(name="wrongsan", san="IP:127.0.0.2,IP:::1")
        hub = self.hub(lambda r: reply(200), cert=cert, key=key)
        with self.assertRaises(tr.TransportError) as cm:
            self.get(hub)
        self.assertEqual(cm.exception.kind, "tls")
        cert, key = self.pki.server(name="dnsonly", san="DNS:localhost")
        hub = self.hub(lambda r: reply(200), cert=cert, key=key)
        with self.assertRaises(tr.TransportError) as cm:
            self.get(hub)
        self.assertEqual(cm.exception.kind, "tls")

    def test_tls12_hub_is_refused(self):
        hub = self.hub(lambda r: reply(200), tls12=True)
        with self.assertRaises(tr.TransportError) as cm:
            self.get(hub)
        self.assertEqual(cm.exception.kind, "tls")

    def test_x509_strict_is_set_and_a_no_keyusage_ca_is_refused(self):
        ctx = self.ctx()
        self.assertTrue(ctx.verify_flags & ssl.VERIFY_X509_STRICT)
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        lax = PKI(lax=True)
        self.addCleanup(lax.cleanup)
        hub = FakeHub(lax, lambda r: reply(200), mtls=False).start()
        self.addCleanup(hub.stop)
        with self.assertRaises(tr.TransportError) as cm:
            tr.request("127.0.0.1", hub.port, "GET", "/v1/policy", ctx=tr.make_context(lax.ca_pem))
        self.assertEqual(cm.exception.kind, "tls")

    def test_unverified_context_for_the_ca_fetch_only(self):
        ctx = tr.make_context(verify=False)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_3)
        hub = self.hub(lambda r: reply(200, body=b"pem"), mtls=False)
        r = tr.request("127.0.0.1", hub.port, "GET", "/v1/ca", ctx=ctx)
        self.assertEqual(r.body, b"pem")
        self.assertIsNone(hub.requests[0].peer_cn)                 # no client certificate was offered

    def test_bad_client_certificate_is_a_tls_error_with_no_status(self):
        evil = PKI(cn="Evil CA")
        self.addCleanup(evil.cleanup)
        ec, ek = evil.client()
        hub = self.hub(lambda r: reply(200))
        with self.assertRaises(tr.TransportError) as cm:
            tr.request("127.0.0.1", hub.port, "GET", "/v1/policy", ctx=tr.make_context(self.pki.ca_pem, ec, ek))
        self.assertEqual(cm.exception.kind, "tls")
        with self.assertRaises(tr.TransportError) as cm:
            tr.request("127.0.0.1", hub.port, "GET", "/v1/policy", ctx=tr.make_context(self.pki.ca_pem))
        self.assertEqual(cm.exception.kind, "tls")
        self.assertEqual(hub.requests, [])

    def test_a_reset_or_a_silent_close_after_the_handshake_is_a_tls_failure(self):
        """TLS 1.3: a refused client certificate can surface as a reset, or an empty close, on the first read
        instead of an alert. It must count towards the three in a row, or the rule breaks on a real network."""
        for resp in (Reset(), Raw(b"")):
            hub = self.hub(lambda r, resp=resp: resp)
            with self.assertRaises(tr.TransportError) as cm:
                self.get(hub)
            self.assertEqual(cm.exception.kind, "tls", resp)
            c = tr.HubClient(lambda hub=hub: tr.Target(["127.0.0.1"], hub.port, self.pki.ca_pem, self.cert, self.key, "gen-1"))
            ocs = [c.call("heartbeat", "POST", "/v1/heartbeat", body=b"{}")[1] for _ in range(3)]
            self.assertEqual([o.action for o in ocs], [tr.BACKOFF, tr.BACKOFF, tr.FORBIDDEN])
            self.assertEqual(ocs[2].code, "tls_rejected")

    def test_a_reset_in_the_middle_of_a_reply_is_a_network_error(self):
        def half(req):
            return Raw(b"HTTP/1.0 200 OK\r\nContent-Length: 100\r\n\r\nab")
        hub = self.hub(half)
        with self.assertRaises(tr.TransportError) as cm:
            self.get(hub)
        self.assertEqual(cm.exception.kind, "protocol")                # cut short, not a certificate problem

    def test_connection_refused_is_a_network_error(self):
        hub = FakeHub(self.pki, lambda r: reply(200))
        port = hub.port
        hub.stop()
        with self.assertRaises(tr.TransportError) as cm:
            tr.request("127.0.0.1", port, "GET", "/v1/policy", ctx=self.ctx())
        self.assertEqual(cm.exception.kind, "network")


class TestBounds(TransportCase):
    def test_body_over_16_mib_declared(self):
        hub = self.hub(lambda r: Stream(200, {"Content-Length": str(16 * 1024 * 1024 + 1)}, [b"x" * 1000]))
        with self.assertRaises(tr.TransportError) as cm:
            self.get(hub)
        self.assertEqual(cm.exception.kind, "protocol")
        self.assertIn("16777216", str(cm.exception))

    def test_body_over_16_mib_streamed_without_length(self):
        chunk = b"y" * 65536
        hub = self.hub(lambda r: Stream(200, {}, (chunk for _ in range(300))))
        with self.assertRaises(tr.TransportError) as cm:
            self.get(hub)
        self.assertEqual(cm.exception.kind, "protocol")

    def test_body_of_exactly_the_limit_is_read(self):
        n = 2 * 1024 * 1024
        hub = self.hub(lambda r: reply(200, body=b"z" * n))
        r = self.get(hub, max_body=n)
        self.assertEqual(len(r.body), n)
        with self.assertRaises(tr.TransportError):
            self.get(hub, max_body=n - 1)

    def test_headers_over_16_kib(self):
        hub = self.hub(lambda r: Raw(b"HTTP/1.0 200 OK\r\nX-Fill: " + b"a" * 20000 + b"\r\n\r\nbody"))
        with self.assertRaises(tr.TransportError) as cm:
            self.get(hub)
        self.assertEqual(cm.exception.kind, "protocol")
        self.assertIn("16384", str(cm.exception))

    def test_too_many_header_lines(self):
        hdrs = b"".join(b"X-%d: 1\r\n" % i for i in range(150))
        hub = self.hub(lambda r: Raw(b"HTTP/1.0 200 OK\r\n" + hdrs + b"\r\nbody"))
        with self.assertRaises(tr.TransportError):
            self.get(hub)

    def test_total_deadline(self):
        def slow(req):
            time.sleep(3)
            return reply(200)
        hub = self.hub(slow)
        t0 = time.time()
        with self.assertRaises(tr.TransportError) as cm:
            self.get(hub, total_s=1.0)
        self.assertEqual(cm.exception.kind, "timeout")
        self.assertLess(time.time() - t0, 2.5)

    def test_slow_drip_cannot_outlast_the_deadline(self):
        def drip(req):
            def gen():
                for _ in range(40):
                    time.sleep(0.1)
                    yield b"x"
            return Stream(200, {}, gen())
        hub = self.hub(drip)
        t0 = time.time()
        with self.assertRaises(tr.TransportError) as cm:
            self.get(hub, total_s=1.0)
        self.assertEqual(cm.exception.kind, "timeout")
        self.assertLess(time.time() - t0, 2.5)

    def test_malformed_replies(self):
        bad = [b"garbage\r\n\r\n", b"HTTP/1.0 20 OK\r\n\r\n", b"HTTP/2 200 OK\r\n\r\n", b"HTTP/1.0 200 OK\r\nbroken header\r\n\r\n",
               b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
               b"HTTP/1.0 200 OK\r\nContent-Length: abc\r\n\r\n",
               b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nabcdef",
               b"HTTP/1.0 200 OK\r\nContent-Length: 10\r\n\r\nshort"]
        for raw in bad:
            hub = self.hub(lambda r, raw=raw: Raw(raw))
            with self.assertRaises(tr.TransportError, msg=raw):
                self.get(hub)

    def test_304_has_no_body_and_close_delimited_body_is_read(self):
        hub = self.hub(lambda r: Raw(b"HTTP/1.0 304 Not Modified\r\nETag: \"abc\"\r\n\r\n"))
        r = self.get(hub)
        self.assertEqual((r.status, r.body, r.headers["etag"]), (304, b"", '"abc"'))
        hub = self.hub(lambda r: Raw(b"HTTP/1.0 200 OK\r\n\r\nuntil close"))
        self.assertEqual(self.get(hub).body, b"until close")


def R(status, headers=None, code=""):
    body = json.dumps({"error": code or "x", "code": code}).encode() if status >= 400 else b"{}"
    return tr.Reply(status, "", {k.lower(): v for k, v in (headers or {}).items()}, body)


class TestStatusTable(unittest.TestCase):
    """Every row of hub Appendix A, What the client does for each status."""

    def check(self, route, status, action, code="", headers=None, nevents=None, wait=None):
        oc = tr.interpret(route, R(status, headers, code), nevents)
        self.assertEqual(oc.action, action, (route, status, code))
        if wait is not None:
            self.assertEqual(oc.wait, wait)
        return oc

    def test_200_and_304(self):
        for route in ("events", "heartbeat", "policy", "renew", "enroll", "ca", "deregister"):
            self.check(route, 200, tr.OK)
        self.check("policy", 304, tr.UNCHANGED)

    def test_400_413_on_events_split_once_or_reject_a_single_event(self):
        self.check("events", 400, tr.SPLIT, "bad_schema", nevents=40)
        self.check("events", 413, tr.SPLIT, "too_large", nevents=40)
        self.check("events", 400, tr.REJECT, "bad_schema", nevents=1)
        self.check("events", 413, tr.REJECT, "too_large", nevents=1)

    def test_400_413_elsewhere_keep_the_previous_state(self):
        for route in ("heartbeat", "policy", "renew", "deregister"):
            self.check(route, 400, tr.LOG_RETRY, "bad_request")
            self.check(route, 413, tr.LOG_RETRY, "too_large")
        self.check("enroll", 400, tr.STOP, "bad_request")

    def test_422_is_never_split_and_retried_hourly(self):
        oc = self.check("events", 422, tr.HOLD, "schema_too_old", nevents=100, wait=3600)
        self.assertEqual(oc.code, "schema_too_old")

    def test_426_hold_hourly(self):
        for route in ("events", "heartbeat", "policy", "renew"):
            self.check(route, 426, tr.HOLD, "proto_unsupported", wait=3600)

    def test_401_enroll_stops(self):
        oc = self.check("enroll", 401, tr.STOP, "invalid_token")
        self.assertIn("token", oc.note)

    def test_403_host_orphan_only_on_policy_and_renew(self):
        self.check("policy", 403, tr.ORPHAN, "host_orphan", wait=3600)
        self.check("renew", 403, tr.ORPHAN, "host_orphan", wait=3600)
        self.check("events", 403, tr.FORBIDDEN, "host_orphan")
        self.check("heartbeat", 403, tr.FORBIDDEN, "host_orphan")

    def test_other_403_stops_sending(self):
        for code in ("host_unknown", "host_revoked", "host_moved", "host_retired", "cert_superseded"):
            for route in ("events", "heartbeat", "policy", "renew", "deregister"):
                oc = self.check(route, 403, tr.FORBIDDEN, code, wait=3600)
                self.assertEqual(oc.code, code)
        self.assertEqual(tr.interpret("events", R(403)).code, "forbidden")

    def test_409_enroll(self):
        self.check("enroll", 409, tr.STOP, "host_exists")

    def test_411_414_431_log_and_keep(self):
        for st in (411, 414, 431):
            self.check("events", st, tr.LOG_RETRY, "length_required", nevents=50)          # an events batch stays unsplit
            self.check("heartbeat", st, tr.LOG_RETRY)

    def test_429_503_wait_retry_after_capped_at_one_hour(self):
        self.check("events", 429, tr.WAIT, "rate_limited", {"Retry-After": "7"}, wait=7)
        self.check("events", 503, tr.WAIT, "busy", {"Retry-After": "120"}, wait=120)
        self.check("heartbeat", 429, tr.WAIT, "rate_limited", {"Retry-After": "99999"}, wait=3600)
        self.check("policy", 503, tr.WAIT, "storage_full", {"Retry-After": "3601"}, wait=3600)

    def test_429_503_without_a_usable_header_back_off_as_5xx(self):
        self.check("events", 429, tr.BACKOFF, "rate_limited")
        self.check("events", 503, tr.BACKOFF, "busy")
        self.check("events", 503, tr.BACKOFF, "busy", {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})
        self.check("events", 503, tr.BACKOFF, "busy", {"Retry-After": "-5"})
        self.check("events", 429, tr.BACKOFF, "busy", {"Retry-After": ""})

    def test_other_5xx_back_off(self):
        for st in (500, 502, 504, 599):
            self.check("events", st, tr.BACKOFF)

    def test_odd_statuses(self):
        self.check("events", 404, tr.LOG_RETRY)
        self.check("events", 302, tr.BACKOFF)
        self.check("events", 204, tr.BACKOFF)

    def test_retry_after_parsing(self):
        for v, want in (("0", 0), ("5", 5), ("3600", 3600), ("86400", 3600), ("007", 7)):
            self.assertEqual(R(429, {"Retry-After": v}).retry_after(), want, v)
        for v in ("", "-1", "1.5", "abc", "1e3", "9" * 20):
            if v == "9" * 20:
                self.assertIsNone(R(429, {"Retry-After": v}).retry_after())
            else:
                self.assertIsNone(R(429, {"Retry-After": v}).retry_after(), v)

    def test_error_code_of_a_bad_body(self):
        r = tr.Reply(403, "", {}, b"not json")
        self.assertEqual(r.error_code(), "")
        self.assertEqual(tr.interpret("events", r).action, tr.FORBIDDEN)
        r = tr.Reply(403, "", {}, json.dumps({"code": "x" * 500}).encode())
        self.assertEqual(len(r.error_code()), 64)


class TestHubClient(TransportCase):
    def target(self, hub, addresses=("127.0.0.1",)):
        return lambda: tr.Target(list(addresses), hub.port, self.pki.ca_pem, self.cert, self.key, "gen-1")

    def test_statuses_over_the_wire(self):
        script = {"events": err(413, "too_large"), "heartbeat": reply(200, {"hub_time": 5, "policy_rev": "b" * 16, "min_client_schema": 0}),
                  "policy": reply(304, body=b""), "renew": err(403, "host_orphan"),
                  "deregister": err(429, "rate_limited", {"Retry-After": "99999"})}
        hub = self.hub(lambda r: script[r.path.split("/")[-1]])
        c = tr.HubClient(self.target(hub))
        rep, oc = c.call("events", "POST", "/v1/events", body=b"x", nevents=10)
        self.assertEqual((oc.action, oc.status, oc.code), (tr.SPLIT, 413, "too_large"))
        rep, oc = c.call("events", "POST", "/v1/events", body=b"x", nevents=1)
        self.assertEqual(oc.action, tr.REJECT)
        rep, oc = c.call("heartbeat", "POST", "/v1/heartbeat", body=b"{}")
        self.assertEqual(oc.action, tr.OK)
        self.assertEqual(rep.json()["hub_time"], 5)
        rep, oc = c.call("policy", "GET", "/v1/policy", headers={"If-None-Match": '"abc"'})
        self.assertEqual(oc.action, tr.UNCHANGED)
        self.assertEqual(hub.requests[-1].headers["if-none-match"], '"abc"')
        rep, oc = c.call("renew", "POST", "/v1/renew", body=b"{}")
        self.assertEqual(oc.action, tr.ORPHAN)
        rep, oc = c.call("deregister", "POST", "/v1/deregister", body=b"{}")
        self.assertEqual((oc.action, oc.wait), (tr.WAIT, 3600.0))
        self.assertEqual(c.last_gen, "gen-1")

    def test_three_handshake_failures_in_a_row_count_as_a_403(self):
        evil = PKI(cn="Evil CA")
        self.addCleanup(evil.cleanup)
        ec, ek = evil.client()
        hub = self.hub(lambda r: reply(200))
        c = tr.HubClient(lambda: tr.Target(["127.0.0.1"], hub.port, self.pki.ca_pem, ec, ek, "gen-1"))
        ocs = [c.call("heartbeat", "POST", "/v1/heartbeat", body=b"{}")[1] for _ in range(3)]
        self.assertEqual([o.action for o in ocs], [tr.BACKOFF, tr.BACKOFF, tr.FORBIDDEN])
        self.assertEqual(ocs[0].code, "tls")
        self.assertEqual(ocs[2].code, "tls_rejected")
        self.assertEqual(ocs[2].wait, 3600)
        self.assertEqual(c.last_code, "tls_rejected")
        # a good answer resets the count
        good = tr.HubClient(self.target(hub))
        c.target_fn = self.target(hub)
        c.tls_fails = 2
        _, oc = c.call("heartbeat", "POST", "/v1/heartbeat", body=b"{}")
        self.assertEqual(oc.action, tr.OK)
        self.assertEqual(c.tls_fails, 0)
        del good

    def test_one_tls_failure_between_network_errors_is_not_three(self):
        evil = PKI(cn="Evil CA")
        self.addCleanup(evil.cleanup)
        ec, ek = evil.client()
        hub = self.hub(lambda r: reply(200))
        c = tr.HubClient(lambda: tr.Target(["127.0.0.1"], hub.port, self.pki.ca_pem, ec, ek, "gen-1"))
        for _ in range(2):
            c.call("heartbeat", "POST", "/v1/heartbeat", body=b"{}")
        dead = FakeHub(self.pki, lambda r: reply(200))
        deadport = dead.port
        dead.stop()
        c.target_fn = lambda: tr.Target(["127.0.0.1"], deadport, self.pki.ca_pem, ec, ek, "gen-1")
        _, oc = c.call("heartbeat", "POST", "/v1/heartbeat", body=b"{}")
        self.assertEqual((oc.action, oc.code), (tr.BACKOFF, "network"))
        self.assertEqual(c.tls_fails, 0)

    def test_next_hub_address_is_tried(self):
        hub = self.hub(lambda r: reply(200, {"ok": 1}))
        c = tr.HubClient(self.target(hub, ["127.0.0.2", "127.0.0.1"]))
        rep, oc = c.call("policy", "GET", "/v1/policy")
        self.assertEqual(oc.action, tr.OK)
        self.assertEqual(c.preferred, 1)                    # the working one is tried first from now on

    def test_not_enrolled(self):
        c = tr.HubClient(lambda: None)
        rep, oc = c.call("policy", "GET", "/v1/policy")
        self.assertIsNone(rep)
        self.assertEqual((oc.action, oc.code), (tr.BACKOFF, "not_enrolled"))

    def test_missing_or_broken_identity_files_do_not_raise(self):
        c = tr.HubClient(lambda: tr.Target(["127.0.0.1"], 18999, "/nonexistent/ca.pem", "/nonexistent/c.pem", "/nonexistent/c.key", "gen-9"))
        rep, oc = c.call("policy", "GET", "/v1/policy")
        self.assertIsNone(rep)
        self.assertEqual(oc.action, tr.BACKOFF)


class TestBackoff(unittest.TestCase):
    def test_full_jitter_bounds_and_cap(self):
        rng = random.Random(5)
        for cap in (60, 300):
            bo = tr.Backoff(cap, rng=rng)
            ceilings = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]
            for i, c in enumerate(ceilings):
                d = bo.failure()
                self.assertGreaterEqual(d, 0)
                self.assertLessEqual(d, min(cap, c))
            bo.reset()
            self.assertLessEqual(bo.failure(), 1)

    def test_jitter_is_full_not_fixed(self):
        rng = random.Random(1)
        samples = set()
        for _ in range(50):
            bo = tr.Backoff(300, rng=rng)
            for _ in range(8):
                d = bo.failure()
            samples.add(round(d, 3))
        self.assertGreater(len(samples), 30)
        self.assertLess(min(samples), 100)
        self.assertGreater(max(samples), 100)
        self.assertLessEqual(max(samples), 128)       # the eighth failure's ceiling is 2**7

    def test_never_zero(self):
        bo = tr.Backoff(60, rng=random.Random(2))
        self.assertTrue(all(bo.failure() > 0 for _ in range(100)))


class TestEventsBody(unittest.TestCase):
    def ev(self, i, pad=50):
        return {"v": 1, "id": "0000abcd:%d" % i, "epoch": 0xabcd, "seq": i, "ts": "2026-11-19T10:00:00.000Z", "sev": "LOW",
                "kind": "x.y", "source": "nginx", "summary": "s", "pad": "x" * pad}

    def test_envelope_shape_and_gzip(self):
        body, used, bid = tr.build_events_body([self.ev(i) for i in range(10)], sent_at="2026-11-19T10:15:03.120Z")
        d = json.loads(gzip.decompress(body))
        self.assertEqual(used, 10)
        self.assertEqual(set(d), {"batch_id", "sent_at", "events"})
        self.assertEqual(d["batch_id"], bid)
        self.assertEqual(d["sent_at"], "2026-11-19T10:15:03.120Z")
        self.assertEqual(len(d["events"]), 10)
        self.assertEqual(gzip.decompress(body)[:1], b"{")

    def test_batch_id_kept_and_sent_at_fresh(self):
        b1, _, bid = tr.build_events_body([self.ev(1)])
        time.sleep(0.01)
        b2, _, bid2 = tr.build_events_body([self.ev(1)], batch_id=bid)
        self.assertEqual(bid, bid2)
        self.assertRegex(json.loads(gzip.decompress(b1))["sent_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")

    def test_at_most_500_events(self):
        body, used, _ = tr.build_events_body([self.ev(i, 5) for i in range(800)])
        self.assertEqual(used, 500)

    def test_raw_cap_3_mib_and_gz_cap_1_mib(self):
        rnd = random.Random(3)
        big = []
        for i in range(500):
            e = self.ev(i)
            e["pad"] = "".join(chr(rnd.randint(33, 126)) for _ in range(5000))     # does not compress
            big.append(e)
        body, used, _ = tr.build_events_body(big)
        self.assertGreater(used, 0)
        self.assertLess(used, 500)
        self.assertLessEqual(len(body), 1024 * 1024)
        self.assertLessEqual(len(gzip.decompress(body)), 3 * 1024 * 1024)
        d = json.loads(gzip.decompress(body))
        self.assertEqual([e["seq"] for e in d["events"]], list(range(used)))          # a prefix: order kept

    def test_single_event_too_big_gives_zero(self):
        import base64
        e = self.ev(1)
        e["pad"] = base64.b64encode(random.Random(4).randbytes(1300000)).decode()
        body, used, _ = tr.build_events_body([e])
        self.assertEqual((body, used), (b"", 0))


if __name__ == "__main__":
    unittest.main()
