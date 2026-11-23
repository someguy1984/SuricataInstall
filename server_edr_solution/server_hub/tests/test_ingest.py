"""The two TLS listeners, the limits, the seven routes (PLAN.md section 2, section 3 and Appendix A; section 12 L0 rows
"Request parser and limits", "Identity", "Storage" and the slow-client tests of L2). Everything here talks real mutual
TLS 1.3 to the real server on 127.0.0.1."""

import gzip
import io
import json
import os
import socket
import ssl
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_ingest_fixture as F  # noqa: E402

import hub_common  # noqa: E402
import hub_db  # noqa: E402
import hub_enroll  # noqa: E402
import hub_ingest  # noqa: E402
import hub_pki  # noqa: E402

DAY = 86_400_000
_seq = [100]


def next_seq():
    _seq[0] += 1
    return _seq[0]


def ev(**kw):
    """A fresh valid event with a unique id."""
    kw.setdefault("seq", next_seq())
    return F.make_event(**kw)


def code_of(body):
    return json.loads(body)["code"]


def ts_ago(seconds):
    return hub_common.ms_to_rfc3339(hub_common.now_ms() - int(seconds * 1000))


def gz_json(obj):
    return gzip.compress(json.dumps(obj).encode())


class IngestCase(F.HubTestCase):
    """A fresh hub and one enrolled client per test."""

    def setUp(self):
        super().setUp()
        self.c = self.fx.enroll("web1")

    def events(self, where="1=1", params=()):
        return self.fx.sql("SELECT * FROM events WHERE %s ORDER BY id" % where, params)

    def host(self, uuid=None):
        return self.fx.sql("SELECT * FROM hosts WHERE uuid=?", (uuid or self.c.uuid,))[0]

    def extra_client(self, name):
        return self.fx.enroll(name)


# =================================================================================================
# Transport: handshakes, deadlines, slots
# =================================================================================================
class TransportTest(IngestCase):
    def test_contexts_are_tls13_strict_ticketless(self):
        fleet, enroll = self.fx.hub.ingest.contexts["fleet"], self.fx.hub.ingest.contexts["enroll"]
        for ctx in (fleet, enroll):
            self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_3)
            self.assertEqual(ctx.num_tickets, 0)
            self.assertTrue(ctx.verify_flags & ssl.VERIFY_X509_STRICT)
        self.assertEqual(fleet.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(enroll.verify_mode, ssl.CERT_NONE)

    def test_no_client_certificate_fails_the_handshake_and_never_reaches_the_parser(self):
        before = dict(self.fx.hub.ingest.stats)
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            self.c.request("GET", "/v1/policy", with_cert=False)
        time.sleep(0.3)
        after = self.fx.hub.ingest.stats
        self.assertEqual(after["requests"], before["requests"])
        self.assertGreater(after["handshake_failed"], before["handshake_failed"])

    def test_certificate_from_another_ca_fails_the_handshake(self):
        import tempfile
        d = tempfile.mkdtemp(dir=F.SCRATCH)
        p = hub_common.Paths(state_dir=d, run_dir=d, etc_dir=d)
        hub_pki.init_ca(p)
        other = hub_pki.Pki(p)
        key, csr = F.make_key_and_csr(d)
        pem = other.sign_client(csr, self.c.uuid)["pem"]
        stranger = F.Client(self.fx, key_path=key)
        stranger.ca_pem = self.fx.hub.pki.ca_pem()
        stranger.cert_path = os.path.join(d, "c.pem")
        with open(stranger.cert_path, "w") as f:
            f.write(pem)
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            stranger.request("GET", "/v1/policy")

    def test_expired_certificate_fails_the_handshake(self):
        key, csr = F.make_key_and_csr(self.fx.tmp)
        pub = os.path.join(self.fx.tmp, "pub.pem")
        with open(pub, "wb") as f:
            f.write(F.openssl("req", "-noout", "-pubkey", stdin=csr.encode()))
        out = os.path.join(self.fx.tmp, "expired.pem")
        F.openssl("x509", "-new", "-force_pubkey", pub, "-subj", "/CN=" + self.c.uuid, "-CA", self.fx.paths.ca_cert, "-CAkey",
                  self.fx.paths.ca_key, "-sha384", "-extfile", self.fx.hub.paths.find_data("pki", "strict", "cli.ext"),
                  "-not_before", "20200101000000Z", "-not_after", "20200102000000Z", "-out", out)
        old = F.Client(self.fx, key_path=key)
        old.ca_pem = self.fx.hub.pki.ca_pem()
        old.cert_path = out
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            old.request("GET", "/v1/policy")

    def test_tls12_is_refused(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.load_cert_chain(self.c.cert_path, self.c.key_path)
        raw = socket.create_connection(("127.0.0.1", self.fx.fleet_port), timeout=5)
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as s:
                s.sendall(b"GET /v1/policy HTTP/1.0\r\n\r\n")
                s.recv(10)

    def test_plain_http_to_the_tls_port_is_closed_and_the_server_lives(self):
        s = socket.create_connection(("127.0.0.1", self.fx.fleet_port), timeout=5)
        s.sendall(b"GET /v1/policy HTTP/1.0\r\n\r\n")
        s.settimeout(5)
        try:
            data = s.recv(100)
        except OSError:
            data = b""
        self.assertNotIn(b"200", data)
        s.close()
        self.assertEqual(self.c.heartbeat()[0], 200)

    def test_handshake_deadline_cuts_a_silent_connection(self):
        s = socket.create_connection(("127.0.0.1", self.fx.fleet_port), timeout=10)
        t0 = time.monotonic()
        s.settimeout(10)
        try:
            data = s.recv(10)
        except OSError:
            data = b""
        took = time.monotonic() - t0
        s.close()
        self.assertEqual(data, b"")
        self.assertGreater(took, 2.0)
        self.assertLess(took, 5.5)                        # 3 s from accept, plus the reaper's tick

    def test_a_trickling_client_is_cut_by_the_wall_clock_reaper(self):
        s = self.c.connect()
        s.settimeout(0.2)
        request = b"GET /v1/policy HTTP/1.0\r\nX-EDR-Proto: 1\r\nX-Padding: " + b"a" * 80
        t0 = time.monotonic()
        sent = 0
        cut_after = None
        while time.monotonic() - t0 < 12:
            try:
                s.sendall(request[sent:sent + 1])
                sent += 1
            except (OSError, ssl.SSLError):
                cut_after = time.monotonic() - t0
                break
            try:
                if s.recv(1) == b"":
                    cut_after = time.monotonic() - t0
                    break
            except socket.timeout:
                pass
            except (OSError, ssl.SSLError):
                cut_after = time.monotonic() - t0
                break
            time.sleep(0.8)
        s.close()
        self.assertIsNotNone(cut_after, "still connected after 12 s")
        self.assertGreater(cut_after, 3.5)
        self.assertLess(cut_after, 8.0)                    # header deadline 5 s (not per-read)
        self.assertGreater(self.fx.hub.ingest.reaper.cut, 0)

    def test_slow_body_is_cut_at_the_request_deadline(self):
        s = self.c.connect()
        s.sendall(b"POST /v1/heartbeat HTTP/1.0\r\nX-EDR-Proto: 1\r\nContent-Length: 1000\r\n\r\n{")
        t0 = time.monotonic()
        s.settimeout(25)
        try:
            data = s.recv(1000)
        except (OSError, ssl.SSLError):
            data = b""
        took = time.monotonic() - t0
        s.close()
        self.assertGreater(took, 12)
        self.assertLess(took, 19)                          # 15 s from the handshake

    def test_one_slow_client_does_not_block_the_accept_loop(self):
        slow = socket.create_connection(("127.0.0.1", self.fx.fleet_port), timeout=5)       # never handshakes
        try:
            t0 = time.monotonic()
            self.assertEqual(self.c.heartbeat()[0], 200)
            self.assertLess(time.monotonic() - t0, 2.0)
        finally:
            slow.close()

    def test_slot_cap_closes_the_socket_at_once(self):
        with mock.patch.object(hub_common, "SLOTS_FLEET", 3), mock.patch.object(hub_common, "SLOTS_PER_SOURCE", 100):
            self.fx.hub.ingest.fleet.close()
            self.fx.hub.ingest.fleet = hub_ingest.Listener(self.fx.hub.ingest, "fleet", "127.0.0.1", self.fx.fleet_port,
                                                           hub_common.SLOTS_FLEET)
            self.fx.hub.ingest.fleet.open()
            held = [socket.create_connection(("127.0.0.1", self.fx.fleet_port), timeout=5) for _ in range(3)]
            try:
                time.sleep(0.2)
                extra = socket.create_connection(("127.0.0.1", self.fx.fleet_port), timeout=5)
                extra.settimeout(2)
                t0 = time.monotonic()
                try:
                    data = extra.recv(10)
                except OSError:
                    data = b""
                self.assertEqual(data, b"")
                self.assertLess(time.monotonic() - t0, 1.0)        # closed at once, not after a deadline
                extra.close()
                self.assertGreaterEqual(self.fx.hub.ingest.fleet.refused_slots, 1)
            finally:
                for h in held:
                    h.close()

    def test_per_source_cap_is_four(self):
        listener = self.fx.hub.ingest.fleet
        held = [socket.create_connection(("127.0.0.1", self.fx.fleet_port), timeout=5) for _ in range(hub_common.SLOTS_PER_SOURCE)]
        try:
            time.sleep(0.3)
            self.assertEqual(listener.source_counts().get("127.0.0.1"), 4)
            extra = socket.create_connection(("127.0.0.1", self.fx.fleet_port), timeout=5)
            extra.settimeout(2)
            try:
                data = extra.recv(10)
            except OSError:
                data = b""
            self.assertEqual(data, b"")
            extra.close()
            self.assertGreaterEqual(listener.refused_source, 1)
        finally:
            for h in held:
                h.close()
        time.sleep(0.5)
        self.assertEqual(self.c.heartbeat()[0], 200)                 # slots come back when the connections end

    def test_ipv6_sources_share_a_slash_64(self):
        self.assertEqual(hub_common.source_key("2001:db8:1:2::5"), hub_common.source_key("2001:db8:1:2:ffff::1"))
        self.assertNotEqual(hub_common.source_key("2001:db8:1:2::5"), hub_common.source_key("2001:db8:1:3::5"))
        self.assertEqual(hub_common.source_key("::ffff:10.1.2.3"), "10.1.2.3")

    def test_four_requests_per_certificate_the_fifth_is_429(self):
        with mock.patch.object(hub_common, "SLOTS_PER_SOURCE", 100):
            held = []
            try:
                for _ in range(hub_common.REQUESTS_PER_CERT):
                    s = self.c.connect()
                    s.sendall(b"POST /v1/heartbeat HTTP/1.0\r\nX-EDR-Proto: 1\r\nContent-Length: 500\r\n\r\n")   # waiting for a body
                    held.append(s)
                time.sleep(0.5)
                status, headers, body = self.c.request("GET", "/v1/policy")
                self.assertEqual(status, 429)
                self.assertEqual(code_of(body), "rate_limited")
                self.assertRegex(headers["retry-after"], r"^\d+$")
            finally:
                for s in held:
                    s.close()
            time.sleep(0.5)
            self.assertEqual(self.c.request("GET", "/v1/policy")[0], 200)

    def test_parse_semaphore_of_four_gives_503_with_retry_after(self):
        with mock.patch.object(hub_common, "SLOTS_PER_SOURCE", 100):
            clients = [self.extra_client("w%d" % i) for i in range(2)]
            held = []
            try:
                for i in range(hub_common.PARSE_SLOTS):
                    s = clients[i % 2].connect()
                    s.sendall(b"POST /v1/heartbeat HTTP/1.0\r\nX-EDR-Proto: 1\r\nContent-Length: 500\r\n\r\n")
                    held.append(s)
                time.sleep(0.5)
                status, headers, body = self.c.heartbeat()
                self.assertEqual(status, 503)
                self.assertEqual(code_of(body), "busy")
                self.assertRegex(headers["retry-after"], r"^\d+$")
            finally:
                for s in held:
                    s.close()
            time.sleep(0.5)
            self.assertEqual(self.c.heartbeat()[0], 200)


# =================================================================================================
# The request parser
# =================================================================================================
class ParserTest(IngestCase):
    def raw(self, data, **kw):
        return self.c.raw_request(data, **kw)

    def test_oversize_header_is_431(self):
        status, _h, body = self.raw(b"GET /v1/policy HTTP/1.0\r\nX-EDR-Proto: 1\r\nX-Big: " + b"a" * 9000 + b"\r\n\r\n")
        self.assertEqual((status, code_of(body)), (431, "header_too_large"))

    def test_header_at_the_limit_is_accepted_and_past_it_is_431(self):
        base = b"GET /v1/policy HTTP/1.0\r\nX-EDR-Proto: 1\r\n"
        used = len(base) + len(b"\r\n")
        pad = 8192 - used - len(b"X-P: \r\n")
        ok = base + b"X-P: " + b"a" * pad + b"\r\n\r\n"
        self.assertEqual(len(ok), 8192)
        self.assertEqual(self.raw(ok)[0], 200)
        self.assertEqual(self.raw(ok.replace(b"X-P: a", b"X-P: aa"))[0], 431)

    def test_32_lines_including_the_request_line(self):
        def req(n_headers):
            lines = [b"GET /v1/policy HTTP/1.0", b"X-EDR-Proto: 1"] + [b"X-H%d: v" % i for i in range(n_headers - 1)]
            return b"\r\n".join(lines) + b"\r\n\r\n"
        self.assertEqual(self.raw(req(31))[0], 200)         # request line + 31 headers
        status, _h, body = self.raw(req(32))
        self.assertEqual((status, code_of(body)), (431, "header_too_large"))

    def test_framing_errors(self):
        base = "POST /v1/heartbeat HTTP/1.0\r\nX-EDR-Proto: 1\r\n"
        cases = {
            "no content-length": (base + "\r\n", 411, "length_required"),
            "transfer-encoding": (base + "Transfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}", 400, "bad_request"),
            "expect": (base + "Expect: 100-continue\r\nContent-Length: 2\r\n\r\n{}", 400, "bad_request"),
            "bad content-length": (base + "Content-Length: abc\r\n\r\n", 400, "bad_request"),
            "negative content-length": (base + "Content-Length: -1\r\n\r\n", 400, "bad_request"),
            "two content-lengths": (base + "Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}", 400, "bad_request"),
            "obs-fold": (base + "Content-Length: 2\r\n  folded\r\n\r\n{}", 400, "bad_request"),
            "no colon": (base + "garbage\r\nContent-Length: 2\r\n\r\n{}", 400, "bad_request"),
            "control char in value": (base + "X-A: a\x01b\r\nContent-Length: 2\r\n\r\n{}", 400, "bad_request"),
            "bad name": (base + "X A: b\r\nContent-Length: 2\r\n\r\n{}", 400, "bad_request"),
        }
        for name, (data, status, code) in cases.items():
            got = self.raw(data.encode("latin-1"))
            self.assertEqual((got[0], code_of(got[2])), (status, code), name)

    def test_bad_request_lines(self):
        for data in (b"GET\r\n\r\n", b"GET /v1/policy\r\n\r\n", b"GET /v1/policy HTTP/2.0\r\n\r\n", b"get /v1/policy HTTP/1.0\r\n\r\n",
                     b"GET v1/policy HTTP/1.0\r\n\r\n", b"GET /v1/policy HTTP/1.0 extra\r\n\r\n", b"\r\n"):
            got = self.raw(data)
            self.assertEqual((got[0], code_of(got[2])), (400, "bad_request"), data)

    def test_a_get_with_a_body_is_refused(self):
        got = self.raw(b"GET /v1/policy HTTP/1.0\r\nX-EDR-Proto: 1\r\nContent-Length: 4\r\n\r\nabcd")
        self.assertEqual((got[0], code_of(got[2])), (400, "bad_request"))

    def test_routes_methods_and_unknown_paths(self):
        self.assertEqual(code_of(self.c.request("GET", "/nope")[2]), "not_found")
        self.assertEqual(self.c.request("GET", "/v1/heartbeat")[0], 405)
        self.assertEqual(self.c.request("POST", "/v1/policy", b"{}")[0], 405)
        self.assertEqual(self.c.request("PUT", "/v1/policy")[0], 405)
        self.assertEqual(self.c.request("DELETE", "/v1/events")[0], 405)
        self.assertEqual(self.c.request("HEAD", "/v1/policy")[0], 405)
        self.assertEqual(self.c.request("GET", "/v1/ca")[0], 404)         # an enrollment route on the fleet port
        self.assertEqual(self.c.request("GET", "/v1/policy?x=1")[0], 200)  # a query string is ignored

    def test_no_request_text_is_ever_echoed_and_headers_are_fixed(self):
        marker = "SECRET-MARKER-123"
        status, headers, body = self.c.request("GET", "/" + marker, headers={"X-Mine": marker})
        self.assertEqual(status, 404)
        self.assertNotIn(marker.encode(), body)
        self.assertNotIn("server", headers)
        self.assertNotIn("date", headers)
        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(int(headers["content-length"]), len(body))
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertEqual(json.loads(body), {"error": hub_common.ERRORS["not_found"][1], "code": "not_found"})

    def test_proto_header(self):
        for proto in ("0", "2", "99", "abc", "", "-1", "1.0"):
            status, _h, body = self.c.request("GET", "/v1/policy", proto=proto)
            self.assertEqual((status, code_of(body)), (426, "proto_unsupported"), proto)
        status, _h, body = self.c.request("GET", "/v1/policy", proto=None)
        self.assertEqual((status, code_of(body)), (426, "proto_unsupported"))
        self.assertEqual(self.c.request("GET", "/v1/policy", proto="1")[0], 200)

    def test_proto_0_on_events_is_426_and_stores_nothing(self):
        status, _h, body = self.c.send_events([ev()], proto="0")
        self.assertEqual((status, code_of(body)), (426, "proto_unsupported"))
        self.assertEqual(self.events(), [])

    def test_content_length_over_the_cap_is_413_without_reading_the_body(self):
        head = b"POST /v1/events HTTP/1.0\r\nX-EDR-Proto: 1\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n"
        got = self.raw(head % (hub_common.BODY_MAX_COMPRESSED + 1))
        self.assertEqual((got[0], code_of(got[2])), (413, "too_large"))
        got = self.raw(b"POST /v1/heartbeat HTTP/1.0\r\nX-EDR-Proto: 1\r\nContent-Length: %d\r\n\r\n" % (256 * 1024 + 1))
        self.assertEqual(got[0], 413)

    def test_body_shorter_than_content_length_is_400(self):
        s = self.c.connect()
        s.sendall(b"POST /v1/heartbeat HTTP/1.0\r\nX-EDR-Proto: 1\r\nContent-Length: 50\r\n\r\n{}")
        s.close()                                                   # the body never completes
        self.assertEqual(self.c.heartbeat()[0], 200)                # nothing broke

    def test_read_head_unit(self):
        head = hub_ingest.read_head(io.BufferedReader(io.BytesIO(b"POST /v1/events?x=1 HTTP/1.1\r\nHost: a\r\nX-A: b \r\n\r\nBODY")))
        self.assertEqual(head, ("POST", "/v1/events", {"host": "a", "x-a": "b"}))
        for bad in (b"", b"GET / HTTP/1.0", b"GET / HTTP/1.0\r\nX: y"):
            with self.assertRaises(hub_ingest.HttpError):
                hub_ingest.read_head(io.BufferedReader(io.BytesIO(bad)))


# =================================================================================================
# Events: bodies, limits, validation
# =================================================================================================
class EventBodyTest(IngestCase):
    def test_gzip_bomb_is_413(self):
        bomb = gzip.compress(b"0" * (hub_common.BODY_MAX_INFLATED + 10))
        self.assertLess(len(bomb), 100_000)
        status, _h, body = self.c.send_events(None, raw_body=bomb)
        self.assertEqual((status, code_of(body)), (413, "too_large"))
        self.assertEqual(self.c.heartbeat()[0], 200)                # the server survived it

    def test_exactly_the_inflated_cap_is_not_413(self):
        def body(pad):
            return json.dumps({"batch_id": "b", "sent_at": ts_ago(0), "events": [], "p": "x" * pad}).encode()
        pad = hub_common.BODY_MAX_INFLATED - len(body(0))
        self.assertEqual(len(body(pad)), hub_common.BODY_MAX_INFLATED)
        status, _h, resp = self.c.send_events(None, raw_body=gzip.compress(body(pad)))
        self.assertEqual(status, 200)
        status, _h, resp = self.c.send_events(None, raw_body=gzip.compress(body(pad + 1)))
        self.assertEqual((status, code_of(resp)), (413, "too_large"))

    def test_gzip_framing_errors_are_400(self):
        good = gz_json({"batch_id": "b", "sent_at": ts_ago(0), "events": []})
        for name, data in (("truncated", good[:-6]), ("trailing bytes", good + b"junk"), ("not gzip", b"plain text"),
                           ("empty", b""), ("corrupt", good[:12] + b"\xff\xff\xff" + good[15:])):
            status, _h, body = self.c.send_events(None, raw_body=data)
            self.assertEqual((status, code_of(body)), (400, "bad_request"), name)

    def test_a_missing_content_encoding_is_400(self):
        raw = json.dumps({"batch_id": "b", "sent_at": ts_ago(0), "events": []}).encode()
        status, _h, body = self.c.request("POST", "/v1/events", raw)
        self.assertEqual((status, code_of(body)), (400, "bad_request"))

    def test_json_errors_are_400(self):
        for name, raw in (("bad json", b"{nope"), ("recursion", b"[" * 200000), ("bad utf-8", b'{"a":"\xff\xfe"}'),
                          ("NaN", b'{"batch_id":"b","x":NaN}'), ("array", b"[1,2]"), ("scalar", b"5")):
            status, _h, body = self.c.send_events(None, raw_body=gzip.compress(raw))
            self.assertEqual(status, 400, name)
            self.assertIn(code_of(body), ("bad_request", "bad_schema"), name)

    def test_batch_over_500_events_is_413(self):
        status, _h, body = self.c.send_events([ev() for _ in range(501)])
        self.assertEqual((status, code_of(body)), (413, "too_large"))
        self.assertEqual(self.events(), [])
        status, _h, body = self.c.send_events([ev(sev="INFO") for _ in range(500)])
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["accepted"], 500)

    def test_event_over_10_kib_is_413_with_its_index(self):
        big = ev(summary="s")
        big["details"] = {"a": "x" * 500, "b": "x" * 500, "c": ["x" * 500] * 20}
        big["context"] = [{"l": "y" * 400}] * 20
        big["proc"] = {"args": "z" * 1000, "binary": "q" * 500}
        self.assertGreater(len(json.dumps(big)), 10 * 1024)
        status, _h, body = self.c.send_events([ev(), big])
        self.assertEqual(status, 413)
        self.assertEqual(json.loads(body), {"error": hub_common.ERRORS["too_large"][1], "code": "too_large", "index": 1})
        self.assertEqual(self.events(), [])                          # accepted or refused as a whole

    def test_schema_errors_name_the_first_bad_event_and_store_nothing(self):
        bad_cases = {
            "not an object": 5,
            "v missing": {k: v for k, v in ev().items() if k != "v"},
            "v future": ev(v=2),
            "bad id": ev(id="nothex:1"),
            "id does not match": ev(id="00000001:2", epoch=1, seq=3),
            "bad ts": ev(ts="yesterday"),
            "ts without Z": ev(ts="2026-11-19T10:15:03.120+01:00"),
            "bad sev": ev(sev="LOUD"),
            "bad kind": ev(kind="Bad Kind!"),
            "bad source": ev(source="telepathy"),
            "summary too long": ev(summary="x" * 257),
            "details not an object": ev(details=["a"]),
            "details null items": ev(details="text"),
            "details string too long": ev(details={"x": "y" * 513}),
            "args too long": ev(details={"args": "y" * 1025}),
            "details too deep": ev(details={"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": {"j": 1}}}}}}}}}}),
            "bad src_ip": ev(src_ip="not-an-ip"),
            "src_ip with scope": ev(src_ip="fe80::1%eth0"),
            "bad src_trust": ev(src_trust="maybe"),
            "dst_port string": ev(dst_port="80"),
            "dst_port range": ev(dst_port=70000),
            "bool as int": ev(count=True),
            "count zero": ev(count=0),
            "bad first_ts": ev(first_ts="x"),
            "proc not object": ev(proc="x"),
            "context too long": ev(context=[{}] * 21),
            "redacted not bool": ev(redacted="yes"),
            "agent_ver too long": ev(agent_ver="v" * 33),
            "community_id too long": ev(community_id="c" * 65),
        }
        for name, bad in bad_cases.items():
            status, _h, body = self.c.send_events([ev(), bad])
            self.assertEqual(status, 400, name)
            parsed = json.loads(body)
            self.assertIn(parsed["code"], ("bad_schema",), name)
            self.assertEqual(parsed.get("index"), 1, name)
        self.assertEqual(self.events(), [])

    def test_envelope_errors(self):
        now = ts_ago(0)
        for name, batch in (("no batch_id", {"sent_at": now, "events": []}), ("empty batch_id", {"batch_id": "", "sent_at": now, "events": []}),
                            ("no sent_at", {"batch_id": "b", "events": []}), ("bad sent_at", {"batch_id": "b", "sent_at": "x", "events": []}),
                            ("events not a list", {"batch_id": "b", "sent_at": now, "events": {}}),
                            ("no events", {"batch_id": "b", "sent_at": now})):
            status, _h, body = self.c.send_events(None, raw_body=gz_json(batch))
            self.assertEqual((status, code_of(body)), (400, "bad_schema"), name)

    def test_old_event_schema_is_422_and_the_previous_is_accepted(self):
        with mock.patch.object(hub_common, "EVENT_SCHEMA", 2):
            status, _h, body = self.c.send_events([ev(v=0)])
            self.assertEqual((status, code_of(body)), (422, "schema_too_old"))
            self.assertEqual(self.c.send_events([ev(v=1)])[0], 200)             # N-1 is accepted
            self.assertEqual(self.c.send_events([ev(v=2)])[0], 200)
        with mock.patch.object(hub_common, "EVENT_SCHEMA", 1):
            status, _h, body = self.c.send_events([ev(v=-1)])
            self.assertEqual(status, 422)

    def test_unknown_keys_are_dropped_and_an_unknown_kind_is_accepted(self):
        e = ev(kind="brand.new_kind")
        e["surprise"] = {"nested": 1}
        e["host"] = "someone-else"
        self.assertEqual(self.c.send_events([e])[0], 200)
        row = self.events()[0]
        self.assertEqual(row["kind"], "brand.new_kind")
        self.assertNotIn("surprise", json.dumps(row))


class EventStoreTest(IngestCase):
    def test_accepted_duplicate_and_dropped_low_counts(self):
        e1, e2 = ev(), ev(sev="HIGH")
        status, headers, body = self.c.send_events([e1, e2])
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(json.loads(body), {"accepted": 2, "duplicate": 0, "dropped_low": 0})
        status, _h, body = self.c.send_events([e1, e2, ev()])             # a retry after a lost reply is harmless
        self.assertEqual(json.loads(body), {"accepted": 1, "duplicate": 2, "dropped_low": 0})
        self.assertEqual(len(self.events()), 3)

    def test_a_duplicate_id_is_counted_not_stored(self):
        e = ev()
        self.c.send_events([e])
        status, _h, body = self.c.send_events([e, e])
        self.assertEqual(json.loads(body)["duplicate"], 2)
        self.assertEqual(len(self.events()), 1)

    def test_host_comes_from_the_certificate_never_from_the_body(self):
        other = self.extra_client("web2")
        e = ev()
        e["host"] = other.uuid
        e["details"] = {"host": other.uuid}
        batch = {"batch_id": "b", "sent_at": ts_ago(0), "events": [e], "host": other.uuid, "host_uuid": other.uuid}
        status, _h, body = self.c.send_events(None, raw_body=gz_json(batch))
        self.assertEqual(status, 200)                                   # and no refusal for naming another host
        self.assertEqual({r["host"] for r in self.events()}, {self.c.uuid})
        # the same event id from two hosts is two rows (UNIQUE is per host)
        e2 = ev()
        self.c.send_events([e2])
        other.send_events([e2])
        self.assertEqual(len(self.events("event_id=?", (e2["id"],))), 2)

    def test_stored_columns(self):
        e = ev(sev="MEDIUM", kind="ssh.fail", source="journal", dst_ip="10.0.0.5", dst_port=22, proto="tcp",
               community_id="1:abc", count=7, first_ts=ts_ago(300), last_ts=ts_ago(1), agent_ver="0.1.0")
        e["proc"] = {"binary": "/bin/x", "args": "-a", "uid": 33, "parent": "/usr/sbin/nginx"}
        e["context"] = [{"line": "GET /"}]
        e["redacted"] = True
        e["truncated"] = False
        e["details"] = {"sid": 5}
        self.assertEqual(self.c.send_events([e])[0], 200)
        r = self.events()[0]
        self.assertEqual((r["host"], r["event_id"], r["severity"], r["hub_severity"], r["kind"], r["source"]),
                         (self.c.uuid, e["id"], "MEDIUM", "MEDIUM", "ssh.fail", "journal"))
        self.assertEqual((r["src_ip"], r["src_trust"], r["dst_ip"], r["dst_port"], r["proto"], r["community_id"]),
                         ("198.51.100.7", "tcp", "10.0.0.5", 22, "tcp", "1:abc"))
        self.assertEqual((r["epoch"], r["seq"], r["agent_ver"], r["count"], r["replayed"]), (e["epoch"], e["seq"], "0.1.0", 7, 0))
        self.assertAlmostEqual(r["first"], hub_common.now_ms() - 300_000, delta=5000)
        self.assertAlmostEqual(r["last"], hub_common.now_ms() - 1000, delta=5000)
        details = json.loads(r["details"])
        self.assertEqual(details["sid"], 5)
        self.assertEqual(details["proc"]["binary"], "/bin/x")                  # proc, context, boot_id, redacted, truncated
        self.assertEqual(details["context"], [{"line": "GET /"}])               # stay inside details
        self.assertEqual(details["boot_id"], e["boot_id"])
        self.assertIs(details["redacted"], True)
        self.assertAlmostEqual(r["received_at"], hub_common.now_ms(), delta=5000)

    def test_hub_rating_is_stored_beside_the_clients_sev(self):
        import hub_rules
        with mock.patch.object(hub_rules, "rate", lambda conn, host, event: ("CRITICAL", "rule.test")):
            self.assertEqual(self.c.send_events([ev(sev="LOW")])[0], 200)
        r = self.events()[0]
        self.assertEqual((r["severity"], r["hub_severity"], r["rated_by"]), ("LOW", "CRITICAL", "rule.test"))
        with mock.patch.object(hub_rules, "rate", lambda conn, host, event: ("nonsense", "x")):
            self.c.send_events([ev(sev="MEDIUM")])
        r = self.events()[-1]
        self.assertEqual((r["hub_severity"], r["rated_by"]), ("MEDIUM", None))
        with mock.patch.object(hub_rules, "rate", side_effect=RuntimeError("rating crashed")):
            self.assertEqual(self.c.send_events([ev(sev="HIGH")])[0], 200)
        self.assertEqual(self.events()[-1]["hub_severity"], "HIGH")

    def test_the_engine_is_called_in_the_same_transaction_with_the_new_rows_only(self):
        e1, e2 = ev(), ev(sev="CRITICAL")
        self.c.send_events([e1, e2])
        calls = F.calls("after_insert")
        self.assertEqual(len(calls), 1)
        _n, args, _kw = calls[0]
        conn, hub, host_row, rows = args
        self.assertIs(hub, self.fx.hub)
        self.assertEqual(host_row["uuid"], self.c.uuid)
        self.assertEqual([r["event_id"] for r in rows], [e1["id"], e2["id"]])
        for r in rows:
            self.assertIn("rowid", r)
            self.assertIn("hub_severity", r)
            self.assertIn("replayed", r)
        self.assertEqual([r["rowid"] for r in rows], [x["id"] for x in self.events()])
        F.CALLS.clear()
        self.c.send_events([e1, e2])                                     # only duplicates: nothing new to tell the engine
        self.assertEqual(F.calls("after_insert"), [])

    def test_an_engine_failure_keeps_the_events(self):
        import hub_engine
        orig = hub_engine.after_insert
        hub_engine.after_insert = mock.Mock(side_effect=RuntimeError("boom"))
        try:
            self.assertEqual(self.c.send_events([ev()])[0], 200)
        finally:
            hub_engine.after_insert = orig
        self.assertEqual(len(self.events()), 1)

    def test_skew_correction_clamp_and_replayed_flag(self):
        now = hub_common.now_ms()
        # the client clock is an hour slow: sent_at and every ts are one hour behind
        slow = lambda s: ts_ago(3600 + s)     # noqa: E731
        e = ev(ts=slow(10))
        self.assertEqual(self.c.send_events([e], sent_at=slow(0))[0], 200)
        r = self.events()[0]
        self.assertAlmostEqual(r["ts"], now - 10_000, delta=6000)          # corrected by the skew
        self.assertEqual(r["replayed"], 0)
        self.assertAlmostEqual(self.host()["skew_ms"], 3_600_000, delta=6000)
        # within 30 s no correction is made
        e = ev(ts=ts_ago(20))
        self.c.send_events([e], sent_at=ts_ago(25))
        self.assertAlmostEqual(self.events("event_id=?", (e["id"],))[0]["ts"], now - 20_000, delta=6000)
        # a ts far in the future is clamped to received_at + 5 minutes
        e = ev(ts=hub_common.ms_to_rfc3339(now + 3 * 86_400_000))
        self.c.send_events([e])
        r = self.events("event_id=?", (e["id"],))[0]
        self.assertAlmostEqual(r["ts"], r["received_at"] + 300_000, delta=10)
        # older than 10 minutes after correction: replayed; 9 minutes: not
        old, fresh = ev(ts=ts_ago(11 * 60)), ev(ts=ts_ago(9 * 60))
        self.c.send_events([old, fresh])
        self.assertEqual(self.events("event_id=?", (old["id"],))[0]["replayed"], 1)
        self.assertEqual(self.events("event_id=?", (fresh["id"],))[0]["replayed"], 0)
        # a spool replay after a long outage: sent_at is fresh, ts is hours old
        e = ev(sev="CRITICAL", ts=ts_ago(3 * 3600 + 12 * 60))
        F.CALLS.clear()
        self.c.send_events([e])
        rows = F.calls("after_insert")[0][1][3]
        self.assertTrue(rows[0]["replayed"])
        self.assertEqual(rows[0]["hub_severity"], "CRITICAL")

    def test_first_and_last_ts_get_the_same_correction(self):
        now = hub_common.now_ms()
        e = ev(ts=ts_ago(3600 + 1), first_ts=ts_ago(3600 + 100), last_ts=ts_ago(3600 + 1))
        self.c.send_events([e], sent_at=ts_ago(3600))
        r = self.events()[0]
        self.assertAlmostEqual(r["first"], now - 100_000, delta=6000)
        self.assertAlmostEqual(r["last"], now - 1_000, delta=6000)

    def test_low_bucket_counts_the_excess_and_stores_the_rest(self):
        self.fx.hub.settings["rate_low_per_hour"] = 5
        status, _h, body = self.c.send_events([ev(sev="LOW") for _ in range(6)] + [ev(sev="INFO") for _ in range(2)])
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"accepted": 5, "duplicate": 0, "dropped_low": 3})
        self.assertEqual(len(self.events()), 5)
        # MEDIUM, HIGH and CRITICAL are not in the LOW bucket
        status, _h, body = self.c.send_events([ev(sev="MEDIUM"), ev(sev="HIGH"), ev(sev="CRITICAL"), ev(sev="LOW")])
        self.assertEqual(json.loads(body), {"accepted": 3, "duplicate": 0, "dropped_low": 1})
        other = self.extra_client("web2")                                   # buckets are per host (certificate CN)
        self.assertEqual(json.loads(other.send_events([ev(sev="LOW") for _ in range(5)])[2])["accepted"], 5)

    def test_high_bucket_is_all_or_nothing_with_retry_after_and_never_drops(self):
        self.fx.hub.settings["rate_high_per_hour"] = 3
        status, _h, body = self.c.send_events([ev(sev="HIGH") for _ in range(4)])
        self.assertEqual((status, code_of(body)), (429, "rate_limited"))
        self.assertEqual(self.events(), [])                                  # stored nothing; the client keeps the batch
        status, headers, body = self.c.send_events([ev(sev="HIGH") for _ in range(2)] + [ev(sev="CRITICAL")])
        self.assertEqual(status, 200)
        status, headers, body = self.c.send_events([ev(sev="CRITICAL")])
        self.assertEqual(status, 429)
        self.assertGreaterEqual(int(headers["retry-after"]), 1)
        self.assertLessEqual(int(headers["retry-after"]), 3600)
        self.assertEqual(len(self.events()), 3)
        # low events in the same refused batch are refused with it
        status, _h, body = self.c.send_events([ev(sev="LOW"), ev(sev="HIGH")])
        self.assertEqual(status, 429)
        self.assertEqual(len(self.events()), 3)

    def test_buckets_unit(self):
        b = hub_ingest.Buckets()
        self.assertEqual(b.take_up_to("h", 10, 4, now=0.0), 4)
        self.assertEqual(b.take_up_to("h", 10, 4, now=0.0), 0)
        b = hub_ingest.Buckets()
        self.assertEqual(b.take_all("h", 3, 3, now=0.0), (True, 0))
        ok, wait = b.take_all("h", 1, 3, now=0.0)
        self.assertFalse(ok)
        self.assertEqual(wait, 1201)                                          # 1 token at 3 an hour
        self.assertEqual(b.take_all("h", 1, 3, now=1201.0), (True, 0))
        self.assertEqual(b.take_all("h", 5, 3, now=0.0), (False, 3600))     # more than an hour's worth can never fit


# =================================================================================================
# Heartbeats
# =================================================================================================
class HeartbeatTest(IngestCase):
    def test_reply_and_stored_rows(self):
        status, headers, body = self.c.heartbeat(kernel="6.8.0", seq=17, epoch=5, policy_rev_applied="a" * 16,
                                                 inventory={"v": 1, "checks": {"sctp": {"status": False}}},
                                                 spool={"depth": 3}, last_apply_error="", paused_until=None)
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json")
        reply = json.loads(body)
        self.assertEqual(set(reply), {"hub_time", "policy_rev", "min_client_schema"})
        self.assertAlmostEqual(reply["hub_time"], time.time(), delta=5)
        self.assertRegex(reply["policy_rev"], r"^[0-9a-f]{16}$")
        self.assertEqual(reply["min_client_schema"], hub_common.EVENT_SCHEMA - 1)
        h = self.host()
        self.assertEqual((h["state"], h["agent_version"], h["agent_sha256"], h["schema"], h["proto"], h["kernel"]),
                         ("active", "0.1.0", "a" * 64, 1, 1, "6.8.0"))
        self.assertEqual((h["last_seq"], h["last_epoch"], h["boot_id"], h["policy_rev_applied"]), (17, 5, "b" * 36, "a" * 16))
        self.assertIsNotNone(h["last_seen"])
        self.assertEqual(h["first_heartbeat_at"], h["last_seen"])
        self.assertLess(abs(h["skew_ms"]), 5000)
        hb = self.fx.sql("SELECT * FROM heartbeats WHERE host=?", (self.c.uuid,))[0]
        body = json.loads(hb["body"])
        self.assertNotIn("inventory", body)
        self.assertEqual(body["spool"], {"depth": 3})
        self.assertEqual(hb["peer_ip"], "127.0.0.1")
        inv = self.fx.sql("SELECT body FROM inventory WHERE host=?", (self.c.uuid,))[0]
        self.assertEqual(json.loads(inv["body"])["checks"]["sctp"], {"status": False})
        self.assertEqual(len(self.fx.sql("SELECT 1 FROM heartbeat_samples")), 1)

    def test_pending_becomes_active_only_on_the_first_heartbeat(self):
        self.assertEqual(self.host()["state"], "pending")
        self.c.send_events([ev()])
        self.assertEqual(self.host()["state"], "pending")
        self.c.heartbeat()
        self.assertEqual(self.host()["state"], "active")

    def test_one_sample_per_five_minutes_latest_row_always(self):
        self.c.heartbeat(seq=1)
        self.c.heartbeat(seq=2)
        self.assertEqual(len(self.fx.sql("SELECT 1 FROM heartbeat_samples")), 1)
        self.fx.writer.call(lambda c: c.execute("UPDATE heartbeat_samples SET received_at=received_at-301000"))
        self.c.heartbeat(seq=3)
        self.assertEqual(len(self.fx.sql("SELECT 1 FROM heartbeat_samples")), 2)
        self.assertEqual(json.loads(self.fx.sql("SELECT body FROM heartbeats")[0]["body"])["seq"], 3)

    def test_the_engine_gets_the_previous_row_and_the_whole_heartbeat(self):
        self.c.heartbeat(boot_id="1" * 36)
        F.CALLS.clear()
        self.c.heartbeat(boot_id="2" * 36, shutdown=True, inventory={"v": 1})
        calls = F.calls("on_heartbeat")
        self.assertEqual(len(calls), 1)
        _n, (conn, hub, prev, hb, received, peer), _kw = calls[0]
        self.assertEqual(prev["boot_id"], "1" * 36)                    # as it was BEFORE the update
        self.assertEqual(hb["boot_id"], "2" * 36)
        self.assertEqual(hb["inventory"], {"v": 1})
        self.assertIs(hb["shutdown"], True)
        self.assertEqual(peer, "127.0.0.1")
        self.assertAlmostEqual(received, hub_common.now_ms(), delta=5000)
        self.assertEqual(self.host()["boot_id"], "2" * 36)
        self.assertIsNotNone(self.host()["shutdown_notice_at"])

    def test_validation(self):
        base = {"sent_at": ts_ago(0), "droplet_id": "d"}
        for name, over in (("no droplet", {"droplet_id": None}), ("empty droplet", {"droplet_id": ""}), ("droplet int", {"droplet_id": 5}),
                           ("no sent_at", {"sent_at": None}), ("bad sent_at", {"sent_at": "now"}),
                           ("schema string", {"schema": "1"}), ("seq bool", {"seq": True}), ("units list", {"units": []}),
                           ("agent_version long", {"agent_version": "x" * 33}), ("bad rev", {"policy_rev_applied": "xyz"}),
                           ("shutdown string", {"shutdown": "yes"}), ("tetragon not list", {"tetragon": {"a": 1}}),
                           ("deep inventory", {"inventory": {"a": {"a": {"a": {"a": {"a": {"a": {"a": {"a": {"a": {"a": 1}}}}}}}}}}})):
            hb = dict(base)
            hb.update(over)
            hb = {k: v for k, v in hb.items() if v is not None}
            status, _h, body = self.c.post_json("/v1/heartbeat", hb)
            self.assertEqual((status, code_of(body)), (400, "bad_schema"), name)
        self.assertEqual(self.c.post_json("/v1/heartbeat", [1])[0], 400)
        self.assertEqual(self.c.request("POST", "/v1/heartbeat", b"{bad", )[0], 400)

    def test_unknown_keys_are_dropped(self):
        self.c.heartbeat(surprise="x", host="evil", settings={"a": 1})
        body = json.loads(self.fx.sql("SELECT body FROM heartbeats")[0]["body"])
        for k in ("surprise", "host", "settings"):
            self.assertNotIn(k, body)

    def test_policy_rev_applied_empty_is_stored_as_null(self):
        self.c.heartbeat(policy_rev_applied="")
        self.assertIsNone(self.host()["policy_rev_applied"])

    def test_peers_recorded_at_most_two(self):
        self.c.heartbeat()
        self.assertEqual(json.loads(self.host()["peer_ips"]), ["127.0.0.1"])
        self.fx.writer.call(lambda c: c.execute("UPDATE hosts SET peer_ips='[\"203.0.113.1\",\"203.0.113.2\"]' WHERE uuid=?", (self.c.uuid,)))
        self.c.heartbeat()
        self.assertEqual(json.loads(self.host()["peer_ips"]), ["203.0.113.2", "127.0.0.1"])

    def test_a_claimed_ip_is_never_a_peer(self):
        self.c.heartbeat(ips=["10.9.9.9"], droplet_id="d2")
        self.assertNotIn("10.9.9.9", self.host()["peer_ips"])


# =================================================================================================
# Identity: the certificate check on every request
# =================================================================================================
class IdentityTest(IngestCase):
    def revoke(self, uuid=None, state="revoked"):
        self.fx.writer.call(lambda c: hub_enroll.host_set_state(c, self.fx.hub, uuid or self.c.uuid, state))

    def test_revoked_host_gets_403_on_every_fleet_route(self):
        self.c.heartbeat()
        self.revoke()
        _k, csr = F.make_key_and_csr(self.fx.tmp)
        for name, (status, _h, body) in (("events", self.c.send_events([ev()])), ("heartbeat", self.c.heartbeat()),
                                         ("policy", self.c.request("GET", "/v1/policy")),
                                         ("renew", self.c.post_json("/v1/renew", {"csr": csr})),
                                         ("deregister", self.c.post_json("/v1/deregister", {"reason": "uninstall"}))):
            self.assertEqual((status, code_of(body)), (403, "host_revoked"), name)
        self.assertEqual(self.events(), [])

    def test_moved_and_retired_get_their_own_codes(self):
        for state, code in (("moved", "host_moved"), ("retired", "host_retired")):
            c = self.extra_client("h-" + state)
            self.revoke(c.uuid, state)
            status, _h, body = c.request("GET", "/v1/policy")
            self.assertEqual((status, code_of(body)), (403, code))

    def test_revoked_txt_wins_over_an_older_database(self):
        """A restored older database says active; the append-only list says revoked."""
        self.c.heartbeat()
        h = self.host()
        self.fx.hub.pki.revoked_add(h["cert_serial"], h["cert_sha256"], self.c.uuid, "revoked")
        status, _h, body = self.c.request("GET", "/v1/policy")
        self.assertEqual((status, code_of(body)), (403, "host_revoked"))

    def test_unknown_certificate_of_an_unknown_cn_makes_an_orphan(self):
        """After a restore: a certificate our CA signed that the hosts table does not hold (section 7, step 5)."""
        import hub_alerts
        self.c.heartbeat()
        self.fx.writer.call(lambda c: c.execute("DELETE FROM hosts WHERE uuid=?", (self.c.uuid,)))
        notices = []
        with mock.patch.object(hub_alerts, "notify", lambda conn, hub, **kw: notices.append(kw) or 1):
            status, _h, body = self.c.send_events([ev(sev="HIGH")])
        self.assertEqual(status, 200)                                         # events are kept
        h = self.host()
        self.assertEqual((h["state"], h["uuid"]), ("orphan", self.c.uuid))
        self.assertTrue(h["name"].startswith("orphan-"))
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(len(notices), 1)
        self.assertEqual((notices[0]["severity"], notices[0]["always"]), ("HIGH", True))
        self.assertEqual(self.c.heartbeat()[0], 200)
        self.assertEqual(self.host()["state"], "orphan")                       # a heartbeat does not activate it
        status, _h, body = self.c.request("GET", "/v1/policy")
        self.assertEqual((status, code_of(body)), (403, "host_orphan"))
        _k, csr = F.make_key_and_csr(self.fx.tmp)
        self.assertEqual(code_of(self.c.post_json("/v1/renew", {"csr": csr})[2]), "host_orphan")
        self.fx.writer.call(lambda c: hub_enroll.host_adopt(c, self.fx.hub, self.c.uuid))
        self.assertEqual(self.c.request("GET", "/v1/policy")[0], 200)

    def test_known_cn_with_a_certificate_the_table_does_not_hold_becomes_orphan(self):
        """A host renewed after the backup: the row is there, with an older certificate."""
        self.c.heartbeat()
        self.fx.writer.call(lambda c: c.execute("UPDATE hosts SET cert_sha256=?, cert_serial='1' WHERE uuid=?", ("e" * 64, self.c.uuid)))
        status, _h, body = self.c.send_events([ev()])
        self.assertEqual(status, 200)
        h = self.host()
        self.assertEqual(h["state"], "orphan")
        self.assertNotEqual(h["cert_sha256"], "e" * 64)

    def test_moved_row_with_an_unknown_certificate_stays_refused(self):
        self.c.heartbeat()
        self.revoke(state="moved")
        self.fx.writer.call(lambda c: c.execute("UPDATE hosts SET cert_sha256=?, cert_serial='1' WHERE uuid=?", ("e" * 64, self.c.uuid)))
        # the certificate is in revoked.txt as moved from the revoke above, but the row now holds another hash
        h = self.host()
        status, _h, body = self.c.request("GET", "/v1/policy")
        self.assertEqual((status, code_of(body)), (403, "host_moved"))
        self.assertEqual(self.host()["state"], "moved")

    def test_renew_pending_certificate_promotion_and_superseding(self):
        self.c.heartbeat()
        old_hash = self.host()["cert_sha256"]
        key, csr = F.make_key_and_csr(self.fx.tmp)
        status, headers, body = self.c.post_json("/v1/renew", {"csr": csr})
        self.assertEqual(status, 200)
        reply = json.loads(body)
        self.assertEqual(set(reply), {"certificate", "not_after"})
        h = self.host()
        info = self.fx.hub.pki.cert_info(reply["certificate"])
        self.assertEqual(h["pending_cert_sha256"], info["der_sha256"])
        self.assertEqual(h["cert_sha256"], old_hash)                          # pending, not yet current
        self.assertEqual(info["subject_cn"], self.c.uuid)
        # the old certificate still works until the new one is used
        self.assertEqual(self.c.request("GET", "/v1/policy")[0], 200)
        new_path = os.path.join(self.fx.tmp, "renewed.pem")
        with open(new_path, "w") as f:
            f.write(reply["certificate"])
        renewed = F.Client(self.fx, key_path=key)
        renewed.ca_pem, renewed.cert_path, renewed.uuid = self.c.ca_pem, new_path, self.c.uuid
        self.assertEqual(renewed.request("GET", "/v1/policy")[0], 200)       # the first request makes it current
        h = self.host()
        self.assertEqual(h["cert_sha256"], info["der_sha256"])
        self.assertEqual(h["cert_serial"], info["serial"])
        self.assertIsNone(h["pending_cert_sha256"])
        self.assertEqual(self.fx.hub.pki.revoked_lookup(old_hash)[2], "superseded")
        status, _h, body = self.c.request("GET", "/v1/policy")                 # the old one is now refused
        self.assertEqual((status, code_of(body)), (403, "cert_superseded"))
        self.assertEqual(renewed.request("GET", "/v1/policy")[0], 200)

    def test_renew_rules(self):
        _k, csr = F.make_key_and_csr(self.fx.tmp)
        self.assertEqual(self.c.post_json("/v1/renew", {"csr": csr})[0], 200)
        status, headers, body = self.c.post_json("/v1/renew", {"csr": csr})   # a renewal loop is rate limited
        self.assertEqual((status, code_of(body)), (429, "rate_limited"))
        self.assertIn("retry-after", headers)
        _k, p384 = F.make_key_and_csr(self.fx.tmp, curve="secp384r1")
        for i, (payload, status, code) in enumerate((({"csr": "garbage"}, 400, "bad_request"), ({"csr": 5}, 400, "bad_schema"),
                                                     ({}, 400, "bad_schema"), ({"csr": p384}, 400, "bad_request"))):
            other = self.extra_client("renew%d" % i)                     # the limit is per host
            status_got, _h, body = other.post_json("/v1/renew", payload)
            self.assertEqual((status_got, code_of(body)), (status, code), payload)

    def test_deregister(self):
        a, b = self.extra_client("a1"), self.extra_client("b1")
        self.assertEqual(a.post_json("/v1/deregister", {"reason": "bogus"})[0], 400)
        self.assertEqual(a.post_json("/v1/deregister", {})[0], 400)
        status, _h, body = a.post_json("/v1/deregister", {"reason": "uninstall"})
        self.assertEqual((status, body), (200, b"{}"))
        self.assertEqual(self.host(a.uuid)["state"], "retired")
        self.assertEqual(self.host(a.uuid)["peer_ips"], "[]")
        self.assertEqual(code_of(a.request("GET", "/v1/policy")[2]), "host_retired")
        self.assertEqual(b.post_json("/v1/deregister", {"reason": "rehome"})[0], 200)
        self.assertEqual(self.host(b.uuid)["state"], "moved")
        self.assertEqual(code_of(b.send_events([ev()])[2]), "host_moved")
        self.assertIsNotNone(self.fx.hub.pki.revoked_lookup(self.host(a.uuid)["cert_sha256"]))

    def test_a_rejected_attempt_is_counted_and_throttled(self):
        self.revoke()
        for _ in range(3):
            self.c.request("GET", "/v1/policy")
        time.sleep(0.5)
        calls = F.calls("on_rejected")
        self.assertEqual(len(calls), 1)                                         # at most one note per host and code every 30 s
        conn, hub, row, code, peer = calls[0][1]
        self.assertEqual((row["uuid"], code, peer), (self.c.uuid, "host_revoked", "127.0.0.1"))
        self.assertEqual(self.fx.hub.ingest.stats["rejected"], 3)

    def test_identity_never_comes_from_a_url_or_header(self):
        other = self.extra_client("web2")
        status, _h, body = self.c.request("GET", "/v1/policy", headers={"X-Host": other.uuid, "X-EDR-Host": other.uuid})
        self.assertEqual(status, 200)
        self.assertEqual(self.c.request("GET", "/v1/policy/" + other.uuid)[0], 404)


# =================================================================================================
# The writer under pressure: queue full, storage full
# =================================================================================================
class QueueFullTest(IngestCase):
    def test_every_ingest_route_is_503_with_retry_after_and_stores_nothing(self):
        self.c.heartbeat()
        w = self.fx.writer
        gate = threading.Event()
        started = threading.Event()
        threading.Thread(target=lambda: w.call(lambda conn: (started.set(), gate.wait(30))), daemon=True).start()
        started.wait(5)
        try:
            for _ in range(hub_common.WRITER_QUEUE):
                w.post(lambda conn: None)
            _k, csr = F.make_key_and_csr(self.fx.tmp)
            for name, (status, headers, body) in (
                    ("low", self.c.send_events([ev(sev="LOW")])), ("high", self.c.send_events([ev(sev="HIGH")])),
                    ("critical", self.c.send_events([ev(sev="CRITICAL")])), ("heartbeat", self.c.heartbeat()),
                    ("deregister", self.c.post_json("/v1/deregister", {"reason": "uninstall"}))):
                self.assertEqual((status, code_of(body)), (503, "busy"), name)
                self.assertRegex(headers["retry-after"], r"^\d+$", name)
        finally:
            gate.set()
        deadline = time.time() + 20
        while time.time() < deadline and w.q.qsize():
            time.sleep(0.05)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.host()["state"], "active")              # the deregister did not happen
        self.assertEqual(self.c.send_events([ev()])[0], 200)           # and the hub is fine afterwards


class StorageFullTest(F.HubTestCase):
    def setUp(self):
        patcher = mock.patch.object(hub_db, "IDLE_TICK_S", 0.3)
        patcher.start()
        self.addCleanup(patcher.stop)
        super().setUp()
        self.c = self.fx.enroll("web1")

    def fill_up(self):
        w = self.fx.writer
        page, pages = w.call(lambda c: (c.execute("PRAGMA page_size").fetchone()[0], c.execute("PRAGMA page_count").fetchone()[0]))
        self.fx.hub.settings["max_db_size"] = str((pages + 30) * page)
        w.call(lambda c: None)
        n = [0]

        def add(conn):
            for _ in range(5):
                n[0] += 1
                conn.execute("INSERT INTO events(host,event_id,received_at,ts,source,severity,hub_severity,kind,summary,epoch,seq) "
                             "VALUES('fill',?,?,?,'agent','HIGH','HIGH','k',?,1,?)",
                             ("00000009:%d" % n[0], hub_common.now_ms(), hub_common.now_ms(), "p" * 900, n[0]))
        with self.assertRaises(hub_db.StorageFull):
            for _ in range(500):
                w.call(add)
        return n[0]

    def test_low_gets_503_high_goes_to_the_overflow_file_and_comes_back(self):
        self.fill_up()
        w = self.fx.writer
        self.assertEqual(w.state, "storage_full")
        status, headers, body = self.c.send_events([ev(sev="LOW"), ev(sev="INFO")])
        self.assertEqual((status, code_of(body)), (503, "storage_full"))
        self.assertRegex(headers["retry-after"], r"^\d+$")
        high, crit, low = ev(sev="HIGH"), ev(sev="CRITICAL"), ev(sev="LOW")
        status, _h, body = self.c.send_events([high, crit, low])
        self.assertEqual(status, 200)                                   # answered only after the append
        self.assertEqual(json.loads(body), {"accepted": 2, "duplicate": 0, "dropped_low": 1})
        with open(self.fx.paths.critical_overflow) as f:
            lines = [json.loads(line) for line in f]
        self.assertEqual([x["event"]["id"] for x in lines], [high["id"], crit["id"]])
        self.assertEqual({x["host"] for x in lines}, {self.c.uuid})
        self.assertTrue(self.fx.hub.writer.hub.memory_alerts if hasattr(self.fx.hub, "memory_alerts") else True)
        self.assertEqual(self.fx.sql("SELECT 1 FROM events WHERE host=?", (self.c.uuid,)), [])
        # space returns: the file is replayed into the database
        self.fx.hub.settings["max_db_size"] = "2G"
        deadline = time.time() + 15
        while time.time() < deadline and os.path.exists(self.fx.paths.critical_overflow):
            time.sleep(0.1)
        self.assertFalse(os.path.exists(self.fx.paths.critical_overflow))
        rows = self.fx.sql("SELECT event_id, hub_severity FROM events WHERE host=? ORDER BY id", (self.c.uuid,))
        self.assertEqual([r["event_id"] for r in rows], [high["id"], crit["id"]])
        self.assertEqual(self.fx.writer.state, "ok")
        self.assertEqual(self.c.send_events([ev(sev="LOW")])[0], 200)

    def test_if_the_append_fails_too_the_answer_is_503(self):
        self.fill_up()
        os.mkdir(self.fx.paths.critical_overflow)                          # the append cannot succeed
        status, headers, body = self.c.send_events([ev(sev="CRITICAL")])
        self.assertEqual((status, code_of(body)), (503, "storage_full"))
        self.assertIn("retry-after", headers)

    def test_the_overflow_file_is_bounded(self):
        self.fill_up()
        with mock.patch.object(hub_db, "OVERFLOW_MAX_BYTES", 900):
            self.assertEqual(self.c.send_events([ev(sev="HIGH")])[0], 200)
            status, _h, body = self.c.send_events([ev(sev="HIGH"), ev(sev="HIGH")])
            self.assertEqual((status, code_of(body)), (503, "storage_full"))


# =================================================================================================
# Pieces
# =================================================================================================
class PiecesTest(unittest.TestCase):
    def test_reaper_cuts_expired_connections_only(self):
        a1, a2 = socket.socketpair()
        b1, b2 = socket.socketpair()
        reaper = hub_ingest.Reaper()
        reaper.start()
        try:
            reaper.add(a1, time.monotonic() + 0.3)
            key = reaper.add(b1, time.monotonic() + 30)
            a2.settimeout(2)
            self.assertEqual(a2.recv(10), b"")                               # shut down at the deadline
            b2.settimeout(0.5)
            with self.assertRaises(socket.timeout):
                b2.recv(10)                                                   # still alive
            reaper.set(key, time.monotonic() + 0.2)
            b2.settimeout(2)
            self.assertEqual(b2.recv(10), b"")
            self.assertEqual(reaper.count(), 0)
            self.assertEqual(reaper.cut, 2)
        finally:
            reaper.stop()
            for s in (a1, a2, b1, b2):
                s.close()

    def test_reaper_remove(self):
        a1, a2 = socket.socketpair()
        reaper = hub_ingest.Reaper()
        reaper.start()
        try:
            key = reaper.add(a1, time.monotonic() + 0.2)
            reaper.remove(key)
            time.sleep(0.6)
            a2.settimeout(0.3)
            with self.assertRaises(socket.timeout):
                a2.recv(1)
        finally:
            reaper.stop()
            a1.close()
            a2.close()

    def test_inflate_limited(self):
        self.assertEqual(hub_ingest.inflate_limited(gzip.compress(b"hello")), b"hello")
        with self.assertRaises(hub_ingest.HttpError) as cm:
            hub_ingest.inflate_limited(gzip.compress(b"0" * (hub_common.BODY_MAX_INFLATED + 1)))
        self.assertEqual(cm.exception.code, "too_large")
        for bad in (gzip.compress(b"hello")[:-4], gzip.compress(b"hello") + b"x", b"nope"):
            with self.assertRaises(hub_ingest.HttpError) as cm:
                hub_ingest.inflate_limited(bad)
            self.assertEqual(cm.exception.code, "bad_request")

    def test_parse_json_object(self):
        self.assertEqual(hub_ingest.parse_json_object(b'{"a": 1}'), {"a": 1})
        for raw, code in ((b"[" * 100000, "bad_request"), (b"{", "bad_request"), (b"\xff", "bad_request"), (b"[]", "bad_schema"),
                          (b'{"a": Infinity}', "bad_request")):
            with self.assertRaises(hub_ingest.HttpError) as cm:
                hub_ingest.parse_json_object(raw)
            self.assertEqual(cm.exception.code, code)

    def test_correct_times(self):
        now = 10_000_000_000_000
        ts, first, last, replayed = hub_ingest.correct_times(now - 5000, None, now - 1000, now, 10_000)
        self.assertEqual((ts, first, last, replayed), (now - 5000, None, now - 1000, False))       # under 30 s: untouched
        ts, _f, _l, replayed = hub_ingest.correct_times(now - 3_600_000 - 5000, None, None, now, 3_600_000)
        self.assertEqual((ts, replayed), (now - 5000, False))
        ts, _f, _l, replayed = hub_ingest.correct_times(now + 10 ** 9, None, None, now, 0)
        self.assertEqual((ts, replayed), (now + 300_000, False))
        ts, _f, _l, replayed = hub_ingest.correct_times(now - 601_000, None, None, now, 0)
        self.assertTrue(replayed)
        ts, _f, _l, replayed = hub_ingest.correct_times(now - 599_000, None, None, now, 0)
        self.assertFalse(replayed)

    def test_validate_event_returns_the_clients_keys(self):
        e, ts, first, last = hub_ingest.validate_event(F.make_event(seq=1, count=3), 0)
        self.assertEqual(e["sev"], "LOW")
        self.assertEqual(e["count"], 3)
        self.assertIsInstance(ts, int)
        self.assertIsNone(first)
        e, *_ = hub_ingest.validate_event(F.make_event(seq=2, src_ip="::ffff:203.0.113.5", dst_ip=""), 0)
        self.assertEqual(e["src_ip"], "203.0.113.5")


if __name__ == "__main__":
    unittest.main()
