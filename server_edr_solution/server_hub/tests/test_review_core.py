"""Findings of the independent review of the network-facing core (hub_ingest, hub_enroll, hub_pki, hub_db, edr_hub).

Each test pins a defect the review found against the real server and that has since been fixed, or something the
review found to be right, so a later change cannot quietly break it. Reuses the real-server fixture of test_ingest_fixture.py (read only).
"""

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
import hub_enroll  # noqa: E402


def conn_from(client, source):
    """A TLS connection to the fleet port from a chosen loopback source address (the per-source cap is 4)."""
    raw = socket.create_connection(("127.0.0.1", client.fx.fleet_port), timeout=10, source_address=(source, 0))
    return client._ctx().wrap_socket(raw, server_hostname="127.0.0.1")


def hold_open(client, source, path="/v1/heartbeat", length=5000):
    """A request whose body never arrives: it holds a per-certificate count and a parsing slot until the deadline."""
    s = conn_from(client, source)
    s.sendall(("POST %s HTTP/1.0\r\nX-EDR-Proto: 1\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\n"
               "Content-Length: %d\r\n\r\nxx" % (path, length)).encode())
    return s


def quick(client, source, path="/v1/policy"):
    s = conn_from(client, source)
    try:
        s.sendall(("GET %s HTTP/1.0\r\nX-EDR-Proto: 1\r\n\r\n" % path).encode())
        return client._read_response(s)[0]
    finally:
        s.close()


class SharedHub(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = F.HubFixture()

    @classmethod
    def tearDownClass(cls):
        cls.fx.stop()


class ConfirmedDefects(unittest.TestCase):
    """One hub per test: these tests open held connections and change host state."""

    def setUp(self):
        self.fx = F.HubFixture()
        self.addCleanup(self.fx.stop)
        self.held = []
        self.addCleanup(lambda: [s.close() for s in self.held])

    def test_per_certificate_cap_of_four_survives_a_rejected_request(self):
        a = self.fx.enroll("web1")
        for _ in range(4):
            self.held.append(hold_open(a, "127.0.0.1", path="/v1/events"))
        time.sleep(0.5)
        self.assertEqual(quick(a, "127.0.0.2"), 429)                       # the 5th: refused, as the plan says
        self.assertEqual(quick(a, "127.0.0.3"), 429)                       # the 6th must be refused too; today it is 200

    def test_one_host_trickling_bodies_cannot_starve_the_other_hosts(self):
        a = self.fx.enroll("web1")
        b = self.fx.enroll("web2")
        for _ in range(4):                                                 # 4 is all one source address may hold
            self.held.append(hold_open(a, "127.0.0.1"))
        time.sleep(0.5)
        hb = json.dumps({"sent_at": hub_common.ms_to_rfc3339(hub_common.now_ms()), "droplet_id": "droplet-1"}).encode()
        s = conn_from(b, "127.0.0.9")
        s.sendall(b"POST /v1/heartbeat HTTP/1.0\r\nX-EDR-Proto: 1\r\nContent-Length: %d\r\n\r\n" % len(hb) + hb)
        self.held.append(s)
        self.assertEqual(b._read_response(s)[0], 200)                      # today: 503 busy for the whole fleet

    def test_a_server_key_that_does_not_match_the_certificate_is_noticed_at_start(self):
        self.fx.hub.pki.issue_server_cert(["127.0.0.1"])
        with open(self.fx.paths.server_key, "wb") as f:                    # what a crash between the two writes leaves
            f.write(F.openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout"))
        self.assertNotEqual(self.fx.hub.pki.server_cert_state(["127.0.0.1"]), "ok")

    def test_opening_the_enrollment_listener_does_no_name_lookup(self):
        listener = self.fx.hub.ingest.enroll
        listener.close()
        with mock.patch("socket.getfqdn", side_effect=lambda *a: time.sleep(1.0) or "slow.example"):
            t0 = time.monotonic()
            listener.open()
        self.assertLess(time.monotonic() - t0, 0.5)

    def test_an_unrecorded_ca_signed_certificate_does_not_orphan_a_host_on_a_hub_that_was_never_restored(self):
        a = self.fx.enroll("web1")
        self.assertIsNone(self.fx.sql("SELECT value FROM meta WHERE key='restored_at'") or None)

        def present(conn):
            return hub_enroll.orphan_from_certificate(conn, self.fx.hub, "ab" * 32, a.uuid, "1234", hub_common.now_ms() + 10 ** 9,
                                                      "203.0.113.5")
        self.fx.writer.call(present)
        # a freshly enrolled host is "pending" (no heartbeat yet); the point is that it did not become an orphan
        self.assertEqual(self.fx.sql("SELECT state FROM hosts WHERE uuid=?", (a.uuid,))[0]["state"], "pending")


class VerifiedGood(SharedHub):
    """Things the review tried to break and could not. They stay as regression tests."""

    def test_handshake_and_header_deadlines_are_wall_clock(self):
        c = self.fx.enroll("web1")
        s = socket.create_connection(("127.0.0.1", self.fx.fleet_port))
        t0 = time.monotonic()
        s.settimeout(10)
        try:
            while s.recv(100):
                pass
        except OSError:
            pass
        self.assertLess(time.monotonic() - t0, 4.5)                        # 3 s, cut by the reaper
        s.close()
        s = c.connect()
        t0 = time.monotonic()
        try:
            for ch in b"GET /v1/policy HTTP/1.0\r\nX-A: " + b"a" * 60:     # one byte every 0.2 s keeps every read alive
                s.send(bytes([ch]))
                time.sleep(0.2)
        except OSError:
            pass
        self.assertLess(time.monotonic() - t0, 7.5)                        # 5 s header deadline
        s.close()

    def test_unknown_wrong_expired_and_used_tokens_answer_alike_and_a_replay_needs_the_same_csr(self):
        fx = self.fx
        tok = fx.make_token(name="web5")["token"]
        key, csr = F.make_key_and_csr(fx.tmp)
        key2, csr2 = F.make_key_and_csr(fx.tmp)
        client = F.Client(fx, key_path=key)
        st, _h, body = client.enroll_request(tok, csr)
        self.assertEqual(st, 200)
        again = client.enroll_request(tok, csr)                            # a lost reply: same CSR within 10 minutes
        self.assertEqual((again[0], json.loads(again[2])["certificate"]), (200, json.loads(body)["certificate"]))
        other = client.enroll_request(tok, csr2)                           # another CSR gets nothing
        unknown = client.enroll_request("ffffffffffff." + tok.split(".")[1] + "." + tok.split(".")[2], csr)
        wrong = client.enroll_request(tok.split(".")[0] + ".AAAAAAAAAAAAAAAAAAAAAA." + tok.split(".")[2], csr)
        for status, _h, text in (other, unknown, wrong):
            self.assertEqual((status, json.loads(text)["code"]), (401, "invalid_token"))
        self.assertEqual(len({other[2], unknown[2], wrong[2]}), 1)

    def test_a_hostile_csr_gets_the_fixed_profile_and_the_uuid_subject(self):
        import subprocess
        fx = self.fx
        key = os.path.join(fx.tmp, "hostile.key")
        with open(key, "wb") as f:
            f.write(F.openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout"))
        cnf = os.path.join(fx.tmp, "hostile.cnf")
        with open(cnf, "w") as f:
            f.write("[req]\ndistinguished_name=dn\nreq_extensions=ext\nprompt=no\n[dn]\nCN=root\nO=evil\n"
                    "[ext]\nbasicConstraints=CA:TRUE\nsubjectAltName=DNS:evil.example\nkeyUsage=keyCertSign\n")
        csr = F.openssl("req", "-new", "-key", key, "-config", cnf).decode()
        client = F.Client(fx, key_path=key)
        st, _h, body = client.enroll_request(fx.make_token(name="evil")["token"], csr)
        self.assertEqual(st, 200)
        client.adopt(json.loads(body))
        text = subprocess.run(["openssl", "x509", "-in", client.cert_path, "-noout", "-subject", "-nameopt", "RFC2253", "-ext",
                               "basicConstraints,subjectAltName,extendedKeyUsage"], capture_output=True, text=True).stdout
        self.assertIn("subject=CN=" + client.uuid, text)
        self.assertIn("CA:FALSE", text)
        self.assertNotIn("evil", text)
        self.assertIn("TLS Web Client Authentication", text)

    def test_a_renewed_certificate_switches_on_first_use_and_the_old_one_is_superseded(self):
        fx = self.fx
        a = fx.enroll("web6")
        key2, csr2 = F.make_key_and_csr(fx.tmp)
        st, _h, body = a.post_json("/v1/renew", {"csr": csr2})
        self.assertEqual(st, 200)
        b = F.Client(fx, key_path=key2)
        b.ca_pem, b.uuid = a.ca_pem, a.uuid
        b.cert_path = os.path.join(fx.tmp, "renewed.pem")
        with open(b.cert_path, "w") as f:
            f.write(json.loads(body)["certificate"])
        self.assertEqual(a.request("GET", "/v1/policy")[0], 200)           # the old one works until the new one is used
        self.assertEqual(b.request("GET", "/v1/policy")[0], 200)
        st, _h, text = a.request("GET", "/v1/policy")
        self.assertEqual((st, json.loads(text)["code"]), (403, "cert_superseded"))
        fx.writer.call(lambda conn: hub_enroll.host_set_state(conn, fx.hub, a.uuid, "revoked"))
        self.assertEqual(json.loads(b.request("GET", "/v1/policy")[2])["code"], "host_revoked")
        self.assertEqual(b.send_events([F.make_event()])[0], 403)

    def test_orphan_host_may_send_events_but_not_use_policy_or_renew(self):
        fx = self.fx
        d = fx.enroll("web7")
        fx.writer.call(lambda conn: conn.execute("UPDATE hosts SET state='orphan' WHERE uuid=?", (d.uuid,)))
        _k, csr = F.make_key_and_csr(fx.tmp)
        self.assertEqual(json.loads(d.request("GET", "/v1/policy")[2])["code"], "host_orphan")
        self.assertEqual(json.loads(d.post_json("/v1/renew", {"csr": csr})[2])["code"], "host_orphan")
        self.assertEqual(d.send_events([F.make_event()])[0], 200)

    def test_deeply_nested_json_is_a_400_not_a_dropped_connection(self):
        c = self.fx.enroll("web8")
        deep = []
        for _ in range(990):
            deep = [deep]
        ev = F.make_event()
        ev["details"] = {"x": deep}
        self.assertEqual(c.send_events([ev])[0], 400)
        import gzip
        self.assertEqual(c.request("POST", "/v1/events", gzip.compress(b"[" * 3000 + b"]" * 3000),
                                   headers={"Content-Encoding": "gzip"})[0], 400)


if __name__ == "__main__":
    unittest.main()
