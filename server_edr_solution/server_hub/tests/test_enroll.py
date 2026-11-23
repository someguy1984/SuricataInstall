"""Tokens, enrollment and host states (PLAN.md section 2; section 12 L0 rows "Tokens and enrollment" and "Identity")."""

import hashlib
import json
import os
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_ingest_fixture as F  # noqa: E402

import hub_common  # noqa: E402
import hub_enroll  # noqa: E402
import hub_pki  # noqa: E402

PEER = "127.0.0.1"
MIN = 60_000


class EnrollCase(F.HubTestCase):
    def tok(self, **kw):
        return self.fx.make_token(**kw)

    def redeem(self, token, csr=None, peer=PEER, **body):
        if csr is None:
            _k, csr = F.make_key_and_csr(self.fx.tmp)
        req = {"token": ".".join(token.split(".")[:2]), "csr": csr, "hostname": "h.example", "os": "Ubuntu",
               "ips": ["203.0.113.9"], "droplet_id": "d-1"}
        req.update(body)
        req = {k: v for k, v in req.items() if v is not None or k in ("host_uuid",)}
        return self.fx.writer.call(lambda conn: hub_enroll.redeem(conn, self.fx.hub, req, peer))

    def token_row(self, token_id):
        return self.fx.sql("SELECT * FROM tokens WHERE id=?", (token_id,))[0]

    def host_row(self, uuid):
        return self.fx.sql("SELECT * FROM hosts WHERE uuid=?", (uuid,))[0]


class TokenTest(EnrollCase):
    def test_format_and_storage(self):
        t = self.tok(name="web1")
        tid, secret, ca = t["token"].split(".")
        self.assertEqual(tid, t["id"])
        self.assertRegex(tid, r"^[0-9a-f]{12}$")
        self.assertGreaterEqual(len(secret), 22)                       # token_urlsafe(16) is 22 characters
        self.assertRegex(secret, r"^[A-Za-z0-9_-]+$")
        self.assertEqual(ca, self.fx.hub.pki.ca_sha256())
        row = self.token_row(tid)
        self.assertEqual(row["secret_sha256"], hashlib.sha256(secret.encode()).hexdigest())
        for value in row.values():
            self.assertNotIn(secret, str(value))
        self.assertEqual(t["enroll_port"], self.fx.enroll_port)
        self.assertEqual(t["port"], self.fx.fleet_port)
        self.assertEqual(t["hub_addresses"], ["127.0.0.1"])
        self.assertEqual(t["name"], "web1")

    def test_ttl_default_max_and_bounds(self):
        now = hub_common.now_ms()
        t = self.tok(name="a1")
        self.assertAlmostEqual(t["expires_at"], now + 15 * MIN, delta=3000)
        t = self.tok(name="a2", ttl_s=24 * 3600)
        self.assertAlmostEqual(t["expires_at"], now + 24 * 3600 * 1000, delta=3000)
        for bad in (24 * 3600 + 1, 0, -5, "x", None):
            with self.assertRaises(ValueError):
                self.tok(name="a3", ttl_s=bad)

    def test_name_rules(self):
        for bad in ("UPPER", "has space", "-lead", "a" * 64, "", "a/b", "ü"):
            with self.assertRaises(ValueError, msg=bad):
                self.tok(name=bad)
        self.tok(name="ok-name-1")
        with self.assertRaises(ValueError):
            self.tok(name="ok-name-1")                                 # a pending token holds the name
        c = self.fx.enroll("web9")
        with self.assertRaises(ValueError):
            self.tok(name="web9")                                      # a host holds the name

    def test_exactly_one_of_name_or_for_host(self):
        with self.assertRaises(ValueError):
            self.tok()
        with self.assertRaises(ValueError):
            self.tok(name="x1", for_host="y")
        with self.assertRaises(ValueError):
            self.tok(for_host="no-such-host")

    def test_for_host_by_name_or_uuid(self):
        c = self.fx.enroll("web1")
        a = self.tok(for_host="web1")
        b = self.tok(for_host=c.uuid)
        self.assertEqual(a["for_host"], c.uuid)
        self.assertEqual(b["for_host"], c.uuid)
        self.assertIsNone(self.token_row(a["id"])["name"])
        self.assertEqual(self.token_row(a["id"])["bound_host"], c.uuid)

    def test_source_cidr_normalised_and_validated(self):
        t = self.tok(name="s1", source_cidr="127.0.0.1")
        self.assertEqual(self.token_row(t["id"])["source_cidr"], "127.0.0.1/32")
        for bad in ("203.0.113.5/24", "nonsense", "1.2.3.4/33"):
            with self.assertRaises(ValueError):
                self.tok(name="s2", source_cidr=bad)

    def test_clients_only_requires_source(self):
        self.fx.hub.settings["clients_only"] = True
        with self.assertRaises(ValueError):
            self.tok(name="s1")
        self.tok(name="s1", source_cidr="10.0.0.0/8")

    def test_list_states_and_no_secrets(self):
        pending = self.tok(name="p1")
        used = self.tok(name="u1")
        self.assertEqual(self.redeem(used["token"])[0], "ok")
        expired = self.tok(name="e1", ttl_s=1)
        revoked = self.tok(name="r1")
        self.assertTrue(self.fx.writer.call(lambda c: hub_enroll.token_revoke(c, self.fx.hub, revoked["id"])))
        self.fx.writer.call(lambda c: c.execute("UPDATE tokens SET expires_at=? WHERE id=?", (hub_common.now_ms() - 1, expired["id"])))
        listing = {r["id"]: r for r in self.fx.writer.call(lambda c: hub_enroll.token_list(c))}
        self.assertEqual(listing[pending["id"]]["state"], "pending")
        self.assertEqual(listing[used["id"]]["state"], "used")
        self.assertEqual(listing[expired["id"]]["state"], "expired")
        self.assertEqual(listing[revoked["id"]]["state"], "revoked")
        self.assertEqual(set(listing[pending["id"]]), {"id", "name", "bound_host", "source_cidr", "expires_at", "state"})

    def test_revoke(self):
        t = self.tok(name="r1")
        self.assertTrue(self.fx.writer.call(lambda c: hub_enroll.token_revoke(c, self.fx.hub, t["id"])))
        self.assertFalse(self.fx.writer.call(lambda c: hub_enroll.token_revoke(c, self.fx.hub, t["id"])))
        self.assertFalse(self.fx.writer.call(lambda c: hub_enroll.token_revoke(c, self.fx.hub, "nope")))
        self.assertEqual(self.redeem(t["token"]), ("err", "invalid_token"))
        used = self.tok(name="u1")
        self.redeem(used["token"])
        self.assertFalse(self.fx.writer.call(lambda c: hub_enroll.token_revoke(c, self.fx.hub, used["id"])))


class RedeemTest(EnrollCase):
    def test_success_creates_a_pending_host_with_a_valid_certificate(self):
        t = self.tok(name="web1")
        status, reply = self.redeem(t["token"], hostname="evil\x1b[31m.example")
        self.assertEqual(status, "ok")
        self.assertEqual(set(reply), {"host_uuid", "certificate", "ca", "hub_addresses", "port", "not_after", "state"})
        self.assertEqual(reply["state"], "pending")
        self.assertEqual(reply["hub_addresses"], ["127.0.0.1"])
        self.assertEqual(reply["port"], self.fx.fleet_port)
        self.assertRegex(reply["not_after"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
        self.assertEqual(reply["ca"], self.fx.hub.pki.ca_pem())
        info = self.fx.hub.pki.cert_info(reply["certificate"])
        self.assertEqual(info["subject_cn"], reply["host_uuid"])
        h = self.host_row(reply["host_uuid"])
        self.assertEqual((h["name"], h["state"], h["droplet_id"], h["enrolled_from"]), ("web1", "pending", "d-1", PEER))
        self.assertEqual(h["cert_sha256"], info["der_sha256"])
        self.assertEqual(h["cert_serial"], info["serial"])
        self.assertEqual(json.loads(h["peer_ips"]), [PEER])
        self.assertNotIn("\x1b", h["reported_name"])                 # display text goes through clean()
        self.assertEqual(json.loads(h["ips"]), ["203.0.113.9"])
        tr = self.token_row(t["id"])
        self.assertEqual((tr["used_by"], tr["used_from"]), (reply["host_uuid"], PEER))
        self.assertIsNotNone(tr["used_at"])

    def test_the_token_name_wins_and_the_hub_mints_the_uuid(self):
        t = self.tok(name="real-name")
        hint = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        status, reply = self.redeem(t["token"], hostname="other", host_uuid=hint)
        self.assertEqual(status, "ok")
        self.assertNotEqual(reply["host_uuid"], hint)
        self.assertEqual(self.host_row(reply["host_uuid"])["name"], "real-name")

    def test_csr_subject_is_ignored(self):
        t = self.tok(name="web1")
        _k, csr = F.make_key_and_csr(self.fx.tmp, subject="/CN=root/O=attacker")
        status, reply = self.redeem(t["token"], csr=csr)
        self.assertEqual(self.fx.hub.pki.cert_info(reply["certificate"])["subject_cn"], reply["host_uuid"])

    def test_single_use_replay_window_and_nothing_else(self):
        t = self.tok(name="web1")
        _k, csr = F.make_key_and_csr(self.fx.tmp)
        first = self.redeem(t["token"], csr=csr)
        self.assertEqual(first[0], "ok")
        again = self.redeem(t["token"], csr=csr)                      # a lost reply costs nothing
        self.assertEqual(again, first)
        self.assertEqual(len(self.fx.sql("SELECT 1 FROM hosts")), 1)
        _k, other = F.make_key_and_csr(self.fx.tmp)
        self.assertEqual(self.redeem(t["token"], csr=other), ("err", "invalid_token"))      # same token, other CSR
        self.fx.writer.call(lambda c: c.execute("UPDATE tokens SET used_at=? WHERE id=?",
                                                (hub_common.now_ms() - 10 * MIN - 1000, t["id"])))
        self.assertEqual(self.redeem(t["token"], csr=csr), ("err", "invalid_token"))        # past 10 minutes
        self.assertEqual(len(self.fx.sql("SELECT 1 FROM hosts")), 1)

    def test_replay_reply_is_byte_identical_over_the_wire(self):
        t = self.tok(name="web1")
        key, csr = F.make_key_and_csr(self.fx.tmp)
        c = F.Client(self.fx, key_path=key)
        s1, _h, b1 = c.enroll_request(t["token"], csr)
        s2, _h, b2 = c.enroll_request(t["token"], csr)
        self.assertEqual((s1, s2), (200, 200))
        self.assertEqual(b1, b2)

    def test_same_401_for_unknown_wrong_expired_used_revoked(self):
        good = self.tok(name="g1")
        wrong_secret = good["token"].replace(good["token"].split(".")[1], "A" * 22)
        unknown = "0123456789ab.%s" % ("B" * 22)
        expired = self.tok(name="e1", ttl_s=1)
        self.fx.writer.call(lambda c: c.execute("UPDATE tokens SET expires_at=1 WHERE id=?", (expired["id"],)))
        used = self.tok(name="u1")
        revoked = self.tok(name="r1")
        self.fx.writer.call(lambda c: hub_enroll.token_revoke(c, self.fx.hub, revoked["id"]))
        key, csr = F.make_key_and_csr(self.fx.tmp)
        c = F.Client(self.fx, key_path=key)
        self.assertEqual(c.enroll_request(used["token"], csr)[0], 200)
        _k2, other = F.make_key_and_csr(self.fx.tmp)
        bodies = set()
        for tok, req_csr in ((wrong_secret, csr), (unknown, csr), (expired["token"], csr), (used["token"], other),
                             (revoked["token"], csr), ("garbage", csr), ("a.b.c.d", csr)):
            self.fx.hub.ingest.limiter = hub_enroll.FailureLimiter(per_source=1000, overall=1000)
            status, _h, body = c.enroll_request(tok, req_csr)
            self.assertEqual(status, 401, tok)
            bodies.add(body)
        self.assertEqual(bodies, {hub_common.error_body("invalid_token")})
        self.assertNotIn(good["token"].split(".")[1].encode(), b"".join(bodies))

    def test_unknown_id_still_compares_against_a_dummy_hash(self):
        calls = []
        real = hub_enroll.hmac.compare_digest

        def spy(a, b):
            calls.append((a, b))
            return real(a, b)
        with mock.patch.object(hub_enroll.hmac, "compare_digest", spy):
            self.redeem("0123456789ab.%s" % ("C" * 22))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], hub_enroll._DUMMY_HASH)

    def test_five_wrong_secrets_burn_the_id(self):
        t = self.tok(name="web1")
        bad = "%s.%s" % (t["id"], "Z" * 22)
        for _ in range(4):
            self.assertEqual(self.redeem(bad), ("err", "invalid_token"))
        self.assertEqual(self.token_row(t["id"])["bad_attempts"], 4)
        self.assertEqual(self.redeem(bad), ("err", "invalid_token"))
        row = self.token_row(t["id"])
        self.assertEqual(row["bad_attempts"], 5)
        self.assertIsNotNone(row["revoked_at"])
        self.assertEqual(self.redeem(t["token"]), ("err", "invalid_token"))          # the right secret is too late
        self.assertEqual(len(self.fx.sql("SELECT 1 FROM hosts")), 0)

    def test_four_wrong_secrets_do_not_burn(self):
        t = self.tok(name="web1")
        for _ in range(4):
            self.redeem("%s.%s" % (t["id"], "Z" * 22))
        self.assertEqual(self.redeem(t["token"])[0], "ok")

    def test_source_binding(self):
        t = self.tok(name="web1", source_cidr="203.0.113.0/24")
        self.assertEqual(self.redeem(t["token"], peer="198.51.100.1"), ("err", "invalid_token"))
        self.assertEqual(self.redeem(t["token"], peer="203.0.113.77")[0], "ok")
        t2 = self.tok(name="web2", source_cidr="2001:db8::/32")
        self.assertEqual(self.redeem(t2["token"], peer="2001:db8::5")[0], "ok")
        self.assertEqual(self.redeem(self.tok(name="web3", source_cidr="10.0.0.0/8")["token"], peer=""), ("err", "invalid_token"))

    def test_expired_token(self):
        t = self.tok(name="web1", ttl_s=1)
        self.fx.writer.call(lambda c: c.execute("UPDATE tokens SET expires_at=? WHERE id=?", (hub_common.now_ms() - 5, t["id"])))
        self.assertEqual(self.redeem(t["token"]), ("err", "invalid_token"))

    def test_hint_matching_a_host_in_any_state_is_409_and_spends_nothing(self):
        c = self.fx.enroll("web1")
        uuid = c.uuid
        for state in ("pending", "active", "orphan", "moved", "retired", "revoked"):
            self.fx.writer.call(lambda conn, s=state: conn.execute("UPDATE hosts SET state=? WHERE uuid=?", (s, uuid)))
            t = self.tok(name="n-" + state)
            self.assertEqual(self.redeem(t["token"], host_uuid=uuid), ("err", "host_exists"), state)
            self.assertIsNone(self.token_row(t["id"])["used_at"])
        # an unknown hint is only a hint
        t = self.tok(name="fresh")
        self.assertEqual(self.redeem(t["token"], host_uuid="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")[0], "ok")

    def test_409_over_the_wire_has_the_fixed_body(self):
        c = self.fx.enroll("web1")
        t = self.tok(name="web2")
        key, csr = F.make_key_and_csr(self.fx.tmp)
        c2 = F.Client(self.fx, key_path=key)
        status, _h, body = c2.enroll_request(t["token"], csr, extra={"host_uuid": c.uuid})
        self.assertEqual((status, body), (409, hub_common.error_body("host_exists")))

    def test_name_taken_between_token_and_redemption_is_409(self):
        t = self.tok(name="late")
        self.fx.writer.call(lambda c: c.execute(
            "INSERT INTO hosts(uuid,name,droplet_id,state,state_since,enrolled_at) VALUES('x','late','d','active',1,1)"))
        self.assertEqual(self.redeem(t["token"]), ("err", "host_exists"))

    def test_for_host_reuses_the_uuid_reissues_and_retires_the_old_certificate(self):
        c = self.fx.enroll("web1")
        old = self.host_row(c.uuid)
        t = self.tok(for_host="web1")
        status, reply = self.redeem(t["token"], droplet_id="d-2")
        self.assertEqual(status, "ok")
        self.assertEqual(reply["host_uuid"], c.uuid)
        new = self.host_row(c.uuid)
        self.assertNotEqual(new["cert_sha256"], old["cert_sha256"])
        self.assertNotEqual(new["cert_serial"], old["cert_serial"])
        self.assertEqual((new["state"], new["droplet_id"], new["name"]), ("pending", "d-2", "web1"))
        gone = self.fx.hub.pki.revoked_lookup(old["cert_sha256"])
        self.assertEqual(gone[1:], (c.uuid, "superseded"))
        self.assertEqual(len(self.fx.sql("SELECT 1 FROM hosts")), 1)
        # the old certificate is now refused with the right code
        status, _h, body = c.request("GET", "/v1/policy")
        self.assertEqual((status, json.loads(body)["code"]), (403, "cert_superseded"))

    def test_for_host_works_for_every_state(self):
        for state in ("moved", "retired", "revoked", "orphan"):
            name = "h-" + state
            c = self.fx.enroll(name)
            self.fx.writer.call(lambda conn, u=c.uuid, s=state: conn.execute("UPDATE hosts SET state=? WHERE uuid=?", (s, u)))
            status, reply = self.redeem(self.tok(for_host=name)["token"])
            self.assertEqual(status, "ok", state)
            self.assertEqual(self.host_row(c.uuid)["state"], "pending")

    def test_bad_csr_is_400_and_the_token_is_not_spent(self):
        t = self.tok(name="web1")
        self.assertEqual(self.redeem(t["token"], csr="garbage"), ("err", "bad_request"))
        _k, p384 = F.make_key_and_csr(self.fx.tmp, curve="secp384r1")
        self.assertEqual(self.redeem(t["token"], csr=p384), ("err", "bad_request"))
        self.assertIsNone(self.token_row(t["id"])["used_at"])
        self.assertEqual(len(self.fx.sql("SELECT 1 FROM hosts")), 0)
        self.assertEqual(self.redeem(t["token"])[0], "ok")

    def test_missing_fields_are_400_and_spend_nothing(self):
        t = self.tok(name="web1")
        for kw in ({"droplet_id": None}, {"droplet_id": ""}, {"droplet_id": 5}, {"droplet_id": "x" * 200},
                   {"droplet_id": "a\x00b"}, {"csr": 5}, {"hostname": 5}):
            result = self.redeem(t["token"], **kw)
            self.assertEqual(result, ("err", "bad_schema"), kw)
        self.assertEqual(self.fx.writer.call(lambda c: hub_enroll.redeem(c, self.fx.hub, {"csr": "x"}, PEER)), ("err", "bad_schema"))
        self.assertIsNone(self.token_row(t["id"])["used_at"])

    def test_a_failed_signing_spends_nothing(self):
        t = self.tok(name="web1")
        with mock.patch.object(self.fx.hub.pki, "sign_client", side_effect=hub_pki.PkiError("boom")):
            self.assertEqual(self.redeem(t["token"]), ("err", "bad_request"))
        self.assertIsNone(self.token_row(t["id"])["used_at"])
        with mock.patch.object(self.fx.hub.pki, "sign_client", side_effect=RuntimeError("crash")):
            with self.assertRaises(RuntimeError):
                self.redeem(t["token"])
        self.assertIsNone(self.token_row(t["id"])["used_at"])
        self.assertEqual(len(self.fx.sql("SELECT 1 FROM hosts")), 0)
        self.assertEqual(self.redeem(t["token"])[0], "ok")

    def test_enroll_is_audited_and_the_engine_is_told(self):
        import hub_audit
        t = self.tok(name="web1")
        status, reply = self.redeem(t["token"])
        calls = F.calls("on_enroll")
        self.assertEqual(len(calls), 1)
        _name, args, _kw = calls[0]
        self.assertEqual(args[1], self.fx.hub)
        self.assertEqual(args[2]["uuid"], reply["host_uuid"])
        self.assertEqual(args[3], PEER)
        self.assertEqual(args[4]["id"], t["id"])
        self.assertIs(args[5], False)
        if getattr(hub_audit, "FAKE", False):
            self.assertIn(("client", "enroll", reply["host_uuid"], "ok"), hub_audit.ROWS)
        else:
            rows = self.fx.sql("SELECT actor_kind, action, target, outcome FROM audit WHERE action='enroll'")
            self.assertEqual(rows, [{"actor_kind": "client", "action": "enroll", "target": reply["host_uuid"], "outcome": "ok"}])
        status, again = self.redeem(self.tok(for_host="web1")["token"])
        self.assertIs(F.calls("on_enroll")[-1][1][5], True)

    def test_a_failing_engine_does_not_undo_an_enrollment(self):
        t = self.tok(name="web1")
        import hub_engine
        orig = hub_engine.on_enroll
        hub_engine.on_enroll = mock.Mock(side_effect=RuntimeError("engine down"))
        try:
            status, reply = self.redeem(t["token"])
        finally:
            hub_engine.on_enroll = orig
        self.assertEqual(status, "ok")
        self.assertEqual(self.host_row(reply["host_uuid"])["state"], "pending")


class WireTest(EnrollCase):
    def test_get_ca_serves_pem_from_memory_and_matches_the_token(self):
        t = self.tok(name="web1")
        c = F.Client(self.fx)
        status, headers, body = c.request("GET", "/v1/ca", port=self.fx.enroll_port, verify=False, with_cert=False, proto=None)
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/x-pem-file")
        self.assertEqual(headers["cache-control"], "no-store")
        der = __import__("ssl").PEM_cert_to_DER_cert(body.decode())
        self.assertEqual(hashlib.sha256(der).hexdigest(), t["token"].split(".")[2])

    def test_enroll_failures_are_limited_per_source(self):
        c = F.Client(self.fx)
        _k, csr = F.make_key_and_csr(self.fx.tmp)
        self.tok(name="web1")
        codes = [c.enroll_request("0123456789ab." + "D" * 22, csr)[0] for _ in range(7)]
        self.assertEqual(codes[:5], [401] * 5)
        self.assertEqual(codes[5:], [429, 429])

    def test_global_failure_limit_and_bounded_table(self):
        lim = hub_enroll.FailureLimiter(per_source=5, overall=8)
        now = 1000.0
        for i in range(8):
            self.assertFalse(lim.blocked("10.0.0.%d" % i, now))
            lim.record("10.0.0.%d" % i, now)
        self.assertTrue(lim.blocked("10.9.9.9", now))
        self.assertFalse(lim.blocked("10.9.9.9", now + 61))
        big = hub_enroll.FailureLimiter(per_source=5, overall=10 ** 9)
        for i in range(hub_enroll.LIMITER_TABLE_MAX + 500):
            big.record("src-%d" % i, now)
        self.assertLessEqual(len(big._by_source), hub_enroll.LIMITER_TABLE_MAX)

    def test_oversize_enroll_body_is_413(self):
        c = F.Client(self.fx)
        self.tok(name="web1")
        status, _h, body = c.request("POST", "/v1/enroll", b"x" * (16 * 1024 + 1), port=self.fx.enroll_port, with_cert=False,
                                     verify=False)
        self.assertEqual(status, 413)

    def test_enrollment_listener_follows_the_tokens(self):
        def can_connect():
            s = socket.socket()
            s.settimeout(2)
            try:
                s.connect(("127.0.0.1", self.fx.enroll_port))
                return True
            except OSError:
                return False
            finally:
                s.close()
        self.assertFalse(can_connect())                                 # no token: the listener is closed
        t = self.tok(name="web1")
        self.assertTrue(can_connect())
        key, csr = F.make_key_and_csr(self.fx.tmp)
        c = F.Client(self.fx, key_path=key)
        self.assertEqual(c.enroll_request(t["token"], csr)[0], 200)
        self.assertTrue(can_connect())                                  # still open for the 10-minute replay window
        self.fx.writer.call(lambda conn: conn.execute("UPDATE tokens SET used_at=?", (hub_common.now_ms() - 11 * MIN,)))
        self.fx.hub.refresh_enroll_listener()
        self.assertFalse(can_connect())
        t2 = self.tok(name="web2", ttl_s=1)
        self.assertTrue(can_connect())
        self.fx.writer.call(lambda conn: hub_enroll.token_revoke(conn, self.fx.hub, t2["id"]))
        self.fx.hub.refresh_enroll_listener()
        self.assertFalse(can_connect())

    def test_fleet_routes_are_not_served_on_the_enrollment_port(self):
        self.tok(name="web1")
        c = F.Client(self.fx)
        status, _h, body = c.request("GET", "/v1/policy", port=self.fx.enroll_port, verify=False, with_cert=False)
        self.assertEqual(status, 404)
        status, _h, body = c.request("POST", "/v1/ca", b"", port=self.fx.enroll_port, verify=False, with_cert=False)
        self.assertEqual(status, 405)


class HostStateTest(EnrollCase):
    def set_state(self, ref_uuid, state, actor=""):
        return self.fx.writer.call(lambda c: hub_enroll.host_set_state(c, self.fx.hub, ref_uuid, state, actor))

    def test_resolve_host(self):
        c = self.fx.enroll("web1")
        r = self.fx.writer.call(lambda conn: hub_enroll.resolve_host(conn, "web1"))
        self.assertEqual(r["uuid"], c.uuid)
        r = self.fx.writer.call(lambda conn: hub_enroll.resolve_host(conn, c.uuid))
        self.assertEqual(r["name"], "web1")
        for ref in ("nope", "", None, "x" * 100):
            self.assertIsNone(self.fx.writer.call(lambda conn, x=ref: hub_enroll.resolve_host(conn, x)))

    def test_revoke_writes_revoked_txt_and_clears_nothing_else(self):
        c = self.fx.enroll("web1")
        before = self.host_row(c.uuid)
        self.set_state(c.uuid, "revoked")
        h = self.host_row(c.uuid)
        self.assertEqual(h["state"], "revoked")
        self.assertEqual(h["peer_ips"], before["peer_ips"])                 # revoked keeps its peers (never-ban table)
        with open(self.fx.paths.revoked) as f:
            line = f.read().splitlines()[-1].split()
        self.assertEqual(line[0], before["cert_serial"])
        self.assertEqual(line[1], before["cert_sha256"])
        self.assertEqual(line[2:4], [c.uuid, "revoked"])
        self.assertEqual(c.request("GET", "/v1/policy")[0], 403)

    def test_moved_and_retired_clear_the_peers_and_maintenance(self):
        for state in ("moved", "retired"):
            c = self.fx.enroll("h-" + state)
            self.fx.writer.call(lambda conn, u=c.uuid: conn.execute("UPDATE hosts SET peer_ips='[\"203.0.113.1\"]' WHERE uuid=?", (u,)))
            self.fx.writer.call(lambda conn, u=c.uuid: conn.execute("INSERT INTO maintenance VALUES(?,?,?,?)", (u, 1, "op", 1)))
            self.set_state(c.uuid, state)
            h = self.host_row(c.uuid)
            self.assertEqual((h["state"], h["peer_ips"]), (state, "[]"))
            self.assertEqual(self.fx.sql("SELECT 1 FROM maintenance WHERE host=?", (c.uuid,)), [])
            self.assertEqual(self.fx.hub.pki.revoked_lookup(h["cert_sha256"])[2], state)

    def test_pending_certificate_is_revoked_too(self):
        c = self.fx.enroll("web1")
        key, csr = F.make_key_and_csr(self.fx.tmp)
        status, _h, body = c.post_json("/v1/renew", {"csr": csr})
        self.assertEqual(status, 200)
        pending = self.host_row(c.uuid)["pending_cert_sha256"]
        self.assertTrue(pending)
        self.set_state(c.uuid, "revoked")
        self.assertEqual(self.fx.hub.pki.revoked_lookup(pending)[2], "revoked")

    def test_transition_table(self):
        allowed = {"revoked": ("pending", "active", "orphan", "moved", "retired"),
                   "retired": ("pending", "active", "orphan", "moved", "revoked"),
                   "moved": ("pending", "active", "orphan")}
        c = self.fx.enroll("web1")
        for target, sources in allowed.items():
            for source in ("pending", "active", "orphan", "moved", "retired", "revoked"):
                self.fx.writer.call(lambda conn, s=source: conn.execute("UPDATE hosts SET state=? WHERE uuid=?", (s, c.uuid)))
                if source in sources:
                    self.set_state(c.uuid, target)
                    self.assertEqual(self.host_row(c.uuid)["state"], target)
                else:
                    with self.assertRaises(ValueError, msg="%s -> %s" % (source, target)):
                        self.set_state(c.uuid, target)
                    self.assertEqual(self.host_row(c.uuid)["state"], source)

    def test_bad_requests(self):
        with self.assertRaises(ValueError):
            self.set_state("no-such-uuid", "revoked")
        c = self.fx.enroll("web1")
        for bad in ("active", "pending", "orphan", "bogus"):
            with self.assertRaises(ValueError):
                self.set_state(c.uuid, bad)

    def test_adopt_only_from_orphan(self):
        c = self.fx.enroll("web1")
        with self.assertRaises(ValueError):
            self.fx.writer.call(lambda conn: hub_enroll.host_adopt(conn, self.fx.hub, c.uuid))
        self.fx.writer.call(lambda conn: conn.execute("UPDATE hosts SET state='orphan' WHERE uuid=?", (c.uuid,)))
        self.fx.writer.call(lambda conn: hub_enroll.host_adopt(conn, self.fx.hub, c.uuid))
        self.assertEqual(self.host_row(c.uuid)["state"], "active")
        with self.assertRaises(ValueError):
            self.fx.writer.call(lambda conn: hub_enroll.host_adopt(conn, self.fx.hub, "nope"))

    def test_peers_follow_the_state_table(self):
        def put(uuid, state, peers):
            self.fx.writer.call(lambda c: c.execute(
                "INSERT INTO hosts(uuid,name,droplet_id,state,state_since,enrolled_at,peer_ips) VALUES(?,?,?,?,1,1,?)",
                (uuid, "n-" + uuid, "d", state, json.dumps(peers))))
        put("u1", "pending", ["203.0.113.1"])
        put("u2", "active", ["203.0.113.2", "2001:db8::1"])
        put("u3", "revoked", ["203.0.113.3"])
        put("u4", "moved", ["203.0.113.4"])
        put("u5", "retired", ["203.0.113.5"])
        put("u6", "orphan", ["203.0.113.6"])
        put("u7", "active", ["203.0.113.2", "::ffff:198.51.100.9", "not-an-ip"])
        got = self.fx.writer.call(lambda c: hub_enroll.peers(c))
        self.assertEqual(got, ["198.51.100.9", "203.0.113.1", "203.0.113.2", "203.0.113.3", "2001:db8::1"])

    def test_peers_are_capped_at_512(self):
        rows = [("u%d" % i, "n%d" % i, "d", "active", 1, 1, json.dumps(["10.%d.%d.%d" % (i // 65536, i // 256 % 256, i % 256)]))
                for i in range(600)]
        self.fx.writer.call(lambda c: c.executemany(
            "INSERT INTO hosts(uuid,name,droplet_id,state,state_since,enrolled_at,peer_ips) VALUES(?,?,?,?,?,?,?)", rows))
        self.assertEqual(len(self.fx.writer.call(lambda c: hub_enroll.peers(c))), 512)

    def test_add_peer_keeps_two_newest(self):
        p = "[]"
        for ip in ("1.1.1.1", "2.2.2.2", "1.1.1.1", "3.3.3.3"):
            p = hub_enroll.add_peer(p, ip)
        self.assertEqual(json.loads(p), ["1.1.1.1", "3.3.3.3"])
        self.assertEqual(json.loads(hub_enroll.add_peer("garbage", "9.9.9.9")), ["9.9.9.9"])


if __name__ == "__main__":
    unittest.main()
