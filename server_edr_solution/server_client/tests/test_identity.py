import json
import os
import shutil
import ssl
import stat
import subprocess
import tempfile
import time
import unittest

import test_transport_pki as support
from test_transport_pki import FakeHub, HubPair, PKI, err, reply
from edragent import identity as idn
from edragent import transport as tr
from edragent import spool as sp


def slurp(path):
    with open(path) as f:
        return f.read()


def openssl(*args, input=None):
    r = subprocess.run([support.OPENSSL] + list(args), capture_output=True, input=input, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout.decode()


class TestDer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = PKI()

    @classmethod
    def tearDownClass(cls):
        cls.pki.cleanup()

    def der(self, pem_text):
        return idn.pem_to_der(pem_text)

    def test_validity_matches_openssl(self):
        cert, _ = self.pki.client(days=123)
        text = slurp(cert)
        out = openssl("x509", "-in", cert, "-noout", "-startdate", "-enddate")
        nb = ssl.cert_time_to_seconds(out.split("notBefore=")[1].split("\n")[0].strip())
        na = ssl.cert_time_to_seconds(out.split("notAfter=")[1].split("\n")[0].strip())
        self.assertEqual(idn.cert_validity(self.der(text)), (nb, na))
        self.assertEqual(idn.cert_not_after(cert), na)
        self.assertAlmostEqual(na - time.time(), 123 * 86400, delta=3600)

    def test_ca_and_curve(self):
        self.assertEqual(idn.cert_ca_p384(self.der(self.pki.pem())), (True, True))
        cert, _ = self.pki.client()
        self.assertEqual(idn.cert_ca_p384(self.der(slurp(cert))), (False, False))
        srv, _ = self.pki.server()
        self.assertEqual(idn.cert_ca_p384(self.der(slurp(srv))), (False, False))

    def test_a_p256_ca_is_not_p384(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        key, pem, cnf = (os.path.join(d, n) for n in ("k", "c.pem", "c.cnf"))
        support.write(cnf, support.CA_CNF % {"cn": "P256 CA"})
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
        openssl("req", "-x509", "-new", "-key", key, "-days", "10", "-config", cnf, "-out", pem)
        self.assertEqual(idn.cert_ca_p384(self.der(slurp(pem))), (True, False))

    def test_lax_ca_without_critical_basic_constraints_still_reads(self):
        lax = PKI(lax=True)
        self.addCleanup(lax.cleanup)
        self.assertEqual(idn.cert_ca_p384(self.der(lax.pem())), (True, True))

    def test_garbage_der_raises_valueerror_or_indexerror(self):
        import random
        rnd = random.Random(1)
        good = ssl.PEM_cert_to_DER_cert(self.pki.pem())
        for i in range(500):
            b = bytearray(good)
            for _ in range(3):
                b[rnd.randrange(len(b))] = rnd.randrange(256)
            try:
                idn.cert_validity(bytes(b))
                idn.cert_ca_p384(bytes(b))
            except (ValueError, IndexError, UnicodeError):
                pass
        for junk in (b"", b"\x30", b"\x30\x84\xff\xff\xff\xff", b"junk" * 10):
            with self.assertRaises((ValueError, IndexError)):
                idn.cert_validity(junk)

    def test_pem_to_der_accepts_exactly_one_block(self):
        pem = self.pki.pem()
        self.assertTrue(idn.pem_to_der(pem))
        for bad in (pem + pem, "", "junk", pem.replace("CERTIFICATE", "PRIVATE KEY"), pem + "trailing junk", "x" + pem, None,
                    pem[:-30]):
            with self.assertRaises(ValueError, msg=repr(bad)[:40]):
                idn.pem_to_der(bad)
        with self.assertRaises(ValueError):
            idn.pem_to_der(pem, cap=100)


class TestKeyAndCsr(unittest.TestCase):
    def test_key_csr(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        csr = idn.make_key_and_csr(d)
        key = os.path.join(d, "client.key")
        self.assertEqual(stat.S_IMODE(os.stat(key).st_mode), 0o600)
        self.assertIn("BEGIN CERTIFICATE REQUEST", csr)
        text = openssl("pkey", "-in", key, "-noout", "-text")
        self.assertIn("prime256v1", text.replace("NIST CURVE: P-256", "prime256v1"))
        openssl("req", "-in", os.path.join(d, "client.csr"), "-verify", "-noout")
        pub1 = openssl("pkey", "-in", key, "-pubout")
        pub2 = openssl("req", "-in", os.path.join(d, "client.csr"), "-pubkey", "-noout")
        self.assertEqual(pub1, pub2)
        key1 = slurp(key)
        idn.make_key_and_csr(d)
        self.assertNotEqual(slurp(key), key1)                  # a new key every time

    def test_generation_numbers_and_modes(self):
        env = support.Env()
        self.addCleanup(env.cleanup)
        n1, csr1 = idn.new_generation(env.paths)
        n2, csr2 = idn.new_generation(env.paths)
        self.assertEqual((n1, n2), (1, 2))
        self.assertNotEqual(csr1, csr2)
        for n in (1, 2):
            self.assertEqual(stat.S_IMODE(os.stat(idn.gen_path(env.paths, n)).st_mode), 0o700)
        self.assertEqual(idn.gen_numbers(env.paths), [1, 2])
        self.assertEqual(idn.next_gen(env.paths), 3)


    def test_root_hands_the_identity_directory_to_the_agent(self):
        """On a first enrollment root makes identity/ itself; the sandboxed agent must be able to renew in it."""
        env = support.Env()
        self.addCleanup(env.cleanup)
        ops = idn.SystemOps(env.paths)
        idn.new_generation(env.paths, ops)
        owned = [c[1] for c in ops.calls if c[0] == "chown"]
        self.assertIn(str(env.paths.identity_dir), owned)
        self.assertEqual(owned[-1], str(env.paths.identity_dir))      # after the key exists, so it is covered


class TestTokenAndHub(unittest.TestCase):
    def test_token(self):
        sha = "ab" * 32
        self.assertEqual(idn.parse_token("tok12345.secretsecret1234." + sha), ("tok12345", "secretsecret1234", sha))
        self.assertEqual(idn.parse_token("  tok12345.secretsecret1234.%s \n" % sha)[0], "tok12345")
        for bad in ("", "a.b.c", "tok12345.secret.%s" % sha, "tok12345.secretsecret1234." + sha[:-1],
                    "tok12345.secretsecret1234." + sha.upper(), "tok 12345.secretsecret1234." + sha,
                    "tok12345.secretsecret1234." + sha + ".x", None):
            with self.assertRaises(idn.IdentityError) as cm:
                idn.parse_token(bad)
            self.assertEqual(cm.exception.code, 3)

    def test_hub(self):
        self.assertEqual(idn.parse_hub("203.0.113.5:8443"), ("203.0.113.5", 8443))
        self.assertEqual(idn.parse_hub("[2001:db8::1]:8443"), ("2001:db8::1", 8443))
        for bad in ("203.0.113.5", "203.0.113.5:0", "203.0.113.5:99999", "host:8443", "2001:db8::1:8443", "[::1]:x", "",
                    "01.2.3.4:80"):
            with self.assertRaises(idn.IdentityError):
                idn.parse_hub(bad)


class IdentityCase(unittest.TestCase):
    def setUp(self):
        self.env = support.Env()
        self.addCleanup(self.env.cleanup)
        self.p = self.env.paths
        self.env.set_droplet("424242")
        self.hubs = HubPair()
        self.addCleanup(self.hubs.stop)
        self.ops = idn.SystemOps(self.p)

    def do_enroll(self, token=None, **kw):
        args = dict(hub="127.0.0.1", port=self.hubs.fleet_port, enroll_port=self.hubs.enroll_port,
                    token=token or self.hubs.token, droplet_id="424242", hostname="web1", os_name="Ubuntu 24.04",
                    ips=["192.0.2.5"], ops=self.ops, allow_loopback=True)
        args.update(kw)
        return idn.enroll(self.p, **args)

    def assertNothingWritten(self):
        self.assertEqual(idn.gen_numbers(self.p), [])
        self.assertIsNone(idn.current_gen_name(self.p))
        self.assertFalse(os.path.exists(self.p.host_id))
        self.assertFalse(os.path.exists(self.ops.dropin_path))


class TestFetchCa(IdentityCase):
    def test_accepts_the_right_ca_and_reencodes_it(self):
        pem = idn.fetch_ca("127.0.0.1", self.hubs.enroll_port, self.hubs.pki.der_sha256())
        self.assertEqual(idn.sha256_hex(idn.pem_to_der(pem)), self.hubs.pki.der_sha256())
        req = self.hubs.enroll.requests[0]
        self.assertEqual((req.method, req.path), ("GET", "/v1/ca"))
        self.assertIsNone(req.peer_cn)                      # no client certificate
        self.assertNotIn(b"tok", req.raw_head)             # no token
        self.assertEqual(req.body, b"")

    def test_hash_mismatch_is_refused(self):
        with self.assertRaises(idn.IdentityError) as cm:
            idn.fetch_ca("127.0.0.1", self.hubs.enroll_port, "0" * 64)
        self.assertIn("SHA-256", str(cm.exception))

    def test_extra_bytes_two_blocks_big_and_non_ca_are_refused(self):
        sha = self.hubs.pki.der_sha256()
        pem = self.hubs.pki.pem()
        srv, _ = self.hubs.pki.server()
        cases = {"two blocks": (pem + pem).encode(), "trailing text": (pem + "extra").encode(), "empty": b"",
                 "junk": b"hello", "too big": (pem + "x" * 3000).encode(), "server cert": slurp(srv).encode()}
        for name, body in cases.items():
            self.hubs.responses["/v1/ca"] = lambda r, body=body: (200, {}, body)
            with self.assertRaises(idn.IdentityError, msg=name):
                idn.fetch_ca("127.0.0.1", self.hubs.enroll_port, sha if name != "server cert" else idn.sha256_hex(idn.pem_to_der(body.decode())))

    def test_non_200_is_refused(self):
        self.hubs.responses["/v1/ca"] = lambda r: err(429, "rate_limited")
        with self.assertRaises(idn.IdentityError):
            idn.fetch_ca("127.0.0.1", self.hubs.enroll_port, self.hubs.pki.der_sha256())

    def test_p256_ca_is_refused(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        key, pem, cnf = (os.path.join(d, n) for n in ("k", "c.pem", "c.cnf"))
        support.write(cnf, support.CA_CNF % {"cn": "P256 CA"})
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
        openssl("req", "-x509", "-new", "-key", key, "-days", "10", "-config", cnf, "-out", pem)
        body = slurp(pem).encode()
        self.hubs.responses["/v1/ca"] = lambda r: (200, {}, body)
        with self.assertRaises(idn.IdentityError) as cm:
            idn.fetch_ca("127.0.0.1", self.hubs.enroll_port, idn.sha256_hex(idn.pem_to_der(body.decode())))
        self.assertIn("P-384", str(cm.exception))


class TestEnroll(IdentityCase):
    def test_two_step_enrollment_layout_and_wire(self):
        rep = self.do_enroll()
        self.assertEqual(rep["host_uuid"], self.hubs.uuid)
        self.assertEqual(rep["state"], "pending")
        # the order on the wire: CA fetch first (no token), then the pinned enroll, then the test call
        e = self.hubs.enroll.requests
        self.assertEqual([(r.method, r.path) for r in e], [("GET", "/v1/ca"), ("POST", "/v1/enroll")])
        self.assertNotIn(b"secretsecret", e[0].raw_head + e[0].body)
        self.assertIsNone(e[0].peer_cn)
        self.assertIsNone(e[1].peer_cn)                              # enrollment connections never load a certificate
        body = e[1].json()
        self.assertEqual(set(body), {"token", "csr", "hostname", "os", "ips", "droplet_id"})
        self.assertEqual(body["token"], "tok12345.secretsecret1234")  # id.secret only; the CA hash stays with the client
        self.assertEqual(body["droplet_id"], "424242")
        self.assertEqual(body["ips"], ["192.0.2.5"])
        self.assertIn("BEGIN CERTIFICATE REQUEST", body["csr"])
        f = self.hubs.fleet.requests
        self.assertEqual([(r.method, r.path) for r in f], [("GET", "/v1/policy")])   # the test call
        self.assertEqual(f[0].peer_cn, self.hubs.uuid)                               # with the new certificate
        # identity layout
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")
        d = idn.gen_path(self.p, 1)
        self.assertEqual(sorted(n for n in os.listdir(d)), ["ca.pem", "client.csr", "client.key", "client.pem", "hub.conf"])
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(d, "client.key")).st_mode), 0o600)
        hc = idn.read_hub_conf(os.path.join(d, "hub.conf"))
        self.assertEqual(hc, {"addresses": ["127.0.0.1"], "port": self.hubs.fleet_port, "enroll_port": self.hubs.enroll_port,
                              "host_uuid": self.hubs.uuid, "ca_sha256": self.hubs.pki.der_sha256()})
        raw = slurp(os.path.join(d, "hub.conf"))
        self.assertTrue(raw.startswith("[hub]\n"))
        self.assertEqual(idn.read_host_id(self.p), self.hubs.uuid)
        self.assertEqual(idn.stored_droplet_id(self.p), "424242")
        self.assertIn("IPAddressAllow=127.0.0.1", slurp(self.ops.dropin_path))
        self.assertIn(["systemctl", "daemon-reload"], self.ops.calls)
        ident = idn.load_current(self.p)
        self.assertEqual((ident.gen, ident.host_uuid, ident.port), (1, self.hubs.uuid, self.hubs.fleet_port))
        self.assertEqual(os.path.realpath(ident.gen_dir), ident.gen_dir)
        self.assertGreater(ident.not_after(), time.time() + 364 * 86400)
        # the ca.pem on disk is the hash-checked one, re-encoded
        self.assertEqual(idn.sha256_hex(idn.pem_to_der(slurp(os.path.join(d, "ca.pem")))), self.hubs.pki.der_sha256())

    def test_host_uuid_hint_only_when_host_id_exists_and_droplet_unchanged(self):
        idn.write_host_id(self.p, "99999999-aaaa-4bbb-8ccc-dddddddddddd")
        idn.write_stored_droplet_id(self.p, "424242")
        self.do_enroll()
        self.assertEqual(self.hubs.enroll.requests[1].json()["host_uuid"], "99999999-aaaa-4bbb-8ccc-dddddddddddd")
        self.assertEqual(idn.read_host_id(self.p), self.hubs.uuid)         # rewritten from the reply

    def test_clone_does_not_send_a_stale_host_uuid_and_deletes_it(self):
        idn.write_host_id(self.p, "99999999-aaaa-4bbb-8ccc-dddddddddddd")
        idn.write_stored_droplet_id(self.p, "111111")                       # enrolled as another droplet
        rep = self.do_enroll()
        self.assertNotIn("host_uuid", self.hubs.enroll.requests[1].json())
        self.assertTrue(rep["stale_host_id_removed"])
        self.assertEqual(idn.read_host_id(self.p), self.hubs.uuid)          # the new one, from the reply
        self.assertEqual(idn.stored_droplet_id(self.p), "424242")

    def test_droplet_id_is_required_and_valid(self):
        for bad in ("", None, "has space", "x" * 65, "a;b"):
            with self.assertRaises(idn.IdentityError) as cm:
                self.do_enroll(droplet_id=bad)
            self.assertEqual(cm.exception.code, 3)
        self.assertNothingWritten()
        self.assertEqual(self.hubs.enroll.requests, [])

    def test_wrong_ca_hash_sends_nothing_secret_and_writes_nothing(self):
        bad = "tok12345.secretsecret1234." + "0" * 64
        with self.assertRaises(idn.IdentityError) as cm:
            self.do_enroll(token=bad)
        self.assertTrue(cm.exception.hub)
        self.assertEqual([(r.method, r.path) for r in self.hubs.enroll.requests], [("GET", "/v1/ca")])   # no POST, no token
        self.assertNothingWritten()

    def test_refused_token_409_and_orphan_cases(self):
        with self.assertRaises(idn.IdentityError) as cm:
            self.do_enroll(token="tok12345.wrongsecret12345." + self.hubs.pki.der_sha256())
        self.assertIn("refused the token", str(cm.exception))
        self.assertTrue(cm.exception.hub)
        self.assertNothingWritten()
        self.hubs.responses["/v1/enroll"] = lambda r: err(409, "host_exists")
        with self.assertRaises(idn.IdentityError) as cm:
            self.do_enroll()
        self.assertIn("--for HOST", str(cm.exception))
        self.assertNothingWritten()
        self.hubs.responses["/v1/enroll"] = lambda r: err(503, "busy", {"Retry-After": "5"})
        with self.assertRaises(idn.IdentityError):
            self.do_enroll()
        self.assertNothingWritten()

    def test_reply_validation_refusals_write_nothing(self):
        cases = {
            "uuid case": lambda rep: rep.update(host_uuid=rep["host_uuid"].upper()),
            "uuid junk": lambda rep: rep.update(host_uuid="not-a-uuid"),
            "uuid braces": lambda rep: rep.update(host_uuid="{%s}" % rep["host_uuid"]),
            "too many addresses": lambda rep: rep.update(hub_addresses=["192.0.2.%d" % i for i in range(1, 6)]),
            "no addresses": lambda rep: rep.update(hub_addresses=[]),
            "bracketed v6": lambda rep: rep.update(hub_addresses=["[2001:db8::1]", "127.0.0.1"]),
            "not an ip": lambda rep: rep.update(hub_addresses=["hub.example.net"]),
            "link local": lambda rep: rep.update(hub_addresses=["127.0.0.1", "169.254.169.254"]),
            "multicast": lambda rep: rep.update(hub_addresses=["127.0.0.1", "224.0.0.1"]),
            "unspecified": lambda rep: rep.update(hub_addresses=["127.0.0.1", "0.0.0.0"]),
            "hub ip missing": lambda rep: rep.update(hub_addresses=["192.0.2.77"]),
            "port differs": lambda rep: rep.update(port=rep["port"] + 1),
            "port string": lambda rep: rep.update(port=str(rep["port"])),
            "port bool": lambda rep: rep.update(port=True),
            "addresses not a list": lambda rep: rep.update(hub_addresses="127.0.0.1"),
        }
        for name, tweak in cases.items():
            self.hubs.enroll_tweak = tweak
            with self.assertRaises(idn.IdentityError, msg=name) as cm:
                self.do_enroll()
            self.assertTrue(cm.exception.hub, name)                    # enroll maps it to exit 5
            self.assertEqual(cm.exception.code, 3, name)
            self.assertNothingWritten()

    def test_loopback_is_refused_unless_a_dev_run(self):
        with self.assertRaises(idn.IdentityError) as cm:
            self.do_enroll(allow_loopback=False)
        self.assertIn("loopback", str(cm.exception))
        self.assertNothingWritten()

    def test_reply_with_a_different_ca_is_refused(self):
        other = PKI(cn="Other CA")
        self.addCleanup(other.cleanup)
        self.hubs.enroll_tweak = lambda rep: rep.update(ca=other.pem())
        with self.assertRaises(idn.IdentityError) as cm:
            self.do_enroll()
        self.assertIn("differs from the pinned CA", str(cm.exception))
        self.assertNothingWritten()

    def test_certificate_must_match_the_key(self):
        other = PKI()
        self.addCleanup(other.cleanup)
        cert, _ = self.hubs.pki.client(name="foreign")
        self.hubs.enroll_tweak = lambda rep: rep.update(certificate=slurp(cert))
        with self.assertRaises(idn.IdentityError):
            self.do_enroll()
        self.assertNothingWritten()

    def test_test_call_failure_aborts_and_cleans_up(self):
        self.hubs.responses["/v1/policy"] = lambda r: err(403, "host_unknown")
        with self.assertRaises(idn.IdentityError) as cm:
            self.do_enroll()
        self.assertIn("test call", str(cm.exception))
        self.assertNothingWritten()

    def test_test_call_is_retried_for_the_window(self):
        calls = []

        def flaky(req):
            calls.append(1)
            return err(503, "busy") if len(calls) < 3 else reply(200, self.hubs.policy_doc())
        self.hubs.responses["/v1/policy"] = flaky
        params_window = {"n": 0}
        real = idn.net_phase

        def quick(params, token, **kw):
            params = dict(params, test_window_s=20)
            return real(params, token, sleep=lambda s: params_window.__setitem__("n", params_window["n"] + 1), **kw)
        rep = self.do_enroll(net_runner=lambda p, t: quick(p, t))
        self.assertEqual(len(calls), 3)
        self.assertEqual(rep["host_uuid"], self.hubs.uuid)

    def test_reenroll_over_an_existing_identity_keeps_the_old_generation_until_cleanup(self):
        self.do_enroll()
        self.hubs.uuid = "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        self.do_enroll()
        self.assertEqual(idn.gen_numbers(self.p), [1, 2])
        self.assertEqual(idn.current_gen_name(self.p), "gen-2")
        self.assertEqual(idn.cleanup_generations(self.p), [1])
        self.assertEqual(idn.gen_numbers(self.p), [2])


class TestHostIdentity(IdentityCase):
    def test_clone_detection(self):
        self.assertFalse(idn.host_identity_changed(self.p))            # nothing recorded yet
        idn.write_host_id(self.p, "99999999-aaaa-4bbb-8ccc-dddddddddddd")
        self.assertFalse(idn.host_identity_changed(self.p))            # no stored droplet id
        idn.write_stored_droplet_id(self.p, "424242")
        self.assertFalse(idn.host_identity_changed(self.p))            # same droplet
        idn.write_stored_droplet_id(self.p, "555")
        self.assertTrue(idn.host_identity_changed(self.p))             # a clone: new droplet id, old identity
        os.unlink(self.p.droplet_id)
        self.assertFalse(idn.host_identity_changed(self.p))            # unreachable metadata fails open

    def test_host_id_must_be_canonical(self):
        for bad in ("ABCDEFAB-bbbb-4ccc-8ddd-eeeeeeeeeeee", "junk", "", "{aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee}"):
            with open(self.p.host_id, "w") as f:
                f.write(bad + "\n")
            self.assertIsNone(idn.read_host_id(self.p), bad)

    def test_droplet_ids(self):
        self.assertEqual(idn.running_droplet_id(self.p), "424242")
        for bad in ("", "a b", "a\nb\x01", "x" * 65):
            with open(self.p.droplet_id, "w") as f:
                f.write(bad + "\n")
            self.assertIsNone(idn.running_droplet_id(self.p))


class TestRenew(IdentityCase):
    def client(self):
        return tr.HubClient(lambda: idn.load_current(self.p).target())

    def test_due_arithmetic(self):
        support.make_identity(self.env, self.hubs.pki, self.hubs.fleet_port, days=40)
        ident = idn.load_current(self.p)
        self.assertFalse(idn.renew_due(ident, time.time()))
        self.assertTrue(idn.renew_due(ident, time.time() + 11 * 86400))
        self.assertFalse(idn.renew_due(ident, time.time() + 9 * 86400))
        support.make_identity(self.env, self.hubs.pki, self.hubs.fleet_port, gen=2, days=29)
        self.assertTrue(idn.renew_due(idn.load_current(self.p)))

    def test_renewal_makes_a_new_generation_with_a_new_key_and_flips(self):
        support.make_identity(self.env, self.hubs.pki, self.hubs.fleet_port, days=20, cn=self.hubs.uuid)
        old_key = slurp(os.path.join(idn.gen_path(self.p, 1), "client.key"))
        st, oc = idn.renew(self.p, self.client())
        self.assertEqual(st, "renewed")
        self.assertEqual(idn.current_gen_name(self.p), "gen-2")
        new = idn.load_current(self.p)
        self.assertGreater(new.not_after(), time.time() + 360 * 86400)
        self.assertNotEqual(slurp(new.key), old_key)
        self.assertEqual(new.host_uuid, self.hubs.uuid)
        self.assertEqual(new.addresses, ["127.0.0.1"])
        req = [r for r in self.hubs.fleet.requests if r.path == "/v1/renew"][0]
        self.assertEqual(set(req.json()), {"csr"})
        self.assertEqual(req.peer_cn, self.hubs.uuid)
        # the previous generation stays until a heartbeat is accepted with the new one
        self.assertEqual(idn.gen_numbers(self.p), [1, 2])
        self.assertEqual(idn.cleanup_generations(self.p), [1])
        self.assertEqual(idn.gen_numbers(self.p), [2])

    def test_a_lost_reply_reuses_the_csr(self):
        support.make_identity(self.env, self.hubs.pki, self.hubs.fleet_port, days=20, cn=self.hubs.uuid)
        self.hubs.responses["/v1/renew"] = lambda r: err(503, "busy", {"Retry-After": "1"})
        st, oc = idn.renew(self.p, self.client())
        self.assertEqual((st, oc.action), ("failed", tr.WAIT))
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")
        csr1 = slurp(os.path.join(idn.gen_path(self.p, 2), "client.csr"))
        st, oc = idn.renew(self.p, self.client())
        csr2 = slurp(os.path.join(idn.gen_path(self.p, 2), "client.csr"))
        self.assertEqual(csr1, csr2)                                   # the same CSR: the hub returns the same certificate
        self.assertEqual(idn.gen_numbers(self.p), [1, 2])
        self.hubs.responses.pop("/v1/renew")
        st, oc = idn.renew(self.p, self.client())
        self.assertEqual(st, "renewed")
        self.assertEqual(idn.gen_numbers(self.p), [1, 2])

    def test_orphan_and_forbidden_do_not_flip(self):
        support.make_identity(self.env, self.hubs.pki, self.hubs.fleet_port, days=20, cn=self.hubs.uuid)
        self.hubs.responses["/v1/renew"] = lambda r: err(403, "host_orphan")
        st, oc = idn.renew(self.p, self.client())
        self.assertEqual((st, oc.action), ("failed", tr.ORPHAN))
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")

    def test_bad_certificate_in_the_reply_is_refused(self):
        support.make_identity(self.env, self.hubs.pki, self.hubs.fleet_port, days=20, cn=self.hubs.uuid)
        cert, _ = self.hubs.pki.client(name="foreign2")           # signed for another key
        self.hubs.responses["/v1/renew"] = lambda r: reply(200, {"certificate": slurp(cert), "not_after": "x"})
        st, oc = idn.renew(self.p, self.client())
        self.assertEqual(st, "failed")
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")
        self.hubs.responses["/v1/renew"] = lambda r: reply(200, {"certificate": "junk"})
        self.assertEqual(idn.renew(self.p, self.client())[0], "failed")

    def test_cleanup_waits_for_a_rehome_to_finish(self):
        support.make_identity(self.env, self.hubs.pki, self.hubs.fleet_port, gen=1)
        support.make_identity(self.env, self.hubs.pki, self.hubs.fleet_port, gen=2)
        sp.atomic_write(os.path.join(str(self.p.identity_dir), "rehome.json"), "{}", 0o600)
        self.assertEqual(idn.cleanup_generations(self.p), [])
        self.assertEqual(idn.gen_numbers(self.p), [1, 2])


class TestDeregister(IdentityCase):
    def test_best_effort_with_the_given_identity(self):
        support.make_identity(self.env, self.hubs.pki, self.hubs.fleet_port, cn=self.hubs.uuid)
        oc = idn.deregister(self.p, "rehome")
        self.assertEqual(oc.action, tr.OK)
        self.assertEqual(self.hubs.deregistered, [(self.hubs.uuid, {"reason": "rehome"})])
        self.hubs.responses["/v1/deregister"] = lambda r: err(403, "host_retired")
        self.assertEqual(idn.deregister(self.p, "uninstall").action, tr.FORBIDDEN)
        other = support.Env()
        self.addCleanup(other.cleanup)
        self.assertIsNone(idn.deregister(other.paths, "uninstall"))                # not enrolled


class TestIdentityLoading(IdentityCase):
    def test_not_enrolled_and_broken_layouts(self):
        self.assertIsNone(idn.load_current(self.p))
        d = support.make_identity(self.env, self.hubs.pki, self.hubs.fleet_port)
        self.assertIsNotNone(idn.load_current(self.p))
        os.unlink(os.path.join(d, "client.key"))
        self.assertIsNone(idn.load_current(self.p))
        d = support.make_identity(self.env, self.hubs.pki, self.hubs.fleet_port)
        for junk in ("[hub]\naddresses = \nport = 1\n", "[hub]\naddresses = 1.2.3.4\nport = x\n", "garbage", "[hub]\naddresses = 1.2.3.4,1.2.3.5,1.2.3.6,1.2.3.7,1.2.3.8\nport = 1\n",
                     "[hub]\naddresses = 1.2.3.4\nport = 99999\n"):
            with open(os.path.join(d, "hub.conf"), "w") as f:
                f.write(junk)
            self.assertIsNone(idn.load_current(self.p), junk)

    def test_current_must_point_at_a_gen_directory(self):
        support.make_identity(self.env, self.hubs.pki, self.hubs.fleet_port)
        cur = os.path.join(str(self.p.identity_dir), "current")
        os.unlink(cur)
        os.symlink("../../../etc", cur)
        self.assertIsNone(idn.load_current(self.p))
        os.unlink(cur)
        os.symlink("/etc", cur)
        self.assertIsNone(idn.load_current(self.p))


class RehomeCase(IdentityCase):
    def setUp(self):
        super().setUp()
        self.old = HubPair(uuid_="11111111-1111-4111-8111-111111111111", token_id="oldtok123", secret="oldsecret1234567")
        self.addCleanup(self.old.stop)
        support.make_identity(self.env, self.old.pki, self.old.fleet_port, cn=self.old.uuid, enroll_port=self.old.enroll_port)
        self.ops.write_dropin(["127.0.0.1"])
        idn.write_host_id(self.p, self.old.uuid)
        idn.write_stored_droplet_id(self.p, "424242")
        self.logs = []

    def rehome(self, confirm=None, **kw):
        args = dict(hub="127.0.0.1", port=self.hubs.fleet_port, enroll_port=self.hubs.enroll_port, token=self.hubs.token,
                    droplet_id="424242", hostname="web1", os_name="Ubuntu", ips=[], ops=self.ops, allow_loopback=True,
                    confirm=confirm or (lambda name, since, timeout: ""), log=self.logs.append, lib_dir="/lib/x")
        args.update(kw)
        return idn.rehome(self.p, {"agent": {"rehome_confirm_timeout": 30}}, **args)

    def dropin(self):
        return slurp(self.ops.dropin_path)


class TestRehome(RehomeCase):
    def test_full_rehome_to_a_new_hub(self):
        rc = self.rehome()
        self.assertEqual(rc, 0, self.logs)
        self.assertEqual(idn.current_gen_name(self.p), "gen-2")
        self.assertEqual(idn.gen_numbers(self.p), [2])                          # the previous generation, key included, is gone
        self.assertEqual(idn.read_host_id(self.p), self.hubs.uuid)              # rewritten from the new reply
        ident = idn.load_current(self.p)
        self.assertEqual(ident.port, self.hubs.fleet_port)
        # best-effort deregister to the OLD hub with the OLD certificate
        self.assertEqual(self.old.deregistered, [(self.old.uuid, {"reason": "rehome"})])
        # the drop-in names the new hub only
        self.assertIn("IPAddressAllow=127.0.0.1", self.dropin())
        self.assertFalse(os.path.exists(os.path.join(str(self.p.identity_dir), "rehome.json")))
        names = [c[0] if c[0] != "systemd-run" else "systemd-run" for c in self.ops.calls]
        self.assertIn("systemd-run", names)                                     # the timed rollback was armed ...
        arm = [c for c in self.ops.calls if c[0] == "systemd-run"][0]
        self.assertIn("--on-active=600", arm)
        self.assertEqual(arm[-2:], ["rehome", "--rollback"])
        self.assertTrue(any(c[:3] == ["systemctl", "stop", "edr-agent-rehome-rollback.timer"] for c in self.ops.calls))   # ... and disarmed
        self.assertTrue(any(c[:2] == ["systemctl", "restart"] for c in self.ops.calls))

    def test_order_of_steps(self):
        seen = []

        def confirm(name, since, timeout):
            seen.append(("confirm", idn.current_gen_name(self.p), self.dropin(), idn.read_host_id(self.p)))
            st = idn.load_rehome_state(self.p)
            seen.append(("state", st["step"]))
            return ""
        self.rehome(confirm=confirm)
        c = seen[0]
        self.assertEqual(c[1], "gen-2")                                           # flipped before the confirm
        self.assertEqual(c[3], self.old.uuid)                                     # host-id changes only at the commit
        self.assertEqual(seen[1], ("state", 5))
        kinds = [(x[0], x[1] if x[0] == "systemctl" else "") for x in self.ops.calls if x[0] in ("systemd-run", "systemctl", "chown")]
        first_arm = next(i for i, x in enumerate(self.ops.calls) if x[0] == "systemd-run")
        first_reload = next(i for i, x in enumerate(self.ops.calls) if x[:2] == ["systemctl", "daemon-reload"])
        first_restart = next(i for i, x in enumerate(self.ops.calls) if x[:2] == ["systemctl", "restart"])
        self.assertLess(first_arm, first_reload)
        self.assertLess(first_reload, first_restart)
        del kinds

    def test_both_hubs_allowed_while_unconfirmed(self):
        new = HubPair(uuid_="22222222-2222-4222-8222-222222222222", addresses=("127.0.0.1", "192.0.2.50"))
        self.addCleanup(new.stop)
        seen = []
        self.rehome(token=new.token, port=new.fleet_port, enroll_port=new.enroll_port,
                    confirm=lambda *a: seen.append(self.dropin()) or "")
        self.assertIn("IPAddressAllow=127.0.0.1 192.0.2.50", seen[0])
        # after the commit: the new hub's addresses only
        self.assertIn("IPAddressAllow=127.0.0.1 192.0.2.50", self.dropin())

    def test_both_generations_are_visible_to_the_never_ban_list_during_the_move(self):
        from edragent import bans as bm
        new = HubPair(uuid_="22222222-2222-4222-8222-222222222222", addresses=("127.0.0.1", "192.0.2.50"))
        self.addCleanup(new.stop)
        seen = []
        self.rehome(token=new.token, port=new.fleet_port, enroll_port=new.enroll_port,
                    confirm=lambda *a: seen.append({str(n) for n in bm.hub_addresses_from_identity(self.p.identity_dir)}) or "")
        self.assertEqual(seen[0], {"127.0.0.1/32", "192.0.2.50/32"})

    def test_drop_spool_flag_is_set_before_the_flip(self):
        flag = os.path.join(str(self.p.identity_dir), "drop-spool.flag")
        seen = []
        self.rehome(drop_spool=True, confirm=lambda *a: seen.append(os.path.exists(flag)) or "")
        self.assertEqual(seen, [True])

    def test_unconfirmed_rehome_rolls_back_to_the_old_hub(self):
        original_dropin = self.dropin()
        rc = self.rehome(confirm=lambda name, since, timeout: "no accepted heartbeat")
        self.assertEqual(rc, 4)
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")
        self.assertEqual(idn.gen_numbers(self.p), [1])                      # gen-2 deleted
        self.assertEqual(self.dropin(), original_dropin)                    # the saved drop-in is back
        self.assertEqual(idn.read_host_id(self.p), self.old.uuid)
        self.assertEqual(self.old.deregistered, [])                         # the old hub was never told
        self.assertFalse(os.path.exists(os.path.join(str(self.p.identity_dir), "rehome.json")))
        self.assertTrue(any("no accepted heartbeat" in m for m in self.logs))
        self.assertTrue(any(c[:2] == ["systemctl", "restart"] for c in self.ops.calls))

    def test_failure_in_the_network_part_changes_nothing(self):
        before = self.dropin()
        for tweak, code in ((lambda rep: rep.update(port=1), 3), (lambda rep: rep.update(host_uuid="x"), 3)):
            self.hubs.enroll_tweak = tweak
            self.assertEqual(self.rehome(), code)
            self.assertEqual(idn.gen_numbers(self.p), [1])
            self.assertEqual(idn.current_gen_name(self.p), "gen-1")
            self.assertEqual(self.dropin(), before)
            self.assertFalse([c for c in self.ops.calls if c[0] == "systemd-run"])      # no timer yet
        self.hubs.enroll_tweak = None
        self.assertEqual(self.rehome(token="tok12345.secretsecret1234." + "0" * 64), 2)  # a CA that does not match: any other failure
        self.assertEqual(idn.gen_numbers(self.p), [1])

    def test_refused_before_anything_changed(self):
        self.assertEqual(self.rehome(token="junk"), 3)
        self.assertEqual(self.rehome(droplet_id=""), 3)
        sp.atomic_write(os.path.join(str(self.p.identity_dir), "rehome.json"), "{}", 0o600)
        self.assertEqual(self.rehome(), 3)                                      # one already in progress
        os.unlink(os.path.join(str(self.p.identity_dir), "rehome.json"))
        shutil.rmtree(str(self.p.identity_dir))
        self.assertEqual(self.rehome(), 3)                                      # not enrolled
        self.assertEqual(self.hubs.enroll.requests, [])

    def test_exception_after_the_timer_is_armed_rolls_back(self):
        class Boom(idn.SystemOps):
            def restart_agent(self):
                raise RuntimeError("restart failed")
        self.ops = Boom(self.p)
        rc = self.rehome()
        self.assertEqual(rc, 4)
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")
        self.assertEqual(idn.gen_numbers(self.p), [1])

    def test_step_7_failure_leaves_the_move_standing_and_the_next_run_finishes(self):
        calls = {"n": 0}
        real = idn.deregister

        def broken(*a, **kw):
            calls["n"] += 1
            raise RuntimeError("cleanup crashed")
        idn.deregister = broken
        try:
            with self.assertRaises(RuntimeError):
                self.rehome()
        finally:
            idn.deregister = real
        st = idn.load_rehome_state(self.p)
        self.assertEqual(st["step"], 7)
        self.assertEqual(idn.current_gen_name(self.p), "gen-2")
        self.assertEqual(idn.gen_numbers(self.p), [1, 2])
        # `rehome --rollback` after step 7 does not undo the move: it finishes the cleanup
        rc = idn.rollback(self.p, self.ops, log=self.logs.append)
        self.assertEqual(rc, 0)
        self.assertEqual(idn.current_gen_name(self.p), "gen-2")
        self.assertEqual(idn.gen_numbers(self.p), [2])
        self.assertEqual(idn.read_host_id(self.p), self.hubs.uuid)


class TestRollbackAtEveryStep(RehomeCase):
    """Kill the move at each step (state left on disk), then run `rehome --rollback`."""

    def stage(self, step):
        n, csr = idn.new_generation(self.p, self.ops)
        d = idn.gen_path(self.p, n)
        idn.write_hub_conf(os.path.join(d, "hub.conf"), ["127.0.0.1"], 9999, 8444, "22222222-2222-4222-8222-222222222222", "0" * 64)
        saved = slurp(self.ops.dropin_path)
        st = {"v": 1, "step": step, "prev": "gen-1", "new": "gen-2", "old_addresses": ["127.0.0.1"], "new_addresses": ["192.0.2.9"],
              "new_host_uuid": "22222222-2222-4222-8222-222222222222", "old_host_uuid": self.old.uuid, "had_dropin": True,
              "armed_at": 1, "droplet_id": "424242"}
        sp.atomic_write(os.path.join(str(self.p.identity_dir), "rehome-dropin.saved"), saved, 0o600)
        sp.atomic_write(os.path.join(str(self.p.identity_dir), "rehome.json"), json.dumps(st), 0o600)
        if step >= 4:
            self.ops.write_dropin(["127.0.0.1", "192.0.2.9"])
        if step >= 5:
            idn.flip_current(self.p, "gen-2")
        return saved

    def test_steps_3_to_6(self):
        for step in (3, 4, 5, 6):
            with self.subTest(step=step):
                shutil.rmtree(str(self.p.identity_dir), ignore_errors=True)
                support.make_identity(self.env, self.old.pki, self.old.fleet_port, cn=self.old.uuid)
                self.ops.write_dropin(["127.0.0.1"])
                self.ops.calls.clear()
                saved = self.stage(step)
                rc = idn.rollback(self.p, self.ops, log=self.logs.append)
                self.assertEqual(rc, 4)
                self.assertEqual(idn.current_gen_name(self.p), "gen-1")
                self.assertEqual(idn.gen_numbers(self.p), [1])
                self.assertEqual(self.dropin(), saved)
                self.assertFalse(os.path.exists(os.path.join(str(self.p.identity_dir), "rehome.json")))
                restarted = any(c[:2] == ["systemctl", "restart"] for c in self.ops.calls)
                self.assertEqual(restarted, step >= 5)
                reloaded = any(c[:2] == ["systemctl", "daemon-reload"] for c in self.ops.calls)
                self.assertEqual(reloaded, step >= 4)
                self.assertEqual(idn.rollback(self.p, self.ops), 0)             # idempotent: nothing left to undo

    def test_no_rehome_pending_is_not_an_error(self):
        self.assertEqual(idn.rollback(self.p, self.ops), 0)
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")

    def test_garbage_state_file_is_removed(self):
        sp.atomic_write(os.path.join(str(self.p.identity_dir), "rehome.json"), "not json", 0o600)
        self.assertEqual(idn.rollback(self.p, self.ops), 0)
        self.assertFalse(idn.rehome_in_progress(self.p))

    def test_rollback_without_a_saved_dropin_rebuilds_it_from_the_old_addresses(self):
        saved = self.stage(5)
        os.unlink(os.path.join(str(self.p.identity_dir), "rehome-dropin.saved"))
        st = idn.load_rehome_state(self.p)
        st["had_dropin"] = False
        sp.atomic_write(os.path.join(str(self.p.identity_dir), "rehome.json"), json.dumps(st), 0o600)
        self.assertEqual(idn.rollback(self.p, self.ops), 4)
        self.assertEqual(self.dropin(), saved)


class TestSystemOps(unittest.TestCase):
    def test_dev_run_executes_nothing_and_writes_under_the_root(self):
        env = support.Env()
        self.addCleanup(env.cleanup)
        ops = idn.SystemOps(env.paths)
        self.assertTrue(ops.dev)
        real = subprocess.run
        subprocess.run = lambda *a, **k: (_ for _ in ()).throw(AssertionError("a command was run"))
        try:
            ops.daemon_reload()
            ops.restart_agent()
            ops.arm_rollback_timer("/lib/x")
            ops.disarm_rollback_timer()
            ops.start_pause_consumers()
            ops.arm_pause_timer("/lib/x", 60)
            ops.cancel_pause_timer()
        finally:
            subprocess.run = real
        self.assertTrue(ops.dropin_path.startswith(env.root))
        ops.write_dropin(["192.0.2.1", "2001:db8::1"])
        self.assertEqual(slurp(ops.dropin_path), "[Service]\nIPAddressAllow=\nIPAddressAllow=192.0.2.1 2001:db8::1\n")
        self.assertGreaterEqual(len(ops.calls), 7)

    def test_sandbox_command_reaches_one_hub_address_only(self):
        cmd = idn.sandbox_command("203.0.113.5", "/usr/local/lib/edr-agent")
        self.assertEqual(cmd[0], "systemd-run")
        for want in ("--pipe", "--wait", "User=edr-agent", "IPAddressDeny=any", "IPAddressAllow=203.0.113.5"):
            self.assertIn(want, cmd)
        self.assertEqual(cmd[-3:], ["-I", "/usr/local/lib/edr-agent/edr-agent.py", "hub-net"])
        self.assertNotIn("tok", " ".join(cmd))

    def test_sandboxed_run_feeds_the_token_on_stdin_and_parses_the_answer(self):
        seen = {}

        class R:
            returncode = 0
            stdout = b'noise\n{"ok": true, "reply": {"host_uuid": "x"}}\n'
            stderr = b""

        def runner(cmd, **kw):
            seen["cmd"], seen["input"] = cmd, kw["input"]
            return R()
        out = idn.run_net_phase_sandboxed({"hub": "203.0.113.5", "port": 8443}, "tokentokentoken", "/lib", runner=runner)
        self.assertEqual(out, {"host_uuid": "x"})
        self.assertIn(b"tokentokentoken", seen["input"])
        self.assertNotIn("tokentokentoken", " ".join(seen["cmd"]))

        class Bad(R):
            stdout = b'{"ok": false, "code": 3, "error": "refused by the hub"}\n'
        with self.assertRaises(idn.IdentityError) as cm:
            idn.run_net_phase_sandboxed({"hub": "203.0.113.5"}, "t", "/lib", runner=lambda c, **k: Bad())
        self.assertEqual(cm.exception.code, 3)

        class Empty(R):
            stdout = b""
        with self.assertRaises(idn.IdentityError):
            idn.run_net_phase_sandboxed({"hub": "203.0.113.5"}, "t", "/lib", runner=lambda c, **k: Empty())


class TestConfirm(IdentityCase):
    def test_default_confirm_needs_both_on_the_new_generation(self):
        p = os.path.join(str(self.p.run_dir), "uplink.json")
        now = time.time()
        sleeps = []

        def write(doc):
            sp.atomic_write(p, json.dumps(doc), 0o644)
        write({"gen": "gen-2", "hb_gen": "gen-2", "last_heartbeat_ok": now + 5, "policy_gen": "gen-1", "last_policy_ok": now + 5})
        t = {"v": now}
        why = idn.default_confirm(self.p, "gen-2", now, 0.1, sleep=lambda s: sleeps.append(s), clock=lambda: t.__setitem__("v", t["v"] + 0.1) or t["v"])
        self.assertEqual(why, "no successful policy poll")
        write({"gen": "gen-2", "hb_gen": "gen-2", "last_heartbeat_ok": now - 5, "policy_gen": "gen-2", "last_policy_ok": now + 5})
        self.assertEqual(idn.default_confirm(self.p, "gen-2", now, 0.1, sleep=lambda s: None,
                                             clock=lambda: t.__setitem__("v", t["v"] + 0.1) or t["v"]), "no accepted heartbeat")
        write({"gen": "gen-1"})
        self.assertIn("still uses", idn.default_confirm(self.p, "gen-2", now, 0.1, sleep=lambda s: None,
                                                        clock=lambda: t.__setitem__("v", t["v"] + 0.1) or t["v"]))
        write({"gen": "gen-2", "hb_gen": "gen-2", "last_heartbeat_ok": now + 5, "policy_gen": "gen-2", "last_policy_ok": now + 6})
        self.assertEqual(idn.default_confirm(self.p, "gen-2", now, 1, sleep=lambda s: None), "")
        os.unlink(p)
        self.assertEqual(idn.default_confirm(self.p, "gen-2", now, 0.1, sleep=lambda s: None,
                                             clock=lambda: t.__setitem__("v", t["v"] + 0.1) or t["v"]), "no report from the agent")


if __name__ == "__main__":
    unittest.main()
