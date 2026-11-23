"""X.509 profiles and the signing procedure (PLAN.md section 2, CA and certificates; section 12 L0 rows
"X.509 profiles" and "Tokens and enrollment" for the CSR rules). Uses the real openssl CLI."""

import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_ingest_fixture as F  # noqa: E402  (also puts the hub directory on sys.path)

import hub_common  # noqa: E402
import hub_pki  # noqa: E402

UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def text_of(pem):
    return F.openssl("x509", "-noout", "-text", stdin=pem.encode() if isinstance(pem, str) else pem).decode()


class PkiBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="edr-pki-test-", dir=F.SCRATCH)
        cls.paths = hub_common.Paths(state_dir=os.path.join(cls.tmp, "state"), run_dir=os.path.join(cls.tmp, "run"),
                                     etc_dir=os.path.join(cls.tmp, "etc"))
        os.makedirs(cls.paths.state_dir)
        hub_pki.init_ca(cls.paths)
        cls.pki = hub_pki.Pki(cls.paths)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def csr(self, **kw):
        return F.make_key_and_csr(self.tmp, **kw)


class CaProfileTest(PkiBase):
    def test_ca_profile(self):
        t = text_of(self.pki.ca_pem())
        self.assertIn("Public-Key: (384 bit)", t)
        self.assertIn("ecdsa-with-SHA384", t)
        self.assertRegex(t, r"Basic Constraints: critical\s+CA:TRUE, pathlen:0")
        self.assertRegex(t, r"Key Usage: critical\s+Certificate Sign, CRL Sign")
        self.assertNotIn("Extended Key Usage", t)
        self.assertIn("Subject Key Identifier", t)
        self.assertIn("Authority Key Identifier", t)
        info = self.pki.cert_info(self.paths.ca_cert)
        years = (info["not_after"] - info["not_before"]) / 1000 / 86400 / 365.25
        self.assertTrue(9.9 < years < 10.1, years)
        self.assertEqual(info["subject_cn"], "edr-hub-ca")

    def test_ca_verifies_strict_and_files_are_private(self):
        out = subprocess.run(["openssl", "verify", "-x509_strict", "-no-CApath", "-no-CAstore", "-CAfile",
                              self.paths.ca_cert, self.paths.ca_cert], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(os.stat(self.paths.ca_key).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.paths.ca_dir).st_mode & 0o777, 0o700)

    def test_init_ca_is_idempotent_and_never_replaces(self):
        before = self.pki.ca_sha256()
        hub_pki.init_ca(self.paths)
        self.assertEqual(hub_pki.Pki(self.paths).ca_sha256(), before)
        self.assertEqual(len(before), 64)

    def test_half_a_ca_is_refused(self):
        d = tempfile.mkdtemp(dir=self.tmp)
        p = hub_common.Paths(state_dir=d, run_dir=d, etc_dir=d)
        os.makedirs(p.ca_dir)
        open(p.ca_key, "w").close()
        with self.assertRaises(ValueError):
            hub_pki.init_ca(p)

    def test_ca_sha256_is_der_hash(self):
        der = ssl.PEM_cert_to_DER_cert(self.pki.ca_pem())
        import hashlib
        self.assertEqual(self.pki.ca_sha256(), hashlib.sha256(der).hexdigest())


class ClientCertTest(PkiBase):
    def test_client_certificate_profile(self):
        key, csr = self.csr(subject="/CN=attacker/O=evil")
        res = self.pki.sign_client(csr, UUID)
        t = text_of(res["pem"])
        self.assertRegex(t, r"Subject: CN\s*=\s*" + UUID + r"\n")
        self.assertRegex(t, r"Basic Constraints: critical\s+CA:FALSE")
        self.assertRegex(t, r"Key Usage: critical\s+Digital Signature")
        self.assertRegex(t, r"Extended Key Usage:\s+TLS Web Client Authentication\s*\n")
        self.assertNotIn("Subject Alternative Name", t)
        self.assertIn("Subject Key Identifier", t)
        self.assertIn("Authority Key Identifier", t)
        self.assertIn("ecdsa-with-SHA384", t)
        self.assertIn("ASN1 OID: prime256v1", t)

    def test_lifetime_and_backdating(self):
        _k, csr = self.csr()
        res = self.pki.sign_client(csr, UUID)
        info = self.pki.cert_info(res["pem"])
        now = hub_common.now_ms()
        self.assertAlmostEqual((now - info["not_before"]) / 86400000, 1.0, delta=0.01)
        self.assertAlmostEqual((info["not_after"] - now) / 86400000, 365, delta=0.01)
        self.assertEqual(res["not_after"], info["not_after"])

    def test_serial_is_15_random_bytes_with_top_bit_clear(self):
        seen = set()
        _k, csr = self.csr()
        for _ in range(4):
            res = self.pki.sign_client(csr, UUID)
            raw = bytes.fromhex(res["serial"].rjust(30, "0"))
            self.assertEqual(len(raw), 15)
            self.assertLess(raw[0], 0x80)
            seen.add(res["serial"])
        self.assertEqual(len(seen), 4)

    def test_csr_subject_and_extensions_are_ignored(self):
        key = os.path.join(self.tmp, "ext.key")
        with open(key, "wb") as f:
            f.write(F.openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout"))
        cnf = os.path.join(self.tmp, "evil.cnf")
        with open(cnf, "w") as f:
            f.write("[req]\ndistinguished_name=dn\nreq_extensions=x\nprompt=no\n[dn]\nCN=root\n[x]\n"
                    "basicConstraints=critical,CA:TRUE\nsubjectAltName=DNS:evil.example,IP:10.0.0.1\n"
                    "extendedKeyUsage=serverAuth\n")
        csr = F.openssl("req", "-new", "-key", key, "-config", cnf).decode()
        self.assertIn("CA:TRUE", F.openssl("req", "-noout", "-text", stdin=csr.encode()).decode())
        res = self.pki.sign_client(csr, UUID)
        t = text_of(res["pem"])
        self.assertNotIn("CA:TRUE", t)
        self.assertNotIn("evil.example", t)
        self.assertNotIn("TLS Web Server", t)
        self.assertRegex(t, r"Subject: CN\s*=\s*" + UUID)

    def test_verify_x509_strict_with_client_purpose(self):
        _k, csr = self.csr()
        res = self.pki.sign_client(csr, UUID)
        path = os.path.join(self.tmp, "c.pem")
        with open(path, "w") as f:
            f.write(res["pem"])
        for purpose, want_ok in (("sslclient", True), ("sslserver", False)):
            out = subprocess.run(["openssl", "verify", "-x509_strict", "-no-CApath", "-no-CAstore", "-CAfile",
                                  self.paths.ca_cert, "-purpose", purpose, path], capture_output=True, text=True)
            self.assertEqual(out.returncode == 0, want_ok, out.stdout + out.stderr)

    def test_fallback_signing_through_openssl_ca(self):
        """openssl 3.0 has no `x509 -not_before`: the same profile is issued through `openssl ca -startdate`."""
        _k, csr = self.csr()
        saved = dict(hub_pki._not_before_support)
        hub_pki._not_before_support[hub_pki.OPENSSL] = False
        try:
            res = self.pki.sign_client(csr, UUID)
        finally:
            hub_pki._not_before_support.clear()
            hub_pki._not_before_support.update(saved)
        info = self.pki.cert_info(res["pem"])
        self.assertAlmostEqual((hub_common.now_ms() - info["not_before"]) / 86400000, 1.0, delta=0.01)
        t = text_of(res["pem"])
        self.assertRegex(t, r"Extended Key Usage:\s+TLS Web Client Authentication")
        self.assertRegex(t, r"Basic Constraints: critical\s+CA:FALSE")
        self.assertRegex(t, r"Subject: CN\s*=\s*" + UUID)

    def test_csr_rules(self):
        _k, good = self.csr()
        # not EC prime256v1
        _k, p384 = self.csr(curve="secp384r1")
        with self.assertRaises(ValueError):
            self.pki.sign_client(p384, UUID)
        rsa_key = os.path.join(self.tmp, "rsa.key")
        F.openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", rsa_key)
        rsa_csr = F.openssl("req", "-new", "-key", rsa_key, "-subj", "/CN=x").decode()
        with self.assertRaises(ValueError):
            self.pki.sign_client(rsa_csr, UUID)
        # two blocks, oversize, garbage, wrong type of request
        with self.assertRaises(ValueError):
            self.pki.sign_client(good + good, UUID)
        with self.assertRaises(ValueError):
            self.pki.sign_client(good.replace("-----END CERTIFICATE REQUEST-----", "A" * 5000 +
                                              "\n-----END CERTIFICATE REQUEST-----"), UUID)
        for bad in ("", "not a csr", "-----BEGIN CERTIFICATE REQUEST-----\n!!!\n-----END CERTIFICATE REQUEST-----\n", None, 5):
            with self.assertRaises(ValueError):
                self.pki.sign_client(bad, UUID)
        # no proof of key possession: tamper with the signature
        lines = good.splitlines()
        body = lines[1:-1]
        flipped = body[-1][:-6] + ("A" if body[-1][-6] != "A" else "B") + body[-1][-5:]
        tampered = "\n".join([lines[0]] + body[:-1] + [flipped, lines[-1]]) + "\n"
        with self.assertRaises(ValueError):
            self.pki.sign_client(tampered, UUID)
        # a bad uuid is refused before openssl runs
        for bad_uuid in ("", "../x", "CN=x", UUID.upper(), UUID + "/CN=root"):
            with self.assertRaises(ValueError):
                self.pki.sign_client(good, bad_uuid)

    def test_messages_do_not_echo_the_csr(self):
        try:
            self.pki.sign_client("-----BEGIN CERTIFICATE REQUEST-----\nSECRET123\n-----END CERTIFICATE REQUEST-----\n", UUID)
        except ValueError as e:
            self.assertNotIn("SECRET123", str(e))
        else:
            self.fail("accepted garbage")


class ServerCertTest(PkiBase):
    def test_server_certificate_profile_and_sans(self):
        self.pki.issue_server_cert(["127.0.0.1", "10.1.2.3", "2001:db8::5"])
        with open(self.paths.server_cert) as f:
            t = text_of(f.read())
        self.assertRegex(t, r"Basic Constraints: critical\s+CA:FALSE")
        self.assertRegex(t, r"Key Usage: critical\s+Digital Signature")
        self.assertRegex(t, r"Extended Key Usage:\s+TLS Web Server Authentication\s*\n")
        self.assertIn("IP Address:127.0.0.1", t)
        self.assertIn("IP Address:10.1.2.3", t)
        self.assertNotIn("DNS:", t)
        info = self.pki.cert_info(self.paths.server_cert)
        self.assertEqual(sorted(info["sans"]), sorted(["127.0.0.1", "10.1.2.3", "2001:db8::5"]))
        self.assertAlmostEqual((info["not_after"] - hub_common.now_ms()) / 86400000, 397, delta=0.01)
        self.assertAlmostEqual((hub_common.now_ms() - info["not_before"]) / 86400000, 1.0, delta=0.01)
        self.assertEqual(os.stat(self.paths.server_key).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.paths.tls_dir).st_mode & 0o777, 0o700)
        out = subprocess.run(["openssl", "verify", "-x509_strict", "-no-CApath", "-no-CAstore", "-CAfile",
                              self.paths.ca_cert, "-purpose", "sslserver", self.paths.server_cert],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_needs_an_address(self):
        with self.assertRaises(ValueError):
            self.pki.issue_server_cert([])
        with self.assertRaises(ValueError):
            self.pki.issue_server_cert(["not-an-ip"])

    def test_server_cert_state(self):
        d = tempfile.mkdtemp(dir=self.tmp)
        p = hub_common.Paths(state_dir=d, run_dir=d, etc_dir=d)
        hub_pki.init_ca(p)
        pki = hub_pki.Pki(p)
        self.assertEqual(pki.server_cert_state(["127.0.0.1"]), "missing")
        pki.issue_server_cert(["127.0.0.1"])
        self.assertEqual(pki.server_cert_state(["127.0.0.1"]), "ok")
        self.assertEqual(pki.server_cert_state(["127.0.0.1", "10.0.0.1"]), "addresses")


class HandshakeTest(PkiBase):
    """A TLS 1.3 mutual handshake with both certificate types (section 12: X.509 profiles)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.pki.issue_server_cert(["127.0.0.1"])
        cls.client_key, csr = F.make_key_and_csr(cls.tmp)
        cls.client_pem = cls.pki.sign_client(csr, UUID)["pem"]
        cls.client_path = os.path.join(cls.tmp, "client.pem")
        with open(cls.client_path, "w") as f:
            f.write(cls.client_pem)

    def server_ctx(self, ca=None):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.verify_flags |= ssl.VERIFY_X509_STRICT
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=ca or self.paths.ca_cert)
        ctx.load_cert_chain(self.paths.server_cert, self.paths.server_key)
        return ctx

    def client_ctx(self, cert=None, key=None, ca=None):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.verify_flags |= ssl.VERIFY_X509_STRICT
        ctx.check_hostname = True
        ctx.load_verify_locations(cafile=ca or self.paths.ca_cert)
        ctx.load_cert_chain(cert or self.client_path, key or self.client_key)
        return ctx

    def handshake(self, sctx, cctx):
        """Returns (server saw cert subject or error, client result)."""
        lsock = socket.socket()
        lsock.bind(("127.0.0.1", 0))
        lsock.listen(1)
        port = lsock.getsockname()[1]
        out = {}

        def serve():
            conn, _ = lsock.accept()
            try:
                with sctx.wrap_socket(conn, server_side=True) as s:
                    out["peer"] = s.getpeercert()
                    out["version"] = s.version()
                    s.recv(1)
                    s.sendall(b"k")
            except (ssl.SSLError, OSError) as e:
                out["err"] = e
        th = threading.Thread(target=serve)
        th.start()
        client_err = None
        try:
            raw = socket.create_connection(("127.0.0.1", port), timeout=5)
            with cctx.wrap_socket(raw, server_hostname="127.0.0.1") as c:
                c.sendall(b"x")
                c.recv(1)
        except (ssl.SSLError, OSError) as e:
            client_err = e
        th.join(10)
        lsock.close()
        return out, client_err

    def test_mutual_tls13_with_our_certificates(self):
        out, cerr = self.handshake(self.server_ctx(), self.client_ctx())
        self.assertIsNone(cerr)
        self.assertEqual(out["version"], "TLSv1.3")
        cn = dict(x[0] for x in out["peer"]["subject"])["commonName"]
        self.assertEqual(cn, UUID)

    def test_certificate_from_another_ca_fails_the_handshake(self):
        d = tempfile.mkdtemp(dir=self.tmp)
        p = hub_common.Paths(state_dir=d, run_dir=d, etc_dir=d)
        hub_pki.init_ca(p)
        other = hub_pki.Pki(p)
        key, csr = F.make_key_and_csr(d)
        pem = other.sign_client(csr, UUID)["pem"]
        path = os.path.join(d, "other.pem")
        with open(path, "w") as f:
            f.write(pem)
        out, cerr = self.handshake(self.server_ctx(), self.client_ctx(cert=path, key=key))
        self.assertTrue("err" in out or cerr is not None)
        self.assertNotIn("peer", out)

    def test_server_only_certificate_is_not_a_client_certificate(self):
        """A server-profile certificate (EKU serverAuth) presented as a client certificate is refused."""
        out, cerr = self.handshake(self.server_ctx(), self.client_ctx(cert=self.paths.server_cert, key=self.paths.server_key))
        self.assertTrue("err" in out or cerr is not None)
        self.assertNotIn("peer", out)

    def test_ca_without_key_usage_is_refused_by_the_strict_check(self):
        d = tempfile.mkdtemp(dir=self.tmp)
        ca_key, ca_pem = os.path.join(d, "ca.key"), os.path.join(d, "ca.pem")
        F.openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", ca_key)
        subprocess.run(["openssl", "req", "-x509", "-new", "-key", ca_key, "-subj", "/CN=plain", "-days", "30", "-out", ca_pem],
                       check=True, capture_output=True, env={"PATH": os.environ["PATH"], "OPENSSL_CONF": "/dev/null"})
        leaf = os.path.join(d, "leaf.pem")
        key, csr = F.make_key_and_csr(d)
        pub = F.openssl("req", "-noout", "-pubkey", stdin=csr.encode())
        with open(os.path.join(d, "pub.pem"), "wb") as f:
            f.write(pub)
        ext = os.path.join(d, "x.cnf")
        with open(ext, "w") as f:
            f.write("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n")
        F.openssl("x509", "-new", "-force_pubkey", os.path.join(d, "pub.pem"), "-subj", "/CN=leaf", "-CA", ca_pem, "-CAkey",
                  ca_key, "-extfile", ext, "-days", "30", "-out", leaf)
        out = subprocess.run(["openssl", "verify", "-x509_strict", "-no-CApath", "-no-CAstore", "-CAfile", ca_pem, leaf],
                             capture_output=True, text=True)
        self.assertNotEqual(out.returncode, 0)


class RevokedFileTest(PkiBase):
    def test_append_load_and_first_reason_stays(self):
        d = tempfile.mkdtemp(dir=self.tmp)
        p = hub_common.Paths(state_dir=d, run_dir=d, etc_dir=d)
        hub_pki.init_ca(p)
        pki = hub_pki.Pki(p)
        h1, h2 = "a" * 64, "b" * 64
        self.assertIsNone(pki.revoked_lookup(h1))
        self.assertTrue(pki.revoked_add("0A1B", h1, UUID, "revoked", 1000))
        self.assertFalse(pki.revoked_add("0A1B", h1, UUID, "superseded", 2000))
        self.assertTrue(pki.revoked_add("ff", h2, UUID, "superseded", 3000))
        self.assertEqual(pki.revoked_lookup(h1), ("a1b", UUID, "revoked"))
        with open(p.revoked) as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], "a1b %s %s revoked 1000" % (h1, UUID))
        self.assertEqual(os.stat(p.revoked).st_mode & 0o777, 0o600)
        again = hub_pki.Pki(p)                      # loaded first thing at start
        self.assertEqual(again.revoked_lookup(h2)[2], "superseded")
        self.assertEqual(again.revoked_count(), 2)
        with self.assertRaises(ValueError):
            pki.revoked_add("1", h1, UUID, "bogus")

    def test_garbage_lines_are_ignored(self):
        d = tempfile.mkdtemp(dir=self.tmp)
        p = hub_common.Paths(state_dir=d, run_dir=d, etc_dir=d)
        hub_pki.init_ca(p)
        with open(p.revoked, "w") as f:
            f.write("junk\n\n1 short x y 1\n" + "1 %s %s moved 5\n" % ("c" * 64, UUID))
        self.assertEqual(hub_pki.Pki(p).revoked_count(), 1)


if __name__ == "__main__":
    unittest.main()
