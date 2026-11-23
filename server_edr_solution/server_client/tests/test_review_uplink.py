"""Security review of the agent's hub side and of the ban decisions.
Each test pins a defect the review found and that has since been fixed, or a guard that holds."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_daemon_support import Tmp, cfgmod                              # noqa: E402
from edragent import identity as idn, policy, sources as src, transport as tr      # noqa: E402
from edragent.sources import nginx                                        # noqa: E402

FORGED = "198.51.100.8"
REAL = "203.0.113.9"


class FakeOps:
    """Records what root would write; stands in for identity.SystemOps."""

    def __init__(self):
        self.dropins = []
        self.calls = []

    def write_dropin(self, addresses):
        self.dropins.append(list(addresses))

    def restore_dropin(self, text, fallback_addresses=()):
        self.dropins.append(list(fallback_addresses))

    def daemon_reload(self):
        self.calls.append("daemon-reload")

    def restart_agent(self):
        self.calls.append("restart")

    def disarm_rollback_timer(self):
        self.calls.append("disarm")

    def chown_agent(self, path):
        pass


class TestErrorLogForgery(Tmp):
    """A web user turns an unescaped nginx error line into a ban of an address of their choice."""

    def source(self):
        cfg = cfgmod.load(self.paths)
        ctx = src.Context(cfg, self.paths, self.clock)
        s = nginx.ErrorLogSource(ctx, "begin")
        self.addCleanup(s.close)
        return s

    def test_two_injected_newlines_and_a_fake_record_start_attribute_the_victims_address(self):
        wu = '*1 client violated connection flow control: received WINDOW_UPDATE frame with window increment "1"'
        lines = [
            "2026/11/19 10:15:02 [error] 1000#1000: *5 open() \"/var/www/x",                                  # the real line, cut by the first %0a
            "2026/11/19 10:15:02 [info] 1000#1000: %s, client: %s, server: victim.test" % (wu, FORGED),     # forged: one trailer
            "2026/11/19 10:15:02 [info] 1000#1000: *1 y\" failed (2: No such file), client: %s, server: real.test, request: \"GET / HTTP/1.1\"" % REAL,
        ]
        s = self.source()
        events = s.process_lines(lines, self.clock()) + s.finish()
        forged = [e for e in events if e["kind"] == "nginx.marker.window_update"]
        self.assertTrue(forged)
        for e in forged:
            self.assertNotEqual((e["src_ip"], e["src_trust"]), (FORGED, "tcp"), "an address the web user wrote became ban evidence")

    def test_one_injected_newline_is_caught(self):
        wu = '*1 client violated connection flow control: received WINDOW_UPDATE frame with window increment "1"'
        lines = ["2026/11/19 10:15:02 [error] 1000#1000: *5 open() \"/var/www/x",
                 "2026/11/19 10:15:02 [info] 1000#1000: %s, client: %s, server: victim.test" % (wu, FORGED),
                 "rest\" failed (2: No such file), client: %s, server: real.test" % REAL]
        s = self.source()
        events = s.process_lines(lines, self.clock()) + s.finish()
        self.assertTrue(all(e["src_ip"] == "" for e in events if e["kind"] == "nginx.marker.window_update"))


class TestRootTrustsAgentOwnedFiles(Tmp):
    """identity/ belongs to the agent (chown_agent), and root reads hub addresses out of it for the unit drop-in."""

    def gens(self, new_addresses, prev_addresses=("203.0.113.4",)):
        for n, addrs in ((1, prev_addresses), (2, new_addresses)):
            d = os.path.join(self.paths.identity_dir, "gen-%d" % n)
            os.makedirs(d)
            self.write(os.path.join(d, "hub.conf"), "[hub]\naddresses = %s\nport = 8443\nenroll_port = 8444\nhost_uuid = %s\nca_sha256 = %s\n"
                       % (",".join(addrs), "11111111-1111-4111-8111-111111111111", "a" * 64))
            for f in ("ca.pem", "client.pem", "client.key"):
                self.write(os.path.join(d, f), "x")

    def test_root_writes_the_validated_addresses_not_whatever_the_agents_hub_conf_says_later(self):
        self.gens(new_addresses=["198.51.100.66"])                                  # the agent edited it after root validated 203.0.113.5
        ops = FakeOps()
        st = {"new": "gen-2", "prev": "gen-1", "new_addresses": ["203.0.113.5"], "new_host_uuid": None, "droplet_id": None, "deregistered": True,
              "step": 6}
        idn.finish_commit(self.paths, ops, st)
        written = [a for d in ops.dropins for a in d]
        self.assertNotIn("198.51.100.66", written)

    def test_chown_agent_works_on_a_single_file(self):
        f = self.write(os.path.join(self.paths.state_dir, "ban-state.json"), "{}")
        calls = []
        pw = mock.Mock(pw_uid=4242)
        gr = mock.Mock(gr_gid=4242)
        with mock.patch("os.geteuid", return_value=0), mock.patch("pwd.getpwnam", return_value=pw), mock.patch("grp.getgrnam", return_value=gr), \
                mock.patch("os.chown", side_effect=lambda *a, **k: calls.append(a)):
            idn.SystemOps(self.paths, dev=False).chown_agent(f)
        self.assertTrue(any(a[0] == f for a in calls), "root left the file it wrote as root")


class TestHubTrustHolds(Tmp):
    """No finding: a hostile hub gets no more than peers and its own addresses into the client."""

    def test_the_policy_reply_is_validated_and_only_peers_and_addresses_survive(self):
        doc = {"rev": "0123456789abcdef", "hub_time": 1795000000, "hub_addresses": ["203.0.113.5", "../../etc/passwd"], "peers": ["198.51.100.1"],
               "bans": [], "feeds": {}}
        with self.assertRaises(policy.PolicyRefused):
            policy.validate(doc)
        doc["hub_addresses"] = ["203.0.113.5"]
        doc["peers"] = ["198.51.100.1", "10.0.0.0/8", "0.0.0.0/0", "::/0", "198.51.100.2/31", "x"]
        p = policy.validate(doc, 1795000000)
        self.assertEqual(p.peers, ["198.51.100.1"])                                   # a range is never a peer: never-ban cannot be widened
        self.assertEqual(p.never_doc(), {"peers": ["198.51.100.1"], "hub_addresses": ["203.0.113.5"]})
        doc["peers"] = ["198.51.100.%d" % (i % 250) for i in range(600)]
        with self.assertRaises(policy.PolicyRefused):
            policy.validate(doc, 1795000000)

    def test_certificate_checks_cannot_be_skipped_for_the_fleet_or_the_pinned_enroll_connection(self):
        import ssl
        ctx = tr.make_context(ca_path=None, verify=False)                               # only for GET /v1/ca
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_3)
        import subprocess
        ca = os.path.join(self.root, "ca.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout",
                        os.path.join(self.root, "ca.key"), "-out", ca, "-days", "2", "-subj", "/CN=ca"], check=True, capture_output=True)
        ctx = tr.make_context(ca_path=ca, verify=True)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertTrue(ctx.verify_flags & ssl.VERIFY_X509_STRICT)
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_3)

    def test_the_ca_fetched_without_verification_must_match_the_tokens_hash(self):
        class Reply:
            status = 200
            body = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        with self.assertRaises(idn.IdentityError):
            idn.fetch_ca("203.0.113.5", 8444, "0" * 64, requester=lambda *a, **k: Reply())

    def test_the_token_never_reaches_argv_or_the_enrollment_error_text(self):
        token = "tokenid1.s3cr3tsecretvalue.%s" % ("a" * 64)
        cmd = idn.sandbox_command("203.0.113.5", "/usr/local/lib/edr-agent")
        self.assertNotIn("s3cr3tsecretvalue", " ".join(cmd))

        def boom(params, tok):
            raise idn.IdentityError("the hub refused the token: make a new token", 2)
        os.makedirs(self.paths.identity_dir, exist_ok=True)
        with self.assertRaises(idn.IdentityError) as cm:
            idn.enroll(self.paths, hub="203.0.113.5", port=8443, enroll_port=8444, token=token, droplet_id="1234", hostname="h", os_name="x",
                       ips=[], ops=FakeOps(), net_runner=boom)
        self.assertNotIn("s3cr3tsecretvalue", str(cm.exception))

    def test_enroll_reply_cannot_point_the_agent_at_loopback_or_link_local_or_another_port(self):
        base = {"host_uuid": "11111111-1111-4111-8111-111111111111", "hub_addresses": ["203.0.113.5"], "port": 8443, "not_after": None, "state": "pending"}
        idn.validate_enroll_reply(base, hub_ip="203.0.113.5", fleet_port=8443)
        for field, value in (("hub_addresses", ["203.0.113.5", "169.254.169.254"]), ("hub_addresses", ["203.0.113.5", "127.0.0.1"]),
                             ("hub_addresses", ["198.51.100.1"]), ("port", 22), ("host_uuid", "../../x"), ("hub_addresses", ["203.0.113.5"] * 5)):
            with self.assertRaises(idn.IdentityError, msg=(field, value)):
                idn.validate_enroll_reply(dict(base, **{field: value}), hub_ip="203.0.113.5", fleet_port=8443)

    def test_reply_bounds(self):
        self.assertLessEqual(tr.MAX_BODY, 16 * 1024 * 1024)
        self.assertLessEqual(tr.MAX_HEADERS, 16 * 1024)


if __name__ == "__main__":
    unittest.main()
