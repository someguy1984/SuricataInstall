"""L0 tests of agent/edr-home-net, edr-droplet-id and edr-notify (client PLAN sections 4.1, 4.6, 4.7).
A fake metadata service and a fake webhook run on 127.0.0.1 at ports of 18000 and up."""

import http.server
import json
import subprocess
import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from test_helper_common import TmpCase, load_helper, run_helper  # noqa: E402

N = load_helper("edr-notify")
H = load_helper("edr-home-net")
NOW = 1795000000

IP_ADDR = """1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 203.0.113.10/20 brd 203.0.127.255 scope global eth0\\       valid_lft forever preferred_lft forever
2: eth0    inet 10.19.0.5/16 brd 10.19.255.255 scope global eth0\\       valid_lft forever preferred_lft forever
3: eth1    inet 10.116.0.2/20 brd 10.116.15.255 scope global eth1\\       valid_lft forever preferred_lft forever
2: eth0    inet6 2001:db8:1::5/64 scope global \\       valid_lft forever preferred_lft forever
2: eth0    inet6 fe80::1c2:3ff:fe4:5/64 scope link \\       valid_lft forever preferred_lft forever
1: lo    inet6 ::1/128 scope host \\       valid_lft forever preferred_lft forever
"""


def write_fx(case, fx):
    path = case.root + "/fx.json"
    with open(path, "w") as fh:
        json.dump(fx, fh)
    return path


class TestHomeNet(TmpCase):
    def run_hn(self, args=(), fx=None, extra_conf=None):
        if extra_conf is not None:
            self.put("/etc/edr-agent/local.conf", extra_conf)
        path = write_fx(self, fx if fx is not None else {"ip -o addr show": {"out": IP_ADDR}})
        return run_helper("edr-home-net", ["--root", self.root, "--exec-fixtures", path] + list(args))

    def test_each_address_is_exact_and_the_on_link_prefix_is_never_used(self):
        rc, out, err = self.run_hn(["--print"])
        self.assertEqual(rc, 0, err)
        nets = out.strip().split(",")
        self.assertIn("203.0.113.10/32", nets)
        self.assertIn("10.19.0.5/32", nets)
        self.assertIn("2001:db8:1::5/128", nets)
        self.assertIn("fe80::1c2:3ff:fe4:5/128", nets)
        self.assertIn("127.0.0.0/8", nets)
        self.assertIn("::1/128", nets)
        for net in nets:
            self.assertFalse(net.endswith("/64") or net.endswith("/20") or net.endswith("/16"), net)

    def test_vpc_cidr_and_extra_addresses_come_from_local_conf(self):
        rc, out, err = self.run_hn(["--print"], extra_conf="[sites]\nvpc_cidr = 10.116.0.0/20\nextra_addresses = 198.51.100.77, 2001:db8:2::9\n")
        nets = out.strip().split(",")
        self.assertIn("10.116.0.0/20", nets)
        self.assertIn("198.51.100.77/32", nets)
        self.assertIn("2001:db8:2::9/128", nets)

    def test_home_net_override_replaces_the_whole_value(self):
        rc, out, err = self.run_hn(["--print"], extra_conf="[suricata]\nhome_net = 192.0.2.0/24, 2001:db8:9::/48\n[sites]\nvpc_cidr = 10.116.0.0/20\n")
        self.assertEqual(out.strip(), "192.0.2.0/24,2001:db8:9::/48")
        rc, out, err = self.run_hn(["--print"], extra_conf="[suricata]\nhome_net = auto\n")
        self.assertIn("203.0.113.10/32", out)

    def test_invalid_entries_are_reported_and_skipped(self):
        rc, out, err = self.run_hn(["--print"], extra_conf="[sites]\nextra_addresses = 198.51.100.77, not-an-address\n")
        self.assertIn("198.51.100.77/32", out)
        self.assertIn("invalid", out + err)

    def test_files_are_written_check_detects_a_stale_value(self):
        rc, out, err = self.run_hn(["--no-reload"], extra_conf="[sites]\nvpc_cidr = 10.116.0.0/20\n")
        self.assertEqual(rc, 0, err)
        with open(self.root + "/etc/suricata/edr-home-net.yaml") as fh:
            text = fh.read()
        self.assertIn('vars.address-groups.HOME_NET: "[', text)
        # Never a nested mapping: Suricata empties a mapping an include names again, which left HOME_NET as the
        # only rule variable and failed the first install with Suricata (EXTERNAL_NET and HTTP_SERVERS undefined).
        self.assertFalse([ln for ln in text.splitlines() if ln.rstrip().endswith(":") and not ln.lstrip().startswith("#")])
        with open(self.root + "/etc/suricata/home-net.extra") as fh:
            self.assertIn("10.116.0.0/20", fh.read())
        self.assertEqual(self.run_hn(["--check"])[0], 0)
        fx = {"ip -o addr show": {"out": IP_ADDR + "2: eth0    inet 192.0.2.99/24 scope global eth0\\       valid_lft forever\n"}}
        self.assertEqual(self.run_hn(["--check"], fx=fx)[0], 1)
        import yaml  # PyYAML is required in CI
        d = yaml.safe_load(text)
        self.assertEqual(list(d), ["vars.address-groups.HOME_NET"])
        self.assertTrue(d["vars.address-groups.HOME_NET"].startswith("["))

    def test_a_failing_ip_command_is_reported_not_trusted(self):
        rc, out, err = self.run_hn(["--print"], fx={})
        self.assertIn("did not run", out + err)
        self.assertIn("127.0.0.0/8", out)

    def test_memory_guard(self):
        self.put("/proc/meminfo", "MemAvailable:    2000000 kB\n")
        self.put("/run/suricata.pid", "77\n")
        self.put("/proc/77/status", "VmRSS:\t  400000 kB\n")
        env = H.Env(self.root, dry=True)
        self.assertTrue(H.mem_guard(env))
        self.put("/proc/meminfo", "MemAvailable:     650000 kB\n")
        self.assertFalse(H.mem_guard(env))                        # under 700 MB
        self.put("/proc/meminfo", "MemAvailable:     900000 kB\n")
        self.put("/proc/77/status", "VmRSS:\t  900000 kB\n")
        self.assertFalse(H.mem_guard(env))                        # under 1.5 times the RSS


class Metadata(http.server.BaseHTTPRequestHandler):
    reply = (200, "12345678")

    def do_GET(self):
        code, body = type(self).reply
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


class TestDropletId(TmpCase):
    def setUp(self):
        super().setUp()
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), Metadata)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        Metadata.reply = (200, "12345678")

    def run_id(self, port=None):
        return run_helper("edr-droplet-id", ["--root", self.root, "--metadata", "127.0.0.1:%d" % (port or self.port), "--timeout", "1"])

    def out(self):
        with open(self.root + "/run/edr-droplet-id") as fh:
            return fh.read()

    def test_the_metadata_id_is_written_mode_0640(self):
        rc, out, err = self.run_id()
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.out(), "12345678\n")
        self.assertEqual(os.stat(self.root + "/run/edr-droplet-id").st_mode & 0o777, 0o640)

    def test_odd_answers_are_not_ids(self):
        for body in ("<html>proxy error</html>", "12 34", "x" * 40, "", "-5", "1" * 30):
            Metadata.reply = (200, body)
            self.run_id()
            self.assertFalse(os.path.exists(self.root + "/run/edr-droplet-id"), body)
        Metadata.reply = (404, "12345")
        self.run_id()
        self.assertFalse(os.path.exists(self.root + "/run/edr-droplet-id"))

    def test_silent_metadata_keeps_the_old_id_or_uses_the_stored_one(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
        s.close()
        self.run_id(dead)
        self.assertFalse(os.path.exists(self.root + "/run/edr-droplet-id"))      # nothing stored, nothing written
        self.put("/var/lib/edr-agent/droplet-id", "mock-droplet-1\n")
        self.run_id(dead)
        self.assertEqual(self.out(), "mock-droplet-1\n")                          # a host that is not a droplet
        self.put("/run/edr-droplet-id", "999\n")
        self.run_id(dead)
        self.assertEqual(self.out(), "999\n")                                     # fail open: the old id stays
        self.run_id()
        self.assertEqual(self.out(), "12345678\n")

    def test_it_writes_in_place_when_only_the_file_is_writable(self):
        # the unit binds the one file read-write: the .tmp and the rename are impossible there
        import test_helper_common as c
        d = c.load_helper("edr-droplet-id")
        self.put("/run/edr-droplet-id", "999\n", mode=0o640)
        target = self.root + "/run/edr-droplet-id"
        ino = os.stat(target).st_ino
        orig = d.atomic_write
        def refuse(*a, **k):
            raise OSError(30, "Read-only file system")
        d.atomic_write = refuse
        try:
            d.write_id(target, "12345678\n")
        finally:
            d.atomic_write = orig
        with open(target) as fh:
            self.assertEqual(fh.read(), "12345678\n")
        self.assertEqual(os.stat(target).st_ino, ino)
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o640)

    def test_a_bad_stored_value_is_ignored(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
        s.close()
        self.put("/var/lib/edr-agent/droplet-id", "bad id; rm -rf /\n")
        self.run_id(dead)
        self.assertFalse(os.path.exists(self.root + "/run/edr-droplet-id"))

    # --seed: the unit's first, unsandboxed run (found by the first reboot in the mock: the sandboxed run cannot
    # read the stored id in /var/lib/edr-agent, so /run/edr-droplet-id came back empty after a reboot).
    def seed(self):
        os.makedirs(self.root + "/run", exist_ok=True)
        return run_helper("edr-droplet-id", ["--root", self.root, "--seed"])

    def test_seed_makes_the_file_and_copies_the_stored_id(self):
        self.put("/var/lib/edr-agent/droplet-id", "mock-droplet-1\n")
        rc, out, err = self.seed()
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.out(), "mock-droplet-1\n")
        self.assertEqual(os.stat(self.root + "/run/edr-droplet-id").st_mode & 0o777, 0o640)

    def test_seed_with_nothing_stored_leaves_an_empty_file(self):
        rc, out, err = self.seed()
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.out(), "")

    def test_seed_never_replaces_an_id_that_is_there_and_ignores_a_bad_stored_value(self):
        self.put("/run/edr-droplet-id", "999\n")
        self.put("/var/lib/edr-agent/droplet-id", "mock-droplet-1\n")
        self.seed()
        self.assertEqual(self.out(), "999\n")
        os.unlink(self.root + "/run/edr-droplet-id")
        self.put("/var/lib/edr-agent/droplet-id", "bad id; rm -rf /\n")
        self.seed()
        self.assertEqual(self.out(), "")

    def test_seed_does_not_follow_a_symlink_in_the_agents_directory(self):
        self.put("/var/lib/edr-agent/elsewhere", "stolen-id\n")
        os.symlink("elsewhere", self.root + "/var/lib/edr-agent/droplet-id")
        self.seed()
        self.assertEqual(self.out(), "")

    def test_after_a_seed_a_silent_metadata_service_keeps_the_stored_id(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
        s.close()
        self.put("/var/lib/edr-agent/droplet-id", "mock-droplet-1\n")
        self.seed()
        self.run_id(dead)
        self.assertEqual(self.out(), "mock-droplet-1\n")
        self.run_id()                                   # and a droplet's real id replaces it
        self.assertEqual(self.out(), "12345678\n")


class Hook(http.server.BaseHTTPRequestHandler):
    posts = []
    status = 200
    redirect = False

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        type(self).posts.append((self.path, self.rfile.read(n)))
        if type(self).redirect:
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/x")
            self.end_headers()
            return
        self.send_response(type(self).status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def alert(i, sev="HIGH", summary="nginx worker tried to exec /bin/sh", kind="tetragon.nginx-exec"):
    return json.dumps({"id": "abcd0001:%d" % i, "sev": sev, "kind": kind, "summary": summary, "ts": "2026-11-19T10:00:00.000Z"})


class TestNotify(TmpCase):
    def setUp(self):
        super().setUp()
        Hook.posts, Hook.status, Hook.redirect = [], 200, False
        # edr-notify speaks https only: a throwaway certificate for 127.0.0.1, trusted through SSL_CERT_FILE
        import ssl
        self.cert = self.root + "/cert.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
                        "-keyout", self.root + "/key.pem", "-out", self.cert, "-subj", "/CN=127.0.0.1",
                        "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True)
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), Hook)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.root + "/key.pem")
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.cred = self.root + "/cred"
        self.state = self.root + "/state"
        os.makedirs(self.cred)
        os.makedirs(self.state)
        self.url("https://127.0.0.1:%d/hook" % self.port)
        self.min("HIGH")

    def url(self, text):
        with open(self.cred + "/url", "w") as fh:
            fh.write(text + "\n")

    def min(self, text):
        with open(self.cred + "/min_severity", "w") as fh:
            fh.write(text + "\n")

    def alerts(self, *lines):
        with open(self.cred + "/alerts.jsonl", "w") as fh:
            fh.write("\n".join(lines) + "\n")

    def notify(self, *extra):
        return run_helper("edr-notify", ["--cred-dir", self.cred, "--state-dir", self.state] + list(extra), env={"SSL_CERT_FILE": self.cert})

    def sent(self):
        return [json.loads(b) for _, b in Hook.posts]

    def test_each_alert_is_sent_once_across_runs_and_restarts(self):
        self.alerts(alert(1), alert(2, "CRITICAL", "second"))
        rc, out, err = self.notify()
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(self.sent()), 2)
        self.notify()
        self.assertEqual(len(self.sent()), 2)                                      # nothing again
        self.alerts(alert(1), alert(2, "CRITICAL", "second"), alert(3, "HIGH", "third"))   # a new copy, new inode
        self.notify()
        self.assertEqual(len(self.sent()), 3)
        self.assertIn("third", self.sent()[2]["text"])

    def test_severity_threshold(self):
        self.alerts(alert(1, "LOW"), alert(2, "MEDIUM"), alert(3, "HIGH"), alert(4, "INFO"))
        self.notify()
        self.assertEqual(len(self.sent()), 1)
        self.min("MEDIUM")
        self.alerts(alert(1, "LOW"), alert(2, "MEDIUM"), alert(3, "HIGH"), alert(4, "INFO"), alert(5, "MEDIUM", "five"))
        self.notify()
        self.assertEqual(len(self.sent()), 2)
        self.assertIn("five", self.sent()[1]["text"])

    def test_a_rotated_file_is_sent_once_in_full(self):
        self.alerts(alert(1), alert(2))
        self.notify()
        self.alerts(alert(10), alert(11))                                         # the last id is not in the copy
        self.notify()
        self.assertEqual(len(self.sent()), 4)
        self.notify()
        self.assertEqual(len(self.sent()), 4)

    def test_a_failed_send_is_retried_without_loss_or_repeat(self):
        self.alerts(alert(1), alert(2), alert(3))
        Hook.status = 500
        rc, out, err = self.notify()
        self.assertEqual(rc, 1)
        Hook.status = 200
        Hook.posts.clear()
        self.assertEqual(self.notify()[0], 0)
        self.assertEqual(len(self.sent()), 3)

    def test_slack_text_is_escaped_and_cut(self):
        self.alerts(alert(1, summary="<!channel> & <https://evil|click> \x1b[31m" + "A" * 400))
        self.notify()
        text = self.sent()[0]["text"]
        self.assertNotIn("<!channel>", text)
        self.assertIn("&lt;!channel&gt;", text)
        self.assertIn("&amp;", text)
        self.assertNotIn("\x1b", text)
        self.assertLessEqual(len(text), 400)
        self.assertFalse(self.sent()[0]["unfurl_links"])

    def test_ntfy_publishes_json_to_the_root_with_a_fixed_title(self):
        self.url("ntfy+https://127.0.0.1:%d/mytopic" % self.port)
        self.alerts(alert(1, "CRITICAL", "danger `x`"))
        self.notify()
        path, body = Hook.posts[0]
        self.assertEqual(path, "/")
        j = json.loads(body)
        self.assertEqual(j["topic"], "mytopic")
        self.assertEqual(j["priority"], 5)
        self.assertTrue(j["title"].startswith("EDR CRITICAL on "))
        self.assertNotIn("click", j)
        self.assertNotIn("actions", j)

    def test_only_kind_severity_host_and_summary_are_sent(self):
        ev = json.loads(alert(1))
        ev.update({"proc": {"binary": "/bin/sh", "args": "-c secret-token-123"}, "context": [{"path": "/x?token=abc"}], "details": {"args": "pw"}})
        self.alerts(json.dumps(ev))
        self.notify()
        raw = Hook.posts[0][1].decode()
        for secret in ("secret-token-123", "token=abc", '"pw"'):
            self.assertNotIn(secret, raw)

    def test_a_flood_is_summarised(self):
        self.alerts(*[alert(i, summary="n%d" % i) for i in range(1, 31)])
        self.notify("--max-send", "5")
        self.assertEqual(len(self.sent()), 6)
        self.assertIn("25 more", self.sent()[5]["text"])
        self.notify()
        self.assertEqual(len(self.sent()), 6)

    def test_redirects_are_not_followed(self):
        Hook.redirect = True
        self.alerts(alert(1))
        rc, out, err = self.notify()
        self.assertEqual(rc, 1)

    def test_no_url_means_off(self):
        os.unlink(self.cred + "/url")
        self.alerts(alert(1))
        rc, out, err = self.notify()
        self.assertEqual(rc, 0)
        self.assertEqual(Hook.posts, [])

    def test_bad_lines_and_oversized_lines_are_skipped(self):
        self.alerts("not json", "[1,2]", "x" * 70000, alert(1))
        self.notify()
        self.assertEqual(len(self.sent()), 1)

    def test_dry_run_sends_and_saves_nothing(self):
        self.alerts(alert(1))
        rc, out, err = self.notify("--dry-run")
        self.assertEqual(rc, 0)
        self.assertEqual(Hook.posts, [])
        self.assertIn("EDR HIGH", out)
        self.assertFalse(os.path.exists(self.state + "/last_id"))

    def test_url_forms(self):
        self.assertEqual(N.parse_url("https://ntfy.example.org/alerts")[0:3:2], ("ntfy", "alerts"))
        self.assertEqual(N.parse_url("slack+https://ntfy.example.org/x")[0], "slack")
        self.assertEqual(N.parse_url("https://hooks.slack.com/services/T/B/C")[0], "slack")
        for bad in ("file:///etc/passwd", "ftp://x/y", "https://", "ntfy+https://h/", "ntfy+https://h/a/b c"):
            with self.assertRaises(ValueError):
                N.parse_url(bad)


if __name__ == "__main__":
    unittest.main()
