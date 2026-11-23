"""edr-notify (client PLAN section 4.7) against a local https server on 127.0.0.1 with a throwaway CA from the openssl CLI,
and the allowlist drop-in that apply-config renders for the unit (IPAddressDeny=any stays; root resolves the webhook's host)."""
import http.server
import json
import os
import random
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_daemon_support import Tmp, cfgmod, CODE                         # noqa: E402
from edragent import render                                                # noqa: E402

NOTIFY = os.path.join(CODE, "edr-notify")
UNIT = os.path.normpath(os.path.join(CODE, "..", "files", "edr-notify.service"))


def openssl(*args):
    subprocess.run(["openssl"] + list(args), check=True, capture_output=True)


def make_pki(d, name, ip="127.0.0.1"):
    """A throwaway CA and a server certificate for an IP address, signed by it. Returns (ca.pem, srv.pem, srv.key)."""
    ca_key, ca_pem = os.path.join(d, name + "-ca.key"), os.path.join(d, name + "-ca.pem")
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", ca_key, "-out", ca_pem,
            "-days", "2", "-subj", "/CN=%s-ca" % name, "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
    key, csr, pem, ext = (os.path.join(d, name + s) for s in ("-srv.key", "-srv.csr", "-srv.pem", "-srv.ext"))
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=hook")
    with open(ext, "w") as f:
        f.write("subjectAltName=IP:%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" % ip)
    openssl("x509", "-req", "-in", csr, "-CA", ca_pem, "-CAkey", ca_key, "-CAcreateserial", "-out", pem, "-days", "2", "-extfile", ext)
    return ca_pem, pem, key


class Hook:
    """A tiny https webhook: records every request and answers by mode (ok, redirect, 500, hang, big)."""

    def __init__(self, certfile, keyfile):
        self.requests, self.mode, self.lock = [], "ok", threading.Lock()
        hook = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(n)
                with hook.lock:
                    hook.requests.append({"path": self.path, "headers": dict(self.headers.items()), "body": body})
                mode = hook.mode
                if mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "https://127.0.0.1:%d/other" % hook.port)
                    self.end_headers()
                elif mode == "500":
                    self.send_response(500)
                    self.end_headers()
                elif mode == "hang":
                    time.sleep(8)
                elif mode == "big":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    try:
                        for _ in range(200):
                            self.wfile.write(b"x" * 65536)
                    except OSError:
                        pass
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")

            do_GET = do_POST

        while True:
            port = random.randint(18100, 18900)
            try:
                self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
                break
            except OSError:
                continue
        self.port = port
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def paths(self):
        with self.lock:
            return [r["path"] for r in self.requests]

    def count(self):
        with self.lock:
            return len(self.requests)

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class NotifyCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = tempfile.mkdtemp(prefix="edr-notify-pki-")
        cls.ca, cls.srv, cls.key = make_pki(cls.pki, "good")
        cls.other_ca, cls.other_srv, cls.other_key = make_pki(cls.pki, "other")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.pki, True)

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="edr-notify-test-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.cred, self.state = os.path.join(self.d, "cred"), os.path.join(self.d, "state")
        os.makedirs(self.cred)
        os.makedirs(self.state)
        self.hook = Hook(self.srv, self.key)
        self.addCleanup(self.hook.stop)
        self.url = "https://127.0.0.1:%d/hook" % self.hook.port
        self.write("url", self.url + "\n")
        self.n = 0

    def write(self, name, text):
        with open(os.path.join(self.cred, name), "w") as f:
            f.write(text)

    def alert(self, sev="HIGH", **kw):
        self.n += 1
        e = {"id": "aabbccdd:%d" % self.n, "sev": sev, "kind": "tetragon.nginx-exec", "summary": "alert %d" % self.n, "ts": "2026-11-19T10:15:02.000Z"}
        e.update(kw)
        return e

    def set_alerts(self, events, append=False):
        """The credential copy of alerts.jsonl: systemd makes a new file (a new inode) at every start."""
        path = os.path.join(self.cred, "alerts.jsonl")
        old = ""
        if append and os.path.exists(path):
            with open(path) as f:
                old = f.read()
        tmp = path + ".new"
        with open(tmp, "w") as f:
            f.write(old + "".join(json.dumps(e) + "\n" for e in events))
        os.replace(tmp, path)

    def run_notify(self, *extra, ca=None, timeout=1.0):
        env = {"PATH": os.environ.get("PATH", "/usr/bin"), "SSL_CERT_FILE": ca or self.ca}
        p = subprocess.run([sys.executable, "-I", NOTIFY, "--cred-dir", self.cred, "--state-dir", self.state, "--timeout", str(timeout)] + list(extra),
                           capture_output=True, text=True, env=env, timeout=60)
        return p.returncode, p.stdout + p.stderr

    def bodies(self):
        with self.hook.lock:
            return [json.loads(r["body"]) for r in self.hook.requests]


class TestUrlRules(NotifyCase):
    def test_an_http_url_is_refused_and_nothing_is_sent(self):
        self.write("url", "http://127.0.0.1:%d/hook\n" % self.hook.port)
        self.set_alerts([self.alert()])
        code, out = self.run_notify()
        self.assertEqual(code, 0)
        self.assertIn("no usable url", out)
        self.assertIn("https", out)
        self.assertEqual(self.hook.count(), 0)

    def test_other_schemes_and_credentials_in_the_url_are_refused(self):
        for bad in ("ftp://127.0.0.1/x", "file:///etc/passwd", "https://user:pw@127.0.0.1:%d/hook" % self.hook.port, "ntfy+http://ntfy.example/topic", "127.0.0.1"):
            self.write("url", bad + "\n")
            self.set_alerts([self.alert()])
            code, out = self.run_notify()
            self.assertEqual((code, self.hook.count()), (0, 0), bad)
            self.assertIn("no usable url", out, bad)

    def test_https_works_and_the_state_moves_on(self):
        self.set_alerts([self.alert()])
        code, out = self.run_notify()
        self.assertEqual(code, 0, out)
        self.assertEqual(self.hook.paths(), ["/hook"])


class TestRequestHygiene(NotifyCase):
    def test_a_redirect_is_not_followed_and_the_alert_is_retried_later(self):
        self.hook.mode = "redirect"
        self.set_alerts([self.alert()])
        code, out = self.run_notify()
        self.assertEqual(code, 1)
        self.assertEqual(self.hook.paths(), ["/hook"])                                # /other was never requested
        self.assertFalse(os.path.exists(os.path.join(self.state, "last_id")))
        self.hook.mode = "ok"
        code, out = self.run_notify()
        self.assertEqual(code, 0)
        self.assertEqual(self.hook.paths(), ["/hook", "/hook"])

    def test_event_text_never_reaches_the_url_or_the_headers(self):
        evil = "x\r\nX-Evil: 1\r\n\r\nGET /other HTTP/1.1 <!channel> `click` \x1b[31m https://evil.test/"
        self.set_alerts([self.alert(kind=evil, summary=evil, click="https://evil.test", actions=["x"], topic="elsewhere", url="https://evil.test")])
        code, out = self.run_notify()
        self.assertEqual(code, 0, out)
        r = self.hook.requests[0]
        self.assertEqual(r["path"], "/hook")
        self.assertEqual(sorted(h.lower() for h in r["headers"]), ["accept-encoding", "connection", "content-length", "content-type", "host", "user-agent"])
        for v in r["headers"].values():
            self.assertNotIn("evil", v.lower())
        body = r["body"].decode()
        self.assertNotIn("evil.test/\"", body)
        self.assertTrue(all(" " <= c <= "~" for c in json.loads(body)["text"].replace("\n", " ")))
        self.assertNotIn("<!channel>", body)

    def test_a_certificate_from_an_unknown_ca_is_not_accepted(self):
        self.hook.stop()
        self.hook = Hook(self.other_srv, self.other_key)
        self.write("url", "https://127.0.0.1:%d/hook\n" % self.hook.port)
        self.set_alerts([self.alert()])
        code, out = self.run_notify()                                               # trusts only the good CA
        self.assertEqual(code, 1)
        self.assertEqual(self.hook.count(), 0)                                      # the handshake failed before any request
        code, out = self.run_notify(ca=self.other_ca)
        self.assertEqual(code, 0)
        self.assertEqual(self.hook.count(), 1)

    def test_a_certificate_for_another_address_is_not_accepted(self):
        ca, pem, key = make_pki(self.pki, "wrongip", ip="127.0.0.2")
        self.hook.stop()
        self.hook = Hook(pem, key)
        self.write("url", "https://127.0.0.1:%d/hook\n" % self.hook.port)
        self.set_alerts([self.alert()])
        self.assertEqual(self.run_notify(ca=ca)[0], 1)
        self.assertEqual(self.hook.count(), 0)

    def test_a_server_that_hangs_or_floods_is_bounded(self):
        self.hook.mode = "hang"
        self.set_alerts([self.alert()])
        t0 = time.monotonic()
        code, out = self.run_notify(timeout=1.0)
        self.assertEqual(code, 1)
        self.assertLess(time.monotonic() - t0, 6)
        self.hook.mode = "big"
        t0 = time.monotonic()
        code, out = self.run_notify(timeout=2.0)
        self.assertLess(time.monotonic() - t0, 10)
        self.assertEqual(code, 0)                                                   # a 2xx; only 4 KiB of the 12 MB were read


class TestSendOnce(NotifyCase):
    def test_each_alert_is_sent_once_across_restarts(self):
        a, b, c = self.alert(), self.alert(), self.alert()
        self.set_alerts([a, b])
        self.assertEqual(self.run_notify()[0], 0)
        self.assertEqual(self.hook.count(), 2)
        self.assertEqual(self.run_notify()[0], 0)                                   # the same copy again: nothing new
        self.assertEqual(self.hook.count(), 2)
        self.set_alerts([c], append=True)
        self.assertEqual(self.run_notify()[0], 0)
        self.assertEqual(self.hook.count(), 3)
        self.assertEqual(self.run_notify()[0], 0)
        self.assertEqual(self.hook.count(), 3)
        titles = [b_["text"] for b_ in self.bodies()]
        self.assertEqual(len({t for t in titles}), 3)

    def test_each_alert_is_sent_once_across_a_rotation_of_alerts_jsonl(self):
        a, b, c = self.alert(), self.alert(), self.alert()
        self.set_alerts([a, b, c])
        self.assertEqual(self.run_notify()[0], 0)
        self.assertEqual(self.hook.count(), 3)
        d, e = self.alert(), self.alert()
        self.set_alerts([d, e])                                                      # rotated: a, b and c are in alerts.jsonl.1 now
        self.assertEqual(self.run_notify()[0], 0)
        self.assertEqual(self.hook.count(), 5)
        self.assertEqual(self.run_notify()[0], 0)
        self.assertEqual(self.hook.count(), 5)
        f = self.alert()
        self.set_alerts([f], append=True)
        self.assertEqual(self.run_notify()[0], 0)
        self.assertEqual(self.hook.count(), 6)

    def test_a_failed_send_is_retried_and_sent_once_when_it_works(self):
        self.set_alerts([self.alert(), self.alert()])
        self.hook.mode = "500"
        self.assertEqual(self.run_notify()[0], 1)
        self.hook.mode = "ok"
        before = self.hook.count()
        self.assertEqual(self.run_notify()[0], 0)
        self.assertEqual(self.hook.count() - before, 2)
        self.assertEqual(self.run_notify()[0], 0)
        self.assertEqual(self.hook.count() - before, 2)

    def test_min_severity_and_the_burst_cap(self):
        self.write("min_severity", "CRITICAL\n")
        self.set_alerts([self.alert("HIGH"), self.alert("CRITICAL"), self.alert("MEDIUM")])
        self.assertEqual(self.run_notify()[0], 0)
        self.assertEqual(self.hook.count(), 1)
        self.write("min_severity", "HIGH\n")
        self.set_alerts([self.alert("HIGH") for _ in range(30)], append=True)
        self.assertEqual(self.run_notify("--max-send", "5")[0], 0)
        self.assertEqual(self.hook.count(), 1 + 5 + 1)                              # five alerts and one "more not sent" notice
        self.assertEqual(self.run_notify("--max-send", "5")[0], 0)
        self.assertEqual(self.hook.count(), 7)

    def test_ntfy_posts_json_to_the_root_with_a_fixed_topic(self):
        self.write("url", "ntfy+https://127.0.0.1:%d/mytopic\n" % self.hook.port)
        self.set_alerts([self.alert()])
        self.assertEqual(self.run_notify()[0], 0)
        self.assertEqual(self.hook.paths(), ["/"])
        self.assertEqual(self.bodies()[0]["topic"], "mytopic")


class TestAllowlistDropin(Tmp):
    def url(self, text):
        self.write(self.paths.notify_url, text + "\n", 0o600)

    def allow(self, resolver=None):
        return render.render_notify_allow(self.paths, resolver)

    def test_an_ip_literal_host_is_written_as_it_is(self):
        self.url("https://203.0.113.80:8443/hook")
        text, note = self.allow(lambda h, p: self.fail("an IP literal needs no lookup"))
        self.assertEqual(text, "[Service]\nIPAddressAllow=\nIPAddressAllow=localhost 203.0.113.80\n")
        self.url("slack+https://[2001:db8::50]/services/T/B/X")
        self.assertEqual(self.allow()[0], "[Service]\nIPAddressAllow=\nIPAddressAllow=localhost 2001:db8::50\n")

    def test_a_name_is_resolved_by_root_and_only_ip_literals_are_written(self):
        self.url("https://hooks.example.test/services/T/B/X")
        seen = []

        def resolver(host, port):
            seen.append((host, port))
            return ["203.0.113.7", "203.0.113.7", "2001:db8::7", "169.254.169.254", "fe80::1%eth0", "224.0.0.1", "0.0.0.0", "127.0.0.1",
                    "::ffff:198.51.100.9", "1.2.3.4; IPAddressAllow=any", "not an ip", "10.0.0.5"]
        text, note = self.allow(resolver)
        self.assertEqual(seen, [("hooks.example.test", 443)])
        self.assertEqual(text, "[Service]\nIPAddressAllow=\nIPAddressAllow=localhost 203.0.113.7 2001:db8::7 198.51.100.9 10.0.0.5\n")
        for line in text.splitlines()[2:]:
            for tok in line.split("=", 1)[1].split()[1:]:
                import ipaddress
                self.assertEqual(str(ipaddress.ip_address(tok)), tok)
        self.assertNotIn("any", text.replace("IPAddressAllow", ""))

    def test_no_usable_answer_gives_no_dropin_and_a_note(self):
        self.url("https://hooks.example.test/x")
        text, note = self.allow(lambda h, p: ["169.254.169.254", "224.0.0.1"])
        self.assertIsNone(text)
        self.assertIn("no usable address", note)
        text, note = self.allow(lambda h, p: [])
        self.assertIsNone(text)
        self.assertIn("did not resolve", note)

    def test_at_most_eight_addresses(self):
        self.url("https://hooks.example.test/x")
        text, _ = self.allow(lambda h, p: ["203.0.113.%d" % i for i in range(1, 30)])
        self.assertEqual(len(text.splitlines()[2].split()), 1 + 8)

    def test_no_url_http_or_junk_gives_nothing(self):
        self.assertEqual(self.allow(), (None, ""))
        for bad in ("http://203.0.113.80/hook", "ftp://203.0.113.80/", "junk", "https://", "https://203.0.113.80:99999/x"):
            self.url(bad)
            text, note = self.allow(lambda h, p: ["203.0.113.80"])
            self.assertIsNone(text, bad)
            self.assertTrue(note, bad)

    def test_a_symlinked_url_file_is_not_read(self):
        target = self.write(os.path.join(self.root, "elsewhere"), "https://203.0.113.80/x\n")
        os.makedirs(os.path.dirname(self.paths.notify_url), exist_ok=True)
        os.symlink(target, self.paths.notify_url)
        self.assertIsNone(self.allow()[0])

    def test_loopback_urls_need_no_dropin(self):
        self.url("https://127.0.0.1:18443/hook")
        self.assertEqual(self.allow(), (None, ""))

    def test_the_unit_keeps_ipaddressdeny_any_and_only_localhost(self):
        with open(UNIT) as f:
            text = f.read()
        active = [l.strip() for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
        self.assertIn("IPAddressDeny=any", active)
        self.assertEqual([l for l in active if l.startswith("IPAddressAllow=")], ["IPAddressAllow=localhost"])
        self.assertIn("CapabilityBoundingSet=", active)
        self.assertIn("User=edr-notify", active)


class TestApplyConfigRendersIt(Tmp):
    def apply(self, resolver=None, check=False):
        from edragent import config
        out = []
        files, skipped, notes = render.render_all(self.paths, cfgmod.load(self.paths), resolver=resolver)
        return files, notes

    def test_render_all_includes_the_dropin_and_apply_config_swaps_it_every_time(self):
        self.write(self.paths.notify_url, "https://203.0.113.80/hook\n", 0o600)
        self.write(self.paths.local_conf, "[sites]\nnginx_bin = /usr/sbin/nginx\n")
        out = []
        code = cfgmod.apply_config(self.paths, out=out.append, kill=lambda p, s: None)
        self.assertEqual(code, 0, out)
        with open(self.paths.notify_allow_dropin) as f:
            self.assertEqual(f.read(), "[Service]\nIPAddressAllow=\nIPAddressAllow=localhost 203.0.113.80\n")
        self.assertIn("would run: systemctl daemon-reload", "\n".join(out))
        self.assertNotIn("restart edr-agent", "\n".join(out))                           # the oneshot unit needs no agent restart
        self.write(self.paths.notify_url, "https://203.0.113.81/hook\n", 0o600)          # the webhook moved: the next apply-config follows it
        out = []
        cfgmod.apply_config(self.paths, out=out.append, kill=lambda p, s: None)
        with open(self.paths.notify_allow_dropin) as f:
            self.assertIn("203.0.113.81", f.read())
        os.unlink(self.paths.notify_url)                                                  # no webhook any more: the allowance goes
        out = []
        cfgmod.apply_config(self.paths, out=out.append, kill=lambda p, s: None)
        self.assertFalse(os.path.exists(self.paths.notify_allow_dropin))
        self.assertIn("removed file", "\n".join(out))

    def test_a_dev_run_resolves_no_names(self):
        self.write(self.paths.notify_url, "https://hooks.example.test/hook\n", 0o600)
        files, notes = self.apply()
        self.assertNotIn("systemd/edr-notify.service.d/10-allow.conf", files)
        self.assertTrue(any("did not resolve" in n for n in notes))

    def test_check_shows_the_dropin_and_changes_nothing(self):
        self.write(self.paths.notify_url, "https://203.0.113.80/hook\n", 0o600)
        out = []
        self.assertEqual(cfgmod.apply_config(self.paths, check_only=True, out=out.append), 0)
        self.assertIn(self.paths.notify_allow_dropin, "\n".join(out))
        self.assertFalse(os.path.exists(self.paths.notify_allow_dropin))


if __name__ == "__main__":
    unittest.main()
