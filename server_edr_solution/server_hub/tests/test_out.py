"""edr_hub_out: the outbound worker, against a local https server (127.0.0.1, port >= 18000) and a fake out.sock."""

import http.server
import json
import os
import random
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
HUB = os.path.normpath(os.path.join(HERE, "..", "hub"))
sys.path.insert(0, HUB)

import edr_hub_out    # noqa: E402
import hub_alerts     # noqa: E402
import hub_common     # noqa: E402

SECRET_PATH = "/services/T000/B000/SECRETSECRETSECRET"
HOSTILE = "<!channel> <@U123> & `x` \x1b[31m ‮"


def openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True, timeout=60)


def make_certs(d):
    """A CA, a server certificate for localhost and 127.0.0.1, and a second CA the client does not trust."""
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
            "-days", "2", "-subj", "/CN=edr-test-ca", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=d)
    openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "srv.key", "-out", "srv.csr",
            "-subj", "/CN=localhost", cwd=d)
    with open(os.path.join(d, "srv.ext"), "w") as f:
        f.write("subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n")
    openssl("x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "srv.pem", "-days", "2",
            "-extfile", "srv.ext", cwd=d)
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "other.key", "-out", "other.pem",
            "-days", "2", "-subj", "/CN=other-ca", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=d)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *a):
        pass

    def handle_any(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        srv = self.server
        srv.requests.append({"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body})
        status, headers, delay = srv.behavior(self)
        if delay:
            time.sleep(delay)
        try:
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        except OSError:
            pass

    do_POST = do_GET = handle_any


class TlsServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def start_server(certdir, behavior):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(certdir, "srv.pem"), os.path.join(certdir, "srv.key"))
    for _ in range(50):
        port = random.randint(18000, 18999)
        try:
            srv = TlsServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            continue
    else:
        raise RuntimeError("no free port")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.requests = []
    srv.behavior = behavior
    srv.port = port
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return srv


class FakeOutSock:
    """The server side of out.sock: answers outbox.take with the configured items, once, and records results."""

    def __init__(self, path):
        self.path = path
        self.items = []
        self.options = {"ntfy_url": "", "webhook_ca_pem": None}
        self.deadman = False
        self.results = []
        self.calls = []
        self.stop = False
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path)
        self.srv.listen(8)
        self.srv.settimeout(0.1)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop:
            try:
                conn, _ = self.srv.accept()
            except (socket.timeout, OSError):
                continue
            with conn:
                conn.settimeout(2)
                buf = b""
                while b"\n" not in buf:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                try:
                    req = json.loads(buf.split(b"\n")[0])
                except ValueError:
                    continue
                self.calls.append(req)
                if req["cmd"] == "outbox.take":
                    items, self.items = self.items, []
                    reply = {"ok": True, "result": {"items": items, "options": self.options, "deadman": self.deadman}}
                elif req["cmd"] == "outbox.result":
                    self.results.append(req["args"])
                    reply = {"ok": True, "result": {}}
                else:
                    reply = {"ok": False, "code": "refused", "error": "no", "exit": 3}
                conn.sendall(json.dumps(reply).encode() + b"\n")

    def close(self):
        self.stop = True
        self.thread.join(timeout=2)
        self.srv.close()


def payload(**kw):
    p = {"title": "nginx worker tried to exec /bin/sh", "severity": "CRITICAL", "host": "web1", "host_ip": "203.0.113.9",
         "kind": "tetragon.nginx-exec", "meaning": "m", "next_step": "n", "incident_id": 41, "commands": ["edr-hub incident 41"],
         "fields": {"source ip": "198.51.100.7"}, "ts": 1, "test": False}
    p.update(kw)
    return p


class OutCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certs = tempfile.mkdtemp(prefix="edr-out-certs-")
        make_certs(cls.certs)
        with open(os.path.join(cls.certs, "ca.pem")) as f:
            cls.ca_pem = f.read()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.certs, ignore_errors=True)

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="edr-out-")
        self.paths = hub_common.Paths(state_dir=os.path.join(self.tmp, "state"), run_dir=os.path.join(self.tmp, "run"),
                                      etc_dir=os.path.join(self.tmp, "etc"), out_state_dir=os.path.join(self.tmp, "out"))
        for d in (self.paths.run_dir, self.paths.etc_dir):
            os.makedirs(d)
        self.sock = FakeOutSock(self.paths.out_sock)
        self.server = None
        self.old_env = {k: os.environ.pop(k, None) for k in ("CREDENTIALS_DIRECTORY",)}
        self.addCleanup(self.cleanup)

    def cleanup(self):
        self.sock.close()
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        for k, v in self.old_env.items():
            if v is not None:
                os.environ[k] = v
        shutil.rmtree(self.tmp, ignore_errors=True)

    def serve(self, status=200, headers=None, delay=0, behavior=None):
        self.server = start_server(self.certs, behavior or (lambda h: (status, headers or {}, delay)))
        return self.server

    def secrets(self, **kw):
        with open(self.paths.secrets, "w") as f:
            json.dump(kw, f)

    def url(self, path=SECRET_PATH, host="localhost"):
        return "https://%s:%d%s" % (host, self.server.port, path)

    def job(self, n=1, channel="webhook", **kw):
        return {"id": n, "channel": channel, "severity": "CRITICAL", "payload": payload(**kw), "attempts": 0}

    def worker(self, allow_private=True):
        return edr_hub_out.Worker(self.paths, allow_private=allow_private)


class SendTests(OutCase):
    def test_webhook_success_and_request_shape(self):
        self.serve()
        self.secrets(webhook_url=self.url())
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": self.ca_pem}
        self.sock.items = [self.job(7, title=HOSTILE)]
        n, deadman = self.worker().take_and_send()
        self.assertEqual((n, deadman), (1, False))
        self.assertEqual(self.sock.results, [{"id": 7, "ok": True, "error": "", "retry_after": None}])
        (req,) = self.server.requests
        self.assertEqual((req["method"], req["path"]), ("POST", SECRET_PATH))
        self.assertEqual(req["headers"]["Content-Type"], "application/json")
        self.assertTrue(req["headers"]["User-Agent"].startswith("edr-hub-out/"))
        doc = json.loads(req["body"])
        self.assertIs(doc["unfurl_links"], False)
        self.assertNotIn("<", doc["text"])
        self.assertIn("&lt;!channel&gt;", doc["text"])
        self.assertNotIn("\x1b", doc["text"])

    def test_ntfy_gets_the_secret_topic_and_bearer_token_from_the_worker(self):
        self.serve()
        self.secrets(ntfy_topic="long-random-topic-4711", ntfy_token="tk_secrettoken")
        self.sock.options = {"ntfy_url": "https://localhost:%d" % self.server.port, "webhook_ca_pem": self.ca_pem}
        self.sock.items = [self.job(3, channel="ntfy")]
        self.worker().take_and_send()
        self.assertEqual(self.sock.results[0]["ok"], True)
        (req,) = self.server.requests
        self.assertEqual(req["path"], "/")
        self.assertEqual(req["headers"]["Authorization"], "Bearer tk_secrettoken")
        doc = json.loads(req["body"])
        self.assertEqual(doc["topic"], "long-random-topic-4711")
        self.assertEqual(doc["title"], "EDR CRITICAL")
        self.assertNotIn("click", doc)
        self.assertNotIn("actions", doc)

    def test_ntfy_without_a_token_sends_no_authorization_header(self):
        self.serve()
        self.secrets(ntfy_topic="t")
        self.sock.options = {"ntfy_url": "https://localhost:%d" % self.server.port, "webhook_ca_pem": self.ca_pem}
        self.sock.items = [self.job(3, channel="ntfy")]
        self.worker().take_and_send()
        self.assertNotIn("Authorization", self.server.requests[0]["headers"])

    def test_redirects_are_refused_and_not_followed(self):
        self.serve(behavior=lambda h: (302, {"Location": "https://localhost:%d/elsewhere" % h.server.port}, 0))
        self.secrets(webhook_url=self.url())
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": self.ca_pem}
        self.sock.items = [self.job(1)]
        self.worker().take_and_send()
        self.assertEqual(self.sock.results[0]["ok"], False)
        self.assertEqual(self.sock.results[0]["error"], "redirect refused")
        self.assertEqual(len(self.server.requests), 1)

    def test_retry_after_is_honoured_and_holds_the_channel(self):
        self.serve(status=429, headers={"Retry-After": "120"})
        self.secrets(webhook_url=self.url())
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": self.ca_pem}
        self.sock.items = [self.job(1), self.job(2)]
        self.worker().take_and_send()
        first, second = self.sock.results
        self.assertEqual((first["ok"], first["error"], first["retry_after"]), (False, "HTTP 429", 120))
        self.assertEqual((second["ok"], second["error"]), (False, "held by Retry-After"))
        self.assertTrue(0 < second["retry_after"] <= 120)
        self.assertEqual(len(self.server.requests), 1)                          # the second was not even sent

    def test_retry_after_is_capped_and_ignored_when_not_a_number(self):
        self.assertEqual(edr_hub_out._retry_after("99999"), 3600)
        self.assertIsNone(edr_hub_out._retry_after("Wed, 21 Oct 2026 07:28:00 GMT"))
        self.assertIsNone(edr_hub_out._retry_after(None))
        self.serve(status=503, headers={"Retry-After": "soon"})
        self.secrets(webhook_url=self.url())
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": self.ca_pem}
        self.sock.items = [self.job(1)]
        self.worker().take_and_send()
        self.assertEqual((self.sock.results[0]["error"], self.sock.results[0]["retry_after"]), ("HTTP 503", None))

    def test_server_error_is_reported_with_its_status(self):
        self.serve(status=500)
        self.secrets(webhook_url=self.url())
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": self.ca_pem}
        self.sock.items = [self.job(1)]
        self.worker().take_and_send()
        self.assertEqual((self.sock.results[0]["ok"], self.sock.results[0]["error"]), (False, "HTTP 500"))

    def test_five_second_timeout(self):
        self.serve(delay=3)
        self.secrets(webhook_url=self.url())
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": self.ca_pem}
        self.sock.items = [self.job(1)]
        self.assertEqual(edr_hub_out.TIMEOUT_S, 5)
        old = edr_hub_out.TIMEOUT_S
        edr_hub_out.TIMEOUT_S = 1
        try:
            t0 = time.time()
            self.worker().take_and_send()
            took = time.time() - t0
        finally:
            edr_hub_out.TIMEOUT_S = old
        self.assertEqual(self.sock.results[0]["error"], "timeout")
        self.assertLess(took, 2.5)

    def test_default_verification_has_no_off_switch(self):
        self.serve()
        self.secrets(webhook_url=self.url())
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": None}                 # the test CA is not in the system store
        self.sock.items = [self.job(1)]
        self.worker().take_and_send()
        self.assertEqual(self.sock.results[0]["error"], "TLS certificate not trusted")
        self.assertEqual(self.server.requests, [])
        # a different private CA does not help either
        with open(os.path.join(self.certs, "other.pem")) as f:
            self.sock.options = {"ntfy_url": "", "webhook_ca_pem": f.read()}
        self.sock.items = [self.job(2)]
        self.worker().take_and_send()
        self.assertEqual(self.sock.results[1]["error"], "TLS certificate not trusted")
        # the right private CA does
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": self.ca_pem}
        self.sock.items = [self.job(3)]
        self.worker().take_and_send()
        self.assertTrue(self.sock.results[2]["ok"])

    def test_host_name_must_match_the_certificate(self):
        self.serve()
        self.secrets(webhook_url="https://localhost.localdomain:%d/x" % self.server.port)
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": self.ca_pem}
        self.sock.items = [self.job(1)]
        self.worker().take_and_send()
        self.assertFalse(self.sock.results[0]["ok"])

    def test_a_bad_private_ca_is_reported(self):
        self.serve()
        self.secrets(webhook_url=self.url())
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": "not a certificate"}
        self.sock.items = [self.job(1)]
        self.worker().take_and_send()
        self.assertEqual(self.sock.results[0]["error"], "the private CA is not usable")

    def test_only_https_urls(self):
        self.serve()
        for bad in ("http://localhost:%d/x" % self.server.port, "ftp://x/y", "https://user:pw@localhost:%d/x" % self.server.port,
                    "https://", "", "https://localhost:99999/x", "https://local host/x", "file:///etc/passwd"):
            self.secrets(webhook_url=bad)
            self.sock.options = {"ntfy_url": "", "webhook_ca_pem": self.ca_pem}
            self.sock.items = [self.job(1)]
            self.sock.results.clear()
            self.worker().take_and_send()
            self.assertFalse(self.sock.results[0]["ok"], bad)
        self.assertEqual(self.server.requests, [])

    def test_private_destinations_are_refused_unless_allowed(self):
        self.serve()
        self.secrets(webhook_url=self.url())
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": self.ca_pem}
        self.sock.items = [self.job(1)]
        self.worker(allow_private=False).take_and_send()
        self.assertEqual(self.sock.results[0]["error"], "the address is private")
        self.assertEqual(self.server.requests, [])
        for ip in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.1.1", "172.16.5.5", "100.64.0.1", "::1", "fe80::1", "fd00::1", "0.0.0.0"):
            with self.assertRaises(edr_hub_out.SendError, msg=ip):
                edr_hub_out.resolve(ip, 443, False)
        self.assertEqual(edr_hub_out.resolve("8.8.8.8", 443, False), "8.8.8.8")

    def test_unconfigured_or_unsupported_channels_fail_with_a_fixed_text(self):
        self.serve()
        self.secrets()
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": None}
        self.sock.items = [self.job(1), self.job(2, channel="ntfy"), self.job(3, channel="discord"), {"id": 4, "channel": "webhook", "payload": "{bad"}]
        self.worker().take_and_send()
        self.assertEqual([r["error"] for r in self.sock.results],
                         ["the channel is not configured", "the channel is not configured", "the channel is not supported", "the payload is not JSON"])

    def test_one_bad_job_does_not_stop_the_rest(self):
        self.serve()
        self.secrets(webhook_url=self.url())
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": self.ca_pem}
        self.sock.items = [{"channel": "webhook"}, self.job(5), "junk", {"id": 6, "channel": "webhook", "payload": 5}]
        n, _ = self.worker().take_and_send()
        self.assertEqual([r["id"] for r in self.sock.results], [5, 6])
        self.assertTrue(self.sock.results[0]["ok"])

    def test_no_secret_reaches_a_stored_error_or_the_log(self):
        self.serve(status=500)
        self.secrets(webhook_url=self.url(), ntfy_topic="TOPICSECRET", ntfy_token="TOKENSECRET")
        self.sock.options = {"ntfy_url": "https://localhost:%d/ntfyroot" % self.server.port, "webhook_ca_pem": None}      # untrusted: TLS error
        self.sock.items = [self.job(1), self.job(2, channel="ntfy")]
        with tempfile.TemporaryFile(mode="w+") as err:
            old = sys.stderr
            sys.stderr = err
            try:
                self.worker().take_and_send()
            finally:
                sys.stderr = old
            err.seek(0)
            shown = err.read() + json.dumps(self.sock.results)
        for secret in ("SECRETSECRETSECRET", "TOPICSECRET", "TOKENSECRET", "/services/", "ntfyroot"):
            self.assertNotIn(secret, shown)


class ChannelsFileTests(OutCase):
    def test_channels_json_holds_options_and_no_secret(self):
        self.serve()
        self.secrets(webhook_url=self.url(), ntfy_topic="TOPICSECRET", ntfy_token="TOKENSECRET", deadman_url="https://dm.example/DEADSECRET")
        self.sock.options = {"ntfy_url": "https://ntfy.example.com", "webhook_ca_pem": self.ca_pem}
        self.sock.items = [self.job(1)]
        self.worker().take_and_send()
        path = self.paths.channels
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
        with open(path) as f:
            text = f.read()
        doc = json.loads(text)
        self.assertEqual(doc["channels"], ["webhook", "ntfy"])
        self.assertEqual(doc["options"]["ntfy_url"], "https://ntfy.example.com")
        self.assertEqual(doc["options"]["webhook_ca_pem"], self.ca_pem)
        self.assertIn("written_at", doc)
        self.assertTrue(doc["status"]["webhook"]["last_ok"])
        for secret in ("TOPICSECRET", "TOKENSECRET", "DEADSECRET", "SECRETSECRETSECRET"):
            self.assertNotIn(secret, text)

    def test_failures_are_recorded_in_the_status(self):
        self.serve(status=500)
        self.secrets(webhook_url=self.url())
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": self.ca_pem}
        self.sock.items = [self.job(1)]
        self.worker().take_and_send()
        with open(self.paths.channels) as f:
            st = json.load(f)["status"]["webhook"]
        self.assertEqual(st["last_error"], "HTTP 500")
        self.assertTrue(st["last_fail"])

    def test_the_file_is_rewritten_only_when_the_options_change(self):
        self.secrets(webhook_url="https://localhost:1/x")
        w = self.worker()
        w.take_and_send()
        first = os.stat(self.paths.channels).st_mtime_ns
        time.sleep(0.02)
        w.take_and_send()
        self.assertEqual(os.stat(self.paths.channels).st_mtime_ns, first)
        self.sock.options = {"ntfy_url": "https://ntfy.example.com", "webhook_ca_pem": None}
        w.take_and_send()
        self.assertNotEqual(os.stat(self.paths.channels).st_mtime_ns, first)


class DeadmanTests(OutCase):
    def test_ping_is_a_plain_get_with_no_body_or_identifiers(self):
        self.serve()
        self.secrets(deadman_url=self.url("/ping/abc123"))
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": self.ca_pem}
        self.sock.deadman = True
        w = self.worker()
        n, deadman = w.take_and_send()
        self.assertTrue(deadman)
        # the ping uses default verification only: trust the test CA through the environment of the default context
        os.environ["SSL_CERT_FILE"] = os.path.join(self.certs, "ca.pem")
        try:
            w.maybe_ping(deadman)
        finally:
            del os.environ["SSL_CERT_FILE"]
        (req,) = self.server.requests
        self.assertEqual((req["method"], req["path"], req["body"]), ("GET", "/ping/abc123", b""))
        for h in req["headers"]:
            self.assertNotIn(h.lower(), ("authorization", "cookie", "x-forwarded-for"))
        self.assertNotIn("web1", json.dumps(req["headers"]))
        # once a minute, not more
        w.maybe_ping(deadman)
        self.assertEqual(len(self.server.requests), 1)
        w._last_ping -= 61
        os.environ["SSL_CERT_FILE"] = os.path.join(self.certs, "ca.pem")
        try:
            w.maybe_ping(deadman)
        finally:
            del os.environ["SSL_CERT_FILE"]
        self.assertEqual(len(self.server.requests), 2)

    def test_no_url_or_flag_means_no_ping(self):
        self.serve()
        w = self.worker()
        self.secrets()
        self.sock.deadman = True
        w.take_and_send()
        w.maybe_ping(True)
        self.secrets(deadman_url=self.url())
        self.sock.deadman = False
        _n, deadman = w.take_and_send()
        w.maybe_ping(deadman)
        self.assertEqual(self.server.requests, [])

    def test_a_failing_ping_is_logged_without_the_url(self):
        self.secrets(deadman_url="https://localhost:1/DEADSECRET")
        with tempfile.TemporaryFile(mode="w+") as err:
            old = sys.stderr
            sys.stderr = err
            try:
                self.assertFalse(self.worker().deadman_ping())
            finally:
                sys.stderr = old
            err.seek(0)
            text = err.read()
        self.assertIn("dead-man ping failed", text)
        self.assertNotIn("DEADSECRET", text)


class SecretsTests(OutCase):
    def test_credentials_directory_wins_and_a_bad_file_is_empty(self):
        self.secrets(webhook_url="https://etc.example/x")
        self.assertEqual(edr_hub_out.load_secrets(self.paths)["webhook_url"], "https://etc.example/x")
        cred = os.path.join(self.tmp, "cred")
        os.makedirs(cred)
        with open(os.path.join(cred, "secrets.json"), "w") as f:
            json.dump({"webhook_url": "https://cred.example/x", "bad": 5}, f)
        os.environ["CREDENTIALS_DIRECTORY"] = cred
        try:
            self.assertEqual(edr_hub_out.load_secrets(self.paths), {"webhook_url": "https://cred.example/x"})
            with open(os.path.join(cred, "secrets.json"), "w") as f:
                f.write("{broken")
            self.assertEqual(edr_hub_out.load_secrets(self.paths), {})
        finally:
            del os.environ["CREDENTIALS_DIRECTORY"]
        os.unlink(self.paths.secrets)
        self.assertEqual(edr_hub_out.load_secrets(self.paths), {})


class SocketTests(OutCase):
    def test_wire_format(self):
        self.sock.items = [self.job(1)]
        res = edr_hub_out.sock_call(self.paths.out_sock, "outbox.take", {"max": 20})
        self.assertEqual(res["items"][0]["id"], 1)
        req = self.sock.calls[0]
        self.assertEqual(req["cmd"], "outbox.take")
        self.assertEqual(req["args"], {"max": 20})
        self.assertIn("actor", req)

    def test_refused_and_unreachable(self):
        with self.assertRaises(edr_hub_out.SendError):
            edr_hub_out.sock_call(self.paths.out_sock, "feed.job", {})
        with self.assertRaises(edr_hub_out.SendError):
            edr_hub_out.sock_call(os.path.join(self.tmp, "nope.sock"), "outbox.take", {})


class ProcessTests(OutCase):
    """The program as the units run it: python3 -I, paths from the environment."""

    def run_out(self, *args, extra_env=None):
        env = {k: v for k, v in os.environ.items() if k not in ("CREDENTIALS_DIRECTORY",)}
        env.update({"EDR_HUB_RUN_DIR": self.paths.run_dir, "EDR_HUB_ETC_DIR": self.paths.etc_dir,
                    "EDR_HUB_OUT_STATE_DIR": self.paths.out_state_dir, "EDR_HUB_STATE_DIR": self.paths.state_dir,
                    "SSL_CERT_FILE": os.path.join(self.certs, "ca.pem")})
        env.update(extra_env or {})
        return subprocess.run([sys.executable, "-I", os.path.join(HUB, "edr_hub_out.py"), *args], capture_output=True, text=True, env=env, timeout=60)

    def test_once_takes_sends_reports_and_pings(self):
        self.serve()
        self.secrets(webhook_url=self.url(), deadman_url=self.url("/ping"))
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": None}
        self.sock.deadman = True
        self.sock.items = [self.job(11)]
        r = self.run_out("--once", "--allow-private")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.sock.results, [{"id": 11, "ok": True, "error": "", "retry_after": None}])
        self.assertEqual([q["path"] for q in self.server.requests], [SECRET_PATH, "/ping"])
        self.assertNotIn("SECRET", r.stderr)

    def test_once_without_the_hub_socket_exits_with_a_message(self):
        self.sock.close()
        os.unlink(self.paths.out_sock)
        self.sock = FakeOutSock(os.path.join(self.tmp, "other.sock"))
        r = self.run_out("--once")
        self.assertEqual(r.returncode, 2)
        self.assertIn("the hub socket is not reachable", r.stderr)

    def test_private_destination_refused_without_the_flag(self):
        self.serve()
        self.secrets(webhook_url=self.url())
        self.sock.items = [self.job(1)]
        r = self.run_out("--once")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(self.sock.results[0]["error"], "the address is private")

    def test_failed_notice_sends_one_message_to_every_channel(self):
        self.serve()
        self.secrets(webhook_url=self.url(), ntfy_topic="TOPICSECRET")
        os.makedirs(self.paths.out_state_dir, mode=0o700)
        with open(self.paths.channels, "w") as f:
            json.dump({"channels": ["webhook", "ntfy"], "options": {"ntfy_url": "https://localhost:%d/" % self.server.port, "webhook_ca_pem": None}}, f)
        r = self.run_out("--failed-notice", "--allow-private")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(q["path"] for q in self.server.requests), sorted([SECRET_PATH, "/"]))
        bodies = [json.loads(q["body"]) for q in self.server.requests]
        text = json.dumps(bodies)
        self.assertIn("edr-hub.service failed", text)
        self.assertIn("journalctl --namespace edr-hub", text)
        self.assertEqual({b.get("title") for b in bodies if "topic" in b}, {"EDR HIGH"})
        self.assertEqual(self.sock.calls, [])                                            # it needs no out.sock: the hub is what failed

    def test_failed_notice_with_nothing_configured_exits_1(self):
        self.secrets()
        r = self.run_out("--failed-notice")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no channel is set up", r.stderr)

    def test_failed_notice_exit_code_follows_the_result(self):
        self.serve(status=500)
        self.secrets(webhook_url=self.url())
        r = self.run_out("--failed-notice", "--allow-private")
        self.assertEqual(r.returncode, 1)
        self.assertIn("HTTP 500", r.stderr)
        self.assertNotIn("SECRETSECRET", r.stderr)

    def test_the_render_of_every_payload_goes_through_hub_alerts(self):
        # the worker sends exactly what hub_alerts.render builds, so the escaping tests there cover the wire
        self.serve()
        self.secrets(webhook_url=self.url())
        self.sock.options = {"ntfy_url": "", "webhook_ca_pem": self.ca_pem}
        p = payload(title=HOSTILE)
        self.sock.items = [{"id": 1, "channel": "webhook", "payload": p}]
        self.worker().take_and_send()
        self.assertEqual(self.server.requests[0]["body"], hub_alerts.render("webhook", p)["body"])


if __name__ == "__main__":
    unittest.main()
