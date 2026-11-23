"""Shared test fixture: a real hub (writer, CA, listeners) on 127.0.0.1 in a temporary directory, and a small
mutual-TLS client that enrolls through the hub's own enrollment code. No test cases here.

Fakes for the other agents' modules (hub_engine, hub_alerts, hub_rules, hub_audit, hub_ctl) are installed into
sys.modules only when the real import fails. The engine entry points are wrapped to record their calls, so tests
can assert what the ingest handed over whether the engine is real or fake.
"""

import gzip
import importlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HUB_DIR = os.path.normpath(os.path.join(HERE, "..", "hub"))
if HUB_DIR not in sys.path:
    sys.path.insert(0, HUB_DIR)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

SCRATCH = os.environ.get("EDR_TEST_TMP") or None


def _fake(name, **attrs):
    mod = types.ModuleType(name)
    mod.__dict__.update(attrs)
    mod.FAKE = True
    sys.modules[name] = mod
    return mod


def ensure_modules():
    """Install fakes for modules owned by other agents when their real import fails."""
    for name in ("hub_rules", "hub_engine", "hub_alerts", "hub_audit", "hub_ctl"):
        try:
            importlib.import_module(name)
        except Exception:       # noqa: BLE001 - a half-written sibling module must not stop these tests
            sys.modules.pop(name, None)
            if name == "hub_rules":
                _fake(name, rate=lambda conn, host, ev: (ev.get("sev", "INFO"), None),
                      describe=lambda kind: {"meaning": "", "next_step": ""}, RULES=[])
            elif name == "hub_engine":
                class Engine:
                    def __init__(self, hub):
                        self.hub = hub

                    def start(self):
                        pass

                    def stop(self):
                        pass
                _fake(name, after_insert=lambda *a, **k: None, on_heartbeat=lambda *a, **k: None,
                      on_enroll=lambda *a, **k: None, on_rejected=lambda *a, **k: None, Engine=Engine)
            elif name == "hub_alerts":
                _fake(name, notify=lambda *a, **k: 0, admin_notice=lambda *a, **k: 0,
                      enqueue_test=lambda *a, **k: [], render=lambda *a, **k: {})
            elif name == "hub_audit":
                rows = []

                def append(conn, *, actor_kind, actor_detail="", action, target="", outcome="ok", details=None):
                    rows.append((actor_kind, action, target, outcome))
                    return len(rows)
                _fake(name, append=append, verify=lambda conn: (True, None), ingest_pending=lambda conn, hub: 0,
                      append_pending=lambda *a, **k: None, ROWS=rows)
            elif name == "hub_ctl":
                class Sockets:
                    def __init__(self, hub):
                        self.hub = hub

                    def start(self):
                        pass

                    def stop(self):
                        pass
                _fake(name, Sockets=Sockets)


ensure_modules()

import hub_common  # noqa: E402
import hub_db  # noqa: E402
import hub_engine  # noqa: E402
import hub_enroll  # noqa: E402
import hub_ingest  # noqa: E402
import hub_pki  # noqa: E402
import edr_hub  # noqa: E402

CALLS = []


def _recording(name):
    original = getattr(hub_engine, name)

    def wrapper(*args, **kwargs):
        CALLS.append((name, args, kwargs))
        return original(*args, **kwargs)
    wrapper.__wrapped__ = original
    return wrapper


for _name in ("after_insert", "on_heartbeat", "on_enroll", "on_rejected"):
    if not hasattr(getattr(hub_engine, _name), "__wrapped__"):
        setattr(hub_engine, _name, _recording(_name))


def calls(name):
    return [c for c in CALLS if c[0] == name]


_port_lock = threading.Lock()
_next_port = [18000 + (os.getpid() % 500) * 20]


def free_ports(n=2):
    """Ports >= 18000 on 127.0.0.1 that nothing is listening on."""
    out = []
    with _port_lock:
        while len(out) < n:
            _next_port[0] += 1
            port = _next_port[0]
            if port >= 65000:
                _next_port[0] = 18000
                continue
            s = socket.socket()
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            finally:
                s.close()
            out.append(port)
    return out


def openssl(*args, stdin=None):
    return subprocess.run(["openssl"] + list(args), input=stdin, capture_output=True, check=True, timeout=30,
                          env={"PATH": os.environ.get("PATH", "/usr/bin"), "OPENSSL_CONF": "/dev/null"}).stdout


def make_key_and_csr(directory, subject="/CN=ignored", curve="prime256v1"):
    """Returns (key path, csr pem str). The client key is EC P-256 like the real client's."""
    key_path = os.path.join(directory, "client-%d.key" % time.monotonic_ns())
    key = openssl("ecparam", "-name", curve, "-genkey", "-noout")
    with open(key_path, "wb") as f:
        f.write(key)
    csr = openssl("req", "-new", "-key", key_path, "-subj", subject).decode()
    return key_path, csr


class FakeAlerts:
    pass


class HubFixture:
    """A hub without the control sockets and the engine thread: writer, CA, certificates, both listeners."""

    def __init__(self, settings=None, bind="127.0.0.1", start=True):
        self.tmp = tempfile.mkdtemp(prefix="edr-hub-test-", dir=SCRATCH)
        self.fleet_port, self.enroll_port = free_ports(2)
        self.paths = hub_common.Paths(state_dir=os.path.join(self.tmp, "state"), run_dir=os.path.join(self.tmp, "run"),
                                      etc_dir=os.path.join(self.tmp, "etc"))
        os.makedirs(self.paths.state_dir)
        os.makedirs(self.paths.run_dir)
        s = hub_common.default_settings()
        s.update({"port": self.fleet_port, "enroll_port": self.enroll_port, "public_ip": ["127.0.0.1"]})
        s.update(settings or {})
        hub_common.save_settings(self.paths, s)
        self.hub = edr_hub.Hub(self.paths, hub_common.load_settings(self.paths), bind=bind)
        self.logs = []
        self.hub.log = lambda level, message: self.logs.append((level, str(message)))
        self.hub.prepare()
        if start:
            self.start()

    def start(self):
        self.hub.open_database()
        self.hub.ingest = hub_ingest.Ingest(self.hub, bind="127.0.0.1")
        self.hub.ingest.start()

    @property
    def writer(self):
        return self.hub.writer

    def stop(self):
        try:
            if self.hub.ingest is not None:
                self.hub.ingest.stop()
            if self.hub.writer is not None:
                self.hub.writer.stop(close=True)
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)

    def sql(self, query, params=()):
        conn = self.hub.ro()
        try:
            return [dict(r) for r in conn.execute(query, params).fetchall()]
        finally:
            conn.close()

    # ---- tokens and enrollment ----
    def make_token(self, name=None, for_host=None, **kw):
        res = self.writer.call(lambda conn: hub_enroll.token_create(conn, self.hub, name=name, for_host=for_host, **kw))
        self.hub.refresh_enroll_listener()
        return res

    def enroll(self, name="web1", token=None, csr=None, extra=None, for_host=None, droplet_id="droplet-1"):
        """Run the real client side of enrollment. Returns a Client."""
        tok = token or self.make_token(name=None if for_host else name, for_host=for_host)["token"]
        key_path, csr_pem = make_key_and_csr(self.tmp)
        client = Client(self, key_path=key_path)
        status, _h, body = client.enroll_request(tok, csr if csr is not None else csr_pem, droplet_id=droplet_id,
                                                 extra=extra)
        if status != 200:
            raise AssertionError("enroll failed: %s %s" % (status, body))
        reply = json.loads(body)
        client.adopt(reply)
        return client


class Client:
    """A test client: enrolls and talks mutual TLS 1.3 to the fleet port the way the real agent does."""

    def __init__(self, fx, key_path=None):
        self.fx = fx
        self.key_path = key_path
        self.cert_path = None
        self.ca_pem = None
        self.uuid = None
        self.reply = None

    def adopt(self, reply):
        self.reply = reply
        self.uuid = reply["host_uuid"]
        self.ca_pem = reply["ca"]
        self.cert_path = os.path.join(self.fx.tmp, "client-%s-%d.pem" % (self.uuid, time.monotonic_ns()))
        with open(self.cert_path, "w") as f:
            f.write(reply["certificate"])

    # ---- low level ----
    def _ctx(self, pinned_ca=None, with_cert=True, verify=True):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if verify:
            ctx.verify_flags |= ssl.VERIFY_X509_STRICT
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cadata=pinned_ca or self.ca_pem or self.fx.hub.pki.ca_pem())
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if with_cert and self.cert_path:
            ctx.load_cert_chain(self.cert_path, self.key_path)
        return ctx

    def connect(self, port=None, with_cert=True, verify=True, pinned_ca=None, timeout=10):
        port = port or self.fx.fleet_port
        raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        ctx = self._ctx(pinned_ca=pinned_ca, with_cert=with_cert, verify=verify)
        return ctx.wrap_socket(raw, server_hostname="127.0.0.1")

    @staticmethod
    def _read_response(sock):
        data = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except (ssl.SSLError, ConnectionError, socket.timeout) as e:
                if not data:
                    raise
                break
            if not chunk:
                break
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split()[1])
        headers = {}
        for line in lines[1:]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        return status, headers, body

    def raw_request(self, request_bytes, port=None, with_cert=True, verify=True, pinned_ca=None, timeout=10):
        s = self.connect(port, with_cert, verify, pinned_ca, timeout)
        try:
            s.sendall(request_bytes)
            return self._read_response(s)
        finally:
            s.close()

    def request(self, method, path, body=b"", headers=None, port=None, proto="1", with_cert=True, verify=True,
                pinned_ca=None, content_length=True):
        h = {}
        if proto is not None:
            h["X-EDR-Proto"] = proto
        h.update(headers or {})
        if content_length and (method != "GET" or body):
            h["Content-Length"] = str(len(body))
        head = "%s %s HTTP/1.0\r\n" % (method, path) + "".join("%s: %s\r\n" % kv for kv in h.items()) + "\r\n"
        return self.raw_request(head.encode() + body, port, with_cert, verify, pinned_ca)

    # ---- enrollment ----
    def enroll_request(self, token, csr, droplet_id="droplet-1", extra=None):
        _status, _h, ca = self.request("GET", "/v1/ca", port=self.fx.enroll_port, verify=False, with_cert=False)
        body = {"token": ".".join(token.split(".")[:2]), "csr": csr, "hostname": "web1.example", "os": "Ubuntu 24.04",
                "ips": ["203.0.113.9"], "droplet_id": droplet_id}
        body.update(extra or {})
        return self.request("POST", "/v1/enroll", json.dumps(body).encode(), port=self.fx.enroll_port, with_cert=False,
                            pinned_ca=ca.decode())

    # ---- fleet routes ----
    def post_json(self, path, obj, **kw):
        return self.request("POST", path, json.dumps(obj).encode(), headers={"Content-Type": "application/json"}, **kw)

    def heartbeat(self, **over):
        hb = {"sent_at": hub_common.ms_to_rfc3339(hub_common.now_ms()), "agent_version": "0.1.0", "agent_sha256": "a" * 64,
              "schema": 1, "proto": 1, "boot_id": "b" * 36, "droplet_id": "droplet-1", "seq": 1, "epoch": 1}
        hb.update(over)
        return self.post_json("/v1/heartbeat", hb)

    def send_events(self, events, sent_at=None, batch_id="batch-1", raw_body=None, headers=None, **kw):
        if raw_body is None:
            batch = {"batch_id": batch_id, "sent_at": sent_at or hub_common.ms_to_rfc3339(hub_common.now_ms()),
                     "events": events}
            raw_body = gzip.compress(json.dumps(batch).encode())
        h = {"Content-Encoding": "gzip", "Content-Type": "application/json"}
        h.update(headers or {})
        return self.request("POST", "/v1/events", raw_body, headers=h, **kw)


def make_event(seq=1, epoch=0x7C21B0E4, sev="LOW", kind="suricata.alert", ts=None, **over):
    ev = {"v": 1, "agent_ver": "0.1.0", "boot_id": "5b1c0000-0000-0000-0000-000000000000",
          "id": "%08x:%d" % (epoch, seq), "epoch": epoch, "seq": seq,
          "ts": ts or hub_common.ms_to_rfc3339(hub_common.now_ms()), "sev": sev, "kind": kind, "source": "suricata",
          "summary": "test event %d" % seq, "details": {"sid": 1}, "src_ip": "198.51.100.7", "src_trust": "tcp"}
    ev.update(over)
    return ev


class HubTestCase(unittest.TestCase):
    """setUp builds a fresh hub; tests that can share one use SharedHubCase."""

    fixture_settings = None

    def setUp(self):
        self.fx = HubFixture(settings=self.fixture_settings)
        self.addCleanup(self.fx.stop)
        CALLS.clear()
