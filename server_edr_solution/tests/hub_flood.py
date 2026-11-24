#!/usr/bin/python3 -I
"""Slow-client and flood tests against the real hub (server_hub/PLAN.md section 12, "Slow-client and flood tests").

    python3 -I server_edr_solution/tests/hub_flood.py

Standard library only. It starts the real hub (server_hub/hub/edr_hub.py) on 127.0.0.1, enrolls a few hosts through the
real enrollment port with its own CSRs, and then speaks raw TLS and HTTP itself so that it can misbehave: it stalls,
trickles, floods, sends oversize, malformed and hostile requests, and holds sockets open. It never imports hub code.

It uses only temporary directories under /tmp and ports above 18000 on 127.0.0.1 (never 80, 443, 8443, 8444 or 8450).
Several source addresses in 127.0.0.0/8 are bound with bind() before connect() so that the per-source cap of 4 does not
hide the slot caps. It runs no installer, no nft, no systemctl. Every child is killed and every directory removed at
the end. One PASS or FAIL line per check; exit 0 when all passed, 2 otherwise.

What is covered (the Limits table of section 2, then sections 3 and 8):
  limits that answer      header block 8 KiB and 32 lines (431), Content-Length missing (411), Transfer-Encoding and
                          Expect (400), compressed body 1 MiB (413), inflated body 3 MiB (413, also a gzip bomb), one
                          event 10 KiB and 501 events (413), truncated or trailing gzip (400), a deeply nested body
                          (400), bad UTF-8 (400), a GET with a body, requests per certificate (429), requests parsing
                          at once (503), the per-route body caps, failed enrollments per source (429), a corpus of
                          malformed requests (never a 5xx)
  limits that cut         handshake 3 s, header block 5 s, whole request 15 s and 30 s, enrollment 5 s, a trickler
                          (one byte a second) cut by the wall-clock reaper, slots 64 and 4, slots per source 4
  memory                  30 connections with maximum-size header blocks: the hub's RSS from /proc/PID/status
  handshake               no certificate and a certificate from another CA never reach the parser
  sockets                 modes of the socket directory and of each local socket
  storage                 a database at its page cap (--max-db-size): LOW and INFO get 503, HIGH and CRITICAL go to
                          critical-overflow.jsonl and are answered 200 after the append, `edr-hub status` says so, and
                          the file's 20 MB bound turns HIGH and CRITICAL into 503 as well
  writer stalled          another process holds the database's write lock while many rejected requests fill the
                          writer queue: every ingest route answers 503 with Retry-After and stores nothing
  survival                the hub is alive, `edr-hub health` is 0 and a normal heartbeat and event batch get 200

The writer queue (256 items) can only be filled from outside while the writer is blocked: the test takes the database's
write lock from another process and sends rejected requests from several hundred source addresses, each of which posts one
job (an old, superseded certificate). No test hook is used. The same lock, with fewer requests, shows the 4 parsing slots.

Not covered, and why: the CLI's login uid under ProtectProc=invisible and the group of ui.sock and out.sock need systemd
and the real service users; a held live feed and the WAL bound belong to the dashboard process, which this does not start.
"""

import gzip
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zlib

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(HERE)
HUB_DIR = os.path.join(ROOT, "server_hub", "hub")
PY = sys.executable
OPENSSL = shutil.which("openssl") or "openssl"
FORBIDDEN_PORTS = {80, 443, 8443, 8444, 8450}
MIB = 1024 * 1024

BASE = None
CHILDREN = []
RESULTS = []
USED_PORTS = set()
CTX = {}
PRINT_LOCK = threading.Lock()
_SRC_LOCK = threading.Lock()
_SRC_N = [0]
_EV_LOCK = threading.Lock()
_EV_N = [0]


# ---- small helpers -----------------------------------------------------------------------------

def free_port():
    for _ in range(200):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        if port >= 18000 and port not in FORBIDDEN_PORTS and port not in USED_PORTS:
            USED_PORTS.add(port)
            return port
    raise RuntimeError("no free port at 18000 or above")


def port_open(port):
    s = socket.socket()
    s.settimeout(1)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


def wait_until(fn, timeout, step=0.5):
    end = time.time() + timeout
    while time.time() < end:
        try:
            got = fn()
        except Exception:               # a probe that fails is "not yet"
            got = None
        if got:
            return got
        time.sleep(step)
    try:
        return fn()
    except Exception:
        return None


def check(cond, message):
    if not cond:
        raise AssertionError(message)


def tail(text, n=300):
    text = (text or "").strip().replace("\n", " | ")
    return text[-n:]


def run(cmd, env=None, input_text=None, timeout=120):
    e = dict(os.environ)
    e.update(env or {})
    r = subprocess.run(cmd, env=e, input=input_text, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def fresh_source():
    """A new 127.x.y.z address, never used before in this run, so no per-source count carries over."""
    with _SRC_LOCK:
        n = _SRC_N[0]
        _SRC_N[0] += 1
    return "127.%d.%d.%d" % (20 + n // 64516, (n % 64516) // 254, n % 254 + 1)


def now_ts(offset_s=0.0):
    t = time.time() + offset_s
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % int((t % 1) * 1000)


def rss_kb(pid, field="VmRSS"):
    with open("/proc/%d/status" % pid) as f:
        for line in f:
            if line.startswith(field + ":"):
                return int(line.split()[1])
    raise RuntimeError("no %s in /proc/%d/status" % (field, pid))


def openssl(*args, stdin=None):
    r = subprocess.run([OPENSSL] + list(args), input=stdin, capture_output=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError("openssl %s failed: %s" % (args[0], r.stderr.decode("utf-8", "replace")[:200]))
    return r.stdout


class Hub:
    def __init__(self, name, extra=()):
        self.name = name
        self.dir = os.path.join(BASE, name)
        self.state, self.run_dir, self.etc = (os.path.join(self.dir, d) for d in ("s", "r", "e"))
        self.port, self.enroll_port, self.ui_port = free_port(), free_port(), free_port()
        self.extra = list(extra)
        self.proc = None
        self.env = {"EDR_HUB_STATE_DIR": self.state, "EDR_HUB_RUN_DIR": self.run_dir, "EDR_HUB_ETC_DIR": self.etc}
        self.log_path = os.path.join(self.dir, "hub.log")

    @property
    def db(self):
        return os.path.join(self.state, "hub.db")

    def start(self):
        os.makedirs(self.dir, exist_ok=True)
        # The unit makes /run/edr-hub 0711 (RuntimeDirectoryMode and ExecStartPre, PLAN section 8); do the same here.
        os.makedirs(self.run_dir, exist_ok=True)
        os.chmod(self.run_dir, 0o711)
        log = open(self.log_path, "ab")
        self.proc = subprocess.Popen(
            [PY, "-I", os.path.join(HUB_DIR, "edr_hub.py"), "--state-dir", self.state, "--run-dir", self.run_dir,
             "--etc-dir", self.etc, "--bind", "127.0.0.1", "--port", str(self.port), "--enroll-port", str(self.enroll_port),
             "--ui-port", str(self.ui_port), "--public-ip", "127.0.0.1"] + self.extra,
            stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True)
        CHILDREN.append(self.proc)

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def stop(self, wait=15):
        p = self.proc
        if p is None or p.poll() is not None:
            return
        try:
            os.killpg(p.pid, signal.SIGTERM)
            p.wait(wait)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(5)
        except OSError:
            pass

    def log_text(self):
        try:
            with open(self.log_path, errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def cli(self, *args, input_text=None, timeout=120):
        return run([PY, "-I", os.path.join(HUB_DIR, "edr-hub")] + list(args), env=self.env, input_text=input_text, timeout=timeout)

    def cli_json(self, *args):
        rc, out, err = self.cli(*args, "--json")
        check(rc == 0, "edr-hub %s exited %d: %s" % (" ".join(args), rc, tail(err or out)))
        rows = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("{"):
                rows.append(json.loads(line))
        if len(rows) == 1 and isinstance(rows[0].get("tokens"), list):
            return rows[0]
        return rows

    def health(self):
        return self.cli("health")[0] == 0

    def events(self, limit=5000):
        return self.cli_json("events", "--limit", str(limit))


# ---- raw TLS and HTTP --------------------------------------------------------------------------

def client_ctx(cert=None, key=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if cert:
        ctx.load_cert_chain(cert, key)
    return ctx


def tcp(port, source=None, timeout=15):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if source:
            s.bind((source, 0))
        s.connect(("127.0.0.1", port))
    except BaseException:
        s.close()
        raise
    return s


def tls(port, ctx, source=None, timeout=15):
    s = tcp(port, source, timeout)
    try:
        return ctx.wrap_socket(s)
    except BaseException:
        s.close()
        raise


class Resp:
    def __init__(self, raw, how=""):
        self.raw, self.how = raw, how
        self.status, self.headers, self.body, self.json = None, {}, b"", None
        if raw.startswith(b"HTTP/"):
            head, _, self.body = raw.partition(b"\r\n\r\n")
            lines = head.split(b"\r\n")
            parts = lines[0].split(b" ", 2)
            try:
                self.status = int(parts[1])
            except (IndexError, ValueError):
                self.status = None
            for line in lines[1:]:
                k, _, v = line.partition(b":")
                self.headers[k.decode("latin-1").lower()] = v.decode("latin-1").strip()
            try:
                self.json = json.loads(self.body.decode("utf-8"))
            except ValueError:
                self.json = None

    @property
    def code(self):
        return self.json.get("code") if isinstance(self.json, dict) else None

    def __repr__(self):
        return "<%s %s %s %s>" % (self.status, self.code, self.how, tail(self.raw.decode("latin-1"), 80) if self.status is None else "")


def read_all(ss, limit=4 * MIB):
    """Read until the peer closes. Returns (bytes, how it ended)."""
    buf = b""
    try:
        while len(buf) < limit:
            chunk = ss.recv(65536)
            if not chunk:
                return buf, "eof"
            buf += chunk
    except socket.timeout:
        return buf, "timeout"
    except ssl.SSLEOFError:
        return buf, "eof"
    except (ssl.SSLError, OSError) as e:
        return buf, "error " + type(e).__name__
    return buf, "limit"


def exchange(port, ctx, data, source=None, read_timeout=20):
    """Connect, send `data` whole, read until the server closes. A refused handshake or a reset is a Resp with no status."""
    try:
        ss = tls(port, ctx, source, read_timeout)
    except (ssl.SSLError, OSError) as e:
        return Resp(b"", "handshake " + type(e).__name__)
    try:
        try:
            ss.sendall(data)
        except (ssl.SSLError, OSError):
            pass                         # the server may answer and close before it has read all of a large body
        raw, how = read_all(ss)
    finally:
        try:
            ss.close()
        except OSError:
            pass
    return Resp(raw, how)


def build(method, path, body=b"", headers=(), proto="1", clen="auto", host="hub"):
    """One request as bytes. `headers` are extra (name, value) lines; clen is 'auto', None or a literal value."""
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: " + host]
    if proto is not None:
        lines.append("X-EDR-Proto: " + proto)
    if clen == "auto":
        clen = str(len(body)) if method == "POST" else None
    if clen is not None:
        lines.append("Content-Length: " + str(clen))
    for k, v in headers:
        lines.append("%s: %s" % (k, v))
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def event(sev="INFO", kind="flood.test", pad=0, details=None, extra=None):
    with _EV_LOCK:
        _EV_N[0] += 1
        seq = _EV_N[0]
    ev = {"v": 1, "agent_ver": "0.1.0", "boot_id": "flood", "id": "%08x:%d" % (1, seq), "epoch": 1, "seq": seq,
          "ts": now_ts(), "sev": sev, "kind": kind, "source": "agent", "summary": "hub_flood " + sev}
    if details:
        ev["details"] = details
    if pad:
        ev["pad"] = "x" * pad
    if extra:
        ev.update(extra)
    return ev


def batch_obj(events):
    return {"batch_id": "flood-%d" % time.time_ns(), "sent_at": now_ts(), "events": events}


def gz(obj):
    raw = obj if isinstance(obj, bytes) else json.dumps(obj, separators=(",", ":")).encode()
    return gzip.compress(raw, 1)


def events_request(body, clen="auto", extra=()):
    return build("POST", "/v1/events", body, [("Content-Type", "application/json"), ("Content-Encoding", "gzip")] + list(extra),
                 clen=clen)


def heartbeat_request(droplet):
    body = json.dumps({"sent_at": now_ts(), "droplet_id": droplet, "agent_version": "0.1.0", "schema": 1, "proto": 1}).encode()
    return build("POST", "/v1/heartbeat", body, [("Content-Type", "application/json")])


class Ident:
    """A host enrolled on a hub: its certificate, key and the TLS context that presents them."""

    def __init__(self, hub, name, uuid, cert, key, droplet):
        self.hub, self.name, self.uuid, self.cert, self.key, self.droplet = hub, name, uuid, cert, key, droplet
        self.ctx = client_ctx(cert, key)

    def send(self, data, source=None, read_timeout=20):
        return exchange(self.hub.port, self.ctx, data, source or fresh_source(), read_timeout)

    def heartbeat(self):
        return self.send(heartbeat_request(self.droplet))

    def events(self, evs):
        return self.send(events_request(gz(batch_obj(evs))))

    def policy(self, extra=()):
        return self.send(build("GET", "/v1/policy", headers=extra))


def make_key_and_csr(directory, label):
    key = os.path.join(directory, label + ".key")
    csr = os.path.join(directory, label + ".csr")
    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
    os.chmod(key, 0o600)
    openssl("req", "-new", "-key", key, "-subj", "/CN=hub-flood", "-out", csr)
    with open(csr) as f:
        return key, f.read()


def enroll(hub, name, droplet=None, token=None):
    """Make a token with the CLI, post a CSR to the real enrollment port, save the certificate. Returns an Ident."""
    droplet = droplet or "flood-%s" % name
    if token is None:
        token = hub.cli_json("token", "create", "--name", name, "--ttl", "1h")["tokens"][0]["token"]
    token = ".".join(token.split(".")[:2])          # id.secret; the CA hash stays with the client
    d = os.path.join(hub.dir, "id-" + name)
    os.makedirs(d, mode=0o700, exist_ok=True)
    key, csr = make_key_and_csr(d, "client")
    check(wait_until(lambda: port_open(hub.enroll_port), 15), "the enrollment port did not open")
    body = json.dumps({"token": token, "csr": csr, "hostname": name, "os": "test", "ips": ["127.0.0.1"], "droplet_id": droplet}).encode()
    r = exchange(hub.enroll_port, client_ctx(), build("POST", "/v1/enroll", body, [("Content-Type", "application/json")]),
                 fresh_source())
    check(r.status == 200 and isinstance(r.json, dict), "enrollment of %s answered %r %s" % (name, r, tail(r.body.decode("latin-1"))))
    cert = os.path.join(d, "client.pem")
    with open(cert, "w") as f:
        f.write(r.json["certificate"])
    return Ident(hub, name, r.json["host_uuid"], cert, key, droplet)


# ---- check bookkeeping -------------------------------------------------------------------------

def say(line):
    with PRINT_LOCK:
        print(line, flush=True)


def case(num, name):
    def deco(fn):
        def runner():
            t0 = time.time()
            try:
                fn()
            except AssertionError as exc:
                RESULTS.append((num, name, False, str(exc)))
                say("FAIL %s  %s: %s" % (num, name, str(exc)[:700]))
            except Exception as exc:
                RESULTS.append((num, name, False, "%s: %s" % (type(exc).__name__, exc)))
                say("FAIL %s  %s: %s: %s" % (num, name, type(exc).__name__, str(exc)[:700]))
            else:
                RESULTS.append((num, name, True, ""))
                say("PASS %s  %s (%.1fs)" % (num, name, time.time() - t0))
        runner.case = (num, name)
        return runner
    return deco


def note(text):
    say("     note: " + text)


def run_parallel(cases):
    threads = [threading.Thread(target=c, daemon=True) for c in cases]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def expect(resp, status, code=None, retry_after=False, what=""):
    check(resp.status == status, "%s: expected %d, got %r" % (what or "request", status, resp))
    if code is not None:
        check(resp.code == code, "%s: expected code %r, got %r (body %s)" % (what or "request", code, resp.code, tail(resp.body.decode("latin-1"))))
    if retry_after:
        ra = resp.headers.get("retry-after", "")
        check(ra.isdigit() and int(ra) >= 1, "%s: no whole-seconds Retry-After (got %r)" % (what or "request", ra))
    if status >= 400:
        check(set(resp.json or {}) <= {"error", "code", "index"}, "%s: the error body is not {error, code}: %s" % (what, tail(resp.body.decode("latin-1"))))
        extra = set(resp.headers) - {"content-type", "content-length", "cache-control", "x-content-type-options", "connection", "retry-after"}
        check(not extra, "%s: headers beyond the fixed set: %s" % (what, sorted(extra)))


def closed_at(ss_or_sock, limit):
    """Block until the peer closes (EOF, reset or TLS error). Returns the seconds waited, or None if still open after `limit`."""
    t0 = time.monotonic()
    ss_or_sock.settimeout(limit)
    try:
        while True:
            chunk = ss_or_sock.recv(4096)
            if not chunk:
                break
    except socket.timeout:
        return None
    except (ssl.SSLError, OSError):
        pass
    return time.monotonic() - t0


# ---- checks: what answers (phase A, one after another) -----------------------------------------

@case("A1", "after a start the socket directory is 0711, ctl.sock 0600 and ui.sock and out.sock 0660 (section 8)")
def a1():
    h = CTX["hub"]
    dmode = stat.S_IMODE(os.stat(h.run_dir).st_mode)
    check(dmode == 0o711, "the socket directory is %04o after the start, not 0711" % dmode)
    want = {"ctl.sock": 0o600, "ui.sock": 0o660, "out.sock": 0o660}
    for name, mode in want.items():
        path = os.path.join(h.run_dir, name)
        st = os.stat(path)
        check(stat.S_ISSOCK(st.st_mode), "%s is not a socket" % name)
        check(stat.S_IMODE(st.st_mode) == mode, "%s is %04o, not %04o" % (name, stat.S_IMODE(st.st_mode), mode))
    note("the group of ui.sock and out.sock is set by the unit (ExecStartPost=+); only the modes are checked here")


@case("A2", "control: a heartbeat, a policy GET and a batch of 500 events (the limit itself) get 200 with the fixed headers")
def a2():
    fa = CTX["fa"]
    r = fa.heartbeat()
    expect(r, 200, what="heartbeat")
    for header in ("cache-control", "x-content-type-options", "content-length"):
        check(header in r.headers, "the reply has no %s header" % header)
    check(set(r.headers) <= {"content-type", "content-length", "cache-control", "x-content-type-options", "connection"},
          "the reply carries more than the fixed headers: %s" % sorted(r.headers))
    expect(fa.policy(), 200, what="policy")
    r = fa.events([event("INFO") for _ in range(500)])
    expect(r, 200, what="500 events")
    check(r.json.get("accepted") == 500, "accepted %r of 500" % r.json)


@case("A3", "header block: 8192 bytes pass, 8193 get 431 header_too_large")
def a3():
    fa = CTX["fa"]

    def block(total):
        head = "GET /v1/policy HTTP/1.1\r\nHost: hub\r\nX-EDR-Proto: 1\r\nX-Pad: "
        pad = total - len(head) - 4          # the value, then CRLF CRLF
        return (head + "a" * pad + "\r\n\r\n").encode()
    exact = block(8192)
    check(len(exact) == 8192, "test bug: the block is %d bytes" % len(exact))
    expect(fa.send(exact), 200, what="8192-byte header block")
    r = fa.send(block(8193))
    expect(r, 431, "header_too_large", what="8193-byte header block")
    r = fa.send(block(70000))
    expect(r, 431, "header_too_large", what="70000-byte header block")


@case("A4", "header block: 32 lines (request line included) pass, 33 get 431")
def a4():
    fa = CTX["fa"]

    def lines(n):
        head = ["GET /v1/policy HTTP/1.1", "Host: hub", "X-EDR-Proto: 1"]
        head += ["X-H%d: v" % i for i in range(n - len(head))]
        return ("\r\n".join(head) + "\r\n\r\n").encode()
    expect(fa.send(lines(32)), 200, what="32 lines")
    expect(fa.send(lines(33)), 431, "header_too_large", what="33 lines")


@case("A5", "Content-Length: missing gives 411; Transfer-Encoding and Expect give 400; a GET with a body is refused")
def a5():
    fa = CTX["fa"]
    body = gz(batch_obj([event()]))
    expect(fa.send(events_request(body, clen=None)), 411, "length_required", what="no Content-Length")
    expect(fa.send(events_request(body, extra=[("Transfer-Encoding", "chunked")])), 400, "bad_request", what="Transfer-Encoding")
    expect(fa.send(events_request(body, extra=[("Expect", "100-continue")])), 400, "bad_request", what="Expect")
    expect(fa.send(build("POST", "/v1/heartbeat", b"{}", [("Transfer-Encoding", "chunked")])), 400, what="Transfer-Encoding on heartbeat")
    # A GET carrying a body: refused (400), and the body is never read as a second request.
    r = fa.send(build("GET", "/v1/policy", b"hello", clen="5"))
    expect(r, 400, "bad_request", what="GET with a body")
    r = fa.send(build("GET", "/v1/policy", b"", clen="0"))
    expect(r, 200, what="GET with Content-Length: 0")
    # Two Content-Length headers, a bad number, a negative number.
    expect(fa.send(build("POST", "/v1/heartbeat", b"{}", [("Content-Length", "2")], clen="2")), 400, what="two Content-Length")
    expect(fa.send(build("POST", "/v1/heartbeat", b"{}", clen="-1")), 400, what="negative Content-Length")


@case("A6", "unknown route 404, wrong method 405, missing or wrong X-EDR-Proto 426")
def a6():
    fa = CTX["fa"]
    expect(fa.send(build("GET", "/v1/nothing")), 404, what="unknown route")
    expect(fa.send(build("GET", "/v1/events")), 405, what="GET on events")
    expect(fa.send(build("GET", "/v1/policy", proto=None)), 426, "proto_unsupported", what="no X-EDR-Proto")
    expect(fa.send(build("GET", "/v1/policy", proto="99")), 426, "proto_unsupported", what="X-EDR-Proto 99")
    expect(fa.send(b"GARBAGE\r\n\r\n"), 400, what="a garbage request line")


@case("A7", "compressed body: 1 MiB reaches the parser (400, not gzip), 1 MiB + 1 gets 413")
def a7():
    fa = CTX["fa"]
    r = fa.send(events_request(b"\x00" * MIB))
    expect(r, 400, "bad_request", what="a body of exactly 1 MiB that is not gzip")
    r = fa.send(events_request(b"\x00" * (MIB + 1)))
    expect(r, 413, "too_large", what="a body of 1 MiB + 1")
    r = fa.send(events_request(b"", clen=str(MIB + 1)))
    expect(r, 413, "too_large", what="a Content-Length of 1 MiB + 1 with no body")
    r = fa.send(events_request(b"", clen="99999999999"))
    check(r.status in (400, 413), "an 11-digit Content-Length gave %r" % r)


@case("A8", "inflated body: 3 MiB passes, 3 MiB + 1 gets 413; a gzip bomb (512 MiB of zeros) gets 413 without growing the hub")
def a8():
    fa, h = CTX["fa"], CTX["hub"]

    def padded(total):
        head = json.dumps({"batch_id": "pad-%d" % time.time_ns(), "sent_at": now_ts(), "events": []}).encode()
        return head + b" " * (total - len(head))
    r = fa.send(events_request(gzip.compress(padded(3 * MIB), 6)))
    expect(r, 200, what="3 MiB inflated")
    r = fa.send(events_request(gzip.compress(padded(3 * MIB + 1), 6)))
    expect(r, 413, "too_large", what="3 MiB + 1 inflated")
    # a 512 MiB gzip bomb: about 0.5 MB on the wire
    comp = zlib.compressobj(9, zlib.DEFLATED, 31)
    chunk = b"\x00" * MIB
    parts = [comp.compress(chunk) for _ in range(512)]
    parts.append(comp.flush())
    bomb = b"".join(parts)
    check(len(bomb) < MIB, "test bug: the bomb is %d bytes, over the 1 MiB wire cap" % len(bomb))
    before = rss_kb(h.proc.pid)
    r = fa.send(events_request(bomb))
    expect(r, 413, "too_large", what="a gzip bomb of %d bytes (512 MiB inflated)" % len(bomb))
    grown = rss_kb(h.proc.pid, "VmHWM") - before
    note("gzip bomb of %d bytes: hub RSS %d MiB before, high-water mark grew by %d MiB" % (len(bomb), before // 1024, max(0, grown) // 1024))
    check(grown < 80 * 1024, "the hub's high-water mark grew by %d MiB on one bomb" % (grown // 1024))


@case("A9", "one event: 10 KiB passes, 10 KiB + 1 gets 413 with its index; 501 events get 413")
def a9():
    fa = CTX["fa"]

    def sized(n):
        base = event("INFO", pad=1)
        size = len(json.dumps(base, separators=(",", ":"), ensure_ascii=False).encode())
        return dict(base, pad="x" * (1 + n - size))
    ok = sized(10 * 1024)
    check(len(json.dumps(ok, separators=(",", ":"), ensure_ascii=False).encode()) == 10240, "test bug: the event is not 10240 bytes")
    expect(fa.events([ok]), 200, what="an event of exactly 10240 bytes")
    big = sized(10 * 1024 + 1)
    r = fa.events([event(), big])
    expect(r, 413, "too_large", what="an event of 10241 bytes")
    check(r.json.get("index") == 1, "the 413 names index %r, not 1" % r.json.get("index"))
    r = fa.events([event() for _ in range(501)])
    expect(r, 413, "too_large", what="501 events")
    r = fa.events([{} for _ in range(501)])
    expect(r, 413, "too_large", what="501 empty events")


@case("A10", "hostile bodies: truncated gzip, trailing bytes, deep nesting, bad UTF-8, not-an-object all get 400")
def a10():
    fa = CTX["fa"]
    good = gz(batch_obj([event()]))
    expect(fa.send(events_request(good[:-6])), 400, "bad_request", what="truncated gzip")
    expect(fa.send(events_request(good + b"junk")), 400, "bad_request", what="trailing bytes after the gzip stream")
    expect(fa.send(events_request(gz(b"[" * 200000 + b"]" * 200000))), 400, "bad_request", what="deeply nested JSON (RecursionError)")
    expect(fa.send(events_request(gz(b'{"batch_id":"\xff\xfe","events":[]}'))), 400, "bad_request", what="bad UTF-8")
    expect(fa.send(events_request(gz(b"[1,2,3]"))), 400, what="a JSON array")
    expect(fa.send(events_request(gz(b'{"batch_id":"x","sent_at":NaN,"events":[]}'))), 400, what="NaN")
    expect(fa.send(build("POST", "/v1/heartbeat", b'{"sent_at":' + b"[" * 100000, clen="auto")), 400, what="deep nesting in a heartbeat")
    # the hub still answers after all of that
    expect(fa.heartbeat(), 200, what="heartbeat after hostile bodies")


@case("A11", "a client with no certificate, and one with a certificate from another CA, fail the handshake and never reach the parser")
def a11():
    h = CTX["hub"]
    hostile = build("GET", "/v1/policy") + b"BOGUS REQUEST\r\n\r\n"
    for label, ctx in (("no certificate", client_ctx()), ("a certificate from another CA", CTX["other_ctx"])):
        r = exchange(h.port, ctx, hostile, fresh_source(), 10)
        check(r.status is None and r.raw == b"", "%s: the hub answered something: %r" % (label, r))
        check(r.how.startswith(("eof", "error", "handshake")) and r.how != "timeout", "%s: the connection ended with %r" % (label, r.how))
    # A parser would answer BOGUS REQUEST with 400; with a valid certificate the same bytes do reach it.
    r = CTX["fa"].send(b"BOGUS REQUEST\r\n\r\n")
    expect(r, 400, what="the same garbage with a valid certificate (control)")
    # The enrollment listener has no client-certificate requirement: /v1/ca answers there.
    r = exchange(h.enroll_port, client_ctx(), build("GET", "/v1/ca", proto=None), fresh_source())
    expect(r, 200, what="GET /v1/ca on the enrollment port")
    check(b"BEGIN CERTIFICATE" in r.body, "/v1/ca did not return a PEM certificate")
    r = exchange(h.enroll_port, client_ctx(), build("GET", "/v1/policy"), fresh_source())
    expect(r, 404, what="a fleet route on the enrollment port")


@case("A12", "other body caps (heartbeat 256 KiB, enroll 16 KiB, renew 8 KiB, deregister 2 KiB) give 413; the sixth failed enrollment from one source gets 429")
def a12():
    h, fa = CTX["hub"], CTX["fa"]
    for path, cap in (("/v1/heartbeat", 256 * 1024), ("/v1/renew", 8 * 1024), ("/v1/deregister", 2 * 1024)):
        r = fa.send(build("POST", path, b"", [("Content-Type", "application/json")], clen=str(cap + 1)))
        expect(r, 413, "too_large", what="%s with Content-Length %d" % (path, cap + 1))
    r = exchange(h.enroll_port, client_ctx(), build("POST", "/v1/enroll", b"", [("Content-Type", "application/json")], clen=str(16 * 1024 + 1)),
                 fresh_source())
    expect(r, 413, "too_large", what="/v1/enroll with Content-Length 16385")
    # unknown token ids: each answer is the same 401, and the sixth in a minute from one source is refused before any work
    src = fresh_source()
    bad = json.dumps({"token": "0123456789ab.AAAAAAAAAAAAAAAAAAAAAA", "csr": "x", "droplet_id": "d"}).encode()
    req = build("POST", "/v1/enroll", bad, [("Content-Type", "application/json")])
    for i in range(5):
        expect(exchange(h.enroll_port, client_ctx(), req, src), 401, "invalid_token", what="failed enrollment %d" % (i + 1))
    expect(exchange(h.enroll_port, client_ctx(), req, src), 429, "rate_limited", retry_after=True, what="the sixth failed enrollment from one source")
    expect(exchange(h.enroll_port, client_ctx(), req, fresh_source()), 401, "invalid_token", what="a failed enrollment from another source")


CORPUS = [
    ("binary junk", b"\x00\x01\x02\xff" * 100 + b"\r\n\r\n"),
    ("request line only", b"GET\r\n\r\n"),
    ("empty request", b"\r\n\r\n"),
    ("HTTP/9.9", b"GET /v1/policy HTTP/9.9\r\nHost: h\r\n\r\n"),
    ("lowercase method", b"get /v1/policy HTTP/1.1\r\nHost: h\r\nX-EDR-Proto: 1\r\n\r\n"),
    ("absolute-form target", b"GET http://h/v1/policy HTTP/1.1\r\nHost: h\r\nX-EDR-Proto: 1\r\n\r\n"),
    ("header without a colon", b"GET /v1/policy HTTP/1.1\r\nHost h\r\nX-EDR-Proto: 1\r\n\r\n"),
    ("obs-fold continuation", b"GET /v1/policy HTTP/1.1\r\nHost: h\r\n  folded\r\nX-EDR-Proto: 1\r\n\r\n"),
    ("space in a header name", b"GET /v1/policy HTTP/1.1\r\nBad Name: v\r\nX-EDR-Proto: 1\r\n\r\n"),
    ("control byte in a value", b"GET /v1/policy HTTP/1.1\r\nX-A: a\x01b\r\nX-EDR-Proto: 1\r\n\r\n"),
    ("NUL in a value", b"GET /v1/policy HTTP/1.1\r\nX-A: a\x00b\r\nX-EDR-Proto: 1\r\n\r\n"),
    ("request line of 9000 bytes", b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\n\r\n"),
    ("path of 4000 bytes", b"GET /" + b"a" * 4000 + b" HTTP/1.1\r\nX-EDR-Proto: 1\r\n\r\n"),
    ("LF line endings only", b"GET /v1/policy HTTP/1.1\nHost: h\nX-EDR-Proto: 1\n\n"),
    ("path traversal", b"GET /v1/../v1/policy HTTP/1.1\r\nX-EDR-Proto: 1\r\n\r\n"),
    ("NUL in the path", b"GET /v1/policy%00 HTTP/1.1\r\nX-EDR-Proto: 1\r\n\r\n"),
    ("double slash", b"GET //v1/policy HTTP/1.1\r\nX-EDR-Proto: 1\r\n\r\n"),
    ("Content-Length 1e3", b"POST /v1/heartbeat HTTP/1.1\r\nContent-Length: 1e3\r\nX-EDR-Proto: 1\r\n\r\n"),
    ("Content-Length 0x10", b"POST /v1/heartbeat HTTP/1.1\r\nContent-Length: 0x10\r\nX-EDR-Proto: 1\r\n\r\n"),
    ("Content-Length 5, 5", b"POST /v1/heartbeat HTTP/1.1\r\nContent-Length: 5, 5\r\nX-EDR-Proto: 1\r\n\r\nhello"),
    ("Content-Length with plus", b"POST /v1/heartbeat HTTP/1.1\r\nContent-Length: +5\r\nX-EDR-Proto: 1\r\n\r\nhello"),
    ("X-EDR-Proto 1.0", b"GET /v1/policy HTTP/1.1\r\nX-EDR-Proto: 1.0\r\n\r\n"),
    ("Content-Encoding br on events", b"POST /v1/events HTTP/1.1\r\nContent-Encoding: br\r\nContent-Length: 3\r\nX-EDR-Proto: 1\r\n\r\nabc"),
    ("two request lines", b"GET /v1/policy HTTP/1.1\r\nGET /v1/policy HTTP/1.1\r\nX-EDR-Proto: 1\r\n\r\n"),
    ("a TLS record on the TLS stream", b"\x16\x03\x01\x00\x05hello"),
    ("pipelined second request", build("GET", "/v1/policy") + build("GET", "/v1/policy")),
]


@case("A13", "a corpus of malformed requests: none gets a 5xx or makes the hub drop a good request")
def a13():
    fa = CTX["fa"]
    seen = {}
    for label, data in CORPUS:
        r = fa.send(data, read_timeout=20)
        seen[label] = r.status
        check(r.status is None or r.status < 500, "%s: the hub answered %r" % (label, r))
        if r.status is not None:
            check(set(r.json or {}) <= {"error", "code", "index"} or r.status == 200, "%s: body is not the fixed error shape" % label)
    note("answers: " + ", ".join("%s" % (v,) for v in seen.values()))
    # the pipelined request gets one answer only: HTTP/1.0, one request per connection
    r = fa.send(build("GET", "/v1/policy") + build("GET", "/v1/policy"))
    check(r.raw.count(b"HTTP/1.0 ") == 1, "a pipelined second request got a second answer")
    expect(fa.heartbeat(), 200, what="heartbeat after the corpus")


# ---- checks: what is cut by a deadline (phase B, concurrently, each from its own source) --------

def within(label, got, low, high):
    check(got is not None, "%s: the connection was still open at the end of the wait" % label)
    check(low <= got <= high, "%s: cut after %.1f s, expected between %.1f and %.1f s" % (label, got, low, high))
    note("%s: cut after %.1f s" % (label, got))


@case("B1", "handshake deadline: a connection that sends nothing is cut at about 3 s")
def b1():
    s = tcp(CTX["hub"].port, fresh_source())
    try:
        within("handshake", closed_at(s, 12), 2.6, 4.5)
    finally:
        s.close()


@case("B2", "header block deadline: a request stalled in its headers is cut at about 5 s after the handshake")
def b2():
    ss = tls(CTX["hub"].port, CTX["fb"].ctx, fresh_source())
    try:
        ss.sendall(b"GET /v1/policy HTTP/1.1\r\nHost: hub\r\n")
        within("header block", closed_at(ss, 14), 4.4, 6.5)
    finally:
        ss.close()


def trickle(ss, prefix, limit_s):
    """Send `prefix`, then one byte a second, until the server closes. Returns (seconds, bytes sent)."""
    t0 = time.monotonic()
    ss.sendall(prefix)
    sent = len(prefix)
    ss.settimeout(1.0)
    while time.monotonic() - t0 < limit_s:
        try:
            ss.sendall(b"a")
            sent += 1
        except (ssl.SSLError, OSError):
            return time.monotonic() - t0, sent
        try:
            chunk = ss.recv(4096)
            if not chunk:
                return time.monotonic() - t0, sent
        except socket.timeout:
            continue
        except (ssl.SSLError, OSError):
            return time.monotonic() - t0, sent
    return None, sent


@case("B3", "trickle in the headers: one byte a second is cut by the wall-clock reaper at about 5 s")
def b3():
    ss = tls(CTX["hub"].port, CTX["fb"].ctx, fresh_source())
    try:
        got, sent = trickle(ss, b"GET /v1/policy HTTP/1.1\r\nHost: hub\r\nX-Slow: ", 20)
    finally:
        ss.close()
    within("header trickle (%d bytes sent)" % sent, got, 4.4, 7.5)


@case("B4", "whole-request deadline: complete headers and no body are cut at about 15 s")
def b4():
    ss = tls(CTX["hub"].port, CTX["fb"].ctx, fresh_source())
    try:
        ss.sendall(build("POST", "/v1/heartbeat", b"", [("Content-Type", "application/json")], clen="1000"))
        within("whole request", closed_at(ss, 25), 14.0, 17.5)
    finally:
        ss.close()


@case("B5", "trickle in the body: one byte a second is cut by the wall-clock reaper at about 15 s, not kept alive by per-read timeouts")
def b5():
    ss = tls(CTX["hub"].port, CTX["fb"].ctx, fresh_source())
    try:
        got, sent = trickle(ss, build("POST", "/v1/heartbeat", b"", [("Content-Type", "application/json")], clen="100000"), 40)
    finally:
        ss.close()
    within("body trickle (%d bytes sent)" % sent, got, 14.0, 17.5)


@case("B6", "whole-request deadline for a body near 1 MiB is 30 s")
def b6():
    ss = tls(CTX["hub"].port, CTX["fb"].ctx, fresh_source())
    try:
        ss.sendall(events_request(b"", clen=str(MIB - 1000)))
        within("big body", closed_at(ss, 40), 28.5, 33.0)
    finally:
        ss.close()


@case("B7", "enrollment: a request stalled after its headers is cut at about 5 s, not 15")
def b7():
    ss = tls(CTX["hub"].enroll_port, client_ctx(), fresh_source())
    try:
        ss.sendall(build("POST", "/v1/enroll", b"", [("Content-Type", "application/json")], clen="5000"))
        within("enrollment", closed_at(ss, 14), 4.4, 6.5)
    finally:
        ss.close()


# ---- checks: slots, per-source, per-certificate, memory (phase C, one after another) -----------

def settle():
    time.sleep(0.6)


def refused_at_once(s, wait=1.5):
    """True when the server closed the connection within `wait` seconds (accepted by the kernel, closed by the hub)."""
    got = closed_at(s, wait)
    return got is not None and got < wait


@case("C1", "slots: with 64 fleet connections open the 65th is closed at once; a freed slot is reused")
def c1():
    h = CTX["hub"]
    settle()
    held = []
    try:
        for _ in range(16):
            src = fresh_source()
            for _ in range(4):
                held.append(tcp(h.port, src))
        time.sleep(0.5)
        extra = tcp(h.port, fresh_source())
        try:
            check(refused_at_once(extra), "the 65th connection (a new source address, 64 open) was not closed at once")
        finally:
            extra.close()
        held.pop().close()
        time.sleep(0.5)
        again = tcp(h.port, fresh_source())
        try:
            check(not refused_at_once(again, 1.0), "after one of the 64 closed, a new connection was still refused")
        finally:
            again.close()
    finally:
        for s in held:
            s.close()


@case("C2", "slots: with 4 enrollment connections open the 5th is closed at once")
def c2():
    h = CTX["hub"]
    check(port_open(h.enroll_port), "the enrollment port is closed: no token is pending")
    settle()
    held = []
    try:
        for _ in range(4):
            held.append(tcp(h.enroll_port, fresh_source()))
        time.sleep(0.4)
        extra = tcp(h.enroll_port, fresh_source())
        try:
            check(refused_at_once(extra), "the 5th enrollment connection (a new source address) was not closed at once")
        finally:
            extra.close()
    finally:
        for s in held:
            s.close()


@case("C3", "slots per source: the 5th connection from one address is closed at once; another address is served")
def c3():
    h = CTX["hub"]
    settle()
    src = fresh_source()
    held = [tcp(h.port, src) for _ in range(4)]
    try:
        time.sleep(0.4)
        fifth = tcp(h.port, src)
        try:
            check(refused_at_once(fifth), "the 5th connection from one source address was not closed at once")
        finally:
            fifth.close()
        other = tcp(h.port, fresh_source())
        try:
            check(not refused_at_once(other, 1.0), "a connection from another address was refused while only one address is full")
        finally:
            other.close()
    finally:
        for s in held:
            s.close()


@case("C4", "requests per certificate: with 4 in flight the 5th gets 429 with Retry-After; the places come back")
def c4():
    h, fc = CTX["hub"], CTX["fc"]
    settle()
    held = []
    try:
        for _ in range(4):
            ss = tls(h.port, fc.ctx, fresh_source())
            ss.sendall(build("POST", "/v1/heartbeat", b"", [("Content-Type", "application/json")], clen="1000"))
            held.append(ss)
        time.sleep(0.8)
        expect(fc.heartbeat(), 429, "rate_limited", retry_after=True, what="the 5th request of one certificate")
        other = CTX["fa"].heartbeat()
        expect(other, 200, what="a request of another certificate meanwhile")
    finally:
        for ss in held:
            ss.close()
    time.sleep(1.0)
    expect(wait_until(lambda: (lambda r: r if r.status == 200 else None)(fc.heartbeat()), 8, 0.5) or fc.heartbeat(), 200,
           what="a heartbeat after the four were dropped (the places must come back)")


@case("C5", "memory: 30 connections with maximum-size header blocks keep the hub's RSS within the section 2 figure (about 220 MiB)")
def c5():
    h, fb = CTX["hub"], CTX["fb"]
    settle()
    pid = h.proc.pid
    base_rss, base_hwm = rss_kb(pid), rss_kb(pid, "VmHWM")
    lines = ["GET /v1/policy HTTP/1.1", "Host: hub", "X-EDR-Proto: 1"]
    # 31 header lines of about 260 bytes: the whole 8 KiB and 32-line budget, with no blank line so the request never ends
    while len("\r\n".join(lines)) < 8192 - 270:
        lines.append("X-Pad-%02d: %s" % (len(lines), "a" * 250))
    data = ("\r\n".join(lines) + "\r\n").encode()
    data += b"X-Last: " + b"a" * (8191 - len(data) - 8)
    check(8100 <= len(data) <= 8191, "test bug: the header block is %d bytes" % len(data))
    conns, peak = [], base_rss
    try:
        srcs = [fresh_source() for _ in range(8)]
        for i in range(30):
            ss = tls(h.port, fb.ctx, srcs[i // 4])
            ss.sendall(data)
            conns.append(ss)
        time.sleep(1.5)
        peak = max(rss_kb(pid), peak)
        time.sleep(1.0)
        peak = max(rss_kb(pid), peak)
    finally:
        for ss in conns:
            ss.close()
    time.sleep(0.5)
    hwm = rss_kb(pid, "VmHWM")
    note("RSS %.1f MiB before, %.1f MiB with 30 x %d-byte header blocks open, %.1f MiB high-water mark (all of this run so far); the plan's figure is about 220 MiB"
         % (base_rss / 1024, peak / 1024, len(data), hwm / 1024))
    CTX["rss"] = (base_rss, peak, hwm)
    check(peak < 220 * 1024, "RSS reached %.0f MiB, over the section 2 figure of 220 MiB" % (peak / 1024))
    check(peak - base_rss < 40 * 1024, "30 header blocks grew the RSS by %.0f MiB (the stdlib default grew it by about 190 MiB)" % ((peak - base_rss) / 1024))
    expect(CTX["fa"].heartbeat(), 200, what="heartbeat after the header flood")


# ---- checks: the database and the writer (phase D) ---------------------------------------------

def mediums(n, kb=3):
    """Fresh MEDIUM events with a few KiB of details: LOW and INFO would be pruned and rate-limited, these are not."""
    details = {"f%d" % i: "x" * 400 for i in range(kb * 2 // 3 + 1)}
    return [event("MEDIUM", "flood.fill", details=details) for _ in range(n)]


@case("D1", "storage: at the page cap LOW and INFO get 503, HIGH and CRITICAL go to critical-overflow.jsonl and get 200 after the append")
def d1():
    hb, sb = CTX["hubB"], CTX["sb"]
    expect(sb.heartbeat(), 200, what="a heartbeat before the fill")
    # Fill with fresh MEDIUM rows (the pressure prune keeps those for 14 days). When a batch no longer fits, halve it,
    # down to one event: what is left is less than one event, so any batch of 20 needs pages that do not exist.
    size, stored, full = 400, 0, None
    for _ in range(400):
        r = sb.events(mediums(size))
        if r.status == 200:
            stored += r.json.get("accepted", 0)
            continue
        full = r
        if size == 1:
            break
        size = max(1, size // 2)
    check(full is not None and size == 1, "the database never reached its cap after %d MEDIUM events (%s)" % (stored, hb.extra))
    expect(full, 503, "storage_full", retry_after=True, what="a MEDIUM event at the cap")
    note("cap reached after %d stored MEDIUM events; the database file is %d KiB" % (stored, os.path.getsize(hb.db) // 1024))
    low = [event("LOW" if i % 2 else "INFO", "flood.fill", details={"f%d" % j: "x" * 400 for j in range(3)}) for i in range(20)]
    expect(sb.events(low), 503, "storage_full", retry_after=True, what="a batch of 20 LOW and INFO events at the cap")
    hi = [event("HIGH" if i % 2 else "CRITICAL", "flood.high", details={"f%d" % j: "x" * 400 for j in range(3)}) for i in range(20)]
    ids_hi = [e["id"] for e in hi]
    path = os.path.join(hb.state, "critical-overflow.jsonl")
    check(not os.path.exists(path) or ids_hi[0] not in open(path).read(), "test bug: the overflow file already holds the events")
    r = sb.events(hi)
    expect(r, 200, what="a batch of 20 HIGH and CRITICAL events at the cap")
    check(r.json.get("accepted") == 20, "accepted %r of 20" % r.json)
    check(os.path.exists(path), "the reply was 200 but there is no critical-overflow.jsonl")
    text = open(path).read()
    check(all(i in text for i in ids_hi), "the 200 came before every event was in critical-overflow.jsonl")
    check(stat.S_IMODE(os.stat(path).st_mode) == 0o640, "critical-overflow.jsonl is %04o, not 0640" % stat.S_IMODE(os.stat(path).st_mode))
    rc, out, err = hb.cli("status")
    check(rc == 1 and re.search(r"storage:\s+storage (was )?full", out) and "critical-overflow.jsonl" in out,
          "`edr-hub status` does not show that storage is full (exit %d): %s" % (rc, tail(out, 500)))
    # a mixed batch: the HIGH events go to the file, the LOW events are dropped and counted
    mixed = low[:10] + [event("HIGH", "flood.high2", details={"f%d" % j: "x" * 400 for j in range(3)}) for _ in range(10)]
    r = sb.events(mixed)
    expect(r, 200, what="a mixed batch of 10 LOW and INFO and 10 HIGH events at the cap")
    check(r.json.get("dropped_low") == 10 and r.json.get("accepted") == 10, "the mixed batch answered %r" % r.json)
    stored_kinds = {e.get("kind") for e in hb.events(8000)}
    check("flood.high" not in stored_kinds and "flood.high2" not in stored_kinds, "the overflow events were also stored in the database")
    text = hb.log_text()
    check("hub.storage_full" in text and "storage state: storage_full" in text, "the hub log has no storage_full line (the alert from memory)")
    check(hb.alive(), "the hub with the full database died")
    check(wait_until(hb.health, 20, 1), "edr-hub health is not 0 on the hub with the full database")


def take_write_lock(hub):
    """Hold the database's write lock from this process (the writer thread then waits in BEGIN IMMEDIATE, up to 5 s)."""
    lock = sqlite3.connect(hub.db, timeout=1, isolation_level=None)
    for _ in range(30):
        try:
            lock.execute("BEGIN IMMEDIATE")
            return lock
        except sqlite3.OperationalError:
            time.sleep(0.2)
    lock.close()
    raise AssertionError("could not take the write lock on %s in 6 s" % hub.db)


@case("D1b", "storage: critical-overflow.jsonl is bounded at 20 MB; past the bound HIGH and CRITICAL get 503 too and the client keeps them")
def d1b():
    hb, sb = CTX["hubB"], CTX["sb"]
    path = os.path.join(hb.state, "critical-overflow.jsonl")
    before = os.path.getsize(path)
    last = None
    batches = 0
    for _ in range(80):
        r = sb.events([event("HIGH", "flood.fill", details={"f%d" % j: "x" * 400 for j in range(3)}) for _ in range(400)])
        batches += 1
        if r.status != 200:
            last = r
            break
    check(last is not None, "the overflow file never reached its bound after %d batches (%d bytes)" % (batches, os.path.getsize(path)))
    expect(last, 503, "storage_full", retry_after=True, what="a HIGH batch past the 20 MB bound")
    size = os.path.getsize(path)
    note("the file held %d bytes (from %d) after %d batches" % (size, before, batches))
    check(size <= 20 * MIB, "critical-overflow.jsonl grew to %d bytes, past 20 MiB" % size)
    check(size > 17 * MIB, "the 503 came at only %d bytes, well under the 20 MB bound" % size)
    low = [event("LOW", "flood.fill", details={"f%d" % j: "x" * 400 for j in range(3)}) for _ in range(20)]
    expect(sb.events(low), 503, "storage_full", retry_after=True, what="20 LOW events past the bound")
    check(hb.alive(), "the hub died")


@case("D3", "parsing slots: with 4 requests parsing and waiting for a stalled writer, the 5th gets 503 with Retry-After at once")
def d3():
    h = CTX["hub"]
    fa, fb, fc = CTX["fa"], CTX["fb"], CTX["fc"]
    expect(fc.heartbeat(), 200, what="control: a heartbeat before the lock")
    lock = take_write_lock(h)
    held = []
    try:
        threads = [threading.Thread(target=lambda who=who: held.append(who.heartbeat()), daemon=True) for who in (fa, fa, fb, fb)]
        for t in threads:
            t.start()
        time.sleep(1.2)
        check(not held, "the four requests were answered while the writer was blocked: %r" % held)
        t0 = time.monotonic()
        r = fc.heartbeat()
        took = time.monotonic() - t0
        expect(r, 503, "busy", retry_after=True, what="the 5th request parsing at once")
        check(took < 2.0, "the 5th request took %.1f s: it waited instead of being refused" % took)
        check(r.headers.get("retry-after") == "5", "Retry-After is %r, not 5" % r.headers.get("retry-after"))
    finally:
        lock.execute("ROLLBACK")
        lock.close()
    for t in threads:
        t.join(30)
    check(len(held) == 4 and all(x.status in (200, 503) for x in held), "the four held requests ended with %r" % held)
    check(wait_until(lambda: fc.heartbeat().status == 200, 30, 1), "the hub did not recover after the lock was released")


@case("D2", "writer stalled: with the database locked by another process and the queue full, every ingest route answers 503 with Retry-After and stores nothing")
def d2():
    h = CTX["hub"]
    fa, fe, fd = CTX["fa"], CTX["fe"], CTX["fd"]
    spare = h.cli_json("token", "create", "--name", "qtok-host", "--ttl", "1h")["tokens"][0]["token"]
    _, qcsr = make_key_and_csr(os.path.join(h.dir, "id-fd"), "q")
    # fd renews and then uses the new certificate: the old one is "superseded", and every 403 it gets from a new
    # source address posts one job for the writer (section 2, Checked on every fleet request; hub_ingest._note_rejected).
    r = fd.send(build("POST", "/v1/renew", json.dumps({"csr": CTX["fd_csr"]}).encode(), [("Content-Type", "application/json")]))
    expect(r, 200, what="renew")
    new_cert = os.path.join(h.dir, "id-fd", "renewed.pem")
    with open(new_cert, "w") as f:
        f.write(r.json["certificate"])
    fd_new = Ident(h, "fd", fd.uuid, new_cert, CTX["fd_key"], fd.droplet)
    expect(fd_new.policy(), 200, what="the renewed certificate's first request")
    expect(fd.policy(), 403, what="the old certificate after the renewed one was used")
    expect(fa.heartbeat(), 200, what="control: a heartbeat before the lock")
    log_before = h.log_text().count("route failed")
    probes_before = {e["id"] for e in h.events(8000)}

    spam_stop = threading.Event()
    spam_count = [0, 0]
    lock = take_write_lock(h)

    def spam():
        while not spam_stop.is_set():
            r = fd.send(build("GET", "/v1/policy"), read_timeout=10)
            spam_count[0 if r.status == 403 else 1] += 1
    threads = [threading.Thread(target=spam, daemon=True) for _ in range(16)]
    probes = {}
    try:
        for t in threads:
            t.start()
        check(wait_until(lambda: spam_count[0] >= 340, 30, 0.2), "only %d rejected requests were sent in 30 s (%d other answers)" % tuple(spam_count))
        t_start = time.monotonic()
        hi_events = [event("HIGH", "flood.q.high"), event("CRITICAL", "flood.q.critical")]
        lo_events = [event("LOW", "flood.q.low")]
        hb_body = heartbeat_request(fa.droplet)
        renew_req = build("POST", "/v1/renew", json.dumps({"csr": qcsr}).encode(), [("Content-Type", "application/json")])
        dereg_req = build("POST", "/v1/deregister", b'{"reason":"uninstall"}', [("Content-Type", "application/json")])
        key2, csr2 = make_key_and_csr(os.path.join(h.dir, "id-fd"), "q2")
        enroll_req = build("POST", "/v1/enroll", json.dumps({"token": ".".join(spare.split(".")[:2]), "csr": csr2, "hostname": "q", "os": "t", "ips": [],
                                                              "droplet_id": "flood-q"}).encode(), [("Content-Type", "application/json")])
        for label, fn in (("events HIGH+CRITICAL", lambda: fa.events(hi_events)), ("events LOW", lambda: fa.events(lo_events)),
                          ("heartbeat", lambda: fa.send(hb_body)), ("renew", lambda: fe.send(renew_req)),
                          ("deregister", lambda: fe.send(dereg_req)),
                          ("enroll", lambda: exchange(h.enroll_port, client_ctx(), enroll_req, fresh_source()))):
            t0 = time.monotonic()
            probes[label] = (fn(), time.monotonic() - t0)
        note("six probes took %.1f s while the writer was blocked" % (time.monotonic() - t_start))
    finally:
        spam_stop.set()
        lock.execute("ROLLBACK")
        lock.close()
        for t in threads:
            t.join(15)
    for label, (r, took) in probes.items():
        expect(r, 503, "busy", retry_after=True, what=label)
        check(took < 3.0, "%s took %.1f s: it waited for the writer instead of finding the queue full" % (label, took))
        check(r.headers.get("retry-after") == "5", "%s: Retry-After is %r, not the queue-full value 5" % (label, r.headers.get("retry-after")))
    check(len(probes) == 6, "only %d probes ran" % len(probes))
    check(h.log_text().count("route failed") == log_before,
          "a probe was queued behind the stalled writer (the hub logged 'route failed'): the queue was not full")
    # recovery, and nothing was stored by the refused requests
    ok = wait_until(lambda: (lambda r: r.status == 200)(fa.heartbeat()), 60, 1.0)
    check(ok, "the hub did not serve a heartbeat within 60 s after the lock was released")
    kinds = {e.get("kind") for e in h.events(8000)}
    check(not kinds & {"flood.q.high", "flood.q.critical", "flood.q.low"}, "a refused batch was stored")
    hosts = {x["name"]: x for x in h.cli_json("host", "list", "--all")}
    check(hosts["fe"]["state"] in ("pending", "active"), "the refused deregister retired the host (state %s)" % hosts["fe"]["state"])
    check("qtok-host" not in hosts, "the refused enrollment created a host")
    check(h.alive(), "the hub died")
    _ = probes_before


# ---- the end: the hub survived -----------------------------------------------------------------

@case("E1", "the hubs are alive, `edr-hub health` is 0, and a normal heartbeat and event batch from the valid certificate get 200")
def e1():
    for key in ("hub", "hubB"):
        h = CTX[key]
        check(h.alive(), "hub %s is not running (exit %r)" % (h.name, h.proc.poll()))
    h, fa = CTX["hub"], CTX["fa"]
    check(wait_until(h.health, 30, 1), "edr-hub health is not 0 (hub log tail: %s)" % tail(h.log_text()))
    expect(fa.heartbeat(), 200, what="a normal heartbeat")
    r = fa.events([event("INFO"), event("MEDIUM", "flood.after")])
    expect(r, 200, what="a normal event batch")
    check(r.json.get("accepted") == 2, "accepted %r of 2" % r.json)
    expect(fa.policy(), 200, what="a policy GET")
    check(wait_until(lambda: any(e.get("kind") == "flood.after" for e in h.events(8000)), 15, 1), "the event batch answered 200 is not in `edr-hub events`")
    note("hub RSS now %.1f MiB (high-water mark %.1f MiB)" % (rss_kb(h.proc.pid) / 1024, rss_kb(h.proc.pid, "VmHWM") / 1024))


# ---- setup and main ----------------------------------------------------------------------------

def setup():
    """Two hubs (the second with a small database cap), a CA of our own for the foreign certificate, enrolled hosts."""
    h = CTX["hub"] = Hub("h1")
    hb = CTX["hubB"] = Hub("h2", extra=["--max-db-size", "2M"])
    h.start()
    hb.start()
    for hub in (h, hb):
        ok = wait_until(hub.health, 60, 1)
        check(ok, "hub %s: edr-hub health never reached 0 (hub log: %s)" % (hub.name, tail(hub.log_text())))
        check(port_open(hub.port), "hub %s is not listening on its fleet port" % hub.name)
    # a spare token keeps the enrollment listener open for the whole run
    CTX["spare"] = h.cli_json("token", "create", "--name", "spare", "--ttl", "1h")["tokens"][0]["token"]
    for name in ("fa", "fb", "fc", "fd", "fe"):
        CTX[name] = enroll(h, name)
    CTX["sb"] = enroll(hb, "sb")
    # the overflow check sends thousands of HIGH events from one host: lift its bucket so that only the file bound can refuse
    rc, out, err = hb.cli("settings", "set", "rate_high_per_hour", "10000000")
    check(rc == 0, "settings set rate_high_per_hour: %s" % tail(err or out))
    d = os.path.join(h.dir, "id-fd")
    CTX["fd_key"], CTX["fd_csr"] = make_key_and_csr(d, "renew")
    # a client certificate from a CA the hub does not know
    od = os.path.join(BASE, "otherca")
    os.makedirs(od, mode=0o700)
    ca_key, ca_pem = os.path.join(od, "ca.key"), os.path.join(od, "ca.pem")
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", ca_key, "-out", ca_pem,
            "-subj", "/CN=other ca", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    key, csr = make_key_and_csr(od, "cli")
    csr_path = os.path.join(od, "cli.csr")
    ext = os.path.join(od, "cli.ext")
    with open(ext, "w") as f:
        f.write("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n")
    pem = os.path.join(od, "cli.pem")
    openssl("x509", "-req", "-in", csr_path, "-CA", ca_pem, "-CAkey", ca_key, "-CAcreateserial", "-days", "2", "-sha256",
            "-extfile", ext, "-out", pem)
    CTX["other_ctx"] = client_ctx(pem, key)


def cleanup():
    for key in ("hub", "hubB"):
        h = CTX.get(key)
        if h is not None:
            h.stop()
    for p in CHILDREN:
        if p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGTERM)
                p.wait(5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait(5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
    if BASE and os.path.isdir(BASE) and not os.environ.get("FLOOD_KEEP"):
        shutil.rmtree(BASE, ignore_errors=True)


def main():
    global BASE
    t_all = time.time()
    BASE = tempfile.mkdtemp(prefix="hubflood", dir="/tmp")
    os.chmod(BASE, 0o700)
    try:
        try:
            setup()
        except Exception as exc:
            RESULTS.append(("0", "setup", False, str(exc)))
            say("FAIL 0  setup: %s: %s" % (type(exc).__name__, str(exc)[:700]))
        else:
            say("PASS 0  two hubs started, five hosts enrolled on the first and one on the second (%.0fs)" % (time.time() - t_all))
            for c in (a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13):
                c()
            run_parallel([b1, b2, b3, b4, b5, b6, b7])
            for c in (c1, c2, c3, c4, c5, d1, d1b, d3, d2, e1):
                c()
    finally:
        cleanup()
    failed = [r for r in RESULTS if not r[2]]
    say("%d checks, %d passed, %d failed, %.0f s" % (len(RESULTS), len(RESULTS) - len(failed), len(failed), time.time() - t_all))
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
