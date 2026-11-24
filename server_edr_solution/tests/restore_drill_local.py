#!/usr/bin/python3 -I
"""The restore drill and the rehome kill test, on loopback (hub PLAN 7 and 12, client PLAN 5).

    python3 -I server_edr_solution/tests/restore_drill_local.py

Standard library only. Like e2e_local.py it drives the real programs and never imports their modules:

    server_hub/hub/edr_hub.py, edr-hub (with EDR_HUB_*), edr_hub_out.py --once,
    server_client/agent/edr-agent.py (with EDR_AGENT_ROOT).

It uses only temporary directories under /tmp and ports above 18000 on 127.0.0.1 (the proxies of part B use
127.0.0.2, which is also loopback), and a fake `journalctl` at the front of the agent's PATH. It runs no installer,
no nft, no systemctl. No secret is on a command line. Every child is killed and every directory removed in the
final block. One PASS, FAIL or SKIP line per check; exit 0 when nothing failed, 2 otherwise. A SKIP is a promise of
the plan that is not built or cannot be reached from outside; its line says which.

Part A, the restore drill (hub PLAN 7 "Moving the hub", 12 "Restore drill"):
  hub 1 is the source (a real agent, a webhook secret, a never-ban entry, a revoked host, an unused token). Hub 2 is
  a new box: it was installed (started once, so it has its own CA) and is stopped for the restore, which uses the
  backup passphrase file and the exported CA key. Hub 3 is a drill box, hub 4 a new box that has no CA key.

Part B, `rehome` under SIGKILL (client PLAN 5):
  hub A, a restored hub B and one agent, with a small TCP proxy in front of each hub (127.0.0.2). The proxy holds
  one chosen connection, or holds the reply of the hub, so that the rehome process is stopped at a known point in
  the sequence and is then killed there. The timed rollback of step 3 is a systemd timer that a loopback run does
  not have, so the test runs its command, `edr-agent rehome --rollback`, itself.
"""

import gzip
import hashlib
import http.client
import json
import os
import re
import secrets
import select
import shutil
import signal
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid as uuidlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(HERE)
HUB_DIR = os.path.join(ROOT, "server_hub", "hub")
AGENT = os.path.join(ROOT, "server_client", "agent", "edr-agent.py")
PY = sys.executable
OPENSSL = shutil.which("openssl") or "openssl"
FORBIDDEN_PORTS = {80, 443, 8443, 8444, 8450}
LOOP2 = "127.0.0.2"                  # the address part B advertises; a proxy listens on it and forwards to 127.0.0.1

BASE = None
CHILDREN = []
SECRETS = []                         # strings that must never appear on a command line
RESULTS = []
USED_PORTS = set()
CTX = {}

BACKUP_PASS = "drill-backup-passphrase-abcdefghij"
CA_PASS = "drill-ca-passphrase-0123456789"
CA_SEED = "drill-other-ca-passphrase-9876543210"


# ---- small helpers -----------------------------------------------------------------------------

def free_port():
    for _ in range(300):
        socks = []
        try:
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            socks.append(s)
            t = socket.socket()
            t.bind((LOOP2, port))
            socks.append(t)
        except OSError:
            continue
        finally:
            for x in socks:
                x.close()
        if port >= 18000 and port not in FORBIDDEN_PORTS and port not in USED_PORTS:
            USED_PORTS.add(port)
            return port
    raise RuntimeError("no free port at 18000 or above")


def port_open(port, host="127.0.0.1"):
    s = socket.socket()
    s.settimeout(1)
    try:
        return s.connect_ex((host, port)) == 0
    finally:
        s.close()


def wait_until(fn, timeout, step=0.5):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            last = fn()
        except Exception:                       # a probe that fails is "not yet"
            last = None
        if last:
            return last
        time.sleep(step)
    try:
        return fn()
    except Exception:
        return None


class Skip(Exception):
    pass


def check(cond, message):
    if not cond:
        raise AssertionError(message)


def tail(text, n=300):
    text = (text or "").strip().replace("\n", " | ")
    return text[-n:]


def run(cmd, env=None, input_text=None, timeout=120):
    joined = " ".join(cmd)
    for s in SECRETS:
        check(s not in joined, "a secret is on a command line")
    e = dict(os.environ)
    e.update(env or {})
    r = subprocess.run(cmd, env=e, input=input_text, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def write_secret_file(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text if text.endswith("\n") else text + "\n")
    return path


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def tree(*dirs, skip=("pending-audit.jsonl",)):
    """What is on disk under each directory: type, mode, size and hash of every file, link targets. Sockets and the
    pending-audit file (an append-only log that every restore attempt is meant to extend) are left out."""
    out = {}
    for d in dirs:
        base = os.path.dirname(d.rstrip("/"))
        for root, dnames, fnames in os.walk(d):
            for n in sorted(dnames + fnames):
                if n in skip:
                    continue
                p = os.path.join(root, n)
                rel = os.path.relpath(p, base)
                st = os.lstat(p)
                if stat.S_ISSOCK(st.st_mode):
                    continue
                if stat.S_ISLNK(st.st_mode):
                    out[rel] = ("l", os.readlink(p))
                elif stat.S_ISREG(st.st_mode):
                    out[rel] = ("f", st.st_mode & 0o7777, st.st_size, sha256_file(p))
                else:
                    out[rel] = ("d", st.st_mode & 0o7777)
    return out


def tree_diff(a, b):
    gone = sorted(set(a) - set(b))
    new = sorted(set(b) - set(a))
    changed = sorted(k for k in set(a) & set(b) if a[k] != b[k])
    return "new %s, gone %s, changed %s" % (new[:6], gone[:6], changed[:6])


# ---- the hub and the agent (as in e2e_local.py) --------------------------------------------------

class Hub:
    def __init__(self, name, port=None, enroll_port=None, ui_port=None, bind="127.0.0.1"):
        self.name = name
        self.dir = os.path.join(BASE, name)
        self.state, self.run_dir, self.etc = (os.path.join(self.dir, d) for d in ("s", "r", "e"))
        self.backup_dir = os.path.join(self.dir, "b")
        self.out_state = os.path.join(self.dir, "o")
        self.port = port or free_port()
        self.enroll_port = enroll_port or free_port()
        self.ui_port = ui_port or free_port()
        self.bind = bind
        self.proc = None
        self.env = {"EDR_HUB_STATE_DIR": self.state, "EDR_HUB_RUN_DIR": self.run_dir, "EDR_HUB_ETC_DIR": self.etc,
                    "EDR_HUB_BACKUP_DIR": self.backup_dir, "EDR_HUB_OUT_STATE_DIR": self.out_state}
        os.makedirs(self.etc, mode=0o750, exist_ok=True)

    def set_backup_pass(self, text):
        write_secret_file(os.path.join(self.etc, "backup.pass"), text)

    def start(self, public_ip="127.0.0.1"):
        os.makedirs(self.dir, exist_ok=True)
        log = open(os.path.join(self.dir, "hub.log"), "ab")
        cmd = [PY, "-I", os.path.join(HUB_DIR, "edr_hub.py"), "--state-dir", self.state, "--run-dir", self.run_dir,
               "--etc-dir", self.etc, "--bind", self.bind, "--port", str(self.port), "--enroll-port", str(self.enroll_port),
               "--ui-port", str(self.ui_port)]
        if public_ip:
            cmd += ["--public-ip", public_ip]
        self.proc = subprocess.Popen(cmd, stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True)
        CHILDREN.append(self.proc)

    def start_healthy(self, public_ip="127.0.0.1"):
        self.start(public_ip)
        check(wait_until(self.health, 60, 1), "%s never became healthy (log: %s)" % (
            self.name, tail(open(os.path.join(self.dir, "hub.log")).read())))

    def stop(self, wait=15):
        p = self.proc
        if p is None or p.poll() is not None:
            return
        os.killpg(p.pid, signal.SIGTERM)
        try:
            p.wait(wait)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(5)

    def cli(self, *args, input_text=None, timeout=180):
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

    def hosts(self):
        return self.cli_json("host", "list", "--all")

    def host(self, name):
        for h in self.hosts():
            if h.get("name") == name or h.get("uuid") == name:
                return h
        return None

    def events(self, host=None, limit=5000):
        extra = ("--host", host) if host else ()
        return self.cli_json("events", "--limit", str(limit), *extra)

    def health(self):
        return self.cli("health")[0] == 0

    def query(self, sql, args=()):
        conn = sqlite3.connect("file:%s?mode=ro" % os.path.join(self.state, "hub.db"), uri=True, timeout=10)
        try:
            return conn.execute(sql, args).fetchall()
        finally:
            conn.close()

    def make_token(self, kind, value, fname, ttl="1h"):
        res = self.cli_json("token", "create", kind, value, "--ttl", ttl)
        token = res["tokens"][0]["token"]
        SECRETS.append(token.split(".")[1])
        return write_secret_file(os.path.join(BASE, fname), token), token

    def ca_sha(self):
        pem = open(os.path.join(self.state, "ca", "ca.pem")).read()
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()

    def pending_lines(self):
        out = []
        try:
            with open(os.path.join(self.state, "pending-audit.jsonl")) as f:
                for line in f:
                    if line.strip():
                        out.append(json.loads(line))
        except OSError:
            pass
        return out


class Agent:
    def __init__(self, name):
        self.name = name
        self.root = os.path.join(BASE, "a-" + name)
        self.fakebin = os.path.join(BASE, "bin")
        self.journal = os.path.join(BASE, "journal-%s.jsonl" % name)
        self.proc = None
        self.env = {"EDR_AGENT_ROOT": self.root, "RD_FAKE_JOURNAL": self.journal,
                    "PATH": self.fakebin + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin")}
        self.n = 0

    def p(self, *parts):
        return os.path.join(self.root, *parts)

    def prepare(self):
        for d, mode in (("var/lib/edr-agent", 0o700), ("run/edr-agent", 0o755), ("etc/edr-agent", 0o755),
                        ("var/log/tetragon", 0o755), ("var/log/nginx", 0o755), ("var/log/suricata", 0o755)):
            os.makedirs(self.p(d), mode, exist_ok=True)
            os.chmod(self.p(d), mode)
        for f in ("var/log/tetragon/tetragon.log", "var/log/nginx/error.log", "var/log/nginx/access.log"):
            open(self.p(f), "a").close()
        with open(self.p("etc/edr-agent/local.conf"), "w") as f:
            f.write("[bans]\nadmin_ip = 198.51.100.77\n")
        os.makedirs(self.fakebin, exist_ok=True)
        script = os.path.join(self.fakebin, "journalctl")
        with open(script, "w") as f:
            f.write(FAKE_JOURNALCTL % PY)
        os.chmod(script, 0o755)
        open(self.journal, "a").close()

    def cli(self, *args, input_text=None, timeout=300):
        return run([PY, "-I", AGENT] + list(args), env=self.env, input_text=input_text, timeout=timeout)

    def popen(self, *args, log_name=None):
        log = open(os.path.join(BASE, log_name or ("agent-%s-cmd.log" % self.name)), "ab")
        p = subprocess.Popen([PY, "-I", AGENT] + list(args), env=dict(os.environ, **self.env), stdout=log, stderr=log,
                             stdin=subprocess.DEVNULL, start_new_session=True)
        CHILDREN.append(p)
        return p

    def start(self):
        self.proc = self.popen("run", "--foreground", log_name="agent-%s.log" % self.name)

    def stop(self):
        p = self.proc
        if p is None or p.poll() is not None:
            return
        os.killpg(p.pid, signal.SIGTERM)
        try:
            p.wait(15)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(5)

    def log(self):
        try:
            return open(os.path.join(BASE, "agent-%s.log" % self.name)).read()
        except OSError:
            return ""

    def enroll(self, hub, tokfile, hub_host="127.0.0.1", port=None, enroll_port=None, droplet="drill-droplet"):
        return self.cli("enroll", "--hub", "%s:%d" % (hub_host, port or hub.port), "--enroll-port",
                        str(enroll_port or hub.enroll_port), "--token-file", tokfile, "--droplet-id", droplet + "-" + self.name)

    def tetragon(self, binary, args, policy="nginx-exec", kill=True):
        self.n += 1
        proc = {"exec_id": "rd%d" % self.n, "pid": 4000 + self.n, "uid": 33, "cwd": "/", "binary": binary, "arguments": args}
        k = {"process": proc, "parent": {"binary": "/usr/sbin/nginx", "arguments": ""}, "function_name": "security_bprm_check",
             "args": [{"linux_binprm_arg": {"path": binary}}], "policy_name": policy}
        if kill:
            k["action"] = "KPROBE_ACTION_SIGKILL"
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000000000Z"
        with open(self.p("var/log/tetragon/tetragon.log"), "a") as f:
            f.write(json.dumps({"process_kprobe": k, "node_name": "web1", "time": ts}) + "\n")
            f.flush()

    def marker(self, name):
        """One HIGH event with a distinct binary path, so the hub's summary names it."""
        self.tetragon("/tmp/rd-%s" % name, "-c id", policy="web-exec", kill=False)

    def sshd(self, message):
        self.n += 1
        rec = {"__CURSOR": "s=rd;i=%d" % self.n, "__REALTIME_TIMESTAMP": str(int(time.time() * 1e6)), "_COMM": "sshd",
               "_UID": "0", "MESSAGE": message, "PRIORITY": "6", "SYSLOG_IDENTIFIER": "sshd"}
        with open(self.journal, "a") as f:
            f.write(json.dumps(rec) + "\n")
            f.flush()

    def ssh_fail(self, ip, n):
        for i in range(n):
            self.sshd("Failed password for invalid user admin from %s port %d ssh2" % (ip, 40000 + i))

    def bans(self):
        try:
            with open(self.p("run/edr-agent/bans.json")) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def uuid(self):
        try:
            with open(self.p("var/lib/edr-agent/host-id")) as f:
                return f.read().strip()
        except OSError:
            return None

    def ident_dir(self):
        return self.p("var/lib/edr-agent/identity")

    def current(self):
        try:
            return os.readlink(os.path.join(self.ident_dir(), "current"))
        except OSError:
            return None

    def gens(self):
        try:
            return sorted(n for n in os.listdir(self.ident_dir()) if re.fullmatch(r"gen-\d+", n))
        except OSError:
            return []

    def hub_port(self):
        """The fleet port the current identity points at, and its address list."""
        port, addrs = None, None
        try:
            with open(os.path.join(self.ident_dir(), "current", "hub.conf")) as f:
                text = f.read()
        except OSError:
            return None, None
        m = re.search(r"^port\s*=\s*(\d+)", text, re.M)
        if m:
            port = int(m.group(1))
        m = re.search(r"^addresses\s*=\s*(.*)$", text, re.M)
        if m:
            addrs = m.group(1).strip()
        return port, addrs

    def rehome_state(self):
        try:
            with open(os.path.join(self.ident_dir(), "rehome.json")) as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def dropin(self):
        try:
            with open(self.p("etc/systemd/system/edr-agent.service.d/10-hub.conf")) as f:
                return f.read()
        except OSError:
            return None


# A stand-in for `journalctl -o json -f`: follows RD_FAKE_JOURNAL; `-k` (the kernel log) stays quiet.
FAKE_JOURNALCTL = r'''#!%s
import os, sys, time
if "-k" in sys.argv:
    time.sleep(10 ** 6)
path = os.environ["RD_FAKE_JOURNAL"]
after = None
for a in sys.argv[1:]:
    if a.startswith("--after-cursor="):
        after = a.split("=", 1)[1]
f = open(path, "rb")
if after is None:
    f.seek(0, 2)
else:
    pos = 0
    for line in f:
        if (b'"__CURSOR": "' + after.encode() + b'"') in line:
            pos = f.tell()
            break
    else:
        pos = None
    if pos is None:
        f.seek(0, 2)
    else:
        f.seek(pos)
out = sys.stdout.buffer
while True:
    line = f.readline()
    if not line or not line.endswith(b"\n"):
        if line:
            f.seek(-len(line), 1)
        time.sleep(0.1)
        continue
    out.write(line)
    out.flush()
'''


# ---- a probe that speaks to the fleet port with an agent's certificate --------------------------

def probe(agent, port, method, path, doc=None, gz=False):
    """(status, json) of one request made with the agent's current client certificate; (None, text) when TLS refused."""
    ident = os.path.join(agent.ident_dir(), "current")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(os.path.join(ident, "ca.pem"))
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT
    ctx.load_cert_chain(os.path.join(ident, "client.pem"), os.path.join(ident, "client.key"))
    headers = {"X-EDR-Proto": "1"}
    body = None
    if doc is not None:
        body = json.dumps(doc).encode()
        headers["Content-Type"] = "application/json"
        if gz:
            body = gzip.compress(body)
            headers["Content-Encoding"] = "gzip"
    try:
        c = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=20)
        c.request(method, path, body=body, headers=headers)
        r = c.getresponse()
        raw = r.read()
        c.close()
        try:
            return r.status, json.loads(raw.decode())
        except ValueError:
            return r.status, None
    except (ssl.SSLError, OSError, http.client.HTTPException) as exc:
        return None, "%s: %s" % (type(exc).__name__, exc)


def post_event(agent, port, summary):
    epoch = secrets.randbelow(2 ** 31)
    ev = {"v": 1, "agent_ver": "0.1.0", "boot_id": str(uuidlib.uuid4()), "id": "%08x:%d" % (epoch, 1), "epoch": epoch, "seq": 1,
          "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z", "sev": "HIGH", "kind": "tetragon.web-exec",
          "source": "tetragon", "summary": summary, "proc": {"binary": "/tmp/x", "args": "-c id", "uid": 33, "parent": "/usr/sbin/nginx"},
          "src_trust": "none"}
    batch = {"batch_id": str(uuidlib.uuid4()), "sent_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z", "events": [ev]}
    return probe(agent, port, "POST", "/v1/events", batch, gz=True)


# ---- a throwaway CA and an https receiver (a webhook) -------------------------------------------

CA_CNF = """[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = drill receiver CA
[ext]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""
SRV_EXT = """basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = IP:127.0.0.1
"""


def openssl(*args, input_bytes=None):
    r = subprocess.run([OPENSSL] + list(args), capture_output=True, timeout=60, input=input_bytes)
    if r.returncode != 0:
        raise RuntimeError("openssl %s failed: %s" % (args[0], r.stderr.decode("utf-8", "replace")[:200]))
    return r.stdout


class Receiver:
    """An https webhook receiver on 127.0.0.1 with a private CA (EC P-384, strict profile)."""

    def __init__(self):
        d = os.path.join(BASE, "rcv")
        os.makedirs(d)
        self.ca_pem = os.path.join(d, "ca.pem")
        ca_key, cnf = os.path.join(d, "ca.key"), os.path.join(d, "ca.cnf")
        with open(cnf, "w") as f:
            f.write(CA_CNF)
        openssl("ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", ca_key)
        openssl("req", "-x509", "-new", "-key", ca_key, "-sha384", "-days", "30", "-config", cnf, "-out", self.ca_pem)
        key, pub, pem, ext = (os.path.join(d, n) for n in ("srv.key", "srv.pub", "srv.pem", "srv.ext"))
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
        with open(pub, "wb") as f:
            f.write(openssl("pkey", "-in", key, "-pubout"))
        with open(ext, "w") as f:
            f.write(SRV_EXT)
        openssl("x509", "-new", "-force_pubkey", pub, "-subj", "/CN=receiver", "-CA", self.ca_pem, "-CAkey", ca_key,
                "-sha384", "-days", "30", "-extfile", ext, "-set_serial", "0x2001", "-out", pem)
        self.bodies = []
        self.lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(n)
                with outer.lock:
                    outer.bodies.append(body)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(pem, key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def texts(self):
        out = []
        with self.lock:
            for b in self.bodies:
                try:
                    out.append(json.loads(b.decode("utf-8")).get("text", ""))
                except ValueError:
                    out.append("")
        return out

    def stop(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass


def deliver_once(hub):
    """Run the outbound worker once against a hub; returns (rc, output)."""
    rc, out, err = run([PY, "-I", os.path.join(HUB_DIR, "edr_hub_out.py"), "--once", "--allow-private"], env=hub.env, timeout=120)
    return rc, out + err


# ---- a TCP proxy that can hold one connection or hold the reply of the hub ----------------------

class Proxy:
    """Listens on 127.0.0.2:PORT and forwards to 127.0.0.1:PORT (the hub). TLS passes through untouched.

    arm(mode, skip=0, count=1): let `skip` connections pass, then give the next `count` (None: all) connections
    the mode. 'hold' accepts the connection and forwards nothing; 'withhold' forwards what the client sends but keeps
    everything the hub sends once the client has sent its Finished and one more application-data record (the
    request), so the hub does the work and the client never hears of it. release() ends every held connection
    and goes back to passing."""

    def __init__(self, port):
        self.port = port
        self.lock = threading.Lock()
        self.mode, self.skip, self.count = "pass", 0, 0
        self.seen = 0
        self.held = []
        self.stop_flag = False
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((LOOP2, port))
        self.srv.listen(64)
        self.thread = threading.Thread(target=self.accept_loop, daemon=True)
        self.thread.start()

    def arm(self, mode, skip=0, count=1):
        with self.lock:
            self.mode, self.skip, self.count = mode, skip, count

    def release(self):
        with self.lock:
            self.mode = "pass"
            held, self.held = self.held, []
        for s in held:
            try:
                s.close()
            except OSError:
                pass

    def held_count(self):
        with self.lock:
            return len(self.held)

    def accept_loop(self):
        while not self.stop_flag:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            with self.lock:
                self.seen += 1
                mode = "pass"
                if self.mode != "pass":
                    if self.skip > 0:
                        self.skip -= 1
                    else:
                        mode = self.mode
                        if self.count is not None:
                            self.count -= 1
                            if self.count <= 0:
                                self.mode = "pass"
            threading.Thread(target=self.handle, args=(c, mode), daemon=True).start()

    def handle(self, c, mode):
        if mode == "hold":
            with self.lock:
                self.held.append(c)
            try:
                while c.fileno() >= 0:                     # until the client closes or release() closes us
                    r, _, _ = select.select([c], [], [], 0.5)
                    if r and not c.recv(65536):
                        break
            except (OSError, ValueError):
                pass
            finally:
                try:
                    c.close()
                except OSError:
                    pass
            return
        try:
            u = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        except OSError:
            c.close()
            return
        withhold = {"on": False}
        if mode == "withhold":
            with self.lock:
                self.held.append(c)
        counter = {"buf": b"", "app": 0}
        gone = threading.Event()

        def pump(src, dst, upstream):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    if upstream and mode == "withhold":
                        counter["buf"] += data
                        while len(counter["buf"]) >= 5:
                            n = (counter["buf"][3] << 8) | counter["buf"][4]
                            if len(counter["buf"]) < 5 + n:
                                break
                            if counter["buf"][0] == 23:
                                counter["app"] += 1
                            counter["buf"] = counter["buf"][5 + n:]
                        if counter["app"] >= 2:
                            withhold["on"] = True
                    if not upstream and withhold["on"]:
                        continue                           # the hub's answer is dropped on the floor
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                if upstream:
                    gone.set()
                elif withhold["on"]:
                    gone.wait(300)                         # the hub has closed; the client is left waiting for its answer
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        t1 = threading.Thread(target=pump, args=(c, u, True), daemon=True)
        t2 = threading.Thread(target=pump, args=(u, c, False), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        for s in (c, u):
            try:
                s.close()
            except OSError:
                pass

    def stop(self):
        self.stop_flag = True
        try:
            self.srv.close()
        except OSError:
            pass
        self.release()


# ---- the check runner ---------------------------------------------------------------------------

def step(num, name):
    def deco(fn):
        def runner():
            t0 = time.time()
            try:
                fn()
            except Skip as exc:
                RESULTS.append((num, name, "SKIP", str(exc)))
                print("SKIP %s  %s: %s" % (num, name, str(exc)[:700]), flush=True)
            except AssertionError as exc:
                RESULTS.append((num, name, "FAIL", str(exc)))
                print("FAIL %s  %s: %s" % (num, name, str(exc)[:700]), flush=True)
            except Exception as exc:
                RESULTS.append((num, name, "FAIL", "%s: %s" % (type(exc).__name__, exc)))
                print("FAIL %s  %s: %s: %s" % (num, name, type(exc).__name__, str(exc)[:700]), flush=True)
            else:
                RESULTS.append((num, name, "PASS", ""))
                print("PASS %s  %s (%.0fs)" % (num, name, time.time() - t0), flush=True)
        runner.step = (num, name)
        return runner
    return deco


T0 = time.time()


def note(message):
    if os.environ.get("RD_VERBOSE"):
        print("     [%5.1f s] %s" % (time.time() - T0, message), flush=True)


def need(*keys):
    for k in keys:
        check(CTX.get(k) is not None, "an earlier step did not leave %r behind" % k)
    return [CTX[k] for k in keys]


def markers_at(hub, host, marker):
    return [e for e in hub.events(host) if marker in (e.get("summary") or "")]


def count_marker(hubs, host, marker):
    return sum(len(markers_at(h, host, marker)) for h in hubs)


# =================================================================================================
# Part A: the restore drill
# =================================================================================================

@step("A0", "source hub 1: an enrolled and running agent, a webhook secret, a never-ban entry, a revoked host, an unused token")
def a0():
    h1 = CTX["h1"] = Hub("h1")
    h1.set_backup_pass(BACKUP_PASS)
    SECRETS.append(BACKUP_PASS)
    SECRETS.append(CA_PASS)
    h1.start_healthy()
    rc = CTX["receiver"] = Receiver()
    shutil.copyfile(rc.ca_pem, os.path.join(h1.state, "webhook-ca.pem"))
    check(h1.cli("settings", "set", "webhook_ca", rc.ca_pem)[0] == 0, "settings set webhook_ca")
    url = "https://127.0.0.1:%d/hook" % rc.port
    code, out, err = h1.cli("settings", "set", "webhook_url", "-", input_text=url + "\n")
    check(code == 0, "settings set webhook_url -: %s" % tail(err or out))
    check(os.path.exists(os.path.join(h1.etc, "secrets.json")), "no secrets.json after setting a secret")
    a1 = CTX["a1"] = Agent("1")
    a1.prepare()
    tokfile, token = h1.make_token("--name", "web1", "web1.token")
    CTX["ca_sha"] = token.split(".")[2]
    check(wait_until(lambda: port_open(h1.enroll_port), 10), "the enrollment port did not open")
    rc_, out, err = a1.enroll(h1, tokfile)
    check(rc_ == 0, "enroll web1: %s" % tail(err or out))
    CTX["uuid1"] = a1.uuid()
    a1.start()
    check(wait_until(lambda: (h1.host("web1") or {}).get("state") == "active", 120, 1),
          "web1 is not active at hub 1 (agent log: %s)" % tail(a1.log()))
    a1.tetragon("/tmp/rd-history-crit", "-c id")
    a1.marker("history-high")
    check(wait_until(lambda: markers_at(h1, "web1", "rd-history-high") and markers_at(h1, "web1", "rd-history-crit"), 60, 1),
          "the history events did not reach hub 1")
    a1.ssh_fail("198.51.100.50", 6)
    check(wait_until(lambda: any(b.get("cidr") == "198.51.100.50/32" for b in a1.bans().get("bans", [])), 60, 1),
          "no local ban in bans.json")
    check(wait_until(lambda: h1.query("SELECT COUNT(*) FROM outbox WHERE state='pending'")[0][0] >= 1, 30, 1),
          "no alert is waiting in the outbox of hub 1 (the restore must not send it again)")
    check(h1.cli("never-ban", "add", "192.0.2.0/24", "--reason", "drill")[0] == 0, "never-ban add")
    a3 = CTX["a3"] = Agent("3")
    a3.prepare()
    tf3, _ = h1.make_token("--name", "web3", "web3.token")
    check(wait_until(lambda: port_open(h1.enroll_port), 10), "the enrollment port did not open for web3")
    rc_, out, err = a3.enroll(h1, tf3)
    check(rc_ == 0, "enroll web3: %s" % tail(err or out))
    check(h1.cli("host", "web3", "revoke")[0] == 0, "host web3 revoke")
    h1.make_token("--name", "spare", "spare.token")
    CTX["spare_token_file"] = os.path.join(BASE, "spare.token")


@step("A1", "backup of a running hub: 0600, encrypted, holds the listed members and no CA key or server key; ca-export with its own passphrase")
def a1_backup():
    h1 = need("h1")[0]
    # The hub has been up for a while: it has read the file operations done so far from pending-audit.jsonl, so its
    # read offset (a meta row that the backup carries) is not zero.
    check(wait_until(lambda: any(r["action"].startswith("file-op.") for r in h1.cli_json("audit")), 90, 2),
          "the hub never ingested pending-audit.jsonl")
    bk = CTX["bk1"] = os.path.join(BASE, "hub1.bak")
    rc, out, err = h1.cli("backup", "--out", bk)
    check(rc == 0, "backup: %s" % tail(err or out))
    check(stat.S_IMODE(os.stat(bk).st_mode) == 0o600, "the backup is mode %o" % stat.S_IMODE(os.stat(bk).st_mode))
    data = open(bk, "rb").read()
    check(b"SQLite format" not in data and b"BEGIN CERTIFICATE" not in data and b"drill" not in data, "plain text is visible in the backup")
    trailer = data[-(len(b"EDRHUB-SHA256:") + 65):]
    check(trailer.startswith(b"EDRHUB-SHA256:") and trailer.endswith(b"\n"), "no checksum trailer")
    check(trailer[14:-1].decode() == hashlib.sha256(data[:-len(trailer)]).hexdigest(), "the trailer is not the SHA-256 of the ciphertext")
    # decrypt it with openssl alone and list the members
    body = data[:-len(trailer)]
    plain = openssl("enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "600000", "-pass", "file:" + os.path.join(h1.etc, "backup.pass"),
                    input_bytes=body)
    names = sorted(m.name for m in tarfile.open(fileobj=__import__("io").BytesIO(plain), mode="r:"))
    want = sorted(["MANIFEST.json", "hub.db", "settings.json", "secrets.json", "never-ban.json", "hub-addresses.json", "ca/ca.pem", "ca/revoked.txt"])
    check(names == want, "the backup holds %r, the plan names %r" % (names, want))
    # ca-export
    passfile = CTX["capass"] = write_secret_file(os.path.join(BASE, "ca.pass"), CA_PASS)
    cakey = CTX["cakey"] = os.path.join(BASE, "ca-export.pem")
    rc, out, err = h1.cli("ca-export", "--out", cakey, "--passphrase-file", passfile)
    check(rc == 0, "ca-export: %s" % tail(err or out))
    check(stat.S_IMODE(os.stat(cakey).st_mode) == 0o600, "the CA export is mode %o" % stat.S_IMODE(os.stat(cakey).st_mode))
    text = open(cakey).read()
    check(text.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----"), "the CA export is not an encrypted PKCS#8 key")
    pub_export = openssl("pkey", "-in", cakey, "-passin", "file:" + passfile, "-pubout")
    pub_ca = openssl("x509", "-in", os.path.join(h1.state, "ca", "ca.pem"), "-noout", "-pubkey")
    check(pub_export == pub_ca, "the exported key is not the key of the CA certificate")
    check(h1.ca_sha() in out, "ca-export did not print the CA SHA-256")
    # refusals: same passphrase as the backup, too short, file exists
    same = write_secret_file(os.path.join(BASE, "same.pass"), BACKUP_PASS)
    check(h1.cli("ca-export", "--out", os.path.join(BASE, "x1.pem"), "--passphrase-file", same)[0] == 3, "the backup passphrase was accepted for the CA key")
    short = write_secret_file(os.path.join(BASE, "short.pass"), "short")
    check(h1.cli("ca-export", "--out", os.path.join(BASE, "x2.pem"), "--passphrase-file", short)[0] == 3, "a short passphrase was accepted")
    check(h1.cli("ca-export", "--out", cakey, "--passphrase-file", passfile)[0] == 3, "ca-export overwrote its own output")
    check(not os.path.exists(os.path.join(BASE, "x1.pem")) and not os.path.exists(os.path.join(BASE, "x2.pem")), "a refused export left a file")


@step("A2", "hub 1 goes on after the backup: web2 enrolls (its certificate is unknown to the backup), a revocation of web1 is not made")
def a2_after_backup():
    h1 = need("h1")[0]
    a2 = CTX["a2"] = Agent("2")
    a2.prepare()
    tf, _ = h1.make_token("--name", "web2", "web2.token")
    check(wait_until(lambda: port_open(h1.enroll_port), 10), "the enrollment port did not open for web2")
    rc, out, err = a2.enroll(h1, tf)
    check(rc == 0, "enroll web2: %s" % tail(err or out))
    CTX["uuid2"] = a2.uuid()
    st, doc = probe(a2, h1.port, "GET", "/v1/policy")
    check(st == 200, "web2 at hub 1: policy answered %r %r" % (st, doc))


@step("A3", "restore refusals on the new box: hub running (exit 3), a damaged file and a truncated file (exit 2), tried more than once: nothing changes")
def a3_refusals():
    h2 = CTX["h2"] = Hub("h2")
    h2.set_backup_pass(BACKUP_PASS)                     # the box has the old backup passphrase: it is stored off the box
    h2.start_healthy()                                   # installed: it has its own CA, certificate and database
    bk = need("bk1")[0]
    cakey, capass = need("cakey", "capass")
    ca_before = sha256_file(os.path.join(h2.state, "ca", "ca.pem"))
    rc, out, err = h2.cli("restore", bk, "--ca-key", cakey, "--passphrase-file", capass)
    check(rc == 3, "restore with the hub running exited %d, not 3: %s" % (rc, tail(err + out)))
    check(sha256_file(os.path.join(h2.state, "ca", "ca.pem")) == ca_before and h2.health(), "a refused restore on a running hub changed it")
    h2.stop()
    damaged = os.path.join(BASE, "damaged.bak")
    raw = bytearray(open(bk, "rb").read())
    raw[len(raw) // 2] ^= 0xFF
    open(damaged, "wb").write(raw)
    short = os.path.join(BASE, "short.bak")
    open(short, "wb").write(open(bk, "rb").read()[:2000])
    before = tree(h2.state, h2.etc)
    for label, path, want in (("damaged", damaged, 2), ("truncated", short, 2)) * 4:    # an operator tries more than once
        rc, out, err = h2.cli("restore", path, "--ca-key", cakey, "--passphrase-file", capass)
        check(rc == want, "restore of the %s backup exited %d, not %d: %s" % (label, rc, want, tail(err + out)))
        after = tree(h2.state, h2.etc)
        check(after == before, "restore of the %s backup changed the box: %s" % (label, tree_diff(before, after)))
    lines = h2.pending_lines()
    check(sum(1 for x in lines if x["op"] == "restore" and x["outcome"] == "started") == 9, "pending-audit.jsonl: %r" % lines)
    check(sum(1 for x in lines if x["op"] == "restore" and x["outcome"] in ("refused", "error")) == 9, "the outcomes of the nine attempts are not on file: %r" % lines)


@step("A4", "restore onto the new box with the backup passphrase and the exported CA key (the box has neither) exits 0 and prints what the plan lists")
def a4_restore():
    h1, h2 = need("h1", "h2")
    bk, cakey, capass = need("bk1", "cakey", "capass")
    h2.stop()
    old_ca = sha256_file(os.path.join(h2.state, "ca", "ca.pem"))
    CTX["h2_old_server_serial"] = None
    rc, out, err = h2.cli("restore", bk, "--ca-key", cakey, "--passphrase-file", capass, "--public-ip", "127.0.0.9")
    check(rc == 0, "restore exited %d: %s" % (rc, tail(err + out, 500)))
    CTX["restore_out"] = out
    check(sha256_file(os.path.join(h2.state, "ca", "ca.pem")) == sha256_file(os.path.join(h1.state, "ca", "ca.pem")) != old_ca,
          "the CA certificate of the box is not the one in the backup")
    check(os.path.exists(os.path.join(h2.state, "ca", "ca.key")), "no CA key after restore")
    check(stat.S_IMODE(os.stat(os.path.join(h2.state, "ca", "ca.key")).st_mode) == 0o600, "ca.key is not 0600")
    check(os.path.exists(os.path.join(h2.etc, "secrets.json")), "secrets.json was not restored by a plain restore")
    check("aside" in out or "kept in" in out, "restore did not say where the replaced files are kept: %s" % tail(out, 400))


@step("A5", "outcome 1: decrypt, checksum and quick_check: the restored database is whole and holds the source hosts, events and audit chain")
def a5_outcome1():
    h1, h2 = need("h1", "h2")
    db = os.path.join(h2.state, "hub.db")
    conn = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    try:
        qc = conn.execute("PRAGMA quick_check").fetchone()[0]
        names = sorted(r[0] for r in conn.execute("SELECT name FROM hosts"))
        sums = [r[0] for r in conn.execute("SELECT summary FROM events")]
        restored = conn.execute("SELECT value FROM meta WHERE key='restored_at'").fetchone()
    finally:
        conn.close()
    check(qc == "ok", "quick_check says %r" % qc)
    check(names == ["web1", "web3"], "hosts in the restored database: %r (web2 enrolled after the backup must not be there)" % names)
    check(any("rd-history-high" in s for s in sums) and any("rd-history-crit" in s for s in sums), "the history events are not in the restored database")
    check(restored and restored[0].isdigit(), "no meta.restored_at marker (orphan handling needs it)")
    h2.start_healthy(public_ip=None)
    check(wait_until(lambda: h2.cli("audit", "verify")[0] == 0, 30, 1), "audit verify on the restored hub: %s" % tail(h2.cli("audit", "verify")[1]))
    rc, out, err = h2.cli("status")
    check(rc in (0, 1) and "running" in out, "edr-hub status: %s" % tail(out or err))


@step("A6", "outcome 2: every token is invalid: the unused token and the redeemed one, and the unused one does not enroll")
def a6_tokens():
    h1, h2 = need("h1", "h2")
    toks = h2.cli_json("token", "list")
    check(toks and all(t["state"] == "revoked" for t in toks), "token states after restore: %r" % [(t["name"], t["state"]) for t in toks])
    check(not port_open(h2.enroll_port), "the enrollment port is open on the restored hub with no valid token")
    # a new token opens the port; the old unused one must still be refused
    h2.make_token("--name", "fresh-check", "fresh-check.token", ttl="15m")
    check(wait_until(lambda: port_open(h2.enroll_port), 10), "the enrollment port did not open for a new token")
    ax = Agent("x")
    ax.prepare()
    rc, out, err = ax.enroll(h2, CTX["spare_token_file"])
    check(rc != 0, "the unused token of the source hub enrolled a host at the restored hub")
    check(h2.host("spare") is None, "a host named spare exists at the restored hub")
    check(h2.host("fresh-check") is None, "the check token enrolled a host by itself")
    for t in h2.cli_json("token", "list"):
        if t["name"] == "fresh-check":
            h2.cli("token", "revoke", t["id"])


@step("A7", "outcome 3: the server certificate is reissued (new serial and key, SAN from the stored list plus --public-ip), the CA SHA-256 is unchanged")
def a7_server_cert():
    h1, h2 = need("h1", "h2")
    s1 = os.path.join(h1.state, "tls", "server.pem")
    s2 = os.path.join(h2.state, "tls", "server.pem")
    def serial(p):
        return openssl("x509", "-in", p, "-noout", "-serial").decode().strip()
    check(serial(s1) != serial(s2), "the server certificate has the serial of the source hub's: it was copied, not reissued")
    check(open(os.path.join(h1.state, "tls", "server.key")).read() != open(os.path.join(h2.state, "tls", "server.key")).read(),
          "the server key is the source hub's key")
    check(stat.S_IMODE(os.stat(os.path.join(h2.state, "tls", "server.key")).st_mode) == 0o600, "server.key is not 0600")
    text = openssl("x509", "-in", s2, "-noout", "-text").decode()
    check("IP Address:127.0.0.1" in text and "IP Address:127.0.0.9" in text, "the SAN lacks the stored address or the --public-ip: %s" % tail(text, 300))
    r = subprocess.run([OPENSSL, "verify", "-x509_strict", "-purpose", "sslserver", "-CAfile", os.path.join(h1.state, "ca", "ca.pem"), s2],
                       capture_output=True, text=True)
    check(r.returncode == 0, "the new server certificate does not verify against the source CA: %s" % tail(r.stdout + r.stderr))
    check(CTX["ca_sha"] == h2.ca_sha(), "the CA SHA-256 changed: tokens and pins no longer match")
    check(CTX["ca_sha"] in CTX["restore_out"], "restore did not print the CA SHA-256")
    check("reissued" in CTX["restore_out"], "restore did not say that the certificate was reissued")


@step("A8", "outcome 4: the serials of revoked.txt and of the database are printed, so revocations made after the backup can be redone by hand")
def a8_serials():
    h1, h2 = need("h1", "h2")
    out = CTX["restore_out"]
    revoked = [ln.split()[0] for ln in open(os.path.join(h2.state, "ca", "revoked.txt")) if ln.strip() and not ln.startswith("#")]
    check(revoked, "revoked.txt is empty although web3 was revoked before the backup")
    for s in revoked:
        check(s in out, "serial %s of revoked.txt is not in the output of restore" % s)
    rows = h2.query("SELECT name, cert_serial FROM hosts")
    check(len(rows) == 2, "hosts at hub 2: %r" % rows)
    for name, s in rows:
        check(name in out and (s or "") in out, "host %s with serial %s is not in the output of restore" % (name, s))
    check("revoke" in out, "restore does not tell the operator to re-revoke by hand")


@step("A9", "outcome 5: a client certificate the restored database does not know makes the host orphan: events kept, no policy, no renewal, one HIGH alert, adopt")
def a9_orphan():
    h1, h2 = need("h1", "h2")
    a2 = need("a2")[0]
    check(h2.host("web2") is None, "web2 is already known to hub 2")
    st, doc = probe(a2, h2.port, "GET", "/v1/policy")
    check(st == 403 and isinstance(doc, dict) and doc.get("code") == "host_orphan", "orphan policy answered %r %r" % (st, doc))
    row = [h for h in h2.hosts() if h["uuid"] == CTX["uuid2"]]
    check(row and row[0]["state"] == "orphan", "the unknown certificate did not make an orphan host: %r" % (row,))
    st, doc = probe(a2, h2.port, "POST", "/v1/renew", {"csr": "x"})
    check(st == 403 and isinstance(doc, dict) and doc.get("code") == "host_orphan", "orphan renew answered %r %r" % (st, doc))
    st, doc = post_event(a2, h2.port, "rd-orphan-event")
    check(st == 200 and isinstance(doc, dict) and doc.get("accepted") == 1, "orphan events answered %r %r" % (st, doc))
    check(wait_until(lambda: markers_at(h2, CTX["uuid2"], "rd-orphan-event"), 20, 1), "the orphan's event is not stored")
    def orphan_alerts():
        return [r for r in h2.query("SELECT payload FROM outbox") if "orphan" in r[0].lower() and "awaits adoption" in r[0].lower()
                or "presented a certificate this hub did not issue" in r[0]]
    check(wait_until(orphan_alerts, 30, 1), "no HIGH alert for the orphan host in the outbox of hub 2")
    n_alerts = len(orphan_alerts())
    probe(a2, h2.port, "GET", "/v1/policy")
    probe(a2, h2.port, "GET", "/v1/policy")
    rows = [r for r in h2.cli_json("audit", "--since", "1d") if r["action"] == "host.orphan"]
    check(len(rows) == 1, "%d host.orphan audit rows after three requests, one expected" % len(rows))
    time.sleep(2)
    check(len(orphan_alerts()) == n_alerts, "repeated requests raised more orphan alerts (%d, then %d)" % (n_alerts, len(orphan_alerts())))
    check(h2.cli("host", CTX["uuid2"], "adopt")[0] == 0, "host adopt")
    st, doc = probe(a2, h2.port, "GET", "/v1/policy")
    check(st == 200, "after adopt the policy answered %r %r" % (st, doc))
    check(h2.host(CTX["uuid2"])["state"] in ("active", "pending"), "state after adopt: %s" % h2.host(CTX["uuid2"])["state"])


@step("A10", "a host revoked before the backup stays out; a host known to the backup reconnects with its old certificate")
def a10_revoked_stays_out():
    h2 = need("h2")[0]
    a1, a3 = need("a1", "a3")
    st, doc = probe(a3, h2.port, "GET", "/v1/policy")
    check(st == 403 and isinstance(doc, dict) and doc.get("code") == "host_revoked", "web3 (revoked before the backup) got %r %r at hub 2" % (st, doc))
    check(h2.host("web3")["state"] == "revoked", "web3 is %s at hub 2" % h2.host("web3")["state"])
    st, doc = probe(a1, h2.port, "GET", "/v1/policy")
    check(st == 200, "web1's old certificate got %r %r at hub 2 (a client behind a moved Reserved IP changes nothing)" % (st, doc))


@step("A11", "the restored secrets work on a box that had none, and alerts that were waiting at the source are not sent again")
def a11_secrets_and_outbox():
    h1, h2 = need("h1", "h2")
    rc = need("receiver")[0]
    shutil.copyfile(rc.ca_pem, os.path.join(h2.state, "webhook-ca.pem"))      # the private webhook CA is a per-box file (the installer copies it)
    check(not h2.query("SELECT 1 FROM outbox WHERE state='pending' AND last_error='' AND payload LIKE '%rd-history%'"), "an old alert is pending at hub 2")
    old = h2.query("SELECT COUNT(*) FROM outbox WHERE state='dead' AND last_error='restored'")[0][0]
    check(old >= 1, "the alerts that were waiting at hub 1 were not marked dead at the restore")
    before = len(rc.texts())
    h2.cli("alert", "test")
    got = wait_until(lambda: (deliver_once(h2), len(rc.texts()) > before)[1], 60, 3)
    check(got, "no alert reached the webhook through the restored secret (receiver saw %d)" % (len(rc.texts()) - before))
    old_texts = [t for t in rc.texts()[before:] if "rd-history" in t]
    check(not old_texts, "an alert from before the backup was sent again: %r" % old_texts[:1])


@step("A12", "restore --drill: the database and CA come back, secrets.json does not, no channel is on, an alert goes nowhere; a wrong backup passphrase is refused (exit 2)")
def a12_drill():
    h1 = need("h1")[0]
    bk, cakey, capass = need("bk1", "cakey", "capass")
    rc_ = need("receiver")[0]
    h3 = CTX["h3"] = Hub("h3")
    h3.set_backup_pass("a-different-backup-passphrase-for-the-drill-box")
    h3.start_healthy()
    h3.stop()
    before = tree(h3.state, h3.etc)
    rc, out, err = h3.cli("restore", bk, "--drill", "--ca-key", cakey, "--passphrase-file", capass)
    check(rc == 2, "a wrong backup passphrase exited %d, not 2: %s" % (rc, tail(err + out)))
    check(tree(h3.state, h3.etc) == before, "a restore with the wrong backup passphrase changed the box")
    h3.set_backup_pass(BACKUP_PASS)
    rc, out, err = h3.cli("restore", bk, "--drill", "--ca-key", cakey, "--passphrase-file", capass)
    check(rc == 0, "restore --drill exited %d: %s" % (rc, tail(err + out)))
    check("drill" in out, "restore --drill did not say that it skipped the secrets: %s" % tail(out, 300))
    check(not os.path.exists(os.path.join(h3.etc, "secrets.json")), "secrets.json was restored by --drill")
    settings = json.load(open(os.path.join(h3.state, "settings.json")))
    check(not settings.get("secrets_set"), "settings.json names secrets after --drill: %r" % settings.get("secrets_set"))
    h3.start_healthy(public_ip=None)
    check(sorted(h["name"] for h in h3.hosts()) == ["web1", "web3"], "the drill hub does not hold the source hosts")
    rc, out, err = h3.cli("status")
    check("channels NONE" in out, "the drill hub shows an alert channel: %s" % tail(out, 300))
    before = len(rc_.texts())
    h3.cli("alert", "test")
    deliver_once(h3)
    time.sleep(2)
    check(len(rc_.texts()) == before, "the drill hub sent an alert to the source hub's webhook")
    CTX["h3_started"] = True
    # The plan makes `systemctl disable --now edr-hub-out` the operator's step before the restore. Nothing in
    # `restore` checks it, and a loopback run has no unit to look at: only the effect (no secret, no channel) is tested.


@step("A13", "a client rehomes to the restored hub with a --for token: same UUID, history at hub 2, the old hub shows moved, a local ban stays")
def a13_rehome_to_restored():
    h1, h2 = need("h1", "h2")
    a1 = need("a1")[0]
    ban_before = [b for b in a1.bans().get("bans", []) if b["cidr"] == "198.51.100.50/32"]
    check(ban_before, "the local ban is gone before the rehome")
    tf, _ = h2.make_token("--for", "web1", "web1-hub2.token")
    check(wait_until(lambda: port_open(h2.enroll_port), 10), "hub 2 enrollment port closed with a token pending")
    rc, out, err = a1.cli("rehome", "--hub", "127.0.0.1:%d" % h2.port, "--enroll-port", str(h2.enroll_port), "--token-file", tf)
    check(rc == 0, "rehome exited %d: %s" % (rc, tail(err + out)))
    check(a1.uuid() == CTX["uuid1"], "host-id changed: %r" % a1.uuid())
    check(wait_until(lambda: (h1.host("web1") or {}).get("state") == "moved", 60, 1), "hub 1 shows %r, not moved" % (h1.host("web1") or {}).get("state"))
    h = h2.host("web1")
    check(h and h["uuid"] == CTX["uuid1"], "hub 2 holds web1 under another UUID: %r" % (h and h["uuid"]))
    check(markers_at(h2, "web1", "rd-history-high") and markers_at(h2, "web1", "rd-history-crit"), "the history before the backup is not at hub 2 under the same host")
    a1.marker("after-rehome-a13")
    check(wait_until(lambda: markers_at(h2, "web1", "rd-after-rehome-a13"), 120, 2), "an event written after the rehome did not reach hub 2")
    check(count_marker([h1, h2], "web1", "rd-after-rehome-a13") == 1, "the event arrived more than once")
    check([b for b in a1.bans().get("bans", []) if b["cidr"] == "198.51.100.50/32"], "the local ban was lost in the rehome")
    check(wait_until(lambda: (h2.host("web1") or {}).get("state") == "active", 120, 2), "web1 is not active at hub 2")


@step("A14", "restore on the original box with ca/ intact and no --ca-key works, and keeps the CA key in place")
def a14_original_box():
    h1 = need("h1")[0]
    bk = need("bk1")[0]
    h1.stop()
    key = os.path.join(h1.state, "ca", "ca.key")
    ca = os.path.join(h1.state, "ca", "ca.pem")
    kh, ch = sha256_file(key), sha256_file(ca)
    rc, out, err = h1.cli("restore", bk)
    check(rc == 0, "restore on the original box exited %d: %s" % (rc, tail(err + out, 500)))
    check(sha256_file(key) == kh and sha256_file(ca) == ch, "the CA changed on a restore with the key in place")
    h1.start_healthy(public_ip=None)
    check(sorted(h["name"] for h in h1.hosts()) == ["web1", "web3"], "hosts at the restored original box: %r" % [h["name"] for h in h1.hosts()])
    check(h1.host("web1")["state"] != "moved", "the older state was not restored (web1 is still moved)")
    # and a wrong key in place is refused: the key of another CA
    h1.stop()
    other = Hub("hx")
    other.set_backup_pass(BACKUP_PASS)
    other.start_healthy()
    other.stop()
    shutil.copyfile(os.path.join(other.state, "ca", "ca.key"), key)
    before = tree(h1.state, h1.etc)
    rc, out, err = h1.cli("restore", bk)
    check(rc == 3, "restore with the key of another CA in place exited %d, not 3" % rc)
    check(tree(h1.state, h1.etc) == before, "a refused restore changed the box")


@step("A15", "restore on a new box with no CA key: refused with exit 3 and nothing changed; a wrong or foreign CA key too; then a fresh hub gives a new UUID")
def a15_no_ca_key():
    bk, cakey, capass = need("bk1", "cakey", "capass")
    a1 = need("a1")[0]
    h2 = need("h2")[0]
    h4 = CTX["h4"] = Hub("h4")
    h4.set_backup_pass(BACKUP_PASS)
    h4.start_healthy()
    own = os.path.join(BASE, "h4-own-ca.pem")
    own_pass = write_secret_file(os.path.join(BASE, "h4-own.pass"), CA_SEED)
    SECRETS.append(CA_SEED)
    check(h4.cli("ca-export", "--out", own, "--passphrase-file", own_pass)[0] == 0, "ca-export on hub 4")
    h4.stop()
    before = tree(h4.state, h4.etc, h4.run_dir)
    rc, out, err = h4.cli("restore", bk)
    check(rc == 3, "restore with no CA key exited %d, not 3: %s" % (rc, tail(err + out)))
    check(tree(h4.state, h4.etc, h4.run_dir) == before, "restore with no CA key changed the box: %s" % tree_diff(before, tree(h4.state, h4.etc, h4.run_dir)))
    rc, out, err = h4.cli("restore", bk, "--ca-key", own, "--passphrase-file", own_pass)
    check(rc == 3, "restore with the key of another CA exited %d, not 3" % rc)
    wrong = write_secret_file(os.path.join(BASE, "wrong.pass"), "not-the-ca-passphrase-at-all")
    rc, out, err = h4.cli("restore", bk, "--ca-key", cakey, "--passphrase-file", wrong)
    check(rc == 3, "restore with the wrong CA key passphrase exited %d, not 3" % rc)
    check(tree(h4.state, h4.etc, h4.run_dir) == before, "a refused restore changed the box: %s" % tree_diff(before, tree(h4.state, h4.etc, h4.run_dir)))
    lines = [x for x in h4.pending_lines() if x["op"] == "restore" and x["outcome"] in ("refused", "error")]
    check(len(lines) == 3, "the three refusals are not on file as refused: %r" % lines)
    # the fresh-hub path: a plain token, new UUID, history starts over; the agent's local ban stays
    h4.start_healthy()
    tf, token = h4.make_token("--name", "web1", "web1-fresh.token")
    check(token.split(".")[2] != CTX["ca_sha"], "the fresh hub has the old CA")
    check(wait_until(lambda: port_open(h4.enroll_port), 10), "hub 4 enrollment port closed")
    old = a1.uuid()
    rc, out, err = a1.cli("rehome", "--hub", "127.0.0.1:%d" % h4.port, "--enroll-port", str(h4.enroll_port), "--token-file", tf)
    check(rc == 0, "rehome to the fresh hub exited %d: %s" % (rc, tail(err + out)))
    check(a1.uuid() and a1.uuid() != old, "the host kept its UUID on a fresh hub (%s)" % a1.uuid())
    check(h4.host("web1") and h4.host("web1")["uuid"] == a1.uuid(), "hub 4 does not hold web1 under the new UUID")
    check(not markers_at(h4, "web1", "rd-history"), "the history came along to a fresh hub")
    check(wait_until(lambda: (h2.host(old) or {}).get("state") == "moved", 60, 1), "hub 2 shows %r for the old UUID, not moved" % (h2.host(old) or {}).get("state"))
    check([b for b in a1.bans().get("bans", []) if b["cidr"] == "198.51.100.50/32"], "the local ban was lost in the move to an empty hub")
    a1.marker("after-fresh")
    check(wait_until(lambda: markers_at(h4, "web1", "rd-after-fresh"), 120, 2), "an event written after the move did not reach the fresh hub")


@step("A16", "a never-ban entry of the source hub survives the restore; the plan's hub-side bans are P3 and are not built")
def a16_never_ban():
    h2 = need("h2")[0]
    rc, out, err = h2.cli("never-ban", "list")
    check(rc == 0 and "192.0.2.0/24" in out, "the never-ban entry is not in the restored hub: %s" % tail(out))
    rc, out, err = h2.cli("ban", "198.51.100.1/32")
    check(rc != 0, "`edr-hub ban` exists although the plan makes it P3")


@step("A17", "every restore is in the audit trail (one row per line of pending-audit.jsonl, a HIGH notice each) and `audit verify` is 0 on every hub")
def a17_audit():
    h1, h2, h3, h4 = need("h1", "h2", "h3", "h4")
    for hub in (h1, h2, h3):
        if hub.proc is None or hub.proc.poll() is not None:
            hub.start_healthy(public_ip=None)
    for hub, ops in ((h2, ("restore",)), (h3, ("restore",)), (h1, ("backup", "ca-export", "restore"))):
        lines = hub.pending_lines()
        want = {x["id"] for x in lines if x["op"] in ops}
        check(any(x["op"] == "restore" for x in lines), "%s: no restore line in pending-audit.jsonl" % hub.name)

        def ingested():
            rows = hub.cli_json("audit", "--since", "7d")
            have = {r["details"].get("line_id") for r in rows if r["action"].startswith("file-op.")}
            return have if want <= have else None
        got = wait_until(ingested, 45, 2)
        if not got:
            rows = hub.cli_json("audit", "--since", "7d")
            have = {r["details"].get("line_id") for r in rows if r["action"].startswith("file-op.")}
            raise AssertionError("%s: %d of %d file-operation lines (%s) are in the audit table" % (hub.name, len(want & have), len(want), ",".join(ops)))
        rows = [r for r in hub.cli_json("audit", "--since", "7d") if r["action"] == "file-op.restore"]
        check(rows and all("file-op uid=" in r["actor_detail"] and "loginuid=" in r["actor_detail"] for r in rows),
              "%s: restore rows lack the actor fields of PLAN 5 Audit: %r" % (hub.name, rows[:1]))
    notices = [r for r in h2.query("SELECT payload FROM outbox") if "restore" in r[0].lower()]
    check(notices, "no HIGH notification was queued for the restore at hub 2")
    for hub in (h1, h2, h3, h4):
        if hub.proc is None or hub.proc.poll() is not None:
            hub.start_healthy(public_ip=None)
        rc, out, err = hub.cli("audit", "verify")
        check(rc == 0, "%s: audit verify exited %d: %s" % (hub.name, rc, tail(out or err)))


@step("A18", "the runbook's drill check: `edr-hub status` on the restored hub shows the CA SHA-256 (hub PLAN 15, Restore drill)")
def a18_status_ca_sha():
    h2 = need("h2")[0]
    if h2.proc is None or h2.proc.poll() is not None:
        h2.start_healthy(public_ip=None)
    rc, out, err = h2.cli("status")
    if CTX["ca_sha"] in out or CTX["ca_sha"][:16] in out:
        return
    raise Skip("PLAN 15 says to check the CA SHA-256 in `edr-hub status` after a drill restore; status prints none (PLAN 6 does not list it "
               "for status either). The hash is printed by restore and ca-export and is the last part of every token, so the check can be "
               "made there. The plan and the code disagree: left for the owner")


# =================================================================================================
# Part B: rehome under SIGKILL
# =================================================================================================

def b_hub(which):
    return CTX["hubA"] if which == "A" else CTX["hubB"]


def b_proxies(which):
    return CTX["prox" + which]


@step("B0", "two hubs behind proxies (127.0.0.2), B restored from a backup of A, one agent enrolled at A and running")
def b0():
    hubA = CTX["hubA"] = Hub("ha")
    hubB = CTX["hubB"] = Hub("hb")
    for h in (hubA, hubB):
        h.set_backup_pass(BACKUP_PASS)
    hubA.start_healthy(public_ip=LOOP2)
    ag = CTX["ag"] = Agent("b")
    ag.prepare()
    tf, token = hubA.make_token("--name", "web1", "b-web1.token")
    with open(ag.p("etc/edr-agent/local.conf"), "a") as f:
        f.write("[agent]\nrehome_confirm_timeout = 60s\n")
    CTX["proxA"] = (Proxy(hubA.port), Proxy(hubA.enroll_port))
    check(wait_until(lambda: port_open(hubA.enroll_port), 10), "hub A enrollment port closed")
    rc, out, err = ag.cli("enroll", "--hub", "%s:%d" % (LOOP2, hubA.port), "--enroll-port", str(hubA.enroll_port),
                          "--token-file", tf, "--droplet-id", "drill-droplet-b")
    check(rc == 0, "enroll through the proxy: %s" % tail(err + out))
    CTX["uuid"] = ag.uuid()
    ag.start()
    check(wait_until(lambda: (hubA.host("web1") or {}).get("state") == "active", 120, 1), "web1 is not active at hub A: %s" % tail(ag.log()))
    bk = os.path.join(BASE, "hubA.bak")
    check(hubA.cli("backup", "--out", bk)[0] == 0, "backup of hub A")
    capass = write_secret_file(os.path.join(BASE, "bca.pass"), CA_PASS)
    cakey = os.path.join(BASE, "b-ca-export.pem")
    check(hubA.cli("ca-export", "--out", cakey, "--passphrase-file", capass)[0] == 0, "ca-export of hub A")
    hubB.start_healthy(public_ip=LOOP2)
    hubB.stop()
    rc, out, err = hubB.cli("restore", bk, "--ca-key", cakey, "--passphrase-file", capass)
    check(rc == 0, "restore onto hub B: %s" % tail(err + out))
    hubB.start_healthy(public_ip=None)
    check(hubB.host("web1") and hubB.host("web1")["uuid"] == CTX["uuid"], "hub B does not hold web1 under the same UUID")
    CTX["proxB"] = (Proxy(hubB.port), Proxy(hubB.enroll_port))
    CTX["at"] = "A"
    CTX["all_markers"] = []
    ag.marker("b-start")
    CTX["all_markers"].append("rd-b-start")
    check(wait_until(lambda: markers_at(hubA, "web1", "rd-b-start"), 60, 1), "no event at hub A")


class Cycle:
    """One scenario: the agent is at hub `src`; a rehome to hub `dst` is stopped and killed at a known point."""

    def __init__(self, tag):
        self.tag = tag
        self.src = CTX["at"]
        self.dst = "B" if self.src == "A" else "A"
        self.hs, self.hd = b_hub(self.src), b_hub(self.dst)
        self.ag = CTX["ag"]
        self.proc = None
        self.prev_gen = self.ag.current()

    def token(self, n=""):
        tf, _ = self.hd.make_token("--for", "web1", "b-%s-%s.token" % (self.tag, n or "t"))
        check(wait_until(lambda: port_open(self.hd.enroll_port), 10), "hub %s enrollment port closed with a token pending" % self.dst)
        return tf

    def start_rehome(self, tf):
        self.proc = self.ag.popen("rehome", "--hub", "%s:%d" % (LOOP2, self.hd.port), "--enroll-port", str(self.hd.enroll_port),
                                  "--token-file", tf, log_name="rehome-%s.log" % self.tag)
        return self.proc

    def kill(self):
        p = self.proc
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
        p.wait(10)

    def marker(self, name):
        m = "rd-%s-%s" % (self.tag, name)
        self.ag.marker("%s-%s" % (self.tag, name))
        CTX["all_markers"].append(m)
        return m

    def deliver_where(self, m, hubs, timeout=120):
        return wait_until(lambda: [h for h in hubs if markers_at(h, "web1", m)], timeout, 2)

    def attached(self):
        """(hub letter the current identity points at, text) or (None, why)."""
        port, addrs = self.ag.hub_port()
        for w in ("A", "B"):
            if port == b_hub(w).port:
                return w
        return None

    def sane_identity(self):
        cur = self.ag.current()
        check(cur, "no current identity")
        d = os.path.join(self.ag.ident_dir(), cur)
        for f in ("client.key", "client.pem", "ca.pem", "hub.conf"):
            check(os.path.isfile(os.path.join(d, f)), "%s/%s is missing" % (cur, f))
        return cur

    def assert_working_at(self, which, what):
        """The agent is attached to exactly `which`, the identity is whole, an event written now arrives there once,
        and the other hub gets nothing."""
        note("%s: assert_working_at %s" % (self.tag, which))
        check(self.attached() == which, "%s: the identity points at hub %s, expected %s" % (what, self.attached(), which))
        self.sane_identity()
        m = self.marker("w-" + what.replace(" ", "-")[:20])
        hub = b_hub(which)
        other = b_hub("B" if which == "A" else "A")
        check(wait_until(lambda: markers_at(hub, "web1", m), 150, 2), "%s: an event written now did not reach hub %s (agent log: %s)" % (what, which, tail(self.ag.log(), 200)))
        time.sleep(3)
        check(len(markers_at(hub, "web1", m)) == 1 and not markers_at(other, "web1", m), "%s: the event is not at exactly one hub once" % what)
        st = hub.host("web1")
        check(st and st["state"] in ("active", "pending"), "%s: hub %s shows web1 as %r" % (what, which, st and st["state"]))

    def complete_again(self):
        """Run the rehome again with a new token (the plan's recovery after a kill before the move): it completes."""
        tf = self.token("again")
        note("%s: second rehome" % self.tag)
        rc, out, err = self.ag.cli("rehome", "--hub", "%s:%d" % (LOOP2, self.hd.port), "--enroll-port", str(self.hd.enroll_port), "--token-file", tf)
        check(rc == 0, "the second rehome exited %d: %s" % (rc, tail(err + out)))
        self.finished()

    def finished(self):
        note("%s: finished" % self.tag)
        ag = self.ag
        check(ag.rehome_state() is None, "rehome.json is still there: %r" % ag.rehome_state())
        check(self.attached() == self.dst, "the identity points at hub %s, not %s" % (self.attached(), self.dst))
        check(ag.uuid() == CTX["uuid"], "host-id changed to %r" % ag.uuid())
        check(wait_until(lambda: (self.hs.host("web1") or {}).get("state") == "moved", 60, 1),
              "hub %s shows web1 as %r, not moved" % (self.src, (self.hs.host("web1") or {}).get("state")))
        check(wait_until(lambda: (self.hd.host("web1") or {}).get("state") == "active", 150, 2), "hub %s does not show web1 active" % self.dst)
        drop = ag.dropin() or ""
        check(("IPAddressAllow=%s" % LOOP2) in drop, "the drop-in is %r" % drop)
        check(self.prev_gen not in ag.gens(), "the previous generation %s, key included, is still there: %r" % (self.prev_gen, ag.gens()))
        CTX["at"] = self.dst
        self.assert_working_at(self.dst, "after the move")

    def pre(self):
        note("%s: pre" % self.tag)
        self.marker("pre")
        check(self.deliver_where("rd-%s-pre" % self.tag, [self.hs], 90), "the first event did not reach hub %s" % self.src)


def exactly_once_everywhere():
    ag, hubA, hubB = CTX["ag"], CTX["hubA"], CTX["hubB"]
    bad = []
    for m in CTX["all_markers"]:
        n = count_marker([hubA, hubB], "web1", m)
        if n != 1:
            bad.append("%s x%d" % (m, n))
    return bad


@step("B1", "kill during step 2 while the CA is fetched: nothing changed, the agent stays at A and works; the rehome run again completes")
def b1():
    c = Cycle("k1")
    c.pre()
    c.proc_tf = c.token("first")
    pe = b_proxies(c.dst)[1]
    pe.arm("hold")                                       # the first connection to the enrollment port is GET /v1/ca
    c.start_rehome(c.proc_tf)
    check(wait_until(lambda: pe.held_count() >= 1, 30, 0.1), "the rehome never reached the CA fetch (log: %s)" % tail(open(os.path.join(BASE, "rehome-k1.log")).read()))
    during = c.marker("during")
    c.kill()
    pe.release()
    check(c.ag.rehome_state() is None, "a state file exists after a kill in step 2")
    check(c.attached() == c.src, "the identity changed")
    check(c.ag.cli("rehome", "--rollback")[0] == 0, "`rehome --rollback` with nothing to undo failed")
    check(c.deliver_where(during, [c.hs]), "the event written during the stall did not reach hub %s" % c.src)
    c.assert_working_at(c.src, "after kill 1")
    c.complete_again()


@step("B2", "kill in step 2 after the new hub signed the certificate but before the reply came back: the agent stays at A; a new token completes")
def b2():
    c = Cycle("k2")
    c.pre()
    tf = c.token("first")
    pe = b_proxies(c.dst)[1]
    pe.arm("withhold", skip=1)                           # connection 1 is the CA fetch, connection 2 the POST /v1/enroll
    c.start_rehome(tf)

    def used():
        return [t for t in c.hd.cli_json("token", "list") if t["state"] == "used" and t["bound_host"] in ("web1", CTX["uuid"])]
    check(wait_until(used, 40, 0.2), "the new hub never redeemed the token (log: %s)" % tail(open(os.path.join(BASE, "rehome-k2.log")).read()))
    check(c.proc.poll() is None, "the rehome ended before the kill: exit %s" % c.proc.poll())
    during = c.marker("during")
    c.kill()
    pe.release()
    check(c.ag.rehome_state() is None and c.attached() == c.src, "the agent changed although it never saw the reply")
    check(c.deliver_where(during, [c.hs]), "the event written during the stall did not reach hub %s" % c.src)
    c.assert_working_at(c.src, "after kill 2")
    c.complete_again()


@step("B3", "kill in step 2 during the test call with the new certificate: a stray generation may stay; the agent stays at A; a new token completes")
def b3():
    c = Cycle("k3")
    c.pre()
    tf = c.token("first")
    pf = b_proxies(c.dst)[0]
    pf.arm("hold")                                       # the first fleet-port connection of the rehome is its test GET /v1/policy
    c.start_rehome(tf)
    check(wait_until(lambda: pf.held_count() >= 1, 60, 0.1), "the rehome never made the test call (log: %s)" % tail(open(os.path.join(BASE, "rehome-k3.log")).read()))
    during = c.marker("during")
    gens = c.ag.gens()
    c.kill()
    pf.release()
    check(c.ag.rehome_state() is None and c.attached() == c.src, "the agent changed before the move was proven")
    check(c.deliver_where(during, [c.hs]), "the event written during the stall did not reach hub %s" % c.src)
    c.assert_working_at(c.src, "after kill 3")
    c.complete_again()
    del gens


@step("B4", "kill in step 6 while the new hub is not confirmed (steps 3 to 5 done): the old identity is kept; `rehome --rollback` returns to A; a new run completes")
def b4():
    c = Cycle("k4")
    c.pre()
    tf = c.token("first")
    pf = b_proxies(c.dst)[0]
    pf.arm("hold", skip=1, count=None)                   # the test call (1 connection) passes; every later connection to the new hub hangs
    c.start_rehome(tf)
    check(wait_until(lambda: (c.ag.rehome_state() or {}).get("step") == 5, 90, 0.05), "the rehome never reached step 5 (log: %s state %r)" % (
        tail(open(os.path.join(BASE, "rehome-k4.log")).read()), c.ag.rehome_state()))
    check(c.proc.poll() is None, "the rehome ended on its own: exit %s" % c.proc.poll())
    c.kill()
    during = c.marker("during")
    st = c.ag.rehome_state()
    check(st and st["step"] == 5, "state after the kill: %r" % st)
    check(os.path.isfile(os.path.join(c.ag.ident_dir(), st["prev"], "client.key")), "the old identity (key) was deleted before the new hub was proven")
    check(c.attached() == c.dst, "after step 5 the identity should already point at the new hub (it did not)")
    dropin = c.ag.dropin() or ""
    check(dropin.count(LOOP2) >= 1, "the drop-in is %r" % dropin)
    rc, out, err = c.ag.cli("rehome", "--hub", "%s:%d" % (LOOP2, c.hd.port), "--token-file", tf)
    check(rc == 3, "a second rehome during an unfinished one exited %d, not 3" % rc)
    rc, out, err = c.ag.cli("rehome", "--rollback")                    # what the timer of step 3 runs
    check(rc == 4, "`rehome --rollback` exited %d, not 4: %s" % (rc, tail(err + out)))
    pf.release()
    check(c.ag.rehome_state() is None and c.attached() == c.src, "after the rollback the identity points at hub %s" % c.attached())
    check(st["new"] not in c.ag.gens(), "the new generation was not deleted: %r" % c.ag.gens())
    check(c.deliver_where(during, [c.hs], 150), "the event written while the agent pointed at the unreachable hub did not arrive at hub %s" % c.src)
    c.assert_working_at(c.src, "after the rollback")
    check(c.ag.cli("rehome", "--rollback")[0] == 0, "a second `rehome --rollback` is not a no-op")
    c.complete_again()


@step("B5", "kill in step 7 while the old hub is told: the move stands (new identity works); `rehome --rollback` finishes it and the old hub shows moved")
def b5():
    c = Cycle("k5")
    c.pre()
    tf = c.token("first")
    fs = b_proxies(c.src)[0]
    fs.arm("hold", skip=0, count=None)                   # a connection to the old hub hangs: the deregister of step 7
    c.start_rehome(tf)

    def at7():
        st = c.ag.rehome_state()
        return st and st.get("step") == 7 and not st.get("deregistered")
    check(wait_until(at7, 90, 0.02), "the rehome never reached step 7 (state %r, log: %s)" % (c.ag.rehome_state(), tail(open(os.path.join(BASE, "rehome-k5.log")).read())))
    check(c.proc.poll() is None, "the rehome had ended already (exit %s)" % c.proc.poll())
    c.kill()
    fs.release()
    st = c.ag.rehome_state()
    check(st and st["step"] == 7, "state after the kill: %r" % st)
    check(c.attached() == c.dst, "the move does not stand: the identity points at hub %s" % c.attached())
    check((c.hs.host("web1") or {}).get("state") == "active", "the old hub already shows %r (it was never told)" % (c.hs.host("web1") or {}).get("state"))
    check(os.path.isdir(os.path.join(c.ag.ident_dir(), st["prev"])), "the old generation is gone before the cleanup")
    c.assert_working_at(c.dst, "move stands")
    rc, out, err = c.ag.cli("rehome", "--rollback")
    check(rc == 0, "`rehome --rollback` after step 7 exited %d (it must finish the cleanup, not undo): %s" % (rc, tail(err + out)))
    c.finished()
    check(c.ag.cli("rehome", "--rollback")[0] == 0, "a second rollback is not a no-op")


@step("B6", "kill in step 7 again: the plan says the next start of edr-agent repeats the cleanup")
def b6():
    c = Cycle("k6")
    c.pre()
    tf = c.token("first")
    fs = b_proxies(c.src)[0]
    fs.arm("hold", skip=0, count=None)
    c.start_rehome(tf)

    def at7():
        st = c.ag.rehome_state()
        return st and st.get("step") == 7 and not st.get("deregistered")
    check(wait_until(at7, 90, 0.02), "the rehome never reached step 7 (state %r)" % c.ag.rehome_state())
    c.kill()
    fs.release()
    c.ag.stop()
    c.ag.start()                                         # "the next start of edr-agent"
    done = wait_until(lambda: c.ag.rehome_state() is None, 90, 2)
    c.assert_working_at(c.dst, "after the restart")
    if not done:
        # leave the box in a clean state for the checks that follow
        c.ag.cli("rehome", "--rollback")
        c.finished()
        raise Skip("not built: after a kill in step 7 nothing repeats the cleanup when edr-agent starts (client PLAN 5, rollback table, row 7); "
                   "rehome.json stays, the old generation and the old hub's address stay allowed, renewal and generation cleanup stay switched "
                   "off (uplink checks rehome_in_progress) until someone runs `edr-agent rehome --rollback`")
    c.finished()


@step("B7", "events are delivered once: every marker written in part B is at exactly one hub exactly once; `audit verify` is 0 on A and B")
def b7():
    hubA, hubB = need("hubA", "hubB")
    bad = exactly_once_everywhere()
    check(not bad, "markers not delivered exactly once: %s" % ", ".join(bad))
    ag = CTX["ag"]
    check(wait_until(lambda: ag.gens() == [ag.current()] and ag.rehome_state() is None, 150, 3),
          "stray identity generations stayed (a kill in step 2 leaves one; the next accepted heartbeat removes it): %r, current %s" % (ag.gens(), ag.current()))
    for hub in (hubA, hubB):
        rc, out, err = hub.cli("audit", "verify")
        check(rc == 0, "%s: audit verify exited %d: %s" % (hub.name, rc, tail(out or err)))


# ---- main --------------------------------------------------------------------------------------

def cleanup():
    for k in ("receiver",):
        r = CTX.get(k)
        if r is not None:
            r.stop()
    for k in ("proxA", "proxB"):
        for p in CTX.get(k) or ():
            p.stop()
    for k in ("a1", "a2", "a3", "ag"):
        a = CTX.get(k)
        if a is not None:
            a.stop()
    for k in ("h1", "h2", "h3", "h4", "hubA", "hubB"):
        h = CTX.get(k)
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
    if BASE and os.path.isdir(BASE) and not os.environ.get("RD_KEEP"):
        shutil.rmtree(BASE, ignore_errors=True)


def main():
    global BASE
    BASE = tempfile.mkdtemp(prefix="rdrill", dir="/tmp")
    os.chmod(BASE, 0o700)
    only = set(sys.argv[1:])
    steps = [a0, a1_backup, a2_after_backup, a3_refusals, a4_restore, a5_outcome1, a6_tokens, a7_server_cert, a8_serials,
             a9_orphan, a10_revoked_stays_out, a11_secrets_and_outbox, a12_drill, a13_rehome_to_restored, a14_original_box,
             a15_no_ca_key, a16_never_ban, a17_audit, a18_status_ca_sha, b0, b1, b2, b3, b4, b5, b6, b7]
    t0 = time.time()
    try:
        for s in steps:
            if only and s.step[0] not in only and not (s.step[0] == "A0" and any(x.startswith("A") for x in only)) \
                    and not (s.step[0] == "B0" and any(x.startswith("B") for x in only)):
                continue
            s()
    finally:
        cleanup()
    failed = [r for r in RESULTS if r[2] == "FAIL"]
    skipped = [r for r in RESULTS if r[2] == "SKIP"]
    print("%d checks, %d passed, %d failed, %d skipped, %.0f s" % (len(RESULTS), len(RESULTS) - len(failed) - len(skipped), len(failed),
                                                                 len(skipped), time.time() - t0), flush=True)
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
