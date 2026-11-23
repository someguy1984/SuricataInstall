#!/usr/bin/python3 -I
"""End-to-end check of the real hub and the real agent on loopback.

    python3 -I server_edr_solution/tests/e2e_local.py

Standard library only. It drives the real programs and never imports their modules:

    server_hub/hub/edr_hub.py, edr-hub (with EDR_HUB_*), edr_hub_ui.py, edr_hub_out.py --once,
    server_client/agent/edr-agent.py (with EDR_AGENT_ROOT).

It uses only temporary directories under /tmp, ports above 18000 on 127.0.0.1, and a fake `journalctl`
at the front of the agent's PATH (so sshd lines can be fed to the agent's own journal reader without
touching the machine's journal). It runs no installer, no nft, no systemctl. Every child is killed
and every directory removed in the final block. One PASS or FAIL line per step; exit 0 when all
passed, 2 otherwise.

Order note: step 10 (webhook) needs a channel to exist when the step 4 alert is raised, because the hub
writes no outbox row for a channel that is not enabled yet. The receiver and the two settings are
therefore made right after step 3 and reported as "10a"; step 10 proper delivers and checks the alert.
"""

import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(HERE)
HUB_DIR = os.path.join(ROOT, "server_hub", "hub")
AGENT = os.path.join(ROOT, "server_client", "agent", "edr-agent.py")
PY = sys.executable
OPENSSL = shutil.which("openssl") or "openssl"
FORBIDDEN_PORTS = {80, 443, 8443, 8444, 8450}

BASE = None
CHILDREN = []
SECRETS = []                      # strings that must never appear on a command line
RESULTS = []
USED_PORTS = set()


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
    last = None
    while time.time() < end:
        try:
            last = fn()
        except Exception as exc:               # a probe that fails is "not yet"
            last = None
            _ = exc
        if last:
            return last
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
    joined = " ".join(cmd)
    for s in SECRETS:
        check(s not in joined, "a secret is on a command line")
    e = dict(os.environ)
    e.update(env or {})
    r = subprocess.run(cmd, env=e, input=input_text, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


class Hub:
    def __init__(self, name, port, enroll_port, ui_port):
        self.name = name
        self.dir = os.path.join(BASE, name)
        self.state, self.run_dir, self.etc = (os.path.join(self.dir, d) for d in ("s", "r", "e"))
        self.port, self.enroll_port, self.ui_port = port, enroll_port, ui_port
        self.proc = None
        self.env = {"EDR_HUB_STATE_DIR": self.state, "EDR_HUB_RUN_DIR": self.run_dir, "EDR_HUB_ETC_DIR": self.etc}

    def start(self):
        os.makedirs(self.dir, exist_ok=True)
        log = open(os.path.join(self.dir, "hub.log"), "ab")
        self.proc = subprocess.Popen(
            [PY, "-I", os.path.join(HUB_DIR, "edr_hub.py"), "--state-dir", self.state, "--run-dir", self.run_dir,
             "--etc-dir", self.etc, "--bind", "127.0.0.1", "--port", str(self.port), "--enroll-port", str(self.enroll_port),
             "--ui-port", str(self.ui_port), "--public-ip", "127.0.0.1"],
            stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True)
        CHILDREN.append(self.proc)

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

    def hosts(self):
        return self.cli_json("host", "list", "--all")

    def host(self, name="web1"):
        for h in self.hosts():
            if h.get("name") == name:
                return h
        return None

    def events(self, limit=2000, extra=()):
        return self.cli_json("events", "--limit", str(limit), *extra)

    def health(self):
        rc, out, err = self.cli("health")
        return rc == 0


class Agent:
    def __init__(self):
        self.root = os.path.join(BASE, "a")
        self.fakebin = os.path.join(BASE, "bin")
        self.journal = os.path.join(BASE, "journal.jsonl")
        self.proc = None
        self.env = {"EDR_AGENT_ROOT": self.root, "E2E_FAKE_JOURNAL": self.journal,
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

    def start(self):
        log = open(os.path.join(BASE, "agent.log"), "ab")
        self.proc = subprocess.Popen([PY, "-I", AGENT, "run", "--foreground"], env=dict(os.environ, **self.env),
                                     stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True)
        CHILDREN.append(self.proc)

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

    def tetragon(self, binary, args, policy="nginx-exec", kill=True):
        self.n += 1
        proc = {"exec_id": "e2e%d" % self.n, "pid": 4000 + self.n, "uid": 33, "cwd": "/", "binary": binary, "arguments": args}
        k = {"process": proc, "parent": {"binary": "/usr/sbin/nginx", "arguments": ""}, "function_name": "security_bprm_check",
             "args": [{"linux_binprm_arg": {"path": binary}}], "policy_name": policy}
        if kill:
            k["action"] = "KPROBE_ACTION_SIGKILL"
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000000000Z"
        line = json.dumps({"process_kprobe": k, "node_name": "web1", "time": ts})
        with open(self.p("var/log/tetragon/tetragon.log"), "a") as f:
            f.write(line + "\n")
            f.flush()

    def sshd(self, message):
        self.n += 1
        rec = {"__CURSOR": "s=e2e;i=%d" % self.n, "__REALTIME_TIMESTAMP": str(int(time.time() * 1e6)), "_COMM": "sshd",
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


# A stand-in for `journalctl -o json -f`: follows E2E_FAKE_JOURNAL; `-k` (the kernel log) stays quiet.
FAKE_JOURNALCTL = r'''#!%s
import os, sys, time
if "-k" in sys.argv:
    time.sleep(10 ** 6)
path = os.environ["E2E_FAKE_JOURNAL"]
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


# ---- a throwaway CA and an https receiver ------------------------------------------------------

CA_CNF = """[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = e2e receiver CA
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


def openssl(*args):
    r = subprocess.run([OPENSSL] + list(args), capture_output=True, timeout=60)
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


# ---- the steps ---------------------------------------------------------------------------------

CTX = {}
MARK = "EVILMARK4"
HOSTILE_ARGS = ("-c `id` <script>alert(1)</script> &amp; @everyone [click](http://evil.example/x) \x1b[31mred " + MARK)


def step(num, name):
    def deco(fn):
        def runner():
            t0 = time.time()
            try:
                fn()
            except AssertionError as exc:
                RESULTS.append((num, name, False, str(exc)))
                print("FAIL %s  %s: %s" % (num, name, str(exc)[:600]), flush=True)
            except Exception as exc:
                RESULTS.append((num, name, False, "%s: %s" % (type(exc).__name__, exc)))
                print("FAIL %s  %s: %s: %s" % (num, name, type(exc).__name__, str(exc)[:600]), flush=True)
            else:
                RESULTS.append((num, name, True, ""))
                print("PASS %s  %s (%.0fs)" % (num, name, time.time() - t0), flush=True)
        runner.step = (num, name)
        return runner
    return deco


@step("1", "hub starts, `edr-hub health` is 0, the enrollment port is closed with no token pending")
def step1():
    h = CTX["hub1"]
    h.start()
    check(wait_until(h.health, 60, 1), "edr-hub health never reached 0 (hub log: %s)" % tail(open(os.path.join(h.dir, "hub.log")).read()))
    check(not port_open(h.enroll_port), "the enrollment port %d is open with no token pending" % h.enroll_port)
    check(port_open(h.port), "the fleet port is not listening")


@step("2", "token create, enroll with --token-file, host pending, the token cannot be used twice")
def step2():
    h, a = CTX["hub1"], CTX["agent"]
    res = h.cli_json("token", "create", "--name", "web1", "--ttl", "1h")
    token = res["tokens"][0]["token"]
    SECRETS.append(token.split(".")[1])
    tokfile = os.path.join(BASE, "web1.token")
    fd = os.open(tokfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
    CTX["tokfile"] = tokfile
    check(wait_until(lambda: port_open(h.enroll_port), 10), "the enrollment port did not open after `token create`")
    rc, out, err = a.cli("enroll", "--hub", "127.0.0.1:%d" % h.port, "--enroll-port", str(h.enroll_port),
                         "--token-file", tokfile, "--droplet-id", "e2e-droplet-1")
    check(rc == 0, "edr-agent enroll exited %d: %s" % (rc, tail(err or out)))
    hosts = h.hosts()
    row = [x for x in hosts if x["name"] == "web1"]
    check(len(row) == 1, "web1 is not in `edr-hub host list`: %r" % [x["name"] for x in hosts])
    check(row[0]["state"] == "pending", "the host is %s, not pending" % row[0]["state"])
    CTX["uuid"] = row[0]["uuid"]
    check(a.uuid() == CTX["uuid"], "the agent's host-id differs from the hub's UUID")
    rc2, out2, err2 = a.cli("enroll", "--hub", "127.0.0.1:%d" % h.port, "--enroll-port", str(h.enroll_port), "--token-file", tokfile,
                            "--droplet-id", "e2e-droplet-1")
    check(rc2 != 0, "the same token enrolled a second time (exit %d)" % rc2)
    row2 = [x for x in h.hosts() if x["name"] == "web1"]
    check(len(h.hosts()) == 1 and row2[0]["uuid"] == CTX["uuid"], "the failed second enrollment changed the host list")
    gens = sorted(n for n in os.listdir(a.p("var/lib/edr-agent/identity")) if n.startswith("gen-"))
    check(gens == ["gen-1"], "the failed second enrollment left identity generations %r" % gens)


@step("3", "agent runs; within 90 s the host is active with a heartbeat stored")
def step3():
    h, a = CTX["hub1"], CTX["agent"]
    a.start()

    def active():
        x = h.host()
        return x if x and x["state"] == "active" and x.get("last_seen") else None
    row = wait_until(active, 90, 1)
    check(row, "the host did not become active in 90 s (agent log: %s)" % tail(open(os.path.join(BASE, "agent.log")).read()))
    show = h.cli_json("host", "web1", "show")
    show = show[0] if isinstance(show, list) else show
    check(show.get("agent_version") == "0.1.0", "no heartbeat on record: agent_version=%r" % show.get("agent_version"))
    check(wait_until(lambda: h.host() and h.host().get("policy_rev_applied"), 90, 1), "the heartbeat never reported policy_rev_applied")


@step("10a", "receiver and webhook settings made early so the step 4 alert has a channel")
def step10a():
    h = CTX["hub1"]
    rc = CTX["receiver"] = Receiver()
    rcode, out, err = h.cli("settings", "set", "webhook_ca", rc.ca_pem)
    check(rcode == 0, "settings set webhook_ca: %s" % tail(err or out))
    url = "https://127.0.0.1:%d/hook" % rc.port
    rcode, out, err = h.cli("settings", "set", "webhook_url", "-", input_text=url + "\n")
    check(rcode == 0, "settings set webhook_url -: %s" % tail(err or out))
    rcode, out, err = h.cli("settings", "set", "webhook_url", url)
    check(rcode != 0, "a secret was accepted on the command line")


@step("4", "a Tetragon nginx-exec line becomes a CRITICAL event, an open incident and an outbox row")
def step4():
    h, a = CTX["hub1"], CTX["agent"]
    a.tetragon("/bin/sh", HOSTILE_ARGS)

    def got():
        for e in h.events(extra=("--host", "web1")):
            if e["kind"] == "tetragon.nginx-exec" and e["hub_severity"] == "CRITICAL":
                return e
        return None
    ev = wait_until(got, 30, 1)
    check(ev, "no CRITICAL tetragon.nginx-exec in `edr-hub events --json` after 30 s (agent log: %s)" % tail(open(os.path.join(BASE, "agent.log")).read()))
    check(ev["severity"] == "CRITICAL", "the client severity is %s" % ev["severity"])
    CTX["crit_event"] = ev
    inc = wait_until(lambda: h.cli_json("incidents", "--open"), 40, 1)
    check(inc, "no open incident after the CRITICAL event")

    def waiting():
        rc, out, err = h.cli("status")
        m = re.search(r"alerts:\s+channels (.*?); (\d+) waiting", out)
        return m and int(m.group(2)) >= 1 and "webhook" in m.group(1)
    check(wait_until(waiting, 30, 1), "`edr-hub status` shows no waiting alert row: %s" % tail(h.cli("status")[1], 400))


@step("5", "ssh failures past the threshold ban an address (ban.local at the hub, bans.json); never-ban addresses are not banned")
def step5():
    h, a = CTX["hub1"], CTX["agent"]
    a.ssh_fail("10.9.9.9", 8)              # a never-ban literal
    a.ssh_fail("198.51.100.77", 8)         # operator admin_ip from local.conf
    a.ssh_fail("198.51.100.50", 6)         # over the 5 in 10 minutes threshold
    ok = wait_until(lambda: any(b.get("cidr") == "198.51.100.50/32" for b in a.bans().get("bans", [])), 45, 1)
    check(ok, "198.51.100.50 is not in bans.json after 45 s: %s" % json.dumps(a.bans())[:300])
    b = [x for x in a.bans()["bans"] if x["cidr"] == "198.51.100.50/32"][0]
    check((b["source"], b["reason"]) == ("local", "ssh_fail"), "unexpected ban entry %r" % b)
    stat = os.stat(a.p("run/edr-agent/bans.json"))
    check(stat.st_mode & 0o777 == 0o644, "bans.json mode is %o" % (stat.st_mode & 0o777))

    def at_hub():
        for e in h.events(extra=("--host", "web1")):
            if e["kind"] == "ban.local" and e.get("src_ip") == "198.51.100.50":
                return e
        return None
    ev = wait_until(at_hub, 40, 1)
    check(ev, "no ban.local for 198.51.100.50 at the hub")
    d = ev["details"]
    check(set(d) == {"cidr", "trigger", "evidence", "ttl_s", "rung"} and d["trigger"] == "ssh_fail" and d["ttl_s"] == 3600,
          "ban.local details are %r" % d)
    time.sleep(3)
    cidrs = [x["cidr"] for x in a.bans()["bans"]]
    check("10.9.9.9/32" not in cidrs and "198.51.100.77/32" not in cidrs, "a never-ban address was banned: %r" % cidrs)
    check("198.51.100.77/32" in a.bans()["never"], "the admin_ip is not in the never list of bans.json")


@step("6", "hub down 20 s while events are written: every HIGH and CRITICAL event arrives once")
def step6():
    h, a = CTX["hub1"], CTX["agent"]
    h.stop()
    check(not port_open(h.port), "the hub is still listening")
    expect = []
    for i in range(5):
        name = "/tmp/e2e6-crit-%d" % i
        a.tetragon(name, "-c id%d" % i)
        expect.append(name)
    for i in range(3):
        name = "/tmp/e2e6-high-%d" % i
        a.tetragon(name, "-c id%d" % i, policy="web-exec", kill=False)
        expect.append(name)
    time.sleep(20)
    h.start()
    check(wait_until(h.health, 60, 1), "the hub did not come back healthy")
    CTX["expect6"] = expect

    def arrived():
        evs = h.events(extra=("--host", "web1"))
        found = {m: sum(1 for e in evs if m in (e.get("summary") or "")) for m in expect}
        return found if all(n >= 1 for n in found.values()) else None
    found = wait_until(arrived, 180, 2)
    check(found, "not every event arrived within 180 s: %s" % json.dumps({m: sum(1 for e in h.events(extra=("--host", "web1")) if m in (e.get("summary") or "")) for m in expect}))
    evs = h.events(extra=("--host", "web1"))
    for m in expect:
        n = sum(1 for e in evs if m in (e.get("summary") or ""))
        check(n == 1, "%s arrived %d times" % (m, n))
    ids = [e["event_id"] for e in evs]
    check(len(ids) == len(set(ids)), "an event id appears twice at the hub")
    sev = {e["summary"]: e["severity"] for e in evs if "e2e6-" in (e.get("summary") or "")}
    check(sum(1 for s in sev.values() if s == "CRITICAL") == 5 and sum(1 for s in sev.values() if s == "HIGH") == 3,
          "severities differ from what was written: %r" % sev)


@step("7", "revoke: 403 host_revoked, the agent keeps spooling; a --for token re-enrolls the same UUID and events flow")
def step7():
    h, a = CTX["hub1"], CTX["agent"]
    rc, out, err = h.cli("host", "web1", "revoke")
    check(rc == 0, "host revoke: %s" % tail(err or out))
    a.tetragon("/tmp/e2e7-during-revoke", "-c id")

    def revoked():
        rc, out, err = a.cli("status")
        return "host_revoked" in out and out
    st = wait_until(revoked, 150, 3)
    check(st, "`edr-agent status` never showed host_revoked: %s" % tail(a.cli("status")[1], 400))
    m = re.search(r"spool: depth (\d+)", st)
    check(m and int(m.group(1)) >= 1, "the agent is not spooling while revoked: %s" % tail(st, 300))
    check(not any("e2e7-during-revoke" in (e.get("summary") or "") for e in h.events(extra=("--host", "web1"))),
          "an event arrived while the host was revoked")
    res = h.cli_json("token", "create", "--for", "web1", "--ttl", "1h")
    token = res["tokens"][0]["token"]
    SECRETS.append(token.split(".")[1])
    tokfile = os.path.join(BASE, "web1-again.token")
    fd = os.open(tokfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
    CTX["tokfile2"] = tokfile
    rc, out, err = a.cli("enroll", "--token-file", tokfile)
    check(rc == 0, "re-enrollment exited %d: %s" % (rc, tail(err or out)))
    check(CTX["uuid"] in out, "the UUID changed: %s" % tail(out))
    check(a.uuid() == CTX["uuid"], "host-id changed")
    a.tetragon("/tmp/e2e7-after-reenroll", "-c id")

    def flowing():
        evs = h.events(extra=("--host", "web1"))
        s = " ".join(e.get("summary") or "" for e in evs)
        return "e2e7-during-revoke" in s and "e2e7-after-reenroll" in s
    check(wait_until(flowing, 150, 2), "events did not flow again after re-enrollment (the spooled one and the new one)")
    check(len(h.hosts()) == 1 and h.host()["uuid"] == CTX["uuid"], "the hub holds another host row")


@step("8", "policy: 16-hex rev, heartbeat reports the same policy_rev_applied, the hub address is in the never list")
def step8():
    h, a = CTX["hub1"], CTX["agent"]
    ident = a.p("var/lib/edr-agent/identity/current")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(os.path.join(ident, "ca.pem"))
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT
    ctx.load_cert_chain(os.path.join(ident, "client.pem"), os.path.join(ident, "client.key"))
    req = urllib.request.Request("https://127.0.0.1:%d/v1/policy" % h.port, headers={"X-EDR-Proto": "1"})
    with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
        check(r.status == 200, "GET /v1/policy answered %d" % r.status)
        doc = json.loads(r.read().decode())
        etag = r.headers.get("ETag")
    rev = doc.get("rev")
    check(isinstance(rev, str) and re.fullmatch(r"[0-9a-f]{16}", rev), "rev is %r" % rev)
    check(etag == '"%s"' % rev, "ETag %r differs from rev %r" % (etag, rev))
    check(doc.get("hub_addresses") == ["127.0.0.1"] and doc.get("port") == h.port, "hub_addresses/port are %r/%r" % (doc.get("hub_addresses"), doc.get("port")))
    check(wait_until(lambda: h.host() and h.host().get("policy_rev_applied") == rev, 120, 2),
          "the heartbeat's policy_rev_applied is %r, not %s" % (h.host() and h.host().get("policy_rev_applied"), rev))
    with open(a.p("var/lib/edr-agent/policy.json")) as f:
        check(json.load(f)["rev"] == rev, "the agent's saved policy rev differs")
    check("127.0.0.1/32" in a.bans().get("never", []), "the hub's address is not in the agent's never-ban list: %r" % a.bans().get("never"))
    CTX["rev"] = rev


@step("9", "dashboard: ui-login code redeemed over HTTP, /api/fleet and /api/events with the bearer token, second use refused")
def step9():
    h = CTX["hub1"]
    ui = subprocess.Popen([PY, "-I", os.path.join(HUB_DIR, "edr_hub_ui.py"), "--state-dir", h.state, "--run-dir", h.run_dir,
                           "--etc-dir", h.etc, "--port", str(h.ui_port)], stdout=open(os.path.join(h.dir, "ui.log"), "ab"),
                          stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
    CTX["ui"] = ui
    CTX["ui_proc"] = ui
    CHILDREN.append(ui)
    check(wait_until(lambda: port_open(h.ui_port), 20), "the dashboard is not listening")
    rc, out, err = h.cli("ui-login")
    check(rc == 0, "ui-login: %s" % tail(err or out))
    m = re.search(r"#code=(\S+)", out)
    check(m, "no code in `edr-hub ui-login` output: %s" % tail(out))
    code = m.group(1)
    base = "http://127.0.0.1:%d" % h.ui_port

    def post(code_):
        req = urllib.request.Request(base + "/api/login", data=json.dumps({"code": code_}).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "Origin": base})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, None
    status, body = post(code)
    check(status == 200 and body and body.get("token"), "login answered %s" % status)
    token = body["token"]

    def get(path, auth=True):
        req = urllib.request.Request(base + path, headers={"Authorization": "Bearer " + token} if auth else {})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, None
    s1, fleet = get("/api/fleet")
    check(s1 == 200 and any(x["name"] == "web1" for x in fleet["hosts"]), "/api/fleet: %s %r" % (s1, fleet))
    s2, events = get("/api/events")
    check(s2 == 200, "/api/events answered %s" % s2)
    text = json.dumps(events)
    check("tetragon.nginx-exec" in text, "/api/events does not list the nginx-exec event")
    check(get("/api/fleet", auth=False)[0] == 401, "/api/fleet answered without a token")
    status2, _ = post(code)
    check(status2 == 401, "a second use of the login code answered %s" % status2)


@step("10", "alerts reach the https receiver through edr_hub_out.py --once, hostile fields escaped")
def step10():
    h, rc = CTX["hub1"], CTX["receiver"]

    def delivered():
        run([PY, "-I", os.path.join(HUB_DIR, "edr_hub_out.py"), "--once", "--allow-private"], env=h.env, timeout=120)
        return [t for t in rc.texts() if MARK in t]
    got = wait_until(delivered, 90, 3)
    check(got, "no alert with the hostile marker reached the receiver (%d bodies seen: %s)" % (len(rc.texts()), [t[:60] for t in rc.texts()]))
    text = got[0]
    outside = re.sub(r"`[^`]*`", "", text)                   # what is outside code spans
    check("<" not in text and ">" not in text, "a raw < or > in the alert text: %r" % text[:300])
    check(not any(ord(ch) < 32 and ch != "\n" for ch in text) and "\x7f" not in text, "a control character in the alert text")
    check("<script" not in text and "[click](http" not in outside and "@everyone" not in outside,
          "hostile text is outside a code span: %r" % outside[:300])
    check("[CRITICAL]" in text, "the alert is not CRITICAL: %r" % text[:120])
    rcode, out, err = h.cli("status")
    check(rcode in (0, 1), "edr-hub status exited %d" % rcode)


@step("11", "backup, restore into a second hub, rehome with a --for token: same UUID, the first hub shows moved")
def step11():
    h1, a = CTX["hub1"], CTX["agent"]
    h2 = CTX["hub2"]
    bkp = os.path.join(BASE, "hub1.backup")
    rc, out, err = h1.cli("backup", "--out", bkp)
    check(rc == 0, "backup: %s" % tail(err or out))
    passfile = os.path.join(BASE, "pass")
    fd = os.open(passfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("e2e-passphrase-0123456789\n")
    cakey = os.path.join(BASE, "ca-export.pem")
    rc, out, err = h1.cli("ca-export", "--out", cakey, "--passphrase-file", passfile)
    check(rc == 0, "ca-export: %s" % tail(err or out))
    rc, out, err = h2.cli("restore", bkp, "--ca-key", cakey, "--passphrase-file", passfile, "--public-ip", "127.0.0.1")
    check(rc == 0, "restore: %s" % tail(err or out))
    h2.start()
    check(wait_until(h2.health, 60, 1), "the second hub is not healthy (log: %s)" % tail(open(os.path.join(h2.dir, "hub.log")).read()))
    row = h2.host()
    check(row is not None and row["uuid"] == CTX["uuid"], "the restored hub does not hold web1 with the same UUID: %r" % (row and row["uuid"]))
    res = h2.cli_json("token", "create", "--for", "web1", "--ttl", "1h")
    token = res["tokens"][0]["token"]
    SECRETS.append(token.split(".")[1])
    tokfile = os.path.join(BASE, "web1-hub2.token")
    fd = os.open(tokfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
    check(wait_until(lambda: port_open(h2.enroll_port), 10), "the second hub's enrollment port is closed with a token pending")
    rc, out, err = a.cli("rehome", "--hub", "127.0.0.1:%d" % h2.port, "--enroll-port", str(h2.enroll_port), "--token-file", tokfile)
    check(rc == 0, "rehome exited %d: %s" % (rc, tail(err + out)))
    check(a.uuid() == CTX["uuid"], "host-id changed by the rehome: %r" % a.uuid())
    with open(a.p("var/lib/edr-agent/identity/current/hub.conf")) as f:
        check("port = %d" % h2.port in f.read(), "identity/current does not point at the second hub")

    def moved():
        x = h1.host()
        return x and x["state"] == "moved"
    check(wait_until(moved, 40, 1), "the first hub shows %r, not moved" % (h1.host() and h1.host()["state"]))
    a.tetragon("/tmp/e2e11-after-rehome", "-c id")
    check(wait_until(lambda: any("e2e11-after-rehome" in (e.get("summary") or "") for e in h2.events()), 120, 2),
          "an event written after the rehome did not reach the second hub")
    CTX["rehomed"] = True


@step("12", "`edr-hub audit verify` is 0 on both hubs")
def step12():
    for name in ("hub1", "hub2"):
        rc, out, err = CTX[name].cli("audit", "verify")
        check(rc == 0, "%s: audit verify exited %d: %s" % (name, rc, tail(out or err)))


# ---- main --------------------------------------------------------------------------------------

def cleanup():
    for k in ("receiver",):
        r = CTX.get(k)
        if r is not None:
            r.stop()
    a = CTX.get("agent")
    if a is not None:
        a.stop()
    for k in ("hub1", "hub2"):
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
    if BASE and os.path.isdir(BASE) and not os.environ.get("E2E_KEEP"):
        shutil.rmtree(BASE, ignore_errors=True)


def main():
    global BASE
    BASE = tempfile.mkdtemp(prefix="e2e", dir="/tmp")
    os.chmod(BASE, 0o700)
    steps = [step1, step2, step3, step10a, step4, step5, step6, step7, step8, step9, step10, step11, step12]
    try:
        CTX["hub1"] = Hub("h1", free_port(), free_port(), free_port())
        CTX["hub2"] = Hub("h2", free_port(), free_port(), free_port())
        CTX["agent"] = Agent()
        CTX["agent"].prepare()
        for s in steps:
            s()
    finally:
        cleanup()
    failed = [r for r in RESULTS if not r[2]]
    print("%d steps, %d passed, %d failed" % (len(RESULTS), len(RESULTS) - len(failed), len(failed)), flush=True)
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
