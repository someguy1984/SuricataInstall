#!/usr/bin/python3 -I
"""The hub-outage test: a real hub and a real agent on loopback, the hub away for the load of an hour of scanning.

    python3 -I server_edr_solution/tests/outage_local.py [--full] [--keep]

Standard library only. It drives the real programs and never imports their modules (the same programs and the same
seams as e2e_local.py): server_hub/hub/edr_hub.py and edr-hub, server_client/agent/edr-agent.py with EDR_AGENT_ROOT. The
agent's sources are fed through their files: a Tetragon log (recorded nginx-exec and web-exec lines) and an nginx access
log (scan lines). It uses only temporary directories under /tmp and ports above 18000 on 127.0.0.1. No installer, no nft,
no systemctl. Every child is killed and every directory removed at the end. One PASS or FAIL line per check; exit 0 when
all passed, 2 otherwise.

What it shows (P2 exit criterion, client PLAN section 10 and 11, hub PLAN section 11): a hub outage loses no HIGH or
CRITICAL event, the spool stays at or under 50 MB, the agent stays alive, and everything is at the hub once, within
5 minutes of its return.

  A  The hub stopped (the port closed). A real-time sample of 50 scan lines a second for a minute, then the load of the
     outage fed as fast as the agent reads it (30,000 lines by default, the equivalent of 10 minutes at 50 a second;
     180,000 with --full, the hour). HIGH and CRITICAL markers sit at known places in the stream, the first at its very
     start and the last at its very end. The agent runs with its default event budget.
  B  The same again with the agent's event budget raised to its largest value, so that the scan fills the spool and
     the oldest low-severity segments are evicted; the hub comes back and is killed with SIGKILL twice while the
     agent is replaying, with fresh CRITICAL events written just before each kill (a hub restart in mid-batch).

The "agent under 10% CPU" figure of the plan (client section 9 and the chaos table) is defined for a real-time feed of
about 50 events a second. The burst phases feed as fast as the agent can read, so their CPU figure is a worst case per
line, not that budget; the real-time sample is the one measured against the 10%.
"""

import argparse
import atexit
import ctypes
import json
import os
import random
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(HERE)
HUB_DIR = os.path.join(ROOT, "server_hub", "hub")
AGENT = os.path.join(ROOT, "server_client", "agent", "edr-agent.py")
PY = sys.executable
FORBIDDEN_PORTS = {80, 443, 8443, 8444, 8450}
MB = 1024 * 1024
CLK = os.sysconf("SC_CLK_TCK")

BASE = None
CHILDREN = []
SECRETS = []
RESULTS = []
USED_PORTS = set()
CTX = {}
OPT = None


# ---- small helpers (the same as in e2e_local.py) -----------------------------------------------

class Interrupted(BaseException):
    """SIGINT, SIGTERM or SIGHUP reached the script. A BaseException, so that no step's `except Exception` takes it for a
    failed check: it unwinds to main()'s `finally`, which kills every child by process group and removes the directory."""


def die_with_parent():
    """preexec_fn for a child: the kernel kills it if this script dies without running its handlers (SIGKILL, an OOM kill).
    Linux only; a failure to set it is ignored, the handlers and the `finally` are the main cover."""
    try:
        ctypes.CDLL(None, use_errno=True).prctl(1, int(signal.SIGKILL), 0, 0, 0)       # PR_SET_PDEATHSIG
    except (OSError, AttributeError):
        pass


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
        except Exception:                       # a probe that fails is "not yet"
            last = None
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


def say(msg):
    print("     " + msg, flush=True)


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
            stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True, preexec_fn=die_with_parent)
        CHILDREN.append(self.proc)

    def stop(self, wait=15):
        """A clean stop: SIGTERM, the listening port closes."""
        p = self.proc
        if p is None or p.poll() is not None:
            return
        os.killpg(p.pid, signal.SIGTERM)
        try:
            p.wait(wait)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(5)

    def kill9(self):
        """The process (and any child of it) gone at once: no shutdown code runs."""
        p = self.proc
        if p is None or p.poll() is not None:
            return
        os.killpg(p.pid, signal.SIGKILL)
        p.wait(10)

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

    def high_events(self):
        """Every HIGH and CRITICAL event the hub holds (the CLI returns at most 10,000 rows)."""
        return self.cli_json("events", "--limit", "10000", "--min-sev", "high")

    def health(self):
        rc, out, err = self.cli("health")
        return rc == 0

    def db(self):
        """A read-only connection to the hub's database, for counts that the CLI does not give."""
        path = os.path.join(self.state, "hub.db")
        con = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=20)
        con.row_factory = sqlite3.Row
        return con

    def low_counts(self):
        """(canary.tripwire LOW rows, every INFO, LOW or MEDIUM row)."""
        con = self.db()
        try:
            scan = con.execute("SELECT COUNT(*) FROM events WHERE kind='canary.tripwire' AND severity='LOW'").fetchone()[0]
            low = con.execute("SELECT COUNT(*) FROM events WHERE severity IN ('INFO','LOW','MEDIUM')").fetchone()[0]
            return scan, low
        finally:
            con.close()

    def count_kind(self, kind):
        con = self.db()
        try:
            return con.execute("SELECT COUNT(*) FROM events WHERE kind=?", (kind,)).fetchone()[0]
        finally:
            con.close()

    def heartbeat(self):
        con = self.db()
        try:
            row = con.execute("SELECT received_at, body FROM heartbeats").fetchone()
            return (row["received_at"], json.loads(row["body"])) if row else (0, {})
        finally:
            con.close()


# ---- the agent and its sources -----------------------------------------------------------------

FAKE_JOURNALCTL = r'''#!%s
import os, time
parent = os.getppid()
while os.getppid() == parent:                   # quiet, and gone when the agent is (even after a kill -9 of the test)
    time.sleep(1)
'''


class Agent:
    def __init__(self):
        self.root = os.path.join(BASE, "a")
        self.fakebin = os.path.join(BASE, "bin")
        self.proc = None
        self.env = {"EDR_AGENT_ROOT": self.root, "PATH": self.fakebin + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin")}
        self.tfile = self.afile = None

    def p(self, *parts):
        return os.path.join(self.root, *parts)

    def prepare(self):
        for d, mode in (("var/lib/edr-agent", 0o700), ("run/edr-agent", 0o755), ("etc/edr-agent", 0o755),
                        ("var/log/tetragon", 0o755), ("var/log/nginx", 0o755), ("var/log/suricata", 0o755)):
            os.makedirs(self.p(d), mode, exist_ok=True)
            os.chmod(self.p(d), mode)
        for f in ("var/log/tetragon/tetragon.log", "var/log/nginx/error.log", "var/log/nginx/access.log"):
            open(self.p(f), "a").close()
        self.write_conf()
        os.makedirs(self.fakebin, exist_ok=True)
        script = os.path.join(self.fakebin, "journalctl")       # the journal sources stay quiet
        with open(script, "w") as f:
            f.write(FAKE_JOURNALCTL % PY)
        os.chmod(script, 0o755)
        self.tfile = open(self.p("var/log/tetragon/tetragon.log"), "a")
        self.afile = open(self.p("var/log/nginx/access.log"), "a")

    def write_conf(self, budget=None):
        with open(self.p("etc/edr-agent/local.conf"), "w") as f:
            f.write("[bans]\nadmin_ip = 198.51.100.77\n")
            if budget is not None:
                f.write("[agent]\nevent_budget_per_hour = %d\n" % budget)

    def cli(self, *args, input_text=None, timeout=300):
        return run([PY, "-I", AGENT] + list(args), env=self.env, input_text=input_text, timeout=timeout)

    def start(self):
        log = open(os.path.join(BASE, "agent.log"), "ab")
        self.proc = subprocess.Popen([PY, "-I", AGENT, "run", "--foreground"], env=dict(os.environ, **self.env),
                                     stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True, preexec_fn=die_with_parent)
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

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def uuid(self):
        try:
            with open(self.p("var/lib/edr-agent/host-id")) as f:
                return f.read().strip()
        except OSError:
            return None

    # -- feeding the sources --
    def tetragon_line(self, marker, policy, kill):
        proc = {"exec_id": marker, "pid": 4000, "uid": 33, "cwd": "/", "binary": "/tmp/" + marker, "arguments": "-c id"}
        k = {"process": proc, "parent": {"binary": "/usr/sbin/nginx", "arguments": ""}, "function_name": "security_bprm_check",
             "args": [{"linux_binprm_arg": {"path": "/tmp/" + marker}}], "policy_name": policy}
        if kill:
            k["action"] = "KPROBE_ACTION_SIGKILL"
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000000000Z"
        return json.dumps({"process_kprobe": k, "node_name": "web1", "time": ts}) + "\n"

    def write_tetragon(self, marker, kind):
        """A CRITICAL (kind 'crit': nginx-exec killed) or a HIGH (kind 'high': web-exec, observed) Tetragon line."""
        if kind == "crit":
            self.tfile.write(self.tetragon_line(marker, "nginx-exec", True))
        else:
            self.tfile.write(self.tetragon_line(marker, "web-exec", False))
        self.tfile.flush()

    def cursor_offset(self, name):
        try:
            with open(self.p("var/lib/edr-agent/cursors", name + ".json")) as f:
                return json.load(f).get("offset", 0)
        except (OSError, ValueError):
            return 0

    def lag_bytes(self):
        return os.fstat(self.afile.fileno()).st_size - self.cursor_offset("nginx_access")

    def spool_files(self):
        out = []
        for lane in ("hi", "lo"):
            d = self.p("var/lib/edr-agent/spool", lane)
            try:
                out += [os.path.join(d, n) for n in os.listdir(d) if n.startswith("seg-")]
            except OSError:
                pass
        return out

    def spool_bytes(self):
        """(bytes in the hi and lo segments, bytes in the whole spool directory)."""
        seg = whole = 0
        base = self.p("var/lib/edr-agent/spool")
        for dirpath, _dirs, files in os.walk(base):
            for n in files:
                try:
                    size = os.lstat(os.path.join(dirpath, n)).st_size
                except OSError:
                    continue
                whole += size
                if n.startswith("seg-") and os.path.basename(dirpath) in ("hi", "lo"):
                    seg += size
        return seg, whole


class Gen:
    """The scan: access-log lines, each a request for a tripwire path answered 404 from an address of its own.
    Each is one LOW canary.tripwire event, so the stream is one event a line (the plan's "50 events a second")."""

    PATHS = ["/.env", "/.git/config", "/xmlrpc.php", "/phpmyadmin/", "/_ignition/health-check", "/.env.bak",
             "/wp-login.php", "/cgi-bin/test.cgi", "/storage/logs/laravel.log", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"]

    def __init__(self):
        self.n = 0
        self.stamp = ""
        self.refresh()

    def refresh(self):
        self.stamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime())

    def ip(self, n):
        v = (11 << 24) + 1 + n                  # 11.0.0.1 upwards: public, one address a line
        return "%d.%d.%d.%d" % (v >> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255)

    def scan_line(self):
        self.n += 1
        return '%s - - [%s] "GET %s HTTP/1.1" 404 146 "-" "Mozilla/5.0 (scanner)"\n' % (
            self.ip(self.n), self.stamp, self.PATHS[self.n % len(self.PATHS)])

    def served_line(self, marker):
        """A tripwire path the site ANSWERED (200): one HIGH canary.tripwire, with the marker in the path."""
        self.n += 1
        return '%s - - [%s] "GET /.git/%s HTTP/1.1" 200 512 "-" "Mozilla/5.0 (scanner)"\n' % (self.ip(self.n), self.stamp, marker)


def plan_markers(tag, total, n_crit, n_high, n_acc, seed):
    """[(position, kind, marker)] over positions 0..total, first at 0 and last at total, both CRITICAL."""
    kinds = ["crit"] * (n_crit - 2) + ["high"] * n_high + ["acc"] * n_acc
    random.Random(seed).shuffle(kinds)
    kinds = ["crit"] + kinds + ["crit"]
    m = len(kinds)
    count = {"crit": 0, "high": 0, "acc": 0}
    out = []
    for j, kind in enumerate(kinds):
        count[kind] += 1
        out.append((round(j * total / (m - 1)), kind, "out%s-%s-%04d" % (tag, kind, count[kind])))
    return out


def feed_burst(agent, gen, lines, markers, chunk=1000, lag_max=400 * 1024, give_up_s=900):
    """Append `lines` scan lines to the access log as fast as the agent reads them, the markers at their positions.

    A marker at position p goes out when p scan lines are out: a Tetragon marker to the Tetragon log, an access-log
    marker (a served tripwire path) into the scan itself. The first marker is at 0 and the last at `lines`."""
    gen.refresh()
    end = time.time() + give_up_s
    sent = idx = 0
    while sent < lines or idx < len(markers):
        upto = min(lines, sent + chunk)
        buf = []
        while True:
            if idx < len(markers) and markers[idx][0] <= upto:
                pos, kind, name = markers[idx]
                idx += 1
                while sent < pos:
                    buf.append(gen.scan_line())
                    sent += 1
                if kind == "acc":
                    buf.append(gen.served_line(name))
                else:
                    agent.afile.write("".join(buf))
                    agent.afile.flush()
                    buf = []
                    agent.write_tetragon(name, kind)
                continue
            while sent < upto:
                buf.append(gen.scan_line())
                sent += 1
            break
        agent.afile.write("".join(buf))
        agent.afile.flush()
        while agent.lag_bytes() > lag_max and time.time() < end:
            time.sleep(0.02)
        check(time.time() < end, "the agent did not read the access log in %d s" % give_up_s)
    return sent


def feed_realtime(agent, gen, seconds, rate, markers):
    """`rate` scan lines a second for `seconds`, in ticks of a tenth of a second, markers spread over the run."""
    ticks = int(seconds * 10)
    per_tick = rate / 10.0
    at = {}
    for j, (kind, name) in enumerate(markers):
        at.setdefault(int(j * (ticks - 1) / max(1, len(markers) - 1)), []).append((kind, name))
    t0 = time.time()
    carry = 0.0
    sent = 0
    for i in range(ticks):
        gen.refresh()
        carry += per_tick
        n = int(carry)
        carry -= n
        buf = []
        for _ in range(n):
            buf.append(gen.scan_line())
        sent += n
        for kind, name in at.get(i, []):
            if kind == "acc":
                buf.append(gen.served_line(name))
            else:
                agent.write_tetragon(name, kind)
        agent.afile.write("".join(buf))
        agent.afile.flush()
        delay = t0 + (i + 1) / 10.0 - time.time()
        if delay > 0:
            time.sleep(delay)
    return sent, time.time() - t0


# ---- measuring the agent -----------------------------------------------------------------------

def cpu_seconds(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            rest = f.read().rsplit(")", 1)[1].split()
        return (int(rest[11]) + int(rest[12])) / float(CLK)
    except (OSError, IndexError, ValueError):
        return None


def proc_kb(pid, key):
    try:
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith(key + ":"):
                    return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return None


class Sampler(threading.Thread):
    """Every 0.25 s: the spool (segments, whole directory) and the agent's RSS; the peaks per named phase."""

    def __init__(self, agent):
        super().__init__(daemon=True)
        self.agent = agent
        self.halt = threading.Event()
        self.phase_name = "start"
        self.peaks = {}
        self.alive_always = True

    def phase(self, name):
        self.phase_name = name
        self.peaks.setdefault(name, {"seg": 0, "whole": 0, "rss": 0})

    def run(self):
        self.phase("start")
        while not self.halt.wait(0.25):
            a = self.agent
            if a.proc is None:
                continue
            if a.proc.poll() is not None:
                self.alive_always = False
                continue
            seg, whole = a.spool_bytes()
            rss = (proc_kb(a.proc.pid, "VmRSS") or 0) * 1024
            pk = self.peaks[self.phase_name]
            pk["seg"], pk["whole"], pk["rss"] = max(pk["seg"], seg), max(pk["whole"], whole), max(pk["rss"], rss)


def hwm_mb(pid):
    kb = proc_kb(pid, "VmHWM")
    return None if kb is None else kb / 1024.0


# ---- what the test allows, and why ---------------------------------------------------------------

PLAN_LIMIT_S = 300          # client PLAN section 10 (P2 exit) and 11 (chaos table): delivered within 5 minutes after the hub is back
POLL_MARGIN_S = 30          # the test finds out by polling `edr-hub events` (a few seconds a poll) and the hub needs a moment to listen
BATCH_EVENTS = 500


def agent_hi_retry_cap():
    """The agent's own share of the delay, read from its source (this script never imports the agent): HI_RETRY_S in
    uplink.py, the longest the events backoff may be while a HIGH or CRITICAL event waits in the spool."""
    with open(os.path.join(ROOT, "server_client", "agent", "edragent", "uplink.py")) as f:
        m = re.search(r"^HI_RETRY_S\s*=\s*([0-9.]+)", f.read(), re.M)
    check(m is not None, "HI_RETRY_S is not defined in uplink.py: the agent has no bound on the retry of a HIGH or CRITICAL event")
    return float(m.group(1))


def delivery_bound(n_high):
    """Seconds after the hub's port opens within which the last of `n_high` HIGH and CRITICAL markers must be at the hub.

    The plan's limit is 300 s. The agent's backoff for events is full jitter, up to 5 minutes, and up to HI_RETRY_S (60 s)
    while a HIGH or CRITICAL event is in the spool (client PLAN 4.5). Its last failed attempt was before the port opened,
    so the next one is at most HI_RETRY_S after that; the `hi` lane then goes first at one batch of 500 a second. The
    test requires that bound plus the polling margin. The plan's 300 s alone would pass with a 5-minute backoff drawn
    near its top, which is a draw that cannot be repeated on demand; the bound is the one the code guarantees, and it
    is below the plan's."""
    bound = agent_hi_retry_cap() + (n_high + BATCH_EVENTS - 1) // BATCH_EVENTS * 1.0 + POLL_MARGIN_S
    check(bound <= PLAN_LIMIT_S, "the agent's own bound (%.0f s) is over the plan's %d s" % (bound, PLAN_LIMIT_S))
    return bound


# ---- the steps ---------------------------------------------------------------------------------

def step(num, name):
    def deco(fn):
        def runner():
            t0 = time.time()
            try:
                fn()
            except AssertionError as exc:
                RESULTS.append((num, name, False, str(exc)))
                print("FAIL %s  %s: %s" % (num, name, str(exc)[:900]), flush=True)
            except Exception as exc:
                RESULTS.append((num, name, False, "%s: %s" % (type(exc).__name__, exc)))
                print("FAIL %s  %s: %s: %s" % (num, name, type(exc).__name__, str(exc)[:900]), flush=True)
            else:
                RESULTS.append((num, name, True, ""))
                print("PASS %s  %s (%.0fs)" % (num, name, time.time() - t0), flush=True)
        runner.step = (num, name)
        return runner
    return deco


def marker_counts(events, names):
    """{marker: [events whose summary holds it]} over a list of hub events."""
    found = {n: [] for n in names}
    for e in events:
        s = e.get("summary") or ""
        for m in set(re.findall(r"out[A-Z]-(?:crit|high|acc)-\d{4}", s)):
            if m in found:
                found[m].append(e)
    return found


@step("1", "hub starts and is healthy; the agent enrols, runs, and a CRITICAL event flows")
def step1():
    h, a = CTX["hub"], CTX["agent"]
    h.start()
    check(wait_until(h.health, 60, 1), "edr-hub health never reached 0 (hub log: %s)" % tail(open(os.path.join(h.dir, "hub.log")).read()))
    res = h.cli_json("token", "create", "--name", "web1", "--ttl", "1h")
    token = res["tokens"][0]["token"]
    SECRETS.append(token.split(".")[1])
    tokfile = os.path.join(BASE, "web1.token")
    fd = os.open(tokfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
    check(wait_until(lambda: port_open(h.enroll_port), 10), "the enrollment port did not open after `token create`")
    rc, out, err = a.cli("enroll", "--hub", "127.0.0.1:%d" % h.port, "--enroll-port", str(h.enroll_port), "--token-file", tokfile,
                         "--droplet-id", "outage-droplet-1")
    check(rc == 0, "edr-agent enroll exited %d: %s" % (rc, tail(err or out)))
    a.start()
    CTX["sampler"] = Sampler(a)
    CTX["sampler"].start()

    def active():
        x = h.host()
        return x if x and x["state"] == "active" and x.get("last_seen") else None
    check(wait_until(active, 90, 1), "the host did not become active in 90 s (agent log: %s)" % tail(open(os.path.join(BASE, "agent.log")).read()))
    a.write_tetragon("outS-crit-0001", "crit")
    got = wait_until(lambda: any("outS-crit-0001" in (e.get("summary") or "") for e in h.high_events()), 30, 1)
    check(got, "the CRITICAL event written while the hub was up did not arrive within 30 s")


@step("2", "A: the hub is stopped (port closed); a real-time sample, 50 lines a second, with markers in it")
def step2():
    h, a, smp = CTX["hub"], CTX["agent"], CTX["sampler"]
    r = CTX["A"] = {}
    r["scan0"], r["low0"] = h.low_counts()
    r["hb0"] = h.heartbeat()[1].get("spool", {})
    r["dl0"] = ((json.loads(a.cli("status", "--json")[1]).get("hub") or {}).get("dropped_low")) or 0
    r["lines"] = 0
    h.stop()
    check(not port_open(h.port), "the hub is still listening")
    r["t_down"] = time.time()
    gen = CTX["gen"] = Gen()
    smp.phase("A-realtime")
    pid = a.proc.pid
    markers = [("crit", "outR-crit-0001"), ("acc", "outR-acc-0001"), ("crit", "outR-crit-0002"), ("high", "outR-high-0001"),
               ("acc", "outR-acc-0002"), ("crit", "outR-crit-0003")]
    r["markers"] = [m for _, m in markers]
    c0, w0 = cpu_seconds(pid), time.time()
    sent, took = feed_realtime(a, gen, OPT.rt_seconds, 50, markers)
    time.sleep(2)
    c1, w1 = cpu_seconds(pid), time.time()
    r["lines"] += sent
    r["rt_cpu_pct"] = 100.0 * (c1 - c0) / (w1 - w0)
    r["rt_rss_mb"] = smp.peaks["A-realtime"]["rss"] / MB
    say("real-time sample: %d lines in %.1f s (%.1f a second); agent CPU %.2f s over %.1f s wall = %.2f%% (plan: under 10%%); RSS peak %.1f MB"
        % (sent, took, sent / took, c1 - c0, w1 - w0, r["rt_cpu_pct"], r["rt_rss_mb"]))
    check(a.alive(), "the agent died during the real-time sample")
    check(r["rt_cpu_pct"] < 10.0, "agent CPU %.2f%% at 50 lines a second (limit 10%%)" % r["rt_cpu_pct"])


@step("3", "A: the load of the outage is fed; the agent stays alive, the spool stays at or under 50 MB")
def step3():
    h, a, smp = CTX["hub"], CTX["agent"], CTX["sampler"]
    r, gen = CTX["A"], CTX["gen"]
    n = OPT.lines
    spec = plan_markers("A", n, OPT.crit, OPT.high, OPT.acc, 1)
    r["markers"] += [m for _, _, m in spec]
    r["burst_lines"] = n
    smp.phase("A-burst")
    pid = a.proc.pid
    c0, w0 = cpu_seconds(pid), time.time()
    feed_burst(a, gen, n, spec)
    check(wait_until(lambda: a.lag_bytes() <= 0, 120, 0.2), "the agent has not read the whole access log after the burst")
    time.sleep(2)
    c1, w1 = cpu_seconds(pid), time.time()
    r["lines"] += n
    r["burst_s"], r["burst_cpu_s"] = w1 - w0, c1 - c0
    pk = smp.peaks["A-burst"]
    r["peak_seg"], r["peak_whole"], r["peak_rss"] = pk["seg"], pk["whole"], pk["rss"]
    say("burst: %d lines in %.1f s (%.0f lines/s); agent CPU %.1f s (%.0f%% of one core over the burst, a worst case: "
        "the feed is not real time); spool peak %.2f MB (segments), %.2f MB (whole directory); RSS peak %.1f MB, kernel HWM %.1f MB"
        % (n, w1 - w0, n / (w1 - w0), c1 - c0, 100.0 * (c1 - c0) / (w1 - w0), pk["seg"] / MB, pk["whole"] / MB,
           pk["rss"] / MB, hwm_mb(pid) or 0))
    check(a.alive(), "the agent died during the load")
    check(pk["seg"] <= 50 * MB, "the spool segments reached %.2f MB (limit 50 MB)" % (pk["seg"] / MB))
    check(pk["whole"] <= 50 * MB + 6 * MB, "the spool directory reached %.2f MB" % (pk["whole"] / MB))


@step("4", "A: the outage is held for the minimum length, the agent still alive")
def step4():
    r, a = CTX["A"], CTX["agent"]
    left = r["t_down"] + OPT.hold - time.time()
    if left > 0:
        say("holding the outage %.0f more seconds (minimum outage %d s, so the events backoff grows)" % (left, OPT.hold))
        time.sleep(left)
    r["outage_s"] = time.time() - r["t_down"]
    check(a.alive(), "the agent died during the outage")
    check(not port_open(CTX["hub"].port), "the hub came back by itself")


def deliver(tag, expected_names, limit_s):
    """Start the hub, wait for the fleet port, poll until every expected marker is there. Returns seconds to all of them."""
    h, a = CTX["hub"], CTX["agent"]
    r = CTX[tag]
    h.start()
    t_start = time.time()
    check(wait_until(lambda: port_open(h.port), 60, 0.1), "the hub's fleet port never opened")
    t0 = time.time()
    r["t_listen"] = t0
    say("hub up: fleet port open %.1f s after the start" % (t0 - t_start))
    seen = {}

    def poll():
        evs = h.high_events()
        found = marker_counts(evs, expected_names)
        for m, rows in found.items():
            if rows and m not in seen:
                seen[m] = time.time() - t0
        return len(seen) == len(expected_names)
    done = wait_until(poll, limit_s + 60, 1.5)
    r["deliver_s"] = max(seen.values()) if seen else None
    r["seen"] = seen
    return done


@step("5", "A: the hub returns; every HIGH and CRITICAL marker is at the hub once, within 5 minutes (and within the agent's own bound)")
def step5():
    h, a = CTX["hub"], CTX["agent"]
    r = CTX["A"]
    names = r["markers"]
    bound = delivery_bound(len(names))
    done = deliver("A", names, PLAN_LIMIT_S)
    evs = h.high_events()
    found = marker_counts(evs, names)
    missing = [m for m, rows in found.items() if not rows]
    r["missing"] = missing
    say("%d markers (%d CRITICAL, %d HIGH); last arrived %.1f s after the hub's port opened; first %.1f s"
        % (len(names), sum(1 for m in names if "-crit-" in m), sum(1 for m in names if "-crit-" not in m),
           r["deliver_s"] or -1, min(r["seen"].values()) if r["seen"] else -1))
    check(done and not missing, "%d of %d markers never arrived (first missing: %s)" % (len(missing), len(names), missing[:5]))
    say("allowed: %.0f s (the agent's retry cap %.0f s + the hi lane at one batch a second + %d s of polling); the plan's limit is %d s"
        % (bound, agent_hi_retry_cap(), POLL_MARGIN_S, PLAN_LIMIT_S))
    check(r["deliver_s"] is not None and r["deliver_s"] <= bound,
          "the last marker arrived %.1f s after the hub's port opened (limit %.0f s; the plan's %d s)" % (r["deliver_s"] or -1, bound, PLAN_LIMIT_S))
    dup = {m: len(rows) for m, rows in found.items() if len(rows) != 1}
    check(not dup, "markers not at the hub exactly once: %s" % json.dumps(dict(list(dup.items())[:5])))
    ids = [e["event_id"] for e in evs]
    check(len(ids) == len(set(ids)), "an event id appears twice at the hub")
    for m, rows in found.items():
        want = "CRITICAL" if "-crit-" in m else "HIGH"
        check(rows[0]["severity"] == want, "%s arrived as %s, expected %s" % (m, rows[0]["severity"], want))


def drained(a):
    return not a.spool_files()


def reconcile(tag, tol, kill_extra=0):
    """What the agent says it dropped against what arrived (see the module docstring and the plan, client 4.5)."""
    h, a = CTX["hub"], CTX["agent"]
    r = CTX[tag]
    t0 = time.time()
    check(wait_until(lambda: drained(a), 600, 1), "the spool did not drain after the hub returned (files left: %d)" % len(a.spool_files()))
    r["drain_s"] = time.time() - r["t_listen"]
    t_drained = time.time()
    # the agent's own account: a heartbeat sent after the drain, and `status --json` after its summary was rewritten
    ok_hb = wait_until(lambda: h.heartbeat()[0] > t_drained * 1000, 150, 2)
    check(ok_hb, "no heartbeat arrived after the spool drained")
    hb = h.heartbeat()[1].get("spool", {})

    def fresh_status():
        d = json.loads(a.cli("status", "--json")[1])
        s = d.get("summary") or {}
        return d if s.get("written_at", 0) > t_drained and (s.get("hub") or {}).get("spool", {}).get("depth") == 0 else None
    st = wait_until(fresh_status, 90, 3)
    check(st, "`edr-agent status --json` never showed an empty spool after the drain")
    hubst = st["summary"]["hub"]
    budget = (st["summary"].get("agent") or {}).get("dropped", {})
    r["hb"], r["status_hub"], r["status_budget"] = hb, hubst, budget
    scan1, low1 = h.low_counts()
    over = lambda d: ((d or {}).get("over_budget") or {}).get("nginx", 0)           # noqa: E731
    dsrc = lambda d: ((d or {}).get("dropped_by_source") or {}).get("nginx", 0)      # noqa: E731
    dlane = lambda d, lane: ((d or {}).get("dropped") or {}).get(lane, 0)             # noqa: E731
    r["scan_events"] = r["lines"]
    r["over_budget"] = over(hb) - over(r["hb0"])
    r["spool_dropped_nginx"] = dsrc(hb) - dsrc(r["hb0"])
    r["spool_dropped_lo"] = dlane(hb, "lo") - dlane(r["hb0"], "lo")
    r["spool_dropped_hi"] = dlane(hb, "hi") - dlane(r["hb0"], "hi")
    r["hub_kept_scan"] = scan1 - r["scan0"]
    r["hub_kept_low"] = low1 - r["low0"]
    r["hub_dropped"] = (hubst.get("dropped_low") or 0) - r["dl0"]
    kept_by_agent = r["scan_events"] - r["over_budget"]
    r["residual"] = kept_by_agent - (r["spool_dropped_nginx"] + r["hub_kept_scan"] + r["hub_dropped"])
    say("scan events %d = over budget at the agent %d + passed on %d; passed on = dropped from a full spool %d + kept at the hub %d + dropped by the hub's "
        "LOW bucket %d + unaccounted %d (tolerance %d)" % (r["scan_events"], r["over_budget"], kept_by_agent, r["spool_dropped_nginx"], r["hub_kept_scan"],
                                                          r["hub_dropped"], r["residual"], tol))
    say("agent's account: heartbeat spool %s; status budget %s; hub kept %d LOW/INFO/MEDIUM rows in all; HIGH dropped from the spool %d"
        % (json.dumps(hb, sort_keys=True)[:300], json.dumps(budget), r["hub_kept_low"], r["spool_dropped_hi"]))
    rc, out, err = a.cli("status")
    say("edr-agent status: " + " | ".join(l for l in out.splitlines() if l.startswith(("spool", "events over", "hub"))))
    check(abs(r["residual"]) <= tol, "the agent's counters and the hub disagree: %d scan events not accounted for (tolerance %d)" % (r["residual"], tol))
    check(r["spool_dropped_hi"] == 0, "%d HIGH or CRITICAL events were evicted from the spool" % r["spool_dropped_hi"])


@step("6", "A: what the agent says it dropped (budget, spool, hub bucket) adds up to what arrived")
def step6():
    r = CTX["A"]
    reconcile("A", 30)
    r["kept"] = r["hub_kept_scan"]
    say("A kept %d of %d LOW scan events at the hub; %d over the agent's budget (default 2000 an hour and source) and %d refused by the hub's LOW bucket"
        % (r["kept"], r["scan_events"], r["over_budget"], r["hub_dropped"]))
    check(r["over_budget"] > 0 or r["scan_events"] <= 2000, "no event was over the agent's default budget with %d events" % r["scan_events"])
    check(r["hub_kept_scan"] > 0, "no LOW scan event reached the hub")


@step("7", "B: the budget is raised, the hub is stopped, the stress load fills the spool; spool at most 50 MB, HIGH and CRITICAL kept")
def step7():
    h, a, smp = CTX["hub"], CTX["agent"], CTX["sampler"]
    r = CTX["B"] = {}
    a.write_conf(1000000)                       # the largest value the configuration accepts
    os.kill(a.proc.pid, signal.SIGHUP)
    time.sleep(1.5)
    r["scan0"], r["low0"] = h.low_counts()
    r["hb0"] = h.heartbeat()[1].get("spool", {})
    r["dl0"] = ((json.loads(a.cli("status", "--json")[1]).get("hub") or {}).get("dropped_low")) or 0
    h.stop()
    check(not port_open(h.port), "the hub is still listening")
    r["t_down"] = time.time()
    gen = CTX["gen"]
    n = OPT.stress_lines
    spec = plan_markers("B", n, OPT.crit, OPT.high, OPT.acc, 2)
    r["markers"] = [m for _, _, m in spec]
    smp.phase("B-burst")
    pid = a.proc.pid
    c0, w0 = cpu_seconds(pid), time.time()
    feed_burst(a, gen, n, spec)
    check(wait_until(lambda: a.lag_bytes() <= 0, 120, 0.2), "the agent has not read the whole access log after the burst")
    time.sleep(2)
    c1, w1 = cpu_seconds(pid), time.time()
    r["lines"] = n
    pk = smp.peaks["B-burst"]
    r["peak_seg"], r["peak_whole"], r["peak_rss"] = pk["seg"], pk["whole"], pk["rss"]
    say("stress: %d lines (event budget 1,000,000 an hour) in %.1f s; agent CPU %.1f s; spool peak %.2f MB (segments), %.2f MB (whole directory); "
        "RSS peak %.1f MB, kernel HWM %.1f MB" % (n, w1 - w0, c1 - c0, pk["seg"] / MB, pk["whole"] / MB, pk["rss"] / MB, hwm_mb(pid) or 0))
    check(a.alive(), "the agent died during the stress load")
    check(pk["seg"] <= 50 * MB, "the spool segments reached %.2f MB (limit 50 MB)" % (pk["seg"] / MB))
    check(pk["whole"] <= 50 * MB + 6 * MB, "the spool directory reached %.2f MB" % (pk["whole"] / MB))
    seg, whole = a.spool_bytes()
    lo_bytes = sum(os.path.getsize(p) for p in a.spool_files() if os.sep + "lo" + os.sep in p)
    r["lo_end"] = lo_bytes
    check(lo_bytes > 30 * MB or n < 100000, "the lo lane holds only %.1f MB after %d events: the load did not fill it" % (lo_bytes / MB, n))
    left = r["t_down"] + OPT.hold_b - time.time()
    if left > 0:
        time.sleep(left)


@step("8", "B: the hub returns and is killed with SIGKILL twice mid-replay; every HIGH and CRITICAL marker, including the ones written just before each kill, is there once")
def step8():
    h, a = CTX["hub"], CTX["agent"]
    r = CTX["B"]
    extra = []
    h.start()
    t_start = time.time()
    check(wait_until(lambda: port_open(h.port), 60, 0.1), "the hub's fleet port never opened")
    r["t_listen"] = time.time()
    seen = {}
    kills = 0
    t0 = r["t_listen"]
    names_all = list(r["markers"])

    def seen_poll():
        found = marker_counts(h.high_events(), names_all + extra)
        for m, rows in found.items():
            if rows and m not in seen:
                seen[m] = time.time() - t0
    def lo_left():
        return sum(os.path.getsize(p) for p in a.spool_files() if os.sep + "lo" + os.sep in p)
    lo0 = max(lo_left(), 1)
    for k, frac in enumerate((0.8, 0.5)):
        # wait until the replay is under way (the lo lane shrinking), write fresh CRITICAL events, and kill the hub
        got = wait_until(lambda: lo_left() <= frac * lo0, 240, 0.2)
        if not got:
            say("the replay did not get down to %.0f%% of the lo lane before the kill; killing anyway" % (100 * frac))
        for j in range(3):
            name = "outB-crit-%04d" % (9001 + 100 * k + j)
            a.write_tetragon(name, "crit")
            extra.append(name)
        time.sleep(0.35)
        h.kill9()
        kills += 1
        say("hub killed with SIGKILL (%d) with %.0f%% of the lo lane left in the spool" % (kills, 100.0 * lo_left() / lo0))
        check(not port_open(h.port), "the hub still listens after SIGKILL")
        time.sleep(8)
        h.start()
        check(wait_until(lambda: port_open(h.port), 60, 0.1), "the hub's fleet port did not open after the restart")
        r.setdefault("restart_at", []).append(time.time())
    seen_poll()
    done = wait_until(lambda: (seen_poll() or True) and all(m in seen for m in names_all + extra), PLAN_LIMIT_S, 2)
    r["seen"] = seen
    found = marker_counts(h.high_events(), names_all + extra)
    missing = [m for m, rows in found.items() if not rows]
    since_last = max(seen.values()) - (r["restart_at"][-1] - t0) if seen else -1
    say("%d markers + %d written just before the kills; last arrived %.1f s after the first start, %.1f s after the last restart"
        % (len(names_all), len(extra), max(seen.values()) if seen else -1, since_last))
    check(done and not missing, "%d markers never arrived (first missing: %s)" % (len(missing), missing[:5]))
    dup = {m: len(rows) for m, rows in found.items() if len(rows) != 1}
    check(not dup, "markers not at the hub exactly once: %s" % json.dumps(dict(list(dup.items())[:5])))
    evs = h.high_events()
    ids = [e["event_id"] for e in evs]
    check(len(ids) == len(set(ids)), "an event id appears twice at the hub")
    bound = delivery_bound(len(names_all) + len(extra))
    say("allowed after the final restart: %.0f s (the plan's limit is %d s)" % (bound, PLAN_LIMIT_S))
    check(since_last <= bound, "the last marker arrived %.1f s after the final restart (limit %.0f s; the plan's %d s)" % (since_last, bound, PLAN_LIMIT_S))
    r["markers"] = names_all + extra
    check(a.alive(), "the agent died while the hub was killed")


@step("9", "B: the spool drains, and what the agent says it dropped adds up to what arrived")
def step9():
    r = CTX["B"]
    # a batch in flight at a kill may have been stored and then offered again: its LOW events can be counted as dropped
    # by the hub's bucket on the second pass, so the tolerance is two batches of 500 per kill, plus a few agent events
    reconcile("B", 2 * 500 * 2 + 40)
    say("B kept %d of %d LOW scan events at the hub; %d over budget (none expected), %d evicted from the full spool, %d refused by the hub's LOW bucket"
        % (r["hub_kept_scan"], r["scan_events"], r["over_budget"], r["spool_dropped_nginx"], r["hub_dropped"]))
    check(r["over_budget"] == 0, "%d events were over the budget with a budget of 1,000,000" % r["over_budget"])
    n_evt = CTX["hub"].count_kind("health.spool_dropped")
    say("the hub holds %d health.spool_dropped events (repeats inside 5 minutes are collapsed into one, so their counts are not the total; "
        "the heartbeat's counters are)" % n_evt)
    check(r["spool_dropped_lo"] > 0 or r["scan_events"] < 100000, "the stress load evicted nothing from the lo lane")
    check(n_evt >= 1 or r["spool_dropped_lo"] == 0, "the spool evicted %d events and no health.spool_dropped event reached the hub" % r["spool_dropped_lo"])


@step("10", "the agent never restarted and stayed within its memory figure; the hub's audit chain holds")
def step10():
    h, a, smp = CTX["hub"], CTX["agent"], CTX["sampler"]
    pid = a.proc.pid
    rss_peak = max(pk["rss"] for pk in smp.peaks.values()) / MB
    hwm = hwm_mb(pid)
    cpu_total, wall_total = cpu_seconds(pid), time.time() - CTX["t_agent_start"]
    say("agent RSS peak %.1f MB sampled, %.1f MB kernel high-water mark (plan: MemoryHigh 96 MB, MemoryMax 128 MB, about 30 MB plus the access ring "
        "of 10 to 20 MB expected); agent CPU over the whole run %.1f s of %.0f s wall" % (rss_peak, hwm or 0, cpu_total, wall_total))
    rss_a = max(smp.peaks[k]["rss"] for k in smp.peaks if k.startswith("A-")) / MB
    say("with the default event budget (phase A) the RSS peak is %.1f MB, against MemoryHigh 96 MB; phase B raises the budget to its "
        "largest value (a stress, not a configuration anyone runs) and its peak %.1f MB may pass MemoryHigh, which throttles and does not kill"
        % (rss_a, max(pk["rss"] for k, pk in smp.peaks.items() if k.startswith("B-")) / MB))
    check(rss_a <= 96, "agent RSS peak %.1f MB with the default budget is over the plan's MemoryHigh of 96 MB" % rss_a)
    check(a.alive() and smp.alive_always, "the agent was not alive throughout")
    check(hwm is not None and hwm <= 128, "agent memory high-water mark %.1f MB is over the plan's 128 MB (MemoryMax)" % (hwm or 0))
    rc, out, err = h.cli("audit", "verify")
    check(rc == 0, "audit verify exited %d: %s" % (rc, tail(out or err)))


# ---- main --------------------------------------------------------------------------------------

def kill_group(p, grace=5):
    """SIGTERM to the child's process group, then SIGKILL to the group whether or not its leader is still there: a child
    of a dead leader keeps the group id, and `killpg` still reaches it."""
    try:
        os.killpg(p.pid, signal.SIGTERM)
        p.wait(grace)
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        os.killpg(p.pid, signal.SIGKILL)            # the leader that ignored SIGTERM, and members it left behind
        p.wait(5)
    except (OSError, subprocess.TimeoutExpired):
        pass


def cleanup():
    """Kill every child by process group and remove the temporary directory. Safe to call twice and never raises: it
    runs from main()'s `finally`, from the signal handler's unwinding and from atexit."""
    if CTX.get("cleaned"):
        return
    CTX["cleaned"] = True
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):      # a second signal must not cut the clean-up short
        try:
            signal.signal(sig, signal.SIG_IGN)
        except (OSError, ValueError):
            pass
    s = CTX.get("sampler")
    if s is not None:
        s.halt.set()
    for p in CHILDREN:
        try:
            kill_group(p, grace=3 if CTX.get("interrupted") else 15)
        except Exception:
            pass
    a = CTX.get("agent")
    if a is not None:
        for f in (a.tfile, a.afile):
            try:
                f.close()
            except (OSError, AttributeError):
                pass
    if BASE and os.path.isdir(BASE) and not (OPT and OPT.keep):
        shutil.rmtree(BASE, ignore_errors=True)


def on_signal(signum, _frame):
    CTX["interrupted"] = signal.Signals(signum).name
    raise Interrupted(signal.Signals(signum).name)


def main():
    global BASE, OPT
    ap = argparse.ArgumentParser(description="the hub-outage test (see the module docstring)")
    ap.add_argument("--full", action="store_true", help="the whole hour: 180,000 scan lines in each of A and B, a 10 minute outage minimum")
    ap.add_argument("--lines", type=int, help="scan lines in A's burst (default 30,000; 180,000 with --full)")
    ap.add_argument("--stress-lines", type=int, help="scan lines in B (default 110,000; 180,000 with --full)")
    ap.add_argument("--hold", type=int, help="the least length of A's outage in seconds (default 120; 600 with --full)")
    ap.add_argument("--rt-seconds", type=int, default=60, help="length of the real-time sample at 50 lines a second (default 60)")
    ap.add_argument("--keep", action="store_true", help="keep the temporary directory (for debugging)")
    OPT = ap.parse_args()
    OPT.lines = OPT.lines or (180000 if OPT.full else 30000)
    OPT.stress_lines = OPT.stress_lines or (180000 if OPT.full else 110000)
    OPT.hold = OPT.hold if OPT.hold is not None else (600 if OPT.full else 120)
    OPT.hold_b = 20
    OPT.crit, OPT.high, OPT.acc = (200, 60, 40) if OPT.full else (60, 40, 20)
    BASE = tempfile.mkdtemp(prefix="outage", dir="/tmp")
    os.chmod(BASE, 0o700)
    atexit.register(cleanup)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, on_signal)
    steps = [step1, step2, step3, step4, step5, step6, step7, step8, step9, step10]
    t_begin = time.time()
    try:
        CTX["hub"] = Hub("h", free_port(), free_port(), free_port())
        CTX["agent"] = Agent()
        CTX["agent"].prepare()
        CTX["t_agent_start"] = time.time()
        print("outage_local: %s run: A %d lines (+%d s real-time sample), B %d lines, outage at least %d s"
              % ("full" if OPT.full else "default", OPT.lines, OPT.rt_seconds, OPT.stress_lines, OPT.hold), flush=True)
        for s in steps:
            s()
    except Interrupted as exc:
        cleanup()
        print("outage_local: interrupted by %s; every child killed, %s removed" % (exc, BASE), flush=True)
        return 130 if str(exc) == "SIGINT" else 143
    finally:
        cleanup()
    failed = [r for r in RESULTS if not r[2]]
    print("%d steps, %d passed, %d failed (%.0f s)" % (len(RESULTS), len(RESULTS) - len(failed), len(failed), time.time() - t_begin), flush=True)
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
