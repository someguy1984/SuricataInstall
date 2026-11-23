"""The main process: the Hub object, start order, --init-only, running unprivileged from a copy of the code, SIGTERM,
refusing a newer database (PLAN.md sections 3, 8 and 17; contract sections 5.1 and 5.2).

The subprocess tests copy the hub code to a temporary directory (so `python3 -I` finds its siblings there) and add
small stub modules for any sibling another agent has not delivered yet."""

import json
import os
import shutil
import signal
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_ingest_fixture as F  # noqa: E402

import hub_common  # noqa: E402
import hub_db  # noqa: E402
import hub_enroll  # noqa: E402
import hub_pki  # noqa: E402
import edr_hub  # noqa: E402

STUBS = {
    "hub_rules.py": "def rate(conn, host_row, event):\n    return event.get('sev', 'INFO'), None\n"
                    "def describe(kind):\n    return {'meaning': '', 'next_step': ''}\nRULES = []\n",
    "hub_engine.py": "def after_insert(*a, **k): pass\ndef on_heartbeat(*a, **k): pass\ndef on_enroll(*a, **k): pass\n"
                     "def on_rejected(*a, **k): pass\nclass Engine:\n    def __init__(self, hub): self.hub = hub\n"
                     "    def start(self): pass\n    def stop(self): pass\n",
    "hub_alerts.py": "def notify(*a, **k): return 0\ndef admin_notice(*a, **k): return 0\ndef enqueue_test(*a, **k): return []\n"
                     "def render(*a, **k): return {}\n",
    "hub_audit.py": "def append(conn, **k): return 0\ndef verify(conn): return (True, None)\ndef ingest_pending(conn, hub): return 0\n"
                    "def append_pending(*a, **k): pass\n",
    "hub_ctl.py": "class Sockets:\n    def __init__(self, hub): self.hub = hub\n    def start(self): pass\n    def stop(self): pass\n",
}
NEEDED = ("hub_rules", "hub_engine", "hub_alerts", "hub_audit", "hub_ctl")


def slurp(path):
    with open(path) as f:
        return f.read()


def jload(path):
    with open(path) as f:
        return json.load(f)


def short_tmp():
    d = tempfile.mkdtemp(prefix="hubmain-")           # short: unix socket paths are limited to 107 bytes
    os.chmod(d, 0o755)
    return d


def make_lib(root):
    """A copy of the hub code in root/lib (and pki/strict beside it), with stubs for missing siblings."""
    lib = os.path.join(root, "lib")
    os.makedirs(lib)
    for name in os.listdir(F.HUB_DIR):
        if name.endswith(".py") or name.endswith(".json"):
            shutil.copy(os.path.join(F.HUB_DIR, name), os.path.join(lib, name))
    for mod in NEEDED:
        if not os.path.exists(os.path.join(lib, mod + ".py")):
            with open(os.path.join(lib, mod + ".py"), "w") as f:
                f.write(STUBS[mod + ".py"])
    shutil.copytree(os.path.join(F.HUB_DIR, "..", "pki"), os.path.join(root, "lib", "pki"))
    for dirpath, dirnames, filenames in os.walk(root):
        os.chmod(dirpath, 0o755)
        for fn in filenames:
            os.chmod(os.path.join(dirpath, fn), 0o644)
    return lib


class Proc:
    """edr_hub.py as `python3 -I`, in a temporary directory, optionally as an unprivileged user."""

    def __init__(self, root, ports, extra=(), env_extra=None, unprivileged=True):
        self.root = root
        self.lib = make_lib(root) if not os.path.exists(os.path.join(root, "lib")) else os.path.join(root, "lib")
        self.fleet_port, self.enroll_port = ports
        self.state, self.run, self.etc = (os.path.join(root, d) for d in ("state", "run", "etc"))
        self.args = ["--state-dir", self.state, "--run-dir", self.run, "--etc-dir", self.etc, "--bind", "127.0.0.1",
                     "--port", str(self.fleet_port), "--enroll-port", str(self.enroll_port), "--public-ip", "127.0.0.1"] + list(extra)
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": root}
        self.env.update(env_extra or {})
        self.unprivileged = unprivileged and os.geteuid() == 0
        self.p = None
        self.err = None

    def _preexec(self):
        if self.unprivileged:
            os.setgid(65534)
            os.setuid(65534)

    def run_to_end(self, timeout=60):
        os.makedirs(self.state, exist_ok=True)
        dirs = [self.state]
        if "--init-only" not in self.args:                 # init-only must not need the run directory
            os.makedirs(self.run, exist_ok=True)
            dirs.append(self.run)
        if self.unprivileged:
            for d in dirs:
                os.chmod(d, 0o777)
        done = subprocess.run([sys.executable, "-I", os.path.join(self.lib, "edr_hub.py")] + self.args, capture_output=True,
                              text=True, timeout=timeout, env=self.env, cwd="/", preexec_fn=self._preexec)
        return done

    def start(self):
        os.makedirs(self.state, exist_ok=True)
        os.makedirs(self.run, exist_ok=True)
        if self.unprivileged:
            for d in (self.state, self.run):
                os.chmod(d, 0o777)
        self.err = open(os.path.join(self.root, "stderr.txt"), "w+")
        self.p = subprocess.Popen([sys.executable, "-I", os.path.join(self.lib, "edr_hub.py")] + self.args, stdout=self.err,
                                  stderr=self.err, env=self.env, cwd="/", preexec_fn=self._preexec)
        return self

    def wait_port(self, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.p.poll() is not None:
                raise AssertionError("hub exited early: %s" % self.stderr())
            s = socket.socket()
            s.settimeout(0.5)
            try:
                s.connect(("127.0.0.1", self.fleet_port))
                return
            except OSError:
                time.sleep(0.1)
            finally:
                s.close()
        raise AssertionError("hub did not listen: %s" % self.stderr())

    def stderr(self):
        self.err.flush()
        self.err.seek(0)
        return self.err.read()

    def stop(self, sig=signal.SIGTERM, timeout=20):
        if self.p is None:
            return None
        if self.p.poll() is None:
            self.p.send_signal(sig)
        try:
            code = self.p.wait(timeout)
        except subprocess.TimeoutExpired:
            self.p.kill()
            code = self.p.wait()
        self.p = None
        return code


class MainCase(unittest.TestCase):
    def setUp(self):
        self.root = short_tmp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.ports = F.free_ports(2)
        self.procs = []
        self.addCleanup(self.kill_all)

    def kill_all(self):
        for p in self.procs:
            if p.p is not None and p.p.poll() is None:
                p.p.kill()
                p.p.wait()
            if p.err is not None:
                p.err.close()

    def proc(self, **kw):
        p = Proc(self.root, self.ports, **kw)
        self.procs.append(p)
        return p


class InitOnlyTest(MainCase):
    def test_creates_everything_and_exits_zero(self):
        p = self.proc(extra=["--init-only", "--ui-port", "18450", "--retention-days", "14", "--max-db-size", "512m"])
        done = p.run_to_end()
        self.assertEqual(done.returncode, 0, done.stderr)
        settings = jload(os.path.join(p.state, "settings.json"))
        self.assertEqual((settings["port"], settings["enroll_port"], settings["public_ip"]), (self.ports[0], self.ports[1], ["127.0.0.1"]))
        self.assertEqual((settings["ui_port"], settings["retention_days"], settings["max_db_size"]), (18450, 14, "512M"))
        self.assertEqual(settings["alert_min_severity"], "HIGH")                # the rest are the defaults
        paths = hub_common.Paths(state_dir=p.state, run_dir=p.run, etc_dir=p.etc)
        for f in (paths.ca_cert, paths.ca_key, paths.server_cert, paths.server_key, paths.db):
            self.assertTrue(os.path.exists(f), f)
        self.assertEqual(stat.S_IMODE(os.stat(paths.ca_key).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(paths.server_key).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(paths.ca_dir).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(paths.tls_dir).st_mode), 0o700)
        conn = sqlite3.connect(paths.db)
        self.assertEqual(conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0], "1")
        self.assertEqual(conn.execute("PRAGMA auto_vacuum").fetchone()[0], 2)
        self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        conn.close()
        pki = hub_pki.Pki(paths)
        self.assertEqual(pki.server_cert_state(["127.0.0.1"]), "ok")
        self.assertFalse(os.path.exists(paths.ctl_sock))                        # init-only starts nothing

    def test_runs_without_root(self):
        if os.geteuid() != 0:
            self.skipTest("already unprivileged: every test in this file runs that way")
        p = self.proc(extra=["--init-only"], unprivileged=True)
        done = p.run_to_end()
        self.assertEqual(done.returncode, 0, done.stderr)
        owner = os.stat(os.path.join(p.state, "hub.db")).st_uid
        self.assertEqual(owner, 65534)                                           # made by the unprivileged user

    def test_second_run_keeps_the_ca_certificate_database_and_settings(self):
        p = self.proc(extra=["--init-only"])
        self.assertEqual(p.run_to_end().returncode, 0)
        paths = hub_common.Paths(state_dir=p.state, run_dir=p.run, etc_dir=p.etc)
        ca_before = hub_pki.Pki(paths).ca_sha256()
        cert_before = slurp(paths.server_cert)
        settings = jload(paths.settings)
        settings["retention_days"] = 99                                          # a later `settings set`
        hub_common.save_settings(paths, settings)
        conn = sqlite3.connect(paths.db)
        conn.execute("INSERT INTO meta(key, value) VALUES('marker', 'kept')")
        conn.commit()
        conn.close()
        p2 = Proc(self.root, self.ports, extra=["--init-only"])
        done = p2.run_to_end()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(hub_pki.Pki(paths).ca_sha256(), ca_before)
        self.assertEqual(slurp(paths.server_cert), cert_before)
        self.assertEqual(jload(paths.settings)["retention_days"], 99)
        conn = sqlite3.connect(paths.db)
        self.assertEqual(conn.execute("SELECT value FROM meta WHERE key='marker'").fetchone()[0], "kept")
        conn.close()

    def test_a_changed_address_list_reissues_the_server_certificate(self):
        p = self.proc(extra=["--init-only"])
        self.assertEqual(p.run_to_end().returncode, 0)
        paths = hub_common.Paths(state_dir=p.state, run_dir=p.run, etc_dir=p.etc)
        before = hub_pki.Pki(paths).cert_info(paths.server_cert)
        p2 = Proc(self.root, self.ports, extra=["--init-only", "--public-ip", "10.1.2.3"])
        self.assertEqual(p2.run_to_end().returncode, 0)
        after = hub_pki.Pki(paths).cert_info(paths.server_cert)
        self.assertEqual(after["sans"], ["127.0.0.1", "10.1.2.3"])          # --public-ip is repeatable and appends
        self.assertNotEqual(after["serial"], before["serial"])
        self.assertEqual(hub_pki.Pki(paths).ca_sha256(), hub_pki.Pki(paths).ca_sha256())

    def test_default_public_ip_follows_bind(self):
        p = self.proc(extra=["--init-only"])
        i = p.args.index("--public-ip")
        del p.args[i:i + 2]
        self.assertEqual(p.run_to_end().returncode, 0)
        self.assertEqual(jload(os.path.join(p.state, "settings.json"))["public_ip"], ["127.0.0.1"])

    def test_ui_host_and_webhook_ca_flags_and_no_run_directory(self):
        p = self.proc(extra=["--init-only", "--ui-host", "hub.example:8450", "--ui-host", "127.0.0.1:8450",
                             "--webhook-ca-path", "/var/lib/edr-hub/webhook-ca.pem"])
        done = p.run_to_end()
        self.assertEqual(done.returncode, 0, done.stderr)
        settings = jload(os.path.join(p.state, "settings.json"))
        self.assertEqual(settings["ui_host"], ["hub.example:8450", "127.0.0.1:8450"])
        self.assertEqual(settings["webhook_ca"], "/var/lib/edr-hub/webhook-ca.pem")
        self.assertFalse(os.path.exists(p.run), "--init-only made the run directory")
        bad = Proc(self.root, self.ports, extra=["--init-only", "--ui-host", "no port here"]).run_to_end()
        self.assertEqual(bad.returncode, 2)

    def test_usage_error_exits_64(self):
        p = self.proc(extra=["--bogus-flag"])
        done = p.run_to_end()
        self.assertEqual(done.returncode, 64)

    def test_bad_flag_values_do_not_start(self):
        for extra in (["--public-ip", "not-an-ip", "--init-only"], ["--max-db-size", "lots", "--init-only"]):
            done = Proc(self.root, self.ports, extra=extra).run_to_end()
            self.assertEqual(done.returncode, 2, extra)


class RunningHubTest(MainCase):
    def make_token(self, p, name="web1"):
        """Prepare a token the way the CLI would (hub stopped): through the same hub_enroll code."""
        paths = hub_common.Paths(state_dir=p.state, run_dir=p.run, etc_dir=p.etc)
        hub = type("H", (), {})()
        hub.paths = paths
        hub.settings = hub_common.load_settings(paths)
        hub.pki = hub_pki.Pki(paths)
        conn = sqlite3.connect(paths.db, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("BEGIN IMMEDIATE")
        res = hub_enroll.token_create(conn, hub, name=name)
        conn.execute("COMMIT")
        conn.close()
        return res["token"]

    def client_for(self, p):
        """A test client (see test_ingest_fixture.Client) bound to this subprocess hub."""
        fx = type("FX", (), {})()
        fx.tmp = self.root
        fx.fleet_port, fx.enroll_port = self.ports
        fx.hub = type("H", (), {})()
        fx.hub.pki = hub_pki.Pki(hub_common.Paths(state_dir=p.state, run_dir=p.run, etc_dir=p.etc))
        return F.Client(fx, key_path=None)

    def test_start_serve_enroll_events_sigterm(self):
        notify_dir = tempfile.mkdtemp(prefix="hubnotify-")
        self.addCleanup(shutil.rmtree, notify_dir, True)
        notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        notify.bind(os.path.join(notify_dir, "n"))
        os.chmod(notify_dir, 0o777)
        os.chmod(os.path.join(notify_dir, "n"), 0o777)
        notify.settimeout(40)
        self.addCleanup(notify.close)
        init = self.proc(extra=["--init-only"])
        self.assertEqual(init.run_to_end().returncode, 0)
        token = self.make_token(init)
        p = Proc(self.root, self.ports, env_extra={"NOTIFY_SOCKET": os.path.join(notify_dir, "n")})
        self.procs.append(p)
        p.start()
        got = []
        while "READY=1" not in got:
            got.append(notify.recv(200).decode())
        p.wait_port()
        # real enrollment and real events against the running process
        key, csr = F.make_key_and_csr(self.root)
        client = self.client_for(p)
        client.key_path = key
        status, _h, body = client.enroll_request(token, csr)
        self.assertEqual(status, 200, p.stderr())
        client.adopt(json.loads(body))
        self.assertEqual(client.heartbeat()[0], 200)
        self.assertEqual(client.send_events([F.make_event(seq=1, sev="HIGH")])[0], 200)
        self.assertEqual(client.request("GET", "/v1/policy")[0], 200)
        # the watchdog is fed from the writer's idle tick (10 s)
        notify.settimeout(20)
        seen = []
        deadline = time.time() + 20
        while time.time() < deadline and "WATCHDOG=1" not in seen:
            seen.append(notify.recv(200).decode())
        self.assertIn("WATCHDOG=1", seen)
        code = p.stop()
        self.assertEqual(code, 0, p.stderr() if p.err else "")
        conn = sqlite3.connect(os.path.join(p.state, "hub.db"))
        meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)
        self.assertEqual(conn.execute("SELECT state FROM hosts").fetchone()[0], "active")
        conn.close()
        self.assertGreaterEqual(int(meta["hub_stopped_at"]), int(meta["hub_started_at"]))
        self.assertFalse(os.path.exists(os.path.join(p.state, "hub.db-wal")) and
                         os.path.getsize(os.path.join(p.state, "hub.db-wal")) > 0, "WAL checkpointed at stop")
        self.assertNotIn("Traceback", p.err.read() if not p.err.closed else "")

    def test_sigkill_then_restart_runs_the_quick_check(self):
        init = self.proc(extra=["--init-only"])
        self.assertEqual(init.run_to_end().returncode, 0)
        p = Proc(self.root, self.ports).start()
        self.procs.append(p)
        p.wait_port()
        p.stop(signal.SIGKILL)
        p2 = Proc(self.root, self.ports).start()
        self.procs.append(p2)
        p2.wait_port()
        deadline = time.time() + 15
        found = False
        while time.time() < deadline and not found:
            conn = sqlite3.connect(os.path.join(p2.state, "hub.db"))
            found = conn.execute("SELECT 1 FROM meta WHERE key='last_quick_check'").fetchone() is not None
            conn.close()
            time.sleep(0.2)
        self.assertTrue(found, "no quick_check after an unclean start")
        self.assertEqual(p2.stop(), 0)

    def test_a_database_newer_than_the_code_is_refused(self):
        init = self.proc(extra=["--init-only"])
        self.assertEqual(init.run_to_end().returncode, 0)
        conn = sqlite3.connect(os.path.join(init.state, "hub.db"))
        conn.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
        conn.commit()
        conn.close()
        done = Proc(self.root, self.ports).run_to_end(timeout=40)
        self.assertEqual(done.returncode, 2)
        self.assertIn("refusing to start", done.stderr)
        s = socket.socket()
        s.settimeout(1)
        with self.assertRaises(OSError):
            s.connect(("127.0.0.1", self.ports[0]))                              # never listened
        s.close()

    def test_enrollment_listener_is_closed_until_a_token_exists(self):
        init = self.proc(extra=["--init-only"])
        self.assertEqual(init.run_to_end().returncode, 0)
        p = Proc(self.root, self.ports).start()
        self.procs.append(p)
        p.wait_port()
        time.sleep(1.5)
        s = socket.socket()
        s.settimeout(1)
        with self.assertRaises(OSError):
            s.connect(("127.0.0.1", self.ports[1]))
        s.close()
        self.assertEqual(p.stop(), 0)


class HubObjectTest(F.HubTestCase):
    def test_contract_surface(self):
        hub = self.fx.hub
        for name in ("paths", "settings", "writer", "ro", "pki", "started_at", "stopping", "refresh_enroll_listener",
                     "reload_server_cert", "log", "update_settings"):
            self.assertTrue(hasattr(hub, name), name)
        self.assertIsInstance(hub.started_at, int)
        self.assertFalse(hub.stopping.is_set())
        ro = hub.ro()
        try:
            self.assertEqual(ro.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()["value"], "1")
            with self.assertRaises(sqlite3.OperationalError):
                ro.execute("DELETE FROM meta")
        finally:
            ro.close()

    def test_update_settings_saves_atomically_and_swaps(self):
        hub = self.fx.hub
        new = dict(hub.settings)
        new["retention_days"] = 77
        old = hub.settings
        hub.update_settings(new)
        self.assertIs(hub.settings, new)
        self.assertIsNot(hub.settings, old)
        self.assertEqual(jload(self.fx.paths.settings)["retention_days"], 77)
        self.assertEqual(hub_common.load_settings(self.fx.paths)["retention_days"], 77)
        leftovers = [f for f in os.listdir(self.fx.paths.state_dir) if f.startswith(".tmp-")]
        self.assertEqual(leftovers, [])

    def test_reload_server_cert_reaches_the_live_context(self):
        def server_serial():
            raw = socket.create_connection(("127.0.0.1", self.fx.fleet_port), timeout=5)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as s:
                    der = s.getpeercert(binary_form=True)
                    return hub_pki.Pki(self.fx.paths).cert_info(ssl.DER_cert_to_PEM_cert(der))["serial"]
            except (ssl.SSLError, OSError):
                return None
        enroll_client = self.fx.enroll("web1")
        before = hub_pki.Pki(self.fx.paths).cert_info(self.fx.paths.server_cert)["serial"]
        self.fx.hub.pki.issue_server_cert(["127.0.0.1"])
        after = hub_pki.Pki(self.fx.paths).cert_info(self.fx.paths.server_cert)["serial"]
        self.assertNotEqual(before, after)
        s_before = enroll_client.request("GET", "/v1/policy")
        self.assertEqual(s_before[0], 200)
        self.fx.hub.reload_server_cert()
        self.assertEqual(enroll_client.request("GET", "/v1/policy")[0], 200)     # still serves, now with the new certificate

    def test_check_server_cert_reissues_for_a_new_address_list_and_near_expiry(self):
        hub = self.fx.hub
        self.assertFalse(hub.check_server_cert(force=True))
        hub.settings["public_ip"] = ["127.0.0.1", "10.0.0.9"]
        self.assertTrue(hub.check_server_cert(force=True))
        self.assertEqual(sorted(hub.pki.cert_info(self.fx.paths.server_cert)["sans"]), ["10.0.0.9", "127.0.0.1"])
        self.assertFalse(hub.check_server_cert(force=True))
        with mock.patch.object(hub_common, "now_ms", lambda: time.time_ns() // 1_000_000 + 380 * 86400 * 1000):
            self.assertEqual(hub.pki.server_cert_state(["127.0.0.1", "10.0.0.9"]), "expiring")
        self.assertFalse(hub.check_server_cert())                                  # throttled to hourly

    def test_log_is_one_clean_line_on_stderr(self):
        import io
        hub = edr_hub.Hub(self.fx.paths, self.fx.hub.settings)
        buf = io.StringIO()
        with mock.patch.object(sys, "stderr", buf):
            hub.log("INFO", "hello\x1b[31m world\nsecond line")
        out = buf.getvalue()
        self.assertEqual(out.count("\n"), 1)
        self.assertNotIn("\x1b", out)
        self.assertTrue(out.startswith("INFO hello"))

    def test_memory_alert_is_logged_and_kept(self):
        hub = edr_hub.Hub(self.fx.paths, self.fx.hub.settings)
        hub.log = lambda level, message: None
        hub.memory_alert("CRITICAL", "hub.storage", "storage full")
        self.assertEqual(hub.memory_alerts[0]["severity"], "CRITICAL")


class StartOrderTest(unittest.TestCase):
    def test_writer_audit_listeners_sockets_engine_ready(self):
        tmp = short_tmp()
        self.addCleanup(shutil.rmtree, tmp, True)
        fleet, enroll = F.free_ports(2)
        paths = hub_common.Paths(state_dir=os.path.join(tmp, "state"), run_dir=os.path.join(tmp, "run"), etc_dir=os.path.join(tmp, "etc"))
        os.makedirs(paths.state_dir)
        os.makedirs(paths.run_dir)
        settings = hub_common.default_settings()
        settings.update({"port": fleet, "enroll_port": enroll, "public_ip": ["127.0.0.1"]})
        hub_common.save_settings(paths, settings)
        hub = edr_hub.Hub(paths, hub_common.load_settings(paths), bind="127.0.0.1")
        hub.log = lambda level, message: None
        hub.prepare()
        order = []

        class Sockets:
            def __init__(self, h):
                order.append(("sockets-init", h is hub))

            def start(self):
                order.append(("sockets", hub.ingest.fleet.is_open()))

            def stop(self):
                order.append(("sockets-stop",))

        class Engine:
            def __init__(self, h):
                order.append(("engine-init", h is hub))

            def start(self):
                order.append(("engine",))

            def stop(self):
                order.append(("engine-stop",))

        def ingest_pending(conn, h):
            order.append(("audit", h is hub, hub.writer is not None, hub.ingest is None))
            return 0
        with mock.patch.object(edr_hub.hub_ctl, "Sockets", Sockets), mock.patch.object(edr_hub.hub_engine, "Engine", Engine), \
                mock.patch.object(edr_hub.hub_audit, "ingest_pending", ingest_pending), \
                mock.patch.object(hub_common, "sd_notify", lambda msg: (order.append(("notify", msg)) if msg == "READY=1" else None) or True):
            try:
                hub.start()
                names = [o[0] for o in order if o[0] != "notify" or o[1] == "READY=1"]
                self.assertEqual(names[:6], ["audit", "sockets-init", "sockets", "engine-init", "engine", "notify"])
                self.assertEqual(order[0], ("audit", True, True, True))        # via the writer, before the listeners exist
                self.assertEqual(order[2], ("sockets", True))                  # the listeners are open before the sockets
                self.assertEqual([o for o in order if o[0] == "notify"][0], ("notify", "READY=1"))
            finally:
                hub.shutdown()
                hub.writer.stop(close=True)
        self.assertEqual([o[0] for o in order if o[0].endswith("-stop")], ["engine-stop", "sockets-stop"])


if __name__ == "__main__":
    unittest.main()
