import errno
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_daemon_support import Tmp, FakeBanEngine, FakeUplink, cfgmod, evmod, ids, CODE         # noqa: E402
from edragent import daemon, cli                                                                  # noqa: E402


def alerts(paths):
    try:
        with open(paths.alerts_jsonl) as f:
            return [json.loads(x) for x in f]
    except FileNotFoundError:
        return []


def tetragon_line(policy="nginx-exec", action="KPROBE_ACTION_SIGKILL", binary="/bin/sh"):
    return json.dumps({"process_kprobe": {"process": {"pid": 4242, "uid": 33, "binary": binary, "arguments": "-c id"},
                                         "parent": {"binary": "/usr/sbin/nginx"}, "function_name": "security_bprm_check",
                                         "args": [{"linux_binprm_arg": {"path": binary}}], "action": action, "policy_name": policy},
                       "time": "2026-11-19T10:15:02.481234567Z"}) + "\n"


class DaemonCase(Tmp):
    def _null(self):
        f = open(os.devnull, "w")
        self.addCleanup(f.close)
        return f

    def make(self, **opt):
        opt.setdefault("no_journal", True)
        opt.setdefault("interval", 0.02)
        opt.setdefault("sandbox_test", "off")
        self.bans = FakeBanEngine()
        self.up = FakeUplink()
        d = daemon.Daemon(self.paths, daemon.Options(**opt), log_stream=self._null(),
                          bans_factory=lambda cfg, paths: self.bans, uplink_factory=lambda cfg, paths, b, hb: self.up)
        self.d = d
        return d

    def run_in_thread(self, d):
        t = threading.Thread(target=d.run, daemon=True)
        t.start()
        self.addCleanup(lambda: (d.stop(), t.join(5)))
        return t

    def wait_for(self, cond, seconds=8.0):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if cond():
                return True
            time.sleep(0.02)
        return False


class TestNotify(Tmp):
    def _null(self):
        f = open(os.devnull, "w")
        self.addCleanup(f.close)
        return f

    def test_ready_and_watchdog_reach_the_notify_socket(self):
        sock_path = os.path.join(self.root, "notify.sock")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.bind(sock_path)
        s.settimeout(3)
        self.addCleanup(s.close)
        env = {"NOTIFY_SOCKET": sock_path}
        self.assertTrue(daemon.sd_notify("READY=1", env))
        self.assertEqual(s.recv(100), b"READY=1")
        self.assertTrue(daemon.sd_notify("WATCHDOG=1", env))
        self.assertEqual(s.recv(100), b"WATCHDOG=1")

    def test_without_a_socket_nothing_happens(self):
        self.assertFalse(daemon.sd_notify("READY=1", {}))
        self.assertFalse(daemon.sd_notify("READY=1", {"NOTIFY_SOCKET": "relative"}))
        self.assertFalse(daemon.sd_notify("READY=1", {"NOTIFY_SOCKET": "/nonexistent/x"}))

    def test_abstract_socket(self):
        name = "edr-agent-test-%d" % os.getpid()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.bind("\0" + name)
        s.settimeout(3)
        self.addCleanup(s.close)
        self.assertTrue(daemon.sd_notify("READY=1", {"NOTIFY_SOCKET": "@" + name}))
        self.assertEqual(s.recv(100), b"READY=1")

    def test_a_run_sends_ready_then_watchdog(self):
        sock_path = os.path.join(self.root, "n2.sock")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.bind(sock_path)
        s.settimeout(0.5)
        self.addCleanup(s.close)
        old = os.environ.get("NOTIFY_SOCKET")
        os.environ["NOTIFY_SOCKET"] = sock_path
        self.addCleanup(lambda: os.environ.pop("NOTIFY_SOCKET", None) if old is None else os.environ.__setitem__("NOTIFY_SOCKET", old))
        bans, up = FakeBanEngine(), FakeUplink()
        d = daemon.Daemon(self.paths, daemon.Options(no_journal=True, interval=0.02, duration=0.5, sandbox_test="off"),
                          log_stream=self._null(), bans_factory=lambda c, p: bans, uplink_factory=lambda c, p, b, h: up)
        self.assertEqual(d.run(), 0)
        got = []
        try:
            while True:
                got.append(s.recv(100))
        except socket.timeout:
            pass
        self.assertEqual(got[0], b"READY=1")
        self.assertIn(b"WATCHDOG=1", got)
        self.assertEqual(got[-1], b"STOPPING=1")


class TestSandboxSelfTest(unittest.TestCase):
    class Sock:
        def __init__(self, err=None):
            self.err = err

        def settimeout(self, t):
            pass

        def sendto(self, data, addr):
            self.sent = (data, addr)
            if self.err is not None:
                raise OSError(self.err, "x")

        def close(self):
            pass

    def test_eperm_is_the_filter_working(self):
        ok, detail = daemon.sandbox_selftest(lambda *a: self.Sock(errno.EPERM))
        self.assertTrue(ok)

    def test_a_sent_datagram_means_the_filter_is_not_in_force(self):
        s = self.Sock()
        ok, detail = daemon.sandbox_selftest(lambda *a: s)
        self.assertFalse(ok)
        self.assertEqual(s.sent[1], ("127.0.0.1", 9))

    def test_another_error_is_not_eperm(self):
        ok, detail = daemon.sandbox_selftest(lambda *a: self.Sock(errno.ENETUNREACH))
        self.assertFalse(ok)


class TestStart(DaemonCase):
    def test_agent_start_event_and_clean_shutdown_marker(self):
        d = self.make(duration=0.3)
        self.assertEqual(d.run(), 0)
        kinds = [e["kind"] for e in self.up.submitted]
        self.assertEqual(kinds[0], "health.agent_start")
        e = self.up.submitted[0]
        self.assertEqual((e["sev"], e["source"]), ("INFO", "agent"))
        self.assertFalse(e["details"]["clean_shutdown"])
        self.assertIsNone(e["details"]["last_seen"])
        self.assertTrue(self.up.started)
        self.assertIs(self.up.stopped, False)
        self.assertTrue(os.path.exists(self.paths.clean_marker))
        self.assertFalse(os.path.exists(self.paths.pid_file))
        epoch = e["epoch"]
        d2 = self.make(duration=0.3)
        d2.run()
        e2 = self.up.submitted[0]
        self.assertTrue(e2["details"]["clean_shutdown"])
        self.assertEqual(e2["epoch"], epoch)                                    # a clean shutdown continues the epoch
        self.assertGreater(e2["seq"], e["seq"])
        self.assertIsNotNone(e2["details"]["last_seen"])

    def test_a_crash_starts_a_new_epoch(self):
        d = self.make(duration=0.2)
        d.run()
        epoch = self.up.submitted[0]["epoch"]
        os.unlink(self.paths.clean_marker)
        d2 = self.make(duration=0.2)
        d2.run()
        self.assertNotEqual(self.up.submitted[0]["epoch"], epoch)
        self.assertFalse(self.up.submitted[0]["details"]["clean_shutdown"])

    def test_sandbox_self_test_failure_is_high(self):
        d = self.make(duration=0.2, sandbox_test="on")
        d.run()
        kinds = {e["kind"]: e for e in self.up.submitted}
        # a normal test environment has no IPAddressDeny: the datagram goes out
        self.assertIn("health.sandbox_ineffective", kinds)
        self.assertEqual(kinds["health.sandbox_ineffective"]["sev"], "HIGH")

    def test_sandbox_self_test_is_skipped_outside_a_service_by_default(self):
        d = self.make(duration=0.2, sandbox_test="auto")
        d.run()
        self.assertNotIn("health.sandbox_ineffective", [e["kind"] for e in self.up.submitted])

    def test_invalid_config_keeps_the_last_good_copy_and_raises_high(self):
        self.write(self.paths.local_conf, "[bans]\nauto_ban = observe\n")
        d = self.make(duration=0.2)
        d.run()
        self.assertNotIn("health.config_invalid", [e["kind"] for e in self.up.submitted])
        self.write(self.paths.local_conf, "[bans]\nauto_ban = bogus\n")
        d = self.make(duration=0.2)
        d.run()
        e = [x for x in self.up.submitted if x["kind"] == "health.config_invalid"]
        self.assertEqual(len(e), 1)
        self.assertEqual((e[0]["sev"], e[0]["details"]["using"]), ("HIGH", "last-good"))
        self.assertIn("auto_ban", e[0]["details"]["errors"][0])
        self.assertEqual(d.cfg["bans"]["auto_ban"], "observe")                  # detection goes on with the last good values
        self.assertIn("health.config_invalid", [a["kind"] for a in alerts(self.paths)])

    def test_reload_changes_the_shared_config_object_in_place(self):
        d = self.make(duration=0.2)
        d.run()
        held = d.cfg                                                            # what the ban engine would hold
        self.write(self.paths.local_conf, "[bans]\nauto_ban = off\n")
        d.reload_config()
        self.assertEqual(held["bans"]["auto_ban"], "off")
        self.write(self.paths.local_conf, "[nope]\n")
        d.reload_config()
        self.assertEqual(held["bans"]["auto_ban"], "off")                       # the last good copy
        self.assertEqual(sum(1 for e in d.inbox.queue) if hasattr(d.inbox, "queue") else 0, 0)

    def test_the_bans_and_the_uplink_get_the_config_paths_and_the_heartbeat(self):
        got = {}
        up = FakeUplink()

        def uplink_factory(cfg, paths, bans, hb):
            got.update(cfg=cfg, paths=paths, bans=bans, hb=hb)
            return up
        bans = FakeBanEngine()
        d = daemon.Daemon(self.paths, daemon.Options(no_journal=True, interval=0.02, duration=0.2, sandbox_test="off"),
                          log_stream=self._null(), bans_factory=lambda c, p: bans, uplink_factory=uplink_factory)
        d.run()
        self.assertIs(got["bans"], bans)
        self.assertIs(got["cfg"], d.cfg)
        hb = got["hb"]()
        self.assertEqual(hb["agent_version"], "0.1.0")


class TestLoop(DaemonCase):
    def test_lines_in_the_logs_become_events_and_alerts(self):
        d = self.make()
        self.write(self.paths.tetragon_log, "")
        self.run_in_thread(d)
        self.assertTrue(self.wait_for(lambda: d.pipeline is not None and d.sources))
        self.append(self.paths.tetragon_log, tetragon_line())
        self.assertTrue(self.wait_for(lambda: any(e["kind"] == "tetragon.nginx-exec" for e in self.up.submitted)))
        self.assertTrue(self.wait_for(lambda: any(a["kind"] == "tetragon.nginx-exec" for a in alerts(self.paths))))
        self.assertEqual([e["kind"] for e in self.bans.observed][:2], ["health.agent_start", "tetragon.nginx-exec"])

    def test_checkpoints_follow_the_batches(self):
        d = self.make()
        self.write(self.paths.tetragon_log, tetragon_line(policy="web-exec", action=None))
        self.run_in_thread(d)
        self.assertTrue(self.wait_for(lambda: any(e["kind"] == "tetragon.web-exec" for e in self.up.submitted)))
        cur = os.path.join(self.paths.cursors_dir, "tetragon.json")
        self.assertTrue(self.wait_for(lambda: os.path.exists(cur)))
        with open(cur) as f:
            self.assertEqual(json.load(f)["offset"], os.path.getsize(self.paths.tetragon_log))

    def test_a_broken_reader_does_not_stop_the_others(self):
        d = self.make()
        self.write(self.paths.tetragon_log, "")
        self.run_in_thread(d)
        self.assertTrue(self.wait_for(lambda: d.sources))

        class Boom:
            name = "boom"

            def poll(self, now):
                raise RuntimeError("reader bug")

            def commit(self):
                pass

            def close(self):
                pass
        d.sources.insert(0, Boom())
        self.append(self.paths.tetragon_log, tetragon_line())
        self.assertTrue(self.wait_for(lambda: any(e["kind"] == "tetragon.nginx-exec" for e in self.up.submitted)))

    def test_events_the_uplink_makes_go_through_the_pipeline_by_the_inbox(self):
        d = self.make()
        self.run_in_thread(d)
        self.assertTrue(self.wait_for(lambda: self.up.local_event_cb is not None))
        self.up.local_event_cb(evmod.make_event("health.spool_dropped", "agent", "MEDIUM", "spool dropped 3", details={"lane": "lo", "count": 3}))
        self.assertTrue(self.wait_for(lambda: any(e["kind"] == "health.spool_dropped" for e in self.up.submitted)))
        e = [x for x in self.up.submitted if x["kind"] == "health.spool_dropped"][0]
        self.assertIn("id", e)

    def test_the_summary_shows_the_agent_and_the_hub_mode(self):
        d = self.make()
        self.run_in_thread(d)
        self.assertTrue(self.wait_for(lambda: os.path.exists(self.paths.summary_json)))
        with open(self.paths.summary_json) as f:
            s = json.load(f)
        self.assertEqual(s["hub"]["mode"], "local")
        self.assertEqual(s["agent"]["pid"], os.getpid())
        self.assertTrue(os.path.exists(self.paths.pid_file))

    def test_hub_unreachable_for_15_minutes_warns_and_marks_the_pipeline(self):
        d = self.make(duration=0.2)
        d.run()
        d.started = self.clock() - 3000
        d.clock = self.clock
        d.last_hub = (0.0, {})
        self.up.mode = "enrolled"
        self.up.status = lambda: {"mode": "enrolled", "hub": "203.0.113.5:8443", "last_heartbeat_ok": self.clock() - 1200, "last_error": "timeout"}
        d.pipeline.clock = self.clock
        d.hub_down_since_warn = 0.0
        d.tick(self.clock())
        self.assertTrue(d.pipeline.hub_down)
        self.assertIn("health.hub_unreachable", [e["kind"] for e in self.up.submitted])
        d.tick(self.clock() + 1)
        self.assertEqual(sum(1 for e in self.up.submitted if e["kind"] == "health.hub_unreachable"), 1)    # recurring, not every second

    def test_local_mode_is_complete_without_a_hub(self):
        d = self.make(duration=0.5)
        self.write(self.paths.tetragon_log, tetragon_line() + tetragon_line(policy="web-exec", action=None))
        d.run()
        self.assertEqual(len([a for a in alerts(self.paths) if a["kind"].startswith("tetragon.")]), 2)


class TestEndToEnd(Tmp):
    """The agent runs unprivileged from the checkout with EDR_AGENT_ROOT and --no-journal."""

    def lines(self):
        return [
            (self.paths.tetragon_log, tetragon_line(policy="web-exec", action=None)),
            (self.paths.nginx_error_log, "2026/11/19 10:15:02 [alert] 1000#1000: worker process 2222 exited on signal 11\n"),
            (self.paths.nginx_access_log, '203.0.113.9 - - [19/Nov/2026:10:15:02 +0000] "GET /.env HTTP/1.1" 200 5 "-" "curl"\n'),
        ]

    def test_in_process_with_the_real_cli(self):
        for path, text in self.lines():
            self.write(path, text)
        self.write(self.paths.nginx_pid, "1000\n")
        old = os.environ.get("EDR_AGENT_ROOT")
        os.environ["EDR_AGENT_ROOT"] = self.root
        self.addCleanup(lambda: os.environ.pop("EDR_AGENT_ROOT", None) if old is None else os.environ.__setitem__("EDR_AGENT_ROOT", old))
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["run", "--foreground", "--no-journal", "--duration", "1.5", "--interval", "0.05"])
        self.assertEqual(code, 0)
        kinds = {a["kind"]: a for a in alerts(self.paths)}
        self.assertIn("tetragon.web-exec", kinds)
        self.assertIn("canary.tripwire", kinds)
        self.assertEqual(kinds["canary.tripwire"]["sev"], "HIGH")
        self.assertEqual(kinds["canary.tripwire"]["src_ip"], "203.0.113.9")

    def test_as_a_subprocess_unprivileged_style(self):
        """edr-agent.py run --foreground --no-journal with EDR_AGENT_ROOT: lines written under the prefix give a HIGH alert."""
        if not all(os.path.exists(os.path.join(CODE, "edragent", n)) for n in ("bans.py", "uplink.py", "spool.py", "transport.py")):
            self.skipTest("the real ban engine and uplink are not present; the in-process test covers the loop")
        env = dict(os.environ, EDR_AGENT_ROOT=self.root)
        script = os.path.join(CODE, "edr-agent.py")
        for path, text in self.lines()[:1]:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "w").close()
        proc = subprocess.Popen([sys.executable, "-I", script, "run", "--foreground", "--no-journal"], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not os.path.exists(self.paths.pid_file):
                time.sleep(0.05)
            self.assertTrue(os.path.exists(self.paths.pid_file), "the agent did not start")
            self.append(self.paths.tetragon_log, tetragon_line(policy="web-exec", action=None))
            found = False
            while time.monotonic() < deadline:
                if any(a["kind"] == "tetragon.web-exec" and a["sev"] == "HIGH" for a in alerts(self.paths)):
                    found = True
                    break
                time.sleep(0.1)
            self.assertTrue(found, "no HIGH alert in alerts.jsonl")
        finally:
            proc.terminate()
            try:
                out, err = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
        self.assertEqual(proc.returncode, 0, err.decode(errors="replace")[-500:])
        self.assertTrue(os.path.exists(self.paths.clean_marker))        # SIGTERM: a clean shutdown


if __name__ == "__main__":
    unittest.main()
