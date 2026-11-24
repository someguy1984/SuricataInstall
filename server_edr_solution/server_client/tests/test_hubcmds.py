import argparse
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

import test_transport_pki as support
from test_transport_pki import HubPair, err, reply, wait_for
from edragent import bans as bm
from edragent import cli
from edragent import hubcmds as hc
from edragent import identity as idn
from edragent import spool as sp
from edragent import transport as tr

T = time.time


def parser():
    ap = argparse.ArgumentParser(prog="edr-agent")
    sub = ap.add_subparsers(dest="cmd")
    hc.register(sub)
    return ap


def run(argv, stdin=None):
    ap = parser()
    args = ap.parse_args(argv)
    out, errb = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(errb):
        if stdin is not None:
            with mock.patch.object(sys, "stdin", io.StringIO(stdin)):
                rc = args.func(args)
        else:
            rc = args.func(args)
    return rc, out.getvalue(), errb.getvalue()


class Case(unittest.TestCase):
    def setUp(self):
        self.env = support.Env()
        self.addCleanup(self.env.cleanup)
        self.p = self.env.paths
        self.env.set_droplet("424242")
        self.hubs = HubPair()
        self.addCleanup(self.hubs.stop)
        real_run = subprocess.run

        def guarded(args, *a, **kw):
            # openssl is fine; nothing may touch the host's services or firewall
            if os.path.basename(str(args[0])) in ("systemctl", "systemd-run", "nft", "iptables", "sysctl", "chown", "useradd"):
                raise AssertionError("a host command was run: %r" % (args,))
            return real_run(args, *a, **kw)
        self.guard = mock.patch("subprocess.run", side_effect=guarded)
        self.guard.start()
        self.addCleanup(self.guard.stop)

    def hubargs(self, hub=None):
        return ["--hub", "127.0.0.1:%d" % (hub or self.hubs).fleet_port, "--enroll-port", str((hub or self.hubs).enroll_port)]

    def tokfile(self, token=None, mode=0o600):
        p = os.path.join(self.env.root, "edr.token")
        with open(p, "w") as f:
            f.write((token or self.hubs.token) + "\n")
        os.chmod(p, mode)
        return p


class TestRegister(unittest.TestCase):
    def test_subcommands_and_funcs(self):
        ap = parser()
        for argv in (["enroll"], ["rehome"], ["bans"], ["unban", "--all"], ["pause"], ["resume"], ["deregister"], ["hub-net"], ["rehome-resume"],
                     ["rehome", "--rollback"], ["rehome", "--drop-spool"], ["pause", "--for", "5m"], ["unban", "198.51.100.7"]):
            a = ap.parse_args(argv)
            self.assertTrue(callable(a.func), argv)

    def test_help_hides_the_internal_subcommand(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                parser().parse_args(["-h"])
        self.assertIn("enroll", buf.getvalue())
        self.assertNotIn("SUPPRESS", buf.getvalue())
        self.assertFalse([l for l in buf.getvalue().splitlines() if l.strip().startswith("hub-net ")])
        self.assertFalse([l for l in buf.getvalue().splitlines() if l.strip().startswith("rehome-resume")])


class TestEnroll(Case):
    def test_token_on_the_command_line_is_refused(self):
        rc, out, errs = run(["enroll"] + self.hubargs() + ["--token", self.hubs.token])
        self.assertEqual(rc, hc.EXIT_USAGE)
        self.assertIn("--token-file", errs)
        self.assertNotIn(self.hubs.secret, out + errs)
        self.assertEqual(self.hubs.enroll.requests, [])

    def test_token_from_stdin(self):
        rc, out, errs = run(["enroll"] + self.hubargs() + ["--token", "-"], stdin=self.hubs.token + "\n")
        self.assertEqual(rc, 0, errs)
        self.assertIn("enrolled: host %s" % self.hubs.uuid, out)
        self.assertIn("pending", out)
        self.assertNotIn(self.hubs.secret, out + errs)
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")
        self.assertEqual(idn.read_host_id(self.p), self.hubs.uuid)

    def test_token_from_a_file_and_the_environment(self):
        rc, out, errs = run(["enroll"] + self.hubargs() + ["--token-file", self.tokfile()])
        self.assertEqual(rc, 0, errs)
        self.assertEqual(errs, "")
        shutil.rmtree(str(self.p.identity_dir))
        hubs2 = HubPair(uuid_="33333333-3333-4333-8333-333333333333")
        self.addCleanup(hubs2.stop)
        with mock.patch.dict(os.environ, {"EDR_TOKEN": hubs2.token}):
            rc, out, errs = run(["enroll"] + self.hubargs(hubs2))
        self.assertEqual(rc, 0, errs)
        self.assertEqual(idn.read_host_id(self.p), hubs2.uuid)

    def test_a_world_readable_token_file_warns(self):
        rc, out, errs = run(["enroll"] + self.hubargs() + ["--token-file", self.tokfile(mode=0o644)])
        self.assertEqual(rc, 0)
        self.assertIn("readable by others", errs)

    def test_bad_token_files(self):
        big = os.path.join(self.env.root, "big")
        with open(big, "w") as f:
            f.write("x" * 2000)
        link = os.path.join(self.env.root, "link")
        os.symlink(self.tokfile(), link)
        for path in (big, link, os.path.join(self.env.root, "missing")):
            rc, out, errs = run(["enroll"] + self.hubargs() + ["--token-file", path])
            self.assertEqual(rc, hc.EXIT_REFUSED, path)
        rc, out, errs = run(["enroll"] + self.hubargs() + ["--token", "-"], stdin="junk")
        self.assertEqual(rc, hc.EXIT_REFUSED)
        rc, out, errs = run(["enroll"] + self.hubargs())
        self.assertEqual(rc, hc.EXIT_USAGE)                         # no token at all
        self.assertEqual(self.hubs.enroll.requests, [])

    def test_hub_is_required_in_local_mode(self):
        rc, out, errs = run(["enroll", "--token-file", self.tokfile()])
        self.assertEqual(rc, hc.EXIT_USAGE)
        self.assertIn("--hub", errs)

    def test_reenrollment_defaults_to_the_stored_hub(self):
        run(["enroll"] + self.hubargs() + ["--token-file", self.tokfile()])
        self.hubs.uuid = "44444444-4444-4444-8444-444444444444"
        self.hubs.secret = "othersecret123456"
        rc, out, errs = run(["enroll", "--token-file", self.tokfile()])
        self.assertEqual(rc, 0, errs)
        self.assertEqual(idn.read_host_id(self.p), "44444444-4444-4444-8444-444444444444")

    def test_an_enrolled_host_is_not_enrolled_with_another_hub_and_not_during_a_rehome(self):
        run(["enroll"] + self.hubargs() + ["--token-file", self.tokfile()])
        other = HubPair(uuid_="55555555-5555-4555-8555-555555555555")
        self.addCleanup(other.stop)
        rc, out, errs = run(["enroll"] + self.hubargs(other) + ["--token-file", self.tokfile(other.token)])
        self.assertEqual(rc, hc.EXIT_REFUSED)
        self.assertIn("rehome", errs)
        self.assertEqual(other.enroll.requests, [])
        sp.atomic_write(os.path.join(str(self.p.identity_dir), "rehome.json"), "{}", 0o600)
        rc, out, errs = run(["enroll"] + self.hubargs() + ["--token-file", self.tokfile()])
        self.assertEqual(rc, hc.EXIT_REFUSED)
        self.assertIn("--rollback", errs)

    def test_failures_that_leave_local_mode_exit_5(self):
        bad_hash = "tok12345.secretsecret1234." + "0" * 64
        rc, out, errs = run(["enroll"] + self.hubargs() + ["--token-file", self.tokfile(bad_hash)])
        self.assertEqual(rc, hc.EXIT_NOT_ENROLLED)
        self.assertIn("not enrolled", errs)
        self.hubs.responses["/v1/enroll"] = lambda r: err(401, "invalid_token")
        rc, out, errs = run(["enroll"] + self.hubargs() + ["--token-file", self.tokfile()])
        self.assertEqual(rc, hc.EXIT_NOT_ENROLLED)
        self.assertIn("new token", errs)
        self.hubs.responses["/v1/enroll"] = lambda r: err(409, "host_exists")
        rc, out, errs = run(["enroll"] + self.hubargs() + ["--token-file", self.tokfile()])
        self.assertEqual(rc, hc.EXIT_NOT_ENROLLED)
        self.assertIn("--for HOST", errs)
        self.hubs.responses.clear()
        self.hubs.enroll_tweak = lambda rep: rep.update(port=1)
        rc, out, errs = run(["enroll"] + self.hubargs() + ["--token-file", self.tokfile()])
        self.assertEqual(rc, hc.EXIT_NOT_ENROLLED)                 # a reply that does not validate aborts with exit 5
        self.assertIsNone(idn.current_gen_name(self.p))
        self.assertEqual(idn.gen_numbers(self.p), [])
        self.assertFalse(os.path.exists(self.p.host_id))

    def test_hub_unreachable_is_exit_5(self):
        dead = HubPair()
        ports = (dead.fleet_port, dead.enroll_port)
        dead.stop()
        rc, out, errs = run(["enroll", "--hub", "127.0.0.1:%d" % ports[0], "--enroll-port", str(ports[1]), "--token-file", self.tokfile()])
        self.assertEqual(rc, hc.EXIT_NOT_ENROLLED)

    def test_droplet_id_rules(self):
        os.unlink(self.p.droplet_id)
        rc, out, errs = run(["enroll"] + self.hubargs() + ["--token-file", self.tokfile()])
        self.assertEqual(rc, hc.EXIT_REFUSED)
        self.assertIn("--droplet-id", errs)
        rc, out, errs = run(["enroll"] + self.hubargs() + ["--token-file", self.tokfile(), "--droplet-id", "bad id"])
        self.assertEqual(rc, hc.EXIT_REFUSED)
        rc, out, errs = run(["enroll"] + self.hubargs() + ["--token-file", self.tokfile(), "--droplet-id", "mock-1"])
        self.assertEqual(rc, 0, errs)
        self.assertEqual(self.hubs.enroll.requests[1].json()["droplet_id"], "mock-1")
        self.assertEqual(idn.stored_droplet_id(self.p), "mock-1")
        # with the metadata id known, --droplet-id is refused
        self.env.set_droplet("424242")
        shutil.rmtree(str(self.p.identity_dir))
        rc, out, errs = run(["enroll"] + self.hubargs() + ["--token-file", self.tokfile(), "--droplet-id", "mock-1"])
        self.assertEqual(rc, hc.EXIT_REFUSED)
        self.assertIn("metadata", errs)

    def test_a_clone_gets_no_uuid_hint_through_the_cli(self):
        idn.write_host_id(self.p, "99999999-aaaa-4bbb-8ccc-dddddddddddd")
        idn.write_stored_droplet_id(self.p, "111111")
        rc, out, errs = run(["enroll"] + self.hubargs() + ["--token-file", self.tokfile()])
        self.assertEqual(rc, 0, errs)
        self.assertNotIn("host_uuid", self.hubs.enroll.requests[1].json())


class TestHubNet(Case):
    def test_the_sandboxed_phase_reads_json_and_answers_json(self):
        n, csr = idn.new_generation(self.p)
        params = {"hub": "127.0.0.1", "port": self.hubs.fleet_port, "enroll_port": self.hubs.enroll_port,
                  "gen_dir": idn.gen_path(self.p, n), "csr": csr, "droplet_id": "424242", "hostname": "web1", "os": "x", "ips": []}
        rc, out, errs = run(["hub-net"], stdin=json.dumps({"params": params, "token": self.hubs.token}))
        self.assertEqual(rc, 0)
        res = json.loads(out.strip().splitlines()[-1])
        self.assertTrue(res["ok"])
        self.assertEqual(res["reply"]["host_uuid"], self.hubs.uuid)
        self.assertNotIn("certificate", res["reply"])
        self.assertNotIn(self.hubs.secret, out)
        self.assertTrue(os.path.exists(os.path.join(params["gen_dir"], "client.pem")))
        bad = dict(params)
        rc, out, errs = run(["hub-net"], stdin=json.dumps({"params": bad, "token": "tok12345.secretsecret1234." + "0" * 64}))
        res = json.loads(out.strip().splitlines()[-1])
        self.assertFalse(res["ok"])
        self.assertEqual(res["code"], 2)
        rc, out, errs = run(["hub-net"], stdin="not json")
        self.assertFalse(json.loads(out)["ok"])


class TestRehome(Case):
    def setUp(self):
        super().setUp()
        self.old = HubPair(uuid_="11111111-1111-4111-8111-111111111111", token_id="oldtok123", secret="oldsecret1234567")
        self.addCleanup(self.old.stop)
        support.make_identity(self.env, self.old.pki, self.old.fleet_port, cn=self.old.uuid, enroll_port=self.old.enroll_port)
        idn.SystemOps(self.p).write_dropin(["127.0.0.1"])
        idn.write_host_id(self.p, self.old.uuid)
        idn.write_stored_droplet_id(self.p, "424242")

    def agent(self, ok=True):
        """A stand-in for the restarted agent: once `current` changes, report a heartbeat and a poll on it."""
        def loop():
            cur = os.path.join(str(self.p.identity_dir), "current")
            end = time.time() + 20
            while time.time() < end:
                try:
                    name = os.readlink(cur)
                except OSError:
                    name = ""
                if name == "gen-2" and ok:
                    now = time.time() + 1
                    sp.atomic_write(os.path.join(str(self.p.run_dir), "uplink.json"), json.dumps(
                        {"gen": "gen-2", "hb_gen": "gen-2", "last_heartbeat_ok": now, "policy_gen": "gen-2", "last_policy_ok": now}), 0o644)
                    return
                time.sleep(0.05)
        t = threading.Thread(target=loop, daemon=True)
        t.start()
        return t

    def test_rehome_end_to_end(self):
        self.agent()
        rc, out, errs = run(["rehome"] + self.hubargs() + ["--token-file", self.tokfile()])
        self.assertEqual(rc, 0, out + errs)
        self.assertIn("rehomed", out)
        self.assertEqual(idn.current_gen_name(self.p), "gen-2")
        self.assertEqual(idn.gen_numbers(self.p), [2])
        self.assertEqual(idn.read_host_id(self.p), self.hubs.uuid)
        self.assertEqual(self.old.deregistered, [(self.old.uuid, {"reason": "rehome"})])
        self.assertNotIn(self.hubs.secret, out + errs)

    def test_unconfirmed_rehome_rolls_back_with_exit_4(self):
        with open(self.p.local_conf, "w") as f:
            f.write("[agent]\nrehome_confirm_timeout = 1s\n")
        self.agent(ok=False)
        rc, out, errs = run(["rehome"] + self.hubargs() + ["--token-file", self.tokfile()])
        self.assertEqual(rc, hc.EXIT_ROLLED_BACK, out + errs)
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")
        self.assertEqual(idn.gen_numbers(self.p), [1])
        self.assertEqual(idn.read_host_id(self.p), self.old.uuid)

    def test_rollback_with_nothing_pending_is_a_no_op(self):
        rc, out, errs = run(["rehome", "--rollback"])
        self.assertEqual(rc, 0)
        self.assertIn("no rehome", out)
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")

    def test_rehome_resume_with_nothing_pending_does_nothing_and_exits_0(self):
        rc, out, errs = run(["rehome-resume"])
        self.assertEqual((rc, out, errs), (0, "", ""))
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")

    def test_rehome_resume_finishes_a_move_killed_in_step_7(self):
        real = idn.deregister
        self.agent()

        def killed(*a, **kw):
            raise SystemExit("killed")
        with mock.patch.object(idn, "deregister", killed), self.assertRaises(SystemExit):
            run(["rehome"] + self.hubargs() + ["--token-file", self.tokfile()])
        self.assertTrue(idn.rehome_in_progress(self.p))
        self.assertEqual(idn.gen_numbers(self.p), [1, 2])
        rc, out, errs = run(["rehome-resume"])
        self.assertEqual(rc, 0, out + errs)
        self.assertIn("finishing the cleanup", out)
        self.assertFalse(idn.rehome_in_progress(self.p))
        self.assertEqual((idn.current_gen_name(self.p), idn.gen_numbers(self.p)), ("gen-2", [2]))
        self.assertIs(idn.deregister, real)

    def test_usage_and_refusals(self):
        rc, out, errs = run(["rehome", "--token-file", self.tokfile()])
        self.assertEqual(rc, hc.EXIT_USAGE)
        rc, out, errs = run(["rehome"] + self.hubargs() + ["--token", "SECRET"])
        self.assertEqual(rc, hc.EXIT_USAGE)
        self.assertNotIn("SECRET", out + errs)
        shutil.rmtree(str(self.p.identity_dir))
        rc, out, errs = run(["rehome"] + self.hubargs() + ["--token-file", self.tokfile()])
        self.assertEqual(rc, hc.EXIT_REFUSED)                       # not enrolled: nothing changed
        self.assertEqual(self.hubs.enroll.requests, [])

    def test_validation_failure_exits_3_and_changes_nothing(self):
        self.hubs.enroll_tweak = lambda rep: rep.update(port=rep["port"] + 1)
        rc, out, errs = run(["rehome"] + self.hubargs() + ["--token-file", self.tokfile()])
        self.assertEqual(rc, hc.EXIT_REFUSED)
        self.assertEqual(idn.gen_numbers(self.p), [1])
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")

    def test_drop_spool_flag_reaches_the_agent(self):
        seen = []

        def watch():
            flag = os.path.join(str(self.p.identity_dir), "drop-spool.flag")
            end = time.time() + 15
            while time.time() < end:
                if os.path.exists(flag):
                    seen.append(True)
                    return
                time.sleep(0.02)
        t = threading.Thread(target=watch, daemon=True)
        t.start()
        self.agent()
        rc, out, errs = run(["rehome", "--drop-spool"] + self.hubargs() + ["--token-file", self.tokfile()])
        t.join(3)
        self.assertEqual(rc, 0, out + errs)
        self.assertEqual(seen, [True])


class BanFiles(Case):
    def engine(self):
        e = bm.BanEngine({"bans": {}, "thresholds": {}, "sites": {}}, self.p, proc_dir=os.path.join(self.env.root, "proc"),
                         resolv_conf="/nonexistent", utmp_path="/nonexistent")
        return e

    def ban(self, e, ip, n=5):
        from edragent import event as evmod
        for _ in range(n):
            e.observe(evmod.make_event("ssh.fail", "journal", "LOW", "x", src_ip=ip, src_trust="tcp"), T())


class TestBansCommand(BanFiles):
    def test_prints_source_remaining_and_counts(self):
        e = self.engine()
        self.ban(e, "198.51.100.7")
        self.ban(e, "2001:db8:1:2::9")
        e.flush()
        with open(self.p.bans_json) as f:
            doc = json.load(f)
        doc["bans"].append({"cidr": "198.51.100.99/32", "expires": int(T()) + 600, "source": "fleet", "reason": "fleet_quorum"})
        doc["feeds"] = {"dshield": {"expires": int(T()) + 100, "cidrs": ["198.51.100.0/24", "203.0.113.0/24"]}}
        sp.atomic_write(self.p.bans_json, json.dumps(doc), 0o644)
        rc, out, errs = run(["bans"])
        self.assertEqual(rc, 0)
        self.assertIn("198.51.100.7/32", out)
        self.assertIn("2001:db8:1:2::/64", out)
        self.assertIn("fleet", out)
        self.assertIn("ssh_fail", out)
        self.assertRegex(out, r"59m\d\ds|1h0m")
        self.assertIn("feed dshield: 2 entries", out)
        self.assertEqual(errs, "")

    def test_no_bans_and_a_pause(self):
        rc, out, errs = run(["bans"])
        self.assertIn("no active bans", out)
        with open(self.p.pause_json, "w") as f:
            json.dump({"until": int(T()) + 600}, f)
        rc, out, errs = run(["bans"])
        self.assertIn("PAUSED until", out)

    def test_hostile_files_are_never_followed_or_trusted(self):
        e = self.engine()
        self.ban(e, "198.51.100.7")
        e.flush()
        real = self.p.ban_state
        secret = os.path.join(self.env.root, "secret.json")
        with open(secret, "w") as f:
            json.dump({"v": 1, "bans": [{"cidr": "203.0.113.200/32", "expires": int(T()) + 999, "source": "local", "reason": "ssh_fail"}]}, f)
        for p in (real, self.p.bans_json):
            os.unlink(p)
            os.symlink(secret, p)                                   # a symlink is ignored
        rc, out, errs = run(["bans"])
        self.assertNotIn("203.0.113.200", out)
        self.assertIn("no active bans", out)
        for p in (real, self.p.bans_json):
            os.unlink(p)
            os.mkfifo(p)                                            # a FIFO must not hang the command
        t0 = time.time()
        rc, out, errs = run(["bans"])
        self.assertLess(time.time() - t0, 3)
        for p in (real, self.p.bans_json):
            os.unlink(p)
            with open(p, "w") as f:
                f.write(" " * (17 * 1024 * 1024))                   # over the cap
        rc, out, errs = run(["bans"])
        self.assertEqual(rc, 0)
        self.assertIn("no active bans", out)

    def test_values_are_validated_and_cleaned(self):
        now = int(T())
        doc = {"v": 1, "written_at": now, "empty": False, "never": ["junk", "10.0.0.0/8"], "feeds": {"evil\x1b[31m": {"cidrs": ["1.2.3.0/24"]}},
               "bans": [{"cidr": "198.51.100.7/32", "expires": now + 600, "source": "\x1b[31mlocal", "reason": "pwned\nline2"},
                        {"cidr": "198.51.100.8\x1b/32", "expires": now + 600, "source": "local", "reason": "ssh_fail"},
                        {"cidr": "198.51.100.9/32", "expires": "never", "source": "local", "reason": "ssh_fail"},
                        {"cidr": "198.51.100.10/32", "expires": now + 600, "source": "operator", "reason": "operator"},
                        {"cidr": "198.51.100.11/32", "expires": now - 5, "source": "local", "reason": "ssh_fail"}, 5]}
        sp.atomic_write(self.p.bans_json, json.dumps(doc), 0o644)
        rc, out, errs = run(["bans"])
        self.assertNotIn("\x1b", out)
        self.assertIn("198.51.100.7/32", out)
        self.assertIn("unknown", out)                                   # a value outside the closed vocabulary shows as unknown
        self.assertNotIn("pwned", out)
        self.assertNotIn("198.51.100.8", out)
        self.assertNotIn("198.51.100.9", out)
        self.assertIn("198.51.100.10/32", out)
        self.assertNotIn("198.51.100.11", out)                          # expired
        for line in out.splitlines():
            self.assertTrue(all(32 <= ord(c) < 127 for c in line))


class TestUnban(BanFiles):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(hc, "CMD_WAIT_S", 0.6)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_without_a_running_agent_the_state_files_change_and_say_empty(self):
        e = self.engine()
        self.ban(e, "198.51.100.7")
        e.flush()
        with open(self.p.bans_json) as f:
            self.assertFalse(json.load(f)["empty"])
        rc, out, errs = run(["unban", "198.51.100.7"])
        self.assertEqual(rc, 0, errs)
        self.assertIn("removed: 198.51.100.7/32", out)
        self.assertIn("did not answer", out)
        with open(self.p.bans_json) as f:
            doc = json.load(f)
        self.assertEqual(doc["bans"], [])
        self.assertTrue(doc["empty"])                                   # explicit empty state, or edr-bans keeps the old one
        e2 = self.engine()
        self.assertEqual(e2.active_bans(), [])
        self.ban(e2, "198.51.100.7", 20)
        self.assertEqual(e2.active_bans(), [])                          # an allow entry: the ladder does not re-ban it
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.p.ban_state), "ban-cmd.json")))
        self.assertEqual(stat.S_IMODE(os.stat(self.p.ban_state).st_mode), 0o600)

    def test_unban_all_without_an_agent(self):
        e = self.engine()
        self.ban(e, "198.51.100.7")
        self.ban(e, "198.51.100.8")
        e.flush()
        rc, out, errs = run(["unban", "--all"])
        self.assertEqual(rc, 0)
        self.assertIn("explicit empty state", out)
        with open(self.p.bans_json) as f:
            doc = json.load(f)
        self.assertEqual((doc["bans"], doc["empty"]), ([], True))
        e2 = self.engine()
        self.assertEqual((e2.active_bans(), e2.memory), ([], {}))

    def test_a_running_agent_answers_through_the_inbox(self):
        e = self.engine()
        self.ban(e, "198.51.100.7")
        e.flush()
        stop = threading.Event()

        def agent():
            while not stop.is_set():
                e.tick(T())
                time.sleep(0.05)
        t = threading.Thread(target=agent, daemon=True)
        t.start()
        self.addCleanup(t.join, 2)
        self.addCleanup(stop.set)
        with mock.patch.object(hc, "CMD_WAIT_S", 5):
            rc, out, errs = run(["unban", "198.51.100.7"])
        self.assertEqual(rc, 0, errs)
        self.assertIn("removed: 198.51.100.7/32", out)
        self.assertNotIn("did not answer", out)
        self.assertEqual(e.active_bans(), [])
        with mock.patch.object(hc, "CMD_WAIT_S", 5):
            rc, out, errs = run(["unban", "--all"])
        self.assertIn("all local bans removed", out)

    def test_usage(self):
        self.assertEqual(run(["unban"])[0], hc.EXIT_USAGE)
        self.assertEqual(run(["unban", "--all", "198.51.100.7"])[0], hc.EXIT_USAGE)
        rc, out, errs = run(["unban", "not-an-ip"])
        self.assertEqual(rc, hc.EXIT_USAGE)
        rc, out, errs = run(["unban", "198.51.100.7/24"])
        self.assertEqual(rc, hc.EXIT_USAGE)                              # host bits set
        rc, out, errs = run(["unban", "198.51.100.77"])
        self.assertEqual(rc, 0)
        self.assertIn("no local ban covers", out)


class TestPause(Case):
    def pause_doc(self):
        with open(self.p.pause_json) as f:
            return json.load(f)

    def test_pause_writes_the_file_for_the_consumers(self):
        rc, out, errs = run(["pause"])
        self.assertEqual(rc, 0, errs)
        d = self.pause_doc()
        self.assertEqual(list(d), ["until"])
        self.assertAlmostEqual(d["until"], T() + 3600, delta=5)
        self.assertEqual(stat.S_IMODE(os.stat(self.p.pause_json).st_mode), 0o640)
        self.assertIn("paused until", out)
        rc, out, errs = run(["pause", "--for", "30m"])
        self.assertAlmostEqual(self.pause_doc()["until"], T() + 1800, delta=5)
        rc, out, errs = run(["pause", "--for", "24h"])
        self.assertEqual(rc, 0)
        self.assertAlmostEqual(self.pause_doc()["until"], T() + 86400, delta=5)

    def test_bounds(self):
        for bad in ("25h", "0s", "0", "junk", "1d1s", "2d"):
            rc, out, errs = run(["pause", "--for", bad])
            self.assertEqual(rc, hc.EXIT_USAGE, bad)
        self.assertFalse(os.path.exists(self.p.pause_json))

    def test_a_negative_duration_is_a_usage_error_on_every_python(self):
        # through the real entry point: Python 3.12's argparse takes "-5m" for an option, 3.14 for the value
        for argv in (["pause", "--for", "-5m"], ["pause", "--for", "-5"], ["pause", "--for=-5m"]):
            errb = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errb):
                rc = cli.main(argv)
            self.assertEqual(rc, hc.EXIT_USAGE, argv)
            self.assertIn("--for must be a duration", errb.getvalue(), argv)
            self.assertFalse(os.path.exists(self.p.pause_json), argv)

    def test_attach_dash_values(self):
        self.assertEqual(cli.attach_dash_values(["pause", "--for", "-5m"]), ["pause", "--for=-5m"])
        self.assertEqual(cli.attach_dash_values(["pause", "--for", "5m"]), ["pause", "--for", "5m"])
        self.assertEqual(cli.attach_dash_values(["pause", "--for", "-"]), ["pause", "--for", "-"])
        self.assertEqual(cli.attach_dash_values(["pause", "--for"]), ["pause", "--for"])

    def test_resume_removes_the_file_and_is_idempotent(self):
        run(["pause"])
        rc, out, errs = run(["resume"])
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(self.p.pause_json))
        rc, out, errs = run(["resume"])
        self.assertEqual(rc, 0)

    def test_a_dev_run_starts_nothing(self):
        # setUp made subprocess.run raise: pause, resume and the systemd calls must not reach it
        self.assertEqual(run(["pause"])[0], 0)
        self.assertEqual(run(["resume"])[0], 0)

    def test_the_engine_honours_what_the_command_wrote(self):
        run(["pause", "--for", "10m"])
        e = bm.BanEngine({"bans": {}, "thresholds": {}, "sites": {}}, self.p, proc_dir=os.path.join(self.env.root, "proc"),
                         resolv_conf="/nonexistent", utmp_path="/nonexistent")
        e.tick(T())
        self.assertIsNotNone(e.paused_until())
        run(["resume"])
        e.tick(T() + 6)
        self.assertIsNone(e.paused_until())


class TestDeregister(Case):
    def test_deregister(self):
        support.make_identity(self.env, self.hubs.pki, self.hubs.fleet_port, cn=self.hubs.uuid)
        rc, out, errs = run(["deregister", "--reason", "uninstall"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.hubs.deregistered, [(self.hubs.uuid, {"reason": "uninstall"})])
        self.hubs.responses["/v1/deregister"] = lambda r: err(403, "host_retired")
        self.assertEqual(run(["deregister"])[0], hc.EXIT_FAIL)

    def test_not_enrolled(self):
        rc, out, errs = run(["deregister"])
        self.assertEqual(rc, 0)
        self.assertIn("not enrolled", out)


if __name__ == "__main__":
    unittest.main()
