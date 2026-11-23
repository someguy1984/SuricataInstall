"""L0 tests of agent/edr-diskguard (client PLAN section 9): the stages and their fixed actions, files
that must not be touched, the restore, the logrotate configuration. Real files in a temporary root;
systemctl and logrotate are fixtures."""

import io
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from test_helper_common import FILES, TmpCase, have, load_helper, run_helper  # noqa: E402

G = load_helper("edr-diskguard")
NOW = 1795000000


class Rec(dict):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.calls = []

    def get(self, key, default=None):
        self.calls.append(key)
        return dict.get(self, key, default if default is not None else {"rc": 0, "out": ""})


class GuardCase(TmpCase):
    def setUp(self):
        super().setUp()
        self.fx = Rec()
        for n in ("eve.json", "eve-bulk.json", "suricata.log"):
            self.put("/var/log/suricata/" + n, "x" * 4096)
        for n in ("eve.json.1", "eve.json.2.gz", "eve.json.3.gz", "eve-bulk.json.1", "eve-bulk.json.2.gz", "suricata.log.1"):
            self.put("/var/log/suricata/" + n, "x" * 4096)
        self.put("/var/lib/suricata/cache/sgh/aa", "y" * 8192)
        self.put("/var/lib/suricata/cache/sgh/sub/bb", "y" * 8192)
        self.put("/var/log/tetragon/tetragon.log", "t" * 100)
        for n in ("tetragon-1.log.gz", "tetragon-2.log.gz", "tetragon-3.log.gz"):
            self.put("/var/log/tetragon/" + n, "t" * 100)
        for i, n in enumerate(("tetragon-1.log.gz", "tetragon-2.log.gz", "tetragon-3.log.gz")):
            os.utime(self.root + "/var/log/tetragon/" + n, (NOW - 1000 + i, NOW - 1000 + i))   # 3 is the newest

    def guard(self, free, *extra):
        env = G.Env(self.root, dry=False, fixtures=self.fx, now=NOW)
        orig = G.parse_common
        G.parse_common = lambda argv: (env, "", ["--free-pct", str(free)] + list(extra))
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                rc = G.main([])
        finally:
            G.parse_common = orig
        self.assertEqual(rc, 0)
        return self.read_json("/run/edr-diskguard/status.json")

    def exists(self, p):
        return os.path.lexists(self.root + p)


class TestStages(GuardCase):
    def test_above_10_percent_only_rotates_and_reports(self):
        doc = self.guard(40)
        self.assertEqual((doc["stage"], doc["free_pct"], doc["freed_mb"]), (0, 40.0, 0))
        self.assertTrue(self.exists("/var/lib/suricata/cache/sgh/aa"))
        self.assertTrue(self.exists("/var/log/suricata/eve.json.2.gz"))
        self.assertEqual(os.path.getsize(self.root + "/var/log/suricata/eve-bulk.json"), 4096)
        self.assertEqual(set(doc), {"written_at", "free_pct", "stage", "freed_mb"})
        self.assertEqual(os.stat(self.root + "/run/edr-diskguard/status.json").st_mode & 0o777, 0o640)
        self.assertTrue([c for c in self.fx.calls if c.startswith("logrotate -s ")])

    def test_stage_boundaries(self):
        for free, stage in ((10.0, 0), (9.9, 1), (5.0, 1), (4.9, 2), (3.0, 2), (2.9, 3), (0.5, 3)):
            self.setUp()
            self.assertEqual(self.guard(free)["stage"], stage, free)

    def test_stage_1_frees_the_cache_and_old_copies_and_truncates_bulk(self):
        doc = self.guard(8)
        self.assertEqual(doc["stage"], 1)
        self.assertFalse(self.exists("/var/lib/suricata/cache/sgh/aa"))
        self.assertFalse(self.exists("/var/lib/suricata/cache/sgh/sub/bb"))
        self.assertTrue(self.exists("/var/log/suricata/eve.json.1"))                 # the first rotated copy stays
        self.assertFalse(self.exists("/var/log/suricata/eve.json.2.gz"))
        self.assertFalse(self.exists("/var/log/suricata/eve.json.3.gz"))
        self.assertEqual(os.path.getsize(self.root + "/var/log/suricata/eve-bulk.json"), 0)
        self.assertEqual(os.path.getsize(self.root + "/var/log/suricata/eve.json"), 4096)    # alerts stay
        self.assertTrue(self.exists("/var/log/tetragon/tetragon-3.log.gz"))          # the newest Tetragon backup stays
        self.assertFalse(self.exists("/var/log/tetragon/tetragon-1.log.gz"))
        self.assertTrue(self.exists("/var/log/tetragon/tetragon.log"))
        self.assertIn("systemctl kill -s HUP suricata.service", self.fx.calls)
        self.assertNotIn("systemctl stop suricata.service", self.fx.calls)
        self.assertGreater(doc["freed_mb"] + 1, 0)

    def test_stage_2_points_bulk_at_dev_null_and_deletes_every_rotated_log(self):
        doc = self.guard(4)
        self.assertEqual(doc["stage"], 2)
        self.assertEqual(os.readlink(self.root + "/var/log/suricata/eve-bulk.json"), "/dev/null")
        for n in ("eve.json.1", "eve-bulk.json.1", "suricata.log.1", "eve.json.2.gz"):
            self.assertFalse(self.exists("/var/log/suricata/" + n), n)
        for n in ("tetragon-1.log.gz", "tetragon-2.log.gz", "tetragon-3.log.gz"):
            self.assertFalse(self.exists("/var/log/tetragon/" + n), n)
        self.assertTrue(self.exists("/var/log/tetragon/tetragon.log"))
        self.assertTrue(self.exists("/var/log/suricata/eve.json"))
        self.assertNotIn("systemctl stop suricata.service", self.fx.calls)

    def test_stage_3_stops_suricata_unless_switched_off(self):
        self.guard(2)
        self.assertIn("systemctl stop suricata.service", self.fx.calls)
        self.setUp()
        self.put("/etc/edr-agent/local.conf", "[diskguard]\nstop_suricata = off\n")
        self.guard(2)
        self.assertNotIn("systemctl stop suricata.service", self.fx.calls)

    def test_back_above_15_percent_restores_bulk(self):
        self.guard(4)
        self.assertTrue(os.path.islink(self.root + "/var/log/suricata/eve-bulk.json"))
        self.guard(12)
        self.assertTrue(os.path.islink(self.root + "/var/log/suricata/eve-bulk.json"))     # between 10% and 15%: not yet
        self.guard(20)
        p = self.root + "/var/log/suricata/eve-bulk.json"
        self.assertTrue(os.path.isfile(p) and not os.path.islink(p))
        self.assertEqual(os.path.getsize(p), 0)
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o640)

    def test_hup_falls_back_to_the_pid_file(self):
        self.fx["systemctl kill -s HUP suricata.service"] = {"rc": 1}
        self.put("/run/suricata.pid", "999999999\n")
        self.guard(8)                                   # no such process: nothing is signalled, nothing crashes


class TestSafety(GuardCase):
    def test_symlinks_are_never_followed(self):
        outside = self.put("/outside/precious", "keep me")
        os.symlink(outside, self.root + "/var/lib/suricata/cache/sgh/link")
        os.symlink(self.root + "/outside", self.root + "/var/lib/suricata/cache/sgh/dirlink")
        self.guard(8)
        self.assertTrue(os.path.isfile(outside))
        self.assertTrue(self.exists("/var/lib/suricata/cache/sgh/link"))

    def test_a_symlinked_cache_directory_is_not_entered(self):
        shutil.rmtree(self.root + "/var/lib/suricata/cache")
        self.put("/outside/precious", "keep me")
        os.makedirs(self.root + "/var/lib/suricata", exist_ok=True)
        os.symlink(self.root + "/outside", self.root + "/var/lib/suricata/cache")
        self.guard(4)
        self.assertTrue(os.path.isfile(self.root + "/outside/precious"))

    def test_a_symlinked_log_directory_is_not_entered(self):
        shutil.rmtree(self.root + "/var/log/suricata")
        self.put("/outside/eve.json.2.gz", "keep me")
        os.symlink(self.root + "/outside", self.root + "/var/log/suricata")
        self.guard(4)
        self.assertTrue(os.path.isfile(self.root + "/outside/eve.json.2.gz"))

    def test_files_of_other_owners_and_fifos_are_left_alone(self):
        os.mkfifo(self.root + "/var/lib/suricata/cache/sgh/fifo")
        if os.geteuid() == 0:
            os.chown(self.root + "/var/log/suricata/eve.json.2.gz", 65534, 65534)
        self.guard(4)
        self.assertTrue(self.exists("/var/lib/suricata/cache/sgh/fifo"))
        if os.geteuid() == 0:
            self.assertTrue(self.exists("/var/log/suricata/eve.json.2.gz"))

    def test_a_missing_nothing_is_fine(self):
        shutil.rmtree(self.root + "/var/log/tetragon")
        shutil.rmtree(self.root + "/var/lib/suricata")
        doc = self.guard(4)
        self.assertEqual(doc["stage"], 2)

    def test_dry_run_deletes_nothing(self):
        rc, out, err = run_helper("edr-diskguard", ["--root", self.root, "--dry-run", "--free-pct", "2", "--now", str(NOW)])
        self.assertEqual(rc, 0, err)
        self.assertTrue(self.exists("/var/lib/suricata/cache/sgh/aa"))
        self.assertTrue(self.exists("/var/log/suricata/eve.json.2.gz"))
        self.assertEqual(os.path.getsize(self.root + "/var/log/suricata/eve-bulk.json"), 4096)


class TestLogrotateConfig(TmpCase):
    def test_kit_stanzas_follow_the_plan(self):
        rc, out, _ = run_helper("edr-diskguard", ["--root", self.root, "--print-logrotate", "--files-dir", FILES])
        self.assertEqual(rc, 0)
        for need in ("size 50M", "rotate 3", "size 25M", "rotate 2", "size 10M", "rotate 1", "delaycompress", "su suricata suricata",
                     "create 640 suricata suricata", "postrotate"):
            self.assertIn(need, out)
        self.assertNotIn("/var/log/nginx/edr.log {", out)

    def test_nginx_info_log_stanza_is_opt_in(self):
        self.put("/etc/edr-agent/local.conf", "[agent]\nnginx_info_log = on\n")
        rc, out, _ = run_helper("edr-diskguard", ["--root", self.root, "--print-logrotate", "--files-dir", FILES])
        self.assertIn("/var/log/nginx/edr.log {", out)
        self.assertIn("size 20M", out)

    @unittest.skipUnless(have("logrotate"), "needs logrotate")
    def test_logrotate_accepts_the_configuration(self):
        for extra in ("", "[agent]\nnginx_info_log = on\n"):
            if extra:
                self.put("/etc/edr-agent/local.conf", extra)
            rc, out, _ = run_helper("edr-diskguard", ["--root", self.root, "--print-logrotate", "--files-dir", FILES])
            # point the paths at a temporary directory: logrotate -d must not look at the real logs
            logs = self.root + "/logs"
            os.makedirs(logs + "/suricata", exist_ok=True)
            os.makedirs(logs + "/nginx", exist_ok=True)
            text = out.replace("/var/log/", logs + "/")
            text = "\n".join(l for l in text.splitlines() if not l.strip().startswith(("su ", "create ")))
            cfg = self.root + "/lr.conf"
            with open(cfg, "w") as fh:
                fh.write(text + "\n")
            r = subprocess.run(["logrotate", "-d", "-s", self.root + "/lr.state", cfg], capture_output=True, text=True)
            bad = [l for l in r.stderr.splitlines() + r.stdout.splitlines() if "unknown option" in l or "error:" in l.lower()]
            self.assertEqual(bad, [], r.stderr)


if __name__ == "__main__":
    unittest.main()
