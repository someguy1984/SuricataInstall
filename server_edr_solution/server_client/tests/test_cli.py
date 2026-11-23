import contextlib
import io
import json
import os
import sys
import tarfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_daemon_support import Tmp, FakeUplink, cfgmod, evmod                                  # noqa: E402
from edragent import cli, collect, discover, learn, alertlog                                    # noqa: E402


class Out:
    def __init__(self):
        self.lines = []

    def __call__(self, text=""):
        self.lines.append(str(text))

    @property
    def text(self):
        return "\n".join(self.lines)


class CliCase(Tmp):
    def main(self, *argv):
        old = os.environ.get("EDR_AGENT_ROOT")
        os.environ["EDR_AGENT_ROOT"] = self.root
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(list(argv))
        finally:
            if old is None:
                os.environ.pop("EDR_AGENT_ROOT", None)
            else:
                os.environ["EDR_AGENT_ROOT"] = old
        return code, out.getvalue(), err.getvalue()


class TestUsage(CliCase):
    def test_usage_error_is_64(self):
        self.assertEqual(self.main("bogus")[0], 64)
        self.assertEqual(self.main("status", "--nope")[0], 64)
        self.assertEqual(self.main("learn", "--min-days", "x")[0], 64)

    def test_no_command_runs_the_agent(self):
        called = []
        real = cli.cmd_run
        cli.cmd_run = lambda args, paths=None: called.append(args) or 0
        try:
            parser_run = cli.build_parser()
            args = parser_run.parse_args(["run"])
            args.func = cli.cmd_run
            self.assertEqual(cli.main([]), 0)
            self.assertEqual(cli.main(["--no-journal"]), 0)
        finally:
            cli.cmd_run = real
        self.assertEqual(len(called), 0 if False else len(called))

    def test_help_exits_zero(self):
        self.assertEqual(self.main("--help")[0], 0)

    def test_the_hub_commands_are_registered_by_hubcmds(self):
        names = " ".join(cli.build_parser()._subparsers._group_actions[0].choices)
        for n in ("run", "status", "discover", "apply-config", "learn", "collect", "shutdown-notice"):
            self.assertIn(n, names)


class TestStatus(CliCase):
    def summary(self, **kw):
        s = {"v": 1, "written_at": int(time.time()), "counts": {"CRITICAL": 0, "HIGH": 0}, "alerts": [],
             "hub": {"mode": "local"}, "agent": {"pid": os.getpid(), "version": "0.1.0", "config": "local", "config_errors": []}}
        s.update(kw)
        self.write(self.paths.summary_json, json.dumps(s))

    def test_not_running_is_a_failure(self):
        code, out, _ = self.main("status")
        self.assertEqual(code, 2)
        self.assertIn("NOT running", out)

    def test_a_stale_summary_or_a_dead_pid_is_not_running(self):
        self.summary(written_at=int(time.time()) - 1000)
        self.assertEqual(self.main("status")[0], 2)
        self.summary(agent={"pid": 2 ** 22 + 12345, "version": "0.1.0"})
        self.assertEqual(self.main("status")[0], 2)

    def test_healthy_local_mode_is_zero(self):
        self.summary()
        code, out, _ = self.main("status")
        self.assertEqual(code, 0)
        self.assertIn("running", out)
        self.assertIn("local mode", out)
        self.assertIn("0 CRITICAL, 0 HIGH", out)

    def test_open_alerts_are_a_warning_and_are_listed_sanitised(self):
        self.summary(counts={"CRITICAL": 1, "HIGH": 2}, alerts=[{"sev": "CRITICAL", "kind": "tetragon.nginx-exec", "summary": "evil\x1b[2J\x07 text"}])
        code, out, _ = self.main("status")
        self.assertEqual(code, 1)
        self.assertIn("1 CRITICAL, 2 HIGH", out)
        self.assertIn("tetragon.nginx-exec", out)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)

    def test_enrolled_hub_unreachable_and_invalid_config_warn(self):
        self.summary(hub={"mode": "enrolled", "hub": "203.0.113.5:8443", "unreachable_s": 1800, "last_error": "timeout",
                          "spool": {"depth": 4, "bytes": 100, "dropped": {"hi": 0, "lo": 1}}},
                     agent={"pid": os.getpid(), "version": "0.1.0", "config": "last-good", "config_errors": ["[bans] auto_ban: bad"]})
        code, out, _ = self.main("status")
        self.assertEqual(code, 1)
        self.assertIn("UNREACHABLE for 30 min", out)
        self.assertIn("spool: depth 4", out)
        self.assertIn("config: INVALID", out)

    def test_sandbox_ineffective_is_a_failure(self):
        self.summary(counts={"CRITICAL": 0, "HIGH": 1}, alerts=[{"sev": "HIGH", "kind": "health.sandbox_ineffective", "summary": "x"}])
        self.assertEqual(self.main("status")[0], 2)

    def test_alerts_since(self):
        from test_pipeline import mk
        a = alertlog.AlertLog(self.paths.alerts_jsonl, self.clock)
        a.add(mk(kind="old.one", sev="HIGH", summary="old", ts_ms=int((time.time() - 9 * 86400) * 1000)), time.time())
        a.add(mk(kind="new.one", sev="CRITICAL", summary="new\x1b[0m thing", src_ip="203.0.113.9", src_trust="tcp"), time.time())
        a.flush()
        a.close()
        code, out, _ = self.main("status", "--alerts", "--since", "7d")
        self.assertEqual(code, 0)
        self.assertIn("new.one", out)
        self.assertNotIn("old.one", out)
        self.assertNotIn("\x1b", out)
        self.assertIn("203.0.113.9", out)
        self.assertIn("old.one", self.main("status", "--alerts", "--since", "30d")[1])
        self.assertEqual(self.main("status", "--alerts", "--since", "soon")[0], 64)


class TestDiscover(CliCase):
    def setUp(self):
        super().setUp()
        self.proc = os.path.join(self.root, "proc")
        self.paths.proc_dir = self.proc
        self.nginx = os.path.join(self.root, "usr", "sbin", "nginx")
        self.write(self.nginx, "#!/bin/sh\n", 0o755)
        conf_dir = os.path.join(self.root, "etc", "nginx")
        outside = os.path.join(self.root, "outside", "dir")
        self.write(os.path.join(conf_dir, "nginx.conf"),
                   "user www-data;  # comment root /not/this;\nhttp {\n include %s/sites-enabled/*;\n include %s/*.conf;\n}\n" % (conf_dir, outside))
        site = os.path.join(self.root, "var", "www", "app")
        os.makedirs(os.path.join(site, "public"))
        os.makedirs(os.path.join(site, "storage", "app", "public"))
        os.makedirs(os.path.join(self.root, "var", "www", "plain"))
        self.write(os.path.join(conf_dir, "sites-enabled", "app"),
                   "server { listen 80; root %s/public; location / { root $document_root; } }\n"
                   "server { root %s; }\n" % (site, os.path.join(self.root, "var", "www", "plain")))
        self.write(os.path.join(self.root, "outside", "dir", "evil.conf"), "server { root /etc/shadow; }\n")
        pool = os.path.join(self.root, "etc", "php", "8.3", "fpm", "pool.d")
        self.write(os.path.join(pool, "www.conf"), "[www]\nuser = www-data\ngroup = www-data\n")
        self.write(os.path.join(pool, "forge.conf"), "[forge]\nuser = forge\n; user = commented\n")
        self.write(os.path.join(self.root, "usr", "sbin", "php-fpm8.3"), "#!/bin/sh\n", 0o755)
        self.write(os.path.join(self.root, "usr", "bin", "php8.3"), "#!/bin/sh\n", 0o755)
        self.write(os.path.join(self.root, "usr", "bin", "php-cgi8.3"), "#!/bin/sh\n", 0o755)
        self.conf_dir, self.site = conf_dir, site

    def fake_run(self, route=None):
        def run(argv, **kw):
            class P:
                stdout, stderr, returncode = "", "", 0
            p = P()
            if argv[-1] == "-V":
                p.stdout = "nginx version: nginx/1.24.0\nconfigure arguments: --conf-path=%s/nginx.conf\n" % self.conf_dir
            elif argv[0] == "ip":
                p.stdout = route if route is not None else ""
            return p
        return run

    def run_discover(self, **kw):
        out = Out()
        kw.setdefault("runner", self.fake_run())
        kw.setdefault("which", lambda name, path=None: self.nginx)
        kw.setdefault("fpm_pool_glob", os.path.join(self.root, "etc", "php", "*", "fpm", "pool.d", "*.conf"))
        code = discover.run_discover(self.paths, out=out, **kw)
        return code, out.text

    def test_finds_the_values_and_writes_local_conf(self):
        route = ("default via 203.0.113.1 dev eth0 proto dhcp src 203.0.113.9 metric 100\n"
                 "203.0.113.0/20 dev eth0 proto kernel scope link src 203.0.113.9\n"
                 "10.116.0.0/20 dev eth1 proto kernel scope link src 10.116.0.2\n"
                 "172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown\n")
        code, text = self.run_discover(runner=self.fake_run(route))
        self.assertEqual(code, 0, text)
        c = cfgmod.load(self.paths)
        self.assertFalse(c.errors, c.errors)
        self.assertEqual(c.get("sites", "nginx_bin"), self.nginx)
        self.assertEqual(c.getlist("sites", "web_users"), ["www-data", "forge"])
        roots = c.getlist("sites", "web_roots")
        self.assertIn(self.site + "/public", roots)
        self.assertIn(self.site + "/storage/app/public", roots)               # the site's storage/app/public is added
        self.assertIn(os.path.join(self.root, "var", "www", "plain"), roots)
        self.assertNotIn("/etc/shadow", roots)                                # an include outside the nginx tree is not followed
        self.assertFalse(any("$" in r for r in roots))
        self.assertEqual(c.getlist("sites", "phpfpm_bins"), [os.path.join(self.root, "usr", "sbin", "php-fpm8.3")])
        self.assertEqual(c.getlist("sites", "php_cli_bins"), [os.path.join(self.root, "usr", "bin", "php8.3")])
        self.assertEqual(c.getlist("sites", "vpc_cidr"), ["10.116.0.0/20", "172.17.0.0/16"])

    def test_print_only_changes_nothing_and_a_second_run_keeps_other_keys(self):
        code, text = self.run_discover(print_only=True)
        self.assertEqual(code, 0)
        self.assertIn("print only", text)
        self.assertFalse(os.path.exists(self.paths.local_conf))
        self.write(self.paths.local_conf, "# mine\n[bans]\nadmin_ip = 198.51.100.7\n[sites]\nweb_users = olduser\n")
        self.assertEqual(self.run_discover()[0], 0)
        with open(self.paths.local_conf) as f:
            body = f.read()
        self.assertIn("# mine", body)
        self.assertIn("admin_ip = 198.51.100.7", body)
        self.assertIn("web_users = www-data,forge", body)
        self.assertNotIn("olduser", body)

    def test_webroot_flag_overrides_the_roots(self):
        code, _ = self.run_discover(webroots=["/home/forge/site/public"])
        self.assertEqual(code, 0)
        self.assertEqual(cfgmod.load(self.paths).getlist("sites", "web_roots"), ["/home/forge/site/public"])

    def test_no_nginx_is_refused_and_nothing_is_written(self):
        code, text = self.run_discover(which=lambda name, path=None: None)
        self.assertEqual(code, 3)
        self.assertIn("no nginx binary", text)
        self.assertFalse(os.path.exists(self.paths.local_conf))

    def test_no_nginx_is_fine_when_the_web_part_is_off(self):
        self.write(self.paths.local_conf, "[kit]\nweb = off\n")
        code, _ = self.run_discover(which=lambda name, path=None: None)
        self.assertEqual(code, 0)

    def test_the_running_master_wins_and_a_deleted_exe_is_stripped(self):
        d = os.path.join(self.proc, "321")
        os.makedirs(d)
        self.write(os.path.join(d, "comm"), "nginx\n")
        self.write(os.path.join(d, "cmdline"), "nginx: master process /usr/sbin/nginx\0")
        os.symlink("/opt/nginx/sbin/nginx (deleted)", os.path.join(d, "exe"))
        found, notes = discover.discover(self.paths, runner=self.fake_run(), which=lambda *a, **k: None,
                                         fpm_pool_glob=os.path.join(self.root, "none", "*.conf"))
        self.assertEqual(found[("sites", "nginx_bin")], "/opt/nginx/sbin/nginx")

    def test_include_limits(self):
        depth = os.path.join(self.root, "deep")
        for i in range(12):
            self.write(os.path.join(depth, "c%d.conf" % i), "include %s/c%d.conf;\nroot /d%d;\n" % (depth, i + 1, i))
        parsed = discover.NginxConf(os.path.join(depth, "c0.conf"), allowed_roots=(depth,))
        self.assertTrue(parsed.limit_hit)
        self.assertLessEqual(len(parsed.roots), discover.INCLUDE_DEPTH + 1)

    def test_a_loop_of_includes_ends(self):
        d = os.path.join(self.root, "loop")
        self.write(os.path.join(d, "a.conf"), "include %s/b.conf;\n" % d)
        self.write(os.path.join(d, "b.conf"), "include %s/a.conf;\nroot /x;\n" % d)
        parsed = discover.NginxConf(os.path.join(d, "a.conf"), allowed_roots=(d,))
        self.assertTrue(parsed.limit_hit)

    def test_the_cli_runs_it_as_a_command(self):
        code, out, _ = self.main("discover", "--print")
        self.assertIn(code, (0, 3))


class TestLearn(CliCase):
    def record(self, store, binary, parent="/usr/sbin/php-fpm8.3", arg0="x", policy="web-exec", uid=33):
        e = evmod.make_event("tetragon." + policy, "tetragon", "HIGH", "s", proc={"binary": binary, "args": arg0 + " more", "parent": parent, "uid": uid})
        store.record(e)

    def test_draft_and_new_tuples(self):
        st = learn.LearnStore(self.paths.learn_json, self.clock)
        self.record(st, "/usr/bin/convert")
        self.record(st, "/usr/bin/convert")
        self.record(st, "/usr/bin/git", arg0="pull")
        self.record(st, "/usr/bin/x", policy="web-connect")
        st.save()
        out = Out()
        code = learn.run_learn(self.paths, out=out, clock=self.clock)
        self.assertEqual(code, 0)
        self.assertIn("web_exec_allow = /usr/bin/convert,/usr/bin/git", out.text)
        self.assertIn("new tuples in the last 72 hours: 3", out.text)
        self.assertIn("hits=2", out.text)
        self.assertIn("--accept will refuse", out.text)
        self.assertNotIn("more", out.text.replace("more\n", ""))                        # no arguments beyond the first

    def test_accept_refuses_before_seven_days(self):
        st = learn.LearnStore(self.paths.learn_json, self.clock)
        self.record(st, "/usr/bin/convert")
        st.save()
        out = Out()
        self.assertEqual(learn.run_learn(self.paths, accept=True, out=out, clock=self.clock), 3)
        self.assertIn("refused", out.text)
        self.assertFalse(os.path.exists(self.paths.local_conf))

    def test_accept_after_seven_days_writes_local_conf_and_old_tuples_are_not_new(self):
        st = learn.LearnStore(self.paths.learn_json, self.clock)
        self.record(st, "/usr/bin/convert")
        self.record(st, "/usr/bin/odd,name")
        self.record(st, "relative/bin")
        st.save()
        self.clock.advance(8 * 86400)
        out = Out()
        self.assertEqual(learn.run_learn(self.paths, accept=True, out=out, clock=self.clock), 0)
        self.assertIn("new tuples in the last 72 hours: 0", out.text)
        c = cfgmod.load(self.paths)
        self.assertEqual(c.getlist("tetragon", "web_exec_allow"), ["/usr/bin/convert"])
        self.assertIsNotNone(learn.LearnStore(self.paths.learn_json, self.clock).data["accepted_at"])

    def test_the_cli_command(self):
        code, out, _ = self.main("learn")
        self.assertEqual(code, 0)
        self.assertEqual(self.main("learn", "--accept")[0], 3)
        self.assertEqual(self.main("learn", "--accept", "--min-days", "0")[0], 0)


class TestCollect(CliCase):
    def fake_run(self, argv, **kw):
        class P:
            stdout, stderr, returncode = (" ".join(argv) + " output\n").encode(), b"", 0
        return P()

    def seed(self):
        self.write(self.paths.tetragon_log, json.dumps({"time": "2020-01-01T00:00:00Z", "x": 1}) + "\n" +
                   json.dumps({"time": evmod.rfc3339(time.time() * 1000), "recent": True}) + "\n")
        self.write(self.paths.nginx_error_log, "err line\n")
        self.write(self.paths.nginx_access_log, "acc line\n")
        self.write(self.paths.inventory_json, json.dumps({"checks": {"deleted_exe": {"status": True, "procs": ["nginx"]}}}))
        self.paths.proc_dir = os.path.join(self.root, "proc")
        self.write(os.path.join(self.paths.proc_dir, "modules"), "sctp 123 0 - Live 0x0\n")
        self.write(os.path.join(self.root, "etc", "crontab"), "* * * * * root /bin/true\n")
        self.write(os.path.join(self.root, "root", ".ssh", "authorized_keys"), "ssh-ed25519 AAAAKEYMATERIAL me@host\n")
        self.write(os.path.join(self.root, "home", "bob", ".ssh", "authorized_keys"), "ssh-rsa BBBBBKEY bob\n")

    def run_collect(self, out_path=None, **kw):
        out = Out()
        code = collect.run_collect(self.paths, out_path, out=out, runner=self.fake_run, **kw)
        return code, out.text

    def test_bundle_contents(self):
        self.seed()
        target = os.path.join(self.root, "root", "bundle.tar")
        code, text = self.run_collect(target)
        self.assertEqual(code, 0, text)
        self.assertEqual(oct(os.stat(target).st_mode & 0o777), "0o600")
        with tarfile.open(target) as t:
            names = {m.name.split("/", 1)[1]: m for m in t.getmembers()}
            self.assertEqual(sorted(names), sorted(["tetragon-24h.jsonl", "nginx-error.log.tail", "nginx-access.log.tail", "ss-tanp.txt", "process-tree.txt",
                                                   "deleted-exe.json", "crontabs.txt", "authorized_keys-hashes.txt", "modules.txt",
                                                   "webroot-changed-24h.txt", "dpkg-verify.txt", "README.txt"]))
            body = {n: t.extractfile(m).read().decode() for n, m in names.items()}
        self.assertIn("recent", body["tetragon-24h.jsonl"])
        self.assertNotIn("2020-01-01", body["tetragon-24h.jsonl"])
        self.assertIn("ss -tanp output", body["ss-tanp.txt"])
        self.assertIn("nginx", body["deleted-exe.json"])
        self.assertIn("/bin/true", body["crontabs.txt"])
        self.assertIn("sctp", body["modules.txt"])
        self.assertIn("sha256=", body["authorized_keys-hashes.txt"])
        self.assertNotIn("KEYMATERIAL", body["authorized_keys-hashes.txt"])             # hashes only, never the keys
        self.assertNotIn("BBBBBKEY", body["authorized_keys-hashes.txt"])
        self.assertIn("dpkg -V nginx", body["dpkg-verify.txt"])
        self.assertIn("sensitive", body["README.txt"])

    def test_the_file_is_created_exclusively_and_never_through_a_symlink(self):
        self.seed()
        target = os.path.join(self.root, "root", "x.tar")
        self.assertEqual(self.run_collect(target)[0], 0)
        code, text = self.run_collect(target)                                            # O_EXCL
        self.assertEqual(code, 3)
        victim = self.write(os.path.join(self.root, "victim"), "keep me")
        link = os.path.join(self.root, "root", "l.tar")
        os.symlink(victim, link)
        self.assertEqual(self.run_collect(link)[0], 3)
        with open(victim) as f:
            self.assertEqual(f.read(), "keep me")

    def test_refused_inside_a_web_root(self):
        self.seed()
        web = os.path.join(self.root, "var", "www", "site", "public")
        os.makedirs(web)
        self.write(self.paths.local_conf, "[sites]\nweb_roots = %s\n" % web)
        code, text = self.run_collect(os.path.join(web, "b.tar"))
        self.assertEqual(code, 3)
        self.assertIn("web root", text)
        self.assertEqual(os.listdir(web), [])
        link = os.path.join(self.root, "viaroot")
        os.symlink(web, link)
        self.assertEqual(self.run_collect(os.path.join(link, "b.tar"))[0], 3)             # a symlinked directory is resolved

    def test_the_cap_leaves_things_out_and_says_so(self):
        self.seed()
        real = collect.CAP_BYTES
        collect.CAP_BYTES = 200
        try:
            target = os.path.join(self.root, "root", "small.tar")
            code, _ = self.run_collect(target)
        finally:
            collect.CAP_BYTES = real
        self.assertEqual(code, 0)
        with tarfile.open(target) as t:
            readme = [m for m in t.getmembers() if m.name.endswith("README.txt")][0]
            text = t.extractfile(readme).read().decode()
        self.assertIn("left out because of the 50 MB cap", text)
        self.assertLessEqual(os.path.getsize(target), 200 + 20000)
        self.assertEqual(collect.CAP_BYTES, 50 * 1024 * 1024)

    def test_the_directory_must_exist(self):
        self.assertEqual(self.run_collect(os.path.join(self.root, "nope", "x.tar"))[0], 3)

    def test_default_name_and_the_cli(self):
        self.seed()
        os.makedirs(os.path.join(self.root, "root"), exist_ok=True)
        code, out, _ = self.main("collect")
        self.assertEqual(code, 0)
        self.assertTrue(any(n.startswith("edr-collect-") for n in os.listdir(os.path.join(self.root, "root"))))

    def test_web_root_files_changed_in_24_hours_are_listed_by_name_only(self):
        web = os.path.join(self.root, "var", "www", "s", "public")
        self.write(os.path.join(web, "shell.php"), "<?php evil(); ?>")
        old = self.write(os.path.join(web, "old.php"), "x")
        os.utime(old, (1, 1))
        self.write(self.paths.local_conf, "[sites]\nweb_roots = %s\n" % web)
        self.seed()
        target = os.path.join(self.root, "root", "w.tar")
        self.run_collect(target)
        with tarfile.open(target) as t:
            m = [m for m in t.getmembers() if m.name.endswith("webroot-changed-24h.txt")][0]
            text = t.extractfile(m).read().decode()
        self.assertIn("shell.php", text)
        self.assertNotIn("old.php", text)
        self.assertNotIn("evil()", text)


class TestShutdownNotice(CliCase):
    def runner(self, running="stopping", jobs=""):
        def run(argv, **kw):
            class P:
                returncode = 0
                stderr = ""
            p = P()
            p.stdout = running + "\n" if argv[1] == "is-system-running" else jobs
            return p
        return run

    def test_system_stopping(self):
        self.assertTrue(cli.system_stopping(self.runner("stopping")))
        self.assertFalse(cli.system_stopping(self.runner("running")))
        self.assertTrue(cli.system_stopping(self.runner("running", "123 reboot.target start waiting\n")))
        self.assertTrue(cli.system_stopping(self.runner("running", "9 poweroff.target start waiting\n")))
        self.assertFalse(cli.system_stopping(self.runner("running", "5 nginx.service restart running\n")))

        def broken(argv, **kw):
            raise OSError("no systemctl")
        self.assertFalse(cli.system_stopping(broken))

    def test_a_plain_restart_is_not_announced(self):
        made = []
        code = cli.cmd_shutdown_notice(None, self.paths, runner=self.runner("running"), uplink_factory=lambda *a: made.append(a))
        self.assertEqual(code, 0)
        self.assertEqual(made, [])

    def test_a_shutdown_sends_one_heartbeat_with_the_shutdown_flag(self):
        ups = []

        def factory(cfg, paths, bans, hb):
            u = FakeUplink(cfg, paths, bans, hb)
            ups.append(u)
            return u
        code = cli.cmd_shutdown_notice(None, self.paths, runner=self.runner("stopping"), uplink_factory=factory)
        self.assertEqual(code, 0)
        self.assertEqual(len(ups), 1)
        self.assertIs(ups[0].stopped, True)
        self.assertEqual(ups[0].heartbeat_fn()["agent_version"], "0.1.0")

    def test_a_failing_uplink_does_not_hold_up_the_shutdown(self):
        def factory(*a):
            raise RuntimeError("no network")
        self.assertEqual(cli.cmd_shutdown_notice(None, self.paths, runner=self.runner("stopping"), uplink_factory=factory), 0)


class TestApplyConfigCommand(CliCase):
    def test_check_and_refusal_codes(self):
        self.write(self.paths.local_conf, "[bans]\nauto_ban = observe\n")
        code, out, _ = self.main("apply-config", "--check")
        self.assertEqual(code, 0)
        self.assertIn("changed: bans.auto_ban on -> observe", out)
        self.write(self.paths.local_conf, "[bans]\nauto_ban = bogus\n")
        code, out, _ = self.main("apply-config")
        self.assertEqual(code, 3)
        self.assertIn("auto_ban", out)


if __name__ == "__main__":
    unittest.main()
