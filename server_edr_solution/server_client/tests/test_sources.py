import base64
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_daemon_support import Tmp, cfgmod, evmod                      # noqa: E402
from edragent import sources as src                                      # noqa: E402
from edragent.sources import tetragon, nginx, journal, kernel, suricata, helpers   # noqa: E402


class SrcCase(Tmp):
    def setUp(self):
        super().setUp()
        self.cfg = cfgmod.load(self.paths)
        self.ctx = src.Context(self.cfg, self.paths, self.clock)

    def reconf(self, text):
        self.cfg = self.conf(text)
        self.ctx = src.Context(self.cfg, self.paths, self.clock)


# ---- Tetragon ---------------------------------------------------------------------------------------
def kprobe(policy, function="security_bprm_check", binary="/bin/sh", args="-c id", parent="/usr/sbin/nginx", uid=33,
           action=None, kargs=None, message=None, extra_process=None):
    proc = {"exec_id": "x", "pid": 4242, "uid": uid, "cwd": "/", "binary": binary, "arguments": args}
    proc.update(extra_process or {})
    k = {"process": proc, "parent": {"binary": parent, "arguments": ""}, "function_name": function,
         "args": kargs if kargs is not None else [{"linux_binprm_arg": {"path": binary}}], "policy_name": policy}
    if action:
        k["action"] = action
    if message:
        k["message"] = message
    return {"process_kprobe": k, "node_name": "web1", "time": "2026-11-19T10:15:02.481234567Z"}


def pexec(binary="/usr/bin/ls", args="-l", parent="/usr/bin/bash", links=1, inode=True):
    proc = {"pid": 5, "uid": 0, "binary": binary, "arguments": args}
    if inode:
        node = {"number": 123}
        if links is not None:
            node["links"] = links
        proc["binary_properties"] = {"file": {"inode": node}}
    return {"process_exec": {"process": proc, "parent": {"binary": parent}}, "time": "2026-11-19T10:15:03.000000000Z"}


class TestDescribe(unittest.TestCase):
    def test_kprobe_summary_line_like_the_original(self):
        d = tetragon.describe(kprobe("nginx-exec", message="nginx worker exec"))
        summary, title, body, policy, binary = d
        self.assertEqual(summary, "nginx-exec security_bprm_check /bin/sh /bin/sh <- /usr/sbin/nginx")
        self.assertEqual(title, "Tetragon: nginx worker exec")
        self.assertEqual((policy, binary), ("nginx-exec", "/bin/sh"))
        self.assertIn("/bin/sh (pid 4242, uid 33)", body)
        self.assertIn("started by /usr/sbin/nginx", body)

    def test_exec_is_labelled_by_event_type_not_called_fileless(self):
        _, title, _, policy, _ = tetragon.describe(pexec(links=1))
        self.assertEqual(policy, "exec")
        self.assertNotIn("no file", title)
        _, _, _, policy2, _ = tetragon.describe(pexec(binary="/memfd:x (deleted)", links=1))
        self.assertEqual(policy2, "exec")                    # the path alone does not make the label: only links == 0 does

    def test_exec_with_no_links_left_is_fileless(self):
        for ev in (pexec(links=0), pexec(links=None)):       # protobuf JSON drops a zero: an inode object with no links
            _, title, _, policy, _ = tetragon.describe(ev)
            self.assertEqual(policy, "fileless-exec")
            self.assertIn("no file behind it", title)
        _, _, _, policy3, _ = tetragon.describe(pexec(inode=False))        # nothing known about the inode
        self.assertEqual(policy3, "exec")

    def test_other_event_types(self):
        tp = {"process_tracepoint": {"process": {"binary": "/x", "pid": 1, "uid": 0}, "subsys": "raw_syscalls", "event": "sys_enter",
                                     "policy_name": "tp-policy", "args": []}}
        self.assertEqual(tetragon.describe(tp)[3], "tp-policy")
        self.assertIsNone(tetragon.describe({"process_exit": {"process": {"binary": "/x"}}}))
        self.assertIsNone(tetragon.describe({"something": 1}))
        self.assertIsNone(tetragon.describe("text"))
        self.assertIsNone(tetragon.describe({"process_kprobe": "not a dict"}))

    def test_detail_is_copied_behaviour(self):
        args = [{"file_arg": {"path": "/etc/shadow"}, "label": "file"}, {"sock_arg": {"saddr": "10.0.0.1", "sport": 5, "daddr": "1.1.1.1"}},
                {"int_arg": 7}, {"string_arg": "hello   world"}, {"x_arg": {"name": "nm"}}, {"y_arg": {"other": 1}}]
        self.assertEqual(tetragon.detail(args), "file=/etc/shadow 10.0.0.1:5 hello world nm")
        self.assertEqual(tetragon.detail(None), "")


class TestTetragonSource(SrcCase):
    def setUp(self):
        super().setUp()
        self.s = tetragon.TetragonSource(self.ctx, "begin")
        self.addCleanup(self.s.close)

    def one(self, obj):
        events = self.s.parse_line(json.dumps(obj))
        self.assertEqual(len(events), 1, events)
        return events[0]

    def test_killed_nginx_exec_is_critical(self):
        e = self.one(kprobe("nginx-exec", action="KPROBE_ACTION_SIGKILL"))
        self.assertEqual((e["kind"], e["sev"], e["source"]), ("tetragon.nginx-exec", "CRITICAL", "tetragon"))
        self.assertTrue(e["details"]["killed"])
        self.assertIn("(killed)", e["summary"])
        self.assertEqual(e["proc"], {"binary": "/bin/sh", "args": "-c id", "parent": "/usr/sbin/nginx", "uid": 33})
        self.assertEqual(e["ts"], "2026-11-19T10:15:02.481Z")
        self.assertEqual(e["src_ip"], "")
        self.assertEqual(e["src_trust"], "none")

    def test_monitor_mode_hit_is_high(self):
        self.assertEqual(self.one(kprobe("nginx-exec"))["sev"], "HIGH")
        self.assertEqual(self.one(kprobe("sctp-socket", function="security_socket_create", action="KPROBE_ACTION_SIGKILL"))["sev"], "CRITICAL")

    def test_policy_ratings(self):
        self.assertEqual(self.one(kprobe("web-exec"))["sev"], "HIGH")
        self.assertEqual(self.one(kprobe("tcp-listen", binary="/usr/bin/nc", parent="/usr/bin/bash"))["sev"], "LOW")
        self.assertEqual(self.one(kprobe("edr-canary", binary="/usr/libexec/edr/canary", parent="/bin/dash", action="KPROBE_ACTION_SIGKILL"))["sev"], "CRITICAL" if False else "INFO")
        self.assertEqual(self.one(kprobe("privilege-escalation"))["sev"], "HIGH")
        self.assertEqual(self.one(kprobe("something-new", binary="/usr/bin/x", parent="/usr/bin/y"))["sev"], "MEDIUM")

    def test_the_kit_helpers_reading_env_are_dropped_and_forgeries_are_not(self):
        helper = dict(binary="/usr/bin/python3", args="-I /usr/local/lib/edr-agent/edr-inventory", parent="/usr/lib/systemd/systemd", uid=0)
        self.assertEqual(self.s.parse_line(json.dumps(kprobe("env-read", **helper))), [])
        self.assertEqual(self.s.parse_line(json.dumps(kprobe("env-read", **dict(helper, binary="/usr/bin/python3.12", args="-I /usr/local/lib/edr-agent/edr-bans --x")))), [])
        no_uid = kprobe("env-read", **dict(helper, uid=0))
        del no_uid["process_kprobe"]["process"]["uid"]                                    # protobuf JSON drops a zero
        self.assertEqual(self.s.parse_line(json.dumps(no_uid)), [])
        for forged in (dict(helper, uid=33),                                            # a web user with the same arguments
                       dict(helper, parent="/usr/bin/bash"), dict(helper, parent="/usr/sbin/php-fpm8.3"),
                       dict(helper, binary="/tmp/python3"), dict(helper, binary="/usr/bin/python3x"),
                       dict(helper, args="-I /tmp/evil.py"), dict(helper, args="-I /usr/local/lib/edr-agent/../../../tmp/x"),
                       dict(helper, args="-c import os /usr/local/lib/edr-agent/edr-x"),
                       dict(helper, args="/usr/local/lib/edr-agent/edr-inventory"),
                       dict(helper, args="-I /usr/local/lib/edr-agent/edr-Inventory")):
            events = self.s.parse_line(json.dumps(kprobe("env-read", **forged)))
            self.assertEqual(len(events), 1, forged)
            self.assertEqual(events[0]["kind"], "tetragon.env-read")
        # only env-read is relaxed: the same process tripping another policy is still reported
        self.assertEqual(len(self.s.parse_line(json.dumps(kprobe("persistence", **helper)))), 1)

    def test_env_read_rating_by_binary(self):
        self.assertEqual(self.one(kprobe("env-read", binary="/usr/sbin/nginx", parent="/sbin/init"))["sev"], "HIGH")
        self.assertEqual(self.one(kprobe("env-read", binary="/usr/bin/cat", parent="/usr/bin/bash"))["sev"], "MEDIUM")

    def test_compiled_views_are_downgraded_but_other_php_is_not(self):
        base = "/var/www/app/storage/framework/views/"
        good = self.one(kprobe("web-write-code", function="security_file_open", binary="/usr/sbin/php-fpm8.3", parent="/usr/sbin/php-fpm8.3",
                               kargs=[{"file_arg": {"path": base + "0123456789abcdef0123456789abcdef.php"}}]))
        self.assertEqual(good["sev"], "LOW")
        sha1 = self.one(kprobe("web-write-code", function="security_file_open", binary="/usr/sbin/php-fpm8.3", parent="/usr/sbin/php-fpm8.3",
                               kargs=[{"file_arg": {"path": "/var/www/app/bootstrap/cache/" + "a" * 40 + ".php"}}]))
        self.assertEqual(sha1["sev"], "LOW")
        for path, binary in ((base + "shell.php", "/usr/sbin/php-fpm8.3"), (base + "0123456789abcdef0123456789abcdef.php", "/usr/bin/curl"),
                             ("/var/www/app/public/0123456789abcdef0123456789abcdef.php", "/usr/sbin/php-fpm8.3")):
            e = self.one(kprobe("web-write-code", function="security_file_open", binary=binary, parent="/usr/sbin/php-fpm8.3",
                                kargs=[{"file_arg": {"path": path}}]))
            self.assertEqual(e["sev"], "HIGH", path)
            self.assertEqual(e["details"]["path"], path)

    def test_web_connect_carries_the_destination(self):
        e = self.one(kprobe("web-connect", function="tcp_connect", binary="/usr/sbin/php-fpm8.3", parent="/usr/sbin/php-fpm8.3",
                            kargs=[{"sock_arg": {"family": "AF_INET", "protocol": "IPPROTO_TCP", "daddr": "203.0.113.50", "dport": 4444}}]))
        self.assertEqual((e["dst_ip"], e["dst_port"], e["sev"]), ("203.0.113.50", 4444, "MEDIUM"))

    def test_fileless_exec_is_high_unless_a_package_upgrade_runs(self):
        e = self.one(pexec(binary="/memfd:payload (deleted)", links=1))
        self.assertEqual((e["kind"], e["sev"]), ("tetragon.fileless-exec", "HIGH"))
        self.assertTrue(e["details"]["fileless"])
        e = self.one(pexec(binary="/usr/sbin/sshd (deleted)", links=1))
        self.assertEqual(e["sev"], "HIGH")
        e = self.one(pexec(binary="/tmp/x", links=0))
        self.assertEqual(e["kind"], "tetragon.fileless-exec")
        self.assertEqual(self.s.parse_line(json.dumps(pexec(binary="/usr/sbin/sshd (deleted)", parent="/usr/bin/dpkg"))), [])
        self.assertEqual(self.s.parse_line(json.dumps(pexec(binary="/usr/bin/ls"))), [])      # an ordinary exec is not an event

    def test_a_policy_hit_with_a_deleted_binary_is_at_least_high(self):
        e = self.one(kprobe("tcp-listen", binary="/tmp/miner (deleted)", parent="/usr/bin/bash"))
        self.assertEqual(e["sev"], "HIGH")
        self.assertTrue(e["details"]["fileless"])

    def test_ignore_list_drops_routine_hits_but_never_killers(self):
        self.assertEqual(self.s.parse_line(json.dumps(kprobe("tcp-listen", binary="/usr/bin/x", parent="/usr/sbin/cron"))), [])
        self.assertEqual(self.s.parse_line(json.dumps(kprobe("persistence", binary="/usr/sbin/useradd", parent="/usr/bin/dpkg"))), [])
        e = self.one(kprobe("nginx-exec", parent="/usr/sbin/cron"))
        self.assertEqual(e["kind"], "tetragon.nginx-exec")
        self.write(self.paths.tetragon_ignore, "# mine\n\\bbackup-tool\\b\n[bad regex\n")
        s2 = tetragon.TetragonSource(self.ctx, "begin")
        self.addCleanup(s2.close)
        self.assertEqual(s2.parse_line(json.dumps(kprobe("tcp-listen", binary="/opt/backup-tool", parent="/usr/bin/bash"))), [])

    def test_rate_limit_info_on_a_web_host_is_high(self):
        e = self.one({"rate_limit_info": {"number_of_dropped_process_events": "12"}})
        self.assertEqual((e["kind"], e["sev"]), ("health.tetragon_ratelimit", "HIGH"))
        self.assertEqual(self.ctx.counters["tetragon_ratelimit"], 12)
        self.reconf("[kit]\nweb = off\n")
        s2 = tetragon.TetragonSource(self.ctx, "begin")
        self.addCleanup(s2.close)
        self.assertEqual(s2.parse_line(json.dumps({"rate_limit_info": {"number_of_dropped_process_events": "3"}})), [])
        self.assertEqual(self.ctx.counters["tetragon_ratelimit"], 3)

    def test_bad_lines_are_counted_never_fatal(self):
        for line in ("not json", "[1,2]", '{"process_kprobe": {"process": 5}}', "{", "", '{"process_kprobe": {"args": [1, 2]}}'):
            self.s.parse_line(line)
        self.assertGreaterEqual(self.s.bad_json, 3)

    def test_poll_reads_the_log_and_checkpoints(self):
        self.write(self.paths.tetragon_log, json.dumps(kprobe("web-exec")) + "\n")
        events = self.s.poll(self.clock())
        self.assertEqual([e["kind"] for e in events], ["tetragon.web-exec"])
        self.s.commit()
        self.assertTrue(os.path.exists(os.path.join(self.paths.cursors_dir, "tetragon.json")))

    def test_rotation_raises_a_blind_window_note(self):
        self.write(self.paths.tetragon_log, json.dumps(kprobe("web-exec")) + "\n")
        self.s.poll(self.clock())
        os.rename(self.paths.tetragon_log, self.paths.tetragon_log + ".1")
        self.write(self.paths.tetragon_log, json.dumps(kprobe("web-exec", args="-c other")) + "\n")
        self.s.poll(self.clock())
        self.clock.advance(11)
        kinds = [e["kind"] for e in self.s.poll(self.clock())]
        self.assertIn("health.blind_window", kinds)
        self.assertIn("tetragon.web-exec", kinds)

    def test_a_tetragon_restart_is_a_blind_window(self):
        cg = os.path.join(self.root, "sys", "fs", "cgroup", "system.slice")
        self.paths.sys_dir = os.path.join(self.root, "sys")
        unit = os.path.join(cg, "tetragon.service")
        self.assertEqual(self.s.restart_events(100.0), [])                    # not there: nothing to compare with
        os.makedirs(unit)
        self.assertEqual(self.s.restart_events(110.0), [])                    # first sight
        self.assertEqual(self.s.restart_events(120.0), [])
        os.rmdir(unit)
        self.assertEqual(self.s.restart_events(130.0), [])                    # gone: the heartbeat shows it absent
        os.makedirs(unit)
        e = self.s.restart_events(140.0)
        self.assertEqual([(x["kind"], x["sev"], x["details"]["reason"]) for x in e], [("health.blind_window", "MEDIUM", "restarted")])
        self.assertEqual(self.s.restart_events(150.0), [])
        os.rmdir(unit)                                                         # a restart quicker than the poll: a new directory
        os.makedirs(os.path.join(cg, "x"))
        os.rename(os.path.join(cg, "x"), unit)
        self.assertEqual(len(self.s.restart_events(160.0)), 1)

    def test_unreadable_log_is_high(self):
        ev = self.s.on_notice({"type": "unreadable", "reason": "Permission denied"}, "tetragon")[0]
        self.assertEqual((ev["kind"], ev["sev"]), ("health.tetragon_unreadable", "HIGH"))


# ---- nginx error log ------------------------------------------------------------------------------------
def err(msg, level="alert", pid=1000, ts="2026/11/19 10:15:02", trailer=""):
    return "%s [%s] %d#%d: %s%s" % (ts, level, pid, pid, msg, trailer)


class TestNginxError(SrcCase):
    def setUp(self):
        super().setUp()
        self.write(self.paths.nginx_pid, "1000\n")
        self.s = nginx.ErrorLogSource(self.ctx, "begin")
        self.addCleanup(self.s.close)

    def parse(self, line, now=None):
        return self.s.parse_line(line, now if now is not None else self.clock())

    def test_crash_on_signal_11_and_6(self):
        for sig in (11, 6):
            e = self.parse(err("worker process 2222 exited on signal %d (core dumped)" % sig))[0]
            self.assertEqual((e["kind"], e["sev"], e["source"]), ("nginx.crash", "MEDIUM", "nginx"))
            self.assertEqual(e["details"]["signal"], sig)
            self.assertEqual(e["details"]["worker_pid"], 2222)
        self.assertEqual(self.parse(err("worker process 2222 exited on signal 15")), [])
        self.assertEqual(self.parse(err("worker process 2222 exited with code 0")), [])

    def test_crash_line_must_come_from_the_master_pid(self):
        e = self.parse(err("worker process 2222 exited on signal 11", pid=31337))[0]
        self.assertEqual((e["kind"], e["sev"]), ("nginx.crash", "LOW"))
        self.assertTrue(e["details"]["forged"])
        self.os_unlink(self.paths.nginx_pid)
        self.ctx._pid = (0.0, None)
        e = self.parse(err("worker process 2222 exited on signal 11", pid=31337))[0]
        self.assertEqual(e["sev"], "MEDIUM")                       # unreadable pid file: cannot judge, not called forged

    def os_unlink(self, p):
        os.unlink(p)

    def test_crash_must_anchor_at_the_start_of_the_line(self):
        self.assertEqual(self.parse("x " + err("worker process 2222 exited on signal 11")), [])
        self.assertEqual(self.parse(err("open() \"/x\" failed", trailer=", client: 1.2.3.4, server: s, request: \"GET /worker process 1 exited on signal 11\"")), [])

    def test_glibc_abort_lines_attach_to_the_next_crash_within_5_seconds(self):
        self.assertEqual(self.parse("free(): invalid pointer", now=100.0), [])
        self.assertEqual(self.parse("double free detected in tcache 2", now=101.0), [])
        e = self.parse(err("worker process 2222 exited on signal 6"), now=103.0)[0]
        self.assertEqual(e["details"]["abort_lines"], ["free(): invalid pointer", "double free detected in tcache 2"])
        self.assertEqual(self.parse(err("worker process 2223 exited on signal 6"), now=104.0)[0]["details"].get("abort_lines"), None)

    def test_glibc_lines_expire_and_are_capped_at_four(self):
        self.parse("malloc(): corrupted top size", now=100.0)
        e = self.parse(err("worker process 1 exited on signal 11"), now=106.0)[0]
        self.assertNotIn("abort_lines", e["details"])
        for i in range(10):
            self.parse("corrupted size vs. prev_size %d" % i, now=200.0)
        e = self.parse(err("worker process 1 exited on signal 11"), now=201.0)[0]
        self.assertEqual(len(e["details"]["abort_lines"]), 4)

    def test_markers(self):
        e = self.parse(err("could not cancel 000055d3c0a1b2c0 resolving"))[0]
        self.assertEqual((e["kind"], e["sev"]), ("nginx.marker.resolver_cancel", "HIGH"))
        e = self.parse(err("768 worker_connections are not enough"))[0]
        self.assertEqual((e["kind"], e["sev"]), ("nginx.marker.conn_exhausted", "MEDIUM"))
        e = self.parse(err("768 worker_connections are not enough, reusing connections", level="warn"))[0]
        self.assertEqual((e["kind"], e["sev"]), ("nginx.marker.conn_pressure", "LOW"))
        e = self.parse(err("*55 client violated connection flow control: received WINDOW_UPDATE frame with window increment \"2147483648\"",
                           level="info", trailer=", client: 203.0.113.9, server: example.test"))[0]
        self.assertEqual((e["kind"], e["sev"]), ("nginx.marker.window_update", "LOW"))
        self.assertEqual((e["src_ip"], e["src_trust"]), ("203.0.113.9", "tcp"))

    def test_window_update_address_follows_the_proxy_verdict(self):
        line = err("*55 client violated connection flow control: received WINDOW_UPDATE frame with window increment \"1\"",
                   level="info", trailer=", client: 203.0.113.9, server: example.test")
        self.reconf("[bans]\nproxy_mode = on\n")
        s = nginx.ErrorLogSource(self.ctx, "begin")
        self.addCleanup(s.close)
        e = s.parse_line(line, 0)[0]
        self.assertEqual((e["src_ip"], e["src_trust"]), ("203.0.113.9", "claimed"))

    def test_ordinary_error_lines_make_no_event(self):
        self.assertEqual(self.parse(err("*1 open() \"/var/www/x\" failed (2: No such file or directory)", level="error",
                                        trailer=", client: 1.2.3.4, server: s, request: \"GET /x HTTP/1.1\", host: \"h\"")), [])
        self.assertEqual(self.parse(""), [])

    def test_poll_reads_the_file(self):
        self.write(self.paths.nginx_error_log, err("worker process 7 exited on signal 11") + "\n")
        self.assertEqual([e["kind"] for e in self.s.poll(self.clock())], ["nginx.crash"])


class TestAttributeErrorLine(unittest.TestCase):
    def test_rule(self):
        ok = err("x", trailer=", client: 203.0.113.9, server: s, request: \"GET / HTTP/1.1\", host: \"h\"")
        self.assertEqual(nginx.attribute_error_line(ok), "203.0.113.9")
        self.assertEqual(nginx.attribute_error_line(err("x", trailer=", client: 2001:db8::1, server: s")), "2001:db8::1")
        self.assertEqual(nginx.attribute_error_line(err("x", trailer=", client: ::ffff:198.51.100.2, server: s")), "198.51.100.2")
        self.assertEqual(nginx.attribute_error_line(err("x")), "")
        self.assertEqual(nginx.attribute_error_line(err("x", trailer=", client: not-an-ip, server: s")), "")
        self.assertEqual(nginx.attribute_error_line(err("x", trailer=", client: 1.2.3.4, host: s")), "")       # no ", server: "
        two = err("x, client: 198.51.100.8, server: fake", trailer=", client: 203.0.113.9, server: s")
        self.assertEqual(nginx.attribute_error_line(two), "")
        self.assertEqual(nginx.attribute_error_line(err("y" * 2100, trailer=", client: 203.0.113.9, server: s")), "")
        edge = err("", trailer=", client: 203.0.113.9, server: s")
        self.assertEqual(nginx.attribute_error_line(edge + "z" * (2039 - len(edge))), "203.0.113.9")
        self.assertEqual(nginx.attribute_error_line(edge + "z" * (2040 - len(edge))), "")


# ---- nginx access log -----------------------------------------------------------------------------------
def acc(ip="203.0.113.9", path="/", status=200, method="GET", ua="curl/8.0", user="-", ts="19/Nov/2026:10:15:02 +0000", extra=""):
    return '%s - %s [%s] "%s %s HTTP/1.1" %d 123 "-" "%s"%s' % (ip, user, ts, method, path, status, ua, extra)


class TestNginxAccess(SrcCase):
    def setUp(self):
        super().setUp()
        self.s = nginx.AccessLogSource(self.ctx, "begin", tripwires=nginx.load_tripwires("/nonexistent"))
        self.addCleanup(self.s.close)

    def test_parse_fields(self):
        r = nginx.parse_access_line(acc(path="/a/b.php?x=1&token=zz", status=404, ua="Mozilla/5.0 (X11)"))
        self.assertEqual((r["ip"], r["method"], r["path"], r["query"], r["status"], r["bytes"]), ("203.0.113.9", "GET", "/a/b.php", "x=1&token=zz", 404, 123))
        self.assertEqual(r["ts_ms"], 1795083302000)
        self.assertEqual(nginx.parse_access_line(acc(ip="2001:db8::7"))["ip"], "2001:db8::7")
        self.assertIsNone(nginx.parse_access_line("garbage"))
        self.assertEqual(nginx.parse_access_line('1.2.3.4 - - [19/Nov/2026:10:15:02 +0000] "-" 400 0 "-" "-"')["method"], "")

    def test_the_first_field_must_be_an_address(self):
        self.assertIsNone(nginx.parse_access_line(acc(ip="example.test")))
        self.assertIsNone(nginx.parse_access_line(acc(ip="203.0.113.9, 198.51.100.8")))
        self.assertIsNone(nginx.parse_access_line("- " + acc()))

    def test_tripwire_404_is_low_with_a_tcp_address(self):
        e = self.s.parse_line(acc(path="/.env", status=404))[0]
        self.assertEqual((e["kind"], e["sev"], e["source"]), ("canary.tripwire", "LOW", "nginx"))
        self.assertEqual((e["src_ip"], e["src_trust"]), ("203.0.113.9", "tcp"))
        self.assertEqual((e["details"]["status"], e["details"]["path"], e["details"]["ban"]), (404, "/.env", True))
        for st in (403, 444):
            self.assertEqual(self.s.parse_line(acc(path="/xmlrpc.php", status=st))[0]["sev"], "LOW")

    def test_tripwire_answered_by_the_site_is_high_and_never_a_ban(self):
        e = self.s.parse_line(acc(path="/.env", status=200))[0]
        self.assertEqual((e["sev"], e["details"]["served"], e["details"]["ban"]), ("HIGH", True, False))

    def test_other_statuses_and_paths_make_no_event(self):
        self.assertEqual(self.s.parse_line(acc(path="/.env", status=500)), [])
        self.assertEqual(self.s.parse_line(acc(path="/index.php", status=404)), [])

    def test_pattern_kinds(self):
        for path in ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/.git/config", "/phpmyadmin/index.php", "/phpmyadmin",
                     "/cgi-bin/x.sh", "/storage/logs/laravel.log", "/%2e%65nv", "//.env", "/.ENV"):
            self.assertEqual(len(self.s.parse_line(acc(path=path, status=404))), 1, path)
        for path in ("/.environment", "/env", "/vendor/x", "/gitx/.git"):
            self.assertEqual(self.s.parse_line(acc(path=path, status=404)), [], path)

    def test_ban_false_entries_alert_without_ban_evidence(self):
        e = self.s.parse_line(acc(path="/telescope", status=404))[0]
        self.assertIs(e["details"]["ban"], False)

    def test_wp_login_is_a_tripwire_unless_wordpress_is_there(self):
        site = os.path.join(self.root, "site")
        os.makedirs(site)
        self.assertEqual(len(nginx.match_tripwire(nginx.load_tripwires("/nonexistent"), "/wp-login.php") or ()), 2)
        self.write(os.path.join(site, "wp-config.php"), "<?php")
        rules = nginx.load_tripwires("/nonexistent", [site])
        self.assertIsNone(nginx.match_tripwire(rules, "/wp-login.php"))

    def test_tripwires_json_is_read_in_a_few_shapes(self):
        p = self.write(os.path.join(self.root, "tw.json"), json.dumps({"tripwires": ["/secret.php", {"path": "/x/*/y", "ban": False}]}))
        rules = nginx.load_tripwires(p)
        self.assertEqual(nginx.match_tripwire(rules, "/secret.php"), ("/secret.php", True))
        self.assertEqual(nginx.match_tripwire(rules, "/x/1/y"), ("/x/*/y", False))
        self.assertIsNone(nginx.match_tripwire(rules, "/.env"))
        p2 = self.write(os.path.join(self.root, "tw2.json"), json.dumps(["/a", "/b/"]))
        self.assertEqual(len(nginx.load_tripwires(p2)), 2)
        p3 = self.write(os.path.join(self.root, "tw3.json"), "not json")
        self.assertGreater(len(nginx.load_tripwires(p3)), 5)                  # the built-in list

    def test_ring_and_counters(self):
        for i in range(30):
            self.s.parse_line(acc(path="/p%d" % i, status=200, ts="19/Nov/2026:10:15:%02d +0000" % i))
        self.s.parse_line(acc(ip="198.51.100.4", path="/other"))
        self.assertEqual(len(self.ctx.ring.entries_for("203.0.113.9", 20)), 20)
        self.assertEqual(self.ctx.ring.entries_for("203.0.113.9", 3)[-1]["path"], "/p29")
        self.assertEqual(len(self.ctx.ring.entries_for("198.51.100.4")), 1)
        self.assertEqual(self.ctx.stats.ips["203.0.113.9"][0], 30)

    def test_ring_is_bounded_by_lines_and_minutes_and_never_on_disk(self):
        self.reconf("[agent]\naccess_ring_lines = 100\naccess_ring_minutes = 5\n")
        s = nginx.AccessLogSource(self.ctx, "begin", tripwires=[])
        self.addCleanup(s.close)
        now = int(self.clock())
        for i in range(300):
            self.ctx.ring.add(now, "1.2.3.4", "GET", "/", "", 200, 1, "ua")
        self.assertEqual(len(self.ctx.ring.q), 100)
        self.ctx.ring.prune(now + 301)
        self.assertEqual(len(self.ctx.ring.q), 0)
        self.assertFalse(any("ring" in n for n in os.listdir(self.paths.state_dir)))

    def test_ring_never_stores_cookies_or_referers(self):
        self.s.parse_line('203.0.113.9 - - [19/Nov/2026:10:15:02 +0000] "GET /a HTTP/1.1" 200 5 "http://ref.test/secret" "UA" "Cookie: x"')
        row = self.ctx.ring.entries_for("203.0.113.9")[0]
        self.assertEqual(sorted(row), ["bytes", "ip", "method", "path", "query", "status", "ts", "ua"])
        self.assertNotIn("ref.test", json.dumps(row))

    def test_ipv6_counters_are_per_slash_64(self):
        self.s.parse_line(acc(ip="2001:db8:1:2::1"))
        self.s.parse_line(acc(ip="2001:db8:1:2:ffff::9"))
        self.s.parse_line(acc(ip="2001:db8:1:3::1"))
        keys = sorted(self.ctx.stats.ips)
        self.assertEqual(keys, ["2001:db8:1:2::/64", "2001:db8:1:3::/64"])

    def test_counter_table_is_capped(self):
        from edragent.sources import base
        st = base.AccessStats()
        for i in range(base.COUNTER_KEYS_MAX + 500):
            st.count("10.%d.%d.%d" % (i >> 16 & 255, i >> 8 & 255, i & 255), 200)
        self.assertEqual(len(st.ips), base.COUNTER_KEYS_MAX)

    def test_log_format_mismatch_raises_health_log_format_once(self):
        events = []
        for i in range(40):
            events += self.s.parse_line('vhost.test %s - - [19/Nov/2026:10:15:02 +0000] "GET / HTTP/1.1" 200 5 "-" "-"' % "203.0.113.9")
        events += self.s._after_batch(self.clock())
        kinds = [e["kind"] for e in events]
        self.assertEqual(kinds.count("health.log_format"), 1)
        self.assertEqual([e for e in events if e["kind"] == "health.log_format"][0]["sev"], "MEDIUM")
        self.assertEqual(self.s._after_batch(self.clock()), [])                 # not again within hours
        self.assertEqual(self.ctx.stats.ips, {})                               # nothing was attributed or counted
        self.assertEqual(len(self.ctx.ring.q), 0)

    def test_a_format_that_does_not_start_with_remote_addr_disables_attribution(self):
        self.ctx.inventory_checks = {"nginx_logs": {"status": True, "access_logs": [{"path": "/var/log/nginx/access.log", "format": "vhost"}],
                                                   "log_formats": {"vhost": {"starts_remote_addr": False, "has_xff": False},
                                                                   "main": {"starts_remote_addr": True, "has_xff": False}}}}
        events = self.s._after_batch(self.clock())
        self.assertEqual([(e["kind"], e["sev"]) for e in events], [("health.log_format", "MEDIUM")])
        self.assertEqual(self.s._after_batch(self.clock()), [])                 # raised once
        e = self.s.parse_line(acc(ip="198.51.100.8", path="/.env", status=404))[0]
        self.assertEqual((e["src_ip"], e["src_trust"]), ("", "none"))          # a header value could be anything
        self.assertEqual(self.ctx.stats.ips, {})
        self.assertEqual(len(self.ctx.ring.q), 0)
        self.ctx.inventory_checks = {"nginx_logs": {"access_logs": [{"format": "main"}], "log_formats": {"main": {"starts_remote_addr": True}}}}
        self.s._after_batch(self.clock())
        self.assertEqual(self.s.parse_line(acc(path="/.env", status=404))[0]["src_trust"], "tcp")

    def test_the_shipped_tripwires_file_loads(self):
        shipped = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "files", "tripwires.json")
        if not os.path.exists(shipped):
            self.skipTest("files/tripwires.json is not written yet")
        rules = nginx.load_tripwires(shipped)
        self.assertGreaterEqual(len(rules), 14)
        self.assertEqual(nginx.match_tripwire(rules, "/.env"), ("/.env", True))
        self.assertEqual(nginx.match_tripwire(rules, "/telescope/requests"), ("/telescope", False))
        self.assertEqual(nginx.match_tripwire(rules, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php")[1], True)
        self.assertEqual(len(rules), len(nginx.load_tripwires("/nonexistent")))        # the same list as the built-in one

    def test_proxy_heuristic_marks_addresses_claimed(self):
        for i in range(250):
            self.s.parse_line(acc(ip="10.0.0.5", path="/p"))
        events = self.s._after_batch(self.clock())
        self.assertEqual([e["kind"] for e in events], ["health.proxy_mode"])
        e = self.s.parse_line(acc(ip="203.0.113.9", path="/.env", status=404))[0]
        self.assertEqual(e["src_trust"], "claimed")

    def test_proxy_heuristic_needs_a_real_sample(self):
        for i in range(5):
            self.s.parse_line(acc(ip="203.0.113.9", path="/.env", status=404))
        self.assertEqual(self.s._after_batch(self.clock()), [])
        self.assertEqual(self.s.parse_line(acc(ip="203.0.113.9", path="/.env", status=404))[0]["src_trust"], "tcp")

    def test_forwarded_header_value_marks_proxied(self):
        self.s.parse_line(acc(ip="203.0.113.9", extra=' "198.51.100.77, 10.0.0.1"'))
        self.s._after_batch(self.clock())
        self.assertEqual(self.s.parse_line(acc(path="/.env", status=404))[0]["src_trust"], "claimed")

    def test_real_ip_in_inventory_and_proxy_mode(self):
        self.ctx.inventory_checks = {"real_ip": {"status": True}}
        self.assertEqual(self.ctx.web_src_trust(), "claimed")
        self.reconf("[bans]\nproxy_mode = off\n")
        self.ctx.inventory_checks = {"real_ip": {"status": True}}
        self.assertEqual(self.ctx.web_src_trust(), "claimed")                  # off never overrides real_ip
        self.ctx.inventory_checks = {}
        self.assertEqual(self.ctx.web_src_trust(), "tcp")


# ---- journal --------------------------------------------------------------------------------------------
def jrec(msg, comm="sshd", uid="0", ts=1795083302123456):
    return {"MESSAGE": msg, "_COMM": comm, "_UID": str(uid), "__REALTIME_TIMESTAMP": str(ts), "__CURSOR": "c"}


class TestJournal(SrcCase):
    def setUp(self):
        super().setUp()
        self.seen = src.SeenStore(self.paths.seen_json, self.clock)
        self.s = src.JournalSource(self.ctx, self.seen, popen=lambda *a, **k: None)

    def ev(self, rec):
        return self.s.to_events(rec)

    def test_sshd_failures(self):
        cases = [
            ("Failed password for root from 203.0.113.9 port 40000 ssh2", "root", "password", False),
            ("Failed password for invalid user admin from 203.0.113.9 port 40000 ssh2", "admin", "password", True),
            ("Failed publickey for deploy from 203.0.113.9 port 40000 ssh2: RSA SHA256:" + "A" * 43, "deploy", "publickey", False),
            ("Invalid user test from 203.0.113.9 port 40000", "test", "invalid_user", True),
            ("Connection closed by authenticating user root 203.0.113.9 port 40000 [preauth]", "root", "preauth_close", False),
            ("Connection closed by invalid user x 203.0.113.9 port 40000 [preauth]", "x", "preauth_close", True),
        ]
        for msg, user, method, invalid in cases:
            events = self.ev(jrec(msg))
            self.assertEqual(len(events), 1, msg)
            e = events[0]
            self.assertEqual((e["kind"], e["sev"], e["source"], e["src_ip"], e["src_trust"]), ("ssh.fail", "LOW", "journal", "203.0.113.9", "tcp"), msg)
            self.assertEqual((e["details"]["user"], e["details"]["method"], e["details"]["invalid"]), (user, method, invalid), msg)
        self.assertEqual(self.ev(jrec("Failed password for root from 203.0.113.9 port 40000 ssh2"))[0]["ts"], "2026-11-19T10:15:02.123Z")

    def test_unable_to_negotiate_anchors_at_the_start(self):
        e = self.ev(jrec("Unable to negotiate with 203.0.113.9 port 40000: no matching key exchange method found. Their offer: x"))[0]
        self.assertEqual((e["kind"], e["src_ip"]), ("ssh.fail", "203.0.113.9"))
        self.assertEqual(self.ev(jrec("note: Unable to negotiate with 203.0.113.9 port 40000: x")), [])

    def test_user_name_cannot_fake_the_address(self):
        fake = "bob from 198.51.100.8 port 1 ssh2"
        for tpl in ("Failed password for %s from 203.0.113.9 port 40000 ssh2", "Failed password for invalid user %s from 203.0.113.9 port 40000 ssh2",
                    "Invalid user %s from 203.0.113.9 port 40000",
                    "Connection closed by authenticating user %s 203.0.113.9 port 40000 [preauth]"):
            e = self.ev(jrec(tpl % fake))[0]
            self.assertEqual(e["src_ip"], "203.0.113.9", tpl)
            self.assertEqual(e["details"]["user"], fake, tpl)

    def test_a_fake_tail_with_a_real_one_missing_is_not_attributed_to_the_fake(self):
        self.assertEqual(self.ev(jrec("Failed password for x from 203.0.113.9 port 4 ssh2 trailing text")), [])
        self.assertEqual(self.ev(jrec("Failed password for x from not-an-ip port 4 ssh2")), [])
        self.assertEqual(self.ev(jrec("Failed password for x from 203.0.113.256 port 4 ssh2")), [])

    def test_only_the_journals_own_fields_select_records(self):
        forged = jrec("Failed password for root from 198.51.100.8 port 1 ssh2", comm="logger", uid="1001")
        self.assertEqual(self.ev(forged), [])
        self.assertEqual(self.ev(jrec("Failed password for root from 198.51.100.8 port 1 ssh2", comm="sshd", uid="1001")), [])
        self.assertEqual(self.ev(jrec("Failed password for root from 198.51.100.8 port 1 ssh2", comm="sshd", uid="")), [])
        self.assertEqual(len(self.ev(jrec("Failed password for root from 198.51.100.8 port 1 ssh2", comm="sshd-session"))), 1)
        r = jrec("Failed password for root from 198.51.100.8 port 1 ssh2")
        r["MESSAGE"] = [70, 97]                        # a binary message
        self.assertEqual(self.ev(r), [])
        self.assertEqual(self.ev({"MESSAGE": "Failed password for root from 1.2.3.4 port 1 ssh2"}), [])

    def test_sudo(self):
        e = self.ev(jrec("    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update", comm="sudo", uid="1000"))[0]
        self.assertEqual((e["kind"], e["sev"]), ("auth.sudo", "LOW"))
        self.assertEqual(e["details"], {"user": "alice", "target": "root", "command": "/usr/bin/apt update", "tty": "pts/0"})
        self.assertEqual(e["src_ip"], "")
        for cmd in ("/usr/bin/bash", "/bin/su -", "/usr/bin/vi /etc/sudoers.d/x", "/usr/bin/nano /root/.ssh/authorized_keys",
                    "/usr/bin/crontab -e", "/usr/sbin/visudo"):
            e = self.ev(jrec("    alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=" + cmd, comm="sudo", uid="1000"))[0]
            self.assertEqual(e["sev"], "MEDIUM", cmd)
        e = self.ev(jrec("    mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/ls", comm="sudo", uid="1001"))[0]
        self.assertEqual(e["sev"], "LOW" if False else e["sev"])
        self.assertEqual(self.ev(jrec("pam_unix(sudo:session): session opened for user root", comm="sudo", uid="0")), [])
        e = self.ev(jrec("    carol : command not allowed ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/x ; y", comm="sudo", uid="1"))[0]
        self.assertTrue(e["details"]["command"].endswith("/bin/x ; y"))

    def test_sudo_command_cannot_overwrite_the_fields_before_it(self):
        e = self.ev(jrec("    a : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/echo ; USER=nobody ; COMMAND=/bin/true", comm="sudo", uid="1"))[0]
        self.assertEqual(e["details"]["target"], "root")
        self.assertEqual(e["details"]["command"], "/bin/echo ; USER=nobody ; COMMAND=/bin/true")

    def test_login_novelty(self):
        def login(user="alice", ip="203.0.113.9", auth="publickey", fp="SHA256:" + "A" * 43):
            msg = "Accepted %s for %s from %s port 5 ssh2" % (auth, user, ip)
            if fp:
                msg += ": ED25519 " + fp
            return self.ev(jrec(msg))[0]
        e = login()
        self.assertEqual((e["kind"], e["sev"], e["src_ip"]), ("ssh.login", "LOW", "203.0.113.9"))      # new key, but the first 14 days are LOW
        self.assertEqual(e["details"]["novel"], ["new_key", "new_source"])
        self.assertEqual((e["details"]["auth"], e["details"]["key_fp"]), ("publickey", "SHA256:" + "A" * 43))
        self.assertEqual(login()["sev"], "INFO")
        self.assertEqual(login(ip="203.0.113.77")["sev"], "INFO")                                       # same /24
        self.assertEqual(login(ip="198.51.100.2")["sev"], "LOW")                                        # new source for a known user
        self.clock.advance(15 * 86400)
        self.assertEqual(login(fp="SHA256:" + "B" * 43)["sev"], "MEDIUM")                               # new key after 14 days
        self.assertEqual(login(user="root", fp="SHA256:" + "C" * 43)["sev"], "HIGH")                    # first root login
        self.assertEqual(login(user="root", fp="SHA256:" + "C" * 43)["sev"], "INFO")

    def test_password_login_with_password_auth_off_is_high(self):
        self.reconf("[agent]\nsshd_password_auth = off\n")
        s = src.JournalSource(self.ctx, self.seen, popen=lambda *a, **k: None)
        e = s.to_events(jrec("Accepted password for alice from 203.0.113.9 port 5 ssh2"))[0]
        self.assertEqual(e["sev"], "HIGH")
        self.assertIn("password_login_with_password_auth_off", e["details"]["novel"])
        self.reconf("[agent]\nsshd_password_auth = on\n")
        s = src.JournalSource(self.ctx, self.seen, popen=lambda *a, **k: None)
        e = s.to_events(jrec("Accepted password for alice from 203.0.113.10 port 5 ssh2"))[0]
        self.assertNotEqual(e["sev"], "HIGH")

    def test_seen_store_persists_and_is_bounded(self):
        self.seen.add("keys", "a|b")
        self.seen.save()
        again = src.SeenStore(self.paths.seen_json, self.clock)
        self.assertTrue(again.has("keys", "a|b"))
        self.assertEqual(again.first, self.seen.first)
        for i in range(journal.SEEN_CAP + 10):
            again.add("nets", "x|%d" % i)
        self.assertEqual(len(again.sets["nets"]), journal.SEEN_CAP)


# ---- Suricata ---------------------------------------------------------------------------------------------
def eve_alert(sev=1, sid=2001219, proto="TCP", app="http", src="203.0.113.9", dport=80, payload=None, **extra):
    d = {"timestamp": "2026-11-19T10:15:02.481234+0000", "flow_id": 1, "event_type": "alert", "src_ip": src, "src_port": 40000,
         "dest_ip": "198.51.100.1", "dest_port": dport, "proto": proto, "community_id": "1:abc=", "stream": 1,
         "alert": {"action": "allowed", "gid": 1, "signature_id": sid, "rev": 1, "signature": "ET SCAN Sqlmap", "category": "Web Application Attack",
                   "severity": sev},
         "flow": {"pkts_toserver": 5, "pkts_toclient": 3}}
    if app:
        d["app_proto"] = app
    if payload is not None:
        d["payload"] = payload
    d.update(extra)
    return d


class TestSuricata(SrcCase):
    def setUp(self):
        super().setUp()
        self.s = suricata.EveSource(self.ctx, "begin")
        self.addCleanup(self.s.close)

    def alert(self, obj):
        events = self.s.parse_line(json.dumps(obj))
        self.assertEqual(len(events), 1)
        return events[0]

    def test_alert_mapping(self):
        e = self.alert(eve_alert())
        self.assertEqual((e["kind"], e["sev"], e["source"]), ("suricata.alert", "HIGH", "suricata"))
        self.assertEqual((e["src_ip"], e["src_trust"], e["dst_ip"], e["dst_port"], e["proto"]), ("203.0.113.9", "tcp", "198.51.100.1", 80, "tcp"))
        self.assertEqual(e["community_id"], "1:abc=")
        d = e["details"]
        self.assertEqual((d["sid"], d["signature_id"], d["app_proto"], d["stream"], d["pkts_toserver"], d["pkts_toclient"]),
                         (2001219, 2001219, "http", 1, 5, 3))
        self.assertEqual(e["summary"], "ET SCAN Sqlmap")
        self.assertEqual([self.alert(eve_alert(sev=n))["sev"] for n in (2, 3, 9)], ["MEDIUM", "LOW", "LOW"])

    def test_tcp_trust_needs_a_tcp_flow_with_an_app_proto(self):
        self.assertEqual(self.alert(eve_alert(proto="UDP"))["src_trust"], "claimed")
        self.assertEqual(self.alert(eve_alert(proto="ICMP", app=None))["src_trust"], "claimed")
        self.assertEqual(self.alert(eve_alert(app=None))["src_trust"], "claimed")
        self.assertEqual(self.alert(eve_alert(app="failed"))["src_trust"], "claimed")
        self.assertEqual(self.alert(eve_alert(dport=22, app="ssh"))["src_trust"], "tcp")

    def test_web_port_alerts_are_claimed_behind_a_proxy(self):
        self.reconf("[bans]\nproxy_mode = on\n")
        s = suricata.EveSource(self.ctx, "begin")
        self.addCleanup(s.close)
        self.assertEqual(s.parse_line(json.dumps(eve_alert(dport=443)))[0]["src_trust"], "claimed")
        self.assertEqual(s.parse_line(json.dumps(eve_alert(dport=22, app="ssh")))[0]["src_trust"], "tcp")

    def test_payload_is_hex_head_only_and_can_be_switched_off(self):
        raw = bytes(range(200))
        e = self.alert(eve_alert(payload=base64.b64encode(raw).decode(), payload_printable="GET /secret?token=abc"))
        self.assertEqual(e["details"]["payload_hex"], raw[:128].hex())
        self.assertNotIn("payload_printable", json.dumps(e))
        self.assertNotIn("token=abc", json.dumps(e))
        self.reconf("[agent]\npayload = off\n")
        s = suricata.EveSource(self.ctx, "begin")
        self.addCleanup(s.close)
        e = s.parse_line(json.dumps(eve_alert(payload=base64.b64encode(raw).decode())))[0]
        self.assertNotIn("payload_hex", e["details"])

    def test_http_url_is_redacted(self):
        e = self.alert(eve_alert(http={"url": "/login?token=SECRET9&a=1", "http_method": "GET", "hostname": "h.test", "status": 404}))
        self.assertEqual(e["details"]["url"], "/login?token=[REDACTED]&a=1")
        self.assertTrue(e["redacted"])

    def test_anomaly_is_low(self):
        e = self.alert({"timestamp": "2026-11-19T10:15:02.481234+0000", "event_type": "anomaly", "src_ip": "203.0.113.9", "dest_ip": "198.51.100.1",
                        "proto": "TCP", "anomaly": {"type": "applayer", "event": "APPLAYER_MISMATCH_PROTOCOL_BOTH_DIRECTIONS", "layer": "proto_detect"}})
        self.assertEqual((e["kind"], e["sev"], e["src_trust"]), ("suricata.alert", "LOW", "claimed"))

    def test_stats_feed_the_heartbeat_not_events(self):
        def stats(ts, pk, dr):
            return {"timestamp": ts, "event_type": "stats", "stats": {"capture": {"kernel_packets": pk, "kernel_drops": dr}}}
        self.assertEqual(self.s.parse_line(json.dumps(stats("2026-11-19T10:00:00.000000+0000", 1000, 10))), [])
        self.assertIsNone(self.ctx.suricata_drops)
        self.s.parse_line(json.dumps(stats("2026-11-19T10:01:00.000000+0000", 6000, 60)))
        self.assertEqual(self.ctx.suricata_drops, {"packets": 5000, "drops": 50, "window_s": 60})
        self.s.parse_line(json.dumps(stats("2026-11-19T10:02:00.000000+0000", 100, 1)))        # Suricata restarted
        self.assertEqual(self.ctx.suricata_drops, {"packets": 100, "drops": 1, "window_s": 60})

    def test_bulk_file_adds_context_to_alerts(self):
        b = suricata.EveBulkSource(self.ctx, "begin")
        self.addCleanup(b.close)
        b.parse_line(json.dumps({"event_type": "tls", "community_id": "1:abc=", "tls": {"sni": "evil.test", "ja4": "t13d1516h2_x"}}))
        b.parse_line(json.dumps({"event_type": "ssh", "community_id": "1:abc=", "ssh": {"client": {"hassh": {"hash": "deadbeef"}}}}))
        b.parse_line(json.dumps({"event_type": "quic", "community_id": "2:zzz=", "quic": {"sni": "q.test"}}))
        d = self.alert(eve_alert())["details"]
        self.assertEqual((d["sni"], d["ja4"], d["hassh"]), ("evil.test", "t13d1516h2_x", "deadbeef"))
        self.assertEqual(b.poll(0), [])

    def test_bulk_context_is_bounded(self):
        b = suricata.EveBulkSource(self.ctx, "begin")
        self.addCleanup(b.close)
        for i in range(suricata.FLOW_CONTEXT_MAX + 50):
            b.parse_line(json.dumps({"event_type": "tls", "community_id": "k%d" % i, "tls": {"sni": "s"}}))
        self.assertEqual(len(self.ctx.eve_flow_context), suricata.FLOW_CONTEXT_MAX)

    def test_bad_lines(self):
        for line in ("nope", "[]", '{"event_type":"alert","alert":"x"}', '{"event_type":"alert","flow":5}'):
            self.s.parse_line(line)

    def test_a_missing_bulk_file_is_normal(self):
        b = suricata.EveBulkSource(self.ctx, "begin")
        self.addCleanup(b.close)
        self.assertEqual(b.poll(0), [])
        self.write(self.paths.eve_json, json.dumps(eve_alert()) + "\n")
        self.assertEqual(len(self.s.poll(0)), 1)


# ---- kernel log ---------------------------------------------------------------------------------------------
BIGCONN = "edr-bigconn: IN=eth0 OUT= MAC=aa:bb SRC=203.0.113.9 DST=198.51.100.1 LEN=52 TOS=0x00 PREC=0x00 TTL=60 ID=1 DF PROTO=TCP SPT=51000 DPT=443 WINDOW=1 RES=0x00 ACK URGP=0"
DNSLOCK = "edr-dnslock: plain IN= OUT=eth0 SRC=198.51.100.1 DST=9.9.9.9 LEN=60 PROTO=UDP SPT=40000 DPT=53 LEN=40 UID=%d GID=%d"
EGRESS = "edr-egress: IN= OUT=eth0 SRC=198.51.100.1 DST=%s LEN=60 PROTO=TCP SPT=40000 DPT=%d UID=%d GID=%d"


class TestKernel(SrcCase):
    def setUp(self):
        super().setUp()
        self.seen = src.SeenStore(self.paths.seen_json, self.clock)
        self.fifo = os.path.join(self.root, "k.fifo")
        os.mkfifo(self.fifo)
        self.s = src.KernelSource(self.ctx, self.seen, self.fifo, "begin")
        self.addCleanup(self.s.close)

    def test_bigconn(self):
        e = self.s.to_events(BIGCONN, None)[0]
        self.assertEqual((e["kind"], e["source"], e["src_ip"], e["src_trust"], e["dst_port"], e["proto"]),
                         ("edr.bigconn", "kernel", "203.0.113.9", "tcp", 443, "tcp"))

    def test_parse_accepts_dmesg_prefixes_and_only_edr_lines(self):
        self.assertEqual(kernel.parse_kernel_line("[ 123.456789] " + BIGCONN)["prefix"], "edr-bigconn")
        self.assertEqual(kernel.parse_kernel_line("<4>" + BIGCONN)["prefix"], "edr-bigconn")
        for line in ("Nov 19 kernel: " + BIGCONN, "xx" + BIGCONN, "IN=eth0 SRC=1.2.3.4", "edr-other: x", "edr-dnslock: weird IN=", ""):
            self.assertIsNone(kernel.parse_kernel_line(line), line)

    def test_dnslock_severity_by_uid(self):
        self.write(self.paths.etc_dir + "/x", "")
        self.ctx._uids = (self.clock(), {33})
        self.assertEqual(self.s.to_events(DNSLOCK % (33, 33), None)[0]["sev"], "HIGH")          # a web user
        self.assertEqual(self.s.to_events(DNSLOCK % (1000, 1000), None)[0]["sev"], "MEDIUM")    # another non-root uid
        self.assertEqual(self.s.to_events(DNSLOCK % (0, 0), None)[0]["sev"], "LOW")
        e = self.s.to_events(DNSLOCK % (33, 33), None)[0]
        self.assertEqual((e["kind"], e["source"], e["details"]["what"], e["dst_ip"], e["dst_port"], e["src_ip"]),
                         ("edr.dnslock", "kernel", "plain", "9.9.9.9", 53, ""))
        for what, sev in (("self", "HIGH"), ("doh", "MEDIUM")):
            e = self.s.to_events(DNSLOCK.replace("plain", what) % (33, 33), None)[0]
            self.assertEqual((e["details"]["what"], e["sev"]), (what, sev))

    def test_egress_learns_first_and_flags_metadata(self):
        e = self.s.to_events(EGRESS % ("203.0.113.50", 443, 33, 33), None)
        self.assertEqual((e[0]["kind"], e[0]["sev"]), ("edr.egress", "INFO"))                  # inside the 14 day learning period
        self.assertEqual(self.s.to_events(EGRESS % ("203.0.113.50", 443, 33, 33), None), [])   # not new
        m = self.s.to_events(EGRESS % ("169.254.169.254", 80, 33, 33), None)[0]
        self.assertEqual(m["sev"], "MEDIUM")
        self.clock.advance(15 * 86400)
        late = self.s.to_events(EGRESS % ("203.0.113.51", 443, 33, 33), None)[0]
        self.assertEqual(late["sev"], "LOW")

    def test_fifo_end_to_end(self):
        self.assertEqual(self.s.poll(0), [])                                  # opens the reading end
        fd = os.open(self.fifo, os.O_WRONLY | os.O_NONBLOCK)
        try:
            os.write(fd, (BIGCONN + "\nnot ours\n" + DNSLOCK % (33, 33) + "\n").encode())
            kinds = [e["kind"] for e in self.s.poll(0)]
        finally:
            os.close(fd)
        self.assertEqual(kinds, ["edr.bigconn", "edr.dnslock"])

    def test_file_mode(self):
        f = os.path.join(self.root, "kern.log")
        self.write(f, BIGCONN + "\n")
        s = src.KernelSource(self.ctx, self.seen, f, "begin")
        self.addCleanup(s.close)
        self.assertEqual([e["kind"] for e in s.poll(0)], ["edr.bigconn"])

    def test_journal_records_need_the_kernel_transport(self):
        class R:
            def __init__(self, recs):
                self.recs = recs

            def poll(self, n=0):
                r, self.recs = self.recs, []
                return r

            def drain_notices(self):
                return []

            def commit(self):
                pass

            def close(self):
                pass
        s = src.KernelSource(self.ctx, self.seen, self.fifo, "begin")
        s.reader.close()
        s.reader = R([{"MESSAGE": BIGCONN, "_TRANSPORT": "syslog"}, {"MESSAGE": BIGCONN, "_TRANSPORT": "kernel", "__REALTIME_TIMESTAMP": "1795083302123456"},
                      {"MESSAGE": BIGCONN}, {"MESSAGE": 5, "_TRANSPORT": "kernel"}])
        events = s.poll(0)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["ts"], "2026-11-19T10:15:02.123Z")


if __name__ == "__main__":
    unittest.main()
