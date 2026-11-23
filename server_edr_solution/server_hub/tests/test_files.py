"""server_hub/files and check.sh: units verify and carry the shared directives, the nft template renders and loads,
the scripts lint, and check.sh's database report works. Nothing here installs or starts anything; check.sh is never run."""

import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
HUB_DIR = os.path.normpath(os.path.join(HERE, ".."))
FILES = os.path.join(HUB_DIR, "files")
sys.path.insert(0, os.path.join(HUB_DIR, "hub"))

import hub_schema    # noqa: E402

NOISE = re.compile(r"is not executable|No such file or directory|not found|Unit .* not found")
UNITS = ["edr-hub.service", "edr-hub-ui.service", "edr-hub-out.service", "edr-hub-failed.service",
         "edr-hub-backup.service", "edr-hub-backup.timer", "edr-hub-nft.service"]

# PLAN section 8 step 4, "Shared directives for every hub unit" (UMask is per unit and checked separately)
SHARED = ["NoNewPrivileges=yes", "CapabilityBoundingSet=", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
          "PrivateDevices=yes", "DevicePolicy=closed", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
          "ProtectKernelLogs=yes", "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes",
          "ProtectProc=invisible", "ProcSubset=pid", "RestrictNamespaces=yes", "RestrictRealtime=yes", "RestrictSUIDSGID=yes",
          "LockPersonality=yes", "MemoryDenyWriteExecute=yes", "SystemCallArchitectures=native",
          "SystemCallFilter=@system-service", "SystemCallFilter=~@privileged @resources", "RemoveIPC=yes",
          "KeyringMode=private", "LogNamespace=edr-hub"]


def read(name):
    with open(os.path.join(FILES, name), encoding="utf-8") as f:
        return f.read()


def section(text, name):
    m = re.search(r"^\[%s\]\n(.*?)(?=^\[|\Z)" % name, text, re.S | re.M)
    return [l for l in (m.group(1).splitlines() if m else []) if l.strip() and not l.startswith("#")]


def run(*cmd, **kw):
    return subprocess.run(list(cmd), capture_output=True, text=True, timeout=60, **kw)


class UnitTests(unittest.TestCase):
    def test_every_unit_verifies(self):
        if not shutil.which("systemd-analyze"):
            self.skipTest("systemd-analyze is not available")
        for name in UNITS:
            r = run("systemd-analyze", "verify", os.path.join(FILES, name))
            out = "\n".join(l for l in (r.stdout + r.stderr).splitlines() if not NOISE.search(l))
            self.assertEqual(out.strip(), "", "%s: %s" % (name, out))

    def test_security_exposure_stays_low(self):
        if not shutil.which("systemd-analyze"):
            self.skipTest("systemd-analyze is not available")
        for name in ("edr-hub.service", "edr-hub-ui.service", "edr-hub-out.service", "edr-hub-failed.service", "edr-hub-backup.service"):
            r = run("systemd-analyze", "security", "--offline=true", os.path.join(FILES, name))
            m = re.search(r"exposure level for \S+: ([0-9.]+)", r.stdout)
            self.assertTrue(m, "%s: %s" % (name, r.stdout + r.stderr))
            self.assertLessEqual(float(m.group(1)), 2.5, name)

    def test_shared_directives_on_every_service(self):
        for name in ("edr-hub.service", "edr-hub-ui.service", "edr-hub-out.service", "edr-hub-failed.service"):
            lines = section(read(name), "Service")
            for want in SHARED:
                self.assertIn(want, lines, "%s lacks %s" % (name, want))
            self.assertLess(lines.index("SystemCallFilter=@system-service"), lines.index("SystemCallFilter=~@privileged @resources"))

    def test_backup_service_keeps_the_shared_directives_but_a_capability_list(self):
        lines = section(read("edr-hub-backup.service"), "Service")
        for want in SHARED:
            if want == "CapabilityBoundingSet=":
                continue
            self.assertIn(want, lines, "edr-hub-backup.service lacks %s" % want)
        caps = [l for l in lines if l.startswith("CapabilityBoundingSet=")]
        self.assertEqual(len(caps), 1)
        granted = set(caps[0].split("=", 1)[1].split())
        self.assertTrue(granted and granted <= {"CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_CHOWN", "CAP_FOWNER"}, granted)
        self.assertIn("SystemCallFilter=@chown", lines)                  # added back after the deny line, for the owner copy
        self.assertEqual(lines.index("SystemCallFilter=@chown") > lines.index("SystemCallFilter=~@privileged @resources"), True)

    def test_umask_per_unit(self):
        self.assertIn("UMask=0027", section(read("edr-hub.service"), "Service"))
        for name in ("edr-hub-ui.service", "edr-hub-out.service", "edr-hub-failed.service", "edr-hub-backup.service"):
            self.assertIn("UMask=0077", section(read(name), "Service"), name)

    def test_no_private_users_and_no_binds_to(self):
        for name in UNITS:
            text = read(name)
            self.assertNotIn("PrivateUsers", text, name)           # SO_PEERCRED would report root as 65534
            self.assertNotIn("BindsTo", text, name)

    def test_every_program_starts_through_python_dash_i(self):
        for name, script in (("edr-hub.service", "edr_hub.py"), ("edr-hub-ui.service", "edr_hub_ui.py"),
                             ("edr-hub-out.service", "edr_hub_out.py"), ("edr-hub-failed.service", "edr_hub_out.py --failed-notice")):
            self.assertIn("ExecStart=/usr/bin/python3 -I /usr/local/lib/edr-hub/%s" % script, section(read(name), "Service"))
        for script in ("edr_hub.py", "edr_hub_out.py"):
            self.assertTrue(os.path.exists(os.path.join(HUB_DIR, "hub", script)), script)
        self.assertIn("ExecStart=/usr/local/sbin/edr-hub backup", section(read("edr-hub-backup.service"), "Service"))

    def test_edr_hub_column(self):
        text = read("edr-hub.service")
        svc, unit = section(text, "Service"), section(text, "Unit")
        for want in ("Type=notify", "WatchdogSec=60", "Restart=on-failure", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
                     "MemoryHigh=400M", "MemoryMax=512M", "TasksMax=200", "ReadWritePaths=/var/lib/edr-hub", "RuntimeDirectory=edr-hub",
                     "User=edr-hub"):
            self.assertIn(want, svc)
        self.assertIn("StartLimitBurst=5", unit)
        self.assertIn("StartLimitIntervalSec=300", unit)
        self.assertIn("After=edr-hub-nft.service network.target", unit)
        self.assertIn("OnFailure=edr-hub-failed.service", unit)

    def test_socket_steps_run_as_root_and_the_process_never_chowns(self):
        svc = section(read("edr-hub.service"), "Service")
        steps = [l for l in svc if l.startswith("ExecStartPre=") or l.startswith("ExecStartPost=")]
        self.assertTrue(steps)
        for l in steps:
            self.assertTrue(l.split("=", 1)[1].startswith("+"), l)           # the + prefix: not under the sandbox
        text = "\n".join(steps)
        for want in ("chmod 0711 /run/edr-hub", "chmod 0600 /run/edr-hub/ctl.sock", "chgrp edr-hub-ui /run/edr-hub/ui.sock",
                     "chmod 0660 /run/edr-hub/ui.sock", "chgrp edr-hub-out /run/edr-hub/out.sock", "chmod 0660 /run/edr-hub/out.sock"):
            self.assertIn(want, text)
        self.assertEqual([l for l in svc if l.startswith("ExecStartPre=")].__len__(), 1)
        self.assertTrue(all(l.split("=", 1)[1].startswith("+/usr/bin/") for l in steps))

    def test_runtime_directory_only_on_the_hub(self):
        for name in UNITS:
            has = any(l.startswith("RuntimeDirectory=") for l in section(read(name), "Service"))
            self.assertEqual(has, name == "edr-hub.service", name)

    def test_ui_column(self):
        text = read("edr-hub-ui.service")
        svc, unit = section(text, "Service"), section(text, "Unit")
        for want in ("Type=exec", "Restart=on-failure", "RestrictAddressFamilies=AF_INET AF_UNIX", "IPAddressDeny=any",
                     "IPAddressAllow=127.0.0.0/8", "MemoryMax=128M", "TasksMax=64", "ReadOnlyPaths=/var/lib/edr-hub",
                     "InaccessiblePaths=/var/lib/edr-hub/ca /var/lib/edr-hub/tls", "User=edr-hub-ui"):
            self.assertIn(want, svc)
        self.assertIn("Wants=edr-hub.service", unit)
        self.assertIn("After=edr-hub.service", unit)
        self.assertIn("OnFailure=edr-hub-failed.service", unit)

    def test_out_column_and_the_failed_unit_share_credential_and_state(self):
        for name in ("edr-hub-out.service", "edr-hub-failed.service"):
            svc = section(read(name), "Service")
            for want in ("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "LoadCredential=secrets.json:/etc/edr-hub/secrets.json",
                         "StateDirectory=edr-hub-out", "StateDirectoryMode=0700", "MemoryMax=128M", "TasksMax=64", "User=edr-hub-out"):
                self.assertIn(want, svc, name)
        out = read("edr-hub-out.service")
        self.assertIn("Wants=edr-hub.service", section(out, "Unit"))
        self.assertIn("After=edr-hub.service", section(out, "Unit"))
        self.assertIn("Type=exec", section(out, "Service"))
        self.assertIn("Type=oneshot", section(read("edr-hub-failed.service"), "Service"))

    def test_only_out_may_connect_out_and_nothing_else_loads_secrets(self):
        for name in UNITS:
            fam = [l for l in section(read(name), "Service") if l.startswith("RestrictAddressFamilies=")]
            if name in ("edr-hub-out.service", "edr-hub-failed.service", "edr-hub.service"):
                continue
            self.assertTrue(all("INET6" not in l for l in fam), name)
        for name in UNITS:
            has = any(l.startswith("LoadCredential=") for l in section(read(name), "Service"))
            self.assertEqual(has, name in ("edr-hub-out.service", "edr-hub-failed.service"), name)

    def test_on_failure_hooks(self):
        for name in ("edr-hub.service", "edr-hub-ui.service", "edr-hub-out.service"):
            self.assertIn("OnFailure=edr-hub-failed.service", section(read(name), "Unit"))
        failed = read("edr-hub-failed.service")
        self.assertFalse([l for l in section(failed, "Unit") + section(failed, "Service") if l.startswith("OnFailure")])   # no loop

    def test_backup_timer(self):
        timer = section(read("edr-hub-backup.timer"), "Timer")
        self.assertIn("OnCalendar=*-*-* 02:15:00 UTC", timer)
        self.assertIn("Persistent=yes", timer)
        self.assertIn("WantedBy=timers.target", section(read("edr-hub-backup.timer"), "Install"))
        r = run("systemd-analyze", "calendar", "*-*-* 02:15:00 UTC") if shutil.which("systemd-analyze") else None
        if r is not None:
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("02:15:00 UTC", r.stdout)

    def test_nft_service(self):
        text = read("edr-hub-nft.service")
        unit, svc = section(text, "Unit"), section(text, "Service")
        self.assertIn("Before=network-pre.target", unit)
        self.assertIn("Type=oneshot", svc)
        self.assertIn("RemainAfterExit=yes", svc)
        pre = [l for l in svc if l.startswith("ExecStartPre=")]
        start = [l for l in svc if l.startswith("ExecStart=")]
        self.assertEqual(pre, ["ExecStartPre=/usr/sbin/nft -c -f /etc/edr-hub/edr-hub.nft"])        # checked first
        self.assertEqual(start, ["ExecStart=/usr/sbin/nft -f /etc/edr-hub/edr-hub.nft"])
        self.assertTrue(text.index("ExecStartPre") < text.index("ExecStart=/usr/sbin/nft -f"))

    def test_journal_namespace_and_apt_files(self):
        j = read("journald@edr-hub.conf")
        self.assertIn("SystemMaxUse=150M", j)
        self.assertIn("RuntimeMaxUse=50M", j)
        self.assertIn("[Journal]", j)
        self.assertIn('Unattended-Upgrade::Automatic-Reboot "false";', read("52edr-hub"))


class ScriptLintTests(unittest.TestCase):
    SCRIPTS = (os.path.join(HUB_DIR, "check.sh"), os.path.join(FILES, "render-nft.sh"))

    def test_bash_n(self):
        for f in self.SCRIPTS:
            r = run("bash", "-n", f)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_shellcheck(self):
        if not shutil.which("shellcheck"):
            self.skipTest("shellcheck is not installed")
        for f in self.SCRIPTS:
            r = run("shellcheck", "-S", "warning", "-x", f)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_style(self):
        for f in self.SCRIPTS:
            with open(f) as fh:
                lines = fh.read().splitlines()
            self.assertEqual(lines[0], "#!/bin/bash")
            self.assertTrue(any(l.startswith("set -") and "pipefail" in l for l in lines), f)
            self.assertTrue(os.access(f, os.X_OK), f)


class CheckScriptTests(unittest.TestCase):
    """check.sh is never run here (it needs the installed hub); its static shape and its database report are tested."""

    def setUp(self):
        with open(os.path.join(HUB_DIR, "check.sh")) as f:
            self.text = f.read()

    def test_never_dumps_the_whole_ruleset_or_uses_the_sqlite_cli(self):
        self.assertNotRegex(self.text, r"nft\s+list\s+ruleset")
        self.assertIn("nft -t list table inet edr_hub", self.text)
        self.assertNotRegex(self.text, r"(^|[\s;|(])sqlite3\s+-|(^|[\s;|(])sqlite3\s+/")
        self.assertIn("mode=ro", self.text)
        self.assertIn("python3 -I", self.text)

    def test_it_is_read_only(self):
        for bad in (r"\bsystemctl\s+(start|stop|restart|enable|disable|daemon-reload|reload|mask|kill)\b", r"\bnft\s+(add|delete|flush|-f)\b",
                    r"\brm\s", r"\bchmod\s", r"\bchown\s", r"\bsed\s+-i\b", r"\btee\b", r"\bapt(-get)?\b"):
            self.assertNotRegex(self.text, bad)
        self.assertNotRegex(self.text, r"[^2]>\s*/(etc|var|usr|run)/")

    def test_every_item_of_the_plan_is_checked(self):
        for needle in ("edr-hub", "edr-hub-out", "edr-hub-ui", "edr-hub-nft.service", "edr-hub-backup.timer",
                       "edr-hub-fw-rollback", "health", "checkend", "auto_vacuum", "WAL", "backup", "silent", "inet edr_hub"):
            self.assertIn(needle, self.text)

    def test_exit_codes(self):
        self.assertIn("exit 64", self.text)
        self.assertIn("exit 2", self.text)
        self.assertIn("exit 1", self.text)
        self.assertTrue(self.text.rstrip().endswith("exit 0"))

    def test_usage_error_exits_64_without_touching_anything(self):
        # Option parsing comes first; an unknown option never reaches a check
        r = run("bash", os.path.join(HUB_DIR, "check.sh"), "--no-such-option")
        self.assertEqual(r.returncode, 64)
        self.assertIn("Unknown option", r.stderr)
        r = run("bash", os.path.join(HUB_DIR, "check.sh"), "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("usage", r.stdout)

    def report_script(self):
        m = re.search(r"python3 -I - \"\$STATE\" \"\$LIB\" <<'PY'\n(.*?)\nPY\n", self.text, re.S)
        self.assertTrue(m, "the database report script was not found in check.sh")
        return m.group(1)

    def test_database_report(self):
        tmp = tempfile.mkdtemp(prefix="edr-check-")
        self.addCleanup(shutil.rmtree, tmp, True)
        state, lib = os.path.join(tmp, "state"), os.path.join(tmp, "lib")
        os.makedirs(state)
        os.makedirs(lib)
        with open(os.path.join(state, "settings.json"), "w") as f:
            f.write('{"port": 18443, "enroll_port": 18444, "ui_port": 18450, "public_ip": ["203.0.113.5"], "max_db_size": "64M"}')
        with open(os.path.join(lib, "advisories.json"), "w") as f:
            f.write('{"updated": "2026-11-19", "rows": []}')
        conn = sqlite3.connect(os.path.join(state, "hub.db"))
        conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
        conn.executescript(hub_schema.DDL)
        now = int(__import__("time").time() * 1000)
        for name, st, last in (("web1", "active", now - 3600_000), ("web2", "active", now - 1000), ("new1", "pending", None)):
            conn.execute("INSERT INTO hosts (uuid, name, droplet_id, state, state_since, enrolled_at, last_seen) VALUES (?,?,?,?,?,?,?)",
                         ("u-" + name, name, "d", st, now, now - 2 * 3600_000, last))
        conn.execute("INSERT INTO incidents (host, chain, opened, updated, severity, title) VALUES ('u-web1','exploit',1,1,'CRITICAL','t')")
        conn.execute("INSERT INTO outbox (created, channel, severity, payload, attempts, next_try, state) VALUES (?,?,?,?,?,?,?)",
                     (now, "webhook", "HIGH", "{}", 3, now, "dead"))
        conn.execute("INSERT INTO meta (key, value) VALUES ('last_backup', ?)", (str(now - 3 * 86400 * 1000),))
        conn.execute("INSERT INTO meta (key, value) VALUES ('engine_tick', ?)", (str(now),))
        conn.commit()
        conn.close()
        r = subprocess.run([sys.executable, "-I", "-", state, lib], input=self.report_script(), capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        got = {}
        for line in r.stdout.splitlines():
            k, _, v = line.partition("=")
            got.setdefault(k, []).append(v)
        self.assertEqual(got["port"], ["18443"])
        self.assertEqual(got["ui_port"], ["18450"])
        self.assertEqual(got["public_ip"], ["203.0.113.5"])
        self.assertEqual(got["cap"], [str(64 * 1024 * 1024)])
        self.assertEqual(got["auto_vacuum"], ["2"])
        self.assertEqual(got["advisory_updated"], ["2026-11-19"])
        self.assertEqual(got["hosts_active"], ["2"])
        self.assertEqual(len(got["down"]), 1)
        self.assertTrue(got["down"][0].startswith("web1|"))
        self.assertEqual(got["pending_silent"], ["new1"])
        self.assertEqual(got["open_critical"], ["1"])
        self.assertEqual(got["outbox_bad"], ["webhook|1"])
        self.assertTrue(2 * 86400 <= int(got["backup_age_s"][0]) <= 4 * 86400)
        self.assertNotIn("db_error", got)
        # a missing database is reported, not a traceback
        os.unlink(os.path.join(state, "hub.db"))
        r = subprocess.run([sys.executable, "-I", "-", state, lib], input=self.report_script(), capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("db_error=", r.stdout)


class RenderTests(unittest.TestCase):
    RENDER = os.path.join(FILES, "render-nft.sh")

    def render(self, *args):
        return run("bash", self.RENDER, *args)

    def hub_user(self):
        """The user the loaded rule names: edr-hub if this machine has it, else one that resolves."""
        return "edr-hub" if run("getent", "passwd", "edr-hub").returncode == 0 else "nobody"

    def load_check(self, text, twice=False):
        if os.geteuid() != 0 or not shutil.which("nft") or not shutil.which("unshare"):
            self.skipTest("needs root, nft and unshare")
        tmp = tempfile.mkdtemp(prefix="edr-nft-")
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "edr-hub.nft")
        with open(path, "w") as f:
            f.write(text)
        r = run("unshare", "-n", "nft", "-c", "-f", path)
        self.assertEqual(r.returncode, 0, r.stderr + "\n" + text)
        return path

    def test_default_render_names_the_ingest_user_and_the_default_shape(self):
        r = self.render("--port", "8443", "--enroll-port", "8444", "--ssh-port", "22")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        body = [l for l in out.splitlines() if l.strip() and not l.strip().startswith("#")]
        self.assertEqual(body[0], "table inet edr_hub")
        self.assertEqual(body[1], "delete table inet edr_hub")
        self.assertIn('meta skuid "edr-hub" ct state new drop', out)
        self.assertIn("policy drop;", out)
        self.assertIn("tcp dport { 8443, 8444 } accept", out)
        self.assertIn("ip6 saddr & ffff:ffff:ffff:ffff::", out)                # IPv6 meter keyed by /64
        self.assertIn("add @synmeter4 { ip saddr limit rate over 5/second burst 10 packets }", out)
        self.assertNotRegex("\n".join(body), r"@[A-Z0-9_]+@")

    def test_no_admin_opens_ssh_with_one_line(self):
        out = self.render("--port", "8443", "--enroll-port", "8444", "--ssh-port", "22", "--hub-user", self.hub_user()).stdout
        body = [l.strip() for l in out.splitlines() if l.strip() and not l.strip().startswith("#")]
        self.assertIn("tcp dport 22 accept", body)
        self.assertFalse([l for l in body if "@admin" in l])
        self.assertFalse([l for l in body if "elements" in l])
        self.load_check(out)

    def test_ipv4_and_ipv6_admins(self):
        out = self.render("--port", "8443", "--enroll-port", "8444", "--ssh-port", "22", "--admin4", "203.0.113.5/32,198.51.100.0/24",
                          "--admin6", "2001:db8::/32,2001:db8:1::5", "--hub-user", self.hub_user()).stdout
        self.assertIn("elements = { 203.0.113.5/32, 198.51.100.0/24 }", out)
        self.assertIn("elements = { 2001:db8::/32, 2001:db8:1::5 }", out)
        self.assertIn("ip saddr @admin4 tcp dport 22 accept", out)
        self.assertIn("ip6 saddr @admin6 tcp dport 22 accept", out)
        self.assertNotIn("\n        tcp dport 22 accept", out)                 # not open to everyone
        self.load_check(out)

    def test_one_family_of_admins_still_closes_ssh(self):
        out = self.render("--port", "8443", "--enroll-port", "8444", "--ssh-port", "22", "--admin4", "203.0.113.5", "--hub-user", self.hub_user()).stdout
        self.assertIn("ip saddr @admin4 tcp dport 22 accept", out)
        self.assertNotIn("\n        tcp dport 22 accept", out)
        self.load_check(out)

    def test_non_default_ports(self):
        out = self.render("--port", "18443", "--enroll-port", "18444", "--ssh-port", "2222", "--admin4", "192.0.2.1", "--hub-user", self.hub_user()).stdout
        self.assertIn("tcp dport { 18443, 18444 } accept", out)
        self.assertIn("ip saddr @admin4 tcp dport 2222 accept", out)
        self.assertNotIn("8443,", out.replace("18443,", ""))
        self.assertNotIn("dport 22 ", out)
        self.load_check(out)

    def test_loading_twice_replaces_the_table(self):
        out = self.render("--port", "8443", "--enroll-port", "8444", "--ssh-port", "22", "--admin4", "192.0.2.1", "--hub-user", self.hub_user()).stdout
        path = self.load_check(out)
        r = run("unshare", "-n", "bash", "-c", 'nft -f "$1" && nft -f "$1" && nft -t list table inet edr_hub', "_", path)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.count("chain input"), 1)
        self.assertEqual(r.stdout.count("policy drop"), 1)

    def test_template_is_documented_and_marked(self):
        text = read("edr-hub.nft.in")
        head = text.split("table inet edr_hub")[0]
        for ph in ("@PORT@", "@ENROLL_PORT@", "@SSH_PORT@", "@ADMIN4_ELEMENTS@", "@ADMIN6_ELEMENTS@", "@HUB_USER@"):
            self.assertIn(ph, head, "%s is not documented at the top" % ph)
            self.assertIn(ph, text)
        self.assertIn("# BEGIN ssh-admin", text)
        self.assertIn("# END ssh-admin", text)
        body = [l for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
        self.assertEqual(body[:2], ["table inet edr_hub", "delete table inet edr_hub"])
        for want in ("synmeter4", "synmeter6", "set admin4", "set admin6", "hook input priority -10; policy drop;", "iif lo accept",
                     "ct state invalid drop", "ct state established,related accept", "limit rate 5/second", "udp sport 67 udp dport 68 accept",
                     "ct state new drop"):
            self.assertIn(want, text)

    def test_bad_arguments_are_refused_with_64_and_never_reach_the_file(self):
        base = ["--port", "8443", "--enroll-port", "8444", "--ssh-port", "22"]
        bad = [base + ["--admin4", "1.2.3.4; flush ruleset"], base + ["--admin6", "::1\naccept"], base + ["--admin4", "1.2.3.4,,"],
               ["--port", "0", "--enroll-port", "8444", "--ssh-port", "22"], ["--port", "8443", "--enroll-port", "99999", "--ssh-port", "22"],
               ["--port", "x", "--enroll-port", "8444", "--ssh-port", "22"], ["--port", "8443", "--enroll-port", "8443", "--ssh-port", "22"],
               base + ["--hub-user", 'x" accept #'], base + ["--bogus", "1"], ["--port", "8443"], [], base + ["--template", "/nonexistent"],
               base + ["--admin4"]]
        for args in bad:
            r = self.render(*args)
            self.assertEqual(r.returncode, 64, "%r -> %d %s" % (args, r.returncode, r.stdout[:80]))
            self.assertEqual(r.stdout, "", args)


if __name__ == "__main__":
    unittest.main()
