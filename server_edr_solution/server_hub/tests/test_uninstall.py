"""uninstall.sh: syntax, shellcheck, and --plan (the only mode ever run here; PLAN section 9)."""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.normpath(os.path.join(HERE, "..", "uninstall.sh"))
ENV_KEYS = ("EDR_HUB_STATE_DIR", "EDR_HUB_RUN_DIR", "EDR_HUB_ETC_DIR", "EDR_HUB_BACKUP_DIR", "EDR_HUB_OUT_STATE_DIR")
A, B = "a" * 64, "b" * 64
STUBS = ("systemctl", "nft", "rm", "rmdir", "userdel", "groupdel", "cp", "mv", "apt-get", "dpkg", "ss", "pgrep", "chmod")


def tree_hash(root):
    h = hashlib.sha256()
    for base, dirs, files in sorted(os.walk(root)):
        dirs.sort()
        h.update(base.encode())
        for name in sorted(files):
            p = os.path.join(base, name)
            h.update(p.encode())
            if os.path.islink(p):
                h.update(os.readlink(p).encode())
            else:
                with open(p, "rb") as f:
                    h.update(f.read())
                h.update(str(stat.S_IMODE(os.stat(p).st_mode)).encode())
    return h.hexdigest()


class PlanCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="edrhub-un-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.dirs = {}
        for key, name in zip(ENV_KEYS, ("state", "run", "etc", "backups", "out")):
            self.dirs[key] = os.path.join(self.root, name)
            os.makedirs(self.dirs[key])
        self.etc = self.dirs["EDR_HUB_ETC_DIR"]
        self.stubs = os.path.join(self.root, "stubs")
        self.calls = os.path.join(self.root, "calls.log")
        os.makedirs(self.stubs)
        for name in STUBS:
            p = os.path.join(self.stubs, name)
            with open(p, "w") as f:
                f.write('#!/bin/sh\necho "%s $*" >> "%s"\nexit 0\n' % (name, self.calls))
            os.chmod(p, 0o755)

    def manifest(self, *items):
        with open(os.path.join(self.etc, "manifest.jsonl"), "w") as f:
            for item in items:
                f.write((item if isinstance(item, str) else json.dumps(item)) + "\n")

    def write(self, name, text):
        p = os.path.join(self.etc, name)
        with open(p, "w") as f:
            f.write(text)
        return p

    def plan(self, *args, stubs=True):
        env = {k: v for k, v in os.environ.items() if k not in ENV_KEYS}
        env.update(self.dirs)
        if stubs:
            env["PATH"] = self.stubs + ":" + os.environ.get("PATH", "/usr/bin:/bin")
        r = subprocess.run(["bash", SCRIPT, "--plan", *args], capture_output=True, text=True, env=env, timeout=60)
        return r

    def called(self):
        try:
            with open(self.calls) as f:
                return f.read()
        except FileNotFoundError:
            return ""


class SyntaxTests(unittest.TestCase):
    def test_bash_n(self):
        r = subprocess.run(["bash", "-n", SCRIPT], capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stderr), (0, ""))

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck is not installed")
    def test_shellcheck(self):
        r = subprocess.run(["shellcheck", "-S", "warning", "-x", SCRIPT], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_shebang_and_mode(self):
        with open(SCRIPT) as f:
            self.assertEqual(f.readline().strip(), "#!/bin/bash")
        self.assertTrue(os.stat(SCRIPT).st_mode & stat.S_IXUSR)

    def test_it_never_flushes_nftables_or_removes_packages(self):
        with open(SCRIPT) as f:
            text = f.read()
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        for line in code.splitlines():
            if re.search(r"(?<![-\w])nft(?![-\w.])", line) and "echo" not in line and "say" not in line:
                self.assertRegex(line, r"nft (list table inet edr_hub|delete table inet edr_hub|-V|list)|command -v nft", line)
        self.assertNotRegex(code, r"nft\s+flush|flush ruleset|delete ruleset|nft\s+-f")
        self.assertNotRegex(code, r"apt(-get)?\s+(remove|purge|autoremove)|dpkg\s+(-r|-P|--remove|--purge)")
        self.assertNotRegex(code, r"\beval\b|\bsed -i\b")

    def test_plan_exits_before_anything_that_changes_state(self):
        with open(SCRIPT) as f:
            text = f.read()
        start = text.index("plan() {")
        end = text.index("if [[ $PLAN -eq 1 ]]")
        body = text[start:end]
        self.assertNotRegex(body, r"(?m)^\s*(rm|rmdir|systemctl|nft|userdel|groupdel|cp|mv|chmod|chown|tee|mkdir|touch)\s")
        self.assertNotRegex(body, r">\s*\"?\$")                            # no redirection into a file
        gate = text[end:end + 80]
        self.assertIn("exit $?", gate)
        first_change = min(text.index(marker) for marker in ("systemctl disable", "rm -f", "rm -rf", "nft delete", "userdel", "EUID"))
        self.assertGreater(first_change, end)


class PlanTests(PlanCase):
    def test_usage_errors_exit_64(self):
        for args in (["--bogus"], ["--plan", "extra"], ["yes"], ["--yes", "-x"]):
            env = {k: v for k, v in os.environ.items() if k not in ENV_KEYS}
            env.update(self.dirs)
            r = subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(r.returncode, 64, args)
            self.assertIn("usage:", r.stderr)
        self.assertEqual(self.called(), "")

    def test_help_exits_0(self):
        env = dict(os.environ, **self.dirs)
        r = subprocess.run(["bash", SCRIPT, "--help"], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0)

    def test_plan_prints_every_step_in_the_order_of_section_9(self):
        self.manifest()
        r = self.plan()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        steps = [m.start() for m in (re.search(p, r.stdout) for p in (
            r"Step 1: final backup", r"Step 2: stop and disable", r"Step 3: the firewall table", r"Step 4: replay",
            r"Step 5: kept", r"Final checks"))]
        self.assertEqual(steps, sorted(steps))
        self.assertIn("delete only 'table inet edr_hub'", r.stdout)
        self.assertIn("edr-hub-fw-rollback", r.stdout)
        self.assertIn("edr-hub-install", r.stdout)
        for word in ("edr-hub-backup.timer", "edr-hub-ui, edr-hub-out, edr-hub", "edr-hub-clients.timer", "secrets.json", "backup.pass"):
            self.assertIn(word, r.stdout)

    def test_plan_replays_the_manifest_last_entry_first(self):
        etc_nft = self.write("edr-hub.nft", "table\n")
        self.manifest(
            {"ts": 1, "kind": "user", "path": "edr-hub", "prior": "absent"},
            {"ts": 2, "kind": "dir", "path": "/usr/local/lib/edr-hub", "prior": "absent"},
            {"ts": 3, "kind": "file", "path": "/etc/systemd/system/edr-hub.service", "prior": "absent", "sha256": A},
            {"ts": 4, "kind": "file", "path": etc_nft, "prior": "absent", "sha256": hashlib.sha256(b"table\n").hexdigest()},
            {"ts": 5, "kind": "unit", "path": "edr-hub.service", "prior": "absent"},
            {"ts": 6, "kind": "link", "path": "/usr/local/sbin/edr-hub", "prior": "absent"},
            {"ts": 7, "kind": "package", "path": "unattended-upgrades", "prior": "present"})
        r = self.plan()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        body = r.stdout.split("Step 4")[1].split("Step 5")[0]
        order = [body.index(x) for x in ("unattended-upgrades", "/usr/local/sbin/edr-hub", "unit edr-hub.service",
                                         etc_nft, "/etc/systemd/system/edr-hub.service", "/usr/local/lib/edr-hub", "user edr-hub")]
        self.assertEqual(order, sorted(order), body)
        self.assertIn("remove %s" % etc_nft, body)
        self.assertIn("leave package unattended-upgrades installed (no package is ever removed)", body)
        self.assertIn("keep user edr-hub", body)

    def test_the_first_prior_and_the_last_hash_decide(self):
        p = self.write("a.conf", "now\n")
        saved = os.path.join(self.etc, "prior", "a.conf")
        os.makedirs(os.path.dirname(saved))
        with open(saved, "w") as f:
            f.write("before\n")
        now = hashlib.sha256(b"now\n").hexdigest()
        self.manifest(
            {"ts": 1, "kind": "file", "path": p, "prior": {"saved": saved}, "sha256": A},       # first line: go back to the saved copy
            {"ts": 2, "kind": "file", "path": p, "prior": "absent", "sha256": now})              # a re-run: hash of what the kit wrote
        out = self.plan().stdout
        self.assertIn("put the saved prior copy back at %s" % p, out)
        self.assertNotIn("changed since install", out)

    def test_no_disable_call_names_more_than_one_unit(self):
        """systemd 255 (Ubuntu 24.04) does nothing for `systemctl disable --now A B` when one unit file is missing."""
        seen = 0
        for script in (SCRIPT, os.path.join(os.path.dirname(SCRIPT), "install.sh")):
            with open(script) as f:
                for no, line in enumerate(f, 1):
                    code = line.strip()
                    if code.startswith(("#", "echo", "say ")) or "UNIT_OFF) echo" in code:
                        continue
                    for m in re.finditer(r"systemctl\s+disable\s+([^;&|<>)\n]*)", code):
                        words = [w for w in m.group(1).split() if not w.startswith("-") and w != "2"]
                        seen += 1
                        self.assertLessEqual(len(words), 1, "%s:%d names %d units: %s" % (os.path.basename(script), no, len(words), code))
        self.assertGreaterEqual(seen, 4)

    def test_the_final_unit_list_ignores_the_bullet_list_units_prints_without_plain(self):
        with open(SCRIPT) as f:
            statement = re.search(r"^units=\$\(\{.*?\)$", f.read(), re.S | re.M).group(0)
        harness = os.path.join(self.root, "list.sh")
        with open(harness, "w") as f:
            f.write('''systemctl() {
    case $1 in
        list-unit-files) ;;
        list-units) if [[ " $* " == *" --plain "* ]]; then echo "edr-hub-ui.service loaded failed failed UI"; else echo "● edr-hub-ui.service loaded failed failed UI"; fi ;;
    esac
}
%s
echo "LIST=[$units]"
''' % statement)
        r = subprocess.run(["bash", harness], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("LIST=[edr-hub-ui.service]", r.stdout)

    def test_the_first_prior_of_a_directory_decides_too(self):
        """A second install records a directory the kit made as present (it is there); the first line still says absent."""
        made, found = os.path.join(self.etc, "d"), os.path.join(self.etc, "e")
        os.makedirs(made)
        os.makedirs(found)
        self.manifest({"ts": 1, "kind": "dir", "path": made, "prior": "absent"},
                      {"ts": 2, "kind": "dir", "path": found, "prior": "present"},
                      {"ts": 3, "kind": "dir", "path": made, "prior": "present"},
                      {"ts": 4, "kind": "dir", "path": found, "prior": "absent"})
        out = self.plan().stdout
        self.assertIn("remove directory %s if it is empty" % made, out)
        self.assertNotIn("leave %s: it existed" % made, out)
        self.assertIn("leave %s: it existed before the kit" % found, out)

    def test_an_edited_file_is_reported_and_removed_only_when_the_prior_is_absent(self):
        edited = self.write("edited.conf", "operator changed me\n")
        keep = self.write("keep.conf", "operator changed me too\n")
        saved = os.path.join(self.etc, "prior", "keep.conf")
        os.makedirs(os.path.dirname(saved))
        with open(saved, "w") as f:
            f.write("original\n")
        self.manifest({"kind": "file", "path": edited, "prior": "absent", "sha256": A},
                      {"kind": "file", "path": keep, "prior": {"saved": saved}, "sha256": B})
        out = self.plan().stdout
        self.assertIn("remove %s (changed since install" % edited, out)
        self.assertIn("leave %s: changed since install and a prior copy exists" % keep, out)

    def test_present_gone_and_not_a_file(self):
        present = self.write("p.conf", "x\n")
        self.manifest(
            {"kind": "file", "path": present, "prior": "present", "sha256": hashlib.sha256(b"x\n").hexdigest()},
            {"kind": "file", "path": os.path.join(self.etc, "missing.conf"), "prior": "absent", "sha256": A},
            {"kind": "dir", "path": os.path.join(self.etc, "d"), "prior": "absent"},
            {"kind": "user", "path": "edr-hub-ui", "prior": "present"},
            {"kind": "group", "path": "edr-hub-out", "prior": "absent"})
        os.makedirs(os.path.join(self.etc, "d"))
        out = self.plan().stdout
        self.assertIn("leave %s: it existed before the kit" % present, out)
        self.assertIn("missing.conf is already gone", out)
        self.assertIn("remove directory %s if it is empty" % os.path.join(self.etc, "d"), out)
        self.assertIn("leave edr-hub-ui: it existed before the kit", out)
        self.assertIn("keep group edr-hub-out", out)

    def test_paths_outside_the_owned_directories_are_refused(self):
        bad = ["/etc/passwd", "/usr/local/lib/edr-hub/../../../etc/passwd", "/usr/local/lib/edr-hubx", "/etc/edr-hub-other/x",
               "/etc/systemd/system/other.service", "/etc/systemd/system", "/usr/local/sbin/other", "relative/path",
               "/usr/local/lib/edr-hub/a b", "/var/lib/edr-hub/hub.db", "/etc/apt/apt.conf.d/50other",
               self.etc + "/../escape", "/usr/local/lib/edr-hub/", "//etc/passwd", "/usr/local/lib/edr-hub/./x"]
        for path in bad:
            self.manifest({"kind": "file", "path": path, "prior": "absent", "sha256": A})
            r = self.plan()
            self.assertEqual(r.returncode, 3, path)
            self.assertIn("REFUSE line 1: path outside the directories the kit owns", r.stdout, path)
            self.assertIn("stops before changing anything", r.stdout)
        self.assertEqual(self.called(), "")

    def test_owned_paths_are_accepted(self):
        good = ["/etc/systemd/system/edr-hub.service", "/etc/systemd/system/edr-hub-nft.service", "/etc/systemd/system/edr-hub.service.d/x.conf",
                "/etc/systemd/journald@edr-hub.conf", "/etc/apt/apt.conf.d/52edr-hub", "/usr/local/lib/edr-hub",
                "/usr/local/lib/edr-hub.prev", "/usr/local/lib/edr-hub/edr_hub.py", "/usr/local/sbin/edr-hub", self.etc + "/prior/x"]
        self.manifest(*[{"kind": "file", "path": p, "prior": "absent", "sha256": A} for p in good])
        r = self.plan()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertNotIn("REFUSE", r.stdout)

    def test_other_bad_lines_are_refused(self):
        lines = [
            "not json at all",
            json.dumps({"kind": "file", "path": "/usr/local/sbin/edr-hub"}),
            json.dumps({"kind": "weird", "path": "/usr/local/sbin/edr-hub", "prior": "absent"}),
            json.dumps({"kind": "file", "path": "/usr/local/sbin/edr-hub", "prior": "maybe"}),
            json.dumps({"kind": "file", "path": "/usr/local/sbin/edr-hub", "prior": {"saved": "/etc/shadow"}}),
            json.dumps({"kind": "file", "path": "/usr/local/sbin/edr-hub", "prior": {"saved": self.etc + "/prior/x", "extra": 1}}),
            json.dumps({"kind": "user", "path": "root", "prior": "absent"}),
            json.dumps({"kind": "group", "path": "sudo", "prior": "absent"}),
            json.dumps({"kind": "unit", "path": "ssh.service", "prior": "absent"}),
            json.dumps({"kind": "unit", "path": "edr-hub.service; rm -rf /", "prior": "absent"}),
            json.dumps({"kind": "file", "path": "/etc/systemd/system/edr-hub.service\nrm -rf /", "prior": "absent"}),
            json.dumps({"kind": "file", "path": 5, "prior": "absent"}),
            json.dumps(["a"]),
            json.dumps({"kind": "file", "path": "/usr/local/sbin/edr-hub", "prior": "absent", "pad": "x" * 5000}),
        ]
        self.manifest(*lines)
        r = self.plan()
        self.assertEqual(r.returncode, 3)
        self.assertEqual(len(re.findall(r"REFUSE line", r.stdout)), len(lines), r.stdout)
        self.assertNotRegex(r.stdout, r"[\x00-\x08\x0b-\x1f\x7f]")                 # a bad field is printed cleaned, never raw
        self.assertEqual(self.called(), "")

    def test_a_good_line_among_bad_ones_does_not_hide_the_refusal(self):
        self.manifest({"kind": "file", "path": "/usr/local/sbin/edr-hub", "prior": "absent"},
                      {"kind": "file", "path": "/etc/passwd", "prior": "absent"})
        r = self.plan()
        self.assertEqual(r.returncode, 3)
        self.assertIn("REFUSE line 2", r.stdout)
        self.assertRegex(r.stdout, r"remove /usr/local/sbin/edr-hub|/usr/local/sbin/edr-hub is already gone")

    def test_no_manifest_and_no_database(self):
        r = self.plan()
        self.assertEqual(r.returncode, 0)
        self.assertIn("there is no manifest", r.stdout)
        self.assertIn("no final backup", r.stdout)

    def test_with_a_database_it_plans_the_final_backup(self):
        with open(os.path.join(self.dirs["EDR_HUB_STATE_DIR"], "hub.db"), "w") as f:
            f.write("x")
        self.assertIn("/usr/local/sbin/edr-hub backup", self.plan().stdout)

    def test_ports_come_from_settings(self):
        with open(os.path.join(self.dirs["EDR_HUB_STATE_DIR"], "settings.json"), "w") as f:
            json.dump({"port": 9443, "enroll_port": 9444, "ui_port": 9450}, f)
        self.assertIn("ports 9443, 9444 and 9450", self.plan().stdout)
        with open(os.path.join(self.dirs["EDR_HUB_STATE_DIR"], "settings.json"), "w") as f:
            f.write("{broken")
        self.assertIn("ports 8443, 8444 and 8450", self.plan().stdout)

    def test_yes_never_answers_a_purge_question_and_purge_needs_a_terminal(self):
        with open(SCRIPT) as f:
            text = f.read()
        func = re.search(r"^confirm\(\) \{.*?^\}", text, re.S | re.M).group(0)
        for prompt, answer, expect_yes in (("Continue?", "y", True), ("Type 'purge'", "purge", False), ("Last chance", "delete everything", False)):
            r = subprocess.run(["bash", "-c", "ASSUME_YES=1\n%s\nconfirm \"%s\" \"%s\"" % (func, prompt, answer)], capture_output=True,
                               text=True, stdin=subprocess.DEVNULL, timeout=20)
            self.assertEqual(r.returncode == 0, expect_yes, prompt)
        gate = text.index("[[ $PURGE -eq 1 && ! -t 0 ]]")
        self.assertLess(gate, text.rindex('say "Step 1: final backup"'))
        self.assertIn("exit 3", text[gate:gate + 400])

    def test_the_mock_never_uses_purge(self):
        mock = os.path.join(os.path.dirname(SCRIPT), "..", "mock", "mock.sh")
        with open(mock) as f:
            self.assertNotIn("--purge", f.read().replace("MOCK_", ""))

    def test_purge_plan_has_the_three_warnings_in_order_and_asks_twice(self):
        self.manifest()
        out = self.plan("--purge").stdout
        i = [out.index(w) for w in ("the CA key is deleted", "every enrolled client", "the backups are deleted too")]
        self.assertEqual(i, sorted(i))
        self.assertIn("ask twice", out)
        self.assertIn("edr-hub ca-export", out)

    def test_plan_changes_nothing_and_calls_no_command_that_could(self):
        self.write("secrets.json", "{}")
        self.write("backup.pass", "pw\n")
        self.write("edr-hub.nft", "x\n")
        with open(os.path.join(self.dirs["EDR_HUB_STATE_DIR"], "hub.db"), "w") as f:
            f.write("db")
        os.makedirs(os.path.join(self.etc, "prior"))
        self.manifest({"kind": "file", "path": os.path.join(self.etc, "edr-hub.nft"), "prior": "absent", "sha256": A},
                      {"kind": "dir", "path": os.path.join(self.etc, "prior"), "prior": "absent"},
                      {"kind": "unit", "path": "edr-hub.service", "prior": "absent"},
                      {"kind": "file", "path": "/etc/passwd", "prior": "absent"})
        for extra in ([], ["--purge"], ["--yes"], ["--purge", "--yes"]):
            before = tree_hash(self.root)
            r = self.plan(*extra)
            self.assertIn(r.returncode, (0, 3))
            after = tree_hash(self.root)
            self.assertEqual(before, after, extra)
            self.assertEqual(self.called(), "", extra)                     # no systemctl, nft, rm, userdel ... was started
        self.assertTrue(os.path.exists(os.path.join(self.dirs["EDR_HUB_STATE_DIR"], "hub.db")))

    def test_plan_needs_no_root_and_stubs_are_not_needed(self):
        self.manifest()
        r = self.plan(stubs=False)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_system_directories_are_refused_as_paths_to_work_on(self):
        for key in ENV_KEYS:
            for bad in ("/", "/etc", "/var/lib", "/usr/local", "/tmp", "/home", "/etc/systemd/system", "relative", "/x/../etc", "/tmp/a b"):
                env = {k: v for k, v in os.environ.items() if k not in ENV_KEYS}
                env.update(self.dirs)
                env[key] = bad
                r = subprocess.run(["bash", SCRIPT, "--plan"], capture_output=True, text=True, env=env, timeout=30)
                self.assertEqual(r.returncode, 3, (key, bad))
                self.assertIn("Refusing", r.stderr)


if __name__ == "__main__":
    unittest.main()
