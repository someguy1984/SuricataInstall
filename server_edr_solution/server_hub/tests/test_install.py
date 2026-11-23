"""install.sh: syntax, shellcheck, usage errors, --plan (the only way it is ever run here) and the manifest it writes
(PLAN.md sections 8, 14 and 17). Nothing here runs a real install: --plan runs with stub commands first on PATH and
must leave their log empty, and the step functions are sourced with run() replaced by a logger."""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HUB = os.path.normpath(os.path.join(HERE, ".."))
SCRIPT = os.path.join(HUB, "install.sh")
UNINSTALL = os.path.join(HUB, "uninstall.sh")
ENV_KEYS = ("EDR_HUB_STATE_DIR", "EDR_HUB_RUN_DIR", "EDR_HUB_ETC_DIR", "EDR_HUB_BACKUP_DIR", "EDR_HUB_OUT_STATE_DIR",
            "EDR_HUB_OS_RELEASE", "EDR_HUB_DF_BYTES", "SSH_CONNECTION", "SSH_CLIENT", "SUDO_USER", "EDR_HUB_IN_UNIT")
# commands that change the system: stubbed, and their log must stay empty during --plan
MUTATORS = ("systemctl", "nft", "useradd", "groupadd", "userdel", "groupdel", "apt-get", "runuser", "setpriv", "systemd-run",
            "chown", "chgrp", "chmod", "install", "cp", "mv", "ln", "mkdir", "tee", "ufw-allow")
# read-only commands with a canned answer, so the plan does not depend on the machine it runs on
CANNED = {
    "timedatectl": 'echo yes',
    "sshd": 'echo "port 2222"',
    "ip": 'echo "2: eth0    inet 203.0.113.10/24 brd 203.0.113.255 scope global eth0"; '
          'echo "2: eth0    inet 10.0.0.5/16 brd 10.0.255.255 scope global eth0"; '
          'echo "3: docker0    inet 172.17.0.1/16 scope global docker0"',
    "ufw": 'echo "Status: inactive"',
    "passwd": 'echo "j P 2026-01-01 0 99999 7 -1"',
}
OS_OK = 'ID=ubuntu\nVERSION_ID="24.04"\n'


def tree_hash(root):
    h = hashlib.sha256()
    for base, dirs, files in sorted(os.walk(root)):
        dirs.sort()
        h.update(base.encode())
        for name in sorted(files):
            p = os.path.join(base, name)
            h.update(p.encode())
            with open(p, "rb") as f:
                h.update(f.read())
    return h.hexdigest()


def code_lines(text):
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


class InstallCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="hubinst-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.dirs = {}
        for key, name in zip(ENV_KEYS[:5], ("state", "run", "etc", "backups", "out")):
            self.dirs[key] = os.path.join(self.root, name)
            os.makedirs(self.dirs[key])
        self.etc = self.dirs["EDR_HUB_ETC_DIR"]
        self.state = self.dirs["EDR_HUB_STATE_DIR"]
        self.stubs = os.path.join(self.root, "stubs")
        self.calls = os.path.join(self.root, "calls.log")
        os.makedirs(self.stubs)
        for name in MUTATORS:
            self.stub(name, "")
        for name, body in CANNED.items():
            self.stub(name, body, log=False)
        self.os_release = os.path.join(self.root, "os-release")
        with open(self.os_release, "w") as f:
            f.write(OS_OK)

    def stub(self, name, body, log=True):
        p = os.path.join(self.stubs, name)
        with open(p, "w") as f:
            f.write('#!/bin/sh\n%s%s\nexit 0\n' % ('echo "%s $*" >> "%s"\n' % (name, self.calls) if log else "", body))
        os.chmod(p, 0o755)

    def env(self, **extra):
        env = {k: v for k, v in os.environ.items() if k not in ENV_KEYS}
        env.update(self.dirs)
        env["EDR_HUB_OS_RELEASE"] = self.os_release
        env["EDR_HUB_DF_BYTES"] = str(500 * 1024 ** 3)
        env["PATH"] = self.stubs + ":" + os.environ.get("PATH", "/usr/bin:/bin")
        env.update(extra)
        return env

    def run_script(self, *args, script=SCRIPT, env=None, timeout=120):
        return subprocess.run(["bash", script, *args], capture_output=True, text=True, env=env or self.env(), timeout=timeout, cwd="/")

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

    def test_it_never_flushes_nftables_edits_ufw_or_removes_packages(self):
        with open(SCRIPT) as f:
            code = "\n".join(code_lines(f.read()))
        self.assertNotRegex(code, r"nft\s+flush|flush ruleset|delete ruleset")
        for line in code.splitlines():
            if re.search(r"(?<![-\w/.])nft(?![-\w.])", line) and not line.lstrip().startswith(("echo", "say", "note")):
                self.assertRegex(line, r"nft (-c -f|-f|delete table inet edr_hub)|command -v nft|nft\.sh", line)
        # ufw is only asked for its status; the allow lines are printed, never run
        for line in code.splitlines():
            if re.search(r"\bufw\b", line):
                self.assertRegex(line, r"ufw status|command -v ufw|echo|warn |refuse |printf", line)
        self.assertNotRegex(code, r"apt(-get)?\s+(remove|purge|autoremove)|dpkg\s+(-r|-P|--remove|--purge)")
        self.assertNotRegex(code, r"\beval\b|\bsed -i\b")

    def test_plan_gate_comes_before_every_step(self):
        with open(SCRIPT) as f:
            text = f.read()
        main = text[text.index("\nmain() {"):]
        gate = main.index("if [[ $PLAN -eq 1 ]]; then")
        self.assertIn("plan\n        exit $?", main[gate:gate + 80])
        for step in ("migration_backup", "step_users", "step_code", "step_init", "step_units", "step_firewall_file", "step_start",
                     "step_firewall_load", "step_finish", "exec systemd-run", "mktemp -d", "trap cleanup"):
            self.assertGreater(main.index(step), gate, step)
        body = text[text.index("plan_row() {"):text.index("# Render the firewall file")]
        self.assertNotRegex(body, r"(?m)^\s*(run|rm -rf \"\$[a-zA-Z]|systemctl|nft|useradd|install|cp|mv|chmod|chown|ln|apt-get)\s")
        self.assertNotRegex("\n".join(l for l in body.splitlines() if "mktemp" not in l and "$tmp" not in l), r"(?<![-\w])>>?\s*\"?\$")

    def test_every_change_goes_through_the_choke_points(self):
        """run(), put_file(), put_kept() and manifest_add() are the only ways the system or the manifest is written."""
        with open(SCRIPT) as f:
            text = f.read()
        start = text.index("# Every change to the system goes through run()")
        for no, line in enumerate(code_lines(text[start:]), 1):
            stripped = line.strip()
            if re.match(r"^(useradd|groupadd|systemctl|install|chown|chmod|mv|cp|ln|mkdir|rm|apt-get|nft -f|systemd-run|runuser|setpriv)\b", stripped):
                self.fail("a change is made outside run(): %s" % stripped)
        self.assertEqual(len(re.findall(r">>\s*\"\$MANIFEST\"", text)), 1)
        self.assertRegex(text, r'record file "\$2" "\$\(sha256_of "\$1"\)"\n\s+run install -m "\$3"')     # manifest line, then the file

    def test_the_kit_files_it_names_are_in_the_tree(self):
        with open(SCRIPT) as f:
            text = f.read()
        for m in re.finditer(r"\$SRC/((?:files|hub|pki|common)/[\w@.+-]+)", text):
            rel = m.group(1)
            self.assertTrue(os.path.exists(os.path.join(HUB, rel)) or os.path.exists(os.path.join(HUB, "..", rel)), rel)


class UsageTests(InstallCase):
    def test_usage_errors_exit_64_and_change_nothing(self):
        for args in (["--bogus"], ["--port"], ["--port", "0"], ["--port", "70000"], ["--port", "x"], ["--enroll-port", "8443", "--port", "8443"],
                     ["--ui-port", "8443", "--port", "8443"], ["--admin-ip", "nonsense"], ["--public-ip", "300.1.1.1"],
                     ["--public-ip", "10.0.0.0/8"], ["--retention-days", "0"], ["--retention-days", "9999"],
                     ["--max-db-size", "lots"], ["--ui-host", "no port"], ["--clients-only"], ["--confirm", "--plan"],
                     ["--confirm", "--yes"], ["extra"], ["--webhook-ca", "/nonexistent/file.pem"], ["--plan", "--bogus"]):
            r = self.run_script(*args)
            self.assertEqual(r.returncode, 64, "%s: %s" % (args, r.stderr))
            self.assertIn("usage:", r.stderr)
        self.assertEqual(self.called(), "")

    def test_help_exits_0(self):
        r = self.run_script("--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--plan", r.stderr)

    def test_equals_form_is_accepted(self):
        r = self.run_script("--plan", "--from-checkout", "--port=9443", "--enroll-port=9444", "--retention-days=14")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("port = 9443", r.stdout)
        self.assertIn("retention_days = 14", r.stdout)


class PlanTests(InstallCase):
    def plan(self, *args, **env):
        return self.run_script("--plan", "--from-checkout", *args, env=self.env(**env))

    def test_plan_lists_every_file_unit_user_directory_and_setting_and_changes_nothing(self):
        before = tree_hash(self.root)
        r = self.plan()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        after = tree_hash(self.root)
        self.assertEqual(self.called(), "")                                  # no stubbed mutating command was called
        self.assertEqual(before, after)
        out = r.stdout
        steps = [out.index(s) for s in ("Step 1: pre-flight", "Step 2: users and directories", "Step 3: code, CA and certificates",
                                        "Step 4: units", "Step 5: firewall rules", "Step 6: updates and reboots", "Step 7: dead-man",
                                        "Step 8: scheduled backups", "Step 9: start", "Step 10: apply the firewall")]
        self.assertEqual(steps, sorted(steps))
        for word in ("edr-hub.service", "edr-hub-out.service", "edr-hub-ui.service", "edr-hub-failed.service", "edr-hub-backup.service",
                     "edr-hub-backup.timer", "edr-hub-nft.service", "journald@edr-hub.conf", "52edr-hub", "/usr/local/lib/edr-hub",
                     "/usr/local/sbin/edr-hub", "edr-hub.nft", "secrets.json", "backup.pass", "manifest.jsonl", "unattended-upgrades",
                     "user and group edr-hub-ui", "user and group edr-hub-out", "user and group edr-hub ", "edr-hub:edr-hub-ui 2750",
                     "/ca (edr-hub 0700)", "/tls (edr-hub 0700)", "root 0700", "--init-only", "nft -c -f", "port = 8443", "enroll_port = 8444", "ui_port = 8450", "public_ip = ", "admin_ip = ", "max_db_size = 2G",
                     "retention_days = 30", "ui_host = ", "webhook_ca = "):
            self.assertIn(word, out, word)
        self.assertIn("[new]", out)
        self.assertIn("Pre-flight passed", out)
        self.assertIn("203.0.113.10", out)
        self.assertNotIn("172.17.0.1", out)                                  # container bridges are not hub addresses
        self.assertIn("ssh 2222", out)                                       # from sshd -T
        for d in self.dirs.values():
            self.assertEqual(os.listdir(d), [])                              # nothing was written into the state directories

    def test_plan_marks_what_is_already_there(self):
        for name in ("secrets.json", "backup.pass"):
            with open(os.path.join(self.etc, name), "w") as f:
                f.write("{}\n")
        with open(os.path.join(self.state, "settings.json"), "w") as f:
            json.dump({"port": 9000, "enroll_port": 9001, "ui_port": 9002, "public_ip": ["198.51.100.4"], "admin_ip": ["203.0.113.0/24"],
                       "max_db_size": "1G", "retention_days": 20}, f)
        r = self.plan()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = r.stdout
        self.assertRegex(out, r"\[there\]\s+.*secrets\.json")
        self.assertRegex(out, r"\[there\]\s+.*backup\.pass")
        self.assertIn("port = 9000 (kept)", out)
        self.assertIn("public_ip = 198.51.100.4 (kept)", out)
        self.assertIn("admin_ip = 203.0.113.0/24 (kept)", out)
        self.assertIn("ports 9000 and 9001", out)
        self.assertEqual(self.called(), "")

    def test_a_flag_that_is_named_again_changes_just_that_setting(self):
        with open(os.path.join(self.state, "settings.json"), "w") as f:
            json.dump({"port": 9000, "admin_ip": ["203.0.113.0/24"], "public_ip": ["198.51.100.4"], "retention_days": 20}, f)
        r = self.plan("--port", "9100", "--admin-ip", "192.0.2.7", "--public-ip", "198.51.100.77", "--ui-host", "hub.example:8450")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("[named]  port = 9100", r.stdout)
        self.assertIn("[named]  admin_ip = 192.0.2.7/32", r.stdout)                 # replaces the stored list
        self.assertIn("[named]  ui_host = hub.example:8450", r.stdout)
        self.assertIn("public_ip = 203.0.113.10,10.0.0.5,198.51.100.77", r.stdout)  # what was found plus the flag
        self.assertIn("retention_days = 20 (kept)", r.stdout)

    def test_over_ssh_the_source_joins_the_admin_list_and_the_timer_is_planned(self):
        r = self.plan("--admin-ip", "192.0.2.0/24", SSH_CONNECTION="198.51.100.9 50000 203.0.113.10 22")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("198.51.100.9/32", r.stdout)
        self.assertIn("joins the admin list", r.stdout)
        self.assertIn("systemd-run --unit=edr-hub-install", r.stdout)
        self.assertIn("systemd-run --on-active=300 --unit=edr-hub-fw-rollback", r.stdout)
        self.assertIn("install.sh --confirm", r.stdout)
        self.assertIn("exits 4", r.stdout)
        self.assertIn("192.0.2.0/24,198.51.100.9/32", r.stdout)
        self.assertEqual(self.called(), "")
        r = self.plan()
        self.assertIn("no timer", r.stdout)
        self.assertNotIn("--on-active=300", r.stdout)

    def test_refusals_exit_3(self):
        r = self.plan(EDR_HUB_DF_BYTES="1000")
        self.assertEqual(r.returncode, 3, r.stdout)
        self.assertRegex(r.stdout, r"REFUSED\].*free disk")
        with open(self.os_release, "w") as f:
            f.write('ID=debian\nVERSION_ID="12"\n')
        r = self.plan()
        self.assertEqual(r.returncode, 3)
        self.assertRegex(r.stdout, r"REFUSED\].*Ubuntu 24.04 and 26.04")
        with open(self.os_release, "w") as f:
            f.write(OS_OK)
        self.stub("timedatectl", "echo no", log=False)
        r = self.plan()
        self.assertEqual(r.returncode, 3)
        self.assertIn("clock is not synchronised", r.stdout)
        self.assertEqual(self.called(), "")

    def test_too_many_addresses_are_refused(self):
        r = self.plan("--public-ip", "198.51.100.1", "--public-ip", "198.51.100.2", "--public-ip", "198.51.100.3")
        self.assertEqual(r.returncode, 3, r.stdout)
        self.assertIn("holds at most 4", r.stdout)

    def test_a_downgrade_needs_force(self):
        lib = os.path.join(self.root, "libcopy")
        os.makedirs(lib)
        # point the check at an "installed" higher version by running a copy of the script with LIB redirected
        with open(SCRIPT) as f:
            text = f.read().replace("LIB=/usr/local/lib/edr-hub\n", "LIB=%s\n" % lib, 1)
        script = os.path.join(HUB, ".install-test-copy.sh")
        with open(script, "w") as f:
            f.write(text)
        self.addCleanup(os.unlink, script)
        with open(os.path.join(lib, "hub_common.py"), "w") as f:
            f.write('VERSION = "9.9.9"\n')
        r = self.run_script("--plan", "--from-checkout", script=script)
        self.assertEqual(r.returncode, 3, r.stdout)
        self.assertIn("a downgrade needs --force", r.stdout)
        r = self.run_script("--plan", "--from-checkout", "--force", script=script)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_tree_without_a_manifest_is_refused_unless_from_checkout(self):
        r = self.run_script("--plan")
        self.assertEqual(r.returncode, 3)
        self.assertIn("MANIFEST.sha256", r.stdout)
        r = self.run_script("--yes")
        self.assertEqual(r.returncode, 3)
        self.assertIn("REFUSED", r.stderr)
        self.assertEqual(self.called(), "")

    def test_the_tree_is_verified_against_manifest_sha256(self):
        tree = os.path.join(self.root, "release")
        os.makedirs(tree)
        for name in ("hub", "files", "pki", "common"):
            src = os.path.join(HUB, name) if name != "common" else os.path.join(HUB, "..", "common")
            shutil.copytree(src, os.path.join(tree, name), ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for name in ("install.sh", "check.sh", "uninstall.sh"):
            shutil.copy(os.path.join(HUB, name), os.path.join(tree, name))
        lines = []
        for base, _d, files in sorted(os.walk(tree)):
            for fn in sorted(files):
                p = os.path.join(base, fn)
                with open(p, "rb") as f:
                    lines.append("%s  %s\n" % (hashlib.sha256(f.read()).hexdigest(), os.path.relpath(p, tree)))
        with open(os.path.join(tree, "MANIFEST.sha256"), "w") as f:
            f.writelines(sorted(lines, key=lambda s: s[66:]))
        script = os.path.join(tree, "install.sh")
        r = self.run_script("--plan", script=script)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("verified against MANIFEST.sha256", r.stdout)
        with open(os.path.join(tree, "files", "edr-hub.service"), "a") as f:
            f.write("# tampered\n")
        r = self.run_script("--plan", script=script)
        self.assertEqual(r.returncode, 3)
        self.assertIn("do not match MANIFEST.sha256", r.stdout)
        r = self.run_script("--yes", script=script)                       # a real run refuses before anything else
        self.assertEqual(r.returncode, 3)
        self.assertEqual(self.called(), "")


class ManifestTests(InstallCase):
    """The real step functions, sourced, with run() replaced by a logger: the manifest they write must be one that
    uninstall.sh accepts, and every file is recorded before it is changed."""

    def harness(self, body):
        script = r'''
set -Eeuo pipefail
source "$INSTALL"
CALLS_LOG="$CALLS"
run() {
    local last=${!#} seen=NEW
    if [[ -f $MANIFEST ]] && { grep -qF "\"path\": \"$last\"" "$MANIFEST" || grep -qF "\"path\": \"${last}\"" "$MANIFEST"; }; then seen=SEEN; fi
    printf '%s\t%s\n' "$seen" "$*" >> "$CALLS_LOG"
}
unit_enabled() { return 1; }
package_present() { return 1; }
nft() { :; }
wait_health() { return 0; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
EFF_PORT=8443 EFF_ENROLL=8444 EFF_UI=8450 SSH_PORT=22 CA_SHA=abc NEW_VERSION=0.1.0
FINAL_PUBLIC=(203.0.113.10) FINAL_ADMIN=(192.0.2.0/24 2001:db8::/32) OVER_SSH=0
MIGRATING=0
'''
        with open(os.path.join(self.root, "harness.sh"), "w") as f:
            f.write(script + body)
        env = self.env(INSTALL=SCRIPT, CALLS=os.path.join(self.root, "run.log"))
        r = subprocess.run(["bash", os.path.join(self.root, "harness.sh")], capture_output=True, text=True, env=env, timeout=120)
        return r

    def run_log(self):
        try:
            with open(os.path.join(self.root, "run.log")) as f:
                return [line.rstrip("\n").split("\t", 1) for line in f]
        except FileNotFoundError:
            return []

    def manifest_lines(self):
        with open(os.path.join(self.etc, "manifest.jsonl")) as f:
            return [json.loads(line) for line in f if line.strip()]

    def uninstall_plan(self):
        env = {k: v for k, v in os.environ.items() if k not in ENV_KEYS}
        env.update(self.dirs)
        return subprocess.run(["bash", UNINSTALL, "--plan"], capture_output=True, text=True, env=env, timeout=60)

    def test_the_whole_install_manifest_is_accepted_by_uninstall_plan(self):
        r = self.harness("step_users\nstep_code\nstep_units\nstep_firewall_file\nstep_updates\nstep_start\nstep_firewall_load\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        lines = self.manifest_lines()
        kinds = {(l["kind"], l["path"]) for l in lines}
        for want in (("user", "edr-hub"), ("user", "edr-hub-ui"), ("user", "edr-hub-out"), ("group", "edr-hub"), ("dir", self.etc),
                     ("dir", "/usr/local/lib/edr-hub"), ("link", "/usr/local/sbin/edr-hub"),
                     ("file", "/etc/systemd/system/edr-hub.service"), ("file", "/etc/systemd/system/edr-hub-backup.timer"),
                     ("file", "/etc/systemd/journald@edr-hub.conf"), ("file", "/etc/apt/apt.conf.d/52edr-hub"),
                     ("file", os.path.join(self.etc, "edr-hub.nft")), ("unit", "edr-hub.service"), ("unit", "edr-hub-backup.timer"),
                     ("unit", "edr-hub-nft.service"), ("package", "unattended-upgrades")):
            self.assertIn(want, kinds)
        for l in lines:
            self.assertEqual(set(l) - {"sha256"}, {"ts", "kind", "path", "prior"})
            self.assertIsInstance(l["ts"], int)
            self.assertEqual("sha256" in l, l["kind"] == "file", l)
            self.assertTrue(l["prior"] in ("absent", "present") or set(l["prior"]) == {"saved"}, l)
        # secrets.json and backup.pass are the operator's: kept across uninstall, so not in the manifest
        self.assertFalse([l for l in lines if l["path"].endswith(("secrets.json", "backup.pass"))])
        units = {l["path"]: l["sha256"] for l in lines if l["kind"] == "file" and l["path"].startswith("/etc/systemd/system/")}
        with open(os.path.join(HUB, "files", "edr-hub.service"), "rb") as f:
            self.assertEqual(units["/etc/systemd/system/edr-hub.service"], hashlib.sha256(f.read()).hexdigest())
        p = self.uninstall_plan()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertNotIn("REFUSE", p.stdout)
        for word in ("unit edr-hub.service", "user edr-hub-out", "unattended-upgrades", "/usr/local/sbin/edr-hub", "/usr/local/lib/edr-hub"):
            self.assertIn(word, p.stdout, word)

    def test_each_file_is_recorded_before_it_is_changed(self):
        r = self.harness("step_users\nstep_code\nstep_units\nstep_firewall_file\nstep_firewall_load\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        log = self.run_log()
        checked = 0
        for seen, cmd in log:
            words = cmd.split()
            dest = words[-1]
            if words[:2] == ["install", "-m"] and (dest.startswith("/etc/systemd/") or dest.startswith("/etc/apt/") or dest.endswith("edr-hub.nft")):
                self.assertEqual(seen, "SEEN", cmd)
                checked += 1
            if words[0] == "ln" or (words[0] == "useradd"):
                self.assertEqual(seen, "SEEN", cmd)
                checked += 1
            if words[:2] == ["systemctl", "enable"]:
                with open(os.path.join(self.etc, "manifest.jsonl")) as f:
                    recorded = f.read()
                for unit in words[2:]:
                    self.assertIn('"path": "%s"' % unit, recorded)
        self.assertGreaterEqual(checked, 13)

    def test_step_commands_are_the_ones_of_the_plan(self):
        r = self.harness("step_users\nstep_code\nstep_units\nstep_firewall_file\nstep_start\nstep_firewall_load\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cmds = [cmd for _s, cmd in self.run_log()]
        text = "\n".join(cmds)
        for want in ("useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin edr-hub",
                     "install -d -m 0750 -o edr-hub -g edr-hub-ui %s" % self.state, "chmod 2750 %s" % self.state,
                     "install -d -m 0700 -o edr-hub -g edr-hub %s/ca" % self.state, "install -d -m 0700 -o edr-hub -g edr-hub %s/tls" % self.state,
                     "install -d -m 0700 -o root -g root %s" % self.dirs["EDR_HUB_BACKUP_DIR"],
                     "install -m 0600 -o root -g root", "install -m 0644 -o root -g root",
                     "ln -sfn /usr/local/lib/edr-hub/edr-hub /usr/local/sbin/edr-hub", "systemctl daemon-reload",
                     "systemctl enable edr-hub.service edr-hub-out.service edr-hub-ui.service edr-hub-backup.timer",
                     "systemctl restart edr-hub.service", "nft -f %s/edr-hub.nft" % self.etc,
                     "systemctl enable edr-hub-nft.service"):
            self.assertIn(want, text, want)
        self.assertNotIn("systemd-run", text)                                  # no ssh session: no rollback timer
        self.assertNotIn("delete table", text)

    def test_over_ssh_the_rollback_timer_is_armed_after_the_table_is_loaded(self):
        script = "OVER_SSH=1\nsystemctl() { return 1; }\nsleep() { :; }\nstep_firewall_file\n( step_firewall_load ) || echo \"exit=$?\"\n"
        r = self.harness(script)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("exit=4", r.stdout)                                     # timer "fired" (never confirmed): exit 4
        self.assertIn("rollback timer fired", r.stderr + r.stdout)
        cmds = [cmd for _s, cmd in self.run_log()]
        load = next(i for i, c in enumerate(cmds) if c.startswith("nft -f"))
        arm = next(i for i, c in enumerate(cmds) if c.startswith("systemd-run --on-active=300 --unit=edr-hub-fw-rollback"))
        self.assertLess(load, arm)
        self.assertTrue(cmds[arm].endswith("/usr/sbin/nft delete table inet edr_hub"))
        self.assertFalse([c for c in cmds if c.startswith("systemctl enable edr-hub-nft")])   # only --confirm enables it

    def test_confirm_cancels_the_timer_then_enables_the_unit_then_marks(self):
        with open(SCRIPT) as f:
            text = f.read()
        body = text[text.index("do_confirm() {"):text.index("# ---- main")]
        self.assertLess(body.index("systemctl stop edr-hub-fw-rollback.timer"), body.index("manifest_add unit edr-hub-nft.service"))
        self.assertLess(body.index("manifest_add unit edr-hub-nft.service"), body.index("systemctl enable edr-hub-nft.service"))
        self.assertLess(body.index("systemctl enable edr-hub-nft.service"), body.index('"$CONFIRM_MARK"'))

    def test_confirm_with_no_pending_change_changes_nothing(self):
        env = self.env()
        self.stub("systemctl", "exit 3")                       # is-active: no timer
        r = subprocess.run(["bash", SCRIPT, "--confirm"], capture_output=True, text=True, env=env, timeout=60)
        if os.geteuid() == 0:
            self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
            self.assertIn("No firewall change is waiting", r.stderr)
            self.assertNotIn("enable", self.called())
        else:
            self.assertEqual(r.returncode, 3)

    def test_a_foreign_file_is_saved_and_the_first_prior_wins_on_a_rerun(self):
        target = os.path.join(self.etc, "foreign.conf")
        with open(target, "w") as f:
            f.write("operator's own\n")
        src = os.path.join(self.root, "new.conf")
        with open(src, "w") as f:
            f.write("kit version\n")
        r = self.harness('mkdir -p "$ETC/prior"\nput_file %s %s 0644 root:root\nput_file %s %s 0644 root:root\n' % (src, target, src, target))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        lines = [l for l in self.manifest_lines() if l["path"] == target]
        self.assertEqual(len(lines), 2)
        saved = lines[0]["prior"]["saved"]
        self.assertTrue(saved.startswith(self.etc + "/prior/"))
        self.assertEqual(lines[1]["prior"], "present")                         # a re-run: the first line still decides
        self.assertTrue(any(c.startswith("cp -p") and saved in c for _s, c in self.run_log()))
        with open(target, "w") as f:                                          # as the install would have left it
            f.write("kit version\n")
        os.makedirs(os.path.dirname(saved), exist_ok=True)
        with open(saved, "w") as f:
            f.write("operator's own\n")
        p = self.uninstall_plan()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("put the saved prior copy back at %s" % target, p.stdout)

    def test_manifest_add_rejects_what_uninstall_would_refuse(self):
        for args in ("file /etc/x y absent", "file /etc/a;b absent", "bogus /etc/x absent", "file /etc/x saved:relative",
                     "file /etc/x absent notahash"):
            r = self.harness("manifest_add %s\n" % args)
            self.assertNotEqual(r.returncode, 0, args)

    def test_manifest_dir_line_is_first_and_etc_is_not_made_by_a_stub_run(self):
        shutil.rmtree(self.etc)
        r = self.harness("step_etc\n")
        # with run() stubbed the directory is not created, so the manifest line cannot be written: it fails loudly
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue(any(cmd.startswith("install -d -m 0750 -o root -g root") for _s, cmd in self.run_log()))


if __name__ == "__main__":
    unittest.main()
