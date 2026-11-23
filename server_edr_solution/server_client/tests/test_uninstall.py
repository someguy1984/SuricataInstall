"""uninstall.sh (client PLAN section 6): syntax, shellcheck, usage errors, --plan against a test root, and the refusal of
a manifest that names anything the kit does not own. The script is never run for real here."""

import json
import os
import re
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from test_install_common import (FILES, INSTALL, UNINSTALL, RootCase, manifest_doc, session, tree_hash)  # noqa: E402
import test_install as ti  # noqa: E402


def text():
    with open(UNINSTALL) as f:
        return f.read()


class TestSyntax(unittest.TestCase):
    def test_bash_n_shellcheck_and_shebang(self):
        r = subprocess.run(["bash", "-n", UNINSTALL], capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(text().splitlines()[0], "#!/bin/bash")
        self.assertTrue(os.access(UNINSTALL, os.X_OK))
        self.assertTrue(shutil.which("shellcheck"), "shellcheck is required (CI fails, never skips)")
        r = subprocess.run(["shellcheck", "-S", "warning", "-x", UNINSTALL], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)

    MUTATING = ti.TestStaticGuarantees.MUTATING

    def test_plan_holds_no_state_changing_command_and_exits_before_the_real_run(self):
        src = text()
        for name in ("plan", "classify", "describe", "fallback_entries", "installed_anything", "manifest_path"):
            body = ti.function_body(src, name)
            code = re.sub(r"\"[^\"]*\"", '""', "\n".join(l for l in body.splitlines() if not l.lstrip().startswith("#")))
            for line in code.splitlines():
                if name == "plan" and re.match(r"\s*(echo|say)\b", line):
                    continue
                self.assertIsNone(self.MUTATING.search(line), "%s: %s" % (name, line))
        gate = src.index("if [[ $PLAN -eq 1 ]]; then\n    plan\n    exit $?\nfi")
        self.assertGreater(src.index("EUID -eq 0", gate), gate)
        for marker in ("nft delete table inet edr_isolate >/dev/null", "systemctl disable --now edr-bans.path", "rm -rf", "userdel \"$u\"", "apt-get -y purge", "swapoff /swapfile-edr 2>/dev/null", "exec /bin/bash"):
            self.assertGreater(src.index(marker), gate, marker)

    def test_packages_users_and_nft_are_limited_to_the_kit(self):
        src = text()
        code = re.sub(r"'[^'\n]*'|\"[^\"\n]*\"", '""', "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#")))
        self.assertNotRegex(code, r"autoremove|nft\s+flush|flush ruleset|iptables|\beval\b")
        self.assertEqual(len(re.findall(r"apt-get -y purge", src)), 1)
        self.assertIn("suricata|suricata-update|dnscrypt-proxy|nftables|tetragon", src)
        for line in src.splitlines():
            if re.search(r"(^|\s)nft\s", line) and not line.lstrip().startswith(("#", "echo")):
                self.assertRegex(line, r"nft (delete table inet edr(_dns|_isolate)?|list table inet edr(_dns|_isolate)?)", line)
        self.assertNotIn("userdel root", src)
        # the removal of trees is a closed list
        self.assertRegex(src, r"/usr/local/lib/edr-agent\|/usr/local/lib/edr-agent\.prev\|/usr/local/lib/tetragon\|/etc/tetragon\|/usr/libexec/edr\|/etc/edr-dns\)")

    def test_it_copies_itself_before_deleting_its_own_tree(self):
        src = text()
        self.assertIn("COPY=$(mktemp -d /run/edr-uninstall.XXXXXX)", src)
        self.assertIn('exec /bin/bash "$COPY/uninstall.sh" --in-copy', src)
        self.assertIn("trap 'rm -rf -- \"$COPY\"' EXIT", src)

    def test_deregister_comes_first_and_carries_on(self):
        src = text()
        i = src.index('timeout 20 python3 -I "$LIB/edr-agent.py" deregister --reason uninstall')
        self.assertLess(i, src.index('say "Step 1: stopping'))
        self.assertIn("carrying on", src[i:i + 400])


class TestUsage(RootCase):
    def test_usage_errors_exit_64(self):
        for args in (["--frobnicate"], ["--keep"], ["--in-copy"], ["extra"]):
            r = self.run_script(UNINSTALL, args)
            self.assertEqual(r.returncode, 64, args)
        r = self.run_script(UNINSTALL, ["--yes"])                 # a real run in a test root is refused
        self.assertEqual(r.returncode, 64)
        self.assertIn("only for --plan", r.stderr)
        self.assertEqual(self.stub_calls(), "")
        self.assertEqual(self.run_script(UNINSTALL, ["--help"]).returncode, 0)


class TestPlan(RootCase):
    def run_plan(self, *args):
        before = tree_hash(self.root)
        r = self.run_script(UNINSTALL, ["--plan"] + list(args))
        self.assertEqual(self.stub_calls(), "", "the plan ran a command that could change the machine")
        self.assertEqual(before, tree_hash(self.root), "the plan changed the test root")
        return r

    def good_manifest(self):
        self.manifest(manifest_doc(session(
            files=[{"path": "/etc/modprobe.d/edr-sctp-block.conf", "sha256": "a" * 64, "mode": "0644", "owner": "root:root", "prior": "absent", "step": 6},
                   {"path": "/etc/suricata/suricata.yaml", "sha256": "b" * 64, "mode": "0644", "owner": "root:suricata",
                    "prior": {"saved": "/var/lib/edr-install/prior/1234abcd-0000-4000-8000-000000000000/1", "sha256": "c" * 64}, "step": 4},
                   {"path": "/usr/local/sbin/edr-check", "sha256": "d" * 64, "mode": "0755", "owner": "root:root", "prior": "absent", "step": 2},
                   {"path": "/etc/systemd/system/edr-bans.service", "sha256": "e" * 64, "mode": "0644", "owner": "root:root", "prior": "absent", "step": 5},
                   {"path": "/etc/systemd/system/dnscrypt-proxy.service.d/50-edr.conf", "sha256": "e" * 64, "mode": "0644", "owner": "root:root", "prior": "absent", "step": 8}],
            dirs=[{"path": "/usr/local/lib/edr-agent", "prior": "absent", "step": 2}, {"path": "/etc/tetragon", "prior": "absent", "step": 7}],
            units=[{"name": "edr-bans.timer", "prior_enabled": None, "prior_active": None, "step": 5},
                   {"name": "suricata.service", "prior_enabled": True, "prior_active": True, "step": 4}],
            sysctls=[{"key": "net.netfilter.nf_conntrack_max", "prior": "65536", "value": "262144", "step": 5}],
            packages=[{"name": "suricata", "by_kit": True, "step": 3}, {"name": "nftables", "by_kit": False, "step": 3}],
            ppa={"name": "ppa:oisf/suricata-stable", "by_kit": False}, users=[{"name": "edr-agent", "by_kit": True, "step": 2}],
            swapfile={"path": "/swapfile-edr", "size": "1G"})))

    def test_the_plan_lists_every_step_in_the_plans_order_and_changes_nothing(self):
        self.good_manifest()
        os.makedirs(self.root + "/usr/local/lib/edr-agent")
        r = self.run_plan()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        steps = [int(n) for n in re.findall(r"==> Step (\d+)", r.stdout)]
        self.assertEqual(steps, [1, 2, 3, 5, 6, 7, 8, 4, 9, 10, 11])         # 4 is the manifest replay heading; see below
        out = r.stdout
        self.assertLess(out.index("Step 2: delete table inet edr"), out.index("Step 3: restore DNS"))
        self.assertLess(out.index("Step 3: restore DNS"), out.index("Step 7: Tetragon"))
        self.assertLess(out.index("Step 7: Tetragon"), out.index("Step 8: Suricata"))
        self.assertLess(out.index("Step 8: Suricata"), out.index("Step 9: the code"))
        for need in ("check that a lookup works",
                     "purge package suricata", "leave package nftables", "leave the apt source ppa:oisf/suricata-stable", "delete the user edr-agent",
                     "put net.netfilter.nf_conntrack_max back to its prior value 65536", "put the saved prior copy back at /etc/suricata/suricata.yaml",
                     "remove directory /usr/local/lib/edr-agent", "this re-opens both SCTP bugs", "swapoff", "/swapfile-edr none swap sw 0 0",
                     "no 'edr', 'edr_dns' or 'edr_isolate' table", "except host-id", "remove /var/lib/edr-install"):
            self.assertIn(need, out, need)
        self.assertNotIn("REFUSE", out)
        self.assertIn("not enrolled: no deregister", out)

    def test_partial_flags_are_in_the_plan(self):
        self.good_manifest()
        out = self.run_plan("--keep-dns", "--keep-tetragon", "--keep-suricata", "--keep-sctp-block", "--keep-config", "--keep-logs", "--purge").stdout
        for need in ("skipped: --keep-dns", "skipped: --keep-tetragon", "skipped: --keep-suricata", "keep /etc/modprobe.d/edr-sctp-block.conf (--keep-sctp-block)",
                     "except local.conf (--keep-config)", "/var/lib/edr-install stays", "--purge removes it too"):
            self.assertIn(need, out, need)
        self.assertNotIn("then the users edr-agent and edr-notify the kit created", out)

    def test_enrolled_host_is_deregistered_first(self):
        os.makedirs(self.root + "/var/lib/edr-agent/identity/gen-1")
        os.symlink("gen-1", self.root + "/var/lib/edr-agent/identity/current")
        out = self.run_plan().stdout
        self.assertIn("run edr-agent deregister --reason uninstall", out)
        self.assertIn("if the hub is unreachable, carry on", out)

    def test_no_manifest_removes_by_name_and_says_so(self):
        self.put("/etc/systemd/system/edr-bans.service", "x")
        self.put("/etc/systemd/system/edr-agent.service", "x")
        self.put("/etc/modprobe.d/edr-sctp-block.conf", "x")
        os.makedirs(self.root + "/usr/local/lib/edr-agent")
        r = self.run_plan()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("there is no manifest: the kit's files are removed by name", r.stdout)
        for need in ("remove /etc/systemd/system/edr-bans.service", "remove /etc/systemd/system/edr-agent.service", "remove /etc/modprobe.d/edr-sctp-block.conf",
                     "remove directory /usr/local/lib/edr-agent"):
            self.assertIn(need, r.stdout, need)

    def test_nothing_installed(self):
        r = self.run_plan()
        self.assertEqual(r.returncode, 0)
        self.assertIn("nothing from the kit was found", r.stdout)

    def test_the_agent_copy_of_the_manifest_is_used_when_there_is_no_root_only_one(self):
        self.put("/etc/update-motd.d/90-edr", "x")
        self.manifest(manifest_doc(session(files=[{"path": "/etc/update-motd.d/90-edr", "sha256": "a" * 64, "mode": "0755", "owner": "root:root",
                                                    "prior": "absent", "step": 9}])), where="/var/lib/edr-agent/manifest.json")
        r = self.run_plan()
        self.assertIn("remove /etc/update-motd.d/90-edr", r.stdout)

    def test_a_present_prior_is_left_alone_and_an_edited_file_is_reported(self):
        target = self.put("/etc/update-motd.d/90-edr", "edited by the operator")
        self.manifest(manifest_doc(session(files=[{"path": "/etc/update-motd.d/90-edr", "sha256": "a" * 64, "mode": "0755", "owner": "root:root",
                                                    "prior": "absent", "step": 9}],
                                           dirs=[{"path": "/var/lib/edr-bans", "prior": "present", "step": 5}])))
        os.makedirs(self.root + "/var/lib/edr-bans")
        r = self.run_plan()
        self.assertIn("(changed since install; the manifest says it did not exist before)", r.stdout)
        self.assertIn("leave /var/lib/edr-bans: it existed before the kit", r.stdout)
        self.assertTrue(os.path.exists(target))

    def test_a_later_session_does_not_change_where_the_first_one_goes_back_to(self):
        a = session(id="aaaa0000-0000-4000-8000-000000000001", files=[{"path": "/etc/suricata/drop.conf", "sha256": "a" * 64, "mode": "0644", "owner": "root:root",
                    "prior": {"saved": "/var/lib/edr-install/prior/aaaa0000-0000-4000-8000-000000000001/1", "sha256": "f" * 64}, "step": 4}])
        b = session(id="bbbb0000-0000-4000-8000-000000000002", kind="upgrade", files=[{"path": "/etc/suricata/drop.conf", "sha256": "b" * 64, "mode": "0644",
                    "owner": "root:root", "prior": {"saved": "/var/lib/edr-install/prior/bbbb0000-0000-4000-8000-000000000002/1", "sha256": "a" * 64}, "step": 4}])
        self.manifest(manifest_doc(a, b))
        r = self.run_plan()
        self.assertEqual(r.stdout.count("/etc/suricata/drop.conf"), 1)                       # one line for the path
        self.assertIn("put the saved prior copy back at /etc/suricata/drop.conf", r.stdout)


class TestRefusedManifests(RootCase):
    """A manifest naming anything the kit does not own is refused: exit 3, and a real run changes nothing."""

    run_plan = TestPlan.run_plan

    def refused(self, doc_or_text, why):
        if isinstance(doc_or_text, str):
            full = self.root + "/var/lib/edr-install/manifest.json"
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as f:
                f.write(doc_or_text)
        else:
            self.manifest(doc_or_text)
        r = self.run_plan()
        self.assertEqual(r.returncode, 3, r.stdout)
        self.assertIn("a real run stops before changing anything (exit 3)", r.stdout)
        self.assertIn(why, r.stdout)
        return r

    def f(self, path, prior="absent"):
        return {"path": path, "sha256": "a" * 64, "mode": "0644", "owner": "root:root", "prior": prior, "step": 2}

    def test_paths_outside_the_kits_own_set(self):
        for path in ("/etc/passwd", "/etc/shadow", "/usr/bin/python3", "/etc/edr-agent/../passwd", "/etc/edr-agent/./x", "relative/path", "/",
                     "/etc/systemd/system/sshd.service", "/etc/systemd/system/edr-x.service.d/evil.conf/../../../ssh.service", "/etc/suricata/other.conf",
                     "/usr/local/sbin/evil", "/usr/local/lib/edr-agentx", "/etc/edr-agent\n/etc/passwd", "/var/lib/suricata/rules/suricata.rules",
                     "/etc/apt/sources.list", "/home/j/.bashrc", "/root/.ssh/authorized_keys", "/swapfile", "/etc/fstab", "/var/lib/edr-agent//x",
                     "/etc/modprobe.d/other.conf", "/lib/systemd/system/edr-x.service"):
            self.refused(manifest_doc(session(files=[self.f(path)])), "path outside what the kit owns")

    def test_the_kits_own_paths_are_accepted(self):
        for path in ("/etc/edr-agent/logrotate.conf", "/usr/local/lib/edr-agent/edr-bans", "/usr/local/lib/edr-agent.prev/x", "/usr/local/sbin/edr-check",
                     "/var/lib/edr-bans/state.json", "/run/edr-droplet-id", "/usr/libexec/edr/canary", "/etc/suricata/drop.conf", "/etc/suricata/edr-home-net.yaml",
                     "/var/lib/suricata/rules/edr-ban-sids.txt", "/etc/apt/preferences.d/suricata-8", "/swapfile-edr", "/etc/systemd/system/edr-bans.service",
                     "/etc/systemd/system/suricata.service.d/override.conf", "/etc/systemd/system/edr-agent.service.d/10-hub.conf",
                     "/etc/sysctl.d/90-edr-conntrack.conf", "/etc/modprobe.d/edr-sctp-block.conf", "/etc/systemd/resolved.conf.d/zz-edr-doh.conf",
                     "/etc/apt/apt.conf.d/zz-edr-inventory", "/etc/needrestart/conf.d/50-edr.conf", "/etc/update-motd.d/90-edr",
                     "/etc/systemd/journald@edr.conf", "/etc/tetragon/tetragon.tp.d/edr-canary.yaml", "/usr/local/bin/tetra"):
            self.manifest(manifest_doc(session(files=[self.f(path)])))
            r = self.run_plan()
            self.assertEqual(r.returncode, 0, path + r.stdout)
            self.assertNotIn("REFUSE", r.stdout, path)

    def test_every_path_the_installer_writes_is_accepted_by_the_uninstaller(self):
        """The two scripts must agree on what the kit owns: a path install.sh records and uninstall.sh refuses would make
        every later uninstall fail. The literal destinations of install_file, write_file and ensure_dir, and the file table."""
        with open(INSTALL) as f:
            src = f.read()
        import shlex
        known = {"$ETC_A": "/etc/edr-agent", "$ETC_DNS": "/etc/edr-dns", "$STATE_A": "/var/lib/edr-agent", "$STATE_I": "/var/lib/edr-install", "$LIB": "/usr/local/lib/edr-agent"}
        files, dirs = set(), set()
        for line in src.splitlines():
            if line.lstrip().startswith("#"):
                continue
            m = re.search(r"\b(install_file|write_file|ensure_dir)\s+(\S.*)$", line)
            if not m:
                continue
            try:
                args = shlex.split(m.group(2).split("|")[0].split(";")[0].split("<<")[0])
            except ValueError:
                continue
            if m.group(1) == "install_file":
                args = args[1:]
            if not args:
                continue
            dest = args[0]
            for var, val in known.items():
                dest = dest.replace(var, val)
            if not dest.startswith("/") or "$" in dest:
                continue
            (dirs if m.group(1) == "ensure_dir" else files).add(dest)
        table = re.search(r"FILE_TABLE='\n(.*?)'\n", src, re.S).group(1)
        files |= {l.split("|")[5] for l in table.splitlines() if l}
        files |= {"/etc/suricata/drop.conf.new", "/etc/systemd/system/edr-agent.service.d/10-hub.conf", "/usr/local/lib/edr-agent/edr-bans",
                  "/etc/systemd/system/tetragon.service.d/10-edr.conf", "/etc/tetragon/tetragon.tp.d/edr-nginx-exec.yaml", "/var/lib/edr-agent/droplet-id"}
        dirs |= {"/usr/local/lib/edr-agent", "/usr/local/lib/edr-agent.prev", "/usr/local/lib/tetragon", "/etc/systemd/system/dnscrypt-proxy.service.d"}
        files = {p for p in files if not p.endswith("/") and "$" not in p}
        self.assertGreater(len(files), 40)
        self.manifest(manifest_doc(session(files=[self.f(p) for p in sorted(files)], dirs=[{"path": p, "prior": "absent", "step": 2} for p in sorted(dirs)],
                                           packages=[{"name": n, "by_kit": True, "step": 3} for n in ("suricata", "dnscrypt-proxy", "nftables")],
                                           users=[{"name": n, "by_kit": True, "step": 2} for n in ("edr-agent", "edr-notify")],
                                           units=[{"name": n, "prior_enabled": None, "prior_active": None, "step": 5} for n in
                                                  ("suricata.service", "dnscrypt-proxy.socket", "dnscrypt-proxy.service", "tetragon.service", "edr-agent.service")])))
        r = self.run_plan()
        self.assertEqual(r.returncode, 0, "\n".join(l for l in r.stdout.splitlines() if l.startswith("REFUSE")))

    def test_a_prior_copy_must_live_in_the_kits_prior_directory(self):
        for saved in ("/etc/passwd", "/var/lib/edr-install/prior/../../../etc/passwd", "/var/lib/edr-agent/x", "relative"):
            self.refused(manifest_doc(session(files=[self.f("/etc/suricata/drop.conf", {"saved": saved, "sha256": "a" * 64})])), "bad prior")
        self.refused(manifest_doc(session(files=[self.f("/etc/suricata/drop.conf", "present")])), "bad prior")
        self.refused(manifest_doc(session(files=[self.f("/etc/suricata/drop.conf", ["saved"])])), "bad prior")

    def test_packages_users_ppa_units_sysctls_swap_dirs(self):
        self.refused(manifest_doc(session(packages=[{"name": "python3", "by_kit": True}])), "not in the kit's list")
        self.refused(manifest_doc(session(packages=[{"name": "openssl", "by_kit": True}])), "not in the kit's list")
        self.refused(manifest_doc(session(packages=[{"name": "suricata", "by_kit": "yes"}])), "not in the kit's list")
        self.refused(manifest_doc(session(users=[{"name": "root", "by_kit": True}])), "not in the kit's list")
        self.refused(manifest_doc(session(users=[{"name": "www-data", "by_kit": True}])), "not in the kit's list")
        self.refused(manifest_doc(session(ppa={"name": "ppa:evil/pkg", "by_kit": True})), "ppa is not the kit's")
        self.refused(manifest_doc(session(units=[{"name": "sshd.service", "prior_enabled": None, "prior_active": None}])), "bad unit name")
        self.refused(manifest_doc(session(units=[{"name": "edr-x.service;rm", "prior_enabled": None, "prior_active": None}])), "bad unit name")
        self.refused(manifest_doc(session(units=[{"name": "edr-bans.timer", "prior_enabled": "yes", "prior_active": None}])), "bad unit state")
        self.refused(manifest_doc(session(sysctls=[{"key": "kernel.randomize_va_space", "prior": "0", "value": "0"}])), "bad sysctl entry")
        self.refused(manifest_doc(session(sysctls=[{"key": "net.netfilter.nf_conntrack_max", "prior": "1; rm -rf /", "value": "2"}])), "bad sysctl entry")
        self.refused(manifest_doc(session(sysctls=[{"key": "net.netfilter.nf_conntrack_max", "prior": "-1", "value": "2"}])), "bad sysctl entry")
        self.refused(manifest_doc(session(swapfile={"path": "/swapfile", "size": "1G"})), "only /swapfile-edr")
        self.refused(manifest_doc(session(swapfile={"path": "/swapfile-edr", "size": "1G; rm"})), "only /swapfile-edr")
        self.refused(manifest_doc(session(dirs=[{"path": "/etc", "prior": "absent"}])), "bad directory entry")
        self.refused(manifest_doc(session(dirs=[{"path": "/var/lib/edr-bans", "prior": "maybe"}])), "bad directory entry")

    def test_malformed_manifests(self):
        self.refused("not json at all", "not a manifest this script understands")
        self.refused("[1, 2, 3]", "not a manifest this script understands")
        self.refused(json.dumps({"v": 2, "sessions": []}), "not a manifest this script understands")
        self.refused(json.dumps({"v": 1, "sessions": [{"id": "x"}]}), "not a session")
        self.refused(json.dumps(manifest_doc(session(state="whatever"))), "not a session")
        self.refused(json.dumps(manifest_doc(session(id="../../etc"))), "not a session")
        self.refused("[" * 100000, "not a manifest this script understands")
        full = self.root + "/var/lib/edr-install/manifest.json"
        with open(full, "w") as f:
            f.write('{"v": 1, "sessions": [], "pad": "' + "x" * (4 * 1024 * 1024) + '"}')
        r = self.run_plan()
        self.assertEqual(r.returncode, 3)
        self.assertIn("larger than 4 MiB", r.stdout)

    def test_a_manifest_with_a_refused_line_does_not_hide_the_good_ones(self):
        self.put("/etc/update-motd.d/90-edr", "x")
        self.manifest(manifest_doc(session(files=[self.f("/etc/passwd"), self.f("/etc/update-motd.d/90-edr")])))
        r = self.run_plan()
        self.assertEqual(r.returncode, 3)
        self.assertIn("remove /etc/update-motd.d/90-edr", r.stdout)
        self.assertIn("REFUSE", r.stdout)

    def test_the_manifest_text_cannot_reach_the_terminal_raw(self):
        r = self.refused(manifest_doc(session(files=[self.f("/etc/passwd\x1b[31m\x07")])), "path outside what the kit owns")
        self.assertNotIn("\x1b", r.stdout)
        self.assertNotIn("\x07", r.stdout)

    def test_a_symlinked_manifest_is_not_followed_into_another_file(self):
        # a manifest that is a link to something big or odd is just a manifest that does not parse
        os.makedirs(self.root + "/var/lib/edr-install")
        os.symlink("/etc/passwd", self.root + "/var/lib/edr-install/manifest.json")
        r = self.run_plan()
        self.assertEqual(r.returncode, 3)


if __name__ == "__main__":
    unittest.main()
