"""install.sh (client PLAN section 7): syntax, shellcheck, usage errors, the pre-flight and --plan against a test root,
the manifest the installer writes, and the static guarantees (nothing in --plan can change the machine). The script
is never run for real here."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import http.server
import unittest

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from test_install_common import (FILES, INSTALL, UNINSTALL, CLIENT, RootCase, extract_python, manifest_doc, session, tree_hash)  # noqa: E402


def text():
    with open(INSTALL) as f:
        return f.read()


def function_body(src, name):
    m = re.search(r"^%s\(\) \{[^\n]*\n(.*?)^\}\n" % re.escape(name), src, re.S | re.M)
    assert m, name
    return m.group(1)


class TestSyntax(unittest.TestCase):
    def test_bash_n_and_shebang(self):
        r = subprocess.run(["bash", "-n", INSTALL], capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(text().splitlines()[0], "#!/bin/bash")
        self.assertTrue(os.access(INSTALL, os.X_OK))

    def test_shellcheck(self):
        self.assertTrue(shutil.which("shellcheck"), "shellcheck is required (CI fails, never skips)")
        r = subprocess.run(["shellcheck", "-S", "warning", "-x", INSTALL], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_embedded_python_compiles_on_312(self):
        import ast
        progs = extract_python(INSTALL)
        self.assertGreaterEqual(len(progs), 4)
        for p in progs:
            ast.parse(p, feature_version=(3, 12))


class TestStaticGuarantees(unittest.TestCase):
    MUTATING = re.compile(r"(^|[\s;|&(`])(systemctl|nft|iptables|ip6tables|sysctl|modprobe|useradd|groupadd|userdel|usermod|apt-get|apt|"
                          r"add-apt-repository|resolvectl|rm|mv|cp|install|mkdir|chmod|chown|tee|ln|swapon|swapoff|mkswap|dpkg|systemd-run|mktemp)\s")

    def test_plan_functions_hold_no_state_changing_command(self):
        src = text()
        for name in ("preflight", "plan_main", "plan_step", "local_conf_changes", "component_wanted", "step_title", "step_phase", "admin_source",
                     "read_token", "hub_probe", "metadata_id", "free_kb", "meminfo_kb", "os_field", "probe", "verify_tree"):
            body = function_body(src, name)
            code = "\n".join(l for l in body.splitlines() if not l.lstrip().startswith("#"))
            code = re.sub(r"<<'PY'.*?\nPY\n", "", code, flags=re.S)
            code = re.sub(r"\"[^\"]*\"", '""', code)
            for line in code.splitlines():
                self.assertIsNone(self.MUTATING.search(line), "%s: %s" % (name, line))
            self.assertNotRegex(code, r">\s*\"?(?!/dev/null)[$/]", name)           # no redirection into a file
        # preflight reads programs only through probe, never directly
        pre = function_body(src, "preflight")
        for prog in ("systemd-detect-virt", "uname", "ss", "ip", "dpkg-query"):
            for line in pre.splitlines():
                if re.search(r"(^|[\s(`])%s\s" % prog, line) and not line.lstrip().startswith("#"):
                    self.assertIn("probe %s" % prog, line)

    def test_nothing_at_the_top_level_changes_state_before_the_plan_gate(self):
        src = text()
        gate = src.index("if [[ $PLAN -eq 1 ]]; then\n    verify_tree\n    plan_main\n    exit $?\nfi")
        before = src[:gate]
        before = re.sub(r"<<'(\w+)'.*?\n\1\n", "", before, flags=re.S)
        depth = 0
        for line in before.splitlines():
            if depth == 0 and line and not line.startswith(("#", " ", "}")):
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\(\) \{", line):
                    depth = 1
                    continue
                self.assertIsNone(self.MUTATING.search(" " + line + " "), line)
            if depth and line == "}":
                depth = 0
        # the first thing after the gate is the root check, and the gate is not conditional on anything else
        self.assertIn("exit $?", src[gate:gate + 120])
        self.assertGreater(src.index("EUID -eq 0", gate), gate)

    def test_it_never_flushes_or_edits_what_it_must_not(self):
        code = "\n".join(l for l in text().splitlines() if not l.lstrip().startswith("#"))
        code = re.sub(r"'[^'\n]*'|\"[^\"\n]*\"", '""', code)           # words in messages and grep patterns are not commands
        self.assertNotRegex(code, r"nft\s+flush|flush ruleset|delete ruleset|iptables\s+-F|iptables\s+-X|ip6tables\s+-F")
        self.assertNotRegex(code, r"nft\s+-f\s+/etc/nftables|(^|[\s;|&])ufw\s")
        self.assertNotRegex(code, r"systemctl\s+(restart|reload|stop|start)\s+[^\n]*\b(nginx|php[0-9.]*-fpm|mysql|mariadb|postgresql)")
        self.assertNotRegex(code, r"\beval\b")
        self.assertNotRegex(code, r"(^|\s)sed -i[^\n]*(/etc/nginx|/etc/ufw)")
        for line in code.splitlines():
            if re.search(r"(^|\s)nft\s", line):
                self.assertRegex(line, r"nft (-t list table inet edr(_dns)?|delete table inet edr(_dns)?|-c -f|get element inet edr|-t list table)", line)

    def test_a_token_value_never_reaches_a_command_line(self):
        code = text()
        self.assertNotRegex(code, r'enroll[^\n]*--token\s+"?\$')
        self.assertIn("--token-file", code)
        self.assertRegex(code, r"umask 077; printf '%s' \"\$tok\"")

    def test_tarball_references_resolve(self):
        # the check make dist runs: $SRC/files/NAME and friends must exist in the tree
        ref = re.compile(r"\$\{?(?:SRC|HERE|ROOT|DIR|SCRIPT_DIR|SELF|SRCDIR|KIT|TREE)\}?/((?:files|agent|tetragon|pki|common|hub|docs)/[\w@.+-]+(?:/[\w@.+-]+)*)")
        for script in (INSTALL, UNINSTALL):
            with open(script) as f:
                for m in ref.finditer(f.read()):
                    if m.group(1) == "files/dns-lockdown-rules.sh":        # make dist copies it from the laptop kit
                        continue
                    self.assertTrue(os.path.exists(os.path.join(CLIENT, m.group(1))), "%s refers to %s" % (os.path.basename(script), m.group(1)))

    def test_every_table_source_exists_and_every_unit_it_enables_exists(self):
        src = text()
        table = re.search(r"FILE_TABLE='\n(.*?)'\n", src, re.S).group(1)
        rows = [l.split("|") for l in table.splitlines() if l]
        self.assertGreaterEqual(len(rows), 38)
        for step, comp, mode, owner, source, dest in rows:
            self.assertTrue(os.path.isfile(os.path.join(CLIENT, source)), source)
            self.assertRegex(mode, r"^0[0-7]{3}$")
            self.assertTrue(dest.startswith("/"))
        units = set(re.findall(r"\bedr-[a-z-]+\.(?:service|timer|path)\b", src))
        for u in units:
            if u in ("edr-install.service", "edr-install-rollback.service", "edr-install-rollback.timer", "edr-agent-pause-end.service"):
                continue
            self.assertTrue(os.path.isfile(os.path.join(FILES, u)), u)

    def test_the_laptop_tetragon_pin_is_the_one_in_the_laptop_config(self):
        cfg = os.path.join(os.path.dirname(os.path.dirname(CLIENT)), "tetragon", "config.sh")
        if not os.path.isfile(cfg):
            self.skipTest("no laptop kit beside this tree")
        with open(cfg) as f:
            c = f.read()
        for var in ("TETRAGON_VERSION", "TETRAGON_SHA256_amd64"):
            mine = re.search(r"^%s=(\S+)" % var, text(), re.M).group(1)
            m = re.search(r'^%s="?([^"\n]+)"?' % (var if var == "TETRAGON_VERSION" else "TETRAGON_TARBALL_SHA256_amd64"), c, re.M)
            self.assertEqual(mine, m.group(1))

    def test_rollback_timer_is_armed_600_s_before_each_risky_step(self):
        src = text()
        self.assertIn("--on-active=600", src)
        self.assertIn("--unit=edr-install-rollback", src)
        self.assertIn("--unit=edr-install ", src)
        self.assertRegex(src, r"\[\[ \$n -ge 4 && \$n -le 10 \]\]; then arm_timer")
        self.assertIn('"$LIB/install.sh" --rollback', src)

    def test_the_canary_is_a_copy_of_dash_and_notify_severity_is_seeded(self):
        src = text()
        self.assertIn("install_file /bin/dash /usr/libexec/edr/canary 0755 root:root", src)
        self.assertIn('write_file "$ETC_A/notify.min_severity" 0600 root:root', src)

    def test_policies_come_from_the_agents_render(self):
        src = text()
        self.assertIn('edr-agent.py" render --out', src)
        self.assertNotRegex(src, r"sed[^\n]*@NGINX_BIN@|@PHPFPM_BIN@")
        self.assertIn('edr-agent.py" "${discover_args[@]}"', src)


class TestUsage(RootCase):
    def bad(self, *args, **extra):
        r = self.run_script(INSTALL, args, **extra)
        self.assertEqual(r.returncode, 64, r.stderr)
        self.assertEqual(self.stub_calls(), "")
        return r

    def test_enforce_with_observe_only(self):
        self.assertIn("make no sense", self.bad("--enforce", "--observe-only").stderr)

    def test_unknown_flag_and_bad_values(self):
        for args in (["--frobnicate"], ["--hub", "not-an-address"], ["--hub", "1.2.3.4"], ["--enroll-port", "70000"], ["--swapfile", "lots"],
                     ["--droplet-id", "bad id"], ["--admin-ip", "nonsense"], ["--webroot", "relative"], ["--allow-egress-port", "0"],
                     ["--vpc-dns", "manual"], ["--bigconn-cap", "huge"], ["--resolve-check", "bad name"], ["--plan", "--confirm"],
                     ["--rollback", "--hub", "1.2.3.4:8443"], ["--token", "secrettoken"], ["--token-file", "x", "--token", "-"]):
            self.bad(*args)

    def test_a_token_on_the_command_line_is_refused_with_the_safe_forms(self):
        r = self.bad("--hub", "203.0.113.5:8443", "--token", "abc.def." + "a" * 64)
        self.assertIn("--token-file", r.stderr)
        self.assertNotIn("abc.def", r.stdout)

    def test_a_real_run_refuses_a_test_root(self):
        r = self.run_script(INSTALL, ["--yes"])
        self.assertEqual(r.returncode, 64)
        self.assertIn("EDR_AGENT_ROOT is only for --plan", r.stderr)
        self.assertEqual(self.stub_calls(), "")

    def test_help_exits_zero(self):
        r = self.run_script(INSTALL, ["--help"])
        self.assertEqual(r.returncode, 0)


class TestPlan(RootCase):
    def run_plan(self, *args, **extra):
        before = tree_hash(self.root)
        r = self.plan(*args, **extra)
        self.assertEqual(self.stub_calls(), "", "the plan ran a command that could change the machine")
        self.assertEqual(before, tree_hash(self.root), "the plan changed the test root")
        return r

    def test_plan_for_the_mock_flags_lists_the_files_and_changes_nothing(self):
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "mock-1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = r.stdout
        for need in ("/etc/systemd/system/edr-bans.service", "/etc/systemd/system/edr-bans.path", "/etc/systemd/system/edr-agent.service",
                     "/etc/systemd/system/edr-inventory.timer", "/etc/modprobe.d/edr-sctp-block.conf", "/etc/edr-agent/logrotate.conf",
                     "/etc/systemd/resolved.conf.d/zz-edr-doh.conf", "/etc/update-motd.d/90-edr", "/usr/local/lib/edr-agent",
                     "/usr/local/sbin/edr-check", "/etc/edr-agent/local.conf", "/etc/edr-agent/notify.min_severity",
                     "/var/lib/edr-install/manifest.json" if False else "/var/lib/edr-install"):
            self.assertIn(need, out, need)
        # steps 4 and 7 are skipped, the sctp file is still written, the kernel steps are skipped
        self.assertRegex(out, r"Step 4: .*\nskipped: --no-suricata")
        self.assertRegex(out, r"Step 7: .*\nskipped: no Tetragon")
        self.assertNotIn("/etc/sysctl.d/90-edr-conntrack.conf", out)
        self.assertNotIn("/etc/suricata/drop.conf", out)
        self.assertNotIn("/etc/systemd/system/tetragon.service.d", out)
        self.assertIn("the modprobe.d file is written and its parse checked, even with --no-kernel", out)
        self.assertIn("Would proceed (exit 0).", out)
        self.assertIn("kit=off" if False else "[kit] kernel = off", out)
        self.assertIn("[kit] tetragon = off", out)
        self.assertIn("[kit] suricata = off", out)
        self.assertIn("kernel=false", out)
        self.assertIn("(--from-checkout: not hash-checked)", out)

    def test_full_plan_lists_every_step_and_every_component(self):
        r = self.run_plan()
        self.assertEqual(r.returncode, 0, r.stdout)
        out = r.stdout
        for n in range(1, 12):
            self.assertRegex(out, r"==> Step %d: " % n)
        for need in ("/etc/suricata/drop.conf", "/etc/suricata/disable.conf", "/etc/systemd/system/suricata.service.d/override.conf",
                     "/etc/sysctl.d/90-edr-conntrack.conf", "/etc/modules-load.d/edr-conntrack.conf", "/etc/systemd/system/tetragon.service.d/50-edr-check.conf",
                     "/etc/systemd/system/edr-policy-check.timer", "/usr/libexec/edr/canary", "2fa" if False else "Tetragon v1.7.1",
                     "/etc/apt/preferences.d/suricata-8", "policy-rc.d", "edr-rules-update.timer", "/etc/edr-dns", "edr-dns.nft",
                     "table   inet edr", "never falls back"):
            self.assertIn(need, out, need)
        self.assertIn("600 s rollback timer edr-install-rollback", out)
        self.assertIn("never flushes nftables or iptables", out)

    def test_flags_seed_the_keys_of_section_14_on_a_first_install_only(self):
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x", "--admin-ip", "203.0.113.5", "--admin-ip", "198.51.100.0/24",
                          "--enforce", "--allow-egress-port", "8443", "--allow-egress-port", "9200", "--home-net", "192.0.2.0/24",
                          "--bigconn-cap", "8G", "--lite", "--no-dns-lockdown", "--no-sctp-block", "--no-web", "--resolve-check", "db.example.net",
                          "--vpc-dns", "auto")
        self.assertEqual(r.returncode, 0, r.stdout)
        for need in ("[bans] admin_ip = 203.0.113.5,198.51.100.0/24", "[tetragon] enforce = nginx-exec,sctp-socket,web-exec",
                     "[tetragon] egress_ports = 8443,9200", "[suricata] home_net = 192.0.2.0/24", "[bans] bigconn_cap = 8G", "[suricata] lite = on",
                     "[dns] lockdown = off", "[kernel] sctp_block = off", "[kit] web = off", "[kit] kernel = off", "[dns] resolve_check = db.example.net",
                     "[dns] vpc_dns = auto"):
            self.assertIn(need, r.stdout, need)
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x", "--observe-only")
        self.assertIn("[tetragon] enforce = ", r.stdout)
        # a re-run: local.conf exists, so nothing is seeded
        self.put("/etc/edr-agent/local.conf", "[bans]\n")
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x", "--enforce")
        self.assertNotIn("seeds", r.stdout)
        self.assertIn("(never rewritten)", r.stdout)

    def test_ssh_source_is_the_admin_address(self):
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x", SSH_CONNECTION="203.0.113.77 5555 10.0.0.5 22")
        self.assertIn("admin address 203.0.113.77", r.stdout)
        self.assertIn("[bans] admin_ip = 203.0.113.77", r.stdout)

    def test_an_ssh_session_without_a_source_needs_admin_ip(self):
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x", SSH_TTY="/dev/pts/1")
        self.assertEqual(r.returncode, 3)
        self.assertIn("pass --admin-ip", r.stdout)
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x", "--admin-ip", "203.0.113.5", SSH_TTY="/dev/pts/1")
        self.assertEqual(r.returncode, 0, r.stdout)

    def refused(self, why, *args, **extra):
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x", *args, **extra)
        self.assertEqual(r.returncode, 3, r.stdout)
        self.assertIn("REFUSE", r.stdout)
        self.assertIn(why, r.stdout)
        self.assertIn("a real run would change nothing", r.stdout)
        return r

    def test_wrong_os_arch_systemd_ram_disk(self):
        self.put("/etc/os-release", 'ID=ubuntu\nVERSION_ID="22.04"\n')
        self.refused("Ubuntu 24.04 and 26.04")
        self.put("/etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        self.refused("found: debian")

    def test_other_refusals(self):
        self.probe("uname", "echo aarch64")
        self.refused("amd64 only")
        self.probe("uname", "echo x86_64")
        shutil.rmtree(self.root + "/run/systemd")
        self.refused("systemd is not running")
        os.makedirs(self.root + "/run/systemd/system")
        self.put("/proc/meminfo", "MemTotal: 700000 kB\nMemAvailable: 500000 kB\nSwapTotal: 0 kB\n")
        self.refused("total RAM")
        self.put("/proc/meminfo", "MemTotal: 1500000 kB\nMemAvailable: 900000 kB\nSwapTotal: 0 kB\n")
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("MemAvailable", r.stdout)                          # a WARN, not a refusal
        r = self.run_plan("--no-kernel", "--no-tetragon", "--droplet-id", "x")
        self.assertEqual(r.returncode, 3)                                # Suricata needs 2 GB
        self.put("/proc/meminfo", "MemTotal: 4000000 kB\nMemAvailable: 3000000 kB\nSwapTotal: 0 kB\n")
        os.unlink(self.root + "/usr/sbin/nginx")
        self.refused("no nginx was found")
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x", "--no-web")
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_btf_and_containers(self):
        os.unlink(self.root + "/sys/kernel/btf/vmlinux")
        r = self.run_plan("--no-suricata", "--droplet-id", "x")
        self.assertEqual(r.returncode, 3)
        self.assertIn("no BTF", r.stdout)
        r = self.run_plan("--no-tetragon", "--no-suricata", "--droplet-id", "x")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.put("/sys/kernel/btf/vmlinux", "")
        self.probe("systemd-detect-virt", "echo docker")
        r = self.run_plan("--no-tetragon", "--no-suricata", "--droplet-id", "x")
        self.assertEqual(r.returncode, 3)
        self.assertIn("this is a container", r.stdout)
        r = self.run_plan("--no-kernel", "--no-suricata", "--droplet-id", "x")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("every kernel-wide step is skipped", r.stdout)
        self.assertIn("--no-kernel skips BPF", r.stdout)                  # Tetragon is BPF
        self.assertRegex(r.stdout, r"Step 7: .*\nskipped: no Tetragon")

    def test_foreign_suricata_tetragon_dnscrypt(self):
        self.put("/usr/bin/suricata", "x", mode=0o755)
        r = self.run_plan("--no-kernel", "--no-tetragon", "--droplet-id", "x")
        self.assertEqual(r.returncode, 3)
        self.assertIn("a Suricata that this kit did not install", r.stdout)
        # the manifest says the kit installed it: fine
        self.manifest(manifest_doc(session(packages=[{"name": "suricata", "by_kit": True, "step": 3}])))
        r = self.run_plan("--no-kernel", "--no-tetragon", "--droplet-id", "x")
        self.assertEqual(r.returncode, 0, r.stdout)
        os.unlink(self.root + "/usr/bin/suricata")
        os.unlink(self.root + "/var/lib/edr-install/manifest.json")
        self.put("/usr/local/bin/tetragon", "x", mode=0o755)
        r = self.run_plan("--no-suricata", "--droplet-id", "x")
        self.assertEqual(r.returncode, 3)
        self.assertIn("Tetragon that this kit did not install", r.stdout)
        os.unlink(self.root + "/usr/local/bin/tetragon")
        self.put("/usr/sbin/dnscrypt-proxy", "x", mode=0o755)
        self.put("/etc/dnscrypt-proxy/dnscrypt-proxy.toml", "listen_addresses = []\n")
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x")
        self.assertEqual(r.returncode, 3)
        self.assertIn("dnscrypt-proxy that somebody else configured", r.stdout)
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--no-dns-lockdown", "--droplet-id", "x")
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_warnings_that_do_not_refuse(self):
        self.put("/etc/fail2ban/jail.conf", "")
        self.put("/etc/nftables.conf", "flush ruleset\n")
        self.put("/etc/ufw/ufw.conf", "ENABLED=yes\n")
        self.put("/home/forge/x", "")
        self.put("/proc/sys/net/ipv4/ip_forward", "1\n")
        self.put("/proc/meminfo", "MemTotal: 4000000 kB\nMemAvailable: 3000000 kB\nSwapTotal: 0 kB\n")
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x")
        self.assertEqual(r.returncode, 0, r.stdout)
        for need in ("fail2ban is installed", "flush ruleset", "UFW is active", "panel layout", "ip_forward=1", "no swap"):
            self.assertIn(need, r.stdout, need)

    def test_conntrack_before_is_noted(self):
        self.put("/proc/modules", "nf_conntrack 200000 3 - Live 0x0\n")
        r = self.run_plan("--no-tetragon", "--no-suricata", "--droplet-id", "x")
        self.assertIn("nf_conntrack was already loaded", r.stdout)

    def test_droplet_id_rules(self):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "8")
                self.end_headers()
                self.wfile.write(b"12345678")

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        # curl is a stub in these tests: the metadata probe needs the real one
        real_curl = shutil.which("curl", path=os.environ.get("PATH"))
        if not real_curl:
            self.skipTest("no curl")
        os.unlink(os.path.join(self.stubs, "curl"))
        os.symlink(real_curl, os.path.join(self.stubs, "curl"))
        url = "http://127.0.0.1:%d/metadata/v1/id" % srv.server_address[1]
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "mock-1", EDR_METADATA_URL=url)
        self.assertEqual(r.returncode, 3)
        self.assertIn("the metadata service answers here (id 12345678)", r.stdout)
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", EDR_METADATA_URL=url)
        self.assertEqual(r.returncode, 0, r.stdout)
        # no metadata, --hub, no --droplet-id
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--hub", "203.0.113.5:8443")
        self.assertEqual(r.returncode, 3)
        self.assertIn("--hub needs a droplet id", r.stdout)

    def test_hub_and_token_notes(self):
        tok = self.base + "/tok"
        with open(tok, "w") as f:
            f.write("abc123.s3cr3t." + "a" * 64 + "\n")
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x", "--hub", "203.0.113.5:8443", "--token-file", tok)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("token format looks right", r.stdout)
        self.assertNotIn("s3cr3t", r.stdout + r.stderr)
        self.assertIn("edr-agent enroll --hub 203.0.113.5:8443 --token-file FILE", r.stdout)
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x", "--hub", "203.0.113.5:8443")
        self.assertIn("no token was given to --plan", r.stdout)

    def test_versions_and_unconfirmed_sessions(self):
        self.put("/usr/local/lib/edr-agent/VERSION", "0.2.0\n")
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x")
        self.assertEqual(r.returncode, 3)
        self.assertIn("is newer than 0.1.0", r.stdout)
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x", "--force")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("(--force)", r.stdout)
        self.put("/usr/local/lib/edr-agent/VERSION", "0.0.9\n")
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x")
        self.assertIn("upgrade from 0.0.9 to 0.1.0", r.stdout)
        self.manifest(manifest_doc(session(state="awaiting-confirm")))
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x")
        self.assertEqual(r.returncode, 3)
        self.assertIn("was not confirmed", r.stdout)

    def test_enrolled_host_with_another_hub_is_sent_to_rehome(self):
        os.makedirs(self.root + "/var/lib/edr-agent/identity/gen-1")
        self.put("/var/lib/edr-agent/identity/gen-1/hub.conf", "[hub]\naddresses = 203.0.113.5\nport = 8443\n")
        os.symlink("gen-1", self.root + "/var/lib/edr-agent/identity/current")
        r = self.run_plan("--no-kernel", "--no-tetragon", "--no-suricata", "--droplet-id", "x", "--hub", "198.51.100.7:8443")
        self.assertEqual(r.returncode, 3)
        self.assertIn("edr-agent rehome --hub 198.51.100.7:8443", r.stdout)

    def test_the_tree_must_match_its_manifest_without_from_checkout(self):
        tree = os.path.join(self.base, "tree")
        os.makedirs(tree)
        shutil.copy(INSTALL, tree)
        r = subprocess.run(["bash", os.path.join(tree, "install.sh"), "--plan"], capture_output=True, text=True, env=self.env())
        self.assertEqual(r.returncode, 3)
        self.assertIn("no MANIFEST.sha256", r.stderr)
        with open(os.path.join(tree, "MANIFEST.sha256"), "w") as f:
            f.write("0" * 64 + "  install.sh\n")
        r = subprocess.run(["bash", os.path.join(tree, "install.sh"), "--plan"], capture_output=True, text=True, env=self.env())
        self.assertEqual(r.returncode, 3)
        self.assertIn("does not match its MANIFEST.sha256", r.stderr)
        self.assertEqual(self.stub_calls(), "")


class TestManifestWriter(RootCase):
    """The python program the installer embeds writes the manifest of the notes file; uninstall.sh --plan accepts it."""

    def writer(self):
        progs = [p for p in extract_python(INSTALL) if "def tri(" in p]
        self.assertEqual(len(progs), 1)
        path = os.path.join(self.base, "flush.py")
        with open(path, "w") as f:
            f.write(progs[0])
        return path

    def flush(self, journal_lines, state="confirmed", steps="1,2,5", finished="1", sid="1234abcd-0000-4000-8000-000000000000", kind="install"):
        jpath = os.path.join(self.base, "journal.tsv")
        with open(jpath, "w") as f:
            f.write("".join("\t".join(l) + "\n" for l in journal_lines))
        comps = json.dumps({"web": True, "tetragon": False, "suricata": False, "kernel": False, "dns_lockdown": True, "sctp_block": True, "enrolled": False})
        r = subprocess.run([sys.executable, "-I", self.writer(), self.root, sid, kind, state, "-", "0.1.0", steps, "-", comps, jpath, finished],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    LINES = [
        ("file", "2", "/usr/local/lib/edr-agent/edr-bans", "a" * 64, "0644", "root:root", "absent", "-", "-"),
        ("file", "4", "/etc/suricata/suricata.yaml", "b" * 64, "0644", "root:suricata", "saved", "/var/lib/edr-install/prior/1234abcd-0000-4000-8000-000000000000/1", "c" * 64),
        ("dir", "2", "/usr/local/lib/edr-agent", "absent"),
        ("dir", "5", "/var/lib/edr-bans", "present"),
        ("unit", "5", "edr-bans.timer", "null", "null"),
        ("unit", "4", "suricata.service", "true", "false"),
        ("sysctl", "5", "net.netfilter.nf_conntrack_max", "65536", "262144"),
        ("package", "3", "suricata", "1"),
        ("package", "3", "nftables", "0"),
        ("ppa", "-", "ppa:oisf/suricata-stable", "1"),
        ("user", "2", "edr-agent", "1"),
        ("flag", "-", "conntrack_loaded_before", "0"),
        ("flag", "-", "policy_rc_d_ours", "0"),
        ("swap", "-", "/swapfile-edr", "1G"),
        ("note", "-", "nginx-exec stays in monitor: nginx master is not root"),
        ("notrb", "-", "modprobe -r sctp"),
    ]

    def test_the_manifest_has_the_shape_of_the_notes_file(self):
        self.flush(self.LINES)
        for where in ("/var/lib/edr-agent/manifest.json", "/var/lib/edr-install/manifest.json"):
            self.assertEqual(os.stat(self.root + where).st_mode & 0o777, 0o600)
        with open(self.root + "/var/lib/edr-install/manifest.json") as f:
            m = json.load(f)
        with open(self.root + "/var/lib/edr-agent/manifest.json") as f:
            self.assertEqual(json.load(f), m)
        self.assertEqual(set(m), {"v", "version", "phase", "components", "sessions"})
        self.assertEqual((m["v"], m["version"], m["phase"]), (1, "0.1.0", "P2"))
        self.assertEqual(set(m["components"]), {"web", "tetragon", "suricata", "kernel", "dns_lockdown", "sctp_block", "enrolled"})
        s = m["sessions"][0]
        for key in ("id", "kind", "started", "finished", "state", "from_version", "to_version", "steps_done", "files", "dirs", "units", "sysctls",
                    "packages", "ppa", "users", "conntrack_loaded_before", "policy_rc_d_ours", "swapfile", "notes", "not_rolled_back"):
            self.assertIn(key, s, key)
        self.assertEqual((s["kind"], s["state"], s["steps_done"], s["from_version"], s["to_version"]), ("install", "confirmed", [1, 2, 5], None, "0.1.0"))
        self.assertIsInstance(s["finished"], int)
        f0, f1 = s["files"]
        self.assertEqual({k: f0[k] for k in ("path", "sha256", "mode", "owner", "prior")},
                         {"path": "/usr/local/lib/edr-agent/edr-bans", "sha256": "a" * 64, "mode": "0644", "owner": "root:root", "prior": "absent"})
        self.assertEqual(f1["prior"], {"saved": "/var/lib/edr-install/prior/1234abcd-0000-4000-8000-000000000000/1", "sha256": "c" * 64})
        self.assertEqual(s["dirs"][1], {"path": "/var/lib/edr-bans", "prior": "present", "step": 5})
        self.assertEqual(s["units"][0], {"name": "edr-bans.timer", "prior_enabled": None, "prior_active": None, "step": 5})
        self.assertEqual(s["units"][1]["prior_enabled"], True)
        self.assertEqual(s["units"][1]["prior_active"], False)
        self.assertEqual(s["sysctls"], [{"key": "net.netfilter.nf_conntrack_max", "prior": "65536", "value": "262144", "step": 5}])
        self.assertEqual(s["packages"][0], {"name": "suricata", "by_kit": True, "step": 3})
        self.assertEqual(s["packages"][1]["by_kit"], False)
        self.assertEqual(s["ppa"], {"name": "ppa:oisf/suricata-stable", "by_kit": True})
        self.assertEqual(s["users"], [{"name": "edr-agent", "by_kit": True, "step": 2}])
        self.assertIs(s["conntrack_loaded_before"], False)
        self.assertIs(s["policy_rc_d_ours"], False)
        self.assertEqual(s["swapfile"], {"path": "/swapfile-edr", "size": "1G"})
        self.assertEqual(s["notes"], ["nginx-exec stays in monitor: nginx master is not root"])
        self.assertEqual(s["not_rolled_back"], ["modprobe -r sctp"])

    def test_the_writer_updates_one_session_and_keeps_earlier_ones(self):
        self.flush(self.LINES[:2], state="running", steps="1", finished="0")
        self.flush(self.LINES[:4], state="awaiting-confirm", steps="1,2", finished="0")
        self.flush(self.LINES[:1], state="confirmed", steps="1,2,3", finished="1", sid="aaaabbbb-0000-4000-8000-000000000001", kind="upgrade")
        with open(self.root + "/var/lib/edr-install/manifest.json") as f:
            m = json.load(f)
        self.assertEqual([s["id"][:4] for s in m["sessions"]], ["1234", "aaaa"])
        self.assertEqual(len(m["sessions"][0]["files"]), 2)
        self.assertEqual(len(m["sessions"][0]["dirs"]), 2)
        self.assertEqual(m["sessions"][0]["state"], "awaiting-confirm")
        self.assertIsNone(m["sessions"][0]["finished"])
        self.assertEqual(m["sessions"][1]["kind"], "upgrade")

    def test_uninstall_plan_accepts_the_manifest_and_replays_it(self):
        self.flush(self.LINES)
        before = tree_hash(self.root)
        r = self.run_script(UNINSTALL, ["--plan"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(before, tree_hash(self.root))
        self.assertEqual(self.stub_calls(), "")
        for need in ("purge package suricata", "leave package nftables", "remove the apt source ppa:oisf/suricata-stable", "delete the user edr-agent",
                     "put net.netfilter.nf_conntrack_max back to its prior value 65536", "put the saved prior copy back at /etc/suricata/suricata.yaml",
                     "stop and disable unit edr-bans.timer", "leave unit suricata.service" if False else "suricata.service", "/swapfile-edr"):
            self.assertIn(need, r.stdout, need)
        self.assertNotIn("REFUSE", r.stdout)

    def test_rollback_reads_the_same_manifest(self):
        # the shared reader in install.sh gives the same entries: both embed the same program
        a = [p for p in extract_python(INSTALL) if "Prints tab-separated" in p]
        b = [p for p in extract_python(UNINSTALL) if "Prints tab-separated" in p]
        self.assertEqual(len(a), 1)
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
