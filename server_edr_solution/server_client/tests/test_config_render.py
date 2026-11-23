import contextlib
import glob
import io
import json
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_daemon_support import Tmp, cfgmod, CODE                          # noqa: E402
from edragent import cli, render                                           # noqa: E402

try:
    import yaml                      # tests may use PyYAML to cross-check the agent's own small parser
except ImportError:
    yaml = None

TEMPLATES = os.path.join(CODE, "..", "tetragon", "policies")


def slurp(path):
    with open(path) as f:
        return f.read()

ONE = "[sites]\nnginx_bin = /usr/sbin/nginx\nphpfpm_bins = /usr/sbin/php-fpm8.3\nphp_cli_bins = /usr/bin/php8.3\nvpc_cidr = 10.116.0.0/20\n" \
      "web_users = www-data\nweb_roots = /var/www/app/public\n"
THREE = "[sites]\nnginx_bin = /usr/sbin/nginx\nphpfpm_bins = /usr/sbin/php-fpm8.1, /usr/sbin/php-fpm8.3, /usr/sbin/php-fpm8.5\n" \
        "php_cli_bins = /usr/bin/php8.1, /usr/bin/php8.3, /usr/bin/php8.5\nvpc_cidr = 10.116.0.0/20\n[tetragon]\negress_ports = 8443, 9200\n"
HOME = "[sites]\nnginx_bin = /usr/sbin/nginx\nphpfpm_bins = /usr/sbin/php-fpm8.3\nphp_cli_bins = /usr/bin/php8.3\nweb_users = forge\n" \
       "web_roots = /home/forge/site/public, /home/forge/site/storage/app/public\n"


class RenderCase(Tmp):
    def render(self, text):
        cfg = self.conf(text)
        self.assertFalse(cfg.errors, cfg.errors)
        return render.render_all(self.paths, cfg, TEMPLATES)

    def names(self):
        return sorted(os.path.basename(p)[:-5] for p in glob.glob(os.path.join(TEMPLATES, "*.yaml")))


class TestRenderPolicies(RenderCase):
    def test_every_shipped_policy_renders_for_a_typical_host(self):
        for label, text in (("one", ONE), ("three", THREE), ("home, no vpc", HOME)):
            files, skipped, notes = self.render(text)
            self.assertEqual(skipped, {}, label)
            policies = {k: v for k, v in files.items() if k.startswith("tetragon.tp.d/")}
            self.assertEqual(len(policies), len(self.names()), label)
            for rel, body in policies.items():
                self.assertNotRegex(body, r"@[A-Z_]+@", "%s %s" % (label, rel))
                self.assertNotIn("@", body, "%s %s" % (label, rel))
                self.assertTrue(body.endswith("\n"))
                name = os.path.basename(rel)[:-5]
                problems, follow = render.check_policy(None, body)
                self.assertEqual(problems, [], "%s %s" % (label, rel))

    def test_files_are_named_edr_dash_policy(self):
        files, _, _ = self.render(ONE)
        self.assertIn("tetragon.tp.d/edr-web-exec.yaml", files)
        self.assertIn("tetragon.tp.d/edr-canary.yaml", files)
        self.assertNotIn("tetragon.tp.d/edr-edr-canary.yaml", files)

    def test_rendered_policies_parse_stay_in_limits_and_hold_the_values(self):
        for text in (ONE, THREE, HOME):
            files, _, _ = self.render(text)
            ids = 0
            for rel, body in files.items():
                if not rel.startswith("tetragon.tp.d/"):
                    continue
                doc = render.parse_policy(body)
                problems, follow = render.analyse(doc)
                self.assertEqual(problems, [], rel)
                ids += len(follow)
                for hook in doc["spec"]["kprobes"]:
                    self.assertLessEqual(len(hook.get("selectors", [])), 5)
            self.assertLessEqual(ids, 64)
        files, _, _ = self.render(THREE)
        doc = render.parse_policy(files["tetragon.tp.d/edr-web-exec.yaml"])
        vals = doc["spec"]["kprobes"][0]["selectors"][0]["matchBinaries"][0]["values"]
        for b in ("/usr/sbin/php-fpm8.1", "/usr/sbin/php-fpm8.3 (deleted)", "/usr/sbin/php-fpm8.5", "/usr/sbin/nginx", "/usr/sbin/nginx (deleted)"):
            self.assertIn(b, vals)
        allow = doc["spec"]["kprobes"][0]["selectors"][0]["matchArgs"][0]["values"]
        self.assertIn("/usr/sbin/sendmail", allow)
        self.assertIn("/usr/sbin/php-fpm8.5", allow)

    def test_a_line_is_repeated_per_value_and_left_out_without_one(self):
        t = '      values:\n        - "@A@"\n        - "@A@ (deleted)"\n        - "x"\n        - "@B@"\n# note @A@ here\n'
        out = render.render_text(t, {"A": ["/a", "/b"], "B": []})
        self.assertEqual(out, '      values:\n        - "/a"\n        - "/b"\n        - "/a (deleted)"\n        - "/b (deleted)"\n        - "x"\n# note A here\n'.replace(
            '        - "/a"\n        - "/b"\n        - "/a (deleted)"\n        - "/b (deleted)"\n', '        - "/a"\n        - "/b"\n        - "/a (deleted)"\n        - "/b (deleted)"\n'))

    def test_values_are_quoted_for_yaml(self):
        out = render.render_text('- "@A@"\n', {"A": ['/odd/"quote\\path']})
        self.assertEqual(out, '- "/odd/\\"quote\\\\path"\n')
        self.assertEqual(render.parse_policy(out), ['/odd/"quote\\path'])
        if yaml is not None:
            self.assertEqual(yaml.safe_load(out), ['/odd/"quote\\path'])

    def test_egress_ports_and_vpc_land_in_web_connect(self):
        files, _, _ = self.render(THREE)
        body = files["tetragon.tp.d/edr-web-connect.yaml"]
        self.assertIn('"8443"', body)
        self.assertIn('"9200"', body)
        self.assertIn('"10.116.0.0/20"', body)
        files, _, _ = self.render(HOME)
        self.assertNotIn("10.116", files["tetragon.tp.d/edr-web-connect.yaml"])
        self.assertIn('"127.0.0.0/8"', files["tetragon.tp.d/edr-web-connect.yaml"])        # the fixed addresses stay

    def test_web_exec_allow_from_local_conf_joins_the_builtins(self):
        files, _, _ = self.render(ONE + "[tetragon]\nweb_exec_allow = /usr/bin/convert, /usr/sbin/nginx\n")
        body = files["tetragon.tp.d/edr-web-exec.yaml"]
        self.assertEqual(body.count('"/usr/bin/convert"'), 1)
        self.assertIn('"/usr/sbin/sendmail"', body)

    def test_a_component_switched_off_leaves_its_policies_out(self):
        files, skipped, _ = self.render(ONE + "[kit]\nweb = off\n")
        left = {os.path.basename(k)[:-5] for k in files if k.startswith("tetragon.tp.d/")}
        for web in ("web-exec", "web-connect", "web-write-code", "nginx-exec", "env-read", "fork-watch"):
            self.assertNotIn("edr-" + web, left)
            self.assertEqual(skipped[web], "[kit] web is off")
        self.assertIn("edr-sctp-socket", left)
        self.assertIn("edr-canary", left)
        files, skipped, _ = self.render(ONE + "[kit]\ntetragon = off\n")
        self.assertEqual([k for k in files if k.startswith("tetragon.tp.d/")], [])
        self.assertEqual(len(skipped), len(self.names()))
        self.assertIn("edr-agent/notify.min_severity", files)

    def test_a_policy_with_no_binary_to_match_is_left_out_not_broken(self):
        files, skipped, _ = self.render("[sites]\nweb_roots = /var/www\n")                 # nothing discovered yet
        self.assertIn("nginx-exec", skipped)
        self.assertIn("NGINX_BIN", skipped["nginx-exec"])
        self.assertNotIn("tetragon.tp.d/edr-nginx-exec.yaml", files)
        for rel, body in files.items():
            if rel.startswith("tetragon.tp.d/"):
                self.assertEqual(render.check_policy(None, body)[0], [], rel)
        files, skipped, _ = self.render("[sites]\nnginx_bin = /usr/sbin/nginx\n")           # nginx but no php-fpm
        self.assertIn("tetragon.tp.d/edr-nginx-exec.yaml", files)
        self.assertIn("tetragon.tp.d/edr-web-exec.yaml", files)

    def test_no_placeholder_survives_even_in_comments(self):
        files, _, _ = self.render(ONE)
        for rel, body in files.items():
            self.assertNotRegex(body, r"@[A-Z_]+@", rel)

    @unittest.skipIf(yaml is None, "PyYAML is only used to cross-check the small parser")
    def test_the_small_parser_agrees_with_pyyaml_on_every_template_and_rendered_policy(self):
        for path in sorted(glob.glob(os.path.join(TEMPLATES, "*.yaml"))):
            with open(path) as f:
                text = f.read()
            raw = text.replace("@", "AT_")
            self.assertEqual(render.parse_policy(raw), yaml.safe_load(raw), path)
        for text in (ONE, THREE, HOME):
            files, _, _ = self.render(text)
            for rel, body in files.items():
                if rel.startswith("tetragon.tp.d/"):
                    self.assertEqual(render.parse_policy(body), yaml.safe_load(body), rel)

    def test_the_small_parser(self):
        doc = render.parse_policy('a: 1\nb:\n- "x" # note\n- y\nc:\n  - k: [0, 1]\n    v: true\n  - "q: r"\nd:\n  e:\n  f: "a # b"\n')
        self.assertEqual(doc, {"a": 1, "b": ["x", "y"], "c": [{"k": [0, 1], "v": True}, "q: r"], "d": {"e": None, "f": "a # b"}})
        for bad in ("a: {x: 1}\n", "a: 'x'\n", "a: |\n  text\n", "a: [1\n", "\tx: 1\n", "a: 1\na: 2\n", "  a: 1\nb: 2\n", "", "a: \"x\n"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                render.parse_policy(bad)

    def test_empty_lists_and_broken_templates_are_caught_without_pyyaml(self):
        problems, _ = render.check_policy(None, 'kind: TracingPolicy\nspec:\n  kprobes:\n  - call: "x"\n    selectors:\n    - matchArgs:\n      - index: 0\n'
                                          '        operator: "Equal"\n        values:\n')
        self.assertIn("x: an empty values list", problems)
        self.assertTrue(render.check_policy(None, "kind: [\n")[0])
        self.assertIn("a placeholder is left", render.check_policy(None, 'kind: TracingPolicy\nx: "@A@"\n')[0])

    def test_the_agent_code_has_no_third_party_import(self):
        with open(render.__file__) as f:
            text = f.read()
        self.assertNotRegex(text, r"(?m)^\s*(import|from)\s+yaml\b")


class TestRefusals(RenderCase):
    def many(self, n):
        fpm = ", ".join("/usr/sbin/php-fpm8.%d" % i for i in range(n))
        return "[sites]\nnginx_bin = /usr/sbin/nginx\nphpfpm_bins = %s\n" % fpm

    def test_too_many_php_fpm_binaries_for_the_followchildren_budget_are_refused(self):
        with self.assertRaises(render.RenderError) as cm:
            self.render(self.many(12))
        self.assertEqual(cm.exception.key, "[sites] phpfpm_bins")
        self.assertIn("64", str(cm.exception))
        self.render(self.many(4))                                                           # still fine

    def test_too_long_a_list_names_its_key(self):
        allow = ", ".join("/opt/tool%d" % i for i in range(80))
        with self.assertRaises(render.RenderError) as cm:
            self.render(ONE + "[tetragon]\nweb_exec_allow = %s\n" % allow)
        self.assertEqual(cm.exception.key, "[tetragon] web_exec_allow")
        ports = ", ".join(str(2000 + i) for i in range(80))
        with self.assertRaises(render.RenderError) as cm:
            self.render(ONE + "[tetragon]\negress_ports = %s\n" % ports)
        self.assertEqual(cm.exception.key, "[tetragon] egress_ports")

    def test_a_template_that_breaks_a_limit_is_refused_and_nothing_is_written(self):
        d = os.path.join(self.root, "tpl")
        selectors = "".join('    - matchArgs:\n      - index: 0\n        operator: "Equal"\n        values:\n        - "x"\n' for _ in range(6))
        self.write(os.path.join(d, "toomany.yaml"), 'apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: "toomany"\n'
                   'spec:\n  kprobes:\n  - call: "security_file_open"\n    syscall: false\n    args:\n    - index: 0\n      type: "file"\n'
                   '    selectors:\n' + selectors)
        cfg = self.conf(ONE)
        with self.assertRaises(render.RenderError) as cm:
            render.render_policies(d, cfg)
        self.assertIn("6 selectors", str(cm.exception))

    def test_apply_config_exits_3_and_keeps_everything(self):
        self.write(self.paths.local_conf, self.many(12))
        out = []
        code = cfgmod.apply_config(self.paths, out=out.append)
        self.assertEqual(code, 3)
        self.assertTrue(any("[sites] phpfpm_bins" in l for l in out))
        self.assertIn("running configuration is kept", "\n".join(out))
        self.assertFalse(os.path.exists(self.paths.tetragon_tp_dir))
        self.assertFalse(os.path.exists(self.paths.config_good))

    def test_the_render_command_refuses_the_same_way(self):
        self.write(self.paths.local_conf, ONE + "[tetragon]\nweb_exec_allow = %s\n" % ", ".join("/opt/t%d" % i for i in range(80)))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.cmd_render(type("A", (), {"out": os.path.join(self.root, "stage")})(), self.paths)
        self.assertEqual(code, 3)
        self.assertIn("[tetragon] web_exec_allow", out.getvalue())
        self.assertFalse(os.path.exists(os.path.join(self.root, "stage")))


class TestDropinAndCredential(RenderCase):
    def enroll(self, addresses, dropin=True):
        d = os.path.join(self.paths.identity_dir, "gen-1")
        os.makedirs(d)
        self.write(os.path.join(d, "hub.conf"), "[hub]\naddresses = %s\nport = 8443\nenroll_port = 8444\nhost_uuid = x\nca_sha256 = %s\n" % (",".join(addresses), "a" * 64))
        os.symlink("gen-1", os.path.join(self.paths.identity_dir, "current"))
        if dropin:                                    # what root wrote at enrollment
            self.write(self.paths.dropin_path, "[Service]\nIPAddressAllow=\nIPAddressAllow=%s\n" % " ".join(addresses))

    def test_local_mode_has_no_dropin(self):
        files, _, _ = self.render(ONE)
        self.assertNotIn("systemd/edr-agent.service.d/10-hub.conf", files)

    def test_enrolled_hub_addresses_become_ipaddressallow(self):
        self.enroll(["203.0.113.5", "198.51.100.9"])
        files, _, _ = self.render(ONE)
        self.assertEqual(files["systemd/edr-agent.service.d/10-hub.conf"], "[Service]\nIPAddressAllow=\nIPAddressAllow=203.0.113.5 198.51.100.9\n")
        self.assertEqual(render.render_dropin([]), None)

    def test_the_agents_own_hub_conf_is_not_trusted_for_the_allowlist(self):
        self.enroll(["203.0.113.5"])
        with open(os.path.join(self.paths.identity_dir, "gen-1", "hub.conf"), "w") as f:         # the agent edits its own file
            f.write("[hub]\naddresses = 198.51.100.66\nport = 8443\nenroll_port = 8444\nhost_uuid = x\nca_sha256 = %s\n" % ("a" * 64))
        files, _, _ = self.render(ONE)
        self.assertEqual(files["systemd/edr-agent.service.d/10-hub.conf"], "[Service]\nIPAddressAllow=\nIPAddressAllow=203.0.113.5\n")
        self.assertNotIn("198.51.100.66", "".join(files.values()))

    def test_an_identity_with_no_dropin_gives_none_and_a_garbled_one_is_cleaned(self):
        self.enroll(["203.0.113.5"], dropin=False)
        self.assertEqual(self.render(ONE)[0].get("systemd/edr-agent.service.d/10-hub.conf"), None)
        self.write(self.paths.dropin_path, "[Service]\nIPAddressAllow=\nIPAddressAllow=203.0.113.5 not-an-ip 10.0.0.1/8 2001:db8::5\n")
        self.assertEqual(render.hub_addresses(self.paths), ["203.0.113.5", "2001:db8::5"])
        os.unlink(self.paths.dropin_path)
        os.symlink("/etc/passwd", self.paths.dropin_path)
        self.assertEqual(render.hub_addresses(self.paths), [])

    def test_notify_min_severity(self):
        files, _, _ = self.render(ONE + "[notify]\nmin_severity = CRITICAL\n")
        self.assertEqual(files["edr-agent/notify.min_severity"], "CRITICAL\n")

    def test_staging_files_have_the_right_modes(self):
        self.enroll(["203.0.113.5"])
        files, _, _ = self.render(ONE)
        stage = os.path.join(self.root, "stage")
        render.write_staging(files, stage)
        self.assertEqual(oct(os.stat(os.path.join(stage, "tetragon.tp.d", "edr-web-exec.yaml")).st_mode & 0o777), "0o600")
        self.assertEqual(oct(os.stat(os.path.join(stage, "edr-agent", "notify.min_severity")).st_mode & 0o777), "0o600")
        self.assertEqual(oct(os.stat(os.path.join(stage, "systemd", "edr-agent.service.d", "10-hub.conf")).st_mode & 0o777), "0o644")


class TestApplyConfig(RenderCase):
    def run_apply(self, check=False, **kw):
        out = []
        code = cfgmod.apply_config(self.paths, check_only=check, out=out.append, kill=lambda p, s: out.append("kill %d %d" % (p, s)), **kw)
        return code, "\n".join(out)

    def tp(self):
        return sorted(os.listdir(self.paths.tetragon_tp_dir)) if os.path.isdir(self.paths.tetragon_tp_dir) else []

    def test_apply_swaps_the_rendered_files_into_the_target_directories(self):
        self.write(self.paths.local_conf, ONE)
        code, out = self.run_apply()
        self.assertEqual(code, 0, out)
        self.assertEqual(len(self.tp()), len(self.names()))
        self.assertIn("edr-web-exec.yaml", self.tp())
        body = slurp(os.path.join(self.paths.tetragon_tp_dir, "edr-web-exec.yaml"))
        self.assertIn('"/usr/sbin/php-fpm8.3"', body)
        self.assertEqual(oct(os.stat(os.path.join(self.paths.tetragon_tp_dir, "edr-web-exec.yaml")).st_mode & 0o777), "0o600")
        self.assertEqual(slurp(self.paths.notify_min_severity), "HIGH\n")
        self.assertIn("changed: sites.nginx_bin (empty) -> /usr/sbin/nginx", out)
        self.assertIn("new file: " + os.path.join(self.paths.tetragon_tp_dir, "edr-web-exec.yaml"), out)
        self.assertFalse([n for n in os.listdir(self.paths.tetragon_tp_dir) if n.startswith(".edr-new")])
        self.assertTrue(os.path.exists(self.paths.config_good))

    def test_the_second_run_changes_nothing_and_a_changed_key_rewrites_only_what_changed(self):
        self.write(self.paths.local_conf, ONE)
        self.run_apply()
        code, out = self.run_apply()
        self.assertEqual(code, 0)
        self.assertNotIn("changed file", out)
        self.assertNotIn("new file", out)
        self.assertIn("no change", out)
        self.assertNotIn("would run: tetra", out)
        self.write(self.paths.local_conf, ONE.replace("php-fpm8.3\n", "php-fpm8.3, /usr/sbin/php-fpm8.5\n"))
        code, out = self.run_apply()
        changed = re.findall(r"changed file: .*/(edr-[a-z-]+\.yaml)", out)
        self.assertIn("edr-web-exec.yaml", changed)
        self.assertNotIn("edr-sctp-socket.yaml", changed)
        self.assertNotIn("edr-canary.yaml", changed)

    def test_check_changes_nothing(self):
        self.write(self.paths.local_conf, ONE)
        code, out = self.run_apply(check=True)
        self.assertEqual(code, 0)
        self.assertIn("new file: " + os.path.join(self.paths.tetragon_tp_dir, "edr-web-exec.yaml"), out)
        self.assertIn("check only", out)
        self.assertFalse(os.path.exists(self.paths.tetragon_tp_dir))
        self.assertFalse(os.path.exists(self.paths.notify_min_severity))
        self.assertFalse(os.path.exists(self.paths.config_good))
        before = sorted(os.listdir(self.root))
        self.run_apply(check=True)
        self.assertEqual(sorted(os.listdir(self.root)), before)

    def test_a_policy_left_out_later_is_removed_and_foreign_files_are_not(self):
        self.write(self.paths.local_conf, ONE)
        self.run_apply()
        self.write(os.path.join(self.paths.tetragon_tp_dir, "privilege-escalation.yaml"), "laptop policy\n")
        self.write(os.path.join(self.paths.tetragon_tp_dir, "edr-gone.yaml"), "stale\n")
        self.write(self.paths.local_conf, ONE + "[kit]\nweb = off\n")
        code, out = self.run_apply()
        self.assertEqual(code, 0)
        left = self.tp()
        self.assertNotIn("edr-web-exec.yaml", left)
        self.assertNotIn("edr-gone.yaml", left)
        self.assertIn("privilege-escalation.yaml", left)
        self.assertIn("edr-sctp-socket.yaml", left)
        self.assertIn("removed file", out)
        self.assertIn("left out: policy web-exec ([kit] web is off)", out)

    def test_php_fpm_restart_is_printed_never_run(self):
        self.write(self.paths.local_conf, ONE)
        calls = []
        code, out = self.run_apply(runner=lambda *a, **k: calls.append(a))
        self.assertIn("restart (not reload) php-fpm", out)
        self.assertIn("systemctl restart php8.3-fpm", out)
        self.assertEqual(calls, [])
        self.write(self.paths.local_conf, ONE.replace("web_roots = /var/www/app/public", "web_roots = /var/www/other"))
        code, out = self.run_apply()
        self.assertNotIn("restart (not reload) php-fpm", out)                                 # no policy changed

    def test_reload_commands_are_printed_under_a_dev_root_and_run_without_one(self):
        d = os.path.join(self.paths.identity_dir, "gen-1")
        os.makedirs(d)
        self.write(os.path.join(d, "hub.conf"), "[hub]\naddresses = 203.0.113.5\nport = 8443\nenroll_port = 8444\nhost_uuid = x\nca_sha256 = %s\n" % ("a" * 64))
        os.symlink("gen-1", os.path.join(self.paths.identity_dir, "current"))
        self.write(self.paths.dropin_path, "[Service]\nIPAddressAllow=\nIPAddressAllow=198.51.100.9\n")     # root's record of the hub
        self.write(self.paths.local_conf, ONE)
        calls = []
        code, out = self.run_apply(runner=lambda *a, **k: calls.append(a))
        self.assertEqual(code, 0)
        self.assertEqual(calls, [])
        self.assertNotIn("daemon-reload", out)                         # the drop-in is root's own record: apply-config leaves it as it is
        self.assertIn("would run: tetra tracingpolicy list", out)
        self.assertEqual(slurp(self.paths.dropin_path), "[Service]\nIPAddressAllow=\nIPAddressAllow=198.51.100.9\n")
        # without a dev root the commands run (here with a fake runner, as root, and no sleeping)
        self.write(self.paths.local_conf, ONE.replace("php-fpm8.3\n", "php-fpm8.3, /usr/sbin/php-fpm8.5\n"))
        self.paths.dev = False
        self.write(self.paths.pid_file, "4242\n")
        ran = []

        class P:
            returncode, stdout, stderr = 0, "edr-web-exec enabled\n", ""
        with mock.patch("os.geteuid", return_value=0):
            code, out = self.run_apply(runner=lambda argv, **k: ran.append(argv) or P(), sleep=lambda s: None)
        self.assertEqual(code, 0, out)
        self.assertEqual(ran, [["tetra", "tracingpolicy", "list"]])
        self.assertIn("running: tetra tracingpolicy list", out)
        self.assertIn("kill", out)                                                             # and the agent is told to re-read local.conf if it runs

    def test_a_failed_reload_command_is_exit_2(self):
        self.write(self.paths.local_conf, ONE)
        self.paths.dev = False

        class P:
            returncode, stdout, stderr = 1, "", "boom"
        with mock.patch("os.geteuid", return_value=0):
            code, out = self.run_apply(runner=lambda argv, **k: P(), sleep=lambda s: None)
        self.assertEqual(code, 2)
        self.assertIn("failed: tetra tracingpolicy list (exit 1)", out)

    def test_a_failed_swap_puts_the_old_files_back(self):
        self.write(self.paths.local_conf, ONE)
        self.run_apply()
        before = {n: slurp(os.path.join(self.paths.tetragon_tp_dir, n)) for n in self.tp()}
        self.write(self.paths.local_conf, ONE.replace("php-fpm8.3\n", "php-fpm8.3, /usr/sbin/php-fpm8.5\n"))
        real = cfgmod._install_file
        count = []

        def flaky(path, text, mode):
            count.append(path)
            if len(count) == 3:
                raise OSError("disk full")
            return real(path, text, mode)
        with mock.patch.object(cfgmod, "_install_file", flaky):
            code, out = self.run_apply()
        self.assertEqual(code, 2)
        self.assertIn("put back", out)
        after = {n: slurp(os.path.join(self.paths.tetragon_tp_dir, n)) for n in self.tp()}
        self.assertEqual(after, before)

    def test_invalid_config_renders_nothing(self):
        self.write(self.paths.local_conf, "[bans]\nauto_ban = bogus\n")
        code, out = self.run_apply()
        self.assertEqual(code, 3)
        self.assertFalse(os.path.exists(self.paths.tetragon_tp_dir))


class TestRenderCommand(RenderCase):
    def test_render_out_writes_only_into_the_directory(self):
        self.write(self.paths.local_conf, ONE)
        stage = os.path.join(self.root, "stage")
        out = io.StringIO()
        old = os.environ.get("EDR_AGENT_ROOT")
        os.environ["EDR_AGENT_ROOT"] = self.root
        try:
            with contextlib.redirect_stdout(out):
                code = cli.main(["render", "--out", stage])
        finally:
            os.environ.pop("EDR_AGENT_ROOT", None) if old is None else os.environ.__setitem__("EDR_AGENT_ROOT", old)
        self.assertEqual(code, 0, out.getvalue())
        self.assertTrue(os.path.exists(os.path.join(stage, "tetragon.tp.d", "edr-nginx-exec.yaml")))
        self.assertFalse(os.path.exists(self.paths.tetragon_tp_dir))
        self.assertFalse(os.path.exists(self.paths.notify_min_severity))
        self.assertIn("rendered ", out.getvalue())

    def test_render_needs_out(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["render"]), 64)


if __name__ == "__main__":
    unittest.main()
