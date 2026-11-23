import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_daemon_support import Tmp, cfgmod, CODE            # noqa: E402

# Every key of the table in client PLAN section 14.
SECTION_14_KEYS = """
sites.web_users sites.web_roots sites.nginx_bin sites.phpfpm_bins sites.php_cli_bins sites.vpc_cidr sites.extra_addresses
bans.admin_ip bans.allow_cidr bans.auto_ban bans.hub_bans bans.feeds bans.proxy_mode bans.bigconn_bytes bans.bigconn_cap
thresholds.ssh_fail thresholds.tripwire thresholds.suricata thresholds.window_update thresholds.bigconn_repeat
thresholds.suricata_sigs thresholds.ban_budget_per_hour thresholds.ban_max_active thresholds.ban_ladder thresholds.ban_memory
tetragon.enforce tetragon.egress_ports tetragon.web_exec_allow suricata.lite suricata.sslbl suricata.home_net kernel.sctp_block
kit.web kit.tetragon kit.suricata kit.kernel diskguard.stop_suricata dns.lockdown dns.lock_forwarded dns.block_doh_ips
dns.vpc_dns dns.resolve_check agent.redact agent.payload agent.args agent.event_budget_per_hour agent.access_ring_minutes
agent.access_ring_lines agent.nginx_info_log agent.laravel_log agent.login_route agent.sshd_password_auth agent.dns_telemetry
agent.rehome_confirm_timeout notify.min_severity response.auto_restart_nginx isolate.allow
""".split()


class TestConfigTable(unittest.TestCase):
    def test_every_key_of_section_14_is_known(self):
        known = {"%s.%s" % k for k in cfgmod.SCHEMA}
        self.assertEqual(set(SECTION_14_KEYS), known)

    def test_defaults_match_the_plan(self):
        c = cfgmod.defaults()
        self.assertEqual(c.get("thresholds", "ssh_fail"), (5, 600))
        self.assertEqual(c.get("thresholds", "tripwire"), (5, 300))
        self.assertEqual(c.get("thresholds", "suricata"), (3, 600))
        self.assertEqual(c.get("thresholds", "bigconn_repeat"), (2, 3600))
        self.assertEqual(c.get("thresholds", "ban_ladder"), [3600, 21600, 86400, 604800])
        self.assertEqual(c.get("thresholds", "ban_memory"), 14 * 86400)
        self.assertEqual(c.get("thresholds", "ban_budget_per_hour"), 30)
        self.assertEqual(c.get("thresholds", "ban_max_active"), 1000)
        self.assertEqual(c.get("bans", "bigconn_bytes"), 4 << 30)
        self.assertEqual(c.get("bans", "bigconn_cap"), 0)
        self.assertEqual(c.get("bans", "auto_ban"), "on")
        self.assertEqual(c.get("bans", "proxy_mode"), "auto")
        self.assertEqual(c.get("tetragon", "enforce"), ["nginx-exec", "sctp-socket"])
        self.assertEqual(c.get("agent", "event_budget_per_hour"), 2000)
        self.assertEqual(c.get("agent", "access_ring_minutes"), 5)
        self.assertEqual(c.get("agent", "access_ring_lines"), 20000)
        self.assertEqual(c.get("agent", "payload"), "hex-head")
        self.assertEqual(c.get("agent", "args"), "redact")
        self.assertTrue(c.get("agent", "redact"))
        self.assertIsNone(c.get("agent", "sshd_password_auth"))
        self.assertEqual(c.get("agent", "rehome_confirm_timeout"), 300)
        self.assertEqual(c.get("notify", "min_severity"), "HIGH")
        self.assertFalse(c.get("response", "auto_restart_nginx"))
        self.assertEqual(c["bans"]["auto_ban"], "on")                 # mapping access, used by the ban engine
        self.assertFalse(c.invalid)

    def test_shipped_defaults_conf_parses_when_present(self):
        path = os.path.join(CODE, "..", "files", "defaults.conf")
        if not os.path.exists(path):
            self.skipTest("files/defaults.conf is not written yet")
        with open(path) as f:
            raw, errors = cfgmod.parse_text(f.read(), "defaults.conf")
        self.assertEqual(errors, [])
        for k, text in raw.items():
            cfgmod.parse_value(k[0], k[1], text)


class TestConfigStrict(Tmp):
    def bad(self, text, needle):
        c = self.conf(text)
        self.assertTrue(c.errors, text)
        self.assertIn(needle, " ".join(c.errors))
        return c

    def test_unknown_section_and_key(self):
        self.bad("[nonsense]\na = 1\n", "unknown section [nonsense]")
        self.bad("[bans]\nauto_bann = on\n", "[bans] auto_bann")

    def test_keys_are_case_sensitive(self):
        self.bad("[bans]\nAuto_Ban = on\n", "unknown key")

    def test_duplicates_are_errors(self):
        self.bad("[bans]\nauto_ban = on\nauto_ban = off\n", "auto_ban")
        self.bad("[bans]\nauto_ban = on\n[bans]\nproxy_mode = on\n", "bans")

    def test_default_section_is_not_special(self):
        self.bad("[DEFAULT]\nauto_ban = on\n", "unknown section")

    def test_wrong_types_name_the_key(self):
        self.bad("[bans]\nauto_ban = sometimes\n", "[bans] auto_ban")
        self.bad("[agent]\nredact = maybe\n", "[agent] redact")
        self.bad("[agent]\nevent_budget_per_hour = many\n", "event_budget_per_hour")
        self.bad("[thresholds]\nssh_fail = fast\n", "[thresholds] ssh_fail")
        self.bad("[thresholds]\nban_memory = 14\n", "ban_memory")

    def test_ranges(self):
        self.bad("[agent]\nevent_budget_per_hour = 0\n", "out of range")
        self.bad("[agent]\naccess_ring_minutes = 61\n", "out of range")
        self.bad("[thresholds]\nban_max_active = 20000\n", "out of range")
        self.bad("[tetragon]\negress_ports = 80, 70000\n", "egress_ports")
        self.bad("[tetragon]\negress_ports = 0\n", "egress_ports")

    def test_cidrs_must_be_clean(self):
        self.bad("[bans]\nallow_cidr = 10.0.0.1/8\n", "allow_cidr")          # host bits
        self.bad("[bans]\nallow_cidr = 010.0.0.0/8\n", "allow_cidr")         # leading zero
        self.bad("[bans]\nallow_cidr = 1.2.3.4/33\n", "allow_cidr")
        self.bad("[bans]\nallow_cidr = 1.2.3.4%eth0\n", "allow_cidr")
        self.bad("[sites]\nvpc_cidr = not-a-net\n", "vpc_cidr")
        self.bad("[sites]\nextra_addresses = 1.2.3.4/24\n", "extra_addresses")
        c = self.conf("[bans]\nallow_cidr = 203.0.113.0/24, 2001:db8::/32\nadmin_ip = 198.51.100.7\n")
        self.assertFalse(c.errors, c.errors)
        self.assertEqual(c.getlist("bans", "allow_cidr"), ["203.0.113.0/24", "2001:db8::/32"])
        self.assertEqual(c.getlist("bans", "admin_ip"), ["198.51.100.7/32"])

    def test_paths_must_be_absolute(self):
        self.bad("[sites]\nnginx_bin = nginx\n", "nginx_bin")
        self.bad("[sites]\nweb_roots = /var/www, relative/dir\n", "web_roots")
        self.bad("[sites]\nweb_roots = /var/www/../etc\n", "web_roots")
        c = self.conf("[sites]\nweb_roots = /var/www/a/public, /home/forge/site/public\nnginx_bin = /usr/sbin/nginx\n")
        self.assertFalse(c.errors)

    def test_login_route_and_names(self):
        self.bad("[agent]\nlogin_route = login\n", "login_route")
        self.bad("[sites]\nweb_users = Bad User\n", "web_users")
        self.bad("[tetragon]\nenforce = nginx exec\n", "enforce")

    def test_valid_file_applies_and_keeps_text_form(self):
        c = self.conf("# a comment\n[bans]\nauto_ban = observe\nproxy_mode = off\n[thresholds]\nssh_fail = 3 per 10m\n"
                      "ban_ladder = 30m, 2h\n[agent]\nredact = off\nsshd_password_auth = off\nevent_budget_per_hour = 50\n")
        self.assertFalse(c.errors)
        self.assertEqual(c.state, "local")
        self.assertEqual(c.get("bans", "auto_ban"), "observe")
        self.assertEqual(c.get("thresholds", "ssh_fail"), (3, 600))
        self.assertEqual(c.get("thresholds", "ban_ladder"), [1800, 7200])
        self.assertFalse(c.get("agent", "redact"))
        self.assertIs(c.get("agent", "sshd_password_auth"), False)
        self.assertEqual(c.get("agent", "event_budget_per_hour"), 50)

    def test_symlink_and_oversize_are_refused(self):
        target = self.write(os.path.join(self.root, "elsewhere.conf"), "[bans]\nauto_ban = off\n")
        os.symlink(target, self.paths.local_conf)
        c = cfgmod.load(self.paths)
        self.assertTrue(c.errors)
        self.assertEqual(c.get("bans", "auto_ban"), "on")
        os.unlink(self.paths.local_conf)
        self.write(self.paths.local_conf, "# " + "x" * (cfgmod.CONF_MAX_BYTES + 10) + "\n")
        c = cfgmod.load(self.paths)
        self.assertTrue(c.errors)

    def test_precedence_local_over_defaults_over_builtin(self):
        defaults = self.write(os.path.join(self.root, "d", "defaults.conf"), "[bans]\nauto_ban = observe\nproxy_mode = on\n")
        self.paths.lib_dir = os.path.dirname(defaults)
        self.write(self.paths.local_conf, "[bans]\nproxy_mode = off\n")
        c = cfgmod.load(self.paths)
        self.assertEqual(c.get("bans", "auto_ban"), "observe")        # defaults.conf beats the built-in
        self.assertEqual(c.get("bans", "proxy_mode"), "off")          # local.conf beats defaults.conf
        self.assertEqual(c.origin[("bans", "auto_ban")], "defaults.conf")
        self.assertEqual(c.origin[("bans", "proxy_mode")], "local.conf")
        self.assertEqual(c.origin[("bans", "hub_bans")], "builtin")

    def test_missing_defaults_conf_is_not_fatal(self):
        self.paths.lib_dir = os.path.join(self.root, "empty")
        os.makedirs(self.paths.lib_dir)
        c = cfgmod.load(self.paths)
        self.assertFalse(c.errors)
        self.assertFalse(c.warnings)


class TestLastGood(Tmp):
    def test_last_good_copy_is_used_when_the_file_breaks(self):
        self.write(self.paths.local_conf, "[bans]\nauto_ban = observe\n")
        good = cfgmod.load(self.paths, save_good=True)
        self.assertEqual(good.state, "local")
        self.assertTrue(os.path.exists(self.paths.config_good))
        self.write(self.paths.local_conf, "[bans]\nauto_ban = bogus\n")
        c = cfgmod.load(self.paths, save_good=True)
        self.assertTrue(c.errors)
        self.assertEqual(c.state, "last-good")
        self.assertEqual(c.get("bans", "auto_ban"), "observe")
        with open(self.paths.config_good) as f:
            self.assertIn("observe", f.read())            # the bad file did not overwrite the good copy

    def test_without_a_good_copy_the_defaults_are_used(self):
        self.write(self.paths.local_conf, "[nope]\n")
        c = cfgmod.load(self.paths)
        self.assertEqual(c.state, "defaults")
        self.assertTrue(c.errors)
        self.assertEqual(c.get("bans", "auto_ban"), "on")

    def test_hash_follows_the_file(self):
        c0 = cfgmod.load(self.paths)
        self.write(self.paths.local_conf, "[bans]\nauto_ban = off\n")
        c1 = cfgmod.load(self.paths)
        self.write(self.paths.local_conf, "[bans]\nauto_ban = on\n")
        c2 = cfgmod.load(self.paths)
        self.assertEqual(len(c1.sha256), 64)
        self.assertEqual(len({c0.sha256, c1.sha256, c2.sha256}), 3)

    def test_update_from_changes_the_object_in_place(self):
        a = cfgmod.defaults()
        self.write(self.paths.local_conf, "[bans]\nauto_ban = off\n")
        a.update_from(cfgmod.load(self.paths))
        self.assertEqual(a["bans"]["auto_ban"], "off")


class TestApplyConfig(Tmp):
    def run_apply(self, check=False, kill=None):
        lines = []
        calls = []
        code = cfgmod.apply_config(self.paths, check_only=check, out=lines.append, kill=kill or (lambda p, s: calls.append((p, s))))
        return code, "\n".join(lines), calls

    def test_check_prints_and_changes_nothing(self):
        self.write(self.paths.local_conf, "[bans]\nauto_ban = observe\n")
        code, out, _ = self.run_apply(check=True)
        self.assertEqual(code, 0)
        self.assertIn("changed: bans.auto_ban on -> observe", out)
        self.assertIn("bans.auto_ban = observe", out)
        self.assertIn("check only", out)
        self.assertFalse(os.path.exists(self.paths.config_good))
        self.assertFalse(os.path.exists(self.paths.notify_min_severity))

    def test_refusal_exits_3_and_names_the_key(self):
        self.write(self.paths.local_conf, "[bans]\nallow_cidr = 10.0.0.1/8\n")
        code, out, _ = self.run_apply()
        self.assertEqual(code, 3)
        self.assertIn("allow_cidr", out)
        self.assertIn("running configuration is kept", out)
        self.assertFalse(os.path.exists(self.paths.config_good))

    def test_apply_swaps_and_renders_the_notify_credential(self):
        self.write(self.paths.local_conf, "[notify]\nmin_severity = MEDIUM\n")
        code, out, _ = self.run_apply()
        self.assertEqual(code, 0)
        self.assertIn("changed: notify.min_severity HIGH -> MEDIUM", out)
        with open(self.paths.notify_min_severity) as f:
            self.assertEqual(f.read().strip(), "MEDIUM")
        self.assertEqual(oct(os.stat(self.paths.notify_min_severity).st_mode & 0o777), "0o600")
        with open(self.paths.config_good) as f:
            self.assertIn("MEDIUM", f.read())
        code, out, _ = self.run_apply()
        self.assertIn("no change", out)

    def test_web_change_prints_the_php_fpm_restart_and_never_runs_it(self):
        self.write(self.paths.local_conf, "[sites]\nphpfpm_bins = /usr/sbin/php-fpm8.3\nweb_users = www-data\n")
        code, out, _ = self.run_apply()
        self.assertEqual(code, 0)
        self.assertIn("restart (not reload) php-fpm", out)
        self.assertIn("systemctl restart php8.3-fpm", out)
        self.assertIn("nothing here runs it", out)

    def test_signals_a_running_agent(self):
        self.write(self.paths.pid_file, "4242\n")
        self.write(self.paths.local_conf, "[bans]\nauto_ban = off\n")
        code, out, calls = self.run_apply()
        self.assertEqual(calls, [(4242, 1)])
        self.assertIn("signalled", out)

    def test_set_key_in_text_keeps_other_lines(self):
        t = "# top\n[sites]\n# nginx\nweb_users = a\n\n[bans]\nauto_ban = on\n"
        t2 = cfgmod.set_key_in_text(t, "sites", "web_users", "b,c")
        self.assertIn("# top", t2)
        self.assertIn("web_users = b,c", t2)
        self.assertIn("auto_ban = on", t2)
        t3 = cfgmod.set_key_in_text(t2, "sites", "nginx_bin", "/usr/sbin/nginx")
        self.assertLess(t3.index("nginx_bin"), t3.index("[bans]"))
        t4 = cfgmod.set_key_in_text(t3, "tetragon", "enforce", "x")
        self.assertTrue(t4.rstrip().endswith("enforce = x"))
        cfgmod.parse_text(t4, "x")
        self.assertEqual(cfgmod.parse_text(t4, "x")[1], [])


if __name__ == "__main__":
    unittest.main()
