"""L0 tests of the files the kit installs (client PLAN sections 4.1 to 4.7, 7, 9): every unit passes
systemd-analyze, carries the sandbox the plan gives it, and the other files (nft, sysctl, modprobe,
needrestart, logrotate, MOTD, apt hooks, journald) have the shape the plan fixes."""

import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from test_helper_common import AGENT, FILES, have  # noqa: E402

NOISE = re.compile(r"is not executable|No such file or directory|not found|Unit .* not found|Failed to open file|Unknown assignment")
SERVICES = sorted(glob.glob(os.path.join(FILES, "*.service")))
UNITS = SERVICES + sorted(glob.glob(os.path.join(FILES, "*.timer"))) + sorted(glob.glob(os.path.join(FILES, "*.path")))


def read(name):
    with open(os.path.join(FILES, name), encoding="utf-8") as fh:
        return fh.read()


def directives(text):
    """{(section, key): [values]} of a unit file."""
    out, sec = {}, ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            sec = line.strip("[]")
        elif "=" in line:
            k, _, v = line.partition("=")
            out.setdefault((sec, k.strip()), []).append(v.strip())
    return out


class TestUnitFiles(unittest.TestCase):
    def test_systemd_analyze_verify_passes_for_every_unit(self):
        if not have("systemd-analyze"):
            self.fail("systemd-analyze is required (CI fails, never skips)")
        self.assertGreaterEqual(len(UNITS), 20)
        for path in UNITS:
            r = subprocess.run(["systemd-analyze", "verify", path], capture_output=True, text=True)
            bad = [l for l in (r.stdout + r.stderr).splitlines() if l.strip() and not NOISE.search(l)]
            self.assertEqual(bad, [], os.path.basename(path))

    def test_drop_ins_verify_beside_a_stand_in_unit(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for unit, drop in (("dnscrypt-proxy", "dnscrypt-proxy-50-edr.conf"), ("suricata", "suricata-edr-override.conf"), ("tetragon", "tetragon-edr-check.conf")):
            os.makedirs("%s/%s.service.d" % (d, unit))
            with open("%s/%s.service" % (d, unit), "w") as fh:
                fh.write("[Service]\nExecStart=/bin/true\n")
            shutil.copy(os.path.join(FILES, drop), "%s/%s.service.d/50-edr.conf" % (d, unit))
            r = subprocess.run(["systemd-analyze", "verify", "%s/%s.service" % (d, unit)], capture_output=True, text=True)
            bad = [l for l in (r.stdout + r.stderr).splitlines() if l.strip() and not NOISE.search(l)]
            self.assertEqual(bad, [], drop)

    def test_security_exposure_is_low(self):
        for path in SERVICES:
            r = subprocess.run(["systemd-analyze", "security", "--offline=true", path], capture_output=True, text=True)
            m = re.search(r"exposure level for .*: ([0-9.]+)", r.stdout)
            self.assertIsNotNone(m, path)
            limit = 4.5 if "rules-update" in path else 3.0
            self.assertLessEqual(float(m.group(1)), limit, os.path.basename(path))

    def test_every_unit_that_runs_a_helper_points_at_an_existing_file(self):
        for path in SERVICES + [os.path.join(FILES, "suricata-edr-override.conf")]:
            for m in re.finditer(r"/usr/local/lib/edr-agent/(files/)?([A-Za-z0-9_.-]+)", read(os.path.basename(path)).replace("\n#", "\n")):
                base = FILES if m.group(1) else AGENT
                if m.group(2) in ("PLAN.md", "edr-agent.prev"):
                    continue
                self.assertTrue(os.path.exists(os.path.join(base, m.group(2))), (os.path.basename(path), m.group(0)))

    def test_helper_units_log_to_the_edr_namespace_and_never_restart_in_a_loop(self):
        for name in ("edr-agent", "edr-bans", "edr-inventory", "edr-diskguard", "edr-dns-watch", "edr-home-net", "edr-notify", "edr-policy-check",
                     "edr-droplet-id", "edr-dnslock", "edr-rules-update"):
            d = directives(read(name + ".service"))
            self.assertEqual(d[("Service", "LogNamespace")], ["edr"], name)
        for name in ("edr-bans", "edr-inventory", "edr-diskguard", "edr-dns-watch", "edr-home-net", "edr-notify", "edr-policy-check",
                     "edr-droplet-id", "edr-dnslock", "edr-agent"):
            self.assertEqual(directives(read(name + ".service"))[("Unit", "StartLimitIntervalSec")], ["0"], name)

    def test_helper_units_start_exactly_as_the_agent_expects(self):
        """The agent drops tetragon.env-read events from the root helpers only for `python3 -I /usr/local/lib/edr-agent/edr-NAME`."""
        for name in ("edr-bans", "edr-inventory", "edr-diskguard", "edr-dns-watch", "edr-home-net", "edr-policy-check", "edr-droplet-id", "edr-notify"):
            exec_start = directives(read(name + ".service"))[("Service", "ExecStart")]
            self.assertEqual(len(exec_start), 1, name)
            self.assertRegex(exec_start[0], r"^/usr/bin/python3 -I /usr/local/lib/edr-agent/%s( [a-z-]+)?$" % name)
        self.assertEqual(directives(read("edr-dnslock.service"))[("Service", "ExecStart")], ["/usr/bin/python3 -I /usr/local/lib/edr-agent/edr-dns-watch boot"])

    def test_bans_units_follow_the_plan(self):
        s = directives(read("edr-bans.service"))
        self.assertEqual(s[("Service", "TimeoutStartSec")], ["10"])
        self.assertEqual(s[("Service", "CapabilityBoundingSet")], ["CAP_NET_ADMIN"])
        self.assertEqual(s[("Service", "RestrictAddressFamilies")], ["AF_NETLINK AF_UNIX"])
        self.assertEqual(s[("Service", "IPAddressDeny")], ["any"])
        self.assertEqual(s[("Service", "MemoryMax")], ["1G"])
        self.assertEqual(s[("Service", "RuntimeDirectoryPreserve")], ["yes"])
        self.assertEqual(s[("Service", "StateDirectory")], ["edr-bans"])
        self.assertEqual(s[("Service", "ProtectSystem")], ["strict"])
        self.assertIn("nftables.service", s[("Unit", "After")][0])
        self.assertEqual(s[("Unit", "Before")], ["network-pre.target"])
        self.assertNotIn("Requires", "".join(k[1] for k in s))
        self.assertEqual(s[("Install", "WantedBy")], ["multi-user.target"])
        p = directives(read("edr-bans.path"))
        self.assertEqual(p[("Path", "TriggerLimitIntervalSec")], ["0"])
        self.assertIn("/run/edr-agent/bans.json", p[("Path", "PathChanged")])
        t = directives(read("edr-bans.timer"))
        self.assertEqual((t[("Timer", "OnBootSec")], t[("Timer", "OnUnitActiveSec")], t[("Timer", "AccuracySec")]), (["20s"], ["60s"], ["1s"]))

    def test_other_timers_follow_the_plan(self):
        want = {"edr-diskguard.timer": (["1min"], ["2min"], ["10s"]), "edr-policy-check.timer": (["1min"], ["2min"], ["10s"]),
                "edr-dns-watch.timer": (["90"], ["15s"], ["1s"]), "edr-home-net.timer": (["2min"], ["15min"], None)}
        for name, (boot, active, acc) in want.items():
            t = directives(read(name))
            self.assertEqual(t[("Timer", "OnBootSec")], boot, name)
            self.assertEqual(t[("Timer", "OnUnitActiveSec")], active, name)
            if acc:
                self.assertEqual(t[("Timer", "AccuracySec")], acc, name)

    def test_inventory_sandbox_is_the_plans(self):
        s = directives(read("edr-inventory.service"))
        self.assertEqual(s[("Service", "CapabilityBoundingSet")], ["CAP_DAC_READ_SEARCH CAP_SYS_PTRACE"])
        self.assertEqual(s[("Service", "RestrictAddressFamilies")], ["AF_UNIX AF_NETLINK"])
        self.assertEqual(s[("Service", "ProtectHome")], ["read-only"])
        self.assertEqual(s[("Service", "TimeoutStartSec")], ["120"])
        self.assertEqual(s[("Service", "MemoryMax")], ["128M"])
        self.assertEqual(s[("Service", "Nice")], ["19"])
        self.assertEqual(s[("Service", "IOSchedulingClass")], ["idle"])
        self.assertEqual(s[("Service", "RuntimeDirectoryPreserve")], ["yes"])
        self.assertEqual(s[("Service", "SystemCallFilter")], ["@system-service", "~@privileged @resources"])
        for forbidden in ("ProtectKernelModules", "ProtectProc"):
            self.assertNotIn(("Service", forbidden), s)

    def test_diskguard_sandbox_is_the_plans(self):
        s = directives(read("edr-diskguard.service"))
        self.assertEqual(s[("Service", "CapabilityBoundingSet")], ["CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER CAP_KILL CAP_SETUID CAP_SETGID"])
        self.assertEqual(s[("Service", "ReadWritePaths")], ["-/var/log/suricata -/var/log/tetragon -/var/lib/suricata/cache"])
        self.assertEqual(s[("Service", "MemoryMax")], ["64M"])
        self.assertEqual(s[("Service", "TimeoutStartSec")], ["90"])

    def test_droplet_id_unit_reaches_only_the_metadata_address(self):
        s = directives(read("edr-droplet-id.service"))
        self.assertEqual(s[("Service", "IPAddressDeny")], ["any"])
        self.assertEqual(s[("Service", "IPAddressAllow")], ["169.254.169.254"])
        self.assertEqual(s[("Unit", "Before")], ["edr-agent.service"])
        self.assertNotIn(("Service", "RemainAfterExit"), s)
        # one file, not all of /run; "-" because the file does not exist when the "+" command that creates it starts
        self.assertEqual(s[("Service", "ReadWritePaths")], ["-/run/edr-droplet-id"])
        self.assertEqual(len(s[("Service", "ExecStartPre")]), 1)
        self.assertTrue(s[("Service", "ExecStartPre")][0].startswith("+"))

    def test_a_writable_path_the_unit_makes_itself_is_optional(self):
        # A path that may be missing when the unit starts (both are on the /run tmpfs) is written "-PATH" and made by
        # a "+" command: without the "-" systemd fails that very command at step NAMESPACE (first mock install).
        for unit, path, maker in (("edr-droplet-id.service", "/run/edr-droplet-id", "/usr/local/lib/edr-agent/edr-droplet-id --seed"),
                                  ("edr-dns-watch.service", "/run/systemd/resolved.conf.d", "/run/systemd/resolved.conf.d")):
            s = directives(read(unit))
            self.assertEqual(s[("Service", "ReadWritePaths")], ["-" + path], unit)
            pre = s[("Service", "ExecStartPre")]
            self.assertEqual(len(pre), 1, unit)
            self.assertTrue(pre[0].startswith("+") and maker in pre[0], unit)

    def test_the_droplet_id_unit_reads_the_stored_id_outside_its_sandbox(self):
        # Found by the first reboot in the mock: the stored id is in /var/lib/edr-agent (edr-agent, 0700), and the
        # main run is root with no capability, so it cannot enter that directory. The "+" run seeds the file.
        s = directives(read("edr-droplet-id.service"))
        self.assertEqual(s[("Service", "CapabilityBoundingSet")], [""])
        self.assertEqual(s[("Service", "ExecStartPre")], ["+/usr/bin/python3 -I /usr/local/lib/edr-agent/edr-droplet-id --seed"])
        self.assertNotIn("--seed", s[("Service", "ExecStart")][0])

    def test_notify_unit_follows_the_plan(self):
        s = directives(read("edr-notify.service"))
        self.assertEqual(s[("Service", "User")], ["edr-notify"])
        self.assertEqual(s[("Service", "LoadCredential")], ["url:/etc/edr-agent/notify.url", "alerts.jsonl:/var/lib/edr-agent/alerts.jsonl",
                                                          "min_severity:/etc/edr-agent/notify.min_severity"])
        self.assertEqual(s[("Service", "StateDirectory")], ["edr-notify"])
        self.assertEqual(s[("Service", "MemoryMax")], ["64M"])
        self.assertEqual(s[("Service", "CapabilityBoundingSet")], [""])
        self.assertEqual(s[("Service", "RestrictAddressFamilies")], ["AF_INET AF_INET6 AF_UNIX"])
        self.assertEqual(s[("Unit", "ConditionPathExists")], ["/etc/edr-agent/notify.url"])
        p = directives(read("edr-notify.path"))
        self.assertEqual(p[("Path", "PathModified")], ["/var/lib/edr-agent/alerts.jsonl"])
        self.assertEqual(p[("Path", "TriggerLimitIntervalSec")], ["0"])

    def test_agent_unit_is_the_sandbox_block_of_the_plan(self):
        s = directives(read("edr-agent.service"))
        one = {"Type": "notify", "NotifyAccess": "main", "WatchdogSec": "90", "Restart": "always", "RestartSec": "5",
               "ExecStop": "/usr/bin/python3 -I /usr/local/lib/edr-agent/edr-agent.py shutdown-notice", "TimeoutStopSec": "5",
               "ExecStart": "/usr/bin/python3 -I /usr/local/lib/edr-agent/edr-agent.py", "User": "edr-agent",
               "SupplementaryGroups": "suricata adm", "CapabilityBoundingSet": "", "NoNewPrivileges": "yes", "ProtectSystem": "strict",
               "ProtectHome": "yes", "ProtectProc": "invisible", "PrivateTmp": "yes", "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX",
               "MemoryDenyWriteExecute": "yes", "SocketBindDeny": "any", "IPAddressDeny": "any", "TemporaryFileSystem": "/var/log:ro",
               "BindReadOnlyPaths": "-/var/log/suricata -/var/log/nginx -/var/log/tetragon -/var/log/dnscrypt-proxy -/var/log/journal -/run/log/journal",
               "StateDirectory": "edr-agent", "RuntimeDirectory": "edr-agent", "MemoryHigh": "96M", "MemoryMax": "128M", "CPUQuota": "10%",
               "OOMScoreAdjust": "300", "RuntimeDirectoryPreserve": "yes", "LogNamespace": "edr", "PrivateDevices": "yes", "PrivateIPC": "yes",
               "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes", "ProtectControlGroups": "yes",
               "ProtectClock": "yes", "ProtectHostname": "yes", "RestrictNamespaces": "yes", "RestrictRealtime": "yes", "RestrictSUIDSGID": "yes",
               "LockPersonality": "yes", "SystemCallArchitectures": "native", "UMask": "0077", "RemoveIPC": "yes", "StateDirectoryMode": "0700",
               "MemorySwapMax": "0", "TasksMax": "32", "LimitNOFILE": "512", "LimitCORE": "0", "Nice": "10", "LogRateLimitBurst": "50000"}
        for k, v in one.items():
            self.assertEqual(s[("Service", k)], [v], k)
        self.assertEqual(s[("Service", "SystemCallFilter")], ["@system-service", "~@privileged @resources"])
        self.assertEqual(s[("Unit", "After")], ["network-online.target edr-droplet-id.service"])
        self.assertEqual(s[("Unit", "Wants")], ["edr-droplet-id.service"])
        self.assertNotIn(("Service", "IPAddressAllow"), s)           # the root-written drop-in holds the hub addresses
        # a rehome killed in step 7 is finished by root before the next start (PLAN 5); "-" so a failure never stops the agent
        self.assertEqual(s[("Service", "ExecStartPre")], ["-+/usr/bin/python3 -I /usr/local/lib/edr-agent/edr-agent.py rehome-resume"])

    def test_suricata_drop_in_follows_the_plan(self):
        s = directives(read("suricata-edr-override.conf"))
        # The bounding set has no CAP_DAC_OVERRIDE, and the package's /etc/suricata is suricata:suricata 0750: the
        # group is what lets the start read suricata.yaml and ExecStop reach the command socket (first install
        # with Suricata in the mock: "failed to open /etc/suricata/suricata.yaml: Permission denied").
        self.assertNotIn("CAP_DAC_OVERRIDE", s[("Service", "CapabilityBoundingSet")][0])
        self.assertNotIn("CAP_DAC_READ_SEARCH", s[("Service", "CapabilityBoundingSet")][0])
        self.assertEqual(s[("Service", "SupplementaryGroups")], ["suricata"])
        self.assertNotIn(("Service", "ExecStart"), s)                # the packaged af-packet ExecStart stays
        # the second line makes /run/suricata at every start: it is on a tmpfs, and without it the command socket
        # (and so ExecStop) was gone after the first reboot in the mock
        self.assertEqual(s[("Service", "ExecStartPre")], ["-+/usr/bin/python3 -I /usr/local/lib/edr-agent/edr-home-net --no-reload",
                                                         "+/usr/bin/install -d -o suricata -g suricata -m 2770 /run/suricata"])
        self.assertEqual(s[("Service", "AmbientCapabilities")], ["CAP_NET_RAW"])
        # the six were measured in the mock (Suricata 8.0.8, af-packet): one fewer and the start fails at capng_change_id
        self.assertEqual(s[("Service", "CapabilityBoundingSet")], ["CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_NICE CAP_SETUID CAP_SETGID CAP_SETPCAP"])
        self.assertEqual(s[("Service", "ReadWritePaths")], ["/var/log/suricata /var/lib/suricata /run"])
        for k, v in (("OOMScoreAdjust", "800"), ("MemoryHigh", "1000M"), ("MemoryMax", "1300M"), ("Restart", "on-failure"), ("RestartSec", "30"),
                     ("Nice", "10"), ("CPUWeight", "50"), ("IOWeight", "20")):
            self.assertEqual(s[("Service", k)], [v], k)
        self.assertEqual((s[("Unit", "StartLimitIntervalSec")], s[("Unit", "StartLimitBurst")]), (["10min"], ["5"]))
        self.assertNotIn(("Service", "MemoryDenyWriteExecute"), s)
        for gone in ("-q 0", "nfqueue", "StartLimitIntervalSec=0", "RestartSec=1\n"):
            self.assertNotIn(gone, "\n".join(l for l in read("suricata-edr-override.conf").splitlines() if not l.startswith("#")) + "\n")

    def test_home_net_unit_can_write_the_packages_directory_and_nothing_else(self):
        # /etc/suricata is suricata:suricata 0750 (the package's choice): root with an empty bounding set could not
        # read or write there, and the unit failed at every timer run (first install with Suricata in the mock).
        s = directives(read("edr-home-net.service"))
        self.assertEqual(s[("Service", "CapabilityBoundingSet")], ["CAP_DAC_OVERRIDE"])
        self.assertEqual(s[("Service", "ProtectSystem")], ["strict"])
        self.assertEqual(s[("Service", "ReadWritePaths")], ["/etc/suricata"])
        self.assertEqual(s[("Service", "IPAddressDeny")], ["any"])

    def test_rule_update_unit_follows_the_plan(self):
        s = directives(read("edr-rules-update.service"))
        for k, v in (("Nice", "19"), ("CPUWeight", "20"), ("IOSchedulingClass", "idle")):
            self.assertEqual(s[("Service", k)], [v], k)
        self.assertTrue(s[("Service", "ExecCondition")][0].endswith("guard"))
        self.assertTrue(s[("Service", "ExecStartPost")][0].startswith("+"))
        t = directives(read("edr-rules-update.timer"))
        self.assertEqual(t[("Timer", "OnCalendar")], ["daily"])


class TestOtherFiles(unittest.TestCase):
    def test_sctp_block_and_conntrack_and_modules(self):
        lines = [l for l in read("edr-sctp-block.conf").splitlines() if l and not l.startswith("#")]
        self.assertEqual(lines, ["install sctp /bin/false"])
        sysctl = dict(l.replace(" ", "").split("=") for l in read("edr-conntrack.conf").splitlines() if l and not l.startswith("#"))
        self.assertEqual(sysctl, {"net.netfilter.nf_conntrack_max": "262144", "net.netfilter.nf_conntrack_acct": "1"})
        self.assertEqual([l for l in read("edr-modules-load.conf").splitlines() if l and not l.startswith("#")], ["nf_conntrack"])

    @unittest.skipUnless(have("perl"), "needs perl")
    def test_needrestart_file_only_adds_keys(self):
        text = read("needrestart-50-edr.conf")
        code = [l for l in text.splitlines() if l.strip() and not l.startswith("#")]
        self.assertEqual(len(code), 3)
        for l in code:
            self.assertRegex(l, r"^\$nrconf\{override_rc\}\{qr\(\^[a-z-]+\)\} = 0;$")
        self.assertNotRegex(text, r"\$nrconf\{override_rc\}\s*=")        # the hash is never reassigned
        r = subprocess.run(["perl", "-c", os.path.join(FILES, "needrestart-50-edr.conf")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_apt_hooks_are_the_plans_line_and_cannot_fail_apt(self):
        want = ('DPkg::Post-Invoke { "[ -d /run/systemd/system ] && timeout 10 systemctl start --no-block edr-inventory.service '
                '>/dev/null 2>&1 || true"; };')
        self.assertIn(want, read("zz-edr-inventory"))
        self.assertIn(want.replace("edr-inventory", "edr-policy-check"), read("zz-edr-policy-check"))

    def test_journal_namespace_file(self):
        t = read("journald-edr.conf")
        self.assertIn("[Journal]", t)
        self.assertIn("SystemMaxUse=150M", t)
        self.assertIn("RuntimeMaxUse=50M", t)

    def test_resolved_drop_in_resets_before_it_sets(self):
        lines = [l for l in read("resolved-zz-edr-doh.conf").splitlines() if l and not l.startswith("#")]
        self.assertEqual(lines, ["[Resolve]", "DNS=", "Domains=", "DNS=127.0.2.1", "Domains=~."])

    @unittest.skipUnless(have("systemd-analyze"), "needs systemd-analyze")
    def test_resolved_drop_in_sorts_after_digitalocean(self):
        self.assertGreater("zz-edr-doh.conf", "DigitalOcean.conf")
        self.assertGreater("zz-edr-doh.conf", "10-x.conf")
        self.assertGreater("zzz-edr-failopen.conf", "zz-edr-doh.conf")

    def test_dnscrypt_drop_in_has_the_marker_for_the_generated_addresses(self):
        t = read("dnscrypt-proxy-50-edr.conf")
        self.assertIn("# @IPADDRESSALLOW@", t)
        d = directives(t)
        self.assertEqual(d[("Service", "ExecStart")], ["", "/usr/sbin/dnscrypt-proxy -config /etc/edr-dns/dnscrypt-proxy.toml"])
        self.assertEqual(d[("Service", "CapabilityBoundingSet")], [""])
        self.assertEqual(d[("Service", "MemoryMax")], ["96M"])
        self.assertEqual((d[("Service", "Restart")], d[("Service", "RestartSec")], d[("Unit", "StartLimitIntervalSec")]), (["always"], ["2"], ["0"]))
        self.assertNotIn(("Service", "WatchdogSec"), d)
        self.assertEqual(d[("Service", "User")], ["_dnscrypt-proxy"])

    def test_dnscrypt_tomls_per_series(self):
        import tomllib
        sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
        for name, key, other in (("dnscrypt-proxy-2.0.toml", "fallback_resolvers", "bootstrap_resolvers"),
                                 ("dnscrypt-proxy-2.1.toml", "bootstrap_resolvers", "fallback_resolvers")):
            with open(os.path.join(FILES, name), "rb") as fh:
                d = tomllib.load(fh)
            self.assertIn(key, d, name)
            self.assertNotIn(other, d, name)
            self.assertEqual(d["listen_addresses"], [], name)
            self.assertIs(d["doh_servers"], True)
            self.assertIs(d["dnscrypt_servers"], False)
            self.assertIs(d["ignore_system_dns"], True)
            self.assertEqual(d["netprobe_timeout"], 0)
            self.assertIs(d["cache"], True)
            self.assertEqual(d["cache_min_ttl"], 2400)
            self.assertNotIn("sources", d)
            self.assertNotIn("require_dnssec", {k for k, v in d.items() if v is True})
            self.assertEqual(sorted(d["server_names"]), sorted(d["static"]))
            self.assertEqual(len(d["static"]), 4)
        # the same keys on both series except the bootstrap one
        with open(os.path.join(FILES, "dnscrypt-proxy-2.0.toml"), "rb") as a, open(os.path.join(FILES, "dnscrypt-proxy-2.1.toml"), "rb") as b:
            ka, kb = set(tomllib.load(a)), set(tomllib.load(b))
        self.assertEqual(ka ^ kb, {"fallback_resolvers", "bootstrap_resolvers"})

    def test_stamps_decode_to_two_operators(self):
        import importlib.util
        from test_helper_common import load_helper
        w = load_helper("edr-dns-watch")
        text = read("dnscrypt-proxy-2.1.toml")
        decoded = [w.decode_stamp(s) for s in w.stamps_in(text)]
        self.assertEqual(sorted(decoded), sorted([("9.9.9.9", "dns.quad9.net"), ("149.112.112.112", "dns.quad9.net"),
                                                  ("1.1.1.1", "cloudflare-dns.com"), ("1.0.0.1", "cloudflare-dns.com")]))
        for stamp in w.stamps_in(text):
            self.assertNotIn("=", stamp)

    def test_defaults_conf_has_every_key_of_the_plan_and_parses(self):
        import configparser
        cp = configparser.ConfigParser(interpolation=None, strict=True, delimiters=("=",), comment_prefixes=("#",), inline_comment_prefixes=None)
        cp.optionxform = str
        cp.read_string(read("defaults.conf"))
        keys = {(s, k) for s in cp.sections() for k in cp[s]}
        plan = {("sites", k) for k in "web_users web_roots nginx_bin phpfpm_bins php_cli_bins vpc_cidr extra_addresses".split()}
        plan |= {("bans", k) for k in "admin_ip allow_cidr auto_ban hub_bans feeds proxy_mode bigconn_bytes bigconn_cap".split()}
        plan |= {("thresholds", k) for k in "ssh_fail tripwire suricata window_update bigconn_repeat suricata_sigs ban_budget_per_hour ban_max_active ban_ladder ban_memory".split()}
        plan |= {("tetragon", k) for k in "enforce egress_ports web_exec_allow".split()}
        plan |= {("suricata", k) for k in "lite sslbl home_net".split()}
        plan |= {("kernel", "sctp_block")} | {("kit", k) for k in "web tetragon suricata kernel".split()}
        plan |= {("diskguard", "stop_suricata")} | {("dns", k) for k in "lockdown lock_forwarded block_doh_ips vpc_dns resolve_check".split()}
        plan |= {("agent", k) for k in "redact payload args event_budget_per_hour access_ring_minutes access_ring_lines nginx_info_log laravel_log login_route sshd_password_auth dns_telemetry rehome_confirm_timeout".split()}
        plan |= {("notify", "min_severity"), ("response", "auto_restart_nginx"), ("isolate", "allow")}
        self.assertEqual(keys, plan)
        defaults = {("bans", "auto_ban"): "on", ("bans", "bigconn_bytes"): "4G", ("bans", "bigconn_cap"): "off", ("thresholds", "ssh_fail"): "5/10m",
                    ("thresholds", "ban_budget_per_hour"): "30", ("thresholds", "ban_max_active"): "1000", ("thresholds", "ban_ladder"): "1h,6h,24h,7d",
                    ("thresholds", "ban_memory"): "14d", ("tetragon", "enforce"): "nginx-exec,sctp-socket", ("agent", "event_budget_per_hour"): "2000",
                    ("agent", "access_ring_lines"): "20000", ("agent", "rehome_confirm_timeout"): "300s", ("notify", "min_severity"): "HIGH",
                    ("response", "auto_restart_nginx"): "false", ("dns", "lockdown"): "on", ("diskguard", "stop_suricata"): "on", ("kernel", "sctp_block"): "on"}
        for (s, k), v in defaults.items():
            self.assertEqual(cp[s][k], v, (s, k))

    def test_defaults_conf_parses_with_the_agents_own_parser(self):
        sys.path.insert(0, AGENT)
        try:
            from edragent import config
        except ImportError:
            self.skipTest("the edragent package is not there")
        raw, errors = config.parse_text(read("defaults.conf"), "defaults.conf")
        self.assertEqual(errors, [])
        for (s, k), v in raw.items():
            config.parse_value(s, k, v)
        self.assertEqual(set(raw), set(config.SCHEMA))

    def test_tripwires_json_and_the_agents_loader(self):
        import json
        with open(os.path.join(FILES, "tripwires.json"), encoding="utf-8") as fh:
            d = json.load(fh)
        paths = [t["path"] for t in d["tripwires"]]
        for need in ("/_ignition/execute-solution", "/_ignition/health-check", "/vendor/phpunit/*/eval-stdin.php", "/.env", "/.env.bak", "/.git/",
                     "/storage/logs/", "/xmlrpc.php", "/phpmyadmin", "/cgi-bin/", "/wp-login.php", "/telescope", "/horizon", "/_debugbar"):
            self.assertIn(need, paths)
        by = {t["path"]: t for t in d["tripwires"]}
        for p in ("/telescope", "/horizon", "/_debugbar"):
            self.assertIs(by[p]["ban"], False)
        self.assertEqual(by["/wp-login.php"]["unless_file"], "wp-config.php")
        sys.path.insert(0, AGENT)
        try:
            from edragent.sources.nginx import load_tripwires, match_tripwire
        except ImportError:
            return
        rules = load_tripwires(os.path.join(FILES, "tripwires.json"), [])
        self.assertEqual(len(rules), len(paths))
        self.assertEqual(match_tripwire(rules, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php")[1], True)
        self.assertEqual(match_tripwire(rules, "/telescope/requests")[1], False)
        self.assertIsNone(match_tripwire(rules, "/index.php"))

    def test_suricata_server_yaml_has_the_servers_values(self):
        try:
            import yaml
        except ImportError:
            self.fail("PyYAML is required")
        text = read("suricata-server.yaml")
        self.assertEqual(text.count("@PUBLIC_IFACE@") - text.count("replaces @PUBLIC_IFACE@"), 1)
        d = yaml.safe_load(text.replace("@PUBLIC_IFACE@", "eth0"))
        self.assertEqual(d["runmode"], "workers")
        ap = d["af-packet"][0]
        self.assertEqual((ap["interface"], ap["threads"], ap["checksum-checks"], ap["tpacket-v3"]), ("eth0", 1, False, True))
        self.assertIs(d["capture"]["disable-offloading"], False)
        self.assertEqual(d["detect"]["profile"], "medium")
        self.assertEqual(d["detect"]["sgh-mpm-caching-max-age"], "7d")
        self.assertEqual(d["mpm-algo"], "auto")
        self.assertEqual(d["flow"]["memcap"], "64 MiB")
        st = d["stream"]
        self.assertEqual((st["memcap"], st["midstream"], st["checksum-validation"], st["reassembly"]["memcap"], st["reassembly"]["depth"]),
                         ("32 MiB", False, False, "128 MiB", "512 KiB"))
        pr = d["app-layer"]["protocols"]
        self.assertEqual(pr["tls"]["encryption-handling"], "bypass")
        self.assertEqual(pr["ssh"]["encryption-handling"], "bypass")
        self.assertIs(pr["ssh"]["hassh"], True)
        self.assertIs(pr["tls"]["ja4-fingerprints"], True)
        evs = [o["eve-log"] for o in d["outputs"]]
        self.assertEqual([e["filename"] for e in evs], ["eve.json", "eve-bulk.json"])
        main = {list(t)[0]: list(t.values())[0] for t in evs[0]["types"]}
        self.assertEqual(set(main), {"alert", "anomaly", "stats"})
        self.assertEqual(main["alert"]["payload-buffer-size"], "4 KiB")
        self.assertIs(main["alert"]["packet"], False)
        self.assertIs(main["alert"]["payload-printable"], False)
        self.assertEqual({list(t)[0] for t in evs[1]["types"]}, {"tls", "ssh", "quic"})
        self.assertNotIn("nfq", d)
        self.assertEqual(d["include"], ["/etc/suricata/edr-home-net.yaml"])
        self.assertEqual(d["stats"]["interval"], 60)
        self.assertEqual(d["rule-files"], ["suricata.rules", "/etc/suricata/local.rules", "/etc/suricata/edr-dns.rules"])
        self.assertNotRegex(text, r"mpm-algo:\s*hs")

    def test_suricata_rule_files(self):
        dis = read("suricata-disable.conf")
        for g in ("dyn_dns", "adware_pup", "web_client", "netbios", "user_agents", "file_sharing", "inappropriate", "voip", "info", "chat", "games",
                  "p2p", "mobile_malware", "scada", "activex", "retired", "deleted", "exploit_kit", "phishing", "tor"):
            self.assertIn("group:emerging-%s.rules" % g, dis, g)
        for kept in ("web_server", "web_specific_apps", "exploit", "scan", "malware", "coinminer", "hunting", "current_events"):
            self.assertNotIn("group:emerging-%s.rules" % kept, dis, kept)
        drop = read("suricata-drop.conf")
        self.assertNotIn("group:drop.rules", drop)
        for line in drop.splitlines():
            if line.startswith("re:"):
                re.compile(line[3:])
        self.assertIn("et/open", [l for l in read("suricata-rule-sources.conf").splitlines() if not l.startswith("#")])
        self.assertIn("Pin: version 1:8.*", read("suricata.apt-pin"))
        for l in read("suricata-local.rules").splitlines():
            if l and not l.startswith("#"):
                self.assertRegex(l, r"^alert tcp .* sid:90003\d\d; rev:1;\)$")

    def test_rules_update_script_syntax_and_the_ban_sid_extraction(self):
        path = os.path.join(FILES, "edr-rules-update")
        self.assertEqual(subprocess.run(["bash", "-n", path]).returncode, 0)
        if have("shellcheck"):
            r = subprocess.run(["shellcheck", "-S", "warning", "-x", path], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout)
        rules = ('drop tcp any any -> any 80 (msg:"a"; sid:2000001; rev:1;)\nalert tcp any any -> any 80 (msg:"b"; sid:2000002; rev:1;)\n'
                 'drop http any any -> any any (msg:"c"; flow:to_server; sid:2000003; rev:4;)\n# drop tcp any any -> any any (sid:2000009;)\n')
        r = subprocess.run(["grep", "-oP", "^drop .*sid:\\K[0-9]+"], input=rules, capture_output=True, text=True)
        self.assertEqual(r.stdout.split(), ["2000001", "2000003"])
        with open(path) as fh:
            self.assertIn('grep -oP "^drop .*sid:\\K[0-9]+"', fh.read())
        r = subprocess.run([path, "bogus"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 64)

    @unittest.skipUnless(os.geteuid() == 0, "needs root for install -g")
    def test_rules_update_run_writes_the_ban_sid_list_the_agent_reads(self):
        """edr-rules-update run, with stubs for suricata-update and the systemd-run test: edr-ban-sids.txt appears (PLAN 4.1.1)."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        rules, state, stubs = d + "/rules", d + "/state", d + "/stubs"
        for p in (rules, state, stubs):
            os.makedirs(p)
        with open(d + "/suricata.yaml", "w") as fh:
            fh.write("%YAML 1.1\n---\n")
        with open(stubs + "/suricata-update", "w") as fh:
            fh.write('#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = --output ] && out=$2; shift; done\n'
                     'printf \'drop tcp any any -> any 80 (msg:"a"; sid:2000001; rev:1;)\\nalert tcp any any -> any 80 (msg:"b"; sid:2000002; rev:1;)\\n'
                     'drop http any any -> any any (msg:"c"; sid:2000003; rev:4;)\\n\' > "$out/suricata.rules"\n')
        for name in ("systemd-run", "logger"):
            with open(stubs + "/" + name, "w") as fh:
                fh.write("#!/bin/sh\nexit 0\n")
        for name in os.listdir(stubs):
            os.chmod(stubs + "/" + name, 0o755)
        env = {"PATH": stubs + ":/usr/bin:/bin", "EDR_RULES_DIR": rules, "EDR_STATE_DIR": state, "EDR_SURICATA_CONF": d + "/suricata.yaml"}
        r = subprocess.run([os.path.join(FILES, "edr-rules-update"), "run"], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        with open(rules + "/edr-ban-sids.txt") as fh:
            self.assertEqual(fh.read().split(), ["2000001", "2000003"])
        self.assertEqual(os.stat(rules + "/edr-ban-sids.txt").st_mode & 0o777, 0o640)
        self.assertTrue(os.path.isfile(rules + "/suricata.rules"))
        with open(rules + "/edr-rules-status.json") as fh:
            st = json.load(fh)
        self.assertIs(st["ok"], True)
        self.assertEqual(st["skipped_days"], 0)
        self.assertEqual([n for n in os.listdir(state) if n.startswith("rules.candidate")], [])      # the candidate directory is gone

    def test_motd_script_is_sanitised_and_bounded(self):
        import json
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        summary = os.path.join(d, "summary.json")
        evil = "x\x1b[31m\x07" + "A" * 500 + "\n\nroot@host:~# "
        with open(summary, "w") as fh:
            json.dump({"v": 1, "counts": {"CRITICAL": 1, "HIGH": 7},
                       "alerts": [{"sev": "CRITICAL", "kind": "tetragon.nginx-exec", "src_ip": "198.51.100.7", "summary": evil}] +
                                 [{"sev": "HIGH", "kind": "k%d" % i, "src_ip": "", "summary": "s%d" % i} for i in range(9)],
                       "hub": {"mode": "enrolled", "unreachable_s": 1800}}, fh)
        script = os.path.join(FILES, "motd-90-edr")
        env = {"PATH": "/usr/bin:/bin", "EDR_SUMMARY_JSON": summary}
        r = subprocess.run([sys.executable, "-I", script], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.splitlines()
        self.assertEqual(len(lines), 1 + 5 + 1)                        # the header, the top 5, the hub line
        self.assertTrue(all(len(l) <= 125 for l in lines))
        self.assertNotIn("\x1b", r.stdout)
        self.assertNotIn("\x07", r.stdout)
        self.assertIn("unreachable for 30 minutes", lines[-1])
        # a symlink, a FIFO and a huge file print nothing
        link = os.path.join(d, "link.json")
        os.symlink(summary, link)
        for bad in (link,):
            r = subprocess.run([sys.executable, "-I", script], capture_output=True, text=True, env=dict(env, EDR_SUMMARY_JSON=bad))
            self.assertEqual((r.returncode, r.stdout), (0, ""))
        big = os.path.join(d, "big.json")
        with open(big, "w") as fh:
            fh.write(" " * (300 * 1024))
        r = subprocess.run([sys.executable, "-I", script], capture_output=True, text=True, env=dict(env, EDR_SUMMARY_JSON=big))
        self.assertEqual(r.stdout, "")
        fifo = os.path.join(d, "fifo.json")
        os.mkfifo(fifo)
        r = subprocess.run([sys.executable, "-I", script], capture_output=True, text=True, env=dict(env, EDR_SUMMARY_JSON=fifo), timeout=10)
        self.assertEqual(r.stdout, "")
        # without the test override only root and sudo or adm members see it
        r = subprocess.run([sys.executable, "-I", script], capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "PAM_USER": "nobody"})
        self.assertEqual(r.stdout, "")
        r = subprocess.run([sys.executable, "-I", script], capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(r.stdout, "")


if __name__ == "__main__":
    unittest.main()
