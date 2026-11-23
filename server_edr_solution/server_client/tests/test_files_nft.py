"""L1-style tests that need a throwaway network namespace (client PLAN section 11): every generated
nft ruleset loads with `unshare -n nft -c -f`, the table replaces atomically, and the sets behave.
Runs as root (`unshare -n`) or, where the kernel allows it, as a user (`unshare -rn`)."""

import ipaddress
import json
import os
import pwd
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from test_helper_common import FILES, TmpCase, have, load_helper, run_helper  # noqa: E402

B = load_helper("edr-bans")
NOW = 1795000000


def netns_prefix():
    """The command prefix that gives an empty network namespace, or None where that is not possible."""
    if not (have("unshare") and have("nft")):
        return None
    for pre in (["unshare", "-n"], ["unshare", "-rn"]):
        if os.geteuid() != 0 and pre == ["unshare", "-n"]:
            continue
        probe = tempfile.mkdtemp()
        try:
            with open(probe + "/p.nft", "w") as fh:
                fh.write("table inet edr_probe\n")
            r = subprocess.run(pre + ["nft", "-c", "-f", probe + "/p.nft"], capture_output=True, text=True)
        finally:
            shutil.rmtree(probe, True)
        if r.returncode == 0:
            return pre
    return None


NS = netns_prefix()


@unittest.skipIf(NS is None, "needs nft and a network namespace (root, or user namespaces allowed)")
class TestRulesets(TmpCase):
    def check(self, path):
        r = subprocess.run(NS + ["nft", "-c", "-f", path], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr[:600])

    def in_ns(self, script):
        return subprocess.run(NS + ["sh", "-c", script], capture_output=True, text=True)

    def script(self, bans=None, extra_conf="", now=NOW, **kw):
        if bans is not None:
            self.put("/run/edr-agent/bans.json", json.dumps(bans))
        if extra_conf:
            self.put("/etc/edr-agent/local.conf", extra_conf)
        rc, out, err = run_helper("edr-bans", ["--root", self.root, "--print-script", "--now", str(now), "--files-dir", FILES], timeout=120)
        self.assertEqual(rc, 0, err)
        path = self.root + "/ruleset.nft"
        with open(path, "w") as fh:
            fh.write(out)
        return path

    def test_the_base_file_alone_loads_and_replaces_itself(self):
        base = os.path.join(FILES, "edr-base.nft")
        self.check(base)
        r = self.in_ns("nft -f %s && nft -f %s && nft -t list table inet edr" % (base, base))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout, r"chain ban \{\s+type filter hook prerouting priority (mangle|-150);")
        for need in ("chain ban", "hook prerouting", "chain bigconn", "priority mangle + 10", "chain egress", "hook output",
                     "set edr_never4", "set edr_ban6", "set edr_feed4", "ip saddr @edr_never4 return", "ct direction original ip saddr @edr_ban4",
                     "ct state untracked ip saddr @edr_ban4 drop", "counter hit_ban4"):
            self.assertIn(need, r.stdout, need)
        # the never-ban check comes before every drop
        text = r.stdout[r.stdout.index("chain ban"):]
        self.assertLess(text.index("@edr_never4 return"), text.index("drop"))
        self.assertLess(text.index("@edr_never6 return"), text.index("drop"))

    def test_generated_scripts_load(self):
        cases = {
            "empty": ({"v": 1, "written_at": NOW, "empty": False, "never": [], "bans": [], "feeds": {}}, ""),
            "mixed": ({"v": 1, "written_at": NOW, "empty": False, "never": ["203.0.113.5/32", "10.10.0.0/16", "2001:db8:f::/48"],
                       "bans": [{"cidr": "198.51.100.7/32", "expires": NOW + 3600, "source": "local", "reason": "ssh_fail"},
                                {"cidr": "198.18.77.0/24", "expires": NOW + 7200, "source": "local", "reason": "tripwire"},
                                {"cidr": "21.1.0.0/16", "expires": NOW + 99, "source": "fleet", "reason": "fleet_quorum"},
                                {"cidr": "2001:db8:1:2::/64", "expires": NOW + 3600, "source": "local", "reason": "ssh_fail"},
                                {"cidr": "2400:cb00::/32", "expires": NOW + 86400 * 30, "source": "operator", "reason": "operator"}],
                       "feeds": {"spamhaus_drop_v4": {"expires": NOW + 70000, "cidrs": ["24.0.0.0/12", "31.5.0.0/16", "31.6.0.0/20"]},
                                 "spamhaus_drop_v6": {"expires": NOW + 70000, "cidrs": ["2a00::/29", "2a01:1::/32"]}}}, ""),
            "uids and cap": ({"v": 1, "written_at": NOW, "bans": [{"cidr": "198.51.100.7/32", "expires": NOW + 60}]},
                             "[bans]\nbigconn_bytes = 2G\nbigconn_cap = 8G\n[sites]\nweb_users = root\n"),
        }
        for name, (doc, conf) in cases.items():
            self.setUp()
            path = self.script(doc, conf)
            self.check(path)
            r = self.in_ns("nft -f %s && nft -f %s && nft -t -j list counters table inet edr" % (path, path))
            self.assertEqual(r.returncode, 0, name + ": " + r.stderr[:400])

    def test_overlapping_input_never_aborts_the_transaction(self):
        doc = {"v": 1, "written_at": NOW, "bans": [
            {"cidr": "21.0.0.0/16", "expires": NOW + 100}, {"cidr": "21.0.5.0/24", "expires": NOW + 900}, {"cidr": "21.0.5.9/32", "expires": NOW + 50},
            {"cidr": "21.1.0.0/16", "expires": NOW + 100}, {"cidr": "21.0.0.0/16", "expires": NOW + 5000}],
            "never": ["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "192.168.0.0/16"],
            "feeds": {"dshield": {"expires": NOW + 999, "cidrs": ["30.0.0.0/16", "30.0.1.0/24", "30.0.0.0/16"]}}}
        path = self.script(doc)
        r = self.in_ns("nft -f %s" % path)
        self.assertEqual(r.returncode, 0, r.stderr[:400])

    def test_sets_behave_in_the_namespace(self):
        doc = {"v": 1, "written_at": NOW, "never": ["203.0.113.5/32"],
               "bans": [{"cidr": "198.51.100.0/24", "expires": NOW + 3600}, {"cidr": "2001:db8:1::/64", "expires": NOW + 3600},
                        {"cidr": "21.0.0.0/16", "expires": NOW + 3600}]}
        path = self.script(doc)
        probes = [("edr_never4", "10.1.2.3", True), ("edr_never4", "169.254.169.254", True), ("edr_never4", "203.0.113.5", True),
                  ("edr_never4", "198.51.100.9", False), ("edr_never6", "fe80::1", True), ("edr_never6", "2001:db8:1::1", False),
                  ("edr_ban4", "198.51.100.200", True), ("edr_ban4", "198.51.101.1", False), ("edr_ban4", "21.0.255.255", True),
                  ("edr_ban6", "2001:db8:1::dead:beef", True), ("edr_ban6", "2001:db8:2::1", False)]
        script = "nft -f %s && " % path + " ; ".join("nft get element inet edr %s '{ %s }' >/dev/null 2>&1 && echo %s,%s,in || echo %s,%s,out" % (s, a, s, a, s, a) for s, a, _ in probes)
        r = self.in_ns(script)
        got = {tuple(l.split(",")[:2]): l.split(",")[2] for l in r.stdout.split()}
        for s, a, want in probes:
            self.assertEqual(got[(s, a)], "in" if want else "out", (s, a))

    def test_the_replace_is_atomic_and_removes_what_the_new_state_lacks(self):
        first = self.script({"v": 1, "written_at": NOW, "bans": [{"cidr": "198.51.100.7/32", "expires": NOW + 3600}]})
        a = self.root + "/ruleset_a.nft"
        shutil.copy(first, a)
        second = self.script({"v": 1, "written_at": NOW + 1, "empty": True, "bans": []})
        b = self.root + "/ruleset_b.nft"
        shutil.copy(second, b)
        probe = "nft get element inet edr edr_ban4 '{ 198.51.100.7 }' >/dev/null 2>&1"
        r = self.in_ns("nft -f %s && %s && echo present; nft -f %s && %s || echo gone" % (a, probe, b, probe))
        self.assertEqual(r.stdout.split(), ["present", "gone"], r.stderr)

    def test_counters_json_from_real_nft_output(self):
        path = self.script({"v": 1, "written_at": NOW, "bans": []})
        r = self.in_ns("nft -f %s && nft -t -j list counters table inet edr" % path)
        self.assertEqual(r.returncode, 0, r.stderr)
        orig = B.run_nft
        B.run_nft = lambda args, stdin=None, timeout=20: (0, r.stdout, "")
        try:
            present, ctr = B.read_counters_nft()
        finally:
            B.run_nft = orig
        self.assertTrue(present)
        self.assertEqual(set(ctr), {"hit_ban4", "hit_ban6", "hit_feed4", "hit_feed6", "hit_bigconn"})
        self.assertTrue(all(v == 0 for v in ctr.values()))

    def test_ten_thousand_bans_and_fifty_thousand_feed_entries(self):
        rnd = random.Random(3)
        bans = [{"cidr": "%d.%d.%d.%d/32" % (21 + n // 65536, (n // 256) % 256, n % 256, 1), "expires": NOW + 3600} for n in range(10000)]
        feed = sorted({"%d.%d.%d.0/24" % (rnd.randint(30, 200), rnd.randint(0, 255), rnd.randint(0, 255)) for _ in range(50000)})
        path = self.script({"v": 1, "written_at": NOW, "bans": bans, "feeds": {"dshield": {"expires": NOW + 7200, "cidrs": feed}}})
        self.check(path)
        self.assertGreater(os.path.getsize(path), 500000)

    def test_dns_lock_renders_and_loads(self):
        if not any(p.pw_name == "nobody" for p in pwd.getpwall()):
            self.skipTest("no nobody user")
        self.put("/etc/edr-dns/doh-self.conf", "9.9.9.9\n149.112.112.112\n1.1.1.1\n1.0.0.1\n2620:fe::fe\ndns.quad9.net\ncloudflare-dns.com\n")
        with open(os.path.join(FILES, "doh-resolvers.conf")) as fh:
            self.put("/etc/edr-dns/doh-resolvers.conf", fh.read())
        for conf in ("", "[dns]\nblock_doh_ips = on\nlock_forwarded = on\nvpc_dns = auto\n"):
            self.put("/etc/edr-agent/local.conf", conf or "\n")
            self.put("/etc/edr-dns/vpc-resolver", "10.116.0.2\n")
            rc, out, err = run_helper("edr-dns-watch", ["render", "--root", self.root, "--proxy-user", "nobody", "--files-dir", FILES])
            self.assertEqual(rc, 0, err)
            self.check(self.root + "/etc/edr-dns/edr-dns.nft")


if __name__ == "__main__":
    unittest.main()
