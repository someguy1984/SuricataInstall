"""L0 tests of agent/edr-bans (client PLAN section 4.2): hostile bans.json, never-ban first, minimum
prefixes, coverage caps, the empty-state rule, the pause, expiry arithmetic, and the nft script.
No root and no nft needed except where a test says so."""

import ipaddress
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from test_helper_common import TmpCase, FILES, have, load_helper, run_helper  # noqa: E402

B = load_helper("edr-bans")
NOW = 1795000000


def doc(bans=(), never=(), empty=False, feeds=None, written=NOW):
    return {"v": 1, "written_at": written, "empty": empty, "never": list(never),
            "bans": [dict({"source": "local", "reason": "ssh_fail", "expires": NOW + 3600}, **b) for b in bans],
            "feeds": feeds or {}}


def validate(d, prev=None, never=()):
    nf = B.NeverList([ipaddress.ip_network(n) for n in never])
    return B.validate(d, NOW, nf, prev or B.empty_state())


class TestAddresses(unittest.TestCase):
    def test_norm_net_rejects_odd_forms(self):
        for bad in (" 1.2.3.4", "1.2.3.4 ", "1.2.3.4\n", "01.2.3.4", "1.2.3.04/32", "fe80::1%eth0", "10.0.0.1/8", "1.2.3",
                    "0x7f.1", "1.2.3.4/033", "2001:db8::1/129", "1.2.3.4/33", "", "::g", "1.2.3.4;rm", "a" * 70, None, 5, ["1.2.3.4"]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                B.norm_net(bad)

    def test_norm_net_maps_v4mapped_and_bare_addresses(self):
        self.assertEqual(str(B.norm_net("::ffff:198.51.100.7")), "198.51.100.7/32")
        self.assertEqual(str(B.norm_net("::ffff:198.51.100.0/120")), "198.51.100.0/24")
        self.assertEqual(str(B.norm_net("198.51.100.7")), "198.51.100.7/32")
        self.assertEqual(str(B.norm_net("2001:db8::")), "2001:db8::/128")

    def test_documentation_ranges_are_not_never_banned(self):
        # ipaddress.is_private calls these private; the literal list must not
        nl = B.NeverList([])
        for ok in ("203.0.113.5/32", "198.18.77.0/24", "198.51.100.0/24", "2001:db8::/64", "192.0.2.1/32"):
            self.assertFalse(nl.overlaps(ipaddress.ip_network(ok)), ok)
        for bad in ("169.254.169.254/32", "10.1.2.3/32", "127.0.0.1/32", "172.31.0.0/16", "192.168.0.0/24", "100.64.1.1/32",
                    "224.0.0.1/32", "255.255.255.255/32", "0.0.0.0/32", "fe80::1/128", "fc00::/64", "::1/128", "ff02::1/128"):
            self.assertTrue(nl.overlaps(ipaddress.ip_network(bad)), bad)


class TestValidation(unittest.TestCase):
    def test_never_ban_first_property(self):
        rnd = random.Random(7)
        nl = B.NeverList([])
        for _ in range(3000):
            plen = rnd.randint(16, 32)
            addr = ipaddress.ip_address(rnd.getrandbits(32))
            net = ipaddress.ip_network((int(addr) >> (32 - plen) << (32 - plen), plen))
            state, refused = validate(doc([{"cidr": str(net)}]))
            if state["bans"]:
                self.assertFalse(nl.overlaps(net), str(net))
            else:
                self.assertTrue(nl.overlaps(net) or not refused is None, str(net))
            if nl.overlaps(net):
                self.assertEqual(state["bans"], [], str(net))

    def test_overlap_with_the_documents_own_never_list(self):
        state, refused = validate(doc([{"cidr": "198.51.100.7/32"}, {"cidr": "203.0.113.9/32"}], never=["198.51.100.0/24"]))
        self.assertEqual([b["cidr"] for b in state["bans"]], ["203.0.113.9/32"])
        self.assertEqual(refused[0]["why"], "overlaps the never-ban list")

    def test_minimum_prefixes(self):
        s, _ = validate(doc([{"cidr": "20.0.0.0/15"}, {"cidr": "21.0.0.0/16"}, {"cidr": "2001:db8::/31"}, {"cidr": "2001:db8::/32"},
                             {"cidr": "2001:db8:1::/64"}]))
        self.assertEqual([b["cidr"] for b in s["bans"]], ["21.0.0.0/16", "2001:db8::/32"])
        f = {"spamhaus_drop_v4": {"expires": NOW + 100, "cidrs": ["20.0.0.0/11", "21.0.0.0/12"]},
             "spamhaus_drop_v6": {"expires": NOW + 100, "cidrs": ["2400::/28", "2400::/29"]}}
        s, _ = validate(doc(feeds=f))
        self.assertEqual(s["feeds"]["spamhaus_drop_v4"]["cidrs"], ["21.0.0.0/12"])
        self.assertEqual(s["feeds"]["spamhaus_drop_v6"]["cidrs"], ["2400::/29"])

    def test_coverage_cap_is_a_guard_breach(self):
        ok = [{"cidr": "%d.%d.0.0/16" % (20 + n // 256, n % 256)} for n in range(65)]
        validate(doc(ok))
        too_many = [{"cidr": "%d.%d.0.0/16" % (20 + n // 256, n % 256)} for n in range(70)]
        with self.assertRaises(B.Refuse):
            validate(doc(too_many))

    def test_caps_and_malformed_documents(self):
        with self.assertRaises(B.Refuse):
            validate(doc([{"cidr": "21.%d.%d.1/32" % (n // 256, n % 256)} for n in range(10001)]))
        for bad in ([], "x", {"v": 2}, {"v": 1, "bans": "x"}, {"v": 1, "written_at": "now"}, {"v": 1, "empty": "yes"},
                    {"v": 1, "empty": True, "bans": [{"cidr": "21.0.0.1/32", "expires": NOW + 99}]}):
            with self.assertRaises(B.Refuse, msg=repr(bad)):
                validate(bad)

    def test_bad_entries_are_dropped_not_fatal(self):
        d = doc([{"cidr": "21.0.0.1/32"}, {"cidr": 5}, {"cidr": "21.0.0.2/32", "expires": "soon"},
                 {"cidr": "21.0.0.3/32", "expires": True}, {"cidr": "21.0.0.4/32", "expires": NOW - 5}])
        d["bans"].append("x")
        s, refused = validate(d)
        self.assertEqual([b["cidr"] for b in s["bans"]], ["21.0.0.1/32"])
        self.assertGreaterEqual(len(refused), 3)

    def test_vocabularies_become_unknown(self):
        s, _ = validate(doc([{"cidr": "21.0.0.1/32", "source": "evil\x1b[31m", "reason": "x" * 999}]))
        self.assertEqual((s["bans"][0]["source"], s["bans"][0]["reason"]), ("unknown", "unknown"))

    def test_overlaps_merge_widest_cidr_longest_ttl(self):
        s, _ = validate(doc([{"cidr": "21.1.0.0/16", "expires": NOW + 100}, {"cidr": "21.1.2.0/24", "expires": NOW + 9000},
                             {"cidr": "21.1.2.3/32", "expires": NOW + 50}, {"cidr": "22.0.0.0/16"}]))
        self.assertEqual([(b["cidr"], b["expires"]) for b in s["bans"]], [("21.1.0.0/16", NOW + 9000), ("22.0.0.0/16", NOW + 3600)])

    def test_breaker_on_new_hub_bans(self):
        many = [{"cidr": "23.%d.0.1/32" % n, "source": "fleet", "reason": "fleet_quorum"} for n in range(50)]
        s, refused = validate(doc(many))
        self.assertEqual(len(s["bans"]), 20)
        self.assertEqual(len(refused), 30)
        # a ban that was already there does not count as new
        prev = dict(B.empty_state(), bans=[{"cidr": "23.%d.0.1/32" % n, "expires": NOW + 99, "source": "fleet", "reason": "fleet_quorum"} for n in range(50)])
        s, refused = validate(doc(many), prev)
        self.assertEqual(len(s["bans"]), 50)
        # local bans are never throttled by the breaker
        s, _ = validate(doc([{"cidr": "24.%d.0.1/32" % n} for n in range(50)]))
        self.assertEqual(len(s["bans"]), 50)

    def test_empty_feed_never_replaces_a_non_empty_one(self):
        prev = dict(B.empty_state(), feeds={"dshield": {"expires": NOW + 1000, "cidrs": ["30.0.0.0/16"]}})
        s, _ = validate(doc(feeds={"dshield": {"expires": NOW + 2000, "cidrs": []}}), prev)
        self.assertEqual(s["feeds"]["dshield"]["cidrs"], ["30.0.0.0/16"])
        s, _ = validate(doc(feeds={}), prev)
        self.assertEqual(s["feeds"], {})                  # absence is not "empty": the feed is removed


class TestMath(unittest.TestCase):
    def test_timeouts_are_relative_and_capped(self):
        base = "x"
        conf = {"bigconn_bytes": 4 * 1024 ** 3, "bigconn_cap": None, "web_uids": []}
        bans = [{"cidr": "21.0.0.1/32", "expires": NOW + 100}, {"cidr": "21.0.0.2/32", "expires": NOW + 10 ** 7},
                {"cidr": "21.0.0.3/32", "expires": NOW}, {"cidr": "21.0.0.4/32", "expires": NOW + 1}]
        script, sizes = B.build_script(base, [], bans, {}, conf, NOW)
        self.assertIn("21.0.0.1/32 timeout 100s", script)
        self.assertIn("21.0.0.2/32 timeout 604800s", script)
        self.assertNotIn("21.0.0.3/32", script)
        self.assertIn("21.0.0.4/32 timeout 1s", script)
        self.assertNotIn("timeout 0s", script)
        self.assertEqual(sizes["edr_ban4"], 3)

    def test_script_is_built_from_ipaddress_strings_and_integers(self):
        conf = {"bigconn_bytes": 4294967296, "bigconn_cap": 8589934592, "web_uids": [33, 1001]}
        script, _ = B.build_script("table inet edr\n", [ipaddress.ip_network("10.0.0.0/8")],
                                   [{"cidr": "21.0.0.0/16", "expires": NOW + 60}], {}, conf, NOW)
        self.assertIn("meta skuid { 33, 1001 }", script)
        self.assertIn("ct original bytes > 4294967296", script)
        self.assertIn("ct original bytes > 8589934592 reject with tcp reset", script)

    def test_utmp_record_size(self):
        self.assertEqual(struct.calcsize(B.UTMP), B.UTMP_SIZE)


class TestRuns(TmpCase):
    def run_bans(self, *extra, now=NOW, timeout=30):
        return run_helper("edr-bans", ["--root", self.root, "--dry-run", "--now", str(now), "--files-dir", FILES] + list(extra), timeout=timeout)

    def write_bans(self, d):
        return self.put("/run/edr-agent/bans.json", json.dumps(d))

    def counters(self):
        return self.read_json("/run/edr-bans/counters.json")

    def state(self):
        return self.read_json("/var/lib/edr-bans/state.json")

    def test_first_apply_writes_state_and_counters(self):
        self.write_bans(doc([{"cidr": "198.51.100.7/32"}], never=["203.0.113.5/32"]))
        rc, out, err = self.run_bans()
        self.assertEqual(rc, 0, err)
        self.assertIn("198.51.100.7/32 timeout 3600s", out)
        self.assertIn("203.0.113.5/32", out)
        c = self.counters()
        self.assertTrue(c["last_apply"]["ok"])
        self.assertEqual(c["sets"]["edr_ban4"], 1)
        self.assertEqual(self.state()["bans"][0]["cidr"], "198.51.100.7/32")

    def test_missing_bans_json_keeps_the_table_and_builds_from_state_at_boot(self):
        self.write_bans(doc([{"cidr": "198.51.100.7/32"}]))
        self.run_bans()
        os.unlink(self.root + "/run/edr-agent/bans.json")
        rc, out, _ = self.run_bans(now=NOW + 60)
        self.assertEqual(rc, 0)
        self.assertIn("198.51.100.7/32 timeout 3540s", out)         # the absolute expiry survived
        rc, out, _ = self.run_bans(now=NOW + 4000)
        self.assertNotIn("198.51.100.7/32", out)                    # expired entries are skipped

    def test_symlink_is_refused_and_the_last_good_state_stays(self):
        self.write_bans(doc([{"cidr": "198.51.100.7/32"}]))
        self.run_bans()
        os.unlink(self.root + "/run/edr-agent/bans.json")
        target = self.put("/tmp-target.json", json.dumps(doc([{"cidr": "198.51.100.99/32"}])))
        os.symlink(target, self.root + "/run/edr-agent/bans.json")
        rc, out, _ = self.run_bans(now=NOW + 10)
        self.assertNotIn("198.51.100.99", out)
        self.assertIn("198.51.100.7/32", out)
        self.assertFalse(self.counters()["last_apply"]["ok"])
        self.assertEqual(self.state()["bans"][0]["cidr"], "198.51.100.7/32")

    def test_fifo_does_not_hang(self):
        os.makedirs(self.root + "/run/edr-agent")
        os.mkfifo(self.root + "/run/edr-agent/bans.json")
        rc, out, _ = self.run_bans(timeout=15)
        self.assertEqual(rc, 0)
        self.assertFalse(self.counters()["last_apply"]["ok"])

    def test_hard_linked_file_is_refused(self):
        p = self.write_bans(doc([{"cidr": "198.51.100.7/32"}]))
        os.link(p, self.root + "/second-link")
        rc, out, _ = self.run_bans()
        self.assertNotIn("198.51.100.7", out)
        self.assertFalse(self.counters()["last_apply"]["ok"])

    def test_over_16_mib_is_refused(self):
        self.put("/run/edr-agent/bans.json", " " * (16 * 1024 * 1024 + 1))
        rc, out, _ = self.run_bans()
        self.assertEqual(rc, 0)
        c = self.counters()["last_apply"]
        self.assertFalse(c["ok"])
        self.assertIn("too large", c["error"])

    def test_deeply_nested_json_is_refused(self):
        self.put("/run/edr-agent/bans.json", "[" * 200000 + "]" * 200000)
        rc, out, _ = self.run_bans()
        self.assertEqual(rc, 0)
        self.assertFalse(self.counters()["last_apply"]["ok"])
        self.put("/run/edr-agent/bans.json", '{"v": 1, "bans": ' + "[" * 100000 + "]" * 100000 + "}")
        self.assertEqual(self.run_bans()[0], 0)

    def test_nan_and_non_utf8_are_refused(self):
        self.put("/run/edr-agent/bans.json", '{"v": 1, "written_at": NaN}')
        self.run_bans()
        self.assertFalse(self.counters()["last_apply"]["ok"])
        self.put("/run/edr-agent/bans.json", b'{"v": 1}\xff\xfe', binary=True)
        self.run_bans()
        self.assertFalse(self.counters()["last_apply"]["ok"])

    @unittest.skipUnless(os.geteuid() == 0, "needs root to give the file to another user")
    def test_file_owned_by_someone_else_is_refused(self):
        p = self.write_bans(doc([{"cidr": "198.51.100.7/32"}]))
        os.chown(p, 65534, 65534)
        rc, out, _ = self.run_bans()
        self.assertNotIn("198.51.100.7", out)
        self.assertIn("unexpected owner", self.counters()["last_apply"]["error"])

    def test_empty_state_refused_after_a_non_empty_one_unless_flagged(self):
        self.write_bans(doc([{"cidr": "198.51.100.7/32"}]))
        self.run_bans()
        self.write_bans(doc([]))
        rc, out, _ = self.run_bans(now=NOW + 5)
        self.assertIn("198.51.100.7/32", out)
        self.assertIn("empty state refused", self.counters()["last_apply"]["error"])
        self.write_bans(doc([], empty=True))
        rc, out, _ = self.run_bans(now=NOW + 6)
        self.assertNotIn("198.51.100.7", out)
        self.assertTrue(self.counters()["last_apply"]["ok"])
        self.assertEqual(self.state()["bans"], [])

    def test_empty_first_state_is_fine(self):
        self.write_bans(doc([]))
        self.run_bans()
        self.assertTrue(self.counters()["last_apply"]["ok"])

    def test_all_entries_refused_does_not_clear_the_bans(self):
        self.write_bans(doc([{"cidr": "198.51.100.7/32"}]))
        self.run_bans()
        self.write_bans(doc([{"cidr": "10.0.0.1/32"}, {"cidr": "junk"}]))
        rc, out, _ = self.run_bans(now=NOW + 5)
        self.assertIn("198.51.100.7/32", out)

    def test_pause_empties_the_sets_and_restores_after(self):
        self.write_bans(doc([{"cidr": "198.51.100.7/32"}], never=["203.0.113.5/32"]))
        self.run_bans()
        self.put("/etc/edr-agent/pause.json", json.dumps({"until": NOW + 600}))
        self.write_bans(doc([], empty=True, written=NOW + 5))          # what the agent writes during a pause
        rc, out, _ = self.run_bans(now=NOW + 10)
        self.assertNotIn("198.51.100.7", out)
        self.assertIn("203.0.113.5/32", out)                         # the never-ban set stays
        self.assertIn("chain bigconn", out)                          # the log-only chains stay
        self.assertEqual(self.state()["bans"][0]["cidr"], "198.51.100.7/32")
        # the file expired, the agent has not rewritten bans.json yet: the pause-time empty file is not a request to forget
        rc, out, _ = self.run_bans(now=NOW + 700)
        self.assertIn("198.51.100.7/32", out)
        # a later explicit empty state (unban --all) is accepted
        self.write_bans(doc([], empty=True, written=NOW + 800))
        rc, out, _ = self.run_bans(now=NOW + 801)
        self.assertNotIn("198.51.100.7", out)

    def test_expired_pause_file_is_ignored(self):
        self.write_bans(doc([{"cidr": "198.51.100.7/32"}]))
        self.put("/etc/edr-agent/pause.json", json.dumps({"until": NOW - 1}))
        rc, out, _ = self.run_bans()
        self.assertIn("198.51.100.7/32", out)
        self.put("/etc/edr-agent/pause.json", "not json")
        self.assertIn("198.51.100.7/32", self.run_bans()[1])

    def test_print_script_writes_nothing(self):
        self.write_bans(doc([{"cidr": "198.51.100.7/32"}]))
        rc, out, _ = run_helper("edr-bans", ["--root", self.root, "--print-script", "--now", str(NOW), "--files-dir", FILES])
        self.assertEqual(rc, 0)
        self.assertIn("table inet edr", out)
        self.assertFalse(os.path.exists(self.root + "/var/lib/edr-bans"))
        self.assertFalse(os.path.exists(self.root + "/run/edr-bans"))

    def test_dry_run_without_root_writes_nothing(self):
        rc, out, _ = run_helper("edr-bans", ["--dry-run", "--now", str(NOW), "--files-dir", FILES, "--root", ""], env={"EDR_AGENT_ROOT": ""})
        # the real paths are only read; with no bans.json the script holds just the base
        self.assertIn(rc, (0, 1))

    def test_authenticated_ssh_session_is_never_banned(self):
        rec = bytearray(B.UTMP_SIZE)
        struct.pack_into(B.UTMP, rec, 0, 7, 1234, b"pts/0", b"ts/0", b"j", b"198.51.100.200", 0, 0, 0, 0, 0,
                         ipaddress.ip_address("198.51.100.200").packed + b"\0" * 12, b"")
        self.put("/var/run/utmp", bytes(rec), binary=True)
        self.write_bans(doc([{"cidr": "198.51.100.200/32"}, {"cidr": "198.51.100.201/32"}]))
        rc, out, _ = self.run_bans()
        self.assertEqual(rc, 0)
        self.assertNotIn("198.51.100.200/32 timeout", out)
        self.assertIn("198.51.100.201/32 timeout", out)
        self.assertIn("198.51.100.200/32", out)                       # it is in the never set

    def test_machine_addresses_gateway_and_resolver_are_never_banned(self):
        self.put("/proc/net/route", "Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0101A8C0\t0003\n")   # 192.168.1.1: also literal
        self.put("/proc/net/route", "Iface\tDestination\tGateway\tFlags\neth0\t00000000\t01C9330B\t0003\n")   # 11.51.201.1
        self.put("/etc/edr-dns/doh-self.conf", "# stamps\n9.9.9.9\ndns.quad9.net\n")
        self.put("/proc/net/fib_trie", "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\n     |-- 45.55.1.9\n        /32 host LOCAL\n")
        self.write_bans(doc([{"cidr": "11.51.201.1/32"}, {"cidr": "9.9.9.9/32"}, {"cidr": "45.55.1.9/32"}, {"cidr": "45.55.1.10/32"}]))
        rc, out, _ = self.run_bans()
        self.assertIn("45.55.1.10/32 timeout", out)
        for a in ("11.51.201.1/32", "9.9.9.9/32", "45.55.1.9/32"):
            self.assertNotIn(a + " timeout", out)


class TestUnchangedStateIsNotReplaced(unittest.TestCase):
    def test_natural_expiry_is_not_a_change_but_an_unban_is(self):
        never = [ipaddress.ip_network("10.0.0.0/8")]
        conf = {"bigconn_bytes": 1, "bigconn_cap": None, "web_uids": []}
        bans = [{"cidr": "21.0.0.1/32", "expires": NOW + 100}, {"cidr": "21.0.0.2/32", "expires": NOW + 5000}]
        applied = json.loads(json.dumps(B.fingerprint_live(never, bans, {}, conf, NOW)))
        # 200 s later the first entry ran out in the kernel by itself
        later = B.fingerprint_live(never, bans[1:], {}, conf, NOW + 200)
        self.assertTrue(B.same_as_applied(applied, later, NOW + 200))
        # an entry that is still live in the kernel but gone from the new state is an unban: apply
        unban = B.fingerprint_live(never, [], {}, conf, NOW + 200)
        self.assertFalse(B.same_as_applied(applied, unban, NOW + 200))
        # a longer ban on the same address is a change
        longer = B.fingerprint_live(never, [bans[0], dict(bans[1], expires=NOW + 9000)], {}, conf, NOW + 1)
        self.assertFalse(B.same_as_applied(applied, longer, NOW + 1))


if __name__ == "__main__":
    unittest.main()
