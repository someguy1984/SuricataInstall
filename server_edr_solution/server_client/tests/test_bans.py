import ipaddress
import json
import os
import random
import shutil
import stat
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock

import test_transport_pki as support
from edragent import bans as bm
from edragent import event as evmod
from edragent import spool as sp

T0 = 1795000000.0


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


def mk(kind, ip, now, trust="tcp", source=None, sev="LOW", dst_port=None, proto=None, **details):
    src = source or {"ssh.fail": "journal", "ssh.login": "journal", "canary.tripwire": "nginx",
                     "suricata.alert": "suricata", "nginx.marker.window_update": "nginx",
                     "edr.bigconn": "kernel"}.get(kind, "agent")
    return evmod.make_event(kind, src, sev, "test event", details=details or None, ts_ms=int(now * 1000),
                            src_ip=ip, src_trust=trust, dst_port=dst_port, proto=proto)


def suricata(ip, now, sid=2001, dst_port=22, **over):
    d = {"sid": sid, "signature_id": sid, "app_proto": "ssh", "stream": 1, "pkts_toserver": 5, "pkts_toclient": 3}
    d.update(over)
    proto = d.pop("proto", "tcp")
    return mk("suricata.alert", ip, now, dst_port=dst_port, proto=proto, **d)


class Base(unittest.TestCase):
    CFG = {}

    def setUp(self):
        self.env = support.Env()
        self.p = self.env.paths
        self.clock = Clock()
        self.proc = os.path.join(self.env.root, "proc", "net")
        os.makedirs(self.proc)
        self.sids = os.path.join(self.env.root, "ban-sids.txt")
        with open(self.sids, "w") as f:
            f.write("2001\n2002\n2003\n")
        self.sids_patch = mock.patch.object(bm, "SURICATA_SIDS_PATH", "/ban-sids.txt")
        self.sids_patch.start()
        self.engine = self.make()

    def tearDown(self):
        self.sids_patch.stop()
        self.env.cleanup()

    def cfg(self):
        c = {"bans": {}, "thresholds": {}, "sites": {}}
        for sec, d in self.CFG.items():
            c[sec].update(d)
        return c

    def make(self, cfg=None):
        e = bm.BanEngine(cfg if cfg is not None else self.cfg(), self.p, proc_dir=os.path.join(self.env.root, "proc"),
                         resolv_conf=os.path.join(self.env.root, "nope"), utmp_path=os.path.join(self.env.root, "nout"),
                         clock=self.clock)
        e.sids_path = self.sids
        return e

    def feed(self, kinds_ips, step=1.0):
        out = []
        for ev in kinds_ips:
            out.extend(self.engine.observe(ev, self.clock.t))
            self.clock.t += step
        return out

    def ssh_fails(self, ip, n, step=1.0, trust="tcp"):
        evs = []
        for i in range(n):
            evs.append(mk("ssh.fail", ip, self.clock.t + i * step, trust=trust))
        out = []
        for ev in evs:
            self.clock.t = max(self.clock.t, bm.parse_rfc3339(ev["ts"]))
            out.extend(self.engine.observe(ev, self.clock.t))
        return out

    def bans_json(self):
        with open(self.p.bans_json) as f:
            return json.load(f)


class TestAddresses(unittest.TestCase):
    def test_norm_ip_accepts(self):
        self.assertEqual(bm.norm_ip("198.51.100.7"), "198.51.100.7")
        self.assertEqual(bm.norm_ip("2001:DB8:0:0:0:0:0:1"), "2001:db8::1")
        self.assertEqual(bm.norm_ip("::ffff:198.51.100.7"), "198.51.100.7")          # mapped goes to IPv4 first
        self.assertEqual(bm.norm_ip("0.0.0.0"), "0.0.0.0")

    def test_norm_ip_rejects(self):
        for bad in ("", " 1.2.3.4", "1.2.3.4 ", "1.2.3.4\n", "01.2.3.4", "1.2.3", "1.2.3.4.5", "256.1.1.1",
                    "fe80::1%eth0", "fe80::1%1", "1.2.3.4/24", "::1/128", "0x7f.0.0.1", "1.2.3.04", "١.٢.٣.٤",
                    "1.2.3.4\x00", "::ffff:1.2.3.4%x", None, 5, "a" * 100, "1..2.3", "1.2.3.-4"):
            self.assertIsNone(bm.norm_ip(bad), repr(bad))

    def test_parse_net(self):
        self.assertEqual(str(bm.parse_net("198.51.100.0/24")), "198.51.100.0/24")
        self.assertEqual(str(bm.parse_net("198.51.100.7")), "198.51.100.7/32")
        self.assertEqual(str(bm.parse_net("2001:db8::/32")), "2001:db8::/32")
        self.assertEqual(str(bm.parse_net("::ffff:198.51.100.0/120")), "198.51.100.0/24")
        for bad in ("198.51.100.7/24", "1.2.3.4/33", "1.2.3.4/024", "1.2.3.4/ 8", "2001:db8::1/32", "x/8", "1.2.3.0/-1",
                    "::ffff:1.2.3.0/64", "1.2.3.0/", "/8"):
            self.assertIsNone(bm.parse_net(bad), repr(bad))

    def test_ban_key_v6_is_64(self):
        self.assertEqual(bm.ban_key(ipaddress.ip_address("2001:db8:1:2:aaaa::1")), "2001:db8:1:2::/64")
        self.assertEqual(bm.ban_key(ipaddress.ip_address("198.51.100.7")), "198.51.100.7")


class TestDurations(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(bm.parse_duration("30s"), 30)
        self.assertEqual(bm.parse_duration("10m"), 600)
        self.assertEqual(bm.parse_duration("1h"), 3600)
        self.assertEqual(bm.parse_duration("7d"), 604800)
        self.assertEqual(bm.parse_duration("14 days"), 14 * 86400)
        self.assertEqual(bm.parse_duration("1h30m"), 5400)
        self.assertEqual(bm.parse_duration(90), 90)
        self.assertEqual(bm.parse_duration("300"), 300)
        for bad in ("", "x", "10x", "-5m", None, True, "m10"):
            self.assertIsNone(bm.parse_duration(bad), repr(bad))
        self.assertEqual(bm.parse_rate("5/10m", None), (5, 600))
        self.assertEqual(bm.parse_rate("2 per 10 min", None), (2, 600))
        self.assertEqual(bm.parse_rate((3, 600), None), (3, 600))
        self.assertEqual(bm.parse_rate("junk", (9, 9)), (9, 9))


class TestNeverList(unittest.TestCase):
    LITERAL_V4 = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
                  "192.0.0.0/24", "192.168.0.0/16", "224.0.0.0/3"]
    LITERAL_V6 = ["::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"]

    def test_the_literal_table_is_compiled_in(self):
        self.assertEqual(list(bm.NEVER_V4), self.LITERAL_V4)
        self.assertEqual(list(bm.NEVER_V6), self.LITERAL_V6)

    def test_literals(self):
        never = bm.LITERAL_NEVER
        for ip in ("10.1.2.3", "100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.169.254", "172.16.0.1",
                   "172.31.255.255", "192.0.0.8", "192.168.1.1", "224.0.0.1", "239.255.255.255", "255.255.255.255",
                   "0.1.2.3", "::", "::1", "fd00::1", "fe80::1", "ff02::1"):
            self.assertTrue(never.contains(ipaddress.ip_address(ip)), ip)
        # ipaddress.is_private calls these private; the literal list must not
        for ip in ("203.0.113.5", "198.18.77.7", "198.51.100.7", "192.0.2.1", "2001:db8::1", "2002::1", "8.8.8.8",
                   "172.32.0.1", "100.128.0.1", "192.0.1.1", "2606:4700::1"):
            self.assertFalse(never.contains(ipaddress.ip_address(ip)), ip)

    def test_overlap_matches_a_naive_check(self):
        rnd = random.Random(7)

        def rnet(v):
            if v == 4:
                plen = rnd.randint(1, 32)
                return ipaddress.ip_network((rnd.getrandbits(32), plen), strict=False)
            plen = rnd.randint(8, 128)
            return ipaddress.ip_network((ipaddress.IPv6Address(rnd.getrandbits(128)), plen), strict=False)
        for _ in range(300):
            nets = [rnet(rnd.choice((4, 6))) for _ in range(rnd.randint(0, 12))]
            nl = bm.NeverList(nets)
            for _ in range(60):
                q = rnet(rnd.choice((4, 6)))
                naive = any(q.version == n.version and q.overlaps(n) for n in nets)
                self.assertEqual(nl.overlaps(q), naive, (q, nets))

    def test_sanitize_property_random_sets(self):
        """Random CIDR sets never overlap the never-ban list; prefixes, /64 and coverage caps hold."""
        rnd = random.Random(20261123)
        lit = [ipaddress.ip_network(x) for x in bm.NEVER_V4 + bm.NEVER_V6]
        for _ in range(1500):
            dyn_nets = [ipaddress.ip_network((rnd.getrandbits(32), rnd.randint(8, 32)), strict=False)
                        for _ in range(rnd.randint(0, 5))]
            dyn = bm.NeverList(dyn_nets)
            cands = []
            for _ in range(rnd.randint(1, 40)):
                if rnd.random() < 0.7:
                    cands.append(str(ipaddress.ip_network((rnd.getrandbits(32), rnd.randint(1, 32)), strict=False)))
                else:
                    cands.append(str(ipaddress.ip_network((ipaddress.IPv6Address(rnd.getrandbits(128)), rnd.randint(8, 128)), strict=False)))
            if rnd.random() < 0.2:
                cands.append(rnd.choice(["junk", "1.2.3.4/33", "10.0.0.0/8", "224.0.0.0/4", "fe80::/64", "::/0"]))
            acc, ref = bm.sanitize_bans(cands, dyn, kind="ban")
            cover = {4: 0, 6: 0}
            for n in acc:
                for l in lit:
                    self.assertFalse(n.version == l.version and n.overlaps(l), (n, l))
                for d in dyn_nets:
                    self.assertFalse(n.overlaps(d) if n.version == d.version else False, (n, d))
                self.assertGreaterEqual(n.prefixlen, bm.MIN_PREFIX_BAN[n.version])
                if n.version == 6:
                    self.assertLessEqual(n.prefixlen, 64)
                cover[n.version] += n.num_addresses
            self.assertLessEqual(cover[4], bm.COVER_CAP_BAN4)
            self.assertLessEqual(cover[6], bm.COVER_CAP_BAN6)
            for i, a in enumerate(acc):
                for b in acc[i + 1:]:
                    self.assertFalse(a.version == b.version and a.overlaps(b))
            self.assertTrue(all(isinstance(r["why"], str) for r in ref))

    def test_sanitize_specifics(self):
        acc, ref = bm.sanitize_bans(["198.51.100.7/32", "198.51.0.0/16", "198.0.0.0/8", "10.0.0.0/16", "192.0.0.0/24",
                                     "169.254.169.254", "2001:db8::/64", "2001::/16", "2001:db8::1/128"])
        got = {str(n) for n in acc}
        self.assertIn("198.51.0.0/16", got)
        self.assertIn("2001:db8::/64", got)
        why = {r["cidr"]: r["why"] for r in ref}
        self.assertEqual(why["198.0.0.0/8"], "prefix too short")
        self.assertEqual(why["10.0.0.0/16"], "never-ban literal")
        self.assertEqual(why["169.254.169.254/32"], "never-ban literal")
        self.assertEqual(why["2001::/16"], "prefix too short")
        self.assertEqual(why["2001:db8::1/128"], "IPv6 bans are /64")
        self.assertEqual(why["198.51.100.7/32"], "inside a wider entry")

    def test_coverage_cap_ban4_is_a_tenth_of_a_percent(self):
        # 0.1% of IPv4 is 4,294,967 addresses (65 /16): eighty /16 cannot all fit
        cands = ["%d.%d.0.0/16" % (20 + i // 20, i % 20) for i in range(80)]
        acc, ref = bm.sanitize_bans(cands)
        total = sum(n.num_addresses for n in acc)
        self.assertLessEqual(total, bm.COVER_CAP_BAN4)
        self.assertTrue(any(r["why"] == "coverage cap" for r in ref))

    def test_feed_profile(self):
        acc, ref = bm.sanitize_bans(["198.51.0.0/12", "198.48.0.0/12", "198.51.100.0/24", "2001:db8::/29"], kind="feed")
        got = {str(n) for n in acc}
        self.assertIn("198.48.0.0/12", got)
        self.assertIn("2001:db8::/29", got)


class TestHostileFiles(unittest.TestCase):
    def test_own_addresses_and_utmp(self):
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "net"))
            with open(os.path.join(d, "net", "fib_trie"), "w") as f:
                f.write("Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\n"
                        "     +-- 203.0.113.0/24 2 0 2\n        |-- 203.0.113.9\n           /32 host LOCAL\n"
                        "        |-- 203.0.113.255\n           /32 link BROADCAST\n")
            with open(os.path.join(d, "net", "if_inet6"), "w") as f:
                f.write("20010db8000000000000000000000042 02 40 00 80 eth0\n")
            with open(os.path.join(d, "net", "route"), "w") as f:
                f.write("Iface\tDestination\tGateway\tFlags\n" "eth0\t00000000\t0100000A\t0003\n")
            rc = os.path.join(d, "resolv.conf")
            with open(rc, "w") as f:
                f.write("nameserver 198.51.100.53\nnameserver fe80::1%eth0\nsearch x\n")
            got = {str(n) for n in bm.own_addresses(d, rc)}
            self.assertIn("203.0.113.9/32", got)
            self.assertNotIn("203.0.113.255/32", got)
            self.assertIn("2001:db8::42/128", got)
            self.assertIn("10.0.0.1/32", got)             # the gateway, from little-endian hex
            self.assertIn("198.51.100.53/32", got)
            ut = os.path.join(d, "utmp")
            rec = bytearray(384)
            struct.pack_into("<h", rec, 0, 7)
            struct.pack_into("<I", rec, 348, int.from_bytes(bytes([198, 51, 100, 77]), "little"))
            dead = bytearray(384)
            struct.pack_into("<h", dead, 0, 8)
            struct.pack_into("<I", dead, 348, int.from_bytes(bytes([198, 51, 100, 78]), "little"))
            with open(ut, "wb") as f:
                f.write(bytes(rec) + bytes(dead))
            self.assertEqual([str(n) for n in bm.utmp_remote_addresses(ut)], ["198.51.100.77/32"])
        finally:
            shutil.rmtree(d)

    def test_missing_files_are_empty(self):
        self.assertEqual(bm.own_addresses("/nonexistent-a5", "/nonexistent-a5/x"), [])
        self.assertEqual(bm.utmp_remote_addresses("/nonexistent-a5"), [])


class TestTriggers(Base):
    def test_ssh_five_in_ten_minutes_bans_for_one_hour(self):
        out = self.ssh_fails("198.51.100.7", 4)
        self.assertEqual(out, [])
        out = self.ssh_fails("198.51.100.7", 1)
        self.assertEqual(len(out), 1)
        e = out[0]
        self.assertEqual(e["kind"], "ban.local")
        self.assertEqual(e["details"], {"cidr": "198.51.100.7/32", "trigger": "ssh_fail", "evidence": "log",
                                        "ttl_s": 3600, "rung": 0})
        self.assertEqual(e["src_ip"], "198.51.100.7")
        self.assertEqual(e["src_trust"], "tcp")
        self.assertEqual(e["source"], "agent")
        b = self.engine.active_bans()
        self.assertEqual(len(b), 1)
        self.assertEqual(b[0]["expires"], int(self.clock.t + 3600))

    def test_window_slides(self):
        out = []
        for i in range(8):
            out += self.feed([mk("ssh.fail", "198.51.100.7", self.clock.t)], step=200)      # one per 200 s: 4 in 10 min
        self.assertEqual(out, [])

    def test_claimed_and_none_trust_never_ban(self):
        self.assertEqual(self.ssh_fails("198.51.100.7", 20, trust="claimed"), [])
        self.assertEqual(self.ssh_fails("198.51.100.8", 20, trust="none"), [])
        self.assertEqual(self.engine.active_bans(), [])

    def test_events_over_fifteen_minutes_old_never_ban(self):
        old = [mk("ssh.fail", "198.51.100.7", self.clock.t - 901 - i) for i in range(20)]
        self.assertEqual(self.feed(old, step=0), [])
        fresh_edge = [mk("ssh.fail", "198.51.100.9", self.clock.t - 800 + i) for i in range(5)]
        self.assertEqual(len(self.feed(fresh_edge, step=0)), 1)

    def test_future_events_are_clamped_not_trusted(self):
        evs = [mk("ssh.fail", "198.51.100.7", self.clock.t + 3600) for _ in range(5)]
        out = self.feed(evs, step=0)
        self.assertEqual(len(out), 1)           # counted at "now", the clock the agent trusts

    def test_tripwire_statuses(self):
        for status, expect in ((404, True), (403, True), (444, True), (200, False), (500, False), (None, False)):
            self.engine = self.make()
            ip = "198.51.100.%d" % (20 + (status or 0) % 50)
            evs = [mk("canary.tripwire", ip, self.clock.t, status=status, ban=True) for _ in range(5)]
            out = self.feed(evs, step=0)
            self.assertEqual(bool(out), expect, status)
            if out:
                self.assertEqual(out[0]["details"]["trigger"], "tripwire")
                self.assertEqual(out[0]["details"]["ttl_s"], 3600)

    def test_tripwire_ban_false_never_bans(self):
        evs = [mk("canary.tripwire", "198.51.100.7", self.clock.t, status=404, ban=False) for _ in range(30)]
        self.assertEqual(self.feed(evs, step=0), [])

    def test_tripwire_five_in_five_minutes(self):
        out = []
        for i in range(5):
            out += self.engine.observe(mk("canary.tripwire", "198.51.100.7", self.clock.t, status=404, ban=True), self.clock.t)
            self.clock.t += 60                     # five hits in 240 s
        self.assertEqual(len(out), 1)
        self.engine = self.make()
        out = []
        for i in range(5):
            out += self.engine.observe(mk("canary.tripwire", "198.51.100.9", self.clock.t, status=404, ban=True), self.clock.t)
            self.clock.t += 100                    # 400 s for five: the first has left the 5 minute window
        self.assertEqual(out, [])

    def test_window_update_and_bigconn(self):
        evs = [mk("nginx.marker.window_update", "198.51.100.7", self.clock.t) for _ in range(3)]
        out = self.feed(evs, step=0)
        self.assertEqual(out[0]["details"]["trigger"], "window_update")
        self.assertEqual(out[0]["details"]["evidence"], "log")
        out = self.feed([mk("edr.bigconn", "198.51.100.8", self.clock.t)], step=3000)
        self.assertEqual(out, [])
        out = self.feed([mk("edr.bigconn", "198.51.100.8", self.clock.t)], step=0)
        self.assertEqual(out[0]["details"]["trigger"], "bigconn")
        self.assertEqual(out[0]["details"]["evidence"], "tcp")
        # one hour is the window: the second event 3601 s later does not count
        self.engine = self.make()
        self.feed([mk("edr.bigconn", "198.51.100.9", self.clock.t)], step=3601)
        out = self.feed([mk("edr.bigconn", "198.51.100.9", self.clock.t)], step=0)
        self.assertEqual(out, [])

    def test_suricata_needs_all_flow_conditions(self):
        good = [suricata("198.51.100.7", self.clock.t, sid=2001) for _ in range(3)]
        out = self.feed(good, step=0)
        self.assertEqual(out[0]["details"], {"cidr": "198.51.100.7/32", "trigger": "suricata", "evidence": "tcp",
                                             "ttl_s": 3600, "rung": 0})
        cases = {
            "udp": dict(proto="udp"), "icmp": dict(proto="icmp"), "no app_proto": dict(app_proto=""),
            "midstream": dict(stream=0), "syn only": dict(pkts_toserver=2), "no reply": dict(pkts_toclient=0),
            "sid not listed": dict(sid=4999, signature_id=4999),
        }
        for name, over in cases.items():
            self.engine = self.make()
            ip = "198.51.100.%d" % (60 + len(name))
            evs = [suricata(ip, self.clock.t, **over) for _ in range(10)]
            self.assertEqual(self.feed(evs, step=0), [], name)

    def test_suricata_claimed_trust_never_bans(self):
        evs = [suricata("198.51.100.7", self.clock.t) for _ in range(10)]
        for e in evs:
            e["src_trust"] = "claimed"
        self.assertEqual(self.feed(evs, step=0), [])

    def test_suricata_two_signatures_also_trigger(self):
        out = self.feed([suricata("198.51.100.7", self.clock.t, sid=2001), suricata("198.51.100.7", self.clock.t, sid=2002)], step=0)
        self.assertEqual(len(out), 1)
        self.engine = self.make()
        out = self.feed([suricata("198.51.100.8", self.clock.t, sid=2001), suricata("198.51.100.8", self.clock.t, sid=2001)], step=0)
        self.assertEqual(out, [])

    def test_suricata_without_a_sid_list_never_bans(self):
        os.unlink(self.sids)
        self.engine = self.make()
        self.assertEqual(self.feed([suricata("198.51.100.7", self.clock.t) for _ in range(5)], step=0), [])

    def test_ipv6_is_banned_as_a_64_and_counts_together(self):
        evs = []
        for i in range(5):
            evs.append(mk("ssh.fail", "2001:db8:aa:bb::%x" % (i + 1), self.clock.t))
        out = self.feed(evs, step=0)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["details"]["cidr"], "2001:db8:aa:bb::/64")
        self.assertEqual(out[0]["details"]["ttl_s"], 3600)
        self.assertEqual(self.bans_after_tick()["bans"][0]["cidr"], "2001:db8:aa:bb::/64")

    def bans_after_tick(self):
        self.clock.t += 6
        self.engine.tick(self.clock.t)
        return self.bans_json()

    def test_ipv6_has_no_local_escalation(self):
        for rnd in range(3):
            evs = [mk("ssh.fail", "2001:db8:aa:bb::1", self.clock.t) for _ in range(5)]
            out = self.feed(evs, step=0)
            self.assertEqual(out[0]["details"]["rung"], 0)
            self.assertEqual(out[0]["details"]["ttl_s"], 3600)
            self.clock.t += 3601
            self.engine.tick(self.clock.t)

    def test_other_kinds_are_ignored(self):
        evs = [mk("tetragon.nginx-exec", "198.51.100.7", self.clock.t, source="tetragon") for _ in range(50)]
        self.assertEqual(self.feed(evs, step=0), [])

    def test_hostile_event_shapes_never_raise(self):
        rnd = random.Random(99)
        junk = [None, 5, "x", [], {}, {"kind": 5}, {"kind": "ssh.fail"}, {"kind": "ssh.fail", "src_ip": 5, "src_trust": "tcp"},
                {"kind": "suricata.alert", "src_ip": "1.2.3.4", "src_trust": "tcp", "details": "str"},
                {"kind": "canary.tripwire", "src_ip": "1.2.3.4", "src_trust": "tcp", "details": {"status": "404x"}},
                {"kind": "ssh.fail", "src_ip": "1.2.3.4", "src_trust": "tcp", "ts": {"a": 1}},
                {"kind": "ssh.fail", "src_ip": "198.51.100.7", "src_trust": "tcp", "ts": "garbage"}]
        for j in junk:
            self.assertEqual(self.engine.observe(j, self.clock.t), [])
        # 20,000 seeded mutations of a good event: no exception, bounded time, no ban from broken evidence
        base = mk("ssh.fail", "198.51.100.7", self.clock.t)
        for i in range(20000):
            e = json.loads(json.dumps(base))
            for _ in range(rnd.randint(1, 3)):
                k = rnd.choice(list(e) + ["extra"])
                e[k] = rnd.choice([None, 1, -1, 2 ** 70, "", "x" * 100, [], {}, "198.51.100.%d" % rnd.randint(0, 300),
                                   "tcp", "::ffff:1.2.3.4", 1.5, True, {"a": {"b": []}}])
            self.engine.observe(e, self.clock.t)
        for b in self.engine.active_bans():
            self.assertIsNotNone(bm.parse_net(b["cidr"]))
        self.assertFalse(self.engine._apply_error.startswith("ban engine:"))


class TestPoliciesOfBanning(Base):
    def test_ladder_escalates_and_is_remembered(self):
        ttls = []
        for _ in range(6):
            out = self.ssh_fails("198.51.100.7", 5)
            self.assertEqual(len(out), 1)
            ttls.append((out[0]["details"]["rung"], out[0]["details"]["ttl_s"]))
            self.clock.t += out[0]["details"]["ttl_s"] + 5
            self.engine.tick(self.clock.t)
            self.assertEqual(self.engine.active_bans(), [])
        self.assertEqual(ttls, [(0, 3600), (1, 21600), (2, 86400), (3, 604800), (3, 604800), (3, 604800)])

    def test_memory_expires_after_fourteen_days(self):
        self.ssh_fails("198.51.100.7", 5)
        self.clock.t += 15 * 86400
        self.engine.tick(self.clock.t)
        out = self.ssh_fails("198.51.100.7", 5)
        self.assertEqual(out[0]["details"]["rung"], 0)

    def test_budget_thirty_an_hour_then_one_high_event(self):
        out = []
        for i in range(34):
            out += self.ssh_fails("198.51.%d.%d" % (100 + i // 200, 1 + i), 5)
        bans = [e for e in out if e["kind"] == "ban.local"]
        exhausted = [e for e in out if e["kind"] == "health.ban_budget"]
        self.assertEqual(len(bans), 30)
        self.assertEqual(len(exhausted), 1)
        self.assertEqual(exhausted[0]["sev"], "HIGH")
        self.assertEqual(self.engine.counts()["budget_used"], 30)
        self.clock.t += 3601
        out = self.ssh_fails("198.51.101.1", 5)
        self.assertEqual(out[0]["kind"], "ban.local")           # the hour rolled

    def test_max_active_cap(self):
        self.CFG = {"thresholds": {"ban_max_active": 3, "ban_budget_per_hour": 100}}
        self.engine = self.make()
        out = []
        for i in range(5):
            out += self.ssh_fails("198.51.100.%d" % (10 + i), 5)
        self.assertEqual(len([e for e in out if e["kind"] == "ban.local"]), 3)
        self.assertEqual(len([e for e in out if e["kind"] == "health.ban_budget"]), 1)

    def test_auto_ban_observe_writes_no_ban(self):
        self.engine = self.make({"bans": {"auto_ban": "observe"}, "thresholds": {}, "sites": {}})
        out = self.ssh_fails("198.51.100.7", 5)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["kind"], "ban.observed")
        self.assertEqual(self.engine.active_bans(), [])
        self.assertNotEqual(out[0]["kind"], "ban.local")           # a fleet vote must not come from observe mode

    def test_auto_ban_off_does_nothing(self):
        self.engine = self.make({"bans": {"auto_ban": "off"}, "thresholds": {}, "sites": {}})
        self.assertEqual(self.ssh_fails("198.51.100.7", 50), [])

    def test_never_ban_source_alerts_but_is_not_banned(self):
        self.engine = self.make({"bans": {"admin_ip": ["203.0.113.5/32"], "allow_cidr": "198.51.100.0/24"},
                                 "thresholds": {}, "sites": {}})
        out = self.feed([mk("canary.tripwire", "203.0.113.5", self.clock.t, status=404, ban=True) for _ in range(6)], step=0)
        self.assertEqual([e["kind"] for e in out], ["health.internal_source"])        # once an hour
        self.assertEqual(out[0]["sev"], "MEDIUM")
        self.assertEqual(self.engine.active_bans(), [])
        # an internal literal address too (10/8), and SSH failures from the admin stay quiet
        out = self.feed([mk("canary.tripwire", "10.1.2.3", self.clock.t, status=404, ban=True) for _ in range(6)], step=0)
        self.assertEqual([e["kind"] for e in out], ["health.internal_source"])
        self.assertEqual(self.ssh_fails("203.0.113.5", 30), [])
        self.assertEqual(self.ssh_fails("198.51.100.99", 30), [])                      # allow_cidr
        self.assertEqual(self.engine.active_bans(), [])

    def test_accepted_login_protects_from_ssh_bans_for_thirty_days(self):
        self.engine.observe(mk("ssh.login", "198.51.100.7", self.clock.t), self.clock.t)
        self.assertEqual(self.ssh_fails("198.51.100.7", 10), [])
        # other triggers still work for that address
        out = self.feed([mk("canary.tripwire", "198.51.100.7", self.clock.t, status=404, ban=True) for _ in range(5)], step=0)
        self.assertEqual(len(out), 1)
        self.engine = self.make()
        self.engine.observe(mk("ssh.login", "198.51.100.8", self.clock.t), self.clock.t)
        self.clock.t += 31 * 86400
        self.engine.tick(self.clock.t)
        self.assertEqual(len(self.ssh_fails("198.51.100.8", 5)), 1)

    def test_ban_that_overlaps_the_dynamic_never_list_is_refused_and_reported(self):
        self.engine = self.make({"bans": {"admin_ip": ["2001:db8:aa:bb::7/128"]}, "thresholds": {}, "sites": {}})
        out = self.feed([mk("ssh.fail", "2001:db8:aa:bb::99", self.clock.t) for _ in range(5)], step=0)
        # the /64 holds the admin's address: nothing is banned, one event and last_apply_error say why
        self.assertEqual([e["kind"] for e in out], ["health.ban_refused"])
        self.assertEqual(self.engine.active_bans(), [])
        self.assertIn("overlaps the never-ban list", self.engine.last_apply_error())
        self.assertEqual(self.engine.counts()["refused"], 1)

    def test_proxy_mode_on_turns_web_sourced_bans_off_but_not_ssh(self):
        self.engine = self.make({"bans": {"proxy_mode": "on"}, "thresholds": {}, "sites": {}})
        self.assertEqual(self.feed([mk("canary.tripwire", "198.51.100.7", self.clock.t, status=404, ban=True) for _ in range(8)], step=0), [])
        self.assertEqual(self.feed([suricata("198.51.100.7", self.clock.t, dst_port=443) for _ in range(4)], step=0), [])
        self.assertEqual(len(self.ssh_fails("198.51.100.7", 5)), 1)
        # suricata on another port is not a web signal
        self.assertEqual(len(self.feed([suricata("198.51.100.8", self.clock.t, dst_port=22) for _ in range(3)], step=0)), 1)

    def test_proxy_mode_off_never_overrides_inventory_real_ip(self):
        inv = self.p.inventory_json
        os.makedirs(os.path.dirname(inv), exist_ok=True)
        with open(inv, "w") as f:
            json.dump({"v": 1, "checks": {"real_ip": {"status": True}}}, f)
        self.engine = self.make({"bans": {"proxy_mode": "off"}, "thresholds": {}, "sites": {}})
        self.assertEqual(self.feed([mk("canary.tripwire", "198.51.100.7", self.clock.t, status=404, ban=True) for _ in range(8)], step=0), [])
        with open(inv, "w") as f:
            json.dump({"v": 1, "checks": {"real_ip": {"status": False}}}, f)
        self.engine = self.make({"bans": {"proxy_mode": "off"}, "thresholds": {}, "sites": {}})
        self.assertEqual(len(self.feed([mk("canary.tripwire", "198.51.100.7", self.clock.t, status=404, ban=True) for _ in range(5)], step=0)), 1)


class TestPause(Base):
    def write_pause(self, until):
        with open(self.p.pause_json, "w") as f:
            json.dump({"until": until}, f)

    def test_pause_stops_new_bans_and_empties_bans_json(self):
        self.ssh_fails("198.51.100.7", 5)
        self.clock.t += 6
        self.engine.tick(self.clock.t)
        self.assertEqual(len(self.bans_json()["bans"]), 1)
        self.write_pause(self.clock.t + 600)
        self.clock.t += 6
        evs = self.engine.tick(self.clock.t)
        self.assertEqual([e["kind"] for e in evs], ["health.pause"])
        j = self.bans_json()
        self.assertTrue(j["empty"])
        self.assertEqual(j["bans"], [])
        self.assertEqual(j["feeds"], {})
        self.assertIsNotNone(self.engine.paused_until())
        self.assertEqual(self.engine.counts()["paused"], 1)
        self.assertEqual(self.ssh_fails("198.51.100.8", 20), [])                 # no new bans while paused
        self.assertEqual(len(self.engine.active_bans()), 1)                     # the old one is kept in state
        # an expired pause file is ignored even though it is still there
        self.write_pause(self.clock.t - 1)
        self.clock.t += 6
        evs = self.engine.tick(self.clock.t)
        self.assertEqual([e["kind"] for e in evs], ["health.pause_end"])
        j = self.bans_json()
        self.assertFalse(j["empty"])
        self.assertEqual([b["cidr"] for b in j["bans"]], ["198.51.100.7/32"])
        self.assertEqual(len(self.ssh_fails("198.51.100.8", 5)), 1)

    def test_junk_pause_file_is_ignored(self):
        for content in ("not json", '{"until": "soon"}', '{"until": true}', "[]", '{"until": -5}'):
            with open(self.p.pause_json, "w") as f:
                f.write(content)
            self.clock.t += 6
            self.engine.tick(self.clock.t)
            self.assertIsNone(self.engine.paused_until(), content)
        os.unlink(self.p.pause_json)


class TestBansJson(Base):
    def test_shape_mode_and_no_tmp_left(self):
        self.engine = self.make({"bans": {"admin_ip": ["203.0.113.5/32"], "allow_cidr": ["198.51.100.0/24"]},
                                 "thresholds": {}, "sites": {"vpc_cidr": ["10.10.0.0/16"]}})
        self.ssh_fails("192.0.2.77", 5)
        self.clock.t += 6
        self.engine.tick(self.clock.t)
        path = self.p.bans_json
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644)
        j = self.bans_json()
        self.assertEqual(set(j), {"v", "written_at", "empty", "never", "bans", "feeds"})
        self.assertEqual(j["v"], 1)
        self.assertEqual(j["empty"], False)
        self.assertIsInstance(j["written_at"], int)
        self.assertEqual(j["feeds"], {})
        for n in ("203.0.113.5/32", "198.51.100.0/24", "10.10.0.0/16"):
            self.assertIn(n, j["never"])
        b = j["bans"][0]
        self.assertEqual(set(b), {"cidr", "expires", "source", "reason"})
        self.assertEqual((b["cidr"], b["source"], b["reason"]), ("192.0.2.77/32", "local", "ssh_fail"))
        self.assertIsInstance(b["expires"], int)
        self.assertEqual([n for n in os.listdir(self.p.run_dir) if n.endswith(".tmp")], [])
        for bad in j["never"]:
            self.assertIsNotNone(bm.parse_net(bad))

    def test_written_at_most_once_per_five_seconds(self):
        writes = []
        real = bm.atomic_write

        def counting(path, data, mode=0o600, fsync=False):
            if str(path) == str(self.p.bans_json):
                writes.append(self.clock.t)
            return real(path, data, mode, fsync)
        with mock.patch.object(bm, "atomic_write", counting):
            for i in range(20):
                self.engine.observe(mk("ssh.fail", "198.51.100.%d" % (i + 1), self.clock.t), self.clock.t)
                if i == 3:
                    self.ssh_fails("198.51.100.200", 5)
                self.engine.tick(self.clock.t)
                self.clock.t += 1
        self.assertGreaterEqual(len(writes), 2)
        for a, b in zip(writes, writes[1:]):
            self.assertGreaterEqual(b - a, 5.0)

    def test_unchanged_state_is_not_rewritten_before_five_minutes(self):
        self.engine.tick(self.clock.t)
        ino = os.stat(self.p.bans_json).st_ino
        for _ in range(10):
            self.clock.t += 10
            self.engine.tick(self.clock.t)
        self.assertEqual(os.stat(self.p.bans_json).st_ino, ino)
        self.clock.t += 400
        self.engine.tick(self.clock.t)
        self.assertNotEqual(os.stat(self.p.bans_json).st_ino, ino)

    def test_empty_flag_after_the_last_ban_goes(self):
        self.ssh_fails("198.51.100.7", 5)
        self.clock.t += 6
        self.engine.tick(self.clock.t)
        self.assertFalse(self.bans_json()["empty"])
        self.assertEqual(self.engine.unban("198.51.100.7"), ["198.51.100.7/32"])
        self.clock.t += 6
        self.engine.tick(self.clock.t)
        j = self.bans_json()
        self.assertEqual(j["bans"], [])
        self.assertTrue(j["empty"])                 # an explicit empty state, or edr-bans keeps the old one
        self.clock.t += 400
        self.engine.tick(self.clock.t)
        self.assertTrue(self.bans_json()["empty"])   # said again on a rewrite: a slow helper must not miss it
        self.clock.t += 1000
        self.engine.tick(self.clock.t)
        self.assertFalse(self.bans_json()["empty"])  # and dropped after 15 minutes

    def test_expiry_removes_the_entry(self):
        self.ssh_fails("198.51.100.7", 5)
        self.clock.t += 3601
        self.engine.tick(self.clock.t)
        self.assertEqual(self.bans_json()["bans"], [])
        self.assertEqual(self.engine.counts()["local"], 0)

    def test_write_failure_is_reported_not_raised(self):
        shutil.rmtree(self.p.run_dir)
        open(self.p.run_dir, "w").close()
        self.engine.tick(self.clock.t)
        self.assertIn("cannot write bans.json", self.engine.last_apply_error())
        os.unlink(self.p.run_dir)
        os.makedirs(self.p.run_dir)


class TestState(Base):
    def test_state_survives_a_restart(self):
        self.ssh_fails("198.51.100.7", 5)
        self.engine.unban("198.51.100.99")
        self.engine.observe(mk("ssh.login", "198.51.100.50", self.clock.t), self.clock.t)
        self.engine.flush()
        self.assertEqual(stat.S_IMODE(os.stat(self.p.ban_state).st_mode), 0o600)
        e2 = self.make()
        self.assertEqual([b["cidr"] for b in e2.active_bans()], ["198.51.100.7/32"])
        self.assertIn("198.51.100.7", e2.memory)
        self.assertIn("198.51.100.99", e2.allow)
        self.assertIn("198.51.100.50", e2.accepted)
        self.assertEqual(e2.memory["198.51.100.7"]["rung"], 0)

    def test_corrupt_state_is_ignored(self):
        for junk in ("not json", "[]", '{"v": 2}', '{"v": 1, "bans": [5, {"cidr": "junk"}, {"cidr": "10.0.0.0/8", "expires": 9e99}]}'):
            with open(self.p.ban_state, "w") as f:
                f.write(junk)
            e = self.make()
            self.assertEqual(len(e.active_bans()), 1 if "10.0.0.0/8" in junk else 0)

    def test_expired_entries_are_not_loaded(self):
        self.ssh_fails("198.51.100.7", 5)
        self.engine.flush()
        self.clock.t += 7200
        self.assertEqual(self.make().active_bans(), [])

    def test_unban_records_an_allow_entry_so_the_ladder_does_not_reban(self):
        self.ssh_fails("198.51.100.7", 5)
        self.assertEqual(self.engine.unban("198.51.100.7"), ["198.51.100.7/32"])
        self.assertEqual(self.engine.active_bans(), [])
        self.assertEqual(self.ssh_fails("198.51.100.7", 20), [])
        # an unban of a covering CIDR works too, and an IPv6 address means its /64
        self.ssh_fails("2001:db8:1:2::5", 5)
        self.assertEqual(self.engine.unban("2001:db8:1:2::77"), ["2001:db8:1:2::/64"])

    def test_unban_all_clears_memory_and_bans(self):
        self.ssh_fails("198.51.100.7", 5)
        self.ssh_fails("198.51.100.8", 5)
        self.assertEqual(self.engine.unban_all(), 2)
        self.assertEqual(self.engine.active_bans(), [])
        self.assertEqual(self.engine.memory, {})
        self.assertEqual(self.engine.counts()["budget_used"], 0)

    def test_command_inbox_is_consumed_and_answered(self):
        self.ssh_fails("198.51.100.7", 5)
        cmd = os.path.join(os.path.dirname(self.p.ban_state), "ban-cmd.json")
        with open(cmd, "w") as f:
            json.dump({"id": "abc", "cmds": [{"op": "unban", "addr": "198.51.100.7/32"}, {"op": "bogus"}, 5]}, f)
        self.clock.t += 6
        self.engine.tick(self.clock.t)
        self.assertFalse(os.path.exists(cmd))
        with open(cmd + ".done") as f:
            done = json.load(f)
        self.assertEqual(done["id"], "abc")
        self.assertEqual(done["results"], [{"op": "unban", "addr": "198.51.100.7/32", "removed": ["198.51.100.7/32"]}])
        self.assertEqual(self.engine.active_bans(), [])


class TestPolicyIntoNeverList(Base):
    def test_peers_and_hub_addresses_become_never_ban(self):
        self.engine.set_policy({"peers": ["192.0.2.10", "192.0.2.11", "10.1.1.1", "bogus", "2001:db8::5"],
                                "hub_addresses": ["192.0.2.200"]})
        self.assertEqual(len(self.ssh_fails("192.0.2.10", 20)), 0)
        self.assertEqual(len(self.ssh_fails("192.0.2.200", 20)), 0)
        self.engine.tick(self.clock.t + 6)
        never = self.bans_json()["never"]
        for n in ("192.0.2.10/32", "192.0.2.11/32", "192.0.2.200/32", "2001:db8::5/128"):
            self.assertIn(n, never)
        self.assertNotIn("10.1.1.1/32", never)                  # a never-ban literal is ignored as a peer
        self.assertEqual(len(self.ssh_fails("192.0.2.12", 5)), 1)

    def test_peers_are_single_addresses_with_a_72_hour_life(self):
        self.engine.set_policy({"peers": ["192.0.2.10"]})
        self.assertAlmostEqual(self.engine.peers["192.0.2.10"], self.clock.t + 72 * 3600, delta=2)
        self.clock.t += 72 * 3600 + 10
        self.engine.tick(self.clock.t)
        self.assertEqual(self.engine.peers, {})
        # refreshed by the next document
        self.engine.set_policy({"peers": ["192.0.2.10"]})
        self.clock.t += 3600
        self.engine.set_policy({"peers": ["192.0.2.10"]})
        self.clock.t += 71 * 3600
        self.engine.tick(self.clock.t)
        self.assertIn("192.0.2.10", self.engine.peers)

    def test_more_than_512_peers_is_refused_and_the_old_set_kept(self):
        self.engine.set_policy({"peers": ["192.0.2.10"]})
        self.engine.set_policy({"peers": ["203.0.%d.%d" % (i // 250, i % 250 + 1) for i in range(513)]})
        self.assertEqual(list(self.engine.peers), ["192.0.2.10"])
        self.assertIn("more than 512 peers", self.engine.last_apply_error())
        self.engine.set_policy({"peers": ["203.0.%d.%d" % (i // 250, i % 250 + 1) for i in range(512)]})
        self.assertEqual(len(self.engine.peers), 512)

    def test_at_most_four_hub_addresses(self):
        self.engine.set_policy({"peers": [], "hub_addresses": ["192.0.2.%d" % i for i in range(1, 9)]})
        self.assertEqual(len(self.engine.hub_policy_addrs), 4)

    def test_none_clears(self):
        self.engine.set_policy({"peers": ["192.0.2.10"]})
        self.engine.set_policy(None)
        self.assertEqual(self.engine.peers, {})

    def test_hub_addresses_of_every_generation_are_never_ban(self):
        from edragent import identity as idn
        for gen, addr in ((1, "192.0.2.100"), (2, "192.0.2.101,2001:db8::100")):
            d = os.path.join(self.p.identity_dir, "gen-%d" % gen)
            os.makedirs(d)
            idn.write_hub_conf(os.path.join(d, "hub.conf"), addr.split(","), 8443, 8444, "u", "0" * 64)
        e = self.make()
        self.assertEqual(len(self.feed_to(e, "192.0.2.100")), 0)
        self.assertEqual(len(self.feed_to(e, "192.0.2.101")), 0)
        e.tick(self.clock.t + 6)
        never = self.bans_json()["never"]
        for n in ("192.0.2.100/32", "192.0.2.101/32", "2001:db8::100/128"):
            self.assertIn(n, never)
        # after the old generation is deleted its address is no longer protected
        shutil.rmtree(os.path.join(self.p.identity_dir, "gen-1"))
        self.clock.t += 40
        e.tick(self.clock.t)
        self.assertNotIn("192.0.2.100/32", self.bans_json()["never"])

    def feed_to(self, e, ip):
        out = []
        for i in range(5):
            out += e.observe(mk("ssh.fail", ip, self.clock.t), self.clock.t)
        return out


class TestErrorsAndCounts(Base):
    def test_last_apply_error_includes_the_helpers_refusal(self):
        os.makedirs(os.path.dirname(self.p.bans_counters), exist_ok=True)
        with open(self.p.bans_counters, "w") as f:
            json.dump({"last_apply": {"ok": False, "error": "script did not parse", "refused": []}}, f)
        self.assertIn("edr-bans: script did not parse", self.engine.last_apply_error())
        with open(self.p.bans_counters, "w") as f:
            json.dump({"last_apply": {"ok": True, "error": ""}}, f)
        self.assertEqual(self.engine.last_apply_error(), "")

    def test_note_apply_error_expires(self):
        self.engine.note_apply_error("policy refused: x")
        self.assertEqual(self.engine.last_apply_error(), "policy refused: x")
        self.clock.t += 3601
        self.assertEqual(self.engine.last_apply_error(), "")

    def test_counts_keys(self):
        self.ssh_fails("198.51.100.7", 5)
        c = self.engine.counts()
        self.assertEqual(c["local"], 1)
        self.assertEqual(c["budget_used"], 1)
        self.assertTrue(all(isinstance(v, int) for v in c.values()))


class TestEdrBansReadsOurFile(Base):
    """The root helper must accept what the engine writes: run `edr-bans --print-script`
    on it. The helper only prints; it writes nothing and calls no nft."""

    HELPER = os.path.join(support.CODE, "edr-bans")

    def script(self):
        import subprocess
        r = subprocess.run([sys.executable, "-I", self.HELPER, "--root", self.env.root, "--print-script"],
                           capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout, r.stderr

    def setUp(self):
        super().setUp()
        if not os.path.exists(self.HELPER):
            self.skipTest("edr-bans is not there")

    def test_bans_never_and_the_empty_state_are_accepted(self):
        self.clock.t = time.time()                      # the helper judges expiry by the real clock
        self.engine = self.make({"bans": {"admin_ip": ["203.0.113.5/32"]}, "thresholds": {}, "sites": {"vpc_cidr": ["10.10.0.0/16"]}})
        self.ssh_fails("198.51.100.7", 5)
        self.ssh_fails("2001:db8:1:2::5", 5)
        self.engine.set_policy({"peers": ["192.0.2.10"], "hub_addresses": ["192.0.2.200"]})
        self.engine.flush()
        rc, out, errs = self.script()
        self.assertEqual(rc, 0, errs)
        self.assertIn("198.51.100.7", out)
        self.assertIn("2001:db8:1:2::/64", out)
        for n in ("203.0.113.5", "192.0.2.10", "192.0.2.200"):
            self.assertIn(n, out)
        # a pause: the explicit empty state
        with open(self.p.pause_json, "w") as f:
            json.dump({"until": int(time.time()) + 600}, f)
        self.clock.t = time.time() + 10
        self.engine.tick(self.clock.t)
        rc, out, errs = self.script()
        self.assertEqual(rc, 0, errs)
        self.assertNotIn("198.51.100.7", out)


if __name__ == "__main__":
    unittest.main()
