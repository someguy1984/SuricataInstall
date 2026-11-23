"""L0 tests of agent/edr-dns-watch (client PLAN section 4.4): the probe against a fake resolver, the
fail-open and re-lock rules, the flap guard, the pause, the boot unit, stamps and the generated lock
file. nft and systemctl are fixtures; one test loads the generated file into a throwaway netns."""

import io
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from test_helper_common import FILES, TmpCase, have, load_helper, run_helper  # noqa: E402

W = load_helper("edr-dns-watch")
W.PROBE_TIMEOUT = 0.3
NOW = 1795000000


class FakeResolver:
    """A UDP DNS server on 127.0.0.1 whose answer is chosen by the test: ok, nx, servfail, refused, drop."""

    def __init__(self):
        self.mode = "ok"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.queries = []
        self.stop = False
        self.t = threading.Thread(target=self.loop, daemon=True)
        self.t.start()

    def loop(self):
        while not self.stop:
            try:
                data, addr = self.sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                return
            self.queries.append(data[12:])
            if self.mode == "drop":
                continue
            rcode = {"ok": 0, "nx": 3, "servfail": 2, "refused": 5}[self.mode]
            self.sock.sendto(data[:2] + struct.pack("!H", 0x8180 | rcode) + data[4:], addr)

    def close(self):
        self.stop = True
        self.t.join(2)
        self.sock.close()


class Rec(dict):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.calls = []

    def get(self, key, default=None):
        self.calls.append(key)
        return dict.get(self, key, default if default is not None else {"rc": 0, "out": ""})


class WatchCase(TmpCase):
    def setUp(self):
        super().setUp()
        self.dns = FakeResolver()
        self.addCleanup(self.dns.close)
        self.fx = Rec({"nft -t list table inet edr_dns": {"rc": 0, "out": "table"}})
        self.put("/etc/edr-dns/edr-dns.nft", "table inet edr_dns\n")
        self.now = NOW
        self.all_out = ""

    def watch(self, cmd="probe", extra=(), now=None):
        env = W.Env(self.root, dry=False, fixtures=self.fx, now=now if now is not None else self.now)
        orig = W.parse_common
        W.parse_common = lambda argv: (env, "", list(argv))
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                rc = W.main([cmd, "--resolver", "127.0.0.1:%d" % self.dns.port] + list(extra))
        finally:
            W.parse_common = orig
        self.out = buf.getvalue()
        self.all_out += self.out
        return rc

    def status(self):
        return self.read_json("/run/edr-dns-watch/status.json")

    def calls(self, prefix):
        return [c for c in self.fx.calls if c.startswith(prefix)]


class TestProbe(WatchCase):
    def test_noerror_and_nxdomain_are_healthy(self):
        for mode, want in (("ok", True), ("nx", True), ("servfail", False), ("refused", False), ("drop", False)):
            self.dns.mode = mode
            self.assertEqual(W.probe("127.0.0.1", self.dns.port, W.fresh_name(), timeout=0.3), want, mode)

    def test_the_probe_uses_a_fresh_label_under_example_com(self):
        a, b = W.fresh_name(), W.fresh_name()
        self.assertNotEqual(a, b)
        self.assertTrue(a.endswith(".example.com"))
        W.probe("127.0.0.1", self.dns.port, a)
        self.assertEqual(self.dns.queries[0][1:1 + a.split(".")[0].__len__()].decode(), a.split(".")[0])

    def test_a_wrong_id_or_a_query_packet_is_not_an_answer(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.settimeout(0.5)
        port = s.getsockname()[1]
        def liar():
            data, addr = s.recvfrom(1024)
            s.sendto(struct.pack("!HH", (struct.unpack("!H", data[:2])[0] + 1) & 0xFFFF, 0x8180) + data[4:], addr)
        t = threading.Thread(target=liar)
        t.start()
        self.assertFalse(W.probe("127.0.0.1", port, "x.example.com", timeout=0.5))
        t.join()
        s.close()

    def test_strict_probe_counts_only_noerror(self):
        self.dns.mode = "nx"
        self.assertFalse(W.probe("127.0.0.1", self.dns.port, "db.internal.example", strict=True))
        self.assertTrue(W.probe("127.0.0.1", self.dns.port, "db.internal.example"))


class TestStateMachine(WatchCase):
    def test_healthy_proxy_keeps_the_lock(self):
        self.assertEqual(self.watch(), 0)
        st = self.status()
        self.assertEqual((st["state"], st["relocks"]), ("locked", 0))
        self.assertEqual(set(st), {"written_at", "state", "since", "relocks"})
        self.assertEqual(os.stat(self.root + "/run/edr-dns-watch/status.json").st_mode & 0o777, 0o640)

    def test_two_failures_restart_the_proxy_four_open_the_lock(self):
        self.dns.mode = "servfail"
        self.watch(now=NOW)
        self.assertEqual(self.calls("systemctl restart dnscrypt"), [])
        self.watch(now=NOW + 15)
        self.assertEqual(len(self.calls("systemctl restart dnscrypt-proxy.service")), 1)
        self.assertEqual(self.status()["state"], "locked")
        self.watch(now=NOW + 30)
        self.assertEqual(self.status()["state"], "locked")
        self.watch(now=NOW + 45)
        self.assertEqual(self.status()["state"], "open")
        self.assertIn("nft delete table inet edr_dns", self.fx.calls)
        self.assertIn("systemctl restart systemd-resolved.service", self.fx.calls)
        with open(self.root + "/run/systemd/resolved.conf.d/zzz-edr-failopen.conf") as fh:
            self.assertEqual(fh.read(), "[Resolve]\nDNS=\nDomains=\n")
        self.assertIn("<2>edr-dns-watch: FAILOPEN", self.out)

    def test_a_good_probe_resets_the_failure_count(self):
        self.dns.mode = "drop"
        self.watch(now=NOW)
        self.watch(now=NOW + 15)
        self.dns.mode = "ok"
        self.watch(now=NOW + 30)
        self.dns.mode = "drop"
        self.watch(now=NOW + 45)
        self.watch(now=NOW + 60)
        self.assertEqual(self.status()["state"], "locked")

    def _open_it(self, t0):
        self.dns.mode = "servfail"
        for i in range(4):
            self.watch(now=t0 + 15 * i)
        self.dns.mode = "ok"
        return t0 + 45

    def test_relock_needs_six_good_probes_and_five_minutes_open(self):
        t = self._open_it(NOW)
        for i in range(1, 12):                                         # good probes, but not yet 5 minutes open
            self.watch(now=t + 15 * i)
        self.assertEqual(self.status()["state"], "open")
        self.assertEqual(self.calls("nft -f "), [])
        self.watch(now=t + 301)
        st = self.status()
        self.assertEqual((st["state"], st["relocks"]), ("locked", 1))
        self.assertIn("nft -c -f %s/etc/edr-dns/edr-dns.nft" % self.root, self.fx.calls)
        self.assertIn("nft -f %s/etc/edr-dns/edr-dns.nft" % self.root, self.fx.calls)
        self.assertFalse(os.path.exists(self.root + "/run/systemd/resolved.conf.d/zzz-edr-failopen.conf"))

    def test_five_minutes_without_six_good_probes_does_not_relock(self):
        t = self._open_it(NOW)
        self.watch(now=t + 400)                                         # one good probe after a long time
        self.assertEqual(self.status()["state"], "open")

    def test_a_lock_file_that_does_not_load_stays_open(self):
        t = self._open_it(NOW)
        self.fx["nft -c -f %s/etc/edr-dns/edr-dns.nft" % self.root] = {"rc": 1, "err": "syntax error"}
        for i in range(1, 10):
            self.watch(now=t + 301 + 15 * i)
        self.assertEqual(self.status()["state"], "open")
        self.assertTrue(os.path.exists(self.root + "/run/systemd/resolved.conf.d/zzz-edr-failopen.conf"))

    def test_three_relocks_in_an_hour_stay_open_as_flapping_until_relock_by_hand(self):
        t = NOW
        for _round in range(3):
            t = self._open_it(t) + 301
            for i in range(7):
                self.watch(now=t + 15 * i)
            t += 120
            self.assertEqual(self.status()["state"], "locked", _round)
        t = self._open_it(t) + 301
        for i in range(8):
            self.watch(now=t + 15 * i)
        st = self.status()
        self.assertEqual(st["state"], "flapping")
        self.assertIn("<3>edr-dns-watch: FLAPPING", self.all_out)
        for i in range(8, 30):
            self.watch(now=t + 15 * i)
        self.assertEqual(self.status()["state"], "flapping")
        self.assertEqual(self.watch("relock", now=t + 600), 0)
        st = self.status()
        self.assertEqual((st["state"], st["relocks"]), ("locked", 0))

    def test_relock_by_hand_needs_a_healthy_proxy(self):
        t = self._open_it(NOW)
        self.dns.mode = "servfail"
        self.assertEqual(self.watch("relock", now=t + 10), 2)
        self.assertEqual(self.status()["state"], "open")

    def test_removed_table_is_open_not_locked(self):
        self.fx["nft -t list table inet edr_dns"] = {"rc": 1}
        self.watch()
        self.assertEqual(self.status()["state"], "open")

    def test_pause_deletes_the_table_never_relocks_and_reports_paused(self):
        self.put("/etc/edr-agent/pause.json", json.dumps({"until": NOW + 3600}))
        self.dns.mode = "servfail"
        for i in range(8):
            self.watch(now=NOW + 15 * i)
        self.assertEqual(self.status()["state"], "paused")
        self.assertIn("nft delete table inet edr_dns", self.fx.calls)
        self.assertEqual(self.calls("systemctl restart dnscrypt"), [])  # no fail-open logic while paused
        self.assertNotIn("FAILOPEN", self.out)
        self.dns.mode = "ok"
        self.fx["nft -t list table inet edr_dns"] = {"rc": 1}
        for i in range(10):
            self.watch(now=NOW + 200 + 15 * i)
        self.assertEqual(self.status()["state"], "paused")
        self.assertEqual(self.calls("nft -f "), [])
        # the pause ends: the same path as RELOCK, after a health check
        self.watch(now=NOW + 3700)
        self.assertEqual(self.status()["state"], "locked")
        self.assertTrue(self.calls("nft -f "))

    def test_pause_end_with_a_dead_proxy_stays_open(self):
        self.put("/etc/edr-agent/pause.json", json.dumps({"until": NOW + 100}))
        self.watch(now=NOW)
        self.dns.mode = "drop"
        self.watch(now=NOW + 200)
        self.assertEqual(self.status()["state"], "open")

    def test_resolve_check_names_must_resolve(self):
        self.put("/etc/edr-agent/local.conf", "[dns]\nresolve_check = db.example.internal\n")
        self.dns.mode = "nx"
        for i in range(4):
            self.watch(now=NOW + 15 * i)
        self.assertEqual(self.status()["state"], "open")               # NXDOMAIN for a site name is a failure


class TestBoot(WatchCase):
    def test_boot_loads_the_lock_after_a_check(self):
        self.assertEqual(self.watch("boot"), 0)
        self.assertEqual(self.status()["state"], "locked")
        i = self.fx.calls.index("nft -c -f %s/etc/edr-dns/edr-dns.nft" % self.root)
        self.assertEqual(self.fx.calls[i + 1], "nft -f %s/etc/edr-dns/edr-dns.nft" % self.root)

    def test_boot_with_a_bad_file_leaves_the_box_open(self):
        self.fx["nft -c -f %s/etc/edr-dns/edr-dns.nft" % self.root] = {"rc": 1, "err": "bad"}
        self.watch("boot")
        self.assertEqual(self.status()["state"], "open")
        self.assertEqual(self.calls("nft -f "), [])

    def test_boot_with_a_missing_file_is_open(self):
        os.unlink(self.root + "/etc/edr-dns/edr-dns.nft")
        self.watch("boot")
        self.assertEqual(self.status()["state"], "open")

    def test_boot_during_a_pause_loads_nothing(self):
        self.put("/etc/edr-agent/pause.json", json.dumps({"until": NOW + 600}))
        self.watch("boot")
        self.assertEqual(self.status()["state"], "paused")
        self.assertEqual(self.calls("nft "), [])

    def test_boot_with_lockdown_off_loads_nothing(self):
        self.put("/etc/edr-agent/local.conf", "[dns]\nlockdown = off\n")
        self.watch("boot")
        self.assertEqual(self.calls("nft "), [])


class TestRender(TmpCase):
    SELF = "# decoded from the stamps\n9.9.9.9\n149.112.112.112\n1.1.1.1\n1.0.0.1\ndns.quad9.net\ncloudflare-dns.com\n"

    def render(self, extra_conf="", proxy_user="nobody", selfconf=None):
        self.put("/etc/edr-dns/doh-self.conf", self.SELF if selfconf is None else selfconf)
        with open(os.path.join(FILES, "doh-resolvers.conf")) as fh:
            self.put("/etc/edr-dns/doh-resolvers.conf", fh.read())
        if extra_conf:
            self.put("/etc/edr-agent/local.conf", extra_conf)
        rc, out, err = run_helper("edr-dns-watch", ["render", "--root", self.root, "--proxy-user", proxy_user, "--files-dir", FILES])
        return rc, err

    def lock(self):
        with open(self.root + "/etc/edr-dns/edr-dns.nft") as fh:
            return fh.read()

    def test_the_kits_own_resolvers_are_never_in_the_blocked_sets(self):
        rc, err = self.render()
        self.assertEqual(rc, 0, err)
        text = self.lock()
        doh4 = [l for l in text.splitlines() if l.strip().startswith("set doh4")][0]
        for own in ("9.9.9.9", "149.112.112.112", "1.1.1.1", "1.0.0.1"):
            self.assertNotIn(own + ",", doh4 + ",", own)
            self.assertNotIn(" " + own + " ", doh4)
        self.assertIn("8.8.8.8", doh4)                                 # other resolvers are logged
        self.assertIn("1.1.1.2", doh4)
        stamp4 = [l for l in text.splitlines() if l.strip().startswith("set stamp4")][0]
        for own in ("9.9.9.9", "149.112.112.112", "1.1.1.1", "1.0.0.1"):
            self.assertIn(own, stamp4)
        with open(self.root + "/etc/edr-dns/doh-resolvers.filtered.conf") as fh:
            filtered = fh.read().split()
        self.assertNotIn("quad9.net", filtered)                          # a suffix of the stamp host dns.quad9.net
        self.assertNotIn("cloudflare-dns.com", filtered)
        self.assertNotIn("9.9.9.9", filtered)
        self.assertIn("dns.google", filtered)

    def test_exemption_is_by_user_name_first_then_reject_then_log_rules(self):
        rc, err = self.render()
        lines = [l.strip() for l in self.lock().splitlines()]
        out = [l for l in lines if l.startswith(("meta", "oifname", "tcp dport"))]
        self.assertEqual(out[0], 'oifname "lo" return')
        self.assertIn('meta skuid "nobody" tcp dport 443 ip daddr @stamp4 accept', out[1])
        self.assertTrue(any("self" in l and "reject" in l for l in out))
        iplain = next(i for i, l in enumerate(out) if '"edr-dnslock: plain "' in l)
        irej = next(i for i, l in enumerate(out) if l.startswith("meta l4proto tcp th dport { 53, 853 } reject with tcp reset"))
        self.assertLess(iplain, irej)                                  # logging has no verdict: reject rules follow
        self.assertFalse(any("@doh4 reject" in l for l in out))        # the DoH rules only log by default

    def test_the_sandbox_drop_in_allows_each_resolver_address(self):
        self.put("/etc/edr-dns/vpc-resolver", "10.116.0.2\n")
        rc, err = self.render("[dns]\nvpc_dns = auto\n")
        self.assertEqual(rc, 0, err)
        path = self.root + "/etc/systemd/system/dnscrypt-proxy.service.d/50-edr.conf"
        with open(path) as fh:
            text = fh.read()
        allows = [l for l in text.splitlines() if l.startswith("IPAddressAllow=")]
        self.assertEqual(allows[0], "IPAddressAllow=localhost")
        for ip in ("9.9.9.9", "149.112.112.112", "1.1.1.1", "1.0.0.1", "10.116.0.2"):
            self.assertIn("IPAddressAllow=" + ip, allows)
        self.assertNotIn("@IPADDRESSALLOW@", text)
        self.assertIn("IPAddressDeny=any", text)
        # rendering again starts from the template, so it never doubles the lines
        self.render("[dns]\nvpc_dns = auto\n")
        with open(path) as fh:
            self.assertEqual(fh.read(), text)

    def test_options_add_rules(self):
        self.put("/etc/edr-dns/vpc-resolver", "10.116.0.2\n")
        rc, err = self.render("[dns]\nblock_doh_ips = on\nvpc_dns = auto\nlock_forwarded = on\n")
        text = self.lock()
        self.assertIn('ip daddr 10.116.0.2 th dport 53 accept', text)
        self.assertIn("@doh4 reject with tcp reset", text)
        self.assertIn("hook forward priority -150", text)

    def test_nothing_is_rendered_without_a_resolver_to_exempt(self):
        rc, err = self.render(selfconf="# empty\n")
        self.assertEqual(rc, 3)
        self.assertFalse(os.path.exists(self.root + "/etc/edr-dns/edr-dns.nft"))
        rc, err = self.render(selfconf="dns.quad9.net\n")
        self.assertEqual(rc, 3)

    @unittest.skipUnless(have("unshare") and have("nft") and os.geteuid() == 0, "needs root, unshare and nft")
    def test_the_rendered_lock_loads_in_a_throwaway_netns(self):
        import pwd
        user = "nobody" if any(p.pw_name == "nobody" for p in pwd.getpwall()) else None
        if user is None:
            self.skipTest("no nobody user")
        for conf in ("", "[dns]\nblock_doh_ips = on\nlock_forwarded = on\n"):
            self.render(conf, proxy_user=user)
            r = subprocess.run(["unshare", "-n", "nft", "-c", "-f", self.root + "/etc/edr-dns/edr-dns.nft"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
        # loaded for real in the empty namespace: the table, then a second load replaces it atomically
        script = "nft -f %s && nft -f %s && nft -t list table inet edr_dns" % ((self.root + "/etc/edr-dns/edr-dns.nft",) * 2)
        r = subprocess.run(["unshare", "-n", "sh", "-c", script], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("edr-dnslock: plain", r.stdout)


class TestStamps(TmpCase):
    def test_decode_the_shipped_tomls(self):
        for name in ("dnscrypt-proxy-2.0.toml", "dnscrypt-proxy-2.1.toml"):
            rc, out, err = run_helper("edr-dns-watch", ["decode-stamps", os.path.join(FILES, name)])
            self.assertEqual(rc, 0, err)
            items = out.split()
            for need in ("9.9.9.9", "149.112.112.112", "1.1.1.1", "1.0.0.1", "dns.quad9.net", "cloudflare-dns.com"):
                self.assertIn(need, items, name)

    def test_decode_stamp_forms(self):
        self.assertIsNone(W.decode_stamp("sdns://!!!"))
        self.assertIsNone(W.decode_stamp("https://x"))
        self.assertIsNone(W.decode_stamp("sdns://AQcAAAAAAAAABzEuMS4xLjEA"))     # a DNSCrypt stamp (0x01), not DoH


if __name__ == "__main__":
    unittest.main()
