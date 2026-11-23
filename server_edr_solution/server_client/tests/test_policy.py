import copy
import json
import os
import random
import time
import unittest

import test_transport_pki as support
from test_transport_pki import HubPair, err, reply
from edragent import bans as bm
from edragent import identity as idn
from edragent import policy as pol
from edragent import transport as tr

NOW = 1795000000.0


def good(**over):
    d = {"rev": "0123456789abcdef", "hub_time": int(NOW), "hub_addresses": ["203.0.113.5"], "port": 8443,
         "bans": [], "feeds": {}, "peers": ["192.0.2.10", "192.0.2.11"]}
    d.update(over)
    return d


class TestValidate(unittest.TestCase):
    def test_a_good_p2_document(self):
        p = pol.validate(good(), NOW)
        self.assertEqual(p.rev, "0123456789abcdef")
        self.assertEqual(p.peers, ["192.0.2.10", "192.0.2.11"])
        self.assertEqual(p.hub_addresses, ["203.0.113.5"])
        self.assertEqual(p.port, 8443)
        self.assertEqual((p.bans, p.feeds), ([], {}))
        self.assertEqual(p.never_doc(), {"peers": ["192.0.2.10", "192.0.2.11"], "hub_addresses": ["203.0.113.5"]})

    def test_unknown_keys_are_ignored(self):
        p = pol.validate(good(future_field={"a": 1}, reason_text="x"), NOW)
        self.assertEqual(p.rev, "0123456789abcdef")

    def test_rev_hub_time_and_types(self):
        for bad in (dict(rev=None), dict(rev="ABCDEF0123456789"), dict(rev="0123456789abcde"), dict(rev="0123456789abcdef0"),
                    dict(rev=5), dict(hub_time="1795000000"), dict(hub_time=True), dict(hub_time=0), dict(hub_time=-5),
                    dict(hub_time=2 ** 50), dict(hub_time=1.5), dict(peers="192.0.2.10"), dict(peers={"a": 1}),
                    dict(bans={}), dict(bans="x"), dict(feeds=[]), dict(feeds="x"), dict(hub_addresses="203.0.113.5"),
                    dict(hub_addresses=["junk"]), dict(hub_addresses=[5]), dict(port="8443"), dict(port=0), dict(port=70000),
                    dict(port=True), dict(feeds={"dshield": "x"})):
            with self.assertRaises(pol.PolicyRefused, msg=repr(bad)):
                pol.validate(good(**bad), NOW)
        for doc in (None, [], "x", 5):
            with self.assertRaises(pol.PolicyRefused):
                pol.validate(doc, NOW)
        d = good()
        del d["rev"]
        with self.assertRaises(pol.PolicyRefused):
            pol.validate(d, NOW)

    def test_missing_optional_parts_are_empty(self):
        p = pol.validate({"rev": "0123456789abcdef", "hub_time": int(NOW)}, NOW)
        self.assertEqual((p.peers, p.bans, p.feeds, p.hub_addresses, p.port), ([], [], {}, [], None))

    def test_peers_are_single_addresses_only(self):
        p = pol.validate(good(peers=["192.0.2.10", "192.0.2.0/24", "junk", " 192.0.2.12", "01.2.3.4", 5, None,
                                     "192.0.2.10", "2001:DB8::5", "::ffff:192.0.2.13"]), NOW)
        self.assertEqual(p.peers, ["192.0.2.10", "2001:db8::5", "192.0.2.13"])
        self.assertEqual(p.invalid, 6)

    def test_caps_are_refused_never_truncated(self):
        ok = ["198.51.%d.%d" % (i // 250, i % 250 + 1) for i in range(512)]
        self.assertEqual(len(pol.validate(good(peers=ok), NOW).peers), 512)
        with self.assertRaises(pol.PolicyRefused) as cm:
            pol.validate(good(peers=ok + ["198.51.9.9"]), NOW)
        self.assertIn("513", str(cm.exception))
        bans = [{"cidr": "198.51.%d.%d/32" % (i // 250, i % 250 + 1), "expires_at": int(NOW) + 3600, "source": "fleet",
                 "reason_id": "fleet_quorum"} for i in range(10000)]
        self.assertEqual(len(pol.validate(good(bans=bans), NOW).bans), 10000)
        with self.assertRaises(pol.PolicyRefused):
            pol.validate(good(bans=bans + [bans[0]]), NOW)
        feed = {"dshield": ["198.51.%d.%d/32" % (i // 250 % 250, i % 250 + 1) for i in range(100000)],
                "spamhaus_drop_v4": ["203.0.%d.%d/32" % (i // 250 % 250, i % 250 + 1) for i in range(100000)]}
        self.assertEqual(sum(len(v) for v in pol.validate(good(feeds=feed), NOW).feeds.values()), 200000)
        feed["spamhaus_drop_v6"] = ["2001:db8::1/128"]
        with self.assertRaises(pol.PolicyRefused) as cm:
            pol.validate(good(feeds=feed), NOW)
        self.assertIn("200000", str(cm.exception))
        with self.assertRaises(pol.PolicyRefused):
            pol.validate(good(hub_addresses=["192.0.2.%d" % i for i in range(1, 6)]), NOW)

    def test_closed_vocabularies(self):
        bans = [{"cidr": "198.51.100.7/32", "expires_at": int(NOW) + 100, "source": "fleet", "reason_id": "fleet_quorum"},
                {"cidr": "198.51.100.8/32", "expires_at": int(NOW) + 100, "source": "operator", "reason_id": "operator"},
                {"cidr": "198.51.100.9/32", "expires_at": int(NOW) + 100, "source": "<script>", "reason_id": "host web-2 said so"},
                {"cidr": "198.51.100.10/32", "expires_at": int(NOW) + 100, "source": 5, "reason_id": None}]
        p = pol.validate(good(bans=bans), NOW)
        self.assertEqual([(b["source"], b["reason_id"]) for b in p.bans],
                         [("fleet", "fleet_quorum"), ("operator", "operator"), ("unknown", "unknown"), ("unknown", "unknown")])
        feeds = {"spamhaus_drop_v4": ["198.51.100.0/24"], "spamhaus_drop_v6": [], "dshield": ["203.0.113.0/24"], "evil_feed": ["1.0.0.0/8"]}
        p = pol.validate(good(feeds=feeds), NOW)
        self.assertEqual(sorted(p.feeds), ["dshield", "spamhaus_drop_v4", "spamhaus_drop_v6"])
        self.assertEqual(p.ignored_feeds, 1)
        self.assertEqual(pol.SOURCES, ("fleet", "operator"))
        self.assertEqual(pol.REASON_IDS, ("fleet_quorum", "operator"))
        self.assertEqual(pol.FEED_NAMES, ("spamhaus_drop_v4", "spamhaus_drop_v6", "dshield"))

    def test_expiry_is_expires_at_minus_hub_time(self):
        """The client's own clock error cannot shift a ban: remaining = expires_at - hub_time."""
        hub_time = 1_900_000_000
        for local in (NOW, NOW - 86400, NOW + 5000):
            doc = good(hub_time=hub_time, bans=[{"cidr": "198.51.100.7/32", "expires_at": hub_time + 600, "source": "fleet",
                                                 "reason_id": "fleet_quorum"},
                                                {"cidr": "198.51.100.8/32", "expires_at": hub_time - 1, "source": "fleet", "reason_id": "fleet_quorum"},
                                                {"cidr": "198.51.100.9/32", "expires_at": hub_time + 99 * 86400, "source": "operator",
                                                 "reason_id": "operator"}])
            p = pol.validate(doc, local)
            self.assertEqual([(b["cidr"], b["remaining"]) for b in p.bans],
                             [("198.51.100.7/32", 600), ("198.51.100.9/32", 7 * 86400)])     # expired dropped, 7 days at most
            self.assertEqual(pol.absolute_expiry(p.bans[0]["remaining"], local), local + 600)
            self.assertAlmostEqual(p.skew, hub_time - local)

    def test_invalid_entries_are_dropped_and_counted(self):
        bans = [{"cidr": "198.51.100.7/24", "expires_at": int(NOW) + 5, "source": "fleet", "reason_id": "fleet_quorum"},
                {"cidr": "198.51.100.8/32", "expires_at": "soon", "source": "fleet"}, 5, {"expires_at": 5},
                {"cidr": "198.51.100.9/32", "expires_at": int(NOW) + 5, "source": "fleet", "reason_id": "fleet_quorum"}]
        p = pol.validate(good(bans=bans), NOW)
        self.assertEqual([b["cidr"] for b in p.bans], ["198.51.100.9/32"])
        self.assertEqual(p.invalid, 4)

    def test_random_documents_never_escape_as_exceptions(self):
        rnd = random.Random(8)
        base = good(bans=[{"cidr": "198.51.100.7/32", "expires_at": int(NOW) + 5, "source": "fleet", "reason_id": "operator"}],
                    feeds={"dshield": ["198.51.100.0/24"]})
        junk = [None, 1, -1, 2 ** 80, "", "x" * 300, [], {}, [[]], {"a": []}, 1.5, True, "198.51.100.7", ["x"] * 3]
        for _ in range(3000):
            d = copy.deepcopy(base)
            for _ in range(rnd.randint(1, 3)):
                k = rnd.choice(list(d))
                d[k] = rnd.choice(junk)
            try:
                p = pol.validate(d, NOW)
            except pol.PolicyRefused:
                continue
            for c in p.peers:
                self.assertIsNotNone(bm.parse_ip(c))
            for b in p.bans:
                self.assertIsNotNone(bm.parse_net(b["cidr"]))


class TestPollerOverTheWire(unittest.TestCase):
    def setUp(self):
        self.env = support.Env()
        self.addCleanup(self.env.cleanup)
        self.p = self.env.paths
        self.hubs = HubPair()
        self.addCleanup(self.hubs.stop)
        support.make_identity(self.env, self.hubs.pki, self.hubs.fleet_port, cn=self.hubs.uuid)
        self.engine = bm.BanEngine({"bans": {}, "thresholds": {}, "sites": {}}, self.p,
                                   proc_dir=os.path.join(self.env.root, "proc"), resolv_conf="/nonexistent",
                                   utmp_path="/nonexistent")
        self.client = tr.HubClient(lambda: idn.load_current(self.p).target())
        self.logs = []
        self.poller = pol.PolicyPoller(self.p, self.client, self.engine, log=self.logs.append)

    def test_first_poll_applies_peers_and_the_second_gets_304(self):
        self.hubs.peers = ["192.0.2.10", "192.0.2.11"]
        oc = self.poller.poll()
        self.assertEqual(oc.action, tr.OK)
        self.assertEqual(self.poller.rev_applied, "0123456789abcdef")
        self.assertEqual(sorted(self.engine.peers), ["192.0.2.10", "192.0.2.11"])
        self.assertEqual(self.poller.last_gen, "gen-1")
        self.assertIsNotNone(self.poller.last_ok)
        self.assertNotIn("if-none-match", self.hubs.fleet.requests[0].headers)
        oc = self.poller.poll()
        self.assertEqual(oc.action, tr.UNCHANGED)
        self.assertEqual(self.hubs.fleet.requests[1].headers["if-none-match"], '"0123456789abcdef"')
        # a 304 refreshes the 72 h peer timeout
        self.engine.peers["192.0.2.10"] = time.time() + 100
        self.poller.poll()
        self.assertGreater(self.engine.peers["192.0.2.10"], time.time() + 71 * 3600)

    def test_a_new_rev_replaces_the_peers(self):
        self.hubs.peers = ["192.0.2.10"]
        self.poller.poll()
        self.hubs.peers = ["192.0.2.12"]
        self.hubs.rev = "fedcba9876543210"
        self.poller.poll()
        self.assertEqual(list(self.engine.peers), ["192.0.2.12"])
        self.assertEqual(self.poller.rev_applied, "fedcba9876543210")

    def test_applied_rev_survives_a_restart_and_a_304_reapplies_the_saved_peers(self):
        self.hubs.peers = ["192.0.2.10"]
        self.poller.poll()
        engine2 = bm.BanEngine({"bans": {}, "thresholds": {}, "sites": {}}, self.p, proc_dir=os.path.join(self.env.root, "proc"),
                               resolv_conf="/nonexistent", utmp_path="/nonexistent")
        engine2.set_policy(None)
        poller2 = pol.PolicyPoller(self.p, self.client, engine2)
        self.assertEqual(poller2.rev_applied, "0123456789abcdef")
        self.assertEqual(poller2.poll().action, tr.UNCHANGED)
        self.assertEqual(list(engine2.peers), ["192.0.2.10"])

    def test_a_policy_over_the_caps_is_refused_and_the_old_state_kept(self):
        self.hubs.peers = ["192.0.2.10"]
        self.poller.poll()
        self.hubs.peers = ["198.51.%d.%d" % (i // 250, i % 250 + 1) for i in range(513)]
        self.hubs.rev = "fedcba9876543210"
        oc = self.poller.poll()
        self.assertEqual(oc.action, tr.LOG_RETRY)
        self.assertEqual(oc.code, "policy_refused")
        self.assertEqual(self.poller.rev_applied, "0123456789abcdef")             # not applied
        self.assertEqual(list(self.engine.peers), ["192.0.2.10"])                  # not truncated, not replaced
        self.assertIn("513", self.engine.last_apply_error())                       # reported in the heartbeat
        self.assertTrue(self.logs)

    def test_orphan_403_is_noted(self):
        self.hubs.responses["/v1/policy"] = lambda r: err(403, "host_orphan")
        oc = self.poller.poll()
        self.assertEqual(oc.action, tr.ORPHAN)
        self.assertTrue(self.poller.orphan)
        self.hubs.responses.pop("/v1/policy")
        self.poller.poll()
        self.assertFalse(self.poller.orphan)

    def test_error_statuses_keep_the_previous_state(self):
        self.hubs.peers = ["192.0.2.10"]
        self.poller.poll()
        for status, code, action in ((403, "host_revoked", tr.FORBIDDEN), (426, "proto_unsupported", tr.HOLD),
                                     (500, "boom", tr.BACKOFF), (400, "bad_request", tr.LOG_RETRY)):
            self.hubs.responses["/v1/policy"] = lambda r, s=status, c=code: err(s, c)
            self.assertEqual(self.poller.poll().action, action)
            self.assertEqual(list(self.engine.peers), ["192.0.2.10"])
        self.assertIn("policy:", self.poller.last_error)

    def test_not_json_is_refused_without_a_crash(self):
        self.hubs.responses["/v1/policy"] = lambda r: (200, {}, b"<html>")
        oc = self.poller.poll()
        self.assertEqual(oc.code, "policy_refused")

    def test_skew_is_recorded(self):
        self.hubs.responses["/v1/policy"] = lambda r: reply(200, dict(self.hubs.policy_doc(), hub_time=int(time.time()) + 120))
        self.poller.poll()
        self.assertGreater(self.poller.skew, 100)
        self.assertTrue(any("skew" in m for m in self.logs))                       # a WARN above 60 s


class TestGoldenPolicyRoute(unittest.TestCase):
    """The document of hub Appendix A, GET /v1/policy, as the hub sends it."""

    GOLDEN = ('{"rev": "3f2a9c01d4e7b568", "hub_time": 1795000000, "hub_addresses": ["203.0.113.5"], "port": 8443,'
              ' "bans": [{"cidr": "198.51.100.7/32", "expires_at": 1795003600, "source": "fleet", "reason_id": "fleet_quorum"}],'
              ' "feeds": {"dshield": ["198.51.100.0/24"]}, "peers": ["203.0.113.21", "203.0.113.22"]}')

    def test_golden(self):
        p = pol.validate(json.loads(self.GOLDEN), NOW)
        self.assertEqual(p.bans, [{"cidr": "198.51.100.7/32", "remaining": 3600, "source": "fleet", "reason_id": "fleet_quorum"}])
        self.assertEqual(p.feeds, {"dshield": ["198.51.100.0/24"]})
        self.assertEqual(p.peers, ["203.0.113.21", "203.0.113.22"])
        # in P2 only peers and hub addresses reach the ban engine
        self.assertEqual(sorted(p.never_doc()), ["hub_addresses", "peers"])

    def test_hub_policy_module_output_validates_if_the_hub_is_present(self):
        hub_dir = os.path.join(os.path.dirname(support.CODE), "..", "server_hub", "hub")
        import sys
        sys.path.insert(0, os.path.realpath(hub_dir))
        try:
            import hub_policy
        except Exception:
            self.skipTest("hub_policy is not importable here")
        finally:
            sys.path.pop(0)
        doc = {"rev": hub_policy.rev({"hub_addresses": ["203.0.113.5"], "port": 8443, "bans": [], "feeds": {}, "peers": []}),
               "hub_time": int(NOW), "hub_addresses": ["203.0.113.5"], "port": 8443, "bans": [], "feeds": {}, "peers": []}
        self.assertEqual(pol.validate(doc, NOW).rev, doc["rev"])


if __name__ == "__main__":
    unittest.main()
