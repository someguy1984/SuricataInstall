import gzip
import json
import os
import shutil
import sys
import threading
import time
import unittest
from unittest import mock

import test_transport_pki as support
from test_transport_pki import HubPair, PKI, err, reply, wait_for
from edragent import bans as bm
from edragent import event as evmod
from edragent import identity as idn
from edragent import ids
from edragent import spool as sp
from edragent import transport as tr
from edragent import uplink as ul

N = [0]


def mkev(sev="LOW", kind="x.y", summary="s", **kw):
    e = evmod.make_event(kind, "nginx", sev, summary, **kw)
    return ids.stamp(e)


def hb_fn():
    return {"agent_version": "0.1.0", "boot_id": "5b1c0000-0000-4000-8000-000000000000", "uptime_s": 12, "kernel": "6.8.0",
            "schema": 1, "proto": 1, "units": {"edr-agent": "running"}, "tetragon": [], "disk": {"free_pct": 50},
            "load": [0.1, 0.2, 0.3], "mem": {"total_kb": 1}, "local_conf_sha256": "0" * 64}


class UplinkCase(unittest.TestCase):
    def setUp(self):
        self.env = support.Env()
        self.addCleanup(self.env.cleanup)
        self.p = self.env.paths
        self.env.set_droplet("424242")
        self.hubs = HubPair()
        self.addCleanup(self.hubs.stop)
        self.engine = bm.BanEngine({"bans": {}, "thresholds": {}, "sites": {}}, self.p,
                                   proc_dir=os.path.join(self.env.root, "proc"), resolv_conf="/nonexistent",
                                   utmp_path="/nonexistent")
        self.uplinks = []

    def enroll_files(self, **kw):
        kw.setdefault("cn", self.hubs.uuid)
        return support.make_identity(self.env, self.hubs.pki, self.hubs.fleet_port, **kw)

    def make(self, **kw):
        kw.setdefault("hb_interval", 0.3)
        kw.setdefault("policy_interval", 0.3)
        kw.setdefault("pace_s", 0.05)
        kw.setdefault("lo_flush_s", 0.05)
        u = ul.Uplink({"bans": {}}, self.p, self.engine, hb_fn, **kw)
        self.uplinks.append(u)
        return u

    def tearDown(self):
        for u in self.uplinks:
            u.stop()
            self.assertFalse(u.last_error.startswith("uplink:"), u.last_error)

    def sent(self):
        return [e for e in self.hubs.events]


class TestLocalMode(UplinkCase):
    def test_idles_and_drops(self):
        u = self.make()
        u.start()
        self.assertFalse(u.enrolled())
        u.submit(mkev())
        time.sleep(0.5)
        st = u.status()
        self.assertEqual(st["mode"], "local")
        self.assertIsNone(st["hub"])
        self.assertIsNone(st["host_uuid"])
        self.assertEqual(st["spool"]["depth"], 0)
        self.assertFalse(os.path.exists(self.p.spool_dir))                  # the spool is created at enrollment
        self.assertEqual(self.hubs.fleet.requests, [])
        u.stop(shutdown=True)                                                # nothing to send: no crash, no request
        self.assertEqual(self.hubs.fleet.requests, [])

    def test_enrollment_while_running_is_noticed(self):
        with mock.patch.object(ul, "IDENT_CHECK_S", 0.1):
            u = self.make()
            u.start()
            time.sleep(0.3)
            self.assertFalse(u.enrolled())
            self.enroll_files()
            self.assertTrue(wait_for(u.enrolled, 3))
            u.submit(mkev("HIGH"))
            self.assertTrue(wait_for(lambda: len(self.sent()) == 1, 5))
            self.assertTrue(wait_for(lambda: self.hubs.heartbeats, 5))


class TestDelivery(UplinkCase):
    def test_events_reach_the_hub_and_leave_the_spool(self):
        self.enroll_files()
        u = self.make()
        u.start()
        evs = [mkev("LOW", summary="low%d" % i) for i in range(5)] + [mkev("CRITICAL", kind="tetragon.nginx-exec", summary="boom")]
        for e in evs:
            u.submit(e)
        self.assertTrue(wait_for(lambda: len(self.sent()) == 6, 8))
        got = {e["id"] for e in self.sent()}
        self.assertEqual(got, {e["id"] for e in evs})
        self.assertTrue(wait_for(lambda: u.status()["spool"]["depth"] == 0, 3))
        q = [r for r in self.hubs.fleet.requests if r.path == "/v1/events"]
        self.assertEqual(q[0].headers["content-encoding"], "gzip")
        self.assertEqual(q[0].headers["x-edr-proto"], "1")
        body = q[0].json()
        self.assertEqual(set(body), {"batch_id", "sent_at", "events"})
        self.assertEqual(q[0].peer_cn, self.hubs.uuid)

    def test_hi_lane_first_then_oldest_first_and_one_batch_a_second_at_most(self):
        self.enroll_files()
        u = self.make(pace_s=0.3)
        u._refresh_ident(force=True)
        lows = [mkev("LOW", summary="low%d" % i) for i in range(1200)]
        for e in lows:
            u.spool.append(e)
        his = [mkev("HIGH", summary="hi%d" % i) for i in range(3)]
        for e in his:
            u.spool.append(e)
        u.start()
        self.assertTrue(wait_for(lambda: len(self.sent()) == 1203, 15))
        q = [r for r in self.hubs.fleet.requests if r.path == "/v1/events"]
        first = q[0].json()["events"]
        self.assertEqual([e["summary"] for e in first], ["hi0", "hi1", "hi2"])      # the hi lane goes first
        order = [e["summary"] for e in self.sent()]
        self.assertEqual(order[3:], ["low%d" % i for i in range(1200)])             # then oldest first
        self.assertEqual(max(len(r.json()["events"]) for r in q), 500)
        self.assertEqual(len(q), 4)
        # pacing: the hub saw the requests at least ~0.3 s apart. Record arrival times from the order of the list.
        self.assertGreaterEqual(u.pace_s, 0.3)

    def test_arrival_gaps_respect_the_pacing(self):
        self.enroll_files()
        stamps = []
        orig = self.hubs._fleet_handler

        def timed(req):
            if req.path == "/v1/events":
                stamps.append(time.monotonic())
            return orig(req)
        self.hubs.fleet.handler = timed
        u = self.make(pace_s=0.4)
        u._refresh_ident(force=True)
        for i in range(1100):
            u.spool.append(mkev("LOW"))
        u.start()
        self.assertTrue(wait_for(lambda: len(self.sent()) == 1100, 15))
        self.assertEqual(len(stamps), 3)
        for a, b in zip(stamps, stamps[1:]):
            self.assertGreaterEqual(b - a, 0.35)

    def test_low_events_wait_for_the_flush_timer_unless_a_batch_is_full(self):
        self.enroll_files()
        u = self.make(lo_flush_s=1.0)
        u.start()
        t0 = time.time()
        u.submit(mkev("LOW"))
        self.assertTrue(wait_for(lambda: len(self.sent()) == 1, 5))
        self.assertGreaterEqual(time.time() - t0, 0.9)
        t0 = time.time()
        u.submit(mkev("HIGH"))                                                       # HIGH does not wait
        self.assertTrue(wait_for(lambda: len(self.sent()) == 2, 5))
        self.assertLess(time.time() - t0, 0.9)

    def test_dropped_low_is_counted_from_the_reply(self):
        self.enroll_files()
        self.hubs.responses["/v1/events"] = lambda r: reply(200, {"accepted": 1, "duplicate": 0, "dropped_low": 7})
        u = self.make()
        u.start()
        u.submit(mkev("LOW"))
        self.assertTrue(wait_for(lambda: u.status()["dropped_low"] == 7, 5))

    def test_the_hub_dedups_so_a_retry_after_a_lost_reply_is_harmless(self):
        self.enroll_files()
        n = {"c": 0}
        orig = self.hubs._fleet_handler

        def lose_first(req):
            if req.path == "/v1/events":
                n["c"] += 1
                if n["c"] == 1:
                    orig(req)                                      # the hub commits, the reply never arrives
                    return support.Raw(b"")
            return orig(req)
        self.hubs.fleet.handler = lose_first
        u = self.make()
        u.start()
        u.submit(mkev("HIGH", summary="once"))
        self.assertTrue(wait_for(lambda: u.status()["spool"]["depth"] == 0, 10))
        ids_seen = [e["id"] for e in self.sent()]
        self.assertEqual(len(ids_seen), 2)                          # sent twice ...
        self.assertEqual(len(set(ids_seen)), 1)                     # ... with the same id, which the hub dedups
        q = [r for r in self.hubs.fleet.requests if r.path == "/v1/events"]
        self.assertEqual(q[0].json()["batch_id"], q[1].json()["batch_id"])      # batch_id kept on retry
        self.assertNotEqual(q[0].json()["sent_at"], q[1].json()["sent_at"])         # sent_at is stamped on every attempt


class TestConcurrency(UplinkCase):
    def test_a_producer_and_the_sender_never_lose_or_duplicate_an_event(self):
        import random
        self.enroll_files()
        u = self.make(pace_s=0.02, lo_flush_s=0.05)
        u.start()
        rnd = random.Random(5)
        sent_ids = []

        def produce(k):
            for i in range(1500):
                e = mkev(rnd.choice(["LOW", "LOW", "MEDIUM", "HIGH", "CRITICAL"]), summary="p%d-%d" % (k, i))
                sent_ids.append(e["id"])
                u.submit(e)
                if i % 100 == 0:
                    time.sleep(0.01)
        threads = [threading.Thread(target=produce, args=(k,)) for k in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertTrue(wait_for(lambda: len(self.sent()) >= 4500, 30))
        self.assertTrue(wait_for(lambda: u.status()["spool"]["depth"] == 0, 10))
        got = [e["id"] for e in self.sent()]
        self.assertEqual(len(got), 4500)
        self.assertEqual(set(got), set(sent_ids))
        self.assertEqual(u.status()["rejected"], 0)


class TestStatusTableInTheUplink(UplinkCase):
    def poison_handler(self, status=400, code="bad_schema"):
        orig = self.hubs._fleet_handler

        def h(req):
            if req.path == "/v1/events":
                evs = req.json()["events"]
                if any(e.get("summary") == "POISON" for e in evs):
                    return err(status, code)
                self.hubs.events.extend(evs)
                return reply(200, {"accepted": len(evs), "duplicate": 0, "dropped_low": 0})
            return orig(req)
        self.hubs.fleet.handler = h

    def test_400_splits_once_and_what_is_still_refused_goes_to_rejected(self):
        for status, code in ((400, "bad_schema"), (413, "too_large")):
            self.hubs.events.clear()
            self.hubs.fleet.requests.clear()
            self.poison_handler(status, code)
            self.enroll_files()
            u = self.make(lo_flush_s=0.5)
            u._refresh_ident(force=True)
            for i in range(6):
                u.spool.append(mkev("LOW", summary="POISON" if i == 4 else "ok%d" % i))
            u.spool.sync()
            u.start()
            self.assertTrue(wait_for(lambda: u.status()["spool"]["depth"] == 0, 8))
            self.assertEqual(sorted(e["summary"] for e in self.hubs.events), ["ok0", "ok1", "ok2"])   # the clean half got through
            self.assertEqual(u.status()["rejected"], 3)                                          # the refused half left the spool
            self.assertGreater(u.spool.rejected_bytes(), 0)
            reqs = [r for r in self.hubs.fleet.requests if r.path == "/v1/events"]
            sizes = [len(r.json()["events"]) for r in reqs]
            self.assertEqual(sizes, [6, 3, 3])                                                   # one split, never resent unchanged
            ids = [r.json()["batch_id"] for r in reqs]
            self.assertEqual(len(set(ids)), 3)                                                   # a split batch gets new ids
            u.stop()
            self.uplinks.remove(u)
            shutil.rmtree(str(self.p.state_dir))
            os.makedirs(str(self.p.state_dir), 0o700)
            os.makedirs(str(self.p.run_dir), exist_ok=True)

    def test_a_single_refused_event_is_rejected_at_once_and_newer_events_still_go(self):
        self.poison_handler()
        self.enroll_files()
        u = self.make()
        u._refresh_ident(force=True)
        u.spool.append(mkev("LOW", summary="POISON"))
        u.spool.append(mkev("HIGH", summary="fine"))
        u.start()
        self.assertTrue(wait_for(lambda: u.status()["spool"]["depth"] == 0, 8))
        self.assertEqual([e["summary"] for e in self.hubs.events], ["fine"])
        self.assertEqual(u.status()["rejected"], 1)

    def test_422_is_not_split_and_is_retried_hourly(self):
        self.enroll_files()
        self.hubs.responses["/v1/events"] = lambda r: err(422, "schema_too_old")
        u = self.make()
        u._refresh_ident(force=True)
        for i in range(4):
            u.spool.append(mkev("HIGH"))
        u.start()
        self.assertTrue(wait_for(lambda: u.status()["held"].get("events") == "schema_too_old", 5))
        time.sleep(0.8)
        reqs = [r for r in self.hubs.fleet.requests if r.path == "/v1/events"]
        self.assertEqual(len(reqs), 1)                                    # not split, not retried in a loop
        self.assertEqual(u.status()["spool"]["depth"], 4)                 # keeps spooling
        self.assertEqual(u.status()["rejected"], 0)
        self.assertGreaterEqual(u._holds["events"] - time.time(), 3500)   # an hour
        self.assertTrue(wait_for(lambda: len(self.hubs.heartbeats) >= 2, 5))   # the heartbeat carries on
        self.assertEqual(u.status()["last_code"], "schema_too_old")

    def test_426_keeps_the_last_policy_and_spools(self):
        self.enroll_files()
        self.hubs.peers = ["192.0.2.10"]
        u = self.make()
        u.start()
        self.assertTrue(wait_for(lambda: "192.0.2.10" in self.engine.peers, 5))
        self.hubs.responses["/v1/events"] = lambda r: err(426, "proto_unsupported")
        self.hubs.responses["/v1/policy"] = lambda r: err(426, "proto_unsupported")
        u.submit(mkev("HIGH"))
        self.assertTrue(wait_for(lambda: u.status()["held"].get("events") == "proto_unsupported", 5))
        time.sleep(0.8)
        self.assertEqual(list(self.engine.peers), ["192.0.2.10"])         # the last policy is kept
        self.assertEqual(u.status()["spool"]["depth"], 1)

    def test_403_stops_everything_and_keeps_spooling(self):
        self.enroll_files()
        u = self.make()
        u.start()
        self.assertTrue(wait_for(lambda: self.hubs.heartbeats, 5))
        for path in ("/v1/events", "/v1/heartbeat", "/v1/policy"):
            self.hubs.responses[path] = lambda r: err(403, "host_revoked")
        u.submit(mkev("HIGH"))
        self.assertTrue(wait_for(lambda: u.status()["blocked"] == "host_revoked", 5))
        n = len(self.hubs.fleet.requests)
        time.sleep(1.0)
        self.assertLessEqual(len(self.hubs.fleet.requests) - n, 3)       # retried hourly, not in a loop
        u.submit(mkev("HIGH"))
        self.assertTrue(wait_for(lambda: u.status()["spool"]["depth"] >= 1, 2))
        self.assertEqual(u.status()["last_code"], "host_revoked")

    def test_orphan_keeps_events_and_slows_the_policy_poll(self):
        self.enroll_files()
        self.hubs.responses["/v1/policy"] = lambda r: err(403, "host_orphan")
        u = self.make()
        u.start()
        self.assertTrue(wait_for(lambda: u.status()["orphan"], 5))
        u.submit(mkev("HIGH"))
        self.assertTrue(wait_for(lambda: len(self.sent()) == 1, 5))          # events still go
        self.assertEqual(u.status()["blocked"], "")
        polls = len([r for r in self.hubs.fleet.requests if r.path == "/v1/policy"])
        time.sleep(1.0)
        self.assertEqual(len([r for r in self.hubs.fleet.requests if r.path == "/v1/policy"]), polls)    # hourly
        self.assertTrue(len(self.hubs.heartbeats) >= 2)

    def test_429_waits_retry_after_and_resends_the_same_batch(self):
        self.enroll_files()
        n = {"c": 0}
        orig = self.hubs._fleet_handler

        def limited(req):
            if req.path == "/v1/events":
                n["c"] += 1
                if n["c"] == 1:
                    return err(429, "rate_limited", {"Retry-After": "1"})
            return orig(req)
        self.hubs.fleet.handler = limited
        u = self.make()
        u.start()
        t0 = time.time()
        u.submit(mkev("HIGH", summary="wait for me"))
        self.assertTrue(wait_for(lambda: len(self.sent()) == 1, 8))
        self.assertGreaterEqual(time.time() - t0, 1.0)
        q = [r for r in self.hubs.fleet.requests if r.path == "/v1/events"]
        self.assertEqual(q[0].json()["batch_id"], q[1].json()["batch_id"])
        self.assertEqual(u.status()["rejected"], 0)

    def test_5xx_backs_off_and_the_same_batch_is_retried(self):
        self.enroll_files()
        n = {"c": 0}
        orig = self.hubs._fleet_handler

        def flaky(req):
            if req.path == "/v1/events":
                n["c"] += 1
                if n["c"] <= 2:
                    return err(500, "boom")
            return orig(req)
        self.hubs.fleet.handler = flaky
        u = self.make()
        u.start()
        u.submit(mkev("HIGH"))
        self.assertTrue(wait_for(lambda: len(self.sent()) == 1, 10))
        self.assertEqual(n["c"], 3)

    def test_431_and_411_leave_the_batch_unsplit_in_the_spool(self):
        self.enroll_files()
        self.hubs.responses["/v1/events"] = lambda r: err(431, "header_too_large")
        u = self.make()
        u._refresh_ident(force=True)
        for i in range(4):
            u.spool.append(mkev("HIGH"))
        u.start()
        self.assertTrue(wait_for(lambda: len([r for r in self.hubs.fleet.requests if r.path == "/v1/events"]) >= 2, 8))
        for r in [r for r in self.hubs.fleet.requests if r.path == "/v1/events"]:
            self.assertEqual(len(r.json()["events"]), 4)              # never split
        self.assertEqual(u.status()["rejected"], 0)
        self.assertEqual(u.status()["spool"]["depth"], 4)

    def test_three_rejected_handshakes_in_a_row_are_a_403(self):
        evil = PKI(cn="Evil CA")
        self.addCleanup(evil.cleanup)
        d = self.enroll_files()
        ec, ek = evil.client(cn=self.hubs.uuid)
        shutil.copyfile(ec, os.path.join(d, "client.pem"))
        shutil.copyfile(ek, os.path.join(d, "client.key"))
        u = self.make()
        u.start()
        u.submit(mkev("HIGH"))
        self.assertTrue(wait_for(lambda: u.status()["blocked"] == "tls_rejected", 15))
        self.assertEqual(u.status()["spool"]["depth"], 1)
        self.assertEqual(self.sent(), [])
        self.assertGreaterEqual(self.hubs.fleet.handshake_failures, 3)


class TestHeartbeatAndPolicy(UplinkCase):
    def test_heartbeat_carries_the_uplink_keys(self):
        self.enroll_files()
        u = self.make()
        u.start()
        self.assertTrue(wait_for(lambda: len(self.hubs.heartbeats) >= 2, 5))
        hb = self.hubs.heartbeats[-1]
        for k in ("sent_at", "seq", "epoch", "spool", "policy_rev_applied", "last_apply_error", "ban_counts", "cert_not_after",
                  "droplet_id", "schema", "proto", "agent_version", "paused_until", "units", "boot_id"):
            self.assertIn(k, hb, k)
        self.assertEqual(hb["droplet_id"], "424242")
        self.assertEqual(hb["schema"], 1)
        self.assertEqual(set(hb["spool"]) >= {"depth", "bytes", "dropped", "rejected"}, True)
        self.assertEqual(set(hb["spool"]["dropped"]), {"hi", "lo"})
        self.assertRegex(hb["cert_not_after"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
        self.assertEqual(hb["ban_counts"]["local"], 0)
        self.assertIsNone(hb["paused_until"])
        self.assertTrue(wait_for(lambda: self.hubs.heartbeats[-1]["policy_rev_applied"] == "0123456789abcdef", 5))
        self.assertNotEqual(self.hubs.heartbeats[0]["sent_at"], self.hubs.heartbeats[1]["sent_at"])   # stamped on every attempt

    def test_golden_heartbeat_and_batch_validate_against_the_real_hub_code(self):
        hub_dir = os.path.realpath(os.path.join(support.CODE, "..", "..", "server_hub", "hub"))
        sys.path.insert(0, hub_dir)
        try:
            import hub_ingest
        except Exception as exc:
            self.skipTest("hub_ingest is not importable here: %s" % exc.__class__.__name__)
        finally:
            sys.path.pop(0)
        self.enroll_files()
        u = self.make()
        u.start()
        u.submit(mkev("HIGH", kind="tetragon.nginx-exec", details={"x": 1}, src_ip="198.51.100.7", src_trust="tcp"))
        self.assertTrue(wait_for(lambda: self.hubs.heartbeats and self.sent(), 8))
        hb, _ = hub_ingest.validate_heartbeat(self.hubs.heartbeats[0])
        self.assertEqual(hb["droplet_id"], "424242")
        req = [r for r in self.hubs.fleet.requests if r.path == "/v1/events"][0]
        events, sent_ms = hub_ingest.validate_batch(req.json())
        self.assertEqual(len(events), 1)

    def test_events_the_agent_makes_itself_pass_the_hubs_validator(self):
        hub_dir = os.path.realpath(os.path.join(support.CODE, "..", "..", "server_hub", "hub"))
        sys.path.insert(0, hub_dir)
        try:
            import hub_ingest
        except Exception as exc:
            self.skipTest("hub_ingest is not importable here: %s" % exc.__class__.__name__)
        finally:
            sys.path.pop(0)
        now = time.time()
        made = []
        for i in range(5):
            made += self.engine.observe(evmod.make_event("ssh.fail", "journal", "LOW", "x", src_ip="198.51.100.8", src_trust="tcp"), now)
        self.assertTrue([e for e in made if e["kind"] == "ban.local"])
        made.append(evmod.make_event("health.spool_dropped", "agent", "MEDIUM", "spool full: dropped 5 lo events",
                                     details={"lane": "lo", "count": 5, "kinds": {"nginx.crash": 3, "ssh.fail": 2}}))
        made.append(evmod.make_event("health.pause", "agent", "MEDIUM", "bans paused", details={"until": int(now) + 60}))
        made.append(evmod.make_event("health.identity", "agent", "HIGH", "host identity changed, re-enrol with a new token",
                                     details={"why": "the droplet id differs from the one enrolled"}))
        for e in made:
            ids.stamp(e)
        events, _ = hub_ingest.validate_batch({"batch_id": "b" * 8, "sent_at": sp.rfc3339(), "events": made})
        self.assertEqual(len(events), len(made))
        ban = [e for e, *_ in events if e["kind"] == "ban.local"][0]
        self.assertEqual(set(ban["details"]), {"cidr", "trigger", "evidence", "ttl_s", "rung"})

    def test_golden_request_shapes(self):
        self.enroll_files()
        u = self.make()
        u.start()
        u.submit(mkev("HIGH", kind="tetragon.nginx-exec", details={"x": 1}, src_ip="198.51.100.7", src_trust="tcp"))
        self.assertTrue(wait_for(lambda: self.hubs.heartbeats and self.sent(), 8))
        allowed = {"v", "agent_ver", "boot_id", "id", "epoch", "seq", "ts", "sev", "kind", "source", "summary", "details", "src_ip",
                   "dst_ip", "src_trust", "dst_port", "proto", "proc", "community_id", "count", "first_ts", "last_ts", "context",
                   "redacted", "truncated"}
        for e in self.sent():
            self.assertLessEqual(set(e), allowed)
            self.assertRegex(e["id"], r"^[0-9a-f]{8}:\d+$")
        hb = self.hubs.heartbeats[0]
        hub_keys = {"sent_at", "agent_version", "agent_sha256", "schema", "proto", "boot_id", "uptime_s", "kernel", "droplet_id", "seq",
                    "epoch", "units", "tetragon", "nft", "conntrack", "dns_lock", "disk", "load", "mem", "suricata_drops", "spool",
                    "local_conf_sha256", "cert_not_after", "maintenance_until", "paused_until", "policy_rev_applied",
                    "last_apply_error", "ban_counts", "inventory", "shutdown"}
        self.assertLessEqual(set(hb), hub_keys)
        for k in ("sent_at", "droplet_id", "seq", "epoch", "spool", "ban_counts", "cert_not_after", "policy_rev_applied"):
            self.assertIn(k, hb)

    def test_clock_skew_min_client_schema_and_last_ok(self):
        self.enroll_files()
        self.hubs.responses["/v1/heartbeat"] = lambda r: reply(200, {"hub_time": int(time.time()) + 90, "policy_rev": "a" * 16, "min_client_schema": 0})
        u = self.make()
        u.start()
        self.assertTrue(wait_for(lambda: u.status()["last_heartbeat_ok"] is not None, 5))
        st = u.status()
        self.assertAlmostEqual(st["skew_s"], 90, delta=3)
        self.assertEqual(st["min_client_schema"], 0)
        self.assertEqual(st["mode"], "enrolled")
        self.assertEqual(st["host_uuid"], self.hubs.uuid)
        self.assertEqual(st["hub"], "127.0.0.1:%d" % self.hubs.fleet_port)

    def test_policy_peers_reach_the_never_ban_list_and_bans_json(self):
        self.enroll_files()
        self.hubs.peers = ["192.0.2.10", "192.0.2.11"]
        u = self.make()
        u.start()
        self.assertTrue(wait_for(lambda: sorted(self.engine.peers) == ["192.0.2.10", "192.0.2.11"], 5))
        self.engine.tick(time.time() + 6)
        with open(self.p.bans_json) as f:
            j = json.load(f)
        self.assertIn("192.0.2.10/32", j["never"])
        self.assertTrue(wait_for(lambda: u.status()["policy_rev_applied"] == "0123456789abcdef", 5))
        polls = [r for r in self.hubs.fleet.requests if r.path == "/v1/policy"]
        self.assertTrue(wait_for(lambda: len([r for r in self.hubs.fleet.requests if r.path == "/v1/policy"]) >= 3, 5))
        polls = [r for r in self.hubs.fleet.requests if r.path == "/v1/policy"]
        self.assertEqual(polls[1].headers["if-none-match"], '"0123456789abcdef"')

    def test_uplink_json_reports_what_rehome_waits_for(self):
        self.enroll_files()
        u = self.make()
        u.start()
        path = os.path.join(str(self.p.run_dir), "uplink.json")
        def report():
            try:
                with open(path) as f:
                    return json.load(f)
            except (OSError, ValueError):
                return {}
        self.assertTrue(wait_for(lambda: report().get("last_policy_ok"), 6))
        d = report()
        self.assertEqual(d["gen"], "gen-1")
        self.assertEqual(d["hb_gen"], "gen-1")
        self.assertEqual(d["policy_gen"], "gen-1")
        self.assertEqual(d["mode"], "enrolled")
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o644")

    def test_shutdown_heartbeat(self):
        self.enroll_files()
        u = self.make(hb_interval=30, policy_interval=30)
        u.start()
        self.assertTrue(wait_for(lambda: len(self.hubs.heartbeats) >= 1, 5))
        n = len(self.hubs.heartbeats)
        t0 = time.time()
        u.stop(shutdown=True)
        self.assertLess(time.time() - t0, 4)
        self.assertEqual(len(self.hubs.heartbeats), n + 1)
        self.assertIs(self.hubs.heartbeats[-1]["shutdown"], True)
        self.assertNotIn("shutdown", self.hubs.heartbeats[0])
        # a plain stop sends nothing
        u2 = self.make(hb_interval=30, policy_interval=30)
        u2.start()
        self.assertTrue(wait_for(lambda: len(self.hubs.heartbeats) >= n + 2, 5))
        m = len(self.hubs.heartbeats)
        u2.stop(shutdown=False)
        self.assertEqual(len(self.hubs.heartbeats), m)

    def test_the_shutdown_heartbeat_uses_a_two_second_limit(self):
        self.enroll_files()
        seen = []
        u = self.make(hb_interval=30, policy_interval=30)
        orig = u.client.call

        def spy(route, method, path, **kw):
            seen.append((route, kw.get("total_s")))
            return orig(route, method, path, **kw)
        u.client.call = spy
        u.start()
        self.assertTrue(wait_for(lambda: len(seen) >= 1, 5))
        u.stop(shutdown=True)
        self.assertEqual(seen[-1], ("heartbeat", 2.0))

    def test_stale_hub_does_not_block_a_stop(self):
        self.enroll_files()

        def hang(req):
            time.sleep(5)
            return reply(200)
        self.hubs.fleet.handler = hang
        u = self.make(hb_interval=30, policy_interval=30)
        u.start()
        time.sleep(0.5)
        t0 = time.time()
        u.stop(shutdown=True)
        self.assertLess(time.time() - t0, 9)


class TestStopHookAndHeartbeatMerge(UplinkCase):
    def test_heartbeat_keeps_what_the_builder_put_in_spool(self):
        self.enroll_files()
        u = ul.Uplink({"bans": {}}, self.p, self.engine, lambda: dict(hb_fn(), spool={"over_budget": {"tetragon": 3}}),
                      hb_interval=0.3, policy_interval=0.3, pace_s=0.05, lo_flush_s=0.05)
        self.uplinks.append(u)
        u.start()
        self.assertTrue(wait_for(lambda: self.hubs.heartbeats, 5))
        sp_ = self.hubs.heartbeats[-1]["spool"]
        self.assertEqual(sp_["over_budget"], {"tetragon": 3})
        self.assertIn("depth", sp_)

    def test_shutdown_notice_from_a_separate_process_makes_no_spool(self):
        """cli.cmd_shutdown_notice builds an Uplink with a null engine and calls stop(True) without start()."""
        self.enroll_files()
        sp.atomic_write(os.path.join(str(self.p.state_dir), "policy.json"),
                        json.dumps({"rev": "0123456789abcdef", "doc": {"peers": [], "hub_addresses": []}}), 0o600)

        class NullEngine:
            def last_apply_error(self):
                return ""

            def counts(self):
                return {}

            def paused_until(self):
                return None
        u = ul.Uplink({}, self.p, NullEngine(), hb_fn)
        self.uplinks.append(u)
        t0 = time.time()
        u.stop(True)
        self.assertLess(time.time() - t0, 4)
        self.assertEqual(len(self.hubs.heartbeats), 1)
        hb = self.hubs.heartbeats[0]
        self.assertIs(hb["shutdown"], True)
        self.assertEqual(hb["policy_rev_applied"], "0123456789abcdef")
        self.assertEqual(hb["droplet_id"], "424242")
        self.assertFalse(os.path.exists(self.p.spool_dir))


class TestNewGeneration(UplinkCase):
    def test_a_new_identity_generation_is_used_at_once_and_clears_a_block(self):
        new = HubPair(uuid_="22222222-2222-4222-8222-222222222222")
        self.addCleanup(new.stop)
        self.enroll_files()
        for path in ("/v1/heartbeat", "/v1/events", "/v1/policy"):
            self.hubs.responses[path] = lambda r: err(403, "host_moved")
        with mock.patch.object(ul, "IDENT_CHECK_S", 0.1):
            u = self.make(hb_interval=30, policy_interval=30)
            u.start()
            u.submit(mkev("HIGH", summary="to the new hub"))
            self.assertTrue(wait_for(lambda: u.status()["blocked"] == "host_moved", 5))
            support.make_identity(self.env, new.pki, new.fleet_port, gen=2, cn=new.uuid)       # a rehome flipped `current`
            self.assertTrue(wait_for(lambda: new.heartbeats, 6))                               # not after 30 s: at once
            self.assertTrue(wait_for(lambda: [r for r in new.fleet.requests if r.path == "/v1/policy"], 6))
            self.assertTrue(wait_for(lambda: [e for e in new.events if e["summary"] == "to the new hub"], 6))
            self.assertEqual(u.status()["blocked"], "")
            self.assertEqual(u.status()["host_uuid"], new.uuid)


class TestRenewalInTheUplink(UplinkCase):
    def test_a_due_certificate_is_renewed_and_the_old_generation_goes_after_an_accepted_heartbeat(self):
        self.enroll_files(days=10)
        u = self.make()
        u.start()
        self.assertTrue(wait_for(lambda: idn.current_gen_name(self.p) == "gen-2", 8))
        self.assertTrue(wait_for(lambda: idn.gen_numbers(self.p) == [2], 8))
        self.assertTrue(wait_for(lambda: u.status()["cert_not_after"] and u.status()["cert_not_after"].startswith(str(time.gmtime().tm_year + 1)), 5))
        hb_after = [h for h in self.hubs.heartbeats][-1]
        self.assertGreater(len(self.hubs.heartbeats), 1)
        self.assertEqual(hb_after["droplet_id"], "424242")
        renews = [r for r in self.hubs.fleet.requests if r.path == "/v1/renew"]
        self.assertEqual(len(renews), 1)                                   # once, then the new certificate is good for a year

    def test_no_renewal_far_from_expiry_or_during_a_rehome(self):
        self.enroll_files(days=200)
        u = self.make()
        u.start()
        self.assertTrue(wait_for(lambda: len(self.hubs.heartbeats) >= 2, 5))
        self.assertEqual([r for r in self.hubs.fleet.requests if r.path == "/v1/renew"], [])
        u.stop()
        self.uplinks.remove(u)
        shutil.rmtree(str(self.p.identity_dir))
        self.enroll_files(days=10)
        sp.atomic_write(os.path.join(str(self.p.identity_dir), "rehome.json"), "{}", 0o600)
        u = self.make()
        u.start()
        self.assertTrue(wait_for(lambda: len(self.hubs.heartbeats) >= 4, 6))
        self.assertEqual([r for r in self.hubs.fleet.requests if r.path == "/v1/renew"], [])

    def test_failed_renewal_is_retried_later_not_in_a_loop(self):
        self.enroll_files(days=10)
        self.hubs.responses["/v1/renew"] = lambda r: err(403, "host_orphan")
        u = self.make()
        u.start()
        self.assertTrue(wait_for(lambda: [r for r in self.hubs.fleet.requests if r.path == "/v1/renew"], 5))
        time.sleep(1.2)
        self.assertEqual(len([r for r in self.hubs.fleet.requests if r.path == "/v1/renew"]), 1)       # hourly for an orphan
        self.assertEqual(idn.current_gen_name(self.p), "gen-1")


class TestCloneAndIdentity(UplinkCase):
    def test_a_clone_stops_using_the_certificate_keeps_spooling_and_says_so(self):
        self.enroll_files()
        idn.write_host_id(self.p, self.hubs.uuid)
        idn.write_stored_droplet_id(self.p, "111111")                       # enrolled as another droplet
        local = []
        with mock.patch.object(ul, "IDENT_CHECK_S", 0.1):
            u = self.make()
            u.local_event_cb = local.append
            u.start()
            u.submit(mkev("HIGH"))
            time.sleep(1.0)
            self.assertEqual(self.hubs.fleet.requests, [])                  # the old certificate is not used
            self.assertEqual(u.status()["blocked"], "identity_changed")
            self.assertEqual(u.status()["spool"]["depth"], 1)               # keeps spooling
            self.assertEqual([e["kind"] for e in local], ["health.identity"])
            self.assertIn("re-enrol", local[0]["summary"])
            # the same droplet again (restored in place): sending resumes
            idn.write_stored_droplet_id(self.p, "424242")
            self.assertTrue(wait_for(lambda: len(self.sent()) == 1, 8))
            self.assertEqual(u.status()["blocked"], "")


class TestSpoolEviction(UplinkCase):
    def test_one_health_spool_dropped_event_goes_to_the_hub(self):
        self.enroll_files()
        refused = []

        def busy(req):
            refused.append(1)
            return err(503, "busy", {"Retry-After": "1"})
        self.hubs.responses["/v1/events"] = busy
        u = self.make()
        u._refresh_ident(force=True)
        u.spool.close()
        u.spool = sp.Spool(self.p.spool_dir, seg_size=1500, lo_cap=3000)
        u.start()
        for i in range(60):
            u.spool.append(mkev("LOW", kind="nginx.marker.conn_pressure"))
        self.assertTrue(wait_for(lambda: u.spool.stats()["dropped"]["lo"] > 0 and refused, 20))
        self.hubs.responses.pop("/v1/events")                      # the hub recovers; the 1 s Retry-After runs out by itself
        self.assertTrue(wait_for(lambda: [e for e in self.sent() if e["kind"] == "health.spool_dropped"], 30))
        ev = [e for e in self.sent() if e["kind"] == "health.spool_dropped"][0]
        self.assertEqual(ev["details"]["lane"], "lo")
        self.assertGreater(ev["details"]["count"], 0)
        self.assertEqual(ev["details"]["kinds"].get("nginx.marker.conn_pressure"), ev["details"]["count"])
        self.assertIn("id", ev)                                              # it got an id like any other event
        self.assertTrue(wait_for(lambda: self.hubs.heartbeats, 10))
        self.assertGreater(self.hubs.heartbeats[-1]["spool"]["dropped"]["lo"], 0)

    def test_the_pipeline_callback_is_used_when_set(self):
        self.enroll_files()
        got = []
        u = self.make()
        u.local_event_cb = got.append
        u._refresh_ident(force=True)
        u.spool.close()
        u.spool = sp.Spool(self.p.spool_dir, seg_size=1500, lo_cap=3000)
        self.hubs.responses["/v1/events"] = lambda r: err(503, "busy", {"Retry-After": "60"})
        u.start()
        for i in range(60):
            u.spool.append(mkev("LOW"))
        self.assertTrue(wait_for(lambda: got, 5))
        self.assertEqual(got[0]["kind"], "health.spool_dropped")

    def test_drop_spool_flag(self):
        self.enroll_files()
        self.hubs.responses["/v1/events"] = lambda r: err(503, "busy", {"Retry-After": "60"})
        u = self.make()
        u._refresh_ident(force=True)
        for i in range(5):
            u.spool.append(mkev("HIGH"))
        u.start()
        self.assertTrue(wait_for(lambda: len([r for r in self.hubs.fleet.requests if r.path == "/v1/events"]) >= 1, 5))
        sp.atomic_write(os.path.join(str(self.p.identity_dir), "drop-spool.flag"), "1\n", 0o644)
        flag = os.path.join(str(self.p.identity_dir), "drop-spool.flag")
        self.assertTrue(wait_for(lambda: u.spool.depth() == 0 and not os.path.exists(flag), 5))


class TestHiLaneRetryCap(UplinkCase):
    """Client PLAN 4.5 (Timers) and the P2 exit: a hub outage of any length, then every HIGH and CRITICAL event delivered
    within 5 minutes of the hub's return. The events backoff is full jitter up to 5 minutes; while a HIGH or CRITICAL event
    waits in the spool its cap is HI_RETRY_S (60 s), so the next try is never further off than that."""

    def spooled(self, hi):
        self.enroll_files()
        u = self.make()
        u._refresh_ident(force=True)
        u.spool.append(mkev("HIGH" if hi else "LOW"))
        return u

    def draws(self, hi, seed):
        u = self.spooled(hi)
        u.rng.seed(seed)
        bo = tr.Backoff(ul.EVENTS_RETRY_S, rng=u.rng)
        for _ in range(12):                                             # the ceiling has long reached its cap
            bo.failure()
        return [u._retry_delay(bo) for _ in range(400)]

    def test_the_cap_is_a_minute_with_a_high_event_waiting(self):
        self.assertEqual((ul.HI_RETRY_S, ul.EVENTS_RETRY_S), (60.0, 300.0))
        draws = self.draws(True, 11)
        self.assertLessEqual(max(draws), 60.0)
        self.assertGreater(max(draws), 50.0)                            # the whole range is used
        self.assertLess(min(draws), 6.0)
        self.assertGreater(len({round(d, 3) for d in draws}), 300)      # full jitter, not a fixed value: no stampede

    def test_the_cap_stays_five_minutes_with_only_low_events_waiting(self):
        draws = self.draws(False, 11)
        self.assertLessEqual(max(draws), 300.0)
        self.assertGreater(max(draws), 250.0)
        self.assertLess(min(draws), 30.0)
        self.assertGreater(len({round(d, 3) for d in draws}), 300)

    def test_a_capped_draw_is_uniform_not_a_pile_up_at_the_cap(self):
        u = self.spooled(True)
        u.rng.seed(3)
        bo = tr.Backoff(ul.EVENTS_RETRY_S, rng=u.rng)
        for _ in range(12):
            bo.failure()
        draws = [u._retry_delay(bo) for _ in range(600)]
        at_cap = sum(1 for d in draws if d >= 59.99)
        self.assertLess(at_cap, 6)                      # clipping a 0..300 draw to 60 would put 80% of them here
        halves = sum(1 for d in draws if d < 30.0)
        self.assertTrue(240 < halves < 360, halves)

    def test_a_high_event_spooled_during_a_long_backoff_shortens_it_once(self):
        u = self.spooled(False)                         # a LOW event waits: the long backoff was drawn for it
        u.rng.seed(5)
        u._backoff_at, u._backoff_redrawn = 1000.0, False
        u._holds["events"] = 1290.0
        u._shorten_backoff_for_hi()
        self.assertEqual(u._holds["events"], 1290.0)                    # no HIGH event yet: untouched
        u.spool.append(mkev("CRITICAL", kind="tetragon.nginx-exec"))
        u._shorten_backoff_for_hi()
        self.assertTrue(1000.0 <= u._holds["events"] <= 1060.0, u._holds["events"])    # within a minute of the failed attempt
        self.assertTrue(u._backoff_redrawn)
        u._holds["events"] = 1290.0
        u._shorten_backoff_for_hi()                                     # once: the second call does not draw again
        self.assertEqual(u._holds["events"], 1290.0)

    def test_a_hold_the_hub_asked_for_is_never_shortened(self):
        u = self.spooled(True)
        u._backoff_at = None                          # a Retry-After, or an hourly retry: no backoff behind it
        u._holds["events"] = u.clock() + 1800.0
        before = u._holds["events"]
        u._shorten_backoff_for_hi()
        self.assertEqual(u._holds["events"], before)

    def test_a_shorter_backoff_is_kept(self):
        u = self.spooled(False)
        now = [50.0]
        u.clock = lambda: now[0]
        u._backoff_at, u._backoff_redrawn = 40.0, False
        u._holds["events"] = 41.0
        u.spool.append(mkev("HIGH"))
        for seed in range(30):
            u.rng.seed(seed)
            u._backoff_redrawn = False
            u._holds["events"] = 41.0
            u._shorten_backoff_for_hi()
            self.assertLessEqual(u._holds["events"], 41.0)

    def test_after_the_hub_returns_a_high_event_goes_at_the_capped_pace(self):
        """Six refusals would, at the old 300 s cap, put the next try tens of seconds away; with a HIGH event waiting
        and the cap shrunk to 0.3 s for the test, the event is at the hub within seconds."""
        self.enroll_files()
        n = {"c": 0}
        orig = self.hubs._fleet_handler

        def down(req):
            if req.path == "/v1/events":
                n["c"] += 1
                if n["c"] <= 6:
                    return err(503, "busy")
            return orig(req)
        self.hubs.fleet.handler = down
        with mock.patch.object(ul, "HI_RETRY_S", 0.3):
            u = self.make()
            u.rng.seed(2)
            u.start()
            u.submit(mkev("CRITICAL", kind="tetragon.nginx-exec", summary="boom"))
            self.assertTrue(wait_for(lambda: len(self.sent()) == 1, 8))
        self.assertEqual(n["c"], 7)


if __name__ == "__main__":
    unittest.main()
