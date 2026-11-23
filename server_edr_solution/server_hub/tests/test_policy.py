"""The per-host policy document and its stateless revision (PLAN.md section 4, Policy document; Appendix A)."""

import copy
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_ingest_fixture as F  # noqa: E402

import hub_common  # noqa: E402
import hub_policy  # noqa: E402


class PolicyCase(F.HubTestCase):
    def doc(self, uuid=None):
        def go(conn):
            row = conn.execute("SELECT * FROM hosts WHERE uuid=?", (uuid,)).fetchone() if uuid else None
            return hub_policy.build(conn, self.fx.hub, row, hub_common.now_ms())
        return self.fx.writer.call(go)

    def put_host(self, uuid, state="active", peers=()):
        self.fx.writer.call(lambda c: c.execute(
            "INSERT INTO hosts(uuid,name,droplet_id,state,state_since,enrolled_at,peer_ips) VALUES(?,?,?,?,1,1,?)",
            (uuid, "n-" + uuid, "d", state, json.dumps(list(peers)))))


class BuildTest(PolicyCase):
    def test_document_shape_in_this_phase(self):
        self.put_host("u1", peers=["203.0.113.1"])
        d = self.doc()
        self.assertEqual(set(d), {"rev", "hub_time", "hub_addresses", "port", "bans", "feeds", "peers"})
        self.assertEqual(d["bans"], [])
        self.assertEqual(d["feeds"], {})
        self.assertEqual(d["peers"], ["203.0.113.1"])
        self.assertEqual(d["hub_addresses"], ["127.0.0.1"])
        self.assertEqual(d["port"], self.fx.fleet_port)
        self.assertIsInstance(d["hub_time"], int)                    # epoch seconds
        self.assertAlmostEqual(d["hub_time"], hub_common.now_ms() / 1000, delta=5)
        self.assertRegex(d["rev"], r"^[0-9a-f]{16}$")

    def test_rev_is_the_sha256_prefix_of_the_canonical_document_without_hub_time(self):
        self.put_host("u1", peers=["203.0.113.1"])
        d = self.doc()
        body = {k: v for k, v in d.items() if k not in ("rev", "hub_time")}
        canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.assertEqual(d["rev"], hashlib.sha256(canon).hexdigest()[:16])
        self.assertEqual(hub_policy.rev(d), d["rev"])

    def test_rev_ignores_hub_time_and_key_order_and_the_rev_field_itself(self):
        d = self.doc()
        other = copy.deepcopy(d)
        other["hub_time"] += 12345
        other["rev"] = "0" * 16
        self.assertEqual(hub_policy.rev(other), d["rev"])
        shuffled = dict(reversed(list(d.items())))
        self.assertEqual(hub_policy.rev(shuffled), d["rev"])

    def test_rev_changes_with_peers_addresses_port_bans_feeds(self):
        base = self.doc()
        self.put_host("u1", peers=["203.0.113.1"])
        with_peer = self.doc()
        self.assertNotEqual(with_peer["rev"], base["rev"])
        self.fx.hub.settings["public_ip"] = ["127.0.0.1", "10.0.0.1"]
        with_addr = self.doc()
        self.assertNotEqual(with_addr["rev"], with_peer["rev"])
        self.assertEqual(with_addr["hub_addresses"], ["127.0.0.1", "10.0.0.1"])
        self.fx.hub.settings["port"] = 9999
        self.assertNotEqual(self.doc()["rev"], with_addr["rev"])
        d = copy.deepcopy(base)
        d["bans"] = [{"cidr": "198.51.100.7/32", "expires_at": 5, "source": "operator", "reason_id": "operator"}]
        self.assertNotEqual(hub_policy.rev(d), base["rev"])
        d = copy.deepcopy(base)
        d["feeds"] = {"dshield": ["198.51.100.0/24"]}
        self.assertNotEqual(hub_policy.rev(d), base["rev"])

    def test_stateless_two_hosts_with_the_same_document_share_the_rev(self):
        self.put_host("u1", peers=["203.0.113.1"])
        self.put_host("u2", peers=["203.0.113.2"])
        self.assertEqual(self.doc("u1")["rev"], self.doc("u2")["rev"])
        self.assertEqual(self.doc("u1")["rev"], self.doc("u1")["rev"])

    def test_peers_come_from_the_state_table_sorted_and_deduplicated(self):
        self.put_host("a", "active", ["203.0.113.9", "203.0.113.2"])
        self.put_host("b", "pending", ["203.0.113.2"])
        self.put_host("c", "revoked", ["203.0.113.5"])           # revoked: kept
        self.put_host("d", "moved", ["203.0.113.6"])             # moved, retired: removed
        self.put_host("e", "retired", ["203.0.113.7"])
        self.put_host("f", "orphan", ["203.0.113.8"])            # orphan: none
        self.assertEqual(self.doc()["peers"], ["203.0.113.2", "203.0.113.5", "203.0.113.9"])

    def test_hub_addresses_are_bare_literals_at_most_four_in_stored_order(self):
        self.fx.hub.settings["public_ip"] = ["10.0.0.1", "2001:db8::1", "bad", "10.0.0.1", "192.0.2.1", "192.0.2.2", "192.0.2.3"]
        self.assertEqual(self.doc()["hub_addresses"], ["10.0.0.1", "2001:db8::1", "192.0.2.1", "192.0.2.2"])
        self.fx.hub.settings["public_ip"] = "203.0.113.4"
        self.assertEqual(self.doc()["hub_addresses"], ["203.0.113.4"])

    def test_peers_at_most_512(self):
        rows = [("u%d" % i, "n%d" % i, "d", "active", 1, 1, json.dumps(["10.0.%d.%d" % (i // 256, i % 256)])) for i in range(700)]
        self.fx.writer.call(lambda c: c.executemany(
            "INSERT INTO hosts(uuid,name,droplet_id,state,state_since,enrolled_at,peer_ips) VALUES(?,?,?,?,?,?,?)", rows))
        self.assertEqual(len(self.doc()["peers"]), 512)

    def test_note_revision_moves_policy_rev_since_only_when_the_value_changes(self):
        self.put_host("u1")

        def note(rev, now):
            def go(conn):
                row = conn.execute("SELECT * FROM hosts WHERE uuid='u1'").fetchone()
                return hub_policy.note_revision(conn, row, rev, now)
            return self.fx.writer.call(go)
        self.assertTrue(note("a" * 16, 100))
        self.assertFalse(note("a" * 16, 200))
        row = self.fx.sql("SELECT policy_rev, policy_rev_since FROM hosts WHERE uuid='u1'")[0]
        self.assertEqual((row["policy_rev"], row["policy_rev_since"]), ("a" * 16, 100))
        self.assertTrue(note("b" * 16, 300))
        self.assertEqual(self.fx.sql("SELECT policy_rev_since FROM hosts")[0]["policy_rev_since"], 300)


class RouteTest(PolicyCase):
    def test_get_policy_has_the_etag_and_the_whole_document(self):
        c = self.fx.enroll("web1")
        status, headers, body = c.request("GET", "/v1/policy")
        self.assertEqual(status, 200)
        d = json.loads(body)
        self.assertEqual(headers["etag"], '"%s"' % d["rev"])
        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(int(headers["content-length"]), len(body))
        self.assertEqual(d["peers"], ["127.0.0.1"] if self.fx.sql("SELECT peer_ips FROM hosts")[0]["peer_ips"] != "[]" else [])
        self.assertEqual(d["bans"], [])
        self.assertEqual(d["feeds"], {})

    def test_if_none_match_gives_304_without_a_body(self):
        c = self.fx.enroll("web1")
        _s, headers, body = c.request("GET", "/v1/policy")
        etag = headers["etag"]
        status, h2, b2 = c.request("GET", "/v1/policy", headers={"If-None-Match": etag})
        self.assertEqual((status, b2), (304, b""))
        self.assertEqual(h2["etag"], etag)
        status, _h, b3 = c.request("GET", "/v1/policy", headers={"If-None-Match": '"0000000000000000"'})
        self.assertEqual(status, 200)
        status, _h, b3 = c.request("GET", "/v1/policy", headers={"If-None-Match": '"0000000000000000", ' + etag})
        self.assertEqual(status, 304)

    def test_policy_changes_when_a_peer_appears_and_the_heartbeat_reply_agrees(self):
        c = self.fx.enroll("web1")
        _s, h, _b = c.request("GET", "/v1/policy")
        before = h["etag"].strip('"')
        c2 = self.fx.enroll("web2")
        status, hb_headers, hb_body = c2.heartbeat()
        self.assertEqual(status, 200)                     # web2's first heartbeat records its peer
        _s, h2, body = c.request("GET", "/v1/policy")
        after = json.loads(body)
        self.assertEqual(h2["etag"].strip('"'), after["rev"])
        status, _h, hb = c.heartbeat()
        self.assertEqual(json.loads(hb)["policy_rev"], after["rev"])
        self.assertRegex(after["rev"], hub_common.REV_RE.pattern)

    def test_hosts_row_keeps_policy_rev_and_since(self):
        c = self.fx.enroll("web1")
        c.heartbeat()
        row = self.fx.sql("SELECT policy_rev, policy_rev_since FROM hosts WHERE uuid=?", (c.uuid,))[0]
        self.assertRegex(row["policy_rev"], r"^[0-9a-f]{16}$")
        first_since = row["policy_rev_since"]
        c.heartbeat()
        row = self.fx.sql("SELECT policy_rev, policy_rev_since FROM hosts WHERE uuid=?", (c.uuid,))[0]
        self.assertEqual(row["policy_rev_since"], first_since)           # unchanged value, unchanged start time

    def test_orphan_gets_403_host_orphan_on_policy_and_renew(self):
        c = self.fx.enroll("web1")
        self.fx.writer.call(lambda conn: conn.execute("UPDATE hosts SET state='orphan' WHERE uuid=?", (c.uuid,)))
        for path, method in (("/v1/policy", "GET"),):
            status, _h, body = c.request(method, path)
            self.assertEqual((status, json.loads(body)["code"]), (403, "host_orphan"))
        _k, csr = F.make_key_and_csr(self.fx.tmp)
        status, _h, body = c.post_json("/v1/renew", {"csr": csr})
        self.assertEqual((status, json.loads(body)["code"]), (403, "host_orphan"))
        self.assertEqual(c.send_events([F.make_event(1)])[0], 200)       # events are still accepted
        self.assertEqual(c.heartbeat()[0], 200)
        self.assertEqual(self.fx.sql("SELECT state FROM hosts")[0]["state"], "orphan")    # a heartbeat does not activate it


if __name__ == "__main__":
    unittest.main()
