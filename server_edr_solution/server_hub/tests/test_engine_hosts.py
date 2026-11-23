"""hub_engine, host side: heartbeat rules, agent-silent, reboots, start-up, self-health, the digest, enrollment notices."""

import json
import os
import sys
import time
import unittest
from collections import namedtuple
from unittest import mock

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "hub"))

import hub_common    # noqa: E402
import hub_engine    # noqa: E402
from test_engine_support import HubTestCase, T0, MIN, HOUR, DAY   # noqa: E402

GOOD_SHA = "a" * 64


class HostCase(HubTestCase):
    def setUp(self):
        super().setUp()
        self.hashes = os.path.join(self.tmp, "agent-hashes.json")
        with open(self.hashes, "w") as f:
            json.dump({"hashes": [GOOD_SHA]}, f)
        hashes = self.hashes

        class P(hub_common.Paths):
            agent_hashes = property(lambda s: hashes)
        self.hub.paths = P(state_dir=self.hub.paths.state_dir, run_dir=self.hub.paths.run_dir, etc_dir=self.hub.paths.etc_dir,
                           out_state_dir=self.hub.paths.out_state_dir, lib_dir=self.hub.paths.lib_dir)
        self.hub.settings["digest_time"] = "23:59"
        self.host = self.hub.add_host("web1", last_seen=T0, boot_id="boot-A", agent_sha256=GOOD_SHA, agent_version="0.1.0")
        self.engine = hub_engine.Engine(self.hub)
        self.engine._t_health = float("inf")
        self.now = T0

    # ---- helpers
    def beat(self, now=None, **body):
        """Send a heartbeat the way hub_ingest does: on_heartbeat after the host columns were updated."""
        now = self.now if now is None else now
        prev = self.hub.host(self.host["uuid"])
        hb = {"boot_id": prev["boot_id"], "agent_version": "0.1.0", "agent_sha256": GOOD_SHA, "droplet_id": "d-1", "seq": 1, "epoch": 1}
        hb.update(body)
        cols = {"last_seen": now}
        for key in ("boot_id", "agent_sha256", "agent_version"):
            if key in hb:
                cols[key] = hb[key]
        if hb.get("shutdown"):
            cols["shutdown_notice_at"] = now
        self.hub.set_host(self.host["uuid"], **cols)
        self.hub.writer.call(lambda c: hub_engine.on_heartbeat(c, self.hub, prev, hb, now, "203.0.113.9"))
        return hb

    def alerts(self, kind=None):
        return [o for o in self.hub.outbox() if o["channel"] == "webhook" and (kind is None or o["payload"]["kind"] == kind)]

    def note_texts(self, rule=None):
        return [(sev, text) for key, sev, text in self.hub.notes() if rule is None or ("|%s|" % rule) in key]

    def tick(self, now):
        self.engine.tick(now)


class RebootTests(HostCase):
    def test_notice_then_new_boot_id_is_info_only(self):
        self.hub.set_host(self.host["uuid"], shutdown_notice_at=T0)
        self.beat(T0 + 5 * MIN, boot_id="boot-B")
        self.assertEqual(self.alerts(), [])
        self.assertEqual(self.note_texts("reboot"), [("INFO", "planned reboot (notice, then a new boot id)")])

    def test_new_boot_id_with_no_notice_is_medium(self):
        self.beat(T0 + MIN, boot_id="boot-B")
        self.assertEqual(self.alerts(), [])
        (sev, text), = self.note_texts("reboot")
        self.assertEqual(sev, "MEDIUM")
        self.assertIn("no shutdown notice", text)

    def test_a_notice_older_than_ten_minutes_does_not_make_it_planned(self):
        self.hub.set_host(self.host["uuid"], shutdown_notice_at=T0)
        self.beat(T0 + 11 * MIN, boot_id="boot-B")
        self.assertEqual(self.note_texts("reboot")[0][0], "MEDIUM")

    def test_high_within_30_minutes_of_a_sigkill_hit(self):
        self.hub.add_event(self.host, "tetragon.nginx-exec", "CRITICAL", received_at=T0)
        self.beat(T0 + 20 * MIN, boot_id="boot-B")
        (a,) = self.alerts("hub.reboot")
        self.assertEqual(a["severity"], "HIGH")
        self.assertEqual(self.hub.incidents()[0]["chain"], "tamper")

    def test_a_hit_older_than_30_minutes_does_not_raise_it(self):
        self.hub.add_event(self.host, "tetragon.nginx-exec", "CRITICAL", received_at=T0)
        self.beat(T0 + 45 * MIN, boot_id="boot-B")
        self.assertEqual(self.alerts("hub.reboot"), [])

    def test_a_maintenance_window_silences_the_reboot_rule(self):
        self.hub.writer.call(lambda c: c.execute("INSERT INTO maintenance (host, until, set_by, set_at) VALUES (?,?,?,?)",
                                                 (self.host["uuid"], T0 + HOUR, "uid=1000", T0)))
        self.beat(T0 + MIN, boot_id="boot-B")
        self.assertEqual(self.note_texts("reboot"), [])
        self.assertEqual(self.alerts(), [])


class BuildAndIdentityTests(HostCase):
    def test_unknown_build_is_high_once(self):
        bad = "b" * 64
        self.beat(T0 + MIN, agent_sha256=bad)
        (a,) = self.alerts("hub.agent_build")
        self.assertEqual(a["severity"], "HIGH")
        self.assertIn("not in the known builds", a["payload"]["title"])
        self.beat(T0 + 2 * MIN, agent_sha256=bad)
        self.beat(T0 + 3 * MIN, agent_sha256=bad)
        self.assertEqual(len(self.alerts("hub.agent_build")), 1)

    def test_known_build_is_quiet_and_a_local_override_counts(self):
        self.beat(T0 + MIN)
        self.assertEqual(self.alerts(), [])
        extra = "c" * 64
        self.hub.writer.call(lambda c: c.execute("INSERT INTO agent_hashes (sha256, ts) VALUES (?,?)", (extra, T0)))
        self.beat(T0 + 2 * MIN, agent_sha256=extra, agent_version="0.1.1")
        self.assertEqual(self.alerts("hub.agent_build"), [])

    def test_changed_while_the_version_did_not(self):
        other = "d" * 64
        with open(self.hashes, "w") as f:
            json.dump({"hashes": [GOOD_SHA, other]}, f)
        self.beat(T0 + MIN, agent_sha256=other, agent_version="0.1.0")
        (a,) = self.alerts("hub.agent_build")
        self.assertIn("changed while the version did not", a["payload"]["title"])

    def test_changed_with_a_new_version_between_known_builds_is_quiet(self):
        other = "d" * 64
        with open(self.hashes, "w") as f:
            json.dump({"hashes": [GOOD_SHA, other]}, f)
        self.beat(T0 + MIN, agent_sha256=other, agent_version="0.2.0")
        self.assertEqual(self.alerts("hub.agent_build"), [])

    def test_empty_hash_list_makes_every_build_unknown(self):
        with open(self.hashes, "w") as f:
            json.dump({"hashes": []}, f)
        self.beat(T0 + MIN)
        self.assertEqual(len(self.alerts("hub.agent_build")), 1)

    def test_droplet_id_change_is_a_possible_clone(self):
        self.beat(T0 + MIN, droplet_id="d-1")
        self.assertEqual(self.alerts(), [])
        self.beat(T0 + 2 * MIN, droplet_id="d-2")
        (a,) = self.alerts("hub.duplicate_identity")
        self.assertEqual(a["severity"], "HIGH")
        self.beat(T0 + 3 * MIN, droplet_id="d-2")
        self.assertEqual(len(self.alerts("hub.duplicate_identity")), 1)

    def test_two_live_boot_ids(self):
        self.beat(T0 + MIN, boot_id="boot-A")
        self.beat(T0 + 2 * MIN, boot_id="boot-B")          # a reboot: MEDIUM note only
        self.assertEqual(self.alerts("hub.duplicate_identity"), [])
        self.beat(T0 + 3 * MIN, boot_id="boot-A")          # the old boot id is back: two machines
        (a,) = self.alerts("hub.duplicate_identity")
        self.assertIn("two live boot ids", a["payload"]["title"])


class HeartbeatRuleTests(HostCase):
    def test_disk_under_ten_percent_is_critical_once(self):
        self.beat(T0 + MIN, disk={"free_pct": 40})
        self.assertEqual(self.alerts(), [])
        self.beat(T0 + 2 * MIN, disk={"free_pct": 6.5})
        (a,) = self.alerts("hub.disk_low")
        self.assertEqual(a["severity"], "CRITICAL")
        self.beat(T0 + 3 * MIN, disk={"free_pct": 6.0})
        self.assertEqual(len(self.alerts("hub.disk_low")), 1)
        self.beat(T0 + 4 * MIN, disk={"root": {"used_pct": 50}})                   # nested shape, cleared
        self.beat(T0 + 20 * MIN, disk={"used_pct": 95})
        self.assertEqual(len(self.alerts("hub.disk_low")), 2)

    def test_policy_lag_over_five_minutes_and_apply_error(self):
        rev = "1" * 16
        self.hub.set_host(self.host["uuid"], policy_rev=rev, policy_rev_since=T0 - 3 * MIN)
        self.beat(T0 + MIN, policy_rev_applied="2" * 16)
        self.assertEqual(self.note_texts("policy_lag"), [])                           # 4 minutes
        self.beat(T0 + 3 * MIN, policy_rev_applied="2" * 16)
        (sev, text), = self.note_texts("policy_lag")
        self.assertEqual(sev, "MEDIUM")
        self.beat(T0 + 4 * MIN, policy_rev_applied=rev)
        self.beat(T0 + 5 * MIN, policy_rev_applied=rev, last_apply_error="refused a ban")
        self.assertIn("apply error", self.note_texts("policy_lag")[0][1])
        self.assertEqual(self.alerts(), [])

    def test_pause_is_one_medium_note_per_pause(self):
        until = hub_common.ms_to_rfc3339(T0 + HOUR)
        for i in range(3):
            self.beat(T0 + (i + 1) * MIN, paused_until=until)
        count = self.hub.q("SELECT count FROM alert_state WHERE key LIKE 'note|%|paused|%'")[0][0]
        self.assertEqual(count, 1)
        self.beat(T0 + 5 * MIN, paused_until=None)
        self.beat(T0 + 6 * MIN, paused_until=hub_common.ms_to_rfc3339(T0 + 2 * HOUR))
        self.assertEqual(self.hub.q("SELECT count FROM alert_state WHERE key LIKE 'note|%|paused|%'")[0][0], 2)
        self.beat(T0 + 7 * MIN, paused_until=hub_common.ms_to_rfc3339(T0 - HOUR))       # an expired pause is not a pause
        self.assertEqual(self.alerts(), [])

    def test_inet_edr_absent_for_two_minutes(self):
        self.beat(T0 + MIN, nft={"table_present": False})
        self.beat(T0 + 2 * MIN + 59_000, nft={"table_present": False})
        self.assertEqual(self.alerts(), [])
        self.beat(T0 + 3 * MIN + 1000, nft={"table_present": False})
        (a,) = self.alerts("hub.nft_absent")
        self.assertEqual(a["severity"], "HIGH")
        self.beat(T0 + 4 * MIN, nft={"table_present": False})
        self.assertEqual(len(self.alerts("hub.nft_absent")), 1)
        self.beat(T0 + 5 * MIN, nft={"table_present": True})
        self.beat(T0 + 6 * MIN, nft={"table_present": False})                              # a blip starts the two minutes again
        self.assertEqual(len(self.alerts("hub.nft_absent")), 1)

    def test_conntrack_levels(self):
        self.beat(T0 + MIN, conntrack={"count": 600, "max": 1000})
        self.assertEqual((self.alerts(), self.note_texts("conntrack")), ([], []))
        self.beat(T0 + 2 * MIN, conntrack={"count": 700, "max": 1000})
        self.assertEqual(self.note_texts("conntrack")[0][0], "MEDIUM")
        self.assertEqual(self.alerts(), [])
        self.beat(T0 + 3 * MIN, conntrack={"count": 920, "max": 1000})
        (a,) = self.alerts("hub.conntrack")
        self.assertEqual(a["severity"], "HIGH")
        self.beat(T0 + 4 * MIN, conntrack={"count": 5, "max": 0})                          # nonsense is ignored
        self.beat(T0 + 5 * MIN, conntrack="x")

    def test_suricata_drops_over_one_percent(self):
        self.beat(T0 + MIN, suricata_drops={"packets": 10000, "drops": 50, "window_s": 60})
        self.assertEqual(self.note_texts("suricata_drops"), [])
        self.beat(T0 + 2 * MIN, suricata_drops={"packets": 0, "drops": 0, "window_s": 60})        # not evaluated at 0 packets
        self.assertEqual(self.note_texts("suricata_drops"), [])
        self.beat(T0 + 3 * MIN, suricata_drops={"packets": 10000, "drops": 200, "window_s": 60})
        self.assertEqual(self.note_texts("suricata_drops")[0][0], "MEDIUM")

    def test_client_certificate_expiry_levels(self):
        def beat_days(minutes, days, as_text=False):
            when = T0 + minutes * MIN + int(days * DAY)
            self.beat(T0 + minutes * MIN, cert_not_after=hub_common.ms_to_rfc3339(when) if as_text else when // 1000)
        beat_days(1, 60)
        self.assertEqual((self.note_texts("client_cert_30"), self.alerts()), ([], []))
        beat_days(2, 20, as_text=True)
        self.assertEqual(self.note_texts("client_cert_30")[0][0], "LOW")
        beat_days(3, 10)
        self.assertEqual(self.note_texts("client_cert_14")[0][0], "MEDIUM")
        self.assertEqual(self.alerts(), [])
        beat_days(4, 5)
        (a,) = self.alerts("hub.client_cert")
        self.assertEqual(a["severity"], "HIGH")
        self.assertIn("token made --for HOST", a["payload"]["next_step"])

    def test_clock_skew_over_five_minutes(self):
        self.hub.set_host(self.host["uuid"], skew_ms=4 * MIN)
        self.beat(T0 + MIN)
        self.assertEqual(self.note_texts("skew"), [])
        self.hub.set_host(self.host["uuid"], skew_ms=-6 * MIN)
        self.beat(T0 + 2 * MIN)
        self.assertEqual(self.note_texts("skew")[0][0], "MEDIUM")

    def test_rising_spool_drops_are_a_digest_line(self):
        self.beat(T0 + MIN, spool={"depth": 3, "dropped": {"hi": 0, "lo": 0}})
        self.beat(T0 + 2 * MIN, spool={"depth": 3, "dropped": {"hi": 0, "lo": 0}})
        self.assertEqual(self.note_texts("event_loss"), [])
        self.beat(T0 + 3 * MIN, spool={"depth": 3, "dropped": {"hi": 0, "lo": 40}, "dropped_by_source": {"nginx": 40}})
        (sev, text), = self.note_texts("event_loss")
        self.assertIn("dropped 40 more events", text)                             # by lane, not counted again by source

    def test_tetragon_unhealthy_after_attack_signals_is_possible_success(self):
        self.beat(T0 + MIN, units={"tetragon": "absent"})
        self.assertEqual(self.alerts("hub.possible_success"), [])                          # no first signals: nothing to chain with
        self.hub.add_event(self.host, "tetragon.fork-watch", "HIGH", received_at=T0 + 5 * MIN)
        self.beat(T0 + 10 * MIN, units={"tetragon": "absent"})
        (a,) = self.alerts("hub.possible_success")
        self.assertEqual(a["severity"], "CRITICAL")
        self.assertIn("Tetragon unhealthy", a["payload"]["title"])

    def test_an_empty_tetragon_policy_list_is_unhealthy_too(self):
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0)
        self.beat(T0 + 10 * MIN, tetragon=[])
        self.assertEqual(len(self.alerts("hub.possible_success")), 1)
        h2 = self.hub.add_host("web2")
        self.assertIsNotNone(h2)

    def test_survived_task_clears_when_workers_restarted_after_the_hit(self):
        self.hub.add_event(self.host, "tetragon.fork-watch", "HIGH", received_at=T0)
        self.hub.add_event(self.host, "tetragon.web-exec", "HIGH", received_at=T0 + MIN)
        self.engine.tick(T0 + 2 * MIN)
        self.assertEqual(len(self.hub.q("SELECT 1 FROM alert_state WHERE key LIKE 'task|survived|%'")), 1)
        old = {"checks": {"nginx_build": {"worker_started_at": [(T0 - HOUR) // 1000]}}}
        self.beat(T0 + 5 * MIN, inventory=old)
        self.assertEqual(len(self.hub.q("SELECT 1 FROM alert_state WHERE key LIKE 'task|survived|%'")), 1)
        new = {"checks": {"deleted_exe": {"status": False, "nginx_started_min": (T0 + 4 * MIN) // 1000, "nginx_started_max": (T0 + 4 * MIN) // 1000}}}
        self.beat(T0 + 6 * MIN, inventory=new)
        self.assertEqual(self.hub.q("SELECT 1 FROM alert_state WHERE key LIKE 'task|survived|%'"), [])

    def test_a_retired_host_is_not_evaluated(self):
        self.hub.set_host(self.host["uuid"], state="retired")
        self.beat(T0 + MIN, disk={"free_pct": 1}, agent_sha256="f" * 64)
        self.assertEqual(self.alerts(), [])

    def test_a_bad_heartbeat_never_raises(self):
        prev = self.hub.host(self.host["uuid"])
        for hb in ({}, None, {"nft": 5, "conntrack": [], "disk": "x", "spool": 3, "suricata_drops": {"packets": "a"}, "cert_not_after": {}},
                   {"inventory": {"checks": "x"}, "paused_until": [], "units": 4, "tetragon": "y"}):
            self.hub.writer.call(lambda c: hub_engine.on_heartbeat(c, self.hub, prev, hb, T0, "203.0.113.9"))
        self.hub.writer.call(lambda c: hub_engine.on_heartbeat(c, self.hub, None, {}, T0, "x"))


class AdvisoryHeartbeatTests(HostCase):
    def inventory(self, version="1.24.0-2ubuntu7.19", http2=True):
        return {"os_release": {"VERSION_CODENAME": "noble"}, "checks": {
            "nginx_pkg": {"status": True, "packages": [{"name": "nginx", "version": version, "origin": "Ubuntu"}]},
            "nginx_exposure": {"status": True, "http2": http2, "h2c": False, "http3": False, "mail_proxy": False, "resolver_bug": False, "tls_listener": True}}}

    def test_vulnerable_and_exposed_is_high_once_then_daily(self):
        self.beat(T0 + MIN, inventory=self.inventory())
        (a,) = self.alerts("hub.advisory")
        self.assertEqual(a["severity"], "HIGH")
        self.assertIn("1.24.0-2ubuntu7.19", a["payload"]["title"])
        self.assertIn("CVE-2026-123007", a["payload"]["fields"]["cves"])
        self.assertEqual(self.hub.incidents()[0]["chain"], "exposure")
        self.beat(T0 + 2 * MIN, inventory=self.inventory())
        self.assertEqual(len(self.alerts("hub.advisory")), 1)
        # the daily digest job repeats it until it is fixed
        self.hub.writer.call(lambda c: c.execute("INSERT INTO inventory (host, received_at, body) VALUES (?,?,?)",
                                                 (self.host["uuid"], T0, json.dumps(self.inventory()))))
        self.hub.settings["digest_time"] = "00:00"
        self.engine._t_minute = 0
        self.tick(T0 + DAY + HOUR)
        self.assertEqual(len(self.alerts("hub.advisory")), 2)

    def test_fixed_package_is_quiet(self):
        self.beat(T0 + MIN, inventory=self.inventory(version="1.24.0-2ubuntu7.20"))
        self.assertEqual(self.alerts(), [])

    def test_vulnerable_without_exposure_is_a_digest_note(self):
        inv = self.inventory(http2=False)
        inv["checks"]["nginx_exposure"]["tls_listener"] = False
        self.beat(T0 + MIN, inventory=inv)
        self.assertEqual(self.alerts(), [])
        self.assertEqual(self.note_texts("advisory_exposed")[0][0], "MEDIUM")

    def test_tls_only_becomes_high_after_24_hours(self):
        inv = self.inventory(http2=False)
        self.beat(T0 + MIN, inventory=inv)
        self.assertEqual(self.alerts("hub.advisory"), [])
        self.beat(T0 + 25 * HOUR, inventory=inv)
        self.assertEqual(len(self.alerts("hub.advisory")), 1)

    def test_override_row_replaces_the_shipped_one(self):
        os.makedirs(self.hub.paths.advisories_d, exist_ok=True)
        row = {"id": "nginx-ubuntu-noble", "origin": "ubuntu", "release": "noble", "packages": ["nginx"], "compare": "dpkg",
               "fixed_in": "1.24.0-2ubuntu7.19", "cves": [], "needs_feature": None, "ref": "https://example.com/x"}
        with open(os.path.join(self.hub.paths.advisories_d, "local.json"), "w") as f:
            json.dump({"rows": [row]}, f)
        self.beat(T0 + MIN, inventory=self.inventory(version="1.24.0-2ubuntu7.19"))
        self.assertEqual(self.alerts("hub.advisory"), [])


class SilentTests(HostCase):
    def test_late_at_four_minutes_high_at_five_once(self):
        self.tick(T0 + 4 * MIN)
        self.assertEqual(self.alerts(), [])
        self.tick(T0 + 5 * MIN + 1000)
        (a,) = self.alerts("hub.agent_silent")
        self.assertEqual(a["severity"], "HIGH")
        self.assertIn("no heartbeat", a["payload"]["title"])
        self.tick(T0 + 8 * MIN)
        self.tick(T0 + 20 * MIN)
        self.assertEqual(len(self.alerts("hub.agent_silent")), 1)
        self.assertEqual(self.hub.incidents()[0]["chain"], "host")

    def test_paging_continues_daily_while_silent(self):
        self.tick(T0 + 6 * MIN)
        self.tick(T0 + 25 * HOUR)
        self.assertEqual(len(self.alerts("hub.agent_silent")), 2)
        self.assertIn("1 days", self.alerts("hub.agent_silent")[1]["payload"]["title"])

    def test_a_heartbeat_ends_it(self):
        self.tick(T0 + 6 * MIN)
        self.beat(T0 + 7 * MIN)
        self.tick(T0 + 8 * MIN)
        self.assertIn(("INFO", "agent is back"), self.note_texts("agent_silent"))
        self.tick(T0 + 20 * MIN)                                                           # silent again within 30 minutes: dedup holds it
        self.assertEqual(len(self.alerts("hub.agent_silent")), 1)
        self.tick(T0 + 50 * MIN)
        self.assertEqual(len(self.alerts("hub.agent_silent")), 1)
        self.beat(T0 + 51 * MIN)
        self.tick(T0 + 70 * MIN)                                                           # a new silence after the window: a new alert
        self.assertEqual(len(self.alerts("hub.agent_silent")), 2)

    def test_start_up_grace(self):
        self.engine.startup(T0 + 10 * MIN)
        self.tick(T0 + 12 * MIN)
        self.assertEqual(self.alerts(), [])                                                # inside the 7 minutes
        self.tick(T0 + 17 * MIN + 1000)
        self.assertEqual(len(self.alerts("hub.agent_silent")), 1)

    def test_operator_maintenance_window_silences_it_and_ending_restores_it(self):
        self.hub.writer.call(lambda c: c.execute("INSERT INTO maintenance (host, until, set_by, set_at) VALUES (?,?,?,?)",
                                                 (self.host["uuid"], T0 + 30 * MIN, "uid=1000", T0)))
        self.tick(T0 + 10 * MIN)
        self.assertEqual(self.alerts(), [])
        self.tick(T0 + 31 * MIN)
        self.assertEqual(len(self.alerts("hub.agent_silent")), 1)

    def test_a_window_the_host_declared_itself_does_not_silence_it(self):
        self.beat(T0 + MIN, maintenance_until=hub_common.ms_to_rfc3339(T0 + 2 * HOUR))
        self.tick(T0 + 20 * MIN)
        self.assertEqual(len(self.alerts("hub.agent_silent")), 1)
        self.assertNotIn("maintenance window", self.alerts("hub.agent_silent")[0]["payload"]["fields"])

    def test_a_shutdown_notice_gives_ten_minutes(self):
        self.hub.set_host(self.host["uuid"], shutdown_notice_at=T0)
        self.tick(T0 + 9 * MIN)
        self.assertEqual(self.alerts(), [])
        self.tick(T0 + 11 * MIN)
        self.assertEqual(len(self.alerts("hub.agent_silent")), 1)

    def test_critical_within_30_minutes_of_an_attack_signal(self):
        self.hub.add_event(self.host, "tetragon.fork-watch", "HIGH", received_at=T0 - 10 * MIN)
        self.tick(T0 + 6 * MIN)
        (a,) = self.alerts("hub.possible_success")
        self.assertEqual(a["severity"], "CRITICAL")
        self.assertIn("after attack signals", a["payload"]["title"])
        self.assertEqual(self.alerts("hub.agent_silent"), [])

    def test_an_attack_signal_older_than_30_minutes_does_not_raise_it(self):
        self.hub.add_event(self.host, "nginx.crash", "MEDIUM", received_at=T0 - 2 * HOUR)
        self.tick(T0 + 6 * MIN)
        self.assertEqual(len(self.alerts("hub.agent_silent")), 1)

    def test_pending_host_that_never_reported(self):
        p = self.hub.add_host("new1", state="pending", last_seen=None, enrolled_at=T0 - 30 * MIN)
        self.tick(T0)
        self.assertEqual(self.alerts("hub.pending_silent"), [])
        self.hub.set_host(p["uuid"], enrolled_at=T0 - 2 * HOUR)
        self.tick(T0 + 20_000)
        self.tick(T0 + 40_000)
        self.assertEqual(len(self.alerts("hub.pending_silent")), 1)

    def test_orphan_is_high_once(self):
        self.hub.add_host("orph1", state="orphan")
        self.hub.set_host(self.host["uuid"], last_seen=T0 + 10 * HOUR)
        self.tick(T0 + 10 * HOUR)
        self.tick(T0 + 10 * HOUR + 20_000)
        self.assertEqual(len(self.alerts("hub.orphan")), 1)

    def test_retired_moved_and_revoked_hosts_are_not_reported_silent(self):
        for st in ("retired", "moved", "revoked"):
            self.hub.add_host("h-" + st, state=st, last_seen=T0 - DAY)
        self.hub.set_host(self.host["uuid"], last_seen=T0 + 10 * MIN)
        self.tick(T0 + 11 * MIN)
        self.assertEqual(self.alerts(), [])


class StartupAndSelfHealthTests(HostCase):
    def test_hub_down_alert_after_ten_minutes(self):
        self.hub.writer.call(lambda c: hub_engine._meta_set(c, "engine_tick", T0 - 30 * MIN))
        self.engine.startup(T0)
        (a,) = self.alerts("hub.down")
        self.assertIn("Hub was down from", a["payload"]["title"])
        self.assertEqual(a["payload"]["fields"]["down for"], "30m")
        self.assertEqual(self.hub.meta("engine_tick"), str(T0))

    def test_no_alert_after_a_short_restart_or_a_first_start(self):
        self.engine.startup(T0)
        self.hub.writer.call(lambda c: hub_engine._meta_set(c, "engine_tick", T0 - 5 * MIN))
        self.engine.startup(T0)
        self.assertEqual(self.alerts(), [])
        self.assertEqual(self.hub.meta("engine_first_tick"), str(T0))

    def set_cert(self, name, days, now):
        self.hub.pki.info[name] = {"not_after": now + int(days * DAY)}

    def test_server_certificate_levels(self):
        now = T0
        self.set_cert("server.pem", 25, now)
        self.hub.writer.call(lambda c: hub_engine._selfhealth(c, self.hub, now))
        self.assertEqual(self.note_texts("server_cert_30")[0][0], "MEDIUM")
        self.assertEqual(self.alerts("hub.server_cert"), [])
        self.set_cert("server.pem", 10, now + 10 * MIN)
        self.hub.writer.call(lambda c: hub_engine._selfhealth(c, self.hub, now + 10 * MIN))
        (a,) = self.alerts("hub.server_cert")
        self.assertEqual(a["severity"], "HIGH")
        self.assertIn("reissue-cert", a["payload"]["next_step"])

    def test_ca_levels(self):
        self.set_cert("ca.pem", 600, T0)
        self.set_cert("server.pem", 90, T0)
        self.hub.writer.call(lambda c: hub_engine._selfhealth(c, self.hub, T0))
        self.assertEqual(self.note_texts("ca_2y")[0][0], "MEDIUM")
        self.assertEqual(self.alerts("hub.ca_expiry"), [])
        self.set_cert("ca.pem", 300, T0 + MIN)
        self.hub.writer.call(lambda c: hub_engine._selfhealth(c, self.hub, T0 + MIN))
        self.assertEqual(self.alerts("hub.ca_expiry")[0]["severity"], "HIGH")

    def test_advisory_table_age(self):
        from datetime import datetime, timezone
        day0 = int(datetime(2026, 11, 19, tzinfo=timezone.utc).timestamp() * 1000)
        self.set_cert("ca.pem", 3000, day0)
        self.set_cert("server.pem", 90, day0)
        for days, expect, status in ((50, [], "ok"), (100, "advisory_90", "old"), (200, "advisory_180", "stale")):
            now = day0 + days * DAY
            self.set_cert("ca.pem", 3000, now)
            self.set_cert("server.pem", 90, now)
            self.hub.writer.call(lambda c: hub_engine._selfhealth(c, self.hub, now))
            self.assertEqual(self.hub.meta("advisory_status"), status)
            if expect:
                self.assertEqual(self.note_texts(expect)[0][0], "MEDIUM")

    def test_backup_age(self):
        self.hub.writer.call(lambda c: hub_engine._meta_set(c, "engine_first_tick", T0 - 8 * DAY))
        self.set_cert("ca.pem", 3000, T0)
        self.set_cert("server.pem", 90, T0)
        self.hub.writer.call(lambda c: hub_engine._selfhealth(c, self.hub, T0))
        (a,) = self.alerts("hub.backup_age")
        self.assertEqual(a["severity"], "HIGH")
        with open(self.hub.paths.last_backup, "w") as f:                    # the marker written by a good backup (epoch seconds)
            f.write("%d\n" % ((T0 - DAY) // 1000))
        self.hub.writer.call(lambda c: c.execute("DELETE FROM alert_state"))
        self.hub.writer.call(lambda c: hub_engine._selfhealth(c, self.hub, T0))
        self.assertEqual(len(self.alerts("hub.backup_age")), 1)           # still one: the recent backup raised nothing

    def test_backup_marker_in_meta_counts_too(self):
        self.set_cert("ca.pem", 3000, T0)
        self.set_cert("server.pem", 90, T0)
        self.hub.writer.call(lambda c: hub_engine._meta_set(c, "engine_first_tick", T0 - 30 * DAY))
        self.hub.writer.call(lambda c: hub_engine._meta_set(c, "last_backup", T0 - HOUR))
        self.hub.writer.call(lambda c: hub_engine._selfhealth(c, self.hub, T0))
        self.assertEqual(self.alerts("hub.backup_age"), [])

    def test_database_and_disk_use(self):
        self.set_cert("ca.pem", 3000, T0)
        self.set_cert("server.pem", 90, T0)
        self.hub.settings["max_db_size"] = "64K"
        Usage = namedtuple("Usage", "total used free")
        with mock.patch.object(hub_engine.shutil, "disk_usage", return_value=Usage(100, 85, 15)):
            self.hub.writer.call(lambda c: hub_engine._selfhealth(c, self.hub, T0))
        self.assertEqual(self.note_texts("db_size")[0][0], "MEDIUM")
        self.assertEqual(self.note_texts("disk_80")[0][0], "MEDIUM")
        self.assertEqual(self.alerts("hub.disk_use"), [])
        with mock.patch.object(hub_engine.shutil, "disk_usage", return_value=Usage(100, 95, 5)):
            self.hub.writer.call(lambda c: hub_engine._selfhealth(c, self.hub, T0 + HOUR))
        self.assertEqual(self.alerts("hub.disk_use")[0]["severity"], "HIGH")

    def test_engine_cursor_behind(self):
        self.hub.add_event(self.host, "ssh.fail", "LOW", received_at=T0)
        self.hub.writer.call(lambda c: self.engine._cursor_check(c, self.hub, T0 + 30_000))
        self.assertEqual(self.alerts("hub.engine_lag"), [])
        self.hub.writer.call(lambda c: self.engine._cursor_check(c, self.hub, T0 + 2 * MIN))
        self.assertEqual(self.alerts("hub.engine_lag")[0]["severity"], "HIGH")

    def test_a_failing_check_does_not_stop_the_others(self):
        # no certificates known to the fake pki: both certificate checks fail, the backup check still runs
        self.hub.writer.call(lambda c: hub_engine._meta_set(c, "engine_first_tick", T0 - 9 * DAY))
        self.hub.writer.call(lambda c: hub_engine._selfhealth(c, self.hub, T0))
        self.assertEqual(len(self.alerts("hub.backup_age")), 1)
        self.assertTrue(any("server certificate failed" in m for _l, m in self.hub.logs))

    def test_engine_thread_ticks_and_stops(self):
        self.hub.add_event(self.host, "tetragon.env-read", "HIGH", received_at=T0)
        self.engine.start()
        deadline = time.time() + 5
        while time.time() < deadline and self.hub.meta("engine_cursor") != "1":
            time.sleep(0.05)
        self.engine.stop()
        self.assertEqual(self.hub.meta("engine_cursor"), "1")
        self.assertFalse(self.engine._thread.is_alive())
        self.assertEqual(len(self.alerts("tetragon.env-read")), 1)


class DigestTests(HostCase):
    def test_digest_content(self):
        w2 = self.hub.add_host("web2", last_seen=T0 - 20 * DAY, schema=0, proto=0)
        self.hub.add_event(self.host, "ssh.fail", "LOW", count=5, received_at=T0 - HOUR)
        self.hub.add_event(w2, "ssh.fail", "LOW", count=7, received_at=T0 - HOUR)
        self.hub.add_event(w2, "inventory.stale", "MEDIUM", received_at=T0 - HOUR)
        self.hub.add_event(self.host, "ssh.login", "INFO", count=50, received_at=T0 - HOUR)
        self.hub.add_event(self.host, "tetragon.env-read", "HIGH", received_at=T0 - HOUR)
        self.hub.add_event(self.host, "ssh.fail", "LOW", received_at=T0 - HOUR, epoch=9, seq=1)
        self.hub.add_event(self.host, "ssh.fail", "LOW", received_at=T0 - HOUR, epoch=9, seq=4)             # seq 2 and 3 never arrived
        self.hub.add_event(self.host, "ssh.fail", "LOW", received_at=T0, ts=T0 - 3 * HOUR, replayed=1, epoch=8, seq=1)
        self.hub.writer.call(lambda c: hub_engine._meta_set(c, "audit_head", "deadbeef" * 8))
        self.engine.tick(T0 + 10_000)
        lines, counts = self.hub.writer.call(lambda c: hub_engine.build_digest(c, self.hub, T0 - DAY, T0 + MIN))
        text = "\n".join(lines)
        self.assertIn("LOW ssh.fail x15 on 2 host(s)", text)                  # sum(count) over six rows (5+7+1+1+1), distinct hosts
        self.assertIn("MEDIUM inventory.stale x1 on 1 host(s)", text)
        self.assertNotIn("ssh.login", text)                                   # INFO stays out
        self.assertIn("Open incidents: 1 (HIGH 1)", text)
        self.assertIn("Silent: web2 for 20 days; retire it? (edr-hub host web2 retire)", text)
        self.assertIn("Lagging client: web2", text)
        self.assertIn("2 sequence number(s) missing from web1 (epoch 9)", text)
        self.assertIn("Late events: 1", text)
        self.assertIn("Audit head: deadbeefdeadbeef", text)
        self.assertEqual(counts["silent"], 1)

    def test_digest_is_sent_once_a_day_at_digest_time_bypassing_the_minimum(self):
        self.hub.settings["digest_time"] = "07:00"
        self.hub.settings["alert_min_severity"] = "CRITICAL"
        day = (T0 // DAY) * DAY
        self.hub.set_host(self.host["uuid"], last_seen=day + 9 * HOUR)
        self.tick(day + 6 * HOUR)
        self.assertEqual(self.alerts("hub.digest"), [])
        self.tick(day + 8 * HOUR)
        (d,) = self.alerts("hub.digest")
        self.assertEqual(d["payload"]["title"], "Daily digest for " + hub_common.ms_to_rfc3339(day)[:10])
        self.assertTrue(d["payload"]["lines"])
        self.tick(day + 8 * HOUR + 2 * MIN)
        self.tick(day + 20 * HOUR)
        self.assertEqual(len(self.alerts("hub.digest")), 1)
        self.hub.set_host(self.host["uuid"], last_seen=day + DAY + 9 * HOUR)
        self.tick(day + DAY + 8 * HOUR)
        self.assertEqual(len(self.alerts("hub.digest")), 2)

    def test_digest_lists_the_notes_made_since_the_last_one(self):
        self.beat(T0 + MIN, conntrack={"count": 750, "max": 1000})
        lines, _ = self.hub.writer.call(lambda c: hub_engine.build_digest(c, self.hub, T0, T0 + HOUR))
        self.assertTrue(any(l.startswith("MEDIUM Conntrack on web1 is 75% full") for l in lines), lines)
        lines, _ = self.hub.writer.call(lambda c: hub_engine.build_digest(c, self.hub, T0 + 2 * HOUR, T0 + 3 * HOUR))
        self.assertFalse(any("Conntrack" in l for l in lines))

    def test_a_failing_channel_is_in_the_digest(self):
        self.hub.writer.call(lambda c: c.execute(
            "INSERT INTO outbox (created, channel, severity, payload, attempts, next_try, state, last_error) VALUES (?,?,?,?,?,?,?,?)",
            (T0, "webhook", "HIGH", "{}", 3, T0, "failed", "HTTP 500")))
        lines, _ = self.hub.writer.call(lambda c: hub_engine.build_digest(c, self.hub, T0 - DAY, T0 + MIN))
        self.assertIn("Alert channel webhook is failing: HTTP 500", lines)


class EnrollAndRejectedTests(HostCase):
    def test_enrollment_is_a_high_notice_that_ignores_the_minimum_and_holds_no_secret(self):
        self.hub.settings["alert_min_severity"] = "CRITICAL"
        token = {"id": "abcd1234efgh5678", "created_by": "uid=0 loginuid=1000 sudo=j", "secret_sha256": "9" * 64}
        self.hub.writer.call(lambda c: hub_engine.on_enroll(c, self.hub, self.host, "203.0.113.50", token, False))
        (a,) = self.alerts("hub.enroll")
        self.assertEqual(a["severity"], "HIGH")
        self.assertIn("web1 enrolled from 203.0.113.50", a["payload"]["title"])
        self.assertIn("token made by uid=0 loginuid=1000 sudo=j", a["payload"]["title"])
        blob = json.dumps(a["payload"])
        self.assertNotIn("9" * 64, blob)
        self.assertNotIn("efgh5678", blob)
        self.hub.writer.call(lambda c: hub_engine.on_enroll(c, self.hub, self.host, "203.0.113.50", token, True))
        self.assertIn("re-enrolled", self.alerts("hub.enroll")[1]["payload"]["title"])

    def test_enrollment_with_odd_input_never_raises(self):
        self.hub.writer.call(lambda c: hub_engine.on_enroll(c, self.hub, None, None, None, False))

    def test_revoked_host_attempts_are_counted_and_alerted_once(self):
        gone = self.hub.add_host("bad1", state="revoked")
        for _ in range(3):
            self.hub.writer.call(lambda c: hub_engine.on_rejected(c, self.hub, gone, "host_revoked", "198.51.100.9"))
        (a,) = self.alerts("hub.rejected")
        self.assertEqual(a["severity"], "HIGH")
        self.assertIn("host_revoked", a["payload"]["title"])
        count = self.hub.q("SELECT count FROM alert_state WHERE key=?", ("rejected|%s|host_revoked" % gone["uuid"],))[0][0]
        self.assertEqual(count, 3)

    def test_moved_and_retired_are_silenced_and_unknown_is_a_note(self):
        gone = self.hub.add_host("old1", state="retired")
        self.hub.writer.call(lambda c: hub_engine.on_rejected(c, self.hub, gone, "host_retired", "198.51.100.9"))
        self.hub.writer.call(lambda c: hub_engine.on_rejected(c, self.hub, None, "host_unknown", "198.51.100.9"))
        self.assertEqual(self.alerts(), [])
        self.assertEqual(self.note_texts("rejected")[0][0], "MEDIUM")


class ClientNumberTests(HostCase):
    def test_a_far_pause_is_counted_as_24_hours_and_still_noted(self):
        self.beat(T0 + MIN, paused_until=10 ** 18)
        (sev, text), = self.note_texts("paused")
        self.assertEqual(sev, "MEDIUM")
        self.assertIn("counted as 24 hours", text)
        self.assertIn(hub_common.ms_to_rfc3339(T0 + MIN + DAY), text)

    def test_odd_numbers_never_stop_a_rule_from_firing(self):
        self.beat(T0 + MIN, conntrack={"count": 1e308, "max": 1})
        (a,) = self.alerts("hub.conntrack")
        self.assertEqual(a["severity"], "HIGH")
        for hb in ({"disk": {"free_pct": 10 ** 400}}, {"suricata_drops": {"packets": 10 ** 400, "drops": 10 ** 399}},
                   {"cert_not_after": float("inf")}, {"cert_not_after": float("nan")}, {"cert_not_after": -5}, {"cert_not_after": "9" * 60},
                   {"paused_until": float("inf")}, {"paused_until": "9" * 50}, {"conntrack": {"count": -1, "max": float("nan")}},
                   {"spool": {"dropped": {"hi": 10 ** 30}}}):
            self.beat(T0 + 2 * MIN, **hb)
        self.assertEqual([m for lvl, m in self.hub.logs if "failed" in m], [])

    def test_ms_is_bounded_and_never_raises(self):
        for v in (10 ** 18, float("inf"), 10 ** 400, "9" * 40, 1e308, 5):
            self.assertLessEqual(hub_engine._ms(v), hub_engine.MAX_MS)
        for v in (float("nan"), -1, "x", None, True, [], {}, "9" * 60):
            self.assertIsNone(hub_engine._ms(v))


class ExposureClockTests(HostCase):
    VULN = {"os_release": "Ubuntu 24.04", "checks": {
        "nginx_pkg": {"status": True, "packages": [{"name": "nginx", "version": "1.24.0-2ubuntu7.1", "origin": "ubuntu"}]},
        "nginx_exposure": {"tls": True}}}

    def eval(self, inv, when):
        self.hub.writer.call(lambda c: hub_engine._advisory_eval(c, self.hub, self.hub.host(self.host["uuid"]), inv, when, daily=False))

    def first_seen(self):
        row = self.hub.q("SELECT data FROM alert_state WHERE key=?", ("adv|" + self.host["uuid"],))[0][0]
        return json.loads(row)["first"]

    def test_unknown_and_missing_checks_keep_the_clock_and_a_definite_fix_clears_it(self):
        self.eval(self.VULN, T0)
        started = self.first_seen()
        self.assertEqual(list(started.values()), [T0])
        self.eval({"os_release": "Ubuntu 24.04", "checks": {"nginx_pkg": {"status": "unknown"}}}, T0 + HOUR)
        self.eval({"os_release": "Ubuntu 24.04", "checks": {}}, T0 + 2 * HOUR)
        self.eval({"checks": "garbage"}, T0 + 3 * HOUR)
        self.assertEqual(self.first_seen(), started)
        fixed = json.loads(json.dumps(self.VULN))
        fixed["checks"]["nginx_pkg"]["packages"][0]["version"] = "1.24.0-2ubuntu7.20"
        self.eval(fixed, T0 + 4 * HOUR)
        self.assertEqual(self.first_seen(), {})
        self.eval(self.VULN, T0 + 5 * HOUR)
        self.assertEqual(list(self.first_seen().values()), [T0 + 5 * HOUR])      # a new exposure starts a new clock

    def test_not_installed_is_a_definite_answer(self):
        self.eval(self.VULN, T0)
        self.eval({"os_release": "Ubuntu 24.04", "checks": {"nginx_pkg": {"status": False}}}, T0 + HOUR)
        self.assertEqual(self.first_seen(), {})


class AlertStateBoundTests(HostCase):
    def test_claimed_droplet_ids_use_one_row(self):
        for i in range(30):
            self.beat(T0 + i * MIN, droplet_id="evil-%d" % i)
        rows = self.hub.q("SELECT key, data FROM alert_state WHERE key LIKE 'dup|droplet|%'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(json.loads(rows[0][1])["ids"]), 3)

    def test_the_daily_job_prunes_rows_untouched_for_seven_days_but_not_live_conditions(self):
        def put(conn, key, last, data):
            conn.execute("INSERT INTO alert_state (key, severity, first, last, count, suppressed, data) VALUES (?,?,?,?,?,?,?)",
                         (key, "", last, last, 1, 0, json.dumps(data)))
        old = T0 - 8 * DAY
        self.hub.writer.call(lambda c: [put(c, "old|x", old, {}), put(c, "note|u|r|v", old, {"summary": "x"}),
                                        put(c, "silent|u", old, {"level": 1, "since": old}), put(c, "cleared|u", old, {"level": 0}),
                                        put(c, "task|survived|u", old, {}), put(c, "fresh|x", T0 - DAY, {}), put(c, "storm", old, {})])
        n = self.hub.writer.call(lambda c: hub_engine.prune_alert_state(c, T0))
        keys = {r[0] for r in self.hub.q("SELECT key FROM alert_state")}
        self.assertEqual(n, 3)
        self.assertEqual(keys, {"silent|u", "task|survived|u", "fresh|x", "storm"})


if __name__ == "__main__":
    unittest.main()
