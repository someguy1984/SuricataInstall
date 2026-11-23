"""hub_rules: the one table, the rating of single events, describe(), the runbook copy."""

import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "hub"))

import hub_common    # noqa: E402
import hub_rules     # noqa: E402
from test_engine_support import HubTestCase   # noqa: E402

# Hub PLAN Appendix A, Request keys of POST /v1/heartbeat (typed here, not imported, so a change to the table is noticed)
APPENDIX_A_HEARTBEAT_KEYS = {
    "sent_at", "agent_version", "agent_sha256", "schema", "proto", "boot_id", "uptime_s", "kernel", "droplet_id", "seq", "epoch",
    "units", "tetragon", "nft", "conntrack", "dns_lock", "disk", "load", "mem", "suricata_drops", "spool", "local_conf_sha256",
    "cert_not_after", "maintenance_until", "paused_until", "policy_rev_applied", "last_apply_error", "ban_counts", "inventory",
    "shutdown",
}

# Client PLAN Appendix B, Kind taxonomy, and the names its prose gives for each family
TETRAGON_POLICIES = {"nginx-exec", "sctp-socket", "web-exec", "web-write-code", "web-connect", "env-read", "fork-watch",
                     "privilege-escalation", "monitor-kernel-modules", "edr-canary"}
EXACT_KINDS = {"suricata.alert", "nginx.crash", "ssh.fail", "ssh.login", "auth.sudo", "ban.local", "inventory.stale",
               "edr.bigconn", "edr.dnslock", "edr.egress"}
NGINX_MARKERS = {"resolver_cancel", "conn_exhausted", "conn_pressure", "window_update"}
INVENTORY_CHECKS = {"nginx_pkg", "nginx_build", "nginx_exposure", "udp443", "nginx_logs", "real_ip", "deleted_exe", "security_pending",
                    "sctp", "kernel_pending", "php", "auth_state", "listeners", "posture", "uncovered_webroots",
                    "uncovered_fpm_binaries", "uncovered_pool_users", "stale"}
HEALTH = {"agent_start", "gap", "blind_window", "spool_dropped", "high_flood", "sandbox_ineffective", "tetragon_unreadable",
          "tetragon_ratelimit", "enforcement_gone", "log_format", "diskguard", "disk_low", "rules_stale", "identity",
          "config_invalid", "nginx_auto_restart"}
CANARY = {"file", "tripwire", "policy_check"}
TAMPER = {"log_truncated"}


def kind_defined(kind):
    """True when the kind (or a `family.*` pattern) is one client Appendix B defines."""
    if kind in EXACT_KINDS:
        return True
    family, _, rest = kind.partition(".")
    if rest == "*":
        return family in ("tetragon", "tamper", "inventory", "health", "canary")
    if family == "tetragon":
        return rest in TETRAGON_POLICIES
    if family == "nginx" and rest.startswith("marker."):
        return rest[len("marker."):] in NGINX_MARKERS
    if family == "inventory":
        return rest in INVENTORY_CHECKS
    if family == "health":
        return rest in HEALTH
    if family == "canary":
        return rest in CANARY
    if family == "tamper":
        return rest in TAMPER
    return False


class TableTests(unittest.TestCase):
    def test_heartbeat_keys_are_appendix_a(self):
        self.assertEqual(set(hub_rules.HEARTBEAT_KEYS), APPENDIX_A_HEARTBEAT_KEYS)

    def test_every_rule_names_a_defined_kind_or_key(self):
        for r in hub_rules.RULES:
            for k in r["kinds"]:
                self.assertTrue(kind_defined(k), "%s names an undefined kind %s" % (r["id"], k))
            for k in r["hb_keys"]:
                self.assertIn(k, APPENDIX_A_HEARTBEAT_KEYS, "%s names an unknown heartbeat key %s" % (r["id"], k))
            for k in r["hub_side"].split(","):
                pass
            if r["hub_side"] == "" and not r["kinds"] and not r["hb_keys"]:
                self.fail("%s reads nothing" % r["id"])
            for col in re.findall(r"hosts\.(\w+)", r["hub_side"]):
                self.assertIn(col, hub_rules.HOST_FIELDS + ("last_seen",), "%s reads an unknown host column %s" % (r["id"], col))

    def test_rows_are_complete_and_unique(self):
        ids = [r["id"] for r in hub_rules.RULES]
        self.assertEqual(len(ids), len(set(ids)))
        groups = {g for g, _ in hub_rules.GROUPS}
        for r in hub_rules.RULES:
            self.assertIn(r["group"], groups)
            for key in ("title", "severity", "meaning", "next_step"):
                self.assertTrue(r[key].strip(), "%s has no %s" % (r["id"], key))
            self.assertRegex(r["severity"].split()[0].rstrip(";,/"), r"^(CRITICAL|HIGH|MEDIUM|LOW|INFO|dashboard)$")
            if r["hub_kind"]:
                self.assertRegex(r["hub_kind"], r"^hub\.[a-z_0-9]+$")
            self.assertRegex(r["id"], r"^[a-z0-9_]+$")

    def test_the_plan_rows_of_p2_are_present(self):
        want = {"web_exec", "sctp", "dnslock", "secrets_read", "nginx_crash", "bigconn", "window_update", "resolver_cancel", "tripwire",
                "auth_state", "log_truncated", "ssh_login", "never_ban_hint", "contained", "survived", "possible_success",
                "enforcement_gone", "agent_silent", "reboot", "agent_build", "duplicate_identity", "disk", "policy_lag", "paused",
                "no_canary", "nft_absent", "conntrack", "suricata_drops", "rules_stale", "advisory_exposed", "deleted_exe",
                "kernel_pending", "app_key_public", "coverage_drift", "inventory_stale", "client_cert_30", "client_cert_14",
                "client_cert_7", "server_cert_30", "server_cert_14", "server_cert_7", "ca_2y", "ca_1y", "advisory_90", "advisory_180",
                "backup_age", "db_size", "disk_80", "outbox_failing", "engine_cursor"}
        self.assertLessEqual(want, set(hub_rules.RULES_BY_ID))
        for p3 in ("fleet_votes", "feed_stale"):
            self.assertNotIn(p3, hub_rules.RULES_BY_ID)

    def test_describe(self):
        d = hub_rules.describe("tetragon.nginx-exec")
        self.assertEqual(set(d), {"meaning", "next_step"})
        self.assertIn("restart nginx", d["next_step"])
        self.assertIn("rotate", hub_rules.describe("tamper.something_new")["next_step"])        # a pattern row
        self.assertIn("NGINX2Root", hub_rules.describe("tetragon.sctp-socket")["next_step"])
        for odd in ("", "x", "tetragon.unknown-policy", None, 5, "a" * 500):
            d = hub_rules.describe(odd)
            self.assertTrue(d["meaning"] and d["next_step"])
        self.assertEqual(hub_rules.describe("hub.agent_silent")["next_step"], hub_rules.RULES_BY_ID["agent_silent"]["next_step"])

    def test_chain_of(self):
        self.assertEqual(hub_rules.chain_of("tetragon.web-exec"), "exploit")
        self.assertEqual(hub_rules.chain_of("nginx.crash"), "exploit")
        self.assertEqual(hub_rules.chain_of("tamper.log_truncated"), "tamper")
        self.assertEqual(hub_rules.chain_of("tetragon.env-read"), "secrets")
        self.assertEqual(hub_rules.chain_of("inventory.auth_state"), "auth")
        self.assertEqual(hub_rules.chain_of("inventory.nginx_pkg"), "exposure")
        self.assertEqual(hub_rules.chain_of("health.diskguard"), "host")


def ev(kind, sev="MEDIUM", **kw):
    d = {"kind": kind, "sev": sev, "source": "tetragon", "details": {}, "src_ip": ""}
    d.update(kw)
    return d


class RateTests(HubTestCase):
    def rate(self, event, host=None):
        return hub_rules.rate(self.hub.writer.conn, host or self.host, event)

    def setUp(self):
        super().setUp()
        self.host = self.hub.add_host("web1")

    def test_web_exec_family_is_critical(self):
        for k in ("tetragon.nginx-exec", "tetragon.web-exec", "tetragon.web-write-code", "tetragon.privilege-escalation"):
            self.assertEqual(self.rate(ev(k, "HIGH")), ("CRITICAL", "web_exec"))
            self.assertEqual(self.rate(ev(k, "CRITICAL")), ("CRITICAL", None))
        # the client's own demotion (php-fpm writing a compiled Laravel view is LOW) is kept
        self.assertEqual(self.rate(ev("tetragon.web-write-code", "LOW")), ("LOW", None))

    def test_sctp(self):
        web = ev("tetragon.sctp-socket", "HIGH", details={"proc": {"binary": "/x", "uid": 33, "parent": "/usr/sbin/nginx"}})
        self.assertEqual(self.rate(web), ("CRITICAL", "sctp"))
        root = ev("tetragon.sctp-socket", "CRITICAL", details={"proc": {"binary": "/usr/bin/python3", "uid": 0, "parent": "/bin/bash"}})
        self.assertEqual(self.rate(root), ("HIGH", "sctp"))
        canary = ev("tetragon.sctp-socket", "HIGH", source="canary", details={"proc": {"binary": "/usr/local/lib/edr-agent/edr-canary", "uid": 0}})
        self.assertEqual(self.rate(canary)[0], "CRITICAL")
        mod = ev("tetragon.monitor-kernel-modules", "MEDIUM", details={"tag": "sctp", "proc": {"uid": 33}})
        self.assertEqual(self.rate(mod), ("CRITICAL", "sctp"))
        client_form = ev("tetragon.monitor-kernel-modules", "MEDIUM", details={"policy": "monitor-kernel-modules", "detail": "sctp", "path": "/lib/modules/x/sctp.ko"})
        self.assertEqual(self.rate(client_form)[0], "HIGH")                       # no proc: not a web tree
        other = ev("tetragon.monitor-kernel-modules", "MEDIUM", details={"module": "dummy"})
        self.assertEqual(self.rate(other), ("MEDIUM", None))

    def test_dnslock_ceiling_and_nginx_resolver(self):
        plain = ev("edr.dnslock", "HIGH", dst_ip="8.8.8.8", details={"what": "plain"})
        self.assertEqual(self.rate(plain), ("HIGH", None))
        self.assertEqual(self.rate(ev("edr.dnslock", "MEDIUM", dst_ip="8.8.8.8", details={"what": "plain"})), ("MEDIUM", None))
        self.assertEqual(self.rate(ev("edr.dnslock", "CRITICAL", dst_ip="8.8.8.8", details={"what": "doh"})), ("HIGH", "dnslock"))
        body = {"checks": {"nginx_exposure": {"status": True, "resolver": ["1.1.1.1", "9.9.9.9"]}}}
        self.hub.writer.call(lambda c: c.execute("INSERT INTO inventory (host, received_at, body) VALUES (?,?,?)", (self.host["uuid"], 1, json.dumps(body))))
        self.assertEqual(self.rate(ev("edr.dnslock", "HIGH", dst_ip="1.1.1.1", details={"what": "plain"})), ("MEDIUM", "dnslock"))
        self.assertEqual(self.rate(ev("edr.dnslock", "HIGH", dst_ip="8.8.8.8", details={"what": "plain"}))[0], "HIGH")
        self.assertEqual(self.rate(ev("edr.dnslock", "MEDIUM", details={"what": "relock"})), ("MEDIUM", None))

    def test_floors(self):
        self.assertEqual(self.rate(ev("tetragon.env-read", "MEDIUM")), ("HIGH", "secrets_read"))
        self.assertEqual(self.rate(ev("tamper.log_truncated", "LOW")), ("HIGH", "log_truncated"))
        self.assertEqual(self.rate(ev("tamper.kit_write", "LOW")), ("HIGH", "secrets_read"))
        self.assertEqual(self.rate(ev("canary.file", "LOW")), ("HIGH", "secrets_read"))
        self.assertEqual(self.rate(ev("canary.file", "CRITICAL")), ("CRITICAL", None))
        self.assertEqual(self.rate(ev("nginx.marker.resolver_cancel", "LOW")), ("HIGH", "resolver_cancel"))
        self.assertEqual(self.rate(ev("inventory.auth_state", "MEDIUM")), ("HIGH", "auth_state"))
        self.assertEqual(self.rate(ev("health.diskguard", "HIGH")), ("CRITICAL", "disk"))
        self.assertEqual(self.rate(ev("health.enforcement_gone", "MEDIUM")), ("HIGH", "enforcement_gone"))
        self.assertEqual(self.rate(ev("health.rules_stale", "LOW")), ("MEDIUM", "rules_stale"))
        self.assertEqual(self.rate(ev("edr.bigconn", "LOW")), ("MEDIUM", "bigconn"))

    def test_tripwire_status(self):
        self.assertEqual(self.rate(ev("canary.tripwire", "LOW", details={"status": 404})), ("LOW", None))
        self.assertEqual(self.rate(ev("canary.tripwire", "LOW", details={"status": 200})), ("HIGH", "tripwire"))
        self.assertEqual(self.rate(ev("canary.tripwire", "HIGH", details={"status": 403})), ("LOW", "tripwire"))

    def test_posture_and_ssh(self):
        self.assertEqual(self.rate(ev("inventory.posture", "MEDIUM", details={"field": "app_key_in_public"})), ("HIGH", "app_key_public"))
        self.assertEqual(self.rate(ev("inventory.posture", "MEDIUM", details={"field": "app_debug_true"})), ("MEDIUM", None))
        self.assertEqual(self.rate(ev("inventory.posture", "MEDIUM", details={"app_key_in_public": True})), ("HIGH", "app_key_public"))
        self.assertEqual(self.rate(ev("inventory.posture", "MEDIUM", details={"app_key_in_public": False})), ("MEDIUM", None))
        login = ev("ssh.login", "LOW", details={"auth": "password", "user": "j"})
        self.assertEqual(self.rate(login), ("LOW", None))               # inventory unknown: no change
        body = {"posture": {"sshd_password_auth": False}}
        self.hub.writer.call(lambda c: c.execute("INSERT INTO inventory (host, received_at, body) VALUES (?,?,?)", (self.host["uuid"], 1, json.dumps(body))))
        self.assertEqual(self.rate(login), ("HIGH", "ssh_login"))
        self.assertEqual(self.rate(ev("ssh.login", "MEDIUM", details={"auth": "publickey"})), ("MEDIUM", None))

    def test_never_ban_range_is_a_medium_hint(self):
        for ip in ("10.1.2.3", "192.168.0.9", "169.254.169.254", "127.0.0.1", "fd00::1", "::ffff:10.0.0.1"):
            self.assertEqual(self.rate(ev("ssh.fail", "LOW", src_ip=ip)), ("MEDIUM", "never_ban_hint"), ip)
        self.assertEqual(self.rate(ev("ssh.fail", "LOW", src_ip="198.18.77.4")), ("LOW", None))        # 198.18/15 is not in the literal table
        self.assertEqual(self.rate(ev("ssh.fail", "HIGH", src_ip="10.1.2.3")), ("HIGH", None))
        self.assertEqual(self.rate(ev("auth.sudo", "LOW", src_ip="10.1.2.3")), ("LOW", None))
        self.hub.writer.call(lambda c: c.execute("INSERT INTO never_ban (cidr, ts) VALUES ('198.51.100.0/24', 1)"))
        self.assertEqual(self.rate(ev("suricata.alert", "LOW", src_ip="198.51.100.7")), ("MEDIUM", "never_ban_hint"))

    def test_unrated_kinds_keep_the_clients_severity(self):
        for k, s in (("nginx.crash", "MEDIUM"), ("ssh.fail", "LOW"), ("auth.sudo", "INFO"), ("tetragon.edr-canary", "INFO"),
                     ("inventory.nginx_pkg", "HIGH"), ("ban.local", "LOW"), ("health.agent_start", "INFO")):
            self.assertEqual(self.rate(ev(k, s)), (s, None))

    def test_odd_input_never_raises(self):
        for odd in ({}, {"kind": None}, {"kind": 5, "sev": "NOPE"}, {"kind": "edr.dnslock", "details": "x", "sev": "HIGH"},
                    {"kind": "tetragon.sctp-socket", "details": {"proc": "x"}, "sev": "HIGH"},
                    {"kind": "ssh.fail", "src_ip": "not an ip", "sev": "LOW"}, {"kind": "canary.tripwire", "details": {"status": "x"}, "sev": "LOW"}):
            sev, by = hub_rules.rate(self.hub.writer.conn, self.host, odd)
            self.assertIn(sev, hub_common.SEVERITIES)
        self.assertEqual(hub_rules.rate(None, None, ev("tetragon.web-exec", "HIGH")), ("CRITICAL", "web_exec"))
        self.assertEqual(hub_rules.rate(None, {}, "not a dict")[0], "LOW")


class RunbookTests(unittest.TestCase):
    RUNBOOK = os.path.join(HERE, "..", "docs", "RUNBOOK.md")

    def test_runbook_table_is_identical_to_the_rules(self):
        with open(self.RUNBOOK, encoding="utf-8") as f:
            text = f.read()
        start = text.index(hub_rules.RUNBOOK_BEGIN)
        end = text.index(hub_rules.RUNBOOK_END) + len(hub_rules.RUNBOOK_END)
        self.assertEqual(text[start:end], hub_rules.runbook_block(),
                         "RUNBOOK.md drifted from hub_rules.RULES: run python3 hub_rules.py --update-runbook docs/RUNBOOK.md")

    def test_every_rule_appears_in_the_runbook(self):
        with open(self.RUNBOOK, encoding="utf-8") as f:
            text = f.read()
        for r in hub_rules.RULES:
            self.assertIn("`%s`" % r["id"], text)
            self.assertIn(r["next_step"].replace("|", "\\|"), text)

    def test_the_runbook_has_the_section_15_runbooks(self):
        with open(self.RUNBOOK, encoding="utf-8") as f:
            text = f.read()
        for head in ("A 03:00 alert from a phone", "Disk full or database corrupt", "Restore drill", "Certificates", "Rotating secrets",
                     "An operator leaves", "CA compromise", "Stolen client key", "Decommissioning a client", "Year-two housekeeping"):
            self.assertIn(head, text)


if __name__ == "__main__":
    unittest.main()
