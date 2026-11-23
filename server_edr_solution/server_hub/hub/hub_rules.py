"""The one rules table (PLAN.md section 4) and the rating of single events.

One table feeds three things: the alert body (meaning and next step), the runbook
(docs/RUNBOOK.md holds a copy that a test keeps identical) and the dashboard.

`rate()` is called by the ingest code for every validated event, before the INSERT.
`describe()` gives the meaning and next step of a kind. Standard library only.
"""

import fnmatch
import ipaddress
import json
import os
import re
import sys

if __name__ == "__main__":                       # run by hand: python3 -I hub_rules.py --print
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from hub_common import SEVERITIES, sev_rank, norm_ip

# Heartbeat keys: hub PLAN Appendix A, Request keys. The authority for every heartbeat key.
HEARTBEAT_KEYS = (
    "sent_at", "agent_version", "agent_sha256", "schema", "proto", "boot_id", "uptime_s", "kernel",
    "droplet_id", "seq", "epoch", "units", "tetragon", "nft", "conntrack", "dns_lock", "disk", "load",
    "mem", "suricata_drops", "spool", "local_conf_sha256", "cert_not_after", "maintenance_until",
    "paused_until", "policy_rev_applied", "last_apply_error", "ban_counts", "inventory", "shutdown",
)

# Host columns a hub-side rule may read (hub PLAN section 3, Tables)
HOST_FIELDS = ("last_seen", "policy_rev", "policy_rev_since", "state", "enrolled_at", "skew_ms",
               "shutdown_notice_at", "first_heartbeat_at")

# Groups, in the order the runbook shows them
GROUPS = (
    ("attack", "Attacks on a host"),
    ("containment", "Containment and loss of visibility"),
    ("inventory", "Inventory and coverage"),
    ("hub", "Hub notices"),
    ("selfhealth", "Hub self-health"),
)


def _rule(rid, group, title, severity, meaning, next_step, kinds=(), hb_keys=(), hub_side="", hub_kind=""):
    return {
        "id": rid, "group": group, "title": title, "kinds": tuple(kinds), "hb_keys": tuple(hb_keys),
        "hub_side": hub_side, "hub_kind": hub_kind, "severity": severity,
        "meaning": meaning, "next_step": next_step,
    }


RULES = (
    # ---- Attacks on a host ---------------------------------------------------------------------
    _rule("web_exec", "attack", "A web-user process execs, writes code or becomes uid 0", "CRITICAL",
          "A process in the web user's tree ran a program, wrote code or became uid 0.",
          "Patch if vulnerable, snapshot, then restart nginx (not reload): Sigkill stops the exec, not code already in the worker.",
          kinds=("tetragon.nginx-exec", "tetragon.web-exec", "tetragon.web-write-code", "tetragon.privilege-escalation")),
    _rule("sctp", "attack", "An SCTP socket, or the sctp module loading", "CRITICAL from a web-user tree, else HIGH",
          "An SCTP socket was opened or the sctp module loaded: the root step of NGINX2Root.",
          "Treat as the root step of NGINX2Root (https://xint.io/blog/nginx2root-remote-code-execution): snapshot, patch the kernel, block the module.",
          kinds=("tetragon.sctp-socket", "tetragon.monitor-kernel-modules")),
    _rule("dnslock", "attack", "A plain-DNS refusal by the DNS lock", "HIGH; MEDIUM when the destination is an nginx resolver of that host",
          "The DNS lock refused a lookup that bypassed the local resolver.",
          "nginx with an outside resolver makes these lookups legitimate: point it at 127.0.0.53 (client section 4.4).",
          kinds=("edr.dnslock",)),
    _rule("log_truncated", "attack", "A tailed log file shrank", "HIGH",
          "A log file the agent tails became shorter: someone may be hiding traces.",
          "Read the host's auth and nginx logs by hand; treat as tampering until explained (client section 4.5, Log shrink).",
          kinds=("tamper.log_truncated",)),
    _rule("secrets_read", "attack", "A .env read by an unexpected program; tampering; a decoy file read", "HIGH",
          "A secrets file was read by an unexpected program, a kit file was tampered with, or a decoy file was read.",
          "Assume .env was read: rotate APP_KEY, database and API secrets.",
          kinds=("tetragon.env-read", "tamper.*", "canary.file")),
    _rule("nginx_crash", "attack", "nginx worker crashes: 3 in 10 minutes on one host", "HIGH",
          "nginx workers crashed three times (sum of count) within ten minutes.",
          "Possible exploit attempts; low fidelity alone (https://cert.europa.eu/publications/security-advisories/2026-022/). Check the package and the exposure.",
          kinds=("nginx.crash",)),
    _rule("bigconn", "attack", "One :443 connection past 4 GiB", "MEDIUM; HIGH if a crash follows in 30 minutes",
          "A single :443 connection carried more than 4 GiB: the heap-corruption stage of CVE-2026-123007.",
          "The client bans the source on a repeat (client section 4.2). Check for a crash and for the nginx version.",
          kinds=("edr.bigconn", "nginx.crash")),
    _rule("window_update", "attack", "Flow-control violation from one IP, 3 in 10 minutes", "MEDIUM",
          "nginx logged 'client violated connection flow control: received WINDOW_UPDATE' for one address.",
          "Local ban. A rejected attempt on patched builds; logged only at info, so edr-check warns if the log is hidden.",
          kinds=("nginx.marker.window_update",)),
    _rule("resolver_cancel", "attack", "'could not cancel ... resolving'", "HIGH",
          "nginx logged the resolver cancel line that only unpatched builds write (CVE-2026-123634).",
          "Patch nginx: this line is logged at ALERT only by unpatched builds.",
          kinds=("nginx.marker.resolver_cancel",)),
    _rule("tripwire", "attack", "Tripwire path hit", "LOW (404, 403, 444); HIGH (200)",
          "A tripwire path was requested. A 200 answer means the site serves that path.",
          "The client bans locally. A 200 means the site serves the path: no ban, check the site.",
          kinds=("canary.tripwire",)),
    _rule("auth_state", "attack", "New uid-0 account, sudoers or authorized_keys change", "HIGH",
          "The account, sudoers or authorized_keys state of the host changed.",
          "Compare with the change you made; if none, assume persistence (client section 4.5.1, auth_state).",
          kinds=("inventory.auth_state",)),
    _rule("ssh_login", "attack", "A new key or first root login, or a password login with password auth off", "MEDIUM / HIGH",
          "An SSH login that is new: a new key, a first root login, or a password where passwords are off.",
          "A new source address is a digest line. Check that the login was yours; novelty stays LOW for the first 14 days.",
          kinds=("ssh.login",)),
    _rule("never_ban_hint", "attack", "Scanner or web signal from an address in the never-ban ranges", "MEDIUM",
          "A scanner or web signal came from an address in the never-ban ranges. It is never banned.",
          "A hint only: load balancers are internal. Check whether the address is really yours.",
          kinds=("suricata.alert", "ssh.fail", "canary.tripwire")),
    # ---- Containment and loss of visibility ----------------------------------------------------
    _rule("contained", "containment", "Attempt contained: a crash, bigconn or flow-control line, then a killed exec or SCTP socket within 30 minutes",
          "CRITICAL",
          "Early signals of an nginx attack were followed within 30 minutes by a blocked exec or SCTP socket: the kill worked this time.",
          "Restart nginx; hunt for persistence (authorized_keys, cron, ld.so.preload); patch.",
          kinds=("nginx.crash", "edr.bigconn", "nginx.marker.window_update", "tetragon.nginx-exec", "tetragon.sctp-socket"),
          hub_kind="hub.contained"),
    _rule("survived", "containment", "Worker survived the kill: a fork-watch hit, then any web event within 10 minutes", "CRITICAL",
          "A fork-watch hit was followed by more web activity: the worker may still be running attacker code.",
          "Restart nginx (not reload). The hub keeps an open operator task until inventory shows worker start times newer than the hit.",
          kinds=("tetragon.fork-watch", "tetragon.web-exec", "tetragon.web-write-code", "tetragon.web-connect"),
          hub_kind="hub.survived"),
    _rule("possible_success", "containment", "Possible success: first signals, then within 30 minutes a heartbeat gap, tamper or Tetragon unhealthy",
          "CRITICAL",
          "Attack signals were followed within 30 minutes by silence, tampering or a Tetragon that is not healthy.",
          "Treat the host as lost: snapshot, rebuild, rotate every secret it held (https://raw.githubusercontent.com/Censys-Research/nginx2root/main/evidence/cve-2026-123007/RCE-CONFIRMED.md).",
          kinds=("nginx.crash", "edr.bigconn", "nginx.marker.window_update", "tetragon.nginx-exec", "tetragon.sctp-socket",
                 "tetragon.fork-watch", "tamper.*"),
          hb_keys=("tetragon", "units"), hub_side="hub-side heartbeat gap", hub_kind="hub.possible_success"),
    _rule("enforcement_gone", "containment", "Enforcement gone", "HIGH",
          "The client reports a policy set to enforce that is not loaded, or a kernel change without a passed canary.",
          "Read the heartbeat's policy list (name, mode, would_be_kills); restart Tetragon; run edr-check on the host.",
          kinds=("health.enforcement_gone",), hb_keys=("tetragon", "kernel")),
    _rule("agent_silent", "containment", "Agent silent", "HIGH; CRITICAL within 30 minutes of a rule above",
          "No heartbeat for five minutes.",
          "Down, tampered with or blinded. Silent 14 days: a daily 'retire it?' line, paging continues.",
          hub_side="hosts.last_seen", hub_kind="hub.agent_silent"),
    _rule("reboot", "containment", "Reboot: notice then a new boot id within 10 minutes / a new boot id with no notice",
          "INFO / MEDIUM; HIGH within 30 minutes of a Sigkill hit",
          "The host started with a new boot id.",
          "Check the console. Over 10 minutes of silence after a notice is the real alert.",
          hb_keys=("shutdown", "boot_id"), hub_kind="hub.reboot"),
    _rule("agent_build", "containment", "Unknown or changed agent build", "HIGH",
          "The agent's SHA-256 is not a known build, or it changed while the version did not.",
          "Re-check the build; add it with 'edr-hub agent-hash add SHA' if intended.",
          hb_keys=("agent_sha256", "agent_version"), hub_kind="hub.agent_build"),
    _rule("duplicate_identity", "containment", "Duplicate identity: one certificate from two droplet ids, or two live boot ids", "HIGH",
          "One certificate is used from two droplets, or two boot ids are live at once.",
          "A clone or a stolen key. Clone: enrol it with a plain token (new UUID) and retire the old row only if its droplet is gone. Stolen key: 'edr-hub host HOST revoke', then re-enrol the real host with a token made --for HOST.",
          hb_keys=("droplet_id", "boot_id"), hub_kind="hub.duplicate_identity"),
    _rule("disk", "containment", "Disk guard tripped, or free space under 10%", "CRITICAL",
          "The disk guard tripped or the disk has less than 10% free.",
          "Sent from memory first, not from a spool on the full disk. Free space on the host; the client empties its low lane first.",
          kinds=("health.diskguard", "health.disk_low"), hb_keys=("disk",), hub_kind="hub.disk_low"),
    _rule("policy_lag", "containment", "policy_rev_applied differs from policy_rev for over 5 minutes, or last_apply_error", "MEDIUM",
          "The host has not applied the policy document the hub issued, or reports an apply error.",
          "The host is not applying bans: check 'edr-agent status' and its journal.",
          hb_keys=("policy_rev_applied", "last_apply_error"), hub_side="hosts.policy_rev, hosts.policy_rev_since",
          hub_kind="hub.policy_lag"),
    _rule("paused", "containment", "A pause is in force", "MEDIUM, once per pause",
          "Bans, feeds, enforcement (except edr-canary) and the DNS lock are off on this host until the pause ends.",
          "Shown on the Fleet page. 'edr-agent resume' on the host ends it. A pause does not silence agent-silent.",
          hb_keys=("paused_until",), hub_kind="hub.paused"),
    _rule("no_canary", "containment", "No daily canary result from a host in 26 hours", "MEDIUM, once per host",
          "The daily canary through edr-policy-check did not report.",
          "Run 'sudo systemctl status edr-policy-check.timer' on the host (client section 4.3).",
          kinds=("canary.policy_check",), hub_kind="hub.no_canary"),
    _rule("nft_absent", "containment", "inet edr absent for 2 minutes", "HIGH",
          "The edr nftables table is missing.",
          "The edr-bans timer did not rebuild it: run 'sudo systemctl start edr-bans.service' and check its journal.",
          hb_keys=("nft",), hub_kind="hub.nft_absent"),
    _rule("conntrack", "containment", "Conntrack use of 70% or more", "MEDIUM; HIGH at 90%",
          "The connection tracking table is nearly full.",
          "Raise nf_conntrack_max or check for a flood (client section 4.2).",
          hb_keys=("conntrack",), hub_kind="hub.conntrack"),
    _rule("suricata_drops", "containment", "Suricata kernel drops over 1% in a window", "MEDIUM",
          "Suricata dropped more than 1% of the packets it was given.",
          "See client section 4.1 (capture, memcap and threads).",
          hb_keys=("suricata_drops",), hub_kind="hub.suricata_drops"),
    _rule("rules_stale", "containment", "Suricata rules not updated for 3 days", "MEDIUM",
          "The Suricata ruleset has not been updated for three days.",
          "See client section 4.1 (rule updates).",
          kinds=("health.rules_stale",)),
    # ---- Inventory, coverage ------------------------------------------------------------------
    _rule("advisory_exposed", "inventory", "Package below its fix and the feature exposed", "HIGH; MEDIUM for the resolver bug when mirror_request_body off is not set",
          "A package is older than the fix in the advisory table and the exposed feature is on.",
          "Repeat daily until fixed. Install the fixed package, then restart nginx. A TLS listener alone: HIGH after 24 hours.",
          kinds=("inventory.nginx_pkg", "inventory.nginx_exposure", "inventory.security_pending"),
          hb_keys=("inventory",), hub_kind="hub.advisory"),
    _rule("deleted_exe", "inventory", "Old nginx processes run the pre-upgrade binary", "HIGH",
          "Processes still run a binary that was replaced by an upgrade.",
          "Restart nginx or let workers drain; a reload never loads a new binary (https://nginx2root.com/).",
          kinds=("inventory.deleted_exe",)),
    _rule("kernel_pending", "inventory", "sctp loadable, running kernel below its fix, updates pending or reboot required over 7 days", "MEDIUM",
          "The running kernel is older than its fix, or security updates wait for a reboot.",
          "Daily digest. The running kernel decides, not the package: plan a reboot.",
          kinds=("inventory.sctp", "inventory.kernel_pending", "inventory.security_pending")),
    _rule("app_key_public", "inventory", "A file under public/ holds an APP_KEY= line", "HIGH",
          "A file the web server may serve contains an APP_KEY line.",
          "Rotate APP_KEY and remove the file (client section 4.5.1).",
          kinds=("inventory.posture",)),
    _rule("coverage_drift", "inventory", "Coverage drift", "MEDIUM",
          "A web root, php-fpm binary or pool user is not covered by the policies.",
          "Daily digest. Run 'edr-agent discover', then 'apply-config' (client section 4.3).",
          kinds=("inventory.uncovered_webroots", "inventory.uncovered_fpm_binaries", "inventory.uncovered_pool_users")),
    _rule("inventory_stale", "inventory", "Inventory file missing or over 2 hours old", "MEDIUM",
          "The agent could not give a fresh inventory. It reports 'unknown', never 'clean'.",
          "Check that edr-inventory.service runs on the host (client section 4.5).",
          kinds=("inventory.stale",)),
    # ---- Hub notices (not rows of the plan's tables; they give alerts a meaning and next step) -
    _rule("admin_action", "hub", "Admin action", "HIGH (always sent)",
          "An operator action changed trust, settings or secrets.",
          "Check that you or a colleague did it: 'edr-hub audit --since 1d'.",
          hub_side="admin actions", hub_kind="hub.admin"),
    _rule("enroll", "hub", "A host enrolled", "HIGH (always sent)",
          "A host was enrolled with a token.",
          "Check that you made the token for this host: 'edr-hub token list', 'edr-hub audit --since 1d'.",
          hub_side="enrollment", hub_kind="hub.enroll"),
    _rule("rejected", "hub", "A revoked or superseded certificate was used", "HIGH",
          "A certificate that the hub no longer accepts was presented on the fleet port.",
          "A stolen key or a stale client. See the 'stolen client key' runbook.",
          hub_side="403 on the fleet listener", hub_kind="hub.rejected"),
    _rule("pending_silent", "hub", "A pending host never reported", "HIGH",
          "A host enrolled over an hour ago and has sent no heartbeat.",
          "Check that the agent runs on the host; 'edr-hub host HOST retire' if the install was abandoned.",
          hub_side="hosts.state, hosts.enrolled_at", hub_kind="hub.pending_silent"),
    _rule("orphan", "hub", "A host awaits adoption", "HIGH",
          "After a restore, the host's certificate is valid but the hub has no record of enrolling it.",
          "Check the host, then 'edr-hub host UUID adopt'.",
          hub_side="hosts.state", hub_kind="hub.orphan"),
    _rule("skew", "hub", "Host clock skew over 5 minutes", "MEDIUM",
          "The host's clock differs from the hub's by more than five minutes.",
          "Fix NTP on the host. Event times are corrected, but the correction is only as good as the skew estimate.",
          hb_keys=("sent_at",), hub_side="hosts.skew_ms", hub_kind="hub.skew"),
    _rule("hub_down", "hub", "The hub was down", "HIGH",
          "The hub was not running for more than ten minutes.",
          "Read the journal for the cause. Clients spooled their events and replay them now.",
          hub_side="meta.engine_tick", hub_kind="hub.down"),
    _rule("event_loss", "hub", "Events were lost", "MEDIUM (digest)",
          "A gap in a host's sequence numbers, or a rising spool drop counter.",
          "Check the host's disk and spool ('edr-agent status').",
          hb_keys=("spool", "seq", "epoch"), hub_kind="hub.event_loss"),
    _rule("digest", "hub", "Daily digest", "MEDIUM and LOW",
          "The daily summary of MEDIUM and LOW findings.",
          "Read it; run 'edr-hub status' for the live state.",
          hub_side="daily", hub_kind="hub.digest"),
    _rule("crit_cap", "hub", "More CRITICAL alerts from one host than the cap allows", "HIGH",
          "One host sent more than 10 CRITICAL alerts in 30 minutes: the rest were held back for that host only.",
          "Read the host's incidents ('edr-hub incidents --open', 'edr-hub events --host HOST --min-sev critical'): a host that "
          "floods CRITICAL events is broken or compromised.",
          hub_side="per-host CRITICAL cap", hub_kind="hub.crit_cap"),
    _rule("storm", "hub", "Alerts suppressed by storm control", "HIGH",
          "More than 20 messages in ten minutes: the rest were held back.",
          "Run 'edr-hub incidents' and 'edr-hub status' for what is open.",
          hub_side="alert storm control", hub_kind="hub.storm"),
    _rule("test_alert", "hub", "Test alert", "INFO",
          "A test alert from 'edr-hub alert test'.",
          "Nothing to do: the channel works.",
          hub_side="edr-hub alert test", hub_kind="hub.test"),
    _rule("hub_failed", "hub", "The hub service failed", "HIGH",
          "edr-hub.service failed several times in a row.",
          "systemctl status edr-hub; journalctl --namespace edr-hub -u edr-hub.",
          hub_side="systemd OnFailure", hub_kind="hub.failed"),
    # ---- Hub self-health -----------------------------------------------------------------------
    _rule("client_cert_30", "selfhealth", "Client certificate under 30 days from expiry, unrenewed", "LOW (digest)",
          "A client certificate expires within 30 days and has not renewed.",
          "An expired one cannot renew: 'edr-agent enroll --token-file FILE' with a token made --for HOST (client section 4.6).",
          hb_keys=("cert_not_after",), hub_kind="hub.client_cert"),
    _rule("client_cert_14", "selfhealth", "Client certificate under 14 days, unrenewed", "MEDIUM",
          "A client certificate expires within 14 days and has not renewed.",
          "The same: re-enrol with a token made --for HOST.",
          hb_keys=("cert_not_after",), hub_kind="hub.client_cert"),
    _rule("client_cert_7", "selfhealth", "Client certificate under 7 days, unrenewed", "HIGH",
          "A client certificate expires within seven days and has not renewed.",
          "The same: re-enrol with a token made --for HOST.",
          hb_keys=("cert_not_after",), hub_kind="hub.client_cert"),
    _rule("server_cert_30", "selfhealth", "Hub server certificate under 30 days", "MEDIUM",
          "The hub's server certificate expires within 30 days: the automatic reissue failed.",
          "A lapse stops the whole fleet: 'edr-hub reissue-cert'.",
          hub_side="tls/server.pem notAfter", hub_kind="hub.server_cert"),
    _rule("server_cert_14", "selfhealth", "Hub server certificate under 14 days", "HIGH",
          "The hub's server certificate expires within 14 days.",
          "'edr-hub reissue-cert' now.",
          hub_side="tls/server.pem notAfter", hub_kind="hub.server_cert"),
    _rule("server_cert_7", "selfhealth", "Hub server certificate under 7 days", "HIGH",
          "The hub's server certificate expires within seven days.",
          "'edr-hub reissue-cert' now.",
          hub_side="tls/server.pem notAfter", hub_kind="hub.server_cert"),
    _rule("ca_2y", "selfhealth", "CA under 2 years", "MEDIUM",
          "The hub CA expires within two years.",
          "Replace the CA by year 8: a CA rollover is a rehome of every client (CA compromise runbook).",
          hub_side="ca/ca.pem notAfter", hub_kind="hub.ca_expiry"),
    _rule("ca_1y", "selfhealth", "CA under 1 year", "HIGH",
          "The hub CA expires within a year.",
          "Replace the CA now (CA compromise runbook, without the compromise).",
          hub_side="ca/ca.pem notAfter", hub_kind="hub.ca_expiry"),
    _rule("advisory_90", "selfhealth", "Advisory table over 90 days old", "MEDIUM",
          "The advisory table shipped with this hub release is older than 90 days.",
          "Update the hub release.",
          hub_side="advisories.json updated", hub_kind="hub.advisory_age"),
    _rule("advisory_180", "selfhealth", "Advisory table over 180 days old", "MEDIUM; status 'unknown', never 'fixed'",
          "The advisory table is older than 180 days: no package is reported as fixed.",
          "Update the hub release.",
          hub_side="advisories.json updated", hub_kind="hub.advisory_age"),
    _rule("backup_age", "selfhealth", "Last good backup over 7 days old", "HIGH",
          "No verified backup in seven days.",
          "'edr-hub backup'; the marker is written by the backup job after a verified backup.",
          hub_side="meta.last_backup, last-backup marker", hub_kind="hub.backup_age"),
    _rule("db_size", "selfhealth", "Database over 80% of its cap, WAL over 256 MB", "MEDIUM",
          "The database is close to its size cap, or the WAL is large.",
          "A pinned reader keeps the WAL growing: check for a stuck 'edr-hub-ui' request or CLI (PLAN section 3).",
          hub_side="database size, WAL size", hub_kind="hub.db_size"),
    _rule("disk_80", "selfhealth", "Disk over 80% used", "MEDIUM; HIGH at 90%",
          "The disk under the hub's state directory is filling up.",
          "Thin the backups in /var/backups/edr-hub; see the 'disk full' runbook.",
          hub_side="disk usage", hub_kind="hub.disk_use"),
    _rule("outbox_failing", "selfhealth", "Outbox failing over 1 hour", "dashboard and edr-hub status",
          "The alert channel has failed for over an hour. The webhook cannot report its own failure.",
          "'edr-hub alert test'; check the channel secret and the network from the hub.",
          hub_side="outbox rows"),
    _rule("engine_cursor", "selfhealth", "Engine cursor over 60 seconds behind", "HIGH",
          "The correlation engine is not keeping up.",
          "'edr-hub health' fails; read the hub journal (PLAN section 4, Watching the hub).",
          hub_side="meta.engine_cursor, meta.engine_tick", hub_kind="hub.engine_lag"),
)

RULES_BY_ID = {r["id"]: r for r in RULES}

# Which incident chain a kind belongs to (hub PLAN section 4, Incident lifecycle: the key is (host, chain))
CHAIN_TITLES = {
    "exploit": "Attack on the web stack",
    "tamper": "Tampering or loss of visibility",
    "secrets": "Secrets or decoys touched",
    "auth": "Authentication or account change",
    "exposure": "Vulnerable and exposed",
    "host": "Host health",
}

_CHAIN_PATTERNS = (
    ("exploit", ("tetragon.nginx-exec", "tetragon.web-*", "tetragon.privilege-escalation", "tetragon.sctp-socket",
                 "tetragon.monitor-kernel-modules", "tetragon.fork-watch", "nginx.*", "edr.bigconn")),
    ("tamper", ("tamper.*", "health.enforcement_gone", "health.tetragon_*", "health.sandbox_ineffective")),
    ("secrets", ("tetragon.env-read", "canary.*", "inventory.posture")),
    ("auth", ("ssh.*", "inventory.auth_state", "auth.*")),
    ("exposure", ("inventory.*",)),
    ("host", ("health.*", "edr.*")),
)


def chain_of(kind):
    """The incident chain for an event kind."""
    for chain, patterns in _CHAIN_PATTERNS:
        if any(fnmatch.fnmatchcase(kind, p) for p in patterns):
            return chain
    return "host"


# ---- Lookup ----------------------------------------------------------------------------------
def rule_for(kind):
    """The rule row that names this kind (exact name first, then a pattern, then a hub kind), or None."""
    if not isinstance(kind, str):
        return None
    for rule in RULES:
        if kind in rule["kinds"] or kind == rule["hub_kind"]:
            return rule
    for rule in RULES:
        if any("*" in k and fnmatch.fnmatchcase(kind, k) for k in rule["kinds"]):
            return rule
    return None


def dedup_kind(kind):
    """The kind part of a dedup key. A kind the table names exactly keeps its own key. Every other kind a client may
    invent shares one key per rule (a glob row such as tamper.*) or one key in all, so a host cannot make as many
    alert_state rows or pages as it can make kind names."""
    if not isinstance(kind, str):
        return "other"
    for rule in RULES:
        if kind in rule["kinds"] or kind == rule["hub_kind"]:
            return kind
    rule = rule_for(kind)
    return "glob:" + rule["id"] if rule else "other"


_GENERIC = {
    "tetragon": ("A Tetragon policy fired on the host.", "Read the event: 'edr-hub events --host HOST --since 1h'."),
    "suricata": ("Suricata raised an alert for traffic to or from the host.", "Read the event and its signature: 'edr-hub events --host HOST --since 1h'."),
    "nginx": ("nginx logged something the agent watches.", "Read the event: 'edr-hub events --host HOST --since 1h'."),
    "inventory": ("An inventory check found something to fix.", "Read the event: 'edr-hub events --host HOST --since 1d'."),
    "health": ("The agent reported a health problem of its own.", "Run 'edr-agent status' and 'edr-check' on the host."),
    "hub": ("The hub raised this notice itself.", "Run 'edr-hub status'."),
}


def describe(kind):
    """{"meaning", "next_step"} for a kind. Never raises; an unknown kind gets a generic text."""
    rule = rule_for(kind)
    if rule:
        return {"meaning": rule["meaning"], "next_step": rule["next_step"]}
    family = kind.split(".", 1)[0] if isinstance(kind, str) else ""
    meaning, step = _GENERIC.get(family, ("The agent sent an event with no rule of its own.",
                                          "Read the event: 'edr-hub events --host HOST --since 1h'."))
    return {"meaning": meaning, "next_step": step}


# ---- Rating ----------------------------------------------------------------------------------
_NEVER_BAN_V4 = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.168.0.0/16", "224.0.0.0/3"))
_NEVER_BAN_V6 = tuple(ipaddress.ip_network(n) for n in ("::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"))
_SCTP_RE = re.compile(r"sctp", re.I)


def _get(obj, key, default=None):
    try:
        v = obj[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if v is None else v


def _client_sev(event):
    sev = event.get("sev", event.get("severity"))
    return sev if sev in SEVERITIES else "LOW"


def _floor(sev, floor):
    return sev if sev_rank(sev) >= sev_rank(floor) else floor


def _cap(sev, ceiling):
    return sev if sev_rank(sev) <= sev_rank(ceiling) else ceiling


def _details(event):
    d = event.get("details")
    return d if isinstance(d, dict) else {}


def _proc(event):
    p = event.get("proc")
    if not isinstance(p, dict):
        p = _details(event).get("proc")
    return p if isinstance(p, dict) else {}


def in_web_tree(event):
    """True when the event comes from a web-user process tree or from the kit's own canary.

    The client's web policies only match the web users, so a non-root uid is taken as the web
    user; a root process counts only when its binary or parent is nginx, php-fpm or the canary.
    """
    kind = str(event.get("kind", ""))
    if event.get("source") == "canary" or kind.startswith("canary."):
        return True
    d = _details(event)
    if d.get("web_user") is True or d.get("web") is True or d.get("tree") == "web":
        return True
    p = _proc(event)
    text = " ".join(str(p.get(k, "")) for k in ("binary", "parent")).lower()
    if any(w in text for w in ("edr-canary", "nginx", "php-fpm", "php8")):
        return True
    uid = p.get("uid")
    return isinstance(uid, int) and not isinstance(uid, bool) and uid != 0


def _inventory_resolvers(conn, host_row):
    """The nginx `resolver` addresses of the host's last inventory (empty when unknown)."""
    uuid = _get(host_row, "uuid")
    if conn is None or not uuid:
        return set()
    row = conn.execute("SELECT body FROM inventory WHERE host=?", (uuid,)).fetchone()
    if not row:
        return set()
    try:
        body = json.loads(row[0])
        exposure = body["checks"]["nginx_exposure"]
    except (ValueError, KeyError, TypeError):
        return set()
    found = set()
    for key in ("resolver", "resolvers", "resolver_addrs", "resolver_addresses"):
        v = exposure.get(key) if isinstance(exposure, dict) else None
        for item in ([v] if isinstance(v, str) else v if isinstance(v, list) else []):
            try:
                found.add(norm_ip(item))
            except (ValueError, TypeError):
                pass
    return found


def _inventory_posture(conn, host_row, name):
    uuid = _get(host_row, "uuid")
    if conn is None or not uuid:
        return None
    row = conn.execute("SELECT body FROM inventory WHERE host=?", (uuid,)).fetchone()
    if not row:
        return None
    try:
        body = json.loads(row[0])
        return body["posture"][name]
    except (ValueError, KeyError, TypeError):
        return None


def in_never_ban_range(conn, ip_text):
    """True when the address is in the literal never-ban table or in the never_ban table."""
    try:
        ip = ipaddress.ip_address(norm_ip(ip_text))
    except (ValueError, TypeError):
        return False
    table = _NEVER_BAN_V4 if ip.version == 4 else _NEVER_BAN_V6
    if any(ip in n for n in table):
        return True
    if conn is None:
        return False
    try:
        for (cidr,) in conn.execute("SELECT cidr FROM never_ban"):
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
    except Exception:
        return False
    return False


def rate(conn, host_row, event):
    """Rate one validated event: (hub_severity, rated_by).

    rated_by is the id of the rule that changed the severity, or None when hub_severity equals
    the client's sev. Pure apart from small reads of `inventory` and `never_ban`; never raises.
    """
    try:
        return _rate(conn, host_row, event)
    except Exception as exc:                       # odd input must not stop ingest
        if isinstance(event, dict):
            print("hub_rules.rate: %s" % type(exc).__name__, file=sys.stderr)
        return (_client_sev(event) if isinstance(event, dict) else "LOW"), None


def _rate(conn, host_row, event):
    client = _client_sev(event)
    kind = event.get("kind")
    kind = kind if isinstance(kind, str) else ""
    sev, by = client, None

    if kind in ("tetragon.nginx-exec", "tetragon.web-exec", "tetragon.web-write-code", "tetragon.privilege-escalation"):
        # A client that rated one of these below MEDIUM judged it benign (php-fpm writing a compiled Laravel view):
        # keep that, or every page view would be a CRITICAL.
        if sev_rank(client) >= sev_rank("MEDIUM"):
            sev, by = "CRITICAL", "web_exec"
    elif kind == "tetragon.sctp-socket" or (kind == "tetragon.monitor-kernel-modules" and _is_sctp_module(event)):
        sev, by = ("CRITICAL" if in_web_tree(event) else "HIGH"), "sctp"
    elif kind == "edr.dnslock":
        what = _details(event).get("what")
        if what in ("plain", "self", "doh"):
            sev, by = _cap(client, "HIGH"), "dnslock"
            dst = event.get("dst_ip")
            if dst and dst_in(_inventory_resolvers(conn, host_row), dst):
                sev = _cap(sev, "MEDIUM")
    elif kind == "tamper.log_truncated":
        sev, by = _floor(client, "HIGH"), "log_truncated"
    elif kind in ("tetragon.env-read", "canary.file") or kind.startswith("tamper."):
        sev, by = _floor(client, "HIGH"), "secrets_read"
    elif kind == "nginx.marker.resolver_cancel":
        sev, by = _floor(client, "HIGH"), "resolver_cancel"
    elif kind == "nginx.marker.window_update":
        sev, by = _floor(client, "LOW"), "window_update"
    elif kind == "edr.bigconn":
        sev, by = _floor(client, "MEDIUM"), "bigconn"
    elif kind == "canary.tripwire":
        status = _details(event).get("status")
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = None
        if status is not None and 200 <= status < 300:
            sev, by = "HIGH", "tripwire"
        elif status is not None:
            sev, by = _cap(client, "LOW"), "tripwire"
    elif kind == "inventory.auth_state":
        sev, by = _floor(client, "HIGH"), "auth_state"
    elif kind == "inventory.posture" and (_details(event).get("field") == "app_key_in_public"
                                          or _details(event).get("app_key_in_public") is True):
        sev, by = _floor(client, "HIGH"), "app_key_public"
    elif kind == "ssh.login":
        d = _details(event)
        if str(d.get("auth", "")).lower().startswith("password") and _inventory_posture(conn, host_row, "sshd_password_auth") is False:
            sev, by = _floor(client, "HIGH"), "ssh_login"
    elif kind in ("health.diskguard", "health.disk_low"):
        sev, by = _floor(client, "CRITICAL"), "disk"
    elif kind == "health.enforcement_gone":
        sev, by = _floor(client, "HIGH"), "enforcement_gone"
    elif kind == "health.rules_stale":
        sev, by = _floor(client, "MEDIUM"), "rules_stale"
    elif kind == "inventory.stale":
        sev, by = _floor(client, "MEDIUM"), "inventory_stale"
    elif kind in ("inventory.uncovered_webroots", "inventory.uncovered_fpm_binaries", "inventory.uncovered_pool_users"):
        sev, by = _floor(client, "MEDIUM"), "coverage_drift"
    elif kind == "inventory.deleted_exe":
        sev, by = _floor(client, "HIGH"), "deleted_exe"       # the table says HIGH; the hub, not the client, owns the rating

    # A scanner or web signal from a never-ban range is a hint worth a digest line
    if kind in ("suricata.alert", "ssh.fail", "canary.tripwire") and sev_rank(sev) < sev_rank("MEDIUM"):
        ip = event.get("src_ip")
        if ip and in_never_ban_range(conn, ip):
            sev, by = "MEDIUM", "never_ban_hint"

    if sev == client:
        by = None
    return sev, by


def dst_in(addresses, ip_text):
    try:
        return norm_ip(ip_text) in addresses
    except (ValueError, TypeError):
        return False


def _is_sctp_module(event):
    d = _details(event)
    tag = d.get("tag")
    if isinstance(tag, str) and tag.lower() == "sctp":
        return True
    tags = d.get("tags")
    if isinstance(tags, list) and any(isinstance(t, str) and t.lower() == "sctp" for t in tags):
        return True
    if any(isinstance(d.get(k), str) and _SCTP_RE.search(d[k]) for k in ("module", "name", "detail", "message", "path")):
        return True
    return isinstance(event.get("summary"), str) and bool(_SCTP_RE.search(event["summary"]))


# ---- The runbook table -----------------------------------------------------------------------
RUNBOOK_BEGIN = "<!-- BEGIN RULES (generated from hub_rules.RULES; run: python3 hub_rules.py --update-runbook FILE) -->"
RUNBOOK_END = "<!-- END RULES -->"


def _cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def runbook_table():
    """The next-step table of the runbook, as Markdown, generated from RULES."""
    out = []
    labels = dict(GROUPS)
    for group, _title in GROUPS:
        rows = [r for r in RULES if r["group"] == group]
        if not rows:
            continue
        out.append("#### %s" % labels[group])
        out.append("")
        out.append("| Rule | Reads | Severity | Meaning | Next step |")
        out.append("|------|-------|----------|---------|-----------|")
        for r in rows:
            reads = ", ".join("`%s`" % k for k in r["kinds"] + r["hb_keys"])
            if r["hub_side"]:
                reads = (reads + "; " if reads else "") + "hub-side: " + r["hub_side"]
            out.append("| `%s` %s | %s | %s | %s | %s |" % (
                r["id"], _cell(r["title"]), _cell(reads), _cell(r["severity"]), _cell(r["meaning"]), _cell(r["next_step"])))
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def runbook_block():
    return RUNBOOK_BEGIN + "\n\n" + runbook_table() + "\n" + RUNBOOK_END


def update_runbook(path):
    """Replace the generated block of the runbook with the current table."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    start = text.index(RUNBOOK_BEGIN)
    end = text.index(RUNBOOK_END) + len(RUNBOOK_END)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text[:start] + runbook_block() + text[end:])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--update-runbook":
        update_runbook(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] == "--print":
        sys.stdout.write(runbook_table())
    else:
        print("usage: hub_rules.py --print | --update-runbook FILE", file=sys.stderr)
        sys.exit(64)
