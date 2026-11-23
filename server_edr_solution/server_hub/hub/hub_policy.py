"""The per-host policy document and its stateless revision (PLAN.md section 4, Policy document; Appendix A).

    {"rev", "hub_time", "hub_addresses", "port", "bans", "feeds", "peers"}

`rev` is the first 16 lowercase hex characters of the SHA-256 of the canonical document without `rev` and
`hub_time` (keys sorted, no spaces, UTF-8). Two hosts with the same document share it. In this phase `bans` and
`feeds` stay empty: the slots are kept so the document shape never changes (P3 fills them).
Times in the document are epoch seconds on the hub clock.
"""

import hashlib

import hub_common
import hub_enroll


def hub_addresses(settings):
    """The stored public_ip list, in stored order, bare IP literals, at most 4."""
    raw = settings.get("public_ip") or []
    if isinstance(raw, str):
        raw = [raw]
    out = []
    for item in raw:
        try:
            ip = hub_common.norm_ip(str(item))
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return out[:hub_common.HUB_ADDRESSES_MAX]


def rev(doc):
    """16 hex characters. hub_time and rev themselves are not part of the hash."""
    body = {k: v for k, v in doc.items() if k not in ("rev", "hub_time")}
    return hashlib.sha256(hub_common.canonical_json(body)).hexdigest()[:16]


def build(conn, hub, host_row, now_ms):
    """The full document for one host. `conn` may be a read-only connection."""
    doc = {
        "hub_time": int(now_ms // 1000),
        "hub_addresses": hub_addresses(hub.settings),
        "port": int(hub.settings.get("port", 8443)),
        "bans": [],             # P3
        "feeds": {},            # P3
        "peers": hub_enroll.peers(conn),
    }
    doc["rev"] = rev(doc)
    return doc


def note_revision(conn, host_row, new_rev, now_ms):
    """Record the revision issued to a host: policy_rev and policy_rev_since change only when the value does.
    Needs the writer's connection. Returns True when it changed."""
    if host_row["policy_rev"] == new_rev:
        return False
    conn.execute("UPDATE hosts SET policy_rev=?, policy_rev_since=? WHERE uuid=?", (new_rev, now_ms, host_row["uuid"]))
    return True
