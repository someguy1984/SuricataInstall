"""Tokens, enrollment and host states (PLAN.md section 2: Tokens, Enrollment, Host states).

Every function that touches the database takes the writer's `conn` and so runs inside `writer.call`:
the single-use rule of a token is then atomic with the transaction that signs and writes the host row.

Token format: `id.secret.ca_sha256`. The secret is 128 bits, kept only as SHA-256. A wrong secret, an unknown id,
an expired, revoked or used token all look the same to the caller (401).
"""

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import threading
import time
import uuid as uuidlib

import hub_common
import hub_db
import hub_pki

TTL_DEFAULT_S = 900
TTL_MAX_S = 24 * 3600
REPLAY_WINDOW_MS = 10 * 60 * 1000
BURN_AFTER = 5                          # wrong secrets that burn a token id
FAIL_PER_SOURCE_PER_MIN = 5
FAIL_GLOBAL_PER_MIN = 60
LIMITER_TABLE_MAX = 4096
TOKEN_ID_RE = re.compile(r"^[0-9a-f]{12}\Z")
TOKEN_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}\Z")
_DUMMY_HASH = hashlib.sha256(b"edr-hub dummy secret, compared when the id is unknown").hexdigest()

# Host state transitions (section 2, Host states). target -> states it may be reached from.
_TRANSITIONS = {
    "revoked": ("pending", "active", "orphan", "moved", "retired"),
    "retired": ("pending", "active", "orphan", "moved", "revoked"),
    "moved": ("pending", "active", "orphan"),
}
_REASON_OF_STATE = {"revoked": "revoked", "retired": "retired", "moved": "moved"}
# States that keep their peers in the never-ban list (section 2): pending, active, revoked.
PEER_STATES = ("pending", "active", "revoked")


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---- tokens ------------------------------------------------------------------------------------
def token_create(conn, hub, *, name=None, for_host=None, ttl_s=TTL_DEFAULT_S, source_cidr=None, created_by=""):
    """Make a token. Returns {"id", "token", "name", "expires_at", "enroll_port", "port", "hub_addresses"}.
    The full token is returned once and never stored. Raises ValueError with a short reason."""
    if (name is None) == (for_host is None):
        raise ValueError("give exactly one of a name or a host to re-enrol")
    try:
        ttl = int(ttl_s)
    except (TypeError, ValueError):
        raise ValueError("ttl must be a number of seconds") from None
    if ttl < 1:
        raise ValueError("ttl must be positive")
    if ttl > TTL_MAX_S:
        raise ValueError("ttl is at most 24 hours")
    now = hub_common.now_ms()
    cidr = None
    if source_cidr:
        try:
            cidr = hub_common.norm_cidr(source_cidr)
        except ValueError:
            raise ValueError("source must be a CIDR such as 203.0.113.0/24") from None
    if hub.settings.get("clients_only") and not cidr:
        raise ValueError("--source is required while clients_only is on")
    bound = None
    if for_host is not None:
        host = resolve_host(conn, str(for_host))
        if host is None:
            raise ValueError("no such host")
        bound = host["uuid"]
        name = None
    else:
        name = str(name)
        if not hub_common.HOST_NAME_RE.match(name):
            raise ValueError("name must be lower-case letters, digits and hyphens, at most 62 characters")
        if conn.execute("SELECT 1 FROM hosts WHERE name=?", (name,)).fetchone():
            raise ValueError("a host with that name exists")
        if conn.execute("SELECT 1 FROM tokens WHERE name=? AND used_at IS NULL AND revoked_at IS NULL AND expires_at>?",
                        (name, now)).fetchone():
            raise ValueError("a pending token for that name exists")
    token_id = secrets.token_hex(6)
    secret = secrets.token_urlsafe(16)
    expires = now + ttl * 1000
    conn.execute("INSERT INTO tokens(id, secret_sha256, name, bound_host, source_cidr, created_at, created_by, expires_at) "
                 "VALUES(?,?,?,?,?,?,?,?)", (token_id, _sha(secret), name, bound, cidr, now, str(created_by)[:200], expires))
    return {
        "id": token_id,
        "token": "%s.%s.%s" % (token_id, secret, hub.pki.ca_sha256()),
        "name": name,
        "for_host": bound,
        "expires_at": expires,
        "enroll_port": int(hub.settings.get("enroll_port", 8444)),
        "port": int(hub.settings.get("port", 8443)),
        "hub_addresses": list(hub.settings.get("public_ip") or []),
    }


def _token_state(row, now):
    if row["used_at"] is not None:
        return "used"
    if row["revoked_at"] is not None:
        return "revoked"
    if row["expires_at"] <= now:
        return "expired"
    return "pending"


def token_list(conn):
    """[{id, name, bound_host, source_cidr, expires_at, state}] newest first. Never a secret or its hash."""
    now = hub_common.now_ms()
    rows = conn.execute("SELECT id, name, bound_host, source_cidr, expires_at, used_at, revoked_at FROM tokens "
                        "ORDER BY created_at DESC, id").fetchall()
    return [{"id": r["id"], "name": r["name"], "bound_host": r["bound_host"], "source_cidr": r["source_cidr"],
             "expires_at": r["expires_at"], "state": _token_state(r, now)} for r in rows]


def token_revoke(conn, hub, token_id):
    """Revoke a token that is still pending. False when there is no such pending token."""
    cur = conn.execute("UPDATE tokens SET revoked_at=? WHERE id=? AND used_at IS NULL AND revoked_at IS NULL",
                       (hub_common.now_ms(), str(token_id)))
    return cur.rowcount == 1


def enroll_listener_wanted(conn, now_ms=None):
    """True while an unexpired, unused, unburnt token exists, and for the 10-minute replay window after the last
    redemption (a client whose reply was lost must be able to ask again)."""
    now = now_ms if now_ms is not None else hub_common.now_ms()
    row = conn.execute(
        "SELECT 1 FROM tokens WHERE revoked_at IS NULL AND ((used_at IS NULL AND expires_at>?) OR "
        "(used_at IS NOT NULL AND used_at>? AND issued_reply IS NOT NULL)) LIMIT 1",
        (now, now - REPLAY_WINDOW_MS)).fetchone()
    return row is not None


# ---- hosts -------------------------------------------------------------------------------------
def resolve_host(conn, ref):
    """A hosts row by name or UUID, or None."""
    if not isinstance(ref, str) or not ref or len(ref) > 64:
        return None
    return conn.execute("SELECT * FROM hosts WHERE uuid=? OR name=? ORDER BY uuid=? DESC LIMIT 1",
                        (ref, ref, ref)).fetchone()


def peers(conn):
    """Never-ban peers for the policy document: the TCP source addresses the hub saw (at most 2 per host) of hosts in
    a state that keeps them. Single IP literals, sorted, at most 512."""
    found = set()
    marks = ",".join("?" * len(PEER_STATES))
    for row in conn.execute("SELECT peer_ips FROM hosts WHERE state IN (%s)" % marks, PEER_STATES):
        try:
            for ip in json.loads(row["peer_ips"]):
                found.add(hub_common.norm_ip(ip))
        except (ValueError, TypeError):
            continue
    ordered = sorted(found, key=lambda t: (ipaddress.ip_address(t).version, ipaddress.ip_address(t)))
    return ordered[:hub_common.PEERS_MAX]


def add_peer(peer_json, ip):
    """peer_ips after seeing a connection from `ip`: at most 2, the newest last."""
    try:
        have = [x for x in json.loads(peer_json) if isinstance(x, str)]
    except (ValueError, TypeError):
        have = []
    if not ip:
        return json.dumps(have[-2:])
    have = [x for x in have if x != ip] + [ip]
    return json.dumps(have[-2:])


def _revoke_certs(conn, hub, row, reason, now):
    """Append the host's current and pending certificate to revoked.txt (synced)."""
    pki = hub.pki
    if row["cert_sha256"]:
        pki.revoked_add(row["cert_serial"] or "0", row["cert_sha256"], row["uuid"], reason, now)
    if row["pending_cert_sha256"]:
        pki.revoked_add(row["pending_cert_serial"] or "0", row["pending_cert_sha256"], row["uuid"], reason, now)


def host_set_state(conn, hub, uuid, new_state, actor=""):
    """revoke, retire and mark-moved. Revokes the certificate (revoked.txt, fsync) and clears the peers of a moved or
    retired host, as the Host states table says. Raises ValueError on a transition the table does not allow."""
    row = conn.execute("SELECT * FROM hosts WHERE uuid=?", (uuid,)).fetchone()
    if row is None:
        raise ValueError("no such host")
    allowed = _TRANSITIONS.get(new_state)
    if allowed is None:
        raise ValueError("unknown state")
    if row["state"] not in allowed:
        raise ValueError("a %s host cannot become %s" % (row["state"], new_state))
    now = hub_common.now_ms()
    _revoke_certs(conn, hub, row, _REASON_OF_STATE[new_state], now)
    peers_json = row["peer_ips"] if new_state == "revoked" else "[]"
    conn.execute("UPDATE hosts SET state=?, state_since=?, peer_ips=? WHERE uuid=?", (new_state, now, peers_json, uuid))
    if new_state in ("moved", "retired"):
        conn.execute("DELETE FROM maintenance WHERE host=?", (uuid,))


def host_adopt(conn, hub, uuid):
    """orphan -> active (after a restore, section 7)."""
    row = conn.execute("SELECT state FROM hosts WHERE uuid=?", (uuid,)).fetchone()
    if row is None:
        raise ValueError("no such host")
    if row["state"] != "orphan":
        raise ValueError("only an orphan host can be adopted")
    conn.execute("UPDATE hosts SET state='active', state_since=? WHERE uuid=?", (hub_common.now_ms(), uuid))


ORPHANS_MAX = 64


def orphan_from_certificate(conn, hub, der_hash, cn, serial, not_after_ms, peer_ip):
    """A certificate signed by our CA that the hosts table does not hold and revoked.txt does not list: a host enrolled
    or renewed after the backup that was restored (section 7, step 5). Makes or converts the host row to `orphan` and
    raises one HIGH notice per host. Returns the hosts row, or None when it must be refused.

    Only on a hub that was restored (meta.restored_at, set by `edr-hub restore`); never with an older certificate than
    the one the row holds; at most 64 orphan rows."""
    if not hub_db.meta_get(conn, "restored_at"):
        return None
    if hub.pki.revoked_lookup(der_hash) or not hub_pki.UUID_RE.match(cn or ""):
        return None
    if conn.execute("SELECT 1 FROM hosts WHERE cert_sha256=? OR pending_cert_sha256=? OR cert_serial=? OR pending_cert_serial=?",
                    (der_hash, der_hash, serial, serial)).fetchone():
        return None
    now = hub_common.now_ms()
    row = conn.execute("SELECT * FROM hosts WHERE uuid=?", (cn,)).fetchone()
    if row is None or row["state"] != "orphan":
        if conn.execute("SELECT COUNT(*) FROM hosts WHERE state='orphan'").fetchone()[0] >= ORPHANS_MAX:
            return None
    if row is None:
        name = "orphan-" + cn[:8]
        n = 1
        while conn.execute("SELECT 1 FROM hosts WHERE name=?", (name,)).fetchone():
            n += 1
            name = "orphan-%s-%d" % (cn[:8], n)
        conn.execute(
            "INSERT INTO hosts(uuid, name, droplet_id, cert_sha256, cert_serial, cert_not_after, state, state_since, "
            "enrolled_at, enrolled_from, peer_ips) VALUES(?,?,?,?,?,?, 'orphan', ?, ?, ?, ?)",
            (cn, name, "", der_hash, serial, not_after_ms, now, now, peer_ip or "", add_peer("[]", peer_ip)))
        newly = True
    elif row["state"] in ("pending", "active", "orphan"):
        if not_after_ms <= (row["cert_not_after"] or 0):
            return None                              # an older certificate never replaces the row's current one
        conn.execute("UPDATE hosts SET cert_sha256=?, cert_serial=?, cert_not_after=?, pending_cert_sha256=NULL, "
                     "pending_cert_serial=NULL, pending_cert_not_after=NULL, state='orphan', "
                     "state_since=CASE WHEN state='orphan' THEN state_since ELSE ? END WHERE uuid=?",
                     (der_hash, serial, not_after_ms, now, cn))
        newly = row["state"] != "orphan"
    else:
        return None
    host = conn.execute("SELECT * FROM hosts WHERE uuid=?", (cn,)).fetchone()
    if newly:
        _notify_orphan(conn, hub, host, peer_ip)         # once per host, not once per attempt
    return host


def _notify_orphan(conn, hub, host, peer_ip):
    try:
        import hub_audit
        hub_db.safely(conn, hub, "audit", lambda: hub_audit.append(
            conn, actor_kind="system", actor_detail="addr=" + (peer_ip or "?"), action="host.orphan",
            target=host["uuid"], outcome="ok", details={"name": host["name"]}))
    except ImportError:
        pass
    try:
        import hub_alerts
        hub_db.safely(conn, hub, "orphan alert", lambda: hub_alerts.notify(
            conn, hub, severity="HIGH", kind="host.orphan", host=host, always=True,
            summary="host %s presented a certificate this hub did not issue; it waits for `edr-hub host %s adopt`"
                    % (hub_common.clean(host["name"], 64), host["uuid"])))
    except ImportError:
        pass


# ---- enrollment --------------------------------------------------------------------------------
class FailureLimiter:
    """Failed enrollments: 5 a minute per source address and a fixed number a minute overall, in a bounded table."""

    def __init__(self, per_source=FAIL_PER_SOURCE_PER_MIN, overall=FAIL_GLOBAL_PER_MIN):
        self.per_source = per_source
        self.overall = overall
        self._lock = threading.Lock()
        self._by_source = {}
        self._all = []

    def _trim(self, now):
        cutoff = now - 60
        self._all = [t for t in self._all if t > cutoff]
        if len(self._by_source) > LIMITER_TABLE_MAX // 2:
            for key in list(self._by_source):
                self._by_source[key] = [t for t in self._by_source[key] if t > cutoff]
                if not self._by_source[key]:
                    del self._by_source[key]

    def blocked(self, source, now=None):
        now = time.monotonic() if now is None else now
        with self._lock:
            self._trim(now)
            hits = [t for t in self._by_source.get(source, ()) if t > now - 60]
            return len(hits) >= self.per_source or len(self._all) >= self.overall

    def record(self, source, now=None):
        now = time.monotonic() if now is None else now
        with self._lock:
            self._trim(now)
            self._all.append(now)
            if source in self._by_source or len(self._by_source) < LIMITER_TABLE_MAX:
                self._by_source.setdefault(source, []).append(now)


def _bad_token(conn, hub, peer_ip, why):
    try:
        import hub_audit
        hub_db.safely(conn, hub, "audit", lambda: hub_audit.append(
            conn, actor_kind="client", actor_detail="addr=" + (peer_ip or "?"), action="enroll", target="",
            outcome="denied", details={"why": why}))
    except ImportError:
        pass
    return ("err", "invalid_token")


def _clean_ips(value):
    out = []
    if isinstance(value, list):
        for item in value[:16]:
            try:
                ip = hub_common.norm_ip(item)
            except ValueError:
                continue
            if ip not in out:
                out.append(ip)
    return out


def redeem(conn, hub, req, peer_ip, now_ms=None):
    """POST /v1/enroll. Runs in the writer. Returns ("ok", reply_dict) or ("err", code).

    A returned ("err", ...) commits (wrong secrets are counted). Only an exception rolls everything back.
    Order of checks (section 2, Enrollment): token id and secret compare, existing-host rules, and only then the
    CSR and openssl."""
    now = now_ms if now_ms is not None else hub_common.now_ms()
    token_text = req.get("token") if isinstance(req, dict) else None
    if not isinstance(token_text, str):
        return ("err", "bad_schema")
    parts = token_text.split(".")
    well_formed = len(parts) == 2 and TOKEN_ID_RE.match(parts[0]) and TOKEN_SECRET_RE.match(parts[1])
    token_id, secret = (parts[0], parts[1]) if well_formed else ("", "")
    row = conn.execute("SELECT * FROM tokens WHERE id=?", (token_id,)).fetchone() if well_formed else None
    # Always compare, against a dummy hash for an unknown id, so timing leaks nothing.
    same = hmac.compare_digest(_sha(secret), row["secret_sha256"] if row is not None else _DUMMY_HASH)
    if row is None:
        return _bad_token(conn, hub, peer_ip, "unknown")
    if not same:
        bad = row["bad_attempts"] + 1
        conn.execute("UPDATE tokens SET bad_attempts=?, revoked_at=CASE WHEN ?>=? THEN COALESCE(revoked_at, ?) ELSE revoked_at END "
                     "WHERE id=?", (bad, bad, BURN_AFTER, now, token_id))
        return _bad_token(conn, hub, peer_ip, "wrong secret")
    if row["revoked_at"] is not None or row["bad_attempts"] >= BURN_AFTER:
        return _bad_token(conn, hub, peer_ip, "revoked")
    if row["source_cidr"]:
        try:
            inside = ipaddress.ip_address(peer_ip) in ipaddress.ip_network(row["source_cidr"])
        except ValueError:
            inside = False
        if not inside:
            return _bad_token(conn, hub, peer_ip, "source")
    csr = req.get("csr")
    if row["used_at"] is not None:
        # Replay: the same token and CSR within 10 minutes get the same certificate; anything else is a used token.
        if (isinstance(csr, str) and row["csr_sha256"] == _sha(csr) and now - row["used_at"] <= REPLAY_WINDOW_MS
                and row["issued_reply"]):
            return ("ok", json.loads(row["issued_reply"]))
        return _bad_token(conn, hub, peer_ip, "used")
    if row["expires_at"] <= now:
        return _bad_token(conn, hub, peer_ip, "expired")

    # The token is good. Now the body, which only describes the host for display.
    droplet = req.get("droplet_id")
    if (not isinstance(csr, str) or not isinstance(droplet, str) or not droplet or len(droplet) > 128
            or hub_common.clean(droplet, 200) != droplet):
        return ("err", "bad_schema")
    hostname = req.get("hostname", "")
    osname = req.get("os", "")
    hint = req.get("host_uuid")
    if not isinstance(hostname, str) or not isinstance(osname, str) or not (hint is None or isinstance(hint, str)):
        return ("err", "bad_schema")
    reported = hub_common.clean(hostname, 100)
    osname = hub_common.clean(osname, 100)
    ips = _clean_ips(req.get("ips"))

    bound = row["bound_host"]
    existing = None
    if bound:
        existing = conn.execute("SELECT * FROM hosts WHERE uuid=?", (bound,)).fetchone()
        if existing is None:
            return _bad_token(conn, hub, peer_ip, "host gone")
        host_uuid, name = existing["uuid"], existing["name"]
    else:
        if isinstance(hint, str) and hub_pki.UUID_RE.match(hint.lower()) and conn.execute(
                "SELECT 1 FROM hosts WHERE uuid=?", (hint.lower(),)).fetchone():
            return ("err", "host_exists")
        name = row["name"]
        if conn.execute("SELECT 1 FROM hosts WHERE name=?", (name,)).fetchone():
            return ("err", "host_exists")
        host_uuid = str(uuidlib.uuid4())

    try:
        signed = hub.pki.sign_client(csr, host_uuid)
    except ValueError:
        return ("err", "bad_request")

    if existing is not None:
        _revoke_certs(conn, hub, existing, "superseded", now)
        conn.execute(
            "UPDATE hosts SET reported_name=?, ips=?, os=?, droplet_id=?, cert_sha256=?, cert_serial=?, cert_not_after=?, "
            "pending_cert_sha256=NULL, pending_cert_serial=NULL, pending_cert_not_after=NULL, state='pending', "
            "state_since=?, enrolled_at=?, enrolled_from=?, source_cidr=?, peer_ips=?, policy_rev=NULL, "
            "policy_rev_applied=NULL, policy_rev_since=NULL WHERE uuid=?",
            (reported, json.dumps(ips), osname, droplet, signed["der_sha256"], signed["serial"], signed["not_after"],
             now, now, peer_ip, row["source_cidr"], add_peer("[]", peer_ip), host_uuid))
    else:
        conn.execute(
            "INSERT INTO hosts(uuid, name, reported_name, ips, peer_ips, os, droplet_id, cert_sha256, cert_serial, "
            "cert_not_after, state, state_since, enrolled_at, enrolled_from, source_cidr) "
            "VALUES(?,?,?,?,?,?,?,?,?,?, 'pending', ?, ?, ?, ?)",
            (host_uuid, name, reported, json.dumps(ips), add_peer("[]", peer_ip), osname, droplet, signed["der_sha256"],
             signed["serial"], signed["not_after"], now, now, peer_ip, row["source_cidr"]))
    reply = {
        "host_uuid": host_uuid,
        "certificate": signed["pem"],
        "ca": hub.pki.ca_pem(),
        "hub_addresses": list(hub.settings.get("public_ip") or [])[:hub_common.HUB_ADDRESSES_MAX],
        "port": int(hub.settings.get("port", 8443)),
        "not_after": hub_common.ms_to_rfc3339(signed["not_after"]),
        "state": "pending",
    }
    spent = conn.execute(
        "UPDATE tokens SET used_at=?, used_by=?, used_from=?, csr_sha256=?, issued_reply=? "
        "WHERE id=? AND used_at IS NULL AND revoked_at IS NULL", (now, host_uuid, peer_ip, _sha(csr), json.dumps(reply), token_id))
    if spent.rowcount != 1:
        raise RuntimeError("token was spent concurrently")       # rolls the host row back
    host = conn.execute("SELECT * FROM hosts WHERE uuid=?", (host_uuid,)).fetchone()
    _after_enroll(conn, hub, host, peer_ip, row, existing is not None)
    return ("ok", reply)


def _after_enroll(conn, hub, host, peer_ip, token_row, reenroll):
    """Audit and the HIGH notice. Neither may undo an enrollment whose certificate is already signed."""
    try:
        import hub_audit
        hub_db.safely(conn, hub, "audit", lambda: hub_audit.append(
            conn, actor_kind="client", actor_detail="addr=" + (peer_ip or "?"),
            action="enroll.reenroll" if reenroll else "enroll", target=host["uuid"], outcome="ok",
            details={"name": host["name"], "token": token_row["id"], "token_created_by": token_row["created_by"]}))
    except ImportError:
        pass
    try:
        import hub_engine
        hub_db.safely(conn, hub, "enrollment notice", lambda: hub_engine.on_enroll(conn, hub, host, peer_ip, token_row, reenroll))
    except ImportError:
        pass
