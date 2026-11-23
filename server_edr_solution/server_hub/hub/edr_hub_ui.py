#!/usr/bin/python3 -I
"""edr-hub-ui: the dashboard of the hub (PLAN.md section 5), standard library only.

One page (ui/index.html) and a small JSON API on 127.0.0.1. It reads hub.db read-only, one connection
per request, and changes nothing itself: the three whitelisted writes (mark moved, set maintenance, end
maintenance) and the redemption of a login code go to the hub over ui.sock.

Ideas copied from tetragon/viewer/server.py (not imported): the exact Host allowlist against DNS
rebinding and the constant-time compare. There is no cookie and no token in any URL: a session is a
256-bit bearer token kept hashed in this process's memory only.
"""

import argparse
import base64
import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import re
import secrets
import select
import signal
import socket
import socketserver
import sqlite3
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

import hub_common  # noqa: E402
from hub_common import clean  # noqa: E402

try:
    import hub_rules  # noqa: E402
except ImportError:                                  # the page still works, with a generic text
    hub_rules = None

SESSION_IDLE_S = 30 * 60
SESSION_ABSOLUTE_S = 12 * 3600
SESSIONS_MAX = 16
FAILED_LOGINS_PER_MINUTE = 5
BODY_MAX = 16 * 1024
HANDLER_DEADLINE_S = 10
CONNECTIONS_MAX = 32
STREAMS_MAX = 8
STREAMS_PER_SESSION = 2
STREAM_PING_S = 15
STREAM_MAX_S = 15 * 60
STREAM_WRITE_TIMEOUT_S = 15
STREAM_QUEUE_MAX = 256
POLL_S = 1.0
REPLAY_MAX = 500
LIST_MAX = 500
FIELD_MAX = 2048
SOCK_REPLY_MAX = 256 * 1024
SETTINGS_RELOAD_S = 30

TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,100}\Z")
REF_RE = re.compile(r"^[A-Za-z0-9-]{1,64}\Z")
DURATION_RE = re.compile(r"^\d{1,3}[mh]\Z")
KIND_FILTER_RE = re.compile(r"^[a-z0-9_.-]{1,64}\*?\Z")

HTTP_TEXT = {
    400: "bad request", 401: "login required", 403: "forbidden", 404: "not found", 405: "method not allowed",
    409: "refused", 411: "length required", 413: "request too large", 415: "unsupported media type",
    429: "too many requests", 500: "internal error", 502: "the hub could not do that", 503: "hub down",
}
PERMISSIONS_POLICY = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=(), interest-cohort=()"
ENROLL_COMMAND = "sudo edr-hub token create --name NAME [--ttl 1h] [--source CIDR]"


def dumps(obj):
    """One line of ASCII JSON. < > & are escaped too, so the text can never form markup if it is ever misread as HTML."""
    text = json.dumps(obj, ensure_ascii=True, separators=(",", ":"))
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


class HubDown(Exception):
    pass


class ApiError(Exception):
    def __init__(self, status, text=None):
        super().__init__(text or HTTP_TEXT.get(status, "error"))
        self.status = status
        self.text = text or HTTP_TEXT.get(status, "error")


def jl(text, default):
    try:
        value = json.loads(text)
        return value
    except (TypeError, ValueError):
        return default


def cut(value, limit=FIELD_MAX):
    return value[:limit] if isinstance(value, str) else value


# ---- the page and its CSP -------------------------------------------------------------------------
def csp_for(page_bytes):
    """The Content-Security-Policy for one page: the SHA-256 of its single inline script and style."""
    text = page_bytes.decode("utf-8")
    scripts = re.findall(r"<script(\s[^>]*)?>(.*?)</script>", text, re.S | re.I)
    styles = re.findall(r"<style(\s[^>]*)?>(.*?)</style>", text, re.S | re.I)
    if len(scripts) != 1 or len(styles) != 1 or scripts[0][0].strip() or styles[0][0].strip():
        raise SystemExit("index.html must hold exactly one inline <script> and one inline <style>, with no attributes")

    def digest(body):
        return "'sha256-%s'" % base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii")
    return ("default-src 'none'; script-src %s; style-src %s; connect-src 'self'; img-src 'self'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'; object-src 'none'" % (digest(scripts[0][1]), digest(styles[0][1])))


# ---- sessions ---------------------------------------------------------------------------------------
class Sessions:
    """Bearer sessions, held as SHA-256 digests in memory only. A restart logs everyone out."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.Lock()
        self.items = {}                  # digest -> [created, last_used]

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create(self, token):
        digest = self.digest(token)
        now = self.clock()
        with self.lock:
            self._expire(now)
            while len(self.items) >= SESSIONS_MAX:
                oldest = min(self.items, key=lambda d: self.items[d][0])
                del self.items[oldest]
            self.items[digest] = [now, now]
        return digest

    def _expire(self, now):
        for digest in [d for d, (created, last) in self.items.items()
                       if now - last > SESSION_IDLE_S or now - created > SESSION_ABSOLUTE_S]:
            del self.items[digest]

    def check(self, token, touch=True):
        """The digest of a live session, or None. Compared in constant time."""
        return self.check_digest(self.digest(token), touch)

    def check_digest(self, presented, touch=True):
        now = self.clock()
        with self.lock:
            self._expire(now)
            found = None
            for digest in self.items:
                if hmac.compare_digest(digest, presented):
                    found = digest
            if found and touch:
                self.items[found][1] = now
            return found

    def drop(self, digest):
        with self.lock:
            self.items.pop(digest, None)


# ---- the live feed ----------------------------------------------------------------------------------
class Client:
    def __init__(self, digest):
        self.digest = digest
        self.q = queue.Queue(STREAM_QUEUE_MAX)
        self.dropped = False


class Feed:
    """One poller thread, a bounded queue per stream. A stream that falls behind is dropped with `reset`."""

    def __init__(self, app):
        self.app = app
        self.lock = threading.Lock()
        self.clients = set()
        self.last_id = None
        self.hub_down = False
        self.thread = threading.Thread(target=self._run, name="feed-poller", daemon=True)

    def start(self):
        self.thread.start()

    def register(self, digest):
        """A new stream, or None when the caps (8 in all, 2 per session) are reached."""
        with self.lock:
            if len(self.clients) >= STREAMS_MAX:
                return None
            if sum(1 for c in self.clients if c.digest == digest) >= STREAMS_PER_SESSION:
                return None
            client = Client(digest)
            self.clients.add(client)
            return client

    def unregister(self, client):
        with self.lock:
            self.clients.discard(client)

    def counts(self):
        with self.lock:
            return len(self.clients)

    def head(self):
        if self.last_id is not None:
            return self.last_id
        try:
            with self.app.db() as conn:
                return conn.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0]
        except HubDown:
            return 0

    def _broadcast(self, items):
        with self.lock:
            clients = list(self.clients)
        for client in clients:
            for item in items:
                try:
                    client.q.put_nowait(item)
                except queue.Full:
                    client.dropped = True
                    with self.lock:
                        self.clients.discard(client)
                    break

    def _run(self):
        conn = None
        version = None
        last_read = 0.0
        while not self.app.stopping.wait(POLL_S):
            try:
                if conn is None:
                    conn = self.app.open_ro()
                    version = None
                    self.hub_down = False
                    if self.last_id is None:
                        self.last_id = conn.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0]
                current = conn.execute("PRAGMA data_version").fetchone()[0]
                if current == version and time.monotonic() - last_read < 10:
                    continue
                version = current
                last_read = time.monotonic()
                rows = conn.execute(EVENT_SELECT + " WHERE e.id > ? ORDER BY e.id LIMIT ?",
                                    (self.last_id, REPLAY_MAX)).fetchall()
                if rows:
                    self.last_id = rows[-1]["id"]
                    self._broadcast([event_row(r) for r in rows])
            except (sqlite3.Error, HubDown):
                self.hub_down = True
                if conn is not None:
                    try:
                        conn.close()
                    except sqlite3.Error:
                        pass
                conn = None
        if conn is not None:
            conn.close()


# ---- rows ---------------------------------------------------------------------------------------------
EVENT_SELECT = ("SELECT e.id, e.received_at, e.ts, e.host, h.name AS host_name, e.source, e.severity, e.hub_severity, "
                "e.kind, e.summary, e.src_ip, e.src_trust, e.dst_ip, e.dst_port, e.count, e.replayed "
                "FROM events e LEFT JOIN hosts h ON h.uuid = e.host")


def event_row(r):
    """A compact event for lists and the live feed: every string at most 2 KiB."""
    return {k: cut(r[k]) for k in r.keys()}


def describe(kind):
    if hub_rules is not None and isinstance(kind, str):
        try:
            return hub_rules.describe(kind)
        except Exception:               # noqa: BLE001 - a rules bug must not take the page down
            pass
    return {"meaning": "No description is available for this kind.", "next_step": "Read the event details."}


def _small(value, limit=2048):
    """Pass a parsed JSON value through only when it is small."""
    try:
        return value if len(json.dumps(value)) <= limit else None
    except (TypeError, ValueError):
        return None


# ---- the application --------------------------------------------------------------------------------
class App:
    """State shared by every request: paths, settings, sessions, the feed, the page and its headers."""

    def __init__(self, paths, port, clock=time.monotonic):
        self.paths = paths
        self.port = port
        self.clock = clock
        self.stopping = threading.Event()
        self.sessions = Sessions(clock)
        self.feed = Feed(self)
        self.fail_lock = threading.Lock()
        self.fails = deque()
        self._settings = None
        self._settings_at = 0.0
        self._lock = threading.Lock()
        with open(paths.ui_index, "rb") as f:
            self.page = f.read()
        self.csp = csp_for(self.page)

    # settings and the Host allowlist
    def settings(self):
        with self._lock:
            now = time.monotonic()
            if self._settings is None or now - self._settings_at > SETTINGS_RELOAD_S:
                try:
                    self._settings = hub_common.load_settings(self.paths)
                except (OSError, ValueError):
                    self._settings = self._settings or hub_common.default_settings()
                self._settings_at = now
            return self._settings

    def allowed_hosts(self):
        s = dict(self.settings())
        s["ui_port"] = self.port              # --port decides the names; ui_host overrides them (section 14)
        return set(hub_common.ui_hosts(s))

    # database: one read-only connection per request
    def open_ro(self):
        uri = "file:%s?mode=ro" % quote(self.paths.db, safe="/")
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=3)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            conn.execute("SELECT 1 FROM meta LIMIT 1").fetchall()
            return conn
        except sqlite3.Error:
            raise HubDown()

    @contextlib.contextmanager
    def db(self):
        conn = self.open_ro()
        try:
            yield conn
        except sqlite3.Error:
            raise HubDown()
        finally:
            conn.close()

    # failed logins: at most 5 a minute in total
    def login_failures(self):
        now = self.clock()
        with self.fail_lock:
            while self.fails and now - self.fails[0] > 60:
                self.fails.popleft()
            return len(self.fails)

    def note_login_failure(self):
        with self.fail_lock:
            self.fails.append(self.clock())

    # ui.sock
    def hub_call(self, cmd, args, actor):
        """One request to the hub. Returns the parsed reply; raises ApiError(503) when the hub is not there."""
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(6)
        try:
            s.connect(self.paths.ui_sock)
            s.sendall(json.dumps({"cmd": cmd, "args": args, "actor": actor}).encode("utf-8") + b"\n")
            buf = bytearray()
            while not buf.endswith(b"\n") and len(buf) < SOCK_REPLY_MAX:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            reply = json.loads(bytes(buf).decode("utf-8"))
            if not isinstance(reply, dict):
                raise ValueError("reply")
            return reply
        except (OSError, ValueError):
            raise ApiError(503)
        finally:
            s.close()

    def log(self, level, message):
        try:
            sys.stderr.write("%s %s\n" % (level, clean(message, 300)))
            sys.stderr.flush()
        except (OSError, ValueError):
            pass


# ---- API: reads -------------------------------------------------------------------------------------
def api_status(app, conn, query, session):
    now = hub_common.now_ms()
    tick = conn.execute("SELECT value FROM meta WHERE key='writer_tick'").fetchone()
    tick_age = (now - int(tick[0])) // 1000 if tick and str(tick[0]).isdigit() else None
    stuck = conn.execute("SELECT COUNT(*) FROM outbox WHERE state IN ('pending','sending','failed') AND channel!='none' AND created < ?",
                         (now - 3600 * 1000,)).fetchone()[0]
    dead = conn.execute("SELECT COUNT(*) FROM outbox WHERE state='dead' AND channel!='none' AND created > ?",
                        (now - 86400 * 1000,)).fetchone()[0]
    last_backup = conn.execute("SELECT value FROM meta WHERE key='last_backup'").fetchone()
    return {
        "version": hub_common.VERSION,
        "now": now,
        "hub_down": tick_age is None or tick_age > 30 or app.feed.hub_down,
        "writer_tick_age_s": tick_age,
        "alerts_failing": bool(stuck or dead),
        "failed_logins_last_minute": app.login_failures(),
        "streams": app.feed.counts(),
        "last_backup": int(last_backup[0]) if last_backup and str(last_backup[0]).isdigit() else None,
        "head_event_id": conn.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0],
    }


def _host_health(hb):
    """The few heartbeat fields the Fleet page shows, each passed through only when small."""
    if not isinstance(hb, dict):
        return {}
    out = {}
    for key in ("units", "tetragon", "dns_lock", "suricata_drops", "disk", "load", "mem", "nft", "spool",
                "ban_counts", "maintenance_until", "paused_until", "last_apply_error", "local_conf_sha256",
                "uptime_s", "kernel"):
        if key in hb:
            value = _small(hb[key])
            if value is not None or hb[key] is None:
                out[key] = value
    return out


def _inventory_issues(inv):
    """Names of inventory checks that are not clean (exposure column), from the heartbeat's inventory object."""
    issues = []
    if isinstance(inv, dict) and isinstance(inv.get("checks"), dict):
        for name, check in list(inv["checks"].items())[:100]:
            if isinstance(check, dict) and check.get("status") in (False, "unknown"):
                issues.append({"check": cut(str(name), 64), "status": check.get("status")})
    return issues


EXPOSURE_CHECKS = ("nginx_pkg", "nginx_exposure", "deleted_exe", "sctp", "kernel_pending")


def exposure_state(inv):
    """The one value of the Fleet column "NGINX2Root exposure": (state, [check names]).

    exposed: a finding of severity HIGH or CRITICAL for one of the five checks; unknown: no inventory, or one of
    the five has status "unknown" (or the checks are missing); ok otherwise. Exposed wins over unknown.
    """
    if not isinstance(inv, dict) or not isinstance(inv.get("checks"), dict):
        return "unknown", []
    exposed = []
    findings = inv.get("findings")
    for f in findings if isinstance(findings, list) else []:
        if not isinstance(f, dict):
            continue
        name = f.get("check")
        name = name[len("inventory."):] if isinstance(name, str) and name.startswith("inventory.") else name
        if name in EXPOSURE_CHECKS and str(f.get("sev", f.get("severity", ""))).upper() in ("HIGH", "CRITICAL") \
                and name not in exposed:
            exposed.append(name)
    if exposed:
        return "exposed", exposed
    unknown = []
    for name in EXPOSURE_CHECKS:
        check = inv["checks"].get(name)
        if isinstance(check, dict) and check.get("status") == "unknown":
            unknown.append(name)
    return ("unknown", unknown) if unknown else ("ok", [])


LATE_MS, SILENT_MS = 4 * 60 * 1000, 5 * 60 * 1000


def is_late(state, last_seen, maintenance_until, now):
    """No heartbeat for 4 to 5 minutes, outside an operator's window: "late" (PLAN section 4; HIGH comes at 5)."""
    if state not in ("active", "pending") or maintenance_until or not last_seen:
        return False
    return LATE_MS <= now - int(last_seen) < SILENT_MS


def api_fleet(app, conn, query, session):
    now = hub_common.now_ms()
    incidents = dict(conn.execute("SELECT host, COUNT(*) FROM incidents WHERE state!='resolved' GROUP BY host").fetchall())
    rows = conn.execute(
        "SELECT h.*, hb.received_at AS hb_at, hb.body AS hb_body, i.body AS inv_body, m.until AS m_until, m.set_by AS m_by "
        "FROM hosts h LEFT JOIN heartbeats hb ON hb.host=h.uuid LEFT JOIN inventory i ON i.host=h.uuid "
        "LEFT JOIN maintenance m ON m.host=h.uuid AND m.until>? WHERE h.state!='retired' ORDER BY h.name", (now,)).fetchall()
    hosts = []
    for r in rows:
        hb = jl(r["hb_body"], {}) if r["hb_body"] else {}
        inv = jl(r["inv_body"], None) if r["inv_body"] else None
        exposure, exposure_checks = exposure_state(inv)
        hosts.append({
            "uuid": r["uuid"], "name": r["name"], "state": r["state"], "state_since": r["state_since"],
            "reported_name": cut(r["reported_name"], 200), "os": cut(r["os"], 200),
            "peer_ips": jl(r["peer_ips"], []), "last_seen": r["last_seen"],
            "agent_version": cut(r["agent_version"] or "", 40), "schema": r["schema"], "kernel": cut(r["kernel"] or "", 100),
            "cert_not_after": r["cert_not_after"], "policy_rev": r["policy_rev"], "policy_rev_applied": r["policy_rev_applied"],
            "open_incidents": incidents.get(r["uuid"], 0),
            "maintenance_until": r["m_until"], "maintenance_by": cut(r["m_by"] or "", 200) if r["m_until"] else None,
            "late": is_late(r["state"], r["last_seen"], r["m_until"], now),
            "health": _host_health(hb), "exposure": exposure, "exposure_checks": exposure_checks,
        })
    return {"hosts": hosts}


def _since_ms(text):
    try:
        return hub_common.now_ms() - hub_common.parse_duration(text) * 1000
    except ValueError:
        raise ApiError(400, "bad since")


def _int_arg(query, key, default=None, lo=0, hi=2 ** 62):
    raw = query.get(key, [None])[0]
    if raw is None or raw == "":
        return default
    if not (raw.isdigit() and raw.isascii()) or not lo <= int(raw) <= hi:
        raise ApiError(400, "bad " + key)
    return int(raw)


def api_events(app, conn, query, session):
    where, params = [], []
    host = query.get("host", [""])[0]
    if host:
        if not REF_RE.match(host):
            raise ApiError(400, "bad host")
        where.append("(h.name=? OR e.host=?)")
        params += [host, host]
    source = query.get("source", [""])[0]
    if source:
        if source not in hub_common.SOURCES:
            raise ApiError(400, "bad source")
        where.append("e.source=?")
        params.append(source)
    kind = query.get("kind", [""])[0]
    if kind:
        if not KIND_FILTER_RE.match(kind):
            raise ApiError(400, "bad kind")
        if kind.endswith("*"):
            where.append("e.kind LIKE ? ESCAPE '\\'")
            params.append(kind[:-1].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        else:
            where.append("e.kind=?")
            params.append(kind)
    min_sev = query.get("min_sev", [""])[0].upper()
    if min_sev:
        if min_sev not in hub_common.SEVERITIES:
            raise ApiError(400, "bad min_sev")
        allowed = hub_common.SEVERITIES[hub_common.sev_rank(min_sev):]
        where.append("e.hub_severity IN (%s)" % ",".join("?" * len(allowed)))
        params += allowed
    since = query.get("since", [""])[0]
    if since:
        where.append("e.received_at>=?")
        params.append(_since_ms(since))
    before = _int_arg(query, "before_id")
    if before:
        where.append("e.id<?")
        params.append(before)
    limit = _int_arg(query, "limit", 100, 1, LIST_MAX)
    rows = conn.execute(EVENT_SELECT + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY e.id DESC LIMIT ?",
                        params + [limit]).fetchall()
    return {"events": [event_row(r) for r in rows],
            "head_event_id": conn.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0]}


def api_event(app, conn, query, session, event_id):
    r = conn.execute("SELECT e.*, h.name AS host_name FROM events e LEFT JOIN hosts h ON h.uuid=e.host WHERE e.id=?",
                     (event_id,)).fetchone()
    if r is None:
        raise ApiError(404)
    d = {k: r[k] for k in r.keys()}
    d["details"] = jl(d.get("details"), {})
    d["describe"] = describe(d["kind"])
    return {"event": d}


def api_describe(app, conn, query, session):
    kind = query.get("kind", [""])[0]
    if not hub_common.KIND_RE.match(kind):
        raise ApiError(400, "bad kind")
    return describe(kind)


def api_incidents(app, conn, query, session):
    state = query.get("state", ["all"])[0]
    if state not in ("all", "open"):
        raise ApiError(400, "bad state")
    rows = conn.execute("SELECT i.*, h.name AS host_name FROM incidents i LEFT JOIN hosts h ON h.uuid=i.host"
                        + (" WHERE i.state!='resolved'" if state == "open" else "")
                        + " ORDER BY i.updated DESC LIMIT 200").fetchall()
    out = []
    for r in rows:
        d = {k: r[k] for k in r.keys()}
        d["kinds"] = jl(d["kinds"], [])
        out.append(d)
    return {"incidents": out}


def api_incident(app, conn, query, session, incident_id):
    r = conn.execute("SELECT i.*, h.name AS host_name FROM incidents i LEFT JOIN hosts h ON h.uuid=i.host WHERE i.id=?",
                     (incident_id,)).fetchone()
    if r is None:
        raise ApiError(404)
    d = {k: r[k] for k in r.keys()}
    d["kinds"] = jl(d["kinds"], [])
    rows = conn.execute(EVENT_SELECT + " JOIN incident_events ie ON ie.event_rowid=e.id WHERE ie.incident_id=? "
                        "ORDER BY e.id LIMIT 500", (incident_id,)).fetchall()
    d["events"] = [event_row(x) for x in rows]
    d["describe"] = {k: describe(k) for k in d["kinds"][:20] if isinstance(k, str)}
    return {"incident": d}


def api_host(app, conn, query, session, ref):
    r = conn.execute("SELECT * FROM hosts WHERE uuid=? OR name=? ORDER BY uuid=? DESC LIMIT 1", (ref, ref, ref)).fetchone()
    if r is None:
        raise ApiError(404)
    uuid = r["uuid"]
    host = {k: r[k] for k in r.keys() if k not in ("cert_sha256", "pending_cert_sha256")}
    host["ips"] = jl(host["ips"], [])
    host["peer_ips"] = jl(host["peer_ips"], [])
    hb = conn.execute("SELECT received_at, peer_ip, body FROM heartbeats WHERE host=?", (uuid,)).fetchone()
    inv = conn.execute("SELECT received_at, body FROM inventory WHERE host=?", (uuid,)).fetchone()
    hb_body = jl(hb["body"], {}) if hb else {}
    inv_body = jl(inv["body"], {}) if inv else {}
    m = conn.execute("SELECT until, set_by FROM maintenance WHERE host=? AND until>?", (uuid, hub_common.now_ms())).fetchone()
    events = conn.execute(EVENT_SELECT + " WHERE e.host=? ORDER BY e.id DESC LIMIT 100", (uuid,)).fetchall()
    incidents = conn.execute("SELECT id, state, severity, title, opened, updated, signals FROM incidents WHERE host=? "
                             "ORDER BY updated DESC LIMIT 50", (uuid,)).fetchall()
    bans = conn.execute("SELECT COUNT(*) FROM events WHERE host=? AND kind='ban.local'", (uuid,)).fetchone()[0]
    return {
        "host": host,
        "heartbeat_at": hb["received_at"] if hb else None,
        "health": _host_health(hb_body),
        "inventory": _small(inv_body, 16 * 1024) or {},
        "inventory_at": inv["received_at"] if inv else None,
        "exposure": _inventory_issues(inv_body),
        "maintenance": {"until": m["until"], "set_by": cut(m["set_by"], 200)} if m else None,
        "ban_counts": _small(hb_body.get("ban_counts")) if isinstance(hb_body, dict) else None,
        "ban_local_events": bans,
        "events": [event_row(x) for x in events],
        "incidents": [{k: x[k] for k in x.keys()} for x in incidents],
    }


def api_tokens(app, conn, query, session):
    now = hub_common.now_ms()
    rows = conn.execute("SELECT t.id, t.name, t.bound_host, t.source_cidr, t.created_at, t.expires_at, t.used_at, t.revoked_at, "
                        "h.name AS host_name FROM tokens t LEFT JOIN hosts h ON h.uuid=t.bound_host "
                        "ORDER BY t.created_at DESC LIMIT 200").fetchall()
    tokens = []
    for r in rows:
        state = "used" if r["used_at"] else "revoked" if r["revoked_at"] else "expired" if r["expires_at"] <= now else "pending"
        tokens.append({"id": r["id"], "name": r["name"], "for_host": r["host_name"] or r["bound_host"],
                       "source_cidr": r["source_cidr"], "expires_at": r["expires_at"], "state": state})
    return {"tokens": tokens, "command": ENROLL_COMMAND}


def api_audit(app, conn, query, session):
    before = _int_arg(query, "before_id")
    limit = _int_arg(query, "limit", 100, 1, LIST_MAX)
    rows = conn.execute("SELECT id, ts, actor_kind, actor_detail, action, target, outcome, details FROM audit "
                        + ("WHERE id<? " if before else "") + "ORDER BY id DESC LIMIT ?",
                        ([before] if before else []) + [limit]).fetchall()
    out = []
    for r in rows:
        d = {k: cut(r[k], 512) for k in r.keys() if k != "details"}
        d["details"] = _small(jl(r["details"], {}), 4096) or {}
        out.append(d)
    return {"audit": out}


def api_settings(app, conn, query, session):
    settings = hub_common.load_settings(app.paths)
    plain = {k: settings.get(k, hub_common.PLAIN_SETTINGS[k][0]) for k in sorted(hub_common.PLAIN_SETTINGS)}
    installer = {k: settings.get(k, hub_common.INSTALLER_SETTINGS[k]) for k in sorted(hub_common.INSTALLER_SETTINGS)}
    have = settings.get("secrets_set") or {}
    secrets_view = {k: (cut(str(have.get(k)), 80) if have.get(k) else "") for k in hub_common.SECRET_SETTINGS}
    never = [{k: cut(r[k], 200) for k in r.keys()} for r in conn.execute(
        "SELECT cidr, reason, added_by, ts FROM never_ban ORDER BY cidr LIMIT 500")]
    history = [{k: cut(r[k], 200) for k in r.keys()} for r in conn.execute(
        "SELECT ts, key, old, new, actor FROM settings_history ORDER BY id DESC LIMIT 50")]
    return {"plain": plain, "installer": installer, "secrets": secrets_view, "never_ban": never, "history": history}


GET_ROUTES = {
    "/api/status": api_status, "/api/fleet": api_fleet, "/api/events": api_events, "/api/describe": api_describe,
    "/api/incidents": api_incidents, "/api/tokens": api_tokens, "/api/audit": api_audit, "/api/settings": api_settings,
}
GET_PREFIX_ROUTES = (
    ("/api/event/", re.compile(r"^\d{1,18}\Z"), api_event, int),
    ("/api/incident/", re.compile(r"^\d{1,18}\Z"), api_incident, int),
    ("/api/host/", REF_RE, api_host, str),
)


# ---- HTTP -------------------------------------------------------------------------------------------
class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    allow_reuse_address = True

    def __init__(self, addr, handler, app):
        self.app = app
        self.slots = threading.BoundedSemaphore(CONNECTIONS_MAX)
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            socketserver.TCPServer.shutdown_request(self, request)     # over the cap: close at once
            return
        super().process_request(request, client_address)

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    timeout = HANDLER_DEADLINE_S
    server_version = "edr-hub-ui"
    sys_version = ""

    # -- plumbing
    def log_message(self, *args):
        pass                                           # nothing from the request reaches a log

    @property
    def app(self):
        return self.server.app

    def handle(self):
        # A wall-clock deadline: one byte a second must not keep a handler for ever.
        self._deadline = threading.Timer(HANDLER_DEADLINE_S, self._cut)
        self._deadline.daemon = True
        self._deadline.start()
        try:
            super().handle()
        finally:
            self._deadline.cancel()

    def _cut(self):
        try:
            socket.socket.shutdown(self.request, socket.SHUT_RDWR)
        except OSError:
            pass

    def end_headers(self):
        self.send_header("Content-Security-Policy", self.app.csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", PERMISSIONS_POLICY)
        super().end_headers()

    def send_error(self, code, message=None, explain=None):
        """Every error is fixed JSON: no request text ever comes back."""
        self.send_json(code, {"error": HTTP_TEXT.get(code, "error")})

    def send_json(self, code, obj, headers=None):
        body = dumps(obj).encode("ascii")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def fail(self, status, text=None):
        self.send_json(status, {"error": text or HTTP_TEXT.get(status, "error")})

    # -- checks shared by every request
    def check_host(self):
        host = self.headers.get("Host", "")
        if host not in self.app.allowed_hosts():
            self.fail(403)
            return False
        return True

    def check_post_origin(self):
        origin = self.headers.get("Origin", "")
        if not origin.startswith("http://") or origin[7:] not in self.app.allowed_hosts():
            self.fail(403)
            return False
        if self.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
            self.fail(403)
            return False
        return True

    def bearer(self):
        """The live session's digest, or None (the 401 has been sent)."""
        header = self.headers.get("Authorization", "")
        token = header[7:] if header.startswith("Bearer ") else ""
        if not TOKEN_RE.match(token):
            self.fail(401)
            return None
        digest = self.app.sessions.check(token)
        if digest is None:
            self.fail(401)
        return digest

    def read_body(self):
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            self.fail(415)
            return None
        length = self.headers.get("Content-Length")
        if length is None:
            self.fail(411)
            return None
        if not (length.isdigit() and length.isascii()):
            self.fail(400)
            return None
        if int(length) > BODY_MAX:
            self.fail(413)
            return None
        try:
            body = json.loads(self.rfile.read(int(length)).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError, OSError):
            self.fail(400)
            return None
        if not isinstance(body, dict):
            self.fail(400)
            return None
        return body

    # -- methods
    def do_GET(self):
        if not self.check_host():
            return
        if self.headers.get("Content-Length", "0") not in ("", "0") or self.headers.get("Transfer-Encoding"):
            return self.fail(400)
        url = urlsplit(self.path)
        path = url.path
        if path in ("/", "/index.html"):
            return self.send_page()
        if not path.startswith("/api/"):
            return self.fail(404)
        digest = self.bearer()
        if digest is None:
            return
        query = parse_qs(url.query, keep_blank_values=True, max_num_fields=20)
        try:
            if path == "/api/stream":
                return self.stream(digest)
            handler, args = GET_ROUTES.get(path), ()
            if handler is None:
                for prefix, shape, func, conv in GET_PREFIX_ROUTES:
                    if path.startswith(prefix):
                        ref = unquote(path[len(prefix):])
                        if not shape.match(ref):
                            return self.fail(404)
                        handler, args = func, (conv(ref),)
                        break
            if handler is None:
                return self.fail(404)
            with self.app.db() as conn:
                result = handler(self.app, conn, query, digest, *args)
            self.send_json(200, result)
        except ApiError as exc:
            self.fail(exc.status, exc.text)
        except HubDown:
            self.fail(503)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass
        except Exception as exc:                        # noqa: BLE001
            self.app.log("ERROR", "request failed: %s" % type(exc).__name__)
            self.fail(500)

    def do_POST(self):
        if not self.check_host() or not self.check_post_origin():
            return
        path = urlsplit(self.path).path
        try:
            if path == "/api/login":
                body = self.read_body()
                if body is not None:
                    self.login(body)
                return
            if path not in ("/api/logout", "/api/host/mark-moved", "/api/host/maintenance"):
                return self.fail(404)
            digest = self.bearer()
            if digest is None:
                return
            body = self.read_body()
            if body is None:
                return
            if path == "/api/logout":
                self.app.sessions.drop(digest)
                return self.send_json(200, {"ok": True})
            self.write_verb(path, body, digest)
        except ApiError as exc:
            self.fail(exc.status, exc.text)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass
        except Exception as exc:                        # noqa: BLE001
            self.app.log("ERROR", "request failed: %s" % type(exc).__name__)
            self.fail(500)

    def method_not_allowed(self):
        if self.check_host():
            self.fail(405)

    do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = method_not_allowed

    # -- pages
    def send_page(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(self.app.page)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(self.app.page)

    # -- login and logout
    def peer_addr(self):
        try:
            return hub_common.norm_ip(self.client_address[0])
        except ValueError:
            return "unknown"

    def login(self, body):
        app = self.app
        code = body.get("code")
        if not isinstance(code, str) or not 0 < len(code) <= 128:
            return self.fail(400)
        if app.login_failures() >= FAILED_LOGINS_PER_MINUTE:
            return self.fail(429)
        token = secrets.token_urlsafe(32)                # 256 bits
        digest = Sessions.digest(token)
        reply = app.hub_call("login.redeem", {"code": code}, {"session": digest[:8], "addr": self.peer_addr()})
        if not reply.get("ok"):
            app.note_login_failure()
            app.log("WARN", "failed dashboard login from %s" % self.peer_addr())
            return self.fail(401, "login refused")
        app.sessions.create(token)
        self.send_json(200, {"token": token, "idle_s": SESSION_IDLE_S, "absolute_s": SESSION_ABSOLUTE_S})

    # -- writes: only the whitelisted verbs, over ui.sock
    def write_verb(self, path, body, digest):
        host = body.get("host")
        if not isinstance(host, str) or not REF_RE.match(host):
            return self.fail(400, "bad host")
        if path == "/api/host/mark-moved":
            cmd, args = "host.mark-moved", {"host": host}
        elif body.get("end") is True:
            cmd, args = "host.maintenance", {"host": host, "end": True}
        else:
            dur = body.get("for")
            if not isinstance(dur, str) or not DURATION_RE.match(dur):
                return self.fail(400, "bad duration")
            cmd, args = "host.maintenance", {"host": host, "for": dur}
        reply = self.app.hub_call(cmd, args, {"session": digest[:8], "addr": self.peer_addr()})
        if reply.get("ok"):
            return self.send_json(200, {"ok": True, "result": reply.get("result")})
        status = {"invalid": 400, "denied": 403, "refused": 409}.get(reply.get("code"), 502)
        self.send_json(status, {"error": clean(str(reply.get("error", "refused")), 120)})

    # -- the live feed
    def stream(self, digest):
        app = self.app
        client = app.feed.register(digest)
        if client is None:
            return self.fail(429)
        try:
            last = self.headers.get("Last-Event-ID", "")
            sent = int(last) if last.isdigit() and last.isascii() and len(last) < 19 else None
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self._deadline.cancel()
            self.request.settimeout(STREAM_WRITE_TIMEOUT_S)
            if sent is None:
                sent = app.feed.head()
            else:
                with app.db() as conn:
                    rows = conn.execute(EVENT_SELECT + " WHERE e.id > ? ORDER BY e.id LIMIT ?", (sent, REPLAY_MAX)).fetchall()
                for r in rows:
                    self.frame(r["id"], "event", event_row(r))
                    sent = r["id"]
            self.wfile.flush()
            started = last_ping = time.monotonic()
            while not app.stopping.is_set():
                try:
                    item = client.q.get(timeout=1)
                except queue.Empty:
                    item = None
                if client.dropped:
                    self.frame(None, "reset", {})
                    return
                if self.peer_closed():
                    return
                now = time.monotonic()
                if item is not None and item["id"] > sent:
                    self.frame(item["id"], "event", item)
                    sent = item["id"]
                if now - last_ping >= STREAM_PING_S:
                    if app.sessions.check_digest(digest, touch=False) is None:
                        self.frame(None, "end", {"reason": "session"})
                        return
                    self.frame(None, "ping", {"hub_down": app.feed.hub_down})
                    last_ping = now
                if now - started >= STREAM_MAX_S:
                    self.frame(None, "end", {"reason": "time"})
                    return
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, socket.timeout, OSError, HubDown):
            pass
        finally:
            app.feed.unregister(client)
            self.close_connection = True

    def peer_closed(self):
        """True when the browser went away: the slot is freed without waiting for the next write to fail."""
        try:
            readable, _, _ = select.select([self.request], [], [], 0)
            return bool(readable) and self.request.recv(1, socket.MSG_PEEK) == b""
        except (OSError, ValueError):
            return True

    def frame(self, event_id, name, data):
        text = "%sevent: %s\ndata: %s\n\n" % ("id: %d\n" % event_id if event_id is not None else "", name,
                                              dumps(data))
        self.wfile.write(text.encode("ascii"))
        self.wfile.flush()


# ---- running ----------------------------------------------------------------------------------------
class UiServer:
    """The dashboard as an object, for tests and for main()."""

    def __init__(self, paths, port=0, clock=time.monotonic):
        self.paths = paths
        self.app = App(paths, port, clock)
        self.httpd = Server(("127.0.0.1", port), Handler, self.app)
        self.port = self.httpd.server_address[1]
        self.app.port = self.port
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05},
                                       name="ui-http", daemon=True)

    def start(self):
        self.app.feed.start()
        self.thread.start()
        return self

    def stop(self):
        self.app.stopping.set()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(5)
        self.app.feed.thread.join(3)


def main(argv=None):
    p = argparse.ArgumentParser(description="edr-hub dashboard (loopback only)")
    p.add_argument("--port", type=int, help="default: ui_port from settings.json (8450)")
    p.add_argument("--state-dir")
    p.add_argument("--run-dir")
    p.add_argument("--etc-dir")
    args = p.parse_args(argv)
    paths = hub_common.Paths(state_dir=args.state_dir, run_dir=args.run_dir, etc_dir=args.etc_dir)
    port = args.port if args.port is not None else int(hub_common.load_settings(paths).get("ui_port", 8450))
    server = UiServer(paths, port)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    server.start()
    server.app.log("INFO", "dashboard on 127.0.0.1:%d, state %s" % (server.port, paths.state_dir))
    stop.wait()
    server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
