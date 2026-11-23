"""Alerts: payloads, dedup and storm control, outbox rows, and the per-channel request (PLAN.md section 4,
Alert delivery).

Everything here runs inside the writer's transaction (`notify` takes the writer's `conn`).
Delivery is edr_hub_out.py's job: it takes outbox rows over out.sock and uses `render()`.
Standard library only.
"""

import json
import re

import hub_common
import hub_rules
from hub_common import SEVERITIES, clean, now_ms, sev_rank, enabled_channels, ms_to_rfc3339

DEDUP_WINDOW_MS = 30 * 60 * 1000          # per (host, kind)
CRITICAL_WINDOW_MS = 5 * 60 * 1000        # CRITICAL: at most one per (host, kind) per 5 minutes
STORM_WINDOW_MS = 10 * 60 * 1000
STORM_MAX = 20
CRIT_CAP = 10                              # CRITICAL pages per host per window; one host cannot page without limit
CRIT_CAP_WINDOW_MS = 30 * 60 * 1000
FIELD_MAX = 200
FIELDS_MAX = 14
COMMANDS_MAX = 4
MESSAGE_MAX = 3500                         # ntfy refuses a message over 4096 bytes
CHANNEL_ORDER = ("webhook", "ntfy")        # the channels P2 can render (Discord and e-mail are P3)

# A token has the form id.secret.ca_sha256; it must never appear in a message
_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{16,}\.[0-9a-fA-F]{64}\b")
_URL_RE = re.compile(r"https?://[^\s`]+")


def _g(row, key, default=None):
    try:
        v = row[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if v is None else v


def scrub(text):
    """Remove bearer secrets from text: a token, and the path and query of any URL (they may hold a webhook secret)."""
    text = _TOKEN_RE.sub("[token removed]", str(text))
    return _URL_RE.sub(lambda m: re.sub(r"^(https?://[^/?#]+).*$", r"\1/...", m.group(0)), text)


def _safe(value, limit=FIELD_MAX):
    return clean(scrub(value), limit)


def _first_ip(host_row):
    for key in ("peer_ips", "ips"):
        try:
            items = json.loads(_g(host_row, key, "[]") or "[]")
        except (TypeError, ValueError):
            continue
        if isinstance(items, list) and items and isinstance(items[0], str):
            return _safe(items[0], 64)
    return ""


# ---- alert_state -----------------------------------------------------------------------------
def query(conn, sql, args=()):
    """Rows as dicts, whatever row_factory the connection has."""
    cur = conn.execute(sql, args)
    cols = [c[0] for c in cur.description or ()]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def query1(conn, sql, args=()):
    rows = query(conn, sql, args)
    return rows[0] if rows else None


def state_get(conn, key):
    """The alert_state row as a dict, or None."""
    return query1(conn, "SELECT key, severity, first, last, count, suppressed, data FROM alert_state WHERE key=?", (key,))


def state_put(conn, key, *, severity="", first=None, last=None, count=0, suppressed=0, data=None):
    conn.execute(
        "INSERT INTO alert_state (key, severity, first, last, count, suppressed, data) VALUES (?,?,?,?,?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET severity=excluded.severity, first=excluded.first, last=excluded.last, "
        "count=excluded.count, suppressed=excluded.suppressed, data=excluded.data",
        (key, severity, first if first is not None else last, last, count, suppressed, json.dumps(data or {})))


# ---- Building a payload ----------------------------------------------------------------------
def _maintenance_line(conn, host_row, now):
    """One line for a window an operator set on the hub; None for none (a host's own window is never shown)."""
    uuid = _g(host_row, "uuid")
    if not uuid:
        return None
    row = conn.execute("SELECT until, set_by FROM maintenance WHERE host=?", (uuid,)).fetchone()
    if not row or row[0] <= now:
        return None
    return "set on the hub by %s until %s" % (_safe(row[1], 64), ms_to_rfc3339(row[0]))


LINES_MAX = 40


def build_payload(conn, *, severity, kind, summary, host=None, fields=None, incident_id=None, now=None,
                  test=False, meaning=None, next_step=None, lines=None):
    now = now_ms() if now is None else now
    info = hub_rules.describe(kind)
    name = _safe(_g(host, "name", ""), 64) if host is not None else ""
    commands = []
    if incident_id:
        commands += ["edr-hub incident %d" % int(incident_id), "edr-hub resolve %d" % int(incident_id)]
    if name:
        commands.append("edr-hub events --host %s --since 1h" % name)
    clean_fields = {}
    for k, v in list((fields or {}).items())[:FIELDS_MAX]:
        clean_fields[_safe(k, 40)] = _safe(v)
    if host is not None and conn is not None:
        line = _maintenance_line(conn, host, now)
        if line:
            clean_fields["maintenance window"] = line
    payload = {
        "title": _safe(summary),
        "severity": severity if severity in SEVERITIES else "HIGH",
        "host": name,
        "host_ip": _first_ip(host) if host is not None else "",
        "kind": _safe(kind, 64),
        "meaning": _safe(meaning if meaning is not None else info["meaning"], 600),
        "next_step": _safe(next_step if next_step is not None else info["next_step"], 400),
        "incident_id": int(incident_id) if incident_id else None,
        "commands": commands[:COMMANDS_MAX],
        "fields": clean_fields,
        "ts": now,
        "test": bool(test),
    }
    if lines:
        payload["lines"] = [_safe(x) for x in list(lines)[:LINES_MAX]]
    return payload


# ---- Outbox ----------------------------------------------------------------------------------
def _write_outbox(conn, hub, payload, severity, dedup_key, now):
    """One row per enabled channel, or one dead row with channel 'none'. Returns the new ids."""
    channels = [c for c in enabled_channels(hub.settings) if c in CHANNEL_ORDER] or ["none"]
    text = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    ids = []
    for ch in channels:
        dead = ch == "none"
        cur = conn.execute(
            "INSERT INTO outbox (created, channel, severity, payload, dedup_key, attempts, next_try, state, last_error) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (now, ch, severity, text, dedup_key, 0, now, "dead" if dead else "pending",
             "no alert channel is configured" if dead else ""))
        ids.append(cur.lastrowid)
    return ids


def _storm_data(conn, now):
    row = state_get(conn, "storm")
    try:
        data = json.loads(row["data"]) if row else {}
    except ValueError:
        data = {}
    sent = [t for t in data.get("sent", []) if now - t < STORM_WINDOW_MS]
    return {"sent": sent, "suppressed": int(data.get("suppressed", 0)), "max_sev": data.get("max_sev", "HIGH"),
            "first": data.get("first")}


def _storm_save(conn, data, now):
    state_put(conn, "storm", severity=data["max_sev"], first=data.get("first") or now, last=now,
              count=len(data["sent"]), suppressed=data["suppressed"], data=data)


def flush_storm(conn, hub, now=None):
    """Send the one 'N alerts suppressed' summary once the storm window has room again. Returns rows written."""
    now = now_ms() if now is None else now
    data = _storm_data(conn, now)
    if not data["suppressed"] or len(data["sent"]) >= STORM_MAX:
        return 0
    n = data["suppressed"]
    payload = build_payload(conn, severity="HIGH", kind="hub.storm", now=now,
                            summary="%d alerts suppressed by storm control" % n,
                            fields={"suppressed": str(n), "limit": "%d messages per 10 minutes" % STORM_MAX})
    ids = _write_outbox(conn, hub, payload, "HIGH", "storm", now)
    data.update(suppressed=0, first=None, max_sev="HIGH")
    data["sent"].append(now)
    _storm_save(conn, data, now)
    return len(ids)


def _crit_state(conn, uuid, now):
    row = state_get(conn, "crit|" + uuid)
    data = _load(row["data"]) if row else {}
    sent = [t for t in data.get("sent", []) if isinstance(t, int) and now - t < CRIT_CAP_WINDOW_MS]
    return row, {"sent": sent, "suppressed": int(data.get("suppressed") or 0), "summary_at": int(data.get("summary_at") or 0),
                 "name": str(data.get("name") or "")}


def _crit_save(conn, uuid, row, d, now):
    state_put(conn, "crit|" + uuid, severity="CRITICAL", first=row["first"] if row else now, last=now, count=len(d["sent"]),
              suppressed=d["suppressed"], data={"sent": d["sent"], "suppressed": d["suppressed"], "summary_at": d["summary_at"],
                                                "name": d["name"]})


def _crit_allow(conn, host, now):
    """Count one CRITICAL page of a host; False when the host has used its 10 pages in 30 minutes."""
    uuid = _g(host, "uuid")
    if not uuid:
        return True
    row, d = _crit_state(conn, uuid, now)
    d["name"] = _safe(_g(host, "name", ""), 64)
    if len(d["sent"]) >= CRIT_CAP:
        d["suppressed"] += 1
        _crit_save(conn, uuid, row, d, now)
        return False
    d["sent"].append(now)
    _crit_save(conn, uuid, row, d, now)
    return True


def flush_host_caps(conn, hub, now=None):
    """One '<N> more CRITICAL alerts from this host suppressed' summary per host and 30 minutes. Returns rows written."""
    now = now_ms() if now is None else now
    written = 0
    for r in query(conn, "SELECT key FROM alert_state WHERE key LIKE 'crit|%' AND suppressed>0"):
        uuid = r["key"][5:]
        row, d = _crit_state(conn, uuid, now)
        if not d["suppressed"] or now - d["summary_at"] < CRIT_CAP_WINDOW_MS:
            continue
        n = d["suppressed"]
        payload = build_payload(conn, severity="HIGH", kind="hub.crit_cap", now=now, host={"name": d["name"], "uuid": uuid},
                                summary="%d more CRITICAL alerts from this host suppressed" % n,
                                fields={"suppressed": str(n), "cap": "%d per 30 minutes per host" % CRIT_CAP})
        written += len(_write_outbox(conn, hub, payload, "HIGH", "critcap|" + uuid, now))
        d["suppressed"], d["summary_at"] = 0, now
        _crit_save(conn, uuid, row, d, now)
    return written


def notify(conn, hub, *, severity, kind, summary, host=None, fields=None, incident_id=None,
           always=False, dedup_key=None, now=None, meaning=None, next_step=None, lines=None):
    """Queue one alert. Returns the number of outbox rows written (0 when it was dropped).

    Order of the checks: the minimum severity (settings alert_min_severity), per (host, kind) dedup
    (30 minutes; CRITICAL 5 minutes; a higher severity always passes), storm control (20 per
    10 minutes; CRITICAL and `always` are exempt), and for CRITICAL a cap of 10 pages per host in 30 minutes (the rest
    become one summary per host and 30 minutes). `always=True` is for admin actions: it skips the minimum severity,
    dedup, the cap and storm control.
    """
    now = now_ms() if now is None else now
    if severity not in SEVERITIES:
        severity = "HIGH"
    if not always and sev_rank(severity) < sev_rank(hub.settings.get("alert_min_severity", "HIGH")):
        return 0
    if not always and severity == "INFO":
        return 0
    flushed = flush_storm(conn, hub, now) + flush_host_caps(conn, hub, now)

    # A kind the rules table does not name exactly shares one dedup key (see hub_rules.dedup_kind): a client picks kinds
    key = dedup_key or "%s|%s" % (_g(host, "uuid", "-") if host is not None else "-", hub_rules.dedup_kind(kind))
    row = state_get(conn, key)
    if not always and row is not None:
        window = CRITICAL_WINDOW_MS if severity == "CRITICAL" else DEDUP_WINDOW_MS
        if now - row["last"] < window and sev_rank(severity) <= sev_rank(row["severity"]):
            state_put(conn, key, severity=row["severity"], first=row["first"], last=row["last"],
                      count=row["count"] + 1, suppressed=row["suppressed"] + 1, data=_load(row["data"]))
            return flushed
    if not always and severity == "CRITICAL" and host is not None and not _crit_allow(conn, host, now):
        return flushed
    if not always and severity != "CRITICAL":
        storm = _storm_data(conn, now)
        if len(storm["sent"]) >= STORM_MAX:
            storm["suppressed"] += 1
            storm["first"] = storm.get("first") or now
            if sev_rank(severity) > sev_rank(storm["max_sev"]):
                storm["max_sev"] = severity
            _storm_save(conn, storm, now)
            return flushed

    payload = build_payload(conn, severity=severity, kind=kind, summary=summary, host=host, fields=fields,
                            incident_id=incident_id, now=now, meaning=meaning, next_step=next_step, lines=lines)
    ids = _write_outbox(conn, hub, payload, severity, key, now)
    state_put(conn, key, severity=severity, first=row["first"] if row is not None and now - row["last"] < DEDUP_WINDOW_MS else now,
              last=now, count=(row["count"] if row is not None else 0) + 1,
              suppressed=row["suppressed"] if row is not None else 0, data=_load(row["data"]) if row is not None else {})
    if not always and severity != "CRITICAL":
        storm = _storm_data(conn, now)
        storm["sent"].append(now)
        _storm_save(conn, storm, now)
    return len(ids) + flushed


def _load(text):
    try:
        v = json.loads(text)
        return v if isinstance(v, dict) else {}
    except (TypeError, ValueError):
        return {}


def admin_notice(conn, hub, action, detail, actor, now=None):
    """An admin action: always HIGH, always sent. The text never holds a token secret (it is scrubbed)."""
    return notify(conn, hub, severity="HIGH", always=True, kind="hub.admin", now=now,
                  summary="%s: %s" % (_safe(action, 60), _safe(detail, 140)),
                  fields={"by": _safe(actor, 80) or "unknown"})


def enqueue_test(conn, hub, channel=None, now=None):
    """Outbox rows for `edr-hub alert test`. channel None means every enabled channel.

    Raises ValueError for an unknown channel or one that is not enabled. With no channel enabled
    and none named, one dead 'none' row is written, so the result still shows.
    """
    now = now_ms() if now is None else now
    enabled = [c for c in enabled_channels(hub.settings) if c in CHANNEL_ORDER]
    if channel is not None:
        if channel not in hub_common.CHANNELS:
            raise ValueError("unknown channel")
        if channel not in enabled:
            raise ValueError("channel is not enabled")
        targets = [channel]
    else:
        targets = enabled or ["none"]
    payload = build_payload(conn, severity="INFO", kind="hub.test", summary="Test alert from edr-hub alert test",
                            now=now, test=True)
    text = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    ids = []
    for ch in targets:
        dead = ch == "none"
        cur = conn.execute(
            "INSERT INTO outbox (created, channel, severity, payload, dedup_key, attempts, next_try, state, last_error) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (now, ch, "INFO", text, "test", 0, now, "dead" if dead else "pending",
             "no alert channel is configured" if dead else ""))
        ids.append(cur.lastrowid)
    return ids


def channel_health(conn, now=None):
    """Per channel with rows: whether it is failing (a result of failed or dead since its last 'sent').

    Returns [{"channel", "failing", "since", "bad_rows", "last_error", "over_1h"}] for the dashboard
    and `edr-hub status`; the webhook cannot report its own failure (PLAN section 4).
    """
    now = now_ms() if now is None else now
    out = []
    for (ch,) in conn.execute("SELECT DISTINCT channel FROM outbox WHERE channel != 'none' ORDER BY channel").fetchall():
        last_sent = conn.execute("SELECT COALESCE(MAX(id), 0) FROM outbox WHERE channel=? AND state='sent'", (ch,)).fetchone()[0]
        bad, since = conn.execute(
            "SELECT COUNT(*), MIN(created) FROM outbox WHERE channel=? AND state IN ('failed','dead') AND attempts>0 AND id>?",
            (ch, last_sent)).fetchone()
        err = conn.execute(
            "SELECT last_error FROM outbox WHERE channel=? AND state IN ('failed','dead') AND attempts>0 AND id>? ORDER BY id DESC LIMIT 1",
            (ch, last_sent)).fetchone()
        out.append({"channel": ch, "failing": bad > 0, "since": since, "bad_rows": bad,
                    "last_error": clean(err[0]) if err else "",
                    "over_1h": bool(bad and since is not None and now - since > 3600 * 1000)})
    return out


# ---- Per-channel request ---------------------------------------------------------------------
def _span(value):
    """An attacker-influenced value as a code span: sanitised, cut to 200 characters, backticks replaced."""
    return "`" + clean(value, FIELD_MAX).replace("`", "'") + "`"


def _text(payload, title_marker=""):
    """The message text, shared by the channels. Fixed text is ours; every other value is a code span."""
    p = payload if isinstance(payload, dict) else {}
    sev = p.get("severity") if p.get("severity") in SEVERITIES else "HIGH"
    lines = []
    head = "[%s]%s %s" % (sev, title_marker, _span(p.get("title", "")))
    lines.append(head)
    host = p.get("host")
    if host:
        ip = p.get("host_ip")
        lines.append("Host: %s%s" % (_span(host), (" (%s)" % _span(ip)) if ip else ""))
    if p.get("kind"):
        lines.append("Kind: %s" % _span(p["kind"]))
    if p.get("meaning"):
        lines.append("What: %s" % clean(p["meaning"], 600).replace("`", "'"))
    if p.get("next_step"):
        lines.append("Next: %s" % clean(p["next_step"], 400).replace("`", "'"))
    if p.get("incident_id"):
        lines.append("Incident: %s" % _span(p["incident_id"]))
    fields = p.get("fields")
    if isinstance(fields, dict):
        for k, v in list(fields.items())[:FIELDS_MAX]:
            lines.append("%s: %s" % (clean(k, 40).replace("`", "'"), _span(v)))
    extra = p.get("lines")
    if isinstance(extra, list):
        for x in extra[:LINES_MAX]:
            lines.append(clean(x, FIELD_MAX).replace("`", "'"))
    cmds = p.get("commands")
    if isinstance(cmds, list) and cmds:
        lines.append("Run on the hub:")
        for c in cmds[:COMMANDS_MAX]:
            lines.append("  " + _span(c))
    return "\n".join(lines)


def _slack_escape(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_NTFY_TAGS = {"CRITICAL": ["rotating_light"], "HIGH": ["warning"], "MEDIUM": ["information_source"],
              "LOW": ["memo"], "INFO": ["white_check_mark"]}
_NTFY_PRIORITY = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def render(channel, payload):
    """The HTTP request for one channel: {"url_key", "headers", "body" (bytes)}.

    The URL is not in the result: `url_key` names the secret or option that holds it
    ("webhook_url" in secrets.json, "ntfy_url" in the job options). For ntfy the body is the JSON
    publish without its `topic` (a secret) and the worker adds `topic` and the bearer header.
    Raises ValueError for a channel P2 does not send to.
    """
    p = payload if isinstance(payload, dict) else {}
    marker = " TEST" if p.get("test") else ""
    if channel == "webhook":
        body = {"text": _slack_escape(_text(p, marker)), "unfurl_links": False, "unfurl_media": False}
        return {"url_key": "webhook_url", "headers": {"Content-Type": "application/json"},
                "body": json.dumps(body, ensure_ascii=True).encode("ascii")}
    if channel == "ntfy":
        sev = p.get("severity") if p.get("severity") in SEVERITIES else "HIGH"
        body = {"title": "EDR TEST" if p.get("test") else "EDR %s" % sev,
                "message": _text(p, marker)[:MESSAGE_MAX],
                "priority": _NTFY_PRIORITY[sev], "tags": _NTFY_TAGS[sev]}
        return {"url_key": "ntfy_url", "headers": {"Content-Type": "application/json"},
                "body": json.dumps(body, ensure_ascii=True).encode("ascii")}
    raise ValueError("no renderer for this channel")
