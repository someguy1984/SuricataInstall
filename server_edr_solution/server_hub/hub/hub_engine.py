"""The correlation engine (PLAN.md section 4): incidents, the three NGINX2Root outcomes, heartbeat rules,
agent-silent, hub self-health and the daily digest.

Entry points other code calls (all take the writer's `conn` and run in its transaction):
    after_insert, on_heartbeat, on_enroll, on_rejected      (never raise: a failure here must not lose an event)
and `Engine(hub).start()/.stop()`, a thread that ticks every 10 seconds.

State lives in tables (`meta.engine_cursor`, `incidents`, `incident_events`, `alert_state`), so a restart
loses nothing. Windows are read from stored events each time, so a late batch lands in the right place.
Findings below HIGH that the hub makes itself (a MEDIUM heartbeat rule, an INFO reboot) are kept as
`alert_state` rows whose key starts with "note|" and are listed in the daily digest.

Fleet bans, votes and acknowledgement are P3 and are not here. Standard library only.
"""

import contextlib
import itertools
import json
import math
import os
import shutil
import threading

import hub_advisory
import hub_alerts
import hub_common
import hub_rules
from hub_alerts import notify, query, query1, state_get, state_put
from hub_common import SEVERITIES, clean, ms_to_rfc3339, now_ms, rfc3339_to_ms, sev_rank

TICK_S = 10
MIN = 60 * 1000
HOUR = 60 * MIN
DAY = 24 * HOUR

SILENT_MS = 5 * MIN                   # agent-silent: HIGH
GRACE_MS = 7 * MIN                    # 2 x heartbeat interval + 5 minutes after any start
HUB_DOWN_ALERT_MS = 10 * MIN
EXTEND_MS = 30 * MIN                  # a signal within 30 minutes extends an incident
RESOLVE_MS = 60 * MIN                 # resolved after 60 minutes with no signal
REPLAY_MS = 10 * MIN
SKEW_MS = 5 * MIN
BATCH = 500
BATCHES_PER_TICK = 4

# Chains of PLAN section 4 (kinds are client Appendix B names; "x.*" is a prefix)
FIRST_A = ("nginx.crash", "edr.bigconn", "nginx.marker.window_update")
SECOND_A = ("tetragon.nginx-exec", "tetragon.sctp-socket")
FIRST_B = ("tetragon.fork-watch",)
SECOND_B = ("tetragon.web-exec", "tetragon.web-write-code", "tetragon.web-connect")
FIRST_C = FIRST_A + FIRST_B + SECOND_A         # "those first signals" of the possible-success rule
TAMPER = ("tamper.*",)
SIGKILL_HITS = SECOND_A
ATTACK_RECENT = FIRST_C + SECOND_B + ("tetragon.privilege-escalation",)

_sp = itertools.count(1)


# ---- Small helpers ---------------------------------------------------------------------------
def _g(row, key, default=None):
    try:
        v = row[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if v is None else v


def _meta_get(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def _meta_set(conn, key, value):
    conn.execute("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (key, str(value)))


MAX_MS = 7_258_118_400_000            # 2200-01-01: a client number beyond this is "far in the future", never an error


def _ms(value):
    """Epoch milliseconds from an int or float (seconds or ms), a digit string or an RFC 3339 string; None if unknown.
    A client may send any number: the result is never above MAX_MS and this never raises."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, float):
        if math.isnan(value) or value < 0:
            return None
        if math.isinf(value):
            return MAX_MS
    if isinstance(value, (int, float)):
        if value < 0:
            return None
        return min(int(value if value > 1e11 else value * 1000), MAX_MS)
    if isinstance(value, str):
        if value.isdigit() and len(value) <= 40:
            return _ms(int(value))
        try:
            return min(rfc3339_to_ms(value), MAX_MS)
        except (ValueError, OverflowError):
            return None
    return None


def _num(value, hi=2 ** 62):
    """A client number as a float within [0, hi], or None (not a number, NaN, negative). Never raises."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        v = float(value)
    except OverflowError:
        return float(hi)
    if math.isnan(v) or v < 0:
        return None
    return min(v, float(hi))


def _json(text, default=None):
    try:
        v = json.loads(text)
        return v if v is not None else default
    except (TypeError, ValueError):
        return default


def _fmt_delay(ms):
    s = max(0, int(ms // 1000))
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return "%dh%02dm" % (h, m)
    if m:
        return "%dm" % m
    return "%ds" % sec


def _like(kinds):
    """SQL for 'kind is one of kinds' (a name ending in .* is a prefix). Returns (sql, args)."""
    exact = [k for k in kinds if not k.endswith(".*")]
    prefixes = [k[:-1] for k in kinds if k.endswith(".*")]
    parts, args = [], []
    if exact:
        parts.append("kind IN (%s)" % ",".join("?" * len(exact)))
        args += exact
    for p in prefixes:
        parts.append("kind LIKE ?")
        args.append(p + "%")
    return "(" + " OR ".join(parts) + ")", args


def _in_kinds(kind, kinds):
    return any(kind == k or (k.endswith(".*") and kind.startswith(k[:-1])) for k in kinds)


def event_time(ev, skew_ms=0):
    """The time an event window uses: the event's own time, unless it is in the future or the host's
    skew is over 5 minutes, then the time the hub received it."""
    ts, rec = _ms(_g(ev, "ts")), _ms(_g(ev, "received_at"))
    if ts is None:
        return rec if rec is not None else now_ms()
    if rec is not None and (ts > rec or abs(skew_ms or 0) > SKEW_MS):
        return rec
    return ts


@contextlib.contextmanager
def _guard(conn, hub, what):
    """Run a block inside a savepoint; on any error roll back just that block, log the type, and carry on."""
    name = "eng_%d" % next(_sp)
    conn.execute("SAVEPOINT " + name)
    try:
        yield
    except Exception as exc:
        try:
            conn.execute("ROLLBACK TO " + name)
        except Exception:
            pass
        try:
            hub.log("error", "engine: %s failed (%s)" % (what, type(exc).__name__))
        except Exception:
            pass
    finally:
        try:
            conn.execute("RELEASE " + name)
        except Exception:
            pass


# ---- Conditions and notes --------------------------------------------------------------------
def _track(conn, key, level, now, remind_ms=None, extra=None):
    """Edge detection for a condition that persists. `level` is 0 (clear) or a positive int.

    Returns (event, since_ms) where event is "new", "up" (level rose), "remind" (still set and
    `remind_ms` have passed since the last emit), "cleared" or None. The caller emits on new, up
    and remind; the state records when it last emitted.
    """
    row = state_get(conn, key)
    data = _json(row["data"], {}) if row else {}
    prev = int(data.get("level") or 0)
    since = data.get("since")
    event = None
    if level <= 0:
        if prev > 0:
            event = "cleared"
            data.update(level=0, since=None)
            state_put(conn, key, severity="", first=row["first"], last=now, count=row["count"], data=data)
        return event, since
    if prev <= 0:
        event, since = "new", now
        data["last_emit"] = now
    elif level > prev:
        event = "up"
        data["last_emit"] = now
    elif remind_ms and now - int(data.get("last_emit") or 0) >= remind_ms:
        event = "remind"
        data["last_emit"] = now
    changed = event is not None or level != prev or (extra and any(data.get(k) != v for k, v in extra.items()))
    data.update(level=level, since=since)
    if extra:
        data.update(extra)
    if changed:
        state_put(conn, key, severity="", first=row["first"] if row else now, last=now,
                  count=(row["count"] if row else 0) + (1 if event else 0), data=data)
    return event, since


def _note(conn, host, rule_id, sev, summary, now, variant=""):
    """Record a finding below HIGH for the digest (one row per host, rule and variant)."""
    key = "note|%s|%s|%s" % (_g(host, "uuid", "-"), rule_id, variant)
    row = state_get(conn, key)
    state_put(conn, key, severity=sev, first=row["first"] if row else now, last=now,
              count=(row["count"] if row else 0) + 1,
              data={"summary": clean(summary, 240), "host": clean(_g(host, "name", ""), 64), "rule": rule_id})


def _finding(conn, hub, host, rule_id, sev, summary, now, *, chain=None, signal=None, fields=None,
             variant="", dedup_key=None, always=False):
    """A finding the hub makes itself. HIGH and above open or extend an incident (when `chain` is
    given) and alert; lower ones become a digest note. Returns the incident id or None."""
    rule = hub_rules.RULES_BY_ID[rule_id]
    if sev_rank(sev) < sev_rank("HIGH"):
        _note(conn, host, rule_id, sev, summary, now, variant)
        return None
    incident_id = None
    if chain and host is not None:
        res = _attach(conn, hub, host, chain, kind=signal or rule["hub_kind"], sev=sev, etime=now, count=0, now=now)
        incident_id = res["incident"]["id"]
    notify(conn, hub, severity=sev, kind=rule["hub_kind"], summary=summary, host=host, fields=fields,
           incident_id=incident_id, now=now, dedup_key=dedup_key, always=always)
    return incident_id


def _once(conn, key, now):
    """True the first time `key` is seen. Rows are pruned after 7 days (the digest job)."""
    full = "once|" + key
    if state_get(conn, full):
        return False
    state_put(conn, full, first=now, last=now, count=1)
    return True


def _maint(conn, uuid, now):
    """The maintenance window an operator set on the hub, if still running."""
    row = query1(conn, "SELECT host, until, set_by, set_at FROM maintenance WHERE host=? AND until>?", (uuid, now))
    return row


# ---- Incidents -------------------------------------------------------------------------------
def _bump_severity(base, kinds):
    """Highest member severity, one level up when two distinct signal kinds are in the incident."""
    rank = sev_rank(base)
    if len(kinds) >= 2:
        rank = min(rank + 1, len(SEVERITIES) - 1)
    return SEVERITIES[rank]


def _attach(conn, hub, host, chain, *, kind, sev, etime, count, now, rowid=None):
    """Add one signal to the (host, chain) incident, opening it when none is near in time.

    A real event (`rowid` given) is pinned in incident_events and counted once: attaching it a
    second time (after_insert and then the tick) returns already=True and changes nothing.
    Returns {"incident": dict, "created", "raised", "already"}.
    """
    uuid = host["uuid"]
    inc = query1(conn, "SELECT * FROM incidents WHERE host=? AND chain=? AND opened-?<=? AND updated+?>=? "
                       "AND (state!='resolved' OR ?<=updated) ORDER BY id DESC LIMIT 1",
                 (uuid, chain, EXTEND_MS, etime, EXTEND_MS, etime, etime))
    created = False
    if inc is None:
        note = ""
        window = _maint(conn, uuid, now)
        if window:
            note = "maintenance window set on the hub by %s until %s" % (clean(window["set_by"], 64), ms_to_rfc3339(window["until"]))
        # a dormant incident of the same chain gives way to the new one
        conn.execute("UPDATE incidents SET state='resolved', closed_at=?, closed_by='system' "
                     "WHERE host=? AND chain=? AND state IN ('open','acknowledged') AND updated<?",
                     (now, uuid, chain, etime - EXTEND_MS))
        cur = conn.execute(
            "INSERT INTO incidents (host, chain, opened, updated, state, severity, kinds, signals, title, note) "
            "VALUES (?,?,?,?,'open',?,?,0,?,?)",
            (uuid, chain, etime, etime, sev, "[]", "%s on %s" % (hub_rules.CHAIN_TITLES.get(chain, chain), clean(host["name"], 64)), note))
        inc = query1(conn, "SELECT * FROM incidents WHERE id=?", (cur.lastrowid,))
        state_put(conn, "incbase|%d" % inc["id"], severity=sev, first=now, last=now, data={"base": sev})
        created = True
    if rowid is not None:
        cur = conn.execute("INSERT OR IGNORE INTO incident_events (incident_id, event_rowid) VALUES (?, ?)", (inc["id"], rowid))
        if cur.rowcount == 0:
            return {"incident": inc, "created": False, "raised": False, "already": True}
    kinds = _json(inc["kinds"], [])
    if kind not in kinds and len(kinds) < 20:
        kinds.append(kind)
    base_row = state_get(conn, "incbase|%d" % inc["id"])
    base = _json(base_row["data"], {}).get("base", inc["severity"]) if base_row else inc["severity"]
    if sev_rank(sev) > sev_rank(base):
        base = sev
    effective = _bump_severity(base, kinds)
    raised = sev_rank(effective) > sev_rank(inc["severity"])
    conn.execute("UPDATE incidents SET signals=signals+?, kinds=?, severity=?, updated=MAX(updated, ?), opened=MIN(opened, ?) WHERE id=?",
                 (max(0, int(count or 0)), json.dumps(kinds), effective, etime, etime, inc["id"]))
    state_put(conn, "incbase|%d" % inc["id"], severity=base, first=base_row["first"] if base_row else now, last=now, data={"base": base})
    inc = query1(conn, "SELECT * FROM incidents WHERE id=?", (inc["id"],))
    return {"incident": inc, "created": created, "raised": raised and not created, "already": False}


def _resolve_stale(conn, now):
    cur = conn.execute("UPDATE incidents SET state='resolved', closed_at=?, closed_by='system' "
                       "WHERE state IN ('open','acknowledged') AND updated<?", (now, now - RESOLVE_MS))
    return cur.rowcount


# ---- Events ----------------------------------------------------------------------------------
def _event_dict(row):
    ev = dict(row)
    d = _json(ev.get("details"), {})
    ev["details"] = d if isinstance(d, dict) else {}
    return ev


def _event_fields(ev, now):
    f = {}
    if ev.get("src_ip"):
        f["source ip"] = ev["src_ip"]
    proc = ev["details"].get("proc") if isinstance(ev.get("details"), dict) else None
    if isinstance(proc, dict) and (proc.get("binary") or proc.get("args")):
        f["process"] = ("%s %s" % (proc.get("binary", ""), proc.get("args", ""))).strip()
    if isinstance(ev.get("details"), dict):
        for key in ("path", "url", "status", "what", "sid"):
            if key in ev["details"] and isinstance(ev["details"][key], (str, int)):
                f[key] = str(ev["details"][key])
    if (ev.get("count") or 1) > 1:
        f["repeats"] = str(ev["count"])
    if ev.get("rated_by"):
        f["rated by"] = ev["rated_by"]
    rec, ts = _ms(ev.get("received_at")), _ms(ev.get("ts"))
    if ev.get("replayed") or (rec is not None and ts is not None and rec - ts > REPLAY_MS):
        f["late"] = "delayed %s" % _fmt_delay((rec if rec is not None else now) - (ts if ts is not None else now))
    return f


def _alert_event(conn, hub, host, ev, incident, now, sev=None):
    sev = sev or ev["hub_severity"]
    summary = ev.get("summary") or ev.get("kind")
    notify(conn, hub, severity=sev, kind=ev["kind"], summary=summary, host=host,
           fields=_event_fields(ev, now), incident_id=incident["id"] if incident else None, now=now)


def after_insert(conn, hub, host_row, rows):
    """CRITICAL events become alerts at once, in the ingest transaction (they are in the outbox before
    the client's batch is acknowledged). Everything else waits for the tick. Never raises."""
    for ev in rows:
        try:
            if ev.get("hub_severity") != "CRITICAL":
                continue
        except AttributeError:
            continue
        with _guard(conn, hub, "after_insert"):
            _critical_now(conn, hub, host_row, ev)


def _critical_now(conn, hub, host, ev, now=None):
    now = _ms(ev.get("received_at")) or now or now_ms()
    ev = dict(ev)
    if not isinstance(ev.get("details"), dict):
        ev["details"] = _json(ev.get("details"), {}) if isinstance(ev.get("details"), str) else {}
    etime = event_time(ev, _g(host, "skew_ms", 0))
    count = int(ev.get("count") or 1)
    res = _attach(conn, hub, host, hub_rules.chain_of(ev["kind"]), kind=ev["kind"], sev="CRITICAL", etime=etime,
                  count=count, now=now, rowid=ev.get("rowid"))
    if res["already"]:
        return
    _alert_event(conn, hub, host, ev, res["incident"], now, "CRITICAL")


# ---- Chains, bursts and escalations ----------------------------------------------------------
def _window(conn, host, kinds, lo, hi, replayed, exclude=None):
    """Events of the host with the given kinds whose event time lies in [lo, hi]."""
    sql, args = _like(kinds)
    skew = _g(host, "skew_ms", 0)
    rows = query(conn,
                 "SELECT id, kind, ts, received_at, count, summary, replayed, src_ip, hub_severity FROM events "
                 "WHERE host=? AND replayed=? AND id!=? AND " + sql + " AND ((ts BETWEEN ? AND ?) OR (received_at BETWEEN ? AND ?)) "
                 "ORDER BY id LIMIT 200",
                 [host["uuid"], 1 if replayed else 0, exclude if exclude is not None else -1] + args + [lo, hi, lo, hi])
    return [r for r in rows if lo <= event_time(r, skew) <= hi]


def _chain_fire(conn, hub, host, name, summary, anchors, now, replayed):
    """CRITICAL chain outcome: one signal on the exploit incident and one alert per distinct pair of events."""
    ids = sorted(a for a in anchors if a is not None)
    if not _once(conn, "chain|%s|%s|%s" % (name, host["uuid"], "-".join(str(i) for i in ids)), now):
        return
    rule = hub_rules.RULES_BY_ID[name]
    res = _attach(conn, hub, host, "exploit", kind="chain." + name, sev="CRITICAL", etime=now, count=0, now=now)
    fields = {"events": ", ".join(str(i) for i in ids)}
    if replayed:
        fields["late"] = "found in a replayed batch"
    notify(conn, hub, severity="CRITICAL", kind=rule["hub_kind"], summary=summary, host=host, fields=fields,
           incident_id=res["incident"]["id"], now=now, dedup_key="chain|%s|%s" % (name, host["uuid"]))
    if name == "survived":
        state_put(conn, "task|survived|%s" % host["uuid"], severity="CRITICAL", first=now, last=now, count=1,
                  data={"hit_ts": now, "summary": "restart nginx (not reload); cleared when inventory shows newer worker start times"})


def _chains(conn, hub, host, ev, etime, now):
    kind = ev["kind"]
    replayed = bool(ev.get("replayed"))
    name = host["name"]
    for rule_id, first, second, win, text in (
            ("contained", FIRST_A, SECOND_A, 30 * MIN, "Attempt contained on %s: early signals, then a blocked exec or SCTP socket"),
            ("survived", FIRST_B, SECOND_B, 10 * MIN, "Worker survived the kill on %s: a fork-watch hit, then web activity")):
        if _in_kinds(kind, second):
            for p in _window(conn, host, first, etime - win, etime, replayed, ev["id"]):
                _chain_fire(conn, hub, host, rule_id, text % clean(name, 64), (p["id"], ev["id"]), now, replayed)
        if _in_kinds(kind, first):
            for p in _window(conn, host, second, etime, etime + win, replayed, ev["id"]):
                _chain_fire(conn, hub, host, rule_id, text % clean(name, 64), (ev["id"], p["id"]), now, replayed)
    text = "Possible success on %s: attack signals, then tampering" % clean(name, 64)
    if _in_kinds(kind, TAMPER):
        for p in _window(conn, host, FIRST_C, etime - 30 * MIN, etime, replayed, ev["id"]):
            _chain_fire(conn, hub, host, "possible_success", text, (p["id"], ev["id"]), now, replayed)
    if _in_kinds(kind, FIRST_C):
        for p in _window(conn, host, TAMPER, etime, etime + 30 * MIN, replayed, ev["id"]):
            _chain_fire(conn, hub, host, "possible_success", text, (ev["id"], p["id"]), now, replayed)


def _escalate_event(conn, hub, host, row, sev, rule_id, now, summary):
    """Raise a stored event's hub_severity, pin it to its incident and alert."""
    if sev_rank(row["hub_severity"]) >= sev_rank(sev):
        return
    conn.execute("UPDATE events SET hub_severity=?, rated_by=? WHERE id=?", (sev, rule_id, row["id"]))
    res = _attach(conn, hub, host, hub_rules.chain_of(row["kind"]), kind=row["kind"], sev=sev,
                  etime=event_time(row, _g(host, "skew_ms", 0)), count=int(row["count"] or 1), now=now, rowid=row["id"])
    if res["already"] or bool(row["replayed"]):
        return
    notify(conn, hub, severity=sev, kind=row["kind"], summary=summary, host=host, incident_id=res["incident"]["id"], now=now,
           fields={"rated by": rule_id, "source ip": row.get("src_ip", "")} if row.get("src_ip") else {"rated by": rule_id})


def _bursts(conn, hub, host, ev, etime, now):
    kind = ev["kind"]
    replayed = bool(ev.get("replayed"))
    skew = _g(host, "skew_ms", 0)
    if kind == "nginx.crash":
        rows = _window(conn, host, ("nginx.crash",), etime - 10 * MIN, etime + 10 * MIN, replayed)
        pts = sorted((event_time(r, skew), int(r["count"] or 1), r["id"]) for r in rows)
        for i, (t0, _c, _i) in enumerate(pts):                       # any 10-minute window holding this event
            total, members = 0, []
            for t, c, rid in pts[i:]:
                if t - t0 > 10 * MIN:
                    break
                total += c
                members.append(rid)
            if total >= 3 and ev["id"] in members:
                if _once(conn, "crash|%s|%d" % (host["uuid"], min(members)), now):
                    res = _attach(conn, hub, host, "exploit", kind="nginx_crash_burst", sev="HIGH", etime=etime, count=0, now=now)
                    if not replayed:
                        notify(conn, hub, severity="HIGH", kind="nginx.crash", summary="nginx workers crashed %d times in 10 minutes on %s" % (total, clean(host["name"], 64)),
                               host=host, incident_id=res["incident"]["id"], fields={"crashes": str(total)}, now=now,
                               dedup_key="crashburst|%s" % host["uuid"])
                break
    text = "A 4 GiB connection was followed by an nginx crash on %s" % clean(host["name"], 64)
    if kind == "nginx.crash":
        for p in _window(conn, host, ("edr.bigconn",), etime - 30 * MIN, etime, replayed, ev["id"]):
            _escalate_event(conn, hub, host, query1(conn, "SELECT * FROM events WHERE id=?", (p["id"],)), "HIGH", "bigconn", now, text)
    elif kind == "edr.bigconn":
        if _window(conn, host, ("nginx.crash",), etime, etime + 30 * MIN, replayed, ev["id"]):
            _escalate_event(conn, hub, host, query1(conn, "SELECT * FROM events WHERE id=?", (ev["id"],)), "HIGH", "bigconn", now, text)
    if kind == "nginx.marker.window_update" and ev.get("src_ip"):
        rows = query(conn, "SELECT id, ts, received_at, count, hub_severity FROM events WHERE host=? AND kind=? AND src_ip=? "
                           "AND received_at BETWEEN ? AND ?",
                     (host["uuid"], kind, ev["src_ip"], etime - 24 * HOUR, etime + 24 * HOUR))
        pts = sorted((event_time(r, skew), int(r["count"] or 1), r["id"]) for r in rows)
        for i, (t0, _c, _i) in enumerate(pts):
            members = [(c, rid) for t, c, rid in pts[i:] if t - t0 <= 10 * MIN]
            if sum(c for c, _ in members) >= 3 and ev["id"] in [rid for _, rid in members]:
                for _c, rid in members:
                    conn.execute("UPDATE events SET hub_severity='MEDIUM', rated_by='window_update' WHERE id=? AND hub_severity IN ('INFO','LOW')", (rid,))
                break


def _process_event(conn, hub, host, ev, now):
    sev = ev["hub_severity"]
    skew = _g(host, "skew_ms", 0)
    etime = event_time(ev, skew)
    ev["received_at"] = _ms(ev.get("received_at")) or now
    _bursts(conn, hub, host, ev, etime, now)
    _chains(conn, hub, host, ev, etime, now)
    if sev_rank(sev) >= sev_rank("HIGH"):
        res = _attach(conn, hub, host, hub_rules.chain_of(ev["kind"]), kind=ev["kind"], sev=sev, etime=etime,
                      count=int(ev.get("count") or 1), now=now, rowid=ev["id"])
        if res["already"] or ev.get("replayed") and sev != "CRITICAL":
            return
        if sev == "CRITICAL" or res["created"] or res["raised"]:
            _alert_event(conn, hub, host, ev, res["incident"], now,
                         sev if sev == "CRITICAL" else res["incident"]["severity"])


def _hosts(conn):
    return {h["uuid"]: h for h in query(conn, "SELECT * FROM hosts")}


def _process_events(conn, hub, now):
    cursor = int(_meta_get(conn, "engine_cursor", 0) or 0)
    hosts = _hosts(conn)
    processed = 0
    for _ in range(BATCHES_PER_TICK):
        rows = query(conn, "SELECT * FROM events WHERE id>? ORDER BY id LIMIT ?", (cursor, BATCH))
        if not rows:
            break
        for row in rows:
            ev = _event_dict(row)
            host = hosts.get(ev["host"]) or query1(conn, "SELECT * FROM hosts WHERE uuid=?", (ev["host"],))
            cursor = ev["id"]
            if host is None or host["state"] in ("retired", "moved"):
                continue
            with _guard(conn, hub, "event"):
                _process_event(conn, hub, host, ev, now)
        _meta_set(conn, "engine_cursor", cursor)
        processed += len(rows)
        if len(rows) < BATCH:
            break
    return processed


# ---- Heartbeat rules -------------------------------------------------------------------------
def _known_hashes(hub, conn):
    """SHA-256 values of accepted agent builds: agent-hashes.json plus the agent_hashes table."""
    known = set()
    try:
        with open(hub.paths.agent_hashes, encoding="utf-8") as f:
            doc = json.load(f)
        for h in doc.get("hashes", []) if isinstance(doc, dict) else []:
            known.add((h.get("sha256") if isinstance(h, dict) else h))
    except (OSError, ValueError, AttributeError):
        pass
    for (h,) in conn.execute("SELECT sha256 FROM agent_hashes").fetchall():
        known.add(h)
    return {str(h).lower() for h in known if h}


def _sum_ints(obj, depth=0):
    if depth > 4:
        return 0
    if isinstance(obj, bool):
        return 0
    if isinstance(obj, int):
        return obj
    if isinstance(obj, dict):
        return sum(_sum_ints(v, depth + 1) for v in obj.values())
    return 0


def _free_pct(disk):
    if not isinstance(disk, dict):
        return None
    for key in ("free_pct", "free_percent"):
        v = _num(disk.get(key), 1000)
        if v is not None:
            return v
    for key in ("used_pct", "used_percent"):
        v = _num(disk.get(key), 1000)
        if v is not None:
            return 100.0 - v
    for v in disk.values():
        if isinstance(v, dict):
            r = _free_pct(v)
            if r is not None:
                return r
    return None


def _tetragon_unhealthy(hb):
    units = hb.get("units")
    if isinstance(units, dict) and units.get("tetragon") == "absent":
        return True
    tet = hb.get("tetragon")
    return isinstance(tet, list) and len(tet) == 0


def _worker_start(inv):
    """The oldest nginx process start time (ms) the inventory reports, or None: `nginx_started_min`
    of the deleted_exe check (epoch seconds), or a `worker_started_at` value or list of them."""
    found = []

    def walk(o, depth=0):
        if depth > 4:
            return
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("nginx_started_min", "worker_started_at", "workers_started_at", "worker_start"):
                    for x in (v if isinstance(v, list) else [v]):
                        t = _ms(x)
                        if t:
                            found.append(t)
                else:
                    walk(v, depth + 1)
    walk(inv.get("checks") if isinstance(inv, dict) else None)
    return min(found) if found else None


def _recent_signal(conn, host, kinds, since, until):
    skew = _g(host, "skew_ms", 0)
    sql, args = _like(kinds)
    rows = query(conn, "SELECT id, kind, ts, received_at, count FROM events WHERE host=? AND " + sql +
                 " AND (received_at BETWEEN ? AND ? OR ts BETWEEN ? AND ?) ORDER BY id DESC LIMIT 50",
                 [host["uuid"]] + args + [since, until, since, until])
    return [r for r in rows if since <= event_time(r, skew) <= until]


def on_heartbeat(conn, hub, prev_host_row, hb, received_at_ms, peer_ip):
    """Heartbeat rules of PLAN section 4. Called after the heartbeat was stored. Never raises."""
    try:
        uuid = prev_host_row["uuid"]
        host = query1(conn, "SELECT * FROM hosts WHERE uuid=?", (uuid,))
    except Exception:
        return
    if host is None or not isinstance(hb, dict) or host["state"] in ("retired", "moved", "revoked"):
        return
    now = received_at_ms
    prev = dict(prev_host_row) if not isinstance(prev_host_row, dict) else prev_host_row
    for name, fn in (("reboot", _hb_reboot), ("identity", _hb_identity), ("build", _hb_build), ("disk", _hb_disk),
                     ("policy", _hb_policy), ("pause", _hb_pause), ("nft", _hb_nft), ("conntrack", _hb_conntrack),
                     ("suricata", _hb_suricata), ("cert", _hb_cert), ("tetragon", _hb_tetragon), ("skew", _hb_skew),
                     ("spool", _hb_spool), ("advisory", _hb_advisory), ("silent", _hb_back)):
        with _guard(conn, hub, "heartbeat " + name):
            fn(conn, hub, host, prev, hb, now)


def _hb_reboot(conn, hub, host, prev, hb, now):
    uuid, new_boot = host["uuid"], hb.get("boot_id")
    old_boot = prev.get("boot_id")
    if not (old_boot and new_boot and old_boot != new_boot):
        return
    if _maint(conn, uuid, now):
        return                                           # a window silences the reboot rule
    notice = prev.get("shutdown_notice_at")
    if notice and 0 <= now - notice <= 10 * MIN:
        _note(conn, host, "reboot", "INFO", "planned reboot (notice, then a new boot id)", now)
        return
    hit = _recent_signal(conn, host, SIGKILL_HITS, now - 30 * MIN, now)
    if hit:
        _finding(conn, hub, host, "reboot", "HIGH", "Unplanned reboot of %s within 30 minutes of a blocked exec" % clean(host["name"], 64),
                 now, chain="tamper", signal="reboot")
    else:
        _finding(conn, hub, host, "reboot", "MEDIUM", "New boot id on %s with no shutdown notice" % clean(host["name"], 64), now)


def _hb_identity(conn, hub, host, prev, hb, now):
    uuid = host["uuid"]
    droplet, enrolled = hb.get("droplet_id"), prev.get("droplet_id")
    if isinstance(droplet, str) and droplet and enrolled and droplet != enrolled:
        # one row per host, holding the last 3 claimed ids: a client cannot make a row per value it invents
        drow = state_get(conn, "dup|droplet|" + uuid)
        seen_ids = _json(drow["data"], {}).get("ids", []) if drow else []
        new_id = droplet[:40] not in seen_ids
        if new_id:
            seen_ids = (seen_ids + [droplet[:40]])[-3:]
        state_put(conn, "dup|droplet|" + uuid, first=drow["first"] if drow else now, last=now, count=(drow["count"] if drow else 0) + (1 if new_id else 0),
                  data={"ids": seen_ids})
        if new_id:
            _finding(conn, hub, host, "duplicate_identity", "HIGH",
                     "Duplicate identity: %s now reports another droplet id" % clean(host["name"], 64), now, chain="tamper",
                     signal="duplicate_identity", fields={"from": clean(_g(host, "enrolled_from", ""), 64)})
    boot = hb.get("boot_id")
    row = state_get(conn, "boot|" + uuid)
    hist = _json(row["data"], {}).get("ids", []) if row else []
    ids = [h[0] for h in hist if isinstance(h, list) and h]
    if isinstance(boot, str) and boot:
        if ids and boot != ids[-1] and boot in ids and now - dict((h[0], h[1]) for h in hist)[boot] < DAY:
            if _once(conn, "dup|boot|%s|%d" % (uuid, now // HOUR), now):
                _finding(conn, hub, host, "duplicate_identity", "HIGH",
                         "Duplicate identity: two live boot ids on %s" % clean(host["name"], 64), now, chain="tamper",
                         signal="duplicate_identity")
        if not ids or ids[-1] != boot:
            hist = (hist + [[boot, now]])[-8:]
        else:
            hist[-1][1] = now
        state_put(conn, "boot|" + uuid, first=row["first"] if row else now, last=now, data={"ids": hist})


def _hb_build(conn, hub, host, prev, hb, now):
    sha = hb.get("agent_sha256")
    if not isinstance(sha, str) or not sha:
        return
    sha = sha.lower()
    uuid = host["uuid"]
    unknown = sha not in _known_hashes(hub, conn)
    changed = bool(prev.get("agent_sha256")) and prev["agent_sha256"].lower() != sha and prev.get("agent_version") == hb.get("agent_version")
    row = state_get(conn, "build|" + uuid)
    last = _json(row["data"], {}).get("sha") if row else None
    if (unknown or changed) and sha != last:
        why = " and ".join(w for w, on in (("not in the known builds", unknown), ("changed while the version did not", changed)) if on)
        _finding(conn, hub, host, "agent_build", "HIGH", "Agent build on %s: %s" % (clean(host["name"], 64), why), now,
                 chain="tamper", signal="agent_build", fields={"sha256": sha[:16] + "..."})
    state_put(conn, "build|" + uuid, first=row["first"] if row else now, last=now, data={"sha": sha if (unknown or changed) else last})


def _hb_disk(conn, hub, host, prev, hb, now):
    free = _free_pct(hb.get("disk"))
    if free is None:
        return
    event, _ = _track(conn, "disk|" + host["uuid"], 1 if free < 10 else 0, now)
    if event in ("new", "up"):
        _finding(conn, hub, host, "disk", "CRITICAL", "Disk on %s has %.1f%% free" % (clean(host["name"], 64), free), now,
                 chain="host", signal="disk_low_hb", dedup_key="disk|%s" % host["uuid"])


def _hb_policy(conn, hub, host, prev, hb, now):
    rev, since = host["policy_rev"], host["policy_rev_since"]
    applied = hb.get("policy_rev_applied")
    err = hb.get("last_apply_error")
    lag = bool(rev and since and applied != rev and now - since > 5 * MIN)
    bad = lag or bool(err)
    event, _ = _track(conn, "policy|" + host["uuid"], 1 if bad else 0, now)
    if event == "new":
        why = "reports an apply error" if err else "has not applied policy %s for over 5 minutes" % clean(rev, 16)
        _finding(conn, hub, host, "policy_lag", "MEDIUM", "%s %s" % (clean(host["name"], 64), why), now)


def _hb_pause(conn, hub, host, prev, hb, now):
    until = _ms(hb.get("paused_until"))
    clamped = False
    if until and until > now + DAY:                   # a pause is 24 hours at most (client PLAN 4.7)
        until, clamped = now + DAY, True
    active = bool(until and until > now)
    row = state_get(conn, "pause|" + host["uuid"])
    last_until = _json(row["data"], {}).get("until") if row else None
    event, _ = _track(conn, "pause|" + host["uuid"], 1 if active else 0, now, extra={"until": until if active else last_until})
    if active and (event == "new" or (last_until and until != last_until and event is None)):
        _finding(conn, hub, host, "paused", "MEDIUM", "%s is paused until %s%s" % (
            clean(host["name"], 64), ms_to_rfc3339(until), " (the host claims more than 24 hours: counted as 24 hours)" if clamped else ""), now)


def _hb_nft(conn, hub, host, prev, hb, now):
    nft = hb.get("nft")
    if not isinstance(nft, dict) or "table_present" not in nft:
        return
    key = "nftgone|" + host["uuid"]
    row = state_get(conn, key)
    if nft["table_present"] is False:
        since = (_json(row["data"], {}).get("since") if row else None) or now
        state_put(conn, key, first=since, last=now, data={"since": since})
        level = 1 if now - since >= 2 * MIN else 0
    else:
        level = 0
        if row:
            conn.execute("DELETE FROM alert_state WHERE key=?", (key,))
    event, _ = _track(conn, "nft|" + host["uuid"], level, now)
    if event in ("new", "up"):
        _finding(conn, hub, host, "nft_absent", "HIGH", "nftables table 'inet edr' is absent on %s" % clean(host["name"], 64), now,
                 chain="host", signal="nft_absent")


def _hb_conntrack(conn, hub, host, prev, hb, now):
    ct = hb.get("conntrack")
    if not isinstance(ct, dict):
        return
    count, maxi = _num(ct.get("count")), _num(ct.get("max"))
    if count is None or maxi is None or maxi <= 0:
        return
    ratio = min(count / maxi, 10.0)                 # a count far above the maximum is still just "full"
    level = 2 if ratio >= 0.9 else 1 if ratio >= 0.7 else 0
    event, _ = _track(conn, "conntrack|" + host["uuid"], level, now)
    if event in ("new", "up"):
        _finding(conn, hub, host, "conntrack", "HIGH" if level == 2 else "MEDIUM",
                 "Conntrack on %s is %d%% full" % (clean(host["name"], 64), int(ratio * 100)), now, chain="host", signal="conntrack")


def _hb_suricata(conn, hub, host, prev, hb, now):
    sd = hb.get("suricata_drops")
    if not isinstance(sd, dict):
        return
    packets, drops = _num(sd.get("packets")), _num(sd.get("drops"))
    if packets is None or drops is None or packets <= 0:
        return
    share = min(drops / packets, 1.0)
    event, _ = _track(conn, "suridrop|" + host["uuid"], 1 if share > 0.01 else 0, now)
    if event == "new":
        _finding(conn, hub, host, "suricata_drops", "MEDIUM",
                 "Suricata on %s dropped %.1f%% of packets" % (clean(host["name"], 64), 100.0 * share), now)


def _hb_cert(conn, hub, host, prev, hb, now):
    na = _ms(hb.get("cert_not_after"))
    if na is None:
        return
    days = (na - now) / DAY
    level = 3 if days < 7 else 2 if days < 14 else 1 if days < 30 else 0
    event, _ = _track(conn, "ccert|" + host["uuid"], level, now)
    if event in ("new", "up"):
        rule_id = {1: "client_cert_30", 2: "client_cert_14", 3: "client_cert_7"}[level]
        sev = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}[level]
        _finding(conn, hub, host, rule_id, sev, "Certificate of %s expires in %d days and has not renewed" % (clean(host["name"], 64), max(0, int(days))),
                 now, chain="host", signal="client_cert")


def _hb_tetragon(conn, hub, host, prev, hb, now):
    if not _tetragon_unhealthy(hb):
        return
    hits = _recent_signal(conn, host, FIRST_C, now - 30 * MIN, now)
    for h in hits[:1]:
        _chain_fire(conn, hub, host, "possible_success",
                    "Possible success on %s: attack signals, then Tetragon unhealthy" % clean(host["name"], 64),
                    (h["id"],), now, False)


def _hb_skew(conn, hub, host, prev, hb, now):
    skew = host["skew_ms"]
    if skew is None:
        return
    event, _ = _track(conn, "skew|" + host["uuid"], 1 if abs(skew) > SKEW_MS else 0, now)
    if event == "new":
        _finding(conn, hub, host, "skew", "MEDIUM", "Clock of %s is %ds off" % (clean(host["name"], 64), abs(skew) // 1000), now)


def _hb_spool(conn, hub, host, prev, hb, now):
    spool = hb.get("spool")
    if not isinstance(spool, dict):
        return
    # the heartbeat gives drops by lane ("dropped") and again by source: count one of them
    key = "dropped" if "dropped" in spool else next((k for k in spool if "drop" in k), None)
    drops = _sum_ints(spool.get(key)) if key else 0
    row = state_get(conn, "spool|" + host["uuid"])
    last = _json(row["data"], {}).get("drops") if row else None
    if last is not None and drops > last:
        _finding(conn, hub, host, "event_loss", "MEDIUM",
                 "%s dropped %d more events from its spool" % (clean(host["name"], 64), drops - last), now, variant="spool")
    state_put(conn, "spool|" + host["uuid"], first=row["first"] if row else now, last=now, data={"drops": drops})


def _hb_back(conn, hub, host, prev, hb, now):
    """A heartbeat ends agent-silent, and clears the survived-the-kill task when inventory shows new workers."""
    event, _ = _track(conn, "silent|" + host["uuid"], 0, now)
    if event == "cleared":
        _note(conn, host, "agent_silent", "INFO", "agent is back", now)
    task = state_get(conn, "task|survived|" + host["uuid"])
    if task:
        inv = hb.get("inventory")
        start = _worker_start(inv) if isinstance(inv, dict) else None
        hit = _json(task["data"], {}).get("hit_ts")
        if start and hit and start > hit:
            conn.execute("DELETE FROM alert_state WHERE key=?", ("task|survived|" + host["uuid"],))
            _note(conn, host, "survived", "INFO", "worker start times are newer than the hit: task cleared", now)


def _hb_advisory(conn, hub, host, prev, hb, now):
    inv = hb.get("inventory")
    if isinstance(inv, dict) and inv:
        _advisory_eval(conn, hub, host, inv, now, daily=False)


_adv_cache = {"mtime": None, "obj": None}


def _advisories(hub):
    paths = hub.paths
    stamp = []
    for p in (paths.find_data("advisories.json"),):
        try:
            stamp.append(os.stat(p).st_mtime_ns)
        except OSError:
            stamp.append(None)
    try:
        stamp.append(tuple(sorted((f, os.stat(os.path.join(paths.advisories_d, f)).st_mtime_ns) for f in os.listdir(paths.advisories_d))))
    except OSError:
        stamp.append(None)
    key = (paths.state_dir, tuple(stamp))
    if _adv_cache["mtime"] != key:
        _adv_cache.update(mtime=key, obj=hub_advisory.load(paths))
    return _adv_cache["obj"]


def _advisory_eval(conn, hub, host, inv, now, daily):
    adv = _advisories(hub)
    key = "adv|" + host["uuid"]
    row = state_get(conn, key)
    data = _json(row["data"], {}) if row else {}
    first = data.get("first", {})
    sevs = data.get("sev", {})
    findings = hub_advisory.evaluate_inventory(adv, inv, now, {k: v for k, v in first.items()})
    seen = set()
    for f in findings:
        rid = f["id"]
        seen.add(rid)
        if f["status"] == "vulnerable":
            first.setdefault(rid, now)
        prev_sev = sevs.get(rid)
        sevs[rid] = f["severity"]
        text = "%s on %s" % (f["summary"], clean(host["name"], 64))
        if f["severity"] == "HIGH":
            if prev_sev != "HIGH" or daily:
                _finding(conn, hub, host, "advisory_exposed", "HIGH", text, now, chain="exposure", signal="advisory." + clean(rid, 40),
                         fields={"fix": f["detail"], "cves": ", ".join(f["cves"][:4]), "ref": f["ref"]},
                         dedup_key="adv|%s|%s|%d" % (host["uuid"], rid, now // DAY if daily else 0))
        else:
            _note(conn, host, "advisory_exposed", f["severity"], text, now, variant=rid)
    # Gone from the findings means "fixed" only when the inventory gave a definite answer. An unknown or missing
    # check says nothing: the 24-hour exposure clock (first) and the last severity stay as they were.
    definite = hub_advisory.inventory_definite(inv)
    for rid in list(sevs):
        if rid in seen:
            continue
        if rid in ("nginx-unknown", "nginx-origin", "kernel-unknown"):     # a "status unknown" note: gone when no longer reported
            sevs.pop(rid, None)
            first.pop(rid, None)
        elif definite["kernel" if rid.startswith("kernel-") else "nginx"]:
            sevs.pop(rid, None)
            first.pop(rid, None)
    state_put(conn, key, first=row["first"] if row else now, last=now, data={"first": first, "sev": sevs})


# ---- Enrollment and rejected requests --------------------------------------------------------
def on_enroll(conn, hub, host_row, peer_ip, token_row, reenroll):
    """The HIGH enrollment notice (always sent). The message never holds a token secret."""
    with _guard(conn, hub, "on_enroll"):
        made_by = clean(_g(token_row, "created_by", ""), 80) or "unknown"
        tid = clean(str(_g(token_row, "id", ""))[:8], 16)
        name = clean(_g(host_row, "name", ""), 64)
        verb = "re-enrolled" if reenroll else "enrolled"
        notify(conn, hub, severity="HIGH", always=True, kind="hub.enroll", host=host_row, now=now_ms(),
               summary="Host %s %s from %s (token made by %s)" % (name, verb, clean(peer_ip, 64), made_by),
               fields={"from": clean(peer_ip, 64), "token id": tid, "token made by": made_by, "state": clean(_g(host_row, "state", ""), 20)})


def on_rejected(conn, hub, host_row_or_none, code, peer_ip):
    """A 403 on the fleet listener: counted per (host, code), alerted for revoked and superseded certificates."""
    with _guard(conn, hub, "on_rejected"):
        now = now_ms()
        uuid = _g(host_row_or_none, "uuid", "-") if host_row_or_none is not None else "-"
        code = clean(code, 40)
        key = "rejected|%s|%s" % (uuid, code)
        row = state_get(conn, key)
        count = (row["count"] if row else 0) + 1
        state_put(conn, key, severity="", first=row["first"] if row else now, last=now, count=count,
                  data={"peer": clean(peer_ip, 64)})
        if code in ("host_moved", "host_retired"):
            return                                       # silenced states
        loud = code in ("host_revoked", "cert_superseded")
        name = clean(_g(host_row_or_none, "name", "unknown host"), 64) if host_row_or_none is not None else "an unknown host"
        if loud and host_row_or_none is not None:
            _finding(conn, hub, host_row_or_none, "rejected", "HIGH", "%s was refused (%s) from %s" % (name, code, clean(peer_ip, 64)), now,
                     fields={"from": clean(peer_ip, 64), "attempts": str(count)}, dedup_key="rejalert|%s|%s" % (uuid, code))
        else:
            _note(conn, host_row_or_none, "rejected", "MEDIUM", "%s refused (%s) from %s, %d times" % (name, code, clean(peer_ip, 64), count), now, variant=code)


# ---- Tick-side checks: silence, pending, orphan, canary --------------------------------------
def _hosts_checks(conn, hub, now, grace_until):
    for host in query(conn, "SELECT * FROM hosts WHERE state IN ('pending','active','orphan')"):
        with _guard(conn, hub, "host check"):
            if host["state"] == "pending":
                _check_pending(conn, hub, host, now)
            elif host["state"] == "orphan":
                event, _ = _track(conn, "orphan|" + host["uuid"], 1, now)
                if event == "new":
                    # The only alert for an orphan (PLAN 2, Host states; 4, Rules): hub_enroll writes the audit row, not an alert.
                    _finding(conn, hub, host, "orphan", "HIGH",
                             "%s presented a certificate this hub did not issue and awaits adoption" % clean(host["name"], 64), now,
                             chain="host", signal="orphan",
                             fields={"uuid": clean(host["uuid"], 40), "adopt with": "edr-hub host %s adopt" % clean(host["uuid"], 40)})
            else:
                _check_silent(conn, hub, host, now, grace_until)


def _check_pending(conn, hub, host, now):
    never = host["last_seen"] is None
    event, _ = _track(conn, "pending|" + host["uuid"], 1 if never and now - host["enrolled_at"] > HOUR else 0, now)
    if event == "new":
        _finding(conn, hub, host, "pending_silent", "HIGH", "%s enrolled over an hour ago and has not sent a heartbeat" % clean(host["name"], 64),
                 now, chain="host", signal="pending_silent")


def _check_silent(conn, hub, host, now, grace_until):
    uuid, last = host["uuid"], host["last_seen"]
    if last is None:
        return
    silent = now - last
    if silent < SILENT_MS or _maint(conn, uuid, now):
        _track(conn, "silent|" + uuid, 0, now)             # back, or silenced by an operator's window
        return
    if now < grace_until:
        return                                             # start-up grace: the host has not had its chance to reconnect
    notice = host["shutdown_notice_at"]
    if notice and last <= notice + 5000 and now - notice < 10 * MIN:
        return                                           # a planned reboot has ten minutes
    crit = bool(_recent_signal(conn, host, ATTACK_RECENT, last - 30 * MIN, now))
    event, since = _track(conn, "silent|" + uuid, 2 if crit else 1, now, remind_ms=DAY)
    if event in ("new", "up", "remind"):
        days = silent // DAY
        text = "%s has sent no heartbeat for %s" % (clean(host["name"], 64), _fmt_delay(silent) if days < 1 else "%d days" % days)
        if crit:
            text += " after attack signals"
            res = _attach(conn, hub, host, "exploit", kind="chain.possible_success", sev="CRITICAL", etime=now, count=0, now=now)
            notify(conn, hub, severity="CRITICAL", kind="hub.possible_success", summary=text, host=host, incident_id=res["incident"]["id"],
                   now=now, dedup_key="silent|%s|%s" % (uuid, event))
        else:
            _finding(conn, hub, host, "agent_silent", "HIGH", text, now, chain="host", signal="agent_silent",
                     dedup_key="silent|%s|%s|%d" % (uuid, event, now // DAY if event == "remind" else 0))


def _check_canary(conn, hub, now):
    for host in query(conn, "SELECT * FROM hosts WHERE state='active'"):
        with _guard(conn, hub, "canary check"):
            born = host["first_heartbeat_at"] or host["enrolled_at"]
            if not born or now - born < 26 * HOUR:
                continue
            seen = query1(conn, "SELECT 1 AS x FROM events WHERE host=? AND kind='canary.policy_check' AND received_at>? LIMIT 1",
                          (host["uuid"], now - 26 * HOUR))
            event, _ = _track(conn, "canary|" + host["uuid"], 0 if seen else 1, now)
            if event == "new":
                _finding(conn, hub, host, "no_canary", "MEDIUM", "%s sent no daily canary result in 26 hours" % clean(host["name"], 64), now)


# ---- Hub self-health -------------------------------------------------------------------------
def _level_alert(conn, hub, key, level, now, rules, text, remind=True):
    """Alert a threshold condition: `rules` maps level -> (rule id, severity). Reminds daily when HIGH."""
    event, _ = _track(conn, key, level, now, remind_ms=DAY if remind else None)
    if event in ("new", "up", "remind") and level in rules:
        rule_id, sev = rules[level]
        if event == "remind" and sev_rank(sev) < sev_rank("HIGH"):
            return
        _finding(conn, hub, None, rule_id, sev, text, now, dedup_key="%s|%d" % (key, now // DAY if event == "remind" else 0))


def _db_used(conn, hub):
    page_count = conn.execute("PRAGMA page_count").fetchone()[0]
    free = conn.execute("PRAGMA freelist_count").fetchone()[0]
    size = conn.execute("PRAGMA page_size").fetchone()[0]
    try:
        wal = os.path.getsize(hub.paths.db + "-wal")
    except OSError:
        wal = 0
    return (page_count - free) * size + wal, wal


def _backup_time(conn, hub):
    best = _ms(_meta_get(conn, "last_backup"))
    t = None
    try:
        with open(hub.paths.last_backup, encoding="utf-8") as f:
            words = f.read(256).split()
        t = _ms(words[0]) if words else None
        if t is None:
            t = int(os.stat(hub.paths.last_backup).st_mtime * 1000)    # a marker with no readable time: its mtime
    except OSError:
        pass
    return max([x for x in (best, t) if x] or [0]) or None


def _selfhealth(conn, hub, now):
    with _guard(conn, hub, "server certificate"):
        info = hub.pki.cert_info(hub.paths.server_cert)
        days = (_ms(info["not_after"]) - now) / DAY
        level = 3 if days < 7 else 2 if days < 14 else 1 if days < 30 else 0
        _level_alert(conn, hub, "selfhealth|server_cert", level, now,
                     {1: ("server_cert_30", "MEDIUM"), 2: ("server_cert_14", "HIGH"), 3: ("server_cert_7", "HIGH")},
                     "The hub server certificate expires in %d days" % max(0, int(days)))
    with _guard(conn, hub, "CA certificate"):
        info = hub.pki.cert_info(hub.paths.ca_cert)
        days = (_ms(info["not_after"]) - now) / DAY
        level = 2 if days < 365 else 1 if days < 730 else 0
        _level_alert(conn, hub, "selfhealth|ca", level, now, {1: ("ca_2y", "MEDIUM"), 2: ("ca_1y", "HIGH")},
                     "The hub CA expires in %d days" % max(0, int(days)))
    with _guard(conn, hub, "advisory age"):
        adv = _advisories(hub)
        state = adv.staleness(now)
        _meta_set(conn, "advisory_status", state)
        level = {"ok": 0, "old": 1, "stale": 2}[state]
        _level_alert(conn, hub, "selfhealth|advisory", level, now, {1: ("advisory_90", "MEDIUM"), 2: ("advisory_180", "MEDIUM")},
                     "The advisory table is %s days old" % ("%d" % adv.age_days(now) if adv.age_days(now) is not None else "many"))
    with _guard(conn, hub, "backup age"):
        first = _meta_get(conn, "engine_first_tick")
        base = _backup_time(conn, hub) or (int(first) if first else now)
        _level_alert(conn, hub, "selfhealth|backup", 1 if now - base > 7 * DAY else 0, now, {1: ("backup_age", "HIGH")},
                     "No verified backup for %d days" % ((now - base) // DAY))
    with _guard(conn, hub, "database size"):
        used, wal = _db_used(conn, hub)
        try:
            cap = hub_common.parse_size(hub.settings.get("max_db_size", "2G"))
        except ValueError:
            cap = 2 * 1024 ** 3
        bad = used > 0.8 * cap or wal > 256 * 1024 * 1024
        _level_alert(conn, hub, "selfhealth|db_size", 1 if bad else 0, now, {1: ("db_size", "MEDIUM")},
                     "The database uses %d%% of its cap; the WAL is %d MB" % (100 * used // cap, wal // (1024 * 1024)), remind=False)
    with _guard(conn, hub, "disk use"):
        du = shutil.disk_usage(hub.paths.state_dir)
        pct = 100.0 * du.used / du.total if du.total else 0
        level = 2 if pct >= 90 else 1 if pct >= 80 else 0
        _level_alert(conn, hub, "selfhealth|disk", level, now, {1: ("disk_80", "MEDIUM"), 2: ("disk_80", "HIGH")},
                     "The hub's disk is %d%% used" % pct)
    _check_canary(conn, hub, now)


# ---- The daily digest ------------------------------------------------------------------------
def build_digest(conn, hub, since, now):
    """(lines, counts) of the daily digest: what a person reads once a day."""
    lines = []
    sev_counts = {}
    inc = query(conn, "SELECT i.id, i.host, i.chain, i.severity, i.kinds, i.state, i.opened, i.updated, h.name AS hname "
                      "FROM incidents i LEFT JOIN hosts h ON h.uuid=i.host WHERE i.state IN ('open','acknowledged') ORDER BY i.id")
    for i in inc:
        sev_counts[i["severity"]] = sev_counts.get(i["severity"], 0) + 1
    lines.append("Open incidents: %d%s" % (len(inc), (" (" + ", ".join("%s %d" % (s, sev_counts[s]) for s in reversed(SEVERITIES) if s in sev_counts) + ")") if inc else ""))
    for i in inc[:8]:
        lines.append("  #%d %s %s %s since %s" % (i["id"], i["severity"], clean(i["hname"] or "?", 40), i["chain"], ms_to_rfc3339(i["opened"])[:16]))
    silent = query(conn, "SELECT name, last_seen FROM hosts WHERE state='active' AND last_seen<? ORDER BY last_seen", (now - SILENT_MS,))
    for h in silent[:10]:
        age = now - h["last_seen"]
        lines.append("Silent: %s for %s%s" % (clean(h["name"], 40), _fmt_delay(age) if age < DAY else "%d days" % (age // DAY),
                                              "; retire it? (edr-hub host %s retire)" % clean(h["name"], 40) if age >= 14 * DAY else ""))
    ev = query(conn, "SELECT kind, hub_severity AS sev, SUM(count) AS total, COUNT(DISTINCT host) AS hosts FROM events "
                     "WHERE received_at>? AND hub_severity IN ('MEDIUM','LOW') GROUP BY kind, hub_severity ORDER BY total DESC LIMIT 15",
               (since,))
    if ev:
        lines.append("MEDIUM and LOW since the last digest:")
        for e in ev:
            lines.append("  %s %s x%d on %d host(s)" % (e["sev"], clean(e["kind"], 64), e["total"], e["hosts"]))
    late = query1(conn, "SELECT COUNT(*) AS n, MAX(received_at-ts) AS worst FROM events WHERE received_at>? AND replayed=1", (since,))
    if late and late["n"]:
        lines.append("Late events: %d, the oldest %s behind" % (late["n"], _fmt_delay(late["worst"] or 0)) +
                     ("; delay over 1 hour" if (late["worst"] or 0) > HOUR else ""))
    for n in query(conn, "SELECT key, severity, last, count, data FROM alert_state WHERE key LIKE 'note|%' AND last>? AND severity IN ('MEDIUM','LOW') ORDER BY last LIMIT 25", (since,)):
        d = _json(n["data"], {})
        lines.append("%s %s%s" % (n["severity"], clean(d.get("summary", n["key"]), 200), (" (x%d)" % n["count"]) if n["count"] > 1 else ""))
    gaps = query(conn, "SELECT h.name AS hname, e.epoch AS epoch, MAX(e.seq)-MIN(e.seq)+1-COUNT(*) AS missing FROM events e JOIN hosts h ON h.uuid=e.host "
                       "WHERE e.received_at>? GROUP BY e.host, e.epoch HAVING missing>0 LIMIT 10", (since,))
    for g in gaps:
        lines.append("MEDIUM events were lost: %d sequence number(s) missing from %s (epoch %d)" % (g["missing"], clean(g["hname"], 40), g["epoch"]))
    lag = query(conn, "SELECT name, schema, proto FROM hosts WHERE state IN ('active','pending') AND (schema<? OR proto<?) LIMIT 10",
                (hub_common.EVENT_SCHEMA, hub_common.PROTO))
    for h in lag:
        lines.append("Lagging client: %s (schema %s, proto %s)" % (clean(h["name"], 40), h["schema"], h["proto"]))
    for t in query(conn, "SELECT key, data FROM alert_state WHERE key LIKE 'task|survived|%'"):
        lines.append("Open task: restart nginx on %s (a worker survived a kill)" % clean(t["key"].rsplit("|", 1)[-1][:8], 16))
    try:
        for ch in hub_alerts.channel_health(conn, now):
            if ch["failing"]:
                lines.append("Alert channel %s is failing: %s" % (ch["channel"], clean(ch["last_error"], 80)))
    except Exception:
        pass
    head = _meta_get(conn, "audit_head")
    if head:
        lines.append("Audit head: %s" % clean(head, 64)[:16])
    return lines, {"incidents": len(inc), "silent": len(silent), "events": len(ev)}


def _digest_due(conn, hub, now):
    try:
        hh, mm = hub.settings.get("digest_time", "07:00").split(":")
        slot = (now // DAY) * DAY + (int(hh) * 60 + int(mm)) * MIN
    except (ValueError, AttributeError):
        slot = (now // DAY) * DAY + 7 * HOUR
    last = _ms(_meta_get(conn, "last_digest"))
    return (slot if now >= slot and (last is None or last < slot) else None), last


def prune_alert_state(conn, now):
    """Delete alert_state rows nobody touched for 7 days. A condition that is still set (level 1 to 3), an open
    survived-the-kill task and the storm row stay. Returns the number of rows deleted."""
    cur = conn.execute("DELETE FROM alert_state WHERE last<? AND key NOT LIKE 'task|%' AND key!='storm' "
                       "AND data NOT GLOB '*\"level\": [1-9]*'", (now - 7 * DAY,))
    return cur.rowcount


def _digest(conn, hub, now):
    slot, last = _digest_due(conn, hub, now)
    if slot is None:
        return False
    since = last if last is not None else now - DAY
    _meta_set(conn, "last_digest", now)
    for host in query(conn, "SELECT * FROM hosts WHERE state='active'"):
        with _guard(conn, hub, "daily advisory"):
            body = query1(conn, "SELECT body FROM inventory WHERE host=?", (host["uuid"],))
            inv = _json(body["body"], None) if body else None
            if isinstance(inv, dict):
                _advisory_eval(conn, hub, host, inv, now, daily=True)
    conn.execute("DELETE FROM alert_state WHERE key LIKE 'once|%' AND last<?", (now - 7 * DAY,))
    prune_alert_state(conn, now)
    lines, counts = build_digest(conn, hub, since, now)
    notify(conn, hub, severity="LOW", always=True, kind="hub.digest", now=now,
           summary="Daily digest for %s" % ms_to_rfc3339(now)[:10], lines=lines,
           fields={"open incidents": str(counts["incidents"]), "silent hosts": str(counts["silent"])},
           dedup_key="digest")
    return True


# ---- The engine ------------------------------------------------------------------------------
class Engine:
    """The 10 second tick thread. `tick(now_ms)` can be called directly (tests do)."""

    def __init__(self, hub):
        self.hub = hub
        self.grace_until = 0
        self._thread = None
        self._stop = threading.Event()
        self._t_minute = 0
        self._t_health = 0

    # lifecycle
    def start(self):
        self.startup()
        self._thread = threading.Thread(target=self._run, name="edr-hub-engine", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        while not self._stop.is_set() and not self.hub.stopping.is_set():
            try:
                self.tick()
            except Exception as exc:
                self.hub.log("error", "engine tick failed (%s)" % type(exc).__name__)
            self._stop.wait(TICK_S)

    def _stage(self, name, fn):
        try:
            return self.hub.writer.call(fn)
        except Exception as exc:
            self.hub.log("error", "engine %s failed (%s)" % (name, type(exc).__name__))
            return None

    def startup(self, now=None):
        """Start-up grace, and one 'hub was down from X to Y' alert after an outage over 10 minutes."""
        now = now_ms() if now is None else now
        self.grace_until = now + GRACE_MS

        def work(conn):
            prev = _ms(_meta_get(conn, "engine_tick"))
            if _meta_get(conn, "engine_first_tick") is None:
                _meta_set(conn, "engine_first_tick", now)
            if prev is not None and now - prev > HUB_DOWN_ALERT_MS:
                notify(conn, self.hub, severity="HIGH", kind="hub.down", now=now,
                       summary="Hub was down from %s to %s" % (ms_to_rfc3339(prev)[:19], ms_to_rfc3339(now)[:19]),
                       fields={"down for": _fmt_delay(now - prev)}, dedup_key="hubdown|%d" % prev)
            _meta_set(conn, "engine_tick", now)
        self._stage("startup", work)

    def tick(self, now=None):
        now = now_ms() if now is None else now
        hub = self.hub
        self._stage("events", lambda c: _process_events(c, hub, now))
        self._stage("incidents", lambda c: _resolve_stale(c, now))
        self._stage("hosts", lambda c: _hosts_checks(c, hub, now, self.grace_until))
        if now - self._t_minute >= MIN:
            self._t_minute = now
            self._stage("storm", lambda c: hub_alerts.flush_storm(c, hub, now) + hub_alerts.flush_host_caps(c, hub, now))
            self._stage("digest", lambda c: _digest(c, hub, now))
        if now - self._t_health >= 5 * MIN:
            self._t_health = now
            self._stage("selfhealth", lambda c: _selfhealth(c, hub, now))
        self._stage("cursor", lambda c: self._cursor_check(c, hub, now))

    def _cursor_check(self, conn, hub, now):
        _meta_set(conn, "engine_tick", now)
        cursor = int(_meta_get(conn, "engine_cursor", 0) or 0)
        behind = query1(conn, "SELECT COUNT(*) AS n FROM events WHERE id>? AND received_at<?", (cursor, now - MIN))
        event, _ = _track(conn, "selfhealth|engine", 1 if behind and behind["n"] else 0, now)
        if event in ("new", "up"):
            _finding(conn, hub, None, "engine_cursor", "HIGH", "The correlation engine is %d events behind" % behind["n"], now)
