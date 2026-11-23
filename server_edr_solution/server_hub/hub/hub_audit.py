"""The hash-chained audit table and the pending-audit.jsonl bridge (PLAN.md section 5, Audit).

Everything that takes a `conn` runs on the writer's connection, inside `hub.writer.call`.
`append_pending` is the one function the root CLI calls without a hub.

Chain rule: hash = sha256(prev_hash || canonical_json(row)), where row holds ts, actor_kind,
actor_detail, action, target, outcome and the stored details text. The first row has the all-zero
prev_hash. Rows that retention deletes leave a gap; every deleted run is recorded in a `prune` row
with the hash of its last deleted row, and `verify` accepts a gap only when that hash is listed.
"""

import hashlib
import json
import os
import secrets
import stat
import time

import hub_common
from hub_common import canonical_json, clean, now_ms

GENESIS = "0" * 64

PRUNE_MAIN_MS = 3 * 365 * 86400 * 1000        # operator, system and enrollment rows: 3 years
PRUNE_FAIL_MS = 30 * 86400 * 1000             # unauthenticated failures: 30 days
FOLD_SOURCES_PER_MINUTE = 1000
FOLD_ROWS_PER_DAY = 10_000
SCHEDULED_GAP_MS = 20 * 3600 * 1000           # a second scheduled backup inside this window notifies
PENDING_LINE_MAX = 4 * 1024
PENDING_LINES_PER_TICK = 200
PENDING_NOTICES_PER_TICK = 10
HUB_INSTALLED_STATE = "/var/lib/edr-hub"
PENDING_READ_MAX = 1024 * 1024
PRUNE_RUNS_PER_ROW = 500
BACKUP_UNIT = "edr-hub-backup.service"

_FAIL_OUTCOMES = ("denied", "invalid")


def _alerts():
    """The alert module, imported late so this file loads without it (tests replace this function)."""
    import hub_alerts
    return hub_alerts


# ---- meta, inlined so this module needs nothing from hub_db -------------------------------------
def _meta_get(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return default if row is None else row[0]


def _meta_set(conn, key, value):
    conn.execute("INSERT INTO meta (key, value) VALUES (?, ?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


# ---- the chain ----------------------------------------------------------------------------------
def _row_hash(prev_hash, ts, actor_kind, actor_detail, action, target, outcome, details):
    row = {"ts": ts, "actor_kind": actor_kind, "actor_detail": actor_detail, "action": action,
           "target": target, "outcome": outcome, "details": details}
    return hashlib.sha256(prev_hash.encode("ascii") + canonical_json(row)).hexdigest()


def _clean_value(value, depth=0):
    if isinstance(value, str):
        return clean(value, 200)
    if isinstance(value, dict) and depth < 4:
        return {clean(str(k), 64): _clean_value(v, depth + 1) for k, v in list(value.items())[:64]}
    if isinstance(value, (list, tuple)) and depth < 4:
        return [_clean_value(v, depth + 1) for v in list(value)[:64]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return clean(str(value), 200)


def _insert(conn, ts, actor_kind, actor_detail, action, target, outcome, details_text):
    row = conn.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = row[0] if row else GENESIS
    digest = _row_hash(prev, ts, actor_kind, actor_detail, action, target, outcome, details_text)
    cur = conn.execute(
        "INSERT INTO audit (ts, actor_kind, actor_detail, action, target, outcome, details, prev_hash, hash) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (ts, actor_kind, actor_detail, action, target, outcome, details_text, prev, digest))
    _meta_set(conn, "audit_head", digest)
    return cur.lastrowid


def append(conn, *, actor_kind, actor_detail="", action, target="", outcome="ok", details=None, fold=False):
    """Add one row to the chain and return its id. Text fields pass through clean().

    A failure of an unauthenticated peer (actor_kind client, outcome denied or invalid) is folded:
    one row per source per minute with a count (see flush_folds). So is a refusal or an invalid request
    on ui.sock or out.sock, when the caller passes fold=True (one row per socket, verb and minute).
    A folded call returns 0.
    """
    actor_detail = clean(actor_detail, 200)
    action = clean(action, 100)
    target = clean(target, 200)
    if (actor_kind == "client" or fold) and outcome in _FAIL_OUTCOMES:
        _fold_add(conn, actor_kind, actor_detail, action, target, outcome)
        return 0
    flush_folds(conn)
    text = canonical_json(_clean_value(details if details is not None else {})).decode("utf-8")
    return _insert(conn, now_ms(), actor_kind, actor_detail, action, target, outcome, text)


def verify(conn):
    """Walk the chain. Returns (True, None) or (False, id of the first bad row)."""
    pruned = set()
    for (text,) in conn.execute("SELECT details FROM audit WHERE action='prune'"):
        try:
            for run in json.loads(text).get("runs", []):
                pruned.add(run["last_hash"])
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
    prev_hash = None
    last_id = None
    cur = conn.execute("SELECT id, ts, actor_kind, actor_detail, action, target, outcome, details, prev_hash, hash "
                       "FROM audit ORDER BY id")
    for r in cur:
        rid, ts, kind, detail, action, target, outcome, details, row_prev, row_hash = tuple(r)
        if _row_hash(row_prev, ts, kind, detail, action, target, outcome, details) != row_hash:
            return False, rid
        if prev_hash is None:
            linked = row_prev == GENESIS or row_prev in pruned
        else:
            linked = row_prev == prev_hash or row_prev in pruned
        if not linked:
            return False, rid
        prev_hash = row_hash
        last_id = rid
    stored = _meta_get(conn, "audit_head")
    if stored is not None and stored != (prev_hash if prev_hash is not None else GENESIS):
        return False, last_id if last_id is not None else 0     # rows were cut off the end
    return True, None


def head(conn):
    """The head hash, for the daily digest and the journal."""
    row = conn.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    return row[0] if row else GENESIS


# ---- folding of unauthenticated failures --------------------------------------------------------
def _day_of(ms):
    return time.strftime("%Y-%m-%d", time.gmtime(ms // 1000))


def _minute_text(minute):
    return time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime(minute * 60))


def _load_json(conn, key, default):
    try:
        value = json.loads(_meta_get(conn, key, ""))
        return value if isinstance(value, dict) else default
    except ValueError:
        return default


def _unkey(key):
    """(actor_kind, actor_detail, action, outcome) of a fold key; an older key had no actor kind (it was a client)."""
    parts = json.loads(key)
    return tuple(parts) if len(parts) == 4 else ("client",) + tuple(parts)


def _fold_add(conn, actor_kind, actor_detail, action, target, outcome):
    """Count one failure. The counts live in meta, so a restart loses nothing."""
    now = now_ms()
    state = _load_json(conn, "audit_fold", {})
    minute = now // 60000
    if state.get("minute") != minute:
        if state.get("items"):
            _fold_write(conn, state)
        state = {"minute": minute, "items": {}}
    items = state["items"]
    sources = {_unkey(k)[1] for k in items}
    if actor_detail not in sources and len(sources) >= FOLD_SOURCES_PER_MINUTE:
        actor_detail = "other"
    key = json.dumps([actor_kind, actor_detail, action, outcome])
    if key in items:
        items[key][0] += 1
    else:
        items[key] = [1, target]
    _meta_set(conn, "audit_fold", json.dumps(state, separators=(",", ":")))


def _fold_write(conn, state):
    minute = state["minute"]
    day = _day_of(minute * 60000)
    cap = _load_json(conn, "audit_fold_day", {})
    if cap.get("day") != day:
        _fold_summary(conn, cap)
        cap = {"day": day, "rows": 0, "dropped": 0}
    ts = minute * 60000 + 59999
    for key in sorted(state.get("items", {})):
        count, target = state["items"][key]
        kind, detail, action, outcome = _unkey(key)
        if cap["rows"] >= FOLD_ROWS_PER_DAY:
            cap["dropped"] += count
            continue
        cap["rows"] += 1
        text = canonical_json({"count": count, "minute": _minute_text(minute)}).decode("utf-8")
        _insert(conn, ts, kind, detail, action, target, outcome, text)
    _meta_set(conn, "audit_fold_day", json.dumps(cap, separators=(",", ":")))


def _fold_summary(conn, cap):
    """One summary row for a day that hit the cap, with the count of failures that got no row."""
    if cap.get("dropped"):
        text = canonical_json({"day": cap.get("day", ""), "count": cap["dropped"],
                               "rows_written": cap.get("rows", 0)}).decode("utf-8")
        _insert(conn, now_ms(), "system", "audit", "client-failures.capped", "", "ok", text)


def flush_folds(conn, now=None):
    """Write the folded rows of every finished minute (and the summary of a finished day)."""
    now = now if now is not None else now_ms()
    state = _load_json(conn, "audit_fold", {})
    if state.get("items") and state.get("minute", 0) < now // 60000:
        _fold_write(conn, state)
        _meta_set(conn, "audit_fold", json.dumps({"minute": now // 60000, "items": {}}))
    cap = _load_json(conn, "audit_fold_day", {})
    if cap.get("dropped") and cap.get("day") != _day_of(now):
        _fold_summary(conn, cap)
        cap["dropped"] = 0
        _meta_set(conn, "audit_fold_day", json.dumps(cap, separators=(",", ":")))


# ---- retention ----------------------------------------------------------------------------------
def prune(conn, now=None):
    """Delete rows past retention and record what was deleted in `prune` rows. Returns rows deleted."""
    now = now if now is not None else now_ms()
    cut_main = now - PRUNE_MAIN_MS
    cut_fail = now - PRUNE_FAIL_MS
    runs = []
    cur_run = None
    for rid, row_hash, ts, kind, outcome, details in conn.execute(
            "SELECT id, hash, ts, actor_kind, outcome, details FROM audit ORDER BY id").fetchall():
        folded = outcome in _FAIL_OUTCOMES and (kind == "client" or ('"count":' in details and '"minute":' in details))
        expired = ts < cut_main or (folded and ts < cut_fail)
        if expired:
            if cur_run is None:
                cur_run = [rid, rid, row_hash, 1]
            else:
                cur_run[1], cur_run[2], cur_run[3] = rid, row_hash, cur_run[3] + 1
        elif cur_run is not None:
            runs.append(cur_run)
            cur_run = None
    if cur_run is not None:
        runs.append(cur_run)
    if not runs:
        return 0
    total = 0
    # Delete and record in the same transaction, so a gap never exists without its prune row.
    for start in range(0, len(runs), PRUNE_RUNS_PER_ROW):
        chunk = runs[start:start + PRUNE_RUNS_PER_ROW]
        details = {"runs": [{"from_id": r[0], "through_id": r[1], "last_hash": r[2], "count": r[3]} for r in chunk]}
        for r in chunk:
            conn.execute("DELETE FROM audit WHERE id BETWEEN ? AND ?", (r[0], r[1]))
            total += r[3]
        _insert(conn, now, "system", "audit", "prune", "", "ok", canonical_json(details).decode("utf-8"))
    return total


# ---- pending-audit.jsonl ------------------------------------------------------------------------
def _loginuid():
    try:
        with open("/proc/self/loginuid") as f:
            value = f.read().strip()
        return "unknown" if not value.isdigit() or int(value) == 4294967295 else value
    except OSError:
        return "unknown"


def is_scheduled_run(cgroup_file="/proc/self/cgroup"):
    """True when this process runs in the cgroup of edr-hub-backup.service (nothing on the command line decides)."""
    try:
        with open(cgroup_file, encoding="utf-8", errors="replace") as f:
            return any(line.rstrip("\n").rsplit("/", 1)[-1] == BACKUP_UNIT for line in f)
    except OSError:
        return False


def append_pending(paths, operation, target, outcome, scheduled=False, op_id=None):
    """Append one line to pending-audit.jsonl (root CLI, no hub needed). Returns the operation id.

    Call it with outcome "started" before the operation and again with its outcome ("ok", "error" or
    "refused"), passing the same op_id. The file is opened append-only and never rewritten.
    """
    op_id = op_id or secrets.token_hex(6)
    line = {
        "id": secrets.token_hex(8),
        "op_id": op_id,
        "ts": now_ms(),
        "op": str(operation),
        "target": str(target),
        "outcome": str(outcome),
        "uid": os.getuid(),
        "sudo_user": os.environ.get("SUDO_USER", ""),
        "loginuid": _loginuid(),
        "scheduled": bool(scheduled),
    }
    data = (json.dumps(line, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
    path = paths.pending_audit
    os.makedirs(os.path.dirname(path), exist_ok=True)
    existed = os.path.exists(path)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o640)
    try:
        if not existed and os.geteuid() == 0:
            try:
                import grp
                os.fchown(fd, 0, grp.getgrnam("edr-hub").gr_gid)
            except (KeyError, OSError, ImportError):
                pass
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return op_id


def _outcome_of(phase):
    return {"started": "ok", "ok": "ok", "error": "error", "refused": "denied"}.get(phase, "invalid")


def _notice(conn, hub, action, detail, actor):
    """A HIGH admin notice that never stops the ingest (the row is already in the chain)."""
    try:
        conn.execute("SAVEPOINT audit_notice")
        try:
            _alerts().admin_notice(conn, hub, action, detail, actor)
            conn.execute("RELEASE audit_notice")
        except Exception:
            conn.execute("ROLLBACK TO audit_notice")
            conn.execute("RELEASE audit_notice")
            raise
    except Exception as exc:                       # alerts missing or failing: say so, keep going
        try:
            hub.log("error", "audit notice not queued: %s" % type(exc).__name__)
        except Exception:
            pass


class _Tick:
    """What one ingest has spent: bad lines are counted, not written one by one; notices have a budget."""

    def __init__(self):
        self.bad = 0
        self.notices = 0
        self.suppressed = 0

    def may_notify(self):
        if self.notices < PENDING_NOTICES_PER_TICK:
            self.notices += 1
            return True
        self.suppressed += 1
        return False


def _ingest_line(conn, hub, raw, tick):
    try:
        item = json.loads(raw.decode("utf-8"))
        if not isinstance(item, dict):
            raise ValueError("not an object")
        line_id = str(item["id"])[:64]
        op = clean(str(item["op"]), 40)
        phase = clean(str(item.get("outcome", "")), 16)
        ts = int(item.get("ts") or now_ms())
    except (ValueError, KeyError, TypeError, UnicodeDecodeError, RecursionError):
        tick.bad += 1
        return 0
    if conn.execute("SELECT 1 FROM pending_audit_seen WHERE line_id=?", (line_id,)).fetchone():
        return 0
    conn.execute("INSERT INTO pending_audit_seen (line_id, ts) VALUES (?, ?)", (line_id, now_ms()))
    uid = clean(str(item.get("uid", "")), 12)
    sudo = clean(str(item.get("sudo_user", "")), 40) or "-"
    loginuid = clean(str(item.get("loginuid", "unknown")), 12)
    scheduled = bool(item.get("scheduled")) and op == "backup"
    target = clean(str(item.get("target", "")), 200)
    actor = "file-op uid=%s sudo=%s loginuid=%s" % (uid, sudo, loginuid)
    details = {"op_id": clean(str(item.get("op_id", "")), 24), "phase": phase, "line_id": line_id,
               "line_ts": ts, "scheduled": scheduled}
    row_ts = ts if 0 < ts <= now_ms() else now_ms()          # the time of the operation, not of the ingest
    _insert(conn, row_ts, "cli", actor, "file-op." + op, target, _outcome_of(phase),
            canonical_json(details).decode("utf-8"))
    notify = False
    if phase == "started":
        notify = True
        if scheduled:
            last = _meta_get(conn, "last_scheduled_backup_ts")
            notify = last is not None and last.lstrip("-").isdigit() and ts - int(last) < SCHEDULED_GAP_MS
            _meta_set(conn, "last_scheduled_backup_ts", ts)
    elif phase != "ok" and not scheduled:
        notify = True                              # a failed or refused file operation is worth a second page
    if notify and tick.may_notify():
        verb = {"started": "started", "ok": "done", "error": "failed", "refused": "refused"}.get(phase, phase)
        _notice(conn, hub, op, "%s %s: %s" % (op, verb, target), actor)
    return 1


def _open_trusted(path, installed):
    """The pending-audit file as a descriptor, or None with the reason. PLAN 5: root:edr-hub 0640, only root appends.

    The directory belongs to the edr-hub user, who could unlink the file and make its own, so the file itself is
    checked: a regular file (opened without following a link), owned by root, with no group or other write bit.
    A dev run (the state directory is not the installed one) also accepts the hub's own uid as owner.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None, None
    except OSError:
        return None, "it is a link or cannot be opened"
    try:
        st = os.fstat(fd)
        owners = (0,) if installed else (0, os.getuid())
        if not stat.S_ISREG(st.st_mode):
            reason = "it is not a regular file"
        elif st.st_uid not in owners:
            reason = "it is not owned by root"
        elif st.st_mode & 0o022:
            reason = "it is writable by group or others"
        else:
            return fd, None
    except OSError:
        reason = "it cannot be checked"
    os.close(fd)
    return None, reason


def _untrusted_once_a_day(conn, hub, reason):
    today = _day_of(now_ms())
    if _meta_get(conn, "pending_audit_untrusted_day") == today:
        return
    _meta_set(conn, "pending_audit_untrusted_day", today)
    _insert(conn, now_ms(), "system", "audit", "pending-audit.untrusted", "", "denied",
            canonical_json({"reason": reason}).decode("utf-8"))
    _notice(conn, hub, "pending-audit", "pending-audit.jsonl is not trustworthy and was not read: %s" % reason, "system")


def ingest_pending(conn, hub):
    """Take new lines of pending-audit.jsonl into the chain. Returns the number of lines ingested.

    Called at start and at every writer tick. Only complete lines are read; the offset is kept in
    meta; a line id seen before is ignored, so an older restored database ingests nothing twice.
    One call takes at most 200 lines, writes one summary row for the bad ones (over 4 KiB, or not a
    JSON object with an id and an op) and sends at most 10 notices, then one summary notice.
    """
    flush_folds(conn)
    _daily_prune(conn)
    path = hub.paths.pending_audit
    fd, reason = _open_trusted(path, hub.paths.state_dir == HUB_INSTALLED_STATE)
    if fd is None:
        if reason:
            _untrusted_once_a_day(conn, hub, reason)
        return 0
    try:
        size = os.fstat(fd).st_size
        offset = int(_meta_get(conn, "pending_audit_offset", "0") or 0)
        if size < offset:
            offset = 0                             # the file was replaced; the seen table stops repeats
        if size == offset:
            return 0
        chunk = os.pread(fd, PENDING_READ_MAX, offset)
    except OSError:
        return 0
    finally:
        os.close(fd)
    end = chunk.rfind(b"\n")
    if end < 0:
        if len(chunk) >= PENDING_LINE_MAX:         # a runaway line with no newline: skip it
            _meta_set(conn, "pending_audit_offset", offset + len(chunk))
            _insert(conn, now_ms(), "system", "audit", "pending-audit.bad-line", "", "invalid", '{"count":1}')
        return 0
    tick = _Tick()
    count = lines = used = 0
    for raw in chunk[:end + 1].split(b"\n")[:-1]:
        if lines >= PENDING_LINES_PER_TICK:
            break                                  # the rest waits for the next tick
        used += len(raw) + 1
        raw = raw.strip()
        if not raw:
            continue
        lines += 1
        if len(raw) > PENDING_LINE_MAX:
            tick.bad += 1
            continue
        count += _ingest_line(conn, hub, raw, tick)
    _meta_set(conn, "pending_audit_offset", offset + used)
    if tick.bad:
        _insert(conn, now_ms(), "system", "audit", "pending-audit.bad-line", "", "invalid",
                canonical_json({"count": tick.bad}).decode("utf-8"))
    if tick.suppressed:
        _notice(conn, hub, "pending-audit", "%d more root-only file operations were ingested without their own notice: "
                "see `edr-hub audit`" % tick.suppressed, "system")
    return count


def _daily_prune(conn):
    last = _meta_get(conn, "audit_last_prune", "0")
    now = now_ms()
    if last.isdigit() and now - int(last) < 24 * 3600 * 1000:
        return
    _meta_set(conn, "audit_last_prune", now)
    prune(conn, now)
