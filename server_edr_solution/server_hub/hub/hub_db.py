"""The hub database: the one writer thread, migrations, retention, pruning, the storage-full path
(PLAN.md section 3). Standard library only.

Rules this module keeps:
- Exactly one write connection, owned by the Writer thread. Everybody else reads with open_ro().
- Every handler waits for the commit of its work (synchronous=FULL), because a client deletes its spool
  on the reply.
- Times are epoch milliseconds and retention uses received_at, never the client's ts.
- The write connection is never closed while the hub runs: a read-only reader cannot open a WAL
  database whose last connection closed cleanly (section 3, Dashboard reader).
"""

import json
import os
import queue
import sqlite3
import threading
import time
import urllib.parse
from datetime import datetime, timezone

import hub_common
import hub_schema

DAY_MS = 86_400_000
IDLE_TICK_S = 10.0
GROUP_MAX_ITEMS = 64
PRUNE_BATCH = 10_000
PRUNE_START = 0.90                 # prune from 90% of the cap
PRUNE_TARGET = 0.85                # and go down to 85%
PIN_FRACTION = 0.10                # events pinned by incidents may use 10% of the cap
ROW_BYTES = 875                    # measured bytes per event row with three indexes (section 3, Sizing)
VACUUM_PAGES = 2000
OVERFLOW_MAX_BYTES = 20 * 1024 * 1024
QUICK_CHECK_EVERY_MS = 7 * DAY_MS
MIN_CAP_BYTES = 64 * 1024

RAW_LOW_DAYS = 7
HIGH_DAYS = 180
DAILY_COUNTS_DAYS = 365
INCIDENT_DAYS = 365
SETTINGS_HISTORY_DAYS = 3 * 365

LOW_SEVERITIES = ("INFO", "LOW")


class Busy(Exception):
    """The writer queue is full or the call timed out."""


class StorageFull(Exception):
    """The database or the disk is full after the emergency prune, or the database failed its check."""


class _NeedPrune(Exception):
    """Internal: an item hit 'database or disk is full' inside a group."""


class SchemaTooNew(Exception):
    """meta.schema_version is newer than this code knows. The hub refuses to start."""


# Migration steps: {from_version: fn(conn)}. Each step runs in its own transaction and moves the
# database from N to N+1. SCHEMA_VERSION is 1, so there are none yet.
MIGRATIONS = {}


# ---- small helpers ------------------------------------------------------------------------------
def open_ro(db_path):
    """A read-only connection for the dashboard, the CLI and the engine. The caller closes it."""
    uri = "file:%s?mode=ro" % urllib.parse.quote(os.path.abspath(db_path))
    conn = sqlite3.connect(uri, uri=True, timeout=5.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def meta_get(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return default if row is None else row[0]


def meta_set(conn, key, value):
    conn.execute("INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (key, str(value)))


def _meta_int(conn, key, default=0):
    try:
        return int(meta_get(conn, key, default))
    except (TypeError, ValueError):
        return default


def is_full_error(exc):
    text = str(exc).lower()
    return isinstance(exc, sqlite3.OperationalError) and ("database or disk is full" in text or "disk i/o error" in text
                                                            or "database is full" in text)


def page_cap(db_size_cap_bytes, page_size):
    return max(MIN_CAP_BYTES, db_size_cap_bytes) // page_size


def db_size_bytes(conn, db_path=None):
    """(page_count - freelist_count) x page_size + WAL. Not the file size, which does not shrink."""
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    pages = conn.execute("PRAGMA page_count").fetchone()[0]
    free = conn.execute("PRAGMA freelist_count").fetchone()[0]
    size = (pages - free) * page_size
    if db_path:
        try:
            size += os.path.getsize(db_path + "-wal")
        except OSError:
            pass
    return size


# ---- opening, creating, migrating ----------------------------------------------------------------
def init_database(paths, max_db_size_bytes):
    """Open the write connection, set the pragmas in the order section 3 requires, create the schema on a
    new file and migrate an old one. Returns the connection (autocommit mode, row_factory Row)."""
    db_path = paths.db
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    new_file = (not os.path.exists(db_path)) or os.path.getsize(db_path) == 0
    if new_file:
        # The file is created 0640 before SQLite touches it, so -wal and -shm inherit the mode.
        fd = os.open(db_path, os.O_WRONLY | os.O_CREAT, 0o640)
        os.close(fd)
    conn = sqlite3.connect(db_path, timeout=5.0, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        if new_file:
            for pragma in hub_schema.PRAGMAS_NEW_FILE:       # auto_vacuum before WAL, before the first CREATE
                conn.execute(pragma).fetchall()
        for pragma in hub_schema.PRAGMAS_WRITER:
            conn.execute(pragma).fetchall()
        if new_file:
            conn.executescript("BEGIN IMMEDIATE;\n" + hub_schema.DDL +
                               "\nINSERT INTO meta(key, value) VALUES('schema_version', '%d');\nCOMMIT;"
                               % hub_schema.SCHEMA_VERSION)
        else:
            _migrate(conn)
            if conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 0:
                # An existing database made with auto_vacuum 0 needs this once, outside a transaction.
                conn.execute("PRAGMA auto_vacuum=INCREMENTAL").fetchall()
                conn.execute("VACUUM")
        page_size = conn.execute("PRAGMA page_size").fetchone()[0]
        conn.execute("PRAGMA max_page_count=%d" % page_cap(max_db_size_bytes, page_size)).fetchall()
    except BaseException:
        conn.close()
        raise
    return conn


def _migrate(conn):
    try:
        have = int(meta_get(conn, "schema_version", "0"))
    except (sqlite3.DatabaseError, ValueError) as e:
        raise sqlite3.DatabaseError("hub.db has no usable meta.schema_version") from e
    if have > hub_schema.SCHEMA_VERSION:
        raise SchemaTooNew("hub.db is schema %d, this hub knows %d: refusing to start" % (have, hub_schema.SCHEMA_VERSION))
    while have < hub_schema.SCHEMA_VERSION:
        step = MIGRATIONS.get(have)
        if step is None:
            raise sqlite3.DatabaseError("no migration from schema %d" % have)
        conn.execute("BEGIN IMMEDIATE")
        try:
            step(conn)
            meta_set(conn, "schema_version", have + 1)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        have += 1


# ---- retention and pruning (run inside the writer's transaction) -----------------------------------
_PINNED = "id NOT IN (SELECT event_rowid FROM incident_events)"


def _rollup_and_delete(conn, ids):
    """Delete these events; LOW and INFO ones are first summed into daily_counts."""
    if not ids:
        return 0
    blob = json.dumps(ids)
    conn.execute(
        "INSERT INTO daily_counts(day, host, source, kind, count) "
        "SELECT strftime('%Y-%m-%d', received_at/1000, 'unixepoch'), host, source, kind, SUM(count) "
        "FROM events WHERE id IN (SELECT value FROM json_each(?)) AND hub_severity IN ('INFO','LOW') "
        "GROUP BY 1, 2, 3, 4 "
        "ON CONFLICT(day, host, source, kind) DO UPDATE SET count = count + excluded.count", (blob,))
    conn.execute("DELETE FROM events WHERE id IN (SELECT value FROM json_each(?))", (blob,))
    return len(ids)


def _delete_where(conn, where, params, limit=PRUNE_BATCH):
    """One batch: oldest first, never an event pinned by an incident. Returns rows deleted."""
    rows = conn.execute("SELECT id FROM events WHERE %s AND %s ORDER BY id LIMIT ?" % (where, _PINNED),
                        tuple(params) + (limit,)).fetchall()
    return _rollup_and_delete(conn, [r[0] for r in rows])


def prune_retention(conn, now_ms, retention_days, max_batches=100):
    """Time-based retention. Returns the number of event rows deleted."""
    total = 0
    tiers = (
        ("hub_severity IN ('INFO','LOW') AND received_at < ?", now_ms - RAW_LOW_DAYS * DAY_MS),
        ("hub_severity = 'MEDIUM' AND received_at < ?", now_ms - int(retention_days) * DAY_MS),
        ("hub_severity IN ('HIGH','CRITICAL') AND received_at < ?", now_ms - HIGH_DAYS * DAY_MS),
    )
    for where, cutoff in tiers:
        for _ in range(max_batches):
            n = _delete_where(conn, where, (cutoff,))
            total += n
            if n < PRUNE_BATCH:
                break
    return total


def prune_tables(conn, now_ms):
    """The small tables of section 3 (Retention). The audit chain is left alone: cutting it is hub_audit's job."""
    conn.execute("DELETE FROM daily_counts WHERE day < ?",
                 (datetime.fromtimestamp((now_ms - DAILY_COUNTS_DAYS * DAY_MS) / 1000, timezone.utc).strftime("%Y-%m-%d"),))
    conn.execute("DELETE FROM heartbeat_samples WHERE received_at < ?", (now_ms - DAY_MS,))
    conn.execute("DELETE FROM tokens WHERE expires_at < ?", (now_ms - 30 * DAY_MS,))
    conn.execute("DELETE FROM login_codes WHERE expires < ?", (now_ms - DAY_MS,))
    conn.execute("DELETE FROM outbox WHERE state='sent' AND sent_at < ?", (now_ms - 30 * DAY_MS,))
    conn.execute("DELETE FROM outbox WHERE state='dead' AND created < ?", (now_ms - 30 * DAY_MS,))
    conn.execute("DELETE FROM settings_history WHERE ts < ?", (now_ms - SETTINGS_HISTORY_DAYS * DAY_MS,))
    conn.execute("DELETE FROM incidents WHERE state='resolved' AND closed_at IS NOT NULL AND closed_at < ?",
                 (now_ms - INCIDENT_DAYS * DAY_MS,))


def prune_pressure(conn, cap_bytes, db_path=None, max_batches=1000):
    """Pressure order (section 3): LOW older than 7 days, then any LOW, then MEDIUM older than 14 days.
    Never HIGH or CRITICAL. Past the 10% pin bound the oldest pinned LOW and MEDIUM rows are released first.
    Returns the number of event rows deleted."""
    now_ms = hub_common.now_ms()
    target = int(cap_bytes * PRUNE_TARGET)
    total = 0
    pinned = conn.execute("SELECT COUNT(DISTINCT event_rowid) FROM incident_events").fetchone()[0]
    if pinned * ROW_BYTES > cap_bytes * PIN_FRACTION:
        excess = pinned - int(cap_bytes * PIN_FRACTION / ROW_BYTES)
        rows = conn.execute(
            "SELECT DISTINCT e.id FROM events e JOIN incident_events ie ON ie.event_rowid = e.id "
            "WHERE e.hub_severity IN ('INFO','LOW','MEDIUM') ORDER BY e.id LIMIT ?", (excess,)).fetchall()
        if rows:
            conn.execute("DELETE FROM incident_events WHERE event_rowid IN (SELECT value FROM json_each(?))",
                         (json.dumps([r[0] for r in rows]),))
    steps = (
        ("hub_severity IN ('INFO','LOW') AND received_at < ?", (now_ms - RAW_LOW_DAYS * DAY_MS,)),
        ("hub_severity IN ('INFO','LOW')", ()),
        ("hub_severity = 'MEDIUM' AND received_at < ?", (now_ms - 14 * DAY_MS,)),
    )
    for where, params in steps:
        for _ in range(max_batches):
            if db_size_bytes(conn, db_path) <= target:
                return total
            n = _delete_where(conn, where, params)
            total += n
            if n == 0:
                break
    return total


def emergency_prune(conn):
    """One emergency prune: the 10,000 oldest LOW and INFO events (rolled up first)."""
    return _delete_where(conn, "hub_severity IN ('INFO','LOW')", ())


# ---- the writer ------------------------------------------------------------------------------------
class _Item:
    __slots__ = ("fn", "done", "result", "exc", "state", "lock")

    def __init__(self, fn):
        self.fn = fn
        self.done = threading.Event()
        self.result = None
        self.exc = None
        self.state = "pending"            # pending | running | cancelled | done
        self.lock = threading.Lock()


class Writer:
    """The single writer thread and its bounded queue (256 items).

    `hub` needs: paths, settings (dict), log(level, text) and stopping (Event); it may also carry
    `memory_alert(severity, kind, summary)` for alerts that must be sent when the database cannot take a write.
    """

    def __init__(self, hub):
        self.hub = hub
        self.paths = hub.paths
        self.q = queue.Queue(maxsize=hub_common.WRITER_QUEUE)
        self.conn = None
        self.thread = None
        self._stop = False
        self.state = "stopped"            # ok | storage_full | corrupt | stopped
        self.state_detail = ""
        self.unclean_start = False
        self._overflow_lock = threading.Lock()
        self._overflow_replayer = None
        self._last_daily_check = 0.0
        self._last_marker = float("-inf")
        self._truncate_wanted = False
        self._post_commit = []
        self._marker_mtime = None
        self._applied_cap = None

    @property
    def cap_bytes(self):
        try:
            return hub_common.parse_size(self.hub.settings.get("max_db_size", "2G"))
        except ValueError:
            return hub_common.parse_size("2G")

    def _apply_cap(self, conn):
        """max_page_count is per connection: set it at open and again when max_db_size changes."""
        cap = self.cap_bytes
        if cap != self._applied_cap:
            page_size = conn.execute("PRAGMA page_size").fetchone()[0]
            conn.execute("PRAGMA max_page_count=%d" % page_cap(cap, page_size)).fetchall()
            self._applied_cap = cap

    # -- lifecycle --
    def start(self):
        """Open and migrate the database, then start the thread. Raises SchemaTooNew or a sqlite error."""
        self.conn = init_database(self.paths, self.cap_bytes)
        self._applied_cap = self.cap_bytes
        now = hub_common.now_ms()
        started = _meta_int(self.conn, "hub_started_at", 0)
        stopped = _meta_int(self.conn, "hub_stopped_at", 0)
        self.unclean_start = started > 0 and stopped < started
        self.conn.execute("BEGIN IMMEDIATE")
        meta_set(self.conn, "hub_started_at", now)
        meta_set(self.conn, "writer_tick", now)
        self.conn.execute("COMMIT")
        self.state = "ok"
        self.thread = threading.Thread(target=self._run, name="hub-writer", daemon=True)
        self.thread.start()
        if self.unclean_start:
            self.post(lambda conn: self._quick_check(conn, "unclean start"))

    def stop(self, close=False):
        """Flush the queue, checkpoint, record a clean stop. The connection stays open unless close=True."""
        if self.thread is None:
            return
        self._stop = True
        self.q.put(None)
        self.thread.join(timeout=30)
        self.thread = None
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            meta_set(self.conn, "hub_stopped_at", hub_common.now_ms())
            self.conn.execute("COMMIT")
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        except sqlite3.Error as e:
            self.hub.log("ERROR", "writer stop: %s" % e)
        self.state = "stopped"
        if close:
            self.conn.close()

    def status(self):
        """For `edr-hub status`: state ok | storage_full | corrupt, and what the database weighs."""
        info = {"state": self.state, "detail": self.state_detail, "queue": self.q.qsize(), "cap_bytes": self.cap_bytes}
        return info

    # -- the API the other hub modules use --
    def call(self, fn, timeout=10.0):
        """Run fn(conn) in the writer's transaction and return its result after the commit."""
        if self.thread is not None and threading.current_thread() is self.thread:
            return self._run_one(fn)
        item = self._enqueue(fn)
        if not item.done.wait(timeout):
            with item.lock:
                if item.state == "pending":
                    item.state = "cancelled"
                    raise Busy("writer timeout")
            item.done.wait(timeout)       # already running: it finishes within one transaction
        if item.exc is not None:
            raise item.exc
        return item.result

    def post(self, fn):
        """Like call() without waiting. Errors are logged. Raises Busy when the queue is full."""
        def logged(conn):
            try:
                return fn(conn)
            except Exception as e:      # noqa: BLE001 - logged, never raised into the writer loop
                self.hub.log("ERROR", "posted writer job failed: %s" % type(e).__name__)
        self._enqueue(logged)

    def _enqueue(self, fn):
        if self._stop or self.thread is None:
            raise Busy("writer is not running")
        item = _Item(fn)
        try:
            self.q.put_nowait(item)
        except queue.Full:
            raise Busy("writer queue full") from None
        return item

    def _run_one(self, fn):
        self.conn.execute("SAVEPOINT inner_call")
        try:
            result = fn(self.conn)
        except BaseException:
            self.conn.execute("ROLLBACK TO inner_call")
            self.conn.execute("RELEASE inner_call")
            raise
        self.conn.execute("RELEASE inner_call")
        return result

    # -- the loop --
    def _run(self):
        """The loop. Periodic jobs (audit ingest, overflow replay, backup marker, daily job) run on their own
        schedule, every IDLE_TICK_S, inside the next transaction whatever the queue load: a busy queue (the engine
        ticks every 10 s) must not starve them. meta.writer_tick is stamped by every commit, so at least that often."""
        conn = self.conn
        next_periodic = time.monotonic() + IDLE_TICK_S
        while True:
            hub_common.sd_notify("WATCHDOG=1")
            try:
                first = self.q.get(timeout=max(0.0, next_periodic - time.monotonic()))
            except queue.Empty:
                first = "idle"
            if first is None:
                self._drain_on_stop()
                return
            items = [] if first == "idle" else [first]
            while len(items) < GROUP_MAX_ITEMS:
                try:
                    nxt = self.q.get_nowait()
                except queue.Empty:
                    break
                if nxt is None:
                    self._stop = True
                    break
                items.append(nxt)
            due = time.monotonic() >= next_periodic
            if due:
                next_periodic = time.monotonic() + IDLE_TICK_S
            try:
                self._process_group(conn, items, idle=due)
            except Exception as e:      # noqa: BLE001 - keep the loop alive; the watchdog would otherwise fire
                self.hub.log("ERROR", "writer loop: %s: %s" % (type(e).__name__, e))
                for item in items:
                    if not item.done.is_set():
                        item.exc = StorageFull("writer failed") if is_full_error(e) else e
                        item.done.set()
            if self._stop:
                self._drain_on_stop()
                return

    def _drain_on_stop(self):
        items = []
        while True:
            try:
                nxt = self.q.get_nowait()
            except queue.Empty:
                break
            if nxt is not None:
                items.append(nxt)
        if items:
            self._process_group(self.conn, items, idle=False)

    def _process_group(self, conn, items, idle):
        live = []
        for item in items:
            with item.lock:
                if item.state == "cancelled":
                    item.done.set()
                    continue
                item.state = "running"
            live.append(item)
        if self.state == "corrupt":
            for item in live:
                item.exc = StorageFull("database failed its integrity check; writes are stopped")
                item.done.set()
            return
        now = hub_common.now_ms()
        try:
            self._apply_cap(conn)             # also a raised cap must take effect before the next write
        except sqlite3.Error:
            pass
        try:
            self._run_group(conn, live, idle, now)
        except _NeedPrune:
            # SQLite gave "database or disk is full" and may have rolled the whole transaction back. Make room
            # once, then run each call in a transaction of its own (a second failure is StorageFull).
            self._emergency_prune_tx(conn)
            for item in live:
                self._run_solo(conn, item, now)
        for item in live:
            item.fn = None                    # drop the closure: it may hold a client socket
            item.done.set()
        self._after_commit(conn, now, idle)

    @staticmethod
    def _rollback_all(conn):
        if conn.in_transaction:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass

    def _run_group(self, conn, live, idle, now):
        conn.execute("BEGIN IMMEDIATE")
        try:
            for item in live:
                self._run_item(conn, item)
            if idle or not live:
                self._guarded_periodic(conn, now)
            meta_set(conn, "writer_tick", now)
            conn.execute("COMMIT")
            actions, self._post_commit = self._post_commit, []
            for action in actions:
                action()
        except _NeedPrune:
            self._post_commit = []
            raise
        except BaseException as e:
            self._post_commit = []
            self._rollback_all(conn)
            if is_full_error(e):
                self._set_state("storage_full", str(e))
            for item in live:
                item.exc = StorageFull("storage full") if is_full_error(e) else e
                item.result = None
            if not isinstance(e, Exception):
                raise
            return
        if live and self.state == "storage_full":
            self._set_state("ok", "")

    def _run_item(self, conn, item):
        conn.execute("SAVEPOINT item")
        try:
            item.result = item.fn(conn)
            conn.execute("RELEASE item")
            item.exc = None
        except BaseException as e:      # noqa: BLE001 - re-raised in the caller's thread
            if is_full_error(e):
                self._rollback_all(conn)
                raise _NeedPrune() from e
            if conn.in_transaction:
                conn.execute("ROLLBACK TO item")
                conn.execute("RELEASE item")
            item.exc = e
            item.result = None

    def _emergency_prune_tx(self, conn):
        try:
            conn.execute("BEGIN IMMEDIATE")
            emergency_prune(conn)
            conn.execute("COMMIT")
        except sqlite3.Error:
            self._rollback_all(conn)

    def _run_solo(self, conn, item, now):
        try:
            conn.execute("BEGIN IMMEDIATE")
            item.result = item.fn(conn)
            item.exc = None
            meta_set(conn, "writer_tick", now)
            conn.execute("COMMIT")
            if self.state == "storage_full":
                self._set_state("ok", "")
        except BaseException as e:      # noqa: BLE001
            self._rollback_all(conn)
            item.result = None
            if is_full_error(e):
                self._set_state("storage_full", str(e))
                item.exc = StorageFull("storage full")
            else:
                item.exc = e
                if not isinstance(e, Exception):
                    raise

    def _set_state(self, state, detail):
        if state != self.state:
            self.state = state
            self.state_detail = detail
            level = "ERROR" if state != "ok" else "INFO"
            self.hub.log(level, "storage state: %s%s" % (state, (" (%s)" % detail) if detail else ""))
            if state in ("storage_full", "corrupt"):
                alert = getattr(self.hub, "memory_alert", None)
                if alert:
                    try:
                        alert("CRITICAL", "hub.storage", "hub storage state: " + state)
                    except Exception:   # noqa: BLE001
                        pass

    # -- jobs between groups --
    def _guarded_periodic(self, conn, now):
        """The periodic jobs in a savepoint: if one fails, the calls in the same transaction still commit."""
        conn.execute("SAVEPOINT periodic")
        try:
            self._idle_jobs(conn, now)
            conn.execute("RELEASE periodic")
        except Exception as e:      # noqa: BLE001
            if not conn.in_transaction:
                if is_full_error(e):
                    raise _NeedPrune() from e       # SQLite rolled the whole transaction back: run the calls again
                raise
            conn.execute("ROLLBACK TO periodic")
            conn.execute("RELEASE periodic")
            if is_full_error(e):
                self._set_state("storage_full", str(e))
            else:
                self.hub.log("ERROR", "periodic jobs: %s: %s" % (type(e).__name__, e))

    def _idle_jobs(self, conn, now):
        """The periodic jobs: audit ingest, overflow replay, the last-backup marker, the daily job."""
        try:
            import hub_audit
        except ImportError:
            hub_audit = None
        if hub_audit is not None:
            conn.execute("SAVEPOINT audit_ingest")
            try:
                hub_audit.ingest_pending(conn, self.hub)
                conn.execute("RELEASE audit_ingest")
            except Exception as e:      # noqa: BLE001
                if not conn.in_transaction:
                    raise
                conn.execute("ROLLBACK TO audit_ingest")
                conn.execute("RELEASE audit_ingest")
                if is_full_error(e):
                    raise
                self.hub.log("ERROR", "audit ingest: %s: %s" % (type(e).__name__, e))
        self._replay_overflow(conn)
        self._read_backup_marker(conn)
        if self._daily_due(conn, now):
            self._daily_job(conn, now)

    def _after_commit(self, conn, now, idle):
        """Outside any transaction: checkpoint, size check, incremental vacuum."""
        try:
            self._apply_cap(conn)
            if self._truncate_wanted:
                self._truncate_wanted = False
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
            else:
                conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchall()
            size = db_size_bytes(conn, self.paths.db)
            if size >= self.cap_bytes * PRUNE_START and self.state != "corrupt":
                conn.execute("BEGIN IMMEDIATE")
                try:
                    n = prune_pressure(conn, self.cap_bytes, self.paths.db)
                    meta_set(conn, "last_prune", now)
                    conn.execute("COMMIT")
                    if n:
                        self.hub.log("WARN", "database near its cap: pruned %d events" % n)
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
            free = conn.execute("PRAGMA freelist_count").fetchone()[0]
            if free >= 256 or (idle and free > 0):
                # Every result must be fetched or nothing is freed (section 3, Pruning).
                conn.execute("PRAGMA incremental_vacuum(%d)" % VACUUM_PAGES).fetchall()
        except sqlite3.Error as e:
            if is_full_error(e):
                self._set_state("storage_full", str(e))
            else:
                self.hub.log("ERROR", "after commit: %s" % e)

    # -- daily job --
    def _daily_due(self, conn, now):
        try:
            hh, mm = [int(x) for x in str(self.hub.settings.get("daily_job_utc", "03:00")).split(":")]
        except ValueError:
            hh, mm = 3, 0
        dt = datetime.fromtimestamp(now / 1000, timezone.utc)
        slot = dt.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if dt < slot:
            return False
        return _meta_int(conn, "last_daily_job", 0) < int(slot.timestamp() * 1000)

    def run_daily_now(self):
        """For tests and `edr-hub`: run the daily job at once, in the writer."""
        return self.call(lambda conn: self._daily_job(conn, hub_common.now_ms()), timeout=60)

    def _daily_job(self, conn, now):
        days = int(self.hub.settings.get("retention_days", 30))
        deleted = prune_retention(conn, now, days)
        prune_tables(conn, now)
        meta_set(conn, "last_daily_job", now)
        meta_set(conn, "last_prune", now)
        if now - _meta_int(conn, "last_quick_check", 0) >= QUICK_CHECK_EVERY_MS:
            self._quick_check(conn, "weekly")
        self._truncate_wanted = True       # TRUNCATE cannot run inside a transaction: _after_commit does it
        return deleted

    def checkpoint_truncate(self):
        """wal_checkpoint(TRUNCATE) at the end of the next group (the daily job asks for it; tests may too)."""
        self._truncate_wanted = True
        self.call(lambda conn: None)

    def _quick_check(self, conn, why):
        """quick_check on a read-only connection. A failure stops writes and raises a CRITICAL from memory."""
        meta_set(conn, "last_quick_check", hub_common.now_ms())
        ro = None
        try:
            ro = open_ro(self.paths.db)
            rows = [r[0] for r in ro.execute("PRAGMA quick_check").fetchall()]
        except sqlite3.Error as e:
            rows = ["quick_check could not run: %s" % e]
        finally:
            if ro is not None:
                ro.close()
        if rows != ["ok"]:
            self._set_state("corrupt", "; ".join(str(r) for r in rows[:3]))
            self.hub.log("CRITICAL", "quick_check (%s) failed: %s" % (why, "; ".join(str(r) for r in rows[:3])))
        return rows == ["ok"]

    def _read_backup_marker(self, conn):
        now = time.monotonic()
        if now - self._last_marker < 30:
            return
        self._last_marker = now
        try:
            st = os.stat(self.paths.last_backup)
        except OSError:
            return
        if self._marker_mtime == st.st_mtime_ns:
            return
        self._marker_mtime = st.st_mtime_ns
        value = int(st.st_mtime * 1000)
        try:
            with open(self.paths.last_backup, encoding="utf-8") as f:
                text = f.read(64).strip()
            if text.isdigit():
                n = int(text)
                value = n if n > 10 ** 11 else n * 1000        # epoch ms or epoch seconds
        except (OSError, ValueError):
            pass
        meta_set(conn, "last_backup", value)

    # -- critical-overflow.jsonl (the storage-full path, section 3) --
    def overflow_append(self, records):
        """Append HIGH and CRITICAL event records to critical-overflow.jsonl (20 MB bound), synced.
        Returns True only when every line is on disk."""
        data = "".join(json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n" for r in records).encode()
        with self._overflow_lock:
            try:
                size = os.path.getsize(self.paths.critical_overflow)
            except OSError:
                size = 0
            if size + len(data) > OVERFLOW_MAX_BYTES:
                return False
            try:
                fd = os.open(self.paths.critical_overflow, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
                try:
                    os.write(fd, data)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError:
                return False
        return True

    def set_overflow_replayer(self, fn):
        """fn(conn, records: list[dict]) stores the records like a normal batch. Set by hub_ingest."""
        self._overflow_replayer = fn

    def _replay_overflow(self, conn):
        """Store the oldest overflow records. The file is trimmed only AFTER the commit (see _forget_overflow), so a
        failed commit loses nothing."""
        if self._overflow_replayer is None or self.state not in ("ok", "storage_full"):
            return
        try:
            with open(self.paths.critical_overflow, "rb") as f:
                raw = f.read(OVERFLOW_MAX_BYTES + 1)
        except OSError:
            return
        lines = raw.splitlines(keepends=True)[:500]
        if not lines:
            return
        records = []
        for line in lines:
            try:
                records.append(json.loads(line))
            except ValueError:
                pass
        conn.execute("SAVEPOINT replay")
        try:
            if records:
                self._overflow_replayer(conn, records)
            conn.execute("RELEASE replay")
        except Exception as e:      # noqa: BLE001
            conn.execute("ROLLBACK TO replay")
            conn.execute("RELEASE replay")
            if is_full_error(e):
                self._set_state("storage_full", str(e))
            else:
                self.hub.log("ERROR", "overflow replay failed, the file is set aside: %s: %s" % (type(e).__name__, e))
                try:
                    os.replace(self.paths.critical_overflow, self.paths.critical_overflow + ".bad")
                except OSError:
                    pass
            return
        self._post_commit.append(lambda n=sum(len(x) for x in lines): self._forget_overflow(n))
        if self.state == "storage_full":
            self._post_commit.append(lambda: self._set_state("ok", ""))      # the replay was the probe: space is back

    def _forget_overflow(self, nbytes):
        """Drop the first nbytes of the overflow file (what was replayed); lines appended since stay."""
        with self._overflow_lock:
            try:
                with open(self.paths.critical_overflow, "rb") as f:
                    data = f.read()
            except OSError:
                return
            rest = data[nbytes:]
            if rest.strip():
                hub_common.atomic_write(self.paths.critical_overflow, rest, 0o640)
            else:
                try:
                    os.unlink(self.paths.critical_overflow)
                except OSError:
                    pass


def safely(conn, hub, label, fn, *args):
    """Run fn(*args) inside its own savepoint. A failure rolls back only fn's writes and is logged; the caller's
    transaction goes on. For helper modules (engine, audit, alerts) that must not take an event or an enrollment down."""
    conn.execute("SAVEPOINT safely")
    try:
        result = fn(*args)
    except Exception as e:      # noqa: BLE001 - the point of this helper
        conn.execute("ROLLBACK TO safely")
        conn.execute("RELEASE safely")
        hub.log("ERROR", "%s failed: %s: %s" % (label, type(e).__name__, e))
        return None
    conn.execute("RELEASE safely")
    return result
