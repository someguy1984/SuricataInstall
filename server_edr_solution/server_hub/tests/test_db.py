"""The writer, pragmas, migrations, retention, pruning and the storage-full path (PLAN.md section 3; section 12 L0 row
"Storage")."""

import json
import os
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_ingest_fixture as F  # noqa: E402,F401  (puts the hub directory on sys.path, installs fakes if needed)

import hub_common  # noqa: E402
import hub_db  # noqa: E402
import hub_schema  # noqa: E402

DAY = 86_400_000


class FakeHub:
    def __init__(self, tmp, settings=None):
        self.paths = hub_common.Paths(state_dir=os.path.join(tmp, "state"), run_dir=os.path.join(tmp, "run"),
                                      etc_dir=os.path.join(tmp, "etc"))
        os.makedirs(self.paths.state_dir, exist_ok=True)
        self.settings = hub_common.default_settings()
        self.settings.update(settings or {})
        self.stopping = threading.Event()
        self.logs = []
        self.memory_alerts = []

    def log(self, level, message):
        self.logs.append((level, message))

    def memory_alert(self, severity, kind, summary):
        self.memory_alerts.append((severity, kind, summary))


_counter = [0]


def add_event(conn, sev="LOW", age_ms=0, count=1, host="h1", source="suricata", kind="suricata.alert", pad=0,
              received_at=None, rated_sev=None):
    _counter[0] += 1
    now = received_at if received_at is not None else hub_common.now_ms() - age_ms
    cur = conn.execute(
        "INSERT INTO events(host, event_id, received_at, ts, source, severity, hub_severity, kind, summary, epoch, seq, count) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (host, "%08x:%d" % (1, _counter[0]), now, now, source, sev, rated_sev or sev, kind, "x" * pad, 1, _counter[0], count))
    return cur.lastrowid


class _Rollback(Exception):
    pass


class DbCase(unittest.TestCase):
    settings = None

    def setUp(self):
        self.tmp = F.make_tmp("hubdb-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.hub = FakeHub(self.tmp, self.settings)
        self.writer = None

    def start(self, idle=None):
        if idle is not None:
            p = mock.patch.object(hub_db, "IDLE_TICK_S", idle)
            p.start()
            self.addCleanup(p.stop)
        self.writer = hub_db.Writer(self.hub)
        self.writer.start()
        self.addCleanup(self.writer.stop, True)
        return self.writer

    def rows(self, sql, params=()):
        ro = hub_db.open_ro(self.hub.paths.db)
        try:
            return [dict(r) for r in ro.execute(sql, params).fetchall()]
        finally:
            ro.close()

    def scratch(self, fn):
        """Run fn(conn) in the writer and roll it back; return what fn returned."""
        box = {}

        def job(conn):
            box["r"] = fn(conn)
            raise _Rollback()
        with self.assertRaises(_Rollback):
            self.writer.call(job)
        return box["r"]


class PragmaAndSchemaTest(DbCase):
    def test_pragmas_values_and_schema_version(self):
        w = self.start()
        c = w.conn
        self.assertEqual(c.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(c.execute("PRAGMA synchronous").fetchone()[0], 2)           # FULL
        self.assertEqual(c.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(c.execute("PRAGMA busy_timeout").fetchone()[0], 5000)
        self.assertEqual(c.execute("PRAGMA cache_size").fetchone()[0], -20000)
        self.assertEqual(c.execute("PRAGMA mmap_size").fetchone()[0], 0)
        self.assertEqual(c.execute("PRAGMA temp_store").fetchone()[0], 2)            # MEMORY
        self.assertEqual(c.execute("PRAGMA journal_size_limit").fetchone()[0], 1048576)
        self.assertEqual(c.execute("PRAGMA auto_vacuum").fetchone()[0], 2)           # INCREMENTAL
        page = c.execute("PRAGMA page_size").fetchone()[0]
        self.assertEqual(c.execute("PRAGMA max_page_count").fetchone()[0], hub_common.parse_size("2G") // page)
        self.assertEqual(hub_db.meta_get(c, "schema_version"), str(hub_schema.SCHEMA_VERSION))
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for t in ("meta", "hosts", "events", "daily_counts", "heartbeats", "tokens", "incidents", "outbox", "audit"):
            self.assertIn(t, tables)
        self.assertEqual(oct(os.stat(self.hub.paths.db).st_mode & 0o777), oct(0o640))

    def test_pragma_order_auto_vacuum_before_wal_before_first_table(self):
        trace = []
        real = sqlite3.connect

        def traced(*a, **k):
            conn = real(*a, **k)
            conn.set_trace_callback(trace.append)
            return conn
        with mock.patch.object(sqlite3, "connect", traced):
            conn = hub_db.init_database(self.hub.paths, hub_common.parse_size("2G"))
        conn.close()
        text = [t for t in trace]
        idx = lambda s: next(i for i, t in enumerate(text) if s in t)      # noqa: E731
        order = [idx("auto_vacuum=INCREMENTAL"), idx("journal_mode=WAL"), idx("synchronous=FULL"), idx("foreign_keys=ON"),
                 idx("busy_timeout=5000"), idx("cache_size=-20000"), idx("mmap_size=0"), idx("temp_store=MEMORY"),
                 idx("journal_size_limit=1048576"), idx("CREATE TABLE meta")]
        self.assertEqual(order, sorted(order), text[:12])

    def test_max_db_size_sets_max_page_count(self):
        self.settings = None
        self.hub.settings["max_db_size"] = "8M"
        w = self.start()
        page = w.conn.execute("PRAGMA page_size").fetchone()[0]
        self.assertEqual(w.conn.execute("PRAGMA max_page_count").fetchone()[0], (8 << 20) // page)

    def test_ro_connection_cannot_write(self):
        self.start()
        ro = hub_db.open_ro(self.hub.paths.db)
        try:
            self.assertEqual(ro.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()["value"], "1")
            with self.assertRaises(sqlite3.OperationalError):
                ro.execute("INSERT INTO meta(key, value) VALUES('x','y')")
        finally:
            ro.close()

    def test_meta_helpers(self):
        w = self.start()
        self.assertIsNone(w.call(lambda c: hub_db.meta_get(c, "nope")))
        self.assertEqual(w.call(lambda c: hub_db.meta_get(c, "nope", "d")), "d")
        w.call(lambda c: hub_db.meta_set(c, "k", 5))
        w.call(lambda c: hub_db.meta_set(c, "k", 6))
        self.assertEqual(w.call(lambda c: hub_db.meta_get(c, "k")), "6")

    def test_auto_vacuum_zero_database_is_converted_once(self):
        path = self.hub.paths.db
        conn = sqlite3.connect(path)
        conn.executescript(hub_schema.DDL + "INSERT INTO meta(key, value) VALUES('schema_version', '1');")
        self.assertEqual(conn.execute("PRAGMA auto_vacuum").fetchone()[0], 0)
        conn.close()
        w = self.start()
        self.assertEqual(w.conn.execute("PRAGMA auto_vacuum").fetchone()[0], 2)

    def test_journal_mode_is_set_to_wal_again_after_a_restore_copy(self):
        w = self.start()
        w.call(lambda c: add_event(c))
        copy = os.path.join(self.tmp, "copy.db")
        w.conn.execute("VACUUM INTO ?", (copy,))
        probe = sqlite3.connect(copy)
        self.assertEqual(probe.execute("PRAGMA journal_mode").fetchone()[0], "delete")
        probe.close()
        w.stop(close=True)
        shutil.copyfile(copy, self.hub.paths.db)
        for ext in ("-wal", "-shm"):
            if os.path.exists(self.hub.paths.db + ext):
                os.unlink(self.hub.paths.db + ext)
        w2 = hub_db.Writer(self.hub)
        w2.start()
        self.addCleanup(w2.stop, True)
        self.assertEqual(w2.conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(w2.conn.execute("PRAGMA auto_vacuum").fetchone()[0], 2)


class MigrationTest(DbCase):
    def test_newer_database_is_refused(self):
        w = self.start()
        w.call(lambda c: hub_db.meta_set(c, "schema_version", hub_schema.SCHEMA_VERSION + 5))
        w.stop(close=True)
        with self.assertRaises(hub_db.SchemaTooNew):
            hub_db.Writer(self.hub).start()

    def test_migration_steps_run_one_transaction_each(self):
        w = self.start()
        w.stop(close=True)

        def step1(conn):
            conn.execute("CREATE TABLE extra1(x)")

        def step2(conn):
            conn.execute("CREATE TABLE extra2(x)")
        with mock.patch.object(hub_schema, "SCHEMA_VERSION", 3), \
                mock.patch.dict(hub_db.MIGRATIONS, {1: step1, 2: step2}):
            w2 = hub_db.Writer(self.hub)
            w2.start()
            self.addCleanup(w2.stop, True)
            self.assertEqual(hub_db.meta_get(w2.conn, "schema_version"), "3")
            names = {r[0] for r in w2.conn.execute("SELECT name FROM sqlite_master")}
            self.assertTrue({"extra1", "extra2"} <= names)

    def test_failed_migration_rolls_back_and_stops_the_start(self):
        w = self.start()
        w.stop(close=True)

        def bad(conn):
            conn.execute("CREATE TABLE half(x)")
            raise RuntimeError("boom")
        with mock.patch.object(hub_schema, "SCHEMA_VERSION", 2), mock.patch.dict(hub_db.MIGRATIONS, {1: bad}):
            with self.assertRaises(RuntimeError):
                hub_db.Writer(self.hub).start()
        probe = sqlite3.connect(self.hub.paths.db)
        self.assertEqual(probe.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0], "1")
        self.assertIsNone(probe.execute("SELECT 1 FROM sqlite_master WHERE name='half'").fetchone())
        probe.close()

    def test_missing_step_is_an_error(self):
        w = self.start()
        w.stop(close=True)
        with mock.patch.object(hub_schema, "SCHEMA_VERSION", 2):
            with self.assertRaises(sqlite3.DatabaseError):
                hub_db.Writer(self.hub).start()


class WriterQueueTest(DbCase):
    def test_call_returns_after_commit_and_result(self):
        w = self.start()
        rid = w.call(lambda c: add_event(c))
        self.assertEqual(rid, 1)
        self.assertEqual(len(self.rows("SELECT * FROM events")), 1)        # visible to a reader at once

    def test_exception_rolls_back_only_that_call_and_is_reraised(self):
        w = self.start()
        gate = threading.Event()
        started = threading.Event()

        def hold(conn):
            started.set()
            gate.wait(5)
        results = {}
        t0 = threading.Thread(target=lambda: w.call(hold))
        t0.start()
        started.wait(5)

        def good(conn):
            add_event(conn, kind="good")

        def bad(conn):
            add_event(conn, kind="bad")
            raise ValueError("nope")

        def run(name, fn):
            try:
                w.call(fn)
                results[name] = "ok"
            except ValueError:
                results[name] = "raised"
        ta = threading.Thread(target=run, args=("a", bad))
        tb = threading.Thread(target=run, args=("b", good))
        ta.start()
        tb.start()
        time.sleep(0.3)             # both are queued behind the held call: they share one transaction
        gate.set()
        for t in (t0, ta, tb):
            t.join(10)
        self.assertEqual(results, {"a": "raised", "b": "ok"})
        self.assertEqual([r["kind"] for r in self.rows("SELECT kind FROM events")], ["good"])

    def test_busy_when_the_queue_is_full_and_work_is_not_lost(self):
        w = self.start()
        gate = threading.Event()
        started = threading.Event()
        threading.Thread(target=lambda: w.call(lambda c: (started.set(), gate.wait(10))), daemon=True).start()
        started.wait(5)
        for _ in range(hub_common.WRITER_QUEUE):
            w.post(lambda c: add_event(c, kind="queued"))
        with self.assertRaises(hub_db.Busy):
            w.post(lambda c: None)
        with self.assertRaises(hub_db.Busy):
            w.call(lambda c: None, timeout=0.2)
        gate.set()
        deadline = time.time() + 20
        while time.time() < deadline and len(self.rows("SELECT 1 FROM events")) < hub_common.WRITER_QUEUE:
            time.sleep(0.05)
        self.assertEqual(len(self.rows("SELECT 1 FROM events")), hub_common.WRITER_QUEUE)

    def test_timeout_is_busy_and_a_cancelled_job_does_not_run(self):
        w = self.start()
        gate = threading.Event()
        started = threading.Event()
        threading.Thread(target=lambda: w.call(lambda c: (started.set(), gate.wait(10))), daemon=True).start()
        started.wait(5)
        ran = []
        with self.assertRaises(hub_db.Busy):
            w.call(lambda c: ran.append(1), timeout=0.2)
        gate.set()
        w.call(lambda c: None)
        self.assertEqual(ran, [])

    def test_post_errors_are_logged_not_raised(self):
        w = self.start()
        w.post(lambda c: 1 / 0)
        w.call(lambda c: None)
        self.assertTrue(any("ZeroDivisionError" in m for _l, m in self.hub.logs))

    def test_call_from_the_writer_thread_runs_inline(self):
        w = self.start()
        self.assertEqual(w.call(lambda c: w.call(lambda c2: 41) + 1), 42)

    def test_writer_tick_on_commit_and_idle(self):
        w = self.start(idle=0.2)
        first = int(self.rows("SELECT value FROM meta WHERE key='writer_tick'")[0]["value"])
        time.sleep(0.6)
        second = int(self.rows("SELECT value FROM meta WHERE key='writer_tick'")[0]["value"])
        self.assertGreater(second, first)                       # idle tick, no work queued
        before = second
        time.sleep(0.01)
        w.call(lambda c: None)
        third = int(self.rows("SELECT value FROM meta WHERE key='writer_tick'")[0]["value"])
        self.assertGreater(third, before)

    def test_idle_tick_feeds_the_watchdog_and_ingests_pending_audit(self):
        short = tempfile.mkdtemp(prefix="hubnotify-")          # a unix socket path must be short
        self.addCleanup(shutil.rmtree, short, True)
        sock_path = os.path.join(short, "n.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        srv.bind(sock_path)
        srv.settimeout(3)
        self.addCleanup(srv.close)
        calls = []
        stub = types.ModuleType("hub_audit")
        stub.ingest_pending = lambda conn, hub: calls.append((conn, hub)) or 0
        with mock.patch.dict(os.environ, {"NOTIFY_SOCKET": sock_path}), mock.patch.dict(sys.modules, {"hub_audit": stub}):
            self.start(idle=0.2)
            msgs = [srv.recv(100) for _ in range(3)]
            time.sleep(0.3)
        self.assertTrue(all(m == b"WATCHDOG=1" for m in msgs))
        self.assertGreaterEqual(len(calls), 2)
        self.assertIs(calls[0][1], self.hub)

    def test_unclean_start_is_detected_and_checked(self):
        w = self.start()
        self.assertFalse(w.unclean_start)
        w.thread = None             # simulate a kill: no stop(), no hub_stopped_at
        w._stop = True
        w.q.put(None)
        time.sleep(0.3)
        w.conn.close()
        w2 = hub_db.Writer(self.hub)
        w2.start()
        self.addCleanup(w2.stop, True)
        self.assertTrue(w2.unclean_start)
        w2.call(lambda c: None)
        deadline = time.time() + 5
        while time.time() < deadline and not self.rows("SELECT 1 FROM meta WHERE key='last_quick_check'"):
            time.sleep(0.05)
        self.assertTrue(self.rows("SELECT 1 FROM meta WHERE key='last_quick_check'"))
        w2.stop()
        w3 = hub_db.Writer(self.hub)
        w3.start()
        self.addCleanup(w3.stop, True)
        self.assertFalse(w3.unclean_start)


class BusyQueueTest(DbCase):
    """The periodic jobs run on their own schedule, whatever the load: the engine's call every 10 s must not starve
    them (scaled down here: a call every 0.1 s against a 0.3 s tick)."""

    def busy_for(self, w, seconds):
        stop = time.time() + seconds
        stamps = []
        while time.time() < stop:
            w.call(lambda c: None)
            stamps.append(time.time())
            time.sleep(0.1)
        return stamps

    def test_periodic_jobs_run_while_calls_arrive_all_the_time(self):
        self.hub.settings["daily_job_utc"] = "00:00"
        marker = self.hub.paths.last_backup
        calls = []
        stub = types.ModuleType("hub_audit")
        stub.ingest_pending = lambda conn, hub: calls.append(time.monotonic()) or 0
        with mock.patch.dict(sys.modules, {"hub_audit": stub}):
            w = self.start(idle=0.3)
            w.call(lambda c: add_event(c, "LOW", 9 * DAY))
            with open(marker, "w") as f:
                f.write("1795000000\n")
            overflow = []
            w.set_overflow_replayer(lambda conn, recs: overflow.extend(recs))
            w.overflow_append([{"host": "h1", "n": 1}])
            stamps = self.busy_for(w, 2.0)
        self.assertGreaterEqual(len(stamps), 12)                     # the queue never had a quiet second
        self.assertGreaterEqual(len(calls), 4, calls)                # audit ingest ran about every 0.3 s
        gaps = [b - a for a, b in zip(calls, calls[1:])]
        self.assertLess(max(gaps), 0.8, gaps)
        self.assertEqual(self.rows("SELECT value FROM meta WHERE key='last_backup'")[0]["value"], str(1795000000 * 1000))
        self.assertTrue(self.rows("SELECT 1 FROM meta WHERE key='last_daily_job'"))      # retention ran
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM events")[0]["n"], 0)       # and deleted the old LOW row
        self.assertEqual(overflow, [{"host": "h1", "n": 1}])                              # the overflow file was replayed

    def test_writer_tick_stays_fresh_under_load(self):
        w = self.start(idle=0.3)
        seen = []
        stop = time.time() + 1.5
        while time.time() < stop:
            w.call(lambda c: None)
            seen.append(int(self.rows("SELECT value FROM meta WHERE key='writer_tick'")[0]["value"]))
            time.sleep(0.05)
        self.assertGreater(seen[-1], seen[0])
        self.assertLess(hub_common.now_ms() - seen[-1], 1000)

    def test_a_failing_periodic_job_does_not_fail_the_calls_it_shares_a_transaction_with(self):
        stub = types.ModuleType("hub_audit")

        def boom(conn, hub):
            conn.execute("INSERT INTO meta(key, value) VALUES('half_done', '1')")
            raise RuntimeError("audit broke")
        stub.ingest_pending = boom
        with mock.patch.dict(sys.modules, {"hub_audit": stub}):
            w = self.start(idle=0.2)
            ok = 0
            stop = time.time() + 1.0
            while time.time() < stop:
                w.call(lambda c: add_event(c, "HIGH"))
                ok += 1
                time.sleep(0.05)
        self.assertGreater(ok, 5)
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM events")[0]["n"], ok)
        self.assertEqual(self.rows("SELECT 1 FROM meta WHERE key='half_done'"), [])      # the job's own writes rolled back


class RetentionTest(DbCase):
    def test_retention_tiers_and_rollup_sums_count(self):
        w = self.start()

        def fill(conn):
            add_event(conn, "LOW", 8 * DAY, count=3, host="h1", kind="k.a")
            add_event(conn, "INFO", 9 * DAY, count=4, host="h1", kind="k.a")
            add_event(conn, "LOW", 6 * DAY, count=1)
            add_event(conn, "MEDIUM", 31 * DAY)
            add_event(conn, "MEDIUM", 29 * DAY)
            add_event(conn, "HIGH", 181 * DAY)
            add_event(conn, "HIGH", 179 * DAY)
            add_event(conn, "CRITICAL", 100 * DAY)
            return hub_db.prune_retention(conn, hub_common.now_ms(), 30)
        deleted = w.call(fill)
        self.assertEqual(deleted, 4)                                        # 2 LOW/INFO, 1 MEDIUM, 1 HIGH
        sevs = sorted(r["hub_severity"] for r in self.rows("SELECT hub_severity FROM events"))
        self.assertEqual(sevs, sorted(["CRITICAL", "HIGH", "LOW", "MEDIUM"]))
        counts = self.rows("SELECT day, host, source, kind, count FROM daily_counts ORDER BY day")
        self.assertEqual(sum(r["count"] for r in counts), 7)                 # 3 + 4: sums count, not rows
        self.assertEqual({r["kind"] for r in counts}, {"k.a"})

    def test_rollup_adds_to_an_existing_daily_row(self):
        w = self.start()

        def go(conn):
            when = hub_common.now_ms() - 10 * DAY
            day = time.strftime("%Y-%m-%d", time.gmtime(when / 1000))
            conn.execute("INSERT INTO daily_counts VALUES(?,?,?,?,?)", (day, "h1", "suricata", "suricata.alert", 10))
            add_event(conn, "LOW", received_at=when, count=5)
            hub_db.prune_retention(conn, hub_common.now_ms(), 30)
        w.call(go)
        self.assertEqual(self.rows("SELECT count FROM daily_counts")[0]["count"], 15)

    def test_pinned_events_survive_retention(self):
        w = self.start()

        def go(conn):
            keep = add_event(conn, "LOW", 20 * DAY)
            gone = add_event(conn, "LOW", 20 * DAY)
            conn.execute("INSERT INTO incidents(host, chain, opened, updated, severity) VALUES('h1','c',1,1,'HIGH')")
            conn.execute("INSERT INTO incident_events VALUES(1, ?)", (keep,))
            hub_db.prune_retention(conn, hub_common.now_ms(), 30)
            return keep, gone
        keep, gone = w.call(go)
        ids = [r["id"] for r in self.rows("SELECT id FROM events")]
        self.assertEqual(ids, [keep])

    def test_retention_uses_received_at_not_the_client_ts(self):
        w = self.start()

        def go(conn):
            now = hub_common.now_ms()
            # a clock set to 2030 must not pin a row; a clock set to 2001 must not make a fresh row look old
            conn.execute("INSERT INTO events(host,event_id,received_at,ts,source,severity,hub_severity,kind,epoch,seq) "
                         "VALUES('h','1:1',?,?,'agent','LOW','LOW','k',1,1)", (now - 8 * DAY, now + 5 * 365 * DAY))
            conn.execute("INSERT INTO events(host,event_id,received_at,ts,source,severity,hub_severity,kind,epoch,seq) "
                         "VALUES('h','1:2',?,?,'agent','LOW','LOW','k',1,2)", (now, 1_000_000_000_000))
            hub_db.prune_retention(conn, now, 30)
        w.call(go)
        self.assertEqual([r["event_id"] for r in self.rows("SELECT event_id FROM events")], ["1:2"])

    def test_hub_rating_decides_the_tier(self):
        w = self.start()

        def go(conn):
            add_event(conn, "LOW", 20 * DAY, rated_sev="HIGH")           # the client said LOW, a rule rated it HIGH
            hub_db.prune_retention(conn, hub_common.now_ms(), 30)
        w.call(go)
        self.assertEqual(len(self.rows("SELECT * FROM events")), 1)

    def test_small_tables(self):
        w = self.start()

        def go(conn):
            now = hub_common.now_ms()
            conn.execute("INSERT INTO tokens(id,secret_sha256,created_at,expires_at) VALUES('old','x',1,?)", (now - 31 * DAY,))
            conn.execute("INSERT INTO tokens(id,secret_sha256,created_at,expires_at) VALUES('new','x',1,?)", (now - 29 * DAY,))
            conn.execute("INSERT INTO login_codes(code_sha256,created,expires) VALUES('a',1,?)", (now - 2 * DAY,))
            conn.execute("INSERT INTO login_codes(code_sha256,created,expires) VALUES('b',1,?)", (now - 1000,))
            conn.execute("INSERT INTO outbox(created,channel,severity,payload,next_try,state,sent_at) VALUES(1,'ntfy','HIGH','{}',1,'sent',?)", (now - 31 * DAY,))
            conn.execute("INSERT INTO outbox(created,channel,severity,payload,next_try,state,sent_at) VALUES(1,'ntfy','HIGH','{}',1,'sent',?)", (now - 1 * DAY,))
            conn.execute("INSERT INTO heartbeat_samples VALUES('h',?, '{}')", (now - 25 * 3600 * 1000,))
            conn.execute("INSERT INTO heartbeat_samples VALUES('h',?, '{}')", (now - 3600 * 1000,))
            conn.execute("INSERT INTO settings_history(ts,key) VALUES(?, 'a')", (now - 1200 * DAY,))
            conn.execute("INSERT INTO settings_history(ts,key) VALUES(?, 'b')", (now - 100 * DAY,))
            conn.execute("INSERT INTO incidents(host,chain,opened,updated,severity,state,closed_at) VALUES('h','c',1,1,'HIGH','resolved',?)", (now - 400 * DAY,))
            conn.execute("INSERT INTO incident_events VALUES(1, 99)")
            conn.execute("INSERT INTO incidents(host,chain,opened,updated,severity,state,closed_at) VALUES('h','d',1,1,'HIGH','resolved',?)", (now - 10 * DAY,))
            conn.execute("INSERT INTO daily_counts VALUES('2020-01-01','h','s','k',1)")
            conn.execute("INSERT INTO daily_counts VALUES(?,'h','s','k',1)", (time.strftime("%Y-%m-%d", time.gmtime()),))
            hub_db.prune_tables(conn, now)
        w.call(go)
        self.assertEqual([r["id"] for r in self.rows("SELECT id FROM tokens")], ["new"])
        self.assertEqual([r["code_sha256"] for r in self.rows("SELECT code_sha256 FROM login_codes")], ["b"])
        self.assertEqual(len(self.rows("SELECT 1 FROM outbox")), 1)
        self.assertEqual(len(self.rows("SELECT 1 FROM heartbeat_samples")), 1)
        self.assertEqual([r["key"] for r in self.rows("SELECT key FROM settings_history")], ["b"])
        self.assertEqual(len(self.rows("SELECT 1 FROM incidents")), 1)
        self.assertEqual(len(self.rows("SELECT 1 FROM incident_events")), 0)          # cascade
        self.assertEqual(len(self.rows("SELECT 1 FROM daily_counts")), 1)

    def test_daily_job_runs_once_at_its_time_and_asks_for_a_truncate(self):
        self.hub.settings["daily_job_utc"] = "00:00"
        w = self.start(idle=0.2)
        w.call(lambda c: add_event(c, "LOW", 9 * DAY))
        deadline = time.time() + 5
        while time.time() < deadline and not self.rows("SELECT 1 FROM meta WHERE key='last_daily_job'"):
            time.sleep(0.05)
        first = self.rows("SELECT value FROM meta WHERE key='last_daily_job'")
        self.assertTrue(first)
        self.assertEqual(len(self.rows("SELECT * FROM events")), 0)
        time.sleep(0.8)
        self.assertEqual(self.rows("SELECT value FROM meta WHERE key='last_daily_job'"), first)     # not again today
        self.assertTrue(self.rows("SELECT 1 FROM meta WHERE key='last_quick_check'"))              # weekly check ran
        self.assertFalse(w._truncate_wanted)

    def test_daily_job_waits_for_its_time(self):
        later = time.gmtime(time.time() + 3600)
        self.hub.settings["daily_job_utc"] = "%02d:%02d" % (later.tm_hour, later.tm_min)
        w = self.start(idle=0.2)
        time.sleep(0.7)
        if time.gmtime().tm_hour == later.tm_hour or later.tm_hour < time.gmtime().tm_hour:
            self.skipTest("run too close to midnight UTC")
        self.assertFalse(self.rows("SELECT 1 FROM meta WHERE key='last_daily_job'"))


class PressureTest(DbCase):
    def fill(self, conn):
        spec = (("LOW", 8 * DAY), ("LOW", 1 * DAY), ("MEDIUM", 20 * DAY), ("MEDIUM", 5 * DAY), ("HIGH", 30 * DAY),
                ("CRITICAL", 30 * DAY))
        for sev, age in spec:
            for _ in range(600):
                add_event(conn, sev, age, pad=300)

    def run_with(self, cap_of_size):
        w = self.start()
        w.call(self.fill)
        w.checkpoint_truncate()                     # the WAL term of the size is then small and steady

        def go(conn):
            size = hub_db.db_size_bytes(conn, self.hub.paths.db)
            cap = int(size / cap_of_size)
            deleted = hub_db.prune_pressure(conn, cap, self.hub.paths.db)
            return deleted, dict(conn.execute("SELECT hub_severity || CASE WHEN received_at < ? THEN '-old' ELSE '' END, COUNT(*) "
                                              "FROM events GROUP BY 1", (hub_common.now_ms() - 6 * DAY,)).fetchall())
        return self.scratch(go)

    def test_order_old_low_first(self):
        deleted, left = self.run_with(0.95)          # a little over the 90% line: old LOW is enough
        self.assertGreater(deleted, 0)
        self.assertNotIn("LOW-old", left)
        self.assertEqual(left.get("LOW"), 600)

    def test_order_then_any_low_then_old_medium_never_high(self):
        deleted, left = self.run_with(1.5)           # 40% of the size must go: LOW, then MEDIUM over 14 days
        self.assertNotIn("LOW-old", left)
        self.assertNotIn("LOW", left)
        self.assertNotIn("MEDIUM-old", left)
        self.assertEqual(left.get("MEDIUM"), 600)    # the 5-day MEDIUM is not older than 14 days
        self.assertEqual(left.get("HIGH-old"), 600)
        self.assertEqual(left.get("CRITICAL-old"), 600)

    def test_high_and_critical_are_never_pruned_even_when_over_the_cap(self):
        deleted, left = self.run_with(5.0)
        self.assertEqual(left.get("HIGH-old"), 600)
        self.assertEqual(left.get("CRITICAL-old"), 600)
        self.assertEqual(left.get("MEDIUM"), 600)

    def test_pins_past_ten_percent_of_the_cap_are_released_oldest_first(self):
        w = self.start()
        cap = 100 * 1024
        allowed = int(cap * hub_db.PIN_FRACTION / hub_db.ROW_BYTES)

        def go(conn):
            ids = [add_event(conn, "LOW", 9 * DAY, pad=300) for _ in range(40)]
            conn.execute("INSERT INTO incidents(host, chain, opened, updated, severity) VALUES('h1','c',1,1,'HIGH')")
            for i in ids:
                conn.execute("INSERT INTO incident_events VALUES(1, ?)", (i,))
            hub_db.prune_pressure(conn, cap, self.hub.paths.db)
            kept_pins = [r[0] for r in conn.execute("SELECT event_rowid FROM incident_events ORDER BY 1")]
            return ids, kept_pins
        ids, kept = self.scratch(go)
        self.assertEqual(len(kept), allowed)
        self.assertEqual(kept, ids[-allowed:])          # the newest pins stay, the oldest were released

    def test_size_accounting_excludes_free_pages_and_counts_the_wal(self):
        w = self.start()
        w.call(self.fill)
        w.call(lambda c: None)
        size_before = w.call(lambda c: hub_db.db_size_bytes(c, self.hub.paths.db))
        file_before = os.path.getsize(self.hub.paths.db)
        w.call(lambda c: c.execute("DELETE FROM events WHERE hub_severity IN ('LOW','MEDIUM')"))
        size_after = w.call(lambda c: hub_db.db_size_bytes(c, self.hub.paths.db))
        self.assertLess(size_after, size_before)
        def check(conn):
            wal = os.path.getsize(self.hub.paths.db + "-wal") if os.path.exists(self.hub.paths.db + "-wal") else 0
            page = conn.execute("PRAGMA page_size").fetchone()[0]
            pages = conn.execute("PRAGMA page_count").fetchone()[0]
            free = conn.execute("PRAGMA freelist_count").fetchone()[0]
            return hub_db.db_size_bytes(conn, self.hub.paths.db), (pages - free) * page + wal
        got, expected = w.call(check)
        self.assertEqual(got, expected)

    def test_incremental_vacuum_gives_pages_back(self):
        w = self.start()
        w.call(lambda c: [add_event(c, "LOW", 9 * DAY, pad=500) for _ in range(6000)])
        pages_full = w.call(lambda c: c.execute("PRAGMA page_count").fetchone()[0])
        w.call(lambda c: c.execute("DELETE FROM events"))
        w.call(lambda c: None)
        free = w.call(lambda c: c.execute("PRAGMA freelist_count").fetchone()[0])
        pages_after = w.call(lambda c: c.execute("PRAGMA page_count").fetchone()[0])
        self.assertLess(pages_after, pages_full)
        self.assertLess(free, 256)                      # the vacuum ran, with every result fetched

    def test_pressure_prune_runs_after_a_commit_near_the_cap(self):
        w = self.start()
        w.call(lambda c: [add_event(c, "LOW", 9 * DAY, pad=400) for _ in range(3000)])
        w.checkpoint_truncate()
        size = w.call(lambda c: hub_db.db_size_bytes(c, self.hub.paths.db))
        self.hub.settings["max_db_size"] = str(int(size / 0.95))
        w.call(lambda c: None)                          # the next group applies the cap and checks the size
        w.call(lambda c: None)
        left = len(self.rows("SELECT 1 FROM events"))
        self.assertLess(left, 3000)
        self.assertTrue(self.rows("SELECT 1 FROM meta WHERE key='last_prune'"))


class StorageFullTest(DbCase):
    def small_cap(self, w, extra_pages=6):
        page, pages = w.call(lambda c: (c.execute("PRAGMA page_size").fetchone()[0], c.execute("PRAGMA page_count").fetchone()[0]))
        self.hub.settings["max_db_size"] = str((pages + extra_pages) * page)
        w.call(lambda c: None)

    def test_emergency_prune_makes_room_and_the_insert_goes_through(self):
        w = self.start()
        self.small_cap(w, 40)
        # fill with old LOW rows until the cap bites; the emergency prune must free them, not fail the call
        for _ in range(400):
            w.call(lambda c: [add_event(c, "LOW", 9 * DAY, pad=900) for _ in range(5)])
            if self.rows("SELECT 1 FROM daily_counts"):
                break
        self.assertTrue(self.rows("SELECT 1 FROM daily_counts"), "the cap never bit")
        self.assertEqual(w.state, "ok")

    def test_still_full_after_the_emergency_prune_raises_storage_full(self):
        w = self.start()
        self.small_cap(w, 30)
        with self.assertRaises(hub_db.StorageFull):
            for _ in range(2000):
                w.call(lambda c: [add_event(c, "HIGH", 0, pad=900) for _ in range(5)])
        self.assertEqual(w.state, "storage_full")
        self.assertTrue(self.hub.memory_alerts)
        self.assertEqual(self.hub.memory_alerts[0][0], "CRITICAL")
        with self.assertRaises(hub_db.StorageFull):
            w.call(lambda c: add_event(c, "LOW", pad=900))
        with self.assertRaises(hub_db.StorageFull):
            w.call(lambda c: [add_event(c, "LOW", pad=900) for _ in range(20)])
        # deletes still work when the database is full (section 3)
        w.call(lambda c: c.execute("DELETE FROM events WHERE id IN (SELECT id FROM events LIMIT 50)"))
        # and the first successful write brings the state back
        w.call(lambda c: add_event(c, "HIGH", pad=10))
        self.assertEqual(w.state, "ok")
        self.assertEqual(status_of(w)["state"], "ok")

    def test_overflow_file_is_appended_bounded_and_replayed(self):
        w = self.start(idle=0.2)
        recs = [{"host": "h1", "event": {"id": "00000001:%d" % i}} for i in range(3)]
        self.assertTrue(w.overflow_append(recs))
        with open(self.hub.paths.critical_overflow) as f:
            lines = [json.loads(line) for line in f]
        self.assertEqual(lines, recs)
        self.assertEqual(oct(os.stat(self.hub.paths.critical_overflow).st_mode & 0o777), oct(0o640))
        got = []
        w.set_overflow_replayer(lambda conn, records: got.extend(records) or [add_event(conn, "HIGH") for _ in records])
        deadline = time.time() + 5
        while time.time() < deadline and os.path.exists(self.hub.paths.critical_overflow):
            time.sleep(0.05)
        self.assertEqual(got, recs)                                   # replayed once space is back (state ok)
        self.assertFalse(os.path.exists(self.hub.paths.critical_overflow))
        self.assertEqual(len(self.rows("SELECT 1 FROM events")), 3)

    def test_overflow_is_bounded_to_20mb(self):
        w = self.start()
        with mock.patch.object(hub_db, "OVERFLOW_MAX_BYTES", 300):
            self.assertTrue(w.overflow_append([{"a": "x" * 100}]))
            self.assertFalse(w.overflow_append([{"a": "y" * 400}]))
        self.assertEqual(hub_db.OVERFLOW_MAX_BYTES, 20 * 1024 * 1024)

    def test_overflow_append_failure_is_reported(self):
        w = self.start()
        os.mkdir(self.hub.paths.critical_overflow)          # a directory: the append must fail, not pretend
        self.assertFalse(w.overflow_append([{"a": 1}]))

    def test_overflow_replay_is_the_probe_while_storage_is_full(self):
        w = self.start(idle=0.2)
        w.overflow_append([{"host": "h1", "n": 1}])
        w.state = "storage_full"
        attempts = []

        def replayer(conn, recs):
            attempts.append(1)
            if len(attempts) < 3:
                raise sqlite3.OperationalError("database or disk is full")
            [add_event(conn, "HIGH") for _ in recs]
        w.set_overflow_replayer(replayer)
        deadline = time.time() + 5
        while time.time() < deadline and w.state != "ok":
            time.sleep(0.05)
        self.assertGreaterEqual(len(attempts), 3)                    # still full: kept and tried again
        self.assertEqual(w.state, "ok")                              # replayed: the space is back
        self.assertFalse(os.path.exists(self.hub.paths.critical_overflow))
        self.assertEqual(len(self.rows("SELECT 1 FROM events")), 1)

    def test_corrupt_state_never_replays(self):
        w = self.start(idle=0.2)
        w.overflow_append([{"host": "h1"}])
        w.state = "corrupt"
        got = []
        w.set_overflow_replayer(lambda conn, recs: got.extend(recs))
        time.sleep(0.8)
        self.assertEqual(got, [])
        w.state = "ok"


def status_of(w):
    return w.status()


class IntegrityTest(DbCase):
    def test_quick_check_ok(self):
        w = self.start()
        self.assertTrue(w.call(lambda c: w._quick_check(c, "test")))
        self.assertEqual(w.state, "ok")

    def test_failed_quick_check_stops_writes_and_alerts_from_memory(self):
        w = self.start()

        class Bad:
            def execute(self, sql):
                return types.SimpleNamespace(fetchall=lambda: [("*** in database main ***",)])

            def close(self):
                pass
        with mock.patch.object(hub_db, "open_ro", lambda path: Bad()):
            ok = w.call(lambda c: w._quick_check(c, "test"))
        self.assertFalse(ok)
        self.assertEqual(w.state, "corrupt")
        self.assertEqual(self.hub.memory_alerts[-1][0], "CRITICAL")
        with self.assertRaises(hub_db.StorageFull):
            w.call(lambda c: add_event(c))
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM events")[0]["n"], 0)

    def test_stop_flushes_and_records_clean_stop(self):
        w = self.start()
        for i in range(20):
            w.post(lambda c: add_event(c))
        w.stop()
        self.assertEqual(len(self.rows("SELECT 1 FROM events")), 20)
        self.assertTrue(self.rows("SELECT 1 FROM meta WHERE key='hub_stopped_at'"))
        self.assertEqual(w.state, "stopped")
        with self.assertRaises(hub_db.Busy):
            w.call(lambda c: None)


class SafelyTest(DbCase):
    def test_safely_rolls_back_only_the_helper(self):
        w = self.start()

        def go(conn):
            add_event(conn, kind="kept")

            def helper():
                add_event(conn, kind="lost")
                raise RuntimeError("x")
            self.assertIsNone(hub_db.safely(conn, self.hub, "helper", helper))
        w.call(go)
        self.assertEqual([r["kind"] for r in self.rows("SELECT kind FROM events")], ["kept"])
        self.assertTrue(any("helper failed" in m for _l, m in self.hub.logs))


if __name__ == "__main__":
    unittest.main()
