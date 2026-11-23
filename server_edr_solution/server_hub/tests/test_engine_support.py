"""Shared fakes for the engine and alert tests: a Hub with a real SQLite file built from hub_schema.DDL.

The writer runs `fn(conn)` on one connection inside BEGIN IMMEDIATE ... COMMIT, like hub_db.Writer. Its
connection keeps the default row factory (tuples), so the code under test must not depend on sqlite3.Row.
This file holds no tests.
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "hub"))

import hub_common    # noqa: E402
import hub_schema    # noqa: E402

MIN = 60 * 1000
HOUR = 60 * MIN
DAY = 24 * HOUR
T0 = 1_795_000_000_000          # a fixed "now" (ms): 2026-11-18


class FakeWriter:
    def __init__(self, path):
        self.conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.lock = threading.RLock()

    def call(self, fn, timeout=10.0):
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                result = fn(self.conn)
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            self.conn.execute("COMMIT")
            return result

    def post(self, fn):
        self.call(fn)


class FakePki:
    def __init__(self):
        self.info = {}

    def cert_info(self, path):
        for key, value in self.info.items():
            if str(path).endswith(key):
                return value
        raise OSError("no such certificate")


class FakeHub:
    def __init__(self, root):
        self.root = root
        self.paths = hub_common.Paths(state_dir=os.path.join(root, "state"), run_dir=os.path.join(root, "run"),
                                      etc_dir=os.path.join(root, "etc"), out_state_dir=os.path.join(root, "out"),
                                      lib_dir=os.path.join(HERE, "..", "hub"))
        for d in (self.paths.state_dir, self.paths.run_dir, self.paths.etc_dir):
            os.makedirs(d, exist_ok=True)
        self.settings = hub_common.default_settings()
        self.settings["secrets_set"] = {"webhook_url": "hooks.example.com ...abcd"}
        db = sqlite3.connect(self.paths.db)
        db.executescript(hub_schema.DDL)
        db.commit()
        db.close()
        self.writer = FakeWriter(self.paths.db)
        self.pki = FakePki()
        self.started_at = T0
        self.stopping = threading.Event()
        self.logs = []

    def ro(self):
        conn = sqlite3.connect("file:%s?mode=ro" % self.paths.db, uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def log(self, level, message):
        self.logs.append((level, message))

    def update_settings(self, new):
        self.settings = new

    # ---- helpers for tests
    def q(self, sql, args=()):
        with self.writer.lock:
            return self.writer.conn.execute(sql, args).fetchall()

    def add_host(self, name="web1", state="active", **kw):
        uuid = kw.pop("uuid", "00000000-0000-4000-8000-%012d" % (sum(map(ord, name)) * 7919))
        row = {"uuid": uuid, "name": name, "droplet_id": "d-1", "state": state, "state_since": T0 - DAY,
               "enrolled_at": T0 - DAY, "last_seen": T0, "peer_ips": json.dumps(["203.0.113.9"]), "skew_ms": 0}
        row.update(kw)
        cols = ",".join(row)
        self.writer.call(lambda c: c.execute("INSERT INTO hosts (%s) VALUES (%s)" % (cols, ",".join("?" * len(row))), list(row.values())))
        return self.host(uuid)

    def host(self, uuid):
        with self.writer.lock:
            cur = self.writer.conn.execute("SELECT * FROM hosts WHERE uuid=?", (uuid,))
            cols = [c[0] for c in cur.description]
            r = cur.fetchone()
        return dict(zip(cols, r)) if r else None

    def set_host(self, uuid, **kw):
        sets = ",".join("%s=?" % k for k in kw)
        self.writer.call(lambda c: c.execute("UPDATE hosts SET %s WHERE uuid=?" % sets, list(kw.values()) + [uuid]))

    def add_event(self, host, kind, sev="HIGH", *, hub_sev=None, ts=None, received_at=None, count=1, replayed=0,
                  src_ip="", summary="", details=None, rated_by=None, epoch=1, seq=None):
        received_at = T0 if received_at is None else received_at
        ts = received_at if ts is None else ts
        n = self.q("SELECT COALESCE(MAX(id),0)+1 FROM events")[0][0]
        seq = n if seq is None else seq
        row = {"host": host["uuid"], "event_id": "%08x:%d" % (epoch, seq), "received_at": received_at, "ts": ts,
               "source": "tetragon", "severity": sev, "hub_severity": hub_sev or sev, "rated_by": rated_by, "kind": kind,
               "summary": summary or kind, "details": json.dumps(details or {}), "src_ip": src_ip, "count": count,
               "replayed": replayed, "epoch": epoch, "seq": seq}
        cols = ",".join(row)

        def work(c):
            cur = c.execute("INSERT INTO events (%s) VALUES (%s)" % (cols, ",".join("?" * len(row))), list(row.values()))
            return cur.lastrowid
        rowid = self.writer.call(work)
        out = dict(row)
        out["rowid"] = rowid
        return out

    def outbox(self):
        out = []
        for r in self.q("SELECT id, channel, severity, payload, dedup_key, state FROM outbox ORDER BY id"):
            out.append({"id": r[0], "channel": r[1], "severity": r[2], "payload": json.loads(r[3]), "dedup_key": r[4], "state": r[5]})
        return out

    def titles(self, channel="webhook"):
        return [o["payload"]["title"] for o in self.outbox() if o["channel"] == channel]

    def incidents(self):
        rows = self.q("SELECT id, host, chain, severity, state, kinds, signals, opened, updated FROM incidents ORDER BY id")
        return [dict(zip(("id", "host", "chain", "severity", "state", "kinds", "signals", "opened", "updated"), r)) for r in rows]

    def meta(self, key, default=None):
        r = self.q("SELECT value FROM meta WHERE key=?", (key,))
        return r[0][0] if r else default

    def notes(self):
        return [(r[0], r[1], json.loads(r[2]).get("summary", "")) for r in self.q("SELECT key, severity, data FROM alert_state WHERE key LIKE 'note|%'")]


class HubTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="edr-hub-test-")
        self.hub = FakeHub(self.tmp)

    def tearDown(self):
        try:
            self.hub.writer.conn.close()
        except Exception:
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)
