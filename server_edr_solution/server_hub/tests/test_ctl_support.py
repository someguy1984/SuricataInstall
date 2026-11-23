"""Shared fakes for the audit, ctl, cli and backup tests (this file holds no tests).

The other agents' modules (hub_enroll, hub_alerts, hub_pki, hub_db) may not exist yet, and the tests
of this layer should not depend on their internals. The code under test reaches them through small
accessor functions (hub_ctl._enroll, hub_ctl._alerts, hub_audit._alerts, hub_backup._pki); the tests
patch those accessors.
"""

import json
import os
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
HUB_DIR = os.path.normpath(os.path.join(HERE, "..", "hub"))
if HUB_DIR not in sys.path:
    sys.path.insert(0, HUB_DIR)

import hub_audit  # noqa: E402
import hub_common  # noqa: E402
import hub_schema  # noqa: E402

EDR_HUB = os.path.join(HUB_DIR, "edr-hub")
SCRATCH = os.environ.get("EDR_TEST_TMP") or None


def make_dirs():
    """A temporary state, run and etc directory; returns (root, Paths)."""
    root = tempfile.mkdtemp(prefix="edrhub-test-", dir=SCRATCH)
    for sub in ("state", "run", "etc", "backups"):
        os.makedirs(os.path.join(root, sub), mode=0o750)
    paths = hub_common.Paths(state_dir=os.path.join(root, "state"), run_dir=os.path.join(root, "run"),
                             etc_dir=os.path.join(root, "etc"), backup_dir=os.path.join(root, "backups"),
                             out_state_dir=os.path.join(root, "out"), lib_dir=HUB_DIR)
    return root, paths


def new_db(path):
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(hub_schema.DDL)
    conn.execute("INSERT INTO meta (key, value) VALUES ('schema_version', ?)", (str(hub_schema.SCHEMA_VERSION),))
    return conn


def add_host(conn, name, state="active", uuid=None, serial="aa01", last_seen=None, peer="203.0.113.7"):
    uuid = uuid or "%08x-0000-4000-8000-%012x" % (abs(hash(name)) % (1 << 32), abs(hash(name + "x")) % (1 << 48))
    now = hub_common.now_ms()
    conn.execute(
        "INSERT INTO hosts (uuid, name, reported_name, ips, peer_ips, os, droplet_id, state, state_since, enrolled_at, "
        "enrolled_from, cert_serial, last_seen, agent_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (uuid, name, "reported-" + name, "[]", json.dumps([peer]), "ubuntu", "1234", state, now, now, peer, serial,
         last_seen if last_seen is not None else now, "0.1.0"))
    return uuid


class FakePki:
    def __init__(self):
        self.issued = []

    def issue_server_cert(self, ips):
        self.issued.append(list(ips))

    def cert_info(self, path):
        return {"serial": "0abc", "not_after": 1, "sans": list(self.issued[-1]) if self.issued else []}


class FakeWriter:
    """One sqlite connection, one lock: writer.call(fn) runs fn(conn) in a transaction like hub_db.Writer."""

    def __init__(self, conn):
        self.conn = conn
        self.lock = threading.RLock()
        self.fail_next = None

    def call(self, fn, timeout=10.0):
        with self.lock:
            if self.fail_next:
                exc, self.fail_next = self.fail_next, None
                raise exc
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                result = fn(self.conn)
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            self.conn.execute("COMMIT")
            return result

    post = call


class FakeHub:
    def __init__(self, paths, settings=None):
        self.paths = paths
        self.db = new_db(paths.db)
        self.writer = FakeWriter(self.db)
        self.settings = hub_common.default_settings()
        self.settings.update({"public_ip": ["203.0.113.10"]})
        self.settings.update(settings or {})
        hub_common.save_settings(paths, self.settings)
        self.pki = FakePki()
        self.started_at = hub_common.now_ms()
        self.stopping = threading.Event()
        self.listener_refreshes = 0
        self.cert_reloads = 0
        self.logs = []

    def update_settings(self, new):
        hub_common.save_settings(self.paths, new)
        self.settings = new

    def ro(self):
        conn = sqlite3.connect("file:%s?mode=ro" % self.paths.db, uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def refresh_enroll_listener(self):
        self.listener_refreshes += 1

    def reload_server_cert(self):
        self.cert_reloads += 1

    def log(self, level, message):
        self.logs.append((level, message))

    def close(self):
        self.db.close()


class FakeAlerts:
    def __init__(self):
        self.notices = []      # (action, detail, actor)
        self.notifies = []     # dict of the keyword arguments
        self.secrets_seen = []

    def admin_notice(self, conn, hub, action, detail, actor):
        self.notices.append((action, detail, actor))
        return 1

    def notify(self, conn, hub, **kw):
        self.notifies.append(kw)
        return 1

    def enqueue_test(self, conn, hub, channel):
        ids = []
        channels = [channel] if channel else (hub_common.enabled_channels(hub.settings) or ["none"])
        for ch in channels:
            cur = conn.execute("INSERT INTO outbox (created, channel, severity, payload, next_try, state) VALUES (?,?,?,?,?,?)",
                               (hub_common.now_ms(), ch, "HIGH", json.dumps({"title": "test", "test": True}),
                                hub_common.now_ms(), "dead" if ch == "none" else "pending"))
            ids.append(cur.lastrowid)
        return ids


class FakeEnroll:
    def __init__(self):
        self.revoked_certs = []
        self.counter = 0

    @staticmethod
    def resolve_host(conn, ref):
        return conn.execute("SELECT * FROM hosts WHERE name=? OR uuid=?", (ref, ref)).fetchone()

    def host_set_state(self, conn, hub, uuid, new_state, actor=""):
        row = conn.execute("SELECT state FROM hosts WHERE uuid=?", (uuid,)).fetchone()
        if row is None or row["state"] not in ("pending", "active", "orphan"):
            raise ValueError("transition not allowed")
        conn.execute("UPDATE hosts SET state=?, state_since=? WHERE uuid=?", (new_state, hub_common.now_ms(), uuid))
        self.revoked_certs.append(uuid)

    @staticmethod
    def host_adopt(conn, hub, uuid):
        conn.execute("UPDATE hosts SET state='active' WHERE uuid=? AND state='orphan'", (uuid,))

    def token_create(self, conn, hub, *, name=None, for_host=None, ttl_s=900, source_cidr=None, created_by=""):
        if name and conn.execute("SELECT 1 FROM hosts WHERE name=?", (name,)).fetchone():
            raise ValueError("duplicate name")
        self.counter += 1
        tid = "tok%d" % self.counter
        secret = "SECRETVALUE%dXYZ" % self.counter
        exp = hub_common.now_ms() + ttl_s * 1000
        conn.execute("INSERT INTO tokens (id, secret_sha256, name, bound_host, source_cidr, created_at, created_by, expires_at) "
                     "VALUES (?,?,?,?,?,?,?,?)", (tid, "00" * 32, name, for_host, source_cidr, hub_common.now_ms(), created_by, exp))
        return {"id": tid, "token": "%s.%s.%s" % (tid, secret, "ab" * 32), "name": name, "expires_at": exp,
                "enroll_port": 8444, "port": 8443, "hub_addresses": ["203.0.113.10"]}

    @staticmethod
    def token_list(conn):
        return [{"id": r["id"], "name": r["name"], "bound_host": r["bound_host"], "source_cidr": r["source_cidr"],
                 "expires_at": r["expires_at"], "state": "revoked" if r["revoked_at"] else "pending"}
                for r in conn.execute("SELECT * FROM tokens")]

    @staticmethod
    def token_revoke(conn, hub, token_id):
        return conn.execute("UPDATE tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL AND used_at IS NULL",
                            (hub_common.now_ms(), token_id)).rowcount == 1


class HubTestCase(unittest.TestCase):
    """A temp tree, a FakeHub on a file database, and the accessors patched to the fakes."""

    settings = None

    def setUp(self):
        self.root, self.paths = make_dirs()
        self.hub = FakeHub(self.paths, self.settings)
        self.alerts = FakeAlerts()
        self.enroll = FakeEnroll()
        self._patches = [
            mock.patch("hub_ctl._alerts", lambda: self.alerts),
            mock.patch("hub_ctl._enroll", lambda: self.enroll),
            mock.patch("hub_audit._alerts", lambda: self.alerts),
        ]
        import hub_ctl  # noqa: F401  (imported here so the patch targets exist)
        for p in self._patches:
            p.start()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for p in self._patches:
            p.stop()
        self.hub.close()
        shutil.rmtree(self.root, ignore_errors=True)

    def rows(self, sql, params=()):
        return self.hub.writer.call(lambda conn: [dict(r) for r in conn.execute(sql, params)])

    def audit_actions(self):
        return [(r["actor_kind"], r["action"], r["outcome"]) for r in self.rows("SELECT * FROM audit ORDER BY id")]


def send(path, request, timeout=5.0, raw=None):
    """Send one line to a socket and return the parsed reply (None when the server closed without one)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
        s.sendall(raw if raw is not None else json.dumps(request).encode("utf-8") + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf) if buf else None
    finally:
        s.close()


def ctl(paths, cmd, args=None, actor=None):
    return send(paths.ctl_sock, {"cmd": cmd, "args": args or {}, "actor": actor or {"loginuid": "1000", "sudo_user": "j"}})
