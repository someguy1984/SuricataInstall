"""Fixes found by tests/restore_drill_local.py, each pinned here (PLAN section 7 and section 5, Audit)."""

import json
import os
import shutil
import sqlite3
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_backup as T  # noqa: E402

import hub_audit  # noqa: E402
import hub_backup  # noqa: E402


class FakeAlerts:
    def __init__(self):
        self.notices = []

    def admin_notice(self, conn, hub, action, detail, actor):
        self.notices.append((action, detail, actor))


class RestoreAuditOffset(T.BackupCase):
    """The backup carries `meta.pending_audit_offset` of the box it came from. On the box it is restored onto, that
    number points into another file: it must not hide the restore's own lines (or any line already on the box).
    The table `pending_audit_seen`, which is restored with it, is what stops a line from being taken twice."""

    def setUp(self):
        super().setUp()
        self.alerts = FakeAlerts()
        p = mock.patch("hub_audit._alerts", lambda: self.alerts)
        p.start()
        self.addCleanup(p.stop)

    def ingest(self, box):
        conn = sqlite3.connect(box.paths.db)
        conn.row_factory = sqlite3.Row
        try:
            hub = types.SimpleNamespace(paths=box.paths, log=lambda *a: None)
            n = hub_audit.ingest_pending(conn, hub)
            conn.commit()
            ids = set()
            for r in conn.execute("SELECT details FROM audit WHERE action LIKE 'file-op.%'"):
                ids.add(json.loads(r["details"]).get("line_id"))
            return n, ids
        finally:
            conn.close()

    def test_restore_drops_the_read_offset_and_every_line_of_the_new_box_is_taken_into_the_chain(self):
        a = self.box("a")
        a.settings()
        a.fill()
        a.db.execute("INSERT INTO meta (key, value) VALUES ('pending_audit_offset', '700') "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        a.db.commit()
        self.assertEqual(hub_backup.backup(a.paths, log=self.say), 0, self.log)
        path = os.path.join(a.paths.backup_dir, [f for f in os.listdir(a.paths.backup_dir) if f.endswith(".bak")][0])
        key = os.path.join(self.root, "ca.enc")
        self.assertEqual(hub_backup.ca_export(a.paths, T.CA_PASS, out=key, log=self.say), 0, self.log)

        b = self.box("b", ca_cn="Fresh CA")
        b.settings(public_ip=["192.0.2.50"])
        b.db.close()
        shutil.copy(a.paths.backup_pass, b.paths.backup_pass)
        for _ in range(4):                                          # earlier attempts on this box: more lines than the old offset
            self.assertEqual(hub_backup.restore(b.paths, os.path.join(self.root, "missing.bak"), log=self.say), 3)
        self.assertGreater(os.path.getsize(b.paths.pending_audit), 700)
        self.assertEqual(hub_backup.restore(b.paths, path, ca_key=key, ca_passphrase=T.CA_PASS, log=self.say), 0, self.log)

        conn = sqlite3.connect(b.paths.db)
        try:
            self.assertIsNone(conn.execute("SELECT value FROM meta WHERE key='pending_audit_offset'").fetchone())
        finally:
            conn.close()
        lines = self.pending(b)
        want = {x["id"] for x in lines}
        self.assertEqual(len(lines), 10)                            # four refused attempts and the restore, a started and an outcome line each
        n, got = self.ingest(b)
        self.assertEqual(n, len(want))
        self.assertTrue(want <= got, "lines never taken into the chain: %r" % sorted(want - got))
        self.assertEqual(self.ingest(b)[0], 0)                      # and a second run reads nothing again


if __name__ == "__main__":
    unittest.main()
