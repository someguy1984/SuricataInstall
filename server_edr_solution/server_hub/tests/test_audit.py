"""Audit chain, folding, pruning and pending-audit.jsonl ingest (PLAN section 5, Audit; section 12 L0)."""

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_ctl_support as S  # noqa: E402

import hub_audit  # noqa: E402
import hub_common  # noqa: E402

HOUR = 3600 * 1000


class ChainTests(S.HubTestCase):
    def conn(self):
        return self.hub.db

    def add(self, n=5):
        for i in range(n):
            hub_audit.append(self.conn(), actor_kind="cli", actor_detail="uid=0 pid=%d" % i, action="act%d" % i,
                             target="t", details={"i": i})

    def test_hash_is_sha256_of_prev_and_canonical_row(self):
        import hashlib
        self.add(2)
        rows = self.rows("SELECT * FROM audit ORDER BY id")
        self.assertEqual(rows[0]["prev_hash"], "0" * 64)
        self.assertEqual(rows[1]["prev_hash"], rows[0]["hash"])
        r = rows[1]
        row = {"ts": r["ts"], "actor_kind": r["actor_kind"], "actor_detail": r["actor_detail"], "action": r["action"],
               "target": r["target"], "outcome": r["outcome"], "details": r["details"]}
        want = hashlib.sha256(r["prev_hash"].encode() + hub_common.canonical_json(row)).hexdigest()
        self.assertEqual(r["hash"], want)
        head = self.rows("SELECT value FROM meta WHERE key='audit_head'")[0]["value"]
        self.assertEqual(head, rows[1]["hash"])

    def test_verify_clean_chain_and_empty_chain(self):
        self.assertEqual(hub_audit.verify(self.conn()), (True, None))
        self.add(6)
        self.assertEqual(hub_audit.verify(self.conn()), (True, None))

    def test_verify_finds_an_edited_row(self):
        self.add(5)
        self.conn().execute("UPDATE audit SET target='evil' WHERE id=3")
        self.assertEqual(hub_audit.verify(self.conn()), (False, 3))

    def test_verify_finds_a_deleted_row(self):
        self.add(5)
        self.conn().execute("DELETE FROM audit WHERE id=2")
        self.assertEqual(hub_audit.verify(self.conn()), (False, 3))

    def test_verify_finds_rows_cut_from_the_end(self):
        self.add(5)
        self.conn().execute("DELETE FROM audit WHERE id=5")
        ok, bad = hub_audit.verify(self.conn())
        self.assertFalse(ok)
        self.assertEqual(bad, 4)

    def test_verify_finds_a_rewritten_row_with_a_matching_hash_only_if_chain_is_redone(self):
        # An attacker who recomputes one hash still breaks the next row's link.
        self.add(4)
        r = self.rows("SELECT * FROM audit WHERE id=2")[0]
        new = hub_audit._row_hash(r["prev_hash"], r["ts"], r["actor_kind"], r["actor_detail"], r["action"], "forged",
                                  r["outcome"], r["details"])
        self.conn().execute("UPDATE audit SET target='forged', hash=? WHERE id=2", (new,))
        self.assertEqual(hub_audit.verify(self.conn()), (False, 3))

    def test_text_is_cleaned_and_details_stay_canonical(self):
        hub_audit.append(self.conn(), actor_kind="ui", actor_detail="ui \x1b[31mx", action="a", target="‮evil",
                         details={"k": "v\x00"})
        r = self.rows("SELECT * FROM audit")[0]
        self.assertNotIn("\x1b", r["actor_detail"])
        self.assertNotIn("‮", r["target"])
        self.assertNotIn("\x00", r["details"])

    def test_prune_leaves_a_verifiable_chain_and_a_prune_row(self):
        now = hub_common.now_ms()
        old = now - 4 * 365 * 86400 * 1000
        c = self.conn()
        # Two old operator rows, then recent rows, one old client failure in the middle, more recent rows.
        hub_audit._insert(c, old, "cli", "x", "old1", "", "ok", "{}")
        hub_audit._insert(c, old + 1, "cli", "x", "old2", "", "ok", "{}")
        hub_audit._insert(c, now - 1000, "cli", "x", "keep1", "", "ok", "{}")
        hub_audit._insert(c, now - 40 * 86400 * 1000, "client", "addr=1.2.3.4", "enroll.denied", "", "denied", "{}")
        hub_audit._insert(c, now - 40 * 86400 * 1000, "client", "addr=1.2.3.4", "enroll.denied", "", "denied", "{}")
        hub_audit._insert(c, now - 500, "cli", "x", "keep2", "", "ok", "{}")
        hub_audit._insert(c, now - 100 * 86400 * 1000, "client", "addr=1.2.3.5", "enroll.ok", "", "ok", "{}")
        self.assertEqual(hub_audit.verify(c), (True, None))
        deleted = hub_audit.prune(c, now)
        self.assertEqual(deleted, 4)
        actions = [r["action"] for r in self.rows("SELECT action FROM audit ORDER BY id")]
        self.assertEqual(actions, ["keep1", "keep2", "enroll.ok", "prune"])
        self.assertEqual(hub_audit.verify(c), (True, None))
        run = json.loads(self.rows("SELECT details FROM audit WHERE action='prune'")[0]["details"])["runs"]
        self.assertEqual(sum(r["count"] for r in run), 4)
        # Tampering after a prune is still caught.
        c.execute("UPDATE audit SET target='x' WHERE action='keep2'")
        self.assertFalse(hub_audit.verify(c)[0])

    def test_prune_with_nothing_old_does_nothing(self):
        self.add(3)
        self.assertEqual(hub_audit.prune(self.conn()), 0)
        self.assertEqual(len(self.rows("SELECT * FROM audit")), 3)


class FoldTests(S.HubTestCase):
    def fail(self, who, n=1, action="enroll.denied"):
        for _ in range(n):
            hub_audit.append(self.hub.db, actor_kind="client", actor_detail="addr=" + who, action=action,
                             target="t", outcome="denied")

    def test_failures_fold_to_one_row_per_source_per_minute(self):
        t0 = 1_800_000_000_000
        with mock.patch("hub_audit.now_ms", lambda: t0):
            self.fail("198.51.100.1", 5)
            self.fail("198.51.100.2", 2)
            self.assertEqual(len(self.rows("SELECT * FROM audit")), 0)       # nothing is written within the minute
        with mock.patch("hub_audit.now_ms", lambda: t0 + 120_000):
            hub_audit.flush_folds(self.hub.db)
        rows = self.rows("SELECT * FROM audit ORDER BY id")
        self.assertEqual(len(rows), 2)
        counts = {r["actor_detail"]: json.loads(r["details"])["count"] for r in rows}
        self.assertEqual(counts, {"addr=198.51.100.1": 5, "addr=198.51.100.2": 2})
        self.assertTrue(all(r["actor_kind"] == "client" and r["outcome"] == "denied" for r in rows))
        self.assertEqual(hub_audit.verify(self.hub.db), (True, None))

    def test_a_later_call_in_a_new_minute_flushes_the_old_one(self):
        t0 = 1_800_000_000_000
        with mock.patch("hub_audit.now_ms", lambda: t0):
            self.fail("198.51.100.1", 3)
        with mock.patch("hub_audit.now_ms", lambda: t0 + 61_000):
            self.fail("198.51.100.1", 1)
        rows = self.rows("SELECT * FROM audit")
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]["details"])["count"], 3)

    def test_operator_rows_are_never_folded(self):
        for _ in range(3):
            hub_audit.append(self.hub.db, actor_kind="cli", action="x", outcome="denied")
        self.assertEqual(len(self.rows("SELECT * FROM audit")), 3)

    def test_sources_over_the_per_minute_limit_share_one_other_row(self):
        t0 = 1_800_000_000_000
        with mock.patch("hub_audit.now_ms", lambda: t0), mock.patch("hub_audit.FOLD_SOURCES_PER_MINUTE", 2):
            for i in range(6):
                self.fail("10.0.0.%d" % i)
        with mock.patch("hub_audit.now_ms", lambda: t0 + 120_000):
            hub_audit.flush_folds(self.hub.db)
        details = sorted(r["actor_detail"] for r in self.rows("SELECT * FROM audit"))
        self.assertEqual(details, ["addr=10.0.0.0", "addr=10.0.0.1", "other"])
        other = [r for r in self.rows("SELECT * FROM audit") if r["actor_detail"] == "other"][0]
        self.assertEqual(json.loads(other["details"])["count"], 4)

    def test_daily_cap_then_one_summary_row_with_the_count(self):
        t0 = 1_800_000_000_000          # a UTC day boundary is at a multiple of 86400000
        day_start = t0 - t0 % 86_400_000
        with mock.patch("hub_audit.FOLD_ROWS_PER_DAY", 3):
            for minute in range(5):
                with mock.patch("hub_audit.now_ms", lambda m=minute: day_start + m * 60_000 + 5):
                    self.fail("192.0.2.%d" % minute, 2)
            with mock.patch("hub_audit.now_ms", lambda: day_start + 10 * 60_000):
                hub_audit.flush_folds(self.hub.db)
            self.assertEqual(len(self.rows("SELECT * FROM audit WHERE actor_kind='client'")), 3)
            with mock.patch("hub_audit.now_ms", lambda: day_start + 86_400_000 + 60_000):
                hub_audit.flush_folds(self.hub.db)
        summary = self.rows("SELECT * FROM audit WHERE action='client-failures.capped'")
        self.assertEqual(len(summary), 1)
        self.assertEqual(json.loads(summary[0]["details"])["count"], 4)

    def test_folded_rows_are_pruned_after_30_days_and_chain_still_verifies(self):
        now = hub_common.now_ms()
        hub_audit._insert(self.hub.db, now - 31 * 86400 * 1000, "client", "addr=1", "x", "", "invalid", "{}")
        hub_audit._insert(self.hub.db, now, "cli", "x", "keep", "", "ok", "{}")
        hub_audit.prune(self.hub.db, now)
        self.assertEqual(hub_audit.verify(self.hub.db), (True, None))
        self.assertEqual([r["action"] for r in self.rows("SELECT * FROM audit ORDER BY id")], ["keep", "prune"])


class PendingTests(S.HubTestCase):
    def ingest(self):
        return hub_audit.ingest_pending(self.hub.db, self.hub)

    def raw_line(self, **kw):
        line = {"id": os.urandom(4).hex(), "op_id": "o1", "ts": hub_common.now_ms(), "op": "backup", "target": "/b",
                "outcome": "started", "uid": 0, "sudo_user": "j", "loginuid": "1000", "scheduled": False}
        line.update(kw)
        with open(self.paths.pending_audit, "ab") as f:
            f.write(json.dumps(line).encode() + b"\n")
        return line

    def test_append_pending_writes_one_json_line_per_call_and_never_rewrites(self):
        with mock.patch.dict(os.environ, {"SUDO_USER": "j"}):
            op = hub_audit.append_pending(self.paths, "restore", "/x/file.bak", "started")
            hub_audit.append_pending(self.paths, "restore", "/x/file.bak", "ok", op_id=op)
        with open(self.paths.pending_audit) as fh:
            lines = [json.loads(x) for x in fh]
        self.assertEqual([x["outcome"] for x in lines], ["started", "ok"])
        self.assertEqual(lines[0]["op_id"], lines[1]["op_id"])
        self.assertEqual(lines[0]["op"], "restore")
        self.assertEqual(lines[0]["sudo_user"], "j")
        self.assertIn("loginuid", lines[0])
        self.assertNotEqual(lines[0]["id"], lines[1]["id"])
        self.assertEqual(os.stat(self.paths.pending_audit).st_mode & 0o777, 0o640)

    def test_ingest_with_the_hub_stopped_makes_chain_rows_and_one_high_notice_per_operation(self):
        hub_audit.append_pending(self.paths, "ca-export", "/x/ca.enc", "started")
        hub_audit.append_pending(self.paths, "ca-export", "/x/ca.enc", "ok")
        self.assertEqual(self.ingest(), 2)
        rows = self.rows("SELECT * FROM audit ORDER BY id")
        self.assertEqual([r["action"] for r in rows], ["file-op.ca-export"] * 2)
        self.assertTrue(all(r["actor_kind"] == "cli" and r["actor_detail"].startswith("file-op ") for r in rows))
        self.assertEqual(len(self.alerts.notices), 1)
        self.assertEqual(self.alerts.notices[0][0], "ca-export")
        self.assertEqual(hub_audit.verify(self.hub.db), (True, None))

    def test_a_failed_operation_notifies_again(self):
        hub_audit.append_pending(self.paths, "restore", "/x", "started")
        hub_audit.append_pending(self.paths, "restore", "/x", "refused")
        self.ingest()
        self.assertEqual(len(self.alerts.notices), 2)
        self.assertEqual([r["outcome"] for r in self.rows("SELECT * FROM audit ORDER BY id")], ["ok", "denied"])

    def test_secrets_write_is_a_root_file_operation_too(self):
        hub_audit.append_pending(self.paths, "secrets.write", "/etc/edr-hub/secrets.json", "started")
        self.ingest()
        self.assertEqual(self.alerts.notices[0][0], "secrets.write")

    def test_a_repeated_line_id_is_ignored(self):
        line = self.raw_line()
        with open(self.paths.pending_audit, "ab") as f:
            f.write(json.dumps(line).encode() + b"\n")
        self.assertEqual(self.ingest(), 1)
        self.assertEqual(len(self.rows("SELECT * FROM audit")), 1)
        self.assertEqual(len(self.alerts.notices), 1)

    def test_offset_is_kept_in_meta_and_a_second_run_reads_nothing(self):
        self.raw_line()
        self.assertEqual(self.ingest(), 1)
        offset = int(self.rows("SELECT value FROM meta WHERE key='pending_audit_offset'")[0]["value"])
        self.assertEqual(offset, os.path.getsize(self.paths.pending_audit))
        self.assertEqual(self.ingest(), 0)
        self.raw_line(op="restore", id="zz")
        self.assertEqual(self.ingest(), 1)

    def test_a_restore_that_brings_back_an_older_offset_ingests_nothing_twice(self):
        self.raw_line()
        self.raw_line(op="restore")
        self.ingest()
        n_rows, n_notices = len(self.rows("SELECT * FROM audit")), len(self.alerts.notices)
        self.hub.db.execute("UPDATE meta SET value='0' WHERE key='pending_audit_offset'")
        self.assertEqual(self.ingest(), 0)
        self.assertEqual(len(self.rows("SELECT * FROM audit")), n_rows)
        self.assertEqual(len(self.alerts.notices), n_notices)

    def test_a_partial_last_line_waits_for_its_newline(self):
        with open(self.paths.pending_audit, "ab") as f:
            f.write(b'{"id":"half","op":"backup","outcome":"star')
        self.assertEqual(self.ingest(), 0)
        with open(self.paths.pending_audit, "ab") as f:
            f.write(b'ted","ts":1,"op_id":"o"}\n')
        self.assertEqual(self.ingest(), 1)

    def test_a_bad_line_leaves_a_row_and_the_rest_goes_on(self):
        with open(self.paths.pending_audit, "ab") as f:
            f.write(b"not json\n")
        self.raw_line()
        self.assertEqual(self.ingest(), 1)
        actions = [r["action"] for r in self.rows("SELECT * FROM audit ORDER BY id")]
        self.assertEqual(sorted(actions), ["file-op.backup", "pending-audit.bad-line"])      # the bad lines are one summary row, after the good ones

    def test_missing_file_is_fine(self):
        self.assertEqual(self.ingest(), 0)

    def test_the_first_scheduled_backup_is_quiet_a_second_within_20_hours_notifies(self):
        t = 1_800_000_000_000
        self.raw_line(scheduled=True, ts=t)
        self.raw_line(scheduled=True, ts=t, outcome="ok")
        self.ingest()
        self.assertEqual(len(self.alerts.notices), 0)
        self.assertEqual(len(self.rows("SELECT * FROM audit WHERE action='file-op.backup'")), 2)   # rows stay
        self.raw_line(scheduled=True, ts=t + 10 * HOUR)
        self.ingest()
        self.assertEqual(len(self.alerts.notices), 1)
        self.assertEqual(self.alerts.notices[0][0], "backup")

    def test_a_scheduled_backup_after_20_hours_is_quiet_again(self):
        t = 1_800_000_000_000
        self.raw_line(scheduled=True, ts=t)
        self.raw_line(scheduled=True, ts=t + 24 * HOUR)
        self.ingest()
        self.assertEqual(len(self.alerts.notices), 0)

    def test_a_hand_run_backup_always_notifies(self):
        t = 1_800_000_000_000
        self.raw_line(scheduled=False, ts=t)
        self.ingest()
        self.assertEqual(len(self.alerts.notices), 1)

    def test_the_scheduled_exception_covers_backup_only(self):
        self.raw_line(scheduled=True, op="restore")
        self.ingest()
        self.assertEqual(len(self.alerts.notices), 1)

    def test_failed_scheduled_backup_does_not_page(self):
        self.raw_line(scheduled=True, outcome="error")
        self.ingest()
        self.assertEqual(len(self.alerts.notices), 0)

    def test_a_failing_alert_module_does_not_stop_ingest(self):
        self.alerts.admin_notice = mock.Mock(side_effect=RuntimeError("boom"))
        self.raw_line()
        self.raw_line(op="restore", id="two")
        self.assertEqual(self.ingest(), 2)
        self.assertEqual(len(self.rows("SELECT * FROM audit")), 2)
        self.assertTrue(self.hub.logs)

    def test_a_world_writable_or_linked_pending_file_is_not_read_and_is_reported_once_a_day(self):
        self.raw_line()
        os.chmod(self.paths.pending_audit, 0o666)
        self.assertEqual(self.ingest(), 0)
        self.assertEqual(self.ingest(), 0)
        rows = self.rows("SELECT action, outcome FROM audit")
        self.assertEqual(rows, [{"action": "pending-audit.untrusted", "outcome": "denied"}])      # one row for the day
        self.assertEqual(len(self.alerts.notices), 1)
        self.assertIn("writable by group or others", self.alerts.notices[0][1])
        os.chmod(self.paths.pending_audit, 0o640)
        self.assertEqual(self.ingest(), 1)                                  # trusted again: the line is taken in
        os.rename(self.paths.pending_audit, self.paths.pending_audit + ".real")
        os.symlink(self.paths.pending_audit + ".real", self.paths.pending_audit)
        self.hub.db.execute("DELETE FROM meta WHERE key='pending_audit_untrusted_day'")
        self.assertEqual(self.ingest(), 0)
        self.assertIn("link", self.rows("SELECT details FROM audit WHERE action='pending-audit.untrusted'")[-1]["details"])

    def test_the_installed_hub_accepts_only_root_as_owner(self):
        self.raw_line()
        real = os.fstat

        def as_user(fd):
            st = real(fd)
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, 1000, st.st_gid, st.st_size, 0, 0, 0))
        fd, reason = hub_audit._open_trusted(self.paths.pending_audit, installed=False)
        self.assertIsNotNone(fd)
        os.close(fd)
        with mock.patch("hub_audit.os.fstat", as_user):
            fd, reason = hub_audit._open_trusted(self.paths.pending_audit, installed=True)
            self.assertIsNone(fd)
            self.assertEqual(reason, "it is not owned by root")

    def test_one_ingest_takes_at_most_200_lines_and_10_notices_then_one_summary(self):
        for i in range(450):
            self.raw_line(id="b%03d" % i, op="restore")
        self.assertEqual(self.ingest(), 200)
        self.assertEqual(len(self.alerts.notices), 11)                       # 10 notices and the summary
        self.assertIn("190 more", self.alerts.notices[-1][1])
        self.assertEqual(self.ingest(), 200)
        self.assertEqual(self.ingest(), 50)
        self.assertEqual(self.ingest(), 0)
        self.assertEqual(len(self.rows("SELECT * FROM audit WHERE action='file-op.restore'")), 450)

    def test_bad_lines_are_one_summary_row_per_ingest(self):
        with open(self.paths.pending_audit, "wb") as f:
            f.write(b"{}\n" * 100 + b"[1]\n" * 5 + b"x" * 5000 + b"\n")
        self.ingest()
        rows = self.rows("SELECT details FROM audit WHERE action='pending-audit.bad-line'")
        self.assertEqual([json.loads(r["details"])["count"] for r in rows], [106])

    def test_is_scheduled_run_reads_the_cgroup(self):
        f = os.path.join(self.root, "cg")
        with open(f, "w") as fh:
            fh.write("0::/system.slice/edr-hub-backup.service\n")
        self.assertTrue(hub_audit.is_scheduled_run(f))
        with open(f, "w") as fh:
            fh.write("0::/user.slice/user-1000.slice/session-3.scope\n")
        self.assertFalse(hub_audit.is_scheduled_run(f))
        with open(f, "w") as fh:
            fh.write("0::/system.slice/edr-hub-backup.service.d/x\n0::/system.slice/not-edr-hub-backup.service\n")
        self.assertFalse(hub_audit.is_scheduled_run(f))
        self.assertFalse(hub_audit.is_scheduled_run(os.path.join(self.root, "missing")))

    def test_ingest_also_flushes_folds_and_prunes_daily(self):
        now = hub_common.now_ms()
        hub_audit._insert(self.hub.db, now - 31 * 86400 * 1000, "client", "addr=1", "x", "", "denied", "{}")
        self.ingest()
        self.assertTrue(any(r["action"] == "prune" for r in self.rows("SELECT * FROM audit")))
        n = len(self.rows("SELECT * FROM audit"))
        self.ingest()
        self.assertEqual(len(self.rows("SELECT * FROM audit")), n)           # not again within a day


if __name__ == "__main__":
    unittest.main()
