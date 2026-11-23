"""backup, restore and ca-export with the real openssl CLI (PLAN section 7; section 12 L0 and the restore drill)."""

import hashlib
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_ctl_support as S  # noqa: E402

import hub_audit  # noqa: E402
import hub_backup  # noqa: E402
import hub_common  # noqa: E402

CA_PASS = "correct horse battery staple"


def R(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def W(path, a, b=None):
    mode, data = ("w", a) if b is None else (a, b)
    with open(path, mode) as f:
        f.write(data)


def J(path):
    with open(path) as f:
        return json.load(f)


def openssl(*args):
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def make_ca(paths, cn="Test CA"):
    os.makedirs(paths.ca_dir, mode=0o700, exist_ok=True)
    openssl("ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", paths.ca_key)
    os.chmod(paths.ca_key, 0o600)
    openssl("req", "-x509", "-new", "-key", paths.ca_key, "-subj", "/CN=" + cn, "-days", "30", "-out", paths.ca_cert)


def tree_hash(root):
    """Hash of every file under a directory (names and bytes), to prove 'nothing changed'."""
    h = hashlib.sha256()
    for base, dirs, files in sorted(os.walk(root)):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(base, name)
            if name.endswith(("-wal", "-shm")):
                continue
            h.update(os.path.relpath(path, root).encode())
            with open(path, "rb") as f:
                h.update(f.read())
    return h.hexdigest()


class FakePkiForRestore:
    """Stands in for hub_pki.Pki: records the call and writes marker files like a real issue would."""
    instances = []

    def __init__(self, paths):
        self.paths = paths
        self.issued = []
        FakePkiForRestore.instances.append(self)

    def issue_server_cert(self, ips):
        self.issued.append(list(ips))
        os.makedirs(self.paths.tls_dir, exist_ok=True)
        with open(self.paths.server_cert, "w") as f:
            f.write("NEW SERVER CERT for %s\n" % ",".join(ips))
        with open(self.paths.server_key, "w") as f:
            f.write("NEW SERVER KEY\n")


class Box:
    """One hub state: a database with data, a CA, settings, secrets and a backup passphrase."""

    def __init__(self, root, name, with_ca=True, ca_cn="Test CA"):
        self.root = os.path.join(root, name)
        for sub in ("state", "run", "etc", "backups"):
            os.makedirs(os.path.join(self.root, sub), mode=0o750)
        self.paths = hub_common.Paths(state_dir=os.path.join(self.root, "state"), run_dir=os.path.join(self.root, "run"),
                                      etc_dir=os.path.join(self.root, "etc"), backup_dir=os.path.join(self.root, "backups"),
                                      out_state_dir=os.path.join(self.root, "out"), lib_dir=S.HUB_DIR)
        self.db = S.new_db(self.paths.db)
        if with_ca:
            make_ca(self.paths, ca_cn)
        with open(self.paths.backup_pass, "w") as f:
            f.write("backup-passphrase-one\n")
        os.chmod(self.paths.backup_pass, 0o600)

    def settings(self, **extra):
        s = hub_common.default_settings()
        s.update({"public_ip": ["203.0.113.10"]})
        s.update(extra)
        hub_common.save_settings(self.paths, s)
        return s

    def fill(self):
        self.uuid = S.add_host(self.db, "web-1", serial="beef01")
        self.db.execute("INSERT INTO events (host, event_id, received_at, ts, source, severity, hub_severity, kind, summary, "
                        "epoch, seq) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (self.uuid, "00000001:1", 1, 1, "agent", "HIGH", "HIGH", "x.y", "hello", 1, 1))
        self.db.execute("INSERT INTO never_ban (cidr, reason, added_by, ts) VALUES ('198.51.100.0/24','monitor','j',1)")
        now = hub_common.now_ms()
        self.db.execute("INSERT INTO tokens (id, secret_sha256, name, created_at, expires_at, used_at) VALUES ('used1','00',NULL,?,?,?)",
                        (now, now + 600_000, now))
        self.db.execute("INSERT INTO tokens (id, secret_sha256, name, created_at, expires_at, issued_reply) VALUES ('open1','00','web-9',?,?,'{}')",
                        (now, now + 600_000))
        self.db.execute("INSERT INTO login_codes (code_sha256, created, expires) VALUES ('c1',?,?)", (now, now + 600_000))
        with open(self.paths.secrets, "w") as f:
            json.dump({"webhook_url": "https://hooks.example.com/SECRETVALUE"}, f)
        os.chmod(self.paths.secrets, 0o600)
        with open(self.paths.revoked, "w") as f:
            f.write("0aaa01 " + "11" * 32 + "\n0aaa02 " + "22" * 32 + "\n")

    def close(self):
        self.db.close()


class BackupCase(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.root = tempfile.mkdtemp(prefix="edrhub-backup-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.log = []
        self.say = self.log.append
        FakePkiForRestore.instances = []
        p = mock.patch("hub_backup._pki", lambda paths: FakePkiForRestore(paths))
        p.start()
        self.addCleanup(p.stop)

    def box(self, name="a", **kw):
        b = Box(self.root, name, **kw)
        self.addCleanup(b.close)
        return b

    @staticmethod
    def slurp(path):
        with open(path, "rb") as f:
            return f.read()

    def pending(self, box):
        try:
            with open(box.paths.pending_audit) as f:
                return [json.loads(x) for x in f]
        except FileNotFoundError:
            return []

    def made_backup(self, box, **kw):
        box.settings()
        box.fill()
        code = hub_backup.backup(box.paths, log=self.say, **kw)
        self.assertEqual(code, 0, self.log)
        files = sorted(os.listdir(box.paths.backup_dir))
        return os.path.join(box.paths.backup_dir, [f for f in files if f.endswith(".bak")][-1])


class BackupTests(BackupCase):
    def test_backup_writes_an_encrypted_verified_file_marker_and_audit_lines(self):
        a = self.box()
        path = self.made_backup(a)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with open(path, "rb") as fh:
            data = fh.read()
        self.assertTrue(data.startswith(b"Salted__"))
        self.assertNotIn(b"SECRETVALUE", data)
        self.assertNotIn(b"hello", data)
        self.assertNotIn(b"SQLite format", data)
        self.assertTrue(data[-hub_backup.TRAILER_LEN:].startswith(b"EDRHUB-SHA256:"))
        marker = R(a.paths.last_backup).strip()
        self.assertAlmostEqual(int(marker), hub_common.now_ms(), delta=60_000)
        self.assertEqual(os.stat(a.paths.last_backup).st_mode & 0o777, 0o644)
        lines = self.pending(a)
        self.assertEqual([x["outcome"] for x in lines], ["started", "ok"])
        self.assertEqual({x["op"] for x in lines}, {"backup"})
        self.assertEqual(lines[0]["op_id"], lines[1]["op_id"])
        self.assertEqual(os.listdir(a.paths.backup_dir), [os.path.basename(path)])      # no temp files left behind

    def test_contents_match_section_7_and_hold_no_ca_key_or_server_key(self):
        a = self.box()
        path = self.made_backup(a)
        dest = os.path.join(self.root, "unpacked")
        os.makedirs(dest)
        manifest = hub_backup._unpack(path, a.paths.backup_pass, dest)
        names = sorted(manifest["files"])
        self.assertEqual(names, sorted(["hub.db", "settings.json", "secrets.json", "never-ban.json", "hub-addresses.json",
                                        "ca/ca.pem", "ca/revoked.txt"]))
        for n in names:
            self.assertTrue(os.path.exists(os.path.join(dest, n)))
        self.assertFalse(os.path.exists(os.path.join(dest, "ca", "ca.key")))
        self.assertFalse(any("server" in n or n.endswith(".key") for n in names))
        self.assertEqual(J(os.path.join(dest, "hub-addresses.json"))["public_ip"], ["203.0.113.10"])
        self.assertEqual(J(os.path.join(dest, "never-ban.json"))[0]["cidr"], "198.51.100.0/24")
        self.assertEqual(manifest["schema_version"], "1")
        conn = sqlite3.connect(os.path.join(dest, "hub.db"))
        self.assertEqual(conn.execute("SELECT summary FROM events").fetchone()[0], "hello")
        conn.close()

    def test_backup_while_the_hub_holds_its_connection_open_in_wal_mode(self):
        a = self.box()
        a.settings()
        a.fill()
        self.assertEqual(a.db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        a.db.execute("BEGIN")
        a.db.execute("INSERT INTO meta (key, value) VALUES ('later','1')")
        self.assertEqual(hub_backup.backup(a.paths, log=self.say), 0, self.log)       # an open write transaction does not block
        a.db.execute("COMMIT")

    def test_rotation_keeps_backup_keep_files(self):
        a = self.box()
        a.settings(backup_keep=3)
        a.fill()
        for i in range(5):
            with open(os.path.join(a.paths.backup_dir, "edr-hub-2020010%dT000000Z.bak" % i), "w") as f:
                f.write("old")
        self.assertEqual(hub_backup.backup(a.paths, log=self.say), 0)
        left = sorted(os.listdir(a.paths.backup_dir))
        self.assertEqual(len(left), 3)
        self.assertTrue(left[-1] > "edr-hub-2026")                # the new one is kept, the oldest are gone

    def test_out_file_is_used_as_given_and_not_rotated(self):
        a = self.box()
        a.settings()
        a.fill()
        out = os.path.join(self.root, "elsewhere", "mine.bak")
        self.assertEqual(hub_backup.backup(a.paths, out=out, log=self.say), 0)
        self.assertTrue(os.path.exists(out))
        self.assertEqual(os.listdir(a.paths.backup_dir), [])
        self.assertEqual(hub_backup.backup(a.paths, out=out, log=self.say), 3)       # will not overwrite

    def test_refused_without_the_passphrase_file_or_database(self):
        a = self.box()
        a.settings()
        os.unlink(a.paths.backup_pass)
        self.assertEqual(hub_backup.backup(a.paths, log=self.say), 3)
        self.assertEqual([x["outcome"] for x in self.pending(a)], ["started", "refused"])
        self.assertEqual(os.listdir(a.paths.backup_dir), [])
        b = self.box("b")
        os.unlink(b.paths.db)
        b.settings()
        self.assertEqual(hub_backup.backup(b.paths, log=self.say), 3)

    def test_refused_when_there_is_not_enough_free_space(self):
        a = self.box()
        a.settings()
        a.fill()
        with mock.patch("hub_backup.shutil.disk_usage", return_value=mock.Mock(free=1000)):
            self.assertEqual(hub_backup.backup(a.paths, log=self.say), 3)
        self.assertTrue(any("free space" in x for x in self.log))
        self.assertEqual(os.listdir(a.paths.backup_dir), [])
        self.assertFalse(os.path.exists(a.paths.last_backup))

    def test_the_scheduled_flag_comes_from_the_cgroup_only(self):
        a = self.box()
        a.settings()
        a.fill()
        with mock.patch("hub_audit.is_scheduled_run", return_value=True):
            self.assertEqual(hub_backup.backup(a.paths, log=self.say), 0)
        self.assertTrue(all(x["scheduled"] for x in self.pending(a)))
        b = self.box("b")
        b.settings()
        b.fill()
        self.assertEqual(hub_backup.backup(b.paths, log=self.say), 0)
        self.assertFalse(any(x["scheduled"] for x in self.pending(b)))

    def test_a_damaged_file_is_detected_by_the_checksum(self):
        a = self.box()
        path = self.made_backup(a)
        raw = bytearray(R(path, "rb"))
        raw[200] ^= 0xFF
        W(path, "wb", bytes(raw))
        with self.assertRaises(hub_backup.BackupError) as cm:
            hub_backup._unpack(path, a.paths.backup_pass)
        self.assertIn("checksum", str(cm.exception))

    def test_the_wrong_passphrase_is_detected(self):
        a = self.box()
        path = self.made_backup(a)
        other = os.path.join(self.root, "other.pass")
        W(other, "w", "not the passphrase\n")
        with self.assertRaises(hub_backup.BackupError):
            hub_backup._unpack(path, other)

    def test_a_file_that_is_not_a_backup(self):
        a = self.box()
        junk = os.path.join(self.root, "junk")
        W(junk, "wb", b"x" * 500)
        with self.assertRaises(hub_backup.BackupError):
            hub_backup._unpack(junk, a.paths.backup_pass)


class BackupSourceTests(BackupCase):
    def test_a_symlinked_ca_certificate_is_refused_and_a_symlinked_revoked_list_is_left_out_with_a_warning(self):
        a = self.box()
        a.settings()
        a.fill()
        secret = os.path.join(self.root, "root-only.txt")
        W(secret, "ROOTONLY")
        os.unlink(a.paths.revoked)
        os.symlink(secret, a.paths.revoked)
        self.assertEqual(hub_backup.backup(a.paths, log=self.say), 0)
        self.assertTrue(any("left out of the backup" in x and "revoked.txt" in x for x in self.log))
        out = os.path.join(a.paths.backup_dir, os.listdir(a.paths.backup_dir)[0])
        dest = os.path.join(self.root, "unpacked")
        os.makedirs(dest)
        hub_backup._unpack(out, a.paths.backup_pass, dest)
        self.assertNotIn("ROOTONLY", R(os.path.join(dest, "ca", "revoked.txt")))
        pem = a.paths.ca_cert
        os.rename(pem, pem + ".real")
        os.symlink(pem + ".real", pem)
        self.assertEqual(hub_backup.backup(a.paths, log=self.say), 3)

    def test_a_symlinked_database_is_refused(self):
        a = self.box()
        a.settings()
        a.fill()
        os.rename(a.paths.db, a.paths.db + ".real")
        os.symlink(a.paths.db + ".real", a.paths.db)
        self.assertEqual(hub_backup.backup(a.paths, log=self.say), 3)

    def test_ca_export_refuses_a_linked_key(self):
        a = self.box()
        a.settings()
        os.rename(a.paths.ca_key, a.paths.ca_key + ".real")
        os.symlink(a.paths.ca_key + ".real", a.paths.ca_key)
        self.assertEqual(hub_backup.ca_export(a.paths, CA_PASS, out=os.path.join(self.root, "x.enc"), log=self.say), 3)
        self.assertFalse(os.path.exists(os.path.join(self.root, "x.enc")))


class CaExportTests(BackupCase):
    def test_export_is_encrypted_pkcs8_with_a_separate_passphrase(self):
        a = self.box()
        a.settings()
        out = os.path.join(self.root, "ca.key.enc")
        self.assertEqual(hub_backup.ca_export(a.paths, CA_PASS, out=out, log=self.say), 0, self.log)
        text = R(out)
        self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", text)
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)
        pw = os.path.join(self.root, "pw")
        W(pw, "w", CA_PASS)
        r = subprocess.run(["openssl", "pkey", "-in", out, "-passin", "file:" + pw, "-pubout"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), hub_backup._pubkey_of_cert(a.paths.ca_cert))
        self.assertEqual([x["outcome"] for x in self.pending(a)], ["started", "ok"])
        self.assertEqual(self.pending(a)[0]["op"], "ca-export")
        self.assertTrue(any("CA SHA-256" in x for x in self.log))

    def test_refusals_leave_no_file(self):
        a = self.box()
        a.settings()
        out = os.path.join(self.root, "x.enc")
        self.assertEqual(hub_backup.ca_export(a.paths, "short", out=out, log=self.say), 3)
        self.assertEqual(hub_backup.ca_export(a.paths, "backup-passphrase-one", out=out, log=self.say), 3)   # same as backup.pass
        self.assertFalse(os.path.exists(out))
        W(out, "w", "exists")
        self.assertEqual(hub_backup.ca_export(a.paths, CA_PASS, out=out, log=self.say), 3)
        self.assertEqual(R(out), "exists")
        os.unlink(a.paths.ca_key)
        self.assertEqual(hub_backup.ca_export(a.paths, CA_PASS, out=out + "2", log=self.say), 3)


class RestoreTests(BackupCase):
    def export_key(self, box):
        out = os.path.join(self.root, "ca-export-%s.enc" % os.path.basename(box.root))
        self.assertEqual(hub_backup.ca_export(box.paths, CA_PASS, out=out, log=self.say), 0, self.log)
        return out

    def test_backup_then_restore_on_a_new_box_end_to_end(self):
        a = self.box("a")
        path = self.made_backup(a)
        key = self.export_key(a)
        # A fresh install on the new box: its own CA, its own settings, its own server certificate.
        b = self.box("b", ca_cn="Fresh CA")
        b.settings(public_ip=["192.0.2.50"], admin_ip=["192.0.2.1/32"], port=8443)
        fresh_ca = R(b.paths.ca_cert)
        os.makedirs(b.paths.tls_dir)
        W(b.paths.server_cert, "w", "OLD SERVER CERT")
        b.db.execute("INSERT INTO hosts (uuid, name, droplet_id, state, state_since, enrolled_at) VALUES ('fresh','fresh','1','active',1,1)")
        b.db.close()
        for f in (b.paths.db + "-wal", b.paths.db + "-shm"):
            if os.path.exists(f):
                os.unlink(f)
        # b has its own passphrase file: a restore uses the passphrase of the box it runs on.
        shutil.copy(a.paths.backup_pass, b.paths.backup_pass)
        code = hub_backup.restore(b.paths, path, ca_key=key, ca_passphrase=CA_PASS, log=self.say)
        self.assertEqual(code, 0, self.log)

        conn = sqlite3.connect(b.paths.db)
        self.assertEqual(conn.execute("SELECT name FROM hosts").fetchall(), [("web-1",)])         # the fresh state was replaced
        self.assertEqual(conn.execute("SELECT summary FROM events").fetchone()[0], "hello")
        self.assertEqual(conn.execute("SELECT cidr FROM never_ban").fetchone()[0], "198.51.100.0/24")
        # step 2: every token invalid, replies gone, login codes gone
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM tokens WHERE revoked_at IS NULL").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM tokens WHERE issued_reply IS NOT NULL").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM login_codes").fetchone()[0], 0)
        self.assertTrue(conn.execute("SELECT value FROM meta WHERE key='restored_at'").fetchone()[0].isdigit())
        self.assertEqual(conn.execute("PRAGMA quick_check").fetchone()[0], "ok")
        conn.close()
        # CA and key restored; same CA as on box a
        self.assertEqual(R(b.paths.ca_cert), R(a.paths.ca_cert))
        self.assertNotEqual(R(b.paths.ca_cert), fresh_ca)
        self.assertEqual(hub_backup._pubkey_of_key(b.paths.ca_key), hub_backup._pubkey_of_cert(b.paths.ca_cert))
        self.assertEqual(os.stat(b.paths.ca_key).st_mode & 0o777, 0o600)
        # step 3: server certificate reissued from the stored address list; the old one set aside, not restored
        self.assertEqual(FakePkiForRestore.instances[-1].issued, [["203.0.113.10"]])
        self.assertIn("NEW SERVER CERT", R(b.paths.server_cert))
        self.assertTrue(any("CA SHA-256" in x and hub_backup._ca_sha256(R(a.paths.ca_cert)) in x for x in self.log))
        # step 4: serials printed
        self.assertTrue(any("0aaa01" in x and "0aaa02" in x for x in self.log))
        self.assertTrue(any("beef01" in x for x in self.log))
        # revoked.txt carries the backup's lines; settings keep this box's installer-owned keys
        self.assertIn("0aaa02", R(b.paths.revoked))
        s = J(b.paths.settings)
        self.assertEqual(s["admin_ip"], ["192.0.2.1/32"])
        self.assertEqual(s["public_ip"], ["203.0.113.10"])
        self.assertEqual(s["secrets_set"], {})
        # secrets restored (not a drill)
        self.assertEqual(J(b.paths.secrets)["webhook_url"], "https://hooks.example.com/SECRETVALUE")
        # replaced files kept aside
        asides = [d for d in os.listdir(b.paths.state_dir) if d.startswith("restore-aside-")]
        self.assertEqual(len(asides), 1)
        self.assertTrue(os.path.exists(os.path.join(b.paths.state_dir, asides[0], "hub.db")))
        self.assertEqual(R(os.path.join(b.paths.state_dir, asides[0], "tls", "server.pem")), "OLD SERVER CERT")
        self.assertEqual([d for d in os.listdir(b.paths.state_dir) if d.startswith(".restore-")], [])    # staging removed
        self.assertEqual([x["outcome"] for x in self.pending(b)], ["started", "ok"])
        self.assertEqual(self.pending(b)[0]["op"], "restore")

    def test_restore_kills_queued_alerts_so_nothing_old_is_resent(self):
        a = self.box("a")
        a.settings()
        a.fill()
        now = hub_common.now_ms()
        for state in ("pending", "sending", "failed", "sent", "dead"):
            a.db.execute("INSERT INTO outbox (created, channel, severity, payload, next_try, state) VALUES (?,?,?,?,?,?)",
                         (now, "webhook", "HIGH", "{}", now, state))
        self.assertEqual(hub_backup.backup(a.paths, log=self.say), 0)
        path = os.path.join(a.paths.backup_dir, os.listdir(a.paths.backup_dir)[0])
        key = self.export_key(a)
        b = self.box("b")
        b.settings()
        shutil.copy(a.paths.backup_pass, b.paths.backup_pass)
        self.assertEqual(hub_backup.restore(b.paths, path, ca_key=key, ca_passphrase=CA_PASS, log=self.say), 0, self.log)
        conn = sqlite3.connect(b.paths.db)
        rows = dict(conn.execute("SELECT id, state || '|' || last_error FROM outbox").fetchall())
        conn.close()
        self.assertEqual(sorted(rows.values()), ["dead|", "dead|restored", "dead|restored", "dead|restored", "sent|"])

    def test_a_restored_database_ingests_its_pending_audit_lines_without_repeats(self):
        a = self.box("a")
        path = self.made_backup(a)
        b = self.box("b")
        b.settings()
        shutil.copy(a.paths.backup_pass, b.paths.backup_pass)
        key = self.export_key(a)
        self.assertEqual(hub_backup.restore(b.paths, path, ca_key=key, ca_passphrase=CA_PASS, log=self.say), 0, self.log)
        fake_alerts = S.FakeAlerts()
        hub = mock.Mock(paths=b.paths)
        conn = sqlite3.connect(b.paths.db, isolation_level=None)
        with mock.patch("hub_audit._alerts", lambda: fake_alerts):
            first = hub_audit.ingest_pending(conn, hub)
            again = hub_audit.ingest_pending(conn, hub)
        self.assertEqual((first, again), (2, 0))
        self.assertEqual(len(fake_alerts.notices), 1)
        conn.close()

    def test_in_place_restore_uses_the_key_on_the_box_when_it_matches(self):
        a = self.box("a")
        path = self.made_backup(a)
        key_before = R(a.paths.ca_key)
        a.db.execute("DELETE FROM events")
        a.db.execute("INSERT INTO hosts (uuid, name, droplet_id, state, state_since, enrolled_at) VALUES ('later','later','1','active',1,1)")
        with open(a.paths.revoked, "a") as f:
            f.write("0aaa03 " + "33" * 32 + "\n")                  # revoked after the backup
        a.db.close()
        code = hub_backup.restore(a.paths, path, log=self.say)
        self.assertEqual(code, 0, self.log)
        self.assertEqual(R(a.paths.ca_key), key_before)
        conn = sqlite3.connect(a.paths.db)
        self.assertEqual(conn.execute("SELECT summary FROM events").fetchone()[0], "hello")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM hosts WHERE name='later'").fetchone()[0], 0)
        conn.close()
        revoked = R(a.paths.revoked)
        for serial in ("0aaa01", "0aaa02", "0aaa03"):              # a revocation made after the backup is not lost
            self.assertIn(serial, revoked)

    def test_a_new_box_without_the_ca_key_is_refused_with_nothing_changed(self):
        a = self.box("a")
        path = self.made_backup(a)
        b = self.box("b", ca_cn="Fresh CA")
        b.settings()
        shutil.copy(a.paths.backup_pass, b.paths.backup_pass)
        b.db.close()
        before = tree_hash(b.root)
        self.assertEqual(hub_backup.restore(b.paths, path, log=self.say), 3)
        self.assertTrue(any("no usable CA key" in x for x in self.log))
        self.assertEqual([x["outcome"] for x in self.pending(b)], ["started", "refused"])
        self.assertEqual(FakePkiForRestore.instances, [])

    def test_nothing_changes_on_a_refusal(self):
        a = self.box("a")
        path = self.made_backup(a)
        b = self.box("b", ca_cn="Fresh CA")
        b.settings()
        shutil.copy(a.paths.backup_pass, b.paths.backup_pass)
        b.db.close()
        before = tree_hash(b.root)
        self.assertEqual(hub_backup.restore(b.paths, path, log=self.say), 3)
        # only the audit trail may differ (pending-audit.jsonl), and no staging directory is left
        pending = b.paths.pending_audit
        data = R(pending, "rb")
        os.unlink(pending)
        self.assertEqual(tree_hash(b.root), before)
        W(pending, "wb", data)

    def test_a_key_that_does_not_match_is_refused_with_nothing_changed(self):
        a = self.box("a")
        path = self.made_backup(a)
        c = self.box("c", ca_cn="Other CA")
        wrong = os.path.join(self.root, "wrong.enc")
        self.assertEqual(hub_backup.ca_export(c.paths, CA_PASS, out=wrong, log=self.say), 0)
        b = self.box("b", ca_cn="Fresh CA")
        b.settings()
        shutil.copy(a.paths.backup_pass, b.paths.backup_pass)
        b.db.close()
        before = tree_hash(b.root)
        self.assertEqual(hub_backup.restore(b.paths, path, ca_key=wrong, ca_passphrase=CA_PASS, log=self.say), 3)
        self.assertEqual(hub_backup.restore(b.paths, path, ca_key=self.export_key(a), ca_passphrase="wrong passphrase!", log=self.say), 3)
        os.unlink(b.paths.pending_audit)
        self.assertEqual(tree_hash(b.root), before)

    def test_restore_refuses_while_the_hub_runs(self):
        a = self.box("a")
        path = self.made_backup(a)
        key = self.export_key(a)
        b = self.box("b")
        b.settings()
        shutil.copy(a.paths.backup_pass, b.paths.backup_pass)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(b.paths.ctl_sock)
        srv.listen(1)
        self.addCleanup(srv.close)
        b.db.close()
        before = self.slurp(b.paths.db)
        self.assertEqual(hub_backup.restore(b.paths, path, ca_key=key, ca_passphrase=CA_PASS, log=self.say), 3)
        self.assertTrue(any("running" in x for x in self.log))
        self.assertEqual(self.slurp(b.paths.db), before)

    def test_a_stale_socket_file_does_not_count_as_running(self):
        a = self.box("a")
        path = self.made_backup(a)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(a.paths.ctl_sock)
        srv.close()                                                # the file stays, nobody listens
        a.db.close()
        self.assertEqual(hub_backup.restore(a.paths, path, log=self.say), 0, self.log)

    def test_drill_skips_the_secrets_and_switches_no_channel_on(self):
        a = self.box("a")
        a.settings(secrets_set={"webhook_url": "hooks.example.com …alue"})
        a.fill()
        self.assertEqual(hub_backup.backup(a.paths, log=self.say), 0)
        path = os.path.join(a.paths.backup_dir, os.listdir(a.paths.backup_dir)[0])
        key = self.export_key(a)
        b = self.box("b")
        b.settings()
        shutil.copy(a.paths.backup_pass, b.paths.backup_pass)
        self.assertFalse(os.path.exists(b.paths.secrets))
        code = hub_backup.restore(b.paths, path, ca_key=key, ca_passphrase=CA_PASS, drill=True, log=self.say)
        self.assertEqual(code, 0, self.log)
        self.assertFalse(os.path.exists(b.paths.secrets))
        self.assertEqual(J(b.paths.settings)["secrets_set"], {})
        self.assertEqual(hub_common.enabled_channels(hub_common.load_settings(b.paths)), [])
        self.assertTrue(any("drill" in x for x in self.log))

    def test_public_ip_adds_to_the_san_list_and_the_limit_is_four(self):
        a = self.box("a")
        path = self.made_backup(a)
        key = self.export_key(a)
        b = self.box("b")
        b.settings()
        shutil.copy(a.paths.backup_pass, b.paths.backup_pass)
        self.assertEqual(hub_backup.restore(b.paths, path, ca_key=key, ca_passphrase=CA_PASS,
                                            public_ips=["192.0.2.77", "203.0.113.10"], log=self.say), 0, self.log)
        self.assertEqual(FakePkiForRestore.instances[-1].issued, [["203.0.113.10", "192.0.2.77"]])
        self.assertEqual(J(b.paths.settings)["public_ip"], ["203.0.113.10", "192.0.2.77"])
        c = self.box("c")
        c.settings()
        shutil.copy(a.paths.backup_pass, c.paths.backup_pass)
        self.assertEqual(hub_backup.restore(c.paths, path, ca_key=key, ca_passphrase=CA_PASS,
                                            public_ips=["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"], log=self.say), 3)
        self.assertEqual(hub_backup.restore(c.paths, path, ca_key=key, ca_passphrase=CA_PASS, public_ips=["nonsense"], log=self.say), 3)

    def test_a_failure_after_the_swap_rolls_everything_back(self):
        a = self.box("a")
        path = self.made_backup(a)
        key = self.export_key(a)
        b = self.box("b", ca_cn="Fresh CA")
        b.settings(public_ip=["192.0.2.50"])
        shutil.copy(a.paths.backup_pass, b.paths.backup_pass)
        b.db.execute("INSERT INTO hosts (uuid, name, droplet_id, state, state_since, enrolled_at) VALUES ('fresh','fresh','1','active',1,1)")
        b.db.close()
        ca_before = R(b.paths.ca_cert)
        key_before = R(b.paths.ca_key)
        with mock.patch.object(FakePkiForRestore, "issue_server_cert", side_effect=RuntimeError("openssl failed")):
            code = hub_backup.restore(b.paths, path, ca_key=key, ca_passphrase=CA_PASS, log=self.say)
        self.assertEqual(code, 2)
        conn = sqlite3.connect(b.paths.db)
        self.assertEqual(conn.execute("SELECT name FROM hosts").fetchall(), [("fresh",)])
        conn.close()
        self.assertEqual(R(b.paths.ca_cert), ca_before)
        self.assertEqual(R(b.paths.ca_key), key_before)
        self.assertEqual(J(b.paths.settings)["public_ip"], ["192.0.2.50"])
        self.assertEqual([x["outcome"] for x in self.pending(b)], ["started", "error"])

    def test_a_damaged_backup_changes_nothing(self):
        a = self.box("a")
        path = self.made_backup(a)
        raw = bytearray(R(path, "rb"))
        raw[300] ^= 0x55
        W(path, "wb", bytes(raw))
        key = self.export_key(a)
        b = self.box("b")
        b.settings()
        shutil.copy(a.paths.backup_pass, b.paths.backup_pass)
        b.db.close()
        before = self.slurp(b.paths.db)
        self.assertEqual(hub_backup.restore(b.paths, path, ca_key=key, ca_passphrase=CA_PASS, log=self.say), 2)
        self.assertEqual(self.slurp(b.paths.db), before)
        self.assertEqual([d for d in os.listdir(b.paths.state_dir) if d.startswith(".restore-") or d.startswith("restore-aside")], [])

    def test_missing_file_is_refused(self):
        b = self.box("b")
        b.settings()
        self.assertEqual(hub_backup.restore(b.paths, os.path.join(self.root, "nope.bak"), log=self.say), 3)

    def test_restore_refuses_a_link_in_the_state_directory_and_changes_nothing(self):
        a = self.box("a")
        path = self.made_backup(a)
        key = self.export_key(a)
        b = self.box("b", ca_cn="Fresh CA")
        b.settings()
        shutil.copy(a.paths.backup_pass, b.paths.backup_pass)
        b.db.close()
        victim = os.path.join(self.root, "victim")
        W(victim, "VICTIM")
        os.symlink(victim, b.paths.settings + ".link")
        os.rename(b.paths.settings, b.paths.settings + ".real")
        os.symlink(b.paths.settings + ".real", b.paths.settings)
        before = self.slurp(b.paths.db)
        self.assertEqual(hub_backup.restore(b.paths, path, ca_key=key, ca_passphrase=CA_PASS, log=self.say), 3)
        self.assertTrue(any("is a link" in x for x in self.log))
        self.assertEqual(self.slurp(b.paths.db), before)
        self.assertEqual(R(victim), "VICTIM")

    def test_the_aside_directory_has_a_random_name_and_a_planted_name_is_not_used(self):
        a = self.box("a")
        path = self.made_backup(a)
        key = self.export_key(a)
        b = self.box("b", ca_cn="Fresh CA")
        b.settings()
        shutil.copy(a.paths.backup_pass, b.paths.backup_pass)
        b.db.close()
        elsewhere = os.path.join(self.root, "elsewhere")
        os.makedirs(elsewhere)
        for stamp in ("20200101T000000Z", time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())):
            os.symlink(elsewhere, os.path.join(b.paths.state_dir, "restore-aside-" + stamp))
        self.assertEqual(hub_backup.restore(b.paths, path, ca_key=key, ca_passphrase=CA_PASS, log=self.say), 0, self.log)
        self.assertEqual(os.listdir(elsewhere), [])
        real = [d for d in os.listdir(b.paths.state_dir) if d.startswith("restore-aside-") and not os.path.islink(os.path.join(b.paths.state_dir, d))]
        self.assertEqual(len(real), 1)
        self.assertEqual(os.stat(os.path.join(b.paths.state_dir, real[0])).st_mode & 0o777, 0o700)

    def test_a_restore_leaves_no_temporary_file_behind(self):
        a = self.box("a")
        path = self.made_backup(a)
        a.db.close()
        self.assertEqual(hub_backup.restore(a.paths, path, log=self.say), 0, self.log)
        for base, _dirs, files in os.walk(a.paths.state_dir):
            self.assertEqual([f for f in files if ".restore-" in f], [], base)


if __name__ == "__main__":
    unittest.main()
