import gzip
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_daemon_support import Tmp                                    # noqa: E402
from edragent import tail                                               # noqa: E402


class TailCase(Tmp):
    def setUp(self):
        super().setUp()
        self.log = os.path.join(self.root, "logs", "app.log")
        os.makedirs(os.path.dirname(self.log))
        self.cursors = self.paths.cursors_dir

    def tailer(self, **kw):
        kw.setdefault("first_start", "begin")
        kw.setdefault("clock", self.clock)
        t = tail.Tailer(self.log, "app", self.cursors, **kw)
        self.addCleanup(lambda: t.f is not None and t.f.close())
        return t


class TestLines(TailCase):
    def test_complete_lines_only_and_partial_waits(self):
        t = self.tailer()
        self.assertEqual(t.poll(), [])                          # the file does not exist yet: normal
        self.write(self.log, "one\ntwo\nthr")
        self.assertEqual(t.poll(), ["one", "two"])
        self.append(self.log, "ee\nfour\n")
        self.assertEqual(t.poll(), ["three", "four"])
        self.assertEqual(t.poll(), [])

    def test_crlf_and_bad_utf8(self):
        self.write(self.log, "")
        with open(self.log, "wb") as f:
            f.write(b"a\r\nb\xff\xfe\n")
        self.assertEqual(self.tailer().poll(), ["a", "b��"])

    def test_long_lines_are_cut_and_counted(self):
        t = self.tailer(max_line=100)
        self.write(self.log, "x" * 5000 + "\nshort\n" + "y" * 300)
        self.assertEqual(t.poll(), ["x" * 100, "short", "y" * 100])
        self.assertEqual(t.counters["truncated"], 2)
        self.append(self.log, "z" * 50 + "\nnext\n")                      # the rest of the long line is discarded
        self.assertEqual(t.poll(), ["next"])

    def test_first_start_end_skips_what_is_there(self):
        self.write(self.log, "old1\nold2\n")
        t = self.tailer(first_start="end")
        self.assertEqual(t.poll(), [])
        self.append(self.log, "new\n")
        self.assertEqual(t.poll(), ["new"])

    def test_first_start_end_drops_the_end_of_a_half_written_line(self):
        self.write(self.log, "old\nhalf wri")
        t = self.tailer(first_start="end")
        self.assertEqual(t.poll(), [])
        self.append(self.log, "tten\nnew\n")
        self.assertEqual(t.poll(), ["new"])

    def test_max_lines_limit(self):
        self.write(self.log, "".join("l%d\n" % i for i in range(50)))
        t = self.tailer()
        got = t.poll(max_lines=10)
        self.assertGreaterEqual(len(got), 10)
        rest = t.poll(max_lines=1000)
        self.assertEqual(len(got) + len(rest), 50)


class TestCheckpoint(TailCase):
    def test_resume_continues_without_repeating_or_losing(self):
        t = self.tailer()
        self.write(self.log, "a\nb\n")
        self.assertEqual(t.poll(), ["a", "b"])
        t.commit()
        t.close()
        self.append(self.log, "c\nd\n")                                  # written while the agent was down
        t2 = self.tailer()
        self.assertEqual(t2.poll(), ["c", "d"])
        self.assertEqual(t2.drain_notices(), [])

    def test_no_commit_means_the_lines_come_again(self):
        t = self.tailer()
        self.write(self.log, "a\nb\n")
        t.poll()
        t.close = lambda: None                                          # a crash: no commit
        t2 = self.tailer()
        self.assertEqual(t2.poll(), ["a", "b"])

    def test_checkpoint_file_holds_inode_offset_and_head_hash(self):
        t = self.tailer()
        self.write(self.log, "hello world\n")
        t.poll()
        t.commit()
        with open(os.path.join(self.cursors, "app.json")) as f:
            cur = json.load(f)
        st = os.stat(self.log)
        self.assertEqual((cur["dev"], cur["ino"], cur["offset"]), (st.st_dev, st.st_ino, 12))
        self.assertEqual(len(cur["head_hash"]), 40)

    def test_commit_is_not_rewritten_when_nothing_changed(self):
        t = self.tailer()
        self.write(self.log, "a\n")
        t.poll()
        t.commit()
        path = os.path.join(self.cursors, "app.json")
        os.utime(path, (1, 1))
        t.commit()
        self.assertEqual(os.stat(path).st_mtime, 1)


class TestRotation(TailCase):
    def test_rotation_while_running_finishes_the_old_file_after_10_seconds_of_eof(self):
        t = self.tailer()
        self.write(self.log, "a\nb\n")
        self.assertEqual(t.poll(), ["a", "b"])
        os.rename(self.log, self.log + ".1")
        self.write(self.log, "n1\n")
        self.assertEqual(t.poll(), [])                                  # still on the old file, EOF clock starts
        self.append(self.log + ".1", "late\n")                          # nginx writes to it until USR1
        self.assertEqual(t.poll(), ["late"])
        self.clock.advance(5)
        self.assertEqual(t.poll(), [])
        self.clock.advance(6)
        self.assertEqual(t.poll(), ["n1"])                              # switches now and reads on
        self.assertEqual([n["type"] for n in t.drain_notices()], ["rotated"])

    def test_rotation_while_down_reads_the_rest_of_the_older_file_then_the_new_one(self):
        t = self.tailer()
        self.write(self.log, "a\nb\n")
        t.poll()
        t.commit()
        t.close()
        self.append(self.log, "c\n")
        os.rename(self.log, self.log + ".1")
        self.write(self.log, "n1\nn2\n")
        t2 = self.tailer()
        got = t2.poll() + t2.poll()
        self.assertEqual(got, ["c", "n1", "n2"])
        self.assertEqual([n["type"] for n in t2.drain_notices() if n["type"] == "gap"], [])

    def test_rotation_while_down_with_a_gz_is_best_effort(self):
        t = self.tailer()
        self.write(self.log, "a\nb\n")
        t.poll()
        t.commit()
        t.close()
        self.append(self.log, "c\n")
        with open(self.log, "rb") as f:
            data = f.read()
        with gzip.open(self.log + ".2.gz", "wb") as g:
            g.write(data)
        os.unlink(self.log)
        self.write(self.log, "n1\n")
        t2 = self.tailer()
        got = t2.poll() + t2.poll()
        self.assertEqual(got, ["c", "n1"])

    def test_rotated_file_that_is_gone_is_a_gap(self):
        t = self.tailer()
        self.write(self.log, "a\nb\n")
        t.poll()
        t.commit()
        t.close()
        os.unlink(self.log)
        self.write(self.log, "n1\n")
        t2 = self.tailer()
        self.assertEqual(t2.poll(), ["n1"])
        kinds = [(n["type"], n.get("reason")) for n in t2.drain_notices()]
        self.assertIn(("gap", "rotated_unread"), kinds)

    def test_file_deleted_and_recreated_while_running(self):
        t = self.tailer()
        self.write(self.log, "a\n")
        t.poll()
        os.unlink(self.log)
        self.write(self.log, "b\n")
        self.assertEqual(t.poll(), [])
        self.clock.advance(11)
        self.assertEqual(t.poll(), ["b"])


class TestShrink(TailCase):
    def test_copytruncate_restarts_at_zero_reports_a_gap(self):
        t = self.tailer()
        self.write(self.log, "aaaa\nbbbb\ncccc\n")
        t.poll()
        with open(self.log, "w") as f:                                   # same inode, smaller
            f.write("new\n")
        self.assertEqual(t.poll(), ["new"])
        notes = t.drain_notices()
        self.assertEqual([n["type"] for n in notes], ["truncated"])
        self.assertEqual(t.counters["gaps"], 1)

    def test_shrink_while_down_is_found_on_resume(self):
        t = self.tailer()
        self.write(self.log, "aaaa\nbbbb\ncccc\n")
        t.poll()
        t.commit()
        t.close()
        with open(self.log, "w") as f:
            f.write("x\n")
        t2 = self.tailer()
        self.assertEqual(t2.poll(), ["x"])
        self.assertEqual([n["type"] for n in t2.drain_notices()], ["truncated"])

    def test_same_inode_rewritten_with_other_head_is_a_truncation(self):
        t = self.tailer()
        self.write(self.log, "AAAA first line\nsecond line\n")
        t.poll()
        t.commit()
        t.close()
        with open(self.log, "r+") as f:                                  # same size, same inode, other content
            f.write("ZZZZ")
        t2 = self.tailer()
        t2.poll()
        self.assertEqual([n["type"] for n in t2.drain_notices()], ["truncated"])

    def test_truncation_becomes_a_high_tamper_event(self):
        from edragent.sources import base
        ctx = base.Context(self.conf(""), self.paths, self.clock)
        s = base.Source(ctx)
        events = s.on_notice({"type": "truncated", "reason": "shrunk", "offset": 99}, "eve.json")
        self.assertEqual(events[0]["kind"], "tamper.log_truncated")
        self.assertEqual(events[0]["sev"], "HIGH")


class TestBacklog(TailCase):
    def test_more_than_the_byte_limit_is_skipped_with_one_gap(self):
        t = self.tailer(backlog_bytes=1000)
        self.write(self.log, "a\n")
        t.poll()
        t.commit()
        t.close()
        self.append(self.log, "".join("line%04d\n" % i for i in range(500)))      # 4500 bytes unread
        os.utime(self.log, (self.clock(), self.clock()))
        t2 = self.tailer(backlog_bytes=1000)
        got = t2.poll()
        self.assertLessEqual(sum(len(x) + 1 for x in got), 1000)
        self.assertEqual(got[-1], "line0499")
        self.assertTrue(all(x.startswith("line") for x in got))                   # no half line at the front
        gaps = [n for n in t2.drain_notices() if n["type"] == "gap"]
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["reason"], "backlog_size")

    def test_older_than_24_hours_is_skipped(self):
        t = self.tailer()
        self.write(self.log, "a\n")
        t.poll()
        t.commit()
        t.close()
        self.append(self.log, "b\nc\n")
        os.utime(self.log, (self.clock() - 90000, self.clock() - 90000))
        t2 = self.tailer()
        self.assertEqual(t2.poll(), [])
        gaps = [n for n in t2.drain_notices() if n["type"] == "gap"]
        self.assertEqual(gaps[0]["reason"], "backlog_age")
        self.append(self.log, "d\n")
        self.assertEqual(t2.poll(), ["d"])


class TestSpecialFiles(TailCase):
    def test_a_fifo_is_not_opened_as_a_regular_file(self):
        os.mkfifo(self.log)
        t = self.tailer()
        self.assertEqual(t.poll(), [])                                   # refused, no hang

    def test_a_symlink_is_not_followed(self):
        target = self.write(os.path.join(self.root, "secret"), "s\n")
        os.symlink(target, self.log)
        self.assertEqual(self.tailer().poll(), [])

    @unittest.skipIf(os.geteuid() == 0, "root reads everything")
    def test_unreadable_is_reported_once(self):
        self.write(self.log, "a\n", mode=0)
        t = self.tailer()
        self.assertEqual(t.poll(), [])
        self.assertEqual(t.poll(), [])
        notes = t.drain_notices()
        self.assertEqual([n["type"] for n in notes], ["unreadable"])

    def test_fifo_reader_and_chooser(self):
        fifo = os.path.join(self.root, "kern.fifo")
        os.mkfifo(fifo)
        src = tail.open_line_source(fifo, "kernel", self.cursors)
        self.assertIsInstance(src, tail.FifoReader)
        self.assertEqual(src.poll(), [])
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.write(fd, b"edr-bigconn: one\nedr-bigconn: tw")
        self.assertEqual(src.poll(), ["edr-bigconn: one"])
        os.write(fd, b"o\n")
        self.assertEqual(src.poll(), ["edr-bigconn: two"])
        os.close(fd)
        self.assertEqual(src.poll(), [])
        src.close()
        plain = tail.open_line_source(self.log, "kernel", self.cursors)
        self.assertIsInstance(plain, tail.Tailer)


class FakeProc:
    def __init__(self, argv, payload=b"", code=None):
        self.argv = argv
        r, w = os.pipe()
        self.stdout = os.fdopen(r, "rb", buffering=0)
        os.write(w, payload)
        self._w = w
        self.code = code
        if code is not None:
            os.close(w)
            self._w = None

    def write(self, data):
        os.write(self._w, data)

    def poll(self):
        return self.code

    def terminate(self):
        self.code = -15

    def kill(self):
        self.code = -9

    def wait(self, timeout=None):
        return self.code


class TestJournal(TailCase):
    def follower(self, procs, **kw):
        launched = []

        def popen(argv, **kwargs):
            p = procs.pop(0)(argv)
            launched.append(p)
            return p
        j = tail.JournalFollower("journal", ["_COMM=sshd", "_UID=0"], self.cursors, popen=popen, clock=self.clock, **kw)
        j.launched = launched
        self.addCleanup(lambda: [p.stdout.close() for p in launched])
        return j

    @staticmethod
    def rec(n, **kw):
        d = {"__CURSOR": "s=c%d" % n, "__REALTIME_TIMESTAMP": str(1795000000000000 + n), "MESSAGE": "m%d" % n}
        d.update(kw)
        return (json.dumps(d) + "\n").encode()

    def test_records_and_cursor(self):
        j = self.follower([lambda argv: FakeProc(argv, self.rec(1) + self.rec(2) + b"not json\n" + self.rec(3)[:10])])
        got = j.poll()
        self.assertEqual([r["MESSAGE"] for r in got], ["m1", "m2"])
        self.assertEqual(j.counters["bad_json"], 1)
        argv = j.launched[0].argv
        self.assertIn("-f", argv)
        self.assertIn("-o", argv)
        self.assertIn("json", argv)
        self.assertEqual(argv[-2:], ["_COMM=sshd", "_UID=0"])
        self.assertIn("-n", argv)                                         # nothing stored yet: only new records
        j.commit()
        with open(os.path.join(self.cursors, "journal.json")) as f:
            self.assertEqual(json.load(f)["cursor"], "s=c2")
        j.close()

    def test_resume_uses_after_cursor(self):
        j = self.follower([lambda argv: FakeProc(argv, self.rec(7))])
        j.poll()
        j.commit()
        j.close()
        j2 = self.follower([lambda argv: FakeProc(argv, self.rec(8))])
        self.assertEqual([r["MESSAGE"] for r in j2.poll()], ["m8"])
        self.assertIn("--after-cursor=s=c7", j2.launched[0].argv)

    def test_a_vacuumed_cursor_falls_back_to_since_and_reports_a_gap(self):
        j = self.follower([lambda argv: FakeProc(argv, self.rec(7))])
        j.poll()
        j.commit()
        j.close()
        j2 = self.follower([lambda argv: FakeProc(argv, b"", code=1), lambda argv: FakeProc(argv, self.rec(9))])
        got = j2.poll()                                                   # journalctl failed at once, then it restarts by time
        got = got or j2.poll()
        self.assertEqual([r["MESSAGE"] for r in got], ["m9"])
        since = [a for a in j2.launched[1].argv if a.startswith("--since=")]
        self.assertEqual(len(since), 1)
        self.assertEqual([n["type"] for n in j2.drain_notices()], ["gap"])

    def test_a_dead_journalctl_is_restarted_with_backoff(self):
        j = self.follower([lambda argv: FakeProc(argv, self.rec(1), code=0), lambda argv: FakeProc(argv, self.rec(2))])
        self.assertEqual(len(j.poll()), 1)
        self.assertEqual(j.poll(), [])
        self.clock.advance(1)
        self.assertEqual(j.poll(), [])                                    # not yet
        self.clock.advance(10)
        self.assertEqual(len(j.poll()), 1)

    def test_kernel_flag_and_output_fields(self):
        j = tail.JournalFollower("kernel", [], self.cursors, kernel=True, popen=lambda argv, **kw: FakeProc(argv), clock=self.clock)
        j.poll()
        argv = j.proc.argv
        self.assertIn("-k", argv)
        self.assertTrue(any(a.startswith("--output-fields=") for a in argv))


if __name__ == "__main__":
    unittest.main()
