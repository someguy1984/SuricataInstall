import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import test_transport_pki  # noqa: F401  (puts the code on sys.path)
from edragent import spool as sp


def ev(n, sev="LOW", kind="x.y", source="nginx", **extra):
    d = {"v": 1, "id": "0000abcd:%d" % n, "epoch": 0xabcd, "seq": n, "ts": "2026-11-19T10:00:00.000Z",
         "sev": sev, "kind": kind, "source": source, "summary": "s%d" % n, "pad": "x" * 100}
    d.update(extra)
    return d


class SpoolBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="a5spool-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def open(self, **kw):
        kw.setdefault("seg_size", 2000)
        return sp.Spool(os.path.join(self.dir, "spool"), **kw)

    def drain(self, s, n=500):
        out = []
        while True:
            b = s.next_batch(max_events=n)
            if b is None:
                return out
            out.extend(b.events)
            s.ack(b)


class TestLanesAndOrder(SpoolBase):
    def test_roundtrip_and_lane_routing(self):
        s = self.open()
        for i in range(3):
            self.assertTrue(s.append(ev(i, "LOW")))
        self.assertTrue(s.append(ev(10, "HIGH")))
        self.assertTrue(s.append(ev(11, "CRITICAL")))
        self.assertEqual(s.depth("hi"), 2)
        self.assertEqual(s.depth("lo"), 3)
        got = self.drain(s)
        self.assertEqual([e["seq"] for e in got], [10, 11, 0, 1, 2])      # hi first, then lo, each oldest first
        self.assertEqual(s.depth(), 0)

    def test_info_and_medium_are_lo(self):
        s = self.open()
        for sev in ("INFO", "LOW", "MEDIUM"):
            self.assertEqual(s.lane_for({"sev": sev}), "lo")
        for sev in ("HIGH", "CRITICAL"):
            self.assertEqual(s.lane_for({"sev": sev}), "hi")

    def test_batch_limits(self):
        s = self.open(seg_size=10 * 1024 * 1024)
        for i in range(30):
            s.append(ev(i))
        b = s.next_batch(max_events=10)
        self.assertEqual(len(b), 10)
        b2 = s.next_batch(max_events=500, max_raw=1000)
        self.assertLess(len(b2), 30)
        self.assertGreaterEqual(len(b2), 1)
        # a batch never crosses a segment
        s2 = sp.Spool(os.path.join(self.dir, "spool2"), seg_size=1500)
        for i in range(30):
            s2.append(ev(i + 100))
        first = s2.next_batch()
        self.assertTrue(len({i.event["seq"] for i in first.items}) == len(first.items))
        self.assertLess(len(first), 30)

    def test_partial_ack_offsets_survive_reopen(self):
        s = self.open(seg_size=10 * 1024 * 1024)
        for i in range(10):
            s.append(ev(i))
        s.sync()
        b = s.next_batch()
        s.ack(b, 4)
        self.assertEqual(s.depth(), 6)
        s.close()
        s2 = self.open(seg_size=10 * 1024 * 1024)
        self.assertEqual(s2.depth(), 6)
        got = self.drain(s2)
        self.assertEqual([e["seq"] for e in got], [4, 5, 6, 7, 8, 9])
        self.assertEqual(s2.depth(), 0)

    def test_acked_segments_are_deleted_whole(self):
        s = self.open(seg_size=1000)
        for i in range(20):
            s.append(ev(i))
        lo_dir = os.path.join(self.dir, "spool", "lo")
        before = [n for n in os.listdir(lo_dir) if n.startswith("seg-")]
        self.assertGreater(len(before), 2)
        b = s.next_batch()
        s.ack(b)
        after = [n for n in os.listdir(lo_dir) if n.startswith("seg-")]
        self.assertEqual(len(after), len(before) - 1)
        self.drain(s)
        self.assertEqual([n for n in os.listdir(lo_dir) if n.startswith("seg-")], [])

    def test_crash_cut_last_line_is_repaired(self):
        s = self.open(seg_size=10 * 1024 * 1024)
        s.append(ev(1))
        s.append(ev(2))
        s.close()
        lo_dir = os.path.join(self.dir, "spool", "lo")
        seg = os.path.join(lo_dir, sorted(n for n in os.listdir(lo_dir) if n.startswith("seg-"))[-1])
        with open(seg, "ab") as f:
            f.write(b'{"id": "cut off')           # a write that never finished
        s2 = self.open(seg_size=10 * 1024 * 1024)
        s2.append(ev(3))
        got = self.drain(s2)
        self.assertEqual([e["seq"] for e in got], [1, 2, 3])
        self.assertEqual(s2.corrupt, 1)

    def test_oversize_event_goes_to_rejected(self):
        s = self.open()
        self.assertFalse(s.append(ev(1, summary="y" * 20000)))
        self.assertEqual(s.depth(), 0)
        self.assertEqual(s.stats()["rejected"], 1)
        self.assertGreater(s.rejected_bytes(), 0)


class TestFsync(SpoolBase):
    def test_critical_synced_at_once_low_in_groups(self):
        s = self.open(seg_size=10 * 1024 * 1024)
        with mock.patch.object(sp.os, "fsync") as fs:
            s.append(ev(1, "LOW"))
            s.append(ev(2, "MEDIUM"))
            base = fs.call_count                              # a new segment also syncs its directory
            s.append(ev(3, "CRITICAL"))
            self.assertGreater(fs.call_count, base)           # CRITICAL: now
            s.append(ev(4, "HIGH"))
            c2 = fs.call_count
            s.append(ev(5, "LOW"))
            self.assertEqual(fs.call_count, c2)               # LOW: not yet
            s.sync()
            self.assertGreater(fs.call_count, c2)             # group commit
            c3 = fs.call_count
            s.sync()
            self.assertEqual(fs.call_count, c3)               # nothing dirty


class TestEviction(SpoolBase):
    def test_lo_evicted_before_hi_whole_segments_one_record(self):
        s = self.open(seg_size=1000, hi_cap=4000, lo_cap=3000)
        for i in range(4):
            s.append(ev(i, "HIGH"))
        for i in range(100, 160):
            s.append(ev(i, "LOW", kind="scan.hit"))
        recs = s.take_drops()
        self.assertTrue(recs)
        self.assertTrue(all(r["lane"] == "lo" for r in recs))
        self.assertEqual(s.depth("hi"), 4)                    # evidence in hi is untouched
        lo = s.lanes["lo"]
        self.assertLessEqual(lo.bytes(), 3000 + 1000)
        self.assertEqual(s.stats()["dropped"]["lo"], sum(r["count"] for r in recs))
        self.assertEqual(recs[0]["kinds"], {"scan.hit": recs[0]["count"]})
        # the survivors are the newest, in order
        got = self.drain(s)
        lo_seqs = [e["seq"] for e in got if e["sev"] == "LOW"]
        self.assertEqual(lo_seqs, sorted(lo_seqs))
        self.assertEqual(lo_seqs[-1], 159)
        self.assertEqual(s.take_drops(), [])

    def test_one_record_per_pass_and_lo_listed_before_hi(self):
        s = self.open(seg_size=500, hi_cap=1000, lo_cap=1000)
        for i in range(30):
            s.append(ev(i, "HIGH", kind="tetragon.nginx-exec", source="tetragon"))
            s.append(ev(i + 1000, "LOW"))
        recs = s.take_drops()
        lanes = [r["lane"] for r in recs]
        self.assertIn("lo", lanes)
        self.assertIn("hi", lanes)
        stats = s.stats()
        self.assertEqual(stats["dropped"]["hi"] + stats["dropped"]["lo"], sum(r["count"] for r in recs))
        self.assertIn("tetragon", stats["dropped_by_source"])

    def test_hi_collapsed_repeats_go_before_first_occurrences(self):
        s = self.open(seg_size=1500, hi_cap=9600, lo_cap=10000)
        # first segment: collapsed repeats (count > 1); later segments: singletons
        for i in range(8):
            s.append(ev(i, "HIGH", count=5, first_ts="2026-11-19T10:00:00.000Z", last_ts="2026-11-19T10:04:00.000Z"))
        for i in range(100, 130):
            s.append(ev(i, "HIGH", kind="tetragon.nginx-exec"))
        got = self.drain(s)
        singles = [e for e in got if "count" not in e]
        self.assertEqual(len(singles), 30)                    # no first occurrence was lost
        recs = s.take_drops()
        self.assertTrue(recs)
        self.assertGreaterEqual(sum(r["count"] for r in recs), 1)

    def test_disk_pressure_empties_lo_and_caps_it(self):
        with mock.patch.object(sp, "LO_CAP_PRESSURE", 2000), mock.patch.object(sp, "HI_CAP_PRESSURE", 3000):
            s = self.open(seg_size=1000, hi_cap=6000, lo_cap=20000)
            for i in range(20):
                s.append(ev(i, "LOW"))
            for i in range(6):
                s.append(ev(100 + i, "HIGH"))
            self.assertEqual(s.depth("lo"), 20)
            s.set_disk_pressure(True)
            self.assertEqual(s.depth("lo"), 0)               # emptied first
            recs = s.take_drops()
            self.assertEqual(sum(r["count"] for r in recs if r["lane"] == "lo"), 20)
            for i in range(200, 240):
                s.append(ev(i, "LOW"))
            self.assertLessEqual(s.lanes["lo"].bytes(), 2000 + 1000)
            s.set_disk_pressure(False)
            self.assertEqual(s.lanes["lo"].cap, 20000)

    def test_clear_discards_without_counting(self):
        s = self.open()
        for i in range(10):
            s.append(ev(i))
        s.clear()
        self.assertEqual(s.depth(), 0)
        self.assertEqual(s.stats()["dropped"], {"hi": 0, "lo": 0})
        s.append(ev(50))
        self.assertEqual(self.drain(s)[0]["seq"], 50)

    def test_drop_counters_persist(self):
        s = self.open(seg_size=500, lo_cap=1000)
        for i in range(40):
            s.append(ev(i))
        n = s.stats()["dropped"]["lo"]
        self.assertGreater(n, 0)
        s.close()
        s2 = self.open(seg_size=500, lo_cap=1000)
        self.assertEqual(s2.stats()["dropped"]["lo"], n)


class TestInFlightBatches(SpoolBase):
    def test_an_ack_for_a_batch_read_before_a_thinning_is_ignored(self):
        s = self.open(seg_size=1500, hi_cap=100000, lo_cap=100000)
        for i in range(8):
            s.append(ev(i, "HIGH", count=5))
        for i in range(100, 108):
            s.append(ev(i, "HIGH"))
        b = s.next_batch()                                     # in flight: read from the oldest segment
        first = b.items[0].event["seq"]
        s.lanes["hi"].cap = 4000                               # pressure arrives: the oldest segment is thinned
        s.append(ev(200, "HIGH"))
        before = s.depth()
        s.ack(b)                                               # the offsets of the old file mean nothing now
        self.assertEqual(s.depth(), before)
        got = self.drain(s)
        self.assertTrue(all(e["seq"] != first or e.get("count") is None for e in got))
        self.assertIn(200, [e["seq"] for e in got])

    def test_segment_numbers_are_never_reused(self):
        s = self.open(seg_size=1000)
        for i in range(6):
            s.append(ev(i))
        b = s.next_batch()
        s.clear()                                              # every segment gone
        s.append(ev(50))
        s.ack(b)                                               # a stale ack must not eat the new event
        self.assertEqual(s.depth(), 1)
        self.assertEqual([e["seq"] for e in self.drain(s)], [50])

    def test_fully_acked_segment_and_stale_ack_file_are_cleaned_at_open(self):
        s = self.open(seg_size=10 * 1024 * 1024)
        for i in range(4):
            s.append(ev(i))
        s.sync()
        b = s.next_batch()
        s.ack(b, 2)
        s.close()
        lo = os.path.join(self.dir, "spool", "lo")
        seg = [n for n in os.listdir(lo) if n.startswith("seg-")][0]
        with open(os.path.join(lo, "ack.json"), "w") as f:
            json.dump({"seg": 1, "off": os.path.getsize(os.path.join(lo, seg)), "lines": 4}, f)   # a crash after the ack, before the delete
        s2 = self.open(seg_size=10 * 1024 * 1024)
        self.assertEqual(s2.depth(), 0)
        self.assertFalse(os.path.exists(os.path.join(lo, "ack.json")))
        s2.append(ev(60))
        s2.close()
        s3 = self.open(seg_size=10 * 1024 * 1024)
        self.assertEqual([e["seq"] for e in self.drain(s3)], [60])


class TestRejected(SpoolBase):
    def test_rejected_is_capped_and_counted(self):
        with mock.patch.object(sp, "REJECT_SEG", 600):
            s = self.open(reject_cap=2000)
            for i in range(50):
                s.reject([ev(i)], "refused 400")
            self.assertEqual(s.stats()["rejected"], 50)
            self.assertLessEqual(s.rejected_bytes(), 2000 + 700)
            names = os.listdir(os.path.join(self.dir, "spool", "rejected"))
            self.assertTrue(all(n.startswith("rej-") for n in names))


class TestHelpers(unittest.TestCase):
    def test_rfc3339_roundtrip(self):
        t = 1795000000.123
        s = sp.rfc3339(t)
        self.assertRegex(s, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
        self.assertAlmostEqual(sp.parse_rfc3339(s), t, places=2)
        self.assertEqual(sp.parse_rfc3339("2026-11-19T10:15:03.120+01:00"), sp.parse_rfc3339("2026-11-19T09:15:03.120Z"))
        for bad in ("", "x", "2026-13-40T00:00:00Z", None, 5, "2026-11-19T10:15:03", "A" * 100):
            self.assertIsNone(sp.parse_rfc3339(bad))

    def test_atomic_write_mode_and_no_tmp(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "f")
            sp.atomic_write(p, b"hello", 0o644)
            self.assertEqual(oct(os.stat(p).st_mode & 0o777), "0o644")
            self.assertEqual(os.listdir(d), ["f"])
            sp.atomic_write(p, "again", 0o600)
            with open(p) as f:
                self.assertEqual(f.read(), "again")
        finally:
            shutil.rmtree(d)

    def test_read_json_safe_refuses_symlink_fifo_and_big(self):
        d = tempfile.mkdtemp()
        try:
            real = os.path.join(d, "real")
            with open(real, "w") as f:
                f.write('{"a": 1}')
            link = os.path.join(d, "link")
            os.symlink(real, link)
            fifo = os.path.join(d, "fifo")
            os.mkfifo(fifo)
            big = os.path.join(d, "big")
            with open(big, "w") as f:
                f.write('{"a": "%s"}' % ("x" * 5000))
            self.assertEqual(sp.read_json_safe(real), {"a": 1})
            self.assertIsNone(sp.read_json_safe(link))
            self.assertIsNone(sp.read_json_safe(fifo))
            self.assertIsNone(sp.read_json_safe(big, cap=1000))
            self.assertIsNone(sp.read_json_safe(os.path.join(d, "missing")))
            deep = os.path.join(d, "deep")
            with open(deep, "w") as f:
                f.write("[" * 100000)
            self.assertIsNone(sp.read_json_safe(deep, cap=1 << 20))
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
