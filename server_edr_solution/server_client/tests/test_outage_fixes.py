"""Pins for what the hub-outage test (tests/outage_local.py) found in the agent.

A scan from very many addresses filled the ban engine's per-address counters (50,000 keys each) with one deque
per key, about 750 bytes for a single entry, and the agent's resident memory reached 127 MB against a limit of
128 MB (client PLAN section 9: MemoryHigh 96 MB, MemoryMax 128 MB). One list per key does the same work in
about a quarter of the space.

Evicting a full spool segment parsed all of its events into dicts only to count their kinds and sources, which
added about 35 MB to the agent's peak while it was dropping low-severity events. It keeps the two fields now.
"""
import os
import shutil
import sys
import tempfile
import tracemalloc
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_daemon_support  # noqa: E402,F401  (puts the agent package on sys.path)
from edragent import bans  # noqa: E402
from edragent import spool as spoolmod  # noqa: E402


class CounterTests(unittest.TestCase):
    def test_window_drops_old_times(self):
        c = bans._Counter(600)
        c.add("a", 0.0)
        self.assertEqual(len(c.add("a", 100.0)), 2)
        self.assertEqual(len(c.add("a", 599.0)), 3)
        self.assertEqual(len(c.add("a", 700.0)), 3)         # 0.0 is older than 700 - 600 and goes
        self.assertEqual([t for t, _ in c.add("a", 5000.0)], [5000.0])

    def test_tokens_kept_with_their_times(self):
        c = bans._Counter(600)
        c.add("a", 1.0, 11)
        got = c.add("a", 2.0, 22)
        self.assertEqual(sorted(t for _, t in got), [11, 22])
        self.assertEqual({t for _, t in got if t is not None}, {11, 22})

    def test_one_key_never_holds_more_than_1000_times(self):
        c = bans._Counter(10 ** 9)
        for i in range(1500):
            n = len(c.add("a", float(i)))
        self.assertEqual(n, 1000)
        self.assertEqual(c.d["a"][0][0], 500.0)             # the oldest 500 went

    def test_lru_cap_drops_the_oldest_key(self):
        c = bans._Counter(600, cap=3)
        for k in "abc":
            c.add(k, 1.0)
        c.add("a", 2.0)                                      # a is now the newest
        c.add("d", 3.0)
        self.assertEqual(list(c.d), ["c", "a", "d"])

    def test_clear_forgets_one_key(self):
        c = bans._Counter(600)
        c.add("a", 1.0)
        c.add("b", 1.0)
        c.clear("a")
        self.assertEqual(list(c.d), ["b"])

    def test_a_full_counter_is_small(self):
        """50,000 addresses with one hit each must not cost the agent tens of megabytes (a deque per key cost 38 MB)."""
        keys = 10000
        names = ["11.%d.%d.%d" % (i >> 16 & 255, i >> 8 & 255, i & 255) for i in range(keys)]
        c = bans._Counter(600)
        tracemalloc.start()
        try:
            base = tracemalloc.get_traced_memory()[0]
            for i, name in enumerate(names):
                c.add(name, float(i))
            used = tracemalloc.get_traced_memory()[0] - base
        finally:
            tracemalloc.stop()
        self.assertLess(used / keys, 300.0, "%.0f bytes a key" % (used / keys))


class EvictionTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="spooltest")
        self.addCleanup(shutil.rmtree, self.dir, True)

    @staticmethod
    def event(i):
        return {"v": 1, "id": "abcd1234:%d" % i, "sev": "LOW", "kind": "canary.tripwire", "source": "nginx",
                "summary": "tripwire path requested: /.env", "src_ip": "11.0.0.1", "src_trust": "tcp",
                "details": {"path": "/.env", "status": 404, "method": "GET", "tripwire": "/.env", "ban": True}}

    def test_kind_and_source_keeps_two_fields(self):
        self.assertEqual(spoolmod.kind_and_source(b'{"kind":"a.b","source":"nginx","summary":"x"}'), {"kind": "a.b", "source": "nginx"})
        self.assertIsNone(spoolmod.kind_and_source(b"not json"))
        self.assertIsNone(spoolmod.kind_and_source(b"[1]"))

    def test_eviction_counts_kinds_and_sources(self):
        sp = spoolmod.Spool(self.dir, lo_cap=2 * 1024 * 1024, seg_size=1024 * 1024)
        for i in range(12000):
            sp.append(self.event(i))
        recs = sp.take_drops()
        self.assertTrue(recs)
        self.assertEqual(sum(r["count"] for r in recs), sp.dropped["lo"])
        self.assertEqual(recs[0]["kinds"], {"canary.tripwire": recs[0]["count"]})
        self.assertEqual(sp.dropped_src, {"nginx": sp.dropped["lo"]})
        sp.close()

    def test_evicting_a_segment_does_not_hold_its_events(self):
        sp = spoolmod.Spool(self.dir, lo_cap=2 * 1024 * 1024, seg_size=1024 * 1024)
        for i in range(8000):                                # fills two segments and a part
            sp.append(self.event(i))
        n0 = sp.dropped["lo"]
        tracemalloc.start()
        try:
            tracemalloc.reset_peak()
            base = tracemalloc.get_traced_memory()[0]
            for i in range(8000, 8600):
                sp.append(self.event(i))                     # one eviction happens in here
            peak = tracemalloc.get_traced_memory()[1] - base
        finally:
            tracemalloc.stop()
        self.assertGreater(sp.dropped["lo"], n0, "no eviction happened")
        self.assertLess(peak, 5.0 * 1024 * 1024, "%.1f MB held while evicting a 1 MB segment (9 MB before the fix, 3.5 MB after)" % (peak / 1e6))
        sp.close()


if __name__ == "__main__":
    unittest.main()
