"""Fixes found by tests/hub_flood.py, the slow-client and flood run against the real hub (PLAN section 12)."""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_ctl_support as S  # noqa: E402
from test_cli import CliCase  # noqa: E402


class StorageFullInStatusTests(CliCase):
    """PLAN section 3: `edr-hub status` shows "storage full" when the cap or the disk is reached."""

    def status_text(self):
        return self.run_cli("status").stdout

    def test_a_healthy_hub_shows_no_storage_line(self):
        self.assertNotIn("storage:", self.status_text())

    def test_the_verb_reports_the_writers_state(self):
        self.assertEqual(S.ctl(self.paths, "status")["result"]["storage"], "ok")
        self.hub.writer.status = lambda: {"state": "storage_full", "detail": "database or disk is full"}
        self.assertEqual(S.ctl(self.paths, "status")["result"]["storage"], "storage_full")

    def test_a_full_writer_is_shown(self):
        self.hub.writer.status = lambda: {"state": "storage_full", "detail": "database or disk is full"}
        text = self.status_text()
        self.assertRegex(text, r"storage:\s+storage full: LOW and INFO events get 503")
        self.assertIn("critical-overflow.jsonl", text)

    def test_events_waiting_in_the_overflow_file_are_shown_after_the_state_went_back_to_ok(self):
        with open(self.paths.critical_overflow, "w") as f:
            f.write("0123456789\n")
        text = self.status_text()
        self.assertRegex(text, r"storage:\s+storage was full: 11 bytes of HIGH and CRITICAL events wait in critical-overflow.jsonl")
        self.assertIsNone(re.search(r"storage full:", text))


if __name__ == "__main__":
    unittest.main()
