import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_daemon_support import Tmp, cfgmod, evmod, ids, hub_modules, Paths      # noqa: E402


class TestSanitise(Tmp):
    def test_controls_and_bidi_become_escapes(self):
        e = evmod.make_event("x.y", "agent", "LOW", "a\x00b\x1b[31m\x7f\u202e\u2028c\x85d\r\n")
        s = e["summary"]
        for ch in "\x00\x1b\x7f\u202e\u2028\x85\r\n":
            self.assertNotIn(ch, s)
        self.assertIn("\\x00", s)
        self.assertIn("\\x1b", s)
        self.assertIn("\\x7f", s)
        self.assertIn("\\u202e", s)
        self.assertIn("\\u2028", s)
        self.assertIn("\\x85", s)

    def test_plain_text_and_unicode_letters_are_kept(self):
        e = evmod.make_event("x", "agent", "LOW", "caf\u00e9 \u4e2d\u6587 ok")
        self.assertEqual(e["summary"], "caf\u00e9 \u4e2d\u6587 ok")
        self.assertNotIn("truncated", e)

    def test_caps_and_truncated_mark(self):
        e = evmod.make_event("x", "agent", "LOW", "s" * 1000, details={"a": "d" * 900, "args": "g" * 3000, "url": "u" * 900})
        self.assertEqual(len(e["summary"]), 256)
        self.assertEqual(len(e["details"]["a"]), 512)
        self.assertEqual(len(e["details"]["args"]), 1024)
        self.assertEqual(len(e["details"]["url"]), 512)
        self.assertTrue(e["truncated"])
        small = evmod.make_event("x", "agent", "LOW", "fine", details={"a": "b"})
        self.assertNotIn("truncated", small)

    def test_shape_and_required_fields(self):
        e = evmod.make_event("tetragon.nginx-exec", "tetragon", "CRITICAL", "s", ts_ms=1795000000123,
                             src_ip="::ffff:203.0.113.9", src_trust="tcp", dst_ip="198.51.100.1", dst_port=443, proto="TCP",
                             proc={"binary": "/bin/sh", "args": "-c id", "uid": 33, "parent": "/usr/sbin/nginx"}, community_id="1:abc")
        self.assertEqual(e["v"], 1)
        self.assertEqual(e["agent_ver"], "0.1.0")
        self.assertEqual(e["boot_id"], "b" * 36)
        self.assertEqual(e["ts"], "2026-11-18T11:06:40.123Z")
        self.assertEqual(e["src_ip"], "203.0.113.9")
        self.assertEqual(e["src_trust"], "tcp")
        self.assertEqual(e["proto"], "tcp")
        self.assertEqual(e["dst_port"], 443)
        self.assertEqual(e["proc"]["uid"], 33)
        self.assertNotIn("id", e)                       # the pipeline assigns id, epoch and seq

    def test_bad_inputs_are_made_safe(self):
        e = evmod.make_event("Bad Kind!!", "weird", "URGENT", "s", src_ip="not an ip", src_trust="tcp", dst_port=99999)
        self.assertEqual(e["kind"], "bad_kind__")
        self.assertEqual(e["source"], "agent")
        self.assertEqual(e["sev"], "MEDIUM")
        self.assertEqual(e["src_ip"], "")
        self.assertEqual(e["src_trust"], "none")
        self.assertNotIn("dst_port", e)
        e = evmod.make_event("k" * 100, "agent", "LOW", "s", src_ip="198.51.100.2", src_trust="whatever")
        self.assertEqual(len(e["kind"]), 64)
        self.assertEqual(e["src_trust"], "claimed")
        e = evmod.make_event("k", "agent", "LOW", "s", ts_ms=-5)
        self.assertRegex(e["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")

    def test_nested_details_are_bounded(self):
        deep = {"a": {"b": {"c": {"d": {"e": 1}}}}}
        e = evmod.make_event("x", "agent", "LOW", "s", details={"deep": deep, "list": list(range(100)), "n": float("nan")})
        json.dumps(e)
        self.assertEqual(len(e["details"]["list"]), 32)
        self.assertIsNone(e["details"]["n"])


class TestRedaction(Tmp):
    CASES = [
        ("mysql -u root -pSecret123 db", "Secret123"),
        ("curl --password hunter2 http://x", "hunter2"),
        ("tool --token=abcdef123", "abcdef123"),
        ("tool --api-key ZZZ999", "ZZZ999"),
        ("tool --secret s3cr3t", "s3cr3t"),
        ("curl -u bob:pw12345 http://x", "pw12345"),
        ("wget https://user:p4ss@example.test/file", "p4ss"),
        ("Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
        ("Cookie: session=deadbeef", "deadbeef"),
        ("X-Api-Key: 12345abcde", "12345abcde"),
        ("DB_PASSWORD=toor APP_KEY=base64:QUJD ls", "toor"),
        ("GET /a?token=aaa111&x=1&key=bbb222&password=ccc333", "aaa111"),
        ("GET /a?sig=SIG999&access_token=TOK888", "SIG999"),
    ]

    def test_secrets_are_cut_out_and_marked(self):
        for text, secret in self.CASES:
            e = evmod.make_event("x", "agent", "LOW", text, details={"args": text}, proc={"binary": "/x", "args": text})
            blob = json.dumps(e)
            self.assertNotIn(secret, blob, text)
            self.assertTrue(e["redacted"], text)
            self.assertIn("[REDACTED]", e["summary"])

    def test_ordinary_text_is_not_touched(self):
        for text in ("nginx worker exited on signal 11", "GET /index.php?page=2", "monkey=1 turkey=5", "ls -la /tmp"):
            e = evmod.make_event("x", "agent", "LOW", text)
            self.assertEqual(e["summary"], text)
            self.assertNotIn("redacted", e)

    def test_redact_off_keeps_text_but_still_cleans(self):
        evmod.configure(self.conf("[agent]\nredact = off\n"))
        e = evmod.make_event("x", "agent", "LOW", "mysql -pSecret123\x1b")
        self.assertIn("Secret123", e["summary"])
        self.assertNotIn("\x1b", e["summary"])
        self.assertNotIn("redacted", e)

    def test_args_drop(self):
        evmod.configure(self.conf("[agent]\nargs = drop\n"))
        e = evmod.make_event("x", "agent", "LOW", "s", details={"args": "a b c", "path": "/p"}, proc={"binary": "/b", "args": "x y"})
        self.assertNotIn("args", e["details"])
        self.assertNotIn("args", e["proc"])
        self.assertEqual(e["details"]["path"], "/p")
        self.assertTrue(e["redacted"])

    def test_payload_head_is_128_bytes_of_hex(self):
        import base64
        raw = bytes(range(256)) * 2
        h = evmod.payload_head_hex(base64.b64encode(raw).decode())
        self.assertEqual(h, raw[:128].hex())
        self.assertEqual(evmod.payload_head_hex("!!notbase64"[:5]), evmod.payload_head_hex("!!not"))
        self.assertEqual(evmod.payload_head_hex(None), "")


class TestSize(Tmp):
    def test_an_event_never_exceeds_5_kib_and_context_goes_first(self):
        ctx = [{"ts": "t", "ip": "1.2.3.4", "method": "GET", "path": "/" + "p" * 190, "query": "q" * 190, "status": 404, "bytes": 1,
                "ua": "u" * 80} for _ in range(20)]
        e = evmod.make_event("x", "agent", "HIGH", "s", details={"a": "d" * 500, "b": "e" * 500, "c": "f" * 500, "d": "g" * 500})
        e = evmod.attach_context(e, ctx)
        self.assertLessEqual(evmod.size_of(e), evmod.EVENT_MAX_BYTES)
        self.assertTrue(e["truncated"])
        self.assertEqual(len(e["details"]), 4)                 # details survive while context can be dropped
        self.assertLessEqual(len(json.dumps(e.get("context", []))), 4096)

    def test_details_are_trimmed_after_context(self):
        e = evmod.make_event("x", "agent", "HIGH", "s", details={k: "v" * 500 for k in "abcdefghijklmn"},
                             proc={"binary": "/b" * 200, "args": "a" * 1024, "parent": "/p" * 200})
        self.assertLessEqual(evmod.size_of(e), evmod.EVENT_MAX_BYTES)
        self.assertTrue(e["truncated"])

    def test_context_entries_are_sanitised_and_redacted(self):
        e = evmod.make_event("x", "agent", "HIGH", "s")
        e = evmod.attach_context(e, [{"ts": "t", "ip": "1.2.3.4", "method": "GET", "path": "/a\x1b[0m", "query": "token=SECRET1&x=1",
                                      "status": 200, "bytes": 3, "ua": "ua\x00"}])
        blob = json.dumps(e)
        self.assertNotIn("SECRET1", blob)
        self.assertNotIn("\\u001b", blob)
        self.assertTrue(e["redacted"])

    def test_events_pass_the_hubs_validator(self):
        mods = hub_modules()
        if mods is None:
            self.skipTest("the hub code is not importable here")
        hub_common, hub_ingest = mods
        e = evmod.make_event("tetragon.nginx-exec", "tetragon", "CRITICAL", "nginx worker tried to exec /bin/sh",
                             details={"policy": "nginx-exec", "args": "x" * 2000}, src_ip="198.51.100.7", src_trust="tcp",
                             proc={"binary": "/bin/sh", "args": "-c id", "uid": 33, "parent": "/usr/sbin/nginx"})
        ids.stamp(e)
        e["count"], e["first_ts"], e["last_ts"] = 3, e["ts"], e["ts"]
        clean, ts, first, last = hub_ingest.validate_event(e, 0)
        self.assertEqual(clean["id"], e["id"])
        self.assertEqual(clean["count"], 3)


class TestTimestamps(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(evmod.parse_ts("2026-11-19T10:15:02.481234567Z"), 1795083302481)
        self.assertEqual(evmod.parse_ts("2026-11-19T10:15:02.481234+0100"), 1795079702481)
        self.assertEqual(evmod.parse_ts("2026-11-19T10:15:02+01:00"), 1795079702000)
        self.assertIsNone(evmod.parse_ts("yesterday"))
        self.assertIsNone(evmod.parse_ts(None))
        self.assertIsNone(evmod.parse_ts("2026-13-40T10:15:02Z"))

    def test_rfc3339(self):
        self.assertEqual(evmod.rfc3339(1795083302481), "2026-11-19T10:15:02.481Z")


class TestIds(Tmp):
    def test_id_format_has_no_host_part(self):
        e = evmod.make_event("x", "agent", "LOW", "s")
        ids.stamp(e)
        self.assertRegex(e["id"], r"^[0-9a-f]{8}:[0-9]+$")
        self.assertEqual(e["id"], "%08x:%d" % (e["epoch"], e["seq"]))
        self.assertIsInstance(e["epoch"], int)
        self.assertGreater(e["epoch"], 0)
        self.assertLess(e["epoch"], 2 ** 32)
        self.assertEqual(ids.current(), (e["epoch"], e["seq"]))

    def test_sequence_is_dense_within_an_epoch(self):
        seqs = [ids.next_id()[1] for _ in range(2500)]
        self.assertEqual(seqs, list(range(seqs[0], seqs[0] + 2500)))
        self.assertEqual(len({ids.current()[0]}), 1)

    def test_clean_shutdown_continues_the_epoch(self):
        e1 = ids.stamp({})
        self.assertTrue(ids.mark_clean_shutdown())
        self.assertTrue(ids.init(self.paths))                  # the marker was there
        e2 = ids.stamp({})
        self.assertEqual(e2["epoch"], e1["epoch"])
        self.assertEqual(e2["seq"], e1["seq"] + 1)
        self.assertFalse(os.path.exists(self.paths.clean_marker))   # consumed: a crash from here on has none

    def test_a_crash_starts_a_new_epoch_and_never_reuses_an_id(self):
        used = set()
        for _ in range(5):
            for _ in range(1500):
                used.add(ids.next_id()[2])
            self.assertFalse(ids.init(self.paths))             # no marker: a crash
        self.assertEqual(len(used), 7500)
        epochs = {i.split(":")[0] for i in used}
        self.assertGreaterEqual(len(epochs), 2)

    def test_block_file_is_written_in_blocks_of_1000(self):
        ids.init(self.paths)
        with open(self.paths.ids_json) as f:
            first = json.load(f)["reserved_to"]
        for _ in range(first + 5):
            ids.next_id()
        with open(self.paths.ids_json) as f:
            self.assertGreater(json.load(f)["reserved_to"], first)

    def test_unwritable_state_directory_does_not_stop_ids(self):
        ids.init(self.paths)
        os.chmod(self.paths.state_dir, 0o500)
        try:
            for _ in range(1200):
                ids.next_id()
        finally:
            os.chmod(self.paths.state_dir, 0o700)


if __name__ == "__main__":
    unittest.main()
