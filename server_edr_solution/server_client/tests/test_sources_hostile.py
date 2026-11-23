"""The forged-line corpus and the seeded mutations of client PLAN section 11 (L0).

The rule under test: `src_ip` is never copied from message text except by the anchored rules of section 4.5, so
an address that an attacker could write (a user name, a request, a user agent, a fake trailer) is never the
event's source address. FORGED below is that address; REAL is the one the daemon itself wrote.
"""
import json
import os
import random
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_daemon_support import Tmp, cfgmod                              # noqa: E402
from edragent import sources as src                                      # noqa: E402
from edragent.sources import nginx, kernel, journal, suricata, tetragon  # noqa: E402

REAL = "203.0.113.9"
FORGED = "198.51.100.8"
FAKE_SSH_TAIL = " from %s port 1 ssh2" % FORGED
FAKE_TRAILER = ", client: %s, server: victim.test" % FORGED


def err_prefix(msg_cls="*7 "):
    return "2026/11/19 10:15:02 [info] 1000#1000: " + msg_cls


class Hostile(Tmp):
    def setUp(self):
        super().setUp()
        self.write(self.paths.nginx_pid, "1000\n")
        self.cfg = cfgmod.load(self.paths)
        self.ctx = src.Context(self.cfg, self.paths, self.clock)
        self.seen = src.SeenStore(self.paths.seen_json, self.clock)
        self.jsrc = src.JournalSource(self.ctx, self.seen, popen=lambda *a, **k: None)
        self.esrc = nginx.ErrorLogSource(self.ctx, "begin")
        self.asrc = nginx.AccessLogSource(self.ctx, "begin", tripwires=nginx.load_tripwires("/nonexistent"))
        self.addCleanup(self.esrc.close)
        self.addCleanup(self.asrc.close)

    def ssh(self, message, comm="sshd", uid="0"):
        return self.jsrc.to_events({"MESSAGE": message, "_COMM": comm, "_UID": uid, "__REALTIME_TIMESTAMP": "1795083302000000"})

    def sources_of(self, events):
        return {e["src_ip"] for e in events}


class TestForgedSsh(Hostile):
    def test_a_user_name_holding_a_fake_tail(self):
        user = "admin" + FAKE_SSH_TAIL
        for msg in ("Failed password for %s from %s port 40000 ssh2" % (user, REAL),
                    "Failed password for invalid user %s from %s port 40000 ssh2" % (user, REAL),
                    "Invalid user %s from %s port 40000" % (user, REAL),
                    "Connection closed by authenticating user %s %s port 40000 [preauth]" % (user, REAL),
                    "Failed publickey for %s from %s port 40000 ssh2: ED25519 SHA256:%s" % (user, REAL, "A" * 43)):
            events = self.ssh(msg)
            self.assertEqual(self.sources_of(events), {REAL}, msg)

    def test_a_user_name_ending_in_a_fake_tail_with_no_real_tail_is_not_attributed(self):
        for msg in ("Failed password for x%s" % FAKE_SSH_TAIL + " trailing", "Invalid user x%s extra" % FAKE_SSH_TAIL):
            self.assertEqual(self.sources_of(self.ssh(msg)) - {""}, set(), msg)

    def test_the_fake_tail_in_a_forged_record_does_not_count(self):
        msg = "Failed password for root%s" % FAKE_SSH_TAIL
        self.assertEqual(self.ssh(msg, comm="logger", uid="1000"), [])
        self.assertEqual(self.ssh(msg, comm="sshd", uid="33"), [])


class TestForgedNginxError(Hostile):
    WU = '*5 client violated connection flow control: received WINDOW_UPDATE frame with window increment "1"'

    def line(self, text):
        return self.esrc.parse_line(text, self.clock())

    def lines(self, *texts):
        return self.esrc.process_lines(list(texts), self.clock()) + self.esrc.finish()

    def test_a_second_newline_that_moves_the_real_trailer_away_drops_the_address(self):
        forged = "2026/11/19 10:15:02 [info] 1000#1000: " + self.WU + FAKE_TRAILER
        rest = 'rest of the path" failed (2: No such file), client: %s, server: real.test' % REAL
        events = self.lines("2026/11/19 10:15:02 [error] 1000#1000: *5 open() \"/var/www/x", forged, rest)
        self.assertEqual([e["src_ip"] for e in events], [""])
        self.assertEqual(events[0]["details"]["address_dropped"], "split_record")
        events = self.lines(forged, "2026/11/19 10:15:03 [info] 1000#1000: *6 something else")             # a genuine record follows
        self.assertEqual([e["src_ip"] for e in events], [FORGED])                                         # (what the one-trailer rule alone accepts)
        events = self.lines("2026/11/19 10:15:02 [info] 1000#1000: " + self.WU + ", client: %s, server: real.test" % REAL)
        self.assertEqual([e["src_ip"] for e in events], [REAL])                                           # the end of the file: a genuine record

    def test_the_address_waits_for_the_next_line_and_is_released_after_2_seconds(self):
        ok = "2026/11/19 10:15:02 [info] 1000#1000: " + self.WU + ", client: %s, server: real.test" % REAL
        self.ctx.ring.add(int(self.clock()), REAL, "GET", "/", "", 200, 1, "ua")           # the access log vouches for REAL
        self.assertEqual(self.esrc.process_lines([ok], 100.0), [])
        self.assertEqual([e["src_ip"] for e in self.esrc.process_lines([], 101.0)], [])
        self.assertEqual([(e["src_ip"], e["src_trust"]) for e in self.esrc.process_lines([], 103.0)], [(REAL, "tcp")])

    def test_an_error_log_address_is_ban_evidence_only_when_the_access_log_shows_a_request_from_it(self):
        mk = lambda ip: "2026/11/19 10:15:02 [info] 1000#1000: " + self.WU + ", client: %s, server: real.test" % ip
        now = self.clock()
        self.ctx.ring.add(int(now), REAL, "GET", "/", "", 200, 1, "ua")
        events = self.lines(mk(REAL), mk(FORGED))
        got = {e["src_ip"]: e for e in events}
        self.assertEqual((got[REAL]["src_trust"], got[REAL]["details"]["addr_corroborated"]), ("tcp", True))
        self.assertEqual((got[FORGED]["src_trust"], got[FORGED]["details"]["addr_corroborated"]), ("claimed", False))
        self.assertEqual(got[FORGED]["kind"], "nginx.marker.window_update")                # still raised
        # a request that fell out of the ring's window does not count
        self.ctx.ring.q.clear()
        self.ctx.ring.add(int(now) - 10 * 60, REAL, "GET", "/", "", 200, 1, "ua")
        self.assertEqual([e["src_trust"] for e in self.lines(mk(REAL))], ["claimed"])

    def test_an_error_log_address_waits_a_few_seconds_for_the_access_log_then_is_claimed(self):
        ok = "2026/11/19 10:15:02 [info] 1000#1000: " + self.WU + ", client: %s, server: real.test" % REAL
        self.assertEqual(self.esrc.process_lines([ok, "2026/11/19 10:15:03 [info] 1000#1000: *9 x"], 100.0), [])
        self.assertEqual(self.esrc.settle(102.0), [])                                    # the access line has not been read yet
        self.ctx.ring.add(100, REAL, "GET", "/", "", 200, 1, "ua")                      # now it has
        self.assertEqual([(e["src_ip"], e["src_trust"]) for e in self.esrc.settle(102.5)], [(REAL, "tcp")])
        self.ctx.ring.q.clear()
        self.assertEqual(self.esrc.process_lines([ok, "2026/11/19 10:15:03 [info] 1000#1000: *9 x"], 200.0), [])
        self.assertEqual([e["src_trust"] for e in self.esrc.settle(206.0)], ["claimed"])

    def test_without_a_usable_access_log_error_log_addresses_are_always_claimed(self):
        ok = "2026/11/19 10:15:02 [info] 1000#1000: " + self.WU + ", client: %s, server: real.test" % REAL
        self.ctx.ring.add(int(self.clock()), REAL, "GET", "/", "", 200, 1, "ua")
        for usable in (False,):
            self.ctx.access_usable = usable
            self.assertEqual([e["src_trust"] for e in self.lines(ok)], ["claimed"])
        # the access source says so when its log is unreadable or its log_format does not start with $remote_addr
        self.ctx.inventory_checks = {"nginx_logs": {"access_logs": [{"format": "vhost"}], "log_formats": {"vhost": {"starts_remote_addr": False}}}}
        self.asrc._after_batch(self.clock())
        self.assertIs(self.ctx.access_usable, False)
        self.assertEqual([e["src_trust"] for e in self.lines(ok)], ["claimed"])
        self.ctx.inventory_checks = {}
        self.asrc._after_batch(self.clock())
        self.assertIs(self.ctx.access_usable, True)
        self.assertEqual([e["src_trust"] for e in self.lines(ok)], ["tcp"])

    def test_the_forged_two_newline_record_with_a_fake_timestamped_line_is_never_ban_evidence(self):
        forged = "2026/11/19 10:15:02 [info] 1000#1000: " + self.WU + FAKE_TRAILER
        lines = ["2026/11/19 10:15:02 [error] 1000#1000: *5 open() \"/var/www/x", forged,
                 "2026/11/19 10:15:02 [info] 1#1: *1 y\" failed (2: No such file), client: %s, server: real.test" % REAL]
        events = self.lines(*lines)
        forged_events = [e for e in events if e["kind"] == "nginx.marker.window_update"]
        self.assertEqual(len(forged_events), 1)
        self.assertEqual((forged_events[0]["src_ip"], forged_events[0]["src_trust"]), (FORGED, "claimed"))

    def test_a_fake_client_trailer_in_a_message_has_two_occurrences(self):
        real_trailer = ", client: %s, server: real.test, request: \"GET / HTTP/1.1\", host: \"real.test\"" % REAL
        injected = "2026/11/19 10:15:02 [info] 1000#1000: " + self.WU + FAKE_TRAILER + '" failed (2: No such file)' + real_trailer
        events = self.line(injected)
        self.assertEqual(self.sources_of(events), {""})                         # the event may exist, but with no address
        self.assertTrue(all(e["src_trust"] == "none" for e in events))

    def test_a_request_that_cuts_the_real_trailer_at_2048_bytes(self):
        pad = "x" * 2200
        head = "2026/11/19 10:15:02 [info] 1000#1000: " + self.WU + FAKE_TRAILER + pad
        line = head[:2047]                                                        # nginx cuts the whole line at 2048
        self.assertGreaterEqual(len(line), 2040)
        events = self.line(line)
        self.assertEqual(self.sources_of(events), {""})

    def test_an_untruncated_single_trailer_is_attributed(self):
        ok = "2026/11/19 10:15:02 [info] 1000#1000: " + self.WU + ", client: %s, server: real.test" % REAL
        self.assertEqual(self.sources_of(self.line(ok)), {REAL})

    def test_a_forged_crash_line_needs_the_masters_pid(self):
        self.assertEqual(self.line("2026/11/19 10:15:02 [alert] 31337#31337: worker process 5 exited on signal 11")[0]["sev"], "LOW")
        self.assertEqual(self.line("2026/11/19 10:15:02 [alert] 1000#1000: worker process 5 exited on signal 11")[0]["sev"], "MEDIUM")

    def test_lines_over_8_kib_are_cut_before_parsing(self):
        long_line = "2026/11/19 10:15:02 [alert] 1000#1000: worker process 5 exited on signal 11" + " " * 20000 + FAKE_TRAILER
        events = self.line(long_line)
        self.assertNotIn(FORGED, self.sources_of(events))
        huge = "2026/11/19 10:15:02 [info] 1000#1000: " + self.WU + FAKE_TRAILER.replace(FORGED, REAL)
        cut = huge + "z" * 9000
        self.assertEqual(self.sources_of(self.line(cut)), {""})                   # cut at 8 KiB, and over 2040 bytes anyway
        self.assertEqual(self.sources_of(self.line(huge + "z" * 3000)), {""})


class TestForgedAccess(Hostile):
    def line(self, text):
        return self.asrc.parse_line(text)

    def test_an_access_line_not_starting_with_remote_addr_is_never_attributed(self):
        fake = '%s - - [19/Nov/2026:10:15:02 +0000] "GET /.env HTTP/1.1" 404 5 "-" "ua"' % FORGED
        for text in ("vhost.test " + fake, "- " + fake, "[19/Nov/2026:10:15:02 +0000] " + fake, "\"" + fake,
                     "$remote_addr " + fake, " " + fake):
            self.assertEqual(self.line(text), [], text)
        self.assertEqual(self.ctx.stats.ips, {})

    def test_forged_text_in_the_request_and_user_agent_does_not_move_the_address(self):
        ua = 'x" 200 5 "-" "%s - - [19/Nov/2026:10:15:02 +0000] \\"GET /.env HTTP/1.1\\" 404 0' % FORGED
        text = '%s - - [19/Nov/2026:10:15:02 +0000] "GET /.env?a=%s HTTP/1.1" 404 5 "-" "%s"' % (REAL, FORGED, ua)
        events = self.line(text)
        self.assertEqual(self.sources_of(events), {REAL})

    def test_a_forged_user_field_cannot_carry_a_second_line_shape(self):
        text = '%s - evil [19/Nov/2026:10:15:02 +0000] "GET /x HTTP/1.1" 200 5 "-" "ua"' % REAL
        self.assertEqual(self.line(text), [])
        text = '%s - a b [19/Nov/2026:10:15:02 +0000] "GET /.env HTTP/1.1" 404 5 "-" "ua"' % REAL
        self.assertEqual(self.line(text), [])                                    # a user name with a space: not attributed at all

    def test_lines_over_8_kib(self):
        text = '%s - - [19/Nov/2026:10:15:02 +0000] "GET /.env HTTP/1.1" 404 5 "-" "%s"' % (REAL, "u" * 9000)
        events = self.line(text)
        self.assertLessEqual(len(events), 1)
        for e in events:
            self.assertEqual(e["src_ip"], REAL)
        text2 = '%s - - [19/Nov/2026:10:15:02 +0000] "GET /' % REAL + "a" * 9000 + '/.env HTTP/1.1" 404 5 "-" "ua"'
        self.assertEqual(self.line(text2), [])


# ---- the seeded mutations --------------------------------------------------------------------------------
FRAGMENTS = [FAKE_SSH_TAIL, FAKE_TRAILER, " port 1 ssh2", "\n", "\r", "\x00", "\x1b[31m", "‮", " ", '"', "\\", "\\x22", "%0a",
             "from ", ", client: ", ", server: ", " [preauth]", "ssh2", "*1 ", "[alert]", "  ", "\t", FORGED, "::ffff:" + FORGED, "999.1.1.1",
             "a" * 300, "é", "\ud800".encode("utf-8", "surrogatepass").decode("utf-8", "replace"), "{\"x\":1}", "}", "]"]


def attacker_text(rng, limit=400):
    parts = []
    for _ in range(rng.randint(0, 6)):
        r = rng.random()
        if r < 0.5:
            parts.append(rng.choice(FRAGMENTS))
        elif r < 0.8:
            parts.append("".join(rng.choice("abcXYZ 0123.:/-_\"\\") for _ in range(rng.randint(1, 40))))
        else:
            parts.append(chr(rng.randint(1, 0x2FF)))
    return "".join(parts)[:limit]


def byte_mutate(rng, text):
    b = bytearray(text.encode("utf-8", "replace"))
    for _ in range(rng.randint(1, 6)):
        if not b:
            break
        i = rng.randrange(len(b))
        op = rng.random()
        if op < 0.25:
            b[i] = rng.randrange(256)
        elif op < 0.5:
            del b[i:i + rng.randint(1, 20)]
        elif op < 0.75:
            b[i:i] = b[max(0, i - rng.randint(1, 30)):i] * rng.randint(1, 5)
        else:
            b[i:i] = rng.choice(FRAGMENTS).encode("utf-8", "replace")
    return bytes(b).decode("utf-8", "replace")


class TestSeededMutations(Hostile):
    N = 20000

    def seeds(self):
        w = tetragon.TetragonSource(self.ctx, "begin")
        self.addCleanup(w.close)
        e = suricata.EveSource(self.ctx, "begin")
        self.addCleanup(e.close)
        return w, e

    def test_twenty_thousand_mutations(self):
        rng = random.Random(20260519)
        tet, eve = self.seeds()
        kern = src.KernelSource(self.ctx, self.seen, os.path.join(self.root, "kern.log"), "begin")
        self.addCleanup(kern.close)
        self.ctx.ring.add(int(self.clock()), REAL, "GET", "/", "", 200, 1, "ua")           # REAL really asked for something
        started = time.monotonic()
        worst = 0.0
        stats = {"ssh": 0, "err": 0, "acc": 0, "other": 0, "events": 0}
        tetragon_seed = json.dumps({"process_kprobe": {"process": {"pid": 1, "uid": 33, "binary": "/bin/sh", "arguments": "-c id"},
                                                       "parent": {"binary": "/usr/sbin/nginx"}, "function_name": "security_bprm_check",
                                                       "args": [{"linux_binprm_arg": {"path": "/bin/sh"}}], "policy_name": "nginx-exec",
                                                       "action": "KPROBE_ACTION_SIGKILL"}, "time": "2026-11-19T10:15:02.481234567Z"})
        eve_seed = json.dumps({"timestamp": "2026-11-19T10:15:02.481234+0000", "event_type": "alert", "src_ip": REAL, "dest_ip": "198.51.100.1",
                               "dest_port": 80, "proto": "TCP", "app_proto": "http", "flow": {"pkts_toserver": 4, "pkts_toclient": 2},
                               "alert": {"signature_id": 1, "signature": "s", "severity": 1}})
        kernel_seed = "edr-bigconn: IN=eth0 OUT= SRC=%s DST=198.51.100.1 PROTO=TCP SPT=1 DPT=443" % REAL
        for i in range(self.N):
            kind = i % 8
            t0 = time.perf_counter()
            if kind in (0, 1, 2):                                             # sshd: attacker text in the user name
                user = attacker_text(rng)
                tpl = rng.choice(["Failed password for %s from %s port 40000 ssh2", "Failed password for invalid user %s from %s port 40000 ssh2",
                                  "Invalid user %s from %s port 40000", "Connection closed by authenticating user %s %s port 40000 [preauth]",
                                  "Failed publickey for %s from %s port 40000 ssh2: RSA SHA256:" + "A" * 43])
                msg = tpl % (user, REAL)                                          # sshd writes its own tail last
                events = self.ssh(msg)
                stats["ssh"] += 1
                for e in events:
                    self.assertNotEqual(e["src_ip"], FORGED, repr(msg))
                    if msg.endswith("[preauth]") or msg.endswith("ssh2") or msg.endswith("40000"):
                        self.assertIn(e["src_ip"], (REAL, ""), repr(msg))
            elif kind in (3, 4):                                              # nginx error.log: attacker text in the message, real trailer after
                msg = '%s%s' % (rng.choice(["*7 client violated connection flow control: received WINDOW_UPDATE frame with window increment \"1\"",
                                            "*7 open() \"/var/www/", "*7 client violated connection flow control: received WINDOW_UPDATE frame with window increment \""]),
                                attacker_text(rng, 600))
                line = "2026/11/19 10:15:02 [info] 1000#1000: %s, client: %s, server: real.test, request: \"GET / HTTP/1.1\", host: \"h\"" % (msg, REAL)
                line = line[:2047] if rng.random() < 0.4 else line                # nginx's own cut
                parts = line.replace("\r", "\n").split("\n")                      # the file is read a physical line at a time
                for e in self.esrc.process_lines(parts, self.clock()) + self.esrc.finish():
                    stats["err"] += 1
                    # the forged address may be seen (claimed) but is never ban evidence; REAL is vouched for by the ring below
                    self.assertNotEqual((e["src_ip"], e["src_trust"]), (FORGED, "tcp"), repr(line))
                    self.assertNotIn(e["src_ip"], (FORGED,) if e["src_trust"] == "tcp" else ())
                    self.assertIn(e["src_trust"], ("tcp", "none", "claimed"))
            elif kind in (5, 6):                                              # nginx access.log: attacker text in request and user agent
                req = attacker_text(rng, 300).replace('"', rng.choice(['\\x22', '"']))
                ua = attacker_text(rng, 200).replace('"', rng.choice(['\\x22', '"']))
                line = '%s - - [19/Nov/2026:10:15:02 +0000] "GET /%s HTTP/1.1" %d 5 "-" "%s"' % (REAL, req, rng.choice([404, 200, 403, 500]), ua)
                stats["acc"] += 1
                for part in line.replace("\r", "\n").split("\n"):
                    for e in self.asrc.parse_line(part):
                        self.assertIn(e["src_ip"], (REAL, ""), repr(part))
                        stats["events"] += 1
                    for e in self.asrc.parse_line(attacker_text(rng, 200) + part):          # junk in front: never attributed to the forged value
                        self.assertNotEqual(e["src_ip"], FORGED, repr(part))
            else:                                                             # byte-level mutation of every other parser's input
                stats["other"] += 1
                which = (i // 8) % 4
                if which == 0:
                    tet.parse_line(byte_mutate(rng, tetragon_seed))
                elif which == 1:
                    eve.parse_line(byte_mutate(rng, eve_seed))
                elif which == 2:
                    kern.to_events(byte_mutate(rng, kernel_seed), None)
                else:
                    self.ssh(byte_mutate(rng, "Failed password for root from %s port 40000 ssh2" % REAL))
                    journal.parse_sudo(byte_mutate(rng, "    a : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"))
            worst = max(worst, time.perf_counter() - t0)
        elapsed = time.monotonic() - started
        self.assertLess(worst, 0.25, "one input took %.3fs" % worst)
        self.assertLess(elapsed, 60.0, "20,000 mutations took %.1fs" % elapsed)
        self.assertGreater(stats["ssh"], 4000)
        self.assertGreater(stats["err"] + stats["events"], 100)             # the corpus really reaches the parsers

    def test_pathological_inputs_stay_fast(self):
        cases = [
            ("Failed password for " + (FAKE_SSH_TAIL * 400) + " from %s port 1 ssh2" % REAL),
            ("Failed password for " + ("from " * 1500) + "x"),
            ("Invalid user " + (" from a port 1" * 600)),
            ("Connection closed by authenticating user " + "a " * 3000 + REAL + " port 1 [preauth]"),
        ]
        for msg in cases:
            t0 = time.perf_counter()
            events = self.ssh(msg)
            self.assertLess(time.perf_counter() - t0, 0.5)
            self.assertNotIn(FORGED, [e["src_ip"] for e in events])
        for line in ('1.2.3.4 - - [x] "' + "\\a" * 3000 + '" 200 1', '1.2.3.4 - - [x] "' + '\\"' * 4000, "1.2.3.4 " + "- " * 4000,
                     "1.2.3.4 - - [" + "[" * 5000):
            t0 = time.perf_counter()
            self.asrc.parse_line(line)
            self.assertLess(time.perf_counter() - t0, 0.5)
        for line in ("2026/11/19 10:15:02 [alert] 1#1: " + ", client: " * 3000, "2026/11/19 10:15:02 [alert] 1#1: " + "*1 " * 3000,
                     ", client: 1.2.3.4, server: " * 400):
            t0 = time.perf_counter()
            self.esrc.parse_line(line, 0)
            self.assertLess(time.perf_counter() - t0, 0.5)


if __name__ == "__main__":
    unittest.main()
