"""Security review of the root helpers: each test pins a defect the review found and that has
since been fixed, or a guard that holds.
Helpers run only with --root <temp dir> and --print-script / --dry-run."""
import importlib.machinery
import importlib.util
import json
import os
import re
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_daemon_support import Tmp, CODE                              # noqa: E402

BANS = os.path.join(CODE, "edr-bans")
NOTIFY = os.path.join(CODE, "edr-notify")
NOW = 1_795_000_000


class BansCase(Tmp):
    def script(self, doc, conf="", dropin=None, raw=None):
        """The nft script edr-bans would load for a bans.json, run with --root and --print-script (nothing is applied)."""
        bj = self.paths.bans_json
        os.makedirs(os.path.dirname(bj), exist_ok=True)
        if raw is not None:
            raw(bj)
        else:
            with open(bj, "w") as f:
                json.dump(doc, f)
        if conf:
            self.write(self.paths.local_conf, conf)
        if dropin:
            self.write(self.paths.dropin_path, dropin)
        p = subprocess.run([sys.executable, "-I", BANS, "--root", self.root, "--print-script", "--now", str(NOW)],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        return "\n".join(l for l in p.stdout.splitlines() if l.startswith("add element inet edr edr_ban"))

    def ban(self, cidr, ttl=3600):
        return {"cidr": cidr, "expires": NOW + ttl, "source": "local", "reason": "ssh_fail"}

    def doc(self, *cidrs, never=()):
        return {"v": 1, "written_at": NOW, "empty": False, "never": list(never), "bans": [self.ban(c) for c in cidrs], "feeds": {}}


class TestBansGuardsHold(BansCase):
    """No finding: these are the guards of PLAN 4.2 and they hold."""

    def test_an_ordinary_ban_reaches_the_script_as_an_ip_string_and_an_integer(self):
        out = self.script(self.doc("198.51.100.99"))
        self.assertIn("198.51.100.99/32 timeout 3600s", out)
        for line in out.splitlines():
            self.assertRegex(line, r"^add element inet edr edr_ban[46] \{ [0-9a-f:./]+ timeout [0-9]+s(, [0-9a-f:./]+ timeout [0-9]+s)* \}$")

    def test_never_ban_literals_and_the_metadata_address_win_over_the_agents_file(self):
        out = self.script(self.doc("10.1.2.3", "169.254.169.254", "169.254.0.0/16", "172.16.0.0/12", "192.168.4.4", "127.0.0.1", "224.0.0.5",
                                   "::1", "fe80::1", "fc00::/7", "::ffff:10.0.0.9", "198.51.100.98"))
        self.assertEqual(re.findall(r"[0-9a-f:.]+/?[0-9]* timeout", out), ["198.51.100.98/32 timeout"])

    def test_minimum_prefix_and_overlap_with_the_never_list(self):
        out = self.script(self.doc("128.0.0.0/8", "198.51.0.0/16", "0.0.0.0/0", "8.0.0.0/7", "2001:db8::/16"))
        self.assertEqual(re.findall(r"[0-9a-f:.]+/[0-9]+ timeout", out), ["198.51.0.0/16 timeout"])

    def test_malformed_addresses_never_get_through(self):
        bad = ["1.2.3.4 ", " 1.2.3.4", "01.2.3.4", "1.2.3.4/255.255.255.0", "1.2.3.4%eth0", "1.2.3.4\n; flush ruleset", "1.2.3.4; flush ruleset",
               "198.51.100.1/24", "::ffff:1.2.3.4/200", "1.2.3", "٣.٣.٣.٣", "{ 1.2.3.4 }", "$(id)"]
        out = self.script(self.doc(*bad))
        self.assertEqual(out, "")

    def test_a_symlink_a_fifo_a_hard_link_and_a_huge_file_keep_the_table(self):
        secret = self.write(os.path.join(self.root, "elsewhere.json"), json.dumps(self.doc("198.51.100.97")))

        def symlink(p):
            os.symlink(secret, p)

        def fifo(p):
            os.mkfifo(p)

        def hardlink(p):
            os.link(secret, p)

        def huge(p):
            with open(p, "wb") as f:
                f.truncate(17 * 1024 * 1024)

        def nested(p):
            with open(p, "w") as f:
                f.write("[" * 500000 + "]" * 500000)
        for make in (symlink, fifo, hardlink, huge, nested):
            bj = self.paths.bans_json
            if os.path.lexists(bj):
                os.unlink(bj)
            self.assertEqual(self.script(None, raw=make), "", make.__name__)

    def test_expired_and_over_capacity_input_is_refused_not_applied(self):
        out = self.script(self.doc(*["198.%d.%d.0/24" % (i // 250, i % 250) for i in range(10001)]))
        self.assertEqual(out, "")
        self.assertEqual(self.script({"v": 1, "written_at": NOW, "bans": [dict(self.ban("198.51.100.5"), expires=NOW - 1)], "never": [], "feeds": {}}), "")

    def test_a_ban_that_merges_never_widens_beyond_the_inputs(self):
        out = self.script(self.doc("198.51.100.0/24", "198.51.100.7"))
        self.assertEqual(re.findall(r"[0-9a-f:.]+/[0-9]+ timeout", out), ["198.51.100.0/24 timeout"])


class TestBansNeverBanFromRoot(BansCase):
    CONF = "[bans]\nadmin_ip = 198.51.100.7\nallow_cidr = 192.0.2.0/25\n[sites]\nextra_addresses = 203.0.113.50\nvpc_cidr = 100.100.0.0/20\n"
    DROPIN = "[Service]\nIPAddressAllow=\nIPAddressAllow=192.0.2.200\n"


    def test_the_admin_the_allowlist_the_hub_and_the_vpc_cannot_be_banned_by_a_compromised_agent(self):
        """The agent writes bans.json and `never` in it; with an empty `never` it can ban the admin and the hub."""
        out = self.script(self.doc("198.51.100.7", "192.0.2.5", "203.0.113.50", "192.0.2.200", "100.100.0.9"), conf=self.CONF, dropin=self.DROPIN)
        banned = set(re.findall(r"([0-9.]+)/[0-9]+ timeout", out))
        self.assertEqual(banned, set(), "root-owned configuration says these must never be banned")


class TestNotifyUrl(unittest.TestCase):
    def load(self):
        loader = importlib.machinery.SourceFileLoader("edr_notify_under_review", NOTIFY)
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        return mod

    def test_event_text_cannot_change_the_target_or_the_fields(self):
        m = self.load()
        ev = {"sev": "CRITICAL", "kind": "x\n\r<!channel>", "summary": "`click` <http://evil|x> \x1b[0m", "click": "http://evil", "actions": [1], "topic": "other"}
        body = json.loads(m.build_message("ntfy", "mytopic", ev, "web1"))
        self.assertEqual(sorted(body), ["message", "priority", "tags", "title", "topic"])
        self.assertEqual(body["topic"], "mytopic")
        for text in (body["title"], body["message"]):
            self.assertTrue(all(" " <= c <= "~" for c in text))
        slack = json.loads(m.build_message("slack", "", ev, "web1"))
        self.assertNotIn("<", slack["text"].replace("&lt;", "").replace("&gt;", ""))

    def test_redirects_are_not_followed(self):
        m = self.load()
        self.assertIsNone(m.NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://evil/"))

    def test_a_plain_http_url_is_refused(self):                  # closed: edr-notify takes https only
        m = self.load()
        with self.assertRaises(ValueError):
            m.parse_url("http://hooks.example.test/services/T000/B000/XXXX")


if __name__ == "__main__":
    unittest.main()
