"""L0 tests of the server Tetragon policy set and export denylist (client PLAN section 4.3): every policy
parses, stays inside the limits `make lint` enforces, the killing policies are ordered so that the
first matching selector does the right thing, and the placeholders render. PyYAML is required."""

import glob
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from test_helper_common import CLIENT, TETRAGON  # noqa: E402

try:
    import yaml
except ImportError:                                   # CI fails, never skips, without PyYAML
    yaml = None

POLICY_DIR = os.path.join(TETRAGON, "policies")
LAPTOP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(CLIENT))), "tetragon", "policies")
PLACEHOLDERS = {"NGINX_BIN", "PHPFPM_BIN", "PHP_CLI_BIN", "WEB_EXEC_ALLOW", "EGRESS_PORTS_EXTRA", "VPC_CIDR"}
# server variants that keep the name of the laptop policy they replace (the lint's cross-directory override list)
OVERRIDES = {"sensitive-files", "persistence", "suspicious-exec", "stack-tamper", "tcp-listen"}
KILLING = {"nginx-exec", "sctp-socket", "web-exec"}
SAMPLE = {"NGINX_BIN": ["/usr/sbin/nginx"], "PHPFPM_BIN": ["/usr/sbin/php-fpm8.3", "/usr/sbin/php-fpm8.5"],
          "PHP_CLI_BIN": ["/usr/bin/php8.3", "/usr/bin/php8.5"],
          "WEB_EXEC_ALLOW": ["/usr/sbin/php-fpm8.3", "/usr/sbin/php-fpm8.5", "/usr/sbin/nginx", "/usr/sbin/sendmail", "/usr/bin/convert"],
          "EGRESS_PORTS_EXTRA": ["8443", "9200"], "VPC_CIDR": ["10.116.0.0/20"]}


def render(text, values):
    """The documented placeholder rule: a line holding a placeholder is repeated once per value and left out without one."""
    out = []
    for line in text.split("\n"):
        names = re.findall(r"@([A-Z_]+)@", line)
        if not names or line.lstrip().startswith("#"):
            out.append(line)
            continue
        name = names[0]
        for v in values.get(name, []):
            out.append(line.replace("@%s@" % name, v))
    return "\n".join(out)


def load_all(values=None):
    docs = {}
    for path in sorted(glob.glob(os.path.join(POLICY_DIR, "*.yaml"))):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        docs[os.path.basename(path)] = (text, yaml.safe_load(render(text, values) if values is not None else text.replace("@", "AT_")))
    return docs


def count_lists(doc):
    prefix = equal = 0
    for hook in doc["spec"]["kprobes"]:
        for sel in hook.get("selectors", []):
            for m in sel.get("matchArgs", []):
                prefix += m["operator"] in ("Prefix", "NotPrefix", "Postfix", "NotPostfix")
                equal += m["operator"] in ("Equal", "NotEqual") and any(not str(v).lstrip("-").isdigit() for v in m["values"])
            for m in sel.get("matchBinaries", []):
                prefix += m["operator"] in ("Prefix", "NotPrefix", "Postfix", "NotPostfix")
    return prefix, equal


@unittest.skipIf(yaml is None, "PyYAML is required")
class TestPolicyFiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = load_all()
        cls.rendered = load_all(SAMPLE)

    def test_the_set_is_there(self):
        names = {d["metadata"]["name"] for _, d in self.raw.values()}
        self.assertTrue({"nginx-exec", "sctp-socket", "fork-watch", "web-exec", "web-write-code", "web-connect", "env-read", "edr-canary"} <= names)
        self.assertTrue(OVERRIDES <= names)

    def test_each_file_is_a_tracing_policy_named_like_its_file(self):
        for fn, (text, d) in self.raw.items():
            self.assertEqual(d["apiVersion"], "cilium.io/v1alpha1", fn)
            self.assertEqual(d["kind"], "TracingPolicy", fn)
            self.assertEqual(d["metadata"]["name"], fn[:-5], fn)
            self.assertTrue(d["spec"]["kprobes"], fn)

    def test_names_are_unique_and_the_overrides_match_the_laptop_set(self):
        names = [d["metadata"]["name"] for _, d in self.raw.values()]
        self.assertEqual(len(names), len(set(names)))
        if os.path.isdir(LAPTOP_DIR):
            laptop = {os.path.basename(p)[:-5] for p in glob.glob(os.path.join(LAPTOP_DIR, "*.yaml"))}
            self.assertEqual(set(names) & laptop, OVERRIDES)

    def test_limits_hold_for_templates_and_for_rendered_policies(self):
        for label, docs in (("template", self.raw), ("rendered", self.rendered)):
            for fn, (text, d) in docs.items():
                symbols = []
                for hook in d["spec"]["kprobes"]:
                    symbols.append(hook["call"])
                    sels = hook.get("selectors", [])
                    self.assertLessEqual(len(sels), 5, "%s %s %s: selectors" % (label, fn, hook["call"]))
                    self.assertLessEqual(len(hook.get("args", [])), 5, "%s %s %s: args" % (label, fn, hook["call"]))
                    for sel in sels:
                        self.assertLessEqual(len(sel.get("matchActions", [])), 3, "%s %s: actions" % (label, fn))
                        for m in sel.get("matchArgs", []):
                            if "args" in m:
                                self.assertTrue(all(0 <= i < len(hook["args"]) for i in m["args"]), "%s %s: matchArgs position" % (label, fn))
                            else:
                                self.assertIn(m["index"], [a["index"] for a in hook["args"]], "%s %s: matchArgs index" % (label, fn))
                self.assertEqual(len(symbols), len(set(symbols)), "%s %s: two kprobes on one symbol" % (label, fn))
                prefix, equal = count_lists(d)
                self.assertLessEqual(prefix, 8, "%s %s: %d prefix/postfix lists" % (label, fn, prefix))
                self.assertLessEqual(equal, 8, "%s %s: %d exact-match lists" % (label, fn, equal))

    def test_followchildren_ids_stay_under_the_shared_budget(self):
        ids = 0
        for fn, (text, d) in self.rendered.items():
            seen = set()
            for hook in d["spec"]["kprobes"]:
                for sel in hook.get("selectors", []):
                    for m in sel.get("matchBinaries", []):
                        if m.get("followChildren"):
                            self.assertEqual(m["operator"], "In", fn)
                            seen.update(m["values"])
            ids += len(seen)
        self.assertGreater(ids, 0)
        self.assertLessEqual(ids, 64)

    def test_no_home_placeholder_and_no_lsm_hooks_and_only_known_placeholders(self):
        for fn, (text, d) in self.raw.items():
            self.assertNotIn("@HOME@", text, fn)
            self.assertNotIn("lsmhooks", text, fn)
            self.assertNotRegex(text, r'"/home/[a-z]', fn)
            used = set(re.findall(r"@([A-Z_]+)@", "\n".join(l for l in text.split("\n") if not l.lstrip().startswith("#"))))
            self.assertTrue(used <= PLACEHOLDERS, (fn, used - PLACEHOLDERS))

    def test_rendering_replaces_every_placeholder(self):
        for fn, (text, d) in self.rendered.items():
            rendered = render(text, SAMPLE)
            code = "\n".join(l for l in rendered.split("\n") if not l.lstrip().startswith("#"))
            self.assertNotIn("@", code, fn)
        web = self.rendered["web-exec.yaml"][1]
        vals = web["spec"]["kprobes"][0]["selectors"][0]["matchBinaries"][0]["values"]
        self.assertEqual(vals, ["/usr/sbin/php-fpm8.3", "/usr/sbin/php-fpm8.5", "/usr/sbin/php-fpm8.3 (deleted)", "/usr/sbin/php-fpm8.5 (deleted)",
                                "/usr/sbin/nginx", "/usr/sbin/nginx (deleted)"])
        # an empty value list removes the line, which must keep the YAML valid
        empty = dict(SAMPLE, EGRESS_PORTS_EXTRA=[], VPC_CIDR=[])
        d = yaml.safe_load(render(self.raw["web-connect.yaml"][0], empty))
        sel = d["spec"]["kprobes"][0]["selectors"][0]
        ports = sel["matchArgs"][0]["values"]
        self.assertNotIn("@EGRESS_PORTS_EXTRA@", ports)
        self.assertEqual(ports[0], "80")

    def test_every_nginx_list_carries_both_spellings(self):
        for fn, (text, d) in self.rendered.items():
            for hook in d["spec"]["kprobes"]:
                for sel in hook.get("selectors", []):
                    for m in sel.get("matchBinaries", []):
                        for v in m["values"]:
                            if v in ("/usr/sbin/nginx", "/usr/sbin/php-fpm8.3", "/usr/sbin/php-fpm8.5", "/usr/bin/php8.3", "/usr/bin/php8.5") and m["operator"] in ("In", "NotIn"):
                                self.assertIn(v + " (deleted)", m["values"], (fn, v))

    def test_killing_policies_install_in_monitor_and_only_they_kill(self):
        for fn, (text, d) in self.raw.items():
            name = d["metadata"]["name"]
            kills = "Sigkill" in text.replace("# ", "#")
            code = "\n".join(l for l in text.split("\n") if not l.lstrip().startswith("#"))
            kills = "Sigkill" in code
            opts = {o["name"]: o["value"] for o in d["spec"].get("options", [])}
            if name in KILLING:
                self.assertTrue(kills, name)
                self.assertEqual(opts.get("policy-mode"), "monitor", name)
            elif name == "edr-canary":
                self.assertTrue(kills)
                self.assertEqual(opts.get("policy-mode"), "enforce")
            else:
                self.assertFalse(kills, name + " must not kill")
                self.assertNotIn("policy-mode", opts, name)

    def test_selector_order_is_the_mechanism(self):
        d = self.raw["nginx-exec.yaml"][1]
        sels = d["spec"]["kprobes"][0]["selectors"]
        self.assertEqual(len(sels), 2)
        self.assertEqual(sels[0]["matchActions"], [{"action": "NoPost"}])
        self.assertEqual(sels[0]["matchCapabilities"][0]["values"], ["CAP_SYS_ADMIN"])
        self.assertEqual(sels[0]["matchNamespaces"][0]["values"], ["host_ns"])
        self.assertEqual(sels[1]["matchActions"], [{"action": "Sigkill"}])
        self.assertNotIn("matchArgs", sels[1])
        for name in ("web-exec",):
            sels = self.raw[name + ".yaml"][1]["spec"]["kprobes"][0]["selectors"]
            self.assertEqual(sels[0]["matchActions"], [{"action": "NoPost"}])
            self.assertEqual(sels[1]["matchActions"], [{"action": "Sigkill"}])
            self.assertTrue(sels[0]["matchBinaries"][0]["followChildren"] and sels[1]["matchBinaries"][0]["followChildren"])
        # sctp: two logging selectors (host root) before the two that kill
        sels = self.raw["sctp-socket.yaml"][1]["spec"]["kprobes"][0]["selectors"]
        self.assertEqual([("matchActions" in s) for s in sels], [False, False, True, True])
        self.assertTrue(all(s["matchActions"] == [{"action": "Sigkill"}] for s in sels[2:]))
        self.assertTrue(all("matchCapabilities" in s for s in sels[:2]) and not any("matchCapabilities" in s for s in sels[2:]))
        self.assertEqual(sels[0]["matchArgs"][0]["values"], ["132"])
        self.assertEqual([m["values"] for m in sels[1]["matchArgs"]], [["2", "10"], ["5"], ["0"]])

    def test_canary_matches_only_the_canary_binary(self):
        d = self.raw["edr-canary.yaml"][1]
        hooks = d["spec"]["kprobes"]
        self.assertEqual(len(hooks), 1)
        self.assertEqual(len(hooks[0]["selectors"]), 1)
        sel = hooks[0]["selectors"][0]
        self.assertEqual(sel["matchBinaries"], [{"operator": "In", "values": ["/usr/libexec/edr/canary"]}])
        self.assertEqual(sel["matchActions"], [{"action": "Sigkill"}])
        self.assertNotIn("matchArgs", sel)

    def test_fork_watch_is_log_only_and_uses_the_credential_resolve(self):
        d = self.raw["fork-watch.yaml"][1]
        hook = d["spec"]["kprobes"][0]
        self.assertEqual(hook["args"][0]["resolve"], "real_cred.euid.val")
        self.assertEqual(hook["selectors"][0]["matchArgs"][0], {"index": 1, "operator": "Mask", "values": ["65536"]})
        self.assertEqual(hook["selectors"][1]["matchArgs"][0]["operator"], "NotEqual")

    def test_rate_limits_follow_the_plan(self):
        for fn, (text, d) in self.raw.items():
            name = d["metadata"]["name"]
            limited = [a for h in d["spec"]["kprobes"] for s in h.get("selectors", []) for a in s.get("matchActions", []) if "rateLimit" in a]
            if name in KILLING or name in ("web-write-code", "env-read", "fork-watch", "edr-canary"):
                self.assertEqual(limited, [], name + ": the killing and web policies use no rateLimit")
        wc = self.raw["web-connect.yaml"][1]["spec"]["kprobes"][0]["selectors"][0]["matchActions"][0]
        self.assertEqual((wc["rateLimit"], wc["rateLimitScope"]), ("10s", "thread"))

    def test_server_variants_drop_the_desktop_and_name_the_server_paths(self):
        pers = self.raw["persistence.yaml"][0]
        self.assertIn("/.ssh/authorized_keys", pers)
        self.assertIn("/etc/ld.so.preload", pers)
        self.assertIn("/var/spool/cron", pers)
        self.assertIn("/opt/digitalocean/bin/droplet-agent", pers)
        self.assertNotIn("/etc/xdg/autostart", pers)
        self.assertNotIn(".config/autostart", pers)
        first = self.raw["persistence.yaml"][1]["spec"]["kprobes"][0]["selectors"][0]
        self.assertEqual(first["matchActions"], [{"action": "NoPost"}])
        stack = self.raw["stack-tamper.yaml"][0]
        for need in ("/etc/edr-agent", "/usr/local/lib/edr-agent", "/var/lib/edr-agent/identity", "/var/log/nginx", "auth.log", "journalctl"):
            self.assertIn(need, stack)
        self.assertIn("/tmp/", self.raw["suspicious-exec.yaml"][0])
        self.assertIn("/var/tmp/", self.raw["suspicious-exec.yaml"][0])
        sens = self.raw["sensitive-files.yaml"][0]
        for need in ("/etc/shadow", "/etc/sudoers", "/.ssh/id_ed25519", "/.aws/credentials"):
            self.assertIn(need, sens)
        self.assertNotIn("firefox", sens.lower())

    def test_lint_sh_logic_agrees(self):
        # the checks of tests/lint.sh, applied to this directory
        for fn, (text, d) in self.raw.items():
            prefix = equal = 0
            for hook in d["spec"]["kprobes"]:
                self.assertLessEqual(len(hook.get("selectors", [])), 5)
                for sel in hook.get("selectors", []):
                    for m in sel.get("matchArgs", []):
                        prefix += m["operator"] in ("Prefix", "NotPrefix", "Postfix", "NotPostfix")
                        equal += m["operator"] in ("Equal", "NotEqual") and any(not str(v).lstrip("-").isdigit() for v in m["values"])
            self.assertLessEqual(prefix, 8, fn)
            self.assertLessEqual(equal, 8, fn)


class TestDenylist(unittest.TestCase):
    def lines(self):
        out = []
        with open(os.path.join(TETRAGON, "export-denylist.jsonl"), encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append((n, json.loads(line)))
        return out

    def test_rules_of_the_list(self):
        lines = self.lines()
        self.assertTrue(lines)
        for n, f in lines:
            self.assertTrue(f.get("event_set") or f.get("policy_names"), "line %d hides policy hits" % n)
            for key in ("binary_regex", "parent_binary_regex"):
                for rx in f.get(key, []):
                    self.assertTrue(rx.startswith("^"), (n, rx))
                    re.compile(rx)
            if f.get("arguments_regex"):
                self.assertTrue(f.get("parent_binary_regex"), "line %d: arguments without a parent" % n)
            for rx in f.get("arguments_regex", []):
                self.assertTrue(rx.startswith("^") and rx.endswith("$"), (n, rx))
                re.compile(rx)

    def test_the_kits_own_helpers_are_filtered_and_an_imitation_is_not(self):
        helper = [f for _, f in self.lines() if f.get("arguments_regex") and "edr-agent" in f["arguments_regex"][0]][0]
        arg = re.compile(helper["arguments_regex"][0])
        binary = re.compile(helper["binary_regex"][0])
        parent = re.compile(helper["parent_binary_regex"][0])
        for name in ("dns-watch", "bans", "diskguard", "policy-check", "home-net", "inventory", "droplet-id", "notify"):
            self.assertTrue(arg.search("-I /usr/local/lib/edr-agent/edr-" + name), name)
        self.assertTrue(arg.search("-I /usr/local/lib/edr-agent/edr-dns-watch probe"))
        for evil in ("-I /tmp/edr-bans", "-I /usr/local/lib/edr-agent/edr-bans; id", "-c import os", "-I /usr/local/lib/edr-agent/../x/edr-bans",
                     "-I /usr/local/lib/edr-agent/edr-evil", "-I /usr/local/lib/edr-agent/edr-bans extra stuff here"):
            self.assertFalse(arg.search(evil), evil)
        self.assertTrue(binary.search("/usr/bin/python3.12") and binary.search("/usr/bin/python3"))
        self.assertFalse(binary.search("/tmp/python3"))
        self.assertTrue(parent.search("/usr/lib/systemd/systemd"))
        self.assertFalse(parent.search("/usr/sbin/nginx"))


if __name__ == "__main__":
    unittest.main()
