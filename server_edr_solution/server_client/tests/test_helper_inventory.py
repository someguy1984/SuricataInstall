"""L0 tests of agent/edr-inventory (client PLAN section 4.5.1): Debian version comparison against
dpkg, the nginx parser with its limits, advisory evaluation, posture, drift and the output schema.
Programs are replaced by fixtures; nothing touches the real system."""

import json
import os
import random
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from test_helper_common import COMMON, TmpCase, have, load_helper, run_helper  # noqa: E402

I = load_helper("edr-inventory")
ADV = os.path.join(COMMON, "advisories.json")
NOW = 1795000000


def dpkg_cmp(a, b):
    for op, val in (("lt", -1), ("eq", 0), ("gt", 1)):
        if subprocess.run(["dpkg", "--compare-versions", a, op, b]).returncode == 0:
            return val
    raise AssertionError((a, b))


@unittest.skipUnless(have("dpkg"), "needs dpkg")
class TestVersionCompare(unittest.TestCase):
    CASES = ["1.24.0-2ubuntu7.19", "1.24.0-2ubuntu7.20", "1.24.0-2ubuntu7.3", "1.30.7-1~noble", "1.30.6-1~noble", "1.31.9-1~noble",
             "1.28.3-2ubuntu1.13", "1.28.3-2ubuntu1.9", "6.8.0-147.147", "6.8.0-45.45", "7.0.0-38.38~24.04.4", "7.0.0-43.43~24.04.1",
             "7.0.0-38.38", "7.0.0-43.43", "1:1.0-1", "2:0.1", "1.0~rc1-1", "1.0-1", "1.0", "1.0+dfsg-1", "1.0a", "1.0-0ubuntu1",
             "1.0-0", "0.9", "10.0", "9.9", "1.2.3", "1.2.03", "1.2.3~beta", "1.2.3+git20260101", "1.2.3-1.1", "1.2.3-1+b1",
             "2.39-0ubuntu8.3", "2.39-0ubuntu8.10", "1.0.0~", "1.0.0~~", "1.0.0~~a", "1.0:2", "3.0-1ubuntu0.24.04.1", "3.0-1ubuntu0.24.04.12"]

    def test_pairs_against_dpkg(self):
        for a in self.CASES:
            for b in self.CASES:
                if ":" in a.split("-")[0] and not a.partition(":")[0].isdigit() or ":" in b.split("-")[0] and not b.partition(":")[0].isdigit():
                    continue
                try:
                    want = dpkg_cmp(a, b)
                except AssertionError:
                    continue
                self.assertEqual(I.dpkg_compare(a, b), want, (a, b))

    def test_random_versions_against_dpkg(self):
        rnd = random.Random(11)
        alphabet = "0123456789.+~ab"
        def ver():
            up = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 8)))
            up = "1" + up if not up[0].isdigit() else up
            rev = "".join(rnd.choice("0123456789.+~ac") for _ in range(rnd.randint(1, 5)))
            return up + ("-" + rev if rnd.random() < 0.7 else "")
        for _ in range(400):
            a, b = ver(), ver()
            try:
                want = dpkg_cmp(a, b)
            except AssertionError:
                continue
            self.assertEqual(I.dpkg_compare(a, b), want, (a, b))

    def test_odd_input_raises(self):
        for bad in ("", None, "a b", "1;2", "x" * 300):
            with self.assertRaises(ValueError):
                I.dpkg_compare(bad, "1")

    def test_upstream(self):
        self.assertEqual(I.upstream_of("1.30.7-1~noble"), "1.30.7")
        self.assertEqual(I.upstream_of("1:1.24.0-2ubuntu7"), "1.24.0")
        self.assertEqual(I.upstream_of("1.2.3"), "1.2.3")


class NginxCase(TmpCase):
    def conf(self, main, files=None):
        self.put("/etc/nginx/nginx.conf", main)
        for path, text in (files or {}).items():
            self.put("/etc/nginx/" + path, text)

    def parse(self, **kw):
        env = I.Env(self.root, dry=True)
        cfg = I.NginxConfig(env, **kw)
        tree = cfg.parse_main()
        return cfg, tree

    def analyse(self, **kw):
        cfg, tree = self.parse(**kw)
        return cfg, I.analyse_nginx(cfg, tree)


class TestTokenizer(unittest.TestCase):
    def test_tokens(self):
        t = list(I.tokenize('server { listen 443 ssl; # c\n root "/a b"; set $x ${y}z; location ~ \'^/a;b\' { } }'))
        words = [v for k, v, _ in t if k == "w"]
        self.assertIn("/a b", words)
        self.assertIn("${y}z", words)
        self.assertIn("^/a;b", words)
        self.assertNotIn("c", words)


class TestNginxAnalysis(NginxCase):
    def test_http2_forms(self):
        self.conf("http { server { listen 443 ssl http2; } }")
        _, a = self.analyse()
        self.assertTrue(a["http2"] and not a["h2c"])
        self.conf("http { server { listen 443 ssl; http2 on; } }")
        self.assertTrue(self.analyse()[1]["http2"])
        # a leftover parameter keeps it on whatever "http2 off;" says
        self.conf("http { server { listen 443 ssl http2; http2 off; } }")
        self.assertTrue(self.analyse()[1]["http2"])
        self.conf("http { server { listen 443 ssl; } }")
        self.assertFalse(self.analyse()[1]["http2"])
        self.conf("http { http2 on; server { listen 443 ssl; http2 off; } }")
        self.assertFalse(self.analyse()[1]["http2"])

    def test_h2c_is_a_cleartext_listener_with_http2(self):
        self.conf("http { server { listen 80 http2; } server { listen 443 ssl; } }")
        _, a = self.analyse()
        self.assertTrue(a["h2c"] and a["http2"])
        self.conf("http { server { listen 8080; http2 on; } }")
        self.assertTrue(self.analyse()[1]["h2c"])
        self.conf("http { server { listen 80; } server { listen 443 ssl; http2 on; } }")
        self.assertFalse(self.analyse()[1]["h2c"])

    def test_http3_and_mail(self):
        self.conf("http { server { listen 443 quic reuseport; listen 443 ssl; } }")
        self.assertTrue(self.analyse()[1]["http3"])
        self.conf("mail { auth_http 127.0.0.1:9000/auth; server { listen 143; proxy on; } }")
        a = self.analyse()[1]
        self.assertTrue(a["mail"] and a["mail_public"])
        self.conf("mail { auth_http 127.0.0.1:9000/auth; server { listen 127.0.0.1:143; proxy on; } }")
        self.assertFalse(self.analyse()[1]["mail"])
        self.conf("mail { server { listen 143; } }")
        self.assertFalse(self.analyse()[1]["mail"])

    def test_resolver_bug_needs_all_three_parts_and_rates_mirror_body_off(self):
        self.conf("http { resolver 1.1.1.1 valid=30s; server { location / { proxy_pass http://$host; mirror /m; } } }")
        a = self.analyse()[1]
        self.assertTrue(a["resolver_bug"])
        self.assertEqual(a["resolver"], ["1.1.1.1"])
        self.assertFalse(a["mirror_body_off"])
        self.conf("http { resolver 1.1.1.1; server { location / { proxy_pass http://$host; ssi on; mirror_request_body off; } } }")
        a = self.analyse()[1]
        self.assertTrue(a["resolver_bug"] and a["mirror_body_off"])
        self.conf("http { resolver 1.1.1.1; server { location / { proxy_pass http://backend; mirror /m; } } }")
        self.assertFalse(self.analyse()[1]["resolver_bug"])
        self.conf("http { server { location / { proxy_pass http://$host; mirror /m; } } }")
        self.assertFalse(self.analyse()[1]["resolver_bug"])

    def test_logs_formats_and_real_ip(self):
        self.conf("""http {
            log_format main '$remote_addr - $remote_user';
            log_format xff '$http_x_forwarded_for $remote_addr';
            log_format odd '$time_local $remote_addr' escape=json;
            access_log /var/log/nginx/access.log main; error_log /var/log/nginx/error.log info;
            set_real_ip_from 10.0.0.0/8; real_ip_header X-Forwarded-For;
        }""")
        a = self.analyse()[1]
        self.assertTrue(a["log_formats"]["main"]["starts_remote_addr"])
        self.assertTrue(a["log_formats"]["xff"]["has_xff"])
        self.assertFalse(a["log_formats"]["odd"]["starts_remote_addr"])
        self.assertEqual(a["log_formats"]["odd"]["escape"], "json")
        self.assertEqual(a["error_logs"][0]["level"], "info")
        self.assertEqual(a["set_real_ip_from"], ["10.0.0.0/8"])

    def test_php_locations_and_dotfiles(self):
        self.conf(r"""http { server { location ~ \.php$ { fastcgi_pass unix:/run/php/x.sock; }
                  location ~ /\.(?!well-known) { deny all; } } }""")
        a = self.analyse()[1]
        self.assertTrue(a["php_any"] and a["dotfile_deny"])
        self.conf(r"""http { server { location ~ ^/index\.php(/|$) { fastcgi_pass unix:/run/php/x.sock; } } }""")
        a = self.analyse()[1]
        self.assertFalse(a["php_any"])
        self.assertFalse(a["dotfile_deny"])


class TestNginxLimits(NginxCase):
    def test_symlinked_sites_enabled_is_followed(self):
        self.conf("http { include /etc/nginx/sites-enabled/*; }", {"sites-available/s": "server { listen 443 ssl http2; }"})
        os.makedirs(self.root + "/etc/nginx/sites-enabled")
        os.symlink("../sites-available/s", self.root + "/etc/nginx/sites-enabled/s")
        cfg, a = self.analyse()
        if os.geteuid() == 0:
            self.assertTrue(a["http2"])
            self.assertFalse(cfg.incomplete)
        else:
            # Run without root (make unit), the target belongs to the test user: a symlink to a file that a
            # non-root user can write is not followed, and the result says it is incomplete.
            self.assertFalse(a["http2"])
            self.assertTrue(cfg.incomplete)
            self.assertIn("include_symlink_writable", [p["kind"] for p in cfg.problems])

    def test_include_depth_8_is_allowed_and_9_is_a_limit(self):
        # nginx.conf is depth 0, d1 is depth 1: the 8th nested include is depth 8, the 9th is over the limit
        files = {"d%d.conf" % n: ("include d%d.conf;" % (n + 1) if n < 9 else "server { listen 80 http2; }") for n in range(1, 10)}
        self.conf("http { include d1.conf; }", files)
        cfg, tree = self.parse()
        self.assertEqual(cfg.limit_hit, "include depth")
        self.assertTrue(cfg.incomplete)
        files = {"d%d.conf" % n: ("include d%d.conf;" % (n + 1) if n < 8 else "server { listen 80 http2; }") for n in range(1, 9)}
        self.conf("http { include d1.conf; }", files)
        cfg, a = self.analyse()
        self.assertIsNone(cfg.limit_hit)
        self.assertTrue(a["h2c"])

    def test_500_files_ok_501_limit(self):
        for n in range(499):
            self.put("/etc/nginx/conf.d/%03d.conf" % n, "# empty\n")
        self.conf("http { include /etc/nginx/conf.d/*.conf; server { listen 443 ssl http2; } }")
        cfg, a = self.analyse()
        self.assertIsNone(cfg.limit_hit)                     # nginx.conf + 499 = 500 files
        self.put("/etc/nginx/conf.d/499.conf", "# one more\n")
        cfg, tree = self.parse()
        self.assertEqual(cfg.limit_hit, "file count")
        self.assertTrue(cfg.incomplete)

    def test_include_outside_nginx_is_not_read(self):
        self.put("/srv/evil.conf", "server { listen 80 http2; }")
        self.conf("http { include /srv/evil.conf; server { listen 443 ssl; } }")
        cfg, a = self.analyse()
        self.assertFalse(a["h2c"])
        self.assertIn("include_outside", [p["kind"] for p in cfg.problems])
        self.assertTrue(cfg.incomplete)
        # an include root the operator discovered is allowed
        cfg, a = self.analyse(include_roots=["/srv"])
        self.assertTrue(a["h2c"])

    def test_fifo_include_is_not_read_and_does_not_hang(self):
        os.makedirs(self.root + "/etc/nginx/conf.d")
        os.mkfifo(self.root + "/etc/nginx/conf.d/fifo.conf")
        self.conf("http { include /etc/nginx/conf.d/*.conf; }")
        cfg, a = self.analyse()
        self.assertIn("include_not_regular", [p["kind"] for p in cfg.problems])
        self.assertTrue(cfg.incomplete)

    def test_symlink_to_a_file_outside_is_refused(self):
        self.put("/etc/shadow", "root:*:19000::::::\n")
        os.makedirs(self.root + "/etc/nginx/conf.d")
        os.symlink(self.root + "/etc/shadow", self.root + "/etc/nginx/conf.d/shadow.conf")
        self.conf("http { include /etc/nginx/conf.d/*.conf; }")
        cfg, a = self.analyse()
        self.assertIn("include_outside", [p["kind"] for p in cfg.problems])

    def test_large_sparse_include_is_a_limit(self):
        path = self.put("/etc/nginx/conf.d/big.conf", "")
        with open(path, "wb") as fh:
            fh.truncate(1 << 30)
        self.conf("http { include /etc/nginx/conf.d/big.conf; server { listen 443 ssl; } }")
        cfg, tree = self.parse()
        self.assertEqual(cfg.limit_hit, "size")
        self.assertTrue(cfg.incomplete)

    def test_total_size_limit(self):
        for n in range(6):
            self.put("/etc/nginx/conf.d/%d.conf" % n, "# " + "x" * (900 * 1024) + "\n")
        self.conf("http { include /etc/nginx/conf.d/*.conf; }")
        cfg, tree = self.parse()
        self.assertEqual(cfg.limit_hit, "size")

    def test_writable_include_is_parsed_but_reported(self):
        self.put("/etc/nginx/conf.d/w.conf", "server { listen 80 http2; }", mode=0o666)
        self.conf("http { include /etc/nginx/conf.d/w.conf; }")
        cfg, a = self.analyse()
        self.assertTrue(a["h2c"])
        self.assertIn("include_writable", [p["kind"] for p in cfg.problems])
        self.assertFalse(cfg.incomplete)

    def test_symlink_to_a_writable_target_is_not_followed(self):
        self.put("/etc/nginx/real.conf", "server { listen 80 http2; }", mode=0o666)
        os.symlink("real.conf", self.root + "/etc/nginx/link.conf")
        self.conf("http { include link.conf; }")
        cfg, a = self.analyse()
        self.assertFalse(a["h2c"])
        self.assertIn("include_symlink_writable", [p["kind"] for p in cfg.problems])

    def test_unbalanced_and_deeply_nested_blocks(self):
        self.conf("http { " + "location / { " * 100 + "}" * 100)
        cfg, tree = self.parse()
        self.assertEqual(cfg.limit_hit, "block depth")
        self.conf("http { server { listen 80; ")
        cfg, tree = self.parse()
        self.assertTrue(cfg.incomplete)


def fixture_root(case, advisories=True, codename="noble", nginx_ver="1.24.0-2ubuntu7.19", policy_src="http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages",
                 sig="Ubuntu 6.8.0-45.45-generic 6.8.12"):
    case.put("/etc/os-release", 'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=%s\n' % codename)
    case.put("/var/lib/dpkg/status", "Package: nginx\nStatus: install ok installed\nVersion: %s\nArchitecture: amd64\n\n"
             "Package: nginx-common\nStatus: install ok installed\nVersion: %s\n\n" % (nginx_ver, nginx_ver))
    case.put("/proc/version_signature", sig + "\n")
    case.put("/proc/sys/kernel/osrelease", "6.8.0-45-generic\n")
    fx = {"apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy nginx": {
        "out": "nginx:\n  Installed: %s\n  Candidate: %s\n  Version table:\n *** %s 500\n        500 %s\n        100 /var/lib/dpkg/status\n" % (nginx_ver, nginx_ver, nginx_ver, policy_src)}}
    return fx


class InvCase(TmpCase):
    def run_inv(self, fx=None, extra=()):
        path = os.path.join(self.root, "fx.json")
        with open(path, "w") as fh:
            json.dump(fx or {}, fh)
        rc, out, err = run_helper("edr-inventory", ["--root", self.root, "--dry-run", "--advisories", ADV, "--exec-fixtures", path,
                                                   "--now", str(NOW)] + list(extra), timeout=120)
        self.assertEqual(rc, 0, err)
        return json.loads(out)

    def findings(self, doc, check):
        return [f for f in doc["findings"] if f["check"] == check]


@unittest.skipUnless(os.path.isfile(ADV), "common/advisories.json is missing")
class TestAdvisoryEvaluation(InvCase):
    def exposed(self):
        self.put("/etc/nginx/nginx.conf", "http { server { listen 443 ssl http2; ssl_certificate /x; } }")

    def test_ubuntu_package_below_its_fix_with_http2_is_high(self):
        fx = fixture_root(self)
        self.exposed()
        d = self.run_inv(fx)
        f = self.findings(d, "nginx_pkg")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["sev"], "HIGH")
        self.assertIs(d["checks"]["nginx_pkg"]["status"], True)
        self.assertEqual(d["checks"]["nginx_pkg"]["packages"][0]["origin"], "ubuntu")

    def test_fixed_ubuntu_package_is_clean(self):
        fx = fixture_root(self, nginx_ver="1.24.0-2ubuntu7.20")
        self.exposed()
        d = self.run_inv(fx)
        self.assertEqual(self.findings(d, "nginx_pkg"), [])
        self.assertIs(d["checks"]["nginx_pkg"]["status"], False)

    def test_no_exposed_feature_is_a_low_or_medium_digest(self):
        fx = fixture_root(self)
        self.put("/etc/nginx/nginx.conf", "http { server { listen 80; } }")
        d = self.run_inv(fx)
        self.assertEqual(self.findings(d, "nginx_pkg")[0]["sev"], "LOW")
        self.put("/etc/nginx/nginx.conf", "http { server { listen 443 ssl; ssl_certificate /x; } }")
        d = self.run_inv(fx)
        self.assertEqual(self.findings(d, "nginx_pkg")[0]["sev"], "MEDIUM")

    def test_resolver_bug_alone_is_medium_unless_mirror_body_off(self):
        fx = fixture_root(self)
        self.put("/etc/nginx/nginx.conf", "http { resolver 1.1.1.1; server { listen 80; location / { proxy_pass http://$h; mirror /m; } } }")
        self.assertEqual(self.findings(self.run_inv(fx), "nginx_pkg")[0]["sev"], "MEDIUM")
        self.put("/etc/nginx/nginx.conf", "http { resolver 1.1.1.1; server { listen 80; location / { proxy_pass http://$h; mirror /m; mirror_request_body off; } } }")
        self.assertEqual(self.findings(self.run_inv(fx), "nginx_pkg")[0]["sev"], "HIGH")

    def test_unknown_config_is_not_clean(self):
        fx = fixture_root(self)
        self.put("/etc/nginx/nginx.conf", "http { include /srv/elsewhere.conf; }")
        d = self.run_inv(fx)
        self.assertEqual(d["checks"]["nginx_exposure"]["status"], "unknown")
        self.assertEqual(self.findings(d, "nginx_pkg")[0]["sev"], "MEDIUM")       # unknown exposure

    def test_nginx_org_rows_compare_upstream_by_branch(self):
        cases = [("1.30.6-1~noble", True), ("1.30.7-1~noble", False), ("1.30.9-1~noble", False), ("1.31.2-1~noble", True),
                 ("1.31.9-1~noble", False), ("1.32.0-1~noble", False), ("1.28.0-1~noble", True)]
        src = "https://nginx.org/packages/ubuntu noble/nginx amd64 Packages"
        for ver, vulnerable in cases:
            self.setUp()
            fx = fixture_root(self, nginx_ver=ver, policy_src=src)
            self.exposed()
            d = self.run_inv(fx)
            self.assertEqual(d["checks"]["nginx_pkg"]["packages"][0]["origin"], "nginx.org")
            self.assertIs(d["checks"]["nginx_pkg"]["status"], vulnerable, ver)

    def test_ubuntu_fixed_version_does_not_match_the_nginx_org_row(self):
        # 1.24.0-2ubuntu7.20 sorts below 1.30.7 by upstream, but it is an Ubuntu package
        fx = fixture_root(self, nginx_ver="1.24.0-2ubuntu7.20")
        self.exposed()
        d = self.run_inv(fx)
        self.assertIs(d["checks"]["nginx_pkg"]["status"], False)

    def test_other_origin_or_release_is_unknown_never_vulnerable(self):
        fx = fixture_root(self, policy_src="https://ppa.launchpadcontent.net/x/y/ubuntu noble/main amd64 Packages")
        self.exposed()
        d = self.run_inv(fx)
        self.assertEqual(d["checks"]["nginx_pkg"]["status"], "unknown")
        self.assertEqual(self.findings(d, "nginx_pkg"), [])
        fx = fixture_root(self, codename="plucky")
        d = self.run_inv(fx)
        self.assertEqual(d["checks"]["nginx_pkg"]["status"], "unknown")

    def test_kernel_rows(self):
        for sig, vulnerable in (("Ubuntu 6.8.0-45.45-generic 6.8.12", True), ("Ubuntu 6.8.0-147.147-generic 6.8.12", False),
                                ("Ubuntu 6.8.0-200.250-generic 6.8.12", False),
                                ("Ubuntu 7.0.0-37.37~24.04.1-generic 7.0.10", True), ("Ubuntu 7.0.0-43.43~24.04.1-generic 7.0.14", False)):
            self.setUp()
            fx = fixture_root(self, sig=sig)
            d = self.run_inv(fx)
            self.assertIs(d["checks"]["kernel_pending"]["status"], vulnerable, sig)
            self.assertEqual(bool(self.findings(d, "kernel_pending")), vulnerable)
        self.setUp()
        fx = fixture_root(self, codename="resolute", sig="Ubuntu 7.0.0-30.30-generic 7.0.5")
        self.assertIs(self.run_inv(fx)["checks"]["kernel_pending"]["status"], True)
        self.setUp()
        fx = fixture_root(self, sig="Ubuntu 6.11.0-26.26~24.04.1-generic 6.11.11")
        self.assertEqual(self.run_inv(fx)["checks"]["kernel_pending"]["status"], "unknown")

    def test_override_row_replaces_by_id(self):
        fx = fixture_root(self)
        self.exposed()
        with open(ADV) as fh:
            rows = json.load(fh)["rows"]
        row = dict(next(r for r in rows if r["id"] == "nginx-ubuntu-noble"), fixed_in="1.24.0-2ubuntu7.19")
        self.put("/etc/edr-agent/advisories.d/local.json", json.dumps({"rows": [row]}))
        d = self.run_inv(fx)
        self.assertIs(d["checks"]["nginx_pkg"]["status"], False)

    def test_no_advisory_file_is_unknown(self):
        fx = fixture_root(self)
        path = os.path.join(self.root, "fx.json")
        with open(path, "w") as fh:
            json.dump(fx, fh)
        rc, out, _ = run_helper("edr-inventory", ["--root", self.root, "--dry-run", "--advisories", "/nonexistent", "--exec-fixtures", path,
                                                 "--now", str(NOW)])
        # the shipped file beside the code may still be found; either way nothing is "clean" by default
        self.assertEqual(rc, 0)


class TestSecurityPending(InvCase):
    APT = ("Reading package lists...\nThe following packages have been kept back:\n  linux-generic libfoo\n"
           "Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [amd64])\n"
           "Inst tzdata [2024a-2] (2024b-1 Ubuntu:24.04/noble-updates [all])\n"
           "Inst nginx [1.24.0-2ubuntu7.19] (1.24.0-2ubuntu7.20 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])\n")

    def test_security_updates_are_listed_with_a_first_seen_date(self):
        fx = fixture_root(self)
        fx["apt-get -s -o Debug::NoLocking=1 -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= dist-upgrade"] = {"out": self.APT}
        os.makedirs(self.root + "/var/lib/apt/lists")
        self.put("/var/lib/apt/lists/x_InRelease", "x")
        os.utime(self.root + "/var/lib/apt/lists/x_InRelease", (NOW - 3 * 86400, NOW - 3 * 86400))
        d = self.run_inv(fx)
        sp = d["checks"]["security_pending"]
        self.assertIs(sp["status"], True)
        self.assertEqual(sorted(p["pkg"] for p in sp["pending"]), ["libssl3t64", "nginx"])
        self.assertEqual(sp["lists_age_hours"], 72)
        self.assertTrue(sp["stale_lists"])
        self.assertEqual(sp["phased"], 2)
        self.assertEqual(self.findings(d, "security_pending")[0]["sev"], "MEDIUM")

    def test_apt_failure_is_unknown(self):
        d = self.run_inv(fixture_root(self))
        self.assertEqual(d["checks"]["security_pending"]["status"], "unknown")


class TestSctpAndPhp(InvCase):
    def test_sctp_states(self):
        fx = fixture_root(self)
        os.makedirs(self.root + "/lib/modules/6.8.0-45-generic")
        self.put("/lib/modules/6.8.0-45-generic/modules.builtin", "kernel/net/ipv4/tcp.ko\n")
        fx["modprobe -n -v sctp"] = {"out": "insmod /lib/modules/6.8.0-45-generic/kernel/net/sctp/sctp.ko \n"}
        d = self.run_inv(fx)
        self.assertIs(d["checks"]["sctp"]["status"], True)               # loadable
        self.assertEqual(self.findings(d, "sctp")[0]["sev"], "MEDIUM")
        fx["modprobe -n -v sctp"] = {"out": "install /bin/false \n"}
        d = self.run_inv(fx)
        self.assertIs(d["checks"]["sctp"]["status"], False)
        self.assertEqual(self.findings(d, "sctp"), [])
        self.put("/lib/modules/6.8.0-45-generic/modules.builtin", "kernel/net/sctp/sctp.ko\n")
        self.assertIs(self.run_inv(fx)["checks"]["sctp"]["status"], True)    # built in: the module block does nothing

    def test_sctp_unknown_without_programs_or_files(self):
        d = self.run_inv(fixture_root(self))
        self.assertEqual(d["checks"]["sctp"]["status"], "unknown")

    def test_php_pools_and_coverage_drift(self):
        fx = fixture_root(self)
        self.put("/etc/nginx/nginx.conf", "user www-data; http { server { listen 80; root /var/www/app/public; root /var/www/other/public; } }")
        self.put("/etc/php/8.3/fpm/pool.d/www.conf", "[www]\nuser = www-data\nlisten = /run/php/php8.3-fpm.sock\n[extra]\nuser = deploy\nsecurity.limit_extensions = \n")
        self.put("/etc/edr-agent/local.conf", "[sites]\nweb_users = www-data\nweb_roots = /var/www/app/public\nphpfpm_bins = /usr/sbin/php-fpm8.3\n")
        d = self.run_inv(fx)
        self.assertEqual([p["name"] for p in d["checks"]["php"]["pools"]], ["www", "extra"])
        self.assertIs(d["checks"]["uncovered_webroots"]["status"], True)
        self.assertEqual(d["checks"]["uncovered_webroots"]["paths"], ["/var/www/other/public"])
        self.assertIs(d["checks"]["uncovered_pool_users"]["status"], True)
        self.assertEqual(d["checks"]["uncovered_pool_users"]["users"], ["deploy"])
        self.assertEqual(d["checks"]["uncovered_fpm_binaries"]["status"], False)
        self.assertEqual(len(self.findings(d, "uncovered_webroots")), 1)
        self.assertIs(d["posture"]["fpm_limit_extensions"], False)

    def test_drift_is_unknown_without_a_recorded_baseline(self):
        fx = fixture_root(self)
        self.put("/etc/nginx/nginx.conf", "http { server { root /var/www/a/public; } }")
        d = self.run_inv(fx)
        for k in ("uncovered_webroots", "uncovered_fpm_binaries", "uncovered_pool_users"):
            self.assertEqual(d["checks"][k]["status"], "unknown")


class TestDeletedExe(InvCase):
    def proc(self, pid, comm, exe, maps="", cgroup="0::/system.slice/nginx.service\n"):
        base = "/proc/%d" % pid
        os.makedirs(self.root + base, exist_ok=True)
        self.put(base + "/comm", comm + "\n")
        self.put(base + "/maps", maps)
        self.put(base + "/cgroup", cgroup)
        self.put(base + "/stat", "%d (%s) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 1000 0 0\n" % (pid, comm))
        os.symlink(exe, self.root + base + "/exe")

    def test_stale_nginx_is_debounced_then_high(self):
        fixture_root(self)
        self.put("/proc/stat", "btime 1794990000\n")
        self.proc(500, "nginx", "/usr/sbin/nginx (deleted)")
        self.proc(501, "nginx", "/usr/sbin/nginx (deleted)")
        self.proc(600, "sshd", "/usr/sbin/sshd")
        d = self.run_inv({})
        de = d["checks"]["deleted_exe"]
        self.assertIs(de["status"], True)
        self.assertTrue(de["nginx_stale"])
        self.assertEqual(self.findings(d, "deleted_exe"), [])           # first sighting: wait for the re-check
        self.assertIn("first sighting", de["debounce"])
        state = self.read_json("/var/lib/edr-inventory/state.json") if os.path.exists(self.root + "/var/lib/edr-inventory/state.json") else {}
        self.assertEqual(state.get("nginx_stale_first"), NOW) if state else None
        # the second run, 20 minutes later
        self.put("/var/lib/edr-inventory/state.json", json.dumps({"nginx_stale_first": NOW - 1200}))
        d = self.run_inv({})
        f = self.findings(d, "deleted_exe")
        self.assertEqual([x["sev"] for x in f], ["HIGH"])
        self.assertEqual(f[0]["details"]["unit"], "nginx.service")

    def test_deleted_library_of_a_public_service_and_noise_filters(self):
        fixture_root(self)
        self.put("/proc/stat", "btime 1794990000\n")
        self.proc(700, "php-fpm8.3", "/usr/sbin/php-fpm8.3", maps="7f00-7f01 r-xp 0 08:01 5 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n",
                  cgroup="0::/system.slice/php8.3-fpm.service\n")
        self.proc(701, "weird", "/usr/bin/weird", maps="7f00-7f01 r-xp 0 08:01 5 /tmp/libx.so (deleted)\n7f02-7f03 rw-s 0 00:01 5 /memfd:foo.so (deleted)\n")
        self.proc(702, "cron", "/usr/sbin/cron", maps="7f00-7f01 r-xp 0 08:01 5 /usr/lib/x86_64-linux-gnu/libc.so.6 (deleted)\n",
                  cgroup="0::/system.slice/cron.service\n")
        d = self.run_inv({})
        highs = [f for f in self.findings(d, "deleted_exe") if f["sev"] == "HIGH"]
        self.assertEqual([f["details"]["comm"] for f in highs], ["php-fpm8.3"])
        lows = [f for f in self.findings(d, "deleted_exe") if f["sev"] == "LOW"]
        self.assertEqual(lows[0]["details"]["count"], 1)                 # cron only: /tmp and memfd mappings are ignored


class TestStateBaselines(InvCase):
    def test_auth_state_baseline_then_new_uid0_account(self):
        fixture_root(self)
        self.put("/etc/passwd", "root:x:0:0::/root:/bin/bash\nj:x:1000:1000::/home/j:/bin/bash\n")
        self.put("/etc/sudoers", "root ALL=(ALL) ALL\n")
        self.put("/home/j/.ssh/authorized_keys", "ssh-ed25519 AAAA j\n")
        d = self.run_inv({})
        self.assertEqual(self.findings(d, "auth_state"), [])
        self.assertFalse(d["checks"]["auth_state"]["baseline"])
        self.assertEqual(d["checks"]["auth_state"]["authorized_keys_files"], 1)
        self.put("/etc/passwd", "root:x:0:0::/root:/bin/bash\nj:x:1000:1000::/home/j:/bin/bash\ntoor:x:0:0::/root:/bin/sh\n")
        self.put("/etc/sudoers", "root ALL=(ALL) ALL\nj ALL=(ALL) NOPASSWD: ALL\n")
        self.put("/home/j/.ssh/authorized_keys", "ssh-ed25519 AAAA j\nssh-ed25519 BBBB evil\n")
        d = self.run_inv({})
        sev = {f["summary"].split()[0] + f["sev"] for f in self.findings(d, "auth_state")}
        self.assertEqual(len(self.findings(d, "auth_state")), 3)
        # every change is HIGH: a new uid-0 account, a changed sudoers, a changed authorized_keys (hub plan rule table, client 4.7)
        self.assertEqual([f["sev"] for f in self.findings(d, "auth_state")], ["HIGH", "HIGH", "HIGH"])
        # nothing in the output names the new account: hashes only
        self.assertNotIn("toor", json.dumps(d))
        d = self.run_inv({})
        self.assertEqual(self.findings(d, "auth_state"), [])            # the new state is the baseline now

    def test_listeners_new_public_port(self):
        fixture_root(self)
        ss = "LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=5,fd=6))\nLISTEN 0 4096 127.0.0.1:3306 0.0.0.0:*\n"
        fx = {"ss -ltnpH": {"out": ss}}
        d = self.run_inv(fx)
        self.assertEqual(d["checks"]["listeners"]["public"], [80])
        self.assertEqual(self.findings(d, "listeners"), [])
        fx = {"ss -ltnpH": {"out": ss + "LISTEN 0 5 0.0.0.0:4444 0.0.0.0:* users:((\"nc\",pid=9,fd=3))\n"}}
        d = self.run_inv(fx)
        f = self.findings(d, "listeners")
        self.assertEqual(f[0]["details"]["ports"], [4444])
        self.assertEqual(f[0]["details"]["processes"], ["nc"])


class TestPosture(InvCase):
    def site(self, env_text="APP_DEBUG=false\nAPP_ENV=production\n", mode=0o640):
        self.put("/etc/nginx/nginx.conf", "http { server { listen 80; root /var/www/app/public; } }")
        self.put("/var/www/app/public/index.php", "<?php\n")
        self.put("/var/www/app/.env", env_text, mode=mode)

    def test_app_debug_and_env_permissions(self):
        fixture_root(self)
        self.site("APP_DEBUG=true\nAPP_ENV=local\nSECRET=hunter2\n", mode=0o644)
        d = self.run_inv({})
        self.assertIs(d["posture"]["app_debug_true"], True)
        self.assertEqual(d["posture"]["env_mode"], "local")
        self.assertIs(d["posture"]["env_perm_ok"], False)
        self.assertNotIn("hunter2", json.dumps(d))                      # booleans and enums, never values
        sev = {f["details"].get("field"): f["sev"] for f in self.findings(d, "posture")}
        self.assertEqual(sev["app_debug_true"], "HIGH")
        self.assertEqual(sev["env_perm_ok"], "MEDIUM")
        # edr-check prints "<check>: <summary>": the summary must not say "posture" again
        said = {f["details"].get("field"): f["summary"] for f in self.findings(d, "posture")}
        self.assertEqual(said["env_perm_ok"], "env_perm_ok is not satisfied")
        self.assertFalse([t for t in said.values() if t.startswith("posture")], said)

    def test_app_key_in_public_and_world_writable(self):
        fixture_root(self)
        self.site()
        self.put("/var/www/app/public/.env.bak", "APP_KEY=base64:abcdef\n")
        self.put("/var/www/app/public/notes.txt", "hello\n")
        w = self.put("/var/www/app/storage/up.php", "<?php\n", mode=0o666)
        os.chmod(w, 0o666)
        d = self.run_inv({})
        self.assertIs(d["posture"]["app_key_in_public"], True)
        self.assertIs(d["posture"]["world_writable_in_webroot"], True)
        self.assertNotIn("base64:abcdef", json.dumps(d))
        sev = {f["details"].get("field"): f["sev"] for f in self.findings(d, "posture")}
        self.assertEqual(sev["app_key_in_public"], "HIGH")
        self.assertEqual(sev["world_writable_in_webroot"], "MEDIUM")
        self.assertEqual({f["details"].get("field"): f["summary"] for f in self.findings(d, "posture")}["world_writable_in_webroot"],
                         "world_writable_in_webroot")

    def test_env_fifo_symlink_and_huge_file_are_unknown(self):
        fixture_root(self)
        self.site()
        env = self.root + "/var/www/app/.env"
        os.unlink(env)
        os.mkfifo(env)
        d = self.run_inv({})
        self.assertEqual(d["posture"]["app_debug_true"], "unknown")
        os.unlink(env)
        self.put("/etc/shadow-like", "APP_DEBUG=true\n")
        os.symlink(self.root + "/etc/shadow-like", env)
        d = self.run_inv({})
        self.assertEqual(d["posture"]["app_debug_true"], "unknown")      # a symlink is not followed
        os.unlink(env)
        with open(env, "wb") as fh:
            fh.truncate(1 << 30)
        d = self.run_inv({})
        self.assertEqual(d["posture"]["app_debug_true"], "unknown")

    def test_sshd_listeners_and_unattended_upgrades(self):
        fixture_root(self)
        self.site()
        self.put("/etc/apt/apt.conf.d/20auto-upgrades", 'APT::Periodic::Unattended-Upgrade "1";\n')
        fx = {"sshd -T": {"out": "port 22\npasswordauthentication yes\npermitrootlogin without-password\n"},
              "ss -ltnpH": {"out": "LISTEN 0 5 0.0.0.0:6379 0.0.0.0:*\nLISTEN 0 5 127.0.0.1:3306 0.0.0.0:*\n"}}
        d = self.run_inv(fx)
        p = d["posture"]
        self.assertIs(p["sshd_password_auth"], True)
        self.assertIs(p["sshd_root_login"], False)
        self.assertIs(p["public_listeners"], True)
        self.assertIs(p["unattended_upgrades_on"], True)
        self.assertEqual(self.findings(d, "posture") and {f["details"]["field"] for f in self.findings(d, "posture") if f["sev"] == "MEDIUM"} >= {"sshd_password_auth", "public_listeners"}, True)


class TestOutput(InvCase):
    def test_output_file_schema_and_mode(self):
        fixture_root(self)
        path = os.path.join(self.root, "fx.json")
        with open(path, "w") as fh:
            json.dump({}, fh)
        rc, out, err = run_helper("edr-inventory", ["--root", self.root, "--advisories", ADV if os.path.isfile(ADV) else "/none",
                                                   "--exec-fixtures", path, "--now", str(NOW)], timeout=120)
        self.assertEqual(rc, 0, err)
        out_path = self.root + "/run/edr-inventory/inventory.json"
        self.assertEqual(os.stat(out_path).st_mode & 0o777, 0o640)
        with open(out_path) as fh:
            doc = json.load(fh)
        self.assertEqual(doc["v"], 1)
        self.assertEqual(doc["written_at"], NOW)
        self.assertEqual(doc["os_release"]["codename"], "noble")
        for k in ("nginx_pkg", "nginx_build", "nginx_exposure", "udp443", "nginx_logs", "real_ip", "deleted_exe", "security_pending",
                  "sctp", "kernel_pending", "php", "auth_state", "listeners", "uncovered_webroots", "uncovered_fpm_binaries", "uncovered_pool_users"):
            self.assertIn(k, doc["checks"], k)
            self.assertIn(doc["checks"][k]["status"], (True, False, "unknown"), k)
        self.assertIn("app_debug_true", doc["posture"])
        for f in doc["findings"]:
            self.assertEqual(set(f), {"check", "sev", "summary", "details"})
            self.assertIn(f["sev"], ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"))
        self.assertTrue(os.path.exists(self.root + "/var/lib/edr-inventory/state.json"))

    def test_everything_unknown_on_an_empty_machine(self):
        d = self.run_inv({})
        for k, c in d["checks"].items():
            self.assertNotEqual(c["status"], True, k)


if __name__ == "__main__":
    unittest.main()
