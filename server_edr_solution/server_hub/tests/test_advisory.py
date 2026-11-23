"""hub_advisory: the shipped table, overrides, Debian version comparison, exposure, staleness."""

import copy
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "hub"))

import hub_advisory as adv    # noqa: E402
import hub_common             # noqa: E402

ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
SHIPPED = os.path.join(ROOT, "common", "advisories.json")
DAY = 86400 * 1000


def at(date):
    return int(datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp() * 1000)


def dpkg(a, op, b):
    return subprocess.run(["dpkg", "--compare-versions", a, op, b], capture_output=True, timeout=10).returncode == 0


class VersionTests(unittest.TestCase):
    CASES = [
        ("1.24.0-2ubuntu7.20", "1.24.0-2ubuntu7.19"), ("1.24.0-2ubuntu7.20", "1.24.0-2ubuntu7.20"), ("1.24.0-2ubuntu7.9", "1.24.0-2ubuntu7.20"),
        ("1.30.7-1~noble", "1.30.7"), ("1.30.6-1~noble", "1.30.7-1~noble"), ("1.0~rc1", "1.0"), ("1:1.0", "2.0"), ("1.0", "0:1.0"),
        ("1.0-1", "1.0-1~noble"), ("1.0+b1", "1.0"), ("a", "1"), ("1.a", "1.1"), ("1.0.0", "1.0"), ("007", "7"), ("1.2.3~", "1.2.3"),
        ("7.0.0-38.38~24.04.4", "7.0.0-38.38"), ("6.8.0-147.147", "6.8.0-147"), ("7.0.0-37.37~24.04.1", "7.0.0-38.38~24.04.4"),
        ("1.28.3-2ubuntu1.13", "1.28.3-2ubuntu1.12"), ("1.2-3-4", "1.2-3-5"), ("2:0.9", "1:9.9"), ("1.0~~", "1.0~"), ("1.0-0", "1.0"),
    ]

    def expected(self, a, b):
        return -1 if dpkg(a, "lt", b) else 0 if dpkg(a, "eq", b) else 1

    def test_against_dpkg_fixed_cases(self):
        for a, b in self.CASES:
            self.assertEqual(adv.dpkg_compare(a, b), self.expected(a, b), (a, b))
            self.assertEqual(adv.dpkg_compare(b, a), self.expected(b, a), (b, a))

    def test_against_dpkg_random_pairs(self):
        rng = random.Random(20261119)
        alphabet = "0123456789.+~-:abz"
        checked = 0
        for _ in range(400):
            a = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 9)))
            b = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 9)))
            try:
                got = adv.dpkg_compare(a, b)
            except ValueError:
                continue                                  # our parser refuses it; dpkg may only warn
            if subprocess.run(["dpkg", "--compare-versions", a, "lt", b], capture_output=True, timeout=10).returncode > 1:
                continue                                  # dpkg calls the version malformed
            self.assertEqual(got, self.expected(a, b), (a, b))
            checked += 1
        self.assertGreater(checked, 150)

    def test_malformed(self):
        for bad in ("", "  ", None, 5, "x:1", "-1"):
            with self.assertRaises(ValueError):
                adv.dpkg_compare(bad, "1.0")

    def test_upstream_of(self):
        self.assertEqual(adv.upstream_of("1.30.7-1~noble"), "1.30.7")
        self.assertEqual(adv.upstream_of("1:1.30.7-1"), "1.30.7")
        self.assertEqual(adv.upstream_of("1.24.0-2ubuntu7.20"), "1.24.0")
        self.assertEqual(adv.upstream_of("1.30.7+dfsg-1"), "1.30.7")


class ShippedTableTests(unittest.TestCase):
    def setUp(self):
        with open(SHIPPED, encoding="utf-8") as f:
            self.doc = json.load(f)

    def test_shape(self):
        self.assertEqual(adv.validate(self.doc), [])
        self.assertEqual(self.doc["updated"], "2026-11-19")
        self.assertEqual(set(self.doc), {"updated", "rows"})

    def test_rows_of_the_plan_table(self):
        rows = {r["id"]: r for r in self.doc["rows"]}
        self.assertEqual(rows["nginx-ubuntu-noble"]["fixed_in"], "1.24.0-2ubuntu7.20")
        self.assertEqual(rows["nginx-ubuntu-resolute"]["fixed_in"], "1.28.3-2ubuntu1.13")
        self.assertEqual(rows["nginx-org-stable"]["fixed_in"], "1.30.7")
        self.assertEqual(rows["nginx-org-mainline"]["fixed_in"], "1.31.9")
        self.assertEqual(rows["kernel-sctp-noble-6.8"]["fixed_in"], "6.8.0-147.147")
        self.assertEqual(rows["kernel-sctp-noble-7.0"]["fixed_in"], "7.0.0-38.38~24.04.4")
        self.assertEqual(rows["kernel-sctp-resolute"]["fixed_in"], "7.0.0-38.38")
        self.assertIsNone(rows["kernel-sctp-xint"]["fixed_in"])
        for cve in ("CVE-2026-123007", "CVE-2026-123633", "CVE-2026-123634", "CVE-2026-113425", "CVE-2026-118899"):
            self.assertIn(cve, rows["nginx-ubuntu-noble"]["cves"])
            self.assertIn(cve, rows["nginx-org-stable"]["cves"])
        self.assertIn("CVE-2026-121810", rows["nginx-ubuntu-resolute"]["cves"])
        self.assertNotIn("CVE-2026-121810", rows["nginx-ubuntu-noble"]["cves"])
        self.assertEqual(len(rows), 8)

    def test_validator_catches_each_kind_of_mistake(self):
        def bad(mutate):
            d = copy.deepcopy(self.doc)
            mutate(d)
            return adv.validate(d)
        self.assertTrue(bad(lambda d: d["rows"][0].pop("ref")))                          # missing key
        self.assertTrue(bad(lambda d: d["rows"][0].update(cves="CVE-1")))                # wrong type
        self.assertTrue(bad(lambda d: d["rows"][0].update(compare="semver")))            # compare outside the three
        self.assertTrue(bad(lambda d: d["rows"][0].update(fixed_in=5)))
        self.assertTrue(bad(lambda d: d["rows"][0].update(extra=1)))
        self.assertTrue(bad(lambda d: d["rows"][1].update(id=d["rows"][0]["id"])))       # duplicate id
        self.assertTrue(bad(lambda d: d.update(updated="19 Nov 2026")))
        self.assertTrue(bad(lambda d: d.update(rows={})))
        self.assertTrue(bad(lambda d: d["rows"][0].update(ref="http://x")))
        self.assertEqual(adv.validate([]), ["top level is not an object"])


class LoadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="edr-adv-")
        self.paths = hub_common.Paths(state_dir=self.tmp, lib_dir=os.path.join(HERE, "..", "hub"))
        os.makedirs(self.paths.advisories_d)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def put(self, name, doc):
        with open(os.path.join(self.paths.advisories_d, name), "w") as f:
            f.write(doc if isinstance(doc, str) else json.dumps(doc))

    def row(self, rid, fixed="9.9", **kw):
        r = {"id": rid, "origin": "ubuntu", "release": "noble", "packages": ["nginx"], "compare": "dpkg", "fixed_in": fixed,
             "cves": [], "needs_feature": None, "ref": "https://example.com/x"}
        r.update(kw)
        return r

    def test_shipped_file_is_found_from_the_checkout(self):
        table = adv.load(self.paths)
        self.assertEqual(table.problems, [])
        self.assertEqual(len(table.rows), 8)
        self.assertEqual(table.updated, "2026-11-19")

    def test_override_replaces_same_id_and_adds_others(self):
        self.put("local.json", {"rows": [self.row("nginx-ubuntu-noble", fixed="1.24.0-2ubuntu7.99"), self.row("mine")]})
        table = adv.load(self.paths)
        by = {r["id"]: r for r in table.rows}
        self.assertEqual(by["nginx-ubuntu-noble"]["fixed_in"], "1.24.0-2ubuntu7.99")
        self.assertIn("mine", by)
        self.assertEqual(len(table.rows), 9)
        self.assertEqual(table.updated, "2026-11-19")                  # an override never changes the date

    def test_override_with_a_date_does_not_refresh_staleness(self):
        self.put("fresh.json", {"updated": "2030-01-01", "rows": []})
        self.assertEqual(adv.load(self.paths).updated, "2026-11-19")

    def test_bad_overrides_are_skipped_and_named(self):
        self.put("a.json", "{not json")
        self.put("b.json", {"rows": [{"id": "x"}]})
        self.put("c.json", {"rows": [self.row("ok-row")]})
        table = adv.load(self.paths)
        self.assertEqual(len(table.problems), 2)
        self.assertTrue(any(p.startswith("a.json skipped") for p in table.problems))
        self.assertIn("ok-row", [r["id"] for r in table.rows])
        self.assertEqual(len(table.rows), 9)

    def test_missing_shipped_table_is_empty_and_stale(self):
        paths = hub_common.Paths(state_dir=self.tmp, lib_dir=os.path.join(self.tmp, "nowhere"))
        table = adv.load(paths)
        self.assertEqual(table.rows, [])
        self.assertEqual(table.staleness(at("2026-11-20")), "stale")
        self.assertTrue(table.problems)

    def test_staleness_rules(self):
        table = adv.Advisories([], "2026-11-19")
        self.assertEqual(table.staleness(at("2026-11-19") + 90 * DAY), "ok")
        self.assertEqual(table.staleness(at("2026-11-19") + 91 * DAY), "old")
        self.assertEqual(table.staleness(at("2026-11-19") + 180 * DAY), "old")
        self.assertEqual(table.staleness(at("2026-11-19") + 181 * DAY), "stale")
        self.assertAlmostEqual(table.age_days(at("2026-11-20")), 1.0, places=2)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.table = adv.load(hub_common.Paths(state_dir="/nonexistent-edr-test", lib_dir=os.path.join(HERE, "..", "hub")))
        self.now = at("2026-11-23")

    def verdict(self, origin, release, package, version, now=None):
        return adv.evaluate_package(self.table, origin=origin, release=release, package=package, version=version, now_ms=now or self.now)

    def statuses(self, *a, **kw):
        return {v["status"] for v in self.verdict(*a, **kw)}

    def test_ubuntu_noble_boundaries(self):
        self.assertEqual(self.statuses("ubuntu", "noble", "nginx", "1.24.0-2ubuntu7.19"), {"vulnerable"})
        self.assertEqual(self.statuses("Ubuntu", "noble", "nginx-core", "1.24.0-2ubuntu7.20"), {"fixed"})
        self.assertEqual(self.statuses("ubuntu", "noble", "nginx", "1.24.0-2ubuntu7.21"), {"fixed"})
        self.assertEqual(self.statuses("ubuntu", "noble", "nginx", "1.24.0-2ubuntu7.9"), {"vulnerable"})

    def test_ubuntu_version_never_matches_the_nginx_org_row(self):
        for v in self.verdict("ubuntu", "noble", "nginx", "1.24.0-2ubuntu7.20"):
            self.assertEqual(v["row"], "nginx-ubuntu-noble")
        # sorting below 1.30.7 does not make the Ubuntu package vulnerable: only its own table row decides
        self.assertEqual(self.statuses("ubuntu", "noble", "nginx", "1.24.0-2ubuntu7.20"), {"fixed"})
        # the other way round: a nginx.org version is judged only by the nginx.org rows
        rows = {v["row"] for v in self.verdict("nginx.org", "noble", "nginx", "1.30.6-1~noble")}
        self.assertTrue(rows <= {"nginx-org-stable", "nginx-org-mainline"})

    def test_nginx_org_upstream_compare(self):
        self.assertEqual(self.statuses("nginx.org", "noble", "nginx", "1.30.7-1~noble"), {"fixed"})
        self.assertEqual(self.statuses("nginx.org", "noble", "nginx", "1.30.6-1~noble"), {"vulnerable"})
        self.assertEqual(self.statuses("nginx.org", "resolute", "nginx", "1.30.8-1~resolute"), {"fixed"})
        self.assertEqual(self.statuses("nginx.org", "noble", "nginx", "1.29.5-1~noble"), {"vulnerable"})
        self.assertEqual(self.statuses("nginx.org", "noble", "nginx", "1.31.8-1~noble"), {"vulnerable"})
        self.assertEqual(self.statuses("nginx.org", "noble", "nginx", "1.31.9-1~noble"), {"fixed"})
        self.assertEqual(self.statuses("nginx.org", "noble", "nginx", "1.31.0-1~noble"), {"vulnerable"})
        self.assertEqual(self.statuses("nginx.org", "noble", "nginx", "1.32.0-1~noble"), {"fixed"})

    def test_resolute_row_and_cross_release(self):
        self.assertEqual(self.statuses("ubuntu", "resolute", "nginx", "1.28.3-2ubuntu1.12"), {"vulnerable"})
        self.assertEqual(self.statuses("ubuntu", "resolute", "nginx", "1.28.3-2ubuntu1.13"), {"fixed"})
        # a noble version string against the resolute row is not judged at all
        self.assertEqual(self.statuses("ubuntu", "plucky", "nginx", "1.24.0-2ubuntu7.1"), {"unknown"})

    def test_unknown_origin_or_release_is_never_vulnerable(self):
        for origin in ("ppa", "Ondrej", "debian", "", None, "other"):
            vs = self.verdict(origin, "noble", "nginx", "0.1")
            self.assertEqual({v["status"] for v in vs}, {"unknown"})
            self.assertIn("check by hand", vs[0]["detail"])
        self.assertEqual(self.statuses("ubuntu", None, "nginx", "0.1"), {"unknown"})
        self.assertEqual(self.statuses("ubuntu", "noble", "apache2", "0.1"), {"unknown"})

    def test_stale_table_never_says_fixed(self):
        late = at("2026-11-19") + 181 * DAY
        self.assertEqual(self.statuses("ubuntu", "noble", "nginx", "1.24.0-2ubuntu7.20", now=late), {"unknown"})
        self.assertEqual(self.statuses("ubuntu", "noble", "nginx", "1.24.0-2ubuntu7.1", now=late), {"vulnerable"})
        self.assertEqual(self.statuses("ubuntu", "noble", "nginx", "1.24.0-2ubuntu7.20", now=at("2026-11-19") + 100 * DAY), {"fixed"})

    def test_garbage_versions_are_unknown(self):
        self.assertEqual(self.statuses("ubuntu", "noble", "nginx", "not a version:"), {"unknown"})


class KernelTests(unittest.TestCase):
    def setUp(self):
        self.table = adv.load(hub_common.Paths(state_dir="/nonexistent-edr-test", lib_dir=os.path.join(HERE, "..", "hub")))
        self.now = at("2026-11-23")

    def ev(self, release, running, sctp=True, now=None):
        return {v["row"]: v["status"] for v in adv.evaluate_kernel(self.table, release=release, running=running, sctp=sctp, now_ms=now or self.now)}

    def test_version_signature_parsing(self):
        self.assertEqual(adv.kernel_version("Ubuntu 7.0.0-43.43-generic 7.0.14"), "7.0.0-43.43")
        self.assertEqual(adv.kernel_version("Ubuntu 7.0.0-37.37~24.04.1-generic 7.0.12"), "7.0.0-37.37~24.04.1")
        self.assertEqual(adv.kernel_version("Ubuntu 6.8.0-147.147-aws 6.8.12"), "6.8.0-147.147")
        self.assertEqual(adv.kernel_version("Ubuntu 6.8.0-147.147-gcp-64k 6.8.12"), "6.8.0-147.147")
        self.assertEqual(adv.kernel_version("6.8.0-147.147"), "6.8.0-147.147")
        self.assertIsNone(adv.kernel_version("6.8.0-147-generic"))              # uname -r lacks the upload number
        self.assertIsNone(adv.kernel_version(None))
        self.assertIsNone(adv.kernel_version("garbage here"))

    def test_series(self):
        self.assertEqual(adv.kernel_series("noble", "6.8.0-100.100"), "noble-6.8")
        self.assertEqual(adv.kernel_series("noble", "7.0.0-37.37~24.04.1"), "noble-7.0")
        self.assertEqual(adv.kernel_series("resolute", "7.0.0-43.43"), "resolute")
        self.assertIsNone(adv.kernel_series("jammy", "5.15.0-1.1"))

    def test_noble_ga(self):
        r = self.ev("noble", "Ubuntu 6.8.0-146.146-generic 6.8.12")
        self.assertEqual(r["kernel-sctp-noble-6.8"], "vulnerable")
        self.assertNotIn("kernel-sctp-noble-7.0", r)
        self.assertEqual(self.ev("noble", "Ubuntu 6.8.0-147.147-generic 6.8.12")["kernel-sctp-noble-6.8"], "fixed")

    def test_noble_hwe_and_resolute(self):
        self.assertEqual(self.ev("noble", "Ubuntu 7.0.0-37.37~24.04.1-generic 7.0.12")["kernel-sctp-noble-7.0"], "vulnerable")
        self.assertEqual(self.ev("noble", "Ubuntu 7.0.0-38.38~24.04.4-generic 7.0.14")["kernel-sctp-noble-7.0"], "fixed")
        self.assertEqual(self.ev("resolute", "Ubuntu 7.0.0-37.37-generic 7.0.12")["kernel-sctp-resolute"], "vulnerable")
        self.assertEqual(self.ev("resolute", "Ubuntu 7.0.0-38.38-generic 7.0.14")["kernel-sctp-resolute"], "fixed")

    def test_xint_row_has_no_fix(self):
        self.assertEqual(self.ev("resolute", "Ubuntu 7.0.0-43.43-generic 7.0.14")["kernel-sctp-xint"], "no_fix")

    def test_blocked_sctp_is_not_exposed_and_unknown_stays_unknown(self):
        r = self.ev("noble", "Ubuntu 6.8.0-100.100-generic 6.8.1", sctp=False)
        self.assertEqual(set(r.values()), {"not_exposed"})
        r = self.ev("noble", "Ubuntu 6.8.0-100.100-generic 6.8.1", sctp=None)
        self.assertEqual(r["kernel-sctp-noble-6.8"], "unknown")

    def test_incomplete_version_is_unknown(self):
        r = {v["row"]: v["status"] for v in adv.evaluate_kernel(self.table, release="noble", running="6.8.0-100-generic", sctp=True)}
        self.assertEqual(r["kernel-sctp-noble-6.8"], "unknown")
        self.assertEqual(r["kernel-sctp-noble-7.0"], "unknown")
        self.assertEqual(r["kernel-sctp-xint"], "no_fix")
        self.assertNotIn("kernel-sctp-resolute", r)
        inv = {"os_release": "noble", "checks": {"kernel_pending": {"status": True, "version": "6.8.0-100-generic"},
                                                 "sctp": {"status": True, "loaded": True}}}
        ids = [f["id"] for f in adv.evaluate_inventory(self.table, inv, self.now)]
        self.assertEqual(ids.count("kernel-unknown"), 1)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.table = adv.load(hub_common.Paths(state_dir="/nonexistent-edr-test", lib_dir=os.path.join(HERE, "..", "hub")))
        self.now = at("2026-11-23")

    def inv(self, version="1.24.0-2ubuntu7.19", origin="Ubuntu", exposure=None, release="noble", **extra):
        body = {"os_release": {"VERSION_CODENAME": release}, "checks": {
            "nginx_pkg": {"status": True, "packages": [{"name": "nginx", "version": version, "origin": origin}]},
            "nginx_exposure": dict({"status": True, "http2": False, "h2c": False, "http3": False, "mail_proxy": False,
                                    "resolver_bug": False, "tls_listener": True}, **(exposure or {}))}}
        body["checks"].update(extra)
        return body

    def ev(self, inv, first=None):
        return adv.evaluate_inventory(self.table, inv, self.now, first)

    def test_exposure_decides_the_severity(self):
        self.assertEqual(self.ev(self.inv(exposure={"http2": True}))[0]["severity"], "HIGH")
        self.assertEqual(self.ev(self.inv(exposure={"http3": True}))[0]["severity"], "HIGH")
        self.assertEqual(self.ev(self.inv(exposure={"mail_proxy": True}))[0]["severity"], "HIGH")
        self.assertEqual(self.ev(self.inv(exposure={"resolver_bug": True}))[0]["severity"], "MEDIUM")
        self.assertEqual(self.ev(self.inv(exposure={"resolver_bug": True, "mirror_request_body_off": True}))[0]["severity"], "HIGH")

    def test_tls_alone_is_high_after_24_hours(self):
        first = {"nginx-ubuntu-noble": self.now - 3600 * 1000}
        self.assertEqual(self.ev(self.inv(), first)[0]["severity"], "MEDIUM")
        first = {"nginx-ubuntu-noble": self.now - 25 * 3600 * 1000}
        self.assertEqual(self.ev(self.inv(), first)[0]["severity"], "HIGH")

    def test_nothing_exposed_is_a_digest_line(self):
        f = self.ev(self.inv(exposure={"tls_listener": False}))[0]
        self.assertEqual((f["severity"], f["status"]), ("MEDIUM", "vulnerable"))

    def test_unknown_exposure_is_treated_like_a_tls_listener(self):
        inv = self.inv()
        inv["checks"]["nginx_exposure"] = {"status": "unknown"}
        self.assertEqual(self.ev(inv, {"nginx-ubuntu-noble": self.now - 25 * 3600 * 1000})[0]["severity"], "HIGH")
        self.assertEqual(self.ev(inv)[0]["severity"], "MEDIUM")

    def test_fixed_package_gives_no_finding(self):
        self.assertEqual(self.ev(self.inv(version="1.24.0-2ubuntu7.20")), [])

    def test_unknown_origin_is_a_low_unknown_never_vulnerable(self):
        f = self.ev(self.inv(origin="PPA"))
        self.assertEqual([(x["status"], x["severity"]) for x in f], [("unknown", "LOW")])
        self.assertIn("check by hand", f[0]["summary"])

    def test_nginx_org_package(self):
        f = self.ev(self.inv(version="1.30.6-1~noble", origin="nginx.org", exposure={"http2": True}))
        self.assertEqual([(x["id"], x["severity"]) for x in f], [("nginx-org-stable", "HIGH")])
        self.assertEqual(self.ev(self.inv(version="1.30.7-1~noble", origin="nginx.org")), [])

    def test_inventory_unknown_package_status(self):
        inv = self.inv()
        inv["checks"]["nginx_pkg"] = {"status": "unknown"}
        f = self.ev(inv)
        self.assertEqual(f[0]["id"], "nginx-unknown")
        inv["checks"]["nginx_pkg"] = {"status": False}
        self.assertEqual(self.ev(inv), [])

    def test_kernel_through_the_inventory(self):
        inv = self.inv(version="1.24.0-2ubuntu7.20",
                       kernel_pending={"status": True, "signature": "Ubuntu 6.8.0-100.100-generic 6.8.12"},
                       sctp={"status": True, "loaded": False, "blocked": False, "builtin": False})
        ids = {f["id"]: f for f in self.ev(inv)}
        self.assertEqual(ids["kernel-sctp-noble-6.8"]["severity"], "MEDIUM")
        self.assertEqual(ids["kernel-sctp-xint"]["status"], "no_fix")
        inv["checks"]["sctp"]["blocked"] = True
        self.assertEqual(self.ev(inv), [])

    def test_garbage_inventory_never_raises(self):
        for odd in ({}, {"checks": []}, {"checks": {"nginx_pkg": "x"}}, {"checks": {"nginx_pkg": {"status": True, "packages": [5, {"name": 3}]}}},
                    {"checks": {"nginx_pkg": {"status": True, "version": 5}}}, {"os_release": 7}):
            self.assertIsInstance(adv.evaluate_inventory(self.table, odd, self.now), list)

    def test_release_codename(self):
        self.assertEqual(adv.release_codename({"VERSION_CODENAME": "Noble"}), "noble")
        self.assertEqual(adv.release_codename({"VERSION_ID": "26.04"}), "resolute")
        self.assertEqual(adv.release_codename("Ubuntu 24.04.3 LTS"), "noble")
        self.assertEqual(adv.release_codename("resolute"), "resolute")
        self.assertIsNone(adv.release_codename("Debian 13"))
        self.assertIsNone(adv.release_codename(None))


if __name__ == "__main__":
    unittest.main()
