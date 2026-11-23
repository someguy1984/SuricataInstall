"""Advisory data for the inventory rules (PLAN.md section 4, Advisory data).

The table is common/advisories.json; files in advisories.d/ replace rows with the same id or
add rows. This module loads it, compares versions the way dpkg does (pure Python) and judges
what a heartbeat's inventory says about nginx and the running kernel.

Standard library only. Nothing here opens the database.
"""

import glob
import json
import os
import re
import stat
from datetime import datetime, timezone

ROW_KEYS = ("id", "origin", "release", "packages", "compare", "fixed_in", "cves", "needs_feature", "ref")
COMPARE_VALUES = ("dpkg", "upstream", "kernel")
STALE_WARN_DAYS = 90
STALE_UNKNOWN_DAYS = 180
FILE_MAX_BYTES = 1024 * 1024

RELEASE_CODENAMES = {"24.04": "noble", "26.04": "resolute"}


# ---- Debian version comparison ---------------------------------------------------------------
def _order(ch):
    """dpkg's order(): '~' sorts before everything, even the end; letters before other signs."""
    if ch == "":
        return 0
    if ch.isdigit():
        return 0
    if ch == "~":
        return -1
    if ch.isalpha() and ch.isascii():
        return ord(ch)
    return ord(ch) + 256


def _digit(ch):
    return ch != "" and ch in "0123456789"


def _verrevcmp(a, b):
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and not _digit(a[i])) or (j < lb and not _digit(b[j])):
            ac = _order(a[i] if i < la else "")
            bc = _order(b[j] if j < lb else "")
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and j < lb and _digit(a[i]) and _digit(b[j]):
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and _digit(a[i]):
            return 1
        if j < lb and _digit(b[j]):
            return -1
        if first_diff:
            return first_diff
    return 0


_VERSION_RE = re.compile(r"^(?:[0-9]+:)?[0-9][A-Za-z0-9.+~:-]*\Z")
VERSION_MAX = 200


def parse_version(text):
    """(epoch, upstream, revision) of a Debian version string. Raises ValueError unless it is a version: an optional
    epoch, then a digit, then only the characters Debian allows (so "none", "unknown" and NUL are not versions)."""
    if not isinstance(text, str) or not text.strip() or len(text) > VERSION_MAX or not _VERSION_RE.match(text.strip()):
        raise ValueError("not a version")
    v = text.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        if not e.isdigit():
            raise ValueError("bad epoch")
        epoch = int(e)
    revision = ""
    if "-" in v:
        v, revision = v.rsplit("-", 1)
    if not v:
        raise ValueError("empty upstream version")
    return epoch, v, revision


def dpkg_compare(a, b):
    """-1, 0 or 1 like `dpkg --compare-versions`. Raises ValueError on a malformed version."""
    ea, ua, ra = parse_version(a)
    eb, ub, rb = parse_version(b)
    if ea != eb:
        return -1 if ea < eb else 1
    for x, y in ((ua, ub), (ra, rb)):
        r = _verrevcmp(x, y)
        if r:
            return -1 if r < 0 else 1
    return 0


def upstream_of(version):
    """The upstream part of a package version: epoch, revision and any +suffix cut off ('1.30.7-1~noble' -> '1.30.7')."""
    _epoch, up, _rev = parse_version(version)
    return re.split(r"[+~]", up, maxsplit=1)[0]


# ---- The table -------------------------------------------------------------------------------
def validate(doc):
    """A list of problems with an advisory document; an empty list means it matches the shape."""
    problems = []
    if not isinstance(doc, dict):
        return ["top level is not an object"]
    updated = doc.get("updated")
    if not isinstance(updated, str) or not re.match(r"^\d{4}-\d\d-\d\d\Z", updated):
        problems.append("updated must be YYYY-MM-DD")
    else:
        try:
            datetime.strptime(updated, "%Y-%m-%d")
        except ValueError:
            problems.append("updated is not a date")
    for key in doc:
        if key not in ("updated", "rows"):
            problems.append("unknown top-level key %r" % key)
    rows = doc.get("rows")
    if not isinstance(rows, list):
        return problems + ["rows must be a list"]
    seen = set()
    for n, row in enumerate(rows):
        where = "row %d" % n
        if not isinstance(row, dict):
            problems.append(where + " is not an object")
            continue
        for key in ROW_KEYS:
            if key not in row:
                problems.append("%s: missing key %s" % (where, key))
        for key in row:
            if key not in ROW_KEYS:
                problems.append("%s: unknown key %s" % (where, key))
        rid = row.get("id")
        if not isinstance(rid, str) or not rid:
            problems.append(where + ": id must be a non-empty string")
        elif rid in seen:
            problems.append("%s: duplicate id %s" % (where, rid))
        else:
            seen.add(rid)
        for key in ("origin", "release", "ref"):
            if key in row and (not isinstance(row[key], str) or not row[key]):
                problems.append("%s: %s must be a non-empty string" % (where, key))
        if "ref" in row and isinstance(row["ref"], str) and not row["ref"].startswith("https://"):
            problems.append(where + ": ref must be an https URL")
        for key in ("packages", "cves"):
            if key in row and (not isinstance(row[key], list) or not all(isinstance(x, str) for x in row[key])):
                problems.append("%s: %s must be a list of strings" % (where, key))
        if row.get("compare") not in COMPARE_VALUES:
            problems.append("%s: compare must be one of %s" % (where, ", ".join(COMPARE_VALUES)))
        for key in ("fixed_in", "needs_feature"):
            if key in row and row[key] is not None and not isinstance(row[key], str):
                problems.append("%s: %s must be a string or null" % (where, key))
        if row.get("compare") != "kernel" and isinstance(row.get("packages"), list) and not row["packages"]:
            problems.append(where + ": a package row needs packages")
    return problems


class Advisories:
    """The merged table. `updated` is the shipped file's date: overrides never change it."""

    def __init__(self, rows, updated, problems=None):
        self.rows = list(rows)
        self.updated = updated
        self.problems = list(problems or [])

    def age_days(self, now_ms):
        try:
            when = datetime.strptime(self.updated, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return None
        return (now_ms / 1000.0 - when.timestamp()) / 86400.0

    def staleness(self, now_ms):
        """'ok', 'old' (over 90 days) or 'stale' (over 180 days: nothing is reported as fixed)."""
        age = self.age_days(now_ms)
        if age is None or age > STALE_UNKNOWN_DAYS:
            return "stale"
        return "old" if age > STALE_WARN_DAYS else "ok"


def _read_json(path):
    """Read a JSON file that is not a link, a FIFO or a device, and is at most 1 MiB. Raises OSError or ValueError."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("not a regular file")
        if st.st_size > FILE_MAX_BYTES:
            raise ValueError("file over 1 MiB")
        chunks, total = [], 0
        while True:
            b = os.read(fd, 1 << 16)
            if not b:
                break
            total += len(b)
            if total > FILE_MAX_BYTES:
                raise ValueError("file over 1 MiB")
            chunks.append(b)
    finally:
        os.close(fd)
    return json.loads(b"".join(chunks).decode("utf-8"))


def load(paths):
    """Load the shipped table and the advisories.d overrides. A bad override file is skipped and
    named in `problems`; a missing or broken shipped file gives an empty, stale table."""
    problems = []
    shipped = paths.find_data("advisories.json")
    try:
        doc = _read_json(shipped)
        bad = validate(doc)
        if bad:
            raise ValueError("; ".join(bad[:3]))
        rows, updated = list(doc["rows"]), doc["updated"]
    except (OSError, ValueError) as exc:
        problems.append("shipped table unusable: %s" % exc)
        rows, updated = [], "1970-01-01"
    by_id = {r["id"]: i for i, r in enumerate(rows)}
    for path in sorted(glob.glob(os.path.join(paths.advisories_d, "*.json"))):
        name = os.path.basename(path)
        try:
            doc = _read_json(path)
            if isinstance(doc, dict) and "updated" not in doc:
                doc = dict(doc, updated="1970-01-01")      # an override need not carry a date
            bad = validate(doc)
            if bad:
                raise ValueError("; ".join(bad[:3]))
        except (OSError, ValueError) as exc:
            problems.append("%s skipped: %s" % (name, exc))
            continue
        for row in doc["rows"]:
            if row["id"] in by_id:
                rows[by_id[row["id"]]] = row
            else:
                by_id[row["id"]] = len(rows)
                rows.append(row)
    return Advisories(rows, updated, problems)


# ---- Judging what the inventory says ---------------------------------------------------------
def normalize_origin(text):
    t = str(text or "").strip().lower()
    if t == "ubuntu":
        return "ubuntu"
    if t in ("nginx.org", "nginx", "upstream", "nginx.org stable", "nginx.org mainline"):
        return "nginx.org"
    return "other"


def release_codename(os_release):
    """'noble' or 'resolute' from an os-release value (a dict, or a string such as 'Ubuntu 24.04'); None if unknown."""
    if isinstance(os_release, dict):
        for key in ("VERSION_CODENAME", "version_codename", "codename"):
            v = os_release.get(key)
            if isinstance(v, str) and v:
                return v.strip().lower()
        for key in ("VERSION_ID", "version_id", "version"):
            v = os_release.get(key)
            if isinstance(v, str) and v.strip() in RELEASE_CODENAMES:
                return RELEASE_CODENAMES[v.strip()]
        return None
    if isinstance(os_release, str):
        low = os_release.lower()
        for name in RELEASE_CODENAMES.values():
            if name in low:
                return name
        for ver, name in RELEASE_CODENAMES.items():
            if ver in low:
                return name
    return None


def _verdict(row, status, detail, **extra):
    d = {"row": row["id"] if row else None, "status": status, "detail": detail,
         "fixed_in": row["fixed_in"] if row else None, "cves": list(row["cves"]) if row else [],
         "ref": row["ref"] if row else "", "needs_feature": row["needs_feature"] if row else None}
    d.update(extra)
    return d


def _below_fix(row, version):
    """True when `version` is vulnerable under the row's compare mode."""
    fixed = row["fixed_in"]
    if row["compare"] == "dpkg" or row["compare"] == "kernel":
        return dpkg_compare(version, fixed) < 0
    # upstream: the version without epoch, revision and suffix against the first fixed version.
    # nginx numbers its mainline line with an odd minor: a mainline fix covers only X.Y.0 up to
    # itself, a stable fix (even minor) covers everything below it.
    have, fix = upstream_of(version), upstream_of(fixed)
    if dpkg_compare(have, fix) >= 0:
        return False
    parts = fix.split(".")
    if len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) % 2 == 1:
        low = "%s.%s.0" % (parts[0], parts[1])
        return dpkg_compare(have, low) >= 0
    return True


def evaluate_package(adv, *, origin, release, package, version, now_ms=None):
    """Verdicts for one installed package: one per applicable row, or a single 'unknown'.

    status is 'vulnerable', 'fixed' or 'unknown'. Only rows of the same origin and release (or
    release 'any') decide; any other origin or release is 'unknown: check by hand', never
    'vulnerable'. A table over 180 days old never says 'fixed'.
    """
    origin = normalize_origin(origin)
    stale = now_ms is not None and adv.staleness(now_ms) == "stale"
    rows = [r for r in adv.rows
            if r["compare"] != "kernel" and r["origin"] == origin and r["release"] in (release, "any")
            and package in r["packages"]]
    if not rows:
        return [_verdict(None, "unknown", "unknown origin or release: check by hand")]
    out = []
    for row in rows:
        if row["fixed_in"] is None:
            out.append(_verdict(row, "unknown", "no fix known"))
            continue
        try:
            below = _below_fix(row, version)
        except ValueError:
            out.append(_verdict(row, "unknown", "version not understood"))
            continue
        if below:
            out.append(_verdict(row, "vulnerable", "%s is older than %s" % (version, row["fixed_in"])))
        elif stale:
            out.append(_verdict(row, "unknown", "table too old to say fixed"))
        else:
            out.append(_verdict(row, "fixed", "%s is at or past %s" % (version, row["fixed_in"])))
    # A package inside the window of one row and fixed by a sibling row (stable and mainline
    # rows of nginx.org) is vulnerable only when it is below its own branch's fix: drop 'fixed'
    # verdicts of rows that do not apply to this version's branch.
    if len(out) > 1 and any(v["status"] == "vulnerable" for v in out):
        out = [v for v in out if v["status"] == "vulnerable"]
    elif len(out) > 1 and all(v["status"] == "fixed" for v in out):
        out = out[:1]
    return out


def kernel_version(text):
    """The package version of the running kernel from a /proc/version_signature line
    ('Ubuntu 7.0.0-43.43-generic 7.0.14' -> '7.0.0-43.43'), or None when it is not a full version."""
    if not isinstance(text, str):
        return None
    tok = text.split()
    if tok and tok[0] == "Ubuntu" and len(tok) >= 2:
        tok = [tok[1]]
    if len(tok) != 1:
        return None
    ver = re.sub(r"-[a-z][a-z0-9]*(-[a-z0-9]+)*$", "", tok[0])      # strip the flavour: -generic, -aws, -gcp-64k
    if re.match(r"^\d+\.\d+\.\d+-\d+\.\d+(~[0-9A-Za-z.]+)?\Z", ver):
        return ver
    return None


def kernel_series(release, version):
    """The row release for a kernel: 'noble-6.8', 'noble-7.0' or 'resolute'; None if unknown."""
    if release == "resolute":
        return "resolute"
    if release == "noble":
        m = re.match(r"^(\d+)\.(\d+)\.", version or "")
        return "noble-%s.%s" % (m.group(1), m.group(2)) if m else None
    return None


def evaluate_kernel(adv, *, release, running, sctp, now_ms=None):
    """Verdicts for the running kernel against the kernel rows.

    `running` is a /proc/version_signature line or a package version, `sctp` is True when the
    module is loadable (loaded, built in or not blocked), False when blocked, None when unknown.
    """
    version = kernel_version(running)
    stale = now_ms is not None and adv.staleness(now_ms) == "stale"
    series = kernel_series(release, version) if version else None
    out = []
    for row in adv.rows:
        if row["compare"] != "kernel":
            continue
        feature = row["needs_feature"]
        if feature == "sctp" and sctp is False:
            out.append(_verdict(row, "not_exposed", "sctp is blocked"))
            continue
        if row["fixed_in"] is None:
            out.append(_verdict(row, "unknown", "no fix known" + ("" if sctp else "; sctp state unknown")))
            if sctp:
                out[-1]["status"] = "no_fix"
            continue
        if row["release"] not in ("any", series):
            if not (version is None and str(row["release"]).split("-")[0] == release):
                continue
        if version is None or series is None:
            out.append(_verdict(row, "unknown", "running kernel version not known in full"))
            continue
        if sctp is None:
            out.append(_verdict(row, "unknown", "sctp state unknown"))
            continue
        try:
            below = dpkg_compare(version, row["fixed_in"]) < 0
        except ValueError:
            out.append(_verdict(row, "unknown", "version not understood"))
            continue
        if below:
            out.append(_verdict(row, "vulnerable", "running %s is older than %s; a reboot is needed after the update" % (version, row["fixed_in"])))
        elif stale:
            out.append(_verdict(row, "unknown", "table too old to say fixed"))
        else:
            out.append(_verdict(row, "fixed", "running %s is at or past %s" % (version, row["fixed_in"])))
    return out


# ---- Exposure --------------------------------------------------------------------------------
_EXPOSURE_ALIASES = {
    "http2": ("http2", "h2"),
    "h2c": ("h2c",),
    "http3": ("http3", "quic"),
    "mail": ("mail", "mail_proxy"),
    "resolver": ("resolver_bug", "resolver_subrequest", "resolver_exposed"),
    "mirror_off": ("mirror_request_body_off",),
    "tls": ("tls", "tls_listener", "ssl", "https"),
}


def exposure_flags(check):
    """Booleans (or None for unknown) for each exposed feature, from the inventory's nginx_exposure check."""
    flags = {name: None for name in _EXPOSURE_ALIASES}
    if not isinstance(check, dict) or check.get("status") == "unknown":
        return flags
    for name, aliases in _EXPOSURE_ALIASES.items():
        for key in aliases:
            if key in check and isinstance(check[key], bool):
                flags[name] = check[key]
                break
            if key in check and check[key] == "unknown":
                break
    return flags


def exposure_severity(flags, first_seen_ms, now_ms):
    """(severity, reason) of a vulnerable nginx package given what is exposed.

    HTTP/2, h2c, HTTP/3 or mail exposed: HIGH now. The resolver bug: HIGH when
    mirror_request_body is off, else MEDIUM. A TLS listener alone (or exposure unknown): HIGH
    after 24 hours, MEDIUM until then. Nothing exposed: MEDIUM (a digest line).
    """
    for name in ("http2", "h2c", "http3", "mail"):
        if flags.get(name):
            return "HIGH", "%s is exposed" % name
    if flags.get("resolver"):
        if flags.get("mirror_off"):
            return "HIGH", "the resolver bug is exposed with mirror_request_body off"
        return "MEDIUM", "the resolver bug is exposed without mirror_request_body off"
    tls_or_unknown = flags.get("tls") is not False
    if tls_or_unknown:
        held = now_ms - first_seen_ms if first_seen_ms is not None else 0
        if held >= 24 * 3600 * 1000:
            return "HIGH", "a TLS listener has been exposed for over 24 hours (CVE-2026-118899)"
        return "MEDIUM", "a TLS listener is exposed; HIGH after 24 hours (CVE-2026-118899)"
    return "MEDIUM", "none of the exposed features is on"


def _checks(inv):
    c = inv.get("checks") if isinstance(inv, dict) else None
    return c if isinstance(c, dict) else {}


def _packages(check):
    if not isinstance(check, dict) or check.get("status") in (False, None):
        return []
    pk = check.get("packages")
    if isinstance(pk, list):
        return [p for p in pk if isinstance(p, dict)]
    if "version" in check or "name" in check:
        return [check]
    return []


def evaluate_inventory(adv, inv, now_ms, first_seen=None):
    """What the advisory table says about one heartbeat inventory object.

    Returns a list of findings {"id", "status", "severity", "summary", "cves", "ref", "detail"}.
    `first_seen` maps a row id to the epoch ms when that row first said 'vulnerable' for this
    host (the caller keeps it). Findings with status 'fixed' are not returned.
    """
    first_seen = first_seen or {}
    findings = []
    checks = _checks(inv)
    release = release_codename(inv.get("os_release") if isinstance(inv, dict) else None)
    flags = exposure_flags(checks.get("nginx_exposure"))

    nginx_chk = checks.get("nginx_pkg")
    if isinstance(nginx_chk, dict) and nginx_chk.get("status") == "unknown":
        findings.append({"id": "nginx-unknown", "status": "unknown", "severity": "LOW", "cves": [], "ref": "",
                         "summary": "nginx package status unknown: check by hand", "detail": "the inventory could not read the package"})
    for pkg in _packages(nginx_chk):
        name, version, origin = pkg.get("name") or "nginx", pkg.get("version"), pkg.get("origin")
        if not isinstance(version, str) or not isinstance(name, str):
            continue
        if not any(name in r["packages"] for r in adv.rows):
            continue
        verdicts = evaluate_package(adv, origin=origin, release=release, package=name, version=version, now_ms=now_ms)
        for v in verdicts:
            if v["status"] == "vulnerable":
                sev, why = exposure_severity(flags, first_seen.get(v["row"]), now_ms)
                findings.append({"id": v["row"], "status": "vulnerable", "severity": sev, "cves": v["cves"], "ref": v["ref"],
                                 "summary": "%s %s is below its fix %s; %s" % (name, version, v["fixed_in"], why), "detail": v["detail"]})
            elif v["status"] == "unknown":
                findings.append({"id": v["row"] or "nginx-origin", "status": "unknown", "severity": "LOW", "cves": v["cves"], "ref": v["ref"],
                                 "summary": "%s %s: %s" % (name, version, v["detail"]), "detail": v["detail"]})

    kernel_chk = checks.get("kernel_pending")
    sctp_chk = checks.get("sctp")
    running = None
    if isinstance(kernel_chk, dict):
        for key in ("signature", "version_signature", "running", "version"):
            if isinstance(kernel_chk.get(key), str):
                running = kernel_chk[key]
                break
    if running is not None:
        findings.extend(_kernel_findings(adv, release, running, sctp_chk, now_ms))
    return findings


def inventory_definite(inv):
    """Whether this inventory answered the nginx and the kernel questions for certain. An unknown or missing check is
    not an answer: a row that has no finding is 'fixed' only when its group is definite."""
    checks = _checks(inv)
    chk = checks.get("nginx_pkg")
    nginx = isinstance(chk, dict) and (chk.get("status") is False or (chk.get("status") is True and bool(_packages(chk))))
    running = None
    kc = checks.get("kernel_pending")
    if isinstance(kc, dict):
        for key in ("signature", "version_signature", "running", "version"):
            if isinstance(kc.get(key), str):
                running = kc[key]
                break
    kernel = running is not None and kernel_version(running) is not None and _sctp_loadable(checks.get("sctp")) is not None
    return {"nginx": bool(nginx), "kernel": bool(kernel)}


def _sctp_loadable(check):
    """True when sctp can load (loaded, built in, or not blocked); False when blocked; None when unknown."""
    if not isinstance(check, dict) or check.get("status") == "unknown":
        return None
    if check.get("loaded") or check.get("builtin") or check.get("built_in"):
        return True
    if "blocked" in check and isinstance(check["blocked"], bool):
        return not check["blocked"]
    if check.get("status") in (True, False):
        return bool(check["status"])
    return None


def _kernel_findings(adv, release, running, sctp_chk, now_ms):
    out = []
    for v in evaluate_kernel(adv, release=release, running=running, sctp=_sctp_loadable(sctp_chk), now_ms=now_ms):
        if v["status"] == "vulnerable":
            out.append({"id": v["row"], "status": "vulnerable", "severity": "MEDIUM", "cves": v["cves"], "ref": v["ref"],
                        "summary": "running kernel below its SCTP fix %s; sctp is loadable" % v["fixed_in"], "detail": v["detail"]})
        elif v["status"] == "no_fix":
            out.append({"id": v["row"], "status": "no_fix", "severity": "LOW", "cves": v["cves"], "ref": v["ref"],
                        "summary": "no fix known yet for the SCTP send-path bug; sctp is loadable; recheck weekly", "detail": v["detail"]})
        elif v["status"] == "unknown" and v["fixed_in"] is not None and not any(f["status"] == "unknown" for f in out):
            out.append({"id": "kernel-unknown", "status": "unknown", "severity": "LOW", "cves": v["cves"], "ref": v["ref"],
                        "summary": "kernel status unknown: %s" % v["detail"], "detail": v["detail"]})
    return out
