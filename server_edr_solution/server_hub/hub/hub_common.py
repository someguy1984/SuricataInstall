"""Shared constants and small helpers for every hub program (PLAN.md sections 2 to 6, 14, 17, Appendix A).

Standard library only, Python 3.12+. Imported by edr_hub.py, edr_hub_ui.py, edr_hub_out.py and the
edr-hub CLI. Nothing here opens a socket or the database.
"""

import ipaddress
import json
import os
import re
import socket
import tempfile
import time
import unicodedata
from datetime import datetime, timezone

VERSION = "0.1.0"

# ---- Protocol (Appendix A) -------------------------------------------------------------------
PROTO = 1                      # X-EDR-Proto this hub speaks; PROTO - 1 is also accepted
PROTO_MIN = 1                  # there is no protocol 0: "X-EDR-Proto: 0" is answered 426
EVENT_SCHEMA = 1               # current event "v"; EVENT_SCHEMA - 1 is also accepted (section 17)
MIN_CLIENT_SCHEMA = EVENT_SCHEMA - 1

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SOURCES = ("tetragon", "suricata", "nginx", "journal", "kernel", "inventory", "agent", "canary")
SRC_TRUST = ("tcp", "claimed", "none")
KIND_RE = re.compile(r"^[a-z0-9_.-]{1,64}\Z")
HOST_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61})\Z")
EVENT_ID_RE = re.compile(r"^[0-9a-f]{8}:[0-9]{1,20}\Z")
REV_RE = re.compile(r"^[0-9a-f]{16}\Z")

# Policy document vocabularies (Appendix A, Closed vocabularies)
BAN_SOURCES = ("fleet", "operator")
BAN_REASON_IDS = ("fleet_quorum", "operator")
FEED_NAMES = ("spamhaus_drop_v4", "spamhaus_drop_v6", "dshield")

# ---- Limits (section 2, Limits) --------------------------------------------------------------
HANDSHAKE_DEADLINE_S = 3
HEADER_DEADLINE_S = 5
HEADER_MAX_BYTES = 8 * 1024
HEADER_MAX_LINES = 32
REQUEST_DEADLINE_S = 15
REQUEST_DEADLINE_BIG_S = 30
ENROLL_DEADLINE_S = 5
SLOTS_FLEET = 64
SLOTS_ENROLL = 4
SLOTS_PER_SOURCE = 4           # per IPv4 address and per IPv6 /64
REQUESTS_PER_CERT = 4
BODY_MAX_COMPRESSED = 1024 * 1024
BODY_MAX_INFLATED = 3 * 1024 * 1024
EVENT_MAX_BYTES = 10 * 1024
BATCH_MAX_EVENTS = 500
PARSE_SLOTS = 4
WRITER_QUEUE = 256
LISTEN_BACKLOG = 128
CSR_MAX_BYTES = 4 * 1024
HUB_ADDRESSES_MAX = 4
PEERS_MAX = 512
POLICY_BANS_MAX = 10_000
POLICY_FEED_MAX = 200_000

# Field caps (section 5, Rendering rules)
SUMMARY_MAX = 256
DETAIL_STR_MAX = 512
DETAIL_ARGS_MAX = 1024
DETAIL_URL_MAX = 512
DETAILS_MAX_BYTES = 4 * 1024

# Sockets (section 5, How changes are made)
SOCK_LINE_MAX = 64 * 1024
SOCK_TIMEOUT_S = 5
SOCK_MAX_CONN = 8

# ---- Exit codes (section 17) -----------------------------------------------------------------
EXIT_OK = 0
EXIT_WARN = 1
EXIT_FAIL = 2
EXIT_REFUSED = 3
EXIT_ROLLED_BACK = 4
EXIT_USAGE = 64

# ---- Error codes: code -> (HTTP status, fixed text) (Appendix A, Error codes) -----------------
ERRORS = {
    "bad_request": (400, "malformed request"),
    "bad_schema": (400, "request does not match the schema"),
    "invalid_token": (401, "token refused"),
    "host_unknown": (403, "host not known"),
    "host_revoked": (403, "host revoked"),
    "host_moved": (403, "host moved"),
    "host_retired": (403, "host retired"),
    "cert_superseded": (403, "certificate superseded"),
    "host_orphan": (403, "host awaiting adoption"),
    "not_found": (404, "no such route"),
    "method_not_allowed": (405, "method not allowed"),
    "host_exists": (409, "host already enrolled"),
    "length_required": (411, "Content-Length required"),
    "too_large": (413, "request too large"),
    "schema_too_old": (422, "event schema too old"),
    "proto_unsupported": (426, "protocol version not supported"),
    "rate_limited": (429, "slow down"),
    "header_too_large": (431, "header block too large"),
    "busy": (503, "busy"),
    "storage_full": (503, "storage full"),
}


def error_body(code, index=None):
    """The JSON body of a 4xx or 5xx answer: fixed text only, never request text."""
    body = {"error": ERRORS[code][1], "code": code}
    if index is not None:
        body["index"] = int(index)
    return json.dumps(body).encode()


# ---- Paths -----------------------------------------------------------------------------------
class Paths:
    """Every file the hub uses. Defaults are the installed paths (section 8 step 2).

    For tests and for running from a checkout without root, set the environment variables
    EDR_HUB_STATE_DIR, EDR_HUB_RUN_DIR, EDR_HUB_ETC_DIR, EDR_HUB_BACKUP_DIR, EDR_HUB_OUT_STATE_DIR
    and EDR_HUB_LIB_DIR, or pass the directories to the constructor.
    """

    def __init__(self, state_dir=None, run_dir=None, etc_dir=None, backup_dir=None, out_state_dir=None, lib_dir=None):
        env = os.environ.get
        self.state_dir = state_dir or env("EDR_HUB_STATE_DIR") or "/var/lib/edr-hub"
        self.run_dir = run_dir or env("EDR_HUB_RUN_DIR") or "/run/edr-hub"
        self.etc_dir = etc_dir or env("EDR_HUB_ETC_DIR") or "/etc/edr-hub"
        self.backup_dir = backup_dir or env("EDR_HUB_BACKUP_DIR") or "/var/backups/edr-hub"
        self.out_state_dir = out_state_dir or env("EDR_HUB_OUT_STATE_DIR") or "/var/lib/edr-hub-out"
        # Where the code lives: the directory of this file, unless overridden
        self.lib_dir = lib_dir or env("EDR_HUB_LIB_DIR") or os.path.dirname(os.path.abspath(__file__))

    # state directory
    db = property(lambda s: os.path.join(s.state_dir, "hub.db"))
    settings = property(lambda s: os.path.join(s.state_dir, "settings.json"))
    ca_dir = property(lambda s: os.path.join(s.state_dir, "ca"))
    ca_cert = property(lambda s: os.path.join(s.state_dir, "ca", "ca.pem"))
    ca_key = property(lambda s: os.path.join(s.state_dir, "ca", "ca.key"))
    revoked = property(lambda s: os.path.join(s.state_dir, "ca", "revoked.txt"))
    tls_dir = property(lambda s: os.path.join(s.state_dir, "tls"))
    server_cert = property(lambda s: os.path.join(s.state_dir, "tls", "server.pem"))
    server_key = property(lambda s: os.path.join(s.state_dir, "tls", "server.key"))
    advisories_d = property(lambda s: os.path.join(s.state_dir, "advisories.d"))
    webhook_ca = property(lambda s: os.path.join(s.state_dir, "webhook-ca.pem"))
    last_backup = property(lambda s: os.path.join(s.state_dir, "last-backup"))
    pending_audit = property(lambda s: os.path.join(s.state_dir, "pending-audit.jsonl"))
    critical_overflow = property(lambda s: os.path.join(s.state_dir, "critical-overflow.jsonl"))
    # runtime directory
    ctl_sock = property(lambda s: os.path.join(s.run_dir, "ctl.sock"))
    ui_sock = property(lambda s: os.path.join(s.run_dir, "ui.sock"))
    out_sock = property(lambda s: os.path.join(s.run_dir, "out.sock"))
    # /etc/edr-hub (root only; the edr-hub user cannot read it)
    secrets = property(lambda s: os.path.join(s.etc_dir, "secrets.json"))
    backup_pass = property(lambda s: os.path.join(s.etc_dir, "backup.pass"))
    ui_url = property(lambda s: os.path.join(s.etc_dir, "ui-url"))
    nft_file = property(lambda s: os.path.join(s.etc_dir, "edr-hub.nft"))
    manifest = property(lambda s: os.path.join(s.etc_dir, "manifest.jsonl"))
    # outbound worker state
    channels = property(lambda s: os.path.join(s.out_state_dir, "channels.json"))
    # shipped data beside the code
    agent_hashes = property(lambda s: os.path.join(s.lib_dir, "agent-hashes.json"))
    ui_index = property(lambda s: os.path.join(s.lib_dir, "ui", "index.html"))
    pki_ext_dir = property(lambda s: os.path.join(s.lib_dir, "pki", "strict"))
    advisories = property(lambda s: os.path.join(s.lib_dir, "advisories.json"))

    def find_data(self, *relative):
        """A shipped data file: beside the code when installed, else in the checkout layout
        (server_hub/pki/strict, common/advisories.json). Returns the first path that exists."""
        here = self.lib_dir
        candidates = [os.path.join(here, *relative), os.path.join(here, "..", *relative),
                      os.path.join(here, "..", "..", "common", relative[-1])]
        for path in candidates:
            if os.path.exists(path):
                return os.path.normpath(path)
        return os.path.normpath(candidates[0])


# ---- Time ------------------------------------------------------------------------------------
def now_ms():
    return time.time_ns() // 1_000_000


_RFC3339 = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,6}))?Z\Z")


def rfc3339_to_ms(text):
    """'2026-11-19T03:00:00.000Z' -> epoch milliseconds. Raises ValueError on anything else."""
    if not isinstance(text, str) or len(text) > 40:
        raise ValueError("not an RFC 3339 UTC time")
    m = _RFC3339.match(text)
    if not m:
        raise ValueError("not an RFC 3339 UTC time")
    y, mo, d, h, mi, s, frac = m.groups()
    dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), tzinfo=timezone.utc)
    return int(dt.timestamp()) * 1000 + int((frac or "0").ljust(6, "0")[:3])


def ms_to_rfc3339(ms):
    dt = datetime.fromtimestamp(ms // 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".%03dZ" % (ms % 1000)


_DURATION = re.compile(r"^(\d+)([smhd])\Z")
_SIZE = re.compile(r"^(\d+)([KMG])?\Z")


def parse_duration(text):
    """'30s', '10m', '1h', '7d' -> seconds. Raises ValueError."""
    m = _DURATION.match(str(text).strip())
    if not m:
        raise ValueError("duration must look like 30s, 10m, 1h or 7d")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def parse_size(text):
    """'64M', '2G', '1048576' -> bytes. Raises ValueError."""
    m = _SIZE.match(str(text).strip().upper())
    if not m:
        raise ValueError("size must look like 64M or 2G")
    return int(m.group(1)) * {None: 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}[m.group(2)]


# ---- JSON ------------------------------------------------------------------------------------
def canonical_json(obj):
    """Keys sorted, no spaces, UTF-8 bytes: the form hashed for the policy rev and the audit chain."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def atomic_write(path, data, mode=0o640):
    """Write bytes or text to a temp file in the same directory, fsync, rename over the target."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---- Output safety (section 6) ---------------------------------------------------------------
_UNSAFE_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def clean(text, limit=200):
    """Make attacker-influenced text safe for a terminal or an alert.

    Characters in the Unicode categories Cc, Cf, Cs, Co, Cn, Zl and Zp (ESC, OSC 8 links, C1 CSI,
    bidi overrides, zero-width characters, DEL) become \\uXXXX, then the text is truncated.
    """
    if not isinstance(text, str):
        text = str(text)
    out = []
    for ch in text[: limit * 2]:
        if unicodedata.category(ch) in _UNSAFE_CATEGORIES:
            cp = ord(ch)
            out.append("\\u%04x" % cp if cp <= 0xFFFF else "\\U%08x" % cp)
        else:
            out.append(ch)
    cleaned = "".join(out)
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1] + "…"
    return cleaned


def sev_rank(sev):
    """INFO=0 ... CRITICAL=4; an unknown value ranks as INFO."""
    try:
        return SEVERITIES.index(sev)
    except ValueError:
        return 0


# ---- Addresses -------------------------------------------------------------------------------
def norm_ip(text):
    """A single IP literal, normalised; ::ffff:a.b.c.d maps to IPv4. Raises ValueError."""
    if not isinstance(text, str) or not text or len(text) > 45 or text != text.strip() or "%" in text:
        raise ValueError("not an IP literal")
    ip = ipaddress.ip_address(text)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def norm_cidr(text):
    """A CIDR with no host bits set, normalised (a bare address becomes /32 or /128). Raises ValueError."""
    if not isinstance(text, str) or not text or len(text) > 49 or text != text.strip() or "%" in text:
        raise ValueError("not a CIDR")
    return str(ipaddress.ip_network(text, strict=True))


def source_key(ip_text):
    """The per-source key for connection caps: the IPv4 address, or the IPv6 /64."""
    ip = ipaddress.ip_address(ip_text)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 4:
        return str(ip)
    return str(ipaddress.ip_network((int(ip) >> 64 << 64, 64)))


# ---- Settings (section 14) -------------------------------------------------------------------
def _sev(v):
    if v not in SEVERITIES:
        raise ValueError("must be one of " + ", ".join(SEVERITIES))
    return v


def _hhmm(v):
    if not re.match(r"^([01]\d|2[0-3]):[0-5]\d\Z", str(v)):
        raise ValueError("must be HH:MM (UTC)")
    return str(v)


def _int_range(lo, hi):
    def check(v):
        n = int(v)
        if not lo <= n <= hi:
            raise ValueError("must be between %d and %d" % (lo, hi))
        return n
    return check


def _choice(*allowed):
    def check(v):
        if v not in allowed:
            raise ValueError("must be one of " + ", ".join(allowed))
        return v
    return check


def _https_url_or_empty(v):
    v = str(v)
    if v and not re.match(r"^https://[A-Za-z0-9.-]+(:\d{1,5})?(/[\x21-\x7e]*)?\Z", v):
        raise ValueError("must be an https URL")
    return v


def _text(maxlen):
    def check(v):
        v = str(v)
        if len(v) > maxlen or any(unicodedata.category(c) in _UNSAFE_CATEGORIES for c in v):
            raise ValueError("too long or holds control characters")
        return v
    return check


def _size(v):
    parse_size(v)
    return str(v).strip().upper()


# Plain keys an operator may set with `edr-hub settings set KEY VALUE`: key -> (default, validator)
PLAIN_SETTINGS = {
    "alert_min_severity": ("HIGH", _sev),
    "digest_time": ("07:00", _hhmm),
    "ntfy_url": ("", _https_url_or_empty),
    "smtp_host": ("", _text(253)),
    "smtp_port": (587, _int_range(1, 65535)),
    "smtp_security": ("starttls", _choice("starttls", "smtps")),
    "smtp_user": ("", _text(254)),
    "smtp_from": ("", _text(254)),
    "smtp_to": ("", _text(254)),
    "webhook_ca": ("", _text(4096)),            # a path; its contents travel inside each out.sock job
    "fleet_ban_mode": ("dry-run", _choice("dry-run", "on")),
    "fleet_ban_budget_per_hour": (20, _int_range(0, 10000)),
    "retention_days": (30, _int_range(1, 3650)),
    "max_db_size": ("2G", _size),
    "daily_job_utc": ("03:00", _hhmm),
    "rate_low_per_hour": (15000, _int_range(1, 10_000_000)),
    "rate_high_per_hour": (1000, _int_range(1, 10_000_000)),
    "backup_keep": (14, _int_range(1, 365)),
    "ui_host": ([], None),                      # list of HOST:PORT; empty means the loopback names with ui_port
}

# Installer-owned keys: shown read-only by `settings get`; only install.sh changes them
INSTALLER_SETTINGS = {
    "port": 8443,
    "enroll_port": 8444,
    "ui_port": 8450,
    "admin_ip": [],
    "public_ip": [],
    "clients_only": False,
}

# Secrets live in /etc/edr-hub/secrets.json, written by the root CLI only; settings.json keeps
# only the masked form under "secrets_set": {key: "host…last4"} so the hub knows which channels are on
SECRET_SETTINGS = ("webhook_url", "discord_url", "ntfy_topic", "ntfy_token", "smtp_password", "deadman_url")

CHANNELS = ("webhook", "ntfy", "discord", "email")


def default_settings():
    d = {k: v[0] for k, v in PLAIN_SETTINGS.items()}
    d.update({k: (list(v) if isinstance(v, list) else v) for k, v in INSTALLER_SETTINGS.items()})
    d["secrets_set"] = {}
    return d


def validate_setting(key, value):
    """Return the normalised value for a plain key, or raise KeyError (unknown) / ValueError (bad)."""
    default, check = PLAIN_SETTINGS[key]
    if key == "ui_host":
        items = value if isinstance(value, list) else [x for x in str(value).split(",") if x]
        for item in items:
            if not re.match(r"^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):\d{1,5}\Z", item):
                raise ValueError("each entry must be HOST:PORT")
        return items
    return check(value)


def load_settings(paths):
    """settings.json merged over the defaults. A missing file gives the defaults."""
    settings = default_settings()
    try:
        with open(paths.settings, encoding="utf-8") as f:
            stored = json.load(f)
        if isinstance(stored, dict):
            settings.update(stored)
    except FileNotFoundError:
        pass
    return settings


def save_settings(paths, settings):
    atomic_write(paths.settings, json.dumps(settings, indent=1, sort_keys=True) + "\n", 0o640)


def mask_secret(value):
    """A secret as it may be shown: the host (for a URL) plus the last 4 characters."""
    value = str(value)
    if not value:
        return ""
    host = ""
    m = re.match(r"^[a-z]+://([^/:@]+)", value)
    if m:
        host = m.group(1) + " "
    return host + "…" + value[-4:]


def enabled_channels(settings):
    """Alert channels that are switched on, from the masked markers the CLI records (section 14)."""
    have = settings.get("secrets_set", {})
    on = []
    if have.get("webhook_url"):
        on.append("webhook")
    if settings.get("ntfy_url") and have.get("ntfy_topic"):
        on.append("ntfy")
    return on


def ui_hosts(settings):
    """The Host allowlist of the dashboard (section 5)."""
    port = settings.get("ui_port", 8450)
    return list(settings.get("ui_host") or []) or ["127.0.0.1:%d" % port, "localhost:%d" % port]


# ---- systemd ---------------------------------------------------------------------------------
def sd_notify(message):
    """Send READY=1, WATCHDOG=1 or STATUS=... to systemd. Does nothing outside a unit."""
    target = os.environ.get("NOTIFY_SOCKET")
    if not target:
        return False
    if target.startswith("@"):
        target = "\0" + target[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.sendto(message.encode(), target)
        return True
    except OSError:
        return False
