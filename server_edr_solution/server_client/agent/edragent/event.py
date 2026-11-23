"""Events: the Appendix B shape, sanitising, redacting and size limits (client PLAN sections 4.5 and 18).

make_event() is what every source calls. What it returns is already safe to log, spool and send: every
string is cleaned of control characters, secrets are cut out, and the serialised event is at most 5 KiB.
The id, epoch and seq are added later by the pipeline, only for events that are really forwarded.
"""
import base64
import binascii
import ipaddress
import json
import re
import time
import unicodedata
from datetime import datetime, timezone

from . import SCHEMA, VERSION

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SOURCES = ("tetragon", "suricata", "nginx", "journal", "kernel", "inventory", "agent", "canary")
SRC_TRUST = ("tcp", "claimed", "none")

SUMMARY_MAX = 256
DETAIL_MAX = 512
ARGS_MAX = 1024
URL_MAX = 512
EVENT_MAX_BYTES = 5 * 1024
CONTEXT_MAX_ENTRIES = 20
CONTEXT_MAX_BYTES = 4 * 1024
PAYLOAD_HEAD = 128

_KIND_BAD = re.compile(r"[^a-z0-9_.-]")
_UNSAFE_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}
_ARGS_KEYS = {"args", "arguments", "command", "cmdline"}
_URL_KEYS = {"url", "path", "uri"}

# What the agent keeps from the configuration. configure() replaces it.
_settings = {"redact": True, "payload": "hex-head", "args": "redact", "agent_ver": VERSION, "boot_id": None}


def configure(cfg=None, boot_id=None, **override):
    """Take the redaction choices from the configuration ([agent] redact, payload, args)."""
    if cfg is not None:
        _settings["redact"] = cfg.getbool("agent", "redact", True)
        _settings["payload"] = cfg.get("agent", "payload", "hex-head")
        _settings["args"] = cfg.get("agent", "args", "redact")
    if boot_id is not None:
        _settings["boot_id"] = boot_id
    _settings.update(override)


def settings():
    return dict(_settings)


def boot_id():
    if _settings["boot_id"] is None:
        try:
            with open("/proc/sys/kernel/random/boot_id") as f:
                _settings["boot_id"] = f.read(64).strip()[:36]
        except OSError:
            _settings["boot_id"] = ""
    return _settings["boot_id"]


# ---- sanitising -------------------------------------------------------------------------------------
def _escape_char(ch):
    cp = ord(ch)
    if cp <= 0xFF:
        return "\\x%02x" % cp
    if cp <= 0xFFFF:
        return "\\u%04x" % cp
    return "\\U%08x" % cp


def clean_text(text):
    """Replace control characters, DEL, bidi marks, line separators and other invisible characters by \\xNN."""
    if not isinstance(text, str):
        text = str(text)
    if text.isascii() and text.isprintable():
        return text
    out = []
    for ch in text:
        if unicodedata.category(ch) in _UNSAFE_CATEGORIES:
            out.append(_escape_char(ch))
        else:
            out.append(ch)
    return "".join(out)


def cut(text, limit):
    """Cap a string at limit characters; the second value says whether something was cut."""
    if len(text) <= limit:
        return text, False
    return text[: limit - 1] + "…", True


# ---- redaction --------------------------------------------------------------------------------------
_R = "[REDACTED]"
_REDACTIONS = [
    # --password VALUE, --token=VALUE, -p VALUE, -pVALUE
    (re.compile(r"(?i)(?<![\w-])(--?(?:password|passwd|pass|token|secret|api[-_]?key|apikey|access[-_]?token))([= ]+)(?:\"[^\"]*\"|'[^']*'|\S+)"),
     lambda m: m.group(1) + m.group(2) + _R),
    (re.compile(r"(?<![\w-])-p(?:[ =]+|(?=\S))(?:\"[^\"]*\"|'[^']*'|\S+)"), lambda m: "-p " + _R),
    # -u user:password
    (re.compile(r"(?<![\w-])-u[ =]+[^\s:]+:\S+"), lambda m: "-u " + _R),
    # scheme://user:pw@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@:]*:[^\s/@]*@"), lambda m: m.group(1) + _R + "@"),
    # Authorization: Bearer ..., Cookie: ..., X-Api-Key: ... (to the end of the text)
    (re.compile(r"(?i)\b(proxy-authorization|authorization|set-cookie|cookie|x-api-key|x-auth-token)\s*[:=]\s*[^\r\n]*"),
     lambda m: m.group(1) + ": " + _R),
    # NAME_PASSWORD=value and the like (environment variables)
    (re.compile(r"\b([A-Za-z0-9_]*(?:PASSWORD|SECRET|TOKEN|KEY))=\S*"), lambda m: m.group(1) + "=" + _R),
    # query parameters
    (re.compile(r"(?i)(?<![A-Za-z0-9_])(token|key|password|secret|sig|access_token|api_key|apikey)=[^&\s#\"']*"),
     lambda m: m.group(1) + "=" + _R),
]


def redact_text(text):
    """Text with secrets cut out, and whether anything was."""
    changed = False
    for pattern, repl in _REDACTIONS:
        new = pattern.sub(repl, text)
        if new != text:
            changed = True
            text = new
    return text, changed


# ---- applying both to nested values ------------------------------------------------------------------
class _Marks:
    def __init__(self):
        self.truncated = False
        self.redacted = False


def _scrub_str(text, limit, marks, redact):
    text = clean_text(text)
    if redact:
        text, changed = redact_text(text)
        marks.redacted = marks.redacted or changed
    text, was_cut = cut(text, limit)
    marks.truncated = marks.truncated or was_cut
    return text


def _scrub(value, key, marks, redact, depth=0):
    """Clean one detail value. Strings are capped by what they hold (args 1024, url 512, others 512)."""
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            return None
        return value
    if isinstance(value, str):
        limit = ARGS_MAX if key in _ARGS_KEYS else URL_MAX if key in _URL_KEYS else DETAIL_MAX
        return _scrub_str(value, limit, marks, redact)
    if isinstance(value, bytes):
        return _scrub_str(value.decode("utf-8", "replace"), DETAIL_MAX, marks, redact)
    if depth >= 3:
        marks.truncated = True
        return None
    if isinstance(value, (list, tuple)):
        if len(value) > 32:
            marks.truncated = True
        return [_scrub(v, key, marks, redact, depth + 1) for v in list(value)[:32]]
    if isinstance(value, dict):
        out = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= 32:
                marks.truncated = True
                break
            k = _scrub_str(str(k), 64, marks, False)
            out[k] = _scrub(v, k, marks, redact, depth + 1)
        return out
    return _scrub_str(str(value), DETAIL_MAX, marks, redact)


def payload_head_hex(payload):
    """The first 128 bytes of an alert payload (base64 text or bytes) as hex, or ''."""
    if isinstance(payload, str):
        try:
            payload = base64.b64decode(payload + "=" * (-len(payload) % 4), validate=False)
        except (binascii.Error, ValueError):
            return ""
    if not isinstance(payload, (bytes, bytearray)):
        return ""
    return bytes(payload[:PAYLOAD_HEAD]).hex()


# ---- time -------------------------------------------------------------------------------------------
def rfc3339(ts_ms):
    """RFC 3339 UTC with milliseconds and Z."""
    sec, ms = divmod(int(ts_ms), 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sec)) + ".%03dZ" % ms


_TS_RE = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:[.,](\d+))?\s*(Z|[+-]\d\d:?\d\d)?\Z")


def parse_ts(text, assume_utc=True):
    """Epoch milliseconds from an RFC 3339 or Suricata timestamp, or None. Nanosecond fractions are cut."""
    if not isinstance(text, str):
        return None
    m = _TS_RE.match(text.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, frac, zone = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), min(int(s), 59), tzinfo=timezone.utc)
    except ValueError:
        return None
    ms = int(((frac or "0") + "000")[:3])
    epoch = int(dt.timestamp())
    if zone and zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        digits = zone[1:].replace(":", "")
        epoch -= sign * (int(digits[:2]) * 3600 + int(digits[2:4]) * 60)
    elif not zone and not assume_utc:
        local = datetime(int(y), int(mo), int(d), int(h), int(mi), min(int(s), 59))
        epoch = int(local.timestamp())
    return epoch * 1000 + ms


# ---- make_event -------------------------------------------------------------------------------------
def _norm_ip(text):
    if not isinstance(text, str) or not text or len(text) > 45 or text != text.strip() or "%" in text:
        return ""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return ""
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def make_event(kind, source, sev, summary, *, details=None, ts_ms=None, src_ip="", src_trust="none",
               dst_ip="", dst_port=None, proto=None, proc=None, community_id=None):
    """One event in the Appendix B shape, sanitised, redacted and capped. id, epoch and seq come later."""
    marks = _Marks()
    redact = _settings["redact"]
    kind = _KIND_BAD.sub("_", str(kind).lower())[:64] or "unknown"
    if source not in SOURCES:
        source = "agent"
    if sev not in SEVERITIES:
        sev = "MEDIUM"
    now_ms = int(time.time() * 1000)
    if ts_ms is None or not isinstance(ts_ms, (int, float)) or ts_ms < 0 or ts_ms > now_ms + 86400000 * 365:
        ts_ms = now_ms
    ev = {
        "v": SCHEMA,
        "agent_ver": _settings["agent_ver"],
        "boot_id": boot_id(),
        "ts": rfc3339(ts_ms),
        "sev": sev,
        "kind": kind,
        "source": source,
        "summary": _scrub_str(str(summary), SUMMARY_MAX, marks, redact),
    }
    if details:
        det = _scrub(dict(details), "", marks, redact)
        if _settings["args"] == "drop":
            for k in list(det):
                if k in _ARGS_KEYS:
                    del det[k]
                    marks.redacted = True
        if det:
            ev["details"] = det
    src = _norm_ip(src_ip)
    ev["src_ip"] = src
    if not src:
        ev["src_trust"] = "none"
    else:
        ev["src_trust"] = src_trust if src_trust in ("tcp", "claimed") else "claimed"
    dst = _norm_ip(dst_ip)
    if dst:
        ev["dst_ip"] = dst
    if isinstance(dst_port, int) and not isinstance(dst_port, bool) and 0 <= dst_port <= 65535:
        ev["dst_port"] = dst_port
    if proto:
        ev["proto"] = _scrub_str(str(proto).lower(), 16, marks, False)
    if proc:
        ev["proc"] = _scrub_proc(proc, marks, redact)
    if community_id:
        ev["community_id"] = _scrub_str(str(community_id), 64, marks, False)
    if marks.redacted:
        ev["redacted"] = True
    if marks.truncated:
        ev["truncated"] = True
    return fit(ev)


def _scrub_proc(proc, marks, redact):
    out = {}
    for k in ("binary", "args", "parent"):
        v = proc.get(k)
        if v is None or v == "":
            continue
        if k == "args" and _settings["args"] == "drop":
            marks.redacted = True
            continue
        limit = ARGS_MAX if k == "args" else DETAIL_MAX
        out[k] = _scrub_str(str(v), limit, marks, redact)
    uid = proc.get("uid")
    if isinstance(uid, int) and not isinstance(uid, bool):
        out["uid"] = uid
    return out


# ---- size ---------------------------------------------------------------------------------------------
def size_of(ev):
    return len(json.dumps(ev, separators=(",", ":"), ensure_ascii=True).encode("ascii"))


def fit(ev, limit=EVENT_MAX_BYTES):
    """Trim an event to the limit: context first, then details, then the summary. Marks it truncated."""
    if size_of(ev) <= limit:
        return ev
    ev["truncated"] = True
    ctx = ev.get("context")
    while ctx and size_of(ev) > limit:
        ctx.pop()
    if "context" in ev and not ev["context"]:
        del ev["context"]
    det = ev.get("details")
    if det and size_of(ev) > limit:
        for cap in (256, 128, 64):
            for k, v in list(det.items()):
                if isinstance(v, str) and len(v) > cap:
                    det[k] = v[: cap - 1] + "…"
                elif isinstance(v, (list, dict)) and len(json.dumps(v)) > cap * 2:
                    det[k] = None
            if size_of(ev) <= limit:
                break
        while det and size_of(ev) > limit:
            biggest = max(det, key=lambda k: len(json.dumps(det[k])))
            del det[biggest]
        if not det:
            ev.pop("details", None)
    proc = ev.get("proc")
    if proc and size_of(ev) > limit:
        for k in ("args", "parent", "binary"):
            if k in proc and len(proc[k]) > 128:
                proc[k] = proc[k][:127] + "…"
        if size_of(ev) > limit:
            ev.pop("proc", None)
    if size_of(ev) > limit:
        ev["summary"] = ev["summary"][:96]
    return ev


def attach_context(ev, entries):
    """Put up to 20 access-log entries (4 KiB at most) on an event, sanitised and redacted like any text."""
    if not entries:
        return ev
    marks = _Marks()
    redact = _settings["redact"]
    kept, used = [], 2
    for entry in entries[:CONTEXT_MAX_ENTRIES]:
        clean = {k: _scrub(v, k, marks, redact) for k, v in entry.items()}
        n = len(json.dumps(clean, separators=(",", ":"))) + 1
        if used + n > CONTEXT_MAX_BYTES:
            marks.truncated = True
            break
        kept.append(clean)
        used += n
    if kept:
        ev["context"] = kept
    if marks.redacted:
        ev["redacted"] = True
    if marks.truncated:
        ev["truncated"] = True
    return fit(ev)


def sev_rank(sev):
    try:
        return SEVERITIES.index(sev)
    except ValueError:
        return 0


def dumps(ev):
    return json.dumps(ev, separators=(",", ":"), ensure_ascii=True)
