"""What every log reader shares: the context, the access ring and counters, notice handling."""
import calendar
import collections
import ipaddress
import pwd
import re
import time

from .. import event as ev

MAX_TEXT_LINE = 8 * 1024        # text logs are cut here before parsing (client PLAN section 4.5, Hostile log content)
COUNTER_KEYS_MAX = 50_000       # per-IP counters, LRU (IPv6 per /64)
PROXY_SAMPLE = 1000             # the last 1000 requests
PROXY_MIN_SAMPLE = 200          # fewer requests than this say nothing about a proxy
PROXY_MIN_PRIVATE_SAMPLE = 20

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def parse_ip(text):
    """An IP literal normalised (::ffff:a.b.c.d to IPv4), or '' when text is not exactly one."""
    if not isinstance(text, str) or not text or len(text) > 45 or text != text.strip() or "%" in text:
        return ""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return ""
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def counter_key(ip):
    """IPv6 addresses are counted per /64."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if a.version == 6:
        return str(ipaddress.ip_network((int(a) >> 64 << 64, 64)))
    return ip


def is_private_or_cgnat(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a in _CGNAT or a.is_loopback or a.is_link_local


def parse_clf_time(text):
    """Epoch milliseconds from an nginx $time_local such as 10/Oct/2000:13:55:36 +0000, or None."""
    m = re.match(r"^(\d{1,2})/([A-Z][a-z]{2})/(\d{4}):(\d\d):(\d\d):(\d\d) ([+-])(\d\d)(\d\d)$", text)
    if not m:
        return None
    d, mon, y, h, mi, s, sign, zh, zm = m.groups()
    if mon not in _MONTHS:
        return None
    try:
        epoch = calendar.timegm((int(y), _MONTHS[mon], int(d), int(h), int(mi), int(s), 0, 0, 0))
    except (ValueError, OverflowError):
        return None
    epoch -= (1 if sign == "+" else -1) * (int(zh) * 3600 + int(zm) * 60)
    return epoch * 1000


class AccessRing:
    """The last few minutes of requests, in memory only (client PLAN section 4.5, Access ring)."""

    def __init__(self, minutes=5, lines=20000):
        self.minutes, self.lines = minutes, lines
        self.q = collections.deque(maxlen=lines)
        self.by_ip = {}

    def set_limits(self, minutes, lines):
        self.minutes = minutes
        if lines != self.lines:
            self.lines = lines
            self.q = collections.deque(self.q, maxlen=lines)

    def add(self, ts, ip, method, path, query, status, nbytes, ua):
        self.q.append((ts, ip, method[:16], path[:200], query[:200], status, nbytes, ua[:80]))

    def prune(self, now):
        limit = now - self.minutes * 60
        q = self.q
        while q and q[0][0] < limit:
            q.popleft()

    def entries_for(self, ip, limit=20):
        """Up to `limit` newest entries for one address, oldest first, as plain dicts."""
        out = []
        for row in reversed(self.q):
            if row[1] == ip:
                out.append({"ts": ev.rfc3339(row[0] * 1000), "ip": row[1], "method": row[2], "path": row[3],
                            "query": row[4], "status": row[5], "bytes": row[6], "ua": row[7]})
                if len(out) >= limit:
                    break
        out.reverse()
        return out


class AccessStats:
    """Per-IP request counters (50,000 keys, LRU) and the evidence for the proxy heuristic."""

    def __init__(self):
        self.ips = collections.OrderedDict()
        self.recent = collections.deque(maxlen=PROXY_SAMPLE)
        self.xff_seen = False
        self.total = 0

    def count(self, ip, status, tripwire=False):
        self.total += 1
        key = counter_key(ip)
        row = self.ips.get(key)
        if row is None:
            row = self.ips[key] = [0, 0, 0, 0]       # requests, 4xx, 5xx, tripwire hits
            if len(self.ips) > COUNTER_KEYS_MAX:
                self.ips.popitem(last=False)
        else:
            self.ips.move_to_end(key)
        row[0] += 1
        if 400 <= status < 500:
            row[1] += 1
        elif status >= 500:
            row[2] += 1
        if tripwire:
            row[3] += 1
        self.recent.append(key)

    def proxy_signals(self):
        """Why the log address may be a proxy's: a list of short reasons, empty when none apply."""
        reasons = []
        n = len(self.recent)
        if self.xff_seen:
            reasons.append("forwarded_header")
        if n >= PROXY_MIN_SAMPLE:
            counts = collections.Counter(self.recent)
            top, top_n = counts.most_common(1)[0]
            if top_n * 2 > n:
                reasons.append("one_address_over_half")
            if len(counts) < 3:
                reasons.append("fewer_than_3_sources")
        if n >= PROXY_MIN_PRIVATE_SAMPLE:
            private = sum(1 for k in self.recent if is_private_or_cgnat(k.split("/")[0]))
            if private * 2 > n:
                reasons.append("private_or_cgnat_majority")
        return reasons


class Context:
    """The things readers need besides their own log: configuration, inventory facts, the ring."""

    def __init__(self, cfg, paths, clock=time.time):
        self.cfg, self.paths, self.clock = cfg, paths, clock
        self.ring = AccessRing(cfg.get("agent", "access_ring_minutes", 5), cfg.get("agent", "access_ring_lines", 20000))
        self.stats = AccessStats()
        self.inventory_checks = {}           # filled by the helper watcher from inventory.json
        self.suricata_drops = None           # {"packets", "drops", "window_s"} from the newest stats record
        self.counters = collections.Counter()
        self.proxy_reasons = []
        self.log_format_ok = None            # True/False once the access log has been seen
        self._uids = (0.0, set())
        self._pid = (0.0, None)
        self.eve_flow_context = collections.OrderedDict()   # community_id -> {sni, ja4, hassh}

    def reload(self):
        self.ring.set_limits(self.cfg.get("agent", "access_ring_minutes", 5), self.cfg.get("agent", "access_ring_lines", 20000))

    def real_ip(self):
        check = self.inventory_checks.get("real_ip")
        if isinstance(check, dict):
            return check.get("status") is True
        return False

    def web_uids(self):
        """Numeric uids of [sites] web_users (cached for a minute)."""
        now = self.clock()
        if now - self._uids[0] < 60:
            return self._uids[1]
        uids = set()
        for name in self.cfg.getlist("sites", "web_users"):
            try:
                uids.add(pwd.getpwnam(name).pw_uid)
            except KeyError:
                pass
        self._uids = (now, uids)
        return uids

    def user_name(self, uid):
        try:
            return pwd.getpwuid(int(uid)).pw_name
        except (KeyError, ValueError, TypeError, OverflowError):
            return str(uid)

    def master_pid(self):
        """The nginx master's pid from /run/nginx.pid, or None when unreadable."""
        now = self.clock()
        if now - self._pid[0] < 5:
            return self._pid[1]
        pid = None
        try:
            with open(self.paths.nginx_pid, "rb") as f:
                text = f.read(32).strip()
            if text.isdigit():
                pid = int(text)
        except OSError:
            pass
        self._pid = (now, pid)
        return pid

    def web_src_trust(self):
        """tcp unless the log address may be a proxy's or a header's (then claimed, and nothing bans on it)."""
        mode = self.cfg.get("bans", "proxy_mode", "auto")
        if self.real_ip() or mode == "on":
            return "claimed"
        if mode == "auto" and self.proxy_reasons:
            return "claimed"
        return "tcp"

    def update_proxy(self):
        """Refresh the proxy verdict from the counters; returns (changed, reasons)."""
        reasons = self.stats.proxy_signals() if self.cfg.get("bans", "proxy_mode", "auto") == "auto" else []
        changed = bool(reasons) != bool(self.proxy_reasons)
        self.proxy_reasons = reasons
        return changed, reasons


class Source:
    """Base of every reader. poll(now) returns new events; commit() saves checkpoints."""

    name = "source"

    def __init__(self, ctx):
        self.ctx = ctx
        self.reader = None
        self.dropped_lines = 0

    def readers(self):
        return [self.reader] if self.reader is not None else []

    def poll(self, now):
        return []

    def commit(self):
        for r in self.readers():
            r.commit()

    def close(self):
        for r in self.readers():
            r.close()

    def notice_events(self, label=None):
        """Events for what the readers noticed: gaps, shrinks, rotations, unreadable files."""
        out = []
        for r in self.readers():
            for n in r.drain_notices():
                out.extend(self.on_notice(n, label or self.name))
        return out

    def on_notice(self, n, label):
        kind = n.get("type")
        if kind == "gap":
            return [ev.make_event("health.gap", "agent", "MEDIUM", "log gap in %s: %s" % (label, n.get("reason", "")),
                                  details={"log": label, "reason": n.get("reason", ""), "skipped_bytes": n.get("skipped_bytes", 0)})]
        if kind == "truncated":
            return [ev.make_event("tamper.log_truncated", "agent", "HIGH", "log %s shrank: it was truncated or emptied" % label,
                                  details={"log": label, "reason": n.get("reason", ""), "offset_was": n.get("offset", 0)})]
        if kind == "unreadable":
            return [ev.make_event("health.log_unreadable", "agent", "MEDIUM", "cannot read log %s (%s)" % (label, n.get("reason", "")),
                                  details={"log": label, "reason": n.get("reason", "")})]
        return []


def cut_line(line):
    """Lines over 8 KiB are cut before parsing."""
    return line[:MAX_TEXT_LINE] if len(line) > MAX_TEXT_LINE else line
