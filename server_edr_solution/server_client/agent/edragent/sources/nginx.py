"""nginx's error log (crash and marker lines) and access log (counters, tripwires, the in-memory ring).

Address attribution follows the "Hostile log content" table of client PLAN section 4.5:
  error.log   an address only if the line has exactly one ", client: ", is under 2040 bytes and matches
              ", client: <IP>, server: ". nginx does not escape error.log, so a request can inject a fake
              trailer; the real one is still appended, so a forgery has two, and a long request can cut the
              real trailer at 2048 bytes, which the length limit and the ", server: " match both reject.
  access.log  the first field only, and only if the whole line matches a log_format that starts with
              $remote_addr; nothing else in the line is ever used as an address.
Message templates match the text before ", client:", anchored to the start of the line.
"""
import fnmatch
import json
import os
import re
import time
import urllib.parse

from .. import event as ev
from .. import tail
from .base import Source, cut_line, parse_ip, parse_clf_time

ERROR_LINE_MAX_FOR_ADDRESS = 2040
HOLD_ATTRIBUTED_S = 2.0
CORROBORATE_WAIT_S = 5.0
GLIBC_HOLD_LINES = 4
GLIBC_HOLD_SECONDS = 5.0
LOG_FORMAT_BAD_MIN = 20
LOG_FORMAT_REMINDER_S = 6 * 3600

_ERR_RE = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(\w+)\] (\d+)#(\d+): (.*)\Z", re.DOTALL)
_RECORD_START = re.compile(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[\w+\] \d+#\d+: ")
_CLIENT_RE = re.compile(r", client: ([0-9A-Fa-f:.]{2,45}), server: ")
_GLIBC_RE = re.compile(
    r"^(free\(\): |malloc\(\): |realloc\(\): |double free or corruption|double free detected|corrupted size|"
    r"corrupted double-linked list|munmap_chunk\(\)|malloc_consolidate\(\)|invalid pointer|free\(\): invalid)")
_CRASH_RE = re.compile(r"^worker process (\d+) exited on signal (\d+)(?: \(core dumped\))?\Z")
_RESOLVER_RE = re.compile(r"^could not cancel .*resolving")
_PRESSURE_RE = re.compile(r"^(?:\d+ )?worker_connections are not enough, reusing connections")
_EXHAUSTED_RE = re.compile(r"^(\d+) worker_connections are not enough\Z")
_WINDOW_RE = re.compile(r"^client violated connection flow control: received WINDOW_UPDATE frame with window increment")


def attribute_error_line(line):
    """The client address of an error.log line under the rule above, or ''."""
    if line.count(", client: ") != 1:
        return ""
    if len(line.encode("utf-8", "replace")) >= ERROR_LINE_MAX_FOR_ADDRESS:
        return ""
    m = _CLIENT_RE.search(line)
    return parse_ip(m.group(1)) if m else ""


def _local_epoch_ms(text):
    try:
        return int(time.mktime(time.strptime(text, "%Y/%m/%d %H:%M:%S"))) * 1000
    except (ValueError, OverflowError):
        return None


class ErrorLogSource(Source):
    def __init__(self, ctx, first_start="end", path=None, label="nginx_error"):
        super().__init__(ctx)
        self.name = "nginx"
        self.label = label
        self.path = path or ctx.paths.nginx_error_log
        self.reader = tail.Tailer(self.path, label, ctx.paths.cursors_dir, first_start=first_start, clock=ctx.clock)
        self.held = []          # (time, text) of unprefixed glibc abort lines
        self.attributed = []    # (time, events): events with an address, waiting to see what the next line is
        self.waiting = []       # (deadline, event): address rules passed, waiting for the access log to confirm the address

    def poll(self, now):
        events = self.process_lines(self.reader.poll(), now) + self.settle(now)
        return self.notice_events(self.label) + events

    # The address of an error.log line is something a web user can try to forge (nginx does not escape the file), and a
    # ban on it would lock out whoever the attacker names. So it is ban evidence (src_trust tcp) only when the access
    # log, which the web user cannot forge, shows a request from the same address inside the ring's window. Without that
    # (the access log unreadable, its format not starting with $remote_addr, no request from the address) the event is
    # still raised, but the address is `claimed`: it can never become a ban or a fleet vote.
    def _corroborated(self, ip, now):
        ctx = self.ctx
        return ctx.access_usable is not False and ctx.ring.has(ip, now)

    def _corroborate(self, events, now):
        out = []
        for e in events:
            if e.get("src_ip") and e.get("src_trust") == "tcp":
                if self._corroborated(e["src_ip"], now):
                    e.setdefault("details", {})["addr_corroborated"] = True
                else:
                    self.waiting.append((now + CORROBORATE_WAIT_S, e))
                    continue
            out.append(e)
        return out

    def settle(self, now=None, force=False):
        """Events whose address the access log has confirmed, or (after a few seconds, or at the end) downgraded to claimed."""
        now = self.ctx.clock() if now is None else now
        out, rest = [], []
        for deadline, e in self.waiting:
            if self._corroborated(e["src_ip"], now):
                e.setdefault("details", {})["addr_corroborated"] = True
                out.append(e)
            elif force or now >= deadline:
                e["src_trust"] = "claimed"
                e.setdefault("details", {})["addr_corroborated"] = False
                out.append(e)
            else:
                rest.append((deadline, e))
        self.waiting = rest
        return out

    def process_lines(self, lines, now=None):
        """parse_line over a run of physical lines, with one extra check on every event that carries an address.

        nginx does not escape error.log. A request that puts a newline into a message can start a line of its
        own, with a genuine-looking template and one fake ", client: " trailer, and a second newline can move the
        real trailer onto the line after it, so the one-trailer rule alone is not enough. A genuine record is
        always followed by another record or the end of the file: if the next physical line does not start like
        a record, the address of the event before it is dropped.
        """
        now = self.ctx.clock() if now is None else now
        out = []
        for line in lines:
            if self.attributed:
                _, held = self.attributed.pop()
                if not _RECORD_START.match(line) and not _GLIBC_RE.match(line):
                    for e in held:
                        e["src_ip"], e["src_trust"] = "", "none"
                        e.setdefault("details", {})["address_dropped"] = "split_record"
                out.extend(held)
            events = self.parse_line(line, now)
            keep = [e for e in events if e.get("src_ip")]
            out.extend(e for e in events if not e.get("src_ip"))
            if keep:
                self.attributed.append((now, keep))
        if self.attributed and now - self.attributed[-1][0] >= HOLD_ATTRIBUTED_S:
            out.extend(self.attributed.pop()[1])        # no line followed: it was the end of the file, so far
        return self._corroborate(out, now)

    def finish(self):
        """Release what is still waiting (at shutdown, and in tests): unconfirmed addresses become claimed."""
        out = []
        while self.attributed:
            out.extend(self.attributed.pop()[1])
        now = self.ctx.clock()
        return self._corroborate(out, now) + self.settle(now, force=True)

    def parse_line(self, line, now=None):
        now = self.ctx.clock() if now is None else now
        line = cut_line(line)
        self.held = [(t, s) for t, s in self.held if now - t <= GLIBC_HOLD_SECONDS]
        m = _ERR_RE.match(line)
        if not m:
            if _GLIBC_RE.match(line) and len(self.held) < GLIBC_HOLD_LINES:
                self.held.append((now, line[:200]))
            return []
        stamp, level, pid, tid, msg = m.groups()
        idx = msg.find(", client: ")
        head = msg if idx < 0 else msg[:idx]
        head = re.sub(r"^\*\d+ ", "", head)           # the connection number nginx puts in front of some messages
        ts_ms = _local_epoch_ms(stamp)
        crash = _CRASH_RE.match(head)
        if crash:
            return self._crash(crash, int(pid), ts_ms, now)
        if _RESOLVER_RE.match(head):
            return [ev.make_event("nginx.marker.resolver_cancel", "nginx", "HIGH",
                                  "nginx could not cancel a resolver request: an unpatched build hit the resolver bug path",
                                  details={"level": level}, ts_ms=ts_ms)]
        if _PRESSURE_RE.match(head):
            return [ev.make_event("nginx.marker.conn_pressure", "nginx", "LOW", "nginx is reusing connections (worker_connections)",
                                  details={"level": level}, ts_ms=ts_ms)]
        ex = _EXHAUSTED_RE.match(head)
        if ex:
            return [ev.make_event("nginx.marker.conn_exhausted", "nginx", "MEDIUM", "nginx worker_connections are not enough",
                                  details={"connections": int(ex.group(1)), "level": level}, ts_ms=ts_ms)]
        if _WINDOW_RE.match(head):
            src = attribute_error_line(line)
            return [ev.make_event("nginx.marker.window_update", "nginx", "LOW",
                                  "HTTP/2 client violated connection flow control (WINDOW_UPDATE)",
                                  details={"level": level}, ts_ms=ts_ms, src_ip=src,
                                  src_trust=self.ctx.web_src_trust() if src else "none")]
        return []

    def _crash(self, m, line_pid, ts_ms, now):
        worker, signal = int(m.group(1)), int(m.group(2))
        if signal not in (6, 11):
            return []
        master = self.ctx.master_pid()
        forged = master is not None and line_pid != master
        details = {"worker_pid": worker, "signal": signal, "logged_by": line_pid}
        if master is not None:
            details["master_pid"] = master
        # abort lines held in the last 5 s belong to this crash
        details_abort = [s for t, s in self.held if now - t <= GLIBC_HOLD_SECONDS]
        self.held = []
        if details_abort:
            details["abort_lines"] = details_abort
        if forged:
            details["forged"] = True
            return [ev.make_event("nginx.crash", "nginx", "LOW",
                                  "a line says an nginx worker crashed, but it was not written by the nginx master",
                                  details=details, ts_ms=ts_ms)]
        return [ev.make_event("nginx.crash", "nginx", "MEDIUM", "nginx worker %d exited on signal %d" % (worker, signal),
                              details=details, ts_ms=ts_ms)]


# ---- access log -------------------------------------------------------------------------------------
_Q = r'"((?:[^"\\]|\\.){0,4096})"'
_ACC_RE = re.compile(r'^(\S{1,45}) \S+ \S+ \[([^\]\n]{1,40})\] ' + _Q + r' (\d{3}) (\d{1,12}|-)'
                     r'(?: "((?:[^"\\]|\\.){0,2048})" "((?:[^"\\]|\\.){0,1024})")?'
                     r'(?: "((?:[^"\\]|\\.){0,512})")?(?: .*)?$', re.DOTALL)
_REQ_RE = re.compile(r"^([A-Za-z]{1,16}) (\S{0,4096})(?: HTTP/\d(?:\.\d)?)?\Z")
_XFF_RE = re.compile(r"^[0-9A-Fa-f:., ]+\Z")

DEFAULT_TRIPWIRES = [
    {"path": "/_ignition/execute-solution"}, {"path": "/_ignition/health-check"},
    {"path": "/vendor/phpunit/*/eval-stdin.php"}, {"path": "/.env"}, {"path": "/.env.bak"}, {"path": "/.git/"},
    {"path": "/storage/logs/"}, {"path": "/xmlrpc.php"}, {"path": "/phpmyadmin"}, {"path": "/cgi-bin/"},
    {"path": "/wp-login.php", "unless_file": "wp-config.php"},
    {"path": "/telescope", "ban": False}, {"path": "/horizon", "ban": False}, {"path": "/_debugbar", "ban": False},
]


def _webroot_has(roots, name):
    for root in roots:
        for base in (root, os.path.dirname(root.rstrip("/"))):
            if os.path.exists(os.path.join(base, name)):
                return True
    return False


def load_tripwires(path, web_roots=()):
    """The tripwire list as [(pattern, kind, ban)]. Missing or bad file: the built-in list."""
    raw = None
    try:
        with open(path, "rb") as f:
            raw = json.loads(f.read(256 * 1024))
    except (OSError, ValueError):
        raw = None
    items = raw
    if isinstance(raw, dict):
        for key in ("tripwires", "paths", "entries", "rules"):
            if isinstance(raw.get(key), list):
                items = raw[key]
                break
    if not isinstance(items, list) or not items:
        items = DEFAULT_TRIPWIRES
    out = []
    for item in items[:2000]:
        if isinstance(item, str):
            item = {"path": item}
        if not isinstance(item, dict):
            continue
        pat = item.get("path", item.get("pattern"))
        if not isinstance(pat, str) or not pat.startswith("/") or len(pat) > 512:
            continue
        unless = item.get("unless_file", item.get("unless_webroot_has"))
        if isinstance(unless, str) and _webroot_has(web_roots, unless):
            continue
        ban = item.get("ban", True) is not False
        pat = pat.lower()
        kind = "glob" if "*" in pat else "prefix" if pat.endswith("/") else "exact"
        out.append((pat, kind, ban))
    return out


def match_tripwire(rules, path):
    """The (pattern, ban) of the first rule the request path matches, or None."""
    p = urllib.parse.unquote(path, errors="replace").lower()
    while "//" in p:
        p = p.replace("//", "/")
    for pat, kind, ban in rules:
        if kind == "exact":
            if p == pat or p.startswith(pat + "/"):
                return pat, ban
        elif kind == "prefix":
            if p.startswith(pat) or p == pat.rstrip("/"):
                return pat, ban
        elif fnmatch.fnmatchcase(p, pat) or fnmatch.fnmatchcase(p, pat + "/*"):
            return pat, ban
    return None


def parse_access_line(line):
    """The fields of an access-log line, or None when the line is not in the $remote_addr format.

    Returns dict(ip, ts_ms, method, path, query, status, bytes, ua, xff).
    """
    m = _ACC_RE.match(cut_line(line))
    if not m:
        return None
    ip = parse_ip(m.group(1))
    if not ip:
        return None
    request = m.group(3)
    rm = _REQ_RE.match(request)
    method, target = (rm.group(1), rm.group(2)) if rm else ("", "")
    path, _, query = target.partition("?")
    extra = m.group(8)
    return {"ip": ip, "ts_ms": parse_clf_time(m.group(2)), "method": method, "path": path, "query": query,
            "status": int(m.group(4)), "bytes": 0 if m.group(5) == "-" else int(m.group(5)),
            "ua": m.group(7) or "", "xff": bool(extra and extra != "-" and _XFF_RE.match(extra))}


class AccessLogSource(Source):
    def __init__(self, ctx, first_start="end", path=None, tripwires=None):
        super().__init__(ctx)
        self.name = "nginx"
        self.path = path or ctx.paths.nginx_access_log
        self.reader = tail.Tailer(self.path, "nginx_access", ctx.paths.cursors_dir, first_start=first_start, clock=ctx.clock)
        roots = ctx.cfg.getlist("sites", "web_roots")
        self.rules = tripwires if tripwires is not None else load_tripwires(ctx.paths.tripwires, roots)
        self.ok = 0
        self.bad = 0
        self.last_format_event = 0.0
        self.proxy_active = False
        self.format_disabled = False     # the inventory says an access_log format does not start with $remote_addr

    def poll(self, now):
        events = []
        for line in self.reader.poll():
            events.extend(self.parse_line(line, now))
        events.extend(self._after_batch(now))
        return self.notice_events("nginx_access") + events

    def parse_line(self, line, now=None):
        rec = parse_access_line(line)
        if rec is None:
            if line.strip():
                self.bad += 1
            return []
        self.ok += 1
        ctx = self.ctx
        ip, status = rec["ip"], rec["status"]
        hit = match_tripwire(self.rules, rec["path"]) if rec["path"] else None
        trust = ctx.web_src_trust()
        if self.format_disabled:
            # the first field is not known to be $remote_addr: it is a header value, so no address is taken from the line
            ip, trust = "", "none"
        else:
            ctx.stats.count(ip, status, tripwire=bool(hit))
            if rec["xff"]:
                ctx.stats.xff_seen = True
            ts_s = (rec["ts_ms"] // 1000) if rec["ts_ms"] else int(ctx.clock())
            ctx.ring.add(ts_s, ip, rec["method"], rec["path"], rec["query"], status, rec["bytes"], rec["ua"])
        if not hit:
            return []
        pattern, ban = hit
        details = {"path": rec["path"], "status": status, "method": rec["method"], "tripwire": pattern, "ban": ban}
        if 200 <= status < 300:
            details["served"] = True
            details["ban"] = False
            return [ev.make_event("canary.tripwire", "nginx", "HIGH",
                                  "a tripwire path was ANSWERED by the site: %s" % rec["path"][:120],
                                  details=details, ts_ms=rec["ts_ms"], src_ip=ip, src_trust=trust)]
        if status in (404, 403, 444):
            return [ev.make_event("canary.tripwire", "nginx", "LOW", "tripwire path requested: %s" % rec["path"][:120],
                                  details=details, ts_ms=rec["ts_ms"], src_ip=ip, src_trust=trust)]
        return []

    def _inventory_format_bad(self):
        """The name of an access_log format that the inventory says does not start with $remote_addr, or ''."""
        logs = self.ctx.inventory_checks.get("nginx_logs")
        if not isinstance(logs, dict):
            return ""
        formats = logs.get("log_formats")
        used = logs.get("access_logs")
        if not isinstance(formats, dict) or not isinstance(used, list):
            return ""
        for entry in used:
            name = entry.get("format") if isinstance(entry, dict) else None
            info = formats.get(name) if isinstance(name, str) else None
            if isinstance(info, dict) and info.get("starts_remote_addr") is False:
                return name[:64]
        return ""

    def _after_batch(self, now):
        events = []
        ctx = self.ctx
        ctx.ring.prune(now)
        bad_format = self._inventory_format_bad()
        if bad_format and not self.format_disabled:
            self.last_format_event = now
            events.append(ev.make_event(
                "health.log_format", "agent", "MEDIUM",
                "an nginx access_log format does not start with $remote_addr: no address is taken from the access log",
                details={"format": bad_format, "source": "inventory"}))
        self.format_disabled = bool(bad_format)
        ctx.access_usable = not (self.format_disabled or self.reader.error is not None or ctx.log_format_ok is False)
        changed, reasons = ctx.update_proxy()
        if changed:
            if reasons:
                events.append(ev.make_event("health.proxy_mode", "agent", "LOW",
                                            "the access log looks like it comes from behind a proxy: web-sourced bans are off",
                                            details={"reasons": reasons}))
            else:
                events.append(ev.make_event("health.proxy_mode", "agent", "INFO",
                                            "the access log no longer looks proxied: web-sourced bans are on again"))
        if self.bad >= LOG_FORMAT_BAD_MIN and self.bad > self.ok * 2:
            ctx.log_format_ok = False
            if now - self.last_format_event >= LOG_FORMAT_REMINDER_S:
                self.last_format_event = now
                events.append(ev.make_event(
                    "health.log_format", "agent", "MEDIUM",
                    "the nginx access log does not start with $remote_addr: no address is taken from it",
                    details={"matched": self.ok, "unmatched": self.bad}))
        elif self.ok:
            ctx.log_format_ok = True
        return events
