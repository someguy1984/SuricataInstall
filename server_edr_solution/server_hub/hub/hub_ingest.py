"""The two TLS listeners, their limits and the seven routes (PLAN.md section 2 and Appendix A).

Design (section 2, Server):
- ThreadingHTTPServer is only the accept loop. process_request() takes a slot with a non-blocking acquire, checks
  the per-source cap and starts one thread per connection. The thread wraps the socket with
  do_handshake_on_connect=False, so no handshake ever runs on the accept thread.
- Deadlines are wall-clock: one reaper thread shuts down any connection past its deadline. A per-read timeout
  would let one byte a second keep a connection open for ever.
- Headers are read through a budget (8 KiB, 32 lines). The request is HTTP/1.0 with one request per connection.
- Identity comes from the client certificate only, checked against `hosts` on every request.
Standard library only.
"""

import hashlib
import http
import http.server
import json
import queue
import re
import socket
import socketserver
import ssl
import threading
import time
import zlib

import hub_common
import hub_db
import hub_enroll
import hub_policy
from hub_common import (BATCH_MAX_EVENTS, BODY_MAX_COMPRESSED, BODY_MAX_INFLATED, ERRORS, EVENT_MAX_BYTES,
                        HEADER_DEADLINE_S, HEADER_MAX_BYTES, HEADER_MAX_LINES, HANDSHAKE_DEADLINE_S, PROTO, PROTO_MIN)

REQUEST_BODY_LIMITS = {"/v1/events": BODY_MAX_COMPRESSED, "/v1/heartbeat": 256 * 1024, "/v1/renew": 8 * 1024,
                       "/v1/deregister": 2 * 1024, "/v1/enroll": 16 * 1024}
BIG_BODY = 512 * 1024                  # a body above this gets the 30 s whole-request deadline
PROCESS_DEADLINE_S = 20                # after the request is read: the writer and the reply
RETRY_BUSY_S = 5
RETRY_STORAGE_S = 30
RENEW_MIN_INTERVAL_S = 60
CA_HITS_PER_MIN = 30
REJECT_NOTE_EVERY_S = 30
RO_POOL_MAX = 8
ENROLL_REFRESH_S = 2

_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_SINGLE_HEADERS = ("content-length", "x-edr-proto", "if-none-match", "content-encoding", "host", "content-type")
_STATE_CODE = {"revoked": "host_revoked", "moved": "host_moved", "retired": "host_retired"}
_REVOKE_REASON_CODE = {"revoked": "host_revoked", "retired": "host_retired", "moved": "host_moved",
                       "superseded": "cert_superseded"}
_HIGH = ("HIGH", "CRITICAL")


class HttpError(Exception):
    """An error answer. Carries a code from hub_common.ERRORS; the text is always the fixed one."""

    def __init__(self, code, retry_after=None, index=None):
        super().__init__(code)
        self.code = code
        self.retry_after = retry_after
        self.index = index


# ---- the reaper ----------------------------------------------------------------------------------
class Reaper(threading.Thread):
    """Holds (monotonic deadline, SSLSocket) per live connection and shuts down expired ones. It must hold the
    SSLSocket: the raw socket is detached by wrap_socket (section 2)."""

    def __init__(self):
        super().__init__(name="hub-reaper", daemon=True)
        self._lock = threading.Lock()
        self._live = {}
        self._next = 1
        self._halt = threading.Event()
        self.cut = 0

    def add(self, sock, deadline):
        with self._lock:
            key = self._next
            self._next += 1
            self._live[key] = [deadline, sock]
        return key

    def set(self, key, deadline):
        with self._lock:
            if key in self._live:
                self._live[key][0] = deadline

    def remove(self, key):
        with self._lock:
            self._live.pop(key, None)

    def count(self):
        with self._lock:
            return len(self._live)

    def run(self):
        while not self._halt.wait(0.2):
            now = time.monotonic()
            expired = []
            with self._lock:
                for key, (deadline, sock) in list(self._live.items()):
                    if deadline <= now:
                        expired.append(sock)
                        del self._live[key]
            for sock in expired:
                self.cut += 1
                try:
                    socket.socket.shutdown(sock, socket.SHUT_RDWR)
                except OSError:
                    pass

    def stop(self):
        self._halt.set()


# ---- token buckets ---------------------------------------------------------------------------------
class Buckets:
    """One token bucket per host: capacity is one hour of the rate, refilled continuously."""

    def __init__(self):
        self._lock = threading.Lock()
        self._state = {}

    def _refill(self, key, per_hour, now):
        tokens, last = self._state.get(key, (float(per_hour), now))
        tokens = min(float(per_hour), tokens + (now - last) * per_hour / 3600.0)
        return tokens

    def take_up_to(self, key, want, per_hour, now=None):
        """Take as many of `want` tokens as there are. Returns the number granted."""
        now = time.monotonic() if now is None else now
        with self._lock:
            tokens = self._refill(key, per_hour, now)
            granted = int(min(want, tokens))
            self._state[key] = (tokens - granted, now)
            return granted

    def take_all(self, key, want, per_hour, now=None):
        """All or nothing. Returns (True, 0) or (False, seconds to wait)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            tokens = self._refill(key, per_hour, now)
            if want <= tokens:
                self._state[key] = (tokens - want, now)
                return True, 0
            self._state[key] = (tokens, now)
            if want > per_hour:
                return False, 3600
            return False, max(1, min(3600, int((want - tokens) * 3600.0 / per_hour) + 1))


# ---- request parsing ---------------------------------------------------------------------------------
def read_head(rfile):
    """Read the request line and headers through the budget. Returns (method, path, headers dict)."""
    used = 0
    lines = 0

    def one():
        nonlocal used, lines
        line = rfile.readline(HEADER_MAX_BYTES - used + 1)
        if not line:
            raise HttpError("bad_request")
        used += len(line)
        if used > HEADER_MAX_BYTES:
            raise HttpError("header_too_large")
        if not line.endswith(b"\n"):
            raise HttpError("bad_request")
        lines += 1
        return line[:-1].rstrip(b"\r")

    request_line = one()
    parts = request_line.split(b" ")
    if len(parts) != 3 or parts[2] not in (b"HTTP/1.0", b"HTTP/1.1"):
        raise HttpError("bad_request")
    method = parts[0].decode("latin-1")
    target = parts[1].decode("latin-1")
    if not target.startswith("/") or not re.fullmatch(r"[A-Z]{3,10}", method):
        raise HttpError("bad_request")
    path = target.split("?", 1)[0]
    headers = {}
    while True:
        line = one()
        if not line:
            break
        if lines > HEADER_MAX_LINES:        # the request line counts as one of the 32
            raise HttpError("header_too_large")
        if line[:1] in (b" ", b"\t") or b":" not in line:
            raise HttpError("bad_request")
        name, _, value = line.partition(b":")
        name = name.decode("latin-1")
        if not _HEADER_NAME.match(name):
            raise HttpError("bad_request")
        value = value.decode("latin-1").strip()
        if any(ord(ch) < 32 and ch != "\t" or ord(ch) == 127 for ch in value):
            raise HttpError("bad_request")
        name = name.lower()
        if name in _SINGLE_HEADERS and name in headers:
            raise HttpError("bad_request")
        headers[name] = value
    if "transfer-encoding" in headers or "expect" in headers:
        raise HttpError("bad_request")
    return method, path, headers


def read_body(rfile, length):
    chunks = []
    left = length
    while left > 0:
        chunk = rfile.read(min(left, 65536))
        if not chunk:
            raise HttpError("bad_request")
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def inflate_limited(data):
    """Streaming gunzip with the 3 MiB cap (section 2, Limits)."""
    d = zlib.decompressobj(31)
    try:
        out = d.decompress(data, BODY_MAX_INFLATED + 1)
    except zlib.error:
        raise HttpError("bad_request") from None
    if len(out) > BODY_MAX_INFLATED or d.unconsumed_tail:
        raise HttpError("too_large")
    if not d.eof or d.unused_data:
        raise HttpError("bad_request")
    return out


def _no_constant(name):
    raise ValueError("not JSON: " + name)


def parse_json_object(raw):
    try:
        obj = json.loads(raw.decode("utf-8"), parse_constant=_no_constant)
    except (RecursionError, ValueError, UnicodeDecodeError):
        raise HttpError("bad_request") from None
    if not isinstance(obj, dict):
        raise HttpError("bad_schema")
    return obj


# ---- validation ----------------------------------------------------------------------------------------
def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _walk_ok(value, depth=0):
    """Depth and string-size bound for free-form JSON (details, proc, context, inventory...)."""
    if depth > 8:
        return False
    if isinstance(value, str):
        return len(value) <= 4096
    if isinstance(value, dict):
        return len(value) <= 256 and all(isinstance(k, str) and len(k) <= 128 and _walk_ok(v, depth + 1)
                                         for k, v in value.items())
    if isinstance(value, list):
        return len(value) <= 256 and all(_walk_ok(v, depth + 1) for v in value)
    return value is None or isinstance(value, (bool, int, float))


def _str_field(obj, key, maxlen, required=False, default=""):
    if key not in obj or obj[key] is None:
        if required:
            raise ValueError(key)
        return default
    v = obj[key]
    if not isinstance(v, str) or len(v) > maxlen:
        raise ValueError(key)
    return v


def validate_event(raw, index):
    """One event of a batch (client Appendix B). Returns (event dict with the client's keys, ts_ms, first_ms, last_ms).
    Raises HttpError with the index of the event."""
    if not isinstance(raw, dict):
        raise HttpError("bad_schema", index=index)
    if len(json.dumps(raw, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > EVENT_MAX_BYTES:
        raise HttpError("too_large", index=index)
    v = raw.get("v")
    if not _is_int(v):
        raise HttpError("bad_schema", index=index)
    if v < hub_common.EVENT_SCHEMA - 1:
        raise HttpError("schema_too_old", index=index)
    if v > hub_common.EVENT_SCHEMA:
        raise HttpError("bad_schema", index=index)
    try:
        ev = {"v": v}
        ev["agent_ver"] = _str_field(raw, "agent_ver", 32)
        ev["boot_id"] = _str_field(raw, "boot_id", 36)
        ev["id"] = _str_field(raw, "id", 80, required=True)
        if not hub_common.EVENT_ID_RE.match(ev["id"]):
            raise ValueError("id")
        epoch, seq = raw.get("epoch"), raw.get("seq")
        if not (_is_int(epoch) and _is_int(seq) and 0 <= epoch < 2 ** 32 and 0 <= seq < 2 ** 63):
            raise ValueError("epoch")
        if ev["id"] != "%08x:%d" % (epoch, seq):
            raise ValueError("id does not match epoch and seq")
        ev["epoch"], ev["seq"] = epoch, seq
        ts_ms = hub_common.rfc3339_to_ms(raw.get("ts"))
        ev["ts"] = raw["ts"]
        ev["sev"] = raw.get("sev")
        if ev["sev"] not in hub_common.SEVERITIES:
            raise ValueError("sev")
        ev["kind"] = _str_field(raw, "kind", 64, required=True)
        if not hub_common.KIND_RE.match(ev["kind"]):
            raise ValueError("kind")
        ev["source"] = raw.get("source")
        if ev["source"] not in hub_common.SOURCES:
            raise ValueError("source")
        ev["summary"] = _str_field(raw, "summary", hub_common.SUMMARY_MAX)
        details = raw.get("details", {})
        if details is None:
            details = {}
        if not isinstance(details, dict) or not _walk_ok(details):
            raise ValueError("details")
        if len(json.dumps(details, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > hub_common.DETAILS_MAX_BYTES:
            raise ValueError("details too big")
        for key, value in details.items():
            if isinstance(value, str):
                cap = hub_common.DETAIL_ARGS_MAX if key == "args" else hub_common.DETAIL_STR_MAX
                if len(value) > cap:
                    raise ValueError("details string")
        ev["details"] = details
        for key in ("src_ip", "dst_ip"):
            value = raw.get(key, "")
            if value is None or value == "":
                ev[key] = ""
            else:
                ev[key] = hub_common.norm_ip(value)
        ev["src_trust"] = raw.get("src_trust", "none")
        if ev["src_trust"] not in hub_common.SRC_TRUST:
            raise ValueError("src_trust")
        port = raw.get("dst_port")
        if port is not None and not (_is_int(port) and 0 <= port <= 65535):
            raise ValueError("dst_port")
        ev["dst_port"] = port
        proto = raw.get("proto")
        if proto is not None and not (isinstance(proto, str) and len(proto) <= 16 or _is_int(proto)):
            raise ValueError("proto")
        ev["proto"] = None if proto is None else str(proto)
        cid = raw.get("community_id")
        if cid is not None and not (isinstance(cid, str) and len(cid) <= 64):
            raise ValueError("community_id")
        ev["community_id"] = cid
        count = raw.get("count", 1)
        if not (_is_int(count) and 1 <= count <= 2_000_000_000):
            raise ValueError("count")
        ev["count"] = count
        first_ms = last_ms = None
        if raw.get("first_ts") is not None:
            first_ms = hub_common.rfc3339_to_ms(raw["first_ts"])
            ev["first_ts"] = raw["first_ts"]
        if raw.get("last_ts") is not None:
            last_ms = hub_common.rfc3339_to_ms(raw["last_ts"])
            ev["last_ts"] = raw["last_ts"]
        for key in ("proc",):
            if raw.get(key) is not None:
                if not isinstance(raw[key], dict) or not _walk_ok(raw[key]):
                    raise ValueError(key)
                ev[key] = raw[key]
        if raw.get("context") is not None:
            ctx = raw["context"]
            if (not isinstance(ctx, list) or len(ctx) > 20 or not _walk_ok(ctx)
                    or len(json.dumps(ctx, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > 4096):
                raise ValueError("context")
            ev["context"] = ctx
        for key in ("redacted", "truncated"):
            if raw.get(key) is not None:
                if not isinstance(raw[key], bool):
                    raise ValueError(key)
                ev[key] = raw[key]
    except (ValueError, TypeError, KeyError):
        raise HttpError("bad_schema", index=index) from None
    return ev, ts_ms, first_ms, last_ms


def validate_batch(obj):
    """The batch envelope. Returns (list of validated events, sent_at_ms). A batch is accepted or refused as a whole."""
    try:
        batch_id = _str_field(obj, "batch_id", 64, required=True)
        if not batch_id:
            raise ValueError("batch_id")
        sent_ms = hub_common.rfc3339_to_ms(obj.get("sent_at"))
    except (ValueError, TypeError):
        raise HttpError("bad_schema") from None
    events = obj.get("events")
    if not isinstance(events, list):
        raise HttpError("bad_schema")
    if len(events) > BATCH_MAX_EVENTS:
        raise HttpError("too_large")
    return [validate_event(e, i) for i, e in enumerate(events)], sent_ms


_HB_STR = {"agent_version": 32, "agent_sha256": 64, "boot_id": 36, "kernel": 128, "local_conf_sha256": 64,
           "last_apply_error": 512, "cert_not_after": 40}
_HB_INT = ("schema", "proto", "seq", "epoch")
_HB_OBJ = ("units", "nft", "conntrack", "dns_lock", "spool", "suricata_drops", "ban_counts", "mem", "inventory")
_HB_ANY = ("disk", "load", "uptime_s", "maintenance_until", "paused_until", "tetragon")


def validate_heartbeat(obj):
    """Validate the heartbeat keys of Appendix A. Unknown keys are dropped. Returns (clean dict, sent_at_ms)."""
    try:
        hb = {}
        sent_ms = hub_common.rfc3339_to_ms(obj.get("sent_at"))
        hb["sent_at"] = obj["sent_at"]
        droplet = obj.get("droplet_id")
        if not isinstance(droplet, str) or not droplet or len(droplet) > 128:
            raise ValueError("droplet_id")
        hb["droplet_id"] = droplet
        for key, cap in _HB_STR.items():
            if obj.get(key) is not None:
                if not isinstance(obj[key], str) or len(obj[key]) > cap:
                    raise ValueError(key)
                hb[key] = obj[key]
        for key in _HB_INT:
            if obj.get(key) is not None:
                if not _is_int(obj[key]) or not -2 ** 63 <= obj[key] < 2 ** 63:
                    raise ValueError(key)
                hb[key] = obj[key]
        for key in _HB_OBJ:
            if obj.get(key) is not None:
                if not isinstance(obj[key], dict) or not _walk_ok(obj[key]):
                    raise ValueError(key)
                hb[key] = obj[key]
        for key in _HB_ANY:
            if obj.get(key) is not None:
                if not _walk_ok(obj[key]):
                    raise ValueError(key)
                hb[key] = obj[key]
        if "tetragon" in hb and not (isinstance(hb["tetragon"], list) and all(isinstance(x, dict) for x in hb["tetragon"])):
            raise ValueError("tetragon")
        applied = obj.get("policy_rev_applied")
        if applied not in (None, "") and not (isinstance(applied, str) and hub_common.REV_RE.match(applied)):
            raise ValueError("policy_rev_applied")
        hb["policy_rev_applied"] = applied or None
        if obj.get("shutdown") is not None:
            if not isinstance(obj["shutdown"], bool):
                raise ValueError("shutdown")
            hb["shutdown"] = obj["shutdown"]
    except (ValueError, TypeError, KeyError):
        raise HttpError("bad_schema") from None
    return hb, sent_ms


# ---- storing events (runs in the writer) ---------------------------------------------------------------
_EVENT_SQL = ("INSERT OR IGNORE INTO events(host, event_id, received_at, ts, source, severity, hub_severity, rated_by, kind, "
              "summary, details, src_ip, src_trust, dst_ip, dst_port, proto, community_id, epoch, seq, agent_ver, count, "
              "first, last, replayed) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")


def correct_times(ts_ms, first_ms, last_ms, received_ms, skew_ms):
    """Skew correction and the 5-minute clamp (section 2). Returns (ts, first, last, replayed)."""
    shift = skew_ms if abs(skew_ms) > 30_000 else 0
    limit = received_ms + 5 * 60 * 1000

    def fix(value):
        return None if value is None else min(value + shift, limit)

    ts = fix(ts_ms)
    return ts, fix(first_ms), fix(last_ms), (received_ms - ts) > 10 * 60 * 1000


def insert_events(conn, hub, host_row, items, received_ms, skew_ms):
    """Rate, INSERT OR IGNORE and call the engine. items: [(event, ts_ms, first_ms, last_ms)].
    Returns (accepted, duplicate)."""
    import hub_engine
    import hub_rules
    inserted = []
    duplicate = 0
    for ev, ts_ms, first_ms, last_ms in items:
        try:
            hub_sev, rated_by = hub_rules.rate(conn, host_row, ev)
        except Exception:       # noqa: BLE001 - rate() never raises; this is the second line
            hub_sev, rated_by = ev["sev"], None
        if hub_sev not in hub_common.SEVERITIES:
            hub_sev, rated_by = ev["sev"], None
        ts, first, last, replayed = correct_times(ts_ms, first_ms, last_ms, received_ms, skew_ms)
        details = dict(ev["details"])
        for key in ("proc", "context", "boot_id", "redacted", "truncated"):
            if key in ev and ev[key] not in (None, ""):
                details[key] = ev[key]
        row = (host_row["uuid"], ev["id"], received_ms, ts, ev["source"], ev["sev"], hub_sev, rated_by, ev["kind"],
               ev["summary"], json.dumps(details, separators=(",", ":"), ensure_ascii=False), ev["src_ip"], ev["src_trust"],
               ev["dst_ip"], ev["dst_port"], ev["proto"], ev["community_id"], ev["epoch"], ev["seq"], ev["agent_ver"],
               ev["count"], first, last, 1 if replayed else 0)
        cur = conn.execute(_EVENT_SQL, row)
        if cur.rowcount == 1:
            d = dict(zip(("host", "event_id", "received_at", "ts", "source", "severity", "hub_severity", "rated_by", "kind",
                          "summary", "details", "src_ip", "src_trust", "dst_ip", "dst_port", "proto", "community_id", "epoch",
                          "seq", "agent_ver", "count", "first", "last", "replayed"), row))
            d["rowid"] = cur.lastrowid
            d["details"] = details
            d["replayed"] = bool(replayed)
            inserted.append(d)
        else:
            duplicate += 1
    if inserted:
        hub_db.safely(conn, hub, "engine after_insert", hub_engine.after_insert, conn, hub, host_row, inserted)
    return len(inserted), duplicate


# ---- one TLS listener ------------------------------------------------------------------------------------
class _AcceptServer(http.server.ThreadingHTTPServer):
    """Only accepts. process_request() hands the socket to the listener, which takes a slot first."""
    request_queue_size = hub_common.LISTEN_BACKLOG
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, listener):
        self.listener = listener
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, None)

    def server_bind(self):
        # HTTPServer.server_bind asks socket.getfqdn(), a DNS lookup the hub's user cannot make and that would stall
        # the listener (and the lock around it). The name is never used: set it literally.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port

    def process_request(self, request, client_address):
        self.listener.accept(request, client_address)

    def handle_error(self, request, client_address):
        pass


class Listener:
    """One listening socket with its slots, per-source cap and a routes table."""

    def __init__(self, ingest, kind, bind, port, slots, deadline_total=None):
        self.ingest = ingest
        self.kind = kind                    # "fleet" or "enroll"
        self.bind = bind
        self.want_port = port
        self.slots = threading.BoundedSemaphore(slots)
        self.deadline_total = deadline_total
        self.server = None
        self.thread = None
        self._lock = threading.Lock()
        self._per_source = {}
        self.refused_slots = 0
        self.refused_source = 0

    @property
    def port(self):
        return self.server.server_address[1] if self.server else None

    def is_open(self):
        return self.server is not None

    def open(self):
        if self.server is not None:
            return
        self.server = _AcceptServer((self.bind, self.want_port), self)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.2},
                                       name="hub-accept-" + self.kind, daemon=True)
        self.thread.start()

    def close(self):
        server, self.server = self.server, None
        if server is None:
            return
        server.shutdown()
        server.server_close()
        self.thread.join(timeout=5)
        self.thread = None

    def accept(self, raw, addr):
        """Runs on the accept thread: no handshake, no parsing, no blocking. Slot first, then the source cap."""
        if not self.slots.acquire(blocking=False):
            self.refused_slots += 1
            self._close_raw(raw)
            return
        try:
            key = hub_common.source_key(addr[0].split("%")[0])
        except ValueError:
            key = addr[0]
        with self._lock:
            if self._per_source.get(key, 0) >= hub_common.SLOTS_PER_SOURCE:
                over = True
            else:
                over = False
                self._per_source[key] = self._per_source.get(key, 0) + 1
        if over:
            self.refused_source += 1
            self.slots.release()
            self._close_raw(raw)
            return
        try:
            threading.Thread(target=self._connection, args=(raw, addr, key), name="hub-conn", daemon=True).start()
        except RuntimeError:
            self._release(key)
            self._close_raw(raw)

    @staticmethod
    def _close_raw(raw):
        try:
            raw.close()
        except OSError:
            pass

    def _release(self, key):
        with self._lock:
            n = self._per_source.get(key, 0) - 1
            if n > 0:
                self._per_source[key] = n
            else:
                self._per_source.pop(key, None)
        self.slots.release()

    def source_counts(self):
        with self._lock:
            return dict(self._per_source)

    def _connection(self, raw, addr, key):
        ing = self.ingest
        ss = None
        token = None
        try:
            ss = ing.contexts[self.kind].wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
            started = time.monotonic()
            token = ing.reaper.add(ss, started + HANDSHAKE_DEADLINE_S)
            ss.settimeout(HANDSHAKE_DEADLINE_S + 5)
            try:
                ss.do_handshake()
            except (ssl.SSLError, OSError, ValueError):
                ing.stats["handshake_failed"] += 1
                return
            t0 = time.monotonic()
            first_deadline = t0 + (self.deadline_total or HEADER_DEADLINE_S)
            ing.reaper.set(token, first_deadline)
            ss.settimeout(40)
            ing.serve_connection(self, ss, addr, token, t0)
        except (ssl.SSLError, OSError, ValueError):
            ing.stats["conn_errors"] += 1
        except Exception as e:      # noqa: BLE001 - one connection must never take the process down
            ing.stats["conn_errors"] += 1
            ing.hub.log("ERROR", "connection handler: %s" % type(e).__name__)
        finally:
            if token is not None:
                ing.reaper.remove(token)
            try:
                if ss is not None:
                    # Close at once, whatever still refers to the socket (a closure, a buffered reader).
                    try:
                        socket.socket.shutdown(ss, socket.SHUT_RDWR)
                    except OSError:
                        pass
                    ss.close()
                else:
                    raw.close()
            except OSError:
                pass
            self._release(key)


# ---- the service ---------------------------------------------------------------------------------------
def make_context(paths, fleet):
    """TLS 1.3 only, no tickets, strict X.509. The fleet context requires a client certificate from our CA."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.num_tickets = 0
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT
    if fleet:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=paths.ca_cert)
    else:
        ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(paths.server_cert, paths.server_key)
    return ctx


class Conn:
    """What a route handler sees of one request."""

    def __init__(self, ss, rfile, peer_ip, method, path, headers, clen):
        self.ss = ss
        self.rfile = rfile
        self.peer_ip = peer_ip
        self.method = method
        self.path = path
        self.headers = headers
        self.clen = clen
        self.host = None
        self.der_sha256 = None
        self.t0 = 0.0
        self.token = None


class Response:
    def __init__(self, status=200, body=b"", ctype="application/json", headers=()):
        self.status = status
        self.body = body
        self.ctype = ctype
        self.headers = list(headers)


def _json_response(obj, status=200, headers=()):
    return Response(status, json.dumps(obj, separators=(",", ":")).encode("utf-8"), "application/json", headers)


class Ingest:
    """Both listeners, the per-request certificate check and the seven routes."""

    FLEET_ROUTES = {"/v1/events": ("POST", "r_events"), "/v1/heartbeat": ("POST", "r_heartbeat"),
                    "/v1/policy": ("GET", "r_policy"), "/v1/renew": ("POST", "r_renew"),
                    "/v1/deregister": ("POST", "r_deregister")}
    ENROLL_ROUTES = {"/v1/ca": ("GET", "r_ca"), "/v1/enroll": ("POST", "r_enroll")}

    def __init__(self, hub, bind="0.0.0.0"):
        self.hub = hub
        self.bind = bind
        self.reaper = Reaper()
        self.contexts = {}
        self.fleet = None
        self.enroll = None
        self.parse_sem = threading.BoundedSemaphore(hub_common.PARSE_SLOTS)
        self.low = Buckets()
        self.high = Buckets()
        self.limiter = hub_enroll.FailureLimiter()
        self.stats = {"handshake_failed": 0, "conn_errors": 0, "requests": 0, "rejected": 0}
        self._cert_lock = threading.Lock()
        self._cert_inflight = {}
        self._ro = queue.LifoQueue()
        self._renew_last = {}
        self._ca_hits = {}
        self._reject_noted = {}
        self._enroll_checked = 0.0
        self._lock = threading.Lock()
        self._started = False

    # -- lifecycle --
    def start(self):
        paths = self.hub.paths
        self.contexts = {"fleet": make_context(paths, True), "enroll": make_context(paths, False)}
        s = self.hub.settings
        self.fleet = Listener(self, "fleet", self.bind, int(s.get("port", 8443)), hub_common.SLOTS_FLEET)
        self.enroll = Listener(self, "enroll", self.bind, int(s.get("enroll_port", 8444)), hub_common.SLOTS_ENROLL,
                               deadline_total=hub_common.ENROLL_DEADLINE_S)
        self.reaper.start()
        self.hub.writer.set_overflow_replayer(self._replay_overflow)
        self.fleet.open()
        self._started = True
        self.refresh_enroll_listener()

    def stop(self):
        for listener in (self.fleet, self.enroll):
            if listener is not None:
                listener.close()
        self.reaper.stop()
        while True:
            try:
                self._ro.get_nowait().close()
            except queue.Empty:
                break

    def reload_server_cert(self):
        paths = self.hub.paths
        for ctx in self.contexts.values():
            ctx.load_cert_chain(paths.server_cert, paths.server_key)

    def refresh_enroll_listener(self):
        """Open the enrollment listener while a token is pending (and for the replay window), close it otherwise."""
        if not self._started:
            return
        with self._lock:
            with self.ro() as conn:
                want = hub_enroll.enroll_listener_wanted(conn)
            if want and not self.enroll.is_open():
                try:
                    self.enroll.open()
                    self.hub.log("INFO", "enrollment listener open on port %s" % self.enroll.port)
                except OSError as e:
                    self.hub.log("ERROR", "enrollment listener could not open: %s" % e)
            elif not want and self.enroll.is_open():
                self.enroll.close()
                self.hub.log("INFO", "enrollment listener closed")

    def tick(self):
        """Called every second or two by the main loop."""
        self.refresh_enroll_listener()

    # -- read-only connection pool --
    class _Ro:
        def __init__(self, ingest):
            self.ingest = ingest
            self.conn = None

        def __enter__(self):
            try:
                self.conn = self.ingest._ro.get_nowait()
            except queue.Empty:
                self.conn = hub_db.open_ro(self.ingest.hub.paths.db)
            return self.conn

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None and self.ingest._ro.qsize() < RO_POOL_MAX:
                self.ingest._ro.put(self.conn)
            else:
                try:
                    self.conn.close()
                except Exception:   # noqa: BLE001
                    pass
            return False

    def ro(self):
        return Ingest._Ro(self)

    # -- one connection --
    def serve_connection(self, listener, ss, addr, token, t0):
        self.stats["requests"] += 1
        fleet = listener.kind == "fleet"
        routes = self.FLEET_ROUTES if fleet else self.ENROLL_ROUTES
        rfile = ss.makefile("rb")
        peer = _peer_ip(addr)
        cert_key = None
        drain = False
        try:
            try:
                method, path, headers = read_head(rfile)
            except HttpError as e:
                drain = True
                raise
            c = Conn(ss, rfile, peer, method, path, headers, 0)
            c.t0, c.token = t0, token
            if path not in routes:
                drain = True
                raise HttpError("not_found")
            want_method, handler_name = routes[path]
            if method != want_method:
                drain = True
                raise HttpError("method_not_allowed")
            self._check_proto(path, headers)
            if fleet:
                c.host, c.der_sha256 = self._authenticate(c, path)
                self._cert_enter(c.der_sha256)       # raises when the certificate already has 4 requests...
                cert_key = c.der_sha256              # ...and only a counted request may give its place back
            clen = self._content_length(c, path)
            c.clen = clen
            deadline = t0 + (self.enroll_total() if not fleet else (
                hub_common.REQUEST_DEADLINE_BIG_S if clen > BIG_BODY else hub_common.REQUEST_DEADLINE_S))
            self.reaper.set(token, deadline)
            response = getattr(self, handler_name)(c)
        except HttpError as e:
            response = self._error_response(e)
            if drain or e.code in ("too_large", "length_required", "header_too_large"):
                drain = True
        except hub_db.Busy:
            response = self._error_response(HttpError("busy", RETRY_BUSY_S))
        except hub_db.StorageFull:
            response = self._error_response(HttpError("storage_full", RETRY_STORAGE_S))
        except OSError:
            raise
        except Exception as e:      # noqa: BLE001 - an unexpected bug answers 503, never leaks text
            self.hub.log("ERROR", "route failed: %s (the answer was 503; details stay out of the log, they may hold client input)"
                         % type(e).__name__)
            response = self._error_response(HttpError("busy", 30))
        finally:
            if cert_key is not None:
                self._cert_leave(cert_key)
        self.reaper.set(token, time.monotonic() + PROCESS_DEADLINE_S)
        self._send(ss, response)
        if drain:
            self._drain(ss)
        try:
            rfile.close()
        except (OSError, ValueError):
            pass

    @staticmethod
    def enroll_total():
        return hub_common.ENROLL_DEADLINE_S

    def _check_proto(self, path, headers):
        raw = headers.get("x-edr-proto")
        if raw is None and path == "/v1/ca":
            return
        if raw is None or not re.fullmatch(r"[0-9]{1,4}", raw) or not PROTO_MIN <= int(raw) <= PROTO:
            raise HttpError("proto_unsupported")

    def _content_length(self, c, path):
        raw = c.headers.get("content-length")
        if c.method == "GET":
            if raw is not None and raw != "0":
                raise HttpError("bad_request")
            return 0
        if raw is None:
            raise HttpError("length_required")
        if not re.fullmatch(r"[0-9]{1,10}", raw):
            raise HttpError("bad_request")
        n = int(raw)
        if n > REQUEST_BODY_LIMITS.get(path, 0):
            raise HttpError("too_large")
        return n

    def _cert_enter(self, key):
        with self._cert_lock:
            n = self._cert_inflight.get(key, 0)
            if n >= hub_common.REQUESTS_PER_CERT:
                raise HttpError("rate_limited", 2)
            self._cert_inflight[key] = n + 1

    def _cert_leave(self, key):
        with self._cert_lock:
            n = self._cert_inflight.get(key, 0) - 1
            if n > 0:
                self._cert_inflight[key] = n
            else:
                self._cert_inflight.pop(key, None)

    def _error_response(self, err):
        status = ERRORS[err.code][0]
        headers = []
        if err.retry_after is not None:
            headers.append(("Retry-After", str(int(err.retry_after))))
        return Response(status, hub_common.error_body(err.code, err.index), "application/json", headers)

    @staticmethod
    def _send(ss, resp):
        reason = http.HTTPStatus(resp.status).phrase
        lines = ["HTTP/1.0 %d %s" % (resp.status, reason)]
        if resp.status != 304:
            lines.append("Content-Type: " + resp.ctype)
            lines.append("Content-Length: %d" % len(resp.body))
        lines += ["Cache-Control: no-store", "X-Content-Type-Options: nosniff", "Connection: close"]
        lines += ["%s: %s" % (k, v) for k, v in resp.headers]
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
        try:
            ss.sendall(head + (resp.body if resp.status != 304 else b""))
        except (OSError, ssl.SSLError):
            pass

    @staticmethod
    def _drain(ss):
        """Let the client finish writing what we did not read, so closing does not reset the reply away."""
        try:
            ss.settimeout(0.3)
            got = 0
            while got < 65536:
                chunk = ss.recv(8192)
                if not chunk:
                    break
                got += len(chunk)
        except (OSError, ssl.SSLError, ValueError):
            pass

    # -- the certificate check on every fleet request --
    def _authenticate(self, c, path):
        """Host from the certificate. Returns (host dict, der sha256). Raises HttpError 403 with the reason."""
        ss = c.ss
        der = ss.getpeercert(binary_form=True)
        if not der:
            raise HttpError("host_unknown")
        dh = hashlib.sha256(der).hexdigest()
        cert = ss.getpeercert() or {}
        try:
            expired = ssl.cert_time_to_seconds(cert["notAfter"]) <= time.time()
        except (KeyError, ValueError):
            expired = True
        if expired:
            raise HttpError("host_unknown")
        pki = self.hub.pki
        gone = pki.revoked_lookup(dh)
        with self.ro() as ro:
            row = ro.execute("SELECT * FROM hosts WHERE cert_sha256=? OR pending_cert_sha256=?", (dh, dh)).fetchone()
        if gone:
            self._note_rejected(row, _REVOKE_REASON_CODE.get(gone[2], "host_revoked"), c.peer_ip)
            raise HttpError(_REVOKE_REASON_CODE.get(gone[2], "host_revoked"))
        if row is None:
            row = self._unknown_certificate(c, der, dh, cert)
        host = dict(row)
        if host["state"] in _STATE_CODE:
            self._note_rejected(host, _STATE_CODE[host["state"]], c.peer_ip)
            raise HttpError(_STATE_CODE[host["state"]])
        if host["pending_cert_sha256"] == dh and host["cert_sha256"] != dh:
            host = dict(self.hub.writer.call(lambda conn: self._promote(conn, host["uuid"], dh)))
        if host["state"] == "orphan" and path in ("/v1/policy", "/v1/renew"):
            raise HttpError("host_orphan")
        return host, dh

    def _promote(self, conn, uuid, dh):
        """A renewed certificate is used for the first time: it becomes current, the old one is superseded."""
        row = conn.execute("SELECT * FROM hosts WHERE uuid=?", (uuid,)).fetchone()
        if row["pending_cert_sha256"] == dh:
            now = hub_common.now_ms()
            self.hub.pki.revoked_add(row["cert_serial"] or "0", row["cert_sha256"], uuid, "superseded", now)
            conn.execute("UPDATE hosts SET cert_sha256=pending_cert_sha256, cert_serial=pending_cert_serial, "
                         "cert_not_after=pending_cert_not_after, pending_cert_sha256=NULL, pending_cert_serial=NULL, "
                         "pending_cert_not_after=NULL WHERE uuid=?", (uuid,))
        return conn.execute("SELECT * FROM hosts WHERE uuid=?", (uuid,)).fetchone()

    def _unknown_certificate(self, c, der, dh, cert):
        """Signed by our CA, not in `hosts`, not in revoked.txt: after a restore this is an orphan (section 7)."""
        cn = ""
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    cn = value
        try:
            info = self.hub.pki.cert_info(ssl.DER_cert_to_PEM_cert(der))
        except ValueError:
            raise HttpError("host_unknown") from None
        host = self.hub.writer.call(lambda conn: hub_enroll.orphan_from_certificate(
            conn, self.hub, dh, cn, info["serial"], info["not_after"], c.peer_ip))
        if host is None:
            with self.ro() as ro:
                known = ro.execute("SELECT * FROM hosts WHERE uuid=?", (cn,)).fetchone()
            if known is not None and known["state"] in _STATE_CODE:
                self._note_rejected(known, _STATE_CODE[known["state"]], c.peer_ip)
                raise HttpError(_STATE_CODE[known["state"]])
            self._note_rejected(None, "host_unknown", c.peer_ip)
            raise HttpError("host_unknown")
        return host

    def _note_rejected(self, host_row, code, peer_ip):
        """A 403 is counted and alerted by the engine; at most one note per host and code every 30 s."""
        self.stats["rejected"] += 1
        key = (host_row["uuid"] if host_row is not None else peer_ip, code)
        now = time.monotonic()
        with self._lock:
            if now - self._reject_noted.get(key, -1e9) < REJECT_NOTE_EVERY_S:
                return
            if len(self._reject_noted) > 4096:
                self._reject_noted.clear()
            self._reject_noted[key] = now
        row = dict(host_row) if host_row is not None else None

        def job(conn):
            import hub_engine
            hub_engine.on_rejected(conn, self.hub, row, code, peer_ip)
        try:
            self.hub.writer.post(job)
        except hub_db.Busy:
            pass

    # -- routes: enrollment listener --
    def r_ca(self, c):
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._ca_hits.get(c.peer_ip, ()) if t > now - 60]
            if len(hits) >= CA_HITS_PER_MIN:
                raise HttpError("rate_limited", 30)
            hits.append(now)
            if len(self._ca_hits) > 4096:
                self._ca_hits.clear()
            self._ca_hits[c.peer_ip] = hits
        return Response(200, self.hub.pki.ca_pem().encode("ascii"), "application/x-pem-file")

    def r_enroll(self, c):
        if self.limiter.blocked(c.peer_ip):
            raise HttpError("rate_limited", 60)
        body = read_body(c.rfile, c.clen)
        obj = parse_json_object(body)
        now = hub_common.now_ms()
        try:
            status, payload = self.hub.writer.call(lambda conn: hub_enroll.redeem(conn, self.hub, obj, c.peer_ip, now),
                                                   timeout=20.0)
        except hub_db.StorageFull:
            raise
        if status == "err":
            if payload == "invalid_token":
                self.limiter.record(c.peer_ip)
            raise HttpError(payload)
        self.refresh_enroll_listener()
        return _json_response(payload)

    # -- routes: fleet listener --
    def _parse_slot(self):
        if not self.parse_sem.acquire(blocking=False):
            raise HttpError("busy", RETRY_BUSY_S)

    def _writer(self, fn, timeout=10.0):
        try:
            return self.hub.writer.call(fn, timeout=timeout)
        except hub_db.Busy:
            raise HttpError("busy", RETRY_BUSY_S) from None

    def r_events(self, c):
        if c.headers.get("content-encoding", "").lower() != "gzip":
            raise HttpError("bad_request")
        body = read_body(c.rfile, c.clen)       # bounded by Content-Length and the reaper; no slot is held while it arrives
        self._parse_slot()
        try:
            batch = parse_json_object(inflate_limited(body))
            items, sent_ms = validate_batch(batch)
            return self._events_reply(c, items, sent_ms)
        finally:
            self.parse_sem.release()

    def _events_reply(self, c, items, sent_ms):
        host = c.host
        uuid = host["uuid"]
        s = self.hub.settings
        # LOW and INFO: over budget the excess is counted, not stored. HIGH and CRITICAL: all or nothing.
        low_idx = [i for i, it in enumerate(items) if it[0]["sev"] in hub_common.SEVERITIES[:2]]
        high_n = sum(1 for it in items if it[0]["sev"] in _HIGH)
        dropped_low = 0
        if high_n:
            ok, wait = self.high.take_all(uuid, high_n, int(s.get("rate_high_per_hour", 1000)))
            if not ok:
                raise HttpError("rate_limited", wait)
        if low_idx:
            granted = self.low.take_up_to(uuid, len(low_idx), int(s.get("rate_low_per_hour", 15000)))
            drop = set(low_idx[granted:])
            if drop:
                dropped_low = len(drop)
                items = [it for i, it in enumerate(items) if i not in drop]
        received = hub_common.now_ms()
        skew = received - sent_ms

        def store(conn):
            row = conn.execute("SELECT * FROM hosts WHERE uuid=?", (uuid,)).fetchone()
            if row is None or row["state"] in _STATE_CODE:
                raise HttpError(_STATE_CODE.get(row["state"] if row else "", "host_unknown"))
            accepted, duplicate = insert_events(conn, self.hub, row, items, received, skew)
            conn.execute("UPDATE hosts SET skew_ms=? WHERE uuid=?", (skew, uuid))
            return accepted, duplicate

        try:
            accepted, duplicate = self._writer(store)
        except hub_db.StorageFull:
            return self._storage_full(uuid, items, received, skew, dropped_low)
        return _json_response({"accepted": accepted, "duplicate": duplicate, "dropped_low": dropped_low})

    def _storage_full(self, uuid, items, received, skew, dropped_low):
        """The cap or the disk is reached (section 3): LOW and INFO get 503; HIGH and CRITICAL go to the overflow file
        and are answered 200 only after the append."""
        keep = [it for it in items if it[0]["sev"] in _HIGH]
        if not keep:
            raise HttpError("storage_full", RETRY_STORAGE_S)
        records = [{"host": uuid, "received_at": received, "skew": skew, "event": ev, "ts": ts, "first": first, "last": last}
                   for ev, ts, first, last in keep]
        if not self.hub.writer.overflow_append(records):
            raise HttpError("storage_full", RETRY_STORAGE_S)
        alert = getattr(self.hub, "memory_alert", None)
        if alert:
            try:
                alert("CRITICAL", "hub.storage_full", "%d HIGH or CRITICAL events kept in critical-overflow.jsonl while "
                      "storage is full (host %s)" % (len(keep), uuid))
            except Exception:       # noqa: BLE001
                pass
        return _json_response({"accepted": len(keep), "duplicate": 0, "dropped_low": dropped_low + len(items) - len(keep)})

    def _replay_overflow(self, conn, records):
        """Called by the writer when space is back: store the overflow records like a normal batch."""
        by_host = {}
        for rec in records:
            by_host.setdefault((rec["host"], rec["received_at"], rec.get("skew", 0)), []).append(
                (rec["event"], rec["ts"], rec.get("first"), rec.get("last")))
        for (uuid, received, skew), items in by_host.items():
            row = conn.execute("SELECT * FROM hosts WHERE uuid=?", (uuid,)).fetchone()
            if row is not None:
                insert_events(conn, self.hub, row, items, received, skew)

    def r_heartbeat(self, c):
        body = read_body(c.rfile, c.clen)
        self._parse_slot()
        try:
            hb, sent_ms = validate_heartbeat(parse_json_object(body))
        except BaseException:
            self.parse_sem.release()
            raise
        try:
            uuid = c.host["uuid"]
            received = hub_common.now_ms()
            skew = received - sent_ms
            reply = self._writer(lambda conn: self._store_heartbeat(conn, uuid, hb, received, skew, c.peer_ip))
        finally:
            self.parse_sem.release()
        return _json_response(reply)

    def _store_heartbeat(self, conn, uuid, hb, received, skew, peer_ip):
        import hub_engine
        prev = conn.execute("SELECT * FROM hosts WHERE uuid=?", (uuid,)).fetchone()
        if prev is None or prev["state"] in _STATE_CODE:
            raise HttpError(_STATE_CODE.get(prev["state"] if prev else "", "host_unknown"))
        inventory = hb.get("inventory")
        body = {k: v for k, v in hb.items() if k != "inventory"}
        conn.execute("INSERT INTO heartbeats(host, received_at, peer_ip, body) VALUES(?,?,?,?) ON CONFLICT(host) DO UPDATE SET "
                     "received_at=excluded.received_at, peer_ip=excluded.peer_ip, body=excluded.body",
                     (uuid, received, peer_ip, json.dumps(body, separators=(",", ":"))))
        if inventory is not None:
            conn.execute("INSERT INTO inventory(host, received_at, body) VALUES(?,?,?) ON CONFLICT(host) DO UPDATE SET "
                         "received_at=excluded.received_at, body=excluded.body",
                         (uuid, received, json.dumps(inventory, separators=(",", ":"))))
        newest = conn.execute("SELECT MAX(received_at) FROM heartbeat_samples WHERE host=?", (uuid,)).fetchone()[0]
        if newest is None or received - newest >= 300_000:
            conn.execute("INSERT OR IGNORE INTO heartbeat_samples(host, received_at, body) VALUES(?,?,?)",
                         (uuid, received, json.dumps(hb, separators=(",", ":"))))
        state = "active" if prev["state"] == "pending" else prev["state"]
        peers_json = hub_enroll.add_peer(prev["peer_ips"], peer_ip) if prev["state"] in ("pending", "active") else prev["peer_ips"]
        conn.execute(
            "UPDATE hosts SET last_seen=?, first_heartbeat_at=COALESCE(first_heartbeat_at, ?), "
            "agent_version=COALESCE(?, agent_version), agent_sha256=COALESCE(?, agent_sha256), schema=COALESCE(?, schema), "
            "proto=COALESCE(?, proto), kernel=COALESCE(?, kernel), boot_id=COALESCE(?, boot_id), "
            "last_seq=COALESCE(?, last_seq), last_epoch=COALESCE(?, last_epoch), policy_rev_applied=?, skew_ms=?, "
            "state=?, state_since=CASE WHEN state=? THEN state_since ELSE ? END, peer_ips=?, "
            "shutdown_notice_at=CASE WHEN ? THEN ? ELSE shutdown_notice_at END WHERE uuid=?",
            (received, received, hb.get("agent_version"), hb.get("agent_sha256"), hb.get("schema"), hb.get("proto"),
             hb.get("kernel"), hb.get("boot_id"), hb.get("seq"), hb.get("epoch"), hb.get("policy_rev_applied"), skew,
             state, state, received, peers_json, 1 if hb.get("shutdown") else 0, received, uuid))
        host = conn.execute("SELECT * FROM hosts WHERE uuid=?", (uuid,)).fetchone()
        doc = hub_policy.build(conn, self.hub, host, received)
        hub_policy.note_revision(conn, host, doc["rev"], received)
        hub_db.safely(conn, self.hub, "engine on_heartbeat", hub_engine.on_heartbeat, conn, self.hub, prev, hb, received, peer_ip)
        return {"hub_time": int(received // 1000), "policy_rev": doc["rev"], "min_client_schema": hub_common.MIN_CLIENT_SCHEMA}

    def r_policy(self, c):
        now = hub_common.now_ms()
        host = c.host
        with self.ro() as ro:
            doc = hub_policy.build(ro, self.hub, host, now)
        rev = doc["rev"]
        if host["policy_rev"] != rev:
            uuid = host["uuid"]

            def note(conn):
                row = conn.execute("SELECT * FROM hosts WHERE uuid=?", (uuid,)).fetchone()
                if row is not None:
                    hub_policy.note_revision(conn, row, rev, now)
            try:
                self.hub.writer.post(note)
            except hub_db.Busy:
                pass
        etag = '"%s"' % rev
        match = c.headers.get("if-none-match", "")
        wanted = [t.strip() for t in match.split(",")]
        wanted = [t[2:] if t.startswith("W/") else t for t in wanted]
        if etag in wanted:
            return Response(304, b"", headers=[("ETag", etag)])
        return _json_response(doc, headers=[("ETag", etag)])

    def r_renew(self, c):
        uuid = c.host["uuid"]
        now = time.monotonic()
        with self._lock:
            if now - self._renew_last.get(uuid, -1e9) < RENEW_MIN_INTERVAL_S:
                raise HttpError("rate_limited", RENEW_MIN_INTERVAL_S)
            self._renew_last[uuid] = now
        body = read_body(c.rfile, c.clen)
        self._parse_slot()
        try:
            obj = parse_json_object(body)
            csr = obj.get("csr")
            if not isinstance(csr, str):
                raise HttpError("bad_schema")
            try:
                signed = self.hub.pki.sign_client(csr, uuid)
            except ValueError:
                raise HttpError("bad_request") from None

            def store(conn):
                row = conn.execute("SELECT * FROM hosts WHERE uuid=?", (uuid,)).fetchone()
                if row is None or row["state"] not in ("pending", "active"):
                    raise HttpError(_STATE_CODE.get(row["state"] if row else "", "host_unknown"))
                if row["pending_cert_sha256"]:
                    self.hub.pki.revoked_add(row["pending_cert_serial"] or "0", row["pending_cert_sha256"], uuid,
                                             "superseded")
                conn.execute("UPDATE hosts SET pending_cert_sha256=?, pending_cert_serial=?, pending_cert_not_after=? "
                             "WHERE uuid=?", (signed["der_sha256"], signed["serial"], signed["not_after"], uuid))
            self._writer(store)
        finally:
            self.parse_sem.release()
        return _json_response({"certificate": signed["pem"], "not_after": hub_common.ms_to_rfc3339(signed["not_after"])})

    def r_deregister(self, c):
        body = read_body(c.rfile, c.clen)
        self._parse_slot()
        try:
            obj = parse_json_object(body)
            reason = obj.get("reason")
            if reason not in ("uninstall", "rehome"):
                raise HttpError("bad_schema")
            uuid = c.host["uuid"]
            new_state = "retired" if reason == "uninstall" else "moved"
            peer = c.peer_ip

            def store(conn):
                hub_enroll.host_set_state(conn, self.hub, uuid, new_state, actor="client")
                try:
                    import hub_audit
                    hub_db.safely(conn, self.hub, "audit", lambda: hub_audit.append(
                        conn, actor_kind="client", actor_detail="addr=" + (peer or "?"), action="deregister",
                        target=uuid, outcome="ok", details={"reason": reason}))
                except ImportError:
                    pass
            try:
                self._writer(store)
            except ValueError:
                raise HttpError("host_unknown") from None
        finally:
            self.parse_sem.release()
        return _json_response({})


def _peer_ip(addr):
    try:
        return hub_common.norm_ip(addr[0].split("%")[0])
    except ValueError:
        return ""
