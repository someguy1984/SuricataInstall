"""Mutual-TLS HTTP/1.0 client for the hub (client PLAN 4.5 Transport; hub Appendix A).

One request per connection. TLS 1.3 only, the hub CA pinned, the hub address checked against
the certificate's IP SAN, VERIFY_X509_STRICT set explicitly. Replies are bounded: 16 MiB of
body, 16 KiB of headers, 30 s in all. Every row of the hub's status table is turned into an
Outcome here, so the callers only look at `outcome.action`.
"""

import gzip
import json
import os
import random
import socket
import ssl
import time
import uuid

from .spool import rfc3339

PROTO = "1"
AGENT_VERSION = "0.1.0"
MAX_BODY = 16 * 1024 * 1024
MAX_HEADERS = 16 * 1024
MAX_HEADER_LINES = 100
TOTAL_S = 30.0
RETRY_AFTER_MAX = 3600
HOLD_S = 3600.0                      # "retry hourly"
TLS_FAILS_AS_403 = 3
EVENTS_MAX_GZ = 1024 * 1024
EVENTS_MAX_RAW = 3 * 1024 * 1024
EVENTS_MAX_N = 500

# Outcome actions
OK = "ok"                    # 200: use the reply
UNCHANGED = "unchanged"      # 304
SPLIT = "split"              # 400/413 on events: split the batch once
REJECT = "reject"            # 400/413 on a single event: it goes to spool/rejected/
HOLD = "hold"                # 422, 426: keep spooling, retry hourly
STOP = "stop"                # 401/409 on enroll: stop and tell the operator
ORPHAN = "orphan"            # 403 host_orphan on policy/renew: carry on, retry hourly
FORBIDDEN = "forbidden"      # other 403, or three TLS failures in a row: stop sending, retry hourly
WAIT = "wait"                # 429/503 with Retry-After
LOG_RETRY = "log_retry"      # other 4xx: keep the previous state, retry at the normal interval
BACKOFF = "backoff"          # 5xx, timeout, network error: exponential backoff with full jitter


class TransportError(Exception):
    """kind: network | timeout | tls | protocol"""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


class Reply:
    def __init__(self, status, reason, headers, body):
        self.status = status
        self.reason = reason
        self.headers = headers          # lower-case name -> value
        self.body = body

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None

    def error_code(self):
        d = self.json()
        if isinstance(d, dict) and isinstance(d.get("code"), str):
            return d["code"][:64]
        return ""

    def retry_after(self):
        v = self.headers.get("retry-after", "")
        if v.isdigit() and len(v) <= 9:
            return min(int(v), RETRY_AFTER_MAX)
        return None


class Outcome:
    __slots__ = ("action", "status", "code", "wait", "note")

    def __init__(self, action, status=0, code="", wait=None, note=""):
        self.action = action
        self.status = status
        self.code = code
        self.wait = wait
        self.note = note

    def __repr__(self):
        return "Outcome(%s status=%s code=%r wait=%r)" % (self.action, self.status, self.code, self.wait)


# ---- TLS contexts ---------------------------------------------------------------------------

def make_context(ca_path=None, cert_path=None, key_path=None, verify=True):
    """verify=True: the hub CA pinned, IP SAN checked, strict. verify=False is only for the
    one GET /v1/ca of enrollment, whose answer is then checked against the token's hash."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.options |= getattr(ssl, "OP_NO_COMPRESSION", 0)
    if verify:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_verify_locations(cafile=str(ca_path))
        ctx.verify_flags |= ssl.VERIFY_X509_STRICT
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if cert_path:
        ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx


# ---- One request ----------------------------------------------------------------------------

def _host_header(ip, port):
    return ("[%s]:%d" % (ip, port)) if ":" in ip else ("%s:%d" % (ip, port))


def _check_header(name, value):
    if any(c in name + value for c in "\r\n\x00"):
        raise ValueError("bad header")


def request(ip, port, method, path, *, ctx, body=b"", headers=None, total_s=TOTAL_S,
            max_body=MAX_BODY, max_headers=MAX_HEADERS):
    """Send one HTTP/1.0 request, return a Reply. Raises TransportError."""
    deadline = time.monotonic() + total_s

    def left():
        r = deadline - time.monotonic()
        if r <= 0:
            raise TransportError("timeout", "deadline passed")
        return r

    head = ["%s %s HTTP/1.0" % (method, path), "Host: " + _host_header(ip, port),
            "X-EDR-Proto: " + PROTO, "User-Agent: edr-agent/" + AGENT_VERSION, "Connection: close"]
    for k, v in (headers or {}).items():
        _check_header(k, v)
        head.append("%s: %s" % (k, v))
    if body or method == "POST":
        head.append("Content-Length: %d" % len(body))
    data = ("\r\n".join(head) + "\r\n\r\n").encode("ascii") + body

    sock = None
    try:
        try:
            sock = socket.create_connection((ip, port), timeout=min(10.0, left()))
            sock.settimeout(left())
            tls = ctx.wrap_socket(sock, server_hostname=ip)
            sock = tls
        except ssl.SSLError as exc:
            raise TransportError("tls", "TLS handshake failed: %s" % exc.__class__.__name__) from None
        except (socket.timeout, TimeoutError):
            raise TransportError("timeout", "connect timed out") from None
        except OSError as exc:
            raise TransportError("network", "connect failed: %s" % (exc.strerror or exc.__class__.__name__)) from None

        first = True
        try:
            sock.settimeout(left())
            sock.sendall(data)
            buf = b""
            while b"\r\n\r\n" not in buf:
                if len(buf) > max_headers:
                    raise TransportError("protocol", "reply headers over %d bytes" % max_headers)
                sock.settimeout(left())
                chunk = sock.recv(4096)
                if not chunk:
                    if first:
                        # the handshake succeeded and the peer closed without a byte: in TLS 1.3 that is how a
                        # refused client certificate can look (hub Appendix A: no status, seen on the first read)
                        raise TransportError("tls", "connection closed on the first read")
                    raise TransportError("network", "connection closed before the reply headers")
                buf += chunk
                first = False
        except ssl.SSLError as exc:
            # TLS 1.3: a bad client certificate shows up on the first read, with no status
            kind = "tls" if first else "protocol"
            raise TransportError(kind, "TLS error on %s: %s" % ("first read" if first else "read", exc.__class__.__name__)) from None
        except (socket.timeout, TimeoutError):
            raise TransportError("timeout", "reply timed out") from None
        except TransportError:
            raise
        except OSError as exc:
            # A reset or broken pipe before any reply byte, after a completed handshake, is the same thing as
            # the alert: the peer refused us after the handshake. (Before the handshake it stays "network".)
            kind = "tls" if first else "network"
            raise TransportError(kind, "I/O error on %s: %s" % ("first read" if first else "read", exc.strerror or exc.__class__.__name__)) from None

        head_raw, _, rest = buf.partition(b"\r\n\r\n")
        if len(head_raw) > max_headers:
            raise TransportError("protocol", "reply headers over %d bytes" % max_headers)
        lines = head_raw.decode("latin-1").split("\r\n")
        if len(lines) > MAX_HEADER_LINES:
            raise TransportError("protocol", "too many reply headers")
        parts = lines[0].split(" ", 2)
        if len(parts) < 2 or not parts[0].startswith("HTTP/1.") or not (parts[1].isdigit() and len(parts[1]) == 3):
            raise TransportError("protocol", "bad status line")
        status = int(parts[1])
        reason = parts[2][:64] if len(parts) > 2 else ""
        hdrs = {}
        for line in lines[1:]:
            k, sep, v = line.partition(":")
            if not sep or not k or k != k.strip():
                raise TransportError("protocol", "bad reply header")
            k = k.lower()
            v = v.strip()
            if k in hdrs and k in ("content-length", "transfer-encoding") and hdrs[k] != v:
                raise TransportError("protocol", "conflicting %s" % k)
            hdrs[k] = v
        if "transfer-encoding" in hdrs:
            raise TransportError("protocol", "unexpected Transfer-Encoding")
        if status in (204, 304) or 100 <= status < 200:
            return Reply(status, reason, hdrs, b"")
        want = None
        if "content-length" in hdrs:
            cl = hdrs["content-length"]
            if not cl.isdigit() or len(cl) > 10:
                raise TransportError("protocol", "bad Content-Length")
            want = int(cl)
            if want > max_body:
                raise TransportError("protocol", "reply body over %d bytes" % max_body)
        chunks = [rest]
        got = len(rest)
        if got > max_body:
            raise TransportError("protocol", "reply body over %d bytes" % max_body)
        try:
            while want is None or got < want:
                sock.settimeout(left())
                chunk = sock.recv(min(65536, (max_body + 1 - got) if want is None else (want - got)))
                if not chunk:
                    break
                chunks.append(chunk)
                got += len(chunk)
                if got > max_body:
                    raise TransportError("protocol", "reply body over %d bytes" % max_body)
        except ssl.SSLError as exc:
            raise TransportError("protocol", "TLS error reading the body: %s" % exc.__class__.__name__) from None
        except (socket.timeout, TimeoutError):
            raise TransportError("timeout", "reply body timed out") from None
        except TransportError:
            raise
        except OSError as exc:
            raise TransportError("network", "I/O error: %s" % (exc.strerror or exc.__class__.__name__)) from None
        body_b = b"".join(chunks)
        if want is not None:
            if len(body_b) < want:
                raise TransportError("protocol", "reply body cut short")
            body_b = body_b[:want]
        return Reply(status, reason, hdrs, body_b)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---- The status table ---------------------------------------------------------------------

def interpret(route, reply, nevents=None):
    """Turn a hub reply into an Outcome (hub Appendix A, What the client does for each status).

    route: events | heartbeat | policy | renew | enroll | ca | deregister"""
    st = reply.status
    code = reply.error_code() if st >= 400 else ""
    if st == 200:
        return Outcome(OK, st)
    if st == 304:
        return Outcome(UNCHANGED, st)
    if st in (400, 413):
        if route == "events":
            return Outcome(REJECT if (nevents is not None and nevents <= 1) else SPLIT, st, code)
        if route in ("enroll", "ca"):
            return Outcome(STOP, st, code, note="the hub refused the request")
        return Outcome(LOG_RETRY, st, code)
    if st in (411, 414, 431):
        return Outcome(LOG_RETRY, st, code)
    if st == 401:
        if route == "enroll":
            return Outcome(STOP, st, code or "invalid_token", note="token refused: make a new token")
        return Outcome(LOG_RETRY, st, code)
    if st == 403:
        if code == "host_orphan" and route in ("policy", "renew"):
            return Outcome(ORPHAN, st, code, HOLD_S)
        return Outcome(FORBIDDEN, st, code or "forbidden", HOLD_S)
    if st == 409:
        if route == "enroll":
            return Outcome(STOP, st, code or "host_exists", note="make a token --for HOST")
        return Outcome(LOG_RETRY, st, code)
    if st == 422:
        return Outcome(HOLD, st, code or "schema_too_old", HOLD_S)
    if st == 426:
        return Outcome(HOLD, st, code or "proto_unsupported", HOLD_S)
    if st in (429, 503):
        ra = reply.retry_after()
        if ra is not None:
            return Outcome(WAIT, st, code, float(ra))
        return Outcome(BACKOFF, st, code)
    if 500 <= st < 600:
        return Outcome(BACKOFF, st, code)
    if 400 <= st < 500:
        return Outcome(LOG_RETRY, st, code)
    return Outcome(BACKOFF, st, code)


def error_outcome(exc):
    """Outcome for a TransportError that is not yet counted (see HubClient)."""
    return Outcome(BACKOFF, 0, exc.kind, note=str(exc))


class Backoff:
    """Exponential backoff with full jitter: uniform(0, min(cap, base * 2**n))."""

    def __init__(self, cap, base=1.0, rng=None, floor=0.1):
        self.cap = float(cap)
        self.base = float(base)
        self.rng = rng or random.Random()
        self.floor = floor
        self.n = 0

    def failure(self, cap=None):
        """The next wait. `cap` lowers the cap for this one draw (the count still advances; the draw is still uniform)."""
        ceiling = min(self.cap if cap is None else min(self.cap, float(cap)), self.base * (2 ** min(self.n, 30)))
        self.n += 1
        return max(min(self.floor, ceiling), self.rng.uniform(0, ceiling))

    def reset(self):
        self.n = 0


# ---- Events body --------------------------------------------------------------------------

def build_events_body(events, batch_id=None, sent_at=None):
    """gzip of {"batch_id", "sent_at", "events"}; at most 500 events, 3 MiB raw, 1 MiB gzipped.

    Returns (body, used, batch_id). `used` may be below len(events) when the size limits cut
    the batch; 0 means even one event does not fit."""
    batch_id = batch_id or str(uuid.uuid4())
    events = list(events[:EVENTS_MAX_N])
    n = len(events)
    while n > 0:
        raw = json.dumps({"batch_id": batch_id, "sent_at": sent_at or rfc3339(), "events": events[:n]},
                         separators=(",", ":")).encode("utf-8")
        if len(raw) <= EVENTS_MAX_RAW:
            gz = gzip.compress(raw, 6, mtime=0)
            if len(gz) <= EVENTS_MAX_GZ:
                return gz, n, batch_id
        n = n // 2 if n > 1 else 0
    return b"", 0, batch_id


def json_body(obj):
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


# ---- The client used by the uplink ---------------------------------------------------------

class Target:
    """What identity.load_current() hands over for one connection."""

    def __init__(self, addresses, port, ca, cert, key, gen=""):
        self.addresses = list(addresses)
        self.port = int(port)
        self.ca = ca
        self.cert = cert
        self.key = key
        self.gen = gen


class HubClient:
    """Resolves the identity once per connection, tries the hub addresses in order, counts
    TLS failures in a row (three count as a 403) and returns (reply, outcome)."""

    def __init__(self, target_fn, *, requester=None, ctx_factory=None):
        self.target_fn = target_fn
        self.requester = requester or request
        self.ctx_factory = ctx_factory or make_context
        self.tls_fails = 0
        self.preferred = 0
        self.last_gen = ""
        self.last_error = ""
        self.last_code = ""
        self._ctx_key = None
        self._ctx = None

    def _context(self, t):
        try:
            key = (t.ca, t.cert, t.key, os.stat(t.cert).st_mtime_ns, os.stat(t.key).st_mtime_ns, os.stat(t.ca).st_mtime_ns)
        except OSError as exc:
            raise TransportError("network", "identity files unreadable: %s" % (exc.strerror or "")) from None
        if self._ctx_key != key:
            try:
                self._ctx = self.ctx_factory(t.ca, t.cert, t.key, True)
            except (ssl.SSLError, OSError, ValueError) as exc:
                raise TransportError("protocol", "cannot load the identity: %s" % exc.__class__.__name__) from None
            self._ctx_key = key
        return self._ctx

    def call(self, route, method, path, *, body=b"", headers=None, total_s=TOTAL_S, nevents=None):
        t = self.target_fn()
        if t is None or not t.addresses:
            return None, Outcome(BACKOFF, 0, "not_enrolled", note="not enrolled")
        self.last_gen = t.gen
        try:
            ctx = self._context(t)
        except TransportError as exc:
            self.last_error = str(exc)
            return None, error_outcome(exc)
        n = len(t.addresses)
        last = None
        for i in range(n):
            idx = (self.preferred + i) % n
            try:
                reply = self.requester(t.addresses[idx], t.port, method, path, ctx=ctx, body=body,
                                       headers=headers, total_s=total_s)
            except TransportError as exc:
                last = exc
                if exc.kind in ("network", "timeout"):
                    continue                              # try the next hub address
                break
            else:
                self.preferred = idx
                self.tls_fails = 0
                oc = interpret(route, reply, nevents)
                self.last_code = oc.code
                self.last_error = "" if oc.action in (OK, UNCHANGED) else "%s %s" % (reply.status, oc.code)
                return reply, oc
        if last.kind == "tls":
            self.tls_fails += 1
            self.last_error = str(last)
            if self.tls_fails >= TLS_FAILS_AS_403:
                self.last_code = "tls_rejected"
                return None, Outcome(FORBIDDEN, 0, "tls_rejected", HOLD_S, str(last))
        else:
            self.tls_fails = 0
            self.last_error = str(last)
        self.last_code = last.kind
        return None, error_outcome(last)
