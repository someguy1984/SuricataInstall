#!/usr/bin/env python3
"""edr-hub-out: the hub's only outbound code (PLAN.md sections 4 and 8).

It takes alert jobs from the hub over out.sock, sends them to the channels (https only, default
certificate verification plus an optional private CA, redirects refused, 5 second timeout, Retry-After
honoured), reports each result, rewrites channels.json and, when a dead-man URL is set, pings it each minute.

    python3 -I edr_hub_out.py               run until stopped
    python3 -I edr_hub_out.py --once        take one batch, send it, ping once, exit (tests)
    python3 -I edr_hub_out.py --failed-notice   send one direct message that the hub failed (OnFailure= unit)

Secrets are read from $CREDENTIALS_DIRECTORY/secrets.json, or from $EDR_HUB_ETC_DIR/secrets.json when that
variable is unset. A secret (a URL, a topic, a token) is never printed or put in an error text.
"""

import argparse
import http.client
import ipaddress
import json
import os
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

import hub_alerts          # noqa: E402
import hub_common          # noqa: E402
import hub_rules           # noqa: E402

TIMEOUT_S = 5
REPLY_MAX = 64 * 1024
IDLE_S = 2.0
DEADMAN_EVERY_S = 60.0
RETRY_AFTER_MAX = 3600
CRITICAL_BACKOFF_MAX = 300         # a CRITICAL never waits behind a channel's back-off for longer than 5 minutes
TAKE_MAX = 20
USER_AGENT = "edr-hub-out/" + hub_common.VERSION


class SendError(Exception):
    """A failure with a fixed text that is safe to store and show (never a URL, topic or token)."""


def log(message):
    print("edr-hub-out: " + message, file=sys.stderr, flush=True)


# ---- Secrets and options ---------------------------------------------------------------------
def load_secrets(paths):
    cred = os.environ.get("CREDENTIALS_DIRECTORY")
    path = os.path.join(cred, "secrets.json") if cred else paths.secrets
    try:
        if os.path.getsize(path) > REPLY_MAX:
            return {}
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in doc.items() if isinstance(k, str) and isinstance(v, str)} if isinstance(doc, dict) else {}


def configured_channels(secrets, options):
    on = []
    if secrets.get("webhook_url"):
        on.append("webhook")
    if secrets.get("ntfy_topic") and options.get("ntfy_url"):
        on.append("ntfy")
    return on


# ---- The HTTPS client ------------------------------------------------------------------------
def parse_https_url(url):
    """(host, port, path) of an https URL. Raises SendError for anything else."""
    if not isinstance(url, str) or not url or any(ord(c) < 33 or ord(c) > 126 for c in url):
        raise SendError("the URL is not usable")
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        raise SendError("the URL must be https")
    try:
        port = u.port or 443
    except ValueError:
        raise SendError("the URL is not usable") from None
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    return u.hostname, port, path


def resolve(host, port, allow_private):
    """Resolve once and return an address to connect to. A private, loopback or link-local address
    (169.254.169.254 included) is refused: the webhook must not reach the hub's own network."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise SendError("the name did not resolve") from None
    addrs = []
    for fam, _t, _p, _c, sa in infos:
        addrs.append(sa[0])
    if not addrs:
        raise SendError("the name did not resolve")
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a.split("%")[0])
        except ValueError:
            raise SendError("the address is not usable") from None
        if not allow_private and not ip.is_global:
            raise SendError("the address is private")
    return addrs[0]


class _Pinned(http.client.HTTPSConnection):
    """Connects to the address we checked (no second DNS lookup), verifies the certificate against the host name."""

    def __init__(self, host, port, ip, context, timeout):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self):
        raw = socket.create_connection((self._ip, self.port), self.timeout)
        self._raw = raw                                   # so the deadline can cut the connection while it handshakes
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise

    def cut(self):
        """Close the connection from another thread: whatever is blocked on it returns at once."""
        for s in (self.sock, getattr(self, "_raw", None)):
            try:
                if s is not None:
                    socket.socket.shutdown(s, socket.SHUT_RDWR)       # the base method: it leaves the TLS object alone
            except (OSError, ValueError):
                pass


def make_context(ca_pem):
    ctx = ssl.create_default_context()                 # verification and host name check on; no off switch
    if ca_pem:
        try:
            ctx.load_verify_locations(cadata=ca_pem)
        except (ssl.SSLError, ValueError):
            raise SendError("the private CA is not usable") from None
    return ctx


def _retry_after(value):
    if value and value.strip().isdigit():
        return min(int(value.strip()), RETRY_AFTER_MAX)
    return None


def http_send(method, url, headers, body, ctx, allow_private=False):
    """One request. Returns (ok, error_text, retry_after_s). Never raises; texts are fixed.

    TIMEOUT_S is a wall-clock limit for the whole exchange (connect, handshake, request, status line and headers), not a
    per-read timeout: a server that drips one byte a second is cut at the deadline. Only the status line and the headers
    are read; the reply body is never read, so it cannot hold the worker either.
    """
    fired = threading.Event()
    conn = None
    timer = None
    try:
        host, port, path = parse_https_url(url)
        ip = resolve(host, port, allow_private)
        conn = _Pinned(host, port, ip, ctx, TIMEOUT_S)

        def deadline():
            fired.set()
            conn.cut()
        timer = threading.Timer(TIMEOUT_S, deadline)
        timer.daemon = True
        timer.start()
        h = {"User-Agent": USER_AGENT}
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        status = resp.status
        ra = _retry_after(resp.getheader("Retry-After"))
    except SendError as exc:
        return False, str(exc), None
    except ssl.SSLCertVerificationError:
        return False, ("timeout" if fired.is_set() else "TLS certificate not trusted"), None
    except ssl.SSLError:
        return False, ("timeout" if fired.is_set() else "TLS error"), None
    except (socket.timeout, TimeoutError):
        return False, "timeout", None
    except ConnectionRefusedError:
        return False, "connection refused", None
    except (http.client.HTTPException, ValueError):
        return False, ("timeout" if fired.is_set() else "bad HTTP reply"), None
    except OSError:
        return False, ("timeout" if fired.is_set() else "network error"), None
    finally:
        if timer is not None:
            timer.cancel()
        if conn is not None:
            conn.close()
    if 200 <= status < 300:
        return True, "", None
    if 300 <= status < 400:
        return False, "redirect refused", None
    return False, "HTTP %d" % status, ra


# ---- The out.sock client ---------------------------------------------------------------------
def sock_call(path, cmd, args):
    """One request line, one reply line (the wire format hub_ctl.py serves). Returns the reply's result or raises SendError."""
    request = json.dumps({"cmd": cmd, "args": args, "actor": {}}, separators=(",", ":")).encode() + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT_S)
        try:
            s.connect(path)
            s.sendall(request)
            buf = b""
            while b"\n" not in buf and len(buf) <= REPLY_MAX:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            raise SendError("the hub socket is not reachable") from None
    try:
        reply = json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise SendError("the hub reply is not JSON") from None
    if not isinstance(reply, dict) or not reply.get("ok"):
        raise SendError("the hub refused the request")
    return reply.get("result") or {}


# ---- The worker ------------------------------------------------------------------------------
class Worker:
    def __init__(self, paths, allow_private=False, clock=time.monotonic):
        self.paths = paths
        self.allow_private = allow_private
        self.clock = clock
        self.blocked = {}              # channel -> (monotonic time until which Retry-After holds it, when the hold began)
        self.status = {}               # channel -> {"last_ok", "last_fail", "last_error"}
        self._written = None
        self._last_ping = None
        self.stop = False

    # sending
    def _request_for(self, channel, payload, secrets, options):
        req = hub_alerts.render(channel, payload)               # ValueError for a channel P2 does not send to
        headers = dict(req["headers"])
        body = req["body"]
        if req["url_key"] == "ntfy_url":
            url = options.get("ntfy_url", "")
            topic = secrets.get("ntfy_topic", "")
            if not url or not topic:
                raise SendError("the channel is not configured")
            doc = json.loads(body.decode("ascii"))
            doc["topic"] = topic
            body = json.dumps(doc, ensure_ascii=True).encode("ascii")
            if secrets.get("ntfy_token"):
                headers["Authorization"] = "Bearer " + secrets["ntfy_token"]
        else:
            url = secrets.get(req["url_key"], "")
            if not url:
                raise SendError("the channel is not configured")
        return url, headers, body

    def send_item(self, item, secrets, options, ctx):
        """(ok, error, retry_after) for one job."""
        channel = item.get("channel")
        critical = item.get("severity") == "CRITICAL" or (isinstance(item.get("payload"), dict) and item["payload"].get("severity") == "CRITICAL")
        hold = self.blocked.get(channel)
        if hold is not None:
            held, began = hold
            if critical:
                held = min(held, began + CRITICAL_BACKOFF_MAX)
            if self.clock() < held:
                return False, "held by Retry-After", max(1, int(held - self.clock()))
        payload = item.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except ValueError:
                return False, "the payload is not JSON", None
        try:
            url, headers, body = self._request_for(channel, payload, secrets, options)
        except SendError as exc:
            return False, str(exc), None
        except (ValueError, KeyError, TypeError):
            return False, "the channel is not supported", None
        ok, err, ra = http_send("POST", url, headers, body, ctx, self.allow_private)
        if ra:
            self.blocked[channel] = (self.clock() + ra, self.clock())
            if critical:
                ra = min(ra, CRITICAL_BACKOFF_MAX)          # what the hub is told to wait before the next try
        return ok, err, ra

    def record(self, channel, ok, error):
        st = self.status.setdefault(channel, {"last_ok": None, "last_fail": None, "last_error": ""})
        if ok:
            st["last_ok"] = hub_common.now_ms()
            st["last_error"] = ""
        else:
            st["last_fail"] = hub_common.now_ms()
            st["last_error"] = error

    def write_channels(self, secrets, options):
        """Rewrite channels.json (non-secret options and the channel list) when it changed, for the OnFailure unit."""
        doc = {"channels": configured_channels(secrets, options), "options": options, "status": self.status}
        text = json.dumps(doc, sort_keys=True, indent=1) + "\n"
        if text == self._written:
            return
        try:
            os.makedirs(self.paths.out_state_dir, mode=0o700, exist_ok=True)
            full = dict(doc, written_at=hub_common.now_ms())
            hub_common.atomic_write(self.paths.channels, json.dumps(full, sort_keys=True, indent=1) + "\n", 0o600)
            self._written = text
        except OSError:
            log("could not write channels.json")

    # one round
    def take_and_send(self):
        """Take up to 20 jobs, send them, report each result. Returns (jobs sent, deadman flag)."""
        secrets = load_secrets(self.paths)
        result = sock_call(self.paths.out_sock, "outbox.take", {"max": TAKE_MAX})
        items = result.get("items") if isinstance(result.get("items"), list) else []
        options = result.get("options") if isinstance(result.get("options"), dict) else {}
        options = {"ntfy_url": str(options.get("ntfy_url") or ""), "webhook_ca_pem": options.get("webhook_ca_pem") or None}
        self.write_channels(secrets, options)
        ctx = None
        for item in items:
            if not isinstance(item, dict) or "id" not in item:
                continue
            try:
                if ctx is None:
                    ctx = make_context(options["webhook_ca_pem"])
                ok, err, ra = self.send_item(item, secrets, options, ctx)
            except SendError as exc:
                ok, err, ra = False, str(exc), None
            except Exception as exc:                     # one bad job must not stop the rest
                ok, err, ra = False, "internal error (%s)" % type(exc).__name__, None
            self.record(item.get("channel"), ok, err)
            try:
                sock_call(self.paths.out_sock, "outbox.result",
                          {"id": item["id"], "ok": bool(ok), "error": err[:200], "retry_after": ra})
            except SendError as exc:
                log("could not report a result: %s" % exc)
        if items:
            self.write_channels(secrets, options)
        return len(items), bool(result.get("deadman"))

    def deadman_ping(self, secrets=None):
        secrets = secrets if secrets is not None else load_secrets(self.paths)
        url = secrets.get("deadman_url", "")
        if not url:
            return None
        try:
            ctx = make_context(None)
        except SendError:
            return False
        ok, err, _ra = http_send("GET", url, {}, None, ctx, self.allow_private)
        if not ok:
            log("dead-man ping failed: %s" % err)
        return ok

    def maybe_ping(self, deadman):
        now = self.clock()
        if deadman and (self._last_ping is None or now - self._last_ping >= DEADMAN_EVERY_S):
            self._last_ping = now
            self.deadman_ping()

    def run(self, once=False):
        if once:
            n, deadman = self.take_and_send()
            if deadman:
                self.deadman_ping()
            return 0
        deadman = False
        while not self.stop:
            try:
                n, deadman = self.take_and_send()
            except SendError as exc:
                log(str(exc))
                n = 0
            self.maybe_ping(deadman)
            if n == 0:
                time.sleep(IDLE_S)
        return 0


# ---- OnFailure mode --------------------------------------------------------------------------
def failed_notice(paths, allow_private=False):
    """Send one direct message that edr-hub.service failed, to every channel that is set up.
    Reads the options from channels.json, which the running worker rewrote. Returns the exit code."""
    secrets = load_secrets(paths)
    try:
        with open(paths.channels, encoding="utf-8") as f:
            doc = json.load(f)
        options = doc.get("options", {}) if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        options = {}
    options = {"ntfy_url": str(options.get("ntfy_url") or ""), "webhook_ca_pem": options.get("webhook_ca_pem") or None}
    channels = configured_channels(secrets, options)
    if not channels:
        log("no channel is set up: nothing sent")
        return 1
    info = hub_rules.describe("hub.failed")
    payload = {"title": "edr-hub.service failed several times in a row", "severity": "HIGH", "host": "", "host_ip": "",
               "kind": "hub.failed", "meaning": info["meaning"], "next_step": info["next_step"], "incident_id": None,
               "commands": ["systemctl status edr-hub", "journalctl --namespace edr-hub -u edr-hub -n 50"],
               "fields": {}, "ts": hub_common.now_ms(), "test": False}
    worker = Worker(paths, allow_private)
    try:
        ctx = make_context(options["webhook_ca_pem"])
    except SendError as exc:
        log(str(exc))
        return 1
    sent = 0
    for ch in channels:
        ok, err, _ra = worker.send_item({"channel": ch, "payload": payload}, secrets, options, ctx)
        log("%s: %s" % (ch, "sent" if ok else err))
        sent += 1 if ok else 0
    return 0 if sent else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="edr_hub_out.py", description="edr-hub outbound worker")
    ap.add_argument("--once", action="store_true", help="take one batch, send it, ping once, exit")
    ap.add_argument("--failed-notice", action="store_true", help="send one message that the hub failed, then exit")
    ap.add_argument("--allow-private", action="store_true",
                    help="allow private and loopback destinations (tests and a self-hosted webhook on a private network only)")
    args = ap.parse_args(argv)
    paths = hub_common.Paths()
    if args.failed_notice:
        return failed_notice(paths, args.allow_private)
    worker = Worker(paths, args.allow_private)

    def on_term(_signo, _frame):
        worker.stop = True
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    try:
        return worker.run(once=args.once)
    except SendError as exc:
        log(str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
