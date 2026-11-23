"""The three local sockets of the hub and every verb on them (PLAN.md sections 5 and 6).

    ctl.sock   root CLI: every verb
    ui.sock    dashboard: login.redeem, host.mark-moved, host.maintenance
    out.sock   edr-hub-out: outbox.take, outbox.result, feed.job, feed.result

One request line and one reply line of JSON, at most 64 KiB, a 5 s deadline, 8 connections at once.
A peer is checked with SO_PEERCRED. Every verb that changes anything runs inside one
`hub.writer.call`, so the change, its audit row and its admin notice commit together.

Reply codes and exit numbers (the CLI exits with `exit`, PLAN section 17):
    invalid  the request was refused before anything changed (bad value, unknown host)   exit 3
    denied   the peer or the verb is not allowed                                         exit 3
    refused  a rule says no (never-ban overlap, secret over the socket)                  exit 3
    error    the hub could not do it (busy, storage full, internal)                      exit 2
"""

import hashlib
import ipaddress
import json
import os
import pwd
import re
import secrets
import socket
import struct
import threading
import time
from collections import deque

import hub_audit
import hub_common
from hub_common import clean, now_ms

TIMEOUT_S = hub_common.SOCK_TIMEOUT_S
LINE_MAX = hub_common.SOCK_LINE_MAX
MAX_CONN = hub_common.SOCK_MAX_CONN

INGEST_TICK_S = 10                         # how often pending-audit.jsonl is looked at (see _ingest_loop)
INGEST_IDLE_S = 60                         # with no new line, the folds and the prune still run this often
LOGIN_CODE_TTL_MS = 10 * 60 * 1000
LOGIN_FAIL_ALERT = 5                       # more than this many failed logins a minute raises a notice
MAINTENANCE_MAX_S = 2 * 3600
TOKEN_TTL_MAX_S = 24 * 3600
TOKENS_PER_CALL = 100
NEVER_BAN_MIN_PREFIX = {4: 16, 6: 32}      # a wider entry would switch banning off for a whole region
OUTBOX_LEASE_MS = 120_000
OUTBOX_LADDER_MIN = (1, 5, 15, 60)
OUTBOX_GIVE_UP_MS = 24 * 3600 * 1000
WEBHOOK_CA_MAX = 64 * 1024

CTL_VERBS = frozenset({
    "host.revoke", "host.retire", "host.mark-moved", "host.adopt", "host.maintenance",
    "incident.resolve",
    "token.create", "token.list", "token.revoke",
    "never-ban.add", "never-ban.remove", "never-ban.list",
    "settings.set", "settings.secret-changed", "alert.test",
    "ui-login.mint", "audit.verify", "reissue-cert", "agent-hash.add", "status",
})
UI_VERBS = frozenset({"login.redeem", "host.mark-moved", "host.maintenance"})
OUT_VERBS = frozenset({"outbox.take", "outbox.result", "feed.job", "feed.result"})
SOCKET_VERBS = {"ctl": CTL_VERBS, "ui": UI_VERBS, "out": OUT_VERBS}
ALL_VERBS = CTL_VERBS | UI_VERBS | OUT_VERBS
SOCKET_KIND = {"ctl": "cli", "ui": "ui", "out": "system"}
SOCKET_USER = {"ctl": None, "ui": "edr-hub-ui", "out": "edr-hub-out"}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}\Z")
_SESSION_RE = re.compile(r"^[0-9a-f]{8}\Z")


# ---- late imports, so tests can replace the other agents' modules -------------------------------
def _alerts():
    import hub_alerts
    return hub_alerts


def _enroll():
    import hub_enroll
    return hub_enroll


# ---- errors a verb raises -----------------------------------------------------------------------
class Reject(Exception):
    code = "invalid"
    exit = 3

    def __init__(self, text):
        super().__init__(text)
        self.text = clean(text, 120)


class Invalid(Reject):
    code = "invalid"


class Denied(Reject):
    code = "denied"


class Refused(Reject):
    code = "refused"


class Failed(Reject):
    code = "error"
    exit = 2


class Ctx:
    """Who is asking, as the audit rows and notices name them."""

    def __init__(self, sock, pid, uid, request_actor):
        self.sock = sock
        self.kind = SOCKET_KIND[sock]
        self.pid = pid
        self.uid = uid
        actor = request_actor if isinstance(request_actor, dict) else {}
        if sock == "ui":
            session = str(actor.get("session", ""))
            session = session if _SESSION_RE.match(session) else "unknown"
            try:
                addr = hub_common.norm_ip(str(actor.get("addr", "")))
            except ValueError:
                addr = "unknown"
            self.session, self.addr = session, addr
            self.detail = "ui session=%s addr=%s" % (session, addr)
            self.short = "ui:" + session
        elif sock == "ctl":
            loginuid = str(actor.get("loginuid", ""))
            loginuid = loginuid if loginuid.isdigit() and loginuid.isascii() and len(loginuid) <= 10 else "unknown"
            sudo = str(actor.get("sudo_user", ""))
            sudo = sudo if re.match(r"^[A-Za-z0-9._-]{1,32}\Z", sudo) else ""
            self.detail = "uid=%d pid=%d loginuid=%s" % (uid, pid, loginuid) + (" sudo=%s" % sudo if sudo else "")
            self.short = sudo or ("uid" + loginuid if loginuid != "unknown" else "uid%d" % uid)
        else:
            self.detail = "uid=%d pid=%d" % (uid, pid)
            self.short = "out"


def _uid_of(user):
    try:
        return pwd.getpwnam(user).pw_uid
    except KeyError:
        return None


def _is_busy(exc):
    return type(exc).__name__ in ("Busy", "StorageFull")


class Sockets:
    """ctl.sock, ui.sock and out.sock for one Hub."""

    def __init__(self, hub):
        self.hub = hub
        self.paths = hub.paths
        self.stopping = threading.Event()
        self.servers = {}
        self.threads = []
        self.slots = {name: threading.BoundedSemaphore(MAX_CONN) for name in SOCKET_VERBS}
        own = os.getuid()
        self.allowed = {}
        for name, user in SOCKET_USER.items():
            uids = {own}
            if name == "ctl":
                uids.add(0)
            elif _uid_of(user) is not None:
                uids.add(_uid_of(user))
            self.allowed[name] = uids
        self._fail_lock = threading.Lock()
        self._login_fails = deque()
        self._login_alerted = 0.0
        self.handlers = {
            "host.revoke": lambda c, a: self._host_state(c, a, "revoked", "host.revoke", True),
            "host.retire": lambda c, a: self._host_state(c, a, "retired", "host.retire", True),
            "host.mark-moved": lambda c, a: self._host_state(c, a, "moved", "host.mark-moved", False),
            "host.adopt": self._host_adopt,
            "host.maintenance": self._host_maintenance,
            "incident.resolve": self._incident_resolve,
            "token.create": self._token_create,
            "token.list": self._token_list,
            "token.revoke": self._token_revoke,
            "never-ban.add": self._never_ban_add,
            "never-ban.remove": self._never_ban_remove,
            "never-ban.list": self._never_ban_list,
            "settings.set": self._settings_set,
            "settings.secret-changed": self._secret_changed,
            "alert.test": self._alert_test,
            "ui-login.mint": self._ui_login_mint,
            "login.redeem": self._login_redeem,
            "audit.verify": self._audit_verify,
            "reissue-cert": self._reissue_cert,
            "agent-hash.add": self._agent_hash_add,
            "status": self._status,
            "outbox.take": self._outbox_take,
            "outbox.result": self._outbox_result,
            "feed.job": lambda c, a: {"jobs": []},          # P3
            "feed.result": lambda c, a: {"accepted": True},  # P3
        }

    # ---- lifecycle ------------------------------------------------------------------------------
    def start(self):
        os.makedirs(self.paths.run_dir, mode=0o750, exist_ok=True)
        old = os.umask(0o117)
        try:
            for name, path in (("ctl", self.paths.ctl_sock), ("ui", self.paths.ui_sock), ("out", self.paths.out_sock)):
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
                srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                srv.bind(path)
                srv.listen(16)
                srv.settimeout(0.5)
                self.servers[name] = srv
        finally:
            os.umask(old)
        os.chmod(self.paths.ctl_sock, 0o600)
        for name, srv in self.servers.items():
            t = threading.Thread(target=self._accept_loop, args=(name, srv), name="sock-" + name, daemon=True)
            t.start()
            self.threads.append(t)
        t = threading.Thread(target=self._ingest_loop, name="audit-ingest", daemon=True)
        t.start()
        self.threads.append(t)

    def _ingest_loop(self):
        """Take new pending-audit.jsonl lines into the chain soon after a root file operation.

        The writer also does this on its idle tick, but that tick only runs when the queue has been empty
        for 10 s, which a busy hub may never see. This loop asks the writer for the same job.
        """
        last_size, last_run = None, 0.0
        while not self.stopping.wait(INGEST_TICK_S):
            try:
                size = os.stat(self.paths.pending_audit).st_size
            except OSError:
                size = 0
            if size == last_size and time.monotonic() - last_run < INGEST_IDLE_S:
                continue
            try:
                self.hub.writer.call(lambda conn: hub_audit.ingest_pending(conn, self.hub), timeout=30)
                last_size, last_run = size, time.monotonic()
            except Exception as exc:
                self._log("error", "audit ingest tick failed: %s" % type(exc).__name__)

    def stop(self):
        self.stopping.set()
        for srv in self.servers.values():
            try:
                srv.shutdown(socket.SHUT_RDWR)      # wakes the accept call at once
            except OSError:
                pass
            try:
                srv.close()
            except OSError:
                pass
        for t in self.threads:
            t.join(2)
        for path in (self.paths.ctl_sock, self.paths.ui_sock, self.paths.out_sock):
            try:
                os.unlink(path)
            except OSError:
                pass

    def _accept_loop(self, name, srv):
        while not self.stopping.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self.slots[name].acquire(blocking=False):
                conn.close()                       # the 9th connection is dropped at once
                continue
            threading.Thread(target=self._serve, args=(name, conn), daemon=True).start()

    # ---- one connection -------------------------------------------------------------------------
    def _serve(self, name, conn):
        try:
            deadline = time.monotonic() + TIMEOUT_S
            try:
                pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                                     struct.calcsize("3i")))
            except OSError:
                return
            if uid not in self.allowed[name]:
                ctx = Ctx(name, pid, uid, None)
                self._audit_quiet(ctx, "socket.denied", name, "denied", {"socket": name})
                self._send(conn, self._error(Denied("peer not allowed")), deadline)
                return
            try:
                line = self._read_line(conn, deadline)
            except _TooLarge:
                self._send(conn, self._error(Invalid("request too large")), deadline)
                return
            except (socket.timeout, OSError, EOFError):
                return
            self._send(conn, self.handle_line(name, pid, uid, line), deadline)
        finally:
            try:
                conn.close()
            except OSError:
                pass
            self.slots[name].release()

    @staticmethod
    def _read_line(conn, deadline):
        buf = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout()
            conn.settimeout(remaining)
            chunk = conn.recv(8192)
            if not chunk:
                if buf:
                    return bytes(buf)
                raise EOFError()
            buf += chunk
            nl = buf.find(b"\n")
            if nl >= 0:
                if nl > LINE_MAX:
                    raise _TooLarge()
                return bytes(buf[:nl])
            if len(buf) > LINE_MAX:
                raise _TooLarge()

    @staticmethod
    def _send(conn, reply, deadline):
        data = (json.dumps(reply, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
        try:
            conn.settimeout(max(0.5, deadline - time.monotonic()))
            conn.sendall(data)
        except OSError:
            pass

    @staticmethod
    def _error(exc):
        return {"ok": False, "code": exc.code, "error": exc.text, "exit": exc.exit}

    def handle_line(self, name, pid, uid, line):
        """Parse and run one request line; returns the reply dict. Public so tests can call it."""
        try:
            req = json.loads(line.decode("utf-8"))
            if not isinstance(req, dict) or not isinstance(req.get("cmd"), str):
                raise ValueError("no cmd")
            args = req.get("args", {})
            if not isinstance(args, dict):
                raise ValueError("args")
        except (ValueError, UnicodeDecodeError, RecursionError):
            ctx = Ctx(name, pid, uid, None)
            self._audit_quiet(ctx, "socket.bad-request", name, "invalid", {"socket": name})
            return self._error(Invalid("malformed request"))
        ctx = Ctx(name, pid, uid, req.get("actor"))
        cmd = req["cmd"]
        if cmd not in SOCKET_VERBS[name] or cmd not in self.handlers:
            self._audit_quiet(ctx, "socket.refused", clean(cmd, 64), "denied", {"socket": name})
            return self._error(Denied("command not allowed"))
        try:
            return {"ok": True, "result": self.handlers[cmd](ctx, args)}
        except _Reply as exc:
            return exc.reply
        except Reject as exc:
            return self._error(exc)
        except Exception as exc:
            if _is_busy(exc):
                return self._error(Failed("hub busy or storage full, try again"))
            self._log("error", "verb %s failed: %s" % (clean(cmd, 40), type(exc).__name__))
            return self._error(Failed("internal error"))

    # ---- shared helpers -------------------------------------------------------------------------
    def _log(self, level, message):
        try:
            self.hub.log(level, message)
        except Exception:
            pass

    def _audit_quiet(self, ctx, action, target, outcome, details=None):
        """Audit a refusal or failure; never raises.

        On ui.sock and out.sock a refusal or an invalid request is folded like an unauthenticated failure (PLAN
        section 5): one row per (socket, verb, minute) with a count, under the same daily cap, because the process
        on the other end may be compromised. ctl.sock is root and keeps one row each.
        """
        try:
            if ctx.sock != "ctl" and outcome in ("denied", "invalid"):
                verb = target if target in ALL_VERBS else (action if action in ALL_VERBS else "unknown")
                self.hub.writer.call(lambda conn: hub_audit.append(
                    conn, actor_kind=ctx.kind, actor_detail="socket=%s verb=%s" % (ctx.sock, verb), action=action,
                    target=verb, outcome=outcome, fold=True))
                return
            self.hub.writer.call(lambda conn: hub_audit.append(
                conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action=action, target=target,
                outcome=outcome, details=details))
        except Exception as exc:
            self._log("error", "audit row not written: %s" % type(exc).__name__)

    def _write(self, ctx, action, target, work, fail_details=None):
        """Run work(conn) in the writer. A refusal or error is audited in a second call."""
        try:
            return self.hub.writer.call(work)
        except Reject as exc:
            outcome = {"error": "error", "invalid": "invalid"}.get(exc.code, "denied")
            self._audit_quiet(ctx, action, target, outcome, dict(fail_details or {}, reason=exc.text))
            raise
        except ValueError as exc:
            text = clean(str(exc), 120)
            self._audit_quiet(ctx, action, target, "invalid", dict(fail_details or {}, reason=text))
            raise Invalid(text)
        except Exception as exc:
            self._audit_quiet(ctx, action, target, "error", dict(fail_details or {}, reason=type(exc).__name__))
            raise

    def _notice(self, conn, ctx, action, detail):
        _alerts().admin_notice(conn, self.hub, action, detail, ctx.detail)

    @staticmethod
    def _str_arg(args, key, limit=200, required=True):
        value = args.get(key)
        if value is None or value == "":
            if required:
                raise Invalid("missing " + key)
            return ""
        if not isinstance(value, str) or len(value) > limit:
            raise Invalid("bad " + key)
        return value

    def _enabled_channels_text(self):
        return ", ".join(hub_common.enabled_channels(self.hub.settings)) or "none"

    # ---- host verbs -----------------------------------------------------------------------------
    def _host_state(self, ctx, args, new_state, action, notify_high):
        ref = self._str_arg(args, "host", 80)
        verb = action.split(".", 1)[1]

        def work(conn):
            row = _enroll().resolve_host(conn, ref)
            if row is None:
                raise Invalid("no such host")
            uuid, name, old = row["uuid"], row["name"], row["state"]
            _enroll().host_set_state(conn, self.hub, uuid, new_state, actor=ctx.short)
            hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action=action, target=name,
                             details={"uuid": uuid, "from": old, "to": new_state})
            text = "host %s (%s) %s" % (clean(name, 63), uuid, {"revoke": "revoked", "retire": "retired",
                                                               "mark-moved": "marked moved"}[verb])
            # mark-moved revokes the certificate too, and it is the one destructive verb the dashboard has: HIGH, always sent
            self._notice(conn, ctx, "host " + {"revoke": "revoked", "retire": "retired", "mark-moved": "marked moved"}[verb], text)
            return {"host": name, "uuid": uuid, "state": new_state}
        return self._write(ctx, action, ref, work)

    def _host_adopt(self, ctx, args):
        ref = self._str_arg(args, "host", 80)

        def work(conn):
            row = _enroll().resolve_host(conn, ref)
            if row is None:
                raise Invalid("no such host")
            if row["state"] != "orphan":
                raise Invalid("host is not an orphan")
            _enroll().host_adopt(conn, self.hub, row["uuid"])
            hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action="host.adopt",
                             target=row["name"], details={"uuid": row["uuid"]})
            self._notice(conn, ctx, "host adopted", "host %s (%s) adopted after a restore" % (clean(row["name"], 63), row["uuid"]))
            return {"host": row["name"], "uuid": row["uuid"], "state": "active"}
        return self._write(ctx, "host.adopt", ref, work)

    def _host_maintenance(self, ctx, args):
        ref = self._str_arg(args, "host", 80)
        end = bool(args.get("end"))
        secs = 0
        if not end:
            value = args.get("for")
            try:
                secs = int(value) if isinstance(value, int) and not isinstance(value, bool) else hub_common.parse_duration(value)
            except (ValueError, TypeError):
                raise Invalid("--for must look like 30m or 2h")
            if not 60 <= secs <= MAINTENANCE_MAX_S:
                raise Invalid("maintenance is 1 minute to 2 hours")

        def work(conn):
            row = _enroll().resolve_host(conn, ref)
            if row is None:
                raise Invalid("no such host")
            name = row["name"]
            now = now_ms()
            if end:
                cur = conn.execute("DELETE FROM maintenance WHERE host=?", (row["uuid"],))
                if cur.rowcount == 0:
                    raise Invalid("no maintenance window is set for this host")
                hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action="host.maintenance-end",
                                 target=name, details={"uuid": row["uuid"]})
                summary = "maintenance ended for %s by %s" % (clean(name, 63), ctx.short)
                until = None
            else:
                if row["state"] not in ("pending", "active", "orphan"):
                    raise Invalid("host is not in service")
                until = now + secs * 1000
                conn.execute("INSERT INTO maintenance (host, until, set_by, set_at) VALUES (?,?,?,?) "
                             "ON CONFLICT(host) DO UPDATE SET until=excluded.until, set_by=excluded.set_by, "
                             "set_at=excluded.set_at", (row["uuid"], until, ctx.detail, now))
                hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action="host.maintenance",
                                 target=name, details={"uuid": row["uuid"], "seconds": secs, "until": until})
                summary = "maintenance window for %s until %s UTC, set by %s" % (
                    clean(name, 63), hub_common.ms_to_rfc3339(until), ctx.short)
            _alerts().notify(conn, self.hub, severity="INFO", kind="admin.maintenance", summary=summary,
                             host=row, fields={"by": ctx.short})
            return {"host": name, "until": until}
        return self._write(ctx, "host.maintenance", ref, work)

    # ---- incidents ------------------------------------------------------------------------------
    def _incident_resolve(self, ctx, args):
        try:
            iid = int(args.get("id"))
        except (TypeError, ValueError):
            raise Invalid("bad incident id")

        def work(conn):
            cur = conn.execute("UPDATE incidents SET state='resolved', closed_at=?, closed_by=? "
                               "WHERE id=? AND state!='resolved'", (now_ms(), ctx.short, iid))
            if cur.rowcount == 0:
                raise Invalid("no such open incident")
            hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action="incident.resolve",
                             target=str(iid))
            return {"id": iid, "state": "resolved"}
        return self._write(ctx, "incident.resolve", str(iid), work)

    # ---- tokens ---------------------------------------------------------------------------------
    def _token_create(self, ctx, args):
        name, names, for_hosts = args.get("name"), args.get("names"), args.get("for")
        if sum(x is not None for x in (name, names, for_hosts)) != 1:
            raise Invalid("give exactly one of --name, --names, --for")
        mode = "name" if name is not None else "names" if names is not None else "for"
        items = [name] if mode == "name" else names if mode == "names" else for_hosts
        if isinstance(items, str):
            items = [x for x in items.split(",")]
        if not isinstance(items, list) or not items or len(items) > TOKENS_PER_CALL \
                or not all(isinstance(x, str) and x and len(x) <= 80 for x in items):
            raise Invalid("bad host list")
        if len(set(items)) != len(items):
            raise Invalid("a host appears twice")
        if mode != "for" and not all(hub_common.HOST_NAME_RE.match(x) for x in items):
            raise Invalid("host names are lower case letters, digits and -")
        try:
            ttl = hub_common.parse_duration(args.get("ttl") or "15m")
        except ValueError:
            raise Invalid("--ttl must look like 15m or 4h")
        if not 60 <= ttl <= TOKEN_TTL_MAX_S:
            raise Invalid("--ttl is 1 minute to 24 hours")
        source = None
        if args.get("source"):
            try:
                source = hub_common.norm_cidr(str(args["source"]))
            except ValueError:
                raise Invalid("--source is not a CIDR")
        if self.hub.settings.get("clients_only") and not source:
            raise Invalid("--source is required while clients_only is on")

        def work(conn):
            made = []
            for item in items:
                if mode == "for":
                    row = _enroll().resolve_host(conn, item)
                    if row is None:
                        raise Invalid("no such host: " + clean(item, 40))
                    tok = _enroll().token_create(conn, self.hub, for_host=row["uuid"], ttl_s=ttl,
                                                 source_cidr=source, created_by=ctx.short)
                    tok = dict(tok, label=row["name"], bound_host=row["uuid"])
                else:
                    tok = _enroll().token_create(conn, self.hub, name=item, ttl_s=ttl,
                                                 source_cidr=source, created_by=ctx.short)
                    tok = dict(tok, label=item)
                made.append(tok)
            labels = [t["label"] for t in made]
            hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action="token.create",
                             target=",".join(labels)[:200],
                             details={"ids": [t["id"] for t in made], "mode": mode, "ttl_s": ttl, "source": source or ""})
            self._notice(conn, ctx, "token created", "%d token(s) created for %s, valid %s%s" % (
                len(made), clean(", ".join(labels), 120), hub_common.ms_to_rfc3339(made[0]["expires_at"]) if made else "",
                " from " + source if source else ""))
            return made
        made = self._write(ctx, "token.create", ",".join(items)[:200], work)
        self._refresh_listener()
        return {"tokens": made}

    def _refresh_listener(self):
        try:
            self.hub.refresh_enroll_listener()
        except Exception as exc:
            self._log("error", "enrollment listener refresh failed: %s" % type(exc).__name__)

    def _token_list(self, ctx, args):
        return {"tokens": self.hub.writer.call(lambda conn: _enroll().token_list(conn))}

    def _token_revoke(self, ctx, args):
        tid = self._str_arg(args, "id", 64)

        def work(conn):
            if not _enroll().token_revoke(conn, self.hub, tid):
                raise Invalid("no such pending token")
            hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action="token.revoke", target=tid)
            return {"id": tid}
        result = self._write(ctx, "token.revoke", tid, work)
        self._refresh_listener()
        return result

    # ---- never-ban ------------------------------------------------------------------------------
    @staticmethod
    def _never_ban_cidr(args):
        try:
            net = ipaddress.ip_network(hub_common.norm_cidr(str(args.get("cidr", ""))))
        except ValueError:
            raise Invalid("not a CIDR (host bits must be zero)")
        if net.prefixlen < NEVER_BAN_MIN_PREFIX[net.version]:
            raise Invalid("never-ban entries are /%d or narrower for IPv%d" % (NEVER_BAN_MIN_PREFIX[net.version], net.version))
        return net

    def _never_ban_add(self, ctx, args):
        net = self._never_ban_cidr(args)
        reason = clean(str(args.get("reason", "")), 200)
        cidr = str(net)

        def work(conn):
            for (other,) in conn.execute("SELECT cidr FROM never_ban").fetchall():
                o = ipaddress.ip_network(other)
                if o.version == net.version and net.subnet_of(o):
                    raise Refused("already covered by " + other)
            for (other,) in conn.execute("SELECT cidr FROM bans WHERE expires > ?", (now_ms() // 1000,)).fetchall():
                try:
                    o = ipaddress.ip_network(other)
                except ValueError:
                    continue
                if o.version == net.version and o.overlaps(net):
                    raise Refused("overlaps an active ban: " + other)
            conn.execute("INSERT INTO never_ban (cidr, reason, added_by, ts) VALUES (?,?,?,?)",
                         (cidr, reason, ctx.short, now_ms()))
            hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action="never-ban.add", target=cidr,
                             details={"reason": reason})
            self._notice(conn, ctx, "never-ban added", "%s added to the never-ban list%s" % (
                cidr, ": " + reason if reason else ""))
            return {"cidr": cidr}
        return self._write(ctx, "never-ban.add", cidr, work)

    def _never_ban_remove(self, ctx, args):
        try:
            cidr = hub_common.norm_cidr(str(args.get("cidr", "")))
        except ValueError:
            raise Invalid("not a CIDR")

        def work(conn):
            if conn.execute("DELETE FROM never_ban WHERE cidr=?", (cidr,)).rowcount == 0:
                raise Invalid("not on the never-ban list")
            hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action="never-ban.remove", target=cidr)
            self._notice(conn, ctx, "never-ban removed", "%s removed from the never-ban list" % cidr)
            return {"cidr": cidr}
        return self._write(ctx, "never-ban.remove", cidr, work)

    def _never_ban_list(self, ctx, args):
        def work(conn):
            return [dict(zip(("cidr", "reason", "added_by", "ts"), tuple(r))) for r in conn.execute(
                "SELECT cidr, reason, added_by, ts FROM never_ban ORDER BY cidr")]
        return {"entries": self.hub.writer.call(work)}

    # ---- settings -------------------------------------------------------------------------------
    @staticmethod
    def _history_text(value):
        return value if isinstance(value, str) else json.dumps(value, sort_keys=True)

    def _settings_set(self, ctx, args):
        key = self._str_arg(args, "key", 64)
        if key in hub_common.SECRET_SETTINGS:
            raise Refused("secret keys are set from stdin by the root CLI, never over the socket")
        if key in hub_common.INSTALLER_SETTINGS:
            raise Refused("installer-owned key: change it with install.sh")
        if key not in hub_common.PLAIN_SETTINGS:
            raise Invalid("unknown setting")
        try:
            value = hub_common.validate_setting(key, args.get("value", ""))
        except (ValueError, TypeError) as exc:
            raise Invalid("bad value: " + clean(str(exc), 80))

        def work(conn):
            old = self.hub.settings.get(key, hub_common.PLAIN_SETTINGS[key][0])
            conn.execute("INSERT INTO settings_history (ts, key, old, new, actor) VALUES (?,?,?,?,?)",
                         (now_ms(), key, self._history_text(old), self._history_text(value), ctx.detail))
            hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action="settings.set", target=key,
                             details={"old": old, "new": value})
            self._notice(conn, ctx, "setting changed", "%s changed from %s to %s" % (
                key, clean(self._history_text(old), 60), clean(self._history_text(value), 60)))
            new = dict(self.hub.settings)
            new[key] = value
            self.hub.update_settings(new)               # last, so a failure here rolls the rows back
            return {"key": key, "value": value}
        return self._write(ctx, "settings.set", key, work)

    def _secret_changed(self, ctx, args):
        """The root CLI wrote secrets.json itself and tells the hub only that KEY changed."""
        key = self._str_arg(args, "key", 64)
        if key not in hub_common.SECRET_SETTINGS:
            raise Invalid("not a secret key")
        masked = clean(str(args.get("masked", "")), 64)
        phase = args.get("phase", "post")
        if phase not in ("pre", "post"):
            raise Invalid("bad phase")
        if phase == "pre":
            # Sent before the file is rewritten, so the notice still reaches the old channel.
            def pre(conn):
                self._notice(conn, ctx, "secret about to change", "%s is about to be replaced" % key)
                return {"queued": True}
            return self._write(ctx, "settings.secret-pre", key, pre)

        def work(conn):
            cleared = masked == ""
            conn.execute("INSERT INTO settings_history (ts, key, old, new, actor) VALUES (?,?,?,?,?)",
                         (now_ms(), key, "changed", "cleared" if cleared else "changed", ctx.detail))
            hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action="settings.secret-changed",
                             target=key, details={"masked": masked})
            self._notice(conn, ctx, "secret changed", "%s %s" % (key, "cleared" if cleared else "changed"))
            new = dict(self.hub.settings)
            have = dict(new.get("secrets_set") or {})
            if cleared:
                have.pop(key, None)
            else:
                have[key] = masked
            new["secrets_set"] = have
            self.hub.update_settings(new)
            return {"key": key, "masked": masked}
        return self._write(ctx, "settings.secret-changed", key, work)

    # ---- alerts ---------------------------------------------------------------------------------
    def _alert_test(self, ctx, args):
        channel = args.get("channel")
        if channel is not None and channel not in hub_common.CHANNELS:
            raise Invalid("channel is webhook, ntfy, discord or email")

        def work(conn):
            ids = _alerts().enqueue_test(conn, self.hub, channel)
            hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action="alert.test",
                             target=channel or "all", details={"outbox_ids": list(ids)})
            return {"ids": list(ids)}
        return self._write(ctx, "alert.test", channel or "all", work)

    # ---- dashboard login ------------------------------------------------------------------------
    def _ui_login_mint(self, ctx, args):
        code = secrets.token_urlsafe(16)
        digest = hashlib.sha256(code.encode("ascii")).hexdigest()
        now = now_ms()

        def work(conn):
            conn.execute("INSERT INTO login_codes (code_sha256, created, expires) VALUES (?,?,?)",
                         (digest, now, now + LOGIN_CODE_TTL_MS))
            hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action="ui-login.mint",
                             details={"expires": now + LOGIN_CODE_TTL_MS})
            return {"code": code, "expires_at": now + LOGIN_CODE_TTL_MS}
        return self._write(ctx, "ui-login.mint", "", work)

    def _login_redeem(self, ctx, args):
        code = args.get("code")
        now = now_ms()
        digest = hashlib.sha256(code.encode("utf-8", "replace")).hexdigest() \
            if isinstance(code, str) and 0 < len(code) <= 128 else None

        def work(conn):
            good = digest is not None and conn.execute(
                "UPDATE login_codes SET used_at=? WHERE code_sha256=? AND used_at IS NULL AND expires>?",
                (now, digest, now)).rowcount == 1
            if good:
                hub_audit.append(conn, actor_kind="ui", actor_detail=ctx.detail, action="login.redeem")
                self._notice(conn, ctx, "dashboard session", "new dashboard session from %s" % ctx.addr)
            return good
        ok = self._write(ctx, "login.redeem", "", work)
        if ok:
            return {"valid": True}
        count = self._count_login_failure(now)
        self._audit_quiet(ctx, "login.redeem", "", "denied", {"failures_last_minute": count})
        if count > LOGIN_FAIL_ALERT:
            self._login_alert(ctx, count)
        err = self._error(Denied("login refused"))
        err["failures"] = count
        raise _Reply(err)

    def _count_login_failure(self, now_ms_):
        with self._fail_lock:
            self._login_fails.append(now_ms_)
            while self._login_fails and now_ms_ - self._login_fails[0] > 60_000:
                self._login_fails.popleft()
            return len(self._login_fails)

    def _login_alert(self, ctx, count):
        with self._fail_lock:
            if time.monotonic() - self._login_alerted < 60:
                return
            self._login_alerted = time.monotonic()
        try:
            self.hub.writer.call(lambda conn: self._notice(
                conn, ctx, "failed dashboard logins", "%d failed dashboard logins in the last minute" % count))
        except Exception as exc:
            self._log("error", "login alert not queued: %s" % type(exc).__name__)

    # ---- audit, certificate, agent hashes, status -----------------------------------------------
    def _audit_verify(self, ctx, args):
        conn = self.hub.ro()
        try:
            ok, bad = hub_audit.verify(conn)
            rows = conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
            head = hub_audit.head(conn)
        finally:
            conn.close()

        def work(conn):
            hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action="audit.verify",
                             outcome="ok" if ok else "error", details={"first_bad_id": bad, "rows": rows})
            if not ok:
                self._notice(conn, ctx, "audit chain broken", "audit verify failed at row %s" % bad)
        self._write(ctx, "audit.verify", "", work)
        return {"ok": ok, "first_bad_id": bad, "rows": rows, "head": head}

    def _reissue_cert(self, ctx, args):
        ips = list(self.hub.settings.get("public_ip") or [])
        try:
            self.hub.pki.issue_server_cert(ips)
            self.hub.reload_server_cert()
            info = self.hub.pki.cert_info(self.paths.server_cert)
        except Exception as exc:
            self._audit_quiet(ctx, "reissue-cert", "", "error", {"reason": type(exc).__name__})
            self._log("error", "reissue-cert failed: %s" % type(exc).__name__)
            raise Failed("could not issue the server certificate")

        def work(conn):
            hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action="reissue-cert",
                             details={"serial": info.get("serial"), "sans": info.get("sans")})
            self._notice(conn, ctx, "server certificate reissued", "new server certificate, serial %s" % info.get("serial"))
        self._write(ctx, "reissue-cert", "", work)
        return {"serial": info.get("serial"), "not_after": info.get("not_after"), "sans": info.get("sans")}

    def _agent_hash_add(self, ctx, args):
        sha = self._str_arg(args, "sha256", 64).lower()
        if not _SHA256_RE.match(sha):
            raise Invalid("a SHA-256 is 64 hex characters")
        note = clean(str(args.get("note", "")), 200)

        def work(conn):
            added = conn.execute("INSERT OR IGNORE INTO agent_hashes (sha256, note, added_by, ts) VALUES (?,?,?,?)",
                                 (sha, note, ctx.short, now_ms())).rowcount == 1
            hub_audit.append(conn, actor_kind=ctx.kind, actor_detail=ctx.detail, action="agent-hash.add", target=sha,
                             details={"note": note, "added": added})
            if added:
                self._notice(conn, ctx, "agent hash added", "agent hash %s… added%s" % (sha[:12], ": " + note if note else ""))
            return {"sha256": sha, "added": added}
        return self._write(ctx, "agent-hash.add", sha, work)

    def _status(self, ctx, args):
        started = getattr(self.hub, "started_at", None)
        return {"version": hub_common.VERSION, "pid": os.getpid(), "started_at": started,
                "uptime_s": int((now_ms() - started) / 1000) if started else None,
                "channels": hub_common.enabled_channels(self.hub.settings)}

    # ---- out.sock -------------------------------------------------------------------------------
    def _outbox_take(self, ctx, args):
        try:
            limit = min(max(int(args.get("max", 20)), 1), 50)
        except (TypeError, ValueError):
            raise Invalid("bad max")

        def work(conn):
            now = now_ms()
            rows = conn.execute(
                "SELECT id, channel, severity, payload, attempts FROM outbox "
                "WHERE channel != 'none' AND state IN ('pending','failed','sending') AND next_try <= ? "
                "ORDER BY id LIMIT ?", (now, limit)).fetchall()
            items = []
            for r in rows:
                try:
                    payload = json.loads(r[3])
                except ValueError:
                    conn.execute("UPDATE outbox SET state='dead', last_error='unreadable payload' WHERE id=?", (r[0],))
                    continue
                conn.execute("UPDATE outbox SET state='sending', next_try=? WHERE id=?", (now + OUTBOX_LEASE_MS, r[0]))
                items.append({"id": r[0], "channel": r[1], "severity": r[2], "payload": payload, "attempts": r[4]})
            return items
        items = self.hub.writer.call(work)
        return {"items": items, "options": self._out_options(),
                "deadman": bool((self.hub.settings.get("secrets_set") or {}).get("deadman_url"))}

    def _out_options(self):
        pem = None
        try:
            with open(self.paths.webhook_ca, encoding="ascii") as f:
                text = f.read(WEBHOOK_CA_MAX + 1)
            if text and len(text) <= WEBHOOK_CA_MAX and "BEGIN CERTIFICATE" in text:
                pem = text
        except (OSError, UnicodeDecodeError):
            pass
        return {"ntfy_url": str(self.hub.settings.get("ntfy_url") or ""), "webhook_ca_pem": pem}

    def _outbox_result(self, ctx, args):
        try:
            oid = int(args.get("id"))
        except (TypeError, ValueError):
            raise Invalid("bad id")
        ok = args.get("ok") is True
        error = clean(str(args.get("error", "")), 200)
        retry_after = args.get("retry_after")
        retry_after = retry_after if isinstance(retry_after, int) and not isinstance(retry_after, bool) and retry_after > 0 else None

        def work(conn):
            row = conn.execute("SELECT state, attempts, created FROM outbox WHERE id=?", (oid,)).fetchone()
            if row is None or row[0] not in ("sending", "pending", "failed"):
                return {"accepted": False}
            now = now_ms()
            attempts = row[1] + 1
            if ok:
                conn.execute("UPDATE outbox SET state='sent', sent_at=?, attempts=?, last_error='' WHERE id=?",
                             (now, attempts, oid))
                return {"accepted": True, "state": "sent"}
            delay = OUTBOX_LADDER_MIN[min(attempts - 1, len(OUTBOX_LADDER_MIN) - 1)] * 60
            if retry_after:
                delay = max(delay, min(retry_after, 3600))
            if now - row[2] + delay * 1000 > OUTBOX_GIVE_UP_MS:
                state = "dead"
            else:
                state = "failed"
            conn.execute("UPDATE outbox SET state=?, attempts=?, next_try=?, last_error=? WHERE id=?",
                         (state, attempts, now + delay * 1000, error, oid))
            return {"accepted": True, "state": state}
        return self.hub.writer.call(work)


class _TooLarge(Exception):
    pass


class _Reply(Reject):
    """A verb that has built its own error reply (login.redeem adds a failure count)."""

    def __init__(self, reply):
        super().__init__(reply.get("error", ""))
        self.reply = reply
        self.code = reply.get("code", "denied")
        self.exit = reply.get("exit", 3)
