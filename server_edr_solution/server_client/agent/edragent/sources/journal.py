"""The journal: sshd and sudo records, selected by the journal's own fields, never by message text.

An unprivileged process cannot set _COMM-and-_UID=0 together with a forged message: a web user running
`logger -t sshd "Failed password ..."` has _COMM=logger. sshd records must have _COMM sshd or sshd-session
and _UID=0 (checked here again, whatever journalctl was asked for); sudo records have _COMM=sudo.

The source address of an sshd line is taken only by the anchored rules of client PLAN section 4.5:
messages that carry a user name anchor at the END of the line ("... from <IP> port <N> ssh2"), because
OpenSSH escapes only control characters, so a user name can hold a fake tail while the real tail is always
last; "Unable to negotiate" anchors at the START.
"""
import ipaddress
import json
import os
import re
import subprocess
import time

from .. import event as ev
from .. import tail
from .base import Source, cut_line, parse_ip

SSHD_COMMS = ("sshd", "sshd-session")
LEARNING_S = 14 * 86400
SEEN_CAP = 20000

_FP = r"(?:: (\S{1,32}) (SHA256:[A-Za-z0-9+/=_-]{20,64}))?"
_FAILED = re.compile(r"^Failed (password|publickey|keyboard-interactive/pam|none|gssapi-with-mic|hostbased) for (invalid user )?(.+) from (\S+) port (\d+) ssh2" + _FP + r"$")
_INVALID = re.compile(r"^Invalid user (.*) from (\S+)(?: port (\d+))?$")
_CLOSED = re.compile(r"^Connection closed by (authenticating|invalid) user (.+) (\S+) port (\d+) \[preauth\]$")
_NEGOTIATE = re.compile(r"^Unable to negotiate with (\S+) port (\d+): ")
_ACCEPTED = re.compile(r"^Accepted (\S+) for (.+) from (\S+) port (\d+) ssh2" + _FP + r"$")
_SUDO = re.compile(r"^\s*(\S{1,64}) : (.*)$", re.DOTALL)
_SHELLS = {"sh", "bash", "dash", "zsh", "fish", "ksh", "tcsh", "csh", "su", "login"}
_SENSITIVE = re.compile(r"/etc/sudoers|visudo|sudoedit|\.ssh/|authorized_keys|/etc/cron|/var/spool/cron|crontab")


class SeenStore:
    """What the agent has seen before (seen.json): ssh keys, sources, egress tuples. Bounded, saved lazily."""

    def __init__(self, path, clock=time.time):
        self.path, self.clock = path, clock
        self.first = None
        self.sets = {}
        self.dirty = False
        self._load()
        if self.first is None:
            self.first = int(clock())
            self.dirty = True

    def _load(self):
        try:
            with open(self.path, "rb") as f:
                obj = json.loads(f.read(4 * 1024 * 1024))
            if isinstance(obj, dict):
                if isinstance(obj.get("first"), int):
                    self.first = obj["first"]
                for k, v in obj.items():
                    if isinstance(v, list):
                        self.sets[k] = dict.fromkeys(str(x) for x in v[-SEEN_CAP:])
        except (OSError, ValueError):
            pass

    def learning(self):
        return self.clock() - self.first < LEARNING_S

    def has(self, bucket, value):
        return value in self.sets.get(bucket, {})

    def add(self, bucket, value):
        """Record a value; True when it was new."""
        d = self.sets.setdefault(bucket, {})
        if value in d:
            return False
        d[value] = None
        if len(d) > SEEN_CAP:
            d.pop(next(iter(d)))
        self.dirty = True
        return True

    def save(self):
        if not self.dirty:
            return
        obj = {"v": 1, "first": self.first}
        obj.update({k: list(v) for k, v in self.sets.items()})
        try:
            os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(obj, f)
            os.replace(tmp, self.path)
            self.dirty = False
        except OSError:
            pass


def _net(ip):
    a = ipaddress.ip_address(ip)
    return str(ipaddress.ip_network((int(a) >> (128 - 48) << (128 - 48), 48))) if a.version == 6 \
        else str(ipaddress.ip_network((int(a) >> 8 << 8, 24)))


def parse_sshd(message):
    """What an sshd message says: dict(type, user, ip, port, method, ...) or None. The address is already validated."""
    msg = cut_line(message).strip()
    m = _FAILED.match(msg)
    if m:
        method, invalid, user, ip, port = m.group(1), bool(m.group(2)), m.group(3), parse_ip(m.group(4)), m.group(5)
        return {"type": "fail", "user": user, "ip": ip, "port": int(port), "method": method, "invalid": invalid} if ip else None
    m = _INVALID.match(msg)
    if m:
        ip = parse_ip(m.group(2))
        return {"type": "fail", "user": m.group(1), "ip": ip, "port": int(m.group(3) or 0), "method": "invalid_user",
                "invalid": True} if ip else None
    m = _CLOSED.match(msg)
    if m:
        ip = parse_ip(m.group(3))
        return {"type": "fail", "user": m.group(2), "ip": ip, "port": int(m.group(4)), "method": "preauth_close",
                "invalid": m.group(1) == "invalid"} if ip else None
    m = _NEGOTIATE.match(msg)
    if m:
        ip = parse_ip(m.group(1))
        return {"type": "fail", "user": "", "ip": ip, "port": int(m.group(2)), "method": "negotiate", "invalid": False} if ip else None
    m = _ACCEPTED.match(msg)
    if m:
        ip = parse_ip(m.group(3))
        return {"type": "login", "user": m.group(2), "ip": ip, "port": int(m.group(4)), "method": m.group(1),
                "key_type": m.group(5) or "", "key_fp": m.group(6) or ""} if ip else None
    return None


def parse_sudo(message):
    """dict(user, target, command, tty, reason) for a sudo log line, or None."""
    msg = cut_line(message)
    m = _SUDO.match(msg)
    if not m:
        return None
    user, rest = m.groups()
    idx = rest.find("; COMMAND=")
    if idx >= 0:
        head, command = rest[:idx], rest[idx + len("; COMMAND="):]
    elif rest.startswith("COMMAND="):
        head, command = "", rest[len("COMMAND="):]
    else:
        head, command = rest, ""
    tty = re.search(r"(?:^|; )TTY=(\S+)", head)
    target = re.search(r"(?:^|; )USER=(\S+)", head)
    reason = ""
    if not command:
        if "NOT in sudoers" in head:
            reason = "not_in_sudoers"
        elif "incorrect password" in head:
            reason = "incorrect_password"
        else:
            return None
    return {"user": user, "target": target.group(1) if target else "", "command": command.strip(),
            "tty": tty.group(1) if tty else "", "reason": reason}


class JournalSource(Source):
    name = "journal"

    MATCHES = ["_COMM=sshd", "_UID=0", "+", "_COMM=sshd-session", "_UID=0", "+", "_COMM=sudo"]

    def __init__(self, ctx, seen, command="journalctl", popen=subprocess.Popen):
        super().__init__(ctx)
        self.seen = seen
        self.reader = tail.JournalFollower("journal", self.MATCHES, ctx.paths.cursors_dir, command=command,
                                           popen=popen, clock=ctx.clock)

    def poll(self, now):
        events = []
        for rec in self.reader.poll():
            events.extend(self.to_events(rec))
        return self.notice_events() + events

    def accepts(self, rec):
        """'ssh' or 'sudo' when the journal's own fields allow it, else None."""
        comm, uid = rec.get("_COMM"), str(rec.get("_UID", ""))
        if comm in SSHD_COMMS and uid == "0":
            return "ssh"
        if comm == "sudo":
            return "sudo"
        return None

    def to_events(self, rec):
        msg = rec.get("MESSAGE")
        if not isinstance(msg, str):
            return []
        which = self.accepts(rec)
        if which is None:
            return []
        try:
            ts = int(rec.get("__REALTIME_TIMESTAMP")) // 1000
        except (TypeError, ValueError):
            ts = None
        if which == "ssh":
            return self.ssh_event(msg, ts)
        return self.sudo_event(msg, ts)

    def ssh_event(self, msg, ts):
        p = parse_sshd(msg)
        if p is None:
            return []
        if p["type"] == "fail":
            details = {"user": p["user"], "method": p["method"], "invalid": p["invalid"], "port": p["port"]}
            who = ("user " + p["user"]) if p["user"] else "no user"
            return [ev.make_event("ssh.fail", "journal", "LOW", "ssh login failed (%s) for %s from %s" % (p["method"], who, p["ip"]),
                                  details=details, ts_ms=ts, src_ip=p["ip"], src_trust="tcp", proto="tcp")]
        return [self._login(p, ts)]

    def _login(self, p, ts):
        user, ip, auth, fp = p["user"], p["ip"], p["method"], p["key_fp"]
        cfg, seen = self.ctx.cfg, self.seen
        learning = seen.learning()
        novel = []
        new_key = bool(fp) and seen.add("keys", user + "|" + fp)
        new_net = seen.add("nets", user + "|" + _net(ip))
        first_root = user == "root" and seen.add("root", "login")
        if new_key:
            novel.append("new_key")
        if new_net:
            novel.append("new_source")
        if first_root:
            novel.append("first_root_login")
        pw_off = auth in ("password", "keyboard-interactive/pam") and cfg.get("agent", "sshd_password_auth", None) is False
        sev = "INFO"
        if pw_off:
            sev = "HIGH"
            novel.append("password_login_with_password_auth_off")
        elif first_root:
            sev = "LOW" if learning else "HIGH"
        elif new_key:
            sev = "LOW" if learning else "MEDIUM"
        elif new_net:
            sev = "LOW"
        details = {"user": user, "src_ip": ip, "auth": auth, "key_fp": fp, "port": p["port"]}
        if novel:
            details["novel"] = novel
        return ev.make_event("ssh.login", "journal", sev, "ssh login for %s from %s (%s)" % (user, ip, auth),
                             details=details, ts_ms=ts, src_ip=ip, src_trust="tcp", proto="tcp")

    def sudo_event(self, msg, ts):
        p = parse_sudo(msg)
        if p is None:
            return []
        cmd = p["command"]
        first = os.path.basename(cmd.split(None, 1)[0]) if cmd.split() else ""
        sev = "LOW"
        if p["reason"] == "not_in_sudoers":
            sev = "MEDIUM"
        elif first in _SHELLS or _SENSITIVE.search(cmd):
            sev = "MEDIUM"
        details = {"user": p["user"], "target": p["target"], "command": cmd, "tty": p["tty"]}
        if p["reason"]:
            details["reason"] = p["reason"]
        summary = "sudo by %s as %s: %s" % (p["user"], p["target"] or "?", cmd or p["reason"])
        return [ev.make_event("auth.sudo", "journal", sev, summary, details=details, ts_ms=ts)]
