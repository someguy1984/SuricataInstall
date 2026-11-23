"""Tetragon's event log: policy hits and fileless execs become tetragon.<policy> events.

detail() is copied unchanged from watch/files/tetragon-notify.py (a desktop script with a hyphenated name:
it is copied, never imported, and the original stays as it is). describe() is split from the original:
process_exec is labelled by its event type and called fileless only when the binary's inode has no links;
other event types are handled. The notify script's dedup and burst limiter are not used here: the event
stream is collapsed only by the pipeline (client PLAN section 4.5, Processing 4).
"""
import json
import os
import re

from .. import event as ev
from .. import tail
from .base import Source

# Policies that are never dropped by an ignore pattern: killers, web policies, tampering.
ALWAYS = {"nginx-exec", "sctp-socket", "web-exec", "web-write-code", "web-connect", "env-read", "fork-watch", "edr-canary",
          "tetragon-tamper", "stack-tamper", "privilege-escalation", "kernel-tampering", "setuid-files",
          "fileless-exec"}

# Rating when a policy has no special rule. Killing policies are CRITICAL once the kill happened.
POLICY_SEV = {
    "nginx-exec": "HIGH", "sctp-socket": "HIGH", "web-exec": "HIGH", "web-write-code": "HIGH",
    "web-connect": "MEDIUM", "env-read": "MEDIUM", "fork-watch": "HIGH", "edr-canary": "INFO",
    "privilege-escalation": "HIGH", "setuid-files": "HIGH", "kernel-tampering": "HIGH",
    "tetragon-tamper": "HIGH", "stack-tamper": "HIGH", "sensitive-files": "HIGH", "persistence": "HIGH",
    "suspicious-exec": "HIGH", "boot-config": "MEDIUM", "monitor-kernel-modules": "MEDIUM",
    "tcp-listen": "LOW", "log-tamper": "HIGH", "link-sensitive": "HIGH", "fileless-exec": "HIGH",
}
KILLERS = {"nginx-exec", "sctp-socket", "web-exec"}

# Routine noise from the system itself (cron and package runs). Never applied to the policies in ALWAYS or to
# a fileless binary.
BUILTIN_IGNORE = [
    r" <- /usr/sbin/cron$",
    r" <- /usr/lib/apt/",
    r" <- /usr/bin/(dpkg|apt|apt-get|unattended-upgrade)$",
]
APT_PARENTS = ("/usr/bin/dpkg", "/usr/bin/apt", "/usr/bin/apt-get", "/usr/bin/unattended-upgrade",
               "/usr/sbin/needrestart", "/usr/bin/needrestart", "/usr/lib/apt/", "/usr/bin/aptitude")
_HELPER_ARGS = re.compile(r"^-I /usr/local/lib/edr-agent/edr-[a-z-]+( .*)?\Z")
_HELPER_PYTHON = re.compile(r"^/usr/bin/python3(\.\d+)?\Z")
_SYSTEMD = ("/usr/lib/systemd/systemd", "/lib/systemd/systemd", "/sbin/init", "/usr/sbin/init")
_COMPILED_VIEW = re.compile(r"^([0-9a-f]{32}|[0-9a-f]{40})\.php\Z")
_KPROBE_LIKE = ("process_kprobe", "process_tracepoint", "process_uprobe", "process_lsm")


def detail(args):
    """The interesting part of a kprobe's arguments: paths, names and addresses."""
    out = []
    for arg in args or []:
        for key, val in arg.items():
            if key == "label":
                continue
            if isinstance(val, dict):
                if "path" in val:
                    val = val["path"]
                elif "saddr" in val or "daddr" in val:
                    val = f'{val.get("saddr", "")}:{val.get("sport", "")}'
                elif "name" in val:
                    val = val["name"]
                else:
                    continue
            elif key in ("int_arg", "uint_arg", "size_arg", "long_arg") and "label" not in arg:
                continue  # access masks and the like: no use to a reader
            text = " ".join(str(val).split())
            if text:
                out.append(f'{arg["label"]}={text}' if "label" in arg else text)
    return " ".join(out)


def _inode_links(proc):
    """Link count of the exec'd file, or None when Tetragon did not say. Protobuf JSON drops a zero, so an
    inode object with no `links` key is a count of 0."""
    props = proc.get("binary_properties") if isinstance(proc, dict) else None
    inode = ((props or {}).get("file") or {}).get("inode") if isinstance(props, dict) else None
    if not isinstance(inode, dict):
        return None
    links = inode.get("links", 0)
    try:
        return int(links)
    except (TypeError, ValueError):
        return None


def describe(event):
    """(summary line, title, body, policy, binary) for one event, or None if it isn't one we report."""
    if not isinstance(event, dict):
        return None
    kind = next((k for k in _KPROBE_LIKE if k in event), None)
    if kind:
        k = event[kind]
        if not isinstance(k, dict):
            return None
        policy = k.get("policy_name", "?")
        function = k.get("function_name") or k.get("symbol") or k.get("event") or "?"
        what = k.get("message") or f"{policy}: {function}"
        extra = detail(k.get("args"))
    elif "process_exec" in event:
        k = event["process_exec"]
        if not isinstance(k, dict):
            return None
        proc0 = k.get("process") if isinstance(k.get("process"), dict) else {}
        # Labelled by the event type. Fileless only when the file behind it has no links left.
        if _inode_links(proc0) == 0:
            policy, function = "fileless-exec", "exec"
            what = "Program executed with no file behind it (no links left)"
        else:
            policy, function = "exec", "exec"
            what = "Program executed"
        extra = " ".join(str(proc0.get("arguments", "")).split())
    else:
        return None
    proc = k.get("process") if isinstance(k.get("process"), dict) else {}
    parent = k.get("parent") if isinstance(k.get("parent"), dict) else {}
    binary = proc.get("binary", "?")
    summary = " ".join(str(x) for x in (policy, function, binary, extra) if x)
    if parent.get("binary"):
        summary += f' <- {parent["binary"]}'
    body = [f'{binary} (pid {proc.get("pid", "?")}, uid {proc.get("uid", "?")})']
    if extra:
        body.append(extra[:300])
    if parent.get("binary"):
        body.append(f'started by {parent["binary"]} {" ".join(str(parent.get("arguments", "")).split())}'[:200])
    body.append(f"journalctl -t tetragon-alerts | grep {policy}")
    return summary, f"Tetragon: {what}", "\n".join(body), policy, binary


def load_ignores(path):
    patterns = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f.read(65536).splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    patterns.append(re.compile(line))
                except re.error:
                    pass
    except OSError:
        pass
    return patterns


def is_kit_helper(binary, args, uid, parent):
    """The kit's own root helpers read .env as text and cannot be excluded by path in a policy (they run as
    `python3 -I /usr/local/lib/edr-agent/edr-NAME`). All four must hold, so a web user cannot hide behind the same
    argument string: python3, those arguments, uid 0 (protobuf JSON drops a zero, so a missing uid is 0) and systemd
    as the parent."""
    return bool(_HELPER_PYTHON.match(str(binary)) and _HELPER_ARGS.match(" ".join(str(args).split())) and
                (uid if uid is not None else 0) == 0 and parent in _SYSTEMD)


def _fileless_path(binary):
    return isinstance(binary, str) and (binary.startswith("/memfd:") or binary.endswith(" (deleted)"))


def _apt_run(k):
    parent = (k.get("parent") or {}).get("binary", "") if isinstance(k.get("parent"), dict) else ""
    chain = [parent]
    for a in k.get("ancestors") or []:
        if isinstance(a, dict):
            chain.append(a.get("binary", ""))
    return any(b and b.startswith(APT_PARENTS) for b in chain)


def _first_path(args):
    for arg in args or []:
        if not isinstance(arg, dict):
            continue
        for key, val in arg.items():
            if isinstance(val, dict) and isinstance(val.get("path"), str):
                return val["path"]
    return ""


def _sock(args):
    for arg in args or []:
        if isinstance(arg, dict) and isinstance(arg.get("sock_arg"), dict):
            return arg["sock_arg"]
    return None


def _port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


class TetragonSource(Source):
    name = "tetragon"

    def __init__(self, ctx, first_start="end", path=None):
        super().__init__(ctx)
        paths = ctx.paths
        self.path = path or paths.tetragon_log
        self.reader = tail.Tailer(self.path, "tetragon", paths.cursors_dir, first_start=first_start, clock=ctx.clock)
        self.ignores = [re.compile(p) for p in BUILTIN_IGNORE] + load_ignores(paths.tetragon_ignore)
        self.bad_json = 0
        self.last_ratelimit_event = 0.0
        self._cg_state = None            # (present, inode) of the tetragon unit's cgroup
        self._cg_checked = 0.0
        self._cg_seen = False            # the unit was seen running at least once since the agent started

    def on_notice(self, n, label):
        kind = n.get("type")
        if kind == "unreadable":
            return [ev.make_event("health.tetragon_unreadable", "agent", "HIGH",
                                  "the Tetragon log cannot be read (%s)" % n.get("reason", ""),
                                  details={"log": self.path, "reason": n.get("reason", "")})]
        if kind == "rotated":
            return [ev.make_event("health.blind_window", "agent", "LOW", "the Tetragon log was rotated",
                                  details={"log": "tetragon", "reason": "inode_changed", "gap": False})]
        if kind == "gap":
            return super().on_notice(n, label) + [
                ev.make_event("health.blind_window", "agent", "MEDIUM", "Tetragon events were not read for a while",
                              details={"log": "tetragon", "reason": n.get("reason", ""), "gap": True})]
        return super().on_notice(n, label)

    def poll(self, now):
        events = []
        for line in self.reader.poll():
            events.extend(self.parse_line(line, now))
        return self.notice_events() + self.restart_events(now) + events

    def restart_events(self, now):
        """A Tetragon restart, seen without running anything: its unit's cgroup disappears and comes back, or is a new
        directory (a restart quicker than the poll). Events in between were not seen: a blind window."""
        if now - self._cg_checked < 2.0:
            return []
        self._cg_checked = now
        path = os.path.join(self.ctx.paths.cgroup_system_slice(), "tetragon.service")
        try:
            state = (True, os.stat(path).st_ino)
        except OSError:
            state = (False, None)
        prev, self._cg_state = self._cg_state, state
        if state[0]:
            seen, self._cg_seen = self._cg_seen, True
        else:
            seen = self._cg_seen
        if prev is None or prev == state or not state[0] or not seen:
            return []
        if prev[0] and prev[1] == state[1]:
            return []
        return [ev.make_event("health.blind_window", "agent", "MEDIUM", "Tetragon was restarted: events in between were not seen",
                              details={"log": "tetragon", "reason": "restarted", "gap": True})]

    def parse_line(self, line, now=None):
        try:
            obj = json.loads(line)
        except ValueError:
            self.bad_json += 1
            return []
        if not isinstance(obj, dict):
            self.bad_json += 1
            return []
        try:
            return self.to_events(obj, now)
        except (KeyError, TypeError, ValueError, AttributeError):
            self.bad_json += 1
            return []

    def to_events(self, obj, now=None):
        if "rate_limit_info" in obj:
            return self._ratelimit(obj, now)
        described = describe(obj)
        if described is None:
            return []
        summary, title, body, policy, binary = described
        kind_key = next((k for k in _KPROBE_LIKE + ("process_exec",) if k in obj), None)
        k = obj[kind_key]
        proc = k.get("process") if isinstance(k.get("process"), dict) else {}
        parent = k.get("parent") if isinstance(k.get("parent"), dict) else {}
        ts_ms = ev.parse_ts(obj.get("time"))
        details = {"policy": policy, "function": k.get("function_name") or kind_key}
        action = str(k.get("action", "") or "")
        killed = "SIGKILL" in action
        fileless = _fileless_path(binary) or policy == "fileless-exec"
        if kind_key == "process_exec":
            if not fileless:
                return []                    # every other exec is the denylist's and the policies' business
            if _apt_run(k):
                return []                    # a package upgrade replaced the file under a running program
            policy = "fileless-exec"
            sev = "HIGH"
        else:
            sev = POLICY_SEV.get(policy, "MEDIUM")
            if killed and policy in KILLERS:
                sev = "CRITICAL"
            if fileless and ev.sev_rank(sev) < 3 and not _apt_run(k):
                sev = "HIGH"
        if killed:
            details["killed"] = True
            summary += " (killed)"
        if fileless:
            details["fileless"] = True
        args_text = " ".join(str(proc.get("arguments", "")).split())
        path = _first_path(k.get("args"))
        if path:
            details["path"] = path
        if kind_key != "process_exec":
            detail_text = detail(k.get("args"))
            if detail_text:
                details["detail"] = detail_text
            if k.get("message"):
                details["message"] = str(k["message"])
        if policy == "env-read" and is_kit_helper(binary, args_text, proc.get("uid"), parent.get("binary", "")):
            return []
        sev = self._policy_specific(policy, sev, binary, path)
        if policy not in ALWAYS and not fileless and any(p.search(summary) for p in self.ignores):
            return []
        dst_ip, dst_port = "", None
        sock = _sock(k.get("args"))
        if sock:
            dst_ip, dst_port = str(sock.get("daddr", "")), _port(sock.get("dport"))
            if sock.get("protocol"):
                details["protocol"] = str(sock["protocol"])
        uid = proc.get("uid")
        pp = {"binary": binary, "args": args_text, "parent": parent.get("binary", "")}
        if isinstance(uid, int):
            pp["uid"] = uid
        return [ev.make_event("tetragon." + policy, "tetragon", sev, summary, details=details, ts_ms=ts_ms,
                              dst_ip=dst_ip, dst_port=dst_port, proc=pp)]

    def _policy_specific(self, policy, sev, binary, path):
        if policy == "web-write-code" and path:
            m = re.search(r"/(?:storage/framework/views|bootstrap/cache)/([^/]+)\Z", path)
            if m and _COMPILED_VIEW.match(m.group(1)) and "php-fpm" in str(binary):
                return "LOW"                 # Laravel's compiled views are written by php-fpm itself
        if policy == "env-read":
            return "HIGH" if "nginx" in os.path.basename(str(binary)) else "MEDIUM"
        return sev

    def _ratelimit(self, obj, now):
        info = obj.get("rate_limit_info")
        dropped = 0
        if isinstance(info, dict):
            for key, val in info.items():
                if "dropped" in key:
                    try:
                        dropped += int(val)
                    except (TypeError, ValueError):
                        pass
        self.ctx.counters["tetragon_ratelimit"] += max(dropped, 1)
        if not self.ctx.cfg.getbool("kit", "web", True):
            return []
        return [ev.make_event("health.tetragon_ratelimit", "agent", "HIGH",
                              "Tetragon dropped events at its rate limit (%d)" % dropped,
                              details={"dropped": dropped})]
