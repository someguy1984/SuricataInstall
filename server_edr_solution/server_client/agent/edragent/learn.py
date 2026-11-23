"""Learning for web-exec (client PLAN section 4.3, Learning): `edr-agent learn [--accept]`.

For 7 days the agent records the distinct tuples (policy, parent binary, binary, first-argument basename, web
user) of web-exec, web-connect and env-read hits, counted per day and without arguments. `learn` prints a
draft allowlist and the tuples that are new in the last 72 hours. Nothing is applied by itself (the week may
include an attacker): `learn --accept` writes [tetragon] web_exec_allow, and web-exec enforcement refuses
until it has run.
"""
import json
import os
import time

from . import config as cfgmod

POLICIES = ("web-exec", "web-connect", "env-read")
MIN_DAYS = 7
NEW_WINDOW_S = 72 * 3600
MAX_TUPLES = 5000
KEEP_DAYS = 14


class LearnStore:
    def __init__(self, path, clock=time.time):
        self.path, self.clock = path, clock
        self.data = {"v": 1, "started": None, "accepted_at": None, "tuples": {}}
        self.dirty = False
        self.load()
        if self.data["started"] is None:
            self.data["started"] = int(clock())
            self.dirty = True

    def load(self):
        try:
            with open(self.path, "rb") as f:
                obj = json.loads(f.read(8 * 1024 * 1024))
            if isinstance(obj, dict) and isinstance(obj.get("tuples"), dict):
                self.data.update(obj)
        except (OSError, ValueError):
            pass

    def record(self, e, user_name=lambda uid: str(uid)):
        kind = e.get("kind", "")
        if not kind.startswith("tetragon.") or kind[9:] not in POLICIES:
            return
        proc = e.get("proc") or {}
        policy = kind[9:]
        args = str(proc.get("args", "")).split()
        arg0 = os.path.basename(args[0]) if args else ""
        user = user_name(proc.get("uid")) if proc.get("uid") is not None else ""
        row = {"policy": policy, "parent": str(proc.get("parent", "")), "binary": str(proc.get("binary", "")),
               "arg0": arg0[:64], "user": user}
        key = "|".join(row.values())
        now = int(self.clock())
        day = time.strftime("%Y-%m-%d", time.gmtime(now))
        t = self.data["tuples"].get(key)
        if t is None:
            if len(self.data["tuples"]) >= MAX_TUPLES:
                return
            t = self.data["tuples"][key] = dict(row, first=now, last=now, days={})
        t["last"] = now
        t["days"][day] = t["days"].get(day, 0) + 1
        if len(t["days"]) > KEEP_DAYS:
            for old in sorted(t["days"])[:-KEEP_DAYS]:
                del t["days"][old]
        self.dirty = True

    def save(self):
        if not self.dirty:
            return
        try:
            os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(self.data, f)
            os.replace(tmp, self.path)
            self.dirty = False
        except OSError:
            pass


def run_learn(paths, accept=False, min_days=MIN_DAYS, out=print, clock=time.time):
    """The `learn` subcommand. Returns the exit code: 0 done, 3 refused."""
    if accept and not paths.dev and os.geteuid() != 0:
        out("refused: learn --accept must run as root")
        return 3
    store = LearnStore(paths.learn_json, clock)
    data = store.data
    now = clock()
    days = (now - (data["started"] or now)) / 86400.0
    tuples = list(data["tuples"].values())
    out("learning since %s (%.1f days); %d distinct tuples" %
        (time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(data["started"] or now)), days, len(tuples)))
    for policy in POLICIES:
        rows = sorted((t for t in tuples if t["policy"] == policy), key=lambda t: (t["binary"], t["parent"], t["arg0"]))
        out("")
        out("%s: %d tuples" % (policy, len(rows)))
        for t in rows:
            total = sum(t["days"].values())
            out("  %s <- %s  arg0=%s user=%s  hits=%d over %d days" %
                (t["binary"] or "?", t["parent"] or "?", t["arg0"] or "-", t["user"] or "?", total, len(t["days"])))
    allow = sorted({t["binary"] for t in tuples if t["policy"] == "web-exec" and _clean_path(t["binary"])})
    out("")
    out("draft allowlist, as it would be written to local.conf:")
    out("  [tetragon]")
    out("  web_exec_allow = " + ",".join(allow))
    fresh = [t for t in tuples if now - t["first"] <= NEW_WINDOW_S]
    out("")
    out("new tuples in the last 72 hours: %d" % len(fresh))
    for t in fresh:
        out("  new: %s %s <- %s" % (t["policy"], t["binary"], t["parent"]))
    if not accept:
        if days < min_days:
            out("")
            out("learning has not run %d days yet; --accept will refuse until it has" % min_days)
        return 0
    if days < min_days:
        out("refused: learning has run %.1f days of the %d needed" % (days, min_days))
        return 3
    try:
        cfgmod.update_local_conf(paths, {("tetragon", "web_exec_allow"): ",".join(allow)})
    except (cfgmod.ConfigError, OSError) as e:
        out("refused: could not write local.conf (%s)" % e)
        return 3
    data["accepted_at"] = int(now)
    store.dirty = True
    store.save()
    out("")
    out("accepted: [tetragon] web_exec_allow written with %d programs. Run `edr-agent apply-config` to apply it." % len(allow))
    return 0


def _clean_path(p):
    return isinstance(p, str) and p.startswith("/") and "," not in p and "\n" not in p and ".." not in p.split("/") \
        and not any(ord(c) < 32 for c in p) and not p.endswith(" (deleted)")
