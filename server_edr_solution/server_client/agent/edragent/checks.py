"""The file-reading half of check.sh (client PLAN section 8): `edr-agent checks SECTION`.

check.sh is shell and talks to the live system (systemctl, nft, ss, tetra, setpriv). Everything that only
reads files is here, so it is unit-tested against temporary directories. Each section returns a list of
(level, text) with level PASS, WARN, FAIL or INFO; the command prints them as `LEVEL<TAB>text` for check.sh.

Rules shared by the sections:
  - a component switched off in [kit] is skipped, never a FAIL;
  - on a paused host (pause.json with an `until` in the future; an expired file is ignored) the DNS lock, the ban
    counts and the policy modes are WARN "paused until T", never FAIL;
  - a missing, oversized or unparsable status file is reported as unknown (WARN), never as clean and never a crash;
  - the manifest and every file the agent wrote are untrusted input: opened with O_NOFOLLOW, size capped.
"""
import grp
import hashlib
import json
import os
import pwd
import re
import stat
import time

from . import SCHEMA, VERSION
from . import config as cfgmod
from . import event as evmod

PHASES = ("P1a", "P1b", "P2")
MANIFEST_MAX = 8 * 1024 * 1024
STATUS_MAX = 1024 * 1024
HEARTBEAT_WARN_S = 120
HEARTBEAT_FAIL_S = 300
DAY = 86400
# Budgets of section 9, in MiB
BUDGETS = [("Suricata eve.json", "/var/log/suricata/eve.json*", 250), ("Suricata eve-bulk.json", "/var/log/suricata/eve-bulk.json*", 100),
           ("suricata.log", "/var/log/suricata/suricata.log*", 20), ("Tetragon log", "/var/log/tetragon/tetragon.log*", 100),
           ("agent state", "{state}", 70), ("nginx edr.log", "/var/log/nginx/edr.log*", 60)]


def phase_ge(have, need):
    try:
        return PHASES.index(have) >= PHASES.index(need)
    except ValueError:
        return True


def read_json(path, limit=STATUS_MAX):
    """(object, reason): reason is '' when read."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None, "missing"
    except OSError:
        return None, "unreadable"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, "not a regular file"
        if st.st_size > limit:
            return None, "over %d bytes" % limit
        data = os.read(fd, limit + 1)
    except OSError:
        return None, "unreadable"
    finally:
        os.close(fd)
    try:
        obj = json.loads(data)
    except (ValueError, RecursionError):
        return None, "not valid JSON"
    return (obj, "") if isinstance(obj, dict) else (None, "not a JSON object")


def file_age(path, now):
    try:
        return now - os.stat(path).st_mtime
    except OSError:
        return None


def clean(text, limit=160):
    return evmod.clean_text(str(text))[:limit].replace("\t", " ")


class Ctx:
    """What the sections share."""

    def __init__(self, paths, cfg, now=None, local=False, owner_uid=0, phase=None, stdin=""):
        self.paths, self.cfg = paths, cfg
        self.stdin = stdin
        self.now = time.time() if now is None else now
        self.local = local
        self.owner_uid = owner_uid
        self.out = []
        self._manifest = None
        self._phase = phase
        self.pause = self._pause()
        self.manifest_reason = ""

    def add(self, level, text):
        self.out.append((level, clean(text, 400)))

    def pass_(self, text):
        self.add("PASS", text)

    def warn(self, text):
        self.add("WARN", text)

    def fail(self, text):
        self.add("FAIL", text)

    def info(self, text):
        self.add("INFO", text)

    def _pause(self):
        obj, _ = read_json(self.paths.pause_json, 4096)
        until = obj.get("until") if obj else None
        if isinstance(until, (int, float)) and not isinstance(until, bool) and until > self.now:
            return until
        return None

    def paused_text(self):
        return "paused until " + evmod.rfc3339(self.pause * 1000)

    def manifest(self):
        if self._manifest is None:
            for p in (self.paths.manifest_json, self.paths.install_manifest):
                obj, reason = read_json(p, MANIFEST_MAX)
                if obj is not None:
                    self._manifest = obj
                    break
                self.manifest_reason = reason
            else:
                self._manifest = {}
        return self._manifest

    def phase(self):
        if self._phase:
            return self._phase
        p = self.manifest().get("phase")
        return p if p in PHASES else "P2"

    def on(self, section, key):
        return self.cfg.getbool(section, key, True)

    def enrolled(self):
        return os.path.exists(os.path.join(self.paths.identity_dir, "current"))


def sessions(manifest):
    s = manifest.get("sessions")
    return [x for x in s if isinstance(x, dict)] if isinstance(s, list) else []


# ---- kit and install (P1a) --------------------------------------------------------------------------
def _safe_abs(path):
    return isinstance(path, str) and path.startswith("/") and ".." not in path.split("/") and "\x00" not in path


def audit_files(ctx):
    """Each file listed in the manifest against the latest sha256 recorded for its path."""
    latest = {}
    for s in sessions(ctx.manifest()):
        for f in s.get("files") or []:
            if isinstance(f, dict) and _safe_abs(f.get("path")) and isinstance(f.get("sha256"), str):
                latest[f["path"]] = f["sha256"]
    if not latest:
        ctx.warn("the manifest lists no files to audit")
        return
    bad = missing = 0
    for path, want in sorted(latest.items()):
        real = ctx.paths._p(path)
        try:
            fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError:
            missing += 1
            ctx.warn("audit: %s is listed in the manifest and is missing" % path)
            continue
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                bad += 1
                ctx.warn("audit: %s is not a regular file any more" % path)
                continue
            h = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                h.update(chunk)
        finally:
            os.close(fd)
        if h.hexdigest() != want.lower():
            bad += 1
            ctx.warn("audit: %s differs from what the installer wrote" % path)
    if not bad and not missing:
        ctx.pass_("audit: %d files match the manifest" % len(latest))


def _lib_permissions(ctx):
    lib = ctx.paths.lib_dir
    problems = []
    for root, dirs, files in os.walk(lib):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in dirs + files:
            p = os.path.join(root, name)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if st.st_uid != ctx.owner_uid:
                problems.append("%s is owned by uid %d" % (os.path.relpath(p, lib), st.st_uid))
            elif st.st_mode & 0o022:
                problems.append("%s is group or other writable" % os.path.relpath(p, lib))
    if problems:
        ctx.fail("code in %s is not root-owned and closed to writes: %s%s" % (lib, "; ".join(problems[:4]), " ..." if len(problems) > 4 else ""))
    else:
        ctx.pass_("code in %s is root-owned and not group or other writable" % lib)


def _local_conf(ctx):
    p = ctx.paths.local_conf
    try:
        st = os.lstat(p)
    except OSError:
        ctx.warn("%s does not exist: every key is at its default" % p)
        return
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        ctx.fail("local.conf is not a regular file")
        return
    mode = st.st_mode & 0o777
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    if st.st_uid != ctx.owner_uid or mode & 0o022:
        ctx.fail("local.conf is owned by uid %d with mode %04o: only root may write it" % (st.st_uid, mode))
    elif mode != 0o640 or (group != "edr-agent" and ctx.owner_uid == 0):
        ctx.warn("local.conf is %s:%s %04o, expected root:edr-agent 0640" % (st.st_uid, group, mode))
    else:
        ctx.pass_("local.conf is root:edr-agent 0640")
    c = cfgmod.load(ctx.paths)
    if c.errors:
        ctx.fail("local.conf is not valid: %s" % "; ".join(c.errors[:3]))
    else:
        ctx.pass_("local.conf parses with no unknown key")


def _stale_code(ctx):
    """An agent process started before the installed code was last changed still runs the old code."""
    proc = ctx.paths.proc_dir
    lib = os.path.realpath(ctx.paths.lib_dir)
    newest = 0.0
    for root, dirs, files in os.walk(lib):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for n in files:
            if n.endswith(".py"):
                try:
                    newest = max(newest, os.stat(os.path.join(root, n)).st_mtime)
                except OSError:
                    pass
    try:
        names = [n for n in os.listdir(proc) if n.isdigit()]
    except OSError:
        return
    boot = None
    try:
        with open(os.path.join(proc, "stat")) as f:
            for line in f:
                if line.startswith("btime "):
                    boot = float(line.split()[1])
    except (OSError, ValueError):
        pass
    if boot is None:
        return
    hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    for n in names:
        try:
            with open(os.path.join(proc, n, "cmdline"), "rb") as f:
                cmd = f.read(2048).replace(b"\0", b" ").decode("utf-8", "replace")
            if os.path.join(lib, "edr-agent.py") not in cmd:
                continue
            with open(os.path.join(proc, n, "stat")) as f:
                fields = f.read().rsplit(")", 1)[1].split()
            started = boot + int(fields[19]) / hz
        except (OSError, ValueError, IndexError):
            continue
        if "shutdown-notice" in cmd or " status" in cmd or " check" in cmd:
            continue
        if newest and started + 5 < newest:
            ctx.warn("edr-agent (pid %s) started before its code was last changed: restart it (systemctl restart edr-agent)" % n)
            return


def kit(ctx):
    m = ctx.manifest()
    if not m:
        ctx.warn("no install manifest (%s): was this installed by the kit? (%s)" % (ctx.paths.manifest_json, ctx.manifest_reason or "empty"))
    else:
        mv = m.get("version")
        if mv == VERSION:
            ctx.pass_("version %s matches the manifest" % VERSION)
        else:
            ctx.fail("the code is version %s but the manifest says %s" % (VERSION, clean(mv, 32)))
        try:
            with open(os.path.join(ctx.paths.lib_dir, "VERSION")) as f:
                fv = f.read(64).strip()
            if fv and fv != VERSION:
                ctx.fail("VERSION file says %s but the code is %s" % (clean(fv, 32), VERSION))
        except OSError:
            pass
        open_sessions = [s for s in sessions(m) if s.get("state") in ("running", "awaiting-confirm")]
        if open_sessions:
            ctx.warn("an install session is not confirmed (%s): run install.sh --confirm from a new session, or let the rollback timer fire"
                     % clean(open_sessions[-1].get("state"), 24))
        else:
            ctx.pass_("no unconfirmed install session")
        last = sessions(m)[-1] if sessions(m) else {}
        if last.get("policy_rc_d_ours") and os.path.exists(ctx.paths._p("/usr/sbin/policy-rc.d")) and not open_sessions:
            ctx.warn("the kit's policy-rc.d is still in place and no install is running: remove /usr/sbin/policy-rc.d")
    _lib_permissions(ctx)
    _local_conf(ctx)
    p = ctx.paths.proc("sys", "kernel", "apparmor_restrict_unprivileged_userns")
    try:
        with open(p) as f:
            v = f.read(8).strip()
        if v == "1":
            ctx.pass_("kernel.apparmor_restrict_unprivileged_userns is 1")
        else:
            ctx.warn("kernel.apparmor_restrict_unprivileged_userns is %s, not 1: an unprivileged user namespace gives a full capability set" % clean(v, 8))
    except OSError:
        ctx.info("kernel.apparmor_restrict_unprivileged_userns is not present on this kernel")
    _stale_code(ctx)


def audit(ctx):
    audit_files(ctx)


# ---- agent and local alerts (P1a; hub P2) --------------------------------------------------------------
def _alerts_24h(ctx):
    from . import alertlog
    return alertlog.read_alerts(ctx.paths.alerts_jsonl, ctx.now - DAY)


def _dir_size(path):
    total = 0
    for root, dirs, files in os.walk(path):
        for n in files:
            try:
                total += os.lstat(os.path.join(root, n)).st_size
            except OSError:
                pass
    return total


def agent(ctx):
    paths = ctx.paths
    summary, reason = read_json(paths.summary_json, 1024 * 1024)
    hub = (summary or {}).get("hub") or {}
    ag = (summary or {}).get("agent") or {}
    age = ctx.now - summary["written_at"] if summary and isinstance(summary.get("written_at"), (int, float)) else None
    if summary is None:
        ctx.fail("the agent is not running: no %s (%s)" % (paths.summary_json, reason))
    elif age is None or age > 180:
        ctx.fail("the agent is not running: its summary is %s old" % ("unknown" if age is None else "%d s" % age))
    else:
        pid = ag.get("pid")
        alive = True
        if isinstance(pid, int) and pid > 0 and not ctx.paths.dev:
            alive = os.path.isdir(os.path.join(paths.proc_dir, str(pid)))
        if alive:
            ctx.pass_("the agent is running (pid %s, version %s, config %s)" % (pid, clean(ag.get("version", "?"), 16), clean(ag.get("config", "?"), 16)))
        else:
            ctx.fail("the agent is not running: pid %s is gone" % pid)
        if ag.get("config_errors"):
            ctx.warn("the agent runs on %s because local.conf is invalid: %s" % (clean(ag.get("config", "?"), 16), clean(ag["config_errors"][0], 100)))
    # sandbox self-test
    alerts = _alerts_24h(ctx)
    if any(a.get("kind") == "health.sandbox_ineffective" for a in alerts) or \
            any(a.get("kind") == "health.sandbox_ineffective" for a in (summary or {}).get("alerts") or []):
        if ctx.on("kit", "kernel"):
            ctx.fail("sandbox self-test failed: the agent's network filter (IPAddressDeny) is not in force")
        else:
            # installed with --no-kernel (a container): systemd has no BPF firewall there, so the filter cannot
            # be in force. Said every time, never passed; on a real host this line is a FAIL.
            ctx.warn("sandbox self-test failed: the agent's network filter (IPAddressDeny) is not in force "
                     "([kit] kernel = off: expected in a container, a FAIL anywhere else)")
    elif summary is not None:
        ctx.pass_("sandbox self-test: no failure recorded")
    # spool
    spool_dir = paths.spool_dir
    if os.path.isdir(spool_dir):
        size = _dir_size(spool_dir)
        if size > 50 * 1024 * 1024:
            ctx.warn("the spool is %d MB, over its 50 MB cap" % (size >> 20))
        else:
            ctx.pass_("spool is %.1f MB of 50" % (size / 1048576.0))
    h24 = ag.get("health_24h") or {}
    for k, label in (("gap", "log gaps"), ("spool_dropped", "events dropped from the spool")):
        if isinstance(h24.get(k), int) and h24[k] > 0:
            ctx.warn("%d %s in the last 24 hours" % (h24[k], label))
    dropped = (hub.get("spool") or {}).get("dropped") or {}
    if isinstance(dropped, dict) and any(isinstance(v, int) and v > 0 for v in dropped.values()):
        ctx.warn("the spool has dropped events since the agent started: %s" % clean(dropped, 60))
    # inventory
    inv_age = file_age(paths.inventory_json, ctx.now)
    if inv_age is None:
        ctx.warn("inventory.json is missing: the inventory checks are unknown, not clean")
    elif inv_age > 7200:
        ctx.warn("inventory.json is %d minutes old (over 2 hours): unknown, not clean" % (inv_age // 60))
    else:
        ctx.pass_("inventory.json is %d minutes old" % (inv_age // 60))
    # certificate, droplet id, hub (P2)
    if ctx.phase() == "P2" and ctx.enrolled():
        _certificate(ctx)
        _droplet(ctx)
    crit = [a for a in alerts if a.get("sev") == "CRITICAL"]
    if crit:
        ctx.warn("%d CRITICAL alert(s) in the last 24 hours, newest: %s %s" % (len(crit), clean(crit[-1].get("kind", ""), 40), clean(crit[-1].get("summary", ""), 80)))
    else:
        ctx.pass_("no CRITICAL alert in the last 24 hours")
    _heartbeat(ctx, summary, hub, ag)


def _certificate(ctx):
    from . import identity
    cur = os.path.join(ctx.paths.identity_dir, "current")
    na = identity.cert_not_after(os.path.join(os.path.realpath(cur), "client.pem"))
    if na is None:
        ctx.warn("the client certificate cannot be read")
        return
    days = (na - ctx.now) / DAY
    when = evmod.rfc3339(na * 1000)[:10]
    if days <= 0:
        ctx.fail("the client certificate expired on %s: enroll again with a token made --for this host" % when)
    elif days < 30:
        ctx.warn("the client certificate expires in %d days (%s) and has not renewed" % (days, when))
    else:
        ctx.pass_("the client certificate is valid for %d more days" % days)


def _droplet(ctx):
    p = ctx.paths.droplet_id
    try:
        st = os.lstat(p)
        with open(p) as f:
            value = f.read(256).strip()
    except OSError:
        value, st = "", None
    if not value or st is None:
        ctx.warn("/run/edr-droplet-id is missing or empty: clone detection is blind without it")
        return
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    if st.st_uid != ctx.owner_uid or (st.st_mode & 0o777) != 0o640 or (ctx.owner_uid == 0 and group != "edr-agent"):
        ctx.warn("/run/edr-droplet-id is %s:%s %04o, expected root:edr-agent 0640" % (st.st_uid, group, st.st_mode & 0o777))
    else:
        ctx.pass_("the droplet id is present (root:edr-agent 0640)")


def _heartbeat(ctx, summary, hub, ag):
    if summary is None:
        return
    if hub.get("mode") != "enrolled":
        state, _ = read_json(ctx.paths.agent_state_json, 8192)
        seen = (state or {}).get("last_seen")
        age = ctx.now - seen if isinstance(seen, (int, float)) else None
        if age is None:
            ctx.info("heartbeat: n/a in local mode (no event processed yet)")
        elif age > HEARTBEAT_FAIL_S:
            ctx.fail("local mode: the last event processed was %d minutes ago" % (age // 60))
        elif age > HEARTBEAT_WARN_S:
            ctx.warn("local mode: the last event processed was %d s ago" % age)
        else:
            ctx.pass_("local mode: heartbeat n/a, last event processed %d s ago" % age)
        return
    if ctx.local:
        ctx.info("hub checks skipped (--local)")
        return
    ok = hub.get("last_heartbeat_ok")
    err = hub.get("last_error") or ""
    unreachable = isinstance(hub.get("unreachable_s"), (int, float)) and hub["unreachable_s"] > HEARTBEAT_WARN_S
    orphan = bool(hub.get("orphan"))
    blocked = hub.get("blocked") or ""
    if orphan or blocked == "host_orphan":
        ctx.warn("the hub says 403 host_orphan: adopt this host on the hub (edr-hub host NAME adopt)")
    elif blocked:
        ctx.fail("the hub refuses this host: %s (revoked, moved, retired or unknown: see the runbook)" % clean(blocked, 40))
    held = hub.get("held") or {}
    for route, code in (held.items() if isinstance(held, dict) else []):
        text = str(code)
        if "426" in text or "proto" in text:
            ctx.warn("the hub says 426 (protocol): this agent is too old for it (%s)" % clean(route, 20))
        elif "422" in text or "schema" in text:
            ctx.warn("the hub says 422 schema_too_old (%s): events are kept and retried hourly" % clean(route, 20))
    mcs = hub.get("min_client_schema")
    if isinstance(mcs, int) and not isinstance(mcs, bool) and SCHEMA < mcs:
        ctx.warn("this agent's event schema %d is below the hub's minimum %d: upgrade it" % (SCHEMA, mcs))
    if unreachable:
        ctx.warn("the hub has been unreachable for %d minutes%s" % (hub["unreachable_s"] // 60, " (last error: %s)" % clean(err, 60) if err else ""))
    if isinstance(ok, (int, float)):
        age = ctx.now - ok
        if age > HEARTBEAT_FAIL_S and not err and not blocked and not orphan:
            ctx.fail("the last accepted heartbeat was %d minutes ago and there is no error: the uplink is stuck" % (age // 60))
        elif age > HEARTBEAT_FAIL_S:
            ctx.warn("the last accepted heartbeat was %d minutes ago (the hub is unreachable or refusing)" % (age // 60))
        elif age > HEARTBEAT_WARN_S:
            ctx.warn("the last accepted heartbeat was %d s ago" % age)
        else:
            ctx.pass_("the last accepted heartbeat was %d s ago" % age)
    else:
        started = ag.get("started")
        up = ctx.now - started if isinstance(started, (int, float)) else 0
        if up > HEARTBEAT_FAIL_S and not err and not blocked and not orphan:
            ctx.fail("no heartbeat has been accepted in the %d minutes since the agent started, and there is no error" % (up // 60))
        else:
            ctx.warn("no heartbeat has been accepted yet (agent up %d s)" % up)


# ---- bans and conntrack (P1b) -----------------------------------------------------------------------------
def bans(ctx):
    paths = ctx.paths
    obj, reason = read_json(paths.bans_counters, 1024 * 1024)
    age = file_age(paths.bans_counters, ctx.now)
    if obj is None:
        ctx.warn("/run/edr-bans/counters.json is %s: nft state unknown" % reason)
    else:
        written = obj.get("written_at")
        age = ctx.now - written if isinstance(written, (int, float)) else age
        if age is not None and age > 300:
            ctx.warn("the ban counters are %d minutes old: edr-bans is not running" % (age // 60))
        sets = obj.get("sets") if isinstance(obj.get("sets"), dict) else {}
        if obj.get("table_present") is True:
            ctx.pass_("table inet edr is present (%s)" % ", ".join("%s=%s" % (clean(k, 20), clean(v, 10)) for k, v in sorted(sets.items())[:8]))
        elif ctx.pause:
            ctx.warn("table inet edr is not in the expected state: %s" % ctx.paused_text())
        else:
            ctx.fail("table inet edr is absent: no ban is in force (edr-bans.service repairs it within a minute)")
        la = obj.get("last_apply") if isinstance(obj.get("last_apply"), dict) else {}
        if la.get("ok") is False or la.get("error"):
            ctx.warn("edr-bans last apply failed: %s" % clean(la.get("error", ""), 100))
        elif la:
            ctx.pass_("edr-bans last apply is clean")
        if ctx.pause:
            ctx.warn("ban sets are empty by design: %s" % ctx.paused_text())
    _conntrack(ctx, obj)
    bj, reason = read_json(paths.bans_json, 16 * 1024 * 1024)
    if bj is not None:
        never = bj.get("never") if isinstance(bj.get("never"), list) else []
        if not never:
            ctx.warn("bans.json has an empty never-ban list")
        else:
            ctx.pass_("never-ban list holds %d entries" % len(never))
        meta = ipaddress_in("169.254.169.254", [b.get("cidr") for b in bj.get("bans") or [] if isinstance(b, dict)])
        if meta:
            ctx.fail("169.254.169.254 is covered by a ban: %s" % meta)
        else:
            ctx.pass_("169.254.169.254 is in no ban")
        for h in hub_addresses(ctx):
            if ipaddress_in(h, never) is None:
                ctx.warn("the hub address %s is not in the never-ban list" % h)


def ipaddress_in(ip, cidrs):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for c in cidrs:
        try:
            if a in ipaddress.ip_network(str(c), strict=False):
                return str(c)
        except ValueError:
            continue
    return None


def hub_addresses(ctx):
    from . import render
    return render.hub_addresses(ctx.paths)


def _conntrack(ctx, counters):
    ct = counters.get("conntrack") if counters and isinstance(counters.get("conntrack"), dict) else None
    count = maxi = None
    if ct:
        count, maxi = ct.get("count"), ct.get("max")
    else:
        try:
            with open(ctx.paths.proc("sys", "net", "netfilter", "nf_conntrack_count")) as f:
                count = int(f.read(32))
            with open(ctx.paths.proc("sys", "net", "netfilter", "nf_conntrack_max")) as f:
                maxi = int(f.read(32))
        except (OSError, ValueError):
            pass
    if not all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (count, maxi)) or not maxi:
        ctx.info("conntrack use is not available")
        return
    pct = 100.0 * count / maxi
    if pct >= 90:
        ctx.fail("conntrack is %d%% full (%d of %d)" % (pct, count, maxi))
    elif pct >= 70:
        ctx.warn("conntrack is %d%% full (%d of %d)" % (pct, count, maxi))
    else:
        ctx.pass_("conntrack is %d%% full" % pct)
    if ct:
        state, _ = read_json(os.path.join(ctx.paths.state_dir, "check-conntrack.json"), 4096)
        cur = {"drop": ct.get("drop", 0), "early_drop": ct.get("early_drop", 0)}
        if state and any(isinstance(cur[k], int) and isinstance(state.get(k), int) and cur[k] > state[k] for k in cur):
            ctx.warn("conntrack drop counters are rising (drop %s, early_drop %s)" % (cur["drop"], cur["early_drop"]))
        try:
            with open(os.path.join(ctx.paths.state_dir, "check-conntrack.json"), "w") as f:
                json.dump(cur, f)
        except OSError:
            pass


# ---- Tetragon (P1a) ---------------------------------------------------------------------------------------
def tetragon(ctx):
    paths = ctx.paths
    if not ctx.on("kit", "tetragon"):
        ctx.info("Tetragon is switched off in local.conf ([kit] tetragon = off): skipped")
        return
    obj, reason = read_json(paths.policy_check_status, STATUS_MAX)
    if obj is None:
        ctx.warn("/run/edr-policy-check/status.json is %s: policy state unknown" % reason)
    else:
        written = obj.get("written_at")
        age = ctx.now - written if isinstance(written, (int, float)) else file_age(paths.policy_check_status, ctx.now)
        if age is None or age > 300:
            ctx.warn("the policy check is %s old (the helper runs every 2 minutes)" % ("of unknown age" if age is None else "%d minutes" % (age // 60)))
        else:
            ctx.pass_("the policy check is %d s old" % age)
        gone = obj.get("enforcement_gone")
        if isinstance(gone, list) and gone:
            ctx.fail("enforcement is gone for: %s" % ", ".join(clean(g, 32) for g in gone[:6]))
        else:
            ctx.pass_("no policy has lost enforcement")
        want = set(ctx.cfg.getlist("tetragon", "enforce"))
        pols = [p for p in obj.get("policies") or [] if isinstance(p, dict) and isinstance(p.get("name"), str)]
        by = {p["name"]: p for p in pols}
        for name in sorted(want):
            p = by.get(name)
            if p is None:
                (ctx.warn if ctx.pause else ctx.fail)("policy %s is set to enforce and is not loaded%s" % (name, " (" + ctx.paused_text() + ")" if ctx.pause else ""))
            elif p.get("state") != "loaded":
                ctx.fail("policy %s is %s" % (name, clean(p.get("state"), 16)))
            elif p.get("mode") == "enforce":
                ctx.pass_("policy %s is loaded and enforcing" % name)
            elif ctx.pause:
                ctx.warn("policy %s is held in monitor: %s" % (name, ctx.paused_text()))
            else:
                ctx.warn("policy %s stays in monitor: %s" % (name, clean(p.get("gate") or "its gate has not passed yet", 100)))
        for p in pols:
            if p["name"] not in want and p.get("state") not in ("loaded", None):
                ctx.fail("policy %s is %s" % (p["name"], clean(p.get("state"), 16)))
        canary = obj.get("canary") if isinstance(obj.get("canary"), dict) else {}
        if canary.get("ok") is False:
            ctx.fail("the enforcement canary failed: %s" % clean(canary.get("detail", ""), 80))
    # the log: edr-agent:640
    p = paths.tetragon_log
    try:
        st = os.stat(p)
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = str(st.st_gid)
        if (st.st_mode & 0o777) != 0o640 or (ctx.owner_uid == 0 and group != "edr-agent"):
            ctx.fail("%s is %s %04o, expected group edr-agent 0640: the agent cannot read it" % (p, group, st.st_mode & 0o777))
        else:
            ctx.pass_("tetragon.log is group edr-agent 0640")
    except OSError:
        ctx.warn("%s does not exist" % p)
    left = []
    try:
        for n in sorted(os.listdir(paths.tetragon_tp_dir)):
            if n.endswith(".yaml") and n.startswith("edr-"):
                with open(os.path.join(paths.tetragon_tp_dir, n), errors="replace") as f:
                    if "@HOME@" in f.read(1 << 20):
                        left.append(n)
    except OSError:
        pass
    if left:
        ctx.fail("@HOME@ is left in a rendered policy (it never matches): %s" % ", ".join(left))
    else:
        ctx.pass_("no @HOME@ in the rendered policies")
    _drift(ctx)


def _drift(ctx):
    if ctx.phase() == "P1a":
        return                            # coverage drift ships with P1b
    inv, _ = read_json(ctx.paths.inventory_json, STATUS_MAX)
    checks = (inv or {}).get("checks") if isinstance((inv or {}).get("checks"), dict) else {}
    found = False
    for name in ("uncovered_webroots", "uncovered_fpm_binaries", "uncovered_pool_users"):
        c = checks.get(name)
        if isinstance(c, dict) and c.get("status") is True:
            found = True
            items = c.get("paths") or c.get("users") or []
            ctx.warn("coverage drift (%s): %s: run edr-agent discover, then apply-config" % (name, clean(", ".join(map(str, items[:4])), 100)))
    if inv and not found:
        ctx.pass_("coverage: every web root, php-fpm binary and pool user is covered by the rendered policies")


# ---- DNS (P1b) --------------------------------------------------------------------------------------------
def dns(ctx):
    if not ctx.on("dns", "lockdown"):
        ctx.info("[dns] lockdown = off: the DNS lock checks are skipped")
        return
    obj, reason = read_json(ctx.paths.dns_watch_status, 65536)
    if obj is None:
        ctx.warn("/run/edr-dns-watch/status.json is %s: the lock state is unknown" % reason)
        return
    state = obj.get("state")
    since = obj.get("since")
    if state == "locked":
        ctx.pass_("the DNS lock is locked (%s re-locks)" % clean(obj.get("relocks", 0), 6))
    elif state == "open":
        ctx.fail("the DNS lock is OPEN: plain DNS is allowed (the watchdog opened it because DoH failed)")
    elif state == "paused":
        ctx.warn("the DNS lock is not in force: %s" % (ctx.paused_text() if ctx.pause else "state paused"))
    elif state == "flapping":
        ctx.warn("the DNS lock keeps failing and re-locking (flapping): fix the proxy, then edr-dns-watch relock")
    else:
        ctx.warn("the DNS lock state is unknown (%s)" % clean(state, 20))
    if state != "paused" and not ctx.pause:
        age = ctx.now - obj["written_at"] if isinstance(obj.get("written_at"), (int, float)) else file_age(ctx.paths.dns_watch_status, ctx.now)
        if age is not None and age > 120:
            ctx.warn("the DNS watch status is %d minutes old" % (age // 60))
    elif ctx.pause:
        ctx.warn("DNS lock checks are relaxed: %s" % ctx.paused_text())


# ---- disk (P1a; Suricata paths P1b) -------------------------------------------------------------------------
def disk(ctx):
    paths = ctx.paths
    obj, reason = read_json(paths.diskguard_status, 65536)
    if obj is None:
        ctx.warn("/run/edr-diskguard/status.json is %s" % reason)
    else:
        written = obj.get("written_at")
        age = ctx.now - written if isinstance(written, (int, float)) else file_age(paths.diskguard_status, ctx.now)
        if age is None or age > 300:
            ctx.warn("the disk guard status is %s old" % ("of unknown age" if age is None else "%d minutes" % (age // 60)))
        else:
            ctx.pass_("the disk guard ran %d s ago" % age)
        stage = obj.get("stage")
        if isinstance(stage, int) and stage > 0:
            ctx.fail("the disk guard is at stage %d (free space %s%%)" % (stage, clean(obj.get("free_pct", "?"), 8)))
        elif isinstance(obj.get("free_pct"), (int, float)):
            ctx.pass_("free disk space is %.0f%%" % obj["free_pct"])
    for label, pattern, budget in BUDGETS:
        if "suricata" in pattern.lower() and (not ctx.on("kit", "suricata") or not phase_ge(ctx.phase(), "P1b")):
            continue
        if "tetragon" in pattern and not ctx.on("kit", "tetragon"):
            continue
        if pattern == "{state}":
            size = _dir_size(paths.state_dir) if os.path.isdir(paths.state_dir) else 0
        else:
            import glob
            size = 0
            for f in glob.glob(paths._p(pattern)):
                try:
                    size += os.lstat(f).st_size
                except OSError:
                    pass
        if size == 0 and pattern != "{state}":
            continue
        mb = size / 1048576.0
        if mb > budget:
            ctx.warn("%s uses %.0f MB, over its %d MB budget" % (label, mb, budget))
        else:
            ctx.pass_("%s uses %.0f MB of %d" % (label, mb, budget))


# ---- nginx, packages and kernel (P1a) ------------------------------------------------------------------------
FAIL_CHECKS = {"nginx_pkg", "nginx_exposure", "deleted_exe"}


def nginx(ctx):
    inv, reason = read_json(ctx.paths.inventory_json, STATUS_MAX)
    if inv is None:
        ctx.warn("inventory.json is %s: package, kernel and nginx exposure are unknown, not clean" % reason)
        return
    checks = inv.get("checks") if isinstance(inv.get("checks"), dict) else {}
    findings = [f for f in inv.get("findings") or [] if isinstance(f, dict)]
    if not findings:
        ctx.pass_("the inventory reports no finding")
    for f in findings:
        check, sev = str(f.get("check", "?")), f.get("sev")
        text = "%s: %s" % (clean(check, 40), clean(f.get("summary", ""), 140))
        if sev in ("HIGH", "CRITICAL") and check in FAIL_CHECKS:
            ctx.fail(text + (" (restart nginx, a reload is not enough)" if check == "deleted_exe" else ""))
        elif sev in ("INFO",):
            ctx.info(text)
        else:
            ctx.warn(text)
    sp = checks.get("security_pending")
    if isinstance(sp, dict):
        lists = sp.get("lists_age_hours")
        if isinstance(lists, (int, float)) and lists > 48:
            ctx.warn("the apt lists are %d hours old (over 48): security_pending may be stale" % lists)
    if os.path.exists(ctx.paths._p("/var/run/reboot-required")) or os.path.exists(ctx.paths._p("/run/reboot-required")):
        ctx.warn("a reboot is required")
    nl = checks.get("nginx_logs")
    if isinstance(nl, dict) and isinstance(nl.get("error_logs"), list):
        blind = set()
        order = ["debug", "info", "notice", "warn", "error", "crit", "alert", "emerg"]
        for e in nl["error_logs"]:
            lvl = e.get("level") if isinstance(e, dict) else None
            if lvl in order:
                i = order.index(lvl)
                if i > order.index("info"):
                    blind.add("window_update (info)")
                if i > order.index("warn"):
                    blind.add("conn_pressure (warn)")
        if blind:
            ctx.info("nginx error_log level hides these markers: %s" % ", ".join(sorted(blind)))
        fmts = nl.get("log_formats") if isinstance(nl.get("log_formats"), dict) else {}
        used = [a.get("format") for a in nl.get("access_logs") or [] if isinstance(a, dict)]
        bad = [n for n in used if isinstance(fmts.get(n), dict) and fmts[n].get("starts_remote_addr") is False]
        if bad:
            ctx.warn("log_format %s does not start with $remote_addr: no address is taken from the access log" % clean(bad[0], 40))
    ri = checks.get("real_ip")
    if isinstance(ri, dict) and ri.get("status") is True:
        ctx.info("real_ip or an X-Forwarded-For log format is configured: web-sourced bans are off")
    sc = checks.get("sctp")
    if isinstance(sc, dict) and sc.get("builtin") is True:
        ctx.warn("SCTP is built into this kernel: the module block cannot cover it")
    posture = inv.get("posture") if isinstance(inv.get("posture"), dict) else {}
    if phase_ge(ctx.phase(), "P1b") and posture:
        # the findings above already print every posture field the inventory judged; only a field it left without a
        # finding (an older inventory file) is added here, so nothing is printed twice
        reported = {(f.get("details") or {}).get("field") for f in findings if f.get("check") == "posture" and isinstance(f.get("details"), dict)}
        for k, v in sorted(posture.items()):
            if k in ("app_debug_true", "nginx_php_any", "app_key_in_public", "world_writable_in_webroot", "public_listeners") and v is True \
                    and k not in reported:
                ctx.warn("posture: %s" % k)


# ---- Suricata drops (P1b) and the network facts check.sh pipes in ----------------------------------------
def suricata(ctx):
    if not ctx.on("kit", "suricata"):
        ctx.info("Suricata is switched off in local.conf: skipped")
        return
    rs, _ = read_json(ctx.paths.rules_status, 65536)
    if rs is not None:
        written = rs.get("written_at")
        age = ctx.now - written if isinstance(written, (int, float)) else None
        skipped = rs.get("skipped_days") if isinstance(rs.get("skipped_days"), int) else 0
        if rs.get("ok") is True and (age is None or age <= 3 * DAY):
            ctx.pass_("the last rule update succeeded%s" % ("" if age is None else " %d hours ago" % (age // 3600)))
        elif rs.get("ok") is True:
            ctx.warn("the last rule update succeeded %d days ago: the rules are going stale" % (age // DAY))
        else:
            ctx.warn("the last rule update did not succeed (%s)%s" % (clean(rs.get("message", ""), 80),
                                                                   ", %d day(s) skipped" % skipped if skipped else ""))
    summary, _ = read_json(ctx.paths.summary_json, 1024 * 1024)
    d = ((summary or {}).get("agent") or {}).get("suricata_drops")
    if not isinstance(d, dict) or not isinstance(d.get("packets"), (int, float)) or d["packets"] <= 0:
        ctx.info("no Suricata stats record has been seen yet: the kernel drop share is unknown")
        return
    share = 100.0 * (d.get("drops") or 0) / d["packets"]
    if share > 1.0:
        ctx.warn("Suricata dropped %.1f%% of packets in the last %s s (over 1%%)" % (share, clean(d.get("window_s", "?"), 6)))
    else:
        ctx.pass_("Suricata dropped %.2f%% of packets in the last %s s" % (share, clean(d.get("window_s", "?"), 6)))


def _split_stdin(text):
    # two separators only: the third part is a YAML file, and its own second line is "---"
    parts = text.split("\n---\n", 2)
    parts += [""] * (3 - len(parts))
    return parts[0], parts[1], parts[2]


def netcheck(ctx):
    """stdin: `ip -o addr`, a line `---`, `ip route show`, a line `---`, the text of edr-home-net.yaml (may be empty).
    HOME_NET must cover every address of the box (FAIL when it does not: Suricata would call its own traffic external);
    the never-ban list must hold the admin addresses, the gateway and the box's own addresses (WARN)."""
    import ipaddress
    addr_text, route_text, yaml_text = _split_stdin(ctx.stdin)
    own = []
    for line in addr_text.splitlines():
        m = re.search(r"\binet6? ([0-9a-fA-F:.]+)/\d+", line)
        if not m:
            continue
        try:
            ip = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local:
            continue
        own.append(ip)
    gw = []
    for m in re.finditer(r"^default via ([0-9a-fA-F:.]+)", route_text, re.MULTILINE):
        try:
            gw.append(ipaddress.ip_address(m.group(1)))
        except ValueError:
            pass
    if ctx.on("kit", "suricata") and phase_ge(ctx.phase(), "P1b"):
        m = re.search(r"HOME_NET:\s*['\"]?\[?([^\]'\"\n]*)", yaml_text)
        nets = []
        if m:
            for part in m.group(1).split(","):
                try:
                    nets.append(ipaddress.ip_network(part.strip(), strict=False))
                except ValueError:
                    pass
        if not nets:
            ctx.warn("HOME_NET could not be read from edr-home-net.yaml")
        else:
            lacking = [str(a) for a in own if not any(a in n for n in nets if n.version == a.version)]
            if lacking:
                ctx.fail("HOME_NET lacks %s: Suricata would treat the box's own traffic as external" % ", ".join(lacking[:4]))
            else:
                ctx.pass_("HOME_NET covers every address of the box")
    bj, _ = read_json(ctx.paths.bans_json, 16 * 1024 * 1024)
    if bj is not None and phase_ge(ctx.phase(), "P1b"):
        never = [str(x) for x in bj.get("never") or []]
        want = [("admin address", ipaddress.ip_address(a.split("/")[0])) for a in ctx.cfg.getlist("bans", "admin_ip") if "/" in a or a]
        want += [("gateway", g) for g in gw] + [("own address", a) for a in own]
        missing = [(label, str(a)) for label, a in want if ipaddress_in(str(a), never) is None]
        if missing:
            ctx.warn("the never-ban list lacks: %s" % ", ".join("%s %s" % m for m in missing[:5]))
        else:
            ctx.pass_("the never-ban list holds the admin addresses, the gateway and the box's own addresses")


# ---- misc entry points ----------------------------------------------------------------------------------------
SECTIONS = {"kit": kit, "audit": audit, "agent": agent, "bans": bans, "tetragon": tetragon, "dns": dns, "disk": disk, "nginx": nginx,
            "suricata": suricata, "netcheck": netcheck}


def run_section(name, paths, cfg, now=None, local=False, owner_uid=0, phase=None, stdin=""):
    ctx = Ctx(paths, cfg, now, local, owner_uid, phase, stdin)
    try:
        SECTIONS[name](ctx)
    except Exception as e:                        # a bug in a check must show as a WARN, never end the whole run
        ctx.warn("check %s failed to run: %r" % (name, e))
    return ctx.out


def helper_value(what, paths, cfg, now=None):
    """Small values check.sh needs: phase, pause, a switch."""
    ctx = Ctx(paths, cfg, now)
    if what == "phase":
        return ctx.phase()
    if what == "pause":
        return "%d" % ctx.pause if ctx.pause else ""
    if what == "enrolled":
        return "yes" if ctx.enrolled() else "no"
    if what == "web_user":
        users = cfg.getlist("sites", "web_users")
        return users[0] if users else ""
    if what == "nginx_bin":
        return cfg.get("sites", "nginx_bin", "")
    if what.startswith("policy_mode:"):
        obj, _ = read_json(paths.policy_check_status, STATUS_MAX)
        for p in (obj or {}).get("policies") or []:
            if isinstance(p, dict) and p.get("name") == what[12:]:
                return "%s/%s" % (p.get("mode", "?"), p.get("state", "?"))
        return "missing"
    if what == "notify":
        return "yes" if os.path.exists(paths.notify_url) else "no"
    if what == "tp_names":
        names = []
        try:
            for n in sorted(os.listdir(paths.tetragon_tp_dir)):
                if n.startswith("edr-") and n.endswith(".yaml"):
                    with open(os.path.join(paths.tetragon_tp_dir, n), errors="replace") as f:
                        m = re.search(r'^\s*name:\s*"?([A-Za-z0-9_.-]+)"?\s*$', f.read(1 << 20), re.MULTILINE)
                    if m:
                        names.append(m.group(1))
        except OSError:
            pass
        return " ".join(names)
    if what.startswith("conf:"):
        s, _, k = what[5:].partition(".")
        v = cfg.raw.get((s, k))
        return "" if v is None else str(v)
    return ""
