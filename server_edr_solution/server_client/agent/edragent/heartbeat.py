"""The heartbeat body (hub PLAN Appendix A is the authority for every key).

build(state) returns every key this module owns. The uplink adds what it owns: sent_at, seq and epoch, spool,
policy_rev_applied, last_apply_error, ban_counts, cert_not_after and droplet_id. Units are read without
spawning systemctl (the agent's own execs would show in the Tetragon log it tails): a long-running unit is
`running` when its cgroup exists under system.slice, a helper that writes a status file is `fresh` or `stale`
by the age of that file. A fact that cannot be read is left out, never guessed: the hub reads some absent
values as unknown and some wrong values as an incident.
"""
import hashlib
import json
import os
import time

from . import SCHEMA, PROTO, VERSION
from . import event as evmod

INVENTORY_RESEND_S = 3600
LONG_RUNNING = (("tetragon", "tetragon"), ("suricata", "suricata"), ("dnscrypt-proxy", None), ("nginx", "web"))
HELPERS = ("edr-bans", "edr-inventory", "edr-diskguard", "edr-dns-watch", "edr-policy-check")

_hash_cache = {}


def agent_sha256(lib_dir):
    """SHA-256 over the agent's code: every .py file under edr-agent.py's directory, by sorted relative path.

    The release build must compute the same value for agent-hashes.json (`edr-agent.py version --hash`).
    """
    key = lib_dir
    if key in _hash_cache:
        return _hash_cache[key]
    h = hashlib.sha256()
    files = []
    for root, dirs, names in os.walk(lib_dir):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for n in sorted(names):
            if n.endswith(".py") and not n.startswith("test_"):
                files.append(os.path.join(root, n))
    for path in files:
        rel = os.path.relpath(path, lib_dir)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        h.update(rel.encode() + b"\0" + data + b"\0")
    _hash_cache[key] = h.hexdigest()
    return _hash_cache[key]


class HeartbeatState:
    """What build() reads. The daemon creates one; tests may fill the fields they need."""

    def __init__(self, cfg, paths, ctx, helpers, pipeline=None, clock=time.time):
        self.cfg, self.paths, self.ctx, self.helpers, self.pipeline, self.clock = cfg, paths, ctx, helpers, pipeline, clock
        self.inventory_sent_sha = None
        self.inventory_sent_at = 0.0


def _read(path, limit=4096):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return None


def _boot_id(paths):
    text = _read(paths.proc("sys", "kernel", "random", "boot_id"), 128)
    return text.strip()[:36] if text else evmod.boot_id()


def _uptime(paths):
    text = _read(paths.proc("uptime"), 128)
    try:
        return int(float(text.split()[0]))
    except (AttributeError, ValueError, IndexError):
        return None


def _kernel(paths):
    text = _read(paths.proc("version_signature"), 256)
    if text and text.strip():
        return text.strip()[:128]
    text = _read(paths.proc("sys", "kernel", "osrelease"), 128)
    return text.strip()[:128] if text and text.strip() else None


def _load(paths):
    text = _read(paths.proc("loadavg"), 128)
    try:
        a = text.split()
        return {"1m": float(a[0]), "5m": float(a[1]), "15m": float(a[2])}
    except (AttributeError, ValueError, IndexError):
        return None


def _mem(paths):
    text = _read(paths.proc("meminfo"), 8192)
    if not text:
        return None
    vals = {}
    for line in text.splitlines():
        name, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            vals[name] = int(parts[0])
    if "MemTotal" not in vals:
        return None
    out = {"total_mb": vals["MemTotal"] // 1024}
    if "MemAvailable" in vals:
        out["available_mb"] = vals["MemAvailable"] // 1024
        out["used_pct"] = round(100.0 * (vals["MemTotal"] - vals["MemAvailable"]) / vals["MemTotal"], 1)
    if "SwapTotal" in vals:
        out["swap_total_mb"] = vals["SwapTotal"] // 1024
        out["swap_free_mb"] = vals.get("SwapFree", 0) // 1024
    return out


def _disk(paths):
    path = paths.state_dir
    while path and not os.path.exists(path):
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    try:
        st = os.statvfs(path)
    except OSError:
        return None
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    if total <= 0:
        return None
    return {"free_pct": round(100.0 * free / total, 1), "free_mb": free // (1024 * 1024), "total_mb": total // (1024 * 1024)}


def _units(state):
    cfg, paths = state.cfg, state.paths
    units = {"edr-agent": "running"}        # this process is the agent
    base = paths.cgroup_system_slice()
    for name, switch in LONG_RUNNING:
        if switch is not None and not cfg.getbool("kit", switch, True):
            continue                         # a component the operator switched off is not "absent"
        units[name] = "running" if os.path.isdir(os.path.join(base, name + ".service")) else "absent"
    for name in HELPERS:
        units[name] = "fresh" if state.helpers is not None and state.helpers.fresh(name, state.clock()) else "stale"
    return units


def _pause_until(paths, now):
    """RFC 3339 time of the end of a valid pause, or None (an expired file is ignored)."""
    try:
        with open(paths.pause_json, "rb") as f:
            until = json.loads(f.read(4096)).get("until")
    except (OSError, ValueError, AttributeError):
        return None
    if isinstance(until, (int, float)) and not isinstance(until, bool) and until > now:
        return evmod.rfc3339(int(until * 1000))
    return None


def build(state):
    """The heartbeat body: a dict of JSON-ready values."""
    now = state.clock()
    cfg, paths, helpers = state.cfg, state.paths, state.helpers
    hb = {"schema": SCHEMA, "proto": PROTO, "agent_version": VERSION, "agent_sha256": agent_sha256(paths.lib_dir),
          "boot_id": _boot_id(paths), "local_conf_sha256": cfg.sha256, "units": _units(state)}
    for key, value in (("uptime_s", _uptime(paths)), ("kernel", _kernel(paths)), ("disk", _disk(paths)),
                       ("load", _load(paths)), ("mem", _mem(paths))):
        if value is not None:
            hb[key] = value
    if helpers is not None:
        if helpers.fresh("edr-policy-check", now):
            hb["tetragon"] = helpers.tetragon_list()
        for key, value in (("nft", helpers.nft()), ("conntrack", helpers.conntrack()), ("dns_lock", helpers.dns_lock())):
            if value:
                hb[key] = value
        inv = helpers.inventory_for_heartbeat()
        # the helper's own time stamp changes with every run; only a change of content is worth resending
        sha = hashlib.sha256(json.dumps({k: v for k, v in inv.items() if k != "written_at"}, sort_keys=True).encode()).hexdigest()
        if sha != state.inventory_sent_sha or now - state.inventory_sent_at >= INVENTORY_RESEND_S:
            hb["inventory"] = inv
            state.inventory_sent_sha, state.inventory_sent_at = sha, now
    if state.ctx is not None and state.ctx.suricata_drops:
        hb["suricata_drops"] = dict(state.ctx.suricata_drops)
    paused = _pause_until(paths, now)
    if paused:
        hb["paused_until"] = paused
    if state.pipeline is not None:
        over = state.pipeline.stats().get("dropped")
        if over:
            hb["spool"] = {"over_budget": over}     # the uplink adds the rest of `spool`
    return hb
