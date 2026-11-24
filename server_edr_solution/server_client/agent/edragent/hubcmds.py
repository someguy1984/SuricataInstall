"""Subcommands of edr-agent that deal with the hub and with bans (client PLAN 4.2, 4.6, 5, 4.7).

    enroll [--hub IP:PORT] (--token-file PATH | --token -) [--enroll-port N] [--droplet-id ID]
    rehome --hub IP:PORT (--token-file PATH | --token -) [--rollback] [--drop-spool]
    bans
    unban ADDR | --all
    pause [--for DURATION]
    resume

The token is read from a file or from stdin, never from the command line. Also here, for the
installer and the unit files: `deregister --reason uninstall|rehome`, the hidden `hub-net`,
the network part of enrollment that runs in a sandbox as edr-agent with a JSON request on stdin, and the hidden
`rehome-resume`, which the agent's unit runs as root before every start to finish a rehome killed in step 7.
Exit codes are PLAN section 15: 0 done, 2 failed, 3 refused, 4 rolled back, 5 not enrolled, 64 usage.
"""

import argparse
import json
import os
import platform
import sys
import time
import uuid

from . import identity as idn
from .bans import BAN_REASONS, BAN_SOURCES, BanEngine, norm_cidr, own_addresses, parse_duration, parse_net
from .spool import atomic_write, read_file_safe, read_json_safe, rfc3339

EXIT_OK, EXIT_FAIL, EXIT_REFUSED, EXIT_ROLLED_BACK, EXIT_NOT_ENROLLED, EXIT_USAGE = 0, 2, 3, 4, 5, 64
PAUSE_DEFAULT_S = 3600
PAUSE_MAX_S = 24 * 3600
TOKEN_CAP = 512
CMD_WAIT_S = 10.0


# ---- helpers ---------------------------------------------------------------------------------

def _clean(text, limit=300):
    """Printable ASCII only: root runs these commands and some text comes from files others can write."""
    out = "".join(c if 32 <= ord(c) < 127 else "?" for c in str(text))
    return out[:limit]


def _say(msg, err=False):
    print(_clean(msg, 600), file=sys.stderr if err else sys.stdout)


def _paths():
    from .paths import Paths
    return Paths()


def _cfg(paths):
    try:
        from . import config
        return config.load(paths)
    except Exception:
        return {}


def _dev(paths):
    return bool(getattr(paths, "dev", os.environ.get("EDR_AGENT_ROOT")))


def _need_root(paths):
    if _dev(paths) or os.geteuid() == 0:
        return True
    _say("this command must run as root (use sudo)", err=True)
    return False


def read_token(args):
    """The token from stdin (--token -), --token-file or EDR_TOKEN. A value on the command line is refused."""
    value = getattr(args, "token", None)
    path = getattr(args, "token_file", None)
    if value is not None:
        if value != "-":
            raise idn.IdentityError("a token on the command line is refused (any local user can read process arguments): "
                                    "use --token-file PATH or --token - with the token on stdin", EXIT_USAGE)
        raw = sys.stdin.read(TOKEN_CAP + 1)
    elif path:
        data = read_file_safe(path, TOKEN_CAP)
        if data is None:
            raise idn.IdentityError("cannot read the token file (it must be a regular file under %d bytes)" % TOKEN_CAP, EXIT_REFUSED)
        try:
            if os.stat(path).st_mode & 0o077:
                _say("warning: the token file is readable by others; create it with umask 077", err=True)
        except OSError:
            pass
        raw = data.decode("utf-8", "replace")
    elif os.environ.get("EDR_TOKEN"):
        raw = os.environ["EDR_TOKEN"]
    else:
        raise idn.IdentityError("no token: use --token-file PATH or --token - (token on stdin)", EXIT_USAGE)
    raw = raw.strip()
    if len(raw) > TOKEN_CAP:
        raise idn.IdentityError("the token is too long", EXIT_REFUSED)
    idn.parse_token(raw)
    return raw


def _labels(paths):
    hostname = platform.node()[:253]
    osname = ""
    raw = read_file_safe("/etc/os-release", 16 * 1024)
    if raw:
        for line in raw.decode("utf-8", "replace").splitlines():
            if line.startswith("PRETTY_NAME="):
                osname = line.split("=", 1)[1].strip().strip('"')[:128]
    if not osname:
        osname = (platform.system() + " " + platform.release())[:128]
    ips = []
    for n in own_addresses(str(getattr(paths, "proc_dir", "/proc"))):
        ip = n.network_address
        if ip.is_loopback or ip.is_link_local or ip.is_multicast:
            continue
        ips.append(str(ip))
    return hostname, osname, ips[:16]


def _droplet_for_enroll(paths, args):
    running = idn.running_droplet_id(paths)
    given = getattr(args, "droplet_id", None)
    if given is not None:
        if running:
            raise idn.IdentityError("--droplet-id is refused: the droplet id is known (%s); it is accepted only when "
                                    "the metadata service does not answer" % _clean(running, 64), EXIT_REFUSED)
        if not idn.valid_droplet_id(given):
            raise idn.IdentityError("--droplet-id is not a valid id", EXIT_REFUSED)
        return given
    did = running or idn.stored_droplet_id(paths)
    if not did:
        raise idn.IdentityError("the droplet id is unknown (no /run/edr-droplet-id): pass --droplet-id ID when "
                                "not on DigitalOcean", EXIT_REFUSED)
    return did


def _net_runner(paths, args, hub_ip):
    if _dev(paths) or os.geteuid() != 0 or getattr(args, "no_sandbox", False):
        return None
    lib = str(paths.lib_dir)

    def run(params, token):
        return idn.run_net_phase_sandboxed(params, token, lib)
    return run


# ---- enroll ----------------------------------------------------------------------------------

def cmd_enroll(args):
    paths = _paths()
    if not _need_root(paths):
        return EXIT_REFUSED
    ops = idn.SystemOps(paths)
    try:
        token = read_token(args)
        cur = idn.load_current(paths)
        if idn.rehome_in_progress(paths):
            raise idn.IdentityError("a rehome is in progress: run `edr-agent rehome --rollback` first", EXIT_REFUSED)
        if args.hub:
            hub, port = idn.parse_hub(args.hub)
            if cur is not None and (hub not in cur.addresses or port != cur.port):
                raise idn.IdentityError("this host is enrolled with another hub: use `edr-agent rehome --hub %s:%d` to move it"
                                        % (hub, port), EXIT_REFUSED)
        elif cur is not None:
            hub, port = cur.addresses[0], cur.port
        else:
            _say("--hub IP:PORT is required in local mode", err=True)
            return EXIT_USAGE
        eport = args.enroll_port or (cur.enroll_port if cur else idn.DEFAULT_ENROLL_PORT)
        if not (0 < eport < 65536):
            raise idn.IdentityError("--enroll-port is not a port", EXIT_USAGE)
        droplet = _droplet_for_enroll(paths, args)
        hostname, osname, ips = _labels(paths)
        rep = idn.enroll(paths, hub=hub, port=port, enroll_port=eport, token=token, droplet_id=droplet,
                         hostname=hostname, os_name=osname, ips=ips, ops=ops,
                         net_runner=_net_runner(paths, args, hub), allow_loopback=_dev(paths))
    except idn.IdentityError as exc:
        _say("enroll: %s" % exc, err=True)
        if exc.hub:
            _say("not enrolled; make a new token on the hub and run `edr-agent enroll` again", err=True)
            return EXIT_NOT_ENROLLED
        return exc.code
    _say("enrolled: host %s, hub %s, state %s" % (rep["host_uuid"], ",".join(rep["addresses"]), rep["state"]))
    _say("the host becomes active on its first accepted heartbeat")
    return EXIT_OK


# ---- rehome ----------------------------------------------------------------------------------

def cmd_rehome(args):
    paths = _paths()
    if not _need_root(paths):
        return EXIT_REFUSED
    ops = idn.SystemOps(paths)
    if args.rollback:
        rc = idn.rollback(paths, ops, log=_say)
        if rc == 0:
            _say("no rehome to roll back")
        return rc
    if not args.hub:
        _say("--hub IP:PORT is required", err=True)
        return EXIT_USAGE
    try:
        token = read_token(args)
        hub, port = idn.parse_hub(args.hub)
        cur = idn.load_current(paths)
        eport = args.enroll_port or (cur.enroll_port if cur else idn.DEFAULT_ENROLL_PORT)
        droplet = _droplet_for_enroll(paths, args) if getattr(args, "droplet_id", None) else (
            idn.running_droplet_id(paths) or idn.stored_droplet_id(paths))
        if not droplet:
            raise idn.IdentityError("the droplet id is unknown: pass --droplet-id ID", EXIT_REFUSED)
        hostname, osname, ips = _labels(paths)
    except idn.IdentityError as exc:
        _say("rehome: %s" % exc, err=True)
        return exc.code
    rc = idn.rehome(paths, _cfg(paths), hub=hub, port=port, enroll_port=eport, token=token, droplet_id=droplet,
                    hostname=hostname, os_name=osname, ips=ips, ops=ops, drop_spool=args.drop_spool,
                    net_runner=_net_runner(paths, args, hub), allow_loopback=_dev(paths),
                    lib_dir=str(paths.lib_dir), log=_say)
    if rc == 0:
        _say("rehomed to %s" % hub)
    return rc


def cmd_rehome_resume(args):
    """Hidden. The unit's ExecStartPre= (root, before every start of edr-agent): finish a rehome killed in step 7,
    touch nothing else (PLAN 5, last row of the rollback table). Never stops the agent from starting: the unit
    ignores the exit code."""
    paths = _paths()
    if not _need_root(paths):
        return EXIT_REFUSED
    res = idn.resume(paths, idn.SystemOps(paths), log=_say)
    return EXIT_FAIL if res == "failed" else EXIT_OK


# ---- deregister and the hidden network phase ---------------------------------------------------

def cmd_deregister(args):
    paths = _paths()
    oc = idn.deregister(paths, args.reason)
    if oc is None:
        _say("not enrolled: nothing to deregister")
        return EXIT_OK
    _say("deregister: %s %s" % (oc.action, oc.code))
    return EXIT_OK if oc.action == "ok" else EXIT_FAIL


def cmd_hub_net(args):
    """Read {"params", "token"} from stdin, run the network phase, print one JSON line."""
    try:
        req = json.loads(sys.stdin.read(64 * 1024))
        rep = idn.net_phase(req["params"], req["token"])
        out = {"ok": True, "reply": rep}
    except idn.IdentityError as exc:
        out = {"ok": False, "code": exc.code, "error": str(exc)[:300]}
    except Exception as exc:                                  # the root side validates everything it reads
        out = {"ok": False, "code": 2, "error": "network phase failed: %s" % exc.__class__.__name__}
    print(json.dumps(out))
    return EXIT_OK


# ---- bans ------------------------------------------------------------------------------------

def _remaining(sec):
    sec = int(sec)
    if sec <= 0:
        return "0s"
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    if d:
        return "%dd%dh" % (d, h)
    if h:
        return "%dh%dm" % (h, m)
    if m:
        return "%dm%ds" % (m, s)
    return "%ds" % s


def cmd_bans(args):
    """Local, hub and feed state: source, remaining time, counters (feeds as counts)."""
    paths = _paths()
    now = time.time()
    state = read_json_safe(str(paths.ban_state), 8 * 1024 * 1024)
    applied = read_json_safe(str(paths.bans_json), 16 * 1024 * 1024)
    pause = read_json_safe(str(paths.pause_json), 4096)
    if isinstance(pause, dict) and isinstance(pause.get("until"), (int, float)) and pause["until"] > now:
        _say("PAUSED until %s: no ban is applied" % rfc3339(pause["until"]))
    rows = []
    seen = set()
    for src in (state.get("bans") if isinstance(state, dict) else None, applied.get("bans") if isinstance(applied, dict) else None):
        if not isinstance(src, list):
            continue
        for b in src[:20000]:
            if not isinstance(b, dict):
                continue
            cidr = norm_cidr(b.get("cidr")) if isinstance(b.get("cidr"), str) else None
            exp = b.get("expires")
            if cidr is None or isinstance(exp, bool) or not isinstance(exp, (int, float)) or cidr in seen:
                continue
            seen.add(cidr)
            source = b.get("source") if b.get("source") in BAN_SOURCES else "unknown"
            reason = b.get("reason") if b.get("reason") in BAN_REASONS else "unknown"
            rung = b.get("rung") if isinstance(b.get("rung"), int) and not isinstance(b.get("rung"), bool) else None
            rows.append((source, cidr, reason, int(exp - now), rung))
    rows.sort(key=lambda r: (r[0], -r[3]))
    if rows:
        _say("%-9s %-40s %-14s %-10s %s" % ("SOURCE", "CIDR", "REASON", "REMAINING", "RUNG"))
        for source, cidr, reason, rem, rung in rows:
            if rem > 0:
                _say("%-9s %-40s %-14s %-10s %s" % (source, cidr, reason, _remaining(rem), "" if rung is None else rung))
    else:
        _say("no active bans")
    feeds = applied.get("feeds") if isinstance(applied, dict) else None
    if isinstance(feeds, dict) and feeds:
        for name, v in sorted(feeds.items())[:16]:
            cidrs = v.get("cidrs") if isinstance(v, dict) else None
            _say("feed %s: %d entries" % (_clean(name, 32), len(cidrs) if isinstance(cidrs, list) else 0))
    if isinstance(applied, dict) and isinstance(applied.get("never"), list):
        _say("never-ban additions: %d" % len(applied["never"]))
    counters = read_json_safe(str(paths.bans_counters), 256 * 1024)
    if isinstance(counters, dict) and isinstance(counters.get("counters"), dict):
        c = counters["counters"]
        nums = ", ".join("%s=%d" % (_clean(k, 16), v) for k, v in sorted(c.items())[:8]
                         if isinstance(v, int) and not isinstance(v, bool))
        if nums:
            _say("kernel counters: " + nums)
    return EXIT_OK


# ---- unban -----------------------------------------------------------------------------------

def _send_ban_cmd(paths, cmd, wait_s=None):
    """Ask the running agent (it owns the ban state) through ban-cmd.json; if it does not answer
    in time, apply the change to the state files directly. Returns (results, via)."""
    wait_s = CMD_WAIT_S if wait_s is None else wait_s
    base = os.path.dirname(str(paths.ban_state))
    os.makedirs(base, 0o700, exist_ok=True)
    cmd_path = os.path.join(base, "ban-cmd.json")
    done_path = cmd_path + ".done"
    cid = uuid.uuid4().hex
    try:
        os.unlink(done_path)
    except OSError:
        pass
    atomic_write(cmd_path, json.dumps({"id": cid, "cmds": [cmd]}), 0o644)
    end = time.time() + wait_s
    while time.time() < end:
        d = read_json_safe(done_path, 64 * 1024)
        if isinstance(d, dict) and d.get("id") == cid:
            try:
                os.unlink(done_path)
            except OSError:
                pass
            return d.get("results", []), "agent"
        time.sleep(0.2)
    try:
        os.unlink(cmd_path)
    except OSError:
        pass
    eng = BanEngine(_cfg(paths), paths)
    results = []
    if cmd["op"] == "unban_all":
        results.append({"op": "unban_all", "removed": eng.unban_all()})
    else:
        results.append({"op": "unban", "addr": cmd["addr"], "removed": eng.unban(cmd["addr"])})
    eng.flush()
    idn.SystemOps(paths).chown_agent(str(paths.ban_state))
    return results, "files"


def cmd_unban(args):
    paths = _paths()
    if not _need_root(paths):
        return EXIT_REFUSED
    if args.all == bool(args.addr):
        _say("give either ADDR or --all", err=True)
        return EXIT_USAGE
    if args.all:
        cmd = {"op": "unban_all"}
    else:
        net = parse_net(args.addr)
        if net is None:
            _say("not an address or CIDR: %s" % _clean(args.addr, 64), err=True)
            return EXIT_USAGE
        cmd = {"op": "unban", "addr": str(net)}
    results, via = _send_ban_cmd(paths, cmd)
    for r in results:
        if r.get("op") == "unban_all":
            _say("all local bans removed (%s); the ban memory is cleared; an explicit empty state was written"
                 % (r.get("removed", 0)))
        else:
            rem = r.get("removed") or []
            if rem:
                _say("removed: %s; it will not be banned again by the ladder" % ", ".join(_clean(x, 64) for x in rem[:20]))
            else:
                _say("no local ban covers %s; it will not be banned again by the ladder" % _clean(r.get("addr", ""), 64))
    if via == "files":
        _say("the agent did not answer: the state files were changed directly")
    return EXIT_OK


# ---- pause and resume --------------------------------------------------------------------------

def cmd_pause(args):
    paths = _paths()
    if not _need_root(paths):
        return EXIT_REFUSED
    secs = PAUSE_DEFAULT_S if args.duration is None else parse_duration(args.duration)
    if secs is None or secs <= 0 or secs > PAUSE_MAX_S:
        _say("--for must be a duration between 1s and 24h (for example 30m)", err=True)
        return EXIT_USAGE
    until = int(time.time() + secs)
    os.makedirs(str(paths.etc_dir), 0o755, exist_ok=True)
    atomic_write(str(paths.pause_json), json.dumps({"until": until}), 0o640)
    ops = idn.SystemOps(paths)
    _chgrp_agent(str(paths.pause_json), ops)
    ops.cancel_pause_timer()
    ops.arm_pause_timer(str(paths.lib_dir), int(secs))
    ops.start_pause_consumers()
    _say("paused until %s: no new bans, enforcing policies in monitor mode, the DNS lock open" % rfc3339(until))
    return EXIT_OK


def _chgrp_agent(path, ops):
    if ops.dev or os.geteuid() != 0:
        return
    try:
        import grp
        os.chown(path, 0, grp.getgrnam("edr-agent").gr_gid)
    except (KeyError, OSError):
        pass


def cmd_resume(args):
    paths = _paths()
    if not _need_root(paths):
        return EXIT_REFUSED
    ops = idn.SystemOps(paths)
    try:
        os.unlink(str(paths.pause_json))
    except FileNotFoundError:
        pass
    except OSError as exc:
        _say("cannot remove the pause file: %s" % (exc.strerror or exc.__class__.__name__), err=True)
        return EXIT_FAIL
    ops.cancel_pause_timer()
    ops.start_pause_consumers()
    _say("resumed: everything is restored from state")
    return EXIT_OK


# ---- registration --------------------------------------------------------------------------------

def register(subparsers):
    def hubargs(p, with_droplet=True):
        p.add_argument("--hub", metavar="IP:PORT", help="the hub's fleet address (an IPv6 address in brackets)")
        p.add_argument("--token-file", metavar="PATH", help="a file holding the token (umask 077)")
        p.add_argument("--token", metavar="-", help="only '-': read the token from stdin; a token value is refused")
        p.add_argument("--enroll-port", type=int, metavar="N", help="the hub's enrollment port (default 8444)")
        p.add_argument("--droplet-id", metavar="ID", help="off DigitalOcean only: the droplet id to report")
        p.add_argument("--no-sandbox", action="store_true", help=argparse.SUPPRESS)

    p = subparsers.add_parser("enroll", help="join a hub with a one-time token")
    hubargs(p)
    p.set_defaults(func=cmd_enroll)

    p = subparsers.add_parser("rehome", help="move this host to a new hub")
    hubargs(p)
    p.add_argument("--rollback", action="store_true", help="undo a rehome that was started and not confirmed")
    p.add_argument("--drop-spool", action="store_true", help="discard the queued events instead of sending them to the new hub")
    p.set_defaults(func=cmd_rehome)

    p = subparsers.add_parser("bans", help="show local, hub and feed bans")
    p.set_defaults(func=cmd_bans)

    p = subparsers.add_parser("unban", help="remove a local ban, or all of them")
    p.add_argument("addr", nargs="?", metavar="ADDR")
    p.add_argument("--all", action="store_true", help="write an explicit empty state and clear the ban memory")
    p.set_defaults(func=cmd_unban)

    p = subparsers.add_parser("pause", help="the kill switch for bans and enforcement")
    p.add_argument("--for", dest="duration", metavar="DURATION", help="default 1h, at most 24h")
    p.set_defaults(func=cmd_pause)

    p = subparsers.add_parser("resume", help="end a pause")
    p.set_defaults(func=cmd_resume)

    p = subparsers.add_parser("deregister", help="tell the hub this host is leaving")
    p.add_argument("--reason", choices=("uninstall", "rehome"), default="uninstall")
    p.set_defaults(func=cmd_deregister)

    p = subparsers.add_parser("hub-net")          # no help line: it is for the enrollment sandbox only
    p.set_defaults(func=cmd_hub_net)

    p = subparsers.add_parser("rehome-resume")    # no help line: it is for the unit's ExecStartPre= only
    p.set_defaults(func=cmd_rehome_resume)
