"""The command line: `run` (the default) and the local subcommands (client PLAN section 4.5 and 15).

Exit codes (section 15): 0 done, 1 warnings (status), 2 failed, 3 refused (validation or a gate), 64 usage.
The hub-facing subcommands (enroll, rehome, bans, unban, pause, resume) are registered by hubcmds.
"""
import argparse
import json
import os
import subprocess
import sys
import time

from . import VERSION
from . import alertlog
from . import config as cfgmod
from . import event as evmod
from . import heartbeat
from .paths import Paths

EXIT_OK, EXIT_WARN, EXIT_FAIL, EXIT_REFUSED, EXIT_USAGE = 0, 1, 2, 3, 64
SUMMARY_FRESH_S = 180


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("%s: error: %s\n" % (self.prog, message))
        raise SystemExit(EXIT_USAGE)


def _safe(text, limit=160):
    """Text from a log or an alert, made safe to print on a terminal (root reads this)."""
    text = evmod.clean_text(str(text))
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---- run ----------------------------------------------------------------------------------------------
def cmd_run(args, paths=None):
    from .daemon import Daemon, Options
    paths = paths or Paths()
    start = True if args.from_start else False if args.from_end else None
    opts = Options(no_journal=args.no_journal, kernel_log=args.kernel_log, from_start=start, interval=args.interval,
                   sandbox_test=args.sandbox_test, duration=args.duration, foreground=args.foreground)
    return Daemon(paths, opts).run()


# ---- status -------------------------------------------------------------------------------------------
def _pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return True            # exists, owned by someone else


def _load_summary(paths):
    try:
        with open(paths.summary_json, "rb") as f:
            obj = json.loads(f.read(1024 * 1024))
        return obj if isinstance(obj, dict) else None
    except (OSError, ValueError):
        return None


def cmd_status(args, paths=None, out=print, clock=time.time):
    paths = paths or Paths()
    now = clock()
    if getattr(args, "json", False):
        return status_json(paths, now, out)
    if args.alerts:
        try:
            since = alertlog.parse_duration(args.since)
        except ValueError:
            out("usage: --since takes 7d, 12h, 30m or seconds")
            return EXIT_USAGE
        rows = alertlog.read_alerts(paths.alerts_jsonl, now - since)
        out("%d alert lines in the last %s" % (len(rows), args.since))
        for e in rows:
            count = " x%s" % e["count"] if isinstance(e.get("count"), int) and e["count"] > 1 else ""
            out("%s %-8s %-28s %-15s %s%s" % (_safe(e.get("ts", ""), 24), _safe(e.get("sev", ""), 8), _safe(e.get("kind", ""), 28),
                                                _safe(e.get("src_ip", ""), 15), _safe(e.get("summary", ""), 120), count))
        return EXIT_OK
    summary = _load_summary(paths)
    code = EXIT_OK
    warnings, failures = [], []
    agent = (summary or {}).get("agent") or {}
    age = now - summary["written_at"] if summary and isinstance(summary.get("written_at"), (int, float)) else None
    pid = agent.get("pid") if isinstance(agent.get("pid"), int) else None
    running = age is not None and age <= SUMMARY_FRESH_S and (pid is None or _pid_alive(pid))
    if running:
        out("edr-agent %s running (pid %s), summary %ds old" % (_safe(agent.get("version", "?"), 16), pid, int(age)))
    else:
        out("edr-agent is NOT running (no fresh summary at %s)" % paths.summary_json)
        failures.append("not running")
    hub = (summary or {}).get("hub") or {}
    mode = hub.get("mode", "local" if running else "unknown")
    if mode == "enrolled":
        line = "hub: enrolled with %s" % _safe(hub.get("hub", "?"), 60)
        if hub.get("unreachable_s", 0) > 900:
            line += ", UNREACHABLE for %d min" % (hub["unreachable_s"] // 60)
            warnings.append("hub unreachable")
        if hub.get("last_error"):
            line += " (last error: %s)" % _safe(hub["last_error"], 80)
        out(line)
        spool = hub.get("spool") or {}
        if spool:
            out("spool: depth %s, %s bytes, dropped %s" % (spool.get("depth", "?"), spool.get("bytes", "?"), _safe(spool.get("dropped", {}), 60)))
    else:
        out("hub: local mode (not enrolled); alerts stay on this host")
    if agent.get("config_errors"):
        out("config: INVALID, using %s: %s" % (_safe(agent.get("config", "?"), 16), _safe(agent["config_errors"][0], 100)))
        warnings.append("config invalid")
    counts = (summary or {}).get("counts") or {}
    out("open alerts, last 7 days: %s CRITICAL, %s HIGH" % (counts.get("CRITICAL", 0), counts.get("HIGH", 0)))
    for a in ((summary or {}).get("alerts") or [])[:5]:
        out("  %s %s %s" % (_safe(a.get("sev", ""), 8), _safe(a.get("kind", ""), 28), _safe(a.get("summary", ""), 100)))
        if a.get("kind") == "health.sandbox_ineffective":
            failures.append("sandbox ineffective")
    if counts.get("CRITICAL", 0) or counts.get("HIGH", 0):
        warnings.append("open alerts")
    dropped = agent.get("dropped") or {}
    if dropped:
        out("events over budget this run (not sent): %s" % _safe(dropped, 100))
    if failures:
        code = EXIT_FAIL
    elif warnings:
        code = EXIT_WARN
    return code


def status_json(paths, now, out=print):
    """One JSON object for scripts (check.sh): the summary the agent wrote, how old it is, whether its process is alive,
    and the last event time. Exit codes as `status`: 0 running, 2 not running."""
    summary = _load_summary(paths)
    agent = (summary or {}).get("agent") or {}
    age = now - summary["written_at"] if summary and isinstance(summary.get("written_at"), (int, float)) else None
    pid = agent.get("pid") if isinstance(agent.get("pid"), int) else None
    running = age is not None and age <= SUMMARY_FRESH_S and (pid is None or _pid_alive(pid))
    state = None
    try:
        with open(paths.agent_state_json, "rb") as f:
            state = json.loads(f.read(8192))
    except (OSError, ValueError):
        pass
    doc = {"v": 1, "running": running, "summary_age_s": None if age is None else int(age), "summary": summary,
           "last_seen": (state or {}).get("last_seen") if isinstance(state, dict) else None,
           "hub": (summary or {}).get("hub") or {}}
    out(json.dumps(doc, sort_keys=True))
    return EXIT_OK if running else EXIT_FAIL


# ---- check.sh helpers -------------------------------------------------------------------------------------
def cmd_checks(args, paths=None, out=print):
    """`edr-agent checks SECTION [--local]`: LEVEL<TAB>text lines for check.sh; `checks value WHAT` prints one value."""
    from . import checks
    paths = paths or Paths()
    cfg = cfgmod.load(paths)
    owner = os.getuid() if paths.dev else 0
    if args.section == "value":
        out(checks.helper_value(args.what or "", paths, cfg))
        return EXIT_OK
    if args.section not in checks.SECTIONS:
        sys.stderr.write("edr-agent checks: unknown section %s\n" % args.section)
        return EXIT_USAGE
    stdin = sys.stdin.read(1 << 20) if args.section == "netcheck" else ""
    for level, text in checks.run_section(args.section, paths, cfg, local=args.local, owner_uid=owner, stdin=stdin):
        out("%s\t%s" % (level, text))
    return EXIT_OK


# ---- config subcommands ---------------------------------------------------------------------------------
def cmd_apply_config(args, paths=None):
    return cfgmod.apply_config(paths or Paths(), check_only=args.check)


def cmd_render(args, paths=None, out=print):
    """Render the policies, the IPAddressAllow drop-in and the notify credential into a directory. Changes nothing else."""
    from . import render
    paths = paths or Paths()
    cfg = cfgmod.load(paths)
    if cfg.errors:
        out("refused: local.conf is not valid")
        for e in cfg.errors:
            out("  " + e)
        return EXIT_REFUSED
    try:
        files, skipped, notes = render.render_all(paths, cfg)
        written = render.write_staging(files, args.out)
    except (render.RenderError, OSError) as e:
        out("refused: %s" % e)
        return EXIT_REFUSED
    for path in written:
        out("rendered " + path)
    for name, why in sorted(skipped.items()):
        out("left out: policy %s (%s)" % (name, why))
    for n in notes:
        out("note: " + n)
    return EXIT_OK


def cmd_discover(args, paths=None):
    from . import discover
    return discover.run_discover(paths or Paths(), webroots=args.webroot or (), print_only=args.print_only)


def cmd_learn(args, paths=None):
    from . import learn
    return learn.run_learn(paths or Paths(), accept=args.accept, min_days=args.min_days)


def cmd_collect(args, paths=None):
    from . import collect
    return collect.run_collect(paths or Paths(), args.out)


# ---- shutdown notice ------------------------------------------------------------------------------------
def system_stopping(runner=subprocess.run):
    """True when the system is shutting down or a reboot job is queued, so a plain restart is not announced."""
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    try:
        p = runner(["systemctl", "is-system-running"], capture_output=True, text=True, timeout=2, check=False, env=env)
        if (p.stdout or "").strip() == "stopping":
            return True
        p = runner(["systemctl", "list-jobs", "--no-legend", "--no-pager"], capture_output=True, text=True, timeout=2,
                   check=False, env=env)
        for line in (p.stdout or "").splitlines():
            if any(t in line for t in ("reboot.target", "poweroff.target", "halt.target", "shutdown.target", "kexec.target")):
                return True
    except (OSError, subprocess.SubprocessError):
        return False
    return False


class _NullEngine:
    """What the uplink asks a ban engine for in a heartbeat, for the stop hook, which has no ban engine of its own."""

    def last_apply_error(self):
        return ""

    def counts(self):
        return {}

    def paused_until(self):
        return None

    def set_policy(self, doc):
        pass

    def note_apply_error(self, text):
        pass


def cmd_shutdown_notice(args, paths=None, runner=subprocess.run, uplink_factory=None):
    paths = paths or Paths()
    if not system_stopping(runner):
        return EXIT_OK
    cfg = cfgmod.load(paths)
    from . import sources as src
    ctx = src.Context(cfg, paths)
    helpers = src.HelperWatcher(ctx)
    helpers.poll(time.time())
    state = heartbeat.HeartbeatState(cfg, paths, ctx, helpers, None)
    build = lambda: heartbeat.build(state)     # noqa: E731
    try:
        if uplink_factory is None:
            from .uplink import Uplink
            uplink_factory = Uplink
        uplink = uplink_factory(cfg, paths, _NullEngine(), build)
        uplink.stop(True)
    except Exception as exc:                   # the notice is best effort; a failure must not hold up the shutdown
        sys.stderr.write("edr-agent: shutdown notice not sent: %r\n" % (exc,))
    return EXIT_OK


def cmd_version(args, paths=None):
    paths = paths or Paths()
    print(VERSION)
    if args.hash:
        print(heartbeat.agent_sha256(paths.lib_dir))
    return EXIT_OK


# ---- parser ---------------------------------------------------------------------------------------------
def build_parser():
    p = _Parser(prog="edr-agent", description="The EDR client agent. With no command it runs.")
    sub = p.add_subparsers(dest="command", parser_class=_Parser)

    r = sub.add_parser("run", help="run the agent (the default)")
    r.add_argument("--foreground", action="store_true", help="stay in the foreground (the only mode; kept for scripts)")
    r.add_argument("--no-journal", action="store_true", help="do not read the journal (sshd, sudo, kernel log)")
    r.add_argument("--kernel-log", default="journal", metavar="journal|FILE|FIFO",
                   help="where the kernel log comes from (default: journal)")
    g = r.add_mutually_exclusive_group()
    g.add_argument("--from-start", action="store_true", help="read existing logs from their start when there is no checkpoint")
    g.add_argument("--from-end", action="store_true", help="skip what is already in the logs when there is no checkpoint")
    r.add_argument("--interval", type=float, default=0.25, help=argparse.SUPPRESS)
    r.add_argument("--duration", type=float, default=None, help=argparse.SUPPRESS)
    r.add_argument("--sandbox-test", choices=("auto", "on", "off"), default="auto", help=argparse.SUPPRESS)
    r.set_defaults(func=cmd_run)

    s = sub.add_parser("status", help="show the agent's state and open alerts")
    s.add_argument("--alerts", action="store_true", help="list alerts.jsonl")
    s.add_argument("--since", default="7d", help="with --alerts: how far back (7d, 12h, 30m)")
    s.add_argument("--json", action="store_true", help="print one JSON object (the summary, its age, whether the agent runs)")
    s.set_defaults(func=cmd_status)

    d = sub.add_parser("discover", help="find nginx, php-fpm, web users and roots and write them to local.conf")
    d.add_argument("--webroot", action="append", help="use this web root instead of the ones in the nginx config")
    d.add_argument("--print", dest="print_only", action="store_true", help="print only; change nothing")
    d.set_defaults(func=cmd_discover)

    a = sub.add_parser("apply-config", help="validate local.conf and apply it")
    a.add_argument("--check", action="store_true", help="print the effective values and the differences; change nothing")
    a.set_defaults(func=cmd_apply_config)

    rd = sub.add_parser("render", help="render the Tetragon policies and unit drop-in into a directory (no swap, no reload)")
    rd.add_argument("--out", required=True, metavar="DIR", help="staging directory to write into")
    rd.set_defaults(func=cmd_render)

    le = sub.add_parser("learn", help="show what the web-exec learning has seen, or accept it")
    le.add_argument("--accept", action="store_true", help="write the learned allowlist to local.conf")
    le.add_argument("--min-days", type=int, default=7, help=argparse.SUPPRESS)
    le.set_defaults(func=cmd_learn)

    c = sub.add_parser("collect", help="write a triage tar (raw, sensitive)")
    c.add_argument("--out", metavar="FILE", help="where to write it (default: /root/edr-collect-TIME.tar)")
    c.set_defaults(func=cmd_collect)

    ck = sub.add_parser("checks", help="the file-reading half of check.sh (prints LEVEL<TAB>text lines)")
    ck.add_argument("section", help="kit, audit, agent, bans, tetragon, dns, disk, nginx, suricata, netcheck, or value")
    ck.add_argument("what", nargs="?", help="with `value`: phase, pause, enrolled, web_user, nginx_bin or conf:SECTION.KEY")
    ck.add_argument("--local", action="store_true", help="skip hub checks")
    ck.set_defaults(func=cmd_checks)

    n = sub.add_parser("shutdown-notice", help="the unit's ExecStop: tell the hub about a shutdown")
    n.set_defaults(func=cmd_shutdown_notice)

    v = sub.add_parser("version", help="print the version")
    v.add_argument("--hash", action="store_true", help="also print the code hash the hub checks")
    v.set_defaults(func=cmd_version)

    try:
        from . import hubcmds
        hubcmds.register(sub)
    except ImportError:
        pass
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0].startswith("-") and argv[0] not in ("-h", "--help"):
        argv = ["run"] + argv                  # the unit runs the script with no command
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else EXIT_USAGE
    if not getattr(args, "func", None):
        parser.print_usage(sys.stderr)
        return EXIT_USAGE
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return EXIT_OK
