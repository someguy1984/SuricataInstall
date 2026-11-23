#!/usr/bin/python3 -I
"""edr-hub.service: the hub's main process (PLAN.md sections 2, 3 and 8).

Starts, in order: the writer (database), the pending-audit ingest, both TLS listeners, the control sockets, the
correlation engine, then tells systemd READY=1. SIGTERM flushes, checkpoints and exits.

Run from a checkout without root (tests, development):

    python3 -I edr_hub.py --state-dir D/state --run-dir D/run --etc-dir D/etc \\
        --bind 127.0.0.1 --port 18443 --enroll-port 18444 --public-ip 127.0.0.1 [--init-only]
"""

import argparse
import collections
import os
import signal
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

import hub_alerts       # noqa: E402,F401 - imported by name so a missing module fails at start, not at the first alert
import hub_audit        # noqa: E402
import hub_common       # noqa: E402
import hub_ctl          # noqa: E402
import hub_db           # noqa: E402
import hub_engine       # noqa: E402
import hub_ingest       # noqa: E402
import hub_pki          # noqa: E402
import hub_rules        # noqa: E402,F401

SERVER_CERT_CHECK_S = 3600
_PRIORITY = {"CRITICAL": 2, "ERROR": 3, "WARN": 4, "INFO": 6, "DEBUG": 7}


class Hub:
    """The one instance every component gets (contract section 5.2)."""

    def __init__(self, paths, settings, bind="0.0.0.0"):
        self.paths = paths
        self.settings = settings
        self.bind = bind
        self.started_at = hub_common.now_ms()
        self.stopping = threading.Event()
        self.pki = None
        self.writer = None
        self.ingest = None
        self.sockets = None
        self.engine = None
        self.memory_alerts = collections.deque(maxlen=100)
        self._settings_lock = threading.Lock()
        self._log_lock = threading.Lock()
        self._last_cert_check = 0.0

    # ---- contract surface ----
    def ro(self):
        """A new read-only connection (row_factory Row). The caller closes it."""
        return hub_db.open_ro(self.paths.db)

    def update_settings(self, new):
        """Replace the settings: saved atomically, then swapped under a lock."""
        with self._settings_lock:
            hub_common.save_settings(self.paths, new)
            self.settings = new

    def refresh_enroll_listener(self):
        if self.ingest is not None:
            self.ingest.refresh_enroll_listener()

    def reload_server_cert(self):
        if self.ingest is not None:
            self.ingest.reload_server_cert()

    def log(self, level, message):
        """One line to stderr, which is the journal. Never a secret, never raw client text."""
        text = hub_common.clean(str(message), 500)
        prefix = "<%d>" % _PRIORITY.get(level, 6) if os.environ.get("JOURNAL_STREAM") else ""
        with self._log_lock:
            try:
                sys.stderr.write("%s%s %s\n" % (prefix, level, text))
                sys.stderr.flush()
            except (OSError, ValueError):
                pass

    def memory_alert(self, severity, kind, summary):
        """An alert for a moment when the database cannot take a write: journal line and an in-memory list."""
        self.memory_alerts.append({"ts": hub_common.now_ms(), "severity": severity, "kind": kind,
                                   "summary": hub_common.clean(summary, 300)})
        self.log("CRITICAL" if severity == "CRITICAL" else "ERROR", "%s: %s" % (kind, summary))

    # ---- start and stop ----
    def prepare(self):
        """Everything that must exist before the database opens: the CA, the server certificate."""
        hub_pki.init_ca(self.paths)
        self.pki = hub_pki.Pki(self.paths)
        self.check_server_cert(force=True)

    def check_server_cert(self, force=False):
        """Issue the server certificate when it is missing, under 30 days from expiry, or the address list changed."""
        now = time.monotonic()
        if not force and now - self._last_cert_check < SERVER_CERT_CHECK_S:
            return False
        self._last_cert_check = now
        ips = list(self.settings.get("public_ip") or [])
        state = self.pki.server_cert_state(ips)
        if state == "ok":
            return False
        self.log("INFO", "issuing the server certificate (%s)" % state)
        self.pki.issue_server_cert(ips)
        if self.ingest is not None:
            self.reload_server_cert()
        return True

    def open_database(self):
        self.writer = hub_db.Writer(self)
        self.writer.start()

    def start(self):
        """Writer, audit ingest, listeners, sockets, engine, READY=1 (in that order)."""
        self.open_database()
        try:
            self.writer.call(lambda conn: hub_audit.ingest_pending(conn, self), timeout=60)
        except Exception as e:      # noqa: BLE001 - a bad pending line must not keep the hub down
            self.log("ERROR", "pending audit ingest: %s: %s" % (type(e).__name__, e))
        self.ingest = hub_ingest.Ingest(self, bind=self.bind)
        self.ingest.start()
        self.sockets = hub_ctl.Sockets(self)
        self.sockets.start()
        self.engine = hub_engine.Engine(self)
        self.engine.start()
        hub_common.sd_notify("READY=1")
        hub_common.sd_notify("STATUS=serving %d and %d" % (self.ingest.fleet.port, self.settings.get("enroll_port", 0)))
        self.log("INFO", "hub %s ready: fleet port %s, state %s" % (hub_common.VERSION, self.ingest.fleet.port,
                                                                   self.paths.state_dir))

    def run(self):
        """The main loop: enrollment listener follows the tokens, the server certificate is checked hourly."""
        while not self.stopping.wait(1.0):
            try:
                self.ingest.tick()
                self.check_server_cert()
            except Exception as e:      # noqa: BLE001
                self.log("ERROR", "main loop: %s: %s" % (type(e).__name__, e))

    def shutdown(self):
        """Flush, checkpoint. The write connection stays open: the process exits instead of closing it."""
        hub_common.sd_notify("STOPPING=1")
        for part, name in ((self.engine, "engine"), (self.sockets, "sockets"), (self.ingest, "listeners")):
            if part is not None:
                try:
                    part.stop()
                except Exception as e:      # noqa: BLE001
                    self.log("ERROR", "stopping %s: %s" % (name, e))
        if self.writer is not None:
            self.writer.stop()


# ---- command line -------------------------------------------------------------------------------------
class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("edr_hub.py: %s\n" % message)
        sys.exit(hub_common.EXIT_USAGE)


def parse_args(argv):
    p = _Parser(prog="edr_hub.py", description="The EDR hub main process.")
    p.add_argument("--state-dir")
    p.add_argument("--run-dir")
    p.add_argument("--etc-dir")
    p.add_argument("--bind", default="0.0.0.0", help="address to listen on (default 0.0.0.0)")
    p.add_argument("--port", type=int)
    p.add_argument("--enroll-port", type=int)
    p.add_argument("--ui-port", type=int)
    p.add_argument("--public-ip", action="append", help="address clients connect to (repeatable); goes into the certificate")
    p.add_argument("--admin-ip", action="append")
    p.add_argument("--retention-days", type=int)
    p.add_argument("--max-db-size")
    p.add_argument("--init-only", action="store_true", help="create the CA, certificate and database, then exit 0")
    p.add_argument("--version", action="version", version=hub_common.VERSION)
    return p.parse_args(argv)


def seed_settings(paths, args):
    """settings.json from the flags as the installer would seed it. A flag that is named wins and is saved."""
    settings = hub_common.load_settings(paths)
    changed = not os.path.exists(paths.settings)
    for key, value in (("port", args.port), ("enroll_port", args.enroll_port), ("ui_port", args.ui_port),
                       ("retention_days", args.retention_days)):
        if value is not None and settings.get(key) != value:
            settings[key] = value
            changed = True
    if args.max_db_size is not None:
        hub_common.parse_size(args.max_db_size)
        if settings.get("max_db_size") != args.max_db_size.upper():
            settings["max_db_size"] = args.max_db_size.upper()
            changed = True
    for key, value in (("public_ip", args.public_ip), ("admin_ip", args.admin_ip)):
        if value:
            norm = [hub_common.norm_ip(v) for v in value] if key == "public_ip" else [hub_common.norm_cidr(v) for v in value]
            if settings.get(key) != norm:
                settings[key] = norm
                changed = True
    if not settings.get("public_ip"):
        settings["public_ip"] = [args.bind] if args.bind not in ("0.0.0.0", "::", "") else ["127.0.0.1"]
        changed = True
    if changed:
        hub_common.save_settings(paths, settings)
    return settings


def make_dirs(paths):
    os.makedirs(paths.state_dir, mode=0o750, exist_ok=True)
    for d in (paths.run_dir,):
        os.makedirs(d, mode=0o755, exist_ok=True)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    paths = hub_common.Paths(state_dir=args.state_dir, run_dir=args.run_dir, etc_dir=args.etc_dir)
    try:
        make_dirs(paths)
        settings = seed_settings(paths, args)
    except (OSError, ValueError) as e:
        sys.stderr.write("edr_hub.py: cannot prepare the state directory: %s\n" % e)
        return hub_common.EXIT_FAIL
    hub = Hub(paths, settings, bind=args.bind)
    try:
        hub.prepare()
        if args.init_only:
            hub.open_database()
            hub.writer.stop(close=True)
            hub.log("INFO", "initialised %s" % paths.state_dir)
            return hub_common.EXIT_OK
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: hub.stopping.set())
        hub.start()
    except hub_db.SchemaTooNew as e:
        hub.log("CRITICAL", str(e))
        return hub_common.EXIT_FAIL
    except (hub_pki.PkiError, OSError, ValueError) as e:
        hub.log("CRITICAL", "start failed: %s: %s" % (type(e).__name__, e))
        hub.shutdown()
        return hub_common.EXIT_FAIL
    except Exception as e:      # noqa: BLE001
        hub.log("CRITICAL", "start failed: %s: %s" % (type(e).__name__, e))
        hub.shutdown()
        return hub_common.EXIT_FAIL
    hub.run()
    hub.shutdown()
    hub.log("INFO", "stopped")
    sys.stderr.flush()
    # Exit without closing the write connection (section 3, Dashboard reader).
    os._exit(hub_common.EXIT_OK)


if __name__ == "__main__":
    sys.exit(main())
