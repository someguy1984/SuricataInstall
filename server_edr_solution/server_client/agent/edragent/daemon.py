"""The main loop (client PLAN section 4.5).

Reads every source, feeds the pipeline, checkpoints after each batch, ticks the ban engine and the alert
writer, and talks to systemd: READY=1 once the sources are open, WATCHDOG=1 from the loop (a hung loop stops
the watchdog, and WatchdogSec=90 restarts the agent). At start it runs the sandbox self-test, emits
health.agent_start and health.config_invalid when they apply, and takes a clean-shutdown marker at the end.
"""
import errno
import os
import queue
import signal
import socket
import sys
import threading
import time

from . import VERSION
from . import config as cfgmod
from . import event as evmod
from . import heartbeat, ids
from . import sources as src
from .pipeline import Pipeline

WATCHDOG_EVERY_S = 10
HUB_DOWN_S = 15 * 60
SYSLOG = {"crit": 2, "err": 3, "warning": 4, "info": 6, "debug": 7}


def sd_notify(message, environ=None):
    """Send a state line to $NOTIFY_SOCKET (an AF_UNIX datagram). Does nothing without it."""
    addr = (environ or os.environ).get("NOTIFY_SOCKET")
    if not addr or len(addr) > 200:
        return False
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    elif not addr.startswith("/"):
        return False
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
        try:
            s.settimeout(1.0)
            s.sendto(message.encode(), addr)
        finally:
            s.close()
        return True
    except OSError:
        return False


def sandbox_selftest(sock_factory=socket.socket):
    """systemd carries on without IPAddressDeny when the BPF firewall is missing, so test it: one UDP datagram
    to 127.0.0.1:9 must fail with EPERM. Returns (effective, detail)."""
    try:
        s = sock_factory(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as e:
        return e.errno == errno.EPERM or e.errno == errno.EACCES, "socket: %s" % e.strerror
    try:
        s.settimeout(1.0)
        s.sendto(b"edr-selftest", ("127.0.0.1", 9))
        return False, "the datagram was sent"
    except OSError as e:
        return e.errno == errno.EPERM, "sendto: errno %s" % e.errno
    finally:
        s.close()


class Options:
    """What the command line says about a run."""

    def __init__(self, no_journal=False, kernel_log="journal", from_start=None, interval=0.25, sandbox_test="auto",
                 duration=None, foreground=True):
        self.no_journal, self.kernel_log, self.from_start = no_journal, kernel_log, from_start
        self.interval, self.sandbox_test, self.duration, self.foreground = interval, sandbox_test, duration, foreground


class Daemon:
    def __init__(self, paths, options=None, clock=time.time, log_stream=None, bans_factory=None, uplink_factory=None):
        self.paths = paths
        self.opt = options or Options()
        self.clock = clock
        self.stream = log_stream or sys.stderr
        self.stop_event = threading.Event()
        self.reload_flag = threading.Event()
        self.bans_factory, self.uplink_factory = bans_factory, uplink_factory
        self.cfg = self.ctx = self.pipeline = self.helpers = self.hbstate = None
        self.bans = self.uplink = None
        self.sources = []
        self.inbox = queue.SimpleQueue()      # events handed in by other threads
        self.started = clock()
        self.errors_logged = {}
        self.last_tick = 0.0
        self.last_watchdog = 0.0
        self.last_hub = (0.0, {})
        self.hub_down_since_warn = 0.0
        self.config_error_key = None
        self.clean_previous = False

    # ---- logging --------------------------------------------------------------------------------
    def log(self, level, message):
        prefix = "<%d>" % SYSLOG.get(level, 6) if os.environ.get("INVOCATION_ID") else ""
        try:
            self.stream.write("%sedr-agent: %s\n" % (prefix, " ".join(str(message).split())[:1000]))
            self.stream.flush()
        except (OSError, ValueError):
            pass

    def _first_start(self):
        if self.opt.from_start is not None:
            return "begin" if self.opt.from_start else "end"
        return "begin" if self.paths.dev else "end"

    # ---- setup ----------------------------------------------------------------------------------
    def setup(self):
        paths = self.paths
        for d, mode in ((paths.state_dir, 0o700), (paths.run_dir, 0o755), (paths.cursors_dir, 0o700)):
            os.makedirs(d, mode=mode, exist_ok=True)
        self.cfg = cfgmod.load(paths, save_good=True)
        evmod.configure(self.cfg)
        self.clean_previous = ids.init(paths)
        self.ctx = src.Context(self.cfg, paths, self.clock)
        self.seen = src.SeenStore(paths.seen_json, self.clock)
        self.helpers = src.HelperWatcher(self.ctx)
        self.hbstate = heartbeat.HeartbeatState(self.cfg, paths, self.ctx, self.helpers, None, self.clock)
        self._make_engines()
        self.pipeline = Pipeline(self.cfg, paths, self.bans, self.uplink, self.ctx, self.clock, self.log)
        self.hbstate.pipeline = self.pipeline
        if hasattr(self.uplink, "local_event_cb"):
            # events the uplink makes itself (spool_dropped, identity) take the same road as every other event
            # (queued, not processed here: the uplink's threads must never wait for the pipeline)
            self.uplink.local_event_cb = self.inbox.put
        self._make_sources()
        self.pipeline.process_many(self._start_events())

    def stop(self):
        self.stop_event.set()

    def _make_engines(self):
        if self.bans_factory is not None:
            self.bans = self.bans_factory(self.cfg, self.paths)
        else:
            from .bans import BanEngine
            self.bans = BanEngine(self.cfg, self.paths)
        build = lambda: heartbeat.build(self.hbstate)       # noqa: E731
        if self.uplink_factory is not None:
            self.uplink = self.uplink_factory(self.cfg, self.paths, self.bans, build)
        else:
            from .uplink import Uplink
            self.uplink = Uplink(self.cfg, self.paths, self.bans, build)

    def _make_sources(self):
        cfg, ctx, first = self.cfg, self.ctx, self._first_start()
        s = self.sources
        if cfg.getbool("kit", "tetragon", True):
            s.append(src.TetragonSource(ctx, first))
        if cfg.getbool("kit", "web", True):
            s.append(src.ErrorLogSource(ctx, first))
            if cfg.getbool("agent", "nginx_info_log", False):
                s.append(src.ErrorLogSource(ctx, first, path=self.paths.nginx_info_log, label="nginx_info"))
            s.append(src.AccessLogSource(ctx, first))
        if cfg.getbool("kit", "suricata", True):
            s.append(src.EveSource(ctx, first))
            s.append(src.EveBulkSource(ctx, first))
        if not self.opt.no_journal:
            s.append(src.JournalSource(ctx, self.seen))
        else:
            self.log("info", "journal sources are off (--no-journal)")
        if self.opt.kernel_log != "journal":
            s.append(src.KernelSource(ctx, self.seen, self.opt.kernel_log, first))
        elif not self.opt.no_journal:
            s.append(src.KernelSource(ctx, self.seen, "journal"))

    def _start_events(self):
        events = []
        last = self.helpers.state.get("last_seen")
        details = {"clean_shutdown": self.clean_previous, "version": VERSION,
                   "last_seen": evmod.rfc3339(last * 1000) if isinstance(last, (int, float)) else None,
                   "config": self.cfg.state}
        events.append(evmod.make_event("health.agent_start", "agent", "INFO",
                                       "edr-agent %s started (%s shutdown before)" % (VERSION, "clean" if self.clean_previous else "unclean or first"),
                                       details=details))
        events.extend(self._config_events())
        mode = self.opt.sandbox_test
        if mode == "on" or (mode == "auto" and os.environ.get("INVOCATION_ID") and not self.paths.dev):
            ok, detail = sandbox_selftest()
            if not ok:
                events.append(evmod.make_event("health.sandbox_ineffective", "agent", "HIGH",
                                               "the agent's network filter is not in force: it could send a datagram it must not",
                                               details={"detail": detail}))
        return events

    def _config_events(self):
        if not self.cfg.errors:
            self.config_error_key = None
            return []
        key = tuple(self.cfg.errors)
        if key == self.config_error_key:
            return []
        self.config_error_key = key
        return [evmod.make_event("health.config_invalid", "agent", "HIGH",
                                 "local.conf is not valid: %s (using %s)" % (self.cfg.errors[0], self.cfg.state),
                                 details={"errors": self.cfg.errors[:8], "using": self.cfg.state})]

    # ---- signals --------------------------------------------------------------------------------
    def install_signals(self):
        try:
            signal.signal(signal.SIGTERM, lambda *a: self.stop_event.set())
            signal.signal(signal.SIGINT, lambda *a: self.stop_event.set())
            signal.signal(signal.SIGHUP, lambda *a: self.reload_flag.set())
        except ValueError:
            pass                          # not the main thread (a test); stop() works instead

    def reload_config(self):
        new = cfgmod.load(self.paths, save_good=True)
        self.cfg.update_from(new)
        evmod.configure(self.cfg)
        self.ctx.reload()
        events = self._config_events()
        self.pipeline.process_many(events)
        self.log("info", "configuration re-read (%s)" % self.cfg.state)

    # ---- the loop -------------------------------------------------------------------------------
    def poll_sources(self, now):
        """One pass over the sources. Returns the number of events handled."""
        total = 0
        for s in self.sources:
            try:
                events = s.poll(now)
            except Exception as exc:               # a reader bug must not end detection
                self._source_error(s, exc)
                continue
            if events:
                total += len(events)
                self.pipeline.process_many(events, now)
            try:
                s.commit()
            except Exception as exc:
                self._source_error(s, exc)
        return total

    def drain_inbox(self, now):
        n = 0
        while n < 500:
            try:
                e = self.inbox.get_nowait()
            except queue.Empty:
                break
            n += 1
            if isinstance(e, dict):
                self.pipeline.process(e, now, observe=False)
        return n

    def _source_error(self, source, exc):
        self._error(source.name, exc)

    def _error(self, name, exc):
        key = (name, type(exc).__name__)
        last = self.errors_logged.get(key, 0)
        if self.clock() - last > 300:
            self.errors_logged[key] = self.clock()
            self.log("err", "%s failed: %r" % (name, exc))

    def tick(self, now):
        """Once a second: helpers, ban engine, alert writer, summary, hub status."""
        self.pipeline.process_many(self.helpers.poll(now), now)
        hub = self._hub_status(now)
        self.pipeline.hub_down = bool(hub.get("unreachable_s", 0) > HUB_DOWN_S)
        self._hub_warning(hub, now)
        extra = {"agent": {"pid": os.getpid(), "started": int(self.started), "version": VERSION, "config": self.cfg.state,
                           "config_errors": self.cfg.errors[:5], "sources": [s.name for s in self.sources],
                           "dropped": self.pipeline.stats().get("dropped", {}), "health_24h": self.pipeline.health_24h(),
                           "suricata_drops": self.ctx.suricata_drops}}
        self.pipeline.tick(now, hub, extra)
        self.seen.save()
        if now - self.helpers.state.get("last_seen", 0) >= 60:
            self.helpers.state["last_seen"] = int(now)
            self.helpers._save_state()

    def _hub_status(self, now):
        if now - self.last_hub[0] < 10:
            return self.last_hub[1]
        status = {}
        try:
            status = dict(self.uplink.status() or {}) if self.uplink is not None else {}
        except Exception as exc:
            self.log("err", "uplink status failed: %r" % (exc,))
        ok = status.get("last_heartbeat_ok")
        if status.get("mode") == "enrolled" and isinstance(ok, (int, float)):
            status["unreachable_s"] = max(0, int(now - ok))
        elif status.get("mode") == "enrolled":
            status["unreachable_s"] = int(now - self.started)
        status.pop("host_uuid", None)
        self.last_hub = (now, status)
        return status

    def _hub_warning(self, hub, now):
        if hub.get("unreachable_s", 0) <= HUB_DOWN_S:
            self.hub_down_since_warn = 0.0
            return
        if now - self.hub_down_since_warn >= HUB_DOWN_S:
            self.hub_down_since_warn = now
            mins = hub["unreachable_s"] // 60
            self.log("warning", "the hub has been unreachable for %d minutes; HIGH and CRITICAL alerts stay in alerts.jsonl and the journal" % mins)
            self.pipeline.process(evmod.make_event("health.hub_unreachable", "agent", "LOW",
                                                   "the hub has been unreachable for %d minutes" % mins,
                                                   details={"minutes": mins, "last_error": hub.get("last_error", "")}), now, observe=False)

    def run(self):
        """Run until SIGTERM (or --duration). Returns the exit code."""
        try:
            self.setup()
        except Exception as exc:
            self.log("crit", "cannot start: %r" % (exc,))
            return 2
        self.install_signals()
        self._write_pid()
        try:
            if self.uplink is not None:
                self.uplink.start()
        except Exception as exc:
            self.log("err", "the uplink did not start: %r" % (exc,))
        sd_notify("READY=1")
        self.log("info", "running (%d sources, uplink %s)" % (len(self.sources), self._mode()))
        try:
            self._loop()
        finally:
            self.shutdown()
        return 0

    def _mode(self):
        try:
            return self.uplink.status().get("mode", "?")
        except Exception:
            return "?"

    def _loop(self):
        end = self.started + self.opt.duration if self.opt.duration else None
        while not self.stop_event.is_set():
            now = self.clock()
            if end is not None and now >= end:
                break
            if self.reload_flag.is_set():
                self.reload_flag.clear()
                try:
                    self.reload_config()
                except Exception as exc:
                    self.log("err", "configuration reload failed: %r" % (exc,))
            handled = self.poll_sources(now) + self.drain_inbox(now)
            if now - self.last_tick >= 1.0:
                self.last_tick = now
                try:
                    self.tick(now)
                except Exception as exc:
                    self._error("tick", exc)
            if now - self.last_watchdog >= WATCHDOG_EVERY_S:
                self.last_watchdog = now
                sd_notify("WATCHDOG=1")
            if not handled:
                self.stop_event.wait(self.opt.interval)

    def _write_pid(self):
        try:
            with open(self.paths.pid_file, "w") as f:
                f.write("%d\n" % os.getpid())
        except OSError:
            pass

    def shutdown(self):
        sd_notify("STOPPING=1")
        try:
            self.poll_sources(self.clock())
            self.drain_inbox(self.clock())
        except Exception:
            pass
        for s in self.sources:
            try:
                s.close()
            except Exception:
                pass
        try:
            self.pipeline.flush()
        except Exception as exc:
            self.log("err", "flush failed: %r" % (exc,))
        try:
            self.seen.save()
            self.helpers.state["last_seen"] = int(self.clock())
            self.helpers._save_state()
        except Exception:
            pass
        try:
            if self.uplink is not None:
                self.uplink.stop(False)
        except Exception as exc:
            self.log("err", "the uplink did not stop cleanly: %r" % (exc,))
        ids.mark_clean_shutdown()
        try:
            os.unlink(self.paths.pid_file)
        except OSError:
            pass
