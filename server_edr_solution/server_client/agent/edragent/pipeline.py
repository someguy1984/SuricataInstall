"""From a normalised event to the ban engine, the alert file and the hub (client PLAN section 4.5, Processing).

Every event the readers make comes through process():
  1. the ban engine sees it first, before any collapsing (its own new events, such as ban.local, go through
     the rest of the chain but are not shown to it again);
  2. HIGH and CRITICAL go to alerts.jsonl, whose writer collapses and caps on its own;
  3. repeats are collapsed: LOW and MEDIUM, and HIGH of the same (kind, address, sid or path), inside a 5 minute
     window. The first occurrence is sent at once; when the window ends one more event carries the number of
     repeats in `count`, with `first_ts` and `last_ts`. CRITICAL is never collapsed, capped or budgeted;
  4. LOW and MEDIUM are budgeted per source (event_budget_per_hour); HIGH from one address is capped at 200 an
     hour and the first excess raises one health.high_flood. The excess is counted, not sent;
  5. what is left gets its id, its access-log context (HIGH and CRITICAL with an address) and goes to the uplink.
Events of source agent and canary are not budgeted.
"""
import collections
import hashlib
import threading
import time

from . import alertlog, ids
from . import event as ev
from . import learn as learnmod

COLLAPSE_WINDOW_S = 300
HIGH_PER_HOUR = 200
BUDGETED = ("tetragon", "suricata", "nginx", "journal", "kernel", "inventory")
MAX_COLLAPSE_KEYS = 10000


class Pipeline:
    def __init__(self, cfg, paths, ban_engine=None, uplink=None, ctx=None, clock=time.time, log=None, web_user_name=None):
        self.cfg, self.paths = cfg, paths
        self.lock = threading.RLock()                 # the uplink's threads hand in events too
        self.bans, self.uplink, self.ctx = ban_engine, uplink, ctx
        self.clock = clock
        self.log = log or (lambda level, msg: None)
        self.alerts = alertlog.AlertLog(paths.alerts_jsonl, clock, log=self.log)
        self.summary = alertlog.Summary(paths.summary_json, clock)
        self.learn = learnmod.LearnStore(paths.learn_json, clock)
        self.user_name = web_user_name or (ctx.user_name if ctx is not None else str)
        self.collapse = {}
        self.budget = {}
        self.flood = {}
        self.dropped = collections.Counter()          # budget and flood drops since the agent started, by source
        self.health = collections.deque(maxlen=500)   # (time, kind) of health.gap and health.spool_dropped, for check.sh
        self.counts = collections.Counter()           # events forwarded, by severity
        self.collapsed_total = 0
        self.hub_down = False                          # set by the daemon: HIGH goes to the journal as crit then
        self.last_summary_write = 0.0
        self.last_save = 0.0
        self.summary.load(paths.alerts_jsonl)

    # ---- entry ----------------------------------------------------------------------------------
    def process(self, e, now=None, observe=True):
        with self.lock:
            self._process(e, now, observe)

    def _process(self, e, now, observe):
        now = self.clock() if now is None else now
        extra = []
        if observe and self.bans is not None:
            try:
                extra = list(self.bans.observe(e, now) or [])
            except Exception as exc:                  # one bad event must not stop the stream
                self.log("err", "ban engine failed on an event: %r" % (exc,))
        try:
            self.learn.record(e, self.user_name)
        except Exception as exc:
            self.log("err", "learning failed on an event: %r" % (exc,))
        sev = e.get("sev", "MEDIUM")
        sent = self._decide(e, now)
        if sent:
            self._forward(e)
        if ev.sev_rank(sev) >= 3:
            self.alerts.add(e, now)
            self.summary.add(e)
            if sent:
                self._journal(e)
        for x in extra:
            if isinstance(x, dict):
                self.process(x, now, observe=False)

    def process_many(self, events, now=None):
        for e in events:
            self.process(e, now)

    # ---- collapse, flood and budget -------------------------------------------------------------------
    @staticmethod
    def _collapse_key(e):
        sev, kind = e.get("sev"), e.get("kind", "")
        det = e.get("details") or {}
        if e.get("source") == "tetragon":
            proc = e.get("proc") or {}
            argv = " ".join(str(proc.get("args", "")).split()[:3])
            return ("t", kind, proc.get("binary", ""), hashlib.sha1(argv.encode("utf-8", "replace")).hexdigest(),
                    proc.get("parent", ""))
        what = det.get("sid") if "sid" in det else det.get("path") if sev == "HIGH" and "path" in det else ""
        return ("l", kind, e.get("src_ip", ""), str(what))

    def _decide(self, e, now):
        sev = e.get("sev", "MEDIUM")
        rank = ev.sev_rank(sev)
        if sev == "CRITICAL":
            return True
        if 1 <= rank <= 3:
            key = self._collapse_key(e)
            st = self.collapse.get(key)
            if st is not None and now < st["until"]:
                st["pending"] += 1
                st["first_ts"] = st["first_ts"] or e.get("ts")
                st["last_ts"] = e.get("ts")
                self.collapsed_total += 1
                return False
            if st is not None:
                self._send_collapsed(key, st)
            self.collapse[key] = {"until": now + COLLAPSE_WINDOW_S, "pending": 0, "first_ts": None, "last_ts": None,
                                  "template": e}
            if len(self.collapse) > MAX_COLLAPSE_KEYS:
                self._evict_collapse(now)
        source = e.get("source", "agent")
        if sev == "HIGH":
            return self._flood_ok(e, now)
        if source in BUDGETED and rank <= 2:
            return self._budget_ok(source, now)
        return True

    def _flood_ok(self, e, now):
        hour = int(now // 3600)
        key = e.get("src_ip") or e.get("source", "")
        row = self.flood.get(key)
        if row is None or row[0] != hour:
            if len(self.flood) > 5000:
                self.flood = {k: v for k, v in self.flood.items() if v[0] == hour}
            row = self.flood[key] = [hour, 0, False]
        row[1] += 1
        if row[1] <= HIGH_PER_HOUR:
            return True
        self.dropped[e.get("source", "agent")] += 1
        if not row[2]:
            row[2] = True
            flood = ev.make_event("health.high_flood", "agent", "HIGH",
                                  "more than %d HIGH events an hour from %s: the rest are counted, not sent" % (HIGH_PER_HOUR, key or "one source"),
                                  details={"key": key, "cap": HIGH_PER_HOUR})
            self.process(flood, now, observe=False)
        return False

    def _budget_ok(self, source, now):
        limit = self.cfg.get("agent", "event_budget_per_hour", 2000)
        hour = int(now // 3600)
        row = self.budget.get(source)
        if row is None or row[0] != hour:
            row = self.budget[source] = [hour, 0]
        if row[1] >= limit:
            self.dropped[source] += 1
            return False
        row[1] += 1
        return True

    def _send_collapsed(self, key, st):
        if not st["pending"]:
            return
        base = dict(st["template"])
        base.pop("id", None)
        base.pop("epoch", None)
        base.pop("seq", None)
        base.pop("context", None)
        base["count"], base["first_ts"], base["last_ts"] = st["pending"], st["first_ts"], st["last_ts"]
        base["ts"] = st["last_ts"] or base.get("ts")
        st["pending"] = 0
        self._forward(ev.fit(base))

    def _evict_collapse(self, now):
        for key in sorted(self.collapse, key=lambda k: self.collapse[k]["until"])[: MAX_COLLAPSE_KEYS // 10]:
            st = self.collapse.pop(key)
            self._send_collapsed(key, st)

    # ---- out ------------------------------------------------------------------------------------
    def _forward(self, e):
        if ev.sev_rank(e.get("sev")) >= 3 and e.get("src_ip") and self.ctx is not None and "context" not in e:
            entries = self.ctx.ring.entries_for(e["src_ip"])
            if entries:
                ev.attach_context(e, entries)
        ids.stamp(e)
        self.counts[e.get("sev", "")] += 1
        if e.get("kind") in ("health.gap", "health.spool_dropped"):
            self.health.append((self.clock(), e["kind"][7:]))
        if self.uplink is not None:
            try:
                self.uplink.submit(e)
            except Exception as exc:
                self.log("err", "the uplink refused an event: %r" % (exc,))

    def _journal(self, e):
        """A copy in the journal: crit for CRITICAL (and for HIGH while the hub is gone), err for HIGH."""
        level = "crit" if e.get("sev") == "CRITICAL" or self.hub_down else "err"
        self.log(level, "ALERT %s %s %s %s" % (e.get("sev"), e.get("kind"), e.get("src_ip", ""), e.get("summary", "")))

    # ---- housekeeping ---------------------------------------------------------------------------
    def tick(self, now=None, hub_status=None, extra=None):
        with self.lock:
            self._tick(now, hub_status, extra)

    def _tick(self, now, hub_status, extra):
        now = self.clock() if now is None else now
        if self.bans is not None:
            try:
                for x in self.bans.tick(now) or []:
                    if isinstance(x, dict):
                        self.process(x, now, observe=False)
            except Exception as exc:
                self.log("err", "ban engine tick failed: %r" % (exc,))
        for key in [k for k, st in self.collapse.items() if now >= st["until"]]:
            st = self.collapse.pop(key)
            self._send_collapsed(key, st)
        self.alerts.tick(now)
        if now - self.last_summary_write >= 10:
            self.last_summary_write = now
            self.summary.write(hub_status, extra=extra)
        if now - self.last_save >= 60:
            self.last_save = now
            self.learn.save()

    def flush(self, now=None):
        with self.lock:
            self._flush(now)

    def _flush(self, now):
        """At shutdown: send what the windows still hold and write what the alert file still holds."""
        now = self.clock() if now is None else now
        for key in list(self.collapse):
            self._send_collapsed(key, self.collapse.pop(key))
        self.alerts.flush(now)
        self.alerts.close()
        self.learn.save()
        self.summary.write(force=True)

    def health_24h(self):
        """{"gap": n, "spool_dropped": n} for the last 24 hours of this run."""
        cut = self.clock() - 86400
        out = {"gap": 0, "spool_dropped": 0}
        for t, k in list(self.health):
            if t >= cut and k in out:
                out[k] += 1
        return out

    def stats(self):
        with self.lock:
            return self._stats()

    def _stats(self):
        return {"dropped": dict(self.dropped), "forwarded": dict(self.counts), "collapsed": self.collapsed_total,
                "alert_lines": self.alerts.written}
