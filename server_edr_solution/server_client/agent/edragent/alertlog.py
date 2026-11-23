"""alerts.jsonl and summary.json: what a host with no hub (or a hub that is down) still tells its owner.

Every HIGH and CRITICAL event is appended to alerts.jsonl (5 MB, 2 files, fsync on CRITICAL). The writer is
separate from the event stream, which sends every distinct event (client PLAN section 4.7):
  - repeats of the same alert are collapsed into one line with a count, written when the window (5 min) ends;
  - lines that are not the first of their alert are capped at 60 a minute; the rest are counted and one
    "N suppressed" line is written when the minute is over;
  - the first occurrence of an alert is never dropped, so a flood of one alert cannot push out older alerts
    or hide a new one.
summary.json (in the agent's run directory) is what `status` and the login message show: the open HIGH and
CRITICAL alerts of the last 7 days and whether the hub is reachable.
"""
import json
import os
import time

from . import event as evmod
from . import ids

WINDOW_S = 300
LINES_PER_MINUTE = 60
MAX_BYTES = 5 * 1024 * 1024
MAX_KEYS = 5000
SUMMARY_DAYS = 7
SUMMARY_MAX = 20


class AlertLog:
    def __init__(self, path, clock=time.time, window=WINDOW_S, cap=LINES_PER_MINUTE, max_bytes=MAX_BYTES, log=None):
        self.path, self.clock = path, clock
        self.window, self.cap, self.max_bytes = window, cap, max_bytes
        self.log = log or (lambda level, msg: None)
        self.state = {}
        self.fd = None
        self.size = 0
        self.minute = None
        self.lines = 0
        self.suppressed = 0
        self.written = 0
        self._n = 0

    # ---- file -----------------------------------------------------------------------------------
    def _open(self):
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        self.fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        self.size = os.fstat(self.fd).st_size

    def _rotate(self):
        os.close(self.fd)
        self.fd = None
        os.replace(self.path, self.path + ".1")
        self._open()

    def _append(self, obj, sync=False):
        try:
            if self.fd is None:
                self._open()
            data = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
            if self.size + len(data) > self.max_bytes:
                self._rotate()
            os.write(self.fd, data)
            self.size += len(data)
            self.written += 1
            if sync:
                os.fsync(self.fd)
        except OSError as e:
            self.log("err", "alerts.jsonl: %s" % e)

    def close(self):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    # ---- the per-minute cap -----------------------------------------------------------------------
    def _roll(self, now):
        minute = int(now // 60)
        if self.minute is None:
            self.minute = minute
        elif minute != self.minute:
            if self.suppressed:
                line = {"v": 1, "ts": evmod.rfc3339(int(now * 1000)), "sev": "HIGH", "kind": "health.alerts_suppressed",
                        "source": "agent", "id": self._alert_id(),
                        "summary": "%d alert lines were suppressed in the last minute (cap %d)" % (self.suppressed, self.cap),
                        "count": self.suppressed}
                self._append(line)
            self.minute, self.lines, self.suppressed = minute, 0, 0

    def _alert_id(self):
        self._n += 1
        return "%08x:a%d" % (ids.current()[0], time.time_ns() // 1000 + self._n)

    def _emit(self, obj, first, now, sync=False, weight=1):
        self._roll(now)
        if not first and self.lines >= self.cap:
            self.suppressed += weight
            return False
        self.lines += 1
        self._append(obj, sync=sync)
        return True

    # ---- alerts ---------------------------------------------------------------------------------
    @staticmethod
    def _key(e):
        return (e.get("kind", ""), e.get("src_ip", ""), str(e.get("summary", ""))[:120])

    def add(self, e, now=None):
        """One HIGH or CRITICAL event, after normalising and before any collapsing of the event stream."""
        now = self.clock() if now is None else now
        if evmod.sev_rank(e.get("sev")) < 3:
            return
        key = self._key(e)
        st = self.state.get(key)
        if st is not None and now < st["until"]:
            st["pending"] += 1
            st["first_ts"] = st["first_ts"] or e.get("ts")
            st["last_ts"] = e.get("ts")
            st["ev"] = e
            return
        if st is not None and st["pending"]:
            self._write_collapsed(st, now)
        line = {k: v for k, v in e.items() if k != "context"}
        line.setdefault("id", self._alert_id())
        self._emit(line, True, now, sync=e.get("sev") == "CRITICAL")
        self.state[key] = {"until": now + self.window, "pending": 0, "first_ts": None, "last_ts": None, "ev": e}
        if len(self.state) > MAX_KEYS:
            self._evict(now)

    def _write_collapsed(self, st, now):
        base = {k: v for k, v in st["ev"].items() if k != "context"}
        base["id"] = self._alert_id()
        base["count"], base["first_ts"], base["last_ts"] = st["pending"], st["first_ts"], st["last_ts"]
        self._emit(base, False, now, sync=base.get("sev") == "CRITICAL", weight=st["pending"])
        st["pending"], st["first_ts"], st["last_ts"] = 0, None, None

    def _evict(self, now):
        for key in sorted(self.state, key=lambda k: self.state[k]["until"])[: MAX_KEYS // 10]:
            st = self.state.pop(key)
            if st["pending"]:
                self._write_collapsed(st, now)

    def tick(self, now=None):
        """Close windows that ended and the minute that ended."""
        now = self.clock() if now is None else now
        self._roll(now)
        for key in [k for k, st in self.state.items() if now >= st["until"]]:
            st = self.state.pop(key)
            if st["pending"]:
                self._write_collapsed(st, now)

    def flush(self, now=None):
        """Write every pending collapsed line (at shutdown)."""
        now = self.clock() if now is None else now
        for st in self.state.values():
            if st["pending"]:
                self._write_collapsed(st, now)
        self.state.clear()
        self._roll(now + 60)


def read_alerts(path, since_epoch=0, limit=100000):
    """Alert lines from the two files, oldest first, newer than since_epoch. Bad lines are skipped."""
    out = []
    for p in (path + ".1", path):
        try:
            with open(p, "rb") as f:
                for raw in f:
                    if len(raw) > 16384:
                        continue
                    try:
                        e = json.loads(raw)
                    except ValueError:
                        continue
                    if not isinstance(e, dict):
                        continue
                    ts = evmod.parse_ts(e.get("ts"))
                    if ts is not None and ts / 1000.0 < since_epoch:
                        continue
                    out.append(e)
                    if len(out) > limit:
                        out.pop(0)
        except OSError:
            continue
    return out


def parse_duration(text):
    """'7d', '12h', '30m' or a bare number of seconds, as seconds; raises ValueError."""
    text = text.strip()
    if text.isdigit():
        return int(text)
    unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(text[-1:])
    if unit is None or not text[:-1].isdigit():
        raise ValueError("not a duration: " + text)
    return int(text[:-1]) * unit


class Summary:
    """The open HIGH and CRITICAL alerts of the last 7 days, for summary.json."""

    def __init__(self, path, clock=time.time):
        self.path, self.clock = path, clock
        self.items = {}
        self.dirty = True
        self.last_write = 0.0

    def load(self, alerts_path):
        for e in read_alerts(alerts_path, self.clock() - SUMMARY_DAYS * 86400):
            self.add(e)

    def add(self, e):
        if evmod.sev_rank(e.get("sev")) < 3:
            return
        key = (e.get("kind", ""), e.get("src_ip", ""), str(e.get("summary", ""))[:120])
        item = self.items.get(key)
        count = e.get("count") if isinstance(e.get("count"), int) else 1
        if item is None:
            self.items[key] = {"ts": e.get("ts"), "sev": e.get("sev"), "kind": e.get("kind", ""),
                               "summary": str(e.get("summary", ""))[:200], "src_ip": e.get("src_ip", ""), "count": count}
            if len(self.items) > 500:
                oldest = min(self.items, key=lambda k: self.items[k]["ts"] or "")
                del self.items[oldest]
        else:
            item["ts"], item["count"] = e.get("ts"), item["count"] + count
            if evmod.sev_rank(e.get("sev")) > evmod.sev_rank(item["sev"]):
                item["sev"] = e.get("sev")
        self.dirty = True

    def snapshot(self, hub=None, extra=None):
        now = self.clock()
        cutoff = evmod.rfc3339((now - SUMMARY_DAYS * 86400) * 1000)
        live = [v for v in self.items.values() if (v["ts"] or "") >= cutoff]
        live.sort(key=lambda v: (evmod.sev_rank(v["sev"]), v["ts"] or ""), reverse=True)
        counts = {"CRITICAL": 0, "HIGH": 0}
        for v in live:
            counts[v["sev"]] = counts.get(v["sev"], 0) + 1
        snap = {"v": 1, "written_at": int(now), "counts": counts, "alerts": live[:SUMMARY_MAX], "hub": hub or {}}
        if extra:
            snap.update(extra)
        return snap

    def write(self, hub=None, force=False, extra=None):
        now = self.clock()
        if not force and not self.dirty and now - self.last_write < 30:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "w") as f:
                json.dump(self.snapshot(hub, extra), f)
            os.chmod(tmp, 0o644)
            os.replace(tmp, self.path)
            self.last_write, self.dirty = now, False
        except OSError:
            pass
