"""The on-disk event spool (client PLAN 4.5, Spool; 9, Disk guard).

Two lanes of append-only newline-JSON segments under spool/:

    hi/   HIGH and CRITICAL events, 15 MB reserved
    lo/   everything else, 35 MB

Each segment is at most 4 MB. A partly acked segment keeps an ack offset in ack.json and
acked segments are deleted whole. When a lane is over its cap the oldest whole segment goes
(inside hi, a segment that holds collapsed repeats is thinned first), and the drop is
recorded once as a pending health.spool_dropped record that the uplink turns into an event.
Events the hub refuses go to spool/rejected/ (5 MB).

fsync rules: a HIGH or CRITICAL event is synced when it is written. Low events are written
at once and synced in groups (sync(), at most about one second later). A new segment also
syncs its directory.

This module also holds the small file helpers the other modules share (atomic_write,
read_json_safe, rfc3339), because it imports nothing from its siblings.
"""

import json
import os
import re
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone

MB = 1024 * 1024
SEG_SIZE = 4 * MB
HI_CAP = 15 * MB
LO_CAP = 35 * MB
HI_CAP_PRESSURE = 10 * MB      # the hi lane is never cut below this (PLAN 9)
LO_CAP_PRESSURE = 5 * MB
REJECT_CAP = 5 * MB
REJECT_SEG = 1 * MB
LINE_MAX = 10 * 1024           # the hub refuses an event over 10 KiB (hub Appendix A)
BATCH_EVENTS = 500
BATCH_RAW = 3 * MB
HI_SEVS = ("HIGH", "CRITICAL")
KINDS_KEPT = 8

_SEG_RE = re.compile(r"^seg-([0-9]{8})\.jsonl\Z")
_REJ_RE = re.compile(r"^rej-([0-9]{8})\.jsonl\Z")


# ---- Small file helpers shared by the other modules ---------------------------------------

def rfc3339(t=None):
    """UTC RFC 3339 string with milliseconds and a Z."""
    if t is None:
        t = time.time()
    dt = datetime.fromtimestamp(float(t), tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (dt.microsecond // 1000)


_RFC_RE = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[Tt ](\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?([Zz]|[+-]\d\d:\d\d)\Z")


def parse_rfc3339(text):
    """Epoch seconds (float) of an RFC 3339 string, or None. Hostile input: never raises."""
    if not isinstance(text, str) or len(text) > 40:
        return None
    m = _RFC_RE.match(text)
    if not m:
        return None
    try:
        y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
        frac = float("0." + m.group(7)) if m.group(7) else 0.0
        dt = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
        off = 0
        tz = m.group(8)
        if tz not in ("Z", "z"):
            sign = 1 if tz[0] == "+" else -1
            off = sign * (int(tz[1:3]) * 3600 + int(tz[4:6]) * 60)
        return dt.timestamp() + frac - off
    except (ValueError, OverflowError, OSError):
        return None


def atomic_write(path, data, mode=0o600, fsync=False):
    """Write bytes to path through a temp file and rename; the file ends up with `mode`."""
    path = str(path)
    if isinstance(data, str):
        data = data.encode("utf-8")
    tmp = path + ".tmp"
    try:
        os.unlink(tmp)
    except OSError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        if fsync:
            os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.close(fd)
    os.replace(tmp, path)


def read_file_safe(path, cap):
    """Bytes of a regular file of at most `cap` bytes, or None. Never follows a final symlink,
    never blocks on a FIFO."""
    fd = None
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        st = os.fstat(fd)
        import stat as _stat
        if not _stat.S_ISREG(st.st_mode) or st.st_size > cap:
            return None
        chunks = []
        got = 0
        while got <= cap:
            chunk = os.read(fd, min(65536, cap + 1 - got))
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
        if got > cap:
            return None
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def read_json_safe(path, cap=1024 * 1024):
    """Parsed JSON of a regular file, or None for anything wrong with it."""
    raw = read_file_safe(path, cap)
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        return None


def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


# ---- The spool ------------------------------------------------------------------------------

class Item:
    __slots__ = ("line", "event", "end", "lines")

    def __init__(self, line, event, end, lines):
        self.line = line        # the raw line, without the newline
        self.event = event      # parsed dict
        self.end = end          # offset just after this line
        self.lines = lines      # lines consumed from the batch start up to and including this one


class Batch:
    """Up to 500 events from one segment of one lane, oldest first."""

    def __init__(self, lane, seg, start, items, end, lines, ver=0):
        self.lane = lane
        self.ver = ver
        self.seg = seg
        self.start = start
        self.items = items      # list of Item (corrupt lines are skipped but counted in `lines`)
        self.end = end          # offset after the last line read (also past skipped lines)
        self.lines = lines      # total lines consumed, skipped ones included

    def __len__(self):
        return len(self.items)

    @property
    def events(self):
        return [i.event for i in self.items]


class _Lane:
    def __init__(self, name, path, cap):
        self.name = name
        self.path = path
        self.cap = cap
        self.segs = OrderedDict()   # seg number -> [size, lines]
        self.fd = None              # append descriptor of the active (highest) segment
        self.active = None          # its number
        self.ack = None             # [seg, off, lines] for the head segment, or None
        self.depth = 0              # unacked lines
        self.dirty = False
        self.next = 1               # the next segment number: never reused, even after every segment is gone
        self.ver = {}               # seg -> rewrite count, so an ack for a batch read before a thinning is ignored

    def seg_path(self, n):
        return os.path.join(self.path, "seg-%08d.jsonl" % n)

    def bytes(self):
        return sum(v[0] for v in self.segs.values())


class Spool:
    def __init__(self, spool_dir, *, hi_cap=HI_CAP, lo_cap=LO_CAP, seg_size=SEG_SIZE,
                 reject_cap=REJECT_CAP, clock=time.time):
        self.dir = str(spool_dir)
        self.seg_size = int(seg_size)
        self.reject_cap = int(reject_cap)
        self._hi_cap0, self._lo_cap0 = int(hi_cap), int(lo_cap)
        self.clock = clock
        self.lock = threading.RLock()
        self.pressure = False
        self.dropped = {"hi": 0, "lo": 0}
        self.dropped_src = {}
        self.rejected = 0
        self.corrupt = 0
        self.damaged = 0                # segments found over the size limit at open and discarded
        self.last_error = ""
        self._pending_drops = []
        self._rej_n = 0
        os.makedirs(self.dir, 0o700, exist_ok=True)
        self.rej_dir = os.path.join(self.dir, "rejected")
        os.makedirs(self.rej_dir, 0o700, exist_ok=True)
        self.lanes = {
            "hi": _Lane("hi", os.path.join(self.dir, "hi"), self._hi_cap0),
            "lo": _Lane("lo", os.path.join(self.dir, "lo"), self._lo_cap0),
        }
        for lane in self.lanes.values():
            os.makedirs(lane.path, 0o700, exist_ok=True)
        self._load_stats()
        for lane in self.lanes.values():
            self._open_lane(lane)
        self._scan_rejected()

    # ---- opening ----------------------------------------------------------------------

    def _stats_path(self):
        return os.path.join(self.dir, "stats.json")

    def _load_stats(self):
        st = read_json_safe(self._stats_path(), 64 * 1024)
        if not isinstance(st, dict):
            return
        d = st.get("dropped")
        if isinstance(d, dict):
            for k in ("hi", "lo"):
                if isinstance(d.get(k), int) and d[k] >= 0:
                    self.dropped[k] = d[k]
        src = st.get("dropped_src")
        if isinstance(src, dict):
            for k, v in list(src.items())[:32]:
                if isinstance(k, str) and isinstance(v, int) and v >= 0:
                    self.dropped_src[k[:16]] = v
        if isinstance(st.get("rejected"), int) and st["rejected"] >= 0:
            self.rejected = st["rejected"]

    def _save_stats(self):
        try:
            atomic_write(self._stats_path(), json.dumps(
                {"dropped": self.dropped, "dropped_src": self.dropped_src, "rejected": self.rejected}),
                0o600)
        except OSError:
            pass

    def _open_lane(self, lane):
        names = []
        for name in os.listdir(lane.path):
            m = _SEG_RE.match(name)
            if m:
                names.append(int(m.group(1)))
            elif name.endswith(".tmp"):
                try:
                    os.unlink(os.path.join(lane.path, name))
                except OSError:
                    pass
        names.sort()
        ack = read_json_safe(os.path.join(lane.path, "ack.json"), 4096)
        ack_t = None
        if isinstance(ack, dict) and all(isinstance(ack.get(k), int) and ack[k] >= 0 for k in ("seg", "off", "lines")):
            ack_t = [ack["seg"], ack["off"], ack["lines"]]
        ack_seg = ack_t[0] if ack_t else 0
        for n in names:
            p = lane.seg_path(n)
            limit = self.seg_size + LINE_MAX + 4096          # a segment never grows past this: a bigger file is damaged
            try:
                with open(p, "rb") as f:
                    data = f.read(limit + 1)
            except OSError:
                continue
            if len(data) > limit:
                self.last_error = "spool: segment %s/%s is over %d bytes: discarded as damaged" % (lane.name, os.path.basename(p), limit)
                self.damaged += 1
                self._unlink(p)
                continue
            if ack_t and n < ack_t[0]:
                # older than the head the ack file names: it was acked, the delete was lost
                self._unlink(p)
                continue
            if ack_t and n == ack_t[0] and ack_t[1] >= len(data):
                self._unlink(p)
                self._unlink(os.path.join(lane.path, "ack.json"))
                ack_t = None
                continue
            if data and not data.endswith(b"\n") and n == names[-1]:
                # a crash cut the last line: end it, so the next append starts a clean line
                try:
                    with open(p, "ab") as f:
                        f.write(b"\n")
                        f.flush()
                        os.fsync(f.fileno())
                    data += b"\n"
                except OSError:
                    pass
            lane.segs[n] = [len(data), data.count(b"\n")]
        if ack_t and ack_t[0] in lane.segs and ack_t[1] <= lane.segs[ack_t[0]][0]:
            lane.ack = ack_t
        else:
            lane.ack = None
        lane.next = max(list(lane.segs) + names + [ack_seg]) + 1 if (lane.segs or names or ack_seg) else 1
        lane.depth = sum(v[1] for v in lane.segs.values())
        if lane.ack:
            lane.depth -= min(lane.ack[2], lane.segs[lane.ack[0]][1])

    def _unlink(self, path):
        try:
            os.unlink(path)
        except OSError:
            pass

    # ---- writing ----------------------------------------------------------------------

    @staticmethod
    def lane_for(event):
        return "hi" if isinstance(event, dict) and event.get("sev") in HI_SEVS else "lo"

    def append(self, event, lane=None):
        """Spool one event. Returns True when it was written. Never raises."""
        try:
            line = json.dumps(event, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        except (TypeError, ValueError):
            return False
        if len(line) > LINE_MAX:
            self.reject([event], "oversize")
            return False
        name = lane or self.lane_for(event)
        sync_now = name == "hi"
        with self.lock:
            ln = self.lanes[name]
            try:
                self._write(ln, line + b"\n", sync_now)
            except OSError as exc:
                self.last_error = "spool write: %s" % (exc.strerror or exc.__class__.__name__)
                return False
            self._enforce()
        return True

    def _write(self, ln, data, sync_now):
        if ln.fd is None and ln.segs:
            last = max(ln.segs)
            if ln.segs[last][0] + len(data) <= self.seg_size:
                # carry on in the last segment after a restart
                ln.fd = os.open(ln.seg_path(last), os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
                ln.active = last
        if ln.fd is None or (ln.segs[ln.active][0] + len(data) > self.seg_size and ln.segs[ln.active][0] > 0):
            self._rotate(ln)
        os.write(ln.fd, data)
        info = ln.segs[ln.active]
        info[0] += len(data)
        info[1] += 1
        ln.depth += 1
        if sync_now:
            os.fsync(ln.fd)
            ln.dirty = False
        else:
            ln.dirty = True

    def _rotate(self, ln):
        if ln.fd is not None:
            try:
                if ln.dirty:
                    os.fsync(ln.fd)
            finally:
                os.close(ln.fd)
                ln.fd = None
                ln.dirty = False
        n = ln.next
        ln.next += 1
        fd = os.open(ln.seg_path(n), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        _fsync_dir(ln.path)
        ln.fd = fd
        ln.active = n
        ln.segs[n] = [0, 0]

    def sync(self):
        """fsync the lanes that have unsynced writes (group commit for low events)."""
        with self.lock:
            for ln in self.lanes.values():
                if ln.dirty and ln.fd is not None:
                    try:
                        os.fsync(ln.fd)
                    except OSError:
                        pass
                    ln.dirty = False

    def close(self):
        with self.lock:
            self.sync()
            for ln in self.lanes.values():
                if ln.fd is not None:
                    os.close(ln.fd)
                    ln.fd = None
                    ln.active = None
            self._save_stats()

    # ---- eviction ---------------------------------------------------------------------

    def _enforce(self):
        """Evict whole oldest segments of lo first, then hi, until each lane fits its cap."""
        for name in ("lo", "hi"):
            ln = self.lanes[name]
            while ln.bytes() > ln.cap and len(ln.segs) > 1:
                oldest = next(iter(ln.segs))
                if name == "hi" and self._thin(ln, oldest):
                    continue
                self._evict(ln, oldest)
        self._flush_drops()

    def _read_unacked(self, ln, n):
        start = ln.ack[1] if ln.ack and ln.ack[0] == n else 0
        try:
            with open(ln.seg_path(n), "rb") as f:
                f.seek(start)
                return f.read()
        except OSError:
            return b""

    def _thin(self, ln, n):
        """Inside hi, collapsed repeats go before first occurrences: rewrite a segment without
        its events that carry a repeat count above 1. Only when it frees a quarter or more."""
        if n == ln.active or (ln.ack and ln.ack[0] == n):
            return False
        data = self._read_unacked(ln, n)
        keep = []
        gone = []
        for line in data.split(b"\n"):
            if not line:
                continue
            drop = False
            if b'"count"' in line:
                try:
                    ev = json.loads(line)
                    drop = isinstance(ev, dict) and isinstance(ev.get("count"), int) and ev["count"] > 1
                except ValueError:
                    drop = False
            (gone if drop else keep).append(line)
        if not gone or sum(len(x) + 1 for x in gone) * 4 < len(data):
            return False
        new = b"".join(x + b"\n" for x in keep)
        try:
            if new:
                atomic_write(ln.seg_path(n), new, 0o600)
            else:
                self._unlink(ln.seg_path(n))
        except OSError:
            return False
        old_lines = ln.segs[n][1]
        ln.ver[n] = ln.ver.get(n, 0) + 1
        if new:
            ln.segs[n] = [len(new), len(keep)]
        else:
            del ln.segs[n]
        ln.depth -= old_lines - len(keep)
        self._note_drop(ln.name, [json_or_none(x) for x in gone])
        return True

    def _evict(self, ln, n, whole_active=False):
        if n == ln.active:
            if ln.fd is not None:
                try:
                    os.close(ln.fd)
                except OSError:
                    pass
            ln.fd = None
            ln.active = None
            ln.dirty = False
        data = self._read_unacked(ln, n)
        events = [kind_and_source(x) for x in data.split(b"\n") if x]      # not the whole events: a segment holds about 10,000
        info = ln.segs.pop(n)
        self._unlink(ln.seg_path(n))
        if ln.ack and ln.ack[0] == n:
            ln.depth -= info[1] - min(ln.ack[2], info[1])
            ln.ack = None
            self._unlink(os.path.join(ln.path, "ack.json"))
        else:
            ln.depth -= info[1]
        if ln.depth < 0:
            ln.depth = 0
        self._note_drop(ln.name, events)

    def _note_drop(self, lane, events):
        if not events:
            return
        rec = None
        for r in self._pending_drops:
            if r["lane"] == lane:
                rec = r
                break
        if rec is None:
            rec = {"lane": lane, "count": 0, "kinds": {}}
            self._pending_drops.append(rec)
        for ev in events:
            rec["count"] += 1
            kind = ev.get("kind") if isinstance(ev, dict) else None
            kind = kind if isinstance(kind, str) else "unknown"
            rec["kinds"][kind[:64]] = rec["kinds"].get(kind[:64], 0) + 1
            src = ev.get("source") if isinstance(ev, dict) else None
            src = (src if isinstance(src, str) else "unknown")[:16]
            self.dropped_src[src] = self.dropped_src.get(src, 0) + 1
        self.dropped[lane] += len(events)

    def _flush_drops(self):
        if self._pending_drops:
            self._save_stats()

    def take_drops(self):
        """Pending spool_dropped records, one per lane per eviction pass:
        [{"lane": "lo", "count": n, "kinds": {kind: n}}]. The uplink turns each into one
        health.spool_dropped event."""
        with self.lock:
            out = self._pending_drops
            self._pending_drops = []
        for rec in out:
            kinds = sorted(rec["kinds"].items(), key=lambda kv: -kv[1])
            rec["kinds"] = dict(kinds[:KINDS_KEPT])
        return out

    def set_disk_pressure(self, on):
        """Under disk pressure the lo lane is emptied and capped at 5 MB; hi may shrink to 10 MB."""
        with self.lock:
            on = bool(on)
            if on == self.pressure:
                return
            self.pressure = on
            lo, hi = self.lanes["lo"], self.lanes["hi"]
            if on:
                lo.cap, hi.cap = LO_CAP_PRESSURE, min(HI_CAP_PRESSURE, self._hi_cap0)
                for n in list(lo.segs):
                    self._evict(lo, n)
            else:
                lo.cap, hi.cap = self._lo_cap0, self._hi_cap0
            self._enforce()

    # ---- reading and acking -----------------------------------------------------------

    def depth(self, lane=None):
        with self.lock:
            if lane:
                return self.lanes[lane].depth
            return sum(ln.depth for ln in self.lanes.values())

    def total_bytes(self):
        with self.lock:
            return sum(ln.bytes() for ln in self.lanes.values())

    def next_batch(self, max_events=BATCH_EVENTS, max_raw=BATCH_RAW):
        """The oldest unacked events, hi lane first. None when the spool is empty."""
        with self.lock:
            for name in ("hi", "lo"):
                ln = self.lanes[name]
                if ln.depth <= 0 or not ln.segs:
                    continue
                b = self._read_batch(ln, max_events, max_raw)
                if b is not None:
                    return b
            return None

    def _read_batch(self, ln, max_events, max_raw):
        n = next(iter(ln.segs))
        size = ln.segs[n][0]
        off = ln.ack[1] if ln.ack and ln.ack[0] == n else 0
        if off >= size:
            return None
        try:
            with open(ln.seg_path(n), "rb") as f:
                f.seek(off)
                data = f.read(min(size - off, max_raw + LINE_MAX + 16))
        except OSError as exc:
            self.last_error = "spool read: %s" % (exc.strerror or exc.__class__.__name__)
            return None
        items = []
        pos = 0
        lines = 0
        raw = 0
        end = off
        while pos < len(data):
            nl = data.find(b"\n", pos)
            if nl < 0:
                break                       # a partial tail: not ours yet
            line = data[pos:nl]
            nxt = nl + 1
            if line:
                if len(items) >= max_events or (items and raw + len(line) + 1 > max_raw):
                    break
                try:
                    ev = json.loads(line)
                    ok = isinstance(ev, dict)
                except (ValueError, RecursionError):
                    ok = False
                lines += 1
                end = off + nxt
                if ok:
                    raw += len(line) + 1
                    items.append(Item(line, ev, end, lines))
                else:
                    self.corrupt += 1
            else:
                lines += 1
                end = off + nxt
            pos = nxt
        if lines == 0:
            return None
        return Batch(ln.name, n, off, items, end, lines, ln.ver.get(n, 0))

    def ack(self, batch, n=None):
        """Drop the first n events of the batch (all by default) from the spool."""
        with self.lock:
            ln = self.lanes[batch.lane]
            if batch.seg not in ln.segs or batch.ver != ln.ver.get(batch.seg, 0):
                return                  # evicted or rewritten since it was read: the events go again, the hub dedups
            if n is None or n >= len(batch.items):
                off, lines = batch.end, batch.lines
            elif n <= 0:
                return
            else:
                it = batch.items[n - 1]
                off, lines = it.end, it.lines
            base_lines = ln.ack[2] if ln.ack and ln.ack[0] == batch.seg else 0
            base_off = ln.ack[1] if ln.ack and ln.ack[0] == batch.seg else 0
            if off <= base_off:
                return
            info = ln.segs[batch.seg]
            new_lines = base_lines + lines
            ln.depth = max(0, ln.depth - lines)
            if off >= info[0]:
                self._drop_segment(ln, batch.seg)
            else:
                ln.ack = [batch.seg, off, new_lines]
                try:
                    atomic_write(os.path.join(ln.path, "ack.json"),
                                 json.dumps({"seg": batch.seg, "off": off, "lines": new_lines}), 0o600)
                except OSError:
                    pass

    def _drop_segment(self, ln, n):
        if n == ln.active:
            if ln.fd is not None:
                try:
                    os.close(ln.fd)
                except OSError:
                    pass
            ln.fd = None
            ln.active = None
            ln.dirty = False
        ln.segs.pop(n, None)
        self._unlink(ln.seg_path(n))
        if ln.ack and ln.ack[0] == n:
            ln.ack = None
        self._unlink(os.path.join(ln.path, "ack.json"))
        if not ln.segs:
            ln.depth = 0

    def clear(self):
        """Discard everything queued (rehome --drop-spool). Not counted as dropped."""
        with self.lock:
            for ln in self.lanes.values():
                for n in list(ln.segs):
                    self._drop_segment(ln, n)
                ln.depth = 0

    # ---- the rejected area ------------------------------------------------------------

    def _scan_rejected(self):
        nums = []
        for name in os.listdir(self.rej_dir):
            m = _REJ_RE.match(name)
            if m:
                nums.append(int(m.group(1)))
        self._rej_n = max(nums) if nums else 0

    def reject(self, events, reason=""):
        """Keep events the hub refused, for the operator. Capped at 5 MB; the oldest file goes."""
        with self.lock:
            lines = []
            for ev in events:
                try:
                    obj = ev if isinstance(ev, dict) else {"raw": str(ev)[:512]}
                    lines.append(json.dumps({"rejected": reason[:32], "event": obj},
                                            separators=(",", ":"))[:LINE_MAX].encode("ascii", "replace") + b"\n")
                except (TypeError, ValueError):
                    continue
            self.rejected += len(events)
            try:
                for ln in lines:
                    self._rej_write(ln)
                self._rej_trim()
            except OSError as exc:
                self.last_error = "spool rejected: %s" % (exc.strerror or exc.__class__.__name__)
            self._save_stats()

    def _rej_files(self):
        out = []
        for name in os.listdir(self.rej_dir):
            m = _REJ_RE.match(name)
            if m:
                out.append((int(m.group(1)), name))
        out.sort()
        return out

    def _rej_write(self, data):
        files = self._rej_files()
        if files:
            n, name = files[-1]
            p = os.path.join(self.rej_dir, name)
            if os.path.getsize(p) + len(data) <= REJECT_SEG:
                with open(p, "ab") as f:
                    f.write(data)
                return
        self._rej_n += 1
        with open(os.path.join(self.rej_dir, "rej-%08d.jsonl" % self._rej_n), "wb") as f:
            f.write(data)

    def _rej_trim(self):
        files = self._rej_files()
        total = sum(os.path.getsize(os.path.join(self.rej_dir, n)) for _, n in files)
        while total > self.reject_cap and len(files) > 1:
            _, name = files.pop(0)
            p = os.path.join(self.rej_dir, name)
            total -= os.path.getsize(p)
            self._unlink(p)

    def rejected_bytes(self):
        with self.lock:
            return sum(os.path.getsize(os.path.join(self.rej_dir, n)) for _, n in self._rej_files())

    # ---- numbers for the heartbeat and status -----------------------------------------

    def stats(self):
        with self.lock:
            return {
                "depth": sum(ln.depth for ln in self.lanes.values()),
                "bytes": sum(ln.bytes() for ln in self.lanes.values()),
                "depth_hi": self.lanes["hi"].depth,
                "depth_lo": self.lanes["lo"].depth,
                "dropped": dict(self.dropped),
                "dropped_by_source": dict(self.dropped_src),
                "rejected": self.rejected,
                "pressure": self.pressure,
            }


def kind_and_source(line):
    """What _note_drop needs of a dropped line: its kind and source (None for a corrupt line)."""
    ev = json_or_none(line)
    return None if ev is None else {"kind": ev.get("kind"), "source": ev.get("source")}


def json_or_none(line):
    try:
        v = json.loads(line)
        return v if isinstance(v, dict) else None
    except (ValueError, RecursionError):
        return None
