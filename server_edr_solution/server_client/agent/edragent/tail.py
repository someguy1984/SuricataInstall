"""Reading logs: a file tailer with checkpoints, a FIFO reader and a journal follower (client PLAN section 4.5).

All three give the daemon plain lines (or parsed journal records) from poll(), and keep a checkpoint
that commit() writes. The daemon commits only after the pipeline has handled a batch, so a crash repeats
lines instead of losing them (at-least-once; the hub dedupes by event id).

File rules, in the order the plan gives them:
  resume      same inode and head hash and size >= offset: continue from the offset
  rotation    a different inode: finish the older file that still holds the stored inode (eve.json.1; a .gz
              only as best effort), then start the new file at 0; a file that was rotated while we run is
              kept open for 10 s of EOF, because nginx writes to it until USR1
  shrink      same inode and size < offset (copytruncate, or a log wiped by hand): start at 0, count a gap and
              report a "truncated" notice (the daemon turns it into HIGH tamper.log_truncated)
  backlog     after downtime read at most 64 MiB or 24 h; skip the rest and report one gap
  long lines  at most 64 KiB are kept, the rest is dropped and counted
"""
import errno
import glob
import gzip
import hashlib
import json
import os
import stat
import subprocess
import time

MAX_LINE = 64 * 1024
BACKLOG_BYTES = 64 * 1024 * 1024
BACKLOG_AGE_S = 24 * 3600
ROTATED_GRACE_S = 10.0
HEAD_BYTES = 256
READ_CHUNK = 64 * 1024


def _decode(raw):
    if raw.endswith(b"\r"):
        raw = raw[:-1]
    return raw.decode("utf-8", errors="replace")


def _atomic_json(path, obj):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def _load_json(path):
    try:
        with open(path, "rb") as f:
            obj = json.loads(f.read(8192))
        return obj if isinstance(obj, dict) else None
    except (OSError, ValueError):
        return None


class Tailer:
    """Follow one log file by name, with a checkpoint under cursors_dir/<name>.json."""

    def __init__(self, path, name, cursors_dir, first_start="end", clock=time.time, max_line=MAX_LINE,
                 backlog_bytes=BACKLOG_BYTES, backlog_age=BACKLOG_AGE_S, grace=ROTATED_GRACE_S):
        self.path, self.name = path, name
        self.cursor_path = os.path.join(cursors_dir, name + ".json")
        self.first_start = first_start
        self.clock = clock
        self.max_line = max_line
        self.backlog_bytes, self.backlog_age, self.grace = backlog_bytes, backlog_age, grace
        self.f = None
        self.is_gz = False
        self.dev = self.ino = None
        self.offset = 0             # file offset of the first byte not yet turned into a line
        self.partial = b""
        self.skipping = False
        self.eof_since = None
        self.notices = []
        self.counters = {"truncated": 0, "gaps": 0, "lines": 0}
        self.error = None           # "unreadable" while the file exists but cannot be opened
        self._saved = None
        self._opened_once = False
        self._pending_new = None    # (file, stat) of the new file to open after finishing an older one

    # ---- opening ---------------------------------------------------------------------------------
    def _notice(self, kind, **info):
        info.update(type=kind, name=self.name)
        self.notices.append(info)

    def drain_notices(self):
        out, self.notices = self.notices, []
        return out

    def _open_path(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            raise OSError(errno.EINVAL, "not a regular file")
        return os.fdopen(fd, "rb", buffering=0), st

    def _head_hash(self, f, length):
        try:
            data = os.pread(f.fileno(), length, 0)
        except OSError:
            return None
        return hashlib.sha1(data).hexdigest() if len(data) == length else None

    def _open(self):
        try:
            f, st = self._open_path(self.path)
        except FileNotFoundError:
            self.error = None
            return False
        except OSError as e:
            if self.error != e.errno:
                self.error = e.errno
                self._notice("unreadable", errno=e.errno, reason=os.strerror(e.errno) if e.errno else "error")
            return False
        self.error = None
        cur = _load_json(self.cursor_path)
        if not self._opened_once:
            self._opened_once = True
            self._resume(f, st, cur)
        else:
            self._attach(f, st, 0)
        return True

    def _attach(self, f, st, offset):
        self.f, self.is_gz = f, False
        self.dev, self.ino = st.st_dev, st.st_ino
        self.offset, self.partial, self.skipping, self.eof_since = offset, b"", False, None
        if offset:
            f.seek(offset)

    def _resume(self, f, st, cur):
        if cur is None or not all(isinstance(cur.get(k), int) for k in ("dev", "ino", "offset")):
            if self.first_start == "end":
                self._attach(f, st, st.st_size)
                try:
                    # the writer may be in the middle of a line: drop its end
                    self.skipping = st.st_size > 0 and os.pread(f.fileno(), 1, st.st_size - 1) != b"\n"
                except OSError:
                    pass
            else:
                self._attach(f, st, 0)
            return
        if (cur["dev"], cur["ino"]) == (st.st_dev, st.st_ino):
            if self._head_changed(f, cur, st):
                self._attach(f, st, 0)
                self._truncated(cur["offset"], "head_changed")
                return
            self._attach(f, st, cur["offset"])
            self._apply_backlog(st)
            return
        # a different inode: the file we were reading was rotated while the agent was down
        older = self._find_older(cur)
        if older is not None:
            of, ost, is_gz = older
            self._attach(of, ost, 0)
            self.is_gz = is_gz
            if is_gz:
                self._skip_gz(of, cur["offset"])
                self.offset = cur["offset"]
            else:
                of.seek(cur["offset"])
                self.offset = cur["offset"]
                self._apply_backlog(ost)
            # the new file follows at once, with no 10 s wait
            self._pending_new = (f, st)
            return
        self._gap("rotated_unread")
        self._attach(f, st, 0)

    def _head_changed(self, f, cur, st):
        if st.st_size < cur["offset"]:
            return True
        length = cur.get("head_len")
        want = cur.get("head_hash")
        if not isinstance(length, int) or not isinstance(want, str) or length <= 0:
            return False
        got = self._head_hash(f, length)
        return got is not None and got != want

    def _find_older(self, cur):
        for suffix in (".1", ".0", ".2", ".3"):
            cand = self.path + suffix
            try:
                f, st = self._open_path(cand)
            except OSError:
                continue
            if (st.st_dev, st.st_ino) == (cur["dev"], cur["ino"]):
                return f, st, False
            f.close()
        saved = cur.get("saved_at") if isinstance(cur.get("saved_at"), (int, float)) else 0
        gz = []
        for cand in glob.glob(glob.escape(self.path) + ".*.gz"):
            try:
                st = os.stat(cand)
            except OSError:
                continue
            if saved and st.st_mtime >= saved - 60:
                gz.append((st.st_mtime, cand))
        for _, cand in sorted(gz):
            try:
                raw = gzip.open(cand, "rb")
                return raw, os.stat(cand), True
            except OSError:
                continue
        return None

    def _skip_gz(self, f, count):
        left = count
        try:
            while left > 0:
                chunk = f.read(min(left, 1 << 20))
                if not chunk:
                    break
                left -= len(chunk)
        except (OSError, EOFError):
            pass

    def _apply_backlog(self, st):
        """Resume rule: at most 64 MiB or 24 h of unread data; skip the rest and report one gap."""
        unread = st.st_size - self.offset
        if unread <= 0:
            return
        before = self.offset
        if self.clock() - st.st_mtime > self.backlog_age:
            self.offset = st.st_size
            self.f.seek(self.offset)
            self._gap("backlog_age", skipped_bytes=self.offset - before)
        elif unread > self.backlog_bytes:
            self.offset = st.st_size - self.backlog_bytes
            self.f.seek(self.offset)
            self.skipping = True
            self._gap("backlog_size", skipped_bytes=self.offset - before)

    def _gap(self, reason, **info):
        self.counters["gaps"] += 1
        self._notice("gap", reason=reason, **info)

    def _truncated(self, was, reason):
        self.counters["gaps"] += 1
        self._notice("truncated", reason=reason, offset=was)

    # ---- reading ---------------------------------------------------------------------------------
    def poll(self, max_lines=2000):
        """New complete lines (strings) since the last call; [] when there is nothing."""
        lines = []
        if self.f is None and not self._open():
            return lines
        retries = 0
        while len(lines) < max_lines:
            try:
                chunk = self.f.read(READ_CHUNK) if self.f is not None else b""
            except (OSError, EOFError):
                chunk = b""
            if not chunk:
                again = self._at_eof(lines)
                if again and retries < 3 and self.f is not None:
                    retries += 1            # the file was reset or replaced: there may be more to read right now
                    continue
                break
            self.eof_since = None
            self._feed(chunk, lines)
        self.counters["lines"] += len(lines)
        return lines

    def _feed(self, buf, lines):
        while buf:
            if self.skipping:
                i = buf.find(b"\n")
                if i < 0:
                    self.offset += len(buf)
                    return
                self.offset += i + 1
                buf = buf[i + 1:]
                self.skipping = False
                continue
            i = buf.find(b"\n")
            if i < 0:
                self.partial += buf
                if len(self.partial) > self.max_line:
                    lines.append(_decode(self.partial[: self.max_line]))
                    self.counters["truncated"] += 1
                    self.offset += len(self.partial)
                    self.partial, self.skipping = b"", True
                return
            raw = self.partial + buf[:i]
            self.offset += len(self.partial) + i + 1
            self.partial, buf = b"", buf[i + 1:]
            if len(raw) > self.max_line:
                raw = raw[: self.max_line]
                self.counters["truncated"] += 1
            lines.append(_decode(raw))

    def _at_eof(self, lines):
        now = self.clock()
        if self.is_gz or self._pending_new is not None:
            self._switch(lines)
            return True
        try:
            fst = os.fstat(self.f.fileno())
        except OSError:
            return False
        position = self.offset + len(self.partial)
        if fst.st_size < position:
            # shrink: copytruncate, or the log was emptied
            self._truncated(position, "shrunk")
            self.partial, self.skipping, self.offset = b"", False, 0
            self.f.seek(0)
            return True
        try:
            pst = os.stat(self.path)
            moved = (pst.st_dev, pst.st_ino) != (self.dev, self.ino)
        except FileNotFoundError:
            moved = True
        except OSError:
            return False
        if not moved:
            self.eof_since = None
            return False
        if self.eof_since is None:
            self.eof_since = now
        if now - self.eof_since >= self.grace:
            self._switch(lines)
            return True
        return False

    def _switch(self, lines):
        """Leave the rotated file (its last unfinished line counts as a line) and open the new one."""
        if self.partial:
            lines.append(_decode(self.partial[: self.max_line]))
            self.partial = b""
        pending, self._pending_new = self._pending_new, None
        try:
            self.f.close()
        except OSError:
            pass
        self.f = None
        if pending is not None:
            f, st = pending
            self._attach(f, st, 0)
            self._notice("rotated", gap=False)
            return
        try:
            f, st = self._open_path(self.path)
        except OSError:
            self.dev = self.ino = None
            return
        self._attach(f, st, 0)
        self._notice("rotated", gap=False)

    # ---- checkpoint ------------------------------------------------------------------------------
    def commit(self):
        """Write the checkpoint for the lines handed out so far."""
        if self.f is None or self.is_gz or self.ino is None:
            return
        head_len = 0
        head_hash = None
        try:
            size = os.fstat(self.f.fileno()).st_size
            head_len = min(HEAD_BYTES, size)
            if head_len:
                head_hash = self._head_hash(self.f, head_len)
        except OSError:
            pass
        cur = {"v": 1, "dev": self.dev, "ino": self.ino, "offset": self.offset, "head_len": head_len if head_hash else 0,
               "head_hash": head_hash, "path": self.path, "saved_at": int(self.clock())}
        key = (cur["dev"], cur["ino"], cur["offset"], cur["head_hash"])
        if key == self._saved:
            return
        try:
            _atomic_json(self.cursor_path, cur)
            self._saved = key
        except OSError:
            pass

    def close(self):
        self.commit()
        if self.f is not None:
            try:
                self.f.close()
            except OSError:
                pass
            self.f = None


class FifoReader:
    """Lines from a FIFO (the --kernel-log test seam). No checkpoint: a FIFO has no past."""

    def __init__(self, path, name, max_line=MAX_LINE):
        self.path, self.name, self.max_line = path, name, max_line
        self.fd = None
        self.buf = b""
        self.notices = []
        self.counters = {"truncated": 0, "gaps": 0, "lines": 0}

    def drain_notices(self):
        out, self.notices = self.notices, []
        return out

    def poll(self, max_lines=2000):
        lines = []
        if self.fd is None:
            try:
                self.fd = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            except OSError:
                return lines
        while len(lines) < max_lines:
            try:
                chunk = os.read(self.fd, READ_CHUNK)
            except BlockingIOError:
                break
            except OSError:
                break
            if not chunk:
                break
            self.buf += chunk
            while True:
                i = self.buf.find(b"\n")
                if i < 0:
                    if len(self.buf) > self.max_line:
                        lines.append(_decode(self.buf[: self.max_line]))
                        self.buf = b""
                        self.counters["truncated"] += 1
                    break
                raw, self.buf = self.buf[:i], self.buf[i + 1:]
                if len(raw) > self.max_line:
                    raw = raw[: self.max_line]
                    self.counters["truncated"] += 1
                lines.append(_decode(raw))
        self.counters["lines"] += len(lines)
        return lines

    def commit(self):
        pass

    def close(self):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None


def open_line_source(path, name, cursors_dir, first_start="end", clock=time.time):
    """A Tailer for a file (also one that does not exist yet) or a FifoReader for a FIFO."""
    try:
        if stat.S_ISFIFO(os.stat(path).st_mode):
            return FifoReader(path, name)
    except OSError:
        pass
    return Tailer(path, name, cursors_dir, first_start=first_start, clock=clock)


# ---- the journal -----------------------------------------------------------------------------------
JOURNAL_FIELDS = "MESSAGE,_COMM,_UID,_EXE,_TRANSPORT,SYSLOG_IDENTIFIER,PRIORITY"
MAX_JOURNAL_LINE = 256 * 1024


class JournalFollower:
    """`journalctl -f -o json`, with the last __CURSOR as the checkpoint.

    matches are journalctl match arguments, for example ["_COMM=sshd", "_UID=0", "+", "_COMM=sudo"].
    A vacuumed cursor makes journalctl fail: the next start uses --since the last record's time minus a
    minute instead, and a gap is reported.
    """

    def __init__(self, name, matches, cursors_dir, kernel=False, command="journalctl", popen=subprocess.Popen,
                 clock=time.time):
        self.name, self.matches, self.kernel = name, list(matches), kernel
        self.cursor_path = os.path.join(cursors_dir, name + ".json")
        self.command, self.popen, self.clock = command, popen, clock
        self.proc = None
        self.buf = b""
        self.cursor = None
        self.last_ts = None          # seconds, of the last record read
        self.next_start = 0.0
        self.backoff = 5.0
        self.notices = []
        self.counters = {"bad_json": 0, "gaps": 0, "lines": 0, "restarts": 0}
        self._saved = None
        self.started_once = False
        cur = _load_json(self.cursor_path)
        if cur and isinstance(cur.get("cursor"), str) and 0 < len(cur["cursor"]) < 1024:
            self.cursor = cur["cursor"]
            if isinstance(cur.get("last_ts"), (int, float)):
                self.last_ts = cur["last_ts"]

    def drain_notices(self):
        out, self.notices = self.notices, []
        return out

    def _argv(self, mode):
        argv = [self.command, "-o", "json", "--no-pager", "--output-fields=" + JOURNAL_FIELDS, "-f"]
        if self.kernel:
            argv.append("-k")
        if mode == "cursor":
            argv.append("--after-cursor=" + self.cursor)
        elif mode == "since":
            t = max(0, int(self.last_ts - 60))
            argv.append("--since=" + time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t)) + " UTC")
        else:
            argv.extend(["-n", "0"])
        argv.extend(self.matches)
        return argv

    def _start(self, mode=None):
        if mode is None:
            mode = "cursor" if self.cursor else "since" if self.last_ts else "new"
        try:
            self.proc = self.popen(self._argv(mode), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   stdin=subprocess.DEVNULL, bufsize=0, close_fds=True)
            os.set_blocking(self.proc.stdout.fileno(), False)
        except (OSError, ValueError):
            self.proc = None
            self.next_start = self.clock() + self.backoff
            self.backoff = min(self.backoff * 2, 60.0)
            return
        self.mode = mode
        self.started_once = True
        self.started_at = self.clock()
        self.buf = b""

    def poll(self, max_lines=2000):
        """New journal records, parsed, as dicts."""
        records = []
        now = self.clock()
        if self.proc is None:
            if now < self.next_start:
                return records
            self._start()
            if self.proc is None:
                return records
        fd = self.proc.stdout.fileno()
        while len(records) < max_lines:
            try:
                chunk = os.read(fd, READ_CHUNK)
            except BlockingIOError:
                break
            except OSError:
                chunk = b""
            if not chunk:
                break
            self.buf += chunk
            while True:
                i = self.buf.find(b"\n")
                if i < 0:
                    if len(self.buf) > MAX_JOURNAL_LINE:
                        self.buf = b""
                        self.counters["bad_json"] += 1
                    break
                raw, self.buf = self.buf[:i], self.buf[i + 1:]
                rec = self._parse(raw)
                if rec is not None:
                    records.append(rec)
        self.counters["lines"] += len(records)
        if self.proc is not None and self.proc.poll() is not None and not records:
            self._exited()
        return records

    def _parse(self, raw):
        if not raw.strip():
            return None
        try:
            rec = json.loads(raw)
        except ValueError:
            self.counters["bad_json"] += 1
            return None
        if not isinstance(rec, dict):
            self.counters["bad_json"] += 1
            return None
        cur = rec.get("__CURSOR")
        if isinstance(cur, str) and len(cur) < 1024:
            self.cursor = cur
        ts = rec.get("__REALTIME_TIMESTAMP")
        try:
            self.last_ts = int(ts) / 1_000_000.0
        except (TypeError, ValueError):
            pass
        self.backoff = 5.0
        return rec

    def _exited(self):
        code = self.proc.poll()
        self.proc = None
        self.counters["restarts"] += 1
        failed_cursor = code not in (0, None) and self.mode == "cursor" and self.clock() - self.started_at < 5
        if failed_cursor:
            # a vacuumed cursor: go by time instead
            self.cursor = None
            self.counters["gaps"] += 1
            self.notices.append({"type": "gap", "name": self.name, "reason": "journal_cursor_lost"})
            self.next_start = self.clock()
            return
        self.next_start = self.clock() + self.backoff
        self.backoff = min(self.backoff * 2, 60.0)

    def commit(self):
        if not self.cursor:
            return
        cur = {"v": 1, "cursor": self.cursor, "last_ts": self.last_ts, "saved_at": int(self.clock())}
        key = (self.cursor,)
        if key == self._saved:
            return
        try:
            _atomic_json(self.cursor_path, cur)
            self._saved = key
        except OSError:
            pass

    def close(self):
        self.commit()
        proc, self.proc = self.proc, None
        if proc is not None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()
            except OSError:
                pass
            try:
                proc.stdout.close()
            except OSError:
                pass
