"""Event ids: <epoch>:<seq> with no host part (client PLAN section 4.5, Spool, and Appendix B).

epoch is a random 32-bit value (8 hex digits in the id) that changes after any start without a
clean-shutdown marker; seq counts inside it, from 1. The counter is saved in blocks of 1000, and a clean
shutdown saves the exact value, so a restart continues the same epoch. After a crash there is no marker,
so a new epoch starts and no id is ever used twice. A gap inside one epoch is loss, which is why only
events that are really forwarded take an id.
"""
import json
import os
import secrets
import threading

BLOCK = 1000

_lock = threading.Lock()
_state = {"epoch": 0, "seq": 0, "block_end": 0, "paths": None, "ready": False}


def _write_json(path, obj):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _read_json(path):
    try:
        with open(path, "rb") as f:
            data = f.read(4096)
        obj = json.loads(data)
        return obj if isinstance(obj, dict) else None
    except (OSError, ValueError):
        return None


def _new_epoch():
    while True:
        value = secrets.randbits(32)
        if value:
            return value


def init(paths):
    """Start the counter for this run. Returns True when the previous run ended cleanly (same epoch)."""
    with _lock:
        _state["paths"] = paths
        os.makedirs(paths.state_dir, mode=0o700, exist_ok=True)
        marker = _read_json(paths.clean_marker)
        clean = False
        epoch = seq = 0
        if marker and isinstance(marker.get("epoch"), int) and isinstance(marker.get("seq"), int) \
                and 0 < marker["epoch"] < 2 ** 32 and marker["seq"] >= 0:
            epoch, seq, clean = marker["epoch"], marker["seq"], True
        try:
            os.unlink(paths.clean_marker)       # consumed: a crash from here on has no marker
        except OSError:
            pass
        if not clean:
            epoch, seq = _new_epoch(), 0
        _state.update(epoch=epoch, seq=seq, block_end=0, ready=True)
        _reserve_block()
        return clean


def _reserve_block():
    paths = _state["paths"]
    _state["block_end"] = _state["seq"] + BLOCK
    try:
        _write_json(paths.ids_json, {"epoch": _state["epoch"], "reserved_to": _state["block_end"]})
    except OSError:
        pass        # an unwritable state directory must not stop events; the epoch changes after a crash anyway


def next_id():
    """(epoch, seq, id string) for the next forwarded event."""
    with _lock:
        if not _state["ready"]:
            _state.update(epoch=_new_epoch(), seq=0, block_end=BLOCK, ready=True)
        _state["seq"] += 1
        if _state["paths"] is not None and _state["seq"] >= _state["block_end"]:
            _reserve_block()
        epoch, seq = _state["epoch"], _state["seq"]
    return epoch, seq, "%08x:%d" % (epoch, seq)


def current():
    """(epoch, seq): the highest id handed out so far."""
    with _lock:
        return _state["epoch"], _state["seq"]


def stamp(ev):
    """Give an event its id, epoch and seq."""
    epoch, seq, ident = next_id()
    ev["id"], ev["epoch"], ev["seq"] = ident, epoch, seq
    return ev


def mark_clean_shutdown():
    """Record the exact counter, so the next start continues this epoch."""
    with _lock:
        paths = _state["paths"]
        if paths is None or not _state["ready"]:
            return False
        try:
            _write_json(paths.clean_marker, {"epoch": _state["epoch"], "seq": _state["seq"]})
            return True
        except OSError:
            return False
