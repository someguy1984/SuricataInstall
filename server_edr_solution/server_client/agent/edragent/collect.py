"""`edr-agent collect [--out FILE]`: a triage tar for an incident (client PLAN section 4.7). Root, local, raw.

Raw means it is sensitive (client PLAN section 18). The file is made with umask 077 and O_EXCL, never inside a
web root, no symlink is followed, and it stops at 50 MB. Contents: 24 hours of Tetragon events, the tails of
the nginx logs, `ss -tanp`, the process tree, the deleted-executable list from the inventory, crontabs,
authorized_keys hashes (never the keys), loaded modules, web root files changed in the last 24 hours (names,
sizes and times only), and `dpkg -V` of nginx and php.
"""
import glob
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import time

from . import config as cfgmod
from . import event as evmod

CAP_BYTES = 50 * 1024 * 1024
MEMBER_CAP = 10 * 1024 * 1024
TAIL_BYTES = 512 * 1024
WALK_FILES = 20000
WALK_SECONDS = 20


def _read_tail(path, limit):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        start = max(0, st.st_size - limit)
        return os.pread(fd, limit, start)
    except OSError:
        return None
    finally:
        os.close(fd)


def _read_all(path, limit=MEMBER_CAP):
    return _read_tail(path, limit)


def _command(runner, argv, timeout=15):
    try:
        p = runner(argv, capture_output=True, timeout=timeout, check=False,
                   env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        return (p.stdout or b"")[:MEMBER_CAP] + (b"\n[stderr]\n" + p.stderr[:4096] if p.stderr else b"")
    except (OSError, subprocess.SubprocessError) as e:
        return ("could not run %s: %s\n" % (argv[0], e)).encode()


def _tetragon_24h(paths, now):
    cutoff = evmod.rfc3339((now - 86400) * 1000)[:19]
    out = []
    for p in (paths.tetragon_log + ".1", paths.tetragon_log):
        data = _read_tail(p, 20 * 1024 * 1024)
        if not data:
            continue
        for line in data.decode("utf-8", "replace").splitlines():
            m = re.search(r'"time":\s*"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)', line)
            if m and m.group(1) >= cutoff:
                out.append(line)
    return ("\n".join(out) + "\n").encode()[:MEMBER_CAP]


def _crontabs(paths):
    parts = []
    for pattern in ("/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/crontabs/*", "/var/spool/cron/*"):
        for p in sorted(glob.glob(paths._p(pattern)))[:200]:
            data = _read_all(p, 256 * 1024)
            if data is not None:
                parts.append("### %s\n%s\n" % (p, data.decode("utf-8", "replace")))
    return "".join(parts).encode()


def _key_hashes(paths):
    lines = []
    homes = [paths._p("/root")] + sorted(glob.glob(paths._p("/home/*")))[:500]
    for home in homes:
        p = os.path.join(home, ".ssh", "authorized_keys")
        data = _read_all(p, 1024 * 1024)
        if data is None:
            continue
        lines.append("%s sha256=%s" % (p, hashlib.sha256(data).hexdigest()))
        for raw in data.splitlines()[:1000]:
            if raw.strip() and not raw.lstrip().startswith(b"#"):
                lines.append("  line sha256=%s" % hashlib.sha256(raw.strip()).hexdigest())
    return ("\n".join(lines) + "\n").encode()


def _recent_files(roots, now):
    out, count, deadline = [], 0, time.monotonic() + WALK_SECONDS
    cutoff = now - 86400
    for root in roots:
        for dirpath, dirs, files in os.walk(root, followlinks=False):
            if time.monotonic() > deadline or count >= WALK_FILES:
                out.append("[walk stopped at its limit]")
                return ("\n".join(out) + "\n").encode()
            for name in files:
                count += 1
                p = os.path.join(dirpath, name)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if st.st_mtime >= cutoff and stat.S_ISREG(st.st_mode):
                    out.append("%s %d %s" % (evmod.rfc3339(st.st_mtime * 1000), st.st_size, p))
    return ("\n".join(out) + "\n").encode()


def build_members(paths, cfg, runner=subprocess.run, now=None):
    """[(name, bytes)] for the tar, in the order they should be written."""
    now = time.time() if now is None else now
    members = [("tetragon-24h.jsonl", _tetragon_24h(paths, now))]
    for label, p in (("nginx-error.log.tail", paths.nginx_error_log), ("nginx-access.log.tail", paths.nginx_access_log)):
        data = _read_tail(p, TAIL_BYTES)
        if data is not None:
            members.append((label, data))
    members.append(("ss-tanp.txt", _command(runner, ["ss", "-tanp"])))
    members.append(("process-tree.txt", _command(runner, ["ps", "-eo", "pid,ppid,uid,user,etime,args", "--forest"])))
    inv = None
    try:
        inv = json.loads(_read_all(paths.inventory_json, 1024 * 1024) or b"null")
    except ValueError:
        inv = None
    checks = inv.get("checks") if isinstance(inv, dict) else None
    members.append(("deleted-exe.json", json.dumps((checks or {}).get("deleted_exe", "unknown"), indent=1).encode()))
    members.append(("crontabs.txt", _crontabs(paths)))
    members.append(("authorized_keys-hashes.txt", _key_hashes(paths)))
    mods = _read_all(paths.proc("modules"), 1024 * 1024)
    members.append(("modules.txt", mods if mods is not None else b"unreadable\n"))
    members.append(("webroot-changed-24h.txt", _recent_files(cfg.getlist("sites", "web_roots"), now)))
    members.append(("dpkg-verify.txt", _command(runner, ["dpkg", "-V", "nginx", "nginx-*", "php*"], timeout=60)))
    return members


def _inside_webroot(path, roots):
    real = os.path.realpath(path)
    for root in roots:
        r = os.path.realpath(root)
        if real == r or real.startswith(r.rstrip("/") + "/"):
            return True
    return False


def run_collect(paths, out_path=None, out=print, runner=subprocess.run, now=None):
    """The `collect` subcommand. Exit code: 0 written, 3 refused, 2 failed."""
    if not paths.dev and os.geteuid() != 0:
        out("refused: collect must run as root")
        return 3
    cfg = cfgmod.load(paths)
    now = time.time() if now is None else now
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
    if out_path is None:
        out_path = os.path.join(paths._p("/root"), "edr-collect-%s.tar" % stamp)
    directory = os.path.dirname(os.path.abspath(out_path))
    if not os.path.isdir(directory):
        out("refused: the directory %s does not exist" % directory)
        return 3
    if _inside_webroot(directory, cfg.getlist("sites", "web_roots")):
        out("refused: the bundle must not be written inside a web root")
        return 3
    old_umask = os.umask(0o077)
    try:
        fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as e:
        out("refused: cannot create %s (%s)" % (out_path, e.strerror))
        return 3
    finally:
        os.umask(old_umask)
    used, skipped = 0, []
    try:
        with os.fdopen(fd, "wb") as f, tarfile.open(fileobj=f, mode="w", format=tarfile.PAX_FORMAT) as tar:
            members = build_members(paths, cfg, runner, now)
            for name, data in members:
                data = data[:MEMBER_CAP]
                if used + len(data) > CAP_BYTES:
                    skipped.append(name)
                    continue
                info = tarfile.TarInfo(name="edr-collect-%s/%s" % (stamp, name))
                info.size, info.mtime, info.mode = len(data), int(now), 0o600
                tar.addfile(info, io.BytesIO(data))
                used += len(data)
            note = ("edr-agent collect, %s UTC\nThis bundle is raw host data: handle it as sensitive.\n"
                    % time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now)))
            if skipped:
                note += "left out because of the 50 MB cap: %s\n" % ", ".join(skipped)
            info = tarfile.TarInfo(name="edr-collect-%s/README.txt" % stamp)
            info.size, info.mtime, info.mode = len(note), int(now), 0o600
            tar.addfile(info, io.BytesIO(note.encode()))
    except (OSError, tarfile.TarError) as e:
        out("failed: %s" % e)
        try:
            os.unlink(out_path)
        except OSError:
            pass
        return 2
    out("wrote %s (%d bytes of data). It is raw: treat it as sensitive." % (out_path, used))
    return 0
