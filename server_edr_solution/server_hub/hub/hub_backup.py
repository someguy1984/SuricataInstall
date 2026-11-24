"""backup, restore and ca-export: the root-only file operations (PLAN.md section 7).

None of these use a socket. Each appends to pending-audit.jsonl before it starts and again with its
outcome (hub_audit.append_pending), so the hub audits and announces them even when it is stopped.
Each public function returns an exit code of PLAN section 17: 0 done, 2 failed, 3 refused with
nothing changed.

Backup file: the output of `openssl enc -aes-256-cbc -pbkdf2 -iter 600000` over a tar stream, then a
trailer line `EDRHUB-SHA256:<hex of the ciphertext>` that restore checks first. The tar starts with
MANIFEST.json (SHA-256 of every member) and holds hub.db, settings.json, secrets.json, never-ban.json,
hub-addresses.json, ca/ca.pem and ca/revoked.txt. It never holds a CA key or the server key.
"""

import errno
import hashlib
import io
import json
import os
import secrets
import shutil
import sqlite3
import ssl
import stat
import subprocess
import tarfile
import tempfile
import threading
import time

import hub_audit
import hub_common
from hub_common import clean, now_ms

FORMAT = 1
TRAILER = b"EDRHUB-SHA256:"
TRAILER_LEN = len(TRAILER) + 64 + 1
PBKDF2_ITER = "600000"
CIPHER = ("enc", "-aes-256-cbc", "-pbkdf2", "-iter", PBKDF2_ITER, "-salt")
MEMBERS = ("hub.db", "settings.json", "secrets.json", "never-ban.json", "hub-addresses.json",
           "ca/ca.pem", "ca/revoked.txt")
INSTALLER_KEYS = ("port", "enroll_port", "ui_port", "admin_ip", "clients_only")
HUB_ADDRESSES_MAX = hub_common.HUB_ADDRESSES_MAX
OPENSSL_TIMEOUT = 600
MIN_CA_PASSPHRASE = 12
FREE_SPACE_FLOOR = 32 * 1024 * 1024


class BackupError(Exception):
    """Something failed after the checks passed (exit 2)."""
    exit = 2


class Refuse(BackupError):
    """A check said no before anything changed (exit 3)."""
    exit = 3


def _pki(paths):
    import hub_pki
    return hub_pki.Pki(paths)


def _say(log, text):
    log(clean(text, 300))


# ---- small helpers ------------------------------------------------------------------------------
def _openssl(args, input_bytes=None, passphrase=None, timeout=60):
    """Run the openssl CLI. `passphrase` goes over a pipe as `-passin/-passout fd:N` (use FD in args)."""
    pass_fds = ()
    rfd = None
    args = list(args)
    if passphrase is not None:
        rfd, wfd = os.pipe()
        os.write(wfd, passphrase.encode("utf-8") + b"\n")
        os.close(wfd)
        pass_fds = (rfd,)
        args = [a.replace("FD", str(rfd)) if a == "fd:FD" else a for a in args]
    try:
        return subprocess.run(["openssl"] + args, input=input_bytes, capture_output=True, timeout=timeout,
                              pass_fds=pass_fds, check=False)
    finally:
        if rfd is not None:
            os.close(rfd)


def _passfile(paths):
    path = paths.backup_pass
    try:
        with open(path, "rb") as f:
            if not f.readline().strip():
                raise Refuse("the backup passphrase file is empty: " + path)
    except OSError:
        raise Refuse("cannot read the backup passphrase file " + path)
    return path


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _ca_sha256(pem_text):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem_text)).hexdigest()


UNSAFE_SOURCES = []     # sources this run left out because they were links or not regular files (reported by backup)


def _open_regular(path):
    """A read-only descriptor for a regular file, never following a link. Raises FileNotFoundError, or OSError
    (ELOOP) for a link, or NotADirectoryError-like OSError for anything that is not a regular file."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", path)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read_bytes(path, default=None, strict=False):
    """The contents of a regular file. A link or a special file is never read: with strict it is a refusal, otherwise
    the source counts as absent and is named in UNSAFE_SOURCES. This is root reading inside directories the edr-hub
    user owns (PLAN section 7), so a planted link must not make root copy another file into a backup."""
    try:
        fd = _open_regular(path)
    except FileNotFoundError:
        return default
    except OSError:
        if strict:
            raise Refuse("%s is a link or not a regular file" % path)
        UNSAFE_SOURCES.append(path)
        return default
    with os.fdopen(fd, "rb") as f:
        return f.read()


def _read_text(path, default=None, strict=False):
    data = _read_bytes(path, None, strict)
    return default if data is None else data.decode("utf-8")


def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _chown_like(path, ref):
    """Give a directory the owner of the stat result `ref`, without following a link. Only root can."""
    if os.geteuid() != 0 or ref is None:
        return
    try:
        os.chown(path, ref.st_uid, ref.st_gid, follow_symlinks=False)
    except OSError:
        pass


def _fchown_like(fd, ref):
    if os.geteuid() != 0 or ref is None:
        return
    try:
        os.fchown(fd, ref.st_uid, ref.st_gid)
    except OSError:
        pass


def _stat(path):
    try:
        return os.stat(path)
    except OSError:
        return None


def _audit_wrap(paths, operation, target, scheduled, body):
    """Run body() between a 'started' and an outcome line of pending-audit.jsonl; returns its exit code."""
    op_id = hub_audit.append_pending(paths, operation, target, "started", scheduled)
    outcome = "error"
    try:
        code = body()
        outcome = "ok" if code == 0 else "refused" if code == 3 else "error"
        return code
    except Refuse:
        outcome = "refused"
        raise
    finally:
        hub_audit.append_pending(paths, operation, target, outcome, scheduled, op_id=op_id)


def _guard(paths, operation, target, scheduled, log, body):
    """_audit_wrap plus the translation of Refuse and BackupError into printed messages and exit codes."""
    try:
        return _audit_wrap(paths, operation, target, scheduled, body)
    except BackupError as exc:
        _say(log, ("refused: " if exc.exit == 3 else "failed: ") + str(exc))
        return exc.exit
    except Exception as exc:                # anything unforeseen is a failure with a message, never a traceback
        _say(log, "failed: %s %s" % (type(exc).__name__, exc))
        return 2


# ---- the encrypted container --------------------------------------------------------------------
def _encrypt_tar(members, passfile, out_path):
    """members: list of (name, source) where source is bytes or a file path. Streams tar into openssl."""
    proc = subprocess.Popen(["openssl", *CIPHER, "-pass", "file:" + passfile, "-out", out_path],
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    err = b""
    try:
        with tarfile.open(fileobj=proc.stdin, mode="w|", format=tarfile.GNU_FORMAT) as tar:
            for name, source in members:
                info = tarfile.TarInfo(name)
                info.mode = 0o600
                info.mtime = int(time.time())
                if isinstance(source, bytes):
                    info.size = len(source)
                    tar.addfile(info, io.BytesIO(source))
                else:
                    info.size = os.path.getsize(source)
                    with open(source, "rb") as f:
                        tar.addfile(info, f)
    except BaseException:
        proc.kill()
        proc.wait()
        raise
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
    err = proc.stderr.read()
    proc.stderr.close()
    if proc.wait(OPENSSL_TIMEOUT) != 0:
        raise BackupError("openssl could not encrypt: " + clean(err.decode("utf-8", "replace"), 120))
    sha = _sha256_file(out_path)
    with open(out_path, "ab") as f:
        f.write(TRAILER + sha.encode("ascii") + b"\n")
        f.flush()
        os.fsync(f.fileno())


def _unpack(path, passfile, dest_dir=None):
    """Check the checksum, decrypt, verify every member against the manifest.

    With dest_dir the members are written there (mode 0600). Returns the manifest. Raises BackupError.
    """
    size = os.path.getsize(path)
    if size <= TRAILER_LEN:
        raise BackupError("not a backup file")
    with open(path, "rb") as f:
        f.seek(size - TRAILER_LEN)
        trailer = f.read()
    if not trailer.startswith(TRAILER) or not trailer.endswith(b"\n"):
        raise BackupError("not a backup file (no checksum trailer)")
    want = trailer[len(TRAILER):-1].decode("ascii", "replace")
    body_len = size - TRAILER_LEN
    h = hashlib.sha256()
    with open(path, "rb") as f:
        left = body_len
        while left:
            chunk = f.read(min(1 << 20, left))
            if not chunk:
                break
            h.update(chunk)
            left -= len(chunk)
    if h.hexdigest() != want:
        raise BackupError("checksum mismatch: the backup file is damaged")

    proc = subprocess.Popen(["openssl", *CIPHER, "-d", "-pass", "file:" + passfile],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def feed():
        try:
            with open(path, "rb") as f:
                left = body_len
                while left:
                    chunk = f.read(min(1 << 20, left))
                    if not chunk:
                        break
                    proc.stdin.write(chunk)
                    left -= len(chunk)
        except (OSError, ValueError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    feeder = threading.Thread(target=feed, daemon=True)
    feeder.start()
    manifest = None
    seen = {}
    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
            for member in tar:
                if not member.isreg():
                    raise BackupError("the backup holds something that is not a plain file")
                if member.name == "MANIFEST.json":
                    if member.size > 1 << 20:
                        raise BackupError("manifest too large")
                    manifest = json.loads(tar.extractfile(member).read().decode("utf-8"))
                    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT \
                            or not isinstance(manifest.get("files"), dict):
                        raise BackupError("unknown backup format")
                    continue
                if manifest is None or member.name not in MEMBERS or member.name in seen:
                    raise BackupError("unexpected member in the backup")
                meta = manifest["files"].get(member.name)
                if not isinstance(meta, dict) or meta.get("size") != member.size:
                    raise BackupError("a member does not match the manifest")
                digest = hashlib.sha256()
                src = tar.extractfile(member)
                out = None
                if dest_dir is not None:
                    target = os.path.join(dest_dir, member.name)
                    os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
                    out = os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
                try:
                    for chunk in iter(lambda: src.read(1 << 20), b""):
                        digest.update(chunk)
                        if out:
                            out.write(chunk)
                finally:
                    if out:
                        out.close()
                if digest.hexdigest() != meta.get("sha256"):
                    raise BackupError("a member does not match the manifest checksum")
                seen[member.name] = True
        proc.stdout.read()                     # drain, so openssl can finish
    except (tarfile.TarError, ValueError, EOFError, UnicodeDecodeError) as exc:
        proc.kill()
        proc.wait()
        raise BackupError("cannot read the backup (wrong passphrase or damaged file): %s" % type(exc).__name__)
    except BaseException:
        proc.kill()
        proc.wait()
        raise
    finally:
        feeder.join(30)
        for pipe in (proc.stdout, proc.stderr):
            try:
                pipe.close()
            except OSError:
                pass
    rc = proc.wait(OPENSSL_TIMEOUT)
    if rc != 0:
        raise BackupError("cannot decrypt the backup (wrong passphrase file?)")
    if manifest is None:
        raise BackupError("the backup has no manifest")
    for name in manifest["files"]:
        if name not in seen:
            raise BackupError("the backup is missing " + clean(name, 40))
    return manifest


# ---- backup -------------------------------------------------------------------------------------
def _free_space_needed(db_path):
    conn = sqlite3.connect("file:%s?mode=ro" % db_path.replace("?", "%3f"), uri=True, timeout=30)
    try:
        pages = conn.execute("PRAGMA page_count").fetchone()[0]
        free = conn.execute("PRAGMA freelist_count").fetchone()[0]
        page = conn.execute("PRAGMA page_size").fetchone()[0]
    finally:
        conn.close()
    return max(pages - free, 1) * page * 2 + FREE_SPACE_FLOOR


def backup(paths, out=None, scheduled=None, log=print):
    """Make one encrypted backup. Returns an exit code."""
    scheduled = hub_audit.is_scheduled_run() if scheduled is None else scheduled
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    final = os.path.abspath(out) if out else os.path.join(paths.backup_dir, "edr-hub-%s.bak" % stamp)
    return _guard(paths, "backup", final, scheduled, log, lambda: _backup(paths, final, out is None, log))


def _backup(paths, final, rotate, log):
    passfile = _passfile(paths)
    del UNSAFE_SOURCES[:]
    if not os.path.exists(paths.db):
        raise Refuse("no database at " + paths.db)
    if os.path.islink(paths.db) or not os.path.isfile(paths.db):
        raise Refuse("%s is a link or not a regular file" % paths.db)
    ca_pem = _read_text(paths.ca_cert, strict=True)
    if ca_pem is None:
        raise Refuse("no CA certificate at " + paths.ca_cert)
    outdir = os.path.dirname(final)
    os.makedirs(outdir, mode=0o700, exist_ok=True)
    if os.path.exists(final):
        if rotate:
            final = final[:-4] + "-%d.bak" % os.getpid()
        else:
            raise Refuse("the output file exists: " + final)
    need = _free_space_needed(paths.db)
    have = shutil.disk_usage(outdir).free
    if have < need:
        raise Refuse("not enough free space in %s: %d MiB free, %d MiB needed" % (outdir, have >> 20, need >> 20))

    work = tempfile.mkdtemp(prefix=".backup-", dir=outdir)
    try:
        dbcopy = os.path.join(work, "hub.db")
        src = sqlite3.connect("file:%s?mode=ro" % paths.db.replace("?", "%3f"), uri=True, timeout=30)
        try:
            src.execute("VACUUM INTO '%s'" % dbcopy.replace("'", "''"))
        finally:
            src.close()
        copy = sqlite3.connect(dbcopy)
        try:
            if copy.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise BackupError("the database copy failed quick_check; not backing up a damaged database")
            row = copy.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            schema = row[0] if row else ""
            never = [dict(zip(("cidr", "reason", "added_by", "ts"), tuple(r))) for r in copy.execute(
                "SELECT cidr, reason, added_by, ts FROM never_ban ORDER BY cidr")]
        finally:
            copy.close()
        settings = hub_common.default_settings()
        settings_text = _read_text(paths.settings)
        try:
            stored = json.loads(settings_text) if settings_text else {}
            settings.update(stored if isinstance(stored, dict) else {})
        except ValueError:
            pass
        blobs = {
            "settings.json": (settings_text or json.dumps(settings)).encode("utf-8"),
            "never-ban.json": json.dumps(never, indent=1).encode("utf-8"),
            "hub-addresses.json": json.dumps({"public_ip": settings.get("public_ip", []), "port": settings.get("port"),
                                              "enroll_port": settings.get("enroll_port")}).encode("utf-8"),
            "ca/ca.pem": ca_pem.encode("utf-8"),
            "ca/revoked.txt": (_read_text(paths.revoked, "") or "").encode("utf-8"),
        }
        secrets_text = _read_text(paths.secrets)
        if secrets_text is not None:
            blobs["secrets.json"] = secrets_text.encode("utf-8")
        files = {"hub.db": {"sha256": _sha256_file(dbcopy), "size": os.path.getsize(dbcopy)}}
        for name, data in blobs.items():
            files[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        manifest = {"format": FORMAT, "version": hub_common.VERSION, "created": now_ms(),
                    "schema_version": schema, "ca_sha256": _ca_sha256(ca_pem), "files": files}
        members = [("MANIFEST.json", json.dumps(manifest, indent=1, sort_keys=True).encode("utf-8")),
                   ("hub.db", dbcopy)] + [(n, blobs[n]) for n in MEMBERS if n in blobs]
        tmp_enc = os.path.join(work, "backup.enc")
        _encrypt_tar(members, passfile, tmp_enc)
        _unpack(tmp_enc, passfile)                  # a backup that cannot be read back is not a backup
        os.chmod(tmp_enc, 0o600)
        os.replace(tmp_enc, final)
        _fsync_dir(outdir)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    hub_common.atomic_write(paths.last_backup, str(now_ms()) + "\n", 0o644)
    if rotate:
        _rotate(outdir, int(settings.get("backup_keep", 14)))
    for path in UNSAFE_SOURCES:
        _say(log, "WARNING: %s is a link or not a regular file: it was left out of the backup" % path)
    _say(log, "backup written: %s (%.1f MiB)" % (final, os.path.getsize(final) / (1 << 20)))
    return 0


def _rotate(outdir, keep):
    names = sorted(n for n in os.listdir(outdir) if n.startswith("edr-hub-") and n.endswith(".bak"))
    for name in names[:-keep] if keep > 0 else []:
        try:
            os.unlink(os.path.join(outdir, name))
        except OSError:
            pass


# ---- ca-export ----------------------------------------------------------------------------------
def ca_export(paths, passphrase, out=None, log=print):
    """Write the CA key as encrypted PKCS#8 for off-box storage. Returns an exit code."""
    stamp = time.strftime("%Y%m%d", time.gmtime())
    final = os.path.abspath(out) if out else os.path.join(paths.backup_dir, "edr-hub-ca-%s.key.enc" % stamp)
    return _guard(paths, "ca-export", final, False, log, lambda: _ca_export(paths, passphrase, final, log))


def _ca_export(paths, passphrase, final, log):
    if not os.path.lexists(paths.ca_key):
        raise Refuse("no CA key at " + paths.ca_key)
    key_pem = _read_bytes(paths.ca_key, strict=True)
    if len(passphrase) < MIN_CA_PASSPHRASE:
        raise Refuse("the passphrase must be at least %d characters" % MIN_CA_PASSPHRASE)
    backup_pass = _read_text(paths.backup_pass)
    if backup_pass is not None and backup_pass.strip() == passphrase:
        raise Refuse("the CA passphrase must differ from the backup passphrase")
    if os.path.exists(final):
        raise Refuse("the output file exists: " + final)
    os.makedirs(os.path.dirname(final), mode=0o700, exist_ok=True)
    res = _openssl(["pkcs8", "-topk8", "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256", "-iter", PBKDF2_ITER,
                    "-passout", "fd:FD"], input_bytes=key_pem, passphrase=passphrase)
    if res.returncode != 0 or b"ENCRYPTED PRIVATE KEY" not in res.stdout:
        raise BackupError("openssl could not export the key: " + clean(res.stderr.decode("utf-8", "replace"), 120))
    fd = os.open(final, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(res.stdout)
        f.flush()
        os.fsync(f.fileno())
    ca_pem = _read_text(paths.ca_cert)
    _say(log, "CA key written, encrypted: " + final)
    if ca_pem:
        _say(log, "CA SHA-256: " + _ca_sha256(ca_pem))
    _say(log, "Keep this file and its passphrase off this box. The passphrase is not the backup passphrase.")
    return 0


# ---- restore ------------------------------------------------------------------------------------
def hub_running(paths):
    """True when something answers on ctl.sock, or (installed layout) systemd says edr-hub is active."""
    import socket
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect(paths.ctl_sock)
        return True
    except OSError:
        pass
    finally:
        s.close()
    if paths.state_dir == "/var/lib/edr-hub" and shutil.which("systemctl"):
        try:
            return subprocess.run(["systemctl", "is-active", "--quiet", "edr-hub"], timeout=10,
                                  check=False).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
    return False


def _pubkey_of_cert(pem_path):
    res = _openssl(["x509", "-in", pem_path, "-noout", "-pubkey"])
    return res.stdout.decode("ascii", "replace").strip() if res.returncode == 0 else None


def _pubkey_of_key(key_path, passphrase=None):
    args = ["pkey", "-in", key_path, "-pubout"]
    if passphrase is not None:
        args += ["-passin", "fd:FD"]
    res = _openssl(args, passphrase=passphrase)
    return res.stdout.decode("ascii", "replace").strip() if res.returncode == 0 else None


def _find_ca_key(paths, staged_ca_pem, ca_key_file, passphrase):
    """The CA key to use after the restore: (pem bytes or None for 'keep the one in place'). Raises Refuse."""
    want = _pubkey_of_cert(staged_ca_pem)
    if not want:
        raise BackupError("cannot read the CA certificate in the backup")
    if ca_key_file:
        if passphrase is None:
            raise Refuse("a passphrase is needed to read the CA key file")
        if _pubkey_of_key(ca_key_file, passphrase) != want:
            raise Refuse("the CA key file does not match the CA certificate in the backup, or the passphrase is wrong")
        res = _openssl(["pkey", "-in", ca_key_file, "-passin", "fd:FD"], passphrase=passphrase)
        if res.returncode != 0:
            raise Refuse("cannot read the CA key file")
        return res.stdout
    if os.path.islink(paths.ca_key):
        raise Refuse("%s is a link: root does not use a key it reaches through one" % paths.ca_key)
    if os.path.exists(paths.ca_key) and _pubkey_of_key(paths.ca_key) == want:
        return None
    raise Refuse("no usable CA key: pass --ca-key FILE (the ca-export file); "
                 "the key in place is missing or belongs to another CA")


def restore(paths, file, ca_key=None, ca_passphrase=None, drill=False, public_ips=(), log=print):
    """Restore a backup into the state directory. The hub must be stopped. Returns an exit code."""
    target = os.path.abspath(file)
    return _guard(paths, "restore", target, False, log,
                  lambda: _restore(paths, target, ca_key, ca_passphrase, drill, list(public_ips), log))


def _restore(paths, file, ca_key_file, ca_passphrase, drill, extra_ips, log):
    if not os.path.isfile(file):
        raise Refuse("no such backup file: " + file)
    if hub_running(paths):
        raise Refuse("edr-hub is running: stop it first (systemctl stop edr-hub)")
    passfile = _passfile(paths)
    for ip in extra_ips:
        try:
            hub_common.norm_ip(ip)
        except ValueError:
            raise Refuse("--public-ip is not an IP address: " + clean(ip, 45))
    # Root writes into directories the edr-hub user owns: nothing it will replace or enter may be a link.
    targets = [paths.state_dir, paths.ca_dir, paths.tls_dir, paths.db, paths.db + "-wal", paths.db + "-shm", paths.settings,
               paths.ca_cert, paths.revoked, paths.ca_key, paths.server_cert, paths.server_key, paths.secrets]
    for path in targets:
        if os.path.islink(path):
            raise Refuse("%s is a link: refusing to write through it" % path)
    os.makedirs(paths.state_dir, exist_ok=True)
    state_stat = _stat(paths.state_dir)
    stage = tempfile.mkdtemp(prefix=".restore-", dir=paths.state_dir)
    try:
        manifest = _unpack(file, passfile, stage)
        staged_db = os.path.join(stage, "hub.db")
        check = sqlite3.connect(staged_db)
        try:
            if check.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise BackupError("the database in the backup failed quick_check")
        finally:
            check.close()
        staged_ca = os.path.join(stage, "ca", "ca.pem")
        if _ca_sha256(_read_text(staged_ca)) != manifest.get("ca_sha256"):
            raise BackupError("the CA certificate does not match the manifest")
        new_key = _find_ca_key(paths, staged_ca, ca_key_file, ca_passphrase)

        restored = json.loads(_read_text(os.path.join(stage, "settings.json")) or "{}")
        if not isinstance(restored, dict):
            raise BackupError("settings.json in the backup is not an object")
        fresh = hub_common.load_settings(paths)
        ips = []
        for ip in list(restored.get("public_ip") or []) + extra_ips:
            ip = hub_common.norm_ip(ip)
            if ip not in ips:
                ips.append(ip)
        if not ips:
            raise Refuse("no hub address is known: pass --public-ip IP")
        if len(ips) > HUB_ADDRESSES_MAX:
            raise Refuse("more than %d hub addresses" % HUB_ADDRESSES_MAX)
        merged = dict(restored)
        merged["public_ip"] = ips
        for key in INSTALLER_KEYS:                   # the firewall of this box was set by its own install
            if key in fresh and os.path.exists(paths.settings):
                merged[key] = fresh[key]
        if drill:
            merged["secrets_set"] = {}               # a drill box must not look as if it had channels
        _prepare_db(staged_db)
        return _swap_in(paths, stage, manifest, merged, new_key, drill, ips, state_stat, log)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _prepare_db(staged_db):
    """Mark every token invalid, drop login codes and queued alerts, and leave a marker that this hub was restored."""
    conn = sqlite3.connect(staged_db)
    try:
        now = now_ms()
        conn.execute("UPDATE tokens SET revoked_at=? WHERE revoked_at IS NULL", (now,))
        conn.execute("UPDATE tokens SET issued_reply=NULL")
        conn.execute("DELETE FROM login_codes")
        # Alerts that were waiting on the old box must not be sent again from the new one.
        conn.execute("UPDATE outbox SET state='dead', last_error='restored' WHERE state IN ('pending','sending','failed')")
        conn.execute("INSERT INTO meta (key, value) VALUES ('restored_at', ?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(now),))
        # The read offset of pending-audit.jsonl in the backup belongs to the file of the box the backup came from. On
        # this box it can point into the middle of a line or past the restore's own lines, so they would never be read.
        # Start at 0: pending_audit_seen (restored with it) stops lines that were already taken from being taken twice.
        conn.execute("DELETE FROM meta WHERE key='pending_audit_offset'")
        conn.commit()
    finally:
        conn.close()


def _merge_revoked(backup_text, current_text):
    lines = [x for x in backup_text.splitlines() if x.strip()]
    seen = set(lines)
    for x in (current_text or "").splitlines():
        if x.strip() and x not in seen:
            lines.append(x)
            seen.add(x)
    return "".join(x + "\n" for x in lines)


def _swap_in(paths, stage, manifest, merged, new_key, drill, ips, state_stat, log):
    aside = None        # made with a random name when the first file is moved aside: a planted name or link is never used
    ca_stat = _stat(paths.ca_dir) or state_stat
    moved = []          # (original, aside copy)
    installed = []      # paths created by this restore

    def put_aside(path, name):
        nonlocal aside
        if os.path.lexists(path):
            if aside is None:
                aside = tempfile.mkdtemp(prefix="restore-aside-", dir=paths.state_dir)
            dest = os.path.join(aside, name)
            os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
            os.replace(path, dest)
            moved.append((path, dest))

    def install(src_bytes_or_path, dest, mode, ref):
        """Write dest through a new file with a random name (O_EXCL, O_NOFOLLOW), set mode and owner on the
        descriptor, then rename it over dest. Nothing here follows a link an attacker left behind."""
        if os.path.islink(dest):
            raise BackupError("%s is a link: refusing to write through it" % dest)
        tmp = "%s.restore-%s" % (dest, secrets.token_hex(6))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                if isinstance(src_bytes_or_path, bytes):
                    f.write(src_bytes_or_path)
                else:
                    src_fd = _open_regular(src_bytes_or_path)
                    with os.fdopen(src_fd, "rb") as src:
                        shutil.copyfileobj(src, f, 1 << 20)
                f.flush()
                os.fchmod(f.fileno(), mode)
                _fchown_like(f.fileno(), ref)
                os.fsync(f.fileno())
            os.replace(tmp, dest)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        installed.append(dest)

    try:
        for suffix in ("", "-wal", "-shm"):
            put_aside(paths.db + suffix, "hub.db" + suffix)
        put_aside(paths.settings, "settings.json")
        put_aside(paths.ca_cert, "ca/ca.pem")
        put_aside(paths.revoked, "ca/revoked.txt")
        if new_key is not None:
            put_aside(paths.ca_key, "ca/ca.key")
        for name in ("server.pem", "server.key"):
            put_aside(os.path.join(paths.tls_dir, name), "tls/" + name)
        os.makedirs(paths.ca_dir, mode=0o700, exist_ok=True)
        os.makedirs(paths.tls_dir, mode=0o750, exist_ok=True)
        if _stat(paths.tls_dir) is not None and state_stat is not None and os.geteuid() == 0 and not os.listdir(paths.tls_dir):
            _chown_like(paths.tls_dir, ca_stat)

        install(os.path.join(stage, "hub.db"), paths.db, 0o640, state_stat)
        install((json.dumps(merged, indent=1, sort_keys=True) + "\n").encode("utf-8"), paths.settings, 0o640, state_stat)
        install(_read_text(os.path.join(stage, "ca", "ca.pem")).encode("utf-8"), paths.ca_cert, 0o644, ca_stat)
        old_revoked = _read_text(moved_path(moved, paths.revoked) or paths.revoked, "")
        install(_merge_revoked(_read_text(os.path.join(stage, "ca", "revoked.txt"), "") or "", old_revoked).encode("utf-8"),
                paths.revoked, 0o640, ca_stat)
        if new_key is not None:
            install(new_key, paths.ca_key, 0o600, ca_stat)
        secrets_path = os.path.join(stage, "secrets.json")
        if not drill and os.path.exists(secrets_path):
            os.makedirs(paths.etc_dir, mode=0o750, exist_ok=True)
            put_aside(paths.secrets, "etc-secrets.json")
            install(secrets_path, paths.secrets, 0o600, None)

        # The server certificate is reissued from the restored CA, never restored (PLAN section 7, step 3).
        pki = _pki(paths)
        pki.issue_server_cert(ips)
    except BaseException:
        for path in reversed(installed):
            try:
                os.unlink(path)
            except OSError:
                pass
        for original, copy in reversed(moved):
            try:
                os.replace(copy, original)
            except OSError:
                pass
        raise

    ca_sha = manifest.get("ca_sha256", "")
    _say(log, "restored from backup made %s (hub version %s)" % (
        hub_common.ms_to_rfc3339(int(manifest.get("created", 0))), clean(str(manifest.get("version", "?")), 20)))
    _say(log, "CA SHA-256 (unchanged, existing pins match): " + ca_sha)
    _say(log, "server certificate reissued for: " + ", ".join(ips))
    if drill:
        _say(log, "drill: secrets.json was not restored and no alert channel is switched on")
    if aside is not None:
        _say(log, "the replaced files are kept in " + aside)
    _say(log, "all tokens were marked invalid: make new ones with `edr-hub token create --for HOST`")
    _print_serials(paths, log)
    _say(log, "Revocations made after this backup exist only in the alerts and the audit of the lost box:")
    _say(log, "re-revoke those hosts by hand (`edr-hub host HOST revoke`). Hosts enrolled after the backup")
    _say(log, "appear as orphan when they connect: check each, then `edr-hub host UUID adopt`.")
    _say(log, "Start edr-hub (and edr-hub-out) when ready.")
    return 0


def moved_path(moved, original):
    for orig, copy in moved:
        if orig == original:
            return copy
    return None


def _print_serials(paths, log):
    revoked = [ln.split()[0] for ln in (_read_text(paths.revoked, "") or "").splitlines()
               if ln.strip() and not ln.lstrip().startswith("#")]
    _say(log, "serials in revoked.txt (%d): %s" % (len(revoked), ", ".join(revoked[:50]) + (" ..." if len(revoked) > 50 else "")))
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % paths.db.replace("?", "%3f"), uri=True)
        try:
            rows = conn.execute("SELECT name, state, cert_serial, pending_cert_serial FROM hosts ORDER BY name").fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        rows = []
    _say(log, "hosts in the restored database (%d):" % len(rows))
    for name, state, serial, pending in rows[:200]:
        _say(log, "  %s  %s  serial %s%s" % (clean(name, 63), state, serial or "-", " pending " + pending if pending else ""))
