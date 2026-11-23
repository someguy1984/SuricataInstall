"""The hub's own CA, its server certificate and client signing (PLAN.md section 2, CA and certificates).

All certificate work goes through the openssl CLI with explicit extension files
(pki/strict/ca.ext, srv.ext, cli.ext), so OpenSSL 3.0 and 3.5 give the same result. Every result is
checked with `openssl verify -x509_strict` before it is used. Standard library only.

revoked.txt (ca/revoked.txt) is the append-only list of certificates that must never be accepted
again, whatever an older database says. One line per certificate:
    <serial hex> <der sha256> <host uuid> <reason> <epoch ms>
reason is one of revoked, retired, moved, superseded.
"""

import datetime
import ipaddress
import os
import re
import secrets
import shutil
import ssl
import subprocess
import tempfile
import threading

import hub_common

OPENSSL = "openssl"
RUN_TIMEOUT_S = 20
SIGNING_SLOTS = 2
CA_DAYS = 3650
SERVER_DAYS = 397
CLIENT_DAYS = 365
BACKDATE_DAYS = 1                   # every certificate starts one day in the past (clock skew on fresh droplets)
SERVER_RENEW_DAYS = 30

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
REVOKE_REASONS = ("revoked", "retired", "moved", "superseded")
_PEM_BLOCK = re.compile(
    r"^-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----\r?\n[A-Za-z0-9+/=\r\n]+-----END (?:NEW )?CERTIFICATE REQUEST-----\r?\n?$")

_not_before_support = {}


class PkiError(ValueError):
    """A certificate step failed. The message is fixed text, never request text."""


def _env():
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}


def _run(args, stdin=None, timeout=RUN_TIMEOUT_S):
    """Run openssl with an argument list. Returns (returncode, stdout bytes, stderr bytes)."""
    try:
        done = subprocess.run([OPENSSL] + list(args), input=stdin, capture_output=True, timeout=timeout,
                              env=_env(), check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise PkiError("openssl could not be run") from e
    return done.returncode, done.stdout, done.stderr


def _must(args, stdin=None, what="openssl step"):
    code, out, _err = _run(args, stdin)
    if code != 0:
        raise PkiError("%s failed" % what)
    return out


def _has_not_before():
    """openssl x509 has -not_before from 3.4; older releases sign through `openssl ca -startdate`."""
    if OPENSSL not in _not_before_support:
        code, out, err = _run(["x509", "-help"])
        _not_before_support[OPENSSL] = b"-not_before" in (out + err)
    return _not_before_support[OPENSSL]


def _stamp(dt):
    return dt.strftime("%Y%m%d%H%M%SZ")


def _random_serial():
    """15 random bytes with the top bit cleared (never negative, never zero)."""
    while True:
        raw = bytearray(secrets.token_bytes(15))
        raw[0] &= 0x7F
        if any(raw):
            return bytes(raw).hex()


def _norm_serial(text):
    text = text.strip().lower().lstrip("0")
    return text or "0"


def _read_ext(path, extra_lines=()):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if not text.endswith("\n"):
        text += "\n"
    return text + "".join(line + "\n" for line in extra_lines)


def der_sha256(pem_text):
    import hashlib
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem_text)).hexdigest()


def _write_new(path, data, mode):
    """Create a file that must not exist, with the given mode from the first byte."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
        f.flush()
        os.fsync(f.fileno())


def _gen_key(curve):
    return _must(["ecparam", "-name", curve, "-genkey", "-noout"], what="key generation")


def _pub_from_key(key_pem):
    return _must(["pkey", "-pubout"], stdin=key_pem, what="public key extraction")


def _sign(tmp, *, pub_pem, csr_pem, subject, ext_path, extra_ext, days, ca_pem_path, ca_key_path, sha, serial_hex,
          self_key_path=None):
    """Sign one certificate; return its PEM text. self_key_path makes a self-signed certificate (the CA).

    Uses `x509 -new -force_pubkey`, never `x509 -req` (that copies the CSR subject and extensions).
    """
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    not_before = now - datetime.timedelta(days=BACKDATE_DAYS)
    not_after = now + datetime.timedelta(days=days)
    ext_file = os.path.join(tmp, "ext.cnf")
    with open(ext_file, "w", encoding="utf-8") as f:
        f.write(_read_ext(ext_path, extra_ext))
    out_path = os.path.join(tmp, "out.pem")
    if self_key_path is not None:
        args = ["x509", "-new", "-key", self_key_path, "-subj", subject, "-sha384", "-extfile", ext_file,
                "-set_serial", "0x" + serial_hex, "-out", out_path]
    else:
        pub_path = os.path.join(tmp, "pub.pem")
        with open(pub_path, "wb") as f:
            f.write(pub_pem)
        args = ["x509", "-new", "-force_pubkey", pub_path, "-subj", subject, "-CA", ca_pem_path, "-CAkey", ca_key_path,
                "-sha384", "-extfile", ext_file, "-set_serial", "0x" + serial_hex, "-out", out_path]
    if _has_not_before():
        args += ["-not_before", _stamp(not_before), "-not_after", _stamp(not_after)]
        _must(args, what="signing")
    else:
        if self_key_path is not None:
            raise PkiError("this openssl cannot back-date a self-signed certificate")
        _sign_with_ca_command(tmp, csr_pem, subject, ext_file, ca_pem_path, ca_key_path, serial_hex,
                              not_before, not_after, out_path)
    with open(out_path, encoding="utf-8") as f:
        return f.read()


def _sign_with_ca_command(tmp, csr_pem, subject, ext_file, ca_pem_path, ca_key_path, serial_hex, not_before,
                          not_after, out_path):
    """The fallback for openssl 3.0: `openssl ca -startdate` with a throwaway config and database."""
    db_dir = os.path.join(tmp, "cadb")
    os.mkdir(db_dir, 0o700)
    open(os.path.join(db_dir, "index.txt"), "w").close()
    with open(os.path.join(db_dir, "serial"), "w") as f:
        f.write(serial_hex.upper() + "\n")
    cnf = os.path.join(tmp, "ca.cnf")
    with open(cnf, "w", encoding="utf-8") as f:
        f.write("[ca]\ndefault_ca = c\n[c]\ndatabase = %s/index.txt\nnew_certs_dir = %s\nserial = %s/serial\n"
                "default_md = sha384\npolicy = p\nunique_subject = no\ncopy_extensions = none\n"
                "[p]\ncommonName = supplied\n" % (db_dir, db_dir, db_dir))
    csr_path = os.path.join(tmp, "req.csr")
    with open(csr_path, "wb") as f:
        f.write(csr_pem)
    _must(["ca", "-batch", "-notext", "-config", cnf, "-cert", ca_pem_path, "-keyfile", ca_key_path, "-in", csr_path,
           "-out", out_path, "-subj", subject, "-md", "sha384", "-startdate", _stamp(not_before),
           "-enddate", _stamp(not_after), "-extfile", ext_file], what="signing")


def _verify(tmp, ca_pem_path, pem_text, purpose):
    path = os.path.join(tmp, "check.pem")
    with open(path, "w", encoding="utf-8") as f:
        f.write(pem_text)
    args = ["verify", "-x509_strict", "-no-CApath", "-no-CAstore", "-CAfile", ca_pem_path]
    if purpose:
        args += ["-purpose", purpose]
    args.append(path)
    code, _out, _err = _run(args)
    if code != 0:
        raise PkiError("the new certificate does not verify")


def init_ca(paths):
    """Create ca/ca.key and ca/ca.pem when they are absent (EC P-384, SHA-384, 10 years)."""
    os.makedirs(paths.ca_dir, mode=0o700, exist_ok=True)
    os.chmod(paths.ca_dir, 0o700)
    if os.path.exists(paths.ca_key) and os.path.exists(paths.ca_cert):
        return
    if os.path.exists(paths.ca_key) != os.path.exists(paths.ca_cert):
        raise PkiError("ca directory holds only one of ca.key and ca.pem; refusing to replace it")
    ext = paths.find_data("pki", "strict", "ca.ext")
    key = _gen_key("secp384r1")
    with tempfile.TemporaryDirectory(prefix="edr-ca-") as tmp:
        os.chmod(tmp, 0o700)
        key_path = os.path.join(tmp, "ca.key")
        _write_new(key_path, key, 0o600)
        pem = _sign(tmp, pub_pem=None, csr_pem=None, subject="/CN=edr-hub-ca", ext_path=ext, extra_ext=(),
                    days=CA_DAYS, ca_pem_path=None, ca_key_path=None, sha="sha384", serial_hex=_random_serial(),
                    self_key_path=key_path)
        ca_path = os.path.join(tmp, "ca.pem")
        with open(ca_path, "w", encoding="utf-8") as f:
            f.write(pem)
        _verify(tmp, ca_path, pem, None)
        # Key first, certificate second: a half-made CA is caught by the check above on the next start.
        shutil.copyfile(key_path, paths.ca_key + ".new")
        os.chmod(paths.ca_key + ".new", 0o600)
        os.replace(paths.ca_key + ".new", paths.ca_key)
        hub_common.atomic_write(paths.ca_cert, pem, 0o644)


class Pki:
    """Holds what is needed to sign and to answer GET /v1/ca from memory."""

    def __init__(self, paths):
        self.paths = paths
        self._sign_sem = threading.BoundedSemaphore(SIGNING_SLOTS)
        self._lock = threading.Lock()
        self._ca_pem = None
        self._ca_sha = None
        self._revoked = {}
        self.load_revoked()

    # ---- the CA certificate ------------------------------------------------------------------
    def ca_pem(self):
        if self._ca_pem is None:
            with open(self.paths.ca_cert, encoding="utf-8") as f:
                pem = f.read()
            self._ca_sha = der_sha256(pem)
            self._ca_pem = pem
        return self._ca_pem

    def ca_sha256(self):
        self.ca_pem()
        return self._ca_sha

    # ---- revoked.txt -------------------------------------------------------------------------
    def load_revoked(self):
        """Read ca/revoked.txt first thing at start. A missing file is an empty list."""
        table = {}
        try:
            with open(self.paths.revoked, encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and re.fullmatch(r"[0-9a-f]{64}", parts[1]):
                        table[parts[1]] = (parts[0], parts[2], parts[3])
        except FileNotFoundError:
            pass
        with self._lock:
            self._revoked = table

    def revoked_add(self, serial, der_hash, uuid, reason, now_ms=None):
        """Append one line, synced to disk, and remember it. Called inside the writer transaction."""
        if reason not in REVOKE_REASONS:
            raise ValueError("unknown reason")
        if not re.fullmatch(r"[0-9a-f]{64}", der_hash or ""):
            return False
        with self._lock:
            if der_hash in self._revoked:
                return False              # the first reason stays
        line = "%s %s %s %s %d\n" % (_norm_serial(str(serial or "0")), der_hash, uuid, reason,
                                      now_ms if now_ms is not None else hub_common.now_ms())
        os.makedirs(self.paths.ca_dir, mode=0o700, exist_ok=True)
        fd = os.open(self.paths.revoked, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        with self._lock:
            self._revoked[der_hash] = (_norm_serial(str(serial or "0")), uuid, reason)
        return True

    def revoked_lookup(self, der_hash):
        """None, or (serial, uuid, reason) when this certificate is in revoked.txt."""
        with self._lock:
            return self._revoked.get(der_hash)

    def revoked_count(self):
        with self._lock:
            return len(self._revoked)

    # ---- certificates ------------------------------------------------------------------------
    def cert_info(self, pem_or_path):
        """{"serial", "der_sha256", "not_before", "not_after" (ms), "subject_cn", "sans"} of one certificate."""
        if "-----BEGIN" in pem_or_path:
            pem = pem_or_path
        else:
            with open(pem_or_path, encoding="utf-8") as f:
                pem = f.read()
        out = _must(["x509", "-noout", "-serial", "-startdate", "-enddate", "-subject", "-nameopt", "RFC2253",
                     "-dateopt", "iso_8601", "-ext", "subjectAltName"], stdin=pem.encode(), what="certificate read")
        text = out.decode("utf-8", "replace")
        info = {"der_sha256": der_sha256(pem), "sans": []}
        for line in text.splitlines():
            if line.startswith("serial="):
                info["serial"] = _norm_serial(line.split("=", 1)[1])
            elif line.startswith("notBefore="):
                info["not_before"] = _iso_to_ms(line.split("=", 1)[1])
            elif line.startswith("notAfter="):
                info["not_after"] = _iso_to_ms(line.split("=", 1)[1])
            elif line.startswith("subject="):
                m = re.search(r"(?:^|,)CN=([^,]+)", line.split("=", 1)[1])
                info["subject_cn"] = m.group(1) if m else ""
        for m in re.finditer(r"IP Address:([0-9A-Fa-f:.]+)", text):
            try:
                info["sans"].append(str(ipaddress.ip_address(m.group(1))))
            except ValueError:
                pass
        for key in ("serial", "not_before", "not_after", "subject_cn"):
            if key not in info:
                raise PkiError("certificate could not be read")
        return info

    def sign_client(self, csr_pem, uuid):
        """Sign a client certificate for `uuid` from a CSR. Only the public key is taken from the CSR.

        Raises ValueError (PkiError) on a bad CSR or a failed step. Steps: size and shape, proof of key
        possession, EC prime256v1 only, sign with the fixed profile, verify, record serial and DER hash.
        """
        if not isinstance(csr_pem, str) or not isinstance(uuid, str) or not UUID_RE.match(uuid):
            raise PkiError("bad request")
        raw = csr_pem.encode("utf-8", "replace")
        if len(raw) > hub_common.CSR_MAX_BYTES or csr_pem.count("-----BEGIN") != 1 or not _PEM_BLOCK.match(csr_pem):
            raise PkiError("the CSR must be one PEM block of at most 4 KiB")
        with self._sign_sem:
            code, _out, _err = _run(["req", "-verify", "-noout"], stdin=raw)
            if code != 0:
                raise PkiError("the CSR is not signed by its own key")
            pub = _must(["req", "-noout", "-pubkey"], stdin=raw, what="public key extraction")
            _check_p256(pub)
            ext = self.paths.find_data("pki", "strict", "cli.ext")
            with tempfile.TemporaryDirectory(prefix="edr-sign-") as tmp:
                os.chmod(tmp, 0o700)
                pem = _sign(tmp, pub_pem=pub, csr_pem=raw, subject="/CN=" + uuid, ext_path=ext, extra_ext=(),
                            days=CLIENT_DAYS, ca_pem_path=self.paths.ca_cert, ca_key_path=self.paths.ca_key,
                            sha="sha384", serial_hex=_random_serial())
                _verify(tmp, self.paths.ca_cert, pem, "sslclient")
        info = self.cert_info(pem)
        if info["subject_cn"] != uuid:
            raise PkiError("the new certificate has the wrong subject")
        return {"pem": pem, "serial": info["serial"], "der_sha256": info["der_sha256"], "not_after": info["not_after"]}

    def issue_server_cert(self, ips):
        """Write tls/server.pem and tls/server.key: EC P-256, IP SANs for every hub address, 397 days."""
        addrs = []
        for ip in ips:
            norm = hub_common.norm_ip(str(ip))
            if norm not in addrs:
                addrs.append(norm)
        if not addrs:
            raise PkiError("a server certificate needs at least one IP address")
        os.makedirs(self.paths.tls_dir, mode=0o700, exist_ok=True)
        os.chmod(self.paths.tls_dir, 0o700)
        key = _gen_key("prime256v1")
        pub = _pub_from_key(key)
        ext = self.paths.find_data("pki", "strict", "srv.ext")
        san = "subjectAltName = " + ",".join("IP:" + a for a in addrs)
        with tempfile.TemporaryDirectory(prefix="edr-srv-") as tmp:
            os.chmod(tmp, 0o700)
            csr = _server_csr(tmp, key)
            with self._sign_sem:
                pem = _sign(tmp, pub_pem=pub, csr_pem=csr, subject="/CN=edr-hub", ext_path=ext, extra_ext=[san],
                            days=SERVER_DAYS, ca_pem_path=self.paths.ca_cert, ca_key_path=self.paths.ca_key,
                            sha="sha384", serial_hex=_random_serial())
                _verify(tmp, self.paths.ca_cert, pem, "sslserver")
        hub_common.atomic_write(self.paths.server_key, key, 0o600)
        hub_common.atomic_write(self.paths.server_cert, pem, 0o644)

    def server_cert_state(self, want_ips):
        """'ok', 'missing', 'mismatch' (key and certificate differ), 'expiring' (under 30 days) or 'addresses'."""
        if not (os.path.exists(self.paths.server_cert) and os.path.exists(self.paths.server_key)):
            return "missing"
        try:
            info = self.cert_info(self.paths.server_cert)
        except (PkiError, OSError):
            return "missing"
        try:
            # key and certificate are two files: a crash between the two writes leaves a pair that does not match
            same = _must(["x509", "-noout", "-pubkey", "-in", self.paths.server_cert], what="read certificate key") == \
                _must(["pkey", "-pubout", "-in", self.paths.server_key], what="read server key")
        except PkiError:
            same = False
        if not same:
            return "mismatch"
        if info["not_after"] < hub_common.now_ms() + SERVER_RENEW_DAYS * 86400 * 1000:
            return "expiring"
        want = sorted(set(hub_common.norm_ip(str(i)) for i in want_ips))
        if sorted(info["sans"]) != want:
            return "addresses"
        return "ok"


def _server_csr(tmp, key_pem):
    """A CSR for the fallback signing route (openssl ca needs one). Its subject is overridden anyway."""
    key_path = os.path.join(tmp, "srv.key")
    _write_new(key_path, key_pem, 0o600)
    return _must(["req", "-new", "-key", key_path, "-subj", "/CN=edr-hub"], what="CSR")


def _check_p256(pub_pem):
    out = _must(["pkey", "-pubin", "-noout", "-text"], stdin=pub_pem, what="public key read").decode("utf-8", "replace")
    if "ASN1 OID: prime256v1" not in out:
        raise PkiError("only EC prime256v1 keys are accepted")


def _iso_to_ms(text):
    """'2026-11-23 12:32:18Z' (openssl -dateopt iso_8601) to epoch milliseconds."""
    dt = datetime.datetime.strptime(text.strip().rstrip("Z"), "%Y-%m-%d %H:%M:%S")
    return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp()) * 1000
