"""Identity, enrollment, renewal and rehome (client PLAN 4.6 and 5).

Layout under state_dir/identity/:

    gen-N/{hub.conf, ca.pem, client.pem, client.key}     one identity generation
    current -> gen-N                                       flipped with one rename(2)
    rehome.json                                            state of a rehome in progress

The agent resolves `current` once per connection, so a key and a certificate of different
generations are never paired. Keys and CSRs come from the openssl CLI (EC P-256). The CA
fetched during enrollment is checked against the SHA-256 in the token before anything secret
is sent, and is re-encoded from its DER, never the received bytes.
"""

import calendar
import configparser
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import time
import uuid

from . import transport as tr
from .bans import cfg_get, parse_duration, parse_ip, norm_ip
from .spool import atomic_write, parse_rfc3339, read_file_safe, read_json_safe

GEN_RE = re.compile(r"^gen-([0-9]{1,6})\Z")
DROPIN_REL = "/etc/systemd/system/edr-agent.service.d/10-hub.conf"
ROLLBACK_UNIT = "edr-agent-rehome-rollback"
PAUSE_UNIT = "edr-agent-pause-end"
RENEW_DAYS = 30
ROLLBACK_AFTER_S = 600
DEFAULT_PORT = 8443
DEFAULT_ENROLL_PORT = 8444
CA_MAX = 2048
CERT_MAX = 8192
TOKEN_RE = re.compile(r"^([A-Za-z0-9_-]{4,64})\.([A-Za-z0-9_-]{8,128})\.([0-9a-f]{64})\Z")
DROPLET_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}\Z")


class IdentityError(Exception):
    """code: the exit code of the CLI (2 failed, 3 refused before anything changed, 5 not enrolled)."""

    def __init__(self, message, code=2, hub=False):
        super().__init__(message)
        self.code = code
        self.hub = hub          # caused by the hub, the token or the network (enroll then exits 5)


# ---- A very small DER reader (enough to read validity, the curve and basicConstraints) -------

def _tlv(b, i, end):
    if i + 2 > end:
        raise ValueError("short")
    tag = b[i]
    ln = b[i + 1]
    j = i + 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or j + n > end:
            raise ValueError("bad length")
        ln = int.from_bytes(b[j:j + n], "big")
        j += n
    if j + ln > end:
        raise ValueError("overrun")
    return tag, j, j + ln


def _children(b, start, end):
    i = start
    while i < end:
        tag, s, e = _tlv(b, i, end)
        yield tag, s, e
        i = e


def _der_time(b, tag, s, e):
    t = b[s:e].decode("ascii")
    if tag == 0x17:
        m = re.match(r"^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z\Z", t)
        if not m:
            raise ValueError("time")
        y = int(m.group(1))
        y += 2000 if y < 50 else 1900
        rest = [int(m.group(i)) for i in range(2, 7)]
    elif tag == 0x18:
        m = re.match(r"^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z\Z", t)
        if not m:
            raise ValueError("time")
        y = int(m.group(1))
        rest = [int(m.group(i)) for i in range(2, 7)]
    else:
        raise ValueError("time tag")
    return calendar.timegm((y, rest[0], rest[1], rest[2], rest[3], rest[4], 0, 0, 0))


def _tbs(der):
    tag, s, e = _tlv(der, 0, len(der))
    if tag != 0x30:
        raise ValueError("not a certificate")
    tag, ts, te = _tlv(der, s, e)
    if tag != 0x30:
        raise ValueError("no tbsCertificate")
    kids = list(_children(der, ts, te))
    idx = 1 if kids and kids[0][0] == 0xA0 else 0     # skip the optional version
    return kids, idx


def cert_validity(der):
    """(not_before, not_after) as epoch seconds."""
    kids, idx = _tbs(der)
    tag, s, e = kids[idx + 3]
    if tag != 0x30:
        raise ValueError("validity")
    times = list(_children(der, s, e))
    if len(times) != 2:
        raise ValueError("validity")
    return _der_time(der, *times[0]), _der_time(der, *times[1])


_OID_P384 = bytes.fromhex("2b81040022")
_OID_BASIC = bytes.fromhex("551d13")


def cert_ca_p384(der):
    """(is_ca, is_p384) read from basicConstraints and the public key parameters."""
    kids, idx = _tbs(der)
    p384 = False
    tag, s, e = kids[idx + 5]                            # subjectPublicKeyInfo
    spki = list(_children(der, s, e))
    if spki and spki[0][0] == 0x30:
        alg = list(_children(der, spki[0][1], spki[0][2]))
        if len(alg) >= 2 and alg[1][0] == 0x06 and der[alg[1][1]:alg[1][2]] == _OID_P384:
            p384 = True
    is_ca = False
    for tag, s, e in kids[idx + 6:]:
        if tag != 0xA3:
            continue
        outer = list(_children(der, s, e))
        if not outer:
            continue
        for _, es, ee in _children(der, outer[0][1], outer[0][2]):
            parts = list(_children(der, es, ee))
            if not parts or parts[0][0] != 0x06 or der[parts[0][1]:parts[0][2]] != _OID_BASIC:
                continue
            octet = parts[-1]
            if octet[0] != 0x04:
                continue
            seq = list(_children(der, octet[1], octet[2]))
            if seq and seq[0][0] == 0x30:
                inner = list(_children(der, seq[0][1], seq[0][2]))
                if inner and inner[0][0] == 0x01 and der[inner[0][1]:inner[0][2]] == b"\xff":
                    is_ca = True
    return is_ca, p384


def pem_to_der(pem, cap=CERT_MAX):
    """DER of exactly one PEM certificate block, or ValueError."""
    if not isinstance(pem, str) or len(pem) > cap or pem.count("-----BEGIN ") != 1 or pem.count("-----END ") != 1:
        raise ValueError("not exactly one PEM block")
    if "-----BEGIN CERTIFICATE-----" not in pem:
        raise ValueError("not a certificate")
    try:
        return ssl.PEM_cert_to_DER_cert(pem.strip())
    except Exception:
        raise ValueError("bad PEM") from None


def cert_not_after(path):
    """Epoch seconds of a certificate file's notAfter, or None."""
    raw = read_file_safe(path, CERT_MAX)
    if raw is None:
        return None
    try:
        return cert_validity(pem_to_der(raw.decode("ascii", "replace")))[1]
    except (ValueError, IndexError, UnicodeError):
        return None


def sha256_hex(der):
    import hashlib
    return hashlib.sha256(der).hexdigest()


# ---- Where things are ----------------------------------------------------------------------

def identity_dir(paths):
    return str(paths.identity_dir)


def gen_numbers(paths):
    out = []
    try:
        for n in os.listdir(identity_dir(paths)):
            m = GEN_RE.match(n)
            if m and os.path.isdir(os.path.join(identity_dir(paths), n)) and not os.path.islink(os.path.join(identity_dir(paths), n)):
                out.append(int(m.group(1)))
    except OSError:
        pass
    return sorted(out)


def gen_name(n):
    return "gen-%d" % n


def gen_path(paths, n):
    return os.path.join(identity_dir(paths), gen_name(n))


def next_gen(paths):
    g = gen_numbers(paths)
    return (g[-1] + 1) if g else 1


def current_gen_name(paths):
    cur = os.path.join(identity_dir(paths), "current")
    try:
        target = os.readlink(cur)
    except OSError:
        return None
    return target if GEN_RE.match(target) else None


def flip_current(paths, name):
    """ln -s gen-N .tmp && mv -T .tmp current: one rename(2)."""
    d = identity_dir(paths)
    tmp = os.path.join(d, ".current.tmp")
    try:
        os.unlink(tmp)
    except OSError:
        pass
    os.symlink(name, tmp)
    os.replace(tmp, os.path.join(d, "current"))


class Identity:
    def __init__(self, gen, gen_dir, host_uuid, addresses, port, enroll_port, ca_sha256):
        self.gen = gen
        self.gen_dir = gen_dir
        self.host_uuid = host_uuid
        self.addresses = addresses
        self.port = port
        self.enroll_port = enroll_port
        self.ca_sha256 = ca_sha256
        self.ca = os.path.join(gen_dir, "ca.pem")
        self.cert = os.path.join(gen_dir, "client.pem")
        self.key = os.path.join(gen_dir, "client.key")

    @property
    def name(self):
        return gen_name(self.gen)

    def target(self):
        return tr.Target(self.addresses, self.port, self.ca, self.cert, self.key, self.name)

    def not_after(self):
        return cert_not_after(self.cert)


def read_hub_conf(path):
    """{"addresses": [...], "port": int, "enroll_port": int, "host_uuid": str, "ca_sha256": str} or None."""
    raw = read_file_safe(path, 16 * 1024)
    if raw is None:
        return None
    cp = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        cp.read_string(raw.decode("utf-8", "replace"))
        sec = cp["hub"]
        addrs = []
        for a in sec.get("addresses", "").split(","):
            ip = parse_ip(a.strip())
            if ip is not None:
                addrs.append(str(ip))
        port = int(sec.get("port", str(DEFAULT_PORT)))
        eport = int(sec.get("enroll_port", str(DEFAULT_ENROLL_PORT)))
    except (configparser.Error, KeyError, ValueError):
        return None
    if not addrs or len(addrs) > 4 or not (0 < port < 65536) or not (0 < eport < 65536):
        return None
    return {"addresses": addrs, "port": port, "enroll_port": eport,
            "host_uuid": sec.get("host_uuid", "").strip(), "ca_sha256": sec.get("ca_sha256", "").strip()}


def write_hub_conf(path, addresses, port, enroll_port, host_uuid, ca_sha256):
    text = ("[hub]\naddresses = %s\nport = %d\nenroll_port = %d\nhost_uuid = %s\nca_sha256 = %s\n"
            % (",".join(addresses), port, enroll_port, host_uuid, ca_sha256))
    atomic_write(path, text, 0o644)


def load_gen(paths, name):
    """The Identity of a named generation, or None if anything is missing."""
    if not GEN_RE.match(name or ""):
        return None
    d = os.path.join(identity_dir(paths), name)
    if os.path.islink(d) or not os.path.isdir(d):
        return None
    hc = read_hub_conf(os.path.join(d, "hub.conf"))
    if hc is None:
        return None
    for f in ("ca.pem", "client.pem", "client.key"):
        if not os.path.isfile(os.path.join(d, f)):
            return None
    return Identity(int(GEN_RE.match(name).group(1)), os.path.realpath(d), hc["host_uuid"], hc["addresses"],
                    hc["port"], hc["enroll_port"], hc["ca_sha256"])


def load_current(paths):
    """The current identity (resolved with realpath once), or None when not enrolled."""
    name = current_gen_name(paths)
    if name is None:
        return None
    return load_gen(paths, name)


# ---- Root's own record of the hub addresses ----------------------------------------------------
# identity/ belongs to the agent, so nothing in it may decide what root writes into the unit's IPAddressAllow=
# drop-in. Root keeps the addresses it validated itself in a file the agent cannot write, and builds the drop-in
# from that record (or from the values it holds in memory) only. The same reason is behind render.hub_addresses().

TRUSTED_REL = "/var/lib/edr-install/hub-addresses.json"


def trusted_path(paths):
    root = str(getattr(paths, "root", "") or "").rstrip("/")
    return root + TRUSTED_REL


def _clean_addresses(values):
    out = []
    for a in values if isinstance(values, list) else []:
        ip = parse_ip(a) if isinstance(a, str) else None
        if ip is not None and str(ip) not in out:
            out.append(str(ip))
    return out[:4]


def read_trusted(paths):
    """{"addresses": [...], "rehome": {"old": [...], "new": [...]}?} from root's record, or None."""
    d = read_json_safe(trusted_path(paths), 64 * 1024)
    if not isinstance(d, dict) or d.get("v") != 1:
        return None
    out = {"addresses": _clean_addresses(d.get("addresses"))}
    rh = d.get("rehome")
    if isinstance(rh, dict):
        out["rehome"] = {"old": _clean_addresses(rh.get("old")), "new": _clean_addresses(rh.get("new"))}
    return out


def write_trusted(paths, addresses, rehome=None):
    doc = {"v": 1, "addresses": _clean_addresses(list(addresses))}
    if rehome is not None:
        doc["rehome"] = {"old": _clean_addresses(list(rehome["old"])), "new": _clean_addresses(list(rehome["new"]))}
    p = trusted_path(paths)
    os.makedirs(os.path.dirname(p), 0o700, exist_ok=True)
    atomic_write(p, json.dumps(doc), 0o600)


def dropin_addresses(text):
    """The addresses of the last IPAddressAllow= assignment in a drop-in text (an empty one resets, as in systemd)."""
    addrs = []
    for line in (text or "").splitlines():
        if line.startswith("IPAddressAllow="):
            addrs = _clean_addresses(line.split("=", 1)[1].split())
    return addrs


# ---- Host id and droplet id ----------------------------------------------------------------

def host_id_path(paths):
    return str(paths.host_id)


def droplet_store_path(paths):
    return os.path.join(os.path.dirname(host_id_path(paths)), "droplet-id")


def _read_line(path, cap=256):
    raw = read_file_safe(path, cap)
    if raw is None:
        return None
    text = raw.decode("utf-8", "replace").strip()
    if "\n" in text or "\r" in text:
        return None                     # these files hold exactly one line
    return text or None


def read_host_id(paths):
    v = _read_line(host_id_path(paths), 128)
    if not v:
        return None
    try:
        return v if str(uuid.UUID(v)) == v else None
    except ValueError:
        return None


def write_host_id(paths, value):
    atomic_write(host_id_path(paths), value + "\n", 0o644)


def valid_droplet_id(v):
    return isinstance(v, str) and bool(DROPLET_RE.match(v))


def running_droplet_id(paths):
    """The droplet id the root oneshot wrote to /run/edr-droplet-id, or None."""
    v = _read_line(str(paths.droplet_id), 256)
    return v if valid_droplet_id(v) else None


def stored_droplet_id(paths):
    v = _read_line(droplet_store_path(paths), 256)
    return v if valid_droplet_id(v) else None


def write_stored_droplet_id(paths, value):
    atomic_write(droplet_store_path(paths), value + "\n", 0o644)


def host_identity_changed(paths):
    """A clone: the host-id file and a stored droplet id exist, the running droplet id differs."""
    if read_host_id(paths) is None:
        return False
    stored, running = stored_droplet_id(paths), running_droplet_id(paths)
    return bool(stored and running and stored != running)


def enroll_hint(paths, droplet_id):
    """(host_uuid hint or None, stale). The hint goes in only when host-id exists and the droplet
    id is unchanged; a stale host-id after a clone is deleted so the new enrollment sends none."""
    hid = read_host_id(paths)
    if hid is None:
        return None, False
    stored = stored_droplet_id(paths)
    if stored is not None and stored != droplet_id:
        try:
            os.unlink(host_id_path(paths))
        except OSError:
            pass
        return None, True
    return hid, False


# ---- Tokens, hub addresses ------------------------------------------------------------------

def parse_token(text):
    """(id, secret, ca_sha256) from 'id.secret.ca_sha256', or IdentityError (exit 3)."""
    t = (text or "").strip()
    m = TOKEN_RE.match(t)
    if not m:
        raise IdentityError("the token is not in the form id.secret.ca_sha256", 3)
    return m.group(1), m.group(2), m.group(3)


def parse_hub(text):
    """'IP:PORT' or '[v6]:PORT' -> (ip string, port)."""
    t = (text or "").strip()
    m = re.match(r"^\[([^\]]+)\]:([0-9]{1,5})\Z", t) or re.match(r"^([0-9.]+):([0-9]{1,5})$", t)
    if not m:
        raise IdentityError("--hub must be IP:PORT (an IPv6 address in brackets)", 3)
    ip = parse_ip(m.group(1))
    port = int(m.group(2))
    if ip is None or not (0 < port < 65536):
        raise IdentityError("--hub must be IP:PORT (an IPv6 address in brackets)", 3)
    return str(ip), port


# ---- openssl: key and CSR -------------------------------------------------------------------

def _openssl():
    for p in ("/usr/bin/openssl", "/bin/openssl"):
        if os.path.exists(p):
            return p
    return shutil.which("openssl") or "openssl"


def _run(args, timeout=30):
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout, check=False, shell=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IdentityError("%s failed: %s" % (args[0], exc.__class__.__name__), 2) from None
    if r.returncode != 0:
        raise IdentityError("%s %s failed: %s" % (os.path.basename(args[0]), args[1],
                                                  r.stderr.decode("utf-8", "replace").strip()[:160]), 2)
    return r.stdout


def make_key_and_csr(gen_dir):
    """EC P-256 key (0600) and a CSR; the subject means nothing, the hub sets its own."""
    key = os.path.join(gen_dir, "client.key")
    csr = os.path.join(gen_dir, "client.csr")
    for p in (key, csr):
        try:
            os.unlink(p)
        except OSError:
            pass
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    os.close(fd)
    ossl = _openssl()
    _run([ossl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key])
    _run([ossl, "req", "-new", "-key", key, "-subj", "/CN=edr-agent", "-out", csr])
    raw = read_file_safe(csr, 8192)
    if not raw or b"BEGIN CERTIFICATE REQUEST" not in raw:
        raise IdentityError("openssl produced no CSR", 2)
    return raw.decode("ascii")


def new_generation(paths, ops=None):
    """Make gen-N+1 (0700) with a fresh key and CSR. Returns (number, csr_pem)."""
    os.makedirs(identity_dir(paths), 0o700, exist_ok=True)
    n = next_gen(paths)
    d = gen_path(paths, n)
    os.mkdir(d, 0o700)
    try:
        if ops is not None:
            ops.chown_agent(identity_dir(paths))     # root made the directory on a first enrollment: the agent must own it
        csr = make_key_and_csr(d)
        if ops is not None:
            ops.chown_agent(identity_dir(paths))
    except BaseException:
        shutil.rmtree(d, ignore_errors=True)
        raise
    return n, csr


# ---- Enrollment: the network part (runs as edr-agent in a sandbox, or in process) ------------

def fetch_ca(ip, port, expected_sha256, *, requester=None):
    """GET /v1/ca on the enrollment port with verification off (no token, no client certificate).
    Accepts exactly one PEM block of at most 2 KiB whose DER hashes to the token's SHA-256, is a
    P-384 CA, and returns it re-encoded from the DER."""
    requester = requester or tr.request
    ctx = tr.make_context(verify=False)
    try:
        reply = requester(ip, port, "GET", "/v1/ca", ctx=ctx, total_s=15, max_body=CA_MAX + 1)
    except tr.TransportError as exc:
        raise IdentityError("cannot fetch the hub CA: %s" % exc, 2) from None
    if reply.status != 200:
        raise IdentityError("the hub answered %d to GET /v1/ca" % reply.status, 2)
    try:
        text = reply.body.decode("ascii")
        if len(reply.body) > CA_MAX:
            raise ValueError("too large")
        der = pem_to_der(text, CA_MAX)
    except (ValueError, UnicodeError):
        raise IdentityError("the hub CA is not exactly one PEM certificate of at most 2 KiB", 2) from None
    if sha256_hex(der) != expected_sha256:
        raise IdentityError("the hub CA does not match the SHA-256 in the token: not trusting this hub", 2)
    try:
        is_ca, p384 = cert_ca_p384(der)
    except (ValueError, IndexError):
        raise IdentityError("the hub CA cannot be read", 2) from None
    if not is_ca or not p384:
        raise IdentityError("the hub CA is not a P-384 CA certificate", 2)
    return ssl.DER_cert_to_PEM_cert(der)


def validate_cert_pem(pem, key_path=None, ca_path=None):
    """The client certificate from the hub: one PEM block, readable, not expired, matching the key."""
    try:
        der = pem_to_der(pem, 8192)
        nb, na = cert_validity(der)
    except (ValueError, IndexError):
        raise IdentityError("the hub sent a certificate that cannot be read", 2) from None
    if na <= time.time():
        raise IdentityError("the hub sent an expired certificate", 2)
    return ssl.DER_cert_to_PEM_cert(der), na


def net_phase(params, token, *, requester=None, sleep=time.sleep, clock=time.monotonic):
    """Steps 2 to 5 of PLAN 4.6, with no root needed:

    params: {hub, port, enroll_port, gen_dir, csr, droplet_id, hostname, os, ips, host_uuid?}
    token:  the full 'id.secret.ca_sha256'

    Writes ca.pem and client.pem into gen_dir and returns the enroll reply (a dict of
    host_uuid, certificate omitted, hub_addresses, port, not_after, state, ca_sha256)."""
    requester = requester or tr.request
    tid, secret, ca_sha = parse_token(token)
    ip, port, eport = params["hub"], int(params["port"]), int(params["enroll_port"])
    gen_dir = params["gen_dir"]
    ca_pem = fetch_ca(ip, eport, ca_sha, requester=requester)
    ca_path = os.path.join(gen_dir, "ca.pem")
    atomic_write(ca_path, ca_pem, 0o644)
    ctx = tr.make_context(ca_path=ca_path, verify=True)          # no client certificate, old or new
    body = {"token": tid + "." + secret, "csr": params["csr"], "hostname": params.get("hostname", "")[:253],
            "os": params.get("os", "")[:128], "ips": list(params.get("ips", []))[:16],
            "droplet_id": params["droplet_id"]}
    if params.get("host_uuid"):
        body["host_uuid"] = params["host_uuid"]
    try:
        reply = requester(ip, eport, "POST", "/v1/enroll", ctx=ctx, body=tr.json_body(body),
                          headers={"Content-Type": "application/json"}, total_s=30)
    except tr.TransportError as exc:
        raise IdentityError("enrollment failed: %s" % exc, 2) from None
    oc = tr.interpret("enroll", reply)
    if oc.action == tr.STOP:
        if reply.status == 409:
            raise IdentityError("the hub already knows this host (host_exists): ask for a token made with "
                                "`edr-hub token create --for HOST`", 2)
        if reply.status == 401:
            raise IdentityError("the hub refused the token: make a new token", 2)
        raise IdentityError("the hub refused enrollment (%d %s)" % (reply.status, oc.code), 2)
    if oc.action != tr.OK:
        raise IdentityError("enrollment failed: the hub answered %d %s" % (reply.status, oc.code), 2)
    doc = reply.json()
    if not isinstance(doc, dict):
        raise IdentityError("the hub's enrollment reply is not JSON", 2)
    # the CA in the reply must be the one we pinned
    try:
        if sha256_hex(pem_to_der(doc.get("ca"), CA_MAX)) != ca_sha:
            raise ValueError("ca")
    except ValueError:
        raise IdentityError("the CA in the enrollment reply differs from the pinned CA", 2) from None
    cert_pem, na = validate_cert_pem(doc.get("certificate"))
    atomic_write(os.path.join(gen_dir, "client.pem"), cert_pem, 0o644)
    out = {"host_uuid": doc.get("host_uuid"), "hub_addresses": doc.get("hub_addresses"), "port": doc.get("port"),
           "not_after": doc.get("not_after"), "state": doc.get("state"), "ca_sha256": ca_sha}
    # step 5: test call with the new certificate on the fleet port, retried for up to 30 s
    key_path = os.path.join(gen_dir, "client.key")
    deadline = clock() + float(params.get("test_window_s", 30))
    last = "no answer"
    while True:
        try:
            tctx = tr.make_context(ca_path, os.path.join(gen_dir, "client.pem"), key_path, True)
            rep = requester(ip, port, "GET", "/v1/policy", ctx=tctx, total_s=10)
            toc = tr.interpret("policy", rep)
            if toc.action in (tr.OK, tr.UNCHANGED):
                return out
            last = "the hub answered %d %s" % (rep.status, toc.code)
            if toc.action not in (tr.BACKOFF, tr.WAIT):
                break
        except tr.TransportError as exc:
            last = str(exc)
        except (ssl.SSLError, OSError) as exc:
            last = "cannot use the new certificate: %s" % exc.__class__.__name__
            break
        if clock() >= deadline:
            break
        sleep(min(2.0, max(0.0, deadline - clock())))
    raise IdentityError("the test call with the new certificate failed (%s)" % last, 2)


def validate_enroll_reply(rep, *, hub_ip, fleet_port, allow_loopback=False):
    """Root's check of the reply before anything is written (PLAN 4.6 step 6)."""
    if not isinstance(rep, dict):
        raise IdentityError("the enrollment reply is malformed", 3)
    hid = rep.get("host_uuid")
    try:
        if not isinstance(hid, str) or str(uuid.UUID(hid)) != hid:
            raise ValueError
    except ValueError:
        raise IdentityError("the host UUID in the reply is not in canonical lower-case form", 3) from None
    addrs = rep.get("hub_addresses")
    if not isinstance(addrs, list) or not (1 <= len(addrs) <= 4):
        raise IdentityError("hub_addresses must be a list of 1 to 4 addresses", 3)
    clean = []
    for a in addrs:
        ip = parse_ip(a) if isinstance(a, str) else None
        if ip is None or (isinstance(a, str) and a != str(ip)):
            raise IdentityError("hub_addresses holds something that is not a bare IP literal", 3)
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or (ip.is_loopback and not allow_loopback):
            raise IdentityError("hub_addresses holds a loopback, link-local, multicast or unspecified address", 3)
        if str(ip) not in clean:
            clean.append(str(ip))
    port = rep.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or port != fleet_port:
        raise IdentityError("the fleet port in the reply differs from the one given with --hub", 3)
    if norm_ip(hub_ip) not in clean:
        raise IdentityError("the address given with --hub is not among the hub's addresses", 3)
    na = parse_rfc3339(rep.get("not_after")) if rep.get("not_after") is not None else None
    state = rep.get("state") if isinstance(rep.get("state"), str) else "pending"
    return {"host_uuid": hid, "addresses": clean, "port": port, "not_after": na, "state": state[:16]}


# ---- System operations (root only; recorded no-ops in a dev run) ------------------------------

class SystemOps:
    """systemctl, systemd-run and the IPAddressAllow drop-in. Under EDR_AGENT_ROOT (a dev or test
    run) nothing is executed: the calls are recorded in `calls` and the drop-in is written under
    the root prefix."""

    def __init__(self, paths, dev=None):
        self.paths = paths
        if dev is None:
            dev = getattr(paths, "dev", bool(os.environ.get("EDR_AGENT_ROOT")))
        self.dev = bool(dev)
        self.calls = []

    @property
    def dropin_path(self):
        prefix = str(getattr(self.paths, "root", os.environ.get("EDR_AGENT_ROOT", "")) or "").rstrip("/")
        return prefix + DROPIN_REL

    def _exec(self, args, timeout=30):
        self.calls.append(list(args))
        if self.dev:
            return 0
        try:
            return subprocess.run(args, capture_output=True, timeout=timeout, check=False, shell=False).returncode
        except (OSError, subprocess.TimeoutExpired):
            return 1

    def chown_agent(self, path):
        """Give a file, or a directory tree, to edr-agent. Root works in a tree the agent owns, so the walk is
        by directory descriptors: it never follows a symlink, never descends into anything that is not a real
        directory, and skips a file with more than one link."""
        self.calls.append(["chown", str(path)])
        if self.dev or os.geteuid() != 0:
            return
        try:
            import grp
            import pwd
            uid, gid = pwd.getpwnam("edr-agent").pw_uid, grp.getgrnam("edr-agent").gr_gid
        except KeyError:
            return
        path = str(path)
        try:
            st = os.lstat(path)
        except OSError:
            return
        if stat.S_ISREG(st.st_mode):
            try:
                os.chown(path, uid, gid, follow_symlinks=False)
            except OSError:
                pass
            return
        if not stat.S_ISDIR(st.st_mode):
            return
        try:
            top = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            return
        try:
            self._chown_tree(top, uid, gid, os.fstat(top), 0)
        finally:
            os.close(top)

    def _chown_tree(self, dirfd, uid, gid, st, depth):
        try:
            os.fchown(dirfd, uid, gid)
            names = os.listdir(dirfd)
        except OSError:
            return
        if depth > 8:
            return
        for name in names:
            try:
                st = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            except OSError:
                continue
            mode = st.st_mode
            if stat.S_ISDIR(mode):
                try:
                    sub = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dirfd)
                except OSError:
                    continue                               # swapped for a symlink or removed: not a real directory now
                try:
                    now = os.fstat(sub)
                    if (now.st_dev, now.st_ino) == (st.st_dev, st.st_ino):
                        self._chown_tree(sub, uid, gid, now, depth + 1)
                finally:
                    os.close(sub)
            elif stat.S_ISREG(mode):
                if st.st_nlink != 1:
                    continue
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dirfd)
                except OSError:
                    continue
                try:
                    now = os.fstat(fd)
                    if stat.S_ISREG(now.st_mode) and now.st_nlink == 1 and (now.st_dev, now.st_ino) == (st.st_dev, st.st_ino):
                        os.fchown(fd, uid, gid)
                except OSError:
                    pass
                finally:
                    os.close(fd)
            elif stat.S_ISLNK(mode):
                try:
                    os.chown(name, uid, gid, dir_fd=dirfd, follow_symlinks=False)    # the link itself, never its target
                except OSError:
                    pass

    def write_dropin(self, addresses):
        text = "[Service]\nIPAddressAllow=\nIPAddressAllow=%s\n" % " ".join(addresses)
        d = os.path.dirname(self.dropin_path)
        os.makedirs(d, 0o755, exist_ok=True)
        atomic_write(self.dropin_path, text, 0o644)

    def read_dropin(self):
        raw = read_file_safe(self.dropin_path, 64 * 1024)
        return raw.decode("utf-8", "replace") if raw is not None else None

    def restore_dropin(self, text, fallback_addresses=()):
        if text is not None:
            atomic_write(self.dropin_path, text, 0o644)
        elif fallback_addresses:
            self.write_dropin(list(fallback_addresses))

    def daemon_reload(self):
        return self._exec(["systemctl", "daemon-reload"])

    def restart_agent(self):
        return self._exec(["systemctl", "restart", "edr-agent.service"])

    def arm_rollback_timer(self, lib_dir, seconds=ROLLBACK_AFTER_S):
        return self._exec(["systemd-run", "--on-active=%d" % seconds, "--unit=" + ROLLBACK_UNIT, "--collect",
                           "--quiet", "/usr/bin/python3", "-I", os.path.join(str(lib_dir), "edr-agent.py"),
                           "rehome", "--rollback"])

    def disarm_rollback_timer(self):
        return self._exec(["systemctl", "stop", ROLLBACK_UNIT + ".timer"])

    def start_pause_consumers(self):
        """pause and resume start each consumer so they act at once (PLAN 4.7)."""
        for unit in ("edr-bans.service", "edr-policy-check.service", "edr-dns-watch.service"):
            self._exec(["systemctl", "start", "--no-block", unit])

    def arm_pause_timer(self, lib_dir, seconds):
        return self._exec(["systemd-run", "--on-active=%d" % int(seconds), "--unit=" + PAUSE_UNIT, "--collect",
                           "--quiet", "/usr/bin/python3", "-I", os.path.join(str(lib_dir), "edr-agent.py"), "resume"])

    def cancel_pause_timer(self):
        return self._exec(["systemctl", "stop", PAUSE_UNIT + ".timer"])


def sandbox_command(ip, lib_dir):
    """The transient sandbox for the network part (PLAN 4.6): edr-agent, one hub address only."""
    return ["systemd-run", "--pipe", "--wait", "--quiet", "--collect", "-p", "User=edr-agent",
            "-p", "IPAddressDeny=any", "-p", "IPAddressAllow=" + ip, "-p", "NoNewPrivileges=yes",
            "-p", "PrivateTmp=yes", "/usr/bin/python3", "-I", os.path.join(str(lib_dir), "edr-agent.py"), "hub-net"]


def run_net_phase_sandboxed(params, token, lib_dir, runner=subprocess.run):
    """Run net_phase as edr-agent in the transient unit, the token on stdin. Returns the reply dict."""
    payload = json.dumps({"params": params, "token": token}).encode()
    try:
        r = runner(sandbox_command(params["hub"], lib_dir), input=payload, capture_output=True, timeout=120,
                   check=False, shell=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IdentityError("could not run the enrollment sandbox: %s" % exc.__class__.__name__, 2) from None
    try:
        res = json.loads(r.stdout.decode("utf-8", "replace").strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise IdentityError("the enrollment sandbox gave no result", 2) from None
    if not isinstance(res, dict) or not res.get("ok"):
        code = res.get("code") if isinstance(res, dict) and isinstance(res.get("code"), int) else 2
        msg = res.get("error") if isinstance(res, dict) and isinstance(res.get("error"), str) else "failed"
        raise IdentityError(msg[:300], code)
    return res["reply"]


# ---- Enrollment (root part) ------------------------------------------------------------------

def commit_identity(paths, gen_n, reply, enroll_port, droplet_id, ops):
    """Write hub.conf into gen-N, host-id and the droplet id; the drop-in; flip current."""
    d = gen_path(paths, gen_n)
    write_hub_conf(os.path.join(d, "hub.conf"), reply["addresses"], reply["port"], enroll_port,
                   reply["host_uuid"], reply["ca_sha256"])
    ops.chown_agent(d)
    write_host_id(paths, reply["host_uuid"])
    write_stored_droplet_id(paths, droplet_id)
    write_trusted(paths, reply["addresses"])                 # what root validated, outside the agent's tree
    ops.write_dropin(reply["addresses"])
    ops.daemon_reload()
    flip_current(paths, gen_name(gen_n))


def enroll(paths, *, hub, port, enroll_port, token, droplet_id, hostname, os_name, ips, ops, net_runner=None,
           allow_loopback=False, lib_dir=None):
    """The whole enrollment (PLAN 4.6, steps 1 to 6). Returns the validated reply.
    Raises IdentityError: code 3 refused, 2 failed."""
    parse_token(token)
    if not valid_droplet_id(droplet_id):
        raise IdentityError("the droplet id is missing or not valid", 3)
    hint, stale = enroll_hint(paths, droplet_id)
    n, csr = new_generation(paths, ops)
    try:
        params = {"hub": hub, "port": port, "enroll_port": enroll_port, "gen_dir": gen_path(paths, n), "csr": csr,
                  "droplet_id": droplet_id, "hostname": hostname, "os": os_name, "ips": ips}
        if hint:
            params["host_uuid"] = hint
        runner = net_runner or (lambda p, t: net_phase(p, t))
        try:
            rep = runner(params, token)
            rep = validate_enroll_reply(rep, hub_ip=hub, fleet_port=port, allow_loopback=allow_loopback)
        except IdentityError as exc:
            exc.hub = True
            raise
        rep["ca_sha256"] = parse_token(token)[2]
        commit_identity(paths, n, rep, enroll_port, droplet_id, ops)
    except BaseException:
        shutil.rmtree(gen_path(paths, n), ignore_errors=True)
        raise
    rep["gen"] = n
    rep["stale_host_id_removed"] = stale
    return rep


# ---- Renewal ------------------------------------------------------------------------------

def renew_due(ident, now=None):
    na = ident.not_after()
    now = time.time() if now is None else now
    return na is not None and na - now <= RENEW_DAYS * 86400


def rehome_in_progress(paths):
    return os.path.exists(os.path.join(identity_dir(paths), "rehome.json"))


def renew(paths, client, ident=None, now=None):
    """POST /v1/renew over mTLS with the current certificate; flip to the new generation.

    A new key and CSR each time, except that a pending generation left by a lost reply keeps
    its CSR (the hub returns the same certificate for the same CSR). Returns (status, Outcome|None)
    where status is 'renewed' or 'failed'."""
    ident = ident or load_current(paths)
    if ident is None:
        return "failed", None
    pending = None
    for n in gen_numbers(paths):
        if n > ident.gen:
            d = gen_path(paths, n)
            if os.path.isfile(os.path.join(d, "client.key")) and os.path.isfile(os.path.join(d, "client.csr")) \
                    and not os.path.isfile(os.path.join(d, "hub.conf")):
                pending = n
    if pending is not None:
        n = pending
        csr = read_file_safe(os.path.join(gen_path(paths, n), "client.csr"), 8192)
        csr = csr.decode("ascii", "replace") if csr else None
        if not csr:
            shutil.rmtree(gen_path(paths, n), ignore_errors=True)
            pending = None
    if pending is None:
        n, csr = new_generation(paths)
    reply, oc = client.call("renew", "POST", "/v1/renew", body=tr.json_body({"csr": csr}),
                            headers={"Content-Type": "application/json"})
    if oc.action != tr.OK:
        return "failed", oc
    doc = reply.json()
    d = gen_path(paths, n)
    try:
        pem, na = validate_cert_pem(doc.get("certificate") if isinstance(doc, dict) else None)
        atomic_write(os.path.join(d, "client.pem"), pem, 0o644)
        tr.make_context(None, os.path.join(d, "client.pem"), os.path.join(d, "client.key"), False)
        shutil.copyfile(ident.ca, os.path.join(d, "ca.pem"))
        write_hub_conf(os.path.join(d, "hub.conf"), ident.addresses, ident.port, ident.enroll_port,
                       ident.host_uuid, ident.ca_sha256)
    except (IdentityError, ssl.SSLError, OSError):
        for f in ("client.pem", "hub.conf", "ca.pem"):
            try:
                os.unlink(os.path.join(d, f))
            except OSError:
                pass
        return "failed", tr.Outcome(tr.LOG_RETRY, reply.status, "bad_certificate")
    flip_current(paths, gen_name(n))
    return "renewed", oc


def cleanup_generations(paths):
    """After a heartbeat was accepted with the current generation: delete the older ones.
    Never during a rehome (the previous generation is the way back)."""
    if rehome_in_progress(paths):
        return []
    cur = current_gen_name(paths)
    if cur is None:
        return []
    num = int(GEN_RE.match(cur).group(1))
    gone = []
    for n in gen_numbers(paths):
        if n < num:
            shutil.rmtree(gen_path(paths, n), ignore_errors=True)
            gone.append(n)
    return gone


# ---- Deregister -----------------------------------------------------------------------------

def deregister(paths, reason, ident=None, timeout=5.0, requester=None):
    """Best-effort POST /v1/deregister with the given (or current) certificate. Returns an Outcome or None."""
    ident = ident or load_current(paths)
    if ident is None:
        return None
    client = tr.HubClient(lambda: ident.target(), requester=requester)
    _, oc = client.call("deregister", "POST", "/v1/deregister", body=tr.json_body({"reason": reason}),
                        headers={"Content-Type": "application/json"}, total_s=timeout)
    return oc


# ---- Rehome (PLAN 5) -------------------------------------------------------------------------

def _state_path(paths):
    return os.path.join(identity_dir(paths), "rehome.json")


def _save_state(paths, st):
    atomic_write(_state_path(paths), json.dumps(st), 0o600)


def load_rehome_state(paths):
    st = None
    raw = read_file_safe(_state_path(paths), 64 * 1024)
    if raw is not None:
        try:
            st = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            st = None
    return st if isinstance(st, dict) and GEN_RE.match(str(st.get("prev", ""))) and GEN_RE.match(str(st.get("new", ""))) else None


def default_confirm(paths, new_name, since, timeout, sleep=time.sleep, clock=time.time):
    """Wait for the running agent to report (run_dir/uplink.json) a heartbeat accepted by the new hub
    and a successful policy poll, both on the new generation. Returns '' on success, else the reason."""
    p = os.path.join(str(paths.run_dir), "uplink.json")
    end = clock() + timeout
    last = "no report from the agent"
    while True:
        st = None
        raw = read_file_safe(p, 64 * 1024)
        if raw is not None:
            try:
                st = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                st = None
        if isinstance(st, dict) and st.get("gen") == new_name:
            hb_ok = st.get("hb_gen") == new_name and isinstance(st.get("last_heartbeat_ok"), (int, float)) \
                and st["last_heartbeat_ok"] >= since
            pol_ok = st.get("policy_gen") == new_name and isinstance(st.get("last_policy_ok"), (int, float)) \
                and st["last_policy_ok"] >= since
            if hb_ok and pol_ok:
                return ""
            last = "no accepted heartbeat" if not hb_ok else "no successful policy poll"
        elif isinstance(st, dict):
            last = "the agent still uses %s" % str(st.get("gen"))[:16]
        if clock() >= end:
            return last
        sleep(2.0)


def rehome(paths, cfg, *, hub, port, enroll_port, token, droplet_id, hostname, os_name, ips, ops,
           drop_spool=False, net_runner=None, confirm=None, allow_loopback=False, lib_dir=None, log=None):
    """Move this host to a new hub (PLAN 5). Returns the exit code: 0 done, 2 failed, 3 refused
    before anything changed, 4 rolled back."""
    log = log or (lambda m: None)
    if rehome_in_progress(paths):
        log("a rehome is already in progress; run `edr-agent rehome --rollback`")
        return 3
    old = load_current(paths)
    if old is None:
        log("this host is not enrolled; use `edr-agent enroll`")
        return 3
    try:
        parse_token(token)
        if not valid_droplet_id(droplet_id):
            raise IdentityError("the droplet id is missing or not valid", 3)
    except IdentityError as exc:
        log(str(exc))
        return exc.code
    timeout = parse_duration(cfg_get(cfg, "agent", "rehome_confirm_timeout", "300s"), 300.0) or 300.0
    # steps 1 and 2: stage and prove. The old hub is untouched.
    hint, _ = enroll_hint(paths, droplet_id)
    try:
        n, csr = new_generation(paths, ops)
    except (IdentityError, OSError) as exc:
        log("cannot stage the new identity: %s" % exc)
        return 2
    new_name = gen_name(n)
    try:
        params = {"hub": hub, "port": port, "enroll_port": enroll_port, "gen_dir": gen_path(paths, n), "csr": csr,
                  "droplet_id": droplet_id, "hostname": hostname, "os": os_name, "ips": ips}
        if hint:
            params["host_uuid"] = hint
        runner = net_runner or (lambda p, t: net_phase(p, t))
        rep = validate_enroll_reply(runner(params, token), hub_ip=hub, fleet_port=port, allow_loopback=allow_loopback)
        rep["ca_sha256"] = parse_token(token)[2]
        write_hub_conf(os.path.join(gen_path(paths, n), "hub.conf"), rep["addresses"], rep["port"], enroll_port,
                       rep["host_uuid"], rep["ca_sha256"])
        ops.chown_agent(gen_path(paths, n))
    except IdentityError as exc:
        shutil.rmtree(gen_path(paths, n), ignore_errors=True)
        log("rehome failed before anything changed: %s" % exc)
        return exc.code
    except (OSError, ValueError) as exc:
        shutil.rmtree(gen_path(paths, n), ignore_errors=True)
        log("rehome failed before anything changed: %s" % exc.__class__.__name__)
        return 2
    # The old hub's addresses come from root's own record or the drop-in root wrote, never from hub.conf
    old_addrs = (read_trusted(paths) or {}).get("addresses") or dropin_addresses(ops.read_dropin()) or []
    st = {"v": 1, "step": 2, "prev": old.name, "new": new_name, "old_addresses": old_addrs,
          "new_addresses": rep["addresses"], "new_host_uuid": rep["host_uuid"], "old_host_uuid": old.host_uuid,
          "had_dropin": False, "armed_at": 0, "droplet_id": droplet_id}
    try:
        # step 3: arm the timed rollback (state first, so a firing timer finds it)
        write_trusted(paths, old_addrs, {"old": old_addrs, "new": rep["addresses"]})
        _save_state(paths, st)
        ops.arm_rollback_timer(lib_dir or str(paths.lib_dir))
        st.update(step=3, armed_at=int(time.time()))
        _save_state(paths, st)
        # step 4: allow both hubs
        saved = ops.read_dropin()
        if saved is not None:
            atomic_write(os.path.join(identity_dir(paths), "rehome-dropin.saved"), saved, 0o600)
            st["had_dropin"] = True
        ops.write_dropin(old_addrs + [a for a in rep["addresses"] if a not in old_addrs])
        ops.daemon_reload()
        if drop_spool:
            atomic_write(os.path.join(identity_dir(paths), "drop-spool.flag"), "1\n", 0o644)
        st["step"] = 4
        _save_state(paths, st)
        # step 5: flip and restart
        flip_current(paths, new_name)
        st["step"] = 5
        st["flipped_at"] = time.time()
        _save_state(paths, st)
        ops.restart_agent()
        # step 6: confirm
        why = (confirm or (lambda nm, since, to: default_confirm(paths, nm, since, to)))(new_name, st["flipped_at"], timeout)
        if why:
            raise IdentityError("the new hub was not confirmed: %s" % why, 4)
        st["step"] = 6
        _save_state(paths, st)
        ops.disarm_rollback_timer()
    except BaseException as exc:
        why = str(exc) if isinstance(exc, IdentityError) else exc.__class__.__name__
        log("rehome failed (%s): rolling back" % why)
        rollback(paths, ops, log=log, lib_dir=lib_dir)
        return 4
    return finish_commit(paths, ops, st, log=log, lib_dir=lib_dir)


def finish_commit(paths, ops, st, *, log=None, requester=None, lib_dir=None):
    """Step 7: the move stands. Idempotent: the next run repeats what did not finish."""
    log = log or (lambda m: None)
    new = load_gen(paths, st["new"])
    if new is None:
        log("the new identity is gone; cannot finish the rehome")
        return 2
    if st.get("new_host_uuid") and read_host_id(paths) != st["new_host_uuid"]:
        write_host_id(paths, st["new_host_uuid"])
    if st.get("droplet_id"):
        write_stored_droplet_id(paths, st["droplet_id"])
    st["step"] = 7
    _save_state(paths, st)
    trusted = read_trusted(paths) or {}
    rh = trusted.get("rehome")
    new_addrs = (rh["new"] if rh else None) or _clean_addresses(st.get("new_addresses")) or []
    old_addrs = (rh["old"] if rh else None) or _clean_addresses(st.get("old_addresses")) or []
    if not new_addrs:
        log("root holds no validated address list for the new hub: the drop-in is left as it is")
        return 2
    prev = load_gen(paths, st["prev"])
    if prev is not None and not st.get("deregistered"):
        if old_addrs:
            prev.addresses = old_addrs                  # root dials the addresses it validated, not the ones in hub.conf
        oc = deregister(paths, "rehome", ident=prev, timeout=5.0, requester=requester)
        log("old hub deregister: %s" % (oc.action if oc else "skipped"))
        st["deregistered"] = True
        _save_state(paths, st)
    ops.write_dropin(new_addrs)
    write_trusted(paths, new_addrs)
    ops.daemon_reload()
    shutil.rmtree(gen_path(paths, int(GEN_RE.match(st["prev"]).group(1))), ignore_errors=True)
    for f in ("rehome.json", "rehome-dropin.saved"):
        try:
            os.unlink(os.path.join(identity_dir(paths), f))
        except OSError:
            pass
    return 0


def rollback(paths, ops, *, log=None, lib_dir=None):
    """Undo a rehome by the state it reached (PLAN 5, Rollback after every step).
    Returns 4 when something was rolled back, 0 when no rehome is pending or the move already stands."""
    log = log or (lambda m: None)
    st = load_rehome_state(paths)
    if st is None:
        if rehome_in_progress(paths):
            try:
                os.unlink(_state_path(paths))
            except OSError:
                pass
        return 0
    if st.get("step", 0) >= 7:
        log("the move already stands; finishing the cleanup")
        finish_commit(paths, ops, st, log=log, lib_dir=lib_dir)
        return 0
    prev = load_gen(paths, st["prev"])
    trusted = read_trusted(paths) or {}
    rh = trusted.get("rehome")
    # root's record first; the saved copy and hub.conf sit in the agent's tree and are never used for the drop-in
    old_addrs = (rh["old"] if rh else None) or _clean_addresses(st.get("old_addresses")) or []
    step = st.get("step", 0)

    def attempt(what, fn, *a):
        try:
            fn(*a)
        except Exception as exc:                      # each undo step is tried; one failure stops none of the others
            log("rollback: %s failed: %s" % (what, exc.__class__.__name__))

    if step >= 5 and prev is not None:
        attempt("point current back", flip_current, paths, st["prev"])
    if step >= 4:
        if old_addrs:
            attempt("restore the drop-in", ops.write_dropin, old_addrs)
            attempt("update root's address record", write_trusted, paths, old_addrs)
        attempt("daemon-reload", ops.daemon_reload)
    if step >= 5:
        attempt("restart edr-agent", ops.restart_agent)
    attempt("disarm the timer", ops.disarm_rollback_timer)
    shutil.rmtree(gen_path(paths, int(GEN_RE.match(st["new"]).group(1))), ignore_errors=True)
    for f in ("rehome.json", "rehome-dropin.saved", "drop-spool.flag"):
        try:
            os.unlink(os.path.join(identity_dir(paths), f))
        except OSError:
            pass
    log("rehome rolled back")
    return 4
