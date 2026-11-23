"""Test support for the agent's hub-side tests (agent 5): a throwaway CA made with the openssl CLI
under the strict profiles of hub section 2, a small TLS 1.3 test server on 127.0.0.1 that plays
the hub, and fakes for the modules agent 4 writes (installed only when the real import fails).

The file holds no tests. It is named test_transport_pki so that it sits among the transport tests.
"""

import atexit
import gzip
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import types

HERE = os.path.dirname(os.path.realpath(__file__))
CODE = os.path.join(os.path.dirname(HERE), "agent")
if CODE not in sys.path:
    sys.path.insert(0, CODE)

OPENSSL = shutil.which("openssl") or "openssl"

CA_CNF = """[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = %(cn)s
[ext]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""

LAX_CA_CNF = """[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = Lax CA
[ext]
basicConstraints = CA:TRUE
subjectKeyIdentifier = hash
"""

SRV_EXT = """basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = %(san)s
"""

CLI_EXT = """basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""


_LIVE = set()


def _sweep():
    """Safety net: remove any temporary directory a test forgot (a setUp that skipped, for example)."""
    for d in list(_LIVE):
        shutil.rmtree(d, ignore_errors=True)
        _LIVE.discard(d)


atexit.register(_sweep)


def run(args, **kw):
    r = subprocess.run(args, capture_output=True, timeout=60, check=False, **kw)
    if r.returncode != 0:
        raise RuntimeError("%s failed: %s" % (" ".join(args[:3]), r.stderr.decode("utf-8", "replace")))
    return r.stdout


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


class PKI:
    """A CA (EC P-384, strict profile) that signs servers and clients."""

    _n = 0

    def __init__(self, dirpath=None, cn="EDR Test CA", lax=False):
        self.dir = dirpath or tempfile.mkdtemp(prefix="a5pki-")
        _LIVE.add(self.dir)
        self.cn = cn
        self.ca_key = os.path.join(self.dir, "ca.key")
        self.ca_pem = os.path.join(self.dir, "ca.pem")
        cnf = os.path.join(self.dir, "ca.cnf")
        write(cnf, (LAX_CA_CNF if lax else CA_CNF % {"cn": cn}))
        run([OPENSSL, "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", self.ca_key])
        run([OPENSSL, "req", "-x509", "-new", "-key", self.ca_key, "-sha384", "-days", "3650", "-config", cnf,
             "-out", self.ca_pem])

    def pem(self):
        with open(self.ca_pem) as f:
            return f.read()

    def der_sha256(self):
        import hashlib
        der = ssl.PEM_cert_to_DER_cert(self.pem())
        return hashlib.sha256(der).hexdigest()

    def _sign(self, pubkey_pem_path, subj, ext_text, days, out):
        PKI._n += 1
        ext = out + ".ext"
        write(ext, ext_text)
        run([OPENSSL, "x509", "-new", "-force_pubkey", pubkey_pem_path, "-subj", subj, "-CA", self.ca_pem,
             "-CAkey", self.ca_key, "-sha384", "-days", str(days), "-extfile", ext,
             "-set_serial", "0x%x" % (0x1000 + PKI._n), "-out", out])

    def server(self, name="srv", san="IP:127.0.0.1,IP:::1", days=397):
        key = os.path.join(self.dir, name + ".key")
        pem = os.path.join(self.dir, name + ".pem")
        pub = os.path.join(self.dir, name + ".pub")
        run([OPENSSL, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key])
        with open(pub, "wb") as f:
            f.write(run([OPENSSL, "pkey", "-in", key, "-pubout"]))
        self._sign(pub, "/CN=hub", SRV_EXT % {"san": san}, days, pem)
        return pem, key

    def client_from_csr(self, csr_pem, cn, days=365):
        """Sign a CSR the way the hub does: take only the public key, set the subject itself."""
        PKI._n += 1
        csr = os.path.join(self.dir, "c%d.csr" % PKI._n)
        pub = os.path.join(self.dir, "c%d.pub" % PKI._n)
        out = os.path.join(self.dir, "c%d.pem" % PKI._n)
        write(csr, csr_pem)
        run([OPENSSL, "req", "-in", csr, "-verify", "-noout"])
        with open(pub, "wb") as f:
            f.write(run([OPENSSL, "req", "-in", csr, "-pubkey", "-noout"]))
        self._sign(pub, "/CN=" + cn, CLI_EXT, days, out)
        with open(out) as f:
            return f.read()

    def client(self, name="cli", cn="11111111-2222-4333-8444-555555555555", days=365):
        key = os.path.join(self.dir, name + ".key")
        csr = os.path.join(self.dir, name + ".csr")
        run([OPENSSL, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key])
        run([OPENSSL, "req", "-new", "-key", key, "-subj", "/CN=x", "-out", csr])
        with open(csr) as f:
            pem = self.client_from_csr(f.read(), cn, days)
        out = os.path.join(self.dir, name + ".pem")
        write(out, pem)
        return out, key

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)
        _LIVE.discard(self.dir)


# ---- the test hub ---------------------------------------------------------------------------

class Request:
    def __init__(self, method, path, version, headers, body, raw_head, peer_cn, tls_version):
        self.method, self.path, self.version = method, path, version
        self.headers, self.body, self.raw_head = headers, body, raw_head
        self.peer_cn, self.tls_version = peer_cn, tls_version

    def json(self):
        body = self.body
        if self.headers.get("content-encoding") == "gzip":
            body = gzip.decompress(body)
        return json.loads(body.decode("utf-8"))


def reply(status, obj=None, headers=None, body=None):
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    if body is None:
        body = json.dumps(obj if obj is not None else {}).encode()
    return (status, h, body)


def err(status, code, headers=None):
    return reply(status, {"error": code, "code": code}, headers)


class Raw:
    def __init__(self, data):
        self.data = data


class Reset:
    """Close the connection with a TCP reset instead of an answer (what a refused certificate can look like)."""


class Stream:
    def __init__(self, status, headers, chunks):
        self.status, self.headers, self.chunks = status, headers, chunks


class FakeHub(threading.Thread):
    """A TLS 1.3 server on 127.0.0.1 (an ephemeral port, always above 18000) playing the hub."""

    def __init__(self, pki, handler, *, mtls=True, cert=None, key=None, tls12=False, host="127.0.0.1"):
        super().__init__(daemon=True)
        self.handler = handler
        self.requests = []
        self.handshake_failures = 0
        self.lock = threading.Lock()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if tls12:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if cert is None:
            cert, key = pki.server()
        ctx.load_cert_chain(cert, key)
        if mtls:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(pki.ca_pem)
        self.ctx = ctx
        self.sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        assert self.port >= 18000, self.port
        self.sock.settimeout(0.2)
        self.stopping = False

    def start(self):
        super().start()
        return self

    def run(self):
        while not self.stopping:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def stop(self):
        self.stopping = True
        try:
            self.sock.close()
        except OSError:
            pass

    def _serve(self, conn):
        conn.settimeout(10)
        try:
            tls = self.ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            with self.lock:
                self.handshake_failures += 1
            conn.close()
            return
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head, _, rest = buf.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            method, path, version = lines[0].split(" ", 2)
            headers = {}
            for ln in lines[1:]:
                k, _, v = ln.partition(":")
                headers[k.strip().lower()] = v.strip()
            want = int(headers.get("content-length", "0"))
            body = rest
            while len(body) < want:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                body += chunk
            cert = tls.getpeercert()
            cn = None
            if cert:
                for rdn in cert.get("subject", ()):
                    for k, v in rdn:
                        if k == "commonName":
                            cn = v
            req = Request(method, path, version, headers, body[:want], head, cn, tls.version())
            with self.lock:
                self.requests.append(req)
            resp = self.handler(req)
            self._send(tls, resp)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def _send(self, tls, resp):
        if isinstance(resp, Reset):
            import struct as _struct
            tls.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, _struct.pack("ii", 1, 0))
            tls.close()
            return
        if isinstance(resp, Raw):
            tls.sendall(resp.data)
            return
        if isinstance(resp, Stream):
            head = "HTTP/1.0 %d X\r\n" % resp.status + "".join("%s: %s\r\n" % kv for kv in resp.headers.items()) + "\r\n"
            tls.sendall(head.encode())
            for c in resp.chunks:
                tls.sendall(c)
            return
        status, headers, body = resp
        h = dict(headers)
        if not any(k.lower() == "content-length" for k in h):
            h["Content-Length"] = str(len(body))
        head = "HTTP/1.0 %d X\r\n" % status + "".join("%s: %s\r\n" % kv for kv in h.items()) + "\r\n"
        tls.sendall(head.encode() + body)


# ---- fakes for what agent 4 writes (only when the real import fails) -------------------------

def install_fakes():
    try:
        import edragent.event      # noqa: F401
        import edragent.paths      # noqa: F401
        import edragent.ids        # noqa: F401
        return False
    except Exception:
        pass
    import time
    pkg = sys.modules.get("edragent")
    if pkg is None:
        pkg = types.ModuleType("edragent")
        pkg.__path__ = [os.path.join(CODE, "edragent")]
        sys.modules["edragent"] = pkg

    def make_event(kind, source, sev, summary, *, details=None, ts_ms=None, src_ip="", src_trust="none",
                   dst_ip="", dst_port=None, proto=None, proc=None, community_id=None):
        ts_ms = ts_ms if ts_ms is not None else int(time.time() * 1000)
        sec, ms = divmod(int(ts_ms), 1000)
        ev = {"v": 1, "agent_ver": "0.1.0", "boot_id": "", "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sec)) + ".%03dZ" % ms,
              "sev": sev, "kind": kind, "source": source, "summary": summary, "src_ip": src_ip,
              "src_trust": src_trust if src_ip else "none"}
        if details:
            ev["details"] = dict(details)
        if dst_port is not None:
            ev["dst_port"] = dst_port
        if proto:
            ev["proto"] = proto
        return ev

    m = types.ModuleType("edragent.event")
    m.make_event = make_event
    sys.modules["edragent.event"] = m
    pkg.event = m

    ids = types.ModuleType("edragent.ids")
    state = {"seq": 0}

    def stamp(ev):
        state["seq"] += 1
        ev["id"], ev["epoch"], ev["seq"] = "0000abcd:%d" % state["seq"], 0xabcd, state["seq"]
        return ev
    ids.stamp = stamp
    ids.current = lambda: (0xabcd, state["seq"])
    sys.modules["edragent.ids"] = ids
    pkg.ids = ids

    paths = types.ModuleType("edragent.paths")

    class Paths:
        def __init__(self, root=None, lib_dir=None):
            self.root = root if root is not None else os.environ.get("EDR_AGENT_ROOT", "")
            self.dev = bool(self.root)
            self.lib_dir = lib_dir or CODE
            self.proc_dir = "/proc"

        def _p(self, p):
            return os.path.join(self.root, p.lstrip("/")) if self.root else p
        etc_dir = property(lambda s: s._p("/etc/edr-agent"))
        pause_json = property(lambda s: os.path.join(s.etc_dir, "pause.json"))
        local_conf = property(lambda s: os.path.join(s.etc_dir, "local.conf"))
        state_dir = property(lambda s: s._p("/var/lib/edr-agent"))
        identity_dir = property(lambda s: os.path.join(s.state_dir, "identity"))
        spool_dir = property(lambda s: os.path.join(s.state_dir, "spool"))
        host_id = property(lambda s: os.path.join(s.state_dir, "host-id"))
        ban_state = property(lambda s: os.path.join(s.state_dir, "ban-state.json"))
        run_dir = property(lambda s: s._p("/run/edr-agent"))
        bans_json = property(lambda s: os.path.join(s.run_dir, "bans.json"))
        droplet_id = property(lambda s: s._p("/run/edr-droplet-id"))
        inventory_json = property(lambda s: s._p("/run/edr-inventory/inventory.json"))
        bans_counters = property(lambda s: s._p("/run/edr-bans/counters.json"))
    paths.Paths = Paths
    sys.modules["edragent.paths"] = paths
    pkg.paths = paths
    return True


FAKED = install_fakes()


class Env:
    """A temporary agent root with every directory the hub-side modules use."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="a5root-")
        _LIVE.add(self.root)
        self._old = os.environ.get("EDR_AGENT_ROOT")
        os.environ["EDR_AGENT_ROOT"] = self.root
        from edragent.paths import Paths
        self.paths = Paths()
        for d in (self.paths.state_dir, self.paths.run_dir, self.paths.etc_dir):
            os.makedirs(d, 0o700, exist_ok=True)
        os.makedirs(os.path.dirname(self.paths.droplet_id), exist_ok=True)

    def set_droplet(self, value):
        with open(self.paths.droplet_id, "w") as f:
            f.write(value + "\n")

    def cleanup(self):
        if self._old is None:
            os.environ.pop("EDR_AGENT_ROOT", None)
        else:
            os.environ["EDR_AGENT_ROOT"] = self._old
        shutil.rmtree(self.root, ignore_errors=True)
        _LIVE.discard(self.root)


def make_identity(env, pki, hub_port, *, gen=1, addresses=("127.0.0.1",), cn="11111111-2222-4333-8444-555555555555",
                  days=365, enroll_port=8444):
    """Write identity/gen-N and point current at it, as an enrolled host would have."""
    from edragent import identity as idn
    d = os.path.join(str(env.paths.identity_dir), "gen-%d" % gen)
    os.makedirs(d, 0o700, exist_ok=True)
    cert, key = pki.client(name="g%d" % gen, cn=cn, days=days)
    shutil.copyfile(cert, os.path.join(d, "client.pem"))
    shutil.copyfile(key, os.path.join(d, "client.key"))
    os.chmod(os.path.join(d, "client.key"), 0o600)
    shutil.copyfile(pki.ca_pem, os.path.join(d, "ca.pem"))
    idn.write_hub_conf(os.path.join(d, "hub.conf"), list(addresses), hub_port, enroll_port, cn, pki.der_sha256())
    idn.flip_current(env.paths, "gen-%d" % gen)
    return d


def wait_for(cond, timeout=10.0, step=0.02):
    import time
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(step)
    return cond()


# ---- an enrollment hub and a fleet hub of one CA ------------------------------------------------

class HubPair:
    """What an enrolling host talks to: the enrollment listener (no client certificate: /v1/ca and
    /v1/enroll) and the fleet listener (client certificate: policy, heartbeat, events, renew,
    deregister). `responses` overrides a path with a callable(request) -> response."""

    def __init__(self, pki=None, *, uuid_="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", token_id="tok12345",
                 secret="secretsecret1234", addresses=("127.0.0.1",), state="pending", cert_days=365):
        import time as _t
        self._time = _t
        self.pki = pki or PKI()
        self.own_pki = pki is None
        self.uuid = uuid_
        self.token_id, self.secret = token_id, secret
        self.addresses = list(addresses)
        self.state = state
        self.cert_days = cert_days
        self.responses = {}
        self.enroll_tweak = None
        self.rev = "0123456789abcdef"
        self.peers = []
        self.events = []
        self.heartbeats = []
        self.deregistered = []
        self.fleet = FakeHub(self.pki, self._fleet_handler).start()
        self.enroll = FakeHub(self.pki, self._enroll_handler, mtls=False).start()

    @property
    def token(self):
        return "%s.%s.%s" % (self.token_id, self.secret, self.pki.der_sha256())

    @property
    def fleet_port(self):
        return self.fleet.port

    @property
    def enroll_port(self):
        return self.enroll.port

    def stop(self):
        self.fleet.stop()
        self.enroll.stop()
        if self.own_pki:
            self.pki.cleanup()

    def policy_doc(self):
        return {"rev": self.rev, "hub_time": int(self._time.time()), "hub_addresses": self.addresses,
                "port": self.fleet.port, "bans": [], "feeds": {}, "peers": list(self.peers)}

    def _enroll_handler(self, req):
        if req.path in self.responses:
            return self.responses[req.path](req)
        if req.method == "GET" and req.path == "/v1/ca":
            return (200, {"Content-Type": "application/x-pem-file"}, self.pki.pem().encode())
        if req.method == "POST" and req.path == "/v1/enroll":
            d = req.json()
            if d.get("token") != self.token_id + "." + self.secret:
                return err(401, "invalid_token")
            cert = self.pki.client_from_csr(d["csr"], self.uuid, self.cert_days)
            rep = {"host_uuid": self.uuid, "certificate": cert, "ca": self.pki.pem(), "hub_addresses": self.addresses,
                   "port": self.fleet.port, "not_after": "2027-11-23T12:00:00.000Z", "state": self.state}
            if self.enroll_tweak:
                self.enroll_tweak(rep)
            return reply(200, rep)
        return err(404, "not_found")

    def _fleet_handler(self, req):
        if req.path in self.responses:
            return self.responses[req.path](req)
        if req.path == "/v1/policy" and req.method == "GET":
            if req.headers.get("if-none-match") == '"%s"' % self.rev:
                return (304, {}, b"")
            return reply(200, self.policy_doc(), {"ETag": '"%s"' % self.rev})
        if req.path == "/v1/heartbeat" and req.method == "POST":
            hb = req.json()
            self.heartbeats.append(hb)
            return reply(200, {"hub_time": int(self._time.time()), "policy_rev": self.rev, "min_client_schema": 0})
        if req.path == "/v1/events" and req.method == "POST":
            b = req.json()
            self.events.extend(b["events"])
            return reply(200, {"accepted": len(b["events"]), "duplicate": 0, "dropped_low": 0})
        if req.path == "/v1/renew" and req.method == "POST":
            d = req.json()
            cert = self.pki.client_from_csr(d["csr"], req.peer_cn, self.cert_days)
            return reply(200, {"certificate": cert, "not_after": "2027-11-23T12:00:00.000Z"})
        if req.path == "/v1/deregister" and req.method == "POST":
            self.deregistered.append((req.peer_cn, req.json()))
            return reply(200, {})
        return err(404, "not_found")
