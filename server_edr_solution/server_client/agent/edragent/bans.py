"""The local ban engine (client PLAN 4.2): never-ban list, triggers, ladder, budget, pause, bans.json.

The unprivileged agent decides and writes /run/edr-agent/bans.json; the root helper edr-bans
applies it. Everything the hub may send is bounded here as well (peers only in P2).

What `observe()` reads from an event (the keys the sources set):

    ssh.fail                 src_ip, src_trust=tcp
    ssh.login                src_ip, src_trust=tcp          (remembered 30 days: never banned for SSH failures)
    canary.tripwire          src_ip, src_trust=tcp, details.status in 403/404/444, details.ban is not False
    suricata.alert           src_ip, src_trust=tcp, proto TCP, dst_port, details.app_proto, details.stream,
                             details.pkts_toserver, details.pkts_toclient, details.sid (or signature_id)
                             and the sid listed in edr-ban-sids.txt (a missing list means no Suricata bans)
    nginx.marker.window_update   src_ip, src_trust=tcp
    edr.bigconn              src_ip, src_trust=tcp

Only src_trust=tcp counts, only events under 15 minutes old count, IPv6 counts by /64.
"""

import bisect
import collections
import ipaddress
import json
import os
import re
import struct
import threading
import time

from . import event as _event
from .spool import atomic_write, parse_rfc3339, read_file_safe, read_json_safe, rfc3339

# ---- Constants compiled in (PLAN 4.2: guards are not keys) ----------------------------------

NEVER_V4 = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
            "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "224.0.0.0/3")
NEVER_V6 = ("::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")

MIN_PREFIX_BAN = {4: 16, 6: 32}
MIN_PREFIX_FEED = {4: 12, 6: 29}
COVER_CAP_BAN4 = 2 ** 32 // 1000                # 0.1% of IPv4
COVER_CAP_BAN6 = 16 * 2 ** 96                   # 16 x /32
COVER_CAP_FEED4 = 2 ** 32 * 2 // 100            # 2% of IPv4
COVER_CAP_FEED6 = 1024 * 2 ** 96                # 1024 x /32
HUB_ADDRESSES_MAX = 4
PEERS_MAX = 512
BANS_MAX = 10_000
FEED_CIDRS_MAX = 200_000
PEER_TTL_S = 72 * 3600

EVENT_MAX_AGE_S = 900
COUNTER_KEYS_MAX = 50_000
ACCEPTED_DAYS_S = 30 * 86400
BANS_WRITE_MIN_S = 5.0
BANS_REFRESH_S = 300.0
NEVER_REFRESH_S = 30.0
PAUSE_CHECK_S = 5.0
STATE_SAVE_MIN_S = 2.0
EMPTY_STICKY_S = 900.0
MAX_TTL_S = 7 * 86400

DEFAULTS = {
    "auto_ban": "on", "proxy_mode": "auto",
    "ssh_fail": "5/10m", "tripwire": "5/5m", "suricata": "3/10m", "suricata_sigs": "2/10m",
    "window_update": "3/10m", "bigconn_repeat": "2/1h",
    "ban_budget_per_hour": 30, "ban_max_active": 1000,
    "ban_ladder": "1h,6h,24h,7d", "ban_memory": "14d",
}

BAN_SOURCES = ("local", "fleet", "operator")
BAN_REASONS = ("ssh_fail", "tripwire", "suricata", "bigconn", "window_update", "fleet_quorum", "operator")
TRIGGERS = ("ssh_fail", "tripwire", "suricata", "window_update", "bigconn")
EVIDENCE = {"ssh_fail": "log", "tripwire": "log", "window_update": "log", "suricata": "tcp", "bigconn": "tcp"}
WEB_TRIGGERS = ("tripwire", "window_update", "suricata")
SCANNER_STATUS = (403, 404, 444)
SURICATA_SIDS_PATH = "/var/lib/suricata/rules/edr-ban-sids.txt"


# ---- Config helpers (the config object is a mapping of sections and keys) -------------------

def cfg_get(cfg, section, key, default=None):
    try:
        val = cfg[section][key]
    except (KeyError, TypeError, IndexError, AttributeError):
        try:
            val = getattr(getattr(cfg, section), key)
        except AttributeError:
            return default
    return default if val is None else val


_UNITS = {
    "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
    "d": 86400, "day": 86400, "days": 86400, "w": 604800, "week": 604800, "weeks": 604800,
}
_DUR_PART = re.compile(r"\s*(\d+(?:\.\d+)?)\s*([a-zA-Z]*)\s*")


def parse_duration(value, default=None):
    """Seconds from 30s, 10m, 1h, 7d, '14 days', '1h30m' or a plain number; default if unparsable."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value) if value >= 0 else default
    if not isinstance(value, str):
        return default
    text = value.strip()
    if not text or len(text) > 40:
        return default
    pos, total = 0, 0.0
    while pos < len(text):
        m = _DUR_PART.match(text, pos)
        if not m or m.end() == pos:
            return default
        unit = m.group(2).lower()
        if unit == "" and pos == 0 and m.end() == len(text):
            mult = 1
        elif unit in _UNITS:
            mult = _UNITS[unit]
        else:
            return default
        total += float(m.group(1)) * mult
        pos = m.end()
    return total


def parse_rate(value, default):
    """('5/10m' or '5 per 10 min' or (5, 600)) -> (count, window_seconds)."""
    if isinstance(value, (tuple, list)) and len(value) == 2:
        try:
            return int(value[0]), float(value[1])
        except (TypeError, ValueError):
            return default
    if isinstance(value, str):
        m = re.match(r"^\s*(\d{1,6})\s*(?:/|per)\s*(.+?)\s*\Z", value, re.I)
        if m:
            w = parse_duration(m.group(2))
            if w and w > 0 and int(m.group(1)) > 0:
                return int(m.group(1)), w
    return default


def as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(x).strip() for x in value if str(x).strip()]
    return [x.strip() for x in str(value).split(",") if x.strip()]


def as_int(value, default):
    try:
        if isinstance(value, bool):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


# ---- Addresses ----------------------------------------------------------------------------

_V4_RE = re.compile(r"^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}\Z")
_PREFIX_RE = re.compile(r"^(?:0|[1-9][0-9]{0,2})\Z")


def parse_ip(text):
    """An ipaddress object, or None. ::ffff:a.b.c.d maps to IPv4 first. Rejects whitespace,
    leading zeros, zone IDs, prefix lengths and anything not ASCII."""
    if not isinstance(text, str) or not text or len(text) > 45:
        return None
    if not text.isascii() or any(c.isspace() or ord(c) < 33 or ord(c) == 127 for c in text):
        return None
    if "%" in text or "/" in text:
        return None
    try:
        if ":" in text:
            ip = ipaddress.IPv6Address(text)
            if ip.ipv4_mapped is not None:
                return ip.ipv4_mapped
            return ip
        if not _V4_RE.match(text):
            return None
        return ipaddress.IPv4Address(text)
    except ValueError:
        return None


def norm_ip(text):
    """The canonical string of an address, or None."""
    ip = parse_ip(text)
    return None if ip is None else str(ip)


def parse_net(text):
    """An ip_network with no host bits, or None. A bare address is a /32 or /128."""
    if not isinstance(text, str) or not text or len(text) > 64:
        return None
    if "/" not in text:
        ip = parse_ip(text)
        if ip is None:
            return None
        return ipaddress.ip_network((ip, ip.max_prefixlen))
    addr, _, plen = text.partition("/")
    if not _PREFIX_RE.match(plen):
        return None
    ip = parse_ip(addr)
    if ip is None:
        return None
    n = int(plen)
    if ":" in addr and ip.version == 4:
        # ::ffff:a.b.c.d/N with N >= 96 is the IPv4 prefix N - 96
        if n < 96:
            return None
        n -= 96
    if n > ip.max_prefixlen:
        return None
    try:
        return ipaddress.ip_network((ip, n), strict=True)
    except ValueError:
        return None


def norm_cidr(text):
    net = parse_net(text)
    return None if net is None else str(net)


def ban_key(ip):
    """What a ban and its counters are keyed on: the address for IPv4, the /64 for IPv6."""
    if ip.version == 4:
        return str(ip)
    return str(ipaddress.ip_network((ip, 64), strict=False))


def net_for(ip):
    if ip.version == 4:
        return ipaddress.ip_network((ip, 32))
    return ipaddress.ip_network((ip, 64), strict=False)


class NeverList:
    """Sorted, merged intervals per family; membership and overlap by bisect."""

    def __init__(self, nets=()):
        self._iv = {4: ([], []), 6: ([], [])}      # version -> (starts, ends)
        self.nets = []
        self.extend(nets)

    def extend(self, nets):
        raw = {4: [], 6: []}
        for n in list(self.nets) + list(nets):
            raw[n.version].append((int(n.network_address), int(n.broadcast_address)))
        self.nets = list(self.nets) + list(nets)
        for v in (4, 6):
            merged = []
            for lo, hi in sorted(raw[v]):
                if merged and lo <= merged[-1][1] + 1:
                    if hi > merged[-1][1]:
                        merged[-1][1] = hi
                else:
                    merged.append([lo, hi])
            self._iv[v] = ([m[0] for m in merged], [m[1] for m in merged])

    def overlaps(self, net):
        starts, ends = self._iv[net.version]
        lo, hi = int(net.network_address), int(net.broadcast_address)
        i = bisect.bisect_right(starts, hi) - 1
        return i >= 0 and ends[i] >= lo

    def contains(self, ip):
        return self.overlaps(ipaddress.ip_network((ip, ip.max_prefixlen)))


LITERAL_NEVER = NeverList([ipaddress.ip_network(x) for x in NEVER_V4 + NEVER_V6])


def sanitize_bans(cidrs, never=None, kind="ban"):
    """Validate candidate ban (or feed) CIDRs the way edr-bans does.

    Returns (accepted: list[ip_network], refused: list[{"cidr", "why"}]). Order of checks:
    parse, never-ban literals, the dynamic never-ban list, minimum prefix, overlap with an
    accepted entry (the wider one is kept), coverage cap (smallest entries first). IPv6 is
    never taken finer than a /64 for a ban."""
    never = never or LITERAL_NEVER
    minp = MIN_PREFIX_BAN if kind == "ban" else MIN_PREFIX_FEED
    cap4 = COVER_CAP_BAN4 if kind == "ban" else COVER_CAP_FEED4
    cap6 = COVER_CAP_BAN6 if kind == "ban" else COVER_CAP_FEED6
    refused = []
    cand = []
    seen = set()
    for c in cidrs:
        net = parse_net(c) if isinstance(c, str) else None
        if net is None:
            refused.append({"cidr": str(c)[:64], "why": "invalid"})
            continue
        if net in seen:
            continue
        seen.add(net)
        if LITERAL_NEVER.overlaps(net):
            refused.append({"cidr": str(net), "why": "never-ban literal"})
        elif never is not LITERAL_NEVER and never.overlaps(net):
            refused.append({"cidr": str(net), "why": "never-ban list"})
        elif net.prefixlen < minp[net.version]:
            refused.append({"cidr": str(net), "why": "prefix too short"})
        elif kind == "ban" and net.version == 6 and net.prefixlen > 64:
            refused.append({"cidr": str(net), "why": "IPv6 bans are /64"})
        else:
            cand.append(net)
    # Overlap between candidates: keep the widest.
    cand.sort(key=lambda n: (n.version, int(n.network_address), n.prefixlen))
    kept = []
    for n in cand:
        if kept and kept[-1].version == n.version and n.subnet_of(kept[-1]):
            refused.append({"cidr": str(n), "why": "inside a wider entry"})
            continue
        kept.append(n)
    # Coverage cap: take the narrowest first so one huge entry cannot crowd small ones out.
    accepted = []
    cover = {4: 0, 6: 0}
    caps = {4: cap4, 6: cap6}
    for n in sorted(kept, key=lambda n: (n.version, -n.prefixlen, int(n.network_address))):
        size = n.num_addresses
        if cover[n.version] + size > caps[n.version]:
            refused.append({"cidr": str(n), "why": "coverage cap"})
            continue
        cover[n.version] += size
        accepted.append(n)
    accepted.sort(key=lambda n: (n.version, int(n.network_address)))
    return accepted, refused


# ---- Reading the machine (own addresses, gateway, resolvers, SSH sessions) ------------------

def own_addresses(proc_dir="/proc", resolv_conf="/etc/resolv.conf"):
    """Every local interface address, the default gateways and the resolvers, as ip_network /32 or /128."""
    out = []

    def add(ip):
        if ip is not None and not ip.is_unspecified:
            out.append(ipaddress.ip_network((ip, ip.max_prefixlen)))

    raw = read_file_safe(os.path.join(proc_dir, "net", "fib_trie"), 1024 * 1024)
    if raw:
        last = None
        for line in raw.decode("ascii", "replace").splitlines():
            s = line.strip()
            if s.startswith("|--"):
                last = parse_ip(s[3:].strip())
            elif s.startswith("/32 host LOCAL") and last is not None:
                add(last)
    raw = read_file_safe(os.path.join(proc_dir, "net", "if_inet6"), 256 * 1024)
    if raw:
        for line in raw.decode("ascii", "replace").splitlines():
            f = line.split()
            if f and len(f[0]) == 32:
                try:
                    add(ipaddress.IPv6Address(bytes.fromhex(f[0])))
                except ValueError:
                    pass
    raw = read_file_safe(os.path.join(proc_dir, "net", "route"), 256 * 1024)
    if raw:
        for line in raw.decode("ascii", "replace").splitlines()[1:]:
            f = line.split()
            if len(f) >= 3 and f[1] == "00000000" and len(f[2]) == 8:
                try:
                    add(ipaddress.IPv4Address(struct.pack("<I", int(f[2], 16))))
                except (ValueError, struct.error):
                    pass
    raw = read_file_safe(os.path.join(proc_dir, "net", "ipv6_route"), 256 * 1024)
    if raw:
        for line in raw.decode("ascii", "replace").splitlines():
            f = line.split()
            if len(f) >= 6 and f[0] == "0" * 32 and f[1] == "00" and len(f[4]) == 32:
                try:
                    add(ipaddress.IPv6Address(bytes.fromhex(f[4])))
                except ValueError:
                    pass
    raw = read_file_safe(resolv_conf, 64 * 1024)
    if raw:
        for line in raw.decode("utf-8", "replace").splitlines():
            f = line.split()
            if len(f) >= 2 and f[0] == "nameserver":
                add(parse_ip(f[1].split("%")[0]))
    uniq = {}
    for n in out:
        uniq[str(n)] = n
    return list(uniq.values())[:256]


def utmp_remote_addresses(path="/run/utmp"):
    """Remote addresses of login records (struct utmp, x86_64 glibc, 384 bytes each). Best effort:
    an authenticated session is the only kind that writes one."""
    raw = read_file_safe(path, 4 * 1024 * 1024)
    out = []
    if not raw:
        return out
    for off in range(0, len(raw) - 383, 384):
        rec = raw[off:off + 384]
        ut_type = struct.unpack_from("<h", rec, 0)[0]
        if ut_type != 7:                    # USER_PROCESS
            continue
        w = struct.unpack_from("<4I", rec, 348)
        if w[1] == w[2] == w[3] == 0:
            if w[0]:
                out.append(ipaddress.ip_network((ipaddress.IPv4Address(struct.pack("<I", w[0])), 32)))
        else:
            try:
                out.append(ipaddress.ip_network((ipaddress.IPv6Address(struct.pack("<4I", *w)), 128)))
            except ValueError:
                pass
        if len(out) >= 256:
            break
    return out


def hub_addresses_from_identity(identity_dir):
    """Hub addresses from the hub.conf of every identity generation present (PLAN 5, step 4)."""
    out = []
    try:
        names = sorted(os.listdir(str(identity_dir)))
    except OSError:
        return out
    for name in names:
        if not re.match(r"^gen-[0-9]+\Z", name):
            continue
        raw = read_file_safe(os.path.join(str(identity_dir), name, "hub.conf"), 16 * 1024)
        if not raw:
            continue
        for line in raw.decode("utf-8", "replace").splitlines():
            k, sep, v = line.partition("=")
            if sep and k.strip() == "addresses":
                for a in v.split(",")[:HUB_ADDRESSES_MAX]:
                    ip = parse_ip(a.strip())
                    if ip is not None:
                        out.append(ipaddress.ip_network((ip, ip.max_prefixlen)))
    return out


# ---- Proxy detection ----------------------------------------------------------------------

# ---- Sliding-window counters --------------------------------------------------------------

class _Counter:
    """Per-key event times in a window, LRU capped. add() returns the number counted now."""

    def __init__(self, window_s, cap=COUNTER_KEYS_MAX):
        self.window = float(window_s)
        self.cap = cap
        self.d = collections.OrderedDict()

    def add(self, key, ts, token=None):
        dq = self.d.get(key)
        if dq is None:
            dq = collections.deque()
            self.d[key] = dq
            if len(self.d) > self.cap:
                self.d.popitem(last=False)
        else:
            self.d.move_to_end(key)
        dq.append((ts, token))
        while dq and dq[0][0] < ts - self.window:
            dq.popleft()
        if len(dq) > 1000:
            dq.popleft()
        return dq

    def clear(self, key):
        self.d.pop(key, None)


# ---- The engine ---------------------------------------------------------------------------

class BanEngine:
    def __init__(self, cfg, paths, *, proc_dir=None, resolv_conf="/etc/resolv.conf",
                 utmp_path="/run/utmp", clock=time.time):
        self.cfg = cfg
        self.paths = paths
        self.proc_dir = proc_dir or str(getattr(paths, "proc_dir", "/proc"))
        self.resolv_conf = resolv_conf
        self.utmp_path = utmp_path
        self.clock = clock
        self.lock = threading.RLock()
        self.state_path = str(paths.ban_state)
        self.bans_path = str(paths.bans_json)
        self.pause_path = str(paths.pause_json)
        self.cmd_path = os.path.join(os.path.dirname(self.state_path), "ban-cmd.json")
        self.sids_path = str(getattr(paths, "ban_sids", "") or "") or (
            str(getattr(paths, "root", os.environ.get("EDR_AGENT_ROOT", "")) or "").rstrip("/") + SURICATA_SIDS_PATH)
        self.inventory_path = str(getattr(paths, "inventory_json", "") or "")
        self.counters_path = str(getattr(paths, "bans_counters", "") or "")
        self.identity_dir = str(getattr(paths, "identity_dir", "") or "")
        self._read_config()
        self.bans = {}            # cidr -> {"cidr", "expires", "source", "reason", "rung", "since"}
        self.memory = {}          # key -> {"rung", "last"}
        self.allow = {}           # key -> until (after unban)
        self.accepted = collections.OrderedDict()   # ip -> last Accepted login (epoch)
        self.peers = {}           # ip str -> expiry (epoch)
        self.hub_policy_addrs = []
        self._hour = collections.deque()           # start times of local bans in the last hour
        self._budget_note = 0.0
        self._internal_note = {}
        self._apply_error = ""
        self._apply_error_at = 0.0
        self._refused = 0
        self._counters = {}
        self._suricata_sigs = {}
        self._real_ip = False
        self._inv_at = -1e9
        self._never_at = -1e9
        self._never = NeverList()
        self._dyn_never = []
        self._paused_until = 0.0
        self._pause_at = -1e9
        self._bans_written_at = -1e9
        self._bans_written_sig = None
        self._bans_dirty = True
        self._last_written_nonempty = False
        self._empty_until = 0.0
        self._state_dirty = False
        self._state_saved_at = -1e9
        self._sids = None
        self._sids_at = -1e9
        self._cmd_mtime = None
        self._load_state()
        self._refresh_never(self.clock(), force=True)

    # ---- configuration ----

    def _read_config(self):
        c, g = self.cfg, cfg_get
        mode = str(g(c, "bans", "auto_ban", DEFAULTS["auto_ban"])).strip().lower()
        self.auto_ban = mode if mode in ("on", "observe", "off") else "on"
        pm = str(g(c, "bans", "proxy_mode", DEFAULTS["proxy_mode"])).strip().lower()
        self.proxy_mode = pm if pm in ("auto", "on", "off") else "auto"
        self.admin_ips = as_list(g(c, "bans", "admin_ip", ""))
        self.allow_cidrs = as_list(g(c, "bans", "allow_cidr", ""))
        self.vpc_cidr = as_list(g(c, "sites", "vpc_cidr", ""))
        self.extra_addresses = as_list(g(c, "sites", "extra_addresses", ""))
        self.rates = {}
        for name in ("ssh_fail", "tripwire", "suricata", "window_update", "bigconn_repeat"):
            dflt = parse_rate(DEFAULTS[name], (5, 600.0))
            self.rates[name] = parse_rate(g(c, "thresholds", name, DEFAULTS[name]), dflt)
        self.rates["suricata_sigs"] = parse_rate(g(c, "thresholds", "suricata_sigs", DEFAULTS["suricata_sigs"]), (2, 600.0))
        self.budget = max(1, as_int(g(c, "thresholds", "ban_budget_per_hour", DEFAULTS["ban_budget_per_hour"]), 30))
        self.max_active = max(1, as_int(g(c, "thresholds", "ban_max_active", DEFAULTS["ban_max_active"]), 1000))
        ladder = []
        for item in as_list(g(c, "thresholds", "ban_ladder", DEFAULTS["ban_ladder"])):
            d = parse_duration(item)
            if d and d > 0:
                ladder.append(min(d, MAX_TTL_S))
        self.ladder = ladder or [3600.0, 21600.0, 86400.0, 604800.0]
        self.memory_s = parse_duration(g(c, "thresholds", "ban_memory", DEFAULTS["ban_memory"]), 14 * 86400.0) or 14 * 86400.0
        self.counters = {}
        for trig, rate in (("ssh_fail", "ssh_fail"), ("tripwire", "tripwire"), ("suricata", "suricata"),
                           ("window_update", "window_update"), ("bigconn", "bigconn_repeat")):
            self.counters[trig] = _Counter(self.rates[rate][1])
        self.sig_counter = _Counter(self.rates["suricata_sigs"][1])

    # ---- persisted state ----

    def _load_state(self):
        st = read_json_safe(self.state_path, 8 * 1024 * 1024)
        if not isinstance(st, dict) or st.get("v") != 1:
            return
        now = self.clock()
        for b in st.get("bans", [])[:BANS_MAX] if isinstance(st.get("bans"), list) else []:
            if not isinstance(b, dict):
                continue
            cidr = norm_cidr(b.get("cidr"))
            exp = b.get("expires")
            if cidr is None or not isinstance(exp, (int, float)) or isinstance(exp, bool) or exp <= now:
                continue
            src = b.get("source") if b.get("source") in BAN_SOURCES else "local"
            rsn = b.get("reason") if b.get("reason") in BAN_REASONS else "operator"
            rung = b.get("rung") if isinstance(b.get("rung"), int) else 0
            self.bans[cidr] = {"cidr": cidr, "expires": int(exp), "source": src, "reason": rsn,
                               "rung": max(0, rung), "since": int(b.get("since", now)) if isinstance(b.get("since"), (int, float)) else int(now)}
        for name, store in (("memory", self.memory), ("allow", self.allow), ("peers", self.peers)):
            d = st.get(name)
            if not isinstance(d, dict):
                continue
            for k, v in list(d.items())[:5000]:
                if name == "memory":
                    if isinstance(v, dict) and isinstance(v.get("rung"), int) and isinstance(v.get("last"), (int, float)) \
                            and now - v["last"] <= self.memory_s:
                        store[str(k)[:64]] = {"rung": max(0, v["rung"]), "last": v["last"]}
                elif isinstance(v, (int, float)) and not isinstance(v, bool) and v > now:
                    key = norm_ip(k) if name == "peers" else str(k)[:64]
                    if key:
                        store[key] = v
        d = st.get("accepted")
        if isinstance(d, dict):
            for k, v in list(d.items())[:5000]:
                ip = norm_ip(k)
                if ip and isinstance(v, (int, float)) and now - v <= ACCEPTED_DAYS_S:
                    self.accepted[ip] = v

    def _save_state(self, now, force=False):
        if not self._state_dirty:
            return
        if not force and now - self._state_saved_at < STATE_SAVE_MIN_S:
            return
        doc = {"v": 1, "saved_at": int(now),
               "bans": sorted(self.bans.values(), key=lambda b: b["cidr"]),
               "memory": self.memory, "allow": self.allow,
               "accepted": dict(self.accepted), "peers": self.peers}
        try:
            atomic_write(self.state_path, json.dumps(doc, separators=(",", ":")), 0o600)
            self._state_dirty = False
            self._state_saved_at = now
        except OSError as exc:
            self._note_error("cannot save ban state: %s" % (exc.strerror or exc.__class__.__name__), now)

    def flush(self):
        """Write the ban state and bans.json now (shutdown)."""
        with self.lock:
            now = self.clock()
            self._save_state(now, force=True)
            self._write_bans_json(now, force=True)

    # ---- errors ----

    def _note_error(self, msg, now):
        self._apply_error = msg[:256]
        self._apply_error_at = now

    def note_apply_error(self, msg):
        """The policy poller reports a refused document here so the heartbeat carries it."""
        with self.lock:
            self._note_error(str(msg), self.clock())

    def last_apply_error(self):
        with self.lock:
            now = self.clock()
            parts = []
            if self._apply_error and now - self._apply_error_at < 3600:
                parts.append(self._apply_error)
            c = read_json_safe(self.counters_path, 256 * 1024) if self.counters_path else None
            la = c.get("last_apply") if isinstance(c, dict) else None
            if isinstance(la, dict) and la.get("ok") is False and isinstance(la.get("error"), str) and la["error"]:
                parts.append("edr-bans: " + la["error"][:200])
            return "; ".join(parts)[:512]

    # ---- the never-ban list ----

    def _refresh_never(self, now, force=False):
        if not force and now - self._never_at < NEVER_REFRESH_S:
            return
        self._never_at = now
        dyn = {}

        def add(net):
            if net is not None:
                dyn[str(net)] = net

        for a in self.admin_ips + self.allow_cidrs + self.vpc_cidr + self.extra_addresses:
            add(parse_net(a))
        if self.identity_dir:
            for n in hub_addresses_from_identity(self.identity_dir):
                add(n)
        for n in self.hub_policy_addrs:
            add(n)
        for ip in list(self.peers):
            add(parse_net(ip))
        for n in own_addresses(self.proc_dir, self.resolv_conf):
            add(n)
        for n in utmp_remote_addresses(self.utmp_path):
            add(n)
        items = sorted(dyn.values(), key=lambda n: (n.version, int(n.network_address), n.prefixlen))[:2048]
        sig = [str(n) for n in items]
        if sig != self._dyn_never:
            self._bans_dirty = True
        self._dyn_never = sig
        self._never = NeverList(items)

    def never_contains(self, ip):
        """True when the address is on the literal list or the dynamic list (literals first)."""
        if LITERAL_NEVER.contains(ip):
            return True
        return self._never.contains(ip)

    def _never_overlaps(self, net):
        return LITERAL_NEVER.overlaps(net) or self._never.overlaps(net)

    # ---- the policy (P2: peers and hub addresses) ----

    def set_policy(self, doc):
        """Apply the never-ban part of a validated policy document. None clears peers.

        Peers are single addresses (at most 512), kept 72 hours from the last document that
        contains them; hub addresses at most 4. A peer that is a never-ban literal is ignored."""
        with self.lock:
            now = self.clock()
            if doc is None:
                self.peers = {}
                self.hub_policy_addrs = []
                self._state_dirty = True
                self._refresh_never(now, force=True)
                return
            peers = {}
            raw = doc.get("peers", []) if isinstance(doc, dict) else []
            if not isinstance(raw, list) or len(raw) > PEERS_MAX:
                self._note_error("policy refused: more than %d peers" % PEERS_MAX, now)
                return
            for p in raw:
                ip = parse_ip(p) if isinstance(p, str) else None
                if ip is None or LITERAL_NEVER.contains(ip):
                    continue
                peers[str(ip)] = now + PEER_TTL_S
            hubs = []
            rawh = doc.get("hub_addresses", []) if isinstance(doc, dict) else []
            if isinstance(rawh, list):
                for a in rawh[:HUB_ADDRESSES_MAX]:
                    ip = parse_ip(a) if isinstance(a, str) else None
                    if ip is not None:
                        hubs.append(ipaddress.ip_network((ip, ip.max_prefixlen)))
            self._state_dirty = True
            self.peers = peers
            self.hub_policy_addrs = hubs
            self._refresh_never(now, force=True)

    # ---- pause ----

    def _check_pause(self, now, force=False):
        out = []
        if not force and now - self._pause_at < PAUSE_CHECK_S:
            return out
        self._pause_at = now
        until = 0.0
        doc = read_json_safe(self.pause_path, 4096)
        if isinstance(doc, dict) and isinstance(doc.get("until"), (int, float)) and not isinstance(doc["until"], bool):
            until = float(doc["until"])
        if until <= now:
            until = 0.0
        if (until > 0) != (self._paused_until > 0):
            self._bans_dirty = True
            if until > 0:
                out.append(self._mk("health.pause", "agent", "MEDIUM", "bans paused until %s" % _iso(until),
                                    details={"until": int(until)}))
            else:
                out.append(self._mk("health.pause_end", "agent", "INFO", "ban pause ended"))
        self._paused_until = until
        return out

    def paused(self):
        return self._paused_until > self.clock()

    def paused_until(self):
        """Epoch seconds, or None."""
        return self._paused_until if self.paused() else None

    # ---- events ----

    def _mk(self, kind, source, sev, summary, **kw):
        return _event.make_event(kind, source, sev, summary, **kw)

    # ---- observing events ----

    def _load_sids(self, now):
        if self._sids is not None and now - self._sids_at < 300:
            return self._sids
        self._sids_at = now
        raw = read_file_safe(self.sids_path, 4 * 1024 * 1024) if self.sids_path else None
        if raw is None:
            self._sids = set()
        else:
            self._sids = {int(x) for x in re.findall(r"^\s*(\d{1,10})\s*$", raw.decode("ascii", "replace"), re.M)}
        return self._sids

    def observe(self, event, now):
        with self.lock:
            try:
                return self._observe(event, now)
            except Exception as exc:                         # a bad event must never stop the pipeline
                self._note_error("ban engine: %s" % exc.__class__.__name__, now)
                return []

    def _event_time(self, ev, now):
        ts = parse_rfc3339(ev.get("ts"))
        if ts is None:
            return None
        return min(ts, now)

    def _observe(self, ev, now):
        if not isinstance(ev, dict):
            return []
        kind = ev.get("kind")
        if not isinstance(kind, str):
            return []
        if kind == "ssh.login":
            self._note_login(ev, now)
            return []
        det = ev.get("details")
        det = det if isinstance(det, dict) else {}
        trig = self._classify(ev, kind, det, now)
        if trig is None:
            return []
        ip = parse_ip(ev.get("src_ip"))
        if ip is None or ev.get("src_trust") != "tcp":
            return []
        ts = self._event_time(ev, now)
        if ts is None or now - ts > EVENT_MAX_AGE_S:
            return []                                        # never a backlog
        if self.auto_ban == "off":
            return []
        if self._paused_until > now:
            return []
        out = []
        self._refresh_never(now)
        if self.never_contains(ip):
            if trig != "ssh_fail":
                last = self._internal_note.get(str(ip), 0)
                if now - last > 3600:
                    self._internal_note[str(ip)] = now
                    if len(self._internal_note) > 5000:
                        self._internal_note.clear()
                    out.append(self._mk("health.internal_source", "agent", "MEDIUM",
                                        "internal source %s on %s signals" % (ip, trig),
                                        details={"trigger": trig}, src_ip=str(ip), src_trust="tcp"))
            return out
        if trig in WEB_TRIGGERS and self._web_blocked(trig, ev, now):
            return out
        key = ban_key(ip)
        ctr = self.counters[trig]
        if trig == "suricata":
            sid = as_int(det.get("sid", det.get("signature_id")), 0)
            dq = ctr.add(key, ts)
            sq = self.sig_counter.add(key, ts, sid)
            n_alerts, n_alert_rate = len(dq), self.rates["suricata"][0]
            sigs = {t for _, t in sq if t is not None}
            hit = n_alerts >= n_alert_rate or len(sigs) >= self.rates["suricata_sigs"][0]
        elif trig == "bigconn":
            dq = ctr.add(key, ts)
            hit = len(dq) >= self.rates["bigconn_repeat"][0]
        else:
            dq = ctr.add(key, ts)
            hit = len(dq) >= self.rates[trig][0]
        if not hit:
            return out
        for c in self.counters.values():
            c.clear(key)
        self.sig_counter.clear(key)
        out.extend(self._ban(ip, key, trig, now))
        return out

    def _classify(self, ev, kind, det, now):
        """The trigger an event feeds, or None. Applies the evidence-quality rules."""
        if kind == "ssh.fail":
            return "ssh_fail"
        if kind == "canary.tripwire":
            status = as_int(det.get("status"), 0)
            if status in SCANNER_STATUS and det.get("ban") is not False:
                return "tripwire"
            return None
        if kind == "suricata.alert":
            proto = str(ev.get("proto") or det.get("proto") or "").upper()
            if proto != "TCP" or not det.get("app_proto"):
                return None
            if as_int(det.get("stream"), 0) != 1:
                return None
            if as_int(det.get("pkts_toserver"), 0) < 3 or as_int(det.get("pkts_toclient"), 0) < 1:
                return None
            sid = as_int(det.get("sid", det.get("signature_id")), 0)
            if sid <= 0 or sid not in self._load_sids(now):
                return None
            return "suricata"
        if kind == "nginx.marker.window_update":
            return "window_update"
        if kind == "edr.bigconn":
            return "bigconn"
        return None

    def _web_blocked(self, trig, ev, now):
        """Web-sourced bans and Suricata bans on ports 80 and 443 are off behind a proxy."""
        if trig == "suricata" and as_int(ev.get("dst_port"), 0) not in (80, 443):
            return False
        return self._proxy_active(now)[0]

    def _proxy_active(self, now):
        self._read_inventory(now)
        if self._real_ip:
            return True, "real_ip or X-Forwarded-For is configured"
        if self.proxy_mode == "on":
            return True, "proxy_mode = on"
        # In "auto" the access-log heuristics belong to the access-log reader (sources/nginx.py): it marks proxied
        # sources src_trust=claimed, and only src_trust=tcp ever bans. Here only the settings and the inventory count.
        return False, ""

    def _read_inventory(self, now):
        if now - self._inv_at < 60:
            return
        self._inv_at = now
        real = False
        inv = read_json_safe(self.inventory_path, 1024 * 1024) if self.inventory_path else None
        if isinstance(inv, dict) and isinstance(inv.get("checks"), dict):
            checks = inv["checks"]
            for name in ("real_ip", "nginx_logs"):
                c = checks.get(name)
                if not isinstance(c, dict):
                    continue
                if name == "real_ip" and c.get("status") is True:
                    real = True
                if c.get("xff") is True or c.get("x_forwarded_for") is True or c.get("real_ip") is True:
                    real = True
        self._real_ip = real

    def _note_login(self, ev, now):
        ip = parse_ip(ev.get("src_ip"))
        if ip is None or ev.get("src_trust") != "tcp":
            return
        s = str(ip)
        prev = self.accepted.get(s)
        if prev is None or now - prev > 3600:
            self.accepted[s] = now
            self.accepted.move_to_end(s)
            while len(self.accepted) > 5000:
                self.accepted.popitem(last=False)
            self._state_dirty = True

    # ---- banning ----

    def _ban(self, ip, key, trig, now):
        out = []
        net = net_for(ip)
        cidr = str(net)
        evidence = EVIDENCE[trig]
        details_base = {"cidr": cidr, "trigger": trig, "evidence": evidence}
        if self.auto_ban == "observe":
            d = dict(details_base)
            d.update({"ttl_s": int(self.ladder[0]), "rung": 0})
            out.append(self._mk("ban.observed", "agent", "MEDIUM",
                                "would ban %s (%s); auto_ban is observe" % (cidr, trig),
                                details=d, src_ip=str(ip), src_trust="tcp"))
            return out
        if cidr in self.bans:
            return out
        if trig == "ssh_fail":
            last = self.accepted.get(str(ip))
            if last is not None and now - last <= ACCEPTED_DAYS_S:
                return out
        until = self.allow.get(key)
        if until is not None and until > now:
            return out
        while self._hour and self._hour[0] < now - 3600:
            self._hour.popleft()
        active_local = sum(1 for b in self.bans.values() if b["source"] == "local")
        if len(self._hour) >= self.budget or active_local >= self.max_active:
            if now - self._budget_note > 3600:
                self._budget_note = now
                out.append(self._mk("health.ban_budget", "agent", "HIGH", "ban budget exhausted",
                                    details={"per_hour": self.budget, "active": active_local,
                                             "max_active": self.max_active}))
            return out
        if self._never_overlaps(net):
            self._refused += 1
            self._note_error("ban refused: %s overlaps the never-ban list" % cidr, now)
            out.append(self._mk("health.ban_refused", "agent", "MEDIUM",
                                "ban of %s refused: it overlaps the never-ban list" % cidr,
                                details={"cidr": cidr, "trigger": trig}, src_ip=str(ip), src_trust="tcp"))
            return out
        rung = 0
        if ip.version == 4:
            mem = self.memory.get(key)
            if mem is not None and now - mem["last"] <= self.memory_s:
                rung = min(mem["rung"] + 1, len(self.ladder) - 1)
        ttl = self.ladder[min(rung, len(self.ladder) - 1)]
        self.bans[cidr] = {"cidr": cidr, "expires": int(now + ttl), "source": "local", "reason": trig,
                           "rung": rung, "since": int(now)}
        if ip.version == 4:
            self.memory[key] = {"rung": rung, "last": now}
            if len(self.memory) > 5000:
                self.memory.pop(next(iter(self.memory)))
        self._hour.append(now)
        self._bans_dirty = True
        self._state_dirty = True
        d = dict(details_base)
        d.update({"ttl_s": int(ttl), "rung": rung})
        out.append(self._mk("ban.local", "agent", "MEDIUM", "banned %s for %ds (%s)" % (cidr, int(ttl), trig),
                            details=d, src_ip=str(ip), src_trust="tcp"))
        return out

    # ---- operator commands ----

    def unban(self, addr, now=None):
        """Remove local bans that cover an address or equal a CIDR, and keep the ladder from
        re-banning it. Returns the CIDRs removed."""
        with self.lock:
            now = now or self.clock()
            net = parse_net(addr)
            if net is None:
                return []
            removed = []
            for cidr in list(self.bans):
                b = parse_net(cidr)
                if b is not None and b.version == net.version and (b.overlaps(net)):
                    del self.bans[cidr]
                    removed.append(cidr)
            ip0 = net.network_address
            key = ban_key(ip0)
            self.allow[key] = now + self.memory_s
            self.memory.pop(key, None)
            self._last_written_nonempty = True
            for c in self.counters.values():
                c.clear(key)
            self._bans_dirty = True
            self._state_dirty = True
            return removed

    def unban_all(self, now=None):
        with self.lock:
            n = len(self.bans)
            self.bans.clear()
            self.memory.clear()
            self._hour.clear()
            self._last_written_nonempty = True
            for c in self.counters.values():
                c.d.clear()
            self._bans_dirty = True
            self._state_dirty = True
            return n

    def _process_commands(self, now):
        try:
            st = os.stat(self.cmd_path)
        except OSError:
            return
        if (st.st_mtime_ns, st.st_ino) == self._cmd_mtime:
            return
        doc = read_json_safe(self.cmd_path, 64 * 1024)
        self._cmd_mtime = (st.st_mtime_ns, st.st_ino)
        results = []
        cmds = doc.get("cmds") if isinstance(doc, dict) else None
        if isinstance(cmds, list):
            for c in cmds[:16]:
                if not isinstance(c, dict):
                    continue
                if c.get("op") == "unban" and isinstance(c.get("addr"), str):
                    results.append({"op": "unban", "addr": c["addr"][:64], "removed": self.unban(c["addr"], now)})
                elif c.get("op") == "unban_all":
                    results.append({"op": "unban_all", "removed": self.unban_all(now)})
        try:
            atomic_write(self.cmd_path + ".done", json.dumps({"id": doc.get("id") if isinstance(doc, dict) else None,
                                                              "results": results}), 0o644)
            os.unlink(self.cmd_path)
        except OSError:
            pass
        self._cmd_mtime = None

    # ---- tick ----

    def tick(self, now):
        with self.lock:
            out = []
            try:
                out.extend(self._check_pause(now))
                self._process_commands(now)
                self._expire(now)
                self._refresh_never(now)
                self._write_bans_json(now)
                self._save_state(now)
            except Exception as exc:
                self._note_error("ban engine tick: %s" % exc.__class__.__name__, now)
            return out

    def _expire(self, now):
        for cidr in [c for c, b in self.bans.items() if b["expires"] <= now]:
            del self.bans[cidr]
            self._bans_dirty = True
            self._state_dirty = True
        for k in [k for k, v in self.allow.items() if v <= now]:
            del self.allow[k]
            self._state_dirty = True
        for k in [k for k, v in self.peers.items() if v <= now]:
            del self.peers[k]
            self._state_dirty = True
            self._never_at = -1e9
        for k in [k for k, v in self.memory.items() if now - v["last"] > self.memory_s]:
            del self.memory[k]
            self._state_dirty = True
        for ip in [k for k, v in self.accepted.items() if now - v > ACCEPTED_DAYS_S]:
            del self.accepted[ip]
            self._state_dirty = True

    # ---- bans.json ----

    def _doc(self, now):
        paused = self._paused_until > now
        bans = []
        if not paused:
            bans = [dict(cidr=b["cidr"], expires=int(b["expires"]), source=b["source"], reason=b["reason"])
                    for b in sorted(self.bans.values(), key=lambda b: b["cidr"]) if b["expires"] > now]
        # An empty state after a non-empty one must say so, or edr-bans keeps the old state. It keeps
        # saying so for EMPTY_STICKY_S, so a helper that was slow to read the first write still sees it.
        empty = bool(paused or (not bans and (self._last_written_nonempty or now < self._empty_until)))
        return {"v": 1, "written_at": int(now), "empty": empty, "never": list(self._dyn_never),
                "bans": bans, "feeds": {}}

    def _write_bans_json(self, now, force=False):
        doc = self._doc(now)
        sig = json.dumps({k: v for k, v in doc.items() if k != "written_at"}, sort_keys=True)
        changed = sig != self._bans_written_sig or self._bans_dirty
        if not force:
            if now - self._bans_written_at < BANS_WRITE_MIN_S:
                return
            if not changed and now - self._bans_written_at < BANS_REFRESH_S:
                return
        try:
            atomic_write(self.bans_path, json.dumps(doc, separators=(",", ":")), 0o644)
        except OSError as exc:
            self._note_error("cannot write bans.json: %s" % (exc.strerror or exc.__class__.__name__), now)
            return
        self._bans_written_at = now
        self._bans_written_sig = sig
        self._bans_dirty = False
        self._last_written_nonempty = bool(doc["bans"])
        if doc["empty"] and not self._paused_until > now:
            self._empty_until = max(self._empty_until, now + EMPTY_STICKY_S)

    # ---- numbers for the heartbeat ----

    def counts(self):
        with self.lock:
            now = self.clock()
            by = collections.Counter(b["source"] for b in self.bans.values() if b["expires"] > now)
            while self._hour and self._hour[0] < now - 3600:
                self._hour.popleft()
            return {"local": by.get("local", 0), "fleet": by.get("fleet", 0), "operator": by.get("operator", 0),
                    "never": len(self._dyn_never), "budget_used": len(self._hour),
                    "refused": self._refused, "paused": 1 if self._paused_until > now else 0}

    def active_bans(self):
        with self.lock:
            now = self.clock()
            return [dict(b) for b in self.bans.values() if b["expires"] > now]


def _iso(t):
    return rfc3339(t)
