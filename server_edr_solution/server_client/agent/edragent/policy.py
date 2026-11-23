"""The policy poll (client PLAN 4.2, What the client expects of /v1/policy; hub Appendix A).

GET /v1/policy with If-None-Match. The document is validated strictly: types, the closed
vocabularies, the bounds. A document over a cap is refused, never truncated, and the previous
state stays. In P2 only the peers and the hub addresses are applied (to the never-ban list);
bans and feeds are validated and kept for P3, but not applied.
"""

import json
import os
import re
import time

from . import transport as tr
from .bans import (BANS_MAX, FEED_CIDRS_MAX, HUB_ADDRESSES_MAX, PEERS_MAX, MAX_TTL_S, parse_ip, parse_net)
from .spool import atomic_write, read_json_safe

REV_RE = re.compile(r"^[0-9a-f]{16}\Z")
SOURCES = ("fleet", "operator")
REASON_IDS = ("fleet_quorum", "operator")
FEED_NAMES = ("spamhaus_drop_v4", "spamhaus_drop_v6", "dshield")
SKEW_WARN_S = 60
HUB_TIME_MAX = 2 ** 40


class PolicyRefused(Exception):
    pass


class Policy:
    def __init__(self):
        self.rev = ""
        self.hub_time = 0
        self.hub_addresses = []
        self.port = None
        self.bans = []          # {"cidr", "remaining", "source", "reason_id"}; kept for P3
        self.feeds = {}         # name -> [cidr, ...]; kept for P3
        self.peers = []
        self.skew = 0.0
        self.invalid = 0        # entries dropped as malformed
        self.ignored_feeds = 0

    def never_doc(self):
        """What the ban engine takes in P2."""
        return {"peers": list(self.peers), "hub_addresses": list(self.hub_addresses)}


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def validate(doc, now=None):
    """The validated Policy of a /v1/policy document. Raises PolicyRefused."""
    now = time.time() if now is None else now
    if not isinstance(doc, dict):
        raise PolicyRefused("the policy is not a JSON object")
    p = Policy()
    rev = doc.get("rev")
    if not isinstance(rev, str) or not REV_RE.match(rev):
        raise PolicyRefused("rev is not 16 lower-case hex characters")
    p.rev = rev
    ht = doc.get("hub_time")
    if not _int(ht) or not (0 < ht < HUB_TIME_MAX):
        raise PolicyRefused("hub_time is not an epoch second count")
    p.hub_time = ht
    p.skew = float(ht) - now

    addrs = doc.get("hub_addresses", [])
    if not isinstance(addrs, list) or len(addrs) > HUB_ADDRESSES_MAX:
        raise PolicyRefused("hub_addresses is not a list of at most %d" % HUB_ADDRESSES_MAX)
    for a in addrs:
        ip = parse_ip(a) if isinstance(a, str) else None
        if ip is None:
            raise PolicyRefused("hub_addresses holds something that is not an IP literal")
        if str(ip) not in p.hub_addresses:
            p.hub_addresses.append(str(ip))
    port = doc.get("port")
    if port is not None:
        if not _int(port) or not (0 < port < 65536):
            raise PolicyRefused("port is not a TCP port")
        p.port = port

    peers = doc.get("peers", [])
    if not isinstance(peers, list):
        raise PolicyRefused("peers is not a list")
    if len(peers) > PEERS_MAX:
        raise PolicyRefused("%d peers is over the cap of %d" % (len(peers), PEERS_MAX))
    for x in peers:
        ip = parse_ip(x) if isinstance(x, str) else None
        if ip is None:
            p.invalid += 1                      # a range or a bad literal is never a peer
            continue
        if str(ip) not in p.peers:
            p.peers.append(str(ip))

    bans = doc.get("bans", [])
    if not isinstance(bans, list):
        raise PolicyRefused("bans is not a list")
    if len(bans) > BANS_MAX:
        raise PolicyRefused("%d bans is over the cap of %d" % (len(bans), BANS_MAX))
    for b in bans:
        if not isinstance(b, dict):
            p.invalid += 1
            continue
        net = parse_net(b.get("cidr")) if isinstance(b.get("cidr"), str) else None
        exp = b.get("expires_at")
        if net is None or not _int(exp):
            p.invalid += 1
            continue
        remaining = exp - ht                    # on the hub clock, so skew shifts nothing
        if remaining <= 0:
            continue
        src = b.get("source") if b.get("source") in SOURCES else "unknown"
        rid = b.get("reason_id") if b.get("reason_id") in REASON_IDS else "unknown"
        p.bans.append({"cidr": str(net), "remaining": min(remaining, MAX_TTL_S), "source": src, "reason_id": rid})

    feeds = doc.get("feeds", {})
    if not isinstance(feeds, dict):
        raise PolicyRefused("feeds is not an object")
    total = 0
    for name, lst in feeds.items():
        if not isinstance(lst, list):
            raise PolicyRefused("a feed is not a list")
        total += len(lst)
        if total > FEED_CIDRS_MAX:
            raise PolicyRefused("feeds are over the cap of %d entries" % FEED_CIDRS_MAX)
    for name, lst in feeds.items():
        if name not in FEED_NAMES:
            p.ignored_feeds += 1
            continue
        out = []
        for c in lst:
            net = parse_net(c) if isinstance(c, str) else None
            if net is None:
                p.invalid += 1
            else:
                out.append(str(net))
        p.feeds[name] = out
    return p


def absolute_expiry(remaining, now):
    """The absolute expiry on the local clock for a ban with `remaining` seconds on the hub clock."""
    return now + remaining


def saved_rev(paths):
    """The rev last applied, from state_dir/policy.json, or ''. For a process that does not poll."""
    d = read_json_safe(os.path.join(str(paths.state_dir), "policy.json"), 4 * 1024 * 1024)
    if isinstance(d, dict) and isinstance(d.get("rev"), str) and REV_RE.match(d["rev"]):
        return d["rev"]
    return ""


class PolicyPoller:
    def __init__(self, paths, client, ban_engine, *, clock=time.time, log=None):
        self.paths = paths
        self.client = client
        self.engine = ban_engine
        self.clock = clock
        self.log = log or (lambda m: None)
        self.path = os.path.join(str(paths.state_dir), "policy.json")
        self.rev_applied = ""
        self.last_doc = None            # the never_doc of the last applied policy
        self.last_ok = None             # epoch of the last 200 or 304
        self.last_gen = ""
        self.last_error = ""
        self.last_code = ""
        self.orphan = False
        self.skew = 0.0
        self.refused = ""
        self._load()

    def _load(self):
        d = read_json_safe(self.path, 4 * 1024 * 1024)
        if isinstance(d, dict) and isinstance(d.get("rev"), str) and REV_RE.match(d["rev"]) and isinstance(d.get("doc"), dict):
            self.rev_applied = d["rev"]
            self.last_doc = d["doc"]

    def _save(self, rev, doc):
        try:
            atomic_write(self.path, json.dumps({"rev": rev, "doc": doc}, separators=(",", ":")), 0o600)
        except OSError:
            pass

    def poll(self):
        """One poll. Returns the transport Outcome (the caller handles backoff and holds)."""
        headers = {}
        if self.rev_applied:
            headers["If-None-Match"] = '"%s"' % self.rev_applied
        reply, oc = self.client.call("policy", "GET", "/v1/policy", headers=headers)
        now = self.clock()
        self.last_code = oc.code
        self.orphan = oc.action == tr.ORPHAN
        if oc.action == tr.UNCHANGED:
            self._ok(now)
            if self.last_doc is not None:
                self.engine.set_policy(self.last_doc)        # refreshes the 72 h peer timeout
            return oc
        if oc.action == tr.OK:
            try:
                doc = reply.json()
                pol = validate(doc, now)
            except PolicyRefused as exc:
                self.refused = "policy refused: %s" % exc
                self.last_error = self.refused
                self.engine.note_apply_error(self.refused)
                self.log(self.refused)
                return tr.Outcome(tr.LOG_RETRY, reply.status, "policy_refused", note=self.refused)
            self.refused = ""
            self.engine.set_policy(pol.never_doc())
            self.rev_applied = pol.rev
            self.last_doc = pol.never_doc()
            self._save(pol.rev, self.last_doc)
            self.skew = pol.skew
            if abs(pol.skew) > SKEW_WARN_S:
                self.log("clock skew against the hub is %+.0f s" % pol.skew)
            self._ok(now)
            return oc
        self.last_error = "policy: %s" % (self.client.last_error or oc.action)
        return oc

    def _ok(self, now):
        self.last_ok = now
        self.last_gen = self.client.last_gen
        self.last_error = ""
