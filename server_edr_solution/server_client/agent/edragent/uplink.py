"""The threads that talk to the hub (client PLAN 4.5: Transport, Spool, Heartbeat; 4.6 renewal).

Three threads, so a slow events POST never delays the heartbeat:

    events     drains the spool (hi lane first, oldest first, at most one batch a second)
    heartbeat  every 60 s +-10%, plus the renewal check and the 2 s shutdown heartbeat
    policy     GET /v1/policy every 60 s +-10% with If-None-Match

In local mode (no identity/current) the threads only idle and submit() drops. Enrollment while
the agent runs is noticed within a few seconds.
"""

import json
import os
import random
import threading
import time

from . import identity as idn
from . import transport as tr
from .policy import PolicyPoller
from .policy import saved_rev as policy_saved_rev
from .spool import Spool, atomic_write, rfc3339

AGENT_VERSION = tr.AGENT_VERSION
HB_INTERVAL = 60.0
POLICY_INTERVAL = 60.0
JITTER = 0.10
PACE_S = 1.0                     # at most one batch a second
LO_FLUSH_S = 5.0                 # a low batch goes after 500 events or 5 s
IDENT_CHECK_S = 5.0
RENEW_RETRY_S = 86400.0
STATUS_WRITE_S = 5.0
PRESSURE_ON_PCT = 10.0
PRESSURE_OFF_PCT = 15.0


class Uplink:
    def __init__(self, cfg, paths, ban_engine, heartbeat_fn, *, clock=time.time, rng=None,
                 hb_interval=HB_INTERVAL, policy_interval=POLICY_INTERVAL, pace_s=PACE_S,
                 lo_flush_s=LO_FLUSH_S, requester=None):
        self.cfg = cfg
        self.paths = paths
        self.engine = ban_engine
        self.heartbeat_fn = heartbeat_fn
        self.clock = clock
        self.rng = rng or random.Random()
        self.hb_interval = hb_interval
        self.policy_interval = policy_interval
        self.pace_s = pace_s
        self.lo_flush_s = lo_flush_s
        self.lock = threading.RLock()
        self.local_event_cb = None       # the pipeline may set it: cb(event) stamps, alerts and submits
        self._requester = requester
        self.client = self._new_client()          # heartbeat and renewal
        self.ev_client = self._new_client()       # events
        self.pol_client = self._new_client()      # policy
        self.spool = None
        self.poller = None
        self._ident = None
        self._ident_at = -1e9
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._threads = []
        self._last_sync = 0.0
        self._pending_since = None
        self._batch_id = None
        # status
        self.last_hb_ok = None
        self.hb_gen = ""
        self._errs = {}                  # route -> (code, text) of its latest failure; cleared by its next success
        self.dropped_low = 0
        self.skew_s = None
        self.min_client_schema = None
        self.hub_policy_rev = None
        self._holds = {"events": 0.0, "heartbeat": 0.0, "policy": 0.0}
        self._hold_code = {}
        self._blocked_until = 0.0
        self._blocked_code = ""
        self._identity_changed = False
        self._identity_note = False
        self._status_at = -1e9
        self._gen_epoch = 0              # counts identity changes; the heartbeat and policy loops fire at once on a change
        self._next_renew = 0.0
        self._renew_note = ""
        self._renewed = False
        self._pressure = False

    # ---- identity and spool ------------------------------------------------------------

    def _new_client(self):
        """One client per thread: each counts its own TLS failures in a row and its own last gen."""
        return tr.HubClient(self._target, requester=self._requester)

    def _target(self):
        ident = idn.load_current(self.paths)
        return ident.target() if ident else None

    @property
    def last_error(self):
        for route in ("uplink", "events", "heartbeat", "policy"):
            if route in self._errs:
                return self._errs[route][1]
        return ""

    @property
    def last_code(self):
        if self._identity_changed:
            return "identity_changed"
        for route in ("events", "heartbeat", "policy"):
            if route in self._errs:
                return self._errs[route][0]
        return ""

    def _refresh_ident(self, force=False, create=True):
        now = self.clock()
        if force or now - self._ident_at >= IDENT_CHECK_S:
            self._ident_at = now
            ident = idn.load_current(self.paths)
            with self.lock:
                old = self._ident.name if self._ident else None
                self._ident = ident
                if ident is not None and old is not None and ident.name != old:
                    # a new identity generation (renewal, rehome, re-enrollment): talk to the hub at once, and
                    # forget holds and blocks that belonged to the old one
                    self._gen_epoch += 1
                    self._blocked_until = 0.0
                    self._holds = {"events": 0.0, "heartbeat": 0.0, "policy": 0.0}
                    self._hold_code.clear()
                    self._errs.clear()
                if ident is not None and self.spool is None and create:
                    self.spool = Spool(self.paths.spool_dir, clock=self.clock)
                if ident is not None and self.poller is None and create:
                    self.poller = PolicyPoller(self.paths, self.pol_client, self.engine, clock=self.clock)
                self._identity_changed = bool(ident is not None and idn.host_identity_changed(self.paths))
        return self._ident

    def enrolled(self):
        return self._refresh_ident() is not None

    def start(self):
        self._refresh_ident(force=True)
        for name, fn in (("edr-uplink-events", self._events_loop), ("edr-uplink-hb", self._hb_loop),
                         ("edr-uplink-policy", self._policy_loop)):
            t = threading.Thread(target=self._guard(fn), name=name, daemon=True)
            t.start()
            self._threads.append(t)

    def _guard(self, fn):
        def run():
            while not self._stop.is_set():
                try:
                    fn()
                    return
                except Exception as exc:                          # a bug must not end the thread
                    self._errs["uplink"] = ("uplink", "uplink: %s" % exc.__class__.__name__)
                    self._stop.wait(5.0)
        return run

    # ---- submit -------------------------------------------------------------------------

    def submit(self, event):
        if self._refresh_ident() is None or self.spool is None:
            return
        self.spool.append(event)
        now = self.clock()
        if now - self._last_sync >= 1.0:
            self._last_sync = now
            self.spool.sync()
        if self._pending_since is None:
            self._pending_since = now
        self._wake.set()

    def _emit(self, ev):
        """An event the uplink makes itself (spool_dropped, identity)."""
        cb = self.local_event_cb
        if cb is not None:
            try:
                cb(ev)
                return
            except Exception:
                pass
        try:
            from . import ids
            ids.stamp(ev)
        except Exception:
            return
        if self.spool is not None and not self._identity_changed:
            self.spool.append(ev)
            self._wake.set()

    def _make_event(self, *a, **kw):
        from . import event as ev
        return ev.make_event(*a, **kw)

    def _drain_drop_records(self):
        if self.spool is None:
            return
        for rec in self.spool.take_drops():
            sev = "HIGH" if rec["lane"] == "hi" else "MEDIUM"
            ev = self._make_event("health.spool_dropped", "agent", sev,
                                  "spool full: dropped %d %s events" % (rec["count"], rec["lane"]),
                                  details={"lane": rec["lane"], "count": rec["count"], "kinds": rec["kinds"]})
            self._emit(ev)

    # ---- holds ---------------------------------------------------------------------------

    def _blocked(self, now):
        return self._identity_changed or now < self._blocked_until

    def _hold(self, route, seconds, code=""):
        self._holds[route] = self.clock() + seconds
        if code:
            self._hold_code[route] = code

    def _note_outcome(self, route, oc, client):
        """Common bookkeeping for a hub answer that was not a success."""
        now = self.clock()
        self._errs[route] = (oc.code or oc.action, client.last_error or oc.note or oc.action)
        if oc.action == tr.FORBIDDEN:
            self._blocked_until = now + (oc.wait or tr.HOLD_S)
            self._blocked_code = oc.code
        elif oc.action in (tr.HOLD,):
            self._hold(route, oc.wait or tr.HOLD_S, oc.code)
        elif oc.action == tr.ORPHAN:
            if route == "policy":
                self._hold("policy", oc.wait or tr.HOLD_S, oc.code)

    # ---- events thread -------------------------------------------------------------------

    def _check_drop_flag(self):
        flag = os.path.join(str(self.paths.identity_dir), "drop-spool.flag")
        if os.path.exists(flag) and self.spool is not None:
            self.spool.clear()
            try:
                os.unlink(flag)
            except OSError:
                pass

    def _events_loop(self):
        bo = tr.Backoff(300.0, rng=self.rng)
        last_send = 0.0
        while not self._stop.is_set():
            ident = self._refresh_ident()
            if ident is None or self.spool is None:
                self._stop.wait(2.0)
                continue
            self._check_drop_flag()
            self.spool.sync()
            self._drain_drop_records()
            now = self.clock()
            if self._blocked(now):
                self._stop.wait(1.0 if self._identity_changed else 5.0)
                continue
            if now < self._holds["events"]:
                self._stop.wait(min(5.0, self._holds["events"] - now))
                continue
            depth = self.spool.depth()
            if depth == 0:
                self._pending_since = None
                self._wake.wait(1.0)
                self._wake.clear()
                continue
            if self._pending_since is None:
                self._pending_since = now
            if self.spool.depth("hi") == 0 and depth < tr.EVENTS_MAX_N and now - self._pending_since < self.lo_flush_s:
                self._stop.wait(0.25)
                continue
            gap = self.pace_s - (time.monotonic() - last_send)
            if gap > 0 and self._stop.wait(gap):
                break
            batch = self.spool.next_batch()
            if batch is None:
                self._stop.wait(0.5)
                continue
            last_send = time.monotonic()
            delay = self._send_batch(batch, bo)
            self._pending_since = None
            self._publish_status()
            if delay:
                # a hold, not a sleep: the loop keeps seeing the drop flag and the eviction records
                self._holds["events"] = max(self._holds["events"], self.clock() + delay)

    def _post_events(self, events, batch_id):
        body, used, bid = tr.build_events_body(events, batch_id=batch_id)
        if used == 0:
            return None, None, 0, bid
        reply, oc = self.ev_client.call("events", "POST", "/v1/events", body=body,
                                     headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
                                     nevents=used)
        return reply, oc, used, bid

    def _send_batch(self, batch, bo):
        """Send one batch and act on the answer. Returns seconds to wait before the next attempt."""
        key = (batch.lane, batch.seg, batch.start, len(batch.items))
        bid = self._batch_id[1] if self._batch_id and self._batch_id[0] == key else None
        events = batch.events
        if not events:
            self.spool.ack(batch)               # only corrupt lines: skip past them
            return 0
        reply, oc, used, bid = self._post_events(events, bid)
        self._batch_id = (key, bid)
        if oc is None:                          # one event does not fit the size limits at all
            self.spool.reject([events[0]], "oversize")
            self.spool.ack(batch, 1)
            return 0
        return self._events_outcome(batch, used, reply, oc, bo)

    def _events_outcome(self, batch, used, reply, oc, bo):
        if oc.action == tr.OK:
            self.spool.ack(batch, used)
            self._batch_id = None
            self._errs.pop("events", None)
            bo.reset()
            d = reply.json()
            if isinstance(d, dict) and isinstance(d.get("dropped_low"), int) and not isinstance(d["dropped_low"], bool) \
                    and d["dropped_low"] > 0:
                self.dropped_low += d["dropped_low"]
            self._holds["events"] = 0.0
            self._hold_code.pop("events", None)
            return 0
        if oc.action == tr.REJECT:
            self.spool.reject(batch.events[:used], "refused %d" % oc.status)
            self.spool.ack(batch, used)
            self._batch_id = None
            self._errs["events"] = (oc.code, "the hub refused an event (%d %s): kept in spool/rejected" % (oc.status, oc.code))
            return 0
        if oc.action == tr.SPLIT:
            return self._split(batch, used, bo)
        self._note_outcome("events", oc, self.ev_client)
        if oc.action == tr.WAIT:
            return oc.wait + self.rng.uniform(0, 1.0)
        if oc.action == tr.BACKOFF:
            return bo.failure()
        if oc.action == tr.LOG_RETRY:
            return bo.failure()
        return 1.0

    def _split(self, batch, used, bo):
        """400 or 413: split once, never resend unchanged. A half the hub still refuses leaves the
        head of the spool for spool/rejected/."""
        items = batch.items[:used]
        mid = len(items) // 2
        done = 0
        for half in (items[:mid], items[mid:]):
            if not half or self._stop.is_set():
                continue
            reply, oc, n, _ = self._post_events([i.event for i in half], None)
            if oc is None:
                self.spool.reject([half[0].event], "oversize")
                done += 1
                self.spool.ack(batch, done)
                continue
            if oc.action == tr.OK:
                done += len(half)
                self.spool.ack(batch, done)
                d = reply.json()
                if isinstance(d, dict) and isinstance(d.get("dropped_low"), int) and not isinstance(d["dropped_low"], bool):
                    self.dropped_low += max(0, d["dropped_low"])
                if half is items[:mid]:
                    self._stop.wait(self.pace_s)
                continue
            if oc.action in (tr.SPLIT, tr.REJECT):
                self.spool.reject([i.event for i in half], "refused %d" % oc.status)
                done += len(half)
                self.spool.ack(batch, done)
                self._errs["events"] = (oc.code, "the hub refused %d events (%d %s): kept in spool/rejected" % (len(half), oc.status, oc.code))
                continue
            self._note_outcome("events", oc, self.ev_client)
            if oc.action == tr.WAIT:
                return oc.wait + self.rng.uniform(0, 1.0)
            return bo.failure() if oc.action in (tr.BACKOFF, tr.LOG_RETRY) else 1.0
        self._batch_id = None
        return 0

    # ---- heartbeat thread ----------------------------------------------------------------

    def _droplet_id(self):
        return idn.running_droplet_id(self.paths) or idn.stored_droplet_id(self.paths)

    def _build_hb(self, shutdown=False):
        hb = dict(self.heartbeat_fn() or {})
        try:
            from . import ids
            epoch, seq = ids.current()
        except Exception:
            epoch, seq = 0, 0
        hb["sent_at"] = rfc3339()
        hb["epoch"], hb["seq"] = epoch, seq
        st = self.spool.stats() if self.spool else {"depth": 0, "bytes": 0, "dropped": {"hi": 0, "lo": 0},
                                                    "dropped_by_source": {}, "rejected": 0}
        mine = {"depth": st["depth"], "bytes": st["bytes"], "dropped": st["dropped"],
                "dropped_by_source": st["dropped_by_source"], "rejected": st["rejected"]}
        theirs = hb.get("spool")
        if isinstance(theirs, dict):                    # keep what the heartbeat builder put there (over_budget)
            mine = dict(theirs, **mine)
        hb["spool"] = mine
        rev = self.poller.rev_applied if self.poller else policy_saved_rev(self.paths)
        hb["policy_rev_applied"] = rev or None
        err = self.engine.last_apply_error()
        hb["last_apply_error"] = err[:512] if err else None
        hb["ban_counts"] = self.engine.counts()
        na = self._ident.not_after() if self._ident else None
        hb["cert_not_after"] = rfc3339(na) if na else None
        hb["droplet_id"] = self._droplet_id() or "unknown"
        hb.setdefault("schema", 1)
        hb.setdefault("proto", 1)
        hb.setdefault("agent_version", AGENT_VERSION)
        if "paused_until" not in hb:
            pu = self.engine.paused_until()
            hb["paused_until"] = rfc3339(pu) if pu else None
        if shutdown:
            hb["shutdown"] = True
        return hb

    def _jitter(self, base):
        return base * (1.0 + self.rng.uniform(-JITTER, JITTER))

    def _hb_loop(self):
        bo = tr.Backoff(60.0, rng=self.rng)
        next_at = 0.0
        seen_gen = self._gen_epoch
        while not self._stop.is_set():
            now = self.clock()
            if seen_gen != self._gen_epoch:
                seen_gen, next_at = self._gen_epoch, 0.0
                bo.reset()
            if now < next_at:
                self._stop.wait(min(1.0, next_at - now))
                continue
            ident = self._refresh_ident()
            if ident is None:
                next_at = now + 2.0
                continue
            self._check_pressure()
            self._identity_check()
            now = self.clock()
            if self._blocked(now):
                next_at = now + (1.0 if self._identity_changed else min(60.0, max(1.0, self._blocked_until - now)))
                self._publish_status(force=True)
                continue
            if now < self._holds["heartbeat"]:
                next_at = self._holds["heartbeat"]
                continue
            hb = self._build_hb()
            sent = self.clock()
            reply, oc = self.client.call("heartbeat", "POST", "/v1/heartbeat", body=tr.json_body(hb),
                                         headers={"Content-Type": "application/json"})
            if oc.action == tr.OK:
                bo.reset()
                self._heartbeat_ok(reply, sent)
                self._maybe_renew()
                next_at = self.clock() + self._jitter(self.hb_interval)
            else:
                self._note_outcome("heartbeat", oc, self.client)
                if oc.action == tr.WAIT:
                    next_at = self.clock() + oc.wait
                elif oc.action == tr.BACKOFF:
                    next_at = self.clock() + bo.failure()
                elif oc.action in (tr.HOLD, tr.FORBIDDEN):
                    next_at = self.clock() + (oc.wait or tr.HOLD_S)
                else:
                    next_at = self.clock() + self._jitter(self.hb_interval)
            self._publish_status(force=True)

    def _heartbeat_ok(self, reply, sent):
        d = reply.json()
        now = self.clock()
        with self.lock:
            self.last_hb_ok = now
            self.hb_gen = self.client.last_gen
            self._errs.pop("heartbeat", None)
            self._blocked_until = 0.0
            self._holds["heartbeat"] = 0.0
            if isinstance(d, dict):
                ht = d.get("hub_time")
                if isinstance(ht, int) and not isinstance(ht, bool) and 0 < ht < 2 ** 40:
                    self.skew_s = float(ht) - (sent + now) / 2.0
                mcs = d.get("min_client_schema")
                if isinstance(mcs, int) and not isinstance(mcs, bool):
                    self.min_client_schema = mcs
                pr = d.get("policy_rev")
                if isinstance(pr, str) and len(pr) == 16:
                    self.hub_policy_rev = pr
        if self._renewed and self.hb_gen == idn.current_gen_name(self.paths):
            idn.cleanup_generations(self.paths)
            self._renewed = False
        elif self.hb_gen:
            idn.cleanup_generations(self.paths)         # a no-op unless an old generation is left over

    def _identity_check(self):
        if self._identity_changed and not self._identity_note:
            self._identity_note = True
            ev = self._make_event("health.identity", "agent", "HIGH",
                                  "host identity changed, re-enrol with a new token",
                                  details={"why": "the droplet id differs from the one enrolled"})
            self._local_only(ev)
        elif not self._identity_changed:
            self._identity_note = False

    def _local_only(self, ev):
        """health.identity stays on the host: alerts.jsonl through the pipeline callback, never the spool
        (the old certificate is no longer used)."""
        cb = self.local_event_cb
        if cb is not None:
            try:
                cb(ev)
            except Exception:
                pass

    def _check_pressure(self):
        if self.spool is None:
            return
        try:
            st = os.statvfs(str(self.paths.state_dir))
            free = 100.0 * st.f_bavail / st.f_blocks if st.f_blocks else 100.0
        except OSError:
            return
        if free < PRESSURE_ON_PCT and not self._pressure:
            self._pressure = True
            self.spool.set_disk_pressure(True)
        elif free > PRESSURE_OFF_PCT and self._pressure:
            self._pressure = False
            self.spool.set_disk_pressure(False)

    def _maybe_renew(self):
        ident = self._ident
        if ident is None or idn.rehome_in_progress(self.paths):
            return
        now = self.clock()
        if now < self._next_renew or not idn.renew_due(ident, now):
            return
        status, oc = idn.renew(self.paths, self.client, ident, now)
        if status == "renewed":
            self._renewed = True
            self._next_renew = 0.0
            self._renew_note = ""
            self._ident_at = -1e9
            return
        self._renew_note = ("renewal: %s" % (oc.code or oc.action)) if oc else "renewal failed"
        if oc is not None and oc.action in (tr.ORPHAN, tr.HOLD, tr.FORBIDDEN):
            self._next_renew = now + tr.HOLD_S                         # retried hourly
        elif oc is not None and oc.action == tr.WAIT:
            self._next_renew = now + (oc.wait or 60.0)
        elif oc is not None and oc.action == tr.BACKOFF:
            self._next_renew = now + self.rng.uniform(600.0, 3600.0)
        else:
            self._next_renew = now + RENEW_RETRY_S * self.rng.uniform(0.8, 1.2)   # daily with jitter

    # ---- policy thread -------------------------------------------------------------------

    def _policy_loop(self):
        bo = tr.Backoff(60.0, rng=self.rng)
        next_at = 0.0
        seen_gen = self._gen_epoch
        while not self._stop.is_set():
            now = self.clock()
            if seen_gen != self._gen_epoch:
                seen_gen, next_at = self._gen_epoch, 0.0
                bo.reset()
            if now < next_at:
                self._stop.wait(min(1.0, next_at - now))
                continue
            if self._refresh_ident() is None or self.poller is None:
                next_at = now + 2.0
                continue
            if self._blocked(now):
                next_at = now + (1.0 if self._identity_changed else 5.0)
                continue
            if now < self._holds["policy"]:
                next_at = self._holds["policy"]
                continue
            oc = self.poller.poll()
            if oc.action in (tr.OK, tr.UNCHANGED):
                bo.reset()
                self._errs.pop("policy", None)
                self._holds["policy"] = 0.0
                next_at = self.clock() + self._jitter(self.policy_interval)
            else:
                self._note_outcome("policy", oc, self.pol_client)
                if oc.action == tr.BACKOFF:
                    next_at = self.clock() + bo.failure()
                elif oc.action == tr.WAIT:
                    next_at = self.clock() + oc.wait
                elif oc.action in (tr.HOLD, tr.FORBIDDEN, tr.ORPHAN):
                    next_at = self.clock() + (oc.wait or tr.HOLD_S)
                else:
                    next_at = self.clock() + self._jitter(self.policy_interval)
            self._publish_status(force=True)

    # ---- status --------------------------------------------------------------------------

    def status(self):
        with self.lock:
            ident = self._ident
            st = self.spool.stats() if self.spool else {"depth": 0, "bytes": 0, "dropped": {"hi": 0, "lo": 0}, "rejected": 0}
            na = ident.not_after() if ident else None
            hub = None
            if ident and ident.addresses:
                a = ident.addresses[0]
                hub = ("[%s]:%d" if ":" in a else "%s:%d") % (a, ident.port)
            now = self.clock()
            held = {r: self._hold_code.get(r) for r, t in self._holds.items() if t > now and self._hold_code.get(r)}
            return {
                "mode": "enrolled" if ident else "local",
                "hub": hub,
                "host_uuid": ident.host_uuid if ident else None,
                "last_heartbeat_ok": self.last_hb_ok,
                "last_error": self.last_error,
                "last_code": self.last_code,
                "spool": {"depth": st["depth"], "bytes": st["bytes"], "dropped": st["dropped"]},
                "rejected": st["rejected"],
                "dropped_low": self.dropped_low,
                "policy_rev_applied": (self.poller.rev_applied if self.poller else "") or None,
                "cert_not_after": rfc3339(na) if na else None,
                "skew_s": self.skew_s,
                "held": held,
                "blocked": self._blocked_code if now < self._blocked_until else ("identity_changed" if self._identity_changed else ""),
                "orphan": bool(self.poller and self.poller.orphan),
                "min_client_schema": self.min_client_schema,
            }

    def _publish_status(self, force=False):
        """run_dir/uplink.json: what `rehome` waits for (a heartbeat and a policy poll on the new generation)."""
        now = self.clock()
        if not force and now - self._status_at < STATUS_WRITE_S:
            return
        self._status_at = now
        ident = self._ident
        p = self.poller
        doc = {"v": 1, "written_at": int(now), "mode": "enrolled" if ident else "local",
               "gen": ident.name if ident else "", "hb_gen": self.hb_gen, "last_heartbeat_ok": self.last_hb_ok,
               "policy_gen": p.last_gen if p else "", "last_policy_ok": p.last_ok if p else None,
               "policy_rev_applied": (p.rev_applied if p else "") or None}
        try:
            atomic_write(os.path.join(str(self.paths.run_dir), "uplink.json"), json.dumps(doc), 0o644)
        except OSError:
            pass

    # ---- stop ----------------------------------------------------------------------------

    def stop(self, shutdown=False):
        self._stop.set()
        self._wake.set()
        for t in self._threads:
            t.join(timeout=3.0)
        self._threads = []
        ident = self._refresh_ident(force=True, create=False)       # the stop hook has no spool of its own
        if shutdown and ident is not None and not self._blocked(self.clock()):
            try:
                hb = self._build_hb(shutdown=True)
                self.client.call("heartbeat", "POST", "/v1/heartbeat", body=tr.json_body(hb),
                                 headers={"Content-Type": "application/json"}, total_s=2.0)
            except Exception:
                pass
        if self.spool is not None:
            self.spool.close()
        flush = getattr(self.engine, "flush", None)
        if flush:
            try:
                flush()
            except Exception:
                pass
