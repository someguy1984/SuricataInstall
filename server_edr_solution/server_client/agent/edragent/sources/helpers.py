"""The status files the root helpers write (contract section 8), read once a minute.

Every file is read the way hostile input is read: no symlink, regular files only, size capped, parsed with
json, and a missing, oversized or unparsable file means "unknown" and never an exception. Out of them come
events (inventory findings, enforcement gone, DNS lock changes, disk guard stages, canary results) and the
facts the heartbeat reports (units, policy modes, nft counters, dns_lock, inventory).
"""
import hashlib
import json
import os
import stat

from .. import event as ev

INTERVAL_S = 60
MAX_BYTES = {"inventory": 1024 * 1024, "default": 64 * 1024}
INVENTORY_STALE_S = 2 * 3600
INVENTORY_GRACE_S = 10 * 60       # a missing file right after the agent starts is not stale yet
FRESH_S = {"edr-bans": 300, "edr-inventory": INVENTORY_STALE_S, "edr-diskguard": 600, "edr-dns-watch": 300,
           "edr-policy-check": 600}
FINDING_REPEAT_S = 24 * 3600
REMINDER_S = 6 * 3600
BOOT_GRACE_S = 300
RULES_SKIPPED_DAYS = 3
RULES_STALE_S = 3 * 86400
HEARTBEAT_INVENTORY_CAP = 256 * 1024
SEVS = ev.SEVERITIES


def read_status_file(path, limit):
    """(object, written_at epoch seconds, reason): reason is '' when the file was read."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None, None, "missing"
    except OSError:
        return None, None, "unreadable"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, None, "not a regular file"
        if st.st_size > limit:
            return None, None, "oversize"
        data = os.read(fd, limit + 1)
    except OSError:
        return None, None, "unreadable"
    finally:
        os.close(fd)
    try:
        obj = json.loads(data)
    except ValueError:
        return None, None, "invalid"
    if not isinstance(obj, dict):
        return None, None, "invalid"
    written = obj.get("written_at")
    if not isinstance(written, (int, float)) or isinstance(written, bool):
        written = st.st_mtime
    return obj, float(written), ""


def _num(value, default=0):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else default


class HelperWatcher:
    def __init__(self, ctx, uptime=None, state_path=None):
        self.ctx = ctx
        self.paths = ctx.paths
        self.started = ctx.clock()
        self.next_poll = 0.0
        self.uptime = uptime or self._proc_uptime
        self.status = {}                 # name -> (obj, written_at, reason)
        self.inventory = None
        self.inventory_reason = "missing"
        self.inventory_sha = ""
        self.stale_announced = 0.0
        self.findings = {}               # key -> last emitted time
        self.dns_state = None
        self.disk_stage = 0
        self.disk_emitted = 0.0
        self.disk_low_at = 0.0
        self.rules_emitted = 0.0
        self.gone_key = None
        self.gone_emitted = 0.0
        self.canary_at = None
        self.kernel_state_path = state_path or self.paths.agent_state_json
        self.state = self._load_state()

    # ---- state kept across restarts -------------------------------------------------------------
    def _load_state(self):
        try:
            with open(self.kernel_state_path, "rb") as f:
                obj = json.loads(f.read(8192))
            return obj if isinstance(obj, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_state(self):
        try:
            os.makedirs(os.path.dirname(self.kernel_state_path), mode=0o700, exist_ok=True)
            tmp = self.kernel_state_path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(self.state, f)
            os.replace(tmp, self.kernel_state_path)
        except OSError:
            pass

    def _proc_uptime(self):
        try:
            with open(self.paths.proc("uptime")) as f:
                return float(f.read(64).split()[0])
        except (OSError, ValueError, IndexError):
            return 1e9

    # ---- polling --------------------------------------------------------------------------------
    def poll(self, now):
        """Events from the status files; reads them at most once a minute."""
        if now < self.next_poll:
            return []
        self.next_poll = now + INTERVAL_S
        p = self.paths
        self.status = {
            "edr-inventory": read_status_file(p.inventory_json, MAX_BYTES["inventory"]),
            "edr-bans": read_status_file(p.bans_counters, MAX_BYTES["default"]),
            "edr-diskguard": read_status_file(p.diskguard_status, MAX_BYTES["default"]),
            "edr-dns-watch": read_status_file(p.dns_watch_status, MAX_BYTES["default"]),
            "edr-policy-check": read_status_file(p.policy_check_status, MAX_BYTES["default"]),
            "rules": read_status_file(p.rules_status, MAX_BYTES["default"]),
        }
        events = []
        events.extend(self._inventory(now))
        events.extend(self._policy_check(now))
        events.extend(self._dns(now))
        events.extend(self._disk(now))
        events.extend(self._disk_low(now))
        events.extend(self._rules(now))
        return events

    def _rules(self, now):
        """edr-rules-update's edr-rules-status.json: {written_at, ok, skipped_days, message}. health.rules_stale (MEDIUM) when
        three days in a row were skipped for want of memory, or the last success is over three days old."""
        if not self.ctx.cfg.getbool("kit", "suricata", True):
            return []
        obj, written, reason = self.status["rules"]
        if obj is None:
            return []
        ok = obj.get("ok") is True
        skipped = obj.get("skipped_days")
        skipped = skipped if isinstance(skipped, int) and not isinstance(skipped, bool) else 0
        if ok:
            self.state["rules_ok_at"] = written
            self._save_state()
        last_ok = self.state.get("rules_ok_at")
        why = None
        if skipped >= RULES_SKIPPED_DAYS:
            why = "%d days of rule updates were skipped (memory too short)" % skipped
        elif isinstance(last_ok, (int, float)) and now - last_ok > RULES_STALE_S:
            why = "the last successful rule update was %d days ago" % ((now - last_ok) // 86400)
        if why is None:
            self.rules_emitted = 0.0
            return []
        if now - self.rules_emitted < REMINDER_S:
            return []
        self.rules_emitted = now
        return [ev.make_event("health.rules_stale", "agent", "MEDIUM", "the Suricata rules are going stale: " + why,
                              details={"skipped_days": skipped, "message": str(obj.get("message", "")), "ok": ok})]

    def _disk_low(self, now):
        """statvfs of the agent's state directory: under 10% free is CRITICAL health.disk_low (every 30 min while it lasts).
        Emptying the low spool lane under pressure is the uplink's job."""
        path = self.paths.state_dir
        while path and not os.path.exists(path):
            parent = os.path.dirname(path)
            if parent == path:
                break
            path = parent
        try:
            st = os.statvfs(path)
        except OSError:
            return []
        if st.f_blocks <= 0:
            return []
        free = 100.0 * st.f_bavail / st.f_blocks
        if free >= 10.0:
            self.disk_low_at = 0.0
            return []
        if now - self.disk_low_at < 1800:
            return []
        self.disk_low_at = now
        return [ev.make_event("health.disk_low", "agent", "CRITICAL", "free disk space is %.1f%%" % free,
                              details={"free_pct": round(free, 1), "path": path})]

    def obj(self, name):
        entry = self.status.get(name)
        return entry[0] if entry else None

    def age(self, name, now=None):
        entry = self.status.get(name)
        if not entry or entry[1] is None:
            return None
        return (now if now is not None else self.ctx.clock()) - entry[1]

    def fresh(self, name, now=None):
        age = self.age(name, now)
        return age is not None and age <= FRESH_S.get(name, 600)

    # ---- inventory ------------------------------------------------------------------------------
    def _inventory(self, now):
        obj, written, reason = self.status["edr-inventory"]
        events = []
        stale = obj is None or now - written > INVENTORY_STALE_S
        if obj is not None and not stale:
            self.inventory, self.inventory_reason = obj, ""
            self.inventory_sha = hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()
            checks = obj.get("checks")
            self.ctx.inventory_checks = checks if isinstance(checks, dict) else {}
            self.stale_announced = 0.0
            events.extend(self._findings(obj, now))
            return events
        self.inventory = None
        self.inventory_reason = reason or "stale"
        self.ctx.inventory_checks = {}
        if obj is None and now - self.started < INVENTORY_GRACE_S:
            return events
        if now - self.stale_announced >= REMINDER_S:
            self.stale_announced = now
            events.append(ev.make_event("inventory.stale", "agent", "MEDIUM",
                                        "the inventory result is missing or over 2 hours old: its checks are unknown, not clean",
                                        details={"reason": self.inventory_reason,
                                                 "age_s": int(now - written) if written else None}))
        return events

    def _findings(self, obj, now):
        events, live = [], set()
        findings = obj.get("findings")
        if not isinstance(findings, list):
            return events
        for f in findings[:200]:
            if not isinstance(f, dict):
                continue
            check = str(f.get("check", ""))[:48]
            sev = f.get("sev") if f.get("sev") in SEVS else "MEDIUM"
            summary = str(f.get("summary", ""))
            details = f.get("details") if isinstance(f.get("details"), dict) else {}
            if not check:
                continue
            key = hashlib.sha1(json.dumps([check, sev, summary, details], sort_keys=True, default=str).encode()).hexdigest()
            live.add(key)
            last = self.findings.get(key)
            if last is None or now - last >= FINDING_REPEAT_S:
                self.findings[key] = now
                events.append(ev.make_event("inventory." + check, "inventory", sev, summary or check, details=details))
        for key in list(self.findings):
            if key not in live:
                del self.findings[key]
        return events

    def inventory_for_heartbeat(self):
        """The inventory object as it is, or an explicit unknown. Never a guess."""
        if self.inventory is None:
            return {"status": "unknown", "reason": self.inventory_reason or "missing"}
        if len(json.dumps(self.inventory)) > HEARTBEAT_INVENTORY_CAP:
            return {"status": "unknown", "reason": "oversize"}
        return self.inventory

    # ---- policy check ---------------------------------------------------------------------------
    def tetragon_list(self):
        obj = self.obj("edr-policy-check")
        out = []
        if obj and isinstance(obj.get("policies"), list):
            for p in obj["policies"][:64]:
                if not isinstance(p, dict) or not isinstance(p.get("name"), str):
                    continue
                mode = p.get("mode") if p.get("mode") in ("monitor", "enforce") else "monitor"
                out.append({"name": p["name"][:64], "mode": mode, "would_be_kills": int(_num(p.get("would_be_kills"), 0))})
        return out

    def _policy_check(self, now):
        obj, written, reason = self.status["edr-policy-check"]
        events = []
        if obj is None:
            return events
        policies = [p for p in obj.get("policies", []) if isinstance(p, dict) and isinstance(p.get("name"), str)] \
            if isinstance(obj.get("policies"), list) else []
        want = set(self.ctx.cfg.getlist("tetragon", "enforce"))
        want |= {p["name"] for p in policies if p.get("want") == "enforce"}
        gone = set()
        listed = obj.get("enforcement_gone")
        if isinstance(listed, list):
            gone |= {str(x)[:64] for x in listed}
        for p in policies:
            if p["name"] in want and p.get("state") in ("missing", "error"):
                gone.add(p["name"])
        reasons = {}
        for name in sorted(gone):
            reasons[name] = "not loaded"
        kernel = obj.get("kernel") if isinstance(obj.get("kernel"), str) else None
        canary = obj.get("canary") if isinstance(obj.get("canary"), dict) else {}
        events.extend(self._canary(canary, now))
        if kernel:
            if self.state.get("kernel") != kernel:
                first = "kernel" not in self.state
                self.state["kernel"] = kernel
                self.state["kernel_changed_at"] = 0 if first else now
                self.state["kernel_alerted"] = bool(first)
                self._save_state()
            changed_at = self.state.get("kernel_changed_at", 0)
            canary_ok = canary.get("ok") is True and _num(canary.get("at")) >= changed_at
            if changed_at and not canary_ok and now - changed_at > BOOT_GRACE_S:
                reasons["kernel"] = "kernel changed and the canary has not passed"
        if canary and canary.get("ok") is False and want:
            reasons["canary"] = "the enforcement canary failed"
        if self.uptime() < BOOT_GRACE_S:
            return events
        key = tuple(sorted(reasons.items()))
        if key and (key != self.gone_key or now - self.gone_emitted >= REMINDER_S):
            self.gone_key, self.gone_emitted = key, now
            events.append(ev.make_event("health.enforcement_gone", "agent", "HIGH",
                                        "enforcement may be gone: " + ", ".join("%s (%s)" % kv for kv in key),
                                        details={"policies": sorted(gone), "reasons": reasons, "kernel": kernel}))
        elif not key:
            self.gone_key = None
        return events

    def _canary(self, canary, now):
        at = canary.get("at")
        if not isinstance(at, (int, float)) or isinstance(at, bool) or at <= 0:
            return []
        known = self.state.get("canary_at", self.canary_at)
        if known == at:
            return []
        self.canary_at = at
        self.state["canary_at"] = at
        self._save_state()
        return [ev.make_event("canary.policy_check", "canary", "INFO", "daily enforcement canary: %s" % ("passed" if canary.get("ok") else "FAILED"),
                              details={"ok": canary.get("ok") is True, "detail": str(canary.get("detail", "")), "at": int(at)},
                              ts_ms=int(at * 1000))]

    # ---- dns watch ------------------------------------------------------------------------------
    def dns_lock(self):
        obj = self.obj("edr-dns-watch")
        if not obj:
            return None
        state = obj.get("state") if obj.get("state") in ("locked", "open", "paused", "flapping") else None
        if state is None:
            return None
        return {"state": state, "since": _num(obj.get("since"), 0), "relocks": int(_num(obj.get("relocks"), 0))}

    def _dns(self, now):
        info = self.dns_lock()
        if info is None:
            return []
        state, prev = info["state"], self.dns_state
        self.dns_state = state
        if state == prev:
            return []
        if state == "open":
            return [ev.make_event("edr.dnslock", "agent", "CRITICAL", "the DNS lock failed open: plain DNS is allowed again",
                                  details={"what": "failopen", "since": info["since"], "relocks": info["relocks"]})]
        if state == "flapping":
            return [ev.make_event("edr.dnslock", "agent", "HIGH", "the DNS lock keeps failing and re-locking (flapping)",
                                  details={"what": "flapping", "since": info["since"], "relocks": info["relocks"]})]
        if state == "locked" and prev in ("open", "flapping"):
            return [ev.make_event("edr.dnslock", "agent", "INFO", "the DNS lock is back",
                                  details={"what": "relock", "since": info["since"], "relocks": info["relocks"]})]
        return []

    # ---- disk guard -----------------------------------------------------------------------------
    def _disk(self, now):
        obj = self.obj("edr-diskguard")
        if not obj:
            return []
        stage = int(_num(obj.get("stage"), 0))
        events = []
        if stage > 0 and (stage != self.disk_stage or now - self.disk_emitted >= 1800):
            self.disk_emitted = now
            events.append(ev.make_event("health.diskguard", "agent", "CRITICAL",
                                        "the disk guard is at stage %d: free space is %s%%" % (stage, _num(obj.get("free_pct"), "?")),
                                        details={"stage": stage, "free_pct": _num(obj.get("free_pct"), -1),
                                                 "freed_mb": _num(obj.get("freed_mb"), 0)}))
        self.disk_stage = stage
        return events

    # ---- for the heartbeat ----------------------------------------------------------------------
    def nft(self):
        obj = self.obj("edr-bans")
        if not obj or not self.fresh("edr-bans"):
            return None                  # unknown: the hub reads table_present False as "the table is gone"
        out = {"table_present": obj.get("table_present") is True}
        if isinstance(obj.get("sets"), dict):
            out["sets"] = {str(k)[:32]: int(_num(v)) for k, v in list(obj["sets"].items())[:16]}
        if isinstance(obj.get("counters"), dict):
            out["counters"] = {str(k)[:32]: int(_num(v)) for k, v in list(obj["counters"].items())[:16]}
        return out

    def conntrack(self):
        obj = self.obj("edr-bans")
        ct = obj.get("conntrack") if obj and isinstance(obj.get("conntrack"), dict) else None
        if ct:
            return {k: int(_num(ct.get(k))) for k in ("count", "max", "drop", "early_drop")}
        out = {}
        for key, name in (("count", "nf_conntrack_count"), ("max", "nf_conntrack_max")):
            try:
                with open(self.paths.proc("sys", "net", "netfilter", name)) as f:
                    out[key] = int(f.read(32).strip())
            except (OSError, ValueError):
                return None
        out["drop"] = out["early_drop"] = 0
        return out

    def disk_stats(self):
        obj = self.obj("edr-diskguard")
        return obj
