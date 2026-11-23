"""Suricata's eve.json (alert, anomaly, stats) and eve-bulk.json (tls, ssh, quic context).

Alerts become suricata.alert events; the 60 s stats record feeds the heartbeat key suricata_drops; the
bulk file only adds SNI, JA4 and HASSH context to alerts of the same flow. A missing bulk file is normal
(the disk guard may drop it). src_trust is `tcp` only for a TCP flow with an app_proto (client PLAN 4.2);
everything else, and a web-port alert while the log address may be a proxy's, is `claimed`.
"""
import json

from .. import event as ev
from .. import tail
from .base import Source

SEVERITY = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
FLOW_CONTEXT_MAX = 5000


def _int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class EveSource(Source):
    name = "suricata"

    def __init__(self, ctx, first_start="end", path=None):
        super().__init__(ctx)
        self.path = path or ctx.paths.eve_json
        self.reader = tail.Tailer(self.path, "eve", ctx.paths.cursors_dir, first_start=first_start, clock=ctx.clock)
        self.bad_json = 0
        self._prev = None

    def poll(self, now):
        events = []
        for line in self.reader.poll():
            events.extend(self.parse_line(line))
        return self.notice_events("eve.json") + events

    def parse_line(self, line):
        try:
            obj = json.loads(line)
        except ValueError:
            self.bad_json += 1
            return []
        if not isinstance(obj, dict):
            self.bad_json += 1
            return []
        kind = obj.get("event_type")
        try:
            if kind == "alert":
                return [self.alert(obj)]
            if kind == "anomaly":
                return [self.anomaly(obj)]
            if kind == "stats":
                self.stats(obj)
        except (KeyError, TypeError, ValueError, AttributeError):
            self.bad_json += 1
        return []

    def _flow_trust(self, obj):
        proto = str(obj.get("proto", "")).upper()
        app = obj.get("app_proto")
        trust = "tcp" if proto == "TCP" and app and app != "failed" else "claimed"
        if trust == "tcp" and _int(obj.get("dest_port")) in (80, 443) and self.ctx.web_src_trust() == "claimed":
            trust = "claimed"
        return trust

    def _context(self, obj):
        key = obj.get("community_id") or obj.get("flow_id")
        return self.ctx.eve_flow_context.get(key) if key else None

    def alert(self, obj):
        a = obj.get("alert") if isinstance(obj.get("alert"), dict) else {}
        flow = obj.get("flow") if isinstance(obj.get("flow"), dict) else {}
        sev = SEVERITY.get(_int(a.get("severity"), 3), "LOW")
        sid = _int(a.get("signature_id"))
        details = {"sid": sid, "signature_id": sid, "signature": str(a.get("signature", "")), "category": str(a.get("category", "")),
                   "severity": _int(a.get("severity"), 3), "action": str(a.get("action", "")),
                   "app_proto": str(obj.get("app_proto", "")), "pkts_toserver": _int(flow.get("pkts_toserver")),
                   "pkts_toclient": _int(flow.get("pkts_toclient"))}
        if "stream" in obj:
            details["stream"] = _int(obj.get("stream"))
        http = obj.get("http") if isinstance(obj.get("http"), dict) else None
        if http:
            for src, dst in (("url", "url"), ("http_method", "method"), ("hostname", "host"), ("status", "http_status")):
                if http.get(src) not in (None, ""):
                    details[dst] = http[src]
        tls = obj.get("tls") if isinstance(obj.get("tls"), dict) else None
        if tls and tls.get("sni"):
            details["sni"] = tls["sni"]
        extra = self._context(obj)
        if extra:
            for k, v in extra.items():
                details.setdefault(k, v)
        mode = self.ctx.cfg.get("agent", "payload", "hex-head")
        if mode == "hex-head" and obj.get("payload"):
            head = ev.payload_head_hex(obj["payload"])
            if head:
                details["payload_hex"] = head
        proto = str(obj.get("proto", "")).lower() or None
        return ev.make_event("suricata.alert", "suricata", sev, str(a.get("signature", "Suricata alert")) or "Suricata alert",
                             details=details, ts_ms=ev.parse_ts(obj.get("timestamp")), src_ip=str(obj.get("src_ip", "")),
                             src_trust=self._flow_trust(obj), dst_ip=str(obj.get("dest_ip", "")),
                             dst_port=_int(obj.get("dest_port"), None) if obj.get("dest_port") is not None else None,
                             proto=proto, community_id=obj.get("community_id"))

    def anomaly(self, obj):
        an = obj.get("anomaly") if isinstance(obj.get("anomaly"), dict) else {}
        details = {"type": str(an.get("type", "")), "event": str(an.get("event", "")), "layer": str(an.get("layer", ""))}
        return ev.make_event("suricata.alert", "suricata", "LOW", "Suricata anomaly: %s %s" % (details["type"], details["event"]),
                             details=details, ts_ms=ev.parse_ts(obj.get("timestamp")), src_ip=str(obj.get("src_ip", "")),
                             src_trust="claimed", dst_ip=str(obj.get("dest_ip", "")),
                             proto=str(obj.get("proto", "")).lower() or None)

    def stats(self, obj):
        st = obj.get("stats") if isinstance(obj.get("stats"), dict) else {}
        cap = st.get("capture") if isinstance(st.get("capture"), dict) else {}
        if "kernel_packets" not in cap:
            return
        packets, drops = _int(cap.get("kernel_packets")), _int(cap.get("kernel_drops"))
        ts = (ev.parse_ts(obj.get("timestamp")) or int(self.ctx.clock() * 1000)) / 1000.0
        prev, self._prev = self._prev, (packets, drops, ts)
        if prev is None:
            return
        dp, dd = packets - prev[0], drops - prev[1]
        if dp < 0 or dd < 0:          # the counters restarted with Suricata
            dp, dd = packets, drops
        self.ctx.suricata_drops = {"packets": dp, "drops": dd, "window_s": max(1, int(round(ts - prev[2])))}


class EveBulkSource(Source):
    name = "suricata_bulk"

    def __init__(self, ctx, first_start="end", path=None):
        super().__init__(ctx)
        self.path = path or ctx.paths.eve_bulk_json
        self.reader = tail.Tailer(self.path, "eve-bulk", ctx.paths.cursors_dir, first_start=first_start, clock=ctx.clock)
        self.bad_json = 0

    def poll(self, now):
        for line in self.reader.poll():
            self.parse_line(line)
        self.notice_events()            # a gap in the bulk file costs context only
        return []

    def parse_line(self, line):
        try:
            obj = json.loads(line)
        except ValueError:
            self.bad_json += 1
            return
        if not isinstance(obj, dict):
            return
        kind = obj.get("event_type")
        key = obj.get("community_id") or obj.get("flow_id")
        if kind not in ("tls", "ssh", "quic") or not key:
            return
        info = {}
        sub = obj.get(kind) if isinstance(obj.get(kind), dict) else {}
        if kind in ("tls", "quic"):
            if sub.get("sni"):
                info["sni"] = sub["sni"]
            if sub.get("ja4"):
                info["ja4"] = sub["ja4"]
        else:
            client = sub.get("client") if isinstance(sub.get("client"), dict) else {}
            hassh = client.get("hassh") if isinstance(client.get("hassh"), dict) else {}
            if hassh.get("hash"):
                info["hassh"] = hassh["hash"]
        if not info:
            return
        flows = self.ctx.eve_flow_context
        flows.setdefault(key, {}).update(info)
        flows.move_to_end(key)
        while len(flows) > FLOW_CONTEXT_MAX:
            flows.popitem(last=False)
