"""The kernel log: the kit's own nftables lines (edr-bigconn:, edr-dnslock:, edr-egress:).

Read from `journalctl -k -f`, or with --kernel-log FILE|FIFO from a file or FIFO (the test seam of client PLAN
section 11). Only lines that start with `edr-` count: the kernel wrote them, so SRC= is trusted. From the
journal a record also needs _TRANSPORT=kernel, a field an unprivileged process cannot set.
"""
import re
import subprocess

from .. import event as ev
from .. import tail
from .base import Source, cut_line, parse_ip

_PREFIX = re.compile(r"^(?:<\d+>)?(?:\[\s*\d+\.\d+\]\s*)?")
_LINE = re.compile(r"^(edr-(?:bigconn|dnslock|egress)): ?(.*)$", re.DOTALL)
_KV = re.compile(r"\b([A-Z]+)=(\S*)")
_METADATA = "169.254.169.254"


def parse_kernel_line(text):
    """dict(prefix, what, fields) for an edr- kernel line, or None."""
    text = cut_line(text).strip()
    text = _PREFIX.sub("", text, count=1)
    m = _LINE.match(text)
    if not m:
        return None
    prefix, rest = m.groups()
    what = ""
    if prefix == "edr-dnslock":
        first = rest.split(None, 1)[0] if rest.split() else ""
        if first in ("plain", "self", "doh"):
            what = first
        else:
            return None
    fields = {k: v for k, v in _KV.findall(rest)}
    return {"prefix": prefix, "what": what, "fields": fields}


class KernelSource(Source):
    name = "kernel"

    def __init__(self, ctx, seen, mode="journal", first_start="end", command="journalctl", popen=subprocess.Popen):
        super().__init__(ctx)
        self.seen = seen
        self.mode = mode
        if mode == "journal":
            self.reader = tail.JournalFollower("kernel", [], ctx.paths.cursors_dir, kernel=True, command=command,
                                               popen=popen, clock=ctx.clock)
        else:
            self.reader = tail.open_line_source(mode, "kernel", ctx.paths.cursors_dir, first_start=first_start, clock=ctx.clock)

    def poll(self, now):
        events = []
        for item in self.reader.poll():
            if isinstance(item, dict):
                if item.get("_TRANSPORT") != "kernel" or not isinstance(item.get("MESSAGE"), str):
                    continue
                try:
                    ts = int(item.get("__REALTIME_TIMESTAMP")) // 1000
                except (TypeError, ValueError):
                    ts = None
                events.extend(self.to_events(item["MESSAGE"], ts))
            else:
                events.extend(self.to_events(item, None))
        return self.notice_events() + events

    def to_events(self, text, ts):
        p = parse_kernel_line(text)
        if p is None:
            return []
        f = p["fields"]
        src, dst = parse_ip(f.get("SRC", "")), parse_ip(f.get("DST", ""))
        proto = f.get("PROTO", "").lower() or None
        dport = int(f["DPT"]) if f.get("DPT", "").isdigit() and int(f["DPT"]) <= 65535 else None
        uid = int(f["UID"]) if f.get("UID", "").isdigit() else None
        prefix = p["prefix"]
        if prefix == "edr-bigconn":
            return [ev.make_event("edr.bigconn", "kernel", "MEDIUM",
                                  "one very large inbound connection to port %s from %s" % (dport or "?", src or "?"),
                                  details={"sport": f.get("SPT", ""), "iface": f.get("IN", "")},
                                  ts_ms=ts, src_ip=src, src_trust="tcp" if src else "none", dst_ip=dst, dst_port=dport, proto=proto)]
        if prefix == "edr-dnslock":
            sev = self._dns_sev(p["what"], uid)
            details = {"what": p["what"], "uid": uid, "user": self.ctx.user_name(uid) if uid is not None else ""}
            return [ev.make_event("edr.dnslock", "kernel", sev,
                                  "plain-DNS lock refused a %s lookup by uid %s to %s" % (p["what"], uid, dst or "?"),
                                  details=details, ts_ms=ts, dst_ip=dst, dst_port=dport, proto=proto)]
        return self._egress(uid, dst, dport, proto, ts)

    def _dns_sev(self, what, uid):
        web = uid is not None and uid in self.ctx.web_uids()
        if what == "doh":
            return "MEDIUM" if web else "LOW"
        if web:
            return "HIGH"
        if uid is None or uid == 0:
            return "LOW"
        return "MEDIUM"

    def _egress(self, uid, dst, dport, proto, ts):
        first = self.seen.add("egress", "%s|%s|%s" % (uid, dst, dport))
        if dst == _METADATA:
            sev, text = "MEDIUM", "a web user connected to the cloud metadata address"
        elif not first:
            return []
        else:
            sev = "INFO" if self.seen.learning() else "LOW"
            text = "first connection by uid %s to %s port %s" % (uid, dst, dport)
        details = {"uid": uid, "user": self.ctx.user_name(uid) if uid is not None else "",
                   "learning": self.seen.learning()}
        return [ev.make_event("edr.egress", "kernel", sev, text, details=details, ts_ms=ts, dst_ip=dst, dst_port=dport, proto=proto)]
