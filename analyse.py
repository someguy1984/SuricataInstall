#!/usr/bin/env python3
"""Security breakdown of the last few minutes of Suricata logs. Read-only: changes nothing.

Run with: ./analyse.py [--minutes 5] [--end now|latest|TIME] [--top 10] [--json] [--no-color]
  --minutes N  length of the window to analyse (default 5)
  --end        end of the window: 'now' (default), 'latest' (newest record in eve.json) or a local
               time such as '2026-10-05T13:55' or '13:55'
  --top N      rows per table (default 10)
  --json       machine-readable output instead of the report

eve.json (and eve.json.1, if the window crosses a rotation) is read backwards from the end, so only
the window is read however big the file is. fast.log and suricata.log are read the same way,
stats.log only if eve.json has no stats records, and the filestore only for directories changed
during the window.

Needs read access to /var/log/suricata (root, or a member of the suricata group).
Exit status: 0 nothing above LOW, 1 something MEDIUM, 2 something HIGH or CRITICAL, 3 logs unreadable.
"""
import argparse
import ipaddress
import json
import math
import os
import re
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from functools import lru_cache

LOG_DIR = '/var/log/suricata'
CONF = '/etc/suricata/suricata.yaml'
DEFAULT_HOME_NET = '192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,fc00::/7,fe80::/10'
# eve.json is written by several threads, so records can be a little out of time order:
# keep reading this far past the start of the window before stopping.
SLACK = 120

SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
RANK = {s: i for i, s in enumerate(SEVERITIES)}
SCORE = {'CRITICAL': 40, 'HIGH': 20, 'MEDIUM': 8, 'LOW': 2, 'INFO': 0}

# Counters that should not increase on a healthy sensor (substring match on flattened stats keys)
HEALTH_COUNTERS = ('memcap', 'emerg_mode_entered', 'overflow', 'fs_errors', 'kernel_drops',
                   'exception_policy', 'reassembly_gap', 'nfq_error', 'decoder.invalid')
GAUGES = ('uptime', 'memuse', 'active', 'avg', 'max_', '_max', 'spare')
# Configured limits and current usage, not event counters
NOT_COUNTERS = ('memcap.', 'host.memcap', 'ippair.memcap', 'http.byterange.memcap', 'ftp.memcap')

RISKY_INBOUND_PORTS = {23: 'telnet', 139: 'netbios', 445: 'smb', 2375: 'docker', 3306: 'mysql',
                       3389: 'rdp', 5432: 'postgres', 5900: 'vnc', 6379: 'redis', 9200: 'elasticsearch',
                       11211: 'memcached', 27017: 'mongodb'}
RISKY_OUTBOUND_PORTS = {23: 'telnet', 139: 'netbios', 445: 'smb', 1080: 'socks', 3389: 'rdp',
                        4444: 'metasploit default', 5555: 'adb', 6667: 'irc', 6697: 'irc',
                        9001: 'tor', 9030: 'tor', 31337: 'backdoor'}
BEACON_SKIP_PORTS = {53, 123, 853, 5353}
SUSPICIOUS_TLDS = {'zip', 'mov', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'cyou', 'click',
                   'country', 'kim', 'work', 'rest', 'fit', 'loan', 'sbs', 'cfd', 'buzz', 'monster'}
TOOL_UA = re.compile(r'curl|wget|python-requests|python-urllib|aiohttp|go-http-client|powershell|'
                     r'winhttp|nmap|sqlmap|nikto|masscan|zgrab|nuclei|gobuster|dirbuster|hydra|'
                     r'libwww-perl|okhttp|^java/', re.I)
SCANNER_UA = re.compile(r'nmap|sqlmap|nikto|masscan|zgrab|nuclei|gobuster|dirbuster|hydra|censys|'
                        r'shodan|expanse|l9explore|wpscan', re.I)
ATTACK_URL = re.compile(r'\.\./|/etc/passwd|\$\{jndi:|union(\s|%20|\+)+select|<script|/\.env\b|'
                        r'/\.git/|wp-login|xmlrpc\.php|phpunit|cgi-bin|/shell|cmd=|eval\(|'
                        r'base64_decode|/boaform|/HNAP1|/manager/html', re.I)
EXEC_EXT = re.compile(r'\.(exe|dll|scr|msi|ps1|vbs|hta|jar|apk|bat|cmd|sh|elf|bin|lnk|iso)(\?|$)', re.I)
EXEC_TYPES = ('x-dosexec', 'x-msdownload', 'x-executable', 'x-sh', 'hta', 'java-archive',
              'vnd.android.package-archive', 'x-elf')
TWO_LEVEL_SUFFIXES = {'co', 'com', 'org', 'net', 'gov', 'ac', 'edu', 'ltd', 'plc', 'me', 'sch', 'nhs'}


# ---------------------------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------------------------

class ReverseFile:
    """Iterate over a file's lines last-first, reading it from the end in chunks."""

    def __init__(self, path, chunk=1 << 20):
        self.path, self.chunk, self.bytes_read = path, chunk, 0

    def __iter__(self):
        with open(self.path, 'rb') as f:
            pos = f.seek(0, os.SEEK_END)
            rest = b''
            while pos > 0:
                step = min(self.chunk, pos)
                pos -= step
                f.seek(pos)
                lines = (f.read(step) + rest).split(b'\n')
                self.bytes_read += step
                rest = lines[0]
                for line in reversed(lines[1:]):
                    if line:
                        yield line
            if rest:
                yield rest


def parse_iso(s):
    """'2026-10-05T13:21:04.035974+0100' -> epoch seconds. Naive times are local."""
    if len(s) > 5 and s[-5] in '+-' and ':' not in s[-5:]:
        s = s[:-2] + ':' + s[-2:]   # fromisoformat only takes +01:00 before Python 3.11
    return datetime.fromisoformat(s).timestamp()


def read_eve(log_dir, start, end):
    """Return (events by type, stats records, info) for records with start <= timestamp <= end."""
    events = defaultdict(list)
    stats = []          # (ts, raw line): records in the window plus the newest one before it
    info = {'files': [], 'bytes': 0, 'lines': 0, 'bad': 0, 'newest': None, 'oldest': None,
            'complete': False}
    have_baseline = False
    for name in ('eve.json', 'eve.json.1'):
        path = os.path.join(log_dir, name)
        if not os.path.exists(path):
            break
        reader = ReverseFile(path)
        info['files'].append(name)
        for line in reader:
            info['lines'] += 1
            if not line.startswith(b'{"timestamp":"'):
                info['bad'] += 1
                continue
            try:
                ts = parse_iso(line[14:line.index(b'"', 14)].decode())
            except ValueError:
                info['bad'] += 1
                continue
            if info['newest'] is None or ts > info['newest']:
                info['newest'] = ts
            info['oldest'] = ts if info['oldest'] is None else min(info['oldest'], ts)
            is_stats = b'"event_type":"stats"' in line[:120]
            if ts < start:
                if is_stats and not have_baseline:
                    stats.append((ts, line))
                    have_baseline = True
                if ts < start - SLACK:
                    info['complete'] = True
                    break
                continue
            if ts > end:
                continue
            if is_stats:
                stats.append((ts, line))
                continue
            try:
                e = json.loads(line)
            except ValueError:       # usually the line Suricata is writing right now
                info['bad'] += 1
                continue
            e['_ts'] = ts
            events[e.get('event_type', '?')].append(e)
        info['bytes'] += reader.bytes_read
        if info['complete']:
            break
    for lst in events.values():
        lst.sort(key=lambda e: e['_ts'])
    stats.sort()
    return events, stats, info


def read_text_log(path, start, end, parse):
    """Lines of a timestamped text log inside the window, oldest first. parse(line) -> (ts, x) or None."""
    out = []
    if not os.path.exists(path):
        return None
    for raw in ReverseFile(path, chunk=1 << 16):
        r = parse(raw.decode('utf-8', 'replace'))
        if r is None:
            continue
        ts, item = r
        if ts < start - SLACK:
            break
        if start <= ts <= end:
            out.append((ts, item))
    out.reverse()
    return out


SURI_LOG = re.compile(r'^\[[^\]]*\] (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (\w+): (.*)')
SURI_LOG_OLD = re.compile(r'^(\d+/\d+/\d{4}) -- (\d\d:\d\d:\d\d) - <(\w+)> -+ ?(.*)')


def parse_suricata_log(line):
    m = SURI_LOG.match(line)
    if m:
        return time.mktime(time.strptime(m[1], '%Y-%m-%d %H:%M:%S')), (m[2], m[3])
    m = SURI_LOG_OLD.match(line)
    if m:
        return time.mktime(time.strptime(f'{m[1]} {m[2]}', '%d/%m/%Y %H:%M:%S')), (m[3], m[4])
    return None


def parse_fast_log(line):
    try:
        ts = datetime.strptime(line[:26], '%m/%d/%Y-%H:%M:%S.%f').timestamp()
    except ValueError:
        return None
    return ts, 'Drop' in line[26:40]


def read_stats_log(path, start, end):
    """Fallback when eve.json has no stats records: (baseline, latest) counter dicts from stats.log."""
    if not os.path.exists(path):
        return []
    blocks, counters = [], {}
    for raw in ReverseFile(path, chunk=1 << 18):
        line = raw.decode('utf-8', 'replace')
        if line.startswith('Date:'):
            m = re.match(r'Date: (\d+/\d+/\d+) -- (\d\d:\d\d:\d\d)', line)
            ts = time.mktime(time.strptime(f'{m[1]} {m[2]}', '%m/%d/%Y %H:%M:%S')) if m else 0
            if ts <= end:
                blocks.append((ts, counters))
                if ts < start:
                    break
            counters = {}
        elif '|' in line and not line.startswith('Counter'):
            parts = [p.strip() for p in line.split('|')]
            if len(parts) == 3 and parts[2].lstrip('-').isdigit():
                counters[parts[0]] = int(parts[2])
    blocks.sort(key=lambda b: b[0])
    return blocks


def recent_filestore(log_dir, start, end):
    """sha256 names of files the filestore wrote during the window."""
    base = os.path.join(log_dir, 'filestore')
    out = []
    try:
        dirs = list(os.scandir(base))
    except OSError:
        return None
    for d in dirs:
        try:
            if not d.is_dir() or d.stat().st_mtime < start:
                continue
            for f in os.scandir(d.path):
                if not f.name.endswith('.json') and start <= f.stat().st_mtime <= end:
                    out.append((f.stat().st_mtime, f.name, f.stat().st_size))
        except OSError:
            continue
    return sorted(out)


# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------

def load_home_net(conf):
    spec = DEFAULT_HOME_NET
    try:
        with open(conf) as f:
            for line in f:
                m = re.match(r'\s+HOME_NET:\s*"\[?([^"\]]*)\]?"', line)
                if m:
                    spec = m[1]
                    break
    except OSError:
        pass
    nets = []
    for part in spec.split(','):
        part = part.strip()
        if part and not part.startswith(('!', '$')) and part != 'any':
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                pass
    return nets or [ipaddress.ip_network(p) for p in DEFAULT_HOME_NET.split(',')]


HOME_NETS = []


@lru_cache(maxsize=1 << 16)
def addr(ip):
    try:
        return ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None


@lru_cache(maxsize=1 << 16)
def is_home(ip):
    a = addr(ip)
    return a is not None and any(a.version == n.version and a in n for n in HOME_NETS)


@lru_cache(maxsize=1 << 16)
def is_special(ip):
    a = addr(ip)
    return (a is None or a.is_multicast or a.is_unspecified or a.is_loopback
            or (a.version == 4 and str(a).endswith('.255')))


def is_external(ip):
    return not is_home(ip) and not is_special(ip)


def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def registered_domain(name):
    labels = name.rstrip('.').lower().split('.')
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in TWO_LEVEL_SUFFIXES:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def fmt_time(ts):
    return time.strftime('%H:%M:%S', time.localtime(ts))


def fmt_bytes(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if abs(n) < 1024 or unit == 'GB':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024


def flatten(d, prefix=''):
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(flatten(v, f'{prefix}{k}.'))
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            out[f'{prefix}{k}'] = v
    return out


def dns_parts(d):
    """(queries, answers) for both eve DNS formats (v2 flat, v3 lists)."""
    queries = d.get('queries') or ([{'rrname': d['rrname'], 'rrtype': d.get('rrtype')}]
                                   if 'rrname' in d else [])
    answers = list(d.get('answers') or [])
    for rrtype, values in (d.get('grouped') or {}).items():
        for v in values:
            if isinstance(v, str):
                answers.append({'rrtype': rrtype, 'rdata': v,
                                'rrname': queries[0]['rrname'] if queries else ''})
    return queries, answers


def flow_bytes(f):
    fl = f.get('flow', {})
    return fl.get('bytes_toserver', 0), fl.get('bytes_toclient', 0)


# ---------------------------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------------------------

class Analysis:
    def __init__(self, events, start, end, top):
        self.ev, self.start, self.end, self.top = events, start, end, top
        self.findings = []
        self.names = defaultdict(Counter)       # ip -> hostnames seen for it (DNS answers, SNI, Host)
        self.dns_answers = defaultdict(list)    # answer ip -> [(ts, query name, client)]
        self.health = {}
        self.alert_groups = []
        self.chains = []
        self.entities = []

    # -- plumbing ---------------------------------------------------------------------------

    def add(self, sev, cat, title, details=(), entities=(), ts=None):
        self.findings.append({'severity': sev, 'category': cat, 'title': title,
                              'details': list(details), 'entities': sorted(set(entities)),
                              'time': ts})

    def label(self, ip):
        n = self.names.get(ip)
        return f'{ip} ({n.most_common(1)[0][0]})' if n else str(ip)

    def endpoint(self, e, side):
        return f"{self.label(e.get(side + '_ip'))}:{e.get(side + '_port', '')}"

    def run(self):
        self.build_names()
        self.alerts()
        self.drops()
        self.anomalies()
        self.flows()
        self.dns()
        self.tls()
        self.http()
        self.files()
        self.ssh()
        self.correlate()
        self.findings.sort(key=lambda f: (RANK[f['severity']], f['category'], f['title']))
        return self

    def build_names(self):
        for e in self.ev['dns']:
            d = e.get('dns', {})
            queries, answers = dns_parts(d)
            if not answers:
                continue
            client = e.get('dest_ip') if e.get('src_port') == 53 else e.get('src_ip')
            qname = (queries[0].get('rrname') if queries else None)
            for a in answers:
                if a.get('rrtype') in ('A', 'AAAA') and a.get('rdata'):
                    name = qname or a.get('rrname')
                    self.names[a['rdata']][name] += 1
                    self.dns_answers[a['rdata']].append((e['_ts'], name, client))
        for e in self.ev['tls']:
            if e.get('tls', {}).get('sni'):
                self.names[e.get('dest_ip')][e['tls']['sni']] += 1
        for e in self.ev['http']:
            host = e.get('http', {}).get('hostname')
            if host and not addr(host):
                self.names[e.get('dest_ip')][host] += 1

    # -- alerts and drops -------------------------------------------------------------------

    @staticmethod
    def alert_blocked(e):
        return (e['alert'].get('action') == 'blocked'
                or (e.get('verdict') or {}).get('action') in ('drop', 'reject'))

    @staticmethod
    def alert_severity(al, blocked):
        sig, cat = al.get('signature', ''), al.get('category', '')
        meta = al.get('metadata') or {}
        sig_sev = (meta.get('signature_severity') or [''])[0]
        if sig.startswith('SURICATA ') or cat == 'Not Suspicious Traffic':
            return 'INFO'
        if sig.startswith(('ET INFO', 'ET POLICY', 'ET HUNTING', 'GPL INFO', 'ET GAMES', 'ET CHAT')):
            return 'LOW' if al.get('severity', 3) <= 2 else 'INFO'
        sev = {1: 'HIGH', 2: 'MEDIUM'}.get(al.get('severity'), 'LOW')
        if blocked:   # the IPS stopped it: still worth knowing, but contained
            return {'HIGH': 'MEDIUM', 'MEDIUM': 'LOW'}.get(sev, sev)
        if sev == 'HIGH' and sig_sev == 'Critical':
            return 'CRITICAL'
        return sev

    def alerts(self):
        groups = {}
        for e in self.ev['alert']:
            al = e['alert']
            key = (al.get('gid', 1), al.get('signature_id'))
            g = groups.get(key)
            if g is None:
                meta = al.get('metadata') or {}
                refs = [r for r in al.get('references', []) if 'cve' in r.lower()]
                refs += [f'CVE-{c}' if not c.upper().startswith('CVE') else c
                         for c in meta.get('cve', [])]
                g = groups[key] = {'gid': key[0], 'sid': key[1], 'signature': al.get('signature', '?'),
                                   'category': al.get('category', ''), 'rule_severity': al.get('severity'),
                                   'confidence': (meta.get('confidence') or [''])[0],
                                   'signature_severity': (meta.get('signature_severity') or [''])[0],
                                   'cves': sorted(set(refs)), 'count': 0, 'blocked': 0,
                                   'pairs': Counter(), 'flows': set(), 'first': e['_ts'], 'last': e['_ts'],
                                   'severity': 'INFO'}
            blocked = self.alert_blocked(e)
            g['count'] += 1
            g['blocked'] += blocked
            g['pairs'][(e.get('src_ip'), e.get('dest_ip'), e.get('dest_port'))] += 1
            g['flows'].add(e.get('flow_id'))
            g['last'] = e['_ts']
            sev = self.alert_severity(al, blocked)
            if RANK[sev] < RANK[g['severity']]:
                g['severity'] = sev
        self.alert_groups = sorted(groups.values(), key=lambda g: (RANK[g['severity']], -g['count']))
        for g in self.alert_groups:
            if g['severity'] == 'INFO':
                continue
            action = ('blocked' if g['blocked'] == g['count'] else
                      'allowed' if not g['blocked'] else f"{g['blocked']} blocked")
            details = [f"{g['category']} | rule severity {g['rule_severity']}"
                       + (f" | {g['signature_severity']}" if g['signature_severity'] else '')
                       + (f" | confidence {g['confidence']}" if g['confidence'] else '')]
            if g['cves']:
                details.append('References: ' + ', '.join(g['cves'][:5]))
            for (s, d, p), n in g['pairs'].most_common(3):
                details.append(f'{self.label(s)} -> {self.label(d)}:{p}  x{n}')
            ents = {ip for s, d, _ in g['pairs'] for ip in (s, d) if not is_special(ip)}
            self.add(g['severity'], 'alert', f"[{action}] {g['sid']} {g['signature']} (x{g['count']})",
                     details, ents, g['first'])

    def drops(self):
        drops = self.ev['drop']
        if not drops:
            return
        reasons = Counter(e.get('drop', {}).get('reason', '?') for e in drops)
        engine = {r: n for r, n in reasons.items() if r != 'rules'}
        if engine:
            peers = Counter(e.get('dest_ip') if is_home(e.get('src_ip')) else e.get('src_ip')
                            for e in drops if e.get('drop', {}).get('reason') != 'rules')
            self.add('INFO', 'drop',
                     'Packets dropped by the engine (not rules): '
                     + ', '.join(f'{r} x{n}' for r, n in sorted(engine.items(), key=lambda x: -x[1])),
                     ['Usually broken/late TCP packets (e.g. RSTs after a flow closed); only a concern '
                      'if one destination dominates or users report breakage.',
                      'Top peers: ' + ', '.join(f'{self.label(p)} x{n}' for p, n in peers.most_common(5))])

    def anomalies(self):
        an = self.ev['anomaly']
        if not an:
            return
        kinds = Counter(f"{e['anomaly'].get('type')}:{e['anomaly'].get('event') or e['anomaly'].get('code')}"
                        for e in an if 'anomaly' in e)
        per_src = Counter(e.get('src_ip') for e in an)
        sev = 'LOW' if len(an) >= 50 else 'INFO'
        self.add(sev, 'anomaly', f'{len(an)} protocol anomalies',
                 [', '.join(f'{k} x{n}' for k, n in kinds.most_common(5)),
                  'Top sources: ' + ', '.join(f'{self.label(s)} x{n}' for s, n in per_src.most_common(5))],
                 [s for s, n in per_src.most_common(3) if n >= 20])

    # -- flows -------------------------------------------------------------------------------

    def flows(self):
        flows = self.ev['flow']
        unanswered_ports = defaultdict(set)    # (src, dst) -> ports
        unanswered_hosts = defaultdict(set)    # (src, port) -> dsts
        answered_inbound = defaultdict(set)    # (dst, port) -> srcs
        ssh_in = defaultdict(int)
        ssh_out = defaultdict(set)
        beacons = defaultdict(list)
        upload = Counter()
        risky_out = defaultdict(set)
        for f in flows:
            src, dst, dport, sport = f.get('src_ip'), f.get('dest_ip'), f.get('dest_port'), f.get('src_port')
            fl = f.get('flow', {})
            proto = f.get('proto')
            replied = fl.get('pkts_toclient', 0) > 0
            if proto == 'TCP' and not replied and not is_special(dst):
                unanswered_ports[(src, dst)].add(dport)
                unanswered_hosts[(src, dport)].add(dst)
            # midstream pickup can reverse direction: ignore "inbound" flows from a low port to a high one
            reversed_guess = sport is not None and dport is not None and sport < 1024 <= dport
            if is_external(src) and is_home(dst) and replied and proto == 'TCP' and not reversed_guess \
                    and fl.get('bytes_toclient', 0) > 0 and dport is not None and dport < 49152:
                answered_inbound[(dst, dport)].add(src)
            if dport == 22 and proto == 'TCP':
                if is_external(src) and is_home(dst):
                    ssh_in[(src, dst)] += 1
                elif is_home(src) and is_external(dst):
                    ssh_out[src].add(dst)
            if is_home(src) and is_external(dst):
                bts, btc = flow_bytes(f)
                upload[(src, dst)] += bts
                if dport not in BEACON_SKIP_PORTS and fl.get('start'):
                    try:
                        beacons[(src, dst, dport, proto)].append(parse_iso(fl['start']))
                    except ValueError:
                        pass
                if dport in RISKY_OUTBOUND_PORTS and replied and proto == 'TCP':
                    risky_out[(dst, dport)].add(src)

        # Scans: many unanswered ports on one host, or one port on many hosts
        for (src, dst), ports in unanswered_ports.items():
            if len(ports) >= 15:
                ext = is_external(src)
                self.add('LOW' if ext else 'MEDIUM', 'scan',
                         f"{'Inbound' if ext else 'Internal'} port scan: {self.label(src)} -> {self.label(dst)} "
                         f'({len(ports)} unanswered ports)',
                         ['Ports: ' + ', '.join(map(str, sorted(ports)[:20])) + (' ...' if len(ports) > 20 else '')],
                         [src, dst])
        for (src, port), dsts in unanswered_hosts.items():
            if len(dsts) >= 15:
                ext = is_external(src)
                self.add('LOW' if ext else 'MEDIUM', 'scan',
                         f'Sweep: {self.label(src)} tried port {port} on {len(dsts)} hosts without reply',
                         ['Hosts: ' + ', '.join(sorted(dsts)[:10]) + (' ...' if len(dsts) > 10 else '')],
                         [src])

        for (dst, port), srcs in sorted(answered_inbound.items(), key=lambda x: -len(x[1])):
            svc = RISKY_INBOUND_PORTS.get(port)
            sev = 'HIGH' if svc else 'MEDIUM' if port == 22 else 'LOW'
            self.add(sev, 'exposure',
                     f"External hosts reached {self.label(dst)}:{port}{f' ({svc})' if svc else ''} "
                     f'from {len(srcs)} source(s)',
                     ['Sources: ' + ', '.join(self.label(s) for s in sorted(srcs)[:8])],
                     [dst, *srcs])

        for (src, dst), n in ssh_in.items():
            if n >= 10:
                self.add('MEDIUM', 'bruteforce', f'Possible SSH brute force: {self.label(src)} -> {dst} ({n} connections)',
                         [], [src, dst])
        for src, dsts in ssh_out.items():
            if len(dsts) >= 10:
                self.add('MEDIUM', 'lateral', f'{src} opened SSH to {len(dsts)} different external hosts',
                         [', '.join(sorted(dsts)[:10])], [src])

        for (dst, port), srcs in risky_out.items():
            self.add('MEDIUM', 'outbound', f'Outbound {RISKY_OUTBOUND_PORTS[port]} (port {port}) to {self.label(dst)} answered',
                     ['From: ' + ', '.join(sorted(srcs))], [dst, *srcs])

        for (src, dst), n in upload.most_common(5):
            if n >= 100 * 1024 * 1024:
                self.add('LOW', 'exfil', f'{src} uploaded {fmt_bytes(n)} to {self.label(dst)}',
                         ['Large outbound transfer in the window; expected for backups/sync, check otherwise.'],
                         [src, dst])

        # Beaconing: regular connections from one host to one destination
        for (src, dst, port, proto), starts in beacons.items():
            if len(starts) < 6:
                continue
            starts.sort()
            gaps = [b - a for a, b in zip(starts, starts[1:])]
            mean = statistics.mean(gaps)
            if mean < 5:
                continue
            cv = statistics.pstdev(gaps) / mean
            if cv <= 0.15:
                self.add('LOW', 'beacon',
                         f'Regular connections {src} -> {self.label(dst)}:{port}/{proto} every ~{mean:.0f}s',
                         [f'{len(starts)} flows, jitter {cv * 100:.0f}% - typical of keep-alives/polling, '
                          'or of malware check-ins if the destination is unfamiliar'],
                         [src, dst])

    # -- protocols ---------------------------------------------------------------------------

    def dns(self):
        nx = Counter()
        responses = Counter()
        nx_names = defaultdict(set)
        by_base = defaultdict(set)
        txt = Counter()
        odd_tld = defaultdict(set)
        dga = defaultdict(set)
        for e in self.ev['dns']:
            d = e.get('dns', {})
            queries, answers = dns_parts(d)
            client = e.get('dest_ip') if e.get('src_port') == 53 else e.get('src_ip')
            is_resp = d.get('type') in ('response', 'answer')
            if is_resp:
                responses[client] += 1
                if d.get('rcode') == 'NXDOMAIN':
                    nx[client] += 1
                    nx_names[client].update(q.get('rrname', '') for q in queries)
                continue
            for q in queries:
                name = (q.get('rrname') or '').lower().rstrip('.')
                if not name or name.endswith(('.arpa', '.local', '.lan', '.home', '.internal')) or '.' not in name:
                    continue
                base = registered_domain(name)
                by_base[(client, base)].add(name)
                if q.get('rrtype') == 'TXT':
                    txt[client] += 1
                tld = name.rsplit('.', 1)[-1]
                if tld in SUSPICIOUS_TLDS:
                    odd_tld[client].add(name)
                label = base.split('.')[0]
                if len(label) >= 12 and entropy(label) >= 3.5 and sum(c.isdigit() for c in label) >= 2:
                    dga[client].add(name)

        for client, n in nx.items():
            if n >= 15 and n / max(responses[client], 1) >= 0.3 and len(nx_names[client]) >= 10:
                self.add('MEDIUM', 'dns', f'{client}: {n} NXDOMAIN answers ({n * 100 // responses[client]}% of lookups)',
                         ['Many failed lookups can mean DGA malware searching for its C2. Examples: '
                          + ', '.join(sorted(nx_names[client])[:6])], [client])
        for client, names in dga.items():
            self.add('MEDIUM' if len(names) >= 3 else 'LOW', 'dns',
                     f'{client} looked up {len(names)} random-looking domain(s)',
                     ['High-entropy names are typical of DGA malware: ' + ', '.join(sorted(names)[:6])], [client])
        for (client, base), names in by_base.items():
            if len(names) >= 30 and statistics.mean(len(n) for n in names) >= 40:
                self.add('MEDIUM', 'dns', f'Possible DNS tunnelling: {client} queried {len(names)} long subdomains of {base}',
                         ['e.g. ' + ', '.join(sorted(names)[:3])], [client])
        for client, n in txt.items():
            if n >= 50:
                self.add('LOW', 'dns', f'{client} made {n} TXT lookups', ['TXT is a common DNS tunnelling channel'], [client])
        for client, names in odd_tld.items():
            self.add('LOW', 'dns', f'{client} looked up {len(names)} domain(s) in abuse-heavy TLDs',
                     [', '.join(sorted(names)[:8])], [client])

    def tls(self):
        old, expired, selfsigned, nosni = defaultdict(set), [], [], Counter()
        for e in self.ev['tls']:
            t = e.get('tls', {})
            dst = e.get('dest_ip')
            if not is_external(dst):
                continue
            who = f"{e.get('src_ip')} -> {self.label(dst)}:{e.get('dest_port')}"
            if t.get('version') in ('SSLv2', 'SSLv3', 'TLS 1.0', 'TLS 1.1'):
                old[t['version']].add(who)
            if t.get('notafter'):
                try:
                    if parse_iso(t['notafter']) < e['_ts']:
                        expired.append((who, t.get('subject', '')))
                except ValueError:
                    pass
            if t.get('subject') and t.get('subject') == t.get('issuerdn'):
                selfsigned.append((who, t['subject']))
            if not t.get('sni') and t.get('version'):
                nosni[(e.get('src_ip'), dst)] += 1
        def summarise(items):
            return [f'{w} x{n}' if n > 1 else w for w, n in Counter(items).most_common(5)]

        for ver, whos in old.items():
            self.add('LOW', 'tls', f'{len(whos)} connection(s) with obsolete {ver}', sorted(whos)[:5],
                     [w.split(' ')[0] for w in whos])
        if expired:
            self.add('MEDIUM', 'tls', f'{len(expired)} TLS session(s) to servers with expired certificates',
                     summarise(f'{w} [{s}]' for w, s in expired), [w.split(' ')[0] for w, _ in expired])
        if selfsigned:
            self.add('LOW', 'tls', f'{len(selfsigned)} TLS session(s) to external self-signed certificates',
                     summarise(f'{w} [{s}]' for w, s in selfsigned), [w.split(' ')[0] for w, _ in selfsigned])
        if nosni:
            self.add('INFO', 'tls', f'{sum(nosni.values())} TLS session(s) without SNI to external IPs',
                     [f'{s} -> {self.label(d)} x{n}' for (s, d), n in nosni.most_common(5)])

    def http(self):
        tool_out, tool_in, ip_host, attacks, errors4xx, odd_methods = (defaultdict(set) for _ in range(6))
        err_count = Counter()
        for e in self.ev['http']:
            h = e.get('http', {})
            src, dst = e.get('src_ip'), e.get('dest_ip')
            ua = h.get('http_user_agent', '')
            url = h.get('url', '')
            host = h.get('hostname', '')
            inbound = is_external(src) and is_home(dst)
            if inbound:
                if SCANNER_UA.search(ua) or TOOL_UA.search(ua):
                    tool_in[src].add(ua[:80])
                if ATTACK_URL.search(url):
                    attacks[src].add(f"{h.get('http_method', '?')} {url[:100]} -> {h.get('status', '-')}")
                if str(h.get('status', '')).startswith('4'):
                    err_count[src] += 1
                if h.get('http_method') in ('PUT', 'DELETE', 'PROPFIND', 'CONNECT', 'TRACE'):
                    odd_methods[src].add(f"{h['http_method']} {url[:80]}")
            elif is_home(src) and is_external(dst):
                if ua and TOOL_UA.search(ua):
                    tool_out[src].add(f'{ua[:60]} -> {host or dst}')
                if host and addr(host.split(':')[0]):
                    ip_host[src].add(f"{h.get('http_method', '?')} http://{host}{url[:80]}")
        for src, items in attacks.items():
            self.add('HIGH' if any(' -> 2' in i for i in items) else 'MEDIUM', 'web-attack',
                     f'{self.label(src)} sent {len(items)} attack-pattern request(s) to your hosts',
                     sorted(items)[:6], [src])
        for src, uas in tool_in.items():
            self.add('MEDIUM', 'web-attack', f'Scanner/tool user-agent from {self.label(src)}', sorted(uas)[:3], [src])
        for src, n in err_count.items():
            if n >= 20:
                self.add('MEDIUM', 'web-attack', f'{self.label(src)} caused {n} HTTP 4xx responses (content discovery?)', [], [src])
        for src, items in odd_methods.items():
            self.add('LOW', 'web-attack', f'Unusual HTTP methods from {self.label(src)}', sorted(items)[:5], [src])
        for src, items in tool_out.items():
            self.add('INFO', 'http', f'{src} used scripted HTTP clients (plain HTTP)', sorted(items)[:5])
        for src, items in ip_host.items():
            self.add('LOW', 'http', f'{src} made plain-HTTP requests straight to IP addresses',
                     ['Common for malware droppers; also IoT/updaters. ' ] + sorted(items)[:5], [src])

    def files(self):
        execs = []
        for e in self.ev['fileinfo']:
            fi = e.get('fileinfo', {})
            name = fi.get('filename', '')
            magic = (fi.get('magic') or '').lower()
            ctype = (e.get('http', {}).get('http_content_type') or '').lower()
            if EXEC_EXT.search(name) or 'executable' in magic or 'pe32' in magic or any(t in ctype for t in EXEC_TYPES):
                execs.append(e)
        for e in execs:
            fi = e['fileinfo']
            host = e.get('http', {}).get('hostname') or self.label(e.get('src_ip'))
            client = e.get('dest_ip') if is_home(e.get('dest_ip')) else e.get('src_ip')
            self.add('MEDIUM', 'file', f"{client} downloaded executable/script {fi.get('filename', '?')[:80]} from {host}",
                     [f"{fi.get('size', '?')} bytes, sha256 {fi.get('sha256', '?')}"
                      + (' (stored in filestore)' if fi.get('stored') else ''),
                      'Look the hash up on VirusTotal/MalwareBazaar.'],
                     [client, e.get('src_ip')], e['_ts'])

    def ssh(self):
        odd = defaultdict(set)
        for e in self.ev['ssh']:
            client = (e.get('ssh', {}).get('client') or {}).get('software_version', '')
            if is_external(e.get('src_ip')) and is_home(e.get('dest_ip')):
                odd[e['src_ip']].add(client or '(none)')
        for src, sw in odd.items():
            self.add('LOW', 'ssh', f'Inbound SSH session from {self.label(src)}',
                     ['Client software: ' + ', '.join(sorted(sw))], [src])

    # -- correlation -------------------------------------------------------------------------

    def correlate(self):
        # Chains: everything seen on each flow that raised a (non-engine) alert, plus the DNS
        # lookup that led to it.
        alert_flows = {}
        for e in self.ev['alert']:
            if e['alert'].get('signature', '').startswith('SURICATA '):
                continue
            fid = e.get('flow_id')
            c = alert_flows.setdefault(fid, {'flow_id': fid, 'first': e['_ts'], 'alerts': Counter(),
                                              'blocked': False, 'src': e.get('src_ip'), 'dst': e.get('dest_ip'),
                                              'sport': e.get('src_port'), 'dport': e.get('dest_port'),
                                              'proto': e.get('proto'), 'app': e.get('app_proto'),
                                              'community_id': e.get('community_id'),
                                              'severity': 'INFO', 'events': []})
            al = e['alert']
            blocked = self.alert_blocked(e)
            c['alerts'][(al.get('signature_id'), al.get('signature'), 'blocked' if blocked else 'allowed')] += 1
            c['blocked'] |= blocked
            sev = self.alert_severity(al, blocked)
            if RANK[sev] < RANK[c['severity']]:
                c['severity'] = sev
        if alert_flows:
            for etype, lst in self.ev.items():
                if etype in ('alert', 'stats', 'dns'):
                    continue
                for e in lst:
                    c = alert_flows.get(e.get('flow_id'))
                    if c is not None:
                        c['events'].append(e)
            for c in alert_flows.values():
                c['lines'] = self.chain_lines(c)
            self.chains = sorted(alert_flows.values(), key=lambda c: (RANK[c['severity']], c['first']))

        # Entities: an IP that shows up in several kinds of finding is more interesting than any
        # one finding on its own.
        ents = defaultdict(lambda: {'score': 0, 'categories': set(), 'serious': set(), 'findings': [],
                                    'worst': 'INFO'})
        for i, f in enumerate(self.findings):
            for ip in f['entities']:
                if not ip or is_special(ip):
                    continue
                x = ents[ip]
                x['score'] += SCORE[f['severity']]
                if f['severity'] != 'INFO':
                    x['categories'].add(f['category'])
                if RANK[f['severity']] <= RANK['MEDIUM']:
                    x['serious'].add(f['category'])
                x['findings'].append(i)
                if RANK[f['severity']] < RANK[x['worst']]:
                    x['worst'] = f['severity']
        incidents, covered = [], set()
        # Local hosts first: a remote peer whose findings are all already shown under a local
        # host isn't repeated.
        for ip, x in sorted(ents.items(), key=lambda kv: (not is_home(kv[0]), -kv[1]['score'])):
            if len(x['categories']) < 2 or x['score'] < 10 or set(x['findings']) <= covered:
                continue
            covered.update(x['findings'])
            # Independent serious signals pointing at the same host: escalate one level
            sev = SEVERITIES[max(RANK[x['worst']] - (len(x['serious']) >= 2), 0)]
            incidents.append((ip, sev, x))
        for ip, sev, x in incidents:
            self.add(sev, 'correlated',
                     f"{self.label(ip)} is involved in {len(x['categories'])} kinds of activity: "
                     + ', '.join(sorted(x['categories'])),
                     [f"- [{self.findings[i]['severity']}] {self.findings[i]['title']}" for i in x['findings'][:6]]
                     + self.timeline(ip), [ip])
        self.entities = sorted(({'ip': ip, 'label': self.label(ip), 'score': x['score'], 'worst': x['worst'],
                                 'categories': sorted(x['categories']), 'home': is_home(ip)}
                                for ip, x in ents.items() if x['score'] > 0),
                               key=lambda x: -x['score'])

    def chain_lines(self, c):
        lines = []
        remote = c['dst'] if is_home(c['src']) else c['src']
        local = c['src'] if remote == c['dst'] else c['dst']
        lookups = [a for a in self.dns_answers.get(remote, []) if a[0] <= c['first'] and a[2] == local]
        if lookups:
            ts, name, _ = lookups[-1]
            lines.append(f'{fmt_time(ts)} DNS   {local} resolved {name} -> {remote}')
        for e in sorted(c['events'], key=lambda e: e['_ts']):
            t = e.get('event_type')
            when = fmt_time(e['_ts'])
            if t == 'http':
                h = e['http']
                lines.append(f"{when} HTTP  {h.get('http_method', '?')} {h.get('hostname', '')}{h.get('url', '')[:90]} "
                             f"-> {h.get('status', '-')} UA \"{h.get('http_user_agent', '')[:50]}\"")
            elif t == 'tls':
                tl = e['tls']
                lines.append(f"{when} TLS   sni={tl.get('sni', '-')} {tl.get('version', '')} "
                             f"ja4={tl.get('ja4', '-')} subject={tl.get('subject', '-')[:60]}")
            elif t == 'fileinfo':
                fi = e['fileinfo']
                lines.append(f"{when} FILE  {fi.get('filename', '?')[:80]} {fi.get('size', '?')} B "
                             f"sha256={fi.get('sha256', '?')[:16]}..{' stored' if fi.get('stored') else ''}")
            elif t == 'anomaly':
                lines.append(f"{when} ANOM  {e['anomaly'].get('event') or e['anomaly'].get('code')}")
            elif t == 'drop':
                lines.append(f"{when} DROP  {e.get('drop', {}).get('reason', '?')}")
            elif t == 'flow':
                fl = e['flow']
                lines.append(f"{when} FLOW  {fl.get('pkts_toserver', 0)} pkts/{fmt_bytes(fl.get('bytes_toserver', 0))} out, "
                             f"{fl.get('pkts_toclient', 0)} pkts/{fmt_bytes(fl.get('bytes_toclient', 0))} back, "
                             f"{fl.get('age', 0)}s, {fl.get('state', '?')} ({fl.get('reason', '?')})")
            elif t in ('ssh', 'smtp', 'ftp', 'smb', 'rdp', 'krb5', 'ldap', 'quic'):
                lines.append(f"{when} {t.upper():5} {json.dumps(e.get(t), separators=(',', ':'))[:110]}")
        return lines

    def timeline(self, ip, limit=12):
        rows = []
        for e in self.ev['alert']:
            if ip in (e.get('src_ip'), e.get('dest_ip')) and not e['alert'].get('signature', '').startswith('SURICATA '):
                act = 'blocked' if self.alert_blocked(e) else 'allowed'
                rows.append((e['_ts'], f"ALERT [{act}] {e['alert'].get('signature', '')[:70]} "
                                       f"{e.get('src_ip')} -> {e.get('dest_ip')}:{e.get('dest_port')}"))
        for e in self.ev['drop']:
            if ip in (e.get('src_ip'), e.get('dest_ip')) and e.get('drop', {}).get('reason') == 'rules':
                rows.append((e['_ts'], f"DROP  {e.get('src_ip')} -> {e.get('dest_ip')}:{e.get('dest_port')}"))
        for e in self.ev['fileinfo']:
            if ip in (e.get('src_ip'), e.get('dest_ip')):
                rows.append((e['_ts'], f"FILE  {e['fileinfo'].get('filename', '?')[:70]}"))
        rows.sort()
        out = [f'  {fmt_time(ts)} {txt}' for ts, txt in rows]
        if len(out) > limit:
            out = out[:limit // 2] + [f'  ... {len(out) - limit} more ...'] + out[-limit // 2:]
        return (['Timeline:'] + out) if out else []

    # -- engine health -----------------------------------------------------------------------

    def engine_health(self, stats, stats_blocks, suri_log, fast, info, end_is_now, now):
        h = self.health
        if stats:
            old, new = json.loads(stats[0][1]), json.loads(stats[-1][1])   # only two parsed
            a, b = flatten(old.get('stats', {})), flatten(new.get('stats', {}))
            h['samples'] = len(stats)
            span = parse_iso(new['timestamp']) - parse_iso(old['timestamp'])
        elif stats_blocks:
            a, b = stats_blocks[0][1], stats_blocks[-1][1]
            h['samples'] = len(stats_blocks)
            span = stats_blocks[-1][0] - stats_blocks[0][0]
        else:
            a = b = {}
            span = 0
            h['samples'] = 0
        uptimes = [int(m[1]) for _, raw in stats if (m := re.search(rb'"uptime":(\d+)', raw))]
        uptimes = uptimes or [blk.get('uptime', 0) for _, blk in stats_blocks]
        restarts = sum(1 for x, y in zip(uptimes, uptimes[1:]) if y < x)
        restarted = restarts > 0
        delta = {k: (v if restarted or any(g in k for g in GAUGES) else v - a.get(k, 0)) for k, v in b.items()}
        h.update(restarted=restarted, span=span, delta=delta, uptime=b.get('uptime'))
        if restarted:
            self.add('MEDIUM', 'engine', f"Suricata restarted {restarts} time(s) during the window", [
                f"Uptime now {b.get('uptime', 0)}s; counters below are since the last restart. "
                'Check suricata.log / journalctl -u suricata for the cause (crash, rule update, reboot).'])
        if h['samples'] and h['samples'] < 2 and not restarted:
            self.add('INFO', 'engine', 'Only one stats sample in the window: counters are since the previous sample or start')

        bad = {k: v for k, v in delta.items() if v > 0 and any(c in k for c in HEALTH_COUNTERS)
               and not any(g in k for g in GAUGES) and not k.startswith(NOT_COUNTERS)}
        if bad:
            self.add('MEDIUM', 'engine', 'Sensor under pressure: counters that should stay at zero increased',
                     [f'{k} +{v}' for k, v in sorted(bad.items(), key=lambda x: -x[1])[:10]]
                     + ['Packets may have been dropped or passed uninspected; check memcaps and CPU.'])
        app_err = sum(v for k, v in delta.items() if k.startswith('app_layer.error.'))
        if app_err:
            h['app_layer_errors'] = app_err

        if end_is_now and info['newest'] is not None and now - info['newest'] > 60:
            self.add('HIGH', 'engine', f"eve.json has not been written for {int(now - info['newest'])}s",
                     ['Stats are logged every few seconds, so Suricata is probably stopped, hung or not logging. '
                      'With --queue-bypass, traffic is then passing uninspected.'])
        if not info['complete'] and info['oldest'] is not None and info['oldest'] > self.start:
            self.add('INFO', 'engine', f"Logs only go back to {fmt_time(info['oldest'])} (rotated or recently started)")

        if suri_log is not None:
            errors = [(ts, m) for ts, (lvl, m) in suri_log if lvl.lower() in ('error', 'critical', 'alert', 'emergency')]
            warns = [(ts, m) for ts, (lvl, m) in suri_log if lvl.lower() == 'warning']
            notices = [(ts, m) for ts, (lvl, m) in suri_log if lvl.lower() == 'notice']
            if errors:
                self.add('MEDIUM', 'engine', f'{len(errors)} error(s) in suricata.log',
                         [f'{fmt_time(ts)} {m[:140]}' for ts, m in errors[-5:]])
            if warns:
                self.add('LOW', 'engine', f'{len(warns)} warning(s) in suricata.log',
                         [f'{fmt_time(ts)} {m[:140]}' for ts, m in warns[-5:]])
            h['suricata_log'] = {'errors': len(errors), 'warnings': len(warns),
                                 'notices': [f'{fmt_time(ts)} {m[:120]}' for ts, m in notices[-3:]]}
        if fast is not None:
            h['fast_log'] = {'alerts': len(fast), 'drops': sum(1 for _, d in fast if d)}
            if abs(len(fast) - len(self.ev['alert'])) > max(5, len(fast) // 10):
                self.add('INFO', 'engine', f"fast.log has {len(fast)} alerts but eve.json {len(self.ev['alert'])}",
                         ['One of the outputs may be disabled or lagging.'])


# ---------------------------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------------------------

class Report:
    def __init__(self, color):
        c = color
        self.B, self.N = ('\033[1m', '\033[0m') if c else ('', '')
        self.D = '\033[2m' if c else ''
        self.sev_color = {'CRITICAL': '\033[1;97;41m', 'HIGH': '\033[1;31m', 'MEDIUM': '\033[33m',
                          'LOW': '\033[36m', 'INFO': '\033[2m'} if c else defaultdict(str)

    def sev(self, s):
        return f'{self.sev_color[s]}{s:<8}{self.N}'

    def section(self, title):
        print(f'\n{self.B}== {title} =={self.N}')

    def table(self, rows, indent=2):
        if not rows:
            return
        widths = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]) - 1)]
        for r in rows:
            print(' ' * indent + '  '.join(f'{str(v):<{w}}' for v, w in zip(r, widths)) + '  ' + str(r[-1]))


def render(an, info, args, sources, risk, counts):
    R = Report(args.color)
    ev, top, h = an.ev, args.top, an.health
    tz = time.strftime('%z')
    day = lambda t: time.strftime('%Y-%m-%d', time.localtime(t))
    end_day = '' if day(an.start) == day(an.end) else day(an.end) + ' '
    print(f"{R.B}Suricata security breakdown{R.N}  {day(an.start)} {fmt_time(an.start)} -> "
          f'{end_day}{fmt_time(an.end)} ({args.minutes:g} min, {tz})')
    print(f'{R.D}Read {", ".join(sources)}{R.N}')
    worst = [f for f in an.findings if RANK[f['severity']] <= RANK['MEDIUM']]
    print(f"Overall risk: {R.sev(risk).rstrip()}  "
          f"({len(worst)} finding(s) at MEDIUM or above, {len(an.findings)} in total)")

    # Engine
    R.section('Engine health')
    d = h.get('delta', {})
    span = h.get('span') or 0
    if d:
        pkts, byts = d.get('decoder.pkts', 0), d.get('decoder.bytes', 0)
        rate = f' ({pkts / span:,.0f} pkt/s, {byts * 8 / span / 1e6:,.2f} Mbit/s)' if span > 0 else ''
        print(f"  Packets {pkts:,} / {fmt_bytes(byts)}{rate}  over {span:.0f}s of stats "
              f"({h.get('samples')} samples, uptime {int((h.get('uptime') or 0) // 3600)}h)")
        print(f"  IPS verdicts: accepted {d.get('ips.accepted', 0):,}, blocked {d.get('ips.blocked', 0):,}, "
              f"rejected {d.get('ips.rejected', 0):,}")
        reasons = {k.split('.')[-1]: v for k, v in d.items() if k.startswith('ips.drop_reason.') and v}
        if reasons:
            print('  Drop reasons: ' + ', '.join(f'{k} {v:,}' for k, v in sorted(reasons.items(), key=lambda x: -x[1])))
        print(f"  Flows {d.get('flow.total', 0):,} new, {d.get('flow.active', 0):,} active | TCP sessions "
              f"{d.get('tcp.sessions', 0):,} | alerts {d.get('detect.alert', 0):,} "
              f"(+{d.get('detect.alerts_suppressed', 0):,} suppressed) | app-layer errors {h.get('app_layer_errors', 0):,}")
    else:
        print('  No stats records in the window (stats output disabled?)')
    if 'suricata_log' in h:
        sl = h['suricata_log']
        print(f"  suricata.log: {sl['errors']} error(s), {sl['warnings']} warning(s)"
              + ('; recent notices: ' + ' | '.join(sl['notices']) if sl['notices'] else ''))
    if 'fast_log' in h:
        print(f"  fast.log: {h['fast_log']['alerts']} alert line(s), {h['fast_log']['drops']} marked Drop")

    # Activity
    R.section('Activity overview')
    print('  Events: ' + ', '.join(f'{t} {n:,}' for t, n in counts.most_common()))
    flows = ev['flow']
    if flows:
        apps = Counter(f.get('app_proto') or f.get('proto') for f in flows)
        print('  Flows by protocol: ' + ', '.join(f'{p} {n:,}' for p, n in apps.most_common(8)))
        local, remote = Counter(), Counter()
        directions = Counter()
        for f in flows:
            out_b, in_b = flow_bytes(f)
            s, dst = f.get('src_ip'), f.get('dest_ip')
            directions['outbound' if is_home(s) and is_external(dst) else
                       'inbound' if is_external(s) and is_home(dst) else
                       'internal' if is_home(s) and is_home(dst) else 'other'] += 1
            for ip in (s, dst):
                if is_home(ip) and not is_special(ip):
                    local[ip] += out_b + in_b
                elif is_external(ip):
                    remote[ip] += out_b + in_b
        print('  Flow directions: ' + ', '.join(f'{k} {v:,}' for k, v in directions.most_common()))
        print(f'  {R.B}Top local hosts by traffic{R.N}')
        R.table([(fmt_bytes(n), ip) for ip, n in local.most_common(min(top, 5))], 4)
        print(f'  {R.B}Top remote endpoints by traffic{R.N}')
        R.table([(fmt_bytes(n), an.label(ip)) for ip, n in remote.most_common(top)], 4)
    queries = Counter()
    for e in ev['dns']:
        if e.get('dns', {}).get('type') in ('request', 'query'):
            for q in dns_parts(e['dns'])[0]:
                queries[registered_domain(q.get('rrname') or '?')] += 1
    if queries:
        print(f'  {R.B}Top DNS domains{R.N}  ' + ', '.join(f'{d} {n}' for d, n in queries.most_common(top)))
    snis = Counter(e['tls'].get('sni') for e in ev['tls'] if e.get('tls', {}).get('sni'))
    if snis:
        print(f'  {R.B}Top TLS SNIs{R.N}  ' + ', '.join(f'{s} {n}' for s, n in snis.most_common(top)))

    # Alerts
    R.section('Alerts')
    if not an.alert_groups:
        print('  None')
    rows = []
    for g in an.alert_groups[:top]:
        act = 'blocked' if g['blocked'] == g['count'] else 'allowed' if not g['blocked'] else 'mixed'
        pair = g['pairs'].most_common(1)[0][0]
        rows.append((R.sev(g['severity']), f"x{g['count']}", act, g['sid'],
                     f"{g['signature'][:70]}  {R.D}{pair[0]} -> {an.label(pair[1])}:{pair[2]}{R.N}"))
    R.table(rows)
    if len(an.alert_groups) > top:
        print(f'  ... {len(an.alert_groups) - top} more signature(s)')

    # Findings
    R.section('Findings')
    shown = [f for f in an.findings if f['severity'] != 'INFO' or args.verbose]
    if not shown:
        print('  Nothing suspicious found')
    for f in shown:
        print(f"  {R.sev(f['severity'])} {R.D}{f['category']:<10}{R.N} {f['title']}")
        for line in f['details']:
            print(f'           {R.D}{line}{R.N}')
    hidden = len(an.findings) - len(shown)
    if hidden:
        print(f'  {R.D}({hidden} INFO finding(s) hidden; use --verbose){R.N}')

    # Correlation
    R.section('Correlated flows (everything logged on flows that raised alerts)')
    chains = [c for c in an.chains if c['severity'] != 'INFO' or args.verbose]
    if not chains:
        print('  None' + (f" ({len(an.chains)} informational, use --verbose)" if an.chains else ''))
    for c in chains[:top]:
        sigs = '; '.join(f'{sid} {sig[:60]} [{act}] x{n}' for (sid, sig, act), n in c['alerts'].most_common(3))
        print(f"  {R.sev(c['severity'])} {fmt_time(c['first'])} {an.label(c['src'])}:{c['sport']} -> "
              f"{an.label(c['dst'])}:{c['dport']} {c['proto']}/{c['app'] or '?'}"
              + (f"  {R.D}community_id {c['community_id']}{R.N}" if c['community_id'] else ''))
        print(f'           ALERT {sigs}')
        for line in c['lines'][:10]:
            print(f'           {R.D}{line}{R.N}')
    if an.entities:
        print(f'\n  {R.B}Hosts ranked by combined risk score{R.N}')
        R.table([(R.sev(x['worst']), f"score {x['score']}", 'local ' if x['home'] else 'remote',
                  f"{x['label']}  {R.D}{', '.join(x['categories'])}{R.N}") for x in an.entities[:top]], 4)

    R.section('Next steps')
    for line in next_steps(an):
        print(f'  - {line}')


def next_steps(an):
    cats = {f['category'] for f in an.findings if RANK[f['severity']] <= RANK['LOW']}
    steps = []
    if 'correlated' in cats:
        steps.append('Start with the correlated hosts: several independent signals point at them.')
    if 'alert' in cats:
        steps.append('Review the alert flows above. For a false positive, add the SID to /etc/suricata/disable.conf '
                     '(or files/modify.conf to stop it dropping), then: sudo suricata-update && sudo systemctl reload suricata')
        steps.append("Full detail for one SID: jq -c 'select(.alert.signature_id==SID)' /var/log/suricata/eve.json | tail")
    if cats & {'exposure', 'bruteforce', 'web-attack'}:
        steps.append('Something reachable from the internet is being probed or used: confirm the port should be open '
                     '(sudo ufw status, ss -tlnp) and that its logs show no successful logins.')
    if cats & {'scan', 'lateral'}:
        steps.append('For an internal host scanning others, identify the process (ss -tnp / lsof -i on that host).')
    if cats & {'dns', 'beacon', 'outbound', 'file', 'http', 'exfil'}:
        steps.append("Check unfamiliar domains/IPs/hashes on VirusTotal, abuse.ch or AbuseIPDB; "
                     "pivot on a flow with: jq -c 'select(.community_id==\"<id>\")' /var/log/suricata/eve.json")
    if 'engine' in cats:
        steps.append('Sensor problem: sudo ./check.sh, and journalctl -u suricata -n 100')
    if not steps:
        steps.append('Nothing needs action. Re-run with --minutes 60 for a longer view, or --verbose for INFO items.')
    return steps


# ---------------------------------------------------------------------------------------------

def parse_end(value, log_dir):
    if value == 'now':
        return time.time(), True
    if value == 'latest':
        for line in ReverseFile(os.path.join(log_dir, 'eve.json'), chunk=1 << 16):
            if line.startswith(b'{"timestamp":"'):
                return parse_iso(line[14:line.index(b'"', 14)].decode()), False
        raise SystemExit('eve.json is empty')
    if re.fullmatch(r'\d\d:\d\d(:\d\d)?', value):
        value = time.strftime('%Y-%m-%dT') + value
    return parse_iso(value), False


def main():
    p = argparse.ArgumentParser(description='Security breakdown of recent Suricata activity (read-only).')
    p.add_argument('--minutes', type=float, default=5, help='window length in minutes (default 5)')
    p.add_argument('--end', default='now', help="end of window: now (default), latest, or a local time")
    p.add_argument('--log-dir', default=LOG_DIR)
    p.add_argument('--config', default=CONF, help='suricata.yaml, for HOME_NET')
    p.add_argument('--top', type=int, default=10, help='rows per table (default 10)')
    p.add_argument('--json', action='store_true', help='JSON output')
    p.add_argument('--verbose', '-v', action='store_true', help='also show INFO findings and flows')
    p.add_argument('--no-color', dest='color', action='store_false')
    args = p.parse_args()
    args.color = args.color and sys.stdout.isatty() and not args.json

    HOME_NETS.extend(load_home_net(args.config))
    t0 = time.time()
    try:
        end, end_is_now = parse_end(args.end, args.log_dir)
        start = end - args.minutes * 60
        events, stats, info = read_eve(args.log_dir, start, end)
    except PermissionError as e:
        print(f'Cannot read {e.filename}: run with sudo, or add yourself to the suricata group', file=sys.stderr)
        return 3
    except (FileNotFoundError, ValueError) as e:
        print(f'Cannot read eve.json: {e}', file=sys.stderr)
        return 3
    if not info['files']:
        print(f'No eve.json in {args.log_dir}', file=sys.stderr)
        return 3

    def safe(fn, *a):
        try:
            return fn(*a)
        except OSError:
            return None

    suri_log = safe(read_text_log, os.path.join(args.log_dir, 'suricata.log'), start, end, parse_suricata_log)
    fast = safe(read_text_log, os.path.join(args.log_dir, 'fast.log'), start, end, parse_fast_log)
    stats_blocks = [] if stats else (safe(read_stats_log, os.path.join(args.log_dir, 'stats.log'), start, end) or [])
    stored = recent_filestore(args.log_dir, start, end)

    an = Analysis(events, start, end, args.top).run()
    an.engine_health(stats, stats_blocks, suri_log, fast, info, end_is_now, time.time())
    if stored:
        known = {e['fileinfo'].get('sha256'): e for e in events['fileinfo'] if e.get('fileinfo', {}).get('stored')}
        an.add('INFO', 'file', f'{len(stored)} file(s) written to the filestore by rule matches',
               [f"{fmt_time(ts)} {name[:16]}.. {fmt_bytes(size)}"
                + (f" {known[name]['fileinfo'].get('filename', '')[:60]}" if name in known else '')
                for ts, name, size in stored[:8]])
    an.findings.sort(key=lambda f: (RANK[f['severity']], f['category'], f['title']))

    counts = Counter({t: len(v) for t, v in events.items() if v})
    counts['stats'] = len(stats)
    risk = an.findings[0]['severity'] if an.findings else 'INFO'
    elapsed = time.time() - t0
    sources = [f"{' + '.join(info['files'])} ({fmt_bytes(info['bytes'])} scanned, {sum(counts.values()):,} records "
               f"in window, {elapsed:.2f}s)"]
    if fast is not None:
        sources.append('fast.log')
    if suri_log is not None:
        sources.append('suricata.log')
    if stats_blocks:
        sources.append('stats.log')
    if stored is not None:
        sources.append(f'filestore ({len(stored)} new)')

    if args.json:
        out = {'window': {'start': start, 'end': end, 'minutes': args.minutes},
               'risk': risk, 'sources': sources, 'counts': counts,
               'health': {k: v for k, v in an.health.items() if k != 'delta'}
               | {'counters': {k: v for k, v in an.health.get('delta', {}).items() if v}},
               'findings': an.findings, 'entities': an.entities,
               'alerts': [{**{k: v for k, v in g.items() if k not in ('pairs', 'flows')},
                           'top_pairs': [list(p) + [n] for p, n in g['pairs'].most_common(5)]}
                          for g in an.alert_groups],
               'correlated_flows': [{'flow_id': c['flow_id'], 'severity': c['severity'], 'first': c['first'],
                                     'src': c['src'], 'dst': c['dst'], 'dport': c['dport'],
                                     'alerts': [list(k) + [n] for k, n in c['alerts'].items()], 'events': c['lines']}
                                    for c in an.chains]}
        json.dump(out, sys.stdout, indent=2, default=str)
        print()
    else:
        render(an, info, args, sources, risk, counts)

    return 2 if RANK[risk] <= RANK['HIGH'] else 1 if risk == 'MEDIUM' else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (BrokenPipeError, KeyboardInterrupt):
        sys.exit(1)
