# Suricata inline IPS for Ubuntu

One-shot setup of Suricata 8.x as an inline IPS: all IPv4/IPv6 traffic is diverted through
Suricata via iptables NFQUEUE rules in the mangle table (so UFW still applies afterwards).

```
suricata_scripts/
├── install.sh      sudo ./install.sh [IPv6-prefix ...]
├── uninstall.sh    sudo ./uninstall.sh [--yes] [--keep-logs]
├── check.sh        sudo ./check.sh [--config-test] [--live]
├── analyse.py      ./analyse.py [--minutes 5] [--end now|latest|TIME] [--json] [-v]
├── README.md
└── files/          everything that gets installed (yaml, drop/modify.conf, units, NFQUEUE script, logrotate)
```

## Quick start

    sudo ./install.sh && sudo ./check.sh --live

## Install

    sudo ./install.sh                       # install, configure, download rules, go inline
    sudo ./install.sh 2a02:c7c:1234::/48    # same, also adding extra IPv6 prefix(es) to HOME_NET
    sudo ./install.sh --no-ipv6-detect      # don't auto-detect IPv6 prefixes

What it does:

1. Checks the machine is Ubuntu, runs `apt update` and adds the OISF PPA (`ppa:oisf/suricata-stable`)
   if it isn't already configured. The yaml is written for Suricata 8.x; Ubuntu's own archive is
   often on 7.x.
2. Installs `suricata`, `iptables`, `curl` and `python3`, then stops Suricata (the package starts it
   in af-packet IDS mode).
3. Saves the existing config once to `/var/lib/suricata-installer/suricata.yaml.orig`, then installs
   `files/suricata.yaml` with this machine's default-route interface filled in (`@DEFAULT_IFACE@`).
   Global IPv6 prefixes on the network are added to HOME_NET: those in the routing table, plus
   those the router advertises (asked with `rdisc6`, so this works even if the machine hasn't
   configured an IPv6 address). Prefixes passed as arguments are added too, e.g. your ISP's whole
   delegated block, which the router only advertises a `/64` of. Installs `drop.conf` and `modify.conf`.
4. Enables the rule sources in `files/rule-sources.conf` (disabling any no longer listed), then runs
   `suricata-update` to download them and convert the high-confidence rules to drop.
5. Runs `suricata -T`. If the test fails it restores the previous config and stops **before touching
   the firewall**.
6. Installs the NFQUEUE firewall script and unit, the systemd override that runs Suricata inline
   (`-q 0`), logrotate and the daily rule-update timer, then starts everything and waits until
   Suricata has attached to the queue.

`install.sh` is safe to re-run, e.g. after editing anything in `files/`, or after your ISP changes
your IPv6 prefix (`check.sh` warns when a prefix in use isn't in HOME_NET). A re-run restarts Suricata
once; `stream.midstream` keeps already-open connections alive through the restart.

## Uninstall

    sudo ./uninstall.sh                     # asks for confirmation first
    sudo ./uninstall.sh --yes --keep-logs   # no prompt, keep /var/log/suricata

What it does:

1. Removes the NFQUEUE firewall rules **first**, so traffic is never sent to a stopped Suricata.
2. Stops and disables Suricata, the NFQUEUE unit and the rule-update timer, and removes the units,
   the override and the logrotate config.
3. Purges the `suricata` package and deletes `/etc/suricata`, `/var/lib/suricata` and
   `/var/log/suricata` (unless `--keep-logs`).
4. Removes the OISF PPA **only if `install.sh` added it**. If it was already configured, it stays.
5. Checks that no NFQUEUE firewall rules are left.

Packages pulled in as dependencies can then be removed with `sudo apt autoremove`.

## Health check

    sudo ./check.sh                 # standard checks, takes a few seconds
    sudo ./check.sh --config-test   # also runs suricata -T (about a minute)
    sudo ./check.sh --live          # also sends a test request to confirm a known rule fires

`check.sh` is read-only. It prints PASS/WARN/FAIL for the services, the rule-update timer, the
NFQUEUE rules (IPv4 and IPv6, none left in the filter table where they'd bypass UFW), UFW, kernel
queue overflows, config settings, rule age, logrotate, errors in `suricata.log`, flows seen in both
directions, IPv6, and why packets were blocked (rules vs engine reasons). It exits non-zero if
anything fails.

`--live` sends an HTTP request with an apt-style User-Agent to `archive.ubuntu.com`, which triggers
SID 2013504 (an alert-only rule, never dropped) and confirms it appears in `eve.json`.

## Security breakdown of recent activity

    ./analyse.py                    # last 5 minutes
    ./analyse.py --minutes 60 -v    # last hour, including INFO findings
    ./analyse.py --end 13:55        # the 5 minutes up to 13:55 today
    ./analyse.py --end latest       # the 5 minutes up to the newest record (if logging has stopped)
    ./analyse.py --json             # for scripts/cron

| Option                    | Meaning                                                                  |
|---------------------------|--------------------------------------------------------------------------|
| `--minutes N`             | Length of the window (default 5)                                         |
| `--end now\|latest\|TIME` | End of the window: now (default), the newest eve.json record, or a local time (`13:55`, `2026-10-05T13:55`) |
| `--top N`                 | Rows per table (default 10)                                              |
| `-v`, `--verbose`         | Also show INFO findings and alerts that are informational only            |
| `--json`                  | Machine-readable output instead of the report                            |
| `--no-color`              | Plain output (automatic when not writing to a terminal)                  |
| `--log-dir`, `--config`   | Other log directory (default `/var/log/suricata`) / suricata.yaml to read HOME_NET from |

`analyse.py` is read-only and uses only the Python standard library. It needs root or membership of the
`suricata` group. Exit status: 0 nothing above LOW, 1 MEDIUM, 2 HIGH/CRITICAL, 3 logs unreadable.

### What it reads

| Source          | Used for                                                                          |
|-----------------|-----------------------------------------------------------------------------------|
| `eve.json`      | Everything: alerts, drops, flows, DNS, TLS, HTTP, files, SSH, anomalies, stats. `eve.json.1` too if the window crosses a rotation |
| `suricata.log`  | Errors, warnings and notices (e.g. rule reloads) during the window                |
| `fast.log`      | Cross-check of the alert count against eve.json                                   |
| `stats.log`     | Engine counters, only if eve.json has no stats records                            |
| `filestore/`    | Files stored by rule matches during the window, matched to their download by sha256 |
| `suricata.yaml` | HOME_NET, to tell local hosts from remote ones (falls back to the private ranges) |

It reads the logs backwards from the end and stops once it passes the start of the window, so the cost
depends on the window, not on the file size: a 5-minute window takes milliseconds and a week of logs
(about 170 MB of eve.json) under a second. Only records in the window are decoded, and of the stats records
only the first and last.

### The report

1. **Engine health**: packets and rate, IPS accepted/blocked, drop reasons, new and active flows, alerts
   (and how many were suppressed by thresholds), app-layer errors, and suricata.log/fast.log counts.
2. **Activity overview**: event counts by type, flows by protocol and direction, top local hosts and remote
   endpoints by traffic, top DNS domains and TLS SNIs. Remote IPs are named from DNS answers, TLS SNI and
   HTTP Host headers seen in the window.
3. **Alerts**: grouped by signature, with count, action (allowed/blocked) and the top source -> destination.
4. **Findings**: everything flagged, worst first, with details.
5. **Correlated flows**: for each flow that raised a real alert, everything else logged on it: the DNS
   lookup that led to it, TLS/HTTP details, files, anomalies, drops and the flow record, plus the flow's
   `community_id` for pivoting (`jq -c 'select(.community_id=="<id>")' /var/log/suricata/eve.json`). Then the
   hosts ranked by combined risk score.
6. **Next steps**: suggested follow-up for the kinds of finding present.

### Severity

| Level    | Meaning                                                                                    |
|----------|--------------------------------------------------------------------------------------------|
| CRITICAL | A severity-1 alert rated Critical by ET that was **allowed**, or a host with several serious signals whose worst was HIGH |
| HIGH     | Severity-1 alert allowed; risky service (SMB, RDP, telnet, databases...) reachable from the internet; attack request that got a 2xx answer; eve.json not written for over 60 s |
| MEDIUM   | Severity-2 alert allowed, or severity-1 alert blocked; scans from inside; brute force; DGA/tunnelling DNS; executable downloads; expired certificates; engine restarts, memcap drops or suricata.log errors |
| LOW      | Severity-2 alert blocked; ET INFO/POLICY rules rated severity 1-2; inbound scans; beaconing; large uploads; obsolete or self-signed TLS; abuse-heavy TLDs; plain HTTP to bare IPs |
| INFO     | Suricata's own stream/decoder events, "Not Suspicious Traffic", engine-reason drops (e.g. stream errors), TLS without SNI. Hidden unless `-v` |

The overall risk is the worst finding. A blocked alert is rated one level lower than an allowed one, since
the IPS has already stopped it.

### Detections and thresholds

All counts are within the window.

| Finding                     | Triggered by                                                                     |
|-----------------------------|----------------------------------------------------------------------------------|
| Port scan                   | One source, 15+ unanswered TCP ports on one host (MEDIUM from inside, LOW from outside) |
| Sweep                       | One source, one port, 15+ hosts without reply                                    |
| Exposed service             | External host completed a TCP connection to a local host (port below 49152; flows that look reversed by midstream pickup are ignored) |
| SSH brute force             | 10+ connections from one external host to port 22 on one local host             |
| SSH fan-out                 | One local host opening SSH to 10+ different external hosts                       |
| Risky outbound port         | Answered connection out to telnet, SMB, RDP, IRC, Tor, SOCKS, 4444, 5555, 31337  |
| Large upload                | 100 MB+ from one local host to one remote host                                   |
| Beaconing                   | 6+ flows from one local host to the same remote host/port, 5 s+ apart, jitter 15% or less (DNS/NTP excluded) |
| NXDOMAIN-heavy DNS          | 15+ NXDOMAIN answers, 30%+ of the host's lookups, 10+ different names            |
| Random-looking domains      | Registered-domain label of 12+ characters, entropy 3.5+, 2+ digits               |
| DNS tunnelling              | 30+ different subdomains of one domain, averaging 40+ characters; or 50+ TXT lookups |
| Abuse-heavy TLDs            | Lookups in `.zip`, `.top`, `.xyz`, `.tk`, `.icu` and similar                     |
| TLS                         | Expired certificate, self-signed certificate, SSLv3/TLS 1.0/1.1, no SNI (external servers only) |
| Web attacks (inbound)       | Attack patterns in URLs (traversal, `/etc/passwd`, `${jndi:`, SQL injection, `.env`, `.git`...), scanner/tool user-agents, 20+ 4xx responses, unusual methods (PUT, DELETE, PROPFIND...) |
| HTTP (outbound)             | Requests straight to IP addresses; scripted clients (curl, python, Go...) as INFO |
| Executable download         | File name, magic or content type of an executable/script (exe, dll, ps1, sh, jar, apk...) |
| Anomalies                   | 50+ protocol anomalies (LOW), otherwise INFO                                     |
| Engine pressure             | Any memcap-drop, emergency-mode, queue-overflow, reassembly-gap, exception-policy or NFQ-error counter increased |
| Restart                     | Uptime went down between two stats records                                      |

### Correlation

Every finding records the hosts it involves. Each host gets a score (CRITICAL 40, HIGH 20, MEDIUM 8, LOW 2).
A host involved in 2+ kinds of finding with a score of 10+ gets a **correlated** finding listing them, with a
timeline of its alerts, rule drops and files. If 2+ of those kinds are MEDIUM or worse, it is raised one
severity level, since independent signals pointing at the same host are stronger than any one alone. Local
hosts are listed first, and a remote host whose findings are already all shown under a local one isn't repeated.

For example, a malware check-in shows up as: a DNS lookup of an unfamiliar domain, an alert on the TLS session
to it, beaconing to the same IP every 30 s and an executable downloaded from it, all under one host.

### Running it on a schedule

The exit status makes it usable from cron, e.g. to keep a copy of every report at MEDIUM or above (in the crontab
of root or of a user in the `suricata` group):

    */5 * * * * /path/to/analyse.py --no-color > ~/suricata-report.txt || cp ~/suricata-report.txt ~/suricata-report-$(date +\%F-\%H\%M).txt

### Limitations

- The thresholds are heuristics for a small network and may need tuning for busy ones (constants near the top
  of `analyse.py`).
- Beaconing also matches normal keep-alives and polling (it is LOW unless the same host has other findings).
- SSH brute force is judged by connection count only; the logs can't show whether a login succeeded.
- With DNS over HTTPS/TLS (e.g. Control D), Suricata sees few DNS lookups, so the DNS checks and naming
  of IPs rely mostly on TLS SNI.
- Over long windows with restarts, the engine counters cover only the time since the last restart.

## What gets installed

| From `files/`                   | Installed to                                            |
|---------------------------------|---------------------------------------------------------|
| `suricata.yaml`                 | `/etc/suricata/suricata.yaml` (`@DEFAULT_IFACE@` filled in) |
| `drop.conf`, `modify.conf`      | `/etc/suricata/` (rules converted to drop / tweaked by suricata-update) |
| `rule-sources.conf`             | not copied: the list of `suricata-update` sources to enable |
| `suricata-nfqueue-apply.sh`     | `/usr/local/sbin/` (`start` adds / `stop` removes the NFQUEUE rules) |
| `suricata-nfqueue.service`      | `/etc/systemd/system/` (applies the rules at boot, removes them on stop) |
| `suricata-override.conf`        | `/etc/systemd/system/suricata.service.d/override.conf` (runs with `-q 0`) |
| `suricata-rules-update.{service,timer}` | `/etc/systemd/system/` (daily `suricata-update` + live reload) |
| `suricata.logrotate`            | `/etc/logrotate.d/suricata` (size-based, 200M x 5)       |

Config highlights vs the stock yaml: `stream.midstream: true`, IPv6 ULA/link-local in HOME_NET,
checksum validation off (offloaded checksums otherwise cause false drops), NFQ `fail-open: no`,
eve.json with payloads, community-id, drop and verdict logging, file-store for rule-matched files.

## Rules and blocking policy

Sources (`files/rule-sources.conf`):

| Source                     | What it covers                                   |
|----------------------------|--------------------------------------------------|
| `et/open`                  | Emerging Threats Open, the main ruleset          |
| `abuse.ch/sslbl-blacklist` | TLS certificates used by malware C2 servers      |
| `abuse.ch/feodotracker`    | Botnet C2 IPs (Emotet, QakBot, Dridex, ...)      |
| `abuse.ch/urlhaus`         | Malware distribution URLs (plain HTTP only)      |

Converted to drop (`files/drop.conf`):

- classtypes `trojan-activity`, `command-and-control`, `exploit-kit`, `domain-c2`, `credential-theft`
- ET groups `emerging-malware`, `emerging-mobile_malware`, `emerging-coinminer`, `ciarmy`, `compromised`, `drop`
- every ET rule rated `confidence High` with severity `Major` or `Critical`, except the INFO,
  HUNTING, POLICY, GAMES, CHAT, P2P, DNS, DYN_DNS, TOR and USER_AGENTS categories
- all abuse.ch rules (SSLBL by message; Feodo Tracker and URLhaus are `trojan-activity`)

Everything else alerts only. With all sources that's about 90k enabled rules, about 67k of them
set to drop. Loading them takes about 50 s and about 800 MB of RAM, and a live reload briefly
needs about double that. When `drop.conf` was introduced, it was checked against this machine's
alert history: none of the normal traffic seen would have been blocked.

## Safety

- **Suricata down → traffic passes.** The NFQUEUE rules use `--queue-bypass`: if Suricata is
  stopped, restarting or crashed, traffic flows uninspected rather than being blocked, so a failed
  start can't cut the network (or an SSH session).
- **Suricata overloaded → excess packets dropped.** NFQ runs with `fail-open: no`: if the queue
  fills because Suricata can't keep up, packets are dropped rather than passed uninspected (TCP
  retransmits them). `check.sh` reports queue overflows; if they appear regularly, investigate
  load or set `fail-open: yes` in `files/suricata.yaml` and re-run `install.sh`.
- The rules sit in the mangle table, so an ACCEPT verdict from Suricata still goes through UFW.
- The daily rule update tests the new ruleset and keeps the old one if the test fails, then reloads
  rules live (no restart).

## Tuning

Something legitimate blocked? Find its SID in `/var/log/suricata/eve.json` (`"event_type":"drop"`
or alerts with `"action":"blocked"`), add it to `/etc/suricata/disable.conf` (or to `files/modify.conf`
as `<sid> "drop" "alert"`), then `sudo suricata-update && sudo systemctl reload suricata`.
Changes made in `files/` are applied with `sudo ./install.sh`.

## Rolling out to a new machine

1. Copy this folder to the machine and run `sudo ./install.sh && sudo ./check.sh --live`.
2. Before relying on it widely, do one full install → check → uninstall cycle on a fresh Ubuntu VM.
