# Laptop security kit for Ubuntu: Suricata IPS, Control D DNS lockdown, Tetragon, alerting

Four kits that work on their own and are stronger together. Each has its own installer,
uninstaller and health check, and each can be re-run safely.

| Kit | Folder | What it does |
|-----|--------|--------------|
| **Suricata IPS** | `.` (`install.sh`, `files/`) | All IPv4/IPv6 traffic goes through Suricata 8.x inline (NFQUEUE in the mangle table, so UFW still applies afterwards). High-confidence malicious traffic is dropped, the rest alerts. |
| **Control D DNS lockdown** | `controld/` | Every DNS lookup has to go through `ctrld`: plain DNS, DoT and public DoH resolvers are refused in the firewall and dropped by Suricata; browsers' own DoH is switched off. |
| **Tetragon** | `tetragon/` | Records what processes do on the machine itself (eBPF): every exec, plus policies for credential theft, persistence, privilege escalation, kernel tampering and tampering with this setup. |
| **Alerting** | `watch/` | Tells you. A 15-minute health and activity check, and desktop notifications for Tetragon policy hits. Without it nothing here speaks up by itself. |

```
├── install.sh, uninstall.sh   Suricata IPS            sudo ./install.sh [CIDR ...]
├── check.sh                   its health check        sudo ./check.sh [--config-test] [--live]
├── analyse.py                 report on recent logs   ./analyse.py [--minutes 5] [--json] [-v]
├── files/                     everything the Suricata kit installs
├── controld/                  DNS lockdown            sudo ./install.sh, ./verify.sh, sudo ./uninstall.sh
├── tetragon/                  Tetragon                ./local_install.sh, sudo ./check.sh, ./local_uninstall.sh
├── watch/                     alerting                sudo ./install.sh, sudo ./uninstall.sh
├── status.sh                  all health checks at once    sudo ./status.sh [--quiet]
├── Makefile, tests/           make lint, sudo make test, make vm-test
└── README.md
```

## Quick start

`ctrld` itself (Control D's client) is installed separately, from Control D; everything else is here.
Any order works, but this one needs no second pass:

    sudo ./install.sh                  # Suricata IPS
    (cd controld && sudo ./install.sh) # DNS lockdown: needs ctrld running and answering first
    tetragon/local_install.sh          # Tetragon (asks for sudo itself)
    (cd watch && sudo ./install.sh)    # alerting: last, it watches whatever is installed
    sudo ./status.sh                   # everything healthy?

Changing something later: edit the file in this repo and re-run that kit's installer. The repo is
the source of truth; files edited in place under `/etc` are overwritten (the installers say so and
keep a copy when they replace one that had local edits).

### How the kits fit together

- **DNS has two layers.** The firewall chain (`DNSLOCK`, from `controld/`) refuses port 53/853 and
  the fixed IPs of public DoH resolvers. Suricata drops the same traffic by content: plain DNS
  that the firewall exempts for ctrld's own fallback, and TLS/QUIC to public resolvers by hostname.
  Both are generated from one list, `controld/files/doh-resolvers.conf`.
- **The Suricata DNS rules belong to the lockdown.** They drop every plain DNS packet leaving the
  machine, so they are installed only when `ctrld` and the lockdown are in place
  (`/etc/suricata/dns-lockdown.rules`; a placeholder otherwise). Installing Suricata alone on a
  machine without ctrld leaves DNS working.
- **Tetragon watches the other two.** The `stack-tamper` policy logs changes to Suricata's and the
  lockdown's config, rules and root-run scripts, as `tetragon-tamper` does for Tetragon itself.
- **Scheduled jobs never run code from this checkout.** The installers put root-owned copies of the
  check scripts in `/usr/local/lib/suricata-ips` and `/usr/local/lib/tetragon-tools`, and `watch/`
  uses those. A checkout in your home directory is writable by anything running as you.

---

# Suricata IPS

## Install

    sudo ./install.sh                       # install, configure, download rules, go inline
    sudo ./install.sh 192.168.1.20/32       # same, also keeping a trusted host/network in HOME_NET

What it does:

1. Checks the machine is Ubuntu, runs `apt update` and adds the OISF PPA (`ppa:oisf/suricata-stable`)
   if it isn't already configured. The yaml is written for Suricata 8.x; Ubuntu's own archive is
   often on 7.x. An apt pin (`/etc/apt/preferences.d/suricata-8`) keeps it on 8.x.
2. Installs `suricata`, `iptables`, `curl` and `python3`. On a first install it stops Suricata (the
   package starts it in af-packet IDS mode); on a re-run Suricata keeps inspecting traffic.
3. Saves the existing config once to `/var/lib/suricata-installer/suricata.yaml.orig`, then builds
   the new one as a **candidate** (`/etc/suricata/suricata.yaml.new`) from `files/suricata.yaml`,
   with this machine's default-route interface and HOME_NET filled in (see [HOME_NET](#home_net)).
   CIDRs passed as arguments are written to `/etc/suricata/home-net.extra` and always kept in
   HOME_NET. Installs `drop.conf`, `disable.conf`, `modify.conf`, `local.rules` and the DNS
   lockdown's rules (or their placeholder).
4. Enables the rule sources in `files/rule-sources.conf` (disabling any no longer listed), then runs
   `suricata-update` to download them, convert the high-confidence rules to drop and leave out the
   categories listed in `disable.conf`.
5. Runs `suricata -T` on the candidate. **If anything fails up to here, the previous files are put
   back and Suricata is left running as it was**; the firewall is not touched.
6. Makes the candidate live, installs the NFQUEUE firewall script and unit, the systemd override
   that runs Suricata inline (`-q 0`) and sandboxed, logrotate, the daily rule-update timer, the
   weekly filestore clean-up and the HOME_NET updater, and copies `check.sh`, `analyse.py` and
   `files/` to `/usr/local/lib/suricata-ips`. Then it restarts Suricata, or only reloads the rules
   if neither the yaml nor the service settings changed, and waits until it is attached to the queue.

`install.sh` is safe to re-run, e.g. after editing anything in `files/`. A re-run restarts Suricata
at most once, at the end; `stream.midstream` keeps already-open connections alive through it.

### HOME_NET

This is a laptop, so "home" is this machine, not whatever network it's on. HOME_NET holds:

- this machine's exact IPv4 addresses, on every interface (Wi-Fi, VPN)
- the `/64` of each global or ULA IPv6 address (temporary privacy addresses rotate inside it,
  so it can't be narrower), and this machine's exact link-local addresses
- the whole subnet of each bridge this machine routes for (libvirt, Docker), so the VMs and
  containers behind it are covered by the outbound rules too. A bridge that carries the default
  route is the uplink and is treated like any other interface.
- loopback, plus anything listed in `/etc/suricata/home-net.extra` (one CIDR per line)

Everyone else, including other devices on the same café, hotel or home Wi-Fi, is `EXTERNAL_NET`,
so rules written for attacks coming from outside fire for them too. `/usr/local/sbin/suricata-home-net`
rewrites the line and reloads the rules live (USR2, no traffic interruption) when the addresses change.
It runs from a NetworkManager hook, a 15-minute timer, and before Suricata starts. Each change costs one
rule reload (about a minute of CPU and briefly double the memory).

    sudo suricata-home-net --check      # print the expected value; exits 1 if the config is stale

## Uninstall

    sudo ./uninstall.sh                     # asks for confirmation first
    sudo ./uninstall.sh --yes --keep-logs   # no prompt, keep /var/log/suricata

What it does:

1. Removes the NFQUEUE firewall rules **first**, so traffic is never sent to a stopped Suricata.
2. Stops and disables Suricata, the NFQUEUE unit and the timers, and removes the units,
   the override, the logrotate config and `/usr/local/lib/suricata-ips`.
3. Purges the `suricata` package and deletes `/etc/suricata`, `/var/lib/suricata` and
   `/var/log/suricata` (unless `--keep-logs`).
4. Removes the OISF PPA **only if `install.sh` added it**. If it was already configured, it stays.
5. Checks that no NFQUEUE firewall rules are left.

Packages pulled in as dependencies can then be removed with `sudo apt autoremove`.

## Health check

    sudo ./check.sh                 # standard checks, takes a few seconds
    sudo ./check.sh --config-test   # also runs suricata -T (about a minute)
    sudo ./check.sh --live          # also sends a test request to confirm a known rule fires

`check.sh` is read-only. It prints PASS/WARN/FAIL for the services, the rule-update timer and
whether its last run failed, the firewall rules (the `SURICATA-NFQ` chain hooked first in mangle
INPUT/OUTPUT/FORWARD for IPv4 and IPv6, nothing left in the filter table where it would bypass UFW),
UFW, kernel queue overflows, config settings, the DNS lockdown's rules, rule age, logrotate, errors
in `suricata.log`, flows seen in both directions, IPv6, and why packets were blocked (rules vs engine
reasons). It exits non-zero if anything fails.

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
| `suricata.yaml`                 | `/etc/suricata/suricata.yaml` (`@DEFAULT_IFACE@` and HOME_NET filled in) |
| `drop.conf`, `disable.conf`, `modify.conf` | `/etc/suricata/` (rules converted to drop / left out / tweaked by suricata-update) |
| `rule-sources.conf`             | not copied: the list of `suricata-update` sources to enable |
| `suricata-nfqueue-apply.sh`     | `/usr/local/sbin/` (`start` builds / `stop` removes the `SURICATA-NFQ` chain) |
| `suricata-nfqueue.service`      | `/etc/systemd/system/` (applies the rules at boot, removes them on stop) |
| `suricata-override.conf`        | `/etc/systemd/system/suricata.service.d/override.conf` (runs with `-q 0`) |
| `suricata-rules-update.{service,timer}` | `/etc/systemd/system/` (daily sandboxed `suricata-update` + live reload) |
| `suricata-filestore-prune.{service,timer}` | `/etc/systemd/system/` (weekly: deletes extracted files older than 30 days) |
| `local.rules`                   | `/etc/suricata/local.rules` (this machine's own rules; suricata-update leaves it alone) |
| (generated by `controld/`)      | `/etc/suricata/dns-lockdown.rules` (the DNS lockdown's rules, or a placeholder) |
| `suricata-home-net.sh`          | `/usr/local/sbin/suricata-home-net` (keeps HOME_NET on this machine's addresses) |
| `suricata-home-net.{service,timer}` | `/etc/systemd/system/` (runs it; timer every 15 min) |
| `90-suricata-home-net`          | `/etc/NetworkManager/dispatcher.d/` (runs it on network changes) |
| `suricata.apt-pin`              | `/etc/apt/preferences.d/suricata-8` (keeps apt on Suricata 8.x) |
| `suricata.logrotate`            | `/etc/logrotate.d/suricata` (size-based, 200M x 5)       |
| `check.sh`, `analyse.py`, `files/` | `/usr/local/lib/suricata-ips/` (root-owned copies for scheduled runs) |

Config highlights vs the stock yaml: `stream.midstream: true`, HOME_NET = this machine only,
checksum validation off (offloaded checksums otherwise cause false drops), NFQ `fail-open: no`,
eve.json with payloads, community-id, drop and verdict logging, file-store for rule-matched files,
Landlock sandbox on, core dumps off (a dump would hold inspected traffic), stats every 60 s to
eve.json only (no `stats.log`).

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
- every ET rule rated `confidence High` with severity `Major` or `Critical`
- all abuse.ch rules (SSLBL by message; Feodo Tracker and URLhaus are `trojan-activity`)

The ET categories that describe policy or informational activity rather than attacks (INFO, HUNTING,
POLICY, GAMES, CHAT, P2P, DNS, DYN_DNS, TOR, USER_AGENTS) stay alert-only, for the classtype lines as
well as the confidence line. The whole-group lines are not affected.

Left out altogether (`files/disable.conf`): the ActiveX, retired and SCADA categories, which can't
apply to this machine (about 700 rules). Three larger alert-only categories (web applications and
web servers hosted here, dynamic-DNS lookups: about 13,000 rules) are listed there commented out;
uncomment them if they are only noise for you. That is where most of the memory and reload time
there is to save would come from.

DNS lockdown rules (`/etc/suricata/dns-lockdown.rules`, installed with `controld/`): plain DNS (53)
and DNS-over-TLS/QUIC (853) leaving the machine are dropped, as are TLS (DoH) and QUIC (DoH3)
connections whose SNI is a well-known public DoH resolver. See [Control D DNS lockdown](#control-d-dns-lockdown).

Everything else alerts only. With all sources that's about 110k enabled rules, most of them set to
drop. Loading them takes about 50 s and well over 1 GB of RAM, and a live reload briefly needs about
double that. When `drop.conf` was introduced, it was checked against this machine's alert history:
none of the normal traffic seen would have been blocked.

## Safety

- **Suricata down → traffic passes.** The NFQUEUE rule uses `--queue-bypass`: if Suricata is
  stopped, restarting or crashed, traffic flows uninspected rather than being blocked, so a failed
  start can't cut the network (or an SSH session). To keep that window short, systemd restarts
  Suricata 1 s after it exits for any reason, and apt is pinned to 8.x so an upgrade can't leave it
  unable to start.
- **A failed install changes nothing.** The new config is tested as a candidate while Suricata keeps
  running on the old one; on any failure the previous files are restored.
- **Sandboxed.** Suricata runs with systemd hardening (read-only system, no kernel or namespace
  access) and Landlock (once started it can only touch its logs, `/var/lib/suricata` and `/run`).
  The daily `suricata-update` runs read-only except `/var/lib/suricata`, with no network admin or
  other privileged capabilities.
- **Suricata overloaded → excess packets dropped.** NFQ runs with `fail-open: no`: if the queue
  fills because Suricata can't keep up, packets are dropped rather than passed uninspected (TCP
  retransmits them). `check.sh` reports queue overflows; if they appear regularly, investigate
  load or set `fail-open: yes` in `files/suricata.yaml` and re-run `install.sh`.
- The rules sit in the mangle table, in a chain of their own (`SURICATA-NFQ`), so an ACCEPT verdict
  from Suricata still goes through UFW and stop/start only ever touch rules this kit created.
- The daily rule update tests the new ruleset and keeps the old one if the test fails, then reloads
  rules live (no restart). `check.sh` fails if the last update failed, not only if the rules are old.

## Tuning

Something legitimate blocked? Find its SID in `/var/log/suricata/eve.json` (`"event_type":"drop"`
or alerts with `"action":"blocked"`), add it to `files/disable.conf` (or to `files/modify.conf`
as `<sid> "drop" "alert"` to keep the alert), then `sudo ./install.sh`. If nothing else changed, that
reloads the rules without restarting Suricata.

---

# Control D DNS lockdown

Needs `ctrld` installed, running and answering on `127.0.0.1:53` first (the installer checks and
refuses otherwise, so DNS is never locked to a dead resolver).

    cd controld
    sudo ./install.sh                  # block direct DNS and public DoH, sandbox ctrld, lock browsers
    sudo MODE=redirect ./install.sh    # redirect hard-coded IPv4 resolvers to ctrld instead of refusing
    ./verify.sh                        # prove it: every bypass route is tried and must fail
    sudo ./uninstall.sh

What it puts in place:

- **Firewall** (`/usr/local/sbin/dns-lockdown.sh`, `dns-lockdown.service`): a `DNSLOCK` chain, first
  in filter OUTPUT and FORWARD, refusing 53, 853, mDNS and LLMNR to anything off-box and 443 to the
  fixed IPs of public DoH resolvers. Loopback and ctrld's own cgroup are exempt. FORWARD covers VMs
  and containers routed through this machine.
- **Suricata rules**, if Suricata is installed: see above. Without Suricata only the firewall layer
  exists; `../install.sh` adds the rules when it is run afterwards.
- **One resolver list** for both: `files/doh-resolvers.conf`. Add a hostname or IP there and re-run
  `install.sh`; hostnames become Suricata SNI rules, IPs become firewall rules.
- **Browsers**: Firefox and the Chromium family (Chromium, and Chrome, Brave and Edge if installed)
  get their own DoH switched off and locked by policy, so they use the system resolver, i.e. ctrld.
  The policy files are world-readable, so they deliberately do not contain the Control D profile URL.
- **ctrld itself**: binary, config and logs made root-only; a systemd sandbox that is removed again
  automatically if ctrld stops resolving under it.

### Captive portals

A hotel or café login page only loads if the network's own DNS can be reached, which the lockdown
forbids. Lift it for a few minutes:

    sudo dns-lockdown.sh pause         # 10 minutes; `pause 30` for longer (60 at most)
    sudo dns-lockdown.sh resume        # re-lock now
    sudo dns-lockdown.sh status

While paused, plain DNS on port 53 may leave the machine (the firewall chain is removed and port 53
skips Suricata); DoT and the public DoH resolvers stay blocked. It re-locks by itself at the stated
time, also straight after a suspend or reboot, and `verify.sh` and the alerting know it is deliberate.

---

# Tetragon

    tetragon/local_install.sh               # install or upgrade, enable at boot, start
    sudo tetragon/check.sh                  # health check; --canary also triggers a real alert
    tetragon/local_uninstall.sh [--purge]   # --purge also deletes the event logs

`local_install.sh` downloads the pinned release (checksum pinned in `config.sh`), installs it as a
systemd service that starts before ordinary services at boot, and loads the policies in `policies/`.
Its header documents every file it installs. `run.sh`/`stop.sh` run the same thing in Docker without
installing anything, which is handy for trying a policy change but has no boot gate, journal copy
or health check.

Everything Tetragon sees goes to `/var/log/tetragon/tetragon.log` (root-only), minus what
`export-denylist.jsonl` filters out. Policy hits are also copied into the journal
(`journalctl -t tetragon-alerts`), a second record that deleting the log directory does not remove.

| Policy | Logs |
|--------|------|
| `sensitive-files` | Reads of `/etc/shadow`, sudoers, SSH and GPG private keys, cloud and Docker credentials, browser password and cookie stores, the login keyring and CLI tokens, by anything other than the program that owns them |
| `persistence` | Writes, symlinks (`systemctl enable`), hard links and renames into cron, systemd, autostart, shell start-up files, PAM, apt hooks and similar |
| `privilege-escalation` | Processes switching to uid 0 |
| `setuid-files` | A file being given the setuid bit |
| `kernel-tampering`, `monitor-kernel-modules` | eBPF program loads, ptrace-style access to other processes, kernel module loads and unloads |
| `suspicious-exec` | Programs run from `/dev/shm`. Programs with no file at all (memfd, deleted) are picked up from exec events by the journal copy |
| `device-access` | Unexpected programs opening keyboards, cameras, microphones, HID devices |
| `tcp-connect`, `tcp-listen` | Outbound TCP connections; programs starting to listen on a network-reachable address |
| `tetragon-tamper`, `stack-tamper` | Changes to Tetragon's own logs, config and binaries; changes to Suricata's and the DNS lockdown's config, rules, scripts and logs |

All policies observe only; nothing is blocked or killed.

Per-machine settings:

- **Whose home directory is watched.** Policy files say `@HOME@`; the installer fills in the home of
  whoever runs it through sudo (`WATCH_USER=name ./local_install.sh` to choose).
- **`export-denylist.jsonl`** and the container networks in `policies/tcp-connect.yaml` name this
  machine's own containers and health checks. Adjust them to yours. Every denylist line must be
  limited to exec events or one policy and tie arguments to a root-owned parent program, otherwise it
  becomes a way to hide from the log; `make lint` and `check.sh` both check this.
- **Excluded programs are matched by their real path**, not a symlink to it (on newer Ubuntu
  `/usr/bin/sudo` is `/usr/lib/cargo/bin/sudo`).
- `/etc/tetragon` is root-only, because the policies and denylist spell out what is and isn't
  watched. This checkout is as private as wherever you keep it.

The web viewer (`http://127.0.0.1:8099`) only serves the event stream to a browser that has the
token: open the link in `sudo cat /etc/tetragon/viewer-url` once and the browser remembers it.

A Tetragon limit worth knowing when editing policies: one policy can hold at most 8 prefix lists and
8 exact-match lists across all its hooks, and 5 selectors per hook. `make lint` checks all three.

---

# Alerting

    cd watch
    sudo ./install.sh        # after the other kits
    sudo ./uninstall.sh

| Piece | What it does |
|-------|--------------|
| `ips-watch.timer` | Every 15 minutes runs Suricata's and Tetragon's health checks, checks ctrld and the `DNSLOCK` chain, and runs `analyse.py` over the last 15 minutes. Health problems notify when they appear, change or clear (and every 6 hours while they last). Suricata findings from MEDIUM up go to the journal; from HIGH up (`NOTIFY_MIN`) also to the desktop. |
| `tetragon-notify.service` | A desktop notification for each Tetragon policy hit and fileless exec that isn't on the ignore list. The same policy and program notify at most once per 10 minutes, and at most 5 notifications per 5 minutes are shown. |
| `ips-notify` | What both use: always writes to the journal (`journalctl -t ips-alert`), and notifies every logged-in desktop user. `sudo ips-notify normal "Test" "It works"` |

Tuning lives in `watch/files/`: `ips-watch.conf` (thresholds) and `tetragon-ignore.conf` (which
policy hits stay off the screen). The ignore list never removes anything from the journal or from
Tetragon's log. To see what your machine produces and what the list drops:

    journalctl -t tetragon-alerts --since -1d -o cat \
      | /usr/local/lib/ips-watch/tetragon-notify.py --print | sort | uniq -c | sort -rn

Expect to tune it during the first days: the shipped list covers a stock Ubuntu desktop with
rootless Docker, and anything else that routinely trips a policy on your machine will notify until
you add it. `sudo tetragon/check.sh --canary` is an end-to-end test: it reads one byte of
`/etc/shadow` and a notification should appear.

---

# Checks and tests

    sudo ./status.sh         # every kit's health check, with a summary
    make lint                # syntax of every script, unit, policy and config; changes nothing
    sudo make test           # the two firewall scripts, in a throwaway network namespace
    make vm-test             # install -> check -> uninstall in a fresh Ubuntu VM (needs multipass)

`make lint` uses `shellcheck` and PyYAML when they are installed and says what it skipped when they
are not. `sudo make test` builds and tears down the real `SURICATA-NFQ`, `DNSLOCK` and pause rules
(including the upgrade from the older rule layout) in a network namespace with its own empty
firewall, so this machine's rules are never touched.

## Rolling out to a new machine

1. Install `ctrld` from Control D if you want the DNS lockdown.
2. Copy this folder to the machine and follow [Quick start](#quick-start).
3. Go through the per-machine settings under [Tetragon](#tetragon) and the notification ignore list.
4. Before relying on it widely, run `make vm-test` (or do one full install → check → uninstall
   cycle on a fresh Ubuntu VM by hand).
