# Suricata inline IPS for Ubuntu

One-shot setup of Suricata 8.x as an inline IPS: all IPv4/IPv6 traffic is diverted through
Suricata via iptables NFQUEUE rules in the mangle table (so UFW still applies afterwards).

```
suricata_scripts/
├── install.sh      sudo ./install.sh [IPv6-prefix ...]
├── uninstall.sh    sudo ./uninstall.sh [--yes] [--keep-logs]
├── check.sh        sudo ./check.sh [--config-test] [--live]
├── README.md
└── files/          everything that gets installed (yaml, drop/modify.conf, units, NFQUEUE script, logrotate)
```

## Quick start

    sudo ./install.sh && sudo ./check.sh --live

## Install

    sudo ./install.sh                       # install, configure, download rules, go inline
    sudo ./install.sh 2a02:c7c:1234::/48    # same, adding your ISP's IPv6 prefix(es) to HOME_NET

What it does:

1. Checks the machine is Ubuntu, runs `apt update` and adds the OISF PPA (`ppa:oisf/suricata-stable`)
   if it isn't already configured. The yaml is written for Suricata 8.x; Ubuntu's own archive is
   often on 7.x.
2. Installs `suricata`, `iptables`, `curl` and `python3`, then stops Suricata (the package starts it
   in af-packet IDS mode).
3. Saves the existing config once to `/var/lib/suricata-installer/suricata.yaml.orig`, then installs
   `files/suricata.yaml` with this machine's default-route interface filled in (`@DEFAULT_IFACE@`)
   and any IPv6 prefixes you passed added to HOME_NET. Installs `drop.conf` and `modify.conf`.
4. Enables the rule sources in `files/rule-sources.conf` (disabling any no longer listed), then runs
   `suricata-update` to download them and convert the high-confidence rules to drop.
5. Runs `suricata -T`. If the test fails it restores the previous config and stops **before touching
   the firewall**.
6. Installs the NFQUEUE firewall script and unit, the systemd override that runs Suricata inline
   (`-q 0`), logrotate and the daily rule-update timer, then starts everything and waits until
   Suricata has attached to the queue.

`install.sh` is safe to re-run, e.g. after editing anything in `files/`. A re-run restarts Suricata
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
