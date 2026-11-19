# server_client: design plan

Status: **design only, no code yet.** This document is the plan for the client half of a small, self-hosted EDR
for DigitalOcean web servers. The other half, the hub, is in [`../server_hub/PLAN.md`](../server_hub/PLAN.md).
The verdict and the HTTPS limit are in §1, the threat model in §13, the NGINX2Root evidence in Appendix A.
Section numbers are stable; phases (P1a, P1b, P2, P3, P4) are defined in §10 and marked in the text.

**Paths:** `server_client/…`, `server_hub/…` and `mock/…` are relative to `server_edr_solution/`. Paths to the
laptop kit this reuses (`install.sh`, `check.sh`, `analyse.py`, `files/`, `tetragon/`, `controld/`, `watch/`,
`tests/`, `Makefile`) are relative to the repository root. A local Docker test bed is in [`../mock/`](../mock/README.md).

**Contents**

- [1. What it is](#1-what-it-is)
- [2. Principles](#2-principles)
- [3. Architecture](#3-architecture)
- [4. Components](#4-components)
  - [4.1 Suricata, server profile](#41-suricata-server-profile)
  - [4.2 Blocking: nftables ban sets](#42-blocking-nftables-ban-sets)
  - [4.3 Tetragon, server policy set](#43-tetragon-server-policy-set)
  - [4.4 DNS over HTTPS, without ctrld](#44-dns-over-https-without-ctrld)
  - [4.5 `edr-agent`](#45-edr-agent)
  - [4.6 Enrollment and identity](#46-enrollment-and-identity)
  - [4.7 Local alerts and local response](#47-local-alerts-and-local-response)
- [5. Moving to a new hub (`rehome`)](#5-moving-to-a-new-hub-rehome)
- [6. Uninstall](#6-uninstall)
- [7. Installer](#7-installer)
- [8. Health check (`check.sh`)](#8-health-check-checksh)
- [9. Disk and CPU budgets](#9-disk-and-cpu-budgets)
- [10. Roadmap](#10-roadmap)
- [11. Repo integration and testing](#11-repo-integration-and-testing)
- [12. Known limits and risks](#12-known-limits-and-risks)
- [13. Threat model](#13-threat-model)
- [14. Configuration](#14-configuration)
- [15. Upgrades, versions and exit codes](#15-upgrades-versions-and-exit-codes)
- [16. Safety rails](#16-safety-rails)
- [17. Operations and runbooks](#17-operations-and-runbooks)
- [18. Privacy and data handling](#18-privacy-and-data-handling)
- [Appendix A: NGINX2Root worked example](#appendix-a-nginx2root-worked-example)
- [Appendix B: Event schema](#appendix-b-event-schema)

---

## 1. What it is

A hardened host kit for **DigitalOcean droplets running Ubuntu 24.04 or 26.04** (amd64) that serve PHP/Laravel
behind nginx and php-fpm. It installs and tunes:

| Part | Job on a web server |
|------|---------------------|
| **Suricata (IDS)** | Inspects network traffic: scans, exploit attempts on plain HTTP, non-HTTP services, and outbound C2 or coin-miner traffic after a compromise (§4.1). |
| **nftables ban sets** | Drop known-bad and recently-hostile IPs in the kernel, with a timeout on every entry (§4.2). |
| **Tetragon** | Records what processes do. After a gate and a canary it kills an nginx worker that starts a program, or a process that opens an SCTP socket. **Most web-attack detection happens here** (§4.3). |
| **DNS over HTTPS** | `dnscrypt-proxy` (DoH only) plus a lock on plain DNS, with a watchdog that relaxes the lock if DoH fails (§4.4). |
| **`edr-agent`** | A sandboxed, standard-library-only Python process. It reads all of the above and sends compact telemetry to the hub over mutual TLS and polls it for fleet peers and, from P3, bans and feeds (§4.5). |
| **Root helpers** | Small oneshot units with fixed JSON in and out: `edr-bans`, `edr-inventory`, `edr-diskguard`, `edr-dns-watch`, `edr-home-net`, `edr-policy-check`; the optional `edr-notify` is the local alert sender (§4.7). |

Installing needs the hub's address and a one-time token. The token never goes on the command line, because any local
user can read process arguments (§4.6). The hub prints these two lines:

    sudo bash -c 'umask 077; read -rs T; printf %s "$T" > /root/edr.token'   # paste the token, press Enter
    sudo ./install.sh --hub 203.0.113.5:8443 --token-file /root/edr.token   # from the unpacked, hash-checked kit tarball (§7)

`install.sh --plan` prints what would change and stops (§7).

**Local mode.** Without `--hub` and a token, or when the hub is unreachable, the installer finishes in local mode and
exits with the "installed, not enrolled" code (§15). Detection, bans and enforcement all work and alerts stay on the
host (§4.7); `sudo edr-agent enroll` joins a hub later. Local mode cannot notice its own root compromise (§12).

### Feasibility verdict

**Feasible and rational.** It is a lightweight, self-hosted cross between CrowdSec (shared IP bans) and
Wazuh/Falco (host telemetry), built mostly from parts this repo already has and tests. The new work is the server
tuning, the web-specific Tetragon policies, the agent and the hub. It costs memory on a 2 GB droplet (§9 shows what
is left for the site), and it is strong for attacks that exec and weak for attacks that do not (§12).

### The one big limit: Suricata can't read HTTPS

nginx terminates TLS **after** the packet has passed Suricata, so for HTTPS traffic Suricata sees only
the encrypted stream: SNI, JA4 fingerprints, sizes and timing, not the URL or body. Exploit payloads
against nginx or PHP sent over HTTPS are **invisible to Suricata**. The design accepts that and
divides the work:

- **Tetragon** catches what an exploit *does*: a shell started from php-fpm, a webshell written, a reverse
  connection, a move to uid 0. That doesn't depend on seeing the request.
- **nginx's own logs** cover what the request looked like: worker crashes, scanner paths, `.env` and `.git` probes, 4xx
  bursts. They do not record HTTP/2 control frames, so frame-level bugs leave at most a crash line (Appendix A.3).
- **Suricata** covers IP reputation, scans, plain port 80, SSH, other exposed services and outbound TLS from the box
  (C2 and miners, by SNI and JA4). It cannot see HTTP/2 frames inside TLS or QUIC (Appendix A.3); the one network trace
  of CVE-2026-123007, a single huge connection, is counted in the kernel (§4.2).
- **The host itself** covers what no packet shows: package and config exposure (§4.5.1), tripwire URLs and canary
  files (§4.7), DNS lookups refused by the lock (§4.4).

### NGINX2Root in short

[NGINX2Root](https://nginx2root.com/) is five unauthenticated nginx memory-safety bugs plus a Linux kernel SCTP bug
that turns a worker's code execution into root ([Xint](https://xint.io/blog/nginx2root-remote-code-execution)).
Upstream fixed the nginx bugs on 18 Nov 2026 (Ubuntu: USN-9159-1); no in-the-wild exploitation was reported as of
19 Nov 2026. The kit **reports exposure** (`edr-inventory`: package against fix, HTTP/2, h2c, HTTP/3, mail, resolver,
stale running binary); **sees nothing on the wire** inside TLS; **kills the step that matters** (any exec by an nginx
worker, any SCTP socket; a crash is only a weak signal, one huge :443 connection a heuristic, §4.2); and **never edits
nginx**. The operator's actions, the bug table and the signal table are in Appendix A.

---

## 2. Principles

1. **The website always wins.** Every part fails open: if Suricata, Tetragon, the agent or the hub goes down, nginx
   keeps serving. No packet is ever queued to user space. These are the deliberate exceptions, and nothing else
   acts on traffic or processes. Each acts on a process or a known-bad address, never on a normal request, and each
   has a way to switch it off (§16):

   | Exception | Acts on | Safe because |
   |-----------|---------|--------------|
   | Tetragon `Sigkill`: `nginx-exec`, `sctp-socket` | a process forked from an nginx worker that starts a program; any SCTP socket by anything but host root | Gate and canary first, monitor mode before that; a healthy worker never execs (§4.3) |
   | Tetragon `Sigkill`: `web-exec` (P2) | any program started in the php-fpm or nginx tree outside the allowlist | Learned from a week of logs, accepted by the operator, off by default (§4.3) |
   | nftables ban and feed sets | source addresses | In-kernel, every entry expires, never-ban list first, hub input (P3) bounded (§4.2) |
   | `bigconn` drop (opt-in, off) | one very large connection | Off by default; log-only otherwise (§4.2) |
   | DNS lock | plain DNS (53, 853) from the box | `edr-dns-watch` removes the lock when DoH fails and restores it when healthy (§4.4) |
   | `edr-diskguard` | kit logs, the MPM cache, Suricata (SIGTERM below 3% free) | Frees the site's disk; fixed actions only, switch in §14 (§9) |
   | Tetragon fork watch `Sigkill` (P3) | a non-root nginx process forking | Local switch, monitor first (§4.3) |
   | Kernel settings | conntrack limit and accounting, SCTP module block | Each recorded in the manifest, reverted by uninstall, skipped with `--no-kernel` or `--no-sctp-block` (§4.2, §7) |
   | Resolver switch | the box's own lookups go to the local DoH proxy | `edr-dns-watch` falls back to the link resolvers (§4.4) |
   | Daily rule update restarts Suricata (hosts under 4 GB) | Suricata | Memory-guarded timer; blind for one cold load (§4.1) |
   | php-fpm restart after a policy change | php-fpm | Operator only; the installer and `apply-config` print the command and never run it (§4.3, §7) |
   | `isolate`, auto nginx restart (P3) | egress; the nginx master | Operator-run or rate limited, with an expiry (§4.7) |

   Enforcement switches are **local only** (§14). Monitoring processes run at lower CPU priority than nginx and
   php-fpm.
2. **The client pulls; the hub never pushes.** The agent connects out to the hub. The hub never connects to clients,
   and there is **no remote command execution**. A compromised hub can send a list of **fleet peer addresses to never
   ban** and, from P3, **bans and feed sets**, and nothing else: it cannot run commands, change files, change thresholds,
   silence detections or switch enforcement. Ignore rules, thresholds, allowlists and enforcement switches are
   local only. The client bounds even what the hub may send (§4.2).
3. **Least privilege.** The agent runs as its own unprivileged user with no capabilities and can reach only the
   hub's addresses. Root work is done by small sandboxed oneshots with fixed inputs and outputs, and the network
   part of enrollment never runs as root (§4.6). Installed code is a root-owned copy; nothing runs from the
   checkout. Every log field is treated as hostile (§4.5).
4. **Bounded resources.** Every log, spool and cache has a size cap and every service a CPU and memory budget (§9).
   The kit cannot fill the disk, and under memory pressure the kernel is set to kill Suricata, then Tetragon, before
   the site.
5. **The repo is the source of truth**, as for the laptop kits. Installers are re-runnable, test changes before
   committing them, record what they changed and roll back on failure. Flags only seed `/etc/edr-agent/local.conf`
   on first install; a re-run never resets a choice (§7, §14).
6. **Say what is not seen.** Each signal carries a strength and each blind spot is written down (§12, §13). Local
   mode is complete on its own; the hub adds history, correlation and a second pair of eyes.

---

## 3. Architecture

```
 droplet (this kit)                                                          hub (../server_hub)
 ┌───────────────────────────────────────────────────────────────────────┐    ┌─────────────────────────────┐
 │ nginx / php-fpm / Laravel (nothing below is in its request path)      │    │ edr-hub  :8443 fleet (mTLS) │
 │                                                                       │    │          :8444 enrollment   │
 │ Suricata (af-packet IDS) -> eve.json, eve-bulk.json ----+             │    │   SQLite, correlation,      │
 │ Tetragon (server policies) -> tetragon.log -------------+             │    │   alerts, feeds, bans       │
 │ nginx logs, sshd and kernel log ------------------------+-> edr-agent ├───►│ POST /v1/events             │
 │ edr-inventory (root oneshot) -> inventory.json ---------+   no root,  │◄───│ GET  /v1/policy             │
 │                                                          hub IPs only │    │   (peers; bans, feeds: P3)  │
 │ edr-agent -> bans.json -> edr-bans (root) -> nft inet edr             │    │ edr-hub-ui :8450            │
 │   sets edr_ban4/6, edr_feed4/6, edr_never4/6                          │    │   (loopback, SSH tunnel)    │
 │   chains ban, bigconn, egress (web-user egress log)                   │    │                             │
 │ dnscrypt-proxy 127.0.2.1 (DoH) + nft inet edr_dns (the lock)          │    │                             │
 │   edr-dns-watch: probes every 15 s, opens the lock on failure         │    │                             │
 │ edr-home-net (own addresses), edr-diskguard (size caps)               │    │                             │
 │ local: alerts.jsonl, login summary, edr-notify (optional)             │    │                             │
 └───────────────────────────────────────────────────────────────────────┘    └─────────────────────────────┘
```

Each root helper has fixed JSON in and out and its own sandbox; the agent never holds root. `nft inet edr` and
`inet edr_dns` are separate tables, so either can be deleted alone. Hub ports: 8443 needs a client certificate, 8444
is enrollment only (open while a token is pending), 8450 is the dashboard on the hub's loopback (hub §5). Runtime
files in the kit's `/run/edr-*/` directories survive a unit restart. Without a hub, the
agent keeps reading, banning and alerting locally (§4.7).

---

## 4. Components

### 4.1 Suricata, server profile

IDS only, on a copy of the traffic: if Suricata dies the site is unaffected (principle 1).

| Setting | Server value | Laptop kit |
|---------|--------------|------------|
| Mode | **af-packet IDS** on the public interface | NFQUEUE inline (`-q 0`) |
| Threads, priority | `workers`, `threads: 1` (2 on 4+ vCPU); `Nice=10`, `CPUWeight=50`, `IOWeight=20` | `auto`, default |
| `detect.profile` | `medium` (`low` saved nothing in tests) | `medium` |
| `mpm-algo` | `auto` (Hyperscan on amd64). Never write `hs`: it is fatal where Hyperscan is absent | `auto` |
| Memcaps (2 GB droplet) | stream 32M, reassembly 128M, flow 64M | 64M / 256M / 128M |
| Offloads, checksums | `capture.disable-offloading: false`; `af-packet: checksum-checks: no`; `stream.checksum-validation: no` | offloads off |
| `stream.midstream` | `false` | `true` |
| `stream.reassembly.depth` | `512kb`, tuned down from memcap use in the VM test | `1mb` |
| TLS, SSH `encryption-handling` | `bypass`; `app-layer.protocols.ssh.hassh: yes` | `track-only` |
| `detect.sgh-mpm-caching` | `yes`, `sgh-mpm-caching-max-age: 7d` | `yes`, no max age |

**NIC offloads.** By default Suricata switches off checksum, SG, GSO, TSO, GRO and LRO on the capture NIC and restores
them only on a clean exit. That slows nginx's send path, and SIGKILL, an OOM kill or a crash loop leaves them off until
reboot. `capture.disable-offloading: false` leaves the NIC alone, so a crash changes nothing: throughput wins over
reassembly fidelity. Checksum checks stay off (virtio TX offload makes captured egress packets look bad). GRO
super-packets can confuse `dsize` rules; the VM test checks the kept rules. Confirm the key on the pinned 8.x; if it is
ignored, add an `ExecStopPost` restoring the saved `ethtool -k`. `check.sh` WARNs on the offloading warning in the log;
a chaos test compares `ethtool -k` before install, while running and after `kill -9`. The af-packet block (`tpacket-v3`,
`cluster-id`, `ring-size`, `block-size`, `mmap-locked`) has never run here: test it in the VM (`mmap-locked: no` if it fails).

**TLS.** `encryption-handling: bypass` for `tls` and `ssh`: SNI, JA4 and HASSH are logged from the handshake, then the
flow is bypassed (tested). Packets are still read but not inspected. Without it, about 128 busy TLS flows at the laptop's 1 MiB depth (twice that at 512kb) fill the 128M
reassembly memcap and plain HTTP then stops being reassembled. `midstream: false` leaves flows open at start uninspected
(accepted) and stops one forged packet starting a stream. Set `ja4-fingerprints: yes` for `ja4.hash` rules (confirm the
key). Later, not v1: a `bpf-filter` dropping server-to-client 443 (one-sided flows, no server certificates).

**Unit.** A drop-in on the packaged `suricata.service`, which already runs af-packet and `--user suricata`. The drop-in has no
`ExecStart=` line: the packaged `/usr/bin/suricata --af-packet -c /etc/suricata/suricata.yaml --pidfile
/run/suricata.pid --user suricata --group suricata` stays (an `ExecStart=` reset would lose `--af-packet`).
`--user suricata` must stay (log group and agent reads depend on it). The list below is applied to the laptop
`files/suricata-override.conf` when building the drop-in:

- **Keep:** `ProtectSystem=strict`, `Protect*`, `Private*`, `Restrict*`, `LockPersonality`, `SystemCallArchitectures`
  (no `MemoryDenyWriteExecute`: it breaks the PCRE2 JIT). **Change:** `AmbientCapabilities=CAP_NET_RAW` only;
  `CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID` as the starting value (the laptop file sets
  none; Suricata starts as root and needs setuid and setgid to drop to `suricata`, and af-packet may need
  `CAP_NET_ADMIN` for promiscuous mode; the VM test removes what it can and records the minimum);
  `ReadWritePaths=/var/log/suricata /var/lib/suricata /run`; keep `--user suricata`. **Delete:**
  `Wants/After=suricata-nfqueue.service`, `-q 0`, `Restart=always`, `RestartSec=1`, `StartLimitIntervalSec=0`.
  **Add:** `ExecStartPre=-+` the root-owned `edr-home-net` under `/usr/local/lib/edr-agent/` (the same script as
  `edr-home-net.service`, which the timer runs every 15 minutes) with `--no-reload` (leading `-`: fail open), and:

    [Unit]
    StartLimitIntervalSec=10min
    StartLimitBurst=5
    [Service]
    OOMScoreAdjust=800
    MemoryHigh=1000M
    MemoryMax=1300M
    Restart=on-failure
    RestartSec=30

- The kernel then kills Suricata before mysqld, php-fpm, nginx or the admin's sshd session; Tetragon gets
  `OOMScoreAdjust=700` (§9). `RestartSec=30` stops a failing start becoming a CPU loop (no queue bypass needs 1 s).
- Limits are starting values for 2 GB: set them after the VM test measures the reload peak, with headroom above it.
  The installer offers a 1 GB swapfile if swap is 0 (opt-in). Chaos test: `stress-ng` plus the update timer; the
  victim must be a kit process.

**Rule update** (reused `suricata-rules-update.{service,timer}`: daily, sandboxed, tested before commit). Changes:

- `Nice=19`, `CPUWeight=20`, `IOSchedulingClass=idle`; `suricata -T` runs under `systemd-run -p MemoryMax=900M` (if
  killed, the candidate is rejected and the old rules stay).
- A memory guard (`ExecCondition`) skips test and reload when `MemAvailable` is below the larger of about 700 MB and
  1.5 times Suricata's RSS; the next day retries and 3 skipped days raise a stale-rules event. A live reload builds a
  second engine (peak about 800 MB at ~41k rules, an estimate: measure), so under 4 GB the update restarts Suricata
  instead (blind for one cold load: about 10 s on a fast CPU, 2-3 times that on a shared vCPU). Confirm both in the VM test.
- A failing source never stops the update; `check.sh` WARNs if a source is older than 7 days, and the installer
  pre-flight WARNs (never rolls back) on an empty or failing one.

**HOME_NET** comes from `edr-home-net` (reused `suricata-home-net.sh`, no NetworkManager hook, bridge logic only if
Docker is used). It runs at each Suricata start and on a 15-minute timer that reloads rules (through the memory guard)
only on change. A stale value silently disables every `-> $HOME_NET` and outbound C2 rule.

| Address | Source |
|---------|--------|
| Public IPv4 and the anchor IP (aliased on eth0 for Reserved IP traffic) | `ip -o addr`, all interfaces, `/32` each |
| IPv6 | the addresses on the interface, **not the on-link /64** (a droplet gets 16 addresses; a /64 would cover other customers; confirm the prefix). The reused script writes a /64 for IPv6; the server copy must write each interface address as an exact /128 (and each IPv4 as /32) |
| VPC CIDR | `[sites] vpc_cidr` (below); `edr-home-net` writes it to `/etc/suricata/home-net.extra` |
| Reserved IP | not on the box; confirm on a droplet with one (`tcpdump`) which destination address arrives |

**One source for the VPC range: `[sites] vpc_cidr`.** `edr-agent discover` (§4.3) fills it from the connected route of
the VPC interface (the route table, not the metadata service), or the installer asks for it; the other addresses
above stay exact. `edr-home-net` writes `home-net.extra` from the key. `[suricata] home_net` overrides HOME_NET only.
§4.2's never-ban list and §4.3's `web-connect` `NotDAddr` read the same key.

No runtime metadata calls. At install the installer prints the detected set (from `ip -o addr`, plus the Reserved IP and public IPv6 from the metadata service when it reports them) and asks for confirmation; `--home-net CIDR` overrides. `check.sh` FAILs if
HOME_NET lacks an address from `ip -o addr`. The same set feeds §4.2's own-addresses never-ban list.

**Reuse and packaging.** Reused: the candidate, test, commit or roll back pattern (`install.sh:62-95`, `:186`,
`:203-204`), `suricata.apt-pin`, `drop.conf`/`modify.conf`/`disable.conf`, the laptop yaml as base (a server `include:`
overlay: verify precedence). Not reused: `suricata-nfqueue-apply.sh`, `suricata-nfqueue.service`, the NetworkManager
hook. Suricata comes from the **OISF stable PPA** on both releases (8.0.8 at time of writing; pin `1:8.*`). Trade-off:
26.04's archive has 8.0.3, so the PPA adds a third-party repository in return for currency in a parser of hostile
traffic. Never fall back to noble's archive (7.0.3, out of support): if the PPA cannot be added, the installer stops.
`check.sh` reports the Hyperscan line of `suricata --build-info`. amd64 only.

#### 4.1.1 Ruleset

- **Sources:** `et/open` and, optionally, `abuse.ch/sslbl-blacklist` only (certificate
  fingerprints, so TLS 1.2 C2 only, for about 50 MB; the 102 ET JA3 rules are the alternative). The ET licence file is the tarball's `BSD-License.txt`.
- **Enabled:** all of `et/open` except the list below, including web_server, web_specific_apps, exploit,
  attack_response, scan, malware, coinminer, hunting, ja3, sql, ftp, telnet, misc, current_events, shellcode, worm,
  remote_access. There is no ET SSH file; SSH is covered by the `ssh` eve type and sshd logs.
- **Disabled** (`group:emerging-X.rules`): dyn_dns, adware_pup, web_client, netbios, user_agents, file_sharing,
  inappropriate, voip, info, chat, games, p2p, mobile_malware, scada, activex, retired, deleted. exploit_kit,
  phishing and tor are large and client-side: disabled by default (the VM test may revisit this). `suricata-update` re-enables rules whose
  flowbits others need, so check the final count.
- **Moved to nftables:** `drop` and `dshield` (hub-fed sets, P3: Spamhaus DROP and FireHOL dshield, §4.2). `ciarmy` and
  `compromised` have no feed behind them: enabled until the VM test shows the rule count or memory over budget.
- **Size:** ~30k rules (ET only), ~41k with sslbl; ~400 MB RSS, ~10 s cold load at 41k on a fast CPU (a shared vCPU may
  be 2-3 times slower; ~4-5 s warm). `--lite` (1 GB): smaller set, measure in the VM test. CI runs `suricata-update`
  offline on a saved tarball and fails outside rule-count bounds set after the VM test.
- **MPM cache** `/var/lib/suricata/cache/sgh`: pruned only by age; it reached about 890 MB on the laptop. §9 budgets
  900 MB until the VM test measures the 7-day size. It is disposable; the disk guard deletes it first.
- **Ban candidates.** `drop.conf` marks rules whose source may be banned; Suricata never drops in IDS mode. A
  drop-converted rule appears as an ordinary alert with `alert.action: allowed` and no `drop` event, so the update job
  writes `/var/lib/suricata/rules/edr-ban-sids.txt` (`root:suricata 0640`) from `suricata.rules` after `drop.conf`
  (`grep -oP "^drop .*sid:\K[0-9]+"`). The agent matches `alert.signature_id`; severity is not used. Re-check
  `drop.conf` against a week of server alerts. The flow conditions that make an alert bannable are in §4.2 (Local
  auto-bans). Thresholds and budget: §4.2; residual risk: §12.

#### 4.1.2 eve.json output

Types are read at start; nothing changes them at runtime. Two `eve-log` instances: `eve.json` (alert, anomaly, stats;
small, always on) and `eve-bulk.json` (tls, ssh, quic; the disk guard may drop it, §9); confirm in the VM test.
Rotation is the kit's own logrotate (§9, authority) followed by `systemctl kill -s HUP suricata.service` (pid-file HUP as the fallback; confirm in the VM test). `delaycompress` stays so `eve.json.1` is plain for the
agent's checkpoint (§4.5); schedule and caps are in §9.

| Type | Setting | Why |
|------|---------|-----|
| alert | on; payload 4 KiB; no `packet`, no printable payload; `payload-length`, `metadata`, `community-id` | Core signal; the laptop's 16 KiB plus packet is about 3 times larger |
| anomaly | on, app-layer only | Rare, useful |
| tls | on, extended (SNI, JA3S, **JA4**) | Outbound C2, miners, inbound fingerprints |
| ssh | on; HASSH needs `app-layer.protocols.ssh.hassh: yes` (an app-layer option, not an eve one) | Brute-force tool fingerprints |
| quic | on | SNI and JA4; free if no HTTP/3 |
| stats | every 60 s, totals only | Heartbeat |
| http | **off** | Alerts carry the request; nginx's access log has the rest. Option: `on` with a daily size cap |
| dns | **off** | The lock rejects plain DNS before the NIC, so af-packet sees none; see dnscrypt-proxy logs (§4.4, P3) |
| flow, netflow, files, file-store, drop | not configured | Most of the logging cost; `drop` is silent in IDS mode |

**Stats and the heartbeat.** The 60 s event gives `capture.kernel_packets`, `capture.kernel_drops` and memcap counters
(confirm names on the pinned build) for the heartbeat; the agent alerts the hub when drops exceed 1% in a window.

### 4.2 Blocking: nftables ban sets

Bans are in-kernel, carry their own timeouts and fail open: deleting the table lifts everything. The unprivileged
agent decides, a small root oneshot (`edr-bans`) applies, and the kit never edits UFW or Docker rules.

- **Table and hooks.** One table, `inet edr` (sets are declared before the chains that use them):

        table inet edr {
          set edr_never4 { type ipv4_addr; flags interval; }                      # + edr_never6
          set edr_ban4   { type ipv4_addr; flags interval,timeout; size 16384; }  # + edr_ban6
          set edr_feed4  { type ipv4_addr; flags interval,timeout; size 400000; } # + edr_feed6
          counter hit_ban4 { }                          # one named counter per drop rule
          chain ban {
            type filter hook prerouting priority -150; policy accept;
            ip saddr @edr_never4 return                 # + ip6; the never-ban check comes first
            ct direction original ip saddr @edr_ban4 counter name hit_ban4 drop
            ct direction original ip saddr @edr_feed4 counter name hit_feed4 drop
            ct state untracked ip saddr @edr_ban4 drop  # notrack'd flows never match the rules above
          }                                             # + ip6 twins; chains bigconn and egress follow
        }

  - **Why prerouting at -150 with `ct direction original`:** after conntrack (-200), before the iptables-nft nat
    chains (-100), so DNAT-forwarded Docker traffic is covered (the input hook never sees it). Replies to
    connections the server started are never dropped. A new ban cuts an established inbound flow at once, which
    matters for the long-lived NGINX2Root connection. A plain `saddr` drop kills our own replies and `ct state
    new` leaves an established flow alive (both tested). nft traps: `;` before `}` in a one-line chain; `fwd` is reserved. Tested on nft 1.1.6; confirm the chain syntax,
    `ct direction original`, `ct original bytes` and the egress rule on 24.04 (nft 1.0.9, kernel 6.8) in the VM test.
- **Sets and TTL.** nft takes only a relative `timeout` and re-adding an element **replaces** it, so state carries
  an **absolute `expires`** (epoch s) and `edr-bans` computes `min(expires - now, 7 days)` at each apply: a
  re-apply keeps the remaining time. An entry with under 1 s left is dropped; `timeout 0s` (permanent) is never written.
  - Overlap in one set aborts the transaction, and nft `auto-merge` makes TTLs arbitrary, so ban sets do not use
    it: `edr-bans` merges overlaps itself, keeping the widest CIDR and the longest TTL.
  - Feeds (P3) expire 72 h after the last successful policy poll (200, or 304 meaning unchanged) whose document
    contains that feed: a dead hub drains them with no process. A feed key absent from the document is removed at the
    next apply (absence is not "empty").
  - `size` is a kernel backstop behind the Python caps. Escalation counts live in the agent.
  - A table replace empties dynamic sets and counters (the agent treats counters as resettable). `edr-bans` skips
    the replace when the validated state is unchanged and the table is present.

#### Never-ban list

Checked in the kernel first (`edr_never4/6`) and again in `edr-bans`. **Do not use `ipaddress.is_private` or
`is_global`**: they call 203.0.113.0/24, 198.18.0.0/15, 2001:db8::/32 and 6to4 private. The literal list:

| Family | Literal prefixes |
|--------|------------------|
| IPv4 | 0.0.0.0/8, 10/8, 100.64/10, 127/8, 169.254/16 (holds the metadata address), 172.16/12, 192.0.0/24, 192.168/16, 224/3 |
| IPv6 | ::/128, ::1/128, fc00::/7, fe80::/10, ff00::/8 |

Added from the machine (`edr-home-net` recomputes at boot and every 15 minutes, and feeds Suricata's HOME_NET too, §4.1) and from configuration:

- **Hub and fleet (P2):** the hub addresses and the policy `peers`. Both are accepted only as single addresses (/32 or
  /128) parsed with `norm_ip()`, never a range; at most 4 hub addresses per identity generation and 512 peers in all
  (more is refused like any guard breach). A peer that is a never-ban literal or the gateway is ignored. Peers are
  additions only and carry the same 72 h timeout as feeds.
- **Administrators:** `admin_ip` (`--admin-ip`); the `SSH_CONNECTION` source at install time, added automatically;
  the remote addresses of **authenticated** SSH sessions (logged-in sessions from `loginctl` or utmp, read at each
  apply), kept for the life of the session and dropped when it ends (a connection still in pre-authentication never
  qualifies, so a brute-forcer cannot place itself on the list); operator `allow_cidr` (crawlers, payment webhooks,
  monitors, panel SSH sources such as Forge's published list).
- **The machine:** gateway, resolver and DoH addresses, the VPC range (`[sites] vpc_cidr`, filled by discovery, §4.1; `edr-home-net` writes `home-net.extra` from it), and its own addresses (every interface address
  plus Reserved and anchor IP from metadata). DigitalOcean gives a droplet 16 IPv6 addresses, so use those, not
  the on-link /64 (other customers). The installer prints the set. `[suricata] home_net` overrides Suricata's HOME_NET only, not this list.
- **Droplet Console** connects from addresses DigitalOcean does not publish: it cannot be allowlisted by IP. SSH
  bans count **failed** authentication only, so a console login never bans. The installer says so, and that
  limiting SSH to `admin_ip` breaks the Console (the Recovery Console still works).

Rules: map `::ffff:a.b.c.d` to IPv4 first; one `norm_ip()` rejects whitespace, leading zeros, zone IDs and host bits;
a CIDR that contains or overlaps any entry is refused (sorted intervals and `bisect`); a refused ban is reported as an
event and in `last_apply_error`, and the rest of the state applies. A property test (random
CIDR sets never overlap the list) runs in `make lint`; the mock attacker uses 198.18.77.0/24 (198.18.0.0/15 is deliberately not in the list, so the mock attacker can be banned).

#### How a ban is applied

1. **Desired state** is local bans (agent-owned, kept in `/var/lib/edr-agent`) plus, from P3, hub fleet bans and hub
   feeds. The agent writes `/run/edr-agent/bans.json` atomically (temp file, rename; at most once per 5 s).
2. **Triggers.** `edr-bans.path` is the fast path; `edr-bans.timer` (`OnBootSec=20s`, `OnUnitActiveSec=60s`, `AccuracySec=1s`) runs the same
   idempotent apply, repairs a flushed table and writes counters, so a dead path unit costs a minute at most.
   - `edr-bans.service` sets `StartLimitIntervalSec=0` (a burst of bans hits 5 starts in 10 s, fails the service,
     then the path unit); `edr-bans.path` sets `TriggerLimitIntervalSec=0`. `check.sh` (§8) FAILs if the path unit
     is not active.
   - systemd ignores changes while the oneshot runs, so the helper re-reads until the file is stable. A missing
     `bans.json` means "keep the table". An empty state is refused after a non-empty one unless it says `"empty": true`.
   - `WantedBy=multi-user.target`, `After=nftables.service` (its `/etc/nftables.conf` starts with `flush ruleset`),
     `Before=network-pre.target`. Confirm with `systemd-analyze verify` that adding `ufw.service` makes no cycle.
     At boot the unit sets `TimeoutStartSec=10` (loading local bans takes under 2 s; the timer applies feeds after
     boot), is never a `Requires=` of anything, and a timeout or failure leaves the site and network up (fail open).
     `check.sh` FAILs if `systemd-analyze critical-chain network-pre.target` lists a kit unit over 5 s.
3. **Boot.** `edr-bans` builds the table from `/var/lib/edr-bans/state.json` (last good state, absolute expiries,
   expired entries skipped): local bans survive a reboot with no hub and no agent.
4. **Hostile input.** The agent owns `/run/edr-agent`, so `bans.json` may be a symlink, FIFO, huge or deeply
   nested. `edr-bans` opens it `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, requires a regular file with one link, owner
   `edr-agent`, at most 16 MiB, reads once, parses with `json`, and on any exception keeps the last good state.
   The agent creates `bans.json` with an explicit `0644` (no secrets in it; `/run/edr-agent` is 0755) because
   `edr-bans` has no DAC override; do not add `CAP_DAC_READ_SEARCH`. The script comes only from `str(ipaddress.ip_network(...))` and integers (nft resolves names through DNS), is
   checked with `nft -c -f -`, then applied with `nft -f -`.
5. **Atomic replace.** One script holds `table inet edr`, `delete table inet edr` and the new definition. Sandbox:
   `CapabilityBoundingSet=CAP_NET_ADMIN`, `RestrictAddressFamilies=AF_NETLINK AF_UNIX`, `IPAddressDeny=any`,
   read-only filesystem except `StateDirectory=edr-bans` (`/var/lib/edr-bans`), `MemoryMax=1G` (starting value; measure
   in the VM test; §9 has the budget), `RuntimeDirectoryPreserve=yes`.
6. **Counters without listing sets.** `nft -j list table inet edr` prints every element (1.5 s, about 390 MB at
   200k feed entries). `edr-bans` reads named counters (`nft -t -j list counters table inet edr`) and knows what
   it wrote. `/run/edr-bans/counters.json` holds `table_present`, set sizes, conntrack use and the last apply result.
   `check.sh` uses `nft -t`, never a bare `nft list ruleset`.

#### Guards against a hostile or broken hub (P3)

Before P3 the agent may poll `/v1/policy` but applies only the never-ban peers and the hub addresses; bans and feeds
are empty in the document and are applied from P3. The agent may be compromised too, so `edr-bans` enforces these itself. A refusal keeps the last good state, raises
CRITICAL and shows in `last_apply_error`. Caps: 10k bans, 200k feed CIDRs, 512 peers.

| Guard | ban4 | ban6 | feed4 | feed6 |
|-------|------|------|-------|-------|
| Minimum prefix length | /16 | /32 | /12 | /29 |
| Coverage cap, after never-ban carving | 0.1% of IPv4 | 16 x /32 | 2% of IPv4 | 1024 x /32 |

- **Change per update.** New feed coverage above 0.5% of IPv4 is refused. More than 20 new hub bans in one update
  or 10 minutes is refused (hub part only; local bans stay).
- **Why.** 70 CIDRs between /16 and /8 that dodge the never-ban list cover 86% of IPv4; real feeds are far inside
  the caps (Spamhaus DROP about 0.35%).
- **Self-test.** After a feed apply, `nft get element` for 169.254.169.254, the hub and the gateway must all be
  absent; otherwise `edr-bans` deletes the feed sets and raises CRITICAL.

**Feeds as the client sees them (P3).** The hub fetches, filters and carves them (hub §4: Spamhaus DROP v4/v6, FireHOL
`dshield`); the client never fetches. It drops each entry that is invalid, under the minimum prefix or still
overlapping the never-ban list, applies the rest and reports the count. The 5% refusal is the hub's (hub §4). Only a
script that fails to parse refuses the whole state. FireHOL level1 is not used (fullbogons, private ranges). An
empty feed never replaces a non-empty one.

#### Local auto-bans (work with no hub)

| Trigger | Evidence | Default | First TTL |
|---------|----------|---------|-----------|
| SSH brute force | `sshd` journal: `Failed password`, `Failed publickey`, `Invalid user`, `Connection closed by authenticating user ... [preauth]` | 5 in 10 min | 1 h |
| Scanner paths | access log, `tripwires.json` (§4.5), status 404, 403 or 444 | 5 hits in 5 min | 1 h |
| Suricata alert | TCP, `app_proto` set, `stream` 1, `pkts_toserver` >= 3, `pkts_toclient` >= 1, `alert.signature_id` on the ban list (§4.1.1; severity is not used) | 3 alerts or 2 signatures in 10 min | 1 h |
| NGINX2Root flow control (opt-in log) | `error.log`: `client violated connection flow control: received WINDOW_UPDATE frame with window increment` | 3 in 10 min | 1 h |
| Large connection | `edr-bigconn` line, repeat from one address | 2 in 1 h | 1 h |

A 200 on a tripwire path is a HIGH alert, not a ban. The WINDOW_UPDATE line is logged at `info`, so that trigger is
inactive until `[agent] nginx_info_log = on` (§4.5) and the operator has added the `error_log ... info` line (the kit
never edits nginx); `check.sh` reports which. By default the crash-line alert (`nginx.crash`, §4.5) and the large-connection watch below are what work; neither bans on that line.
The line comes from the [nginx source](https://raw.githubusercontent.com/nginx/nginx/release-1.31.9/src/http/v2/ngx_http_v2.c).

- **Evidence an attacker cannot forge.** Each event has `src_trust` (Appendix B): `tcp` (an established flow, or an
  address the writing daemon recorded and the anchored rules of §4.5 extracted), `claimed` (a header or any field
  those rules do not accept; everything when `real_ip` is configured) or `none` (no address). Only `tcp` bans.
  - Address attribution per source is in §4.5 (Hostile log content). SSH counts journal failures only, never
    Suricata SSH events.
  - Suricata never bans on UDP, ICMP, SYN-only or `stream`-event alerts (one spoofed packet would ban a customer).
    It needs `stream.midstream: false` (the laptop default is true): `check.sh` verifies it, and until it passes
    Suricata bans are off. An on-path attacker can still forge a flow (§12, §13).
  - Only events under 15 minutes old count, never a backlog. Per-address counters are LRU capped at 50k.
  - An address with an `Accepted` login in the last 30 days is never banned for SSH failures (agent state; P2).
- **Budget.** At most 30 new local bans per hour and 1000 active; then banning stops and HIGH "ban budget
  exhausted" is raised, so a flood cannot fill the 10k cap or lock out real users.
- **TTL ladder.** 1 h, 6 h, 24 h, 7 d, remembered for 14 days (so the 7 d rung is reachable). Hub bans use the same
  ladder and add only a source flag. **IPv6** is banned as the /64, with no local escalation.
- **Behind a proxy or CDN** the log address is the edge's. Web-sourced bans and Suricata bans on ports 80 and 443
  turn off (with a WARN) when inventory reports `real_ip` or X-Forwarded-For, when the access log shows
  X-Forwarded-For or CF-Connecting-IP values while no `real_ip` is configured, when over 50% of the last 1000
  requests share one address or a private or CGNAT address, or when fewer than 3 distinct sources appear. When
  `real_ip` is configured, web-sourced bans are off, with no exception for private or CDN ranges. SSH bans stay.
  `proxy_mode` in `local.conf`: `auto` (detect, above), `on` (force proxy handling), `off` (no heuristic
  detection). `off` never overrides inventory's `real_ip`: web-sourced bans stay off whenever `real_ip` or an
  X-Forwarded-For log format is present.
- **Never-ban ranges still alert.** An internal source on scanner or web signals raises MEDIUM "internal source"
  (CRITICAL only for `web-exec`, §4.3).

#### Conntrack is a declared dependency

The `ct` expressions need conntrack, and the kit must not be what fills it. Pre-flight records whether
`nf_conntrack` was already loaded (UFW and Docker usually load it).

- **Sizing when the kit is first.** A 2 GB droplet gets 65,536 entries (about 550 new connections a second fill it
  with TIME_WAIT alone), and a full table drops new connections. If the limit is still the default the installer
  sets `nf_conntrack_max=262144` (about 67 MB worst case) after the module loads (`sysctl -p` or `modules-load.d`;
  `sysctl.d` can run first). Established timeouts are not shortened. Uninstall removes the drop-in if the kit made it.
- **Monitoring.** The heartbeat reports count, maximum, and `drop` and `early_drop` from `/proc/net/stat/nf_conntrack`.
  The hub alerts at 70%; `check.sh` WARNs at 70% and FAILs at 90%.
- **Connections that existed before install** are picked up mid-stream (tested: a flow that predates the rule is never counted)
  without byte counters, so `bigconn` sees only later connections, and an old attacker flow may outlive its ban until it closes.
- **Test:** SYN flood, 5k/s for 2 minutes: at least 95% of new connections to the site succeed. Also confirm in the
  VM that mid-stream pick-up of older flows produces no INVALID packets.

#### Large-connection watch (NGINX2Root, CVE-2026-123007)

Per Rapid7 (not verified by us) the exploit's bulk is client to server: 13-byte `WINDOW_UPDATE` frames plus request
headers, about 60 GiB for the crash stage and 119 GiB for RCE, 17 minutes at 1 Gbit/s
([Rapid7](https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/)).
So the rule counts `ct original bytes`; both directions would trip on every big download. It sees the crash and RCE
stages, not the 5.69 MB probe, and an unreleased exploit may differ: a heuristic, not a detector.

    chain bigconn {   # sets edr_big4/6: flags dynamic,timeout; size 4096; timeout 10m
      type filter hook prerouting priority -140; policy accept;
      tcp dport 443 ct original bytes > 4294967296 ip saddr != @edr_big4 add @edr_big4 { ip saddr } log prefix "edr-bigconn: "
    }                 # + ip6 twin

- **A dynamic set, not a `ct mark`** (a mark bit can collide with policy routing, WireGuard, Tailscale, Docker). Each
  source logs once per 10 minutes: bounded log volume, yet a repeat reaches the ban trigger. Loading the rule switches
  on `nf_conntrack_acct`. `[bans] bigconn_bytes` defaults to 4 GiB (nft needs bytes; the installer converts
  `4G`) and is set only in `local.conf`. Big legitimate uploads go on the allowlist. UDP 443 (HTTP/3) is not covered.
- The log lines appear only in the initial netns: test them once in the VM with a real long-lived connection.
- **Log-only by default.** `[bans] bigconn_cap` (default off; seeded by the installer flag `--bigconn-cap SIZE`) adds `tcp dport 443 ct original bytes > CAP reject with tcp reset`.
  That reject is valid in prerouting, input, forward and output, not postrouting; the reset reaches the attacker
  only and nginx's socket is not reset. `drop` is the alternative. It defeats the public strategy, not the bug.

#### Web-user egress record (P2)

A log-only record of where the web users connect: a reverse shell or C2 over 80 or 443 is otherwise silent (§4.3
`web-connect` ignores those ports). The installer renders the uid list from discovery (`local.conf`), never a fixed web identity. Loads on nft 1.1.6:

    set edr_egress_seen { typeof meta skuid . ip daddr . tcp dport; flags dynamic,timeout; size 4096; timeout 1d; }
    chain egress {   # hook output priority 0; ip6 twin omitted
      meta skuid { <web uids from local.conf> } ct state new tcp dport { 80, 443 } meta skuid . ip daddr . tcp dport != @edr_egress_seen \
        add @edr_egress_seen { meta skuid . ip daddr . tcp dport } limit rate 30/minute log prefix "edr-egress: " flags skuid
    }

The agent learns tuples for 14 days; a new one afterwards is a LOW digest entry (`edr.egress`), HIGH if followed by
`web-exec` or `web-write-code`. Past the rate limit a first-seen tuple goes unlogged. Confirm in the VM that the log
line carries the uid. The rule never drops.

#### Operator commands, failure and removal

| Command | What it does |
|---------|--------------|
| `edr-agent bans` | Local, hub and feed state: source, remaining time, counters (feeds as counts). |
| `edr-agent unban ADDR` | Removes a local ban and records an allow entry so the ladder does not re-ban it. |
| `edr-agent unban --all` | Writes an explicit empty state (`"empty": true`) and clears local ban memory. |
| `nft get element inet edr edr_ban4 { 198.51.100.7 }` | Tests one address without listing a set. |
| `edr-agent pause [--for DURATION]` | Kill switch (§4.7). While `/etc/edr-agent/pause.json` is valid, `edr-bans` applies an explicit empty state (`"empty": true`): ban and feed sets are emptied, the table, never-ban set and log-only chains stay. `resume`, or the end of the period, restores from state. |

Break-glass without the agent: the commands are in §4.7 (they stop the path and timer units first, or those rebuild the table).

- **Uninstall** (§6): stop the path and timer, delete `inet edr` first, then remove `/var/lib/edr-bans`.
- **`edr-bans` fails:** the last good table stays and every entry still expires by its own timeout.
- **Rehome, hub loss, agent stop:** §5 and §17 (Hub away). Every entry expires by its own timeout and local bans
  survive a reboot from `state.json` (How a ban is applied, step 3).

#### What the client expects of `/v1/policy` (hub Appendix A, P3)

Before P3 only `peers` and the hub addresses are used (see Guards, above). The `/v1/policy` document and its field names are in hub Appendix A: `rev` (the ETag; 304 when unchanged),
`hub_time`, bans as `{cidr, expires_at, source, reason_id}` (`expires_at` in epoch seconds on the hub clock), feeds
and `peers`, nothing else in v1. The agent computes the remaining time as `expires_at - hub_time` and stores an
absolute expiry on its own clock at receipt, so skew shifts nothing; it WARNs above 60 s. `source` and `reason_id`
are validated against closed vocabularies (else shown as `unknown`) and cleaned before display in `edr-agent bans`
and `check.sh`, because root runs them. An unban is absence from the next document. Unknown fields are ignored; no
reason text names another host. The heartbeat returns `policy_rev_applied`, `ban_counts` and `last_apply_error`.

### 4.3 Tetragon, server policy set

Installed with the laptop kit's machinery (`tetragon/local_install.sh`, `tetragon/config.sh`); server policies live
in `server_client/tetragon/policies/`. BTF must be present (`/sys/kernel/btf/vmlinux`).

**Version.** The pin is v1.7.1 (2026-08-25), checksums in `config.sh`. It loads kprobe policies on kernel 7.0;
enforcement is proved only by the VM canaries (§11) on 24.04 (6.8 GA, HWE) and 26.04. v1.8.0 (2026-10-30) is a large
release and is not adopted. A newer release is adopted by changing the version and all checksums together, passing the
whole VM matrix, and shipping the pin in a kit release (§15). Never use `--keep-sensors-on-exit` (it breaks fail-open).
Policies hook `security_*` kprobes and `tcp_connect`, never `lsmhooks:` (24.04's default LSM list has no `bpf`).

**Selector facts** (v1.7.1 source, parse-tested against a 7.0 BTF; `make lint` enforces them):

| Fact | Consequence |
|------|-------------|
| First matching selector wins | Order is the mechanism: log-only or `NoPost` selectors go before the killing one |
| Max 5 selectors, 5 args, 3 actions per hook; 8 prefix/postfix lists per policy; one kprobe per symbol per policy | Lint counts them, `matchBinaries` Prefix/Postfix included |
| `followChildren` needs exact binary paths and shares 64 ids across policies | Paths are templated; lint counts them; children older than the policy are missed |
| `matchBinaries` is a stored path; a process older than Tetragon with an upgraded binary reads `/usr/sbin/nginx (deleted)` | Every nginx list carries both spellings |
| No uid selector, no `NotMask`, no `matchParentBinaries` without `--parents-map-enabled` | Match by process tree; `enable-ancestors base` is set; "not CLONE_THREAD" is two ordered selectors |
| `matchCapabilities` ignores the user namespace | **No capability-based exemption.** `unshare(CLONE_NEWUSER)` gives a worker a full effective set (tested, 26.04). A capability counts only with `matchNamespaces User In host_ns` |

#### Installing on a server

Changes needed in `tetragon/local_install.sh` and `check.sh` (a server wrapper may set them instead):

| Change | Why |
|--------|-----|
| `POLICY_DIRS` (reused laptop plus server policies) staged into one directory, used by `check.sh` and the tools copy; `DENYLIST` override (local_install.sh:165, :446; check.sh:113) | Reused policies live in the laptop directory; the denylist is rendered from the repo file |
| `config.sh` as `: "${TETRAGON_LOG_MAX_SIZE_MB:=50}"`; one `LOG_PERM` shared with check.sh:148 (asserts 600) | Assigned unconditionally today. Server: 20 MB, 5 backups, 640 (§9) |
| `--no-watch-user`: no `@HOME@` substitution; lint fails on `@HOME@` in a server policy | Unreplaced it never matches (39 uses in `persistence`, 22 in `sensitive-files`). Server variants use Postfix such as `/.ssh/authorized_keys` |
| `health-server-address` `127.0.0.1:6789`; `check.sh` FAILs on a non-loopback Tetragon listener | The default `:6789` is on every interface |
| `--no-viewer` always passed (it exists); boot gate off (`--no-boot-gate`) | The gate holds `basic.target` up to 90 s if Tetragon hangs |

- **Boot.** Tetragon starts alongside everything and never delays `sshd` or `nginx`; policies may load seconds later
  (a restart emits a "blind window" event, §4.5). `followChildren` misses workers older than the policy, so php-fpm
  must be restarted (not reloaded) after the policies load. The installer prints the command and never runs it (§7);
  the `web-exec` gate requires it. Whether a graceful reload also re-execs the master is a VM-test question.
- **Log access.** Rotation (cilium lumberjack v2.4.2) gives the new file the owner and group of the file it rotates,
  not the directory's, and applies `export-file-perm`. The installer sets `/var/log/tetragon` to `root:edr-agent 2750`
  and runs `chgrp edr-agent`, `chmod 640` on the existing `tetragon.log` while Tetragon runs. Later files follow; old
  backups keep their group and are never read. `check.sh` asserts `edr-agent:640` (§8). The agent gets no
  `CAP_DAC_READ_SEARCH`, which could read `/etc/shadow`, and Tetragon is not stopped to fix the file (that would drop
  enforcement); on EACCES the agent raises HIGH `health.tetragon_unreadable` (§4.5).

#### Policies

| Policy | Hook | Selects | Default mode |
|--------|------|---------|--------------|
| `nginx-exec` | `security_bprm_check` | any exec by an nginx process except the master's exec of itself | monitor, then enforce |
| `sctp-socket` | `security_socket_create` | protocol 132, or `SOCK_SEQPACKET` with protocol 0; host root only logged | monitor, then enforce |
| fork watch | `security_task_alloc` | fork by an nginx process with euid not 0, threads ignored | log only |
| `web-exec` | `security_bprm_check` | **any** exec in the php-fpm or nginx tree except the allowlist | monitor; enforce P2 |
| `web-write-code` | `security_file_open`, `security_path_rename`, `_link`, `_symlink` | `.php .phtml .pht .php5 .phar .user.ini` written, renamed or linked under the web roots and each site's `storage/app/public` (the resolved target of `public/storage`); `*.php` in `/tmp`, `/var/tmp`, `/dev/shm` | log only |
| `web-connect` | `tcp_connect` | php-fpm or nginx to a port outside the list, address not local or VPC | log only |
| `env-read` | `security_file_open` | `.env` opened by anything but php-fpm and php CLI; nginx opening one is HIGH | log only |

- **`web-exec` is inverted.** A name list is evaded by a renamed copy, `env`, `awk`, `php -r`. Selector 1: `matchBinaries
  In` [php-fpm, nginx paths] with `followChildren`, `matchArgs` arg0 Postfix [allowlist], `NoPost`. Selector 2: the same
  binaries, `Post`; enforced, `Sigkill`. Default allowlist: the php-fpm and nginx binaries (a reload re-execs them) and
  `/usr/sbin/sendmail` (confirm which path string the hook gives for symlinks).
- **`web-write-code`** uses exact versioned paths with `followChildren` and `f_mode` Mask 2; not a syscall hook, so
  io_uring is covered. `.htaccess` is dropped (nginx ignores it). Compiled views have no kernel exclusion: the agent
  downgrades a php-fpm write under `storage/framework/views` or `bootstrap/cache` only for `^([0-9a-f]{32}|[0-9a-f]{40})\.php$` (xxh128 on current Laravel,
  sha1 on older) and alerts on any other `.php` there. `edr-inventory` hashes `*.php` under `public/`.
- **`web-connect`** uses `tcp_connect` (`security_socket_connect` cannot match a destination port) with `NotDPort` and
  `NotDAddr` (127.0.0.0/8, ::1, `[sites] vpc_cidr` (§4.1), fe80::/10; never all of 10/8). It does not see UDP, ICMP or IPv4-mapped IPv6 connects.

`nginx-exec` (parse-checked on 7.0 BTF; the host-root test on selector 1 is added to the tested file: re-run lint and
the VM canary). `security_bprm_check` sees x64, 32-bit `int 0x80`, `execveat`, memfd and shebang execs:

    kprobes:
    - call: security_bprm_check
      syscall: false
      args: [{index: 0, type: linux_binprm}]
      selectors:
      # the master re-exec-ing itself (upgrade): host root only, so a worker cannot run "nginx -c evil.conf"
      - matchBinaries: [{operator: In, values: ["/usr/sbin/nginx", "/usr/sbin/nginx (deleted)"]}]
        matchArgs: [{index: 0, operator: Equal, values: ["/usr/sbin/nginx"]}]
        matchNamespaces: [{namespace: User, operator: In, values: ["host_ns"]}]
        matchCapabilities: [{type: Effective, operator: In, values: ["CAP_SYS_ADMIN"]}]
        matchActions: [{action: NoPost}]
      - matchBinaries: [{operator: In, values: ["/usr/sbin/nginx", "/usr/sbin/nginx (deleted)"]}]
        matchActions: [{action: Sigkill}]

A master without `CAP_SYS_ADMIN` fails selector 1 and would be killed on upgrade: those hosts stay in monitor.

`sctp-socket` (tested `sctp-fixed.yaml`; args 0 to 2 are `int`). Host root is logged, everyone else is killed:

    selectors:
    # 1,2: host user namespace AND CAP_SYS_ADMIN, no action = log only
    - matchNamespaces: [{namespace: User, operator: In, values: ["host_ns"]}]
      matchCapabilities: [{type: Effective, operator: In, values: ["CAP_SYS_ADMIN"]}]
      matchArgs: [{index: 2, operator: Equal, values: ["132"]}]
    - (same filters) matchArgs: [{index: 0, Equal, ["2","10"]}, {index: 1, Equal, ["5"]}, {index: 2, Equal, ["0"]}]
    # 3,4: the same two arg forms, no namespace or capability filter: everyone else
    - matchArgs: [{index: 2, operator: Equal, values: ["132"]}]
      matchActions: [{action: Sigkill}]
    - (same SEQPACKET args) matchActions: [{action: Sigkill}]

Verified in kernel 6.8 and 7.0 source: the hook sees the type with `SOCK_NONBLOCK`/`SOCK_CLOEXEC` masked, fires before
the module autoload, and io_uring reaches it. SEQPACKET with protocol 0 is SCTP only if the module is registered, so
where it is blocked (§7) protocol 132 is the form that matters. A root process in a new user namespace is killed too.

**Fork watch.** A payload usually forks first, so `nginx-exec` kills the child and the worker survives; workers never
fork. `real_cred.euid` of the new task (arg 0) is the parent's uid and user namespaces cannot hide it (tested
`fork-euid.yaml`): `args` = `[{index: 0, type: uint32, resolve: "real_cred.euid.val"},
{index: 1, type: ulong}]`; both selectors `matchBinaries In` nginx (both spellings); selector 1 `matchArgs` index 1
Mask 65536 (CLONE_THREAD) with `NoPost`; selector 2 index 0 NotEqual 0 (a non-root nginx process forking is a worker).
Log-only, installed only where pre-flight saw master euid 0; `Sigkill` (P3) is a local switch on that condition. A hit
followed by any web-policy event within 10 minutes is a hub rule rated CRITICAL (hub §4).

#### Reused laptop policies

| Policy | Change |
|--------|--------|
| `privilege-escalation`, `setuid-files`, `kernel-tampering`, `tetragon-tamper` | none |
| `sensitive-files` | keep `/etc/shadow`, `/etc/passwd`, `/etc/group`, sudoers, SSH and cloud keys; drop desktop entries (keeps `check.sh --canary`) |
| `monitor-kernel-modules` | tag `sctp` and unused protocol loads HIGH (our inference, no published IOC: [Xint](https://xint.io/blog/nginx2root-remote-code-execution)) |
| `persistence` | drop autostart; add `authorized_keys`, `/etc/ld.so.preload`, `/var/spool/cron`; writes to `/etc/passwd`, `/etc/group`, `/etc/sudoers.d`; exec of `useradd`, `usermod`, `adduser` (lint: at most 8 prefix/postfix lists). DigitalOcean's droplet-agent rewrites `authorized_keys` for each Console session, so a write by `/opt/digitalocean/bin/droplet-agent` is allowlisted by binary (first selector, `NoPost`; confirm the path with `dpkg -L droplet-agent`); any other writer stays HIGH |
| `suspicious-exec`, `stack-tamper` | add `/tmp`, `/var/tmp` (the agent treats `/memfd:` and `(deleted)` exec paths as signals); point `stack-tamper` at this kit's Suricata, `/etc/edr-agent`, `/usr/local/lib/edr-agent`, `/var/lib/edr-agent/identity`, `edr-*`, nft and dnscrypt paths; add writes and unlinks on `/var/log/auth.log` and `/var/log/nginx` (directory prefix) and an exec of `journalctl --vacuum*` |
| `tcp-listen` | ignore nginx, php-fpm, sshd, mysqld, postgres, redis, agent; allowlist Octane or Reverb per host |

Dropped: `device-access`, the all-process `tcp-connect`. P3 additions: `log-tamper` (truncate, unlink, rename under
`/var/log` except by logrotate, journald, rsyslog, dpkg), `link-sensitive` (links onto `/etc/passwd`, `/etc/shadow`,
`.env` by the web tree) and decoy credential files outside every served tree read-watched by `sensitive-files` (§4.7).
Rejected: `ptrace` (noisy), bulk delete (cache clears), DNS telemetry (§4.4).

#### Enforcement

**Monitor first.** Killing policies install with `spec.options policy-mode: monitor` and count would-be kills in
`NMONITOR` (`tetra tp list`; `tetra tp set-mode` flips it). `[tetragon] enforce` in `local.conf` lists policies allowed
to enforce (default `nginx-exec,sctp-socket`; empty is observe-only, what `install.sh --observe-only` writes). It is
**local only** (§2). The root helper `edr-policy-check` (below) promotes a policy when its gate passes; the install does
not wait for a gate. The heartbeat reports modes and counts. While `edr-agent pause` is in force (§4.7) the helper
holds every enforcing policy in monitor mode, `edr-canary` excepted, and does not re-promote; it reads the `until` of
`/etc/edr-agent/pause.json` itself, so an expired file is ignored. When the pause ends the modes are restored from state.

| Policy | Gate (pre-flight; otherwise it stays in monitor and `check.sh` says why) |
|--------|------|
| `nginx-exec` | master euid 0, not containerised; `systemctl show nginx -p CapabilityBoundingSet` lists `cap_sys_admin` (an unrestricted unit does; an empty or narrower list keeps it in monitor); no lua, perl, rtmp `exec_push`/`exec_static`, passenger or njs in `nginx -V` or `/etc/nginx`; 24 h in monitor with `NMONITOR` 0; canary passes |
| `sctp-socket` | `ss --sctp` empty, no SCTP user installed; the monitor canary raised `NMONITOR` |
| `web-exec` | learning accepted (below); no new tuple for 72 h; the operator has restarted php-fpm after the policy loaded (the gate compares the master's start time with the load time); canary passes |

**What a kill does and does not stop.** `Sigkill` ends the process making the call (the worker or its forked child);
the master starts a new worker and in-flight HTTP/2 streams on it are lost. A `web-exec` false positive is a failed
request. Tetragon's docs say SIGKILL "does not always stop the operation". It does not stop code already in other workers, FastCGI from a compromised worker, or anything that never execs; the hub alert says "restart nginx", which the
hub only tracks as an open operator task. **Override** (returns `EPERM`) is P3 hardening: `Override argError: -1` on
`security_bprm_check` needs the policy option `disable-kprobe-multi` (slower load; read from source, never run), and
syscall Override (`__x64_sys_execve`, `_execveat`, `_socket`) misses 32-bit and io_uring. `sctp-socket` stays
`Sigkill`-only unless the VM test proves otherwise; BPF-LSM Override is 26.04-only and never relied on.

**Canary.** `/usr/libexec/edr/canary` is a copy of `/bin/dash`; policy `edr-canary` (always enforce) matches only it,
with `Sigkill`. A pause does not switch it to monitor (§4.7): it cannot touch the site, and it keeps proving that
enforcement works. `check.sh --live` and the post-upgrade self-test run it as the web user (root holds `CAP_SYS_ADMIN`);
with no web user (`--no-web`) they run it, and the SCTP canaries, as `nobody` (uid and gid 65534):
`setpriv --reuid <web user> --regid <web user> --clear-groups /usr/libexec/edr/canary -c "exec /bin/true"`, and require
death by SIGKILL plus an event. An `unshare -U` then SCTP canary runs once `sctp-socket` enforces. VM tests expect zero kills for a
`kill -USR2` upgrade under a hardened unit, certbot's `nginx -t` and `apt install nginx` (§11).

#### Discovery and drift

No policy hard-codes `www-data` or `/var/www`. `edr-agent discover` (root, run by the installer) writes to `local.conf`:
the nginx binary (`readlink /proc/<master>/exe` minus ` (deleted)`, `command -v nginx`, `nginx -V`; none found fails
pre-flight), each php-fpm binary (exact: `php-fpm8.3` on 24.04, `php-fpm8.5` on 26.04) and php CLI binary, the web
users (nginx `user`, pool `user =`), the web roots (every nginx `root`, following includes) and `[sites] vpc_cidr`
(authority §4.1). Forge runs
php-fpm and deploys as `forge` under `/home/<user>/<site>` with `releases/`; Ploi may differ (verify before release); a
site root includes `releases/` and `current/public`. Policies carry `@NGINX_BIN@`, `@PHPFPM_BIN@`, `@WEB_ROOTS@`;
`--webroot` overrides the roots. Each site directory is the parent of its nginx `public` root, and its
`storage/app/public` is added to `@WEB_ROOTS@`. Drift after an apt run, including an nginx with a deleted exe
(`nginx-exec` degraded until restart), is reported by `edr-inventory` (§4.5.1). `edr-agent discover` then `apply-config`
re-renders the policies, reloads those that changed and prints the php-fpm restart command for affected units.

**Egress defaults** for `web-connect`: 80, 443, 3306, 5432, 6379, 11211, 25, 465, 587, plus 25060, 25061 (DigitalOcean
managed MySQL/Postgres, Redis and Valkey TLS), 2525, 6380. `install.sh --allow-egress-port N` (repeatable) adds to
`[tetragon] egress_ports`. Pre-flight prints the effective list and an `ss -tnp` sample of php-fpm's outbound ports.
The kit does not parse `.env`. Loopback nginx upstreams are excluded by address. First-seen egress is an nft rule (§4.2).

**Normal Laravel behaviour.** Cron `schedule:run`, queue workers, Horizon, Octane, Reverb and deploys run outside the
php-fpm tree, so they do not trip `web-exec` or `web-write-code` (they can trip `tcp-listen`). From a web request:

- `Process`/`proc_open` for ImageMagick, ffmpeg, wkhtmltopdf, jpegoptim, Browsershot, or a deploy webhook running git
  or composer, trips `web-exec`: allowlist the exact path (or deploy outside the request).
- `mail()` runs `sh -c sendmail`, so enforcing needs `/bin/sh` allowed, which weakens it: prefer SMTP (confirm
  whether the sendmail transport uses a shell). Compiled views and Livewire uploads: the agent's name rule (above).

**Learning (P2).** For 7 days `edr-agent learn` records distinct tuples (policy, parent binary, binary, first-argument
basename, web user) for `web-exec`, `web-connect`, `env-read`, counted per day, without arguments. It prints a draft
allowlist in lint format and "new tuples in the last 72 h". Nothing is applied automatically (the week may include an
attacker): the operator reads it and runs `edr-agent learn --accept`, which writes `[tetragon] web_exec_allow`.
`web-exec` enforcement refuses until then. `edr-agent maintenance` is described in §4.7.

**Volume control.** The kernel `rateLimit` key is the hook, thread or process, and the first 40 bytes of each logged
argument, so two long paths sharing 40 bytes are one event; `--export-rate-limit` is one bucket over everything, so
noise can empty it and drop the hit (Sigkill still runs). Hence `--export-rate-limit` stays -1; the killing
policies, `web-exec`, `web-write-code`, `env-read` and the fork watch use no `rateLimit`; `web-connect` uses `10s`,
scope `thread`; reused policies keep `1m` (VM check: targets differ within 40 bytes). The rest is the denylist
(`PROCESS_EXIT`, routine execs tied to a root-owned parent, anchored regexes, `event_set`, lint) and agent
deduplication (§4.5). The agent raises HIGH on any `rate_limit_info` drop on a web host.

**Kernel memory.** The figures and the `--lite` WARN are in §9; measure with `bpftool map show` in the VM, with
`enable-ancestors base` on. Each `rateLimit` policy costs about 9.7 MB, so rate-limited hooks are merged into at most
two server policy files (one kprobe per symbol per policy, so only different symbols merge); the VM measures the saving
and sets the §9 figure. Reused laptop policies keep their own files.

**`edr-policy-check`.** After a kernel upgrade a symbol, `resolve` path or BTF can stop one policy loading while
Tetragon stays up. `edr-policy-check.service` (root oneshot plus timer; at boot after Tetragon, after kernel or package
changes) compares `tetra tracingpolicy list -o json` with the rendered set (state, MODE, counters), checks the gates
above, promotes a policy to enforce when its gate passes (only within `[tetragon] enforce`), holds monitor mode during
a pause, and runs the daily canary (P2). It writes `/run/edr-policy-check/status.json` (`root:edr-agent 0640`) for the
agent, which cannot call `tetra`. From that file the agent raises HIGH `health.enforcement_gone` locally, so the signal
exists with no hub, and INFO `canary.policy_check` for each daily canary (§4.5). The heartbeat carries the `tetragon`
key (policy name, mode, would-be kills) and `kernel` (hub Appendix A). The hub raises HIGH "enforcement gone"
(hub §4) when a policy set to enforce is disabled or missing, or the kernel changed without a passed canary,
5 minutes after boot.

`check.sh` checks `kernel.apparmor_restrict_unprivileged_userns=1` (the Ubuntu default; the kit does not set it). amd64 only.

### 4.4 DNS over HTTPS, without ctrld

**Why dnscrypt-proxy.** resolved's `DNSOverTLS=yes` uses port 853 only and has no stamps (`opportunistic` falls back
to plain DNS); Unbound or knot-resolver are heavier. dnscrypt-proxy is small, with stamps and a query log.

**Package and config.** The distro package on both releases, with **two config templates**: 24.04 ships 2.0.45
(bootstrap key `fallback_resolvers`), 26.04 ships 2.1.14 (`bootstrap_resolvers`), both universe.

- Unknown keys are fatal on both, so each template uses only keys its series accepts, and the installer runs
  `dnscrypt-proxy -check -config /etc/edr-dns/dnscrypt-proxy.toml` before any restart; a failure aborts the DNS step.
  Confirm every key name with `-check` on each series.
- The packaged toml is a conffile and is never edited, so upgrades never prompt. A drop-in sets an empty
  `ExecStart=`, then `ExecStart=/usr/sbin/dnscrypt-proxy -config /etc/edr-dns/dnscrypt-proxy.toml`.
- The unit is **socket-activated**: `dnscrypt-proxy.socket` owns `127.0.2.1:53`. The config keeps
  `listen_addresses = []` (the service user cannot bind port 53) and adds no listeners.
- `cache = true`, `cache_min_ttl = 2400` are set explicitly. `block_undelegated` defaults to true (`.internal`,
  `.lan`, private PTR names get a local NXDOMAIN); set it false only if a VPC zone needs it.
- Universe has no security support without Ubuntu Pro (§12); `edr-inventory` reports a proxy older than the tested one.

**Static stamps.** Two operators (Quad9 and Cloudflare), as `[static.*]` stamps carrying the resolver IP, with no
`[sources]`, `doh_servers = true`, `dnscrypt_servers = false`, `ignore_system_dns = true`, `netprobe_timeout = 0`.
With an IP in the stamp the proxy never resolves a name, and a zero netprobe sends nothing (2.1.14's CLI default
may override it, harmlessly), so **no plain DNS is ever needed**. The stamps are copied from the upstream list at
implementation time and pinned, with certificate hashes stripped (they rot when a provider changes CA).

**DNSSEC is not validated on the box.** `require_dnssec` only filters remote-list servers by a self-declared bit and
ignores static stamps, so it is not set. The two resolvers validate upstream and are trusted to.

**Sandbox.** `files/dnscrypt-proxy.service.d/50-edr.conf`: empty capabilities, `ProtectSystem=strict`,
`SystemCallFilter=@system-service`, `MemoryMax=96M`, `IPAddressDeny=any` with `IPAddressAllow=` for localhost and
each stamp IP (generated), `Restart=always`, `RestartSec=2`, `StartLimitIntervalSec=0`. No `WatchdogSec=`: the proxy
has no sd_notify. Scores 1.2 OK in `systemd-analyze security --offline`; not yet run live.

**System.** `/etc/systemd/resolved.conf.d/zz-edr-doh.conf` starts with empty `DNS=` and `Domains=` (resets
DigitalOcean's `DigitalOcean.conf` list), then `DNS=127.0.2.1`, `Domains=~.`. Drop-ins sort by file name across
directories and digits sort before letters, so a `10-` or `50-` name would sort before DigitalOcean's
`DigitalOcean.conf` and keep its servers; `zz-` sorts after it (tested). The VM test checks the result with
`systemd-analyze cat-config systemd/resolved.conf`. Apply with `systemctl restart
systemd-resolved` (SIGHUP reload needs systemd 256; 24.04 has 255). Pre-flight checks that `/etc/resolv.conf` is the
stub. The per-link resolvers from netplan and cloud-init stay: they are the fail-open path, and a cloud-init
regeneration brings them back. `check.sh` WARNs when the Global scope of `resolvectl status` lists a server other than `127.0.2.1`, or when a link
has `Domains=~.` that sends lookups away from the proxy. Link servers with no routing domain are expected and do not
warn. Confirm in the VM
test that a locked box queries only the proxy and resolved does not stall on a refused link server.

**Names public DoH cannot resolve.** Some DigitalOcean managed services (database, Redis) use private hostnames that
only the VPC resolver (the second-to-last address of the VPC range, `[sites] vpc_cidr`, §4.1) answers; public DoH gives NXDOMAIN. Pre-flight
reads the hosts in the web roots' `.env` (`DB_HOST`, `REDIS_HOST`, `MAIL_HOST`, ...) and those from
`--resolve-check NAME`, resolves each through the link resolvers and through the proxy, and **does not lock** (WARN)
if the answers differ or the proxy gives NXDOMAIN. They are also the watchdog's extra probes. `--vpc-dns auto` adds a
`forwarding_rules = '/etc/edr-dns/forwarding-rules.txt'` to the toml and one `<zone> <vpc-resolver>` line to that
file. The generator also adds `meta skuid "_dnscrypt-proxy" ip daddr <vpc-resolver> th dport 53 accept` before the
reject rule and the same address to `IPAddressAllow=` in the sandbox drop-in. Confirm `forwarding_rules` is accepted by
`dnscrypt-proxy -check` on both series; if not, `--vpc-dns` is refused on that series. The zone list is owner input.
Not tested on a live droplet.

**The lock: `inet edr_dns`.** Native nftables, own table, hook **output only**, priority -150: removable without
touching `inet edr` (§4.2), ahead of UFW and Docker chains, both families in one atomic file. The laptop script is
the behaviour reference and its netns test is ported. Tested sketch (names generated at install):

    table inet edr_dns {
      set stamp4 { type ipv4_addr; flags interval; elements = { 192.0.2.53 } }    # decoded from the stamps
      set doh4   { type ipv4_addr; flags interval; elements = { 203.0.113.8 } }   # the laptop list (doh-resolvers.conf) minus stamps
      set noisy     { typeof meta skuid; flags dynamic,timeout; timeout 10m; size 256; }
      set noisy_doh { typeof meta skuid; flags dynamic,timeout; timeout 10m; size 256; }
      chain out {
        type filter hook output priority -150; policy accept;
        oifname "lo" return
        meta skuid "_dnscrypt-proxy" tcp dport 443 ip daddr @stamp4 accept      # and an ip6 twin
        meta skuid "_dnscrypt-proxy" counter log prefix "edr-dnslock: self " flags skuid reject
        meta l4proto { tcp, udp } th dport { 53, 853, 5353, 5355 } update @noisy \
            { meta skuid limit rate 3/minute burst 2 packets } log prefix "edr-dnslock: " flags skuid
        meta l4proto tcp th dport { 53, 853 } reject with tcp reset
        meta l4proto udp th dport { 53, 853 } reject
        tcp dport 443 ip daddr @doh4 update @noisy_doh { meta skuid limit rate 3/minute burst 2 packets } \
            log prefix "edr-dnslock: doh " flags skuid      # log only; reject added by `[dns] block_doh_ips = on`
      }
    }

- **Exemption by service user, not cgroup.** A cgroup match fails to load when the cgroup does not exist (socket
  activation: not at boot) and goes stale on each restart; the uid survives both. It is resolved by name at load,
  so the unit keeps a fixed `User=`; a missing name means the lock does not load. Confirm the 24.04 user name.
- **Logging has no verdict.** `update @set { ... limit rate ... }` acts as a match, so a reject in the same rule
  would stop applying over the limit. Each log rule stands alone, unconditional rejects follow. Every uid has its
  own bucket (tested: uid 33 and uid 1000 logged 2 each), so one noisy process cannot hide another. A UDP refusal
  shows as `EPERM` on the first send. Confirm the log line format (`UID=33`) on a real host.
- **Severity.** The agent reads `edr-dnslock:` from the kernel journal (the one prefix; `self` and `doh` after it
  are the event's `what`); the exemption is the first rule and everything else from that uid is refused. A refusal
  by a web user (§4.3, Discovery and drift) is HIGH, other non-root uids MEDIUM, unless nginx has an outside `resolver`. `edr-inventory` records nginx `resolver`
  addresses, the installer WARNs and suggests `resolver 127.0.0.53;`, the hub downgrades matching hits. Lookups
  through `127.0.0.53` are allowed and not logged. Precursor names only "unusual lookups from nginx hosts" as a
  lead ([source](https://www.precursorsecurity.com/blog/nginx2root-critical-nginx-rce-vulnerabilities)).
- **Boot.** `edr-dnslock.service` (oneshot, `RemainAfterExit`, `Before=network-pre.target`, `TimeoutStartSec=10`,
  no `Requires=` anywhere) loads the file after `nft -c`; a failed or timed-out load leaves the box unlocked and
  writes state `open` to the status file (below). The installer runs `nft -c -f` after the package install and aborts the DNS
  step on failure, and locks only after the lookup test through the proxy passes. Removal is
  `nft delete table inet edr_dns`.
- **Pause (§4.7)** deletes `inet edr_dns` and leaves the proxy, the resolved drop-in and the per-link resolvers
  alone. While the pause file is valid, `edr-dns-watch` does not re-lock and keeps probing; the state is `paused`, not
  `open`. After a reboot the watch removes the table again on its first run. `resume` or the end of the period
  reloads the lock file, only if it loads.

**Detect-only public-DoH block.** Any HTTPS host can answer DoH, so a list is trivially bypassed and a reject could
break a legitimate fetch from `dns.google`. The `@doh` rules log only; the Suricata SNI rules are `alert` at low
priority, outside the auto-ban trigger. The plain 53/853 refusal is the main control. **The kit cannot block its own
resolvers by construction:** the installer decodes the stamps into `/etc/edr-dns/doh-self.conf`, and the generator
(the laptop kit's `controld/files/dns-lockdown-rules.sh`) removes from its `doh-resolvers.conf` (copied to
`server_client/files/`) every IP in it and every entry that is a suffix of a stamp hostname
(`dns9.quad9.net` matches `quad9.net`). `check.sh` FAILs if the sets intersect and the installer aborts before
locking. The laptop list contains 9.9.9.9, 1.0.0.1 and `quad9.net`, which are the kit's own resolvers, so the stamp-removal
step is required.

**Containers, LXD, WireGuard.** The lock covers the box's own lookups only. Pre-flight detects `docker`,
`containerd`, `lxd`, `podman`, a `wireguard` link, bridges and `ip_forward=1`, prints "their DNS is not locked", and
`check.sh` lists them. `[dns] lock_forwarded = on` adds a forward chain and is not advised there. Giving guests DoH (a
`ListenStream=<bridge IP>:53` socket) is untested. Confirm on a Docker host that lookups survive the lock.

**Fail-open: `edr-dns-watch`** (root oneshot; timer `OnBootSec=90`, `OnUnitActiveSec=15s`, `AccuracySec=1s`: the default 1 min accuracy would blur the 15 s cadence). Each run sends one UDP query
for a random label under `example.com` to `127.0.2.1` (bash `/dev/udp`); a cached name would hide a dead upstream.
NOERROR or NXDOMAIN is healthy; timeout, SERVFAIL or REFUSED is a failure. The site's pre-flight names are probed too.

| Trigger | Action |
|---------|--------|
| 2 failures in a row | Restart `dnscrypt-proxy` |
| 4 failures (about 1 min) | Delete `inet edr_dns`; write `/run/systemd/resolved.conf.d/zzz-edr-failopen.conf` (empty `DNS=`, `Domains=`; sorts after `zz-edr-doh.conf`, cleared by reboot); restart resolved; log `edr-dns-watch: FAILOPEN` at crit |
| 6 good probes, open at least 5 min | Reload the nft file; only if it loads, remove the drop-in, restart resolved, log `RELOCK` |
| 3 re-locks in an hour | Stay open, log `FLAPPING`; fix, then `edr-dns-watch relock` |

While `/etc/edr-agent/pause.json` is valid (§4.7: root-owned, with its own expiry `until`), `edr-dns-watch` deletes
`inet edr_dns`, never re-locks and never logs FLAPPING; it still probes and reports. `resume` or the end of the period
reloads the lock file through the same path as RELOCK, after the same health check.

- **Status file.** `edr-dns-watch` and `edr-dnslock.service` write `/run/edr-dns-watch/status.json`: `state`
  (`locked`, `open`, `paused` or `flapping`), `since`, and the re-lock count. The agent reads it (§4.5) and raises
  the `edr.dnslock` events from it (Appendix B; `what` is `failopen`, `relock` or `flapping`; `failopen` is CRITICAL),
  and the heartbeat reports the key `dns_lock` with the same four values (hub Appendix A). The kernel-log refusals
  (`self`, `doh`) are `edr.dnslock` events too. `check.sh` fails while the state is `open` and warns while it is
  `paused` (§8). Open means the per-link plain-DNS resolvers: the exception listed in principle 1.
- Tested with a fake resolver and mocked `nft` and `systemctl`, including the flap guard and a bad lock file. Chaos
  tests: `kill -9`, `SIGSTOP`; black-hole 443 to the stamp IPs for 10 minutes under a lookup loop; restart
  `dnscrypt-proxy` 20 times and resolve after each. Lookups work again within 90 s (4 failed probes at 15 s, then
  the per-link resolvers); the lock re-arms after 6 good probes and at least 5 minutes open.

**Boot and upgrades.** The service starts on the first query; the 90 s grace avoids a false `FAILOPEN`. A package
upgrade restarts it (a short stall): VM-test `apt install --reinstall dnscrypt-proxy` during a lookup loop. Pre-flight
WARNs on literal upstream hostnames in nginx ("host not found in upstream" if the first answer is slow); the kit
suggests a `Restart=on-failure` drop-in for nginx, never writes one.

**DNS telemetry (P3).** With DoH, Suricata's `dns` events are empty (§4.1.2). The proxy's `[query_log]` (`file = '/var/log/dnscrypt-proxy/query.log'`,
`format = 'tsv'`, `ignored_qtypes = ['DNSKEY','NS']`; group read for `edr-agent`; the top-level
`log_files_max_size = 5` and `log_files_max_backups = 2` set rotation; confirm with `-check` on both series) feeds the agent, which ships **counters, never lines**:
NXDOMAIN/SERVFAIL per minute with a burst alert, first-seen names (state capped at 50k, 200 new per heartbeat, two
labels unless over 60 characters or high-entropy) and top-N. Privacy: no uid, and names may be customer data
(webhook or SSRF hosts); raw lines stay on the box, with a local off switch (§14, §18). Feed domains alert only.

### 4.5 `edr-agent`

One Python file using only the standard library (`agent/edr-agent.py`), like `analyse.py`, so there is nothing to
`pip install`. It is a root-owned copy in `/usr/local/lib/edr-agent/` and runs as `edr-agent`. Until the host is
enrolled it runs in **local mode**: everything below except the transport (§4.7). Choices that change what the agent
forwards (redaction, budgets, optional inputs) are local only, in `local.conf` (§14).

**Subcommands** (root, except `status`): `status [--alerts --since D]`, `pause [--for]`, `resume`,
`maintenance --for`, `collect [--out]`, `isolate --for [--all]` (§4.7); `enroll` (§4.6); `rehome [--rollback]
[--drop-spool]` (§5); `discover` and `apply-config [--check]` (§14); `learn [--accept]` (§4.3); `bans`,
`unban ADDR|--all` (§4.2); `webroot rebaseline` (P3, §4.5.1); `shutdown-notice` (the unit's `ExecStop`, below).

**Inputs**

| Source | Phase | How | Becomes |
|--------|-------|-----|---------|
| Tetragon `/var/log/tetragon/tetragon.log` | P1a | Tail; `json.loads` only | `tetragon.<policy>` events |
| nginx `error.log` | P1a | Tail; whole-line patterns | `nginx.crash`, `nginx.marker.<name>` |
| Journal: sshd and sudo | P1a | `journalctl -f -o json`, by `_COMM` | `ssh.fail`, `ssh.login`, `auth.sudo` |
| `/run/edr-inventory/inventory.json` | P1a | Hourly and after apt (§4.5.1) | `inventory.<check>` |
| `/etc/edr-agent/pause.json` (§4.7) | P1b | Read each minute; `until` is checked, so an expired file is ignored | No new bans while valid; heartbeat `paused_until` |
| Suricata `eve.json` (alert, anomaly, stats) | P1b | Tail; `json.loads` only | `suricata.alert` (alert, anomaly); stats feed the heartbeat (kernel drops, memcap) |
| Suricata `eve-bulk.json` (tls, ssh, quic) | P1b | Tail; `json.loads` only; a missing file is normal (the disk guard may drop it, §9) | SNI, JA4 and HASSH context for alerts and the first-seen egress digest (§4.7) |
| nginx `access.log` | P1b | Tail; counters, plus the ring below | Scanner and tripwire hits; context |
| Kernel log | P1b | `journalctl -k -f`; `--kernel-log journal\|FILE\|FIFO` reads a file or FIFO instead (test seam, §11); lines starting `edr-` only (kernel-written, `SRC=` trusted) | `edr.bigconn`, `edr.dnslock`, `edr.egress`. One DNS prefix, `edr-dnslock: `; the word after it, `self` or `doh`, is the event's `what` (§4.4) |
| `/run/edr-diskguard/status.json` (§9) | P1b | Each minute | `health.diskguard` |
| `/run/edr-bans/counters.json` (§4.2) | P1b | Each minute | Heartbeat only |
| `/run/edr-policy-check/status.json` (§4.3) | P1a | Each minute | Heartbeat policy modes; `health.enforcement_gone` (HIGH) when a policy set to enforce is not loaded, so the signal exists with no hub; a fresh daily canary result becomes `canary.policy_check` (INFO) |
| `/run/edr-dns-watch/status.json` (§4.4) | P1b | Each minute | `edr.dnslock` events on a change of state; heartbeat `dns_lock` |
| dnscrypt-proxy query log (if §4.4 enables it) | P3 | Counters only | NXDOMAIN bursts, first-seen names |
| Laravel log (opt-in) and login-route counters | P4 | Counters only | Counters, never lines |

The helper directories use `RuntimeDirectoryPreserve=yes` (§3). A missing or stale (over 2 h) `inventory.json` means
"unknown", never "clean", and raises `inventory.stale` (MEDIUM).

**nginx error-log markers.** The kit never edits nginx config. `check.sh` reads the effective `error_log` level and
reports which markers are blind at that level
([nginx source](https://raw.githubusercontent.com/nginx/nginx/release-1.31.9/src/http/v2/ngx_http_v2.c),
[connections](https://raw.githubusercontent.com/nginx/nginx/release-1.31.9/src/event/ngx_connection.c)).

| Marker text | nginx level | Default-visible | Kind, client severity |
|-------------|-------------|-----------------|-----------------------|
| `worker process N exited on signal 11` or `6` | alert | yes | `nginx.crash`, MEDIUM |
| `could not cancel … resolving` | alert (vulnerable builds) | yes | `nginx.marker.resolver_cancel`, HIGH |
| `N worker_connections are not enough` | alert | yes | `nginx.marker.conn_exhausted`, MEDIUM |
| `worker_connections are not enough, reusing connections` | warn | no | `nginx.marker.conn_pressure`, LOW |
| `client violated connection flow control: received WINDOW_UPDATE …` | info | no | `nginx.marker.window_update`, LOW |

- `resolver_cancel` appears only on a vulnerable build: an **unpatched** host hit the CVE-2026-123634 path.
  `conn_exhausted` is the visible precondition for CVE-2026-123633.
- glibc heap-abort lines (`free(): …`, `malloc(): …`, `double free detected`, `corrupted size`, `munmap_chunk()`)
  carry no nginx timestamp. The parser holds up to 4 unprefixed lines for 5 s and attaches them to the next
  `exited on signal` line, else drops them. In Censys's lab one appeared just after a successful command
  ([Censys](https://raw.githubusercontent.com/Censys-Research/nginx2root/main/evidence/cve-2026-123007/RCE-CONFIRMED.md)).
- The `info` log is **opt-in** (`nginx_info_log = off`): it copies every client-side INFO event. If enabled
  (`error_log /var/log/nginx/edr.log info;`) it needs a stanza in the kit's logrotate configuration, run by
  `edr-diskguard` every 2 minutes (`size 20M`, `rotate 2`, §9), and the agent tails it as a second error-log source.

**Other inputs**
- **Authentication.** `ssh.fail` and `auth.sudo` are read from P1a (the SSH ban rule is P1b, §4.2); `ssh.login` and
  novelty are P2. sshd `Accepted` lines become `ssh.login {user, src_ip, auth, key_fp}`; `sudo` lines become
  `auth.sudo {user, target, command, tty}` (same format under sudo-rs, Ubuntu 26.04). `seen.json` holds seen
  `(user, key_fp)` and `(user, /24 or /48)`. New key: MEDIUM. First root login, or a password login with
  `sshd_password_auth` off: HIGH. New source for a known user: LOW (admins roam). Sudo: LOW, MEDIUM for a shell or an
  edit of sudoers, ssh or cron files. Novelty stays LOW for the first 14 days. Match `_COMM` `sshd` and `sshd-session`
  (OpenSSH 10.x on 26.04) and expect `PerSourcePenalties` `drop connection` lines.
- **Access-log counters and tripwires.** Per-IP counters (cap 50,000 keys, LRU; IPv6 per /64); no raw line is stored
  or sent except the ring slice below. `tripwires.json` is a shipped, operator-editable list: `/_ignition/execute-solution`,
  `/_ignition/health-check`, `/vendor/phpunit/*/eval-stdin.php`, `/.env`, `/.env.bak`, `/.git/`, `/storage/logs/`,
  `/xmlrpc.php`, `/phpmyadmin`, `/cgi-bin/`, and `/wp-login.php` unless a discovered web root holds `wp-config.php`. A hit answered 404, 403
  or 444 is ban evidence (thresholds in §4.2). A 2xx answer means the site serves the path: HIGH alert, **no ban**.
  `/telescope`, `/horizon` and `/_debugbar` are `ban=false` until the owner confirms they are unused. A victim's
  browser can be made to request a tripwire path, so bans stay short and never-ban applies.
- **Credential stuffing (P4).** Per-IP count of POSTs to the login route (`[agent] login_route`, §14) answered 401, 422
  or by a redirect back, above 10 a minute: a LOW event, never a ban. Rate only; usernames are not counted.
- **Laravel log (P4, `laravel_log = PATH`).** Read through a default ACL (`setfacl -d -m u:edr-agent:r` on
  `storage/logs`). Counts `ERROR` per minute, "The MAC is invalid" and "Too Many Attempts"; lines are never forwarded.
  A path under `/home` needs a drop-in relaxing `ProtectHome` (confirm in the VM test).

**Hostile log content.** Every log field is attacker-influenced unless shown otherwise.
- Journal records are selected by the journal's own fields, which an unprivileged process cannot set: `_COMM`, and
  for sshd also `_UID=0`. A web user running `logger -t sshd "Failed password …"` has `_COMM=logger`. Confirm in the
  VM test, on both releases, that real failed-login lines carry `_UID=0` and that the `logger` forgery is ignored.
- **`src_ip` is never copied from message text** except by the rules below; otherwise it stays empty.

| Source | Rule for attributing a source address |
|--------|----------------------------------------|
| sshd | Whole line anchored. User-bearing messages anchor at the **end** (`… from <IP> port <N> ssh2`; OpenSSH escapes only control characters, so a user name can hold a fake tail); `Unable to negotiate` anchors at the **start**. IP parsed with `ipaddress` |
| nginx `error.log` | Only if the line has exactly one `, client: `, is under 2040 bytes and matches `, client: <IP>, server: ` |
| nginx `access.log` | First field only, and only if the `log_format` starts with `$remote_addr`; whole-line pattern |
| Suricata | JSON `src_ip`; `src_trust=tcp` only for a TCP flow with an `app_proto` (ban rules in §4.2) |
| Tetragon, Laravel, DNS log | None |

- **Why the error-log rule is sound.** nginx does not escape `error.log`. A request can inject a newline and a fake
  `, client: <victim>, server: ` text, but the real trailer is still appended, so a forgery has two occurrences,
  never one; a long path can cut the real trailer at 2048 bytes, which the 2040-byte limit and the `, server: `
  match reject. First-match and last-match regexes both fail.
- Message templates (`exited on signal`, `WINDOW_UPDATE`) match the text **before** `, client:`, anchored to the line
  start. For `exited on signal` the `pid#tid` must be the nginx master's (from `/run/nginx.pid`; confirm it is
  readable); another pid is a forgery: LOW, and not counted toward the 3-crash rule. Crash and marker lines are
  low-fidelity, so **ban decisions prefer `access.log`** (§4.2).
- **`real_ip` or a custom `log_format`.** If `edr-inventory` reports `real_ip` or an `X-Forwarded-For` format,
  `$remote_addr` is a client-chosen header: every web-sourced `src_ip` is `src_trust=claimed` (Appendix B) and web-sourced bans are
  off (§4.2). A format not starting with `$remote_addr` disables access-log attribution and raises `health.log_format` (MEDIUM);
  `check.sh` WARNs too.
- Lines over 8 KiB are cut before parsing. The forged-line corpus and the seeded-mutation test are in §11 (L0).

**Tail and checkpoints**
- Checkpoint per file in `/var/lib/edr-agent/cursors/<source>.json`, by atomic rename: `(dev, inode, offset, SHA-1 of
  the first 256 bytes)`. Journal sources store the last `__CURSOR` from the JSON output.
- **Resume.** Same inode and head hash, size >= offset: continue. Different inode: finish the older file that has the
  stored inode (`eve.json.1`, plain because `delaycompress` stays, §9; a `.gz` only as best effort), then start the new
  file at 0. Same inode and size < offset (copytruncate): start at 0 and count a gap. Keep a rotated file open for
  10 s of EOF, because nginx writes to it until `USR1`. A forward seek from the stored offset is used;
  `analyse.py`'s `ReverseFile` reads backwards and serves only a bounded "last 5 minutes" catch-up.
- Lines are read with a 64 KiB cap (the rest discarded, counted `truncated`), decoded with `errors=replace`; a bad JSON
  line is counted, never fatal.
- **Order.** Spool and fsync first, then advance the checkpoint (at-least-once; the hub dedupes by id). A vacuumed
  journal cursor makes `journalctl` fail: fall back to `--since` the last `ts` minus 1 min.
- **Backlog.** After downtime read at most 64 MB or 24 h, skip the rest and emit one `health.gap`. Backlog never feeds
  ban decisions (events over 15 minutes old do not, §4.2).
- **Blind windows.** At start the agent emits `health.agent_start` with its last-seen `ts`. A `tetragon.log` inode
  change or Tetragon restart emits `health.blind_window`, so the hub shows the gap as unobserved.
- **Log shrink.** If a tailed log has offset > size with the same inode, or its size drops with no rotation, emit HIGH
  `tamper.log_truncated`, reset to 0 and count a gap.

**Reuse from `watch/files/tetragon-notify.py`.** It is a desktop-notification script with a hyphenated name, so the
agent **copies, never imports** it, and the original stays untouched.
- `detail()` is copied unchanged. `describe()` is split: `process_exec` is labelled by event type and called fileless
  only when `binary_properties.file.inode.links == 0` (the laptop copy labels every exec fileless). Other event types
  are handled.
- Its dedup and burst limiter are inline in `main()`, so they are rewritten. The burst limiter applies to
  **notifications only**; the event stream is collapsed only as in Processing step 4, so every distinct event is sent.
- The ignore list is a new server file (php-fpm, cron, apt), not `tetragon-ignore.conf`. Unit tests feed recorded
  Tetragon JSON through `describe()`.

**Processing**
1. **Normalise** to the Appendix B shape (versions, id, sequence, boot id, UTC `ts`).
2. **Sanitise** every forwarded string: replace C0 and C1 controls, DEL, bidi marks and U+2028/9 by `\xNN`; cap
   summary 256, each detail 512, arguments 1024, URL 512 characters; mark `truncated`. A serialised event is at most
   5 KiB (Appendix B): the agent trims `context` first, then `details`.
3. **Redact** before spooling (`redact = on`): values after `-p`, `--password`, `--token`, `--secret`, `--api-key`,
   `-u user:pw`; `scheme://user:pw@`; `Authorization`, `Cookie`, `X-Api-Key` values; `NAME_(PASSWORD|SECRET|TOKEN|KEY)=`
   values; query parameters `token`, `key`, `password`, `secret`, `sig`, `access_token`; never `.env` contents.
   `payload = hex-head` (default) keeps 128 bytes of an alert payload as hex only; `payload = off` drops it;
   `args = drop` removes arguments. Mark `redacted`. The installer never enables Suricata `dump-all-headers` or a
   `custom` cookie or authorization field, and `check.sh` FAILs if set.
4. **Collapse repeats** into one event with `count`, `first_ts`, `last_ts`, never dropping a distinct event. Tetragon
   events key on `(policy, binary, sha1 of argv[0:3], parent binary)`; Suricata and log-derived events key on
   `(sid or kind, src_ip)`, so a second attacker stays visible. LOW and MEDIUM only, window 5 minutes, and they are
   budgeted (below). HIGH repeats of the same `(kind, src_ip, sid or path)` within 5 minutes also collapse; HIGH from
   one source is capped at 200 an hour, and the first excess raises one `health.high_flood` (HIGH). CRITICAL is never
   collapsed, capped or budgeted.
5. **Count** Tetragon `rate_limit_info` lines; any drop on a web host is a HIGH `health.tetragon_ratelimit`.
6. **Fileless exec.** A `process_exec` or policy hit whose binary path starts `/memfd:` or ends ` (deleted)` is HIGH
   (`tetragon.<policy>`, `details.fileless`), except a known package upgrade during an apt run. The label in
   `describe()` still needs `links == 0`.

**Event budget.** Each of six sources has a budget (`event_budget_per_hour`, default 2,000): `tetragon`, `suricata`,
`nginx`, `journal`, `kernel` and `inventory`, so the ceiling is 12,000 events an hour per host. `agent` and `canary`
events are not budgeted. The excess is counted per source in the heartbeat and not sent; HIGH and CRITICAL bypass it.
The hub cap only protects its disk (hub §2). The agent adds
`dropped_low` from each 200 reply to a heartbeat counter shown in `status`.

**Access ring.** The agent keeps the last 5 minutes of access-log requests in memory, at most 20,000 lines
(`access_ring_minutes`, `access_ring_lines`; about 10 to 20 MB, to measure; the window is shorter on a busy site).
An entry is `(ts, ip, method, path, query, status, bytes, user agent cut to 80)`, under 512 bytes. It is never written
to disk. For a HIGH or CRITICAL event with a `src_ip`, the agent attaches up to 20 entries for that address, at most
4 KiB, sanitised and redacted as in step 3 (no cookies or referrers are ever stored). The operator sees the request
that came with the exploit without the access log being shipped. A larger context pack (Tetragon events for the
process tree) is P3 and needs its own bounded endpoint.

**Transport**
- `POST /v1/events`: batches of up to 500 events or 5 s, at most 1 MiB gzipped and 3 MiB before compression (cut at
  whichever comes first), no event over 5 KiB (the client's own cap, Appendix B), over **mutual TLS 1.3** with the hub CA
  pinned and `X-EDR-Proto: 1`. The agent resolves `identity/current` once per connection and opens all files under it.
- **Timers.** Heartbeat and `GET /v1/policy` (ETag): every 60 s with +-10% jitter and their own backoff capped at 60 s.
  Events: backoff with full jitter capped at 5 min. A failed events POST never delays the heartbeat.
- **Replay pacing.** After an outage `hi` goes first, then the rest oldest first, at most one batch a second.
- **Clock.** `ts` is the event's own time in UTC milliseconds (nginx local times use their offset). `batch_id` is kept
  on retry and is for logs only (the hub dedups by event id); a split batch gets new ids. `sent_at` is stamped on
  **every attempt**. The client does not set its clock; the hub computes skew.
- **Hub responses are bounded** (hub Appendix A): body 16 MiB, headers 16 KiB, 30 s in total, streamed parse; a
  policy above the caps in §4.2 is refused, not truncated. In P2 the policy document carries only `peers` (bans and
  feeds are empty): the client applies the peers and the hub addresses to its never-ban list (§4.2).

Hub Appendix A is the authority for every status and code. This table is a summary of the client's action.

| Status | Client action |
|--------|----------------|
| 200 | Accepted (counts of accepted and duplicate). Drop the batch from the spool |
| 304 (policy) | Keep the current policy |
| 400, 413 (events) | Split the batch once; events that still fail go to `spool/rejected/` (5 MB cap, counted); continue |
| 422 `schema_too_old` | Do not split: keep spooling, retry hourly, show in `status`; `check.sh` WARNs |
| 401 (enroll) | Token refused: stop, stay in local mode, tell the operator to make a new token |
| 403 `host_orphan` (policy, renew) | Keep sending events and local bans; retry policy and renew hourly; `check.sh` WARNs "adopt me on the hub" |
| other 403 | Revoked, moved, retired or unknown: stop sending, keep spooling, retry hourly, `check.sh` FAILs with the `code` |
| 409 (enroll) | `host_exists`: stop; tell the operator to make a token `--for HOST` (§4.6) |
| 426 | Client too old (protocol): keep the last policy, keep spooling, retry hourly, show in `status`; `check.sh` WARNs |
| other 400, 413 (heartbeat, policy, renew); 411, 431, 414 | Log it, keep the previous state, retry at the normal interval |
| 429, 503 | Wait `Retry-After` (at most 1 h) and retry the same batch; no header: back off as for 5xx |
| other 5xx, timeout | Exponential backoff with jitter |

A bad certificate fails the TLS handshake or the first read with no status. One such failure is a network error
(backoff); three in a row are treated like any other 403.

**Spool** (`/var/lib/edr-agent/spool/`, **50 MB**, counted in §9)
- Append-only newline-JSON segments of 4 MB in two lanes: `hi` (HIGH and CRITICAL, 15 MB reserved) and `lo` (35 MB).
  Each batch is fsynced, a CRITICAL event at once. A partly acked segment keeps an ack offset; acked segments are
  deleted whole.
- **Eviction** drops whole oldest segments of `lo` first, then `hi`, and writes one `health.spool_dropped {lane, count,
  kinds}` event. Per-lane drop counters go into the heartbeat. Inside `hi`, collapsed repeats go before first
  occurrences. Noise cannot push out evidence held in `hi` beyond the HIGH cap (Processing step 4).
- **Under disk pressure** (§9) the `lo` lane is emptied first and capped at 5 MB; the `hi` lane is never cut below 10 MB.
- **How long it lasts** (estimates; measure in week one): at about 600 bytes an event `lo` holds about 58,000 events
  (about 4 days at 500 an hour, about 5 hours at the budget ceiling of 12,000 an hour); `hi` about 25,000.
- Event ids are `<epoch>:<seq>` with no host part (Appendix B). `seq` is persisted in blocks of 1000, and a new `epoch`
  starts after any start without a clean-shutdown marker, so a crash never reuses an id and a gap is loss only inside
  one epoch. Before enrollment local-mode events live only in `alerts.jsonl` and the journal; the spool is created at
  enrollment. After a rehome or a re-enrollment that returns a different UUID, the agent rewrites `host-id` from the
  reply and sends the queued spool unchanged (§5); the hub takes the host from the certificate.

**Heartbeat** (every 60 s; the hub alerts if it stops). Fields:
- `units`, read without spawning `systemctl`, so the agent's own execs stay out of the Tetragon log it tails
  (confirm in the VM test): the long-running units (`edr-agent`, `tetragon`, `suricata`, `dnscrypt-proxy`, `nginx`)
  by cgroup presence under `/sys/fs/cgroup/system.slice/` (`running` or `absent`); the root helpers that write a
  status file (`edr-bans`, `edr-inventory`, `edr-diskguard`, `edr-dns-watch`, `edr-policy-check`) by the age of that
  file (`fresh` or `stale`). Timers and path units are not reported; `check.sh` covers them (§8);
- Tetragon policy names, modes and would-be-kill counts; the `inet edr` table (`table_present`, set sizes, counters
  from `/run/edr-bans/counters.json`); conntrack count and maximum; `dns_lock` (`state`: `locked`, `open`, `paused` or
  `flapping`, with `since` and the re-lock count, from `/run/edr-dns-watch/status.json`, §4.4); disk, load, memory;
  Suricata kernel drops;
- spool depth, drop counters by lane and source, highest sequence number, `boot_id`
  (`/proc/sys/kernel/random/boot_id`), `uptime_s`, `kernel`;
- `agent_version`, `agent_sha256`, `droplet_id` (§4.6), `sent_at`, `schema`, `local_conf_sha256`, `cert_not_after`,
  `maintenance_until` and `paused_until` (UTC time or null, §4.7), `policy_rev_applied`, `last_apply_error`,
  `ban_counts`, `inventory` (§4.5.1).

Hub Appendix A is the authority for every heartbeat key; the names above are its names. There is no `settings` key:
the hub's settings view shows `local_conf_sha256` and the policy modes.

**Shutdown notice.** On system shutdown the agent's stop hook (`ExecStop`) sends one heartbeat with
`"shutdown": true` (2 s timeout) **only** if `systemctl is-system-running` reports `stopping` or a reboot job is
queued, so a plain restart is not announced. That one `systemctl` exec at stop is accepted. The
unit is `After=network-online.target`, so it stops before the network, and `ExecStop=` with `TimeoutStopSec=5` makes
systemd wait for the notice. The hub reads "notice, then a new `boot_id`
within 10 minutes" as a planned reboot (hub §4). Confirm in the VM test that the notice leaves in time.

**Sandbox** (`edr-agent.service`; 1.2 in `systemd-analyze security` against 3.1 for a plain unit, tested with systemd
259; every directive exists in systemd 255 on 24.04)

    [Unit]
    After=network-online.target
    StartLimitIntervalSec=0
    [Service]
    Type=notify
    NotifyAccess=main
    WatchdogSec=90
    Restart=always
    RestartSec=5
    ExecStop=/usr/bin/python3 -I /usr/local/lib/edr-agent/edr-agent.py shutdown-notice
    TimeoutStopSec=5
    ExecStart=/usr/bin/python3 -I /usr/local/lib/edr-agent/edr-agent.py
    User=edr-agent
    SupplementaryGroups=suricata adm          # eve.json, nginx logs, journal
    CapabilityBoundingSet=
    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    ProtectProc=invisible                     # not ProcSubset=pid: it hides /proc/loadavg
    PrivateTmp=yes
    RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
    MemoryDenyWriteExecute=yes
    SystemCallFilter=@system-service
    SystemCallFilter=~@privileged @resources
    SocketBindDeny=any
    IPAddressDeny=any
    IPAddressAllow=<hub IP>                   # root-written drop-in (install, rehome); none in local mode
    TemporaryFileSystem=/var/log:ro           # hides auth.log and PHP logs
    BindReadOnlyPaths=-/var/log/suricata -/var/log/nginx -/var/log/tetragon -/var/log/journal -/run/log/journal
    StateDirectory=edr-agent                  # identity/, spool/, cursors/
    RuntimeDirectory=edr-agent
    MemoryHigh=96M
    MemoryMax=128M
    CPUQuota=10%
    OOMScoreAdjust=300
    RuntimeDirectoryPreserve=yes
    LogNamespace=edr                          # name fixed in §9

- Also set: `PrivateDevices`, `PrivateIPC`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`,
  `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`,
  `LockPersonality`, `SystemCallArchitectures=native`, `UMask=0077`, `RemoveIPC=yes`, `StateDirectoryMode=0700`,
  `MemorySwapMax=0`, `TasksMax=32`, `LimitNOFILE=512`, `LimitCORE=0`, `Nice=10`, `LogRateLimitBurst=50000`. The agent never runs
  `php -v` (unsafe under `MemoryDenyWriteExecute`); `edr-inventory` reads the php-fpm versions (§4.5.1).
- The agent has no DNS (it uses the hub's IP) and no capabilities. Confirm on 24.04 that `journalctl` still reads through
  the narrowed `/var/log` view (the persistent journal may be absent; `/run/log/journal` is also `adm`-readable).
- **Self-test of the address filter.** `systemd` logs a missing BPF firewall at debug level only and carries on without
  `IPAddressDeny`, so "hub IP only" could be false with no sign. At start the agent sends one UDP datagram to
  `127.0.0.1:9`; it must fail with `EPERM`. If not, HIGH `health.sandbox_ineffective`, shown by `check.sh`. Containers
  need cgroup v2 BPF; the mock is privileged, so test it.
- **Restart and watchdog.** The agent sends `READY=1` and `WATCHDOG=1` to `$NOTIFY_SOCKET` (a small AF_UNIX datagram,
  tested). `WatchdogSec=90` restarts a hung agent; `Restart=always` never gives up; the OOM score makes the kernel
  kill the agent before nginx or php-fpm.

**Access to Tetragon's log** is set up by the installer as described in §4.3 (group `edr-agent`, mode 640, no
capability for the agent). On `EACCES` the agent raises HIGH `health.tetragon_unreadable`.

**Tamper resistance, stated honestly**
- **The web user cannot** stop or signal the agent (another uid), change its code, configuration or units
  (root-owned), or read its state, identity and spool (`0700`). It can flood logs (lanes, budgets, caps), forge log
  lines (the rules above) and crash nginx (a MEDIUM signal).
- **Root can** undo every control here; only the hub notices (heartbeat loss and the signals below; §12, §13).
- **Signals that remain.** Hub heartbeat alerts (hub §4). Tetragon's `stack-tamper` logs writes to the agent's code,
  configuration, units and `/var/lib/edr-agent/identity`, writes and unlinks on `/var/log/auth.log` and the nginx logs,
  and a `journalctl --vacuum` exec (§4.3). The log-shrink check above raises `tamper.log_truncated`.
- **Configuration fingerprint.** The heartbeat carries `local_conf_sha256` and the effective Tetragon policy modes.
  A change to ignore rules or enforcement switches shows on the hub, though the hub cannot read or set them.

#### 4.5.1 `edr-inventory` (root oneshot)

`nginx -v` is not a vulnerability check. Ubuntu backports fixes without changing it (noble stays `1.24.0`), so fixes
are judged from full package versions ([Xint](https://xint.io/blog/nginx2root-remote-code-execution)). **Vulnerability
status is computed on the client from apt**, so it works with no hub and covers every package, not only nginx. The hub's
advisory file (`common/advisories.json`, hub §4) adds exposure context, origins apt cannot judge (nginx.org, PPAs) and
"no fix yet" cases. Checks that need root run in this small unit, which writes a fixed-schema JSON file (the `edr-bans`
split). The agent sends the file's contents as the `inventory` object in the heartbeat (hash-compared, so unchanged
content is not resent more than hourly) and raises `inventory.<check>` events only for findings. A stale or missing
file is sent as `unknown`. Fields are `true`, `false` or `unknown`; a failed or limit-hit check is `unknown`, never
"clean". All P1a unless marked.

| Field | How | Why |
|-------|-----|-----|
| `nginx_pkg`, `nginx_build` | `dpkg-query -W nginx*` with origin (Ubuntu, nginx.org, PPA); `nginx -V` (opens no log) for the v2, v3, mail modules | Fix status; compiled-in bug classes |
| `nginx_exposure`, `udp443` | Parse `/etc/nginx` with `include` (limits below), not `nginx -T` (opens logs for writing); `ss -lun 'sport = :443'` | Each CVE's precondition (Appendix A.1) |
| `nginx_logs`, `real_ip` | `access_log` and `error_log` paths and levels, `log_format`, `escape=`; `set_real_ip_from`, `real_ip_header` | What the agent may parse (§4.5) |
| `deleted_exe` | Any process whose `/proc/<pid>/exe` or mapped `.so` ends `(deleted)`, with its unit; reboot-required. Ignore `memfd:`, `/tmp` and `/dev/shm` mappings (Tetragon's job, §4.3) | Fixed, but old code still runs |
| `security_pending` | `apt-get -s dist-upgrade`: `Inst` lines with a `-security` origin as `{pkg, installed, candidate, since}`; `lists_age_hours`; held and phased counts | Live, needs no table |
| `sctp` | loaded (`/sys/module/sctp`), blocked (`modprobe -n -v sctp` prints `install /bin/false`), built in (`CONFIG_IP_SCTP=y`) | NGINX2Root's root step |
| `kernel_pending` | Running kernel from `/proc/version_signature` (`Ubuntu 7.0.0-43.43-generic 7.0.14`) against the fixed version | Two SCTP bugs (below) |
| `php` | `dpkg-query -W 'php*-fpm'`, each php-fpm master's `/proc/<pid>/exe`, pools from `pool.d` text; never `php -v` (it names the CLI default) | FPM versions |
| `auth_state` (P1b) | uid-0 accounts, `sudoers*`, `authorized_keys`: hashes only | Diffs (§4.7) |
| `listeners` (P2) | `ss -ltnH` ports | Diffs (§4.7) |
| `posture`, `uncovered_*` | Below | Misconfiguration; coverage drift |

- **HTTP/2** is on when any `listen` for the address has the `http2` parameter or `http2 on;` applies; a leftover
  parameter keeps it on whatever `http2 off;` says. A `listen` without `ssl` plus HTTP/2 is cleartext **h2c**, which
  an ALPN check cannot see. Noble's 1.24 has no `http2` directive. Also `quic`/`http3 on`; `mail {}` with `proxy on` and `auth_http`.
- **Resolver bug:** match `resolver` set, a `proxy_pass` with a `$` variable, and `mirror <uri>` or `ssi on`.
  `mirror_request_body off` (the form Xint demonstrated) is not part of the match; it only sets the rating (below).
- **Rating** is the client's (Appendix B): exposed and unfixed is HIGH, except the resolver bug without
  `mirror_request_body off`, which is MEDIUM (Appendix A.1). `deleted_exe` is HIGH only for nginx, php-fpm,
  sshd and public listeners, else digest. apt data is as fresh as its lists: WARN when `lists_age_hours` is over 48.
  nginx is debounced (mechanism: Appendix A.3): after an apt run the hook starts the service, which schedules one
  re-check 15 minutes later (`systemd-run --on-active=15m`); alert when the process is stale on both runs (a report
  about 20 minutes after the upgrade), or when it is over 1 h older than the install (the `keepalive_time` default).
- **Two different SCTP bugs; the module block covers both.** `kernel_pending` compares the running kernel with the
  per-flavour fixed versions in Appendix A.2 (`dpkg --compare-versions`). Xint's send-path bug has no CVE or fix
  known as of 19 Nov 2026.

**Posture** (`posture{}`, hourly; computed and shown by `edr-check` from P1b, forwarded to the hub from P2). Booleans or
enums, never values; `.env` is read as text, never executed; paths come from the nginx `root` parse, null if that fails.
- **HIGH:** `app_debug_true` (Ignition class; `env_mode` alongside). `nginx_php_any` (a `.php` location not limited to
  `index.php`; Laravel's docs use `^/index\.php`) only with `world_writable_in_webroot` or a writable upload path.
  `app_key_in_public` (a file under `public/` holds an `APP_KEY=` line, for example a copied `.env` or a backup; only
  names starting `.env` or ending `.bak`, `.old`, `.orig` or `.txt` are read, as text, 1 MiB at most).
- **MEDIUM (digest):** `env_perm_ok` (not world-readable, not under `public/`); `nginx_dotfile_deny`;
  `nginx_default_server`; `nginx_php_any` otherwise; `php_disable_functions_empty`, `open_basedir_set`, `fpm_limit_extensions` (ini, `conf.d`,
  `pool.d` as text); `sshd_password_auth`, `sshd_root_login` (`sshd -T`; confirm it runs in the sandbox);
  `public_listeners` (3306, 5432, 6379, 11211, 9000 beyond loopback); `unattended_upgrades_on`;
  `world_writable_in_webroot` (`find` in the webroot, 20 s limit, 20 paths).

**Coverage drift (P1b).** Compare every discovered `root`, `fastcgi_pass` socket, pool user, nginx user and running
php-fpm exe with what `edr-agent discover` recorded in `local.conf` when the policies were rendered. Emit
`uncovered_webroots`, `uncovered_fpm_binaries`, `uncovered_pool_users`: `edr-check` WARNs, the hub digests it (MEDIUM).
Fix: `edr-agent discover`, then `apply-config` (§17).

**Web-root integrity (P3, `edr-webroot` inside this unit).** Never git as root: a repo's `.git/config` can run code
(`core.fsmonitor`, tested). Read-only, no repo content executed. (a) `*.php *.phar *.phtml .htaccess .user.ini` under
`public/` other than `index.php`, or in an upload directory: HIGH. (b) With a `current` symlink or `releases/*`, record
sha256 and mtime of every PHP file when the release changes (20 000 files; skip `storage/`, `bootstrap/cache`); a later
change, addition or unlisted file is HIGH "release modified after deploy". (c) Otherwise a first-seen baseline of
`public/` and `bootstrap/app.php`, reset by `sudo edr-agent webroot rebaseline`. Hash only files with a new mtime, at
`nice` and idle I/O; manifest in `/var/lib/edr-inventory/`. Each file is opened `O_NOFOLLOW|O_NONBLOCK`, must be a
regular file with one link and under 8 MiB (larger is recorded as `oversize` and counted HIGH), is hashed in 64 KiB
blocks, and the run stops at a 90 s wall-clock budget, resuming next hour from its cursor. Never `exec` anything from
the tree.

**Running:** hourly, and after apt through `zz-edr-inventory` (sorts after needrestart's, §7), a hook that cannot fail apt:

    DPkg::Post-Invoke { "[ -d /run/systemd/system ] && timeout 10 systemctl start --no-block edr-inventory.service >/dev/null 2>&1 || true"; };

**Parser limits** (includes may reach files a web user can write): depth 8, 500 files, 4 MiB in total; regular files
only; the resolved path stays inside `/etc/nginx` or a discovered include root (else `include_outside`); no symlink to a
target a non-root user can write; a writable regular file is parsed but reported (`include_writable`). A limit hit
makes the dependent fields `unknown`. The same limits apply to every file a non-root user can write or replace
(`.env`, php `.ini`, pool files, webroot entries): open with `O_NOFOLLOW|O_NONBLOCK`, require a regular file with one
link, cap at 1 MiB, read once, and stop the whole run at `TimeoutStartSec`. A failure makes the dependent field
`unknown`. A test places a FIFO, a symlink to `/etc/shadow` and a 1 GiB sparse file at those paths.

**Sandbox** (also `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, `IPAddressDeny=any`, `MemoryDenyWriteExecute`):

    CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE   # other users' files; /proc/<pid>/exe and maps
    RestrictAddressFamilies=AF_UNIX AF_NETLINK                 # ss uses netlink
    ProtectHome=read-only                                      # panel sites under /home
    SystemCallFilter=@system-service
    SystemCallFilter=~@privileged @resources
    RuntimeDirectory=edr-inventory
    RuntimeDirectoryPreserve=yes                               # else removed when the oneshot exits
    StateDirectory=edr-inventory                               # 0700; the P3 web-root manifest
    Nice=19
    IOSchedulingClass=idle
    TimeoutStartSec=120
    MemoryMax=128M

No `ProtectKernelModules=yes` (`modprobe -n -v` reads `/lib/modules`), no `ProtectProc=` and no `hidepid`. Output is
written to `.tmp` and renamed, `root:edr-agent 0640` (confirm `Group=edr-agent` plus `UMask=0027` gives that without
`CAP_CHOWN`).

**Kit Tetragon policies.** The helpers run as root outside the web user's tree, so `web-exec` and `nginx-exec` skip
them. Reads of `.env` and `authorized_keys`, and `sshd -T`, must not trip `env-read`, the canary watches or
`monitor-kernel-modules`: the policies exclude `/usr/local/lib/edr-agent/` by exact path and the helper never opens a
canary. `edr-check --live` confirms nothing fires on the helpers.

### 4.6 Enrollment and identity

**The token.** The hub creates it (`edr-hub token create --name web1`) in the form `id.secret.ca_sha256`. It is
single-use, expires (15 minutes by default, 24 hours at most), is bound to a name, and is stored hashed on the
hub (hub §2, Tokens). A host the hub already knows needs a token made with `--for HOST` (see Host identity).

**Delivery: never on the command line.** `/proc` has no `hidepid`, so any local user, the web user included, can
read another process's arguments, and `sudo` logs them. The installer takes the token from `--token-file PATH`,
from stdin (`--token -`), from `EDR_TOKEN`, or from a prompt without echo. A `--token <value>` argument is refused
with a message that names the safe forms. The hub prints the exact lines, with a file write that keeps the secret
out of shell history:

    sudo bash -c 'umask 077; read -rs T; printf %s "$T" > /root/edr.token'   # paste the token, press Enter
    sudo ./install.sh --hub 203.0.113.5:8443 --token-file /root/edr.token   # from the unpacked, hash-checked tarball (§7)

The installer deletes the file once enrollment succeeds. A spent token in a log is harmless; an unspent one in
cloud-init user data is not, because the metadata service may not authenticate callers (not confirmed in
DigitalOcean's documentation). If a token goes into user data, keep the TTL short and bind it with `--source`.

**Usage.** The installer runs enrollment as its last step, after the confirmation (§7). To enroll later, or to
enroll again, run it by hand:

    sudo edr-agent enroll [--hub IP:PORT] (--token-file PATH | --token -) [--enroll-port N]

`--hub` is required in local mode. On re-enrollment of an enrolled host it defaults to the address stored in
`hub.conf`. The token is delivered as above. Exit codes are in §15: 0 enrolled, 2 failed, 5 not enrolled.

**Install-time sequence.** The network steps (2 to 5) run as the unprivileged `edr-agent` user in a transient
sandbox (`systemd-run --pipe --wait -p User=edr-agent -p IPAddressDeny=any -p IPAddressAllow=<hub IP>`, the IP part
of `--hub`) with the token on stdin. Root only generates the key, writes the drop-in and flips `current`. Confirm in the VM test that
stdin reaches the unit and that nothing else is reachable from it.

1. **Key and CSR.** Root makes a new generation directory `identity/gen-N/` (0700, owned by `edr-agent`) and an
   EC P-256 key (`edr-agent:edr-agent 0600`, so the unprivileged test call in step 5 can read it) with a CSR. The CSR subject means nothing: the hub sets the subject itself.
2. **CA fetch** on the enrollment port (8444, default; `--enroll-port` if the hub prints another): TLS with
   verification off, `GET /v1/ca`, **no token and no client certificate**. Accept exactly one PEM block of at
   most 2 KiB. Convert it with `ssl.PEM_cert_to_DER_cert`, require that **the SHA-256 of that DER equals the
   full 64-hex `ca_sha256`**, check `CA:TRUE` and the P-384 curve, and write it back with
   `ssl.DER_cert_to_PEM_cert(der)`, never the received bytes, so nothing unhashed rides along. (Python 3.12 cannot
   read the server's chain from a handshake, so the CA is fetched explicitly.)
3. **Pinned reconnect** to the same port with `cafile` set to that CA, TLS 1.3 minimum, the hub address checked
   against the certificate's IP SAN, and `VERIFY_X509_STRICT` set explicitly (Python 3.12 does not set it, 3.13+
   does; the same flag on every version keeps 24.04 and 26.04 identical). Nothing is sent before this succeeds.
   Enrollment connections never load a client certificate, old or new.
4. **Enroll:** `POST /v1/enroll {token (id.secret), csr, host_uuid (only if host-id exists and the droplet id is
   unchanged), hostname, os, ips, droplet_id}`. A stale `host-id` after a clone is not sent (see Host identity).
   The reply carries the host UUID the hub minted, the signed client certificate (CN = UUID, 365 days), the CA, the
   hub's address list, the expiry and the host state `pending`. Hostname, `os` and `ips` are labels only. A 409
   (`host_exists`: the hint matches a host the hub already holds, in any state, and the token is a plain one)
   stops the installer with a message to ask for a token made with `--for HOST`. If the reply is lost, repeat the call with the same key and CSR: within
   10 minutes the hub returns the same certificate.
5. **Test call.** `GET /v1/policy` on the fleet port (8443) with the new certificate and key.
6. **Commit (root).** Before writing, root validates the reply: `host_uuid` must round-trip through `uuid.UUID`
   to canonical lower-case form; `hub_addresses` is a list of bare IP literals (hub Appendix A) and the
   port is a separate field of the reply. Each address must be accepted by `ipaddress`, not loopback, link-local
   (169.254.169.254 included), multicast or unspecified; there are at most 4 of them; the port must equal the
   fleet port the installer was given; and the IP part of `--hub` must be among the addresses. Anything else aborts
   the enrollment (exit 5, local mode) and nothing is written. Then write `host-id` from the reply (the spool keeps
   its ids, which carry no host part, Appendix B), write the `IPAddressAllow=` drop-in (every hub address and
   nothing else), then flip `current`: `ln -s gen-N .tmp && mv -T .tmp current` (one `rename(2)`).
   The host becomes `active` on its first accepted heartbeat.

If the hub is unreachable or the token is bad, the installer finishes in **local mode** (the website always
wins), exits with the documented "installed, not enrolled" code (§15), and prints the exact `edr-agent enroll`
line to run later (usage above). After a successful enrollment it prints the `state` from the enrollment reply (`pending`;
`active` after the first accepted heartbeat).

**Where the files land.** `/var/lib/edr-agent/identity/gen-N/{hub.conf,ca.pem,client.pem,client.key}` plus the
`current` symlink, all in the agent's `StateDirectory`, so the sandboxed agent can renew without root. Only the
`IPAddressAllow=` drop-in lives outside. The agent resolves `current` once per connection
(`os.path.realpath`) and opens every file under that path, so a key and certificate from different generations
can never be paired. The tamper watch (`tamper.<what>` events) covers this directory.

**Renewal.** Starts 30 days before expiry, retried daily with jitter.
1. New P-256 key and CSR every time, in a new `gen-N+1`. `POST /v1/renew` over mTLS with the current certificate.
2. The hub signs and keeps both serials valid. A repeat with the same CSR returns the same certificate, so a
   lost reply costs nothing. The hub retires the old serial on the first request made with the new one.
3. The agent flips `current`, keeps the previous generation until a heartbeat is accepted with the new one, then
   deletes it.
4. **Expired certificates** cannot renew: in TLS 1.3 the handshake appears to succeed and the first read fails.
   The agent treats a first-read `SSLError` as an authentication failure, not an outage, backs off, and raises
   a local alert. Recovery is `token create --for HOST` and `edr-agent enroll`. The hub raises LOW (digest) under 30 days,
   MEDIUM under 14 and HIGH under 7 (hub §4). `check.sh` follows §8: WARN at 30, 14 and 7 days, FAIL when expired.

**Host identity.** The hub mints the host UUID, which is also the certificate CN. The client's `host-id` file only
records what the hub sent. The UUID in a request is only a hint, used to answer 409 to a plain token. The file survives `install.sh` re-runs
and uninstall plus reinstall (uninstall keeps it unless `--purge`). When an enrollment or a rehome reply carries a
different UUID, the agent rewrites `host-id` from the reply and sends the queued spool unchanged (event ids have no
host part, Appendix B; the hub takes the host from the certificate). Because the hub refuses to give a
known UUID to a plain token, a **reinstall or re-enrollment of a known host needs a token made with `--for HOST`**.
- **Bound to the droplet.** The installer stores the DigitalOcean droplet id (`/metadata/v1/id` on
  169.254.169.254) beside `host-id`. An `ExecStartPre=+` step of `edr-agent.service` (root, 2 s timeout) reads it
  again at every start into `/run/edr-agent/`, so the sandboxed agent needs no metadata access. The agent sends
  it with enrollment and every heartbeat.
- **A clone** (snapshot or copied image: same `host-id`, key and certificate, new droplet id) stops using the old
  certificate, keeps spooling, logs `host identity changed, re-enrol with a new token`, and raises
  `health.identity` locally. A plain token then mints a new UUID for the clone. The old row stays on the hub
  (HIGH "possible clone"); the operator retires it (`edr-hub host OLD retire`) only if the original droplet is
  gone. The client deletes its stale `host-id`, so the new enrollment sends no UUID hint, and writes the new one from the
  reply.
- **Unreachable metadata fails open:** the old identity stays. A droplet rebuilt or restored in place keeps its
  id and so its identity. The hub alerts when one certificate reports two droplet ids (hub §2).

### 4.7 Local alerts and local response

A host with no hub, or a hub that is down, must still tell its owner something. Everything here runs on the host,
adds no hub-to-client path, and keeps the agent's network sandbox (`IPAddressDeny=any`, §4.5) unchanged.

**Alert path**
- The agent appends every HIGH and CRITICAL event to `/var/lib/edr-agent/alerts.jsonl` (5 MB, 2 files, `fsync` on
  CRITICAL). That is roughly the last 10 000 alerts. The journal (shared, capped, rate-limited) is only a copy. The
  agent unit sets `LogRateLimitBurst=50000`. The file's writer is separate from the event stream (§4.5, which sends
  every distinct event): it collapses repeats of the same alert into one line with a count, caps lines at 60 a minute
  and then writes one "N suppressed" line for the rest of that minute, and never drops the first occurrence of an
  alert. A flood of one alert therefore cannot rotate out older alerts.
- The agent writes `/run/edr-agent/summary.json` (open HIGH and CRITICAL of the last 7 days, hub reachability).
  `edr-agent status` shows it; `edr-agent status --alerts --since 7d` lists the file; `edr-check` prints the last
  24 h and WARNs on any CRITICAL.
- `/etc/update-motd.d/90-edr` prints the top 5 and "hub unreachable for N min" at login, to root and `sudo`/`adm`
  users only. It runs as root on a file the unprivileged agent wrote, and summaries carry attacker text (user agents,
  arguments), so it opens with `O_NOFOLLOW`, caps size, keeps printable ASCII only, and cuts lines at 120 characters.
- Hub unreachable over 15 min: a recurring WARN, and HIGH and CRITICAL kept in the journal at priority `crit`.
- **Optional `edr-notify`** (P1b, off by default until `/etc/edr-agent/notify.url` exists, root 0600; `[notify] min_severity` in
  `local.conf`, default `HIGH`): `edr-notify.path` (`PathModified=` on `alerts.jsonl`, which fires on plain writes;
  `TriggerLimitIntervalSec=` set so a burst does not trip the path unit's limit) starts a oneshot `edr-notify.service` as user `edr-notify`, which
  posts ntfy or a Slack-compatible webhook. The `edr-notify` user is always created at install, so creating
  `notify.url` later needs nothing else. The sender keeps `(inode, offset)` in its `StateDirectory`, handles rotation
  as the agent's cursors do (§4.5), and sends each alert once, and only at or above `min_severity`. The sender cannot
  read `local.conf`, so `apply-config` (§14) renders `min_severity` into a root-owned file that the unit loads as a
  second credential. It has its own copy of the payload templates (hub code is not shared) and
  sends only `kind`, severity, host and a 200-character summary, escaped for the channel, never excerpts.

        User=edr-notify
        LoadCredential=url:/etc/edr-agent/notify.url   # root 0600; alerts.jsonl is passed the same way
        LoadCredential=min_severity:/etc/edr-agent/notify.min_severity   # root 0600, rendered by apply-config
        StateDirectory=edr-notify                      # (inode, offset) of alerts.jsonl
        CapabilityBoundingSet=
        RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
        IPAddressDeny=any
        IPAddressAllow=localhost <webhook addresses>   # resolver stub; addresses from apply-config
        ProtectSystem=strict
        NoNewPrivileges=yes
        MemoryMax=64M

  The agent's identity and spool stay out of reach. Confirm in the VM test how webhook addresses that rotate are
  refreshed, and that a rotation of `alerts.jsonl` is seen through the credential copy.

**Local response.** All of it is run by the operator or triggered by a local event, as root, with no network. The hub
cannot start any of it. Each is journalled and sent as an event (`health.<what>`); the full list of fail-open
mechanisms and kill switches is §16.

| Command | What it does | Phase |
|---------|--------------|-------|
| `sudo edr-agent collect [--out FILE]` | Triage tar, `umask 077`, `O_EXCL` outside the webroot, no symlinks followed, 50 MB cap: 24 h of Tetragon events, nginx log tails, `ss -tanp`, process tree, `deleted_exe` list, crontabs, `authorized_keys` hashes, modules, webroot files from the last 24 h, `dpkg -V` of nginx and php. Raw, so treat it as sensitive (§18) | P2 |
| `sudo edr-agent isolate --for 1h [--all]` | Table `inet edr_isolate`, output hook. Default drops egress by the web users (`meta skuid`); `--all` drops everything except loopback, replies to **inbound** connections (`ct state established,related ct direction reply`), the hub, the DoH stamps and the `allow4` and `allow6` sets, filled from `[isolate] allow` (§14: database and Redis hosts) plus the metadata address 169.254.169.254 and the local resolver. Accepting replies only also cuts an attacker's existing outbound connection. `--for` is mandatory, 24 h at most, removed by `systemd-run --on-active`; a reboot clears it | P3 |
| `sudo edr-agent pause [--for DURATION]` / `resume` | The kill switch (root only; default 1 h, at most 24 h). Effects and mechanism: "How pause works" below. `resume`, or the end of the period, restores everything from state | P1b |
| `sudo edr-agent maintenance --for 30m` | For deploys (2 h at most). Events under the release path keep their severity but carry a `maintenance` tag and go as a digest; scanner-burst bans wait. Never touches `nginx-exec`, `sctp-socket`, never-ban or transport; `web-write-code` outside the release path is unchanged and new `.php` is hashed | P3 |

**How pause works** (the authority for `pause`; §4.2, §4.3, §4.4 and §16 state only their own part and point here).
While paused: no new local bans are written, and hub bans and feeds (P3) are not applied; every enforcing Tetragon
policy except `edr-canary` runs in monitor mode; the DNS lock table `inet edr_dns` is deleted and not re-locked.
Detection, logging and the heartbeat continue. The hub shows the pause and raises a MEDIUM notice.
- **State.** `edr-agent pause` (root) writes `/etc/edr-agent/pause.json` (`root:edr-agent 0640`, one field `until`,
  epoch seconds) and starts a transient timer (`systemd-run --on-active`) for the end. Nothing is written under
  `/run/edr-agent`: that directory belongs to the unprivileged agent. `resume` deletes the file, cancels the timer
  and starts each consumer below, so it acts at once.
- **Every consumer checks `until` itself.** A file whose `until` has passed is ignored even if the timer never
  fired, and a reboot keeps the pause until `until`.

| Consumer | While the file is valid |
|----------|-------------------------|
| `edr-bans` | Applies the explicit empty state: ban and feed sets emptied; the table, the never-ban set and the log-only chains stay (§4.2) |
| `edr-policy-check` | Holds every enforcing policy in monitor mode and does not promote any (§4.3) |
| `edr-dns-watch` and the boot unit | Delete `inet edr_dns`, keep probing and do not re-lock; the resolver set-up is left alone; status `paused` (§4.4) |
| The agent | Writes no new bans; reports `paused_until` in the heartbeat (UTC time or null) |

`edr-canary` is excluded: it matches only the canary binary, so it cannot touch the site, and it keeps proving that
enforcement works. `edr-check` reports a paused host as WARN "paused until T", not FAIL.

**Break-glass** (the CLI is unusable; no agent needed; the other kill switches are in §16). Stop every timer and path
unit that rebuilds or re-locks first, then delete the tables:

    systemctl stop edr-bans.path edr-bans.timer edr-dns-watch.timer
    nft delete table inet edr; nft delete table inet edr_dns

§4.2, §6, §16 and §17 point here. `edr-agent unban --all` clears local bans without removing the table (§4.2).

**Opt-in automatic nginx restart** (P3, `response.auto_restart_nginx=false`). After an `nginx-exec` event the agent
writes `/run/edr-agent/restart.flag` (its RuntimeDirectory); `edr-restart.path` (`PathExists=`) starts the oneshot
`edr-restart.service`, which runs `nginx -t && systemctl restart nginx`, deletes the flag and reports
`health.nginx_auto_restart`. The flag is agent-writable, so the root unit ignores its content and keeps its own
counter in root-owned `/var/lib/edr-restart/`; it allows one restart per 15 min and 4 per day, so an attacker cannot make a restart loop; the website wins. A restart
gives fresh workers; it does not fix the bug or remove persistence. There is no automatic isolate.

**Cheap extra detections** (all local, none needs a new root path):

| Signal | How | Kind, rating | Phase |
|--------|-----|--------------|-------|
| Tripwire paths | Access-log counters on the paths in the shipped `tripwires.json` (§4.5); a 404, 403 or 444 counts towards the §4.2 threshold and ban rules; a 200 means the site serves it: HIGH, no ban | `canary.tripwire` | P1b |
| Decoy credential files (canary files) | Fake `id_rsa` and cloud credentials in `/root` and home directories, never in a served tree, with obviously fake content (no valid cloud key format); the Tetragon read-watch (§4.3, P3) has a per-site allowlist of backup and indexer binaries (`updatedb`, `rsync`, the site's backup tool), else every nightly run is a HIGH | `canary.file`, HIGH | P3 |
| Auth state diff | `auth_state` (§4.5.1): new uid-0 account, `sudoers`, `authorized_keys` | `inventory.auth_state`, HIGH for uid 0 | P1b |
| Log truncation | Agent check on every log it tails, defined in §4.5; writes to auth.log and nginx logs are covered by Tetragon (§4.3) | `tamper.log_truncated`, HIGH | P1b |
| New listener, first-seen egress | `listeners` snapshot; first-seen destination or SNI per web user (digest) | `inventory.listeners`, `edr.egress` | P2 |
| Metadata and Redis probes | nft counter by `skuid` to `169.254.169.254`; Suricata rule for inbound 6379 and 9000 on the public interface | `edr.egress`, `suricata.alert` | P2 |
| SSH login novelty | First-seen source per account (digest only: admins roam) | `ssh.login` | P2 |
| `.env` read under a config cache | php-fpm reading `.env` when `bootstrap/cache/config.php` exists | `tetragon.env-read`, MEDIUM | P3 |

An `APP_KEY` left in `public/` is the posture boolean `app_key_in_public` (§4.5.1). What these signals still miss is
listed in §12.

---

## 5. Moving to a new hub (`rehome`)

A new hub IP or port, or a new box, means each client moves with a new token from the new hub. If the new hub
sits behind the same Reserved IP and was restored with the same CA (hub §7), clients need nothing. Rehome is for
a changed address, another region or a hub with a new CA.

    sudo edr-agent rehome --hub 198.51.100.7:8443 --token-file /root/edr.token
    # install.sh on an enrolled host with a different --hub refuses (exit 3) and prints this command

The token is delivered as in §4.6 and is never on the command line. **Which token:** as in §4.6 (Host identity):
`--for HOST` keeps the UUID on a restored hub; a fresh hub mints a new UUID and history starts over.

**Sequence.** Nothing the agent uses changes until the new hub is proven. The network steps run as `edr-agent`
in the transient sandbox of §4.6, allowed to reach the new hub only.

1. **Stage.** Root creates `identity/gen-N+1/` and a new key and CSR in it.
2. **Prove.** CA fetch on the enrollment port with the hash check on one DER certificate, pinned reconnect,
   `POST /v1/enroll`, then a test `GET /v1/policy` with the new certificate (all as in §4.6), and root validates
   the reply as in §4.6 step 6 (UUID form, address list, port, the IP part of `--hub` among the addresses). The
   old hub is untouched. A failure here deletes `gen-N+1`, the agent carries on, and `rehome` exits with the
   reason: 3 for a refusal before anything changed (pre-flight or validation), 2 for any other failure.
3. **Arm a timed rollback.** A transient timer runs `edr-agent rehome --rollback` after 10 minutes unless
   disarmed, so a dropped SSH session cannot leave the box half moved.
4. **Allow both hubs.** Root writes the `IPAddressAllow=` drop-in with the **old and the new** hub addresses (the
   new ones are the validated reply addresses only),
   keeps a copy of the old drop-in, and runs `daemon-reload`. The never-ban set takes its hub addresses from the
   `hub.conf` of every generation present, so the new hub is protected from the moment it appears and the old
   one stays protected until step 7.
5. **Flip** `current` to `gen-N+1` (`ln -s gen-N+1 .tmp && mv -T .tmp current`) and restart `edr-agent`.
6. **Confirm.** Wait for a heartbeat the new hub accepts and for the first successful policy poll
   (`rehome_confirm_timeout`, default 300 s). Then disarm the timer. A rollback after the timer was armed (steps 3
   to 6) ends with exit 4 (§15).
7. **Commit.** Write `host-id` from the new reply if it differs. Send the old hub a best-effort `POST /v1/deregister {reason: rehome}` with the old certificate
   (5 s timeout), then remove the old addresses from the drop-in and the never-ban set, run `daemon-reload`, and
   delete the previous generation, key included.

**Rollback after every step.**

| Failed at | Rollback |
|-----------|----------|
| 1 to 2 | Delete `gen-N+1`. Nothing else changed. A host row the new hub already made stays `pending`; retire it there |
| 3 to 4 | Restore the saved drop-in, `daemon-reload`, delete `gen-N+1` |
| 5 | Point `current` back at the previous generation, restore the drop-in, `daemon-reload`, restart `edr-agent` |
| 6 (timeout or timer) | Same as step 5, then report which check failed. Steps 5 and 6 can be repeated safely |
| 7 | The move stands. The next start of `edr-agent` repeats the cleanup |

**Behaviour around the move:**
- **The spool** is kept, with its ids (`<epoch>:<seq>`, no host part, Appendix B). If the new reply carries a
  different UUID, the agent rewrites `host-id` from it (step 7) and sends the queued events unchanged; the hub takes
  the host from the new certificate. Events queued before the move go to the new hub, which the operator chose
  with a token; `--drop-spool` discards them instead. Replay stays under the hub's per-source
  meter (one batch per second, §4.5).
- **Bans.** Local bans always remain. From P3, hub-sourced bans and feeds keep their remaining TTL until the
  first successful poll from the new hub, then are replaced; a feed the new document omits is removed (§4.2). In P2
  the policy document carries peers only. A new, empty hub therefore never wipes a local ban.
- **The old hub,** if reachable, marks the host `moved` and revokes that certificate (hub §2, Host states).
  Otherwise its heartbeats just stop; the operator runs `edr-hub host HOST mark-moved` or `retire` there.
- **History.** With a restored hub and a `--for HOST` token the UUID is the same, so history continues. A brand-new
  hub starts fresh. An expired certificate is not a rehome problem: enrollment never presents the old one.
- **Tests** (server VM test): rehome to an empty hub leaves a local ban in place; a kill at each step leaves a
  working agent after the rollback.

---

## 6. Uninstall

    sudo /usr/local/sbin/edr-uninstall            # asks first; shows what the manifest will remove
    sudo edr-uninstall --yes --keep-logs
    sudo edr-uninstall --purge                    # also forget this host's identity (host-id)
    # partial: --keep-suricata, --keep-tetragon, --keep-dns, --keep-sctp-block, --keep-config

Uninstall is **driven by the install manifest** (§7): it removes what the kit wrote, restores each prior value the
manifest recorded, and purges **only packages the kit installed** (never `python3`, `openssl`, or a package that was
already there; no `autoremove`). The directory holding the first copy of the manifest
(`/var/lib/edr-agent/manifest.json`, `root:root 0600`) is owned by the agent, which can replace the file, so uninstall
treats any manifest as untrusted input and keeps three limits in the script itself:
- **Paths:** only the kit's own prefixes (`/usr/local/lib/edr-agent`, `/etc/edr-*`, `/var/lib/edr-*`, unit and drop-in
  names starting `edr-`, the named drop-ins below); any other entry is refused.
- **Packages:** purged only if the name is in the script's built-in list (`suricata`, `suricata-update`,
  `dnscrypt-proxy`, and Tetragon's deb if used) **and** the manifest marks it as the kit's.
- **Prior values:** restored only for a built-in key list (`nf_conntrack_max`, `nf_conntrack_acct`, the resolved
  drop-in state), each checked as an integer or enum.

It prefers the root-only copy (`/var/lib/edr-install/manifest.json`, `root:root 0600`, §7) and warns if the two
differ. Without a manifest it removes by name and says so.

**It runs from a copy.** The script lives in the tree it deletes, so `edr-uninstall` first copies itself and the
manifest to a root-only directory under `/run` and runs from there; the directory goes at exit.

**The order is chosen so the network never breaks:**
1. **Stop everything that rebuilds or re-locks:** `edr-install-rollback` if armed, the transient timer that ends a
   `pause`, `edr-bans.{path,timer}`, `edr-dns-watch.timer`, `edr-policy-check.timer`, `edr-home-net.timer`. Remove
   `inet edr_isolate` if present.
2. **Delete the `inet edr` table,** which lifts all bans, feeds and the bigconn and egress rules at once.
3. **Restore DNS:**
   - delete `inet edr_dns`; remove `edr-dnslock.service`;
   - remove `zz-edr-doh.conf` and any `/run/systemd/resolved.conf.d/zzz-edr-failopen.conf`, restart resolved;
   - **check that a lookup works** through `/etc/resolv.conf` and the link resolvers;
   - then stop and purge dnscrypt-proxy (if the kit installed it), its sandbox drop-in and `/etc/edr-dns/`.
4. `POST /v1/deregister {reason: uninstall}` to the hub (best effort, 5 s timeout). The hub keeps the host and its
   history; `host-id` stays so a reinstall with a `--for HOST` token continues it (§4.6).
5. Stop and remove `edr-agent`, `edr-notify` (with `edr-notify.path`), `edr-bans`, `edr-inventory`, `edr-diskguard`
   (with the kit's `/etc/edr-agent/logrotate.conf` and its state file), `edr-policy-check`, `edr-dns-watch`,
   `edr-home-net` and the auto-restart path unit, with their timers and the boot unit of the DNS lock; the `zz-edr-inventory` apt hook,
   `/etc/needrestart/conf.d/50-edr.conf`, `/etc/update-motd.d/90-edr`, `/etc/systemd/journald@edr.conf` and the `edr`
   journal namespace (its data too, unless `--keep-logs`). The main journald is not touched.
6. **Kernel settings:** remove the conntrack sysctl drop-in and, **only if the kit changed them**, write the recorded
   prior values back live (`nf_conntrack_max`, `nf_conntrack_acct`; the live value would otherwise stay until reboot).
   Remove `/etc/modprobe.d/edr-sctp-block.conf` unless `--keep-sctp-block`, and say that removing it re-opens both
   SCTP bugs behind NGINX2Root (Appendix A.2 has what is patched).
7. **Tetragon:** `tetragon/local_uninstall.sh` (`--purge` unless `--keep-logs`), then the `edr-canary` policy and
   `/usr/libexec/edr/`. Enforcement ends here, after DNS and bans are restored.
8. **Suricata:** stop, purge if the kit installed it, remove its rules, cache, `home-net.extra`, the update units and
   `files/suricata.apt-pin`. Remove the OISF PPA **only if this kit added it**. A package the operator had stays.
9. Remove `/usr/local/lib/edr-agent` and `/usr/local/lib/edr-agent.prev`, the `/usr/local/sbin` links, `/etc/edr-agent`
   (`local.conf` kept with `--keep-config`), `/var/lib/edr-agent` **except `host-id`** (removed with `--purge`),
   `/var/lib/edr-bans`, `-inventory`, `-restart`, `-diskguard`, `-notify`, `/var/lib/edr-install`, every `/run/edr-*`
   directory (`/etc/edr-agent` takes `pause.json` with it), and last the users `edr-agent` and `edr-notify`
   (`/var/log/tetragon` is group `edr-agent` until step 7 has run).
10. **Final check:** no `edr`, `edr_dns` or `edr_isolate` table; no `edr-*` unit or kit drop-in left; DNS resolves; sshd
    still listens; nginx answers on `127.0.0.1` when present; prior sysctl values restored. Partial flags relax
    it (below). Report PASS or FAIL (exit codes: §15).

**Partial flags.** Each skips the steps shown, and the final check relaxes only the items shown. The kept parts stay
as they are, and a later full `edr-uninstall` finishes the job, so any partial run keeps `/var/lib/edr-install`.

| Flag | Steps skipped | Final check relaxes |
|------|---------------|---------------------|
| `--keep-dns` | 3 whole, and `edr-dns-watch` with its timer and boot unit in steps 1 and 5; `/etc/edr-dns/` and `local.conf` stay for the watchdog | `inet edr_dns`, `edr-dns-watch` and the proxy may remain; DNS must still resolve |
| `--keep-tetragon` | 7; the policies, `/usr/libexec/edr/` and the user `edr-agent` (the log group) stay in step 9; enforcement stays on with nothing to promote or hold it | Tetragon, its policies and the user `edr-agent` may remain |
| `--keep-suricata` | 8; the kit's log rotation goes in step 5, so Suricata's own packaged rotation applies | Suricata, its rules and `home-net.extra` may remain |
| `--keep-sctp-block` | the `modprobe.d` file in step 6 | that file may remain |
| `--keep-config` | `local.conf` in step 9 | `/etc/edr-agent/local.conf` may remain |

A partial run ends with the same PASS or FAIL as a full one, over the relaxed list; each relaxed item is printed as
"kept by --keep-...". `--keep-logs` and `--purge` are in the commands above.

**Break-glass, no agent needed:** the commands are in §4.7, next to `pause`. The other kill switches are in §16.
`edr-agent unban --all` clears local bans without removing the table (§4.2). A partial uninstall that stops at
any step leaves the earlier steps done and is safe to re-run.

---

## 7. Installer

**Delivery.** Nothing runs from a checkout on a droplet. `make dist` builds one tarball with only what a server needs
(reused laptop files included), a `MANIFEST.sha256` of every file, a `VERSION` file and a tarball `.sha256`. The
operator copies it with `scp`, checks the hash against the one printed on the build machine (never one that travelled
with the tarball) and runs `install.sh`. The installer verifies the tree against `MANIFEST.sha256` (catches damage, not
a forged tarball), then copies it to
`/usr/local/lib/edr-agent/` (`root:root`, `0755`, no group or other write) and links `/usr/local/sbin/edr-agent`,
`edr-uninstall` and `edr-check`. `edr-check` is the installed `check.sh` and `edr-uninstall` the installed
`uninstall.sh`: this plan uses the script names, and the runbooks (§17) use the installed ones. The copy holds the agent, helpers, policies, `files/`, `uninstall.sh`, `check.sh`,
`defaults.conf` and the installer, so uninstall and `rehome` never need the checkout. `VERSION` and the agent's
SHA-256 go in the manifest and the heartbeat; the hub holds the known hashes (hub §17).

The install command is always run from the unpacked, hash-checked tarball, for example
`sudo ./install.sh --hub 203.0.113.5:8443 --token-file /root/edr.token` (the hub prints the same form).

    sudo ./install.sh --plan  [flags]                   # read-only: pre-flight and everything that would change
    sudo ./install.sh [--hub IP:PORT --token-file PATH | --token - ]  [--yes]
        [--admin-ip CIDR ...] [--lite] [--no-dns-lockdown] [--no-sctp-block] [--bigconn-cap SIZE]
        [--webroot PATH ...] [--allow-egress-port N ...] [--enforce | --observe-only] [--enroll-port N]
        [--home-net CIDR ...] [--resolve-check NAME ...] [--vpc-dns auto] [--swapfile SIZE] [--no-web]
        [--no-tetragon] [--no-suricata] [--no-kernel] [--force]
    sudo /usr/local/lib/edr-agent/install.sh --confirm | --rollback | --plan    # session control (below)

- **`--plan` is the documented first command on production.** It runs pre-flight, then prints every file, unit,
  package, sysctl value, nftables table and `local.conf` key the install would write, marked "new" or "already
  there", and exits 0 (would proceed) or 3 (refused). Without `--yes` the real run prints the same list and asks. It adds nothing to
  `local.conf`: on an upgrade it lists the keys that `defaults.conf` gains (§15).
- **Flags only seed `local.conf` on first install** (§14); a re-run never resets a choice. `--enforce` adds `web-exec`
  to `[tetragon] enforce` (still gated, §4.3), `--observe-only` empties it; both together is a usage error.
  `--webroot` overrides the discovered roots. `--home-net` seeds `[suricata] home_net`, which only overrides HOME_NET;
  the VPC range is `[sites] vpc_cidr`, which `edr-agent discover` fills from the VPC interface's connected route and
  the installer asks for when there is none (§4.1). `--bigconn-cap SIZE` seeds `[bans] bigconn_cap` (default off);
  the watch threshold `bigconn_bytes` is set only in `local.conf` (§4.2). `--no-web` is for a host with no nginx (the
  hub's own droplet): nginx policies, web checks and web-sourced bans are off, and the canaries run as `nobody` (§4.3). `--no-kernel` skips sysctl, `modprobe` and conntrack,
  and is for the mock; `--no-tetragon`, `--no-suricata` likewise. Each `--no-*` writes `off` to its `[kit]` key (§14),
  so a re-run and `check.sh` know the host was installed without that part. `--force` allows installing an older
  `VERSION` over a newer one (§15). `--swapfile SIZE` is opt-in; no swap is created
  otherwise. The token never goes on the command line (§4.6); it is read before the hand-off below and deleted after use.
- A flag given on a re-run for a key already set is ignored and said so ("kept enforce = ...; edit `local.conf`,
  then `edr-agent apply-config`").
- **Phases.** The steps and the §8 blocks carry the phase that ships them (§10). An install built from an earlier phase
  skips the later steps, as if `--no-suricata`, `--no-dns-lockdown` and no `--hub` were given, and `check.sh` skips
  their blocks. P1a installs Tetragon, the kernel block, the agent in local mode and the disk guard for Tetragon
  paths; Suricata, nftables bans and the DNS lock are P1b; enrollment is P2.

**Pre-flight** (nothing changes until it finishes). Each line has one action: **refuse** (exit 3), **WARN**, or
**note** (recorded in the manifest and shown by `--plan`).

| Check | Action |
|-------|--------|
| Ubuntu 24.04 or 26.04, systemd, **amd64**, `/sys/kernel/btf/vmlinux`, root | refuse; no BTF means `--no-tetragon` or refuse |
| `systemd-detect-virt --container` not `none` | refuse unless `--no-kernel`; then WARN |
| Total RAM below §9 minimum (2 GB; 1 GB with `--lite` or `--no-suricata`, unsupported until measured); free disk below the §9 total plus 25% (and 5 GB) | refuse |
| `MemAvailable` below the §9 budget plus 25%; swap size | WARN; swap 0 offers `--swapfile` |
| Another Suricata or Tetragon not installed by this kit, or a dnscrypt-proxy someone else configured | refuse |
| fail2ban or CrowdSec; `nftables.service` with a ruleset that flushes; UFW active | WARN; note whether conntrack was already loaded (§4.2) |
| Docker, LXD, podman, WireGuard, bridges, `ip_forward=1` | WARN "their DNS is not locked" (§4.4); bans still cover forwarded traffic |
| Panel layout (Forge or Ploi style, other panels that manage nginx or the firewall) | WARN; discovery handles `/home/<user>` sites |
| No nginx found | refuse unless `--no-web`; else the master path, `user`, roots, pool users, php-fpm binaries are discovered (§4.3) |
| nginx master not root, in a container, bounding set without `cap_sys_admin`, or lua, perl, rtmp exec, passenger, njs | note; `nginx-exec` stays in monitor |
| nginx exposure report (the Appendix A.4 rows): package against the advisory, stale running binary, h2c, HTTP/3, resolver | WARN only; the kit never edits nginx |
| `.env` and nginx upstream hostnames; DNS answers differing between link resolvers and the proxy (§4.4) | WARN and **do not lock** |
| Unattended-upgrades or cloud-init holding the dpkg lock | wait (below) |
| Admin account has no local password; Droplet Console needs port 22 open beyond admin addresses (§4.2) | WARN |
| Hub unreachable (P2) | WARN; the install continues and step 11 ends in local mode (exit 5) |
| No token pending (enroll port 8444 closed; P2) | WARN; local mode |
| Hub reachable but the CA SHA-256 it serves differs from the token's (P2) | refuse (wrong hub or token) |
| Host clock more than 60 s from the hub's `Date` (P2) | WARN |
| Rule sources and the PPA reachable (§4.1, P1b) | WARN only |
| Token: format only (P2). An open 8444 proves some token is pending, not that this one is valid; step 11 proves that | note |

**Safe apply over SSH.** A dropped session must not leave the box half changed.
1. **Admin address.** Before anything changes the installer reads the `SSH_CONNECTION` source (else the peer of the
   sshd ancestor from `ss`). It is added to `[bans] admin_ip` and the never-ban list (§4.2). If neither works and no
   `--admin-ip` was given, an SSH install refuses.
2. **Survive the session.** The installer re-executes itself as the transient unit `systemd-run --unit=edr-install
   --collect --wait` (or inside `tmux`), so a dropped SSH session cannot kill it; prompts and the token are read
   first. Output goes to the journal (`journalctl -fu edr-install`). The unit runs every step below, including the
   wait for confirmation and the enrollment, and `--wait` hands its exit code back to the shell. Confirm in the VM
   test that killing the SSH session leaves it running.
3. **Timed rollback and confirmation.** Steps 4 to 9 are the risky ones. Before the first of them that runs, the unit
   arms `systemd-run --on-active=600 --unit=edr-install-rollback /usr/local/lib/edr-agent/install.sh --rollback`.
   Each of those steps re-arms the timer for 600 s as it starts, and it is armed for 600 s again after the last one,
   so a slow step never eats the time left for confirmation. Step 10 runs `check.sh`; with no FAIL
   the unit then waits for `install.sh --confirm` from a **new** SSH session (which re-runs the check and releases
   the wait). Under `--yes` the unit confirms itself once the automated checks pass; they include reaching sshd
   from the recorded admin address. Only then does it disarm the timer and run step 11, enrollment, as the last
   step. A failed enrollment cannot roll the install back: the host is already proven good, so it ends in local
   mode (exit 5). If nobody confirms within the 600 s, the timer fires, the session is rolled back (below) and
   the exit code is 4. An upgrade (§15) uses the same timer and the same confirmation.
4. **The manifest** (`/var/lib/edr-agent/manifest.json`, `root:root 0600`, written atomically before and after each
   step): the kit version and components; every file written (path, SHA-256, prior content or "absent"); every sysctl,
   resolved and unit state prior value; `nf_conntrack` loaded before or not; each package and the PPA as "installed
   by the kit" or "was already there"; whether a `policy-rc.d` was ours. It keeps one delta for each install or
   upgrade session. `install.sh --rollback` undoes the last session from its delta (for an upgrade, the swap back to
   `edr-agent.prev`, §15); the timer runs the same command. A second copy is written to
   `/var/lib/edr-install/manifest.json` (`root:root 0600`, outside the agent's state directory); uninstall prefers it
   (§6). Uninstall and `check.sh --audit` replay it. **Not rolled back**, and said so: `modprobe -r sctp`,
   packages the operator had, anything a package's own scripts did.

**Steps.** In order; each is re-runnable and names its rollback. A failure stops the run, undoes that step and exits 2; a run nobody confirms is rolled back and exits 4 (above).

| # | Phase | Step | Rollback |
|---|-------|------|----------|
| 1 | P1a | **Pre-flight** (above); `--plan` stops here | none needed |
| 2 | P1a | **Stage.** Copy the tree, create the users `edr-agent` and `edr-notify`, start the manifest, seed `local.conf` (a commented reference of every key, plus flag and `edr-agent discover` values), previous version to `edr-agent.prev` | remove from manifest |
| 3 | P1a; P1b packages | **Packages.** `python3`, `openssl` (P1a); OISF PPA and pin, `suricata`, `nftables`, `dnscrypt-proxy` (P1b); `apt-get -o DPkg::Lock::Timeout=300`; `apt-get update` in a bounded loop (10 x 30 s), since that lock is not covered; a `policy-rc.d` written only if none exists, answering 101 for `suricata` and `dnscrypt-proxy` (it checks `$1`) and 0 for everything else, removed by a trap on every exit and by `--rollback`; `check.sh` WARNs if it is left behind (§8) | purge packages marked "by the kit" |
| 4 | P1b | **Suricata** (§4.1): candidate yaml, `suricata-update`, `suricata -T` under `systemd-run -p MemoryMax=900M` and the memory guard, unit drop-in with the limits, `edr-home-net`; then start, already tuned | discard candidate; remove drop-in |
| 5 | P1b | **nftables** (§4.2): conntrack sizing, `inet edr`, `edr-bans` units | delete table; restore sysctl |
| 6 | P1a | **Kernel** (NGINX2Root): `edr-sctp-block.conf`; `modprobe -r sctp` only if loaded with no users; WARN if `CONFIG_IP_SCTP=y` | remove file |
| 7 | P1a | **Tetragon** (§4.3): `local_install.sh` with the change table there, `--no-viewer`, no boot gate; every policy installed in **monitor**; log group and mode; the canary binary `/usr/libexec/edr/canary` and the `edr-canary` policy; `edr-policy-check` (§4.3), which promotes `sctp-socket` after its canary and `nginx-exec` after its 24 h gate, within the `[tetragon] enforce` list (§4.3), and the install does not wait for either | `local_uninstall.sh` |
| 8 | P1b | **DNS** (§4.4): config check, proxy, resolved drop-in, lookup test, then the lock and `edr-dns-watch` | delete lock, drop-ins, restart resolved |
| 9 | P1a; P1b parts | **Agent, inventory, local alerts:** units, `zz-edr-inventory` hook, `/etc/needrestart/conf.d/50-edr.conf` (adds keys for `^tetragon`, `^edr-`, `^dnscrypt-proxy`; never reassigns the hash), `edr-diskguard` (service and timer; runs the kit's `/etc/edr-agent/logrotate.conf`, Suricata paths P1b, §9), `edr-notify` units (P1b, off until `notify.url` exists), journal namespace `edr`, MOTD line; start the agent (§4.5, §4.7) | remove units and files |
| 10 | P1a | **Health and confirm:** `check.sh`, then wait for `--confirm` (or the `--yes` self-confirm); disarm the rollback timer | none |
| 11 | P2 | **Enroll** (§4.6), last: after the host is proven good, so a bad token never costs the install | local mode, exit 5 |

Step 11 runs after the rollback timer is disarmed (above). It is skipped if already enrolled to the same hub; with a
different `--hub` the installer refuses (exit 3) and prints the exact `edr-agent rehome --hub ... --token-file ...`
command (§5). With no `--hub` the agent stays in **local mode** (§4.7); `edr-agent enroll` joins a hub later (usage in §4.6).

**On a busy production host.** The installer restarts only what it installs and `systemd-resolved`, never nginx,
php-fpm or the database, and runs under `Nice=19`, idle I/O and `CPUWeight=20`. The `policy-rc.d` keeps Suricata and dnscrypt-proxy from starting on a stock config; each starts once its own step is done. If `MemAvailable` is under the memory guard (§4.1) when step 4 would
test the rules, Suricata is left installed and stopped with a WARN, and a re-run finishes it.

**A re-run** reads the manifest and `local.conf` and skips finished steps; an interrupted session is offered `--rollback`
or resume. Files the operator edited (hash differs from the manifest) are left and the new copy is written as `.new`. A newer `VERSION` is an upgrade, an older one is refused without `--force`
(§15). `local.conf`, identity, `host-id`, the spool and the tuning files are never touched.

**File layout (planned)**

    server_client/            (the tarball holds the same tree)
    ├── PLAN.md  VERSION  MANIFEST.sha256     (VERSION and MANIFEST.sha256 come from make dist)
    ├── install.sh  uninstall.sh  check.sh    §7, §6, §8 (`rehome` is `edr-agent rehome`, §5)
    ├── agent/edr-agent.py                    stdlib only; the helpers (edr-bans, edr-inventory, edr-diskguard,
    │                                         edr-dns-watch, edr-home-net, edr-policy-check, edr-notify) beside it
    ├── files/                suricata-server.yaml and unit drop-in, update job, logrotate, nft file, units and timers,
    │                         sctp, conntrack, dnscrypt-proxy toml (per series) and drop-in, resolved drop-in,
    │                         `inet edr_dns` file, needrestart, apt hook, MOTD, defaults.conf, tripwires.json
    └── tetragon/             policies/ (the §4.3 set, edr-canary, adapted ones), export-denylist.jsonl
    on the host, for example (§6 removes each of these; the manifest has the full list):
      /usr/local/lib/edr-agent/ (the tree), edr-agent.prev       /usr/local/sbin/{edr-agent,edr-uninstall,edr-check}
      /usr/libexec/edr/ (canary)                                 /etc/edr-agent/{local.conf,notify.url,pause.json,logrotate.conf}
      /etc/edr-dns/                                              /etc/suricata/home-net.extra
      /etc/systemd/journald@edr.conf                             /etc/update-motd.d/90-edr
      /etc/needrestart/conf.d/50-edr.conf                        /etc/modprobe.d/edr-sctp-block.conf
      the resolved drop-in zz-edr-doh.conf and the conntrack sysctl drop-in
      /var/lib/edr-agent/{manifest.json,identity,spool,cursors,host-id,alerts.jsonl,seen.json}
      /var/lib/edr-{bans,inventory,restart,diskguard,install,notify}
      /run/edr-{agent,bans,inventory,diskguard,policy-check,dns-watch}

---

## 8. Health check (`check.sh`)

Read-only, PASS/WARN/FAIL, like the repo root's `check.sh`. It uses `nft -t` and never a bare `nft list ruleset`.
Exit 0 all PASS, 1 WARN only, 2 any FAIL (§15). Hub liveness is its own WARN, so a hub outage is never an agent FAIL.
Options: `--live` (canaries below), `--audit` (installed files against the manifest), `--local` (skip hub checks). A
component switched off in `[kit]` (§14) is skipped, never a FAIL. The blocks carry the phase that ships them (§10); an
install of an earlier phase skips the blocks of later ones (§7). The installed name is `edr-check` (§7).

**Paused host.** When `/etc/edr-agent/pause.json` has an `until` in the future (§4.7; an expired file is ignored), the
DNS lock, the ban counts and the policy modes are reported as WARN "paused until T", never FAIL: the empty ban sets,
the missing `inet edr_dns` table, the policies held in monitor and the plain query to `9.9.9.9:53` that now succeeds
are all expected. `edr-canary` is not paused and is still checked, and `--live` still runs its canary.

**Kit and install** (P1a)
- Version matches the manifest; copies under `/usr/local/lib/edr-agent` are root-owned and not group or other writable;
  `local.conf` is `root:edr-agent 0640`, parses, and has no unknown key (§14). `--audit` WARNs on a changed file.
- No unconfirmed install session or armed `edr-install-rollback`, no kit service on a deleted library, no kit
  `policy-rc.d` left with no install session running, and `kernel.apparmor_restrict_unprivileged_userns` is 1 (each a
  WARN).

**Suricata (§4.1)** (P1b)
- Running in af-packet mode; kernel drop share (WARN over 1%); rule age; last update succeeded; each source not older
  than 7 days (WARN); no run of skipped updates (stale rules); the kit config passes `suricata -T` through the memory guard.
- **FAIL:** HOME_NET lacks an address from `ip -o addr`; `stream.midstream` is not `false` (Suricata bans stay off);
  `dump-all-headers` or a custom cookie or authorization field is set. WARN: the offloading warning in the log, or
  `ethtool -k` differs from the value saved at install; `edr-ban-sids.txt` missing or not `root:suricata 0640`.
- Prints the Hyperscan line of `suricata --build-info`.

**Bans and conntrack (§4.2)** (P1b)
- `inet edr` and its sets present with counts; `edr-bans.path` active (**FAIL** if not), timer running,
  `last_apply_error` empty; never-ban holds the hub addresses (P2), admin address, gateway and own addresses;
  `169.254.169.254` is in no ban or feed set. Conntrack use WARN at 70%, **FAIL** at 90%; `drop` and `early_drop` not
  rising.
- **FAIL** if `systemd-analyze critical-chain network-pre.target` lists a kit unit that took over 5 s (§4.2).

**Tetragon (§4.3)** (P1a)
- Running at the pinned version; every rendered policy loaded, in the mode `local.conf` says (reuse
  `tetragon/check.sh`); the gate reason for any policy kept in monitor; `/run/edr-policy-check/status.json` fresh (the helper's timer period
  plus a margin) and free of `enforcement_gone`.
- `/var/log/tetragon/tetragon.log` is `edr-agent:640`; **FAIL** on a Tetragon listener on a non-loopback address; no
  `@HOME@` left in a rendered policy; WARN when the `KERNELMEMORY` sum is over 150 MB on `--lite`.
- Coverage drift: `uncovered_webroots`, `uncovered_fpm_binaries`, `uncovered_pool_users` (WARN).

**DNS (§4.4)** (P1b)
- `dnscrypt-proxy -check` passes; lookups work via `/etc/resolv.conf` and for the site's names; no routable resolver
  but `127.0.2.1` (WARN); the lock matches `[dns] lockdown`: with `on`, `inet edr_dns` is present and `/run/edr-dns-watch/status.json` shows
  `locked` (state `open` is a **FAIL**; `paused` is a WARN, see above; `flapping` a WARN); skipped when lockdown is `off`;
  the exempt uid exists; stamp and
  block-list sets disjoint (**FAIL**); a plain query to `9.9.9.9:53` as a non-proxy uid (`setpriv`) **fails**;
  detected containers and tunnels listed.

**Agent and local alerts (§4.5, §4.7)** (P1a; hub checks P2)
- Running; sandbox self-test passed; spool size; no `gap` or `spool_dropped` in 24 h (WARN); `inventory.json` under
  2 h old; certificate expiry (P2; WARN at 30, 14 and 7 days, FAIL when expired); any CRITICAL in `alerts.jsonl` in 24 h (WARN).
- **Heartbeat:** last accepted one over 5 minutes old is a **FAIL**, over 2 minutes a WARN (the hub calls a host "late"
  at 4 minutes and HIGH at 5; heartbeat every 60 s; hub §4). In local mode "n/a": the last event processed is used.
  Hub unreachable is a separate WARN; 403 (revoked or moved) FAILs with the reason; 426, 422 `schema_too_old` and a
  `v` below the reply's `min_client_schema` are WARNs (§15; statuses in hub Appendix A).

**Disk (§9)** (P1a; Suricata paths P1b)
- Disk use of each log against its budget (§9).
- WARN if the `edr-diskguard` timer is inactive or `/run/edr-diskguard/status.json` is over 5 minutes old.

**nginx, packages and kernel (§4.5.1, Appendix A)** (P1a; posture lines from P1b)
- Package at or past its advisory fix (FAIL if vulnerable and the matching feature is exposed, WARN otherwise); the
  running binary matches the installed one (FAIL if stale: "restart, a reload is not enough"); `security_pending` and
  `lists_age_hours` over 48 (WARN); reboot required; running kernel against the fixed version for CVE-2026-64564.
- `sctp` not loaded and blocked (`modprobe -n -v sctp` shows `install /bin/false`); WARN if built in.
- Which nginx markers are blind at the effective `error_log` level; `log_format` starts with `$remote_addr`;
  `real_ip` or X-Forwarded-For (web-sourced bans off, printed); posture lines (WARN, from P1b).

**`--live` canaries** (P1a) change nothing durable and say what they do before they run.
1. `tetragon/check.sh --canary`, which reads one byte of `/etc/shadow`.
2. **Enforcement canary** (§4.3), run as the web user (discovered, never assumed `www-data`; `nobody` with `--no-web`;
   no `sudo` needed). It
   must die by SIGKILL and an event must follow. It proves the exec hook, the kill and the kernel, not the `web-exec`
   or `nginx-exec` selectors (VM tests do, §11).
3. **SCTP canaries,** only when safe: `sctp-socket` is enforcing (or the module is blocked), `ss --sctp` is empty and
   no SCTP user is installed (the §4.3 gate). Otherwise they print SKIP and why. Run as the same user:
   `python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132)'` and the same with
   `socket.SOCK_SEQPACKET, 0`. Each must be killed by `sctp-socket`.
4. Nothing fires on the root helpers (§4.5.1).
Canary events are rated INFO, so they do not reach `alerts.jsonl` (§4.7). Each event must appear in the agent's journal
(`journalctl --namespace=edr`) within 10 s and, when enrolled, the hub within 2 minutes (batches leave every 5 s;
the margin covers one failed attempt). They never page.

---

## 9. Disk and CPU budgets

Every log, cache and state directory the kit creates has a cap here. "Estimate" means the VM test (§11) measures it.
The Suricata and DNS rows ship with P1b and P3; the Tetragon, agent and inventory rows ship with P1a (§10).

| Item | Worst case | How |
|------|-----------|-----|
| Suricata `eve.json` (alert, anomaly, stats) | ~250 MB | `size 50M`, `rotate 3`, `delaycompress`: four files of 50 MB (older ones compressed, so a bound) plus the overshoot, rate x 120 s between runs: 100 alerts/s x 4 KiB is ~48 MB |
| Suricata `eve-bulk.json` (tls, ssh, quic) | ~100 MB | `size 25M`, `rotate 2`, `delaycompress`; the first thing the guard drops (§4.1.2) |
| `suricata.log`; rules and update cache | 20 MB; ~100 MB | `size 10M`, `rotate 1`; the cache is an estimate |
| Suricata MPM cache (`/var/lib/suricata/cache/sgh`) | 900 MB until measured | `sgh-mpm-caching-max-age: 7d`; it reached ~890 MB on the laptop; disposable, the guard deletes it first |
| Tetragon `tetragon.log` | ~100 MB | Native rotation: 20 MB x 5 backups, compressed, mode 640; the guard removes backups only |
| Agent state (`/var/lib/edr-agent/`) | ~70 MB | Spool 50 MB (`hi` 15, `lo` 35), `spool/rejected` 5 MB, `alerts.jsonl` 5 MB x 2, cursors and `seen.json` |
| Journal namespace `edr` | 150 MB | `SystemMaxUse=150M` (below) |
| dnscrypt-proxy query log (P3) | 15 MB | 5 MB live + 2 x 5 MB backups (§4.4) |
| `edr-bans`, `edr-inventory`, `edr-notify` state, install manifest, `/usr/local/lib/edr-agent.prev` | a few MB | Webroot manifest (P3): at most 20,000 files |
| Opt-in: nginx `edr.log`, `collect` bundle | ~60 MB, 50 MB | `size 20M`, `rotate 2` on the same 2-minute run; the bundle is written by hand and deleted by hand |
| Opt-in swapfile (`--swapfile`) | 1 GB | Created only on request; counted in the free-disk pre-flight (§7) |
| nginx logs, the system journal | unchanged | Ubuntu's own rotation; the kit never changes `SystemMaxUse` |
| **Total kit** (without the swapfile) | **~0.9 GB; ~1.8 GB with the MPM cache** | Check the cache against a small disk first |

**Disk guard: `edr-diskguard`.** The agent has no capabilities and a read-only `/var/log`, and Suricata reads its eve
types only at start, so the agent cannot rotate, signal or reconfigure anything. It only observes: `os.statvfs` at
each heartbeat; below 10% free it sends CRITICAL `health.disk_low` and empties its `lo` spool lane first, capping it at
5 MB; the `hi` lane is never cut below 10 MB (§4.5 has the lanes). The work is done by a **root oneshot** on a timer
(`OnBootSec=1min`, `OnUnitActiveSec=2min`, `AccuracySec=10s`), which also runs the kit's `logrotate` (own config
`/etc/edr-agent/logrotate.conf`, own state file under `/var/lib/edr-diskguard`, so the stock daily run cannot clash).
The kit's stanza uses `su suricata suricata` and `create 640 suricata suricata`, because the packaged `/var/log/suricata`
is not root-owned.

    CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER CAP_KILL CAP_SETUID CAP_SETGID
    ProtectSystem=strict
    ReadWritePaths=-/var/log/suricata -/var/log/tetragon -/var/lib/suricata/cache   # plus -/var/log/nginx when nginx_info_log = on
    StateDirectory=edr-diskguard               # logrotate state; writable
    RuntimeDirectory=edr-diskguard             # status.json, root:edr-agent 0640
    RuntimeDirectoryPreserve=yes
    MemoryMax=64M
    Nice=19
    IOSchedulingClass=idle
    TimeoutStartSec=90
    LogNamespace=edr

The `-` prefix keeps the unit starting with `--no-suricata` or `--no-tetragon`; the installer renders the nginx path
only when `nginx_info_log = on`. Because the guard is root working in directories owned by `suricata`, it uses
`su suricata suricata` for Suricata paths, opens files with `O_NOFOLLOW`, acts only on regular files owned by the
expected user, deletes by `unlinkat` on a directory descriptor and never follows a link in `/var/log/suricata` or
`/var/lib/suricata/cache`. The VM test confirms that rotating `eve.json` succeeds in this sandbox.

| Free space | Fixed actions (nothing else; it never restarts Suricata) |
|------------|-------------------------------------------------------|
| Every run | `logrotate` of the kit's config; write `status.json` (`free_pct`, `stage`, `freed_mb`, time) |
| below 10% | Delete the MPM cache; `logrotate -f`; delete rotated copies beyond the first; truncate `eve-bulk.json`, then HUP Suricata |
| below 5% | Delete all rotated kit logs and Tetragon backups; point `eve-bulk.json` at `/dev/null` and HUP |
| below 3% | `SIGTERM` Suricata (a clean stop; `Restart=on-failure` leaves it down), unless `[diskguard] stop_suricata` is `off` (§14). The site's disk matters more than the IDS |
| back above 15% | Restore a real `eve-bulk.json`, HUP; an operator starts Suricata again (§17) |

- Deleting an open file frees nothing until the HUP, so truncate or rotate first. HUP is `systemctl kill -s HUP
  suricata.service` (also the logrotate postrotate), with the pid-file signal (`/run/suricata.pid`, `CAP_KILL`) as the
  fallback; the stage-3 TERM is `systemctl stop suricata.service` with the same fallback. The VM test confirms which
  works from this sandbox. The `/dev/null` symlink is untested: verify in the VM, else keep truncating. Alerts stay in
  the small `eve.json`.
- The agent turns any stage above 0 in `status.json` into CRITICAL `health.diskguard`; the guard also journals
  `edr-diskguard: <free>% freed <n> MB`. `check.sh` WARNs if the timer is inactive or the file is over 5 minutes
  old. Chaos test: fill the disk to 95% (§11).

**Journal.** The kit sets no system-wide journal cap, so sshd, kernel and auth history keep Ubuntu's default. Its own units (`edr-agent`,
`edr-bans`, `edr-inventory`, `edr-diskguard`, `edr-dns-watch`, `edr-home-net`, `edr-notify`, `edr-policy-check`) set
`LogNamespace=edr`, with `/etc/systemd/journald@edr.conf` (`SystemMaxUse=150M`, `RuntimeMaxUse=50M`). Read it with
`journalctl --namespace=edr`. Kernel and audit lines (`edr-bigconn:`, `edr-dnslock:`, `edr-egress:`) stay in the default
journal only, and so do Suricata, Tetragon and dnscrypt-proxy (packaged units, own files). Uninstall removes the file.
Confirm in the VM that the agent's `BindReadOnlyPaths` reach the namespace store and `check.sh` reads the right journal.

| CPU and memory | Budget |
|----------------|--------|
| Suricata | ~400 MB at ~41k rules (estimate), `--lite` smaller; unit limits in §4.1 |
| Suricata **reload peak** | ~800 MB total (estimate, never measured); update handling in §4.1 |
| Tetragon | User space 100-150 MB (laptop: 140 MB RSS, 375 MB cgroup peak, 7 policies); `OOMScoreAdjust=700` |
| Tetragon **kernel memory** | ~145-155 MB locked, not counted in the cgroup (estimate; `bpftool map show`): 8 `rateLimit` policies x 9.7 MB = 78, `execve_map` ~32, about 17 other policies at 2-2.5 MB each. Tune `--execve-map-entries` on `--lite`; `check.sh` WARNs above 150 MB on `--lite` (§4.3) |
| `edr-agent` | `MemoryHigh=96M`, `MemoryMax=128M`, `CPUQuota=10%`; ~30 MB and under 1% CPU expected, plus the access ring (10-20 MB, estimate) |
| `edr-bans` | Idle most of the time; `MemoryMax=1G` (starting value, set after the VM test measures an apply at 200k entries; ~3 s, 0.3-0.8 GB estimated), ~30 MB of kernel memory for the sets (§4.2) |
| conntrack | Up to ~67 MB at `nf_conntrack_max=262144`, only if the kit loaded the module (§4.2) |
| `edr-inventory`, `edr-notify`, dnscrypt-proxy | `MemoryMax` 128M, 64M and 96M; dnscrypt-proxy uses ~20 MB. Oneshots run at idle priority |
| `edr-diskguard`, `edr-dns-watch`, `edr-home-net`, `edr-policy-check` | `MemoryMax=64M` each (starting value; measure), idle priority |

**Minimum droplet.** Steady state is about 0.8 GB for the kit (Suricata ~400 MB, Tetragon ~250-300 MB with kernel
memory, the rest ~100 MB) and the reload peak adds ~400 MB. **2 GB** is a floor for a light site, not a comfortable
size; **4 GB** is the recommendation with MySQL on the same droplet. **1 GB** runs only with `--lite` or
`--no-suricata`, unsupported until measured. With swap 0 the installer offers a 1 GB swapfile (opt-in).

---

## 10. Roadmap

A phase starts only when the previous one has met its exit criteria (tiers and chaos suite: §11). The phase tags in
§4 to §9 say what ships where.

**P1a, thin core (no hub, no Suricata, useful alone). Ships**
- Tetragon server policies (§4.3): `nginx-exec` and `sctp-socket` enforcing once `edr-policy-check` finds their gate
  and canary passed (the install does not wait for it), every other policy observe-only; the SCTP module block;
  `edr-inventory` computed from apt (§4.5.1).
- `edr-agent` in **local mode** (§4.5): Tetragon, nginx `error.log`, the journal (sshd and sudo) and the inventory;
  `discover` and `apply-config`; the local alert path and `edr-agent status` (§4.7); the local `health.enforcement_gone`
  event (§4.3).
- `edr-diskguard` (Tetragon paths only), the journal namespace `edr`, the install manifest and `--plan`, `check.sh`
  with `--live`, `uninstall.sh`.

**P1a exit**
- Install and uninstall, twice each, on a clean 24.04 (GA kernel), 24.04 (HWE kernel) and 26.04 VM, leave no table,
  unit, user, port or file (residue diff, §11).
- Core chaos set (§11) passes: `nginx` answers 200 while Tetragon, the agent and the inventory are killed in turn;
  disk at 95%; three reboots, after each of which the Tetragon policies and the agent are back within 60 s;
  `apt full-upgrade` with a new nginx exits 0.
- Canaries fire (`check.sh --live`); a kernel upgrade without a loadable policy raises HIGH `health.enforcement_gone`
  in `alerts.jsonl` within 5 minutes (§4.3, §11).
- Agent under 1% CPU and 128 MB over 24 h. Seven days on a real droplet with no legitimate process killed.

**P1b, network side (no hub, useful alone). Ships**
- Suricata server profile (§4.1) with `edr-home-net`; nftables sets, local auto-bans, never-ban and the ban ladder
  (§4.2); `bigconn`; the kernel-log reader with its `--kernel-log` test input; the conntrack sizing and monitoring.
- Agent additions: eve files, access-log counters, tripwires and scanner bans; the kernel log and the disk guard's
  status as inputs (`health.diskguard`); `pause` (§4.7); optional `edr-notify`; `auth_state` diff and log-shrink
  checks; coverage drift and posture WARNs in `check.sh` (§4.5.1); `edr-diskguard` gains the Suricata paths.
- DoH lock (§4.4): `dnscrypt-proxy`, `inet edr_dns` and `edr-dns-watch`, behind `--no-dns-lockdown`, installed
  **last** in the phase, with its lock state in `/run/edr-dns-watch/status.json` and `edr.dnslock` events (§4.4,
  §4.5). It is the part most able to break the site: if its criterion below is not met it moves to P3
  without holding the rest back.
- **Owner decision:** the DNS lock is on by default (`--no-dns-lockdown` skips it); it ships last in P1b with its own
  exit criterion below and moves to P3 if that is not met.

**P1b exit**
- Suricata kernel drops under 1% and a measured reload peak, from which the unit limits and the memory guard are set.
- Three reboots with `inet edr` back within 30 s and `inet edr_dns` within 60 s; `apt full-upgrade` with a new
  Suricata exits 0.
- 24 h on a real droplet with nginx p99 latency within 5% of the no-kit baseline; NIC offload flags unchanged after
  `kill -9` of Suricata; ban ladder and never-ban refusal tested (§11); a `>4 GiB` transfer produces `edr-bigconn:`.
- Install over SSH with a deliberately failing last step keeps the session alive and the state accurate; an install
  nobody confirms rolls back and exits 4 (§7).
- DoH lock: DoH blocked for 10 minutes, lookups recover within 90 s, the lock re-arms itself, the site's own names
  resolve with the lock on.

**P2, with the hub MVP. Ships**
- Enrollment, mTLS transport, spool, heartbeat, event ids (§4.5, §4.6, Appendix B); inventory and posture forwarded;
  `rehome` (§5). The agent polls `/v1/policy`, which carries peers only in this phase: bans and feeds are empty, and
  the client applies only the peers and the hub addresses to the never-ban list (§4.2).
- **`edr-agent learn`** and the `web-exec` gate (§4.3); `collect`; the web-user egress record; `ssh.login` novelty; a
  daily canary through `edr-policy-check` (INFO `canary.policy_check`; hub rule: no canary in 26 h is MEDIUM, once per
  host).

**P2 exit**
- A canary event reaches the hub within 2 minutes; a revoked certificate is refused; a 60-minute hub outage loses no
  HIGH or CRITICAL event (spool at most 50 MB, delivered within 5 minutes after); the previous agent version works
  against the new hub; `rehome` survives a kill at each step and works onto a restored hub; the restore drill works onto a second hub (hub §12).
- `web-exec` enforces only after `learn --accept` and no new tuple for 72 h.

**P3, with hub correlation. Ships**
- Fleet bans and feed sets applied from the hub (guards in §4.2), with the hub's ban commands and Bans page (hub §5,
  §6); `isolate`, `maintenance`, opt-in nginx restart;
  webroot integrity (§4.5.1); `log-tamper` and `link-sensitive` policies, decoy credential files with their Tetragon read-watch (§4.3, §4.7), `Override` hardening after a canary proves
  `EPERM`; DNS telemetry; the context pack; JSONL export from the hub.

**P3 exit**
- A two-host fleet-ban round trip under 2 minutes; the restore drill is repeated on the operator's own schedule (hub §15); feed carving and the 5%
  refusal tested; `fleet_ban_mode` has run in dry-run for a week.

**P4. Ships** Laravel log counters (`laravel_log`, counters only) and credential-stuffing counters (§4.5); ATT&CK
technique ids on the hub's rules (hub §4); the hub's read-only view of each client's local settings (the
`local_conf_sha256` and policy modes the heartbeat already carries). **Exit:** a test proves no Laravel line leaves the
host; the view shows the `local.conf` hash and modes.

**Not built** (so scope does not drift toward a SIEM): a WAF (HTTPS bodies are invisible; run CrowdSec AppSec or
ModSecurity beside it); a CIS benchmark engine (Lynis, `usg`); a fleet query tool (osquery); whole-disk file
integrity (AIDE; here only the webroot manifest); auditd (only the fallback where Tetragon cannot run on a kernel, §12); fail2ban; remote commands,
hub-triggered isolation, raw access-log shipping; a vulnerability database beyond apt's data.

---

## 11. Repo integration and testing

### Makefile and lint integration (complete list)

`tests/lint.sh:30-32` fails on any shell script missing from `SH_FILES`. Changes to `Makefile` and `tests/lint.sh`:

1. **File lists.** Every new script under `server_edr_solution/` goes into `SH_FILES`. The agent, the helpers beside
   it (§7 layout) and the hub's files, including the extension-less `edr-hub`, go into `PY_FILES`;
   the shebang scan also matches `python3`. Root-run code is a root-owned copy under `/usr/local/lib/edr-agent/`.
2. **Policy checks run once per directory** (`tetragon/policies`, then the server one) plus a cross-directory name
   check with an explicit override list: server variants of reused policies keep their `metadata.name`, which the
   global duplicate check rejects today (tested).
3. **Denylist check** takes a list of files; a line with `arguments_regex` also needs `parent_binary_regex` and `^...$`
   anchors on every regex (today only `binary_regex` and `parent_binary_regex` are checked). The 5-selector and
   8-list limits stay, and `matchBinaries` Prefix and Postfix count towards the 8.
4. **Units.** Globs gain `*.path`, `*.socket` and the server directories; each unit gets `systemd-analyze verify` and
   `security --offline=true --threshold=N` (N from the first measured scores).
5. **Data and imports.** The advisory file (hub §4) joins the JSON list with a schema check; `dns-lockdown-rules.sh`
   runs on the server's filtered resolver list; an AST check allows only `sys.stdlib_module_names` imports. `nft -c`
   on generated rulesets needs root, so it is L1.
6. **`make unit`** runs `python3 -m unittest`, no root (the hub plan names it). **CI fails, never skips,** when
   `shellcheck`, PyYAML or `systemd-analyze` is missing. **`dry-run-server`** fails if `nft list ruleset` on the host
   differs before and after.

**Why `tests/dry-run.sh` is not used for the server installers yet.** It isolates files with `unshare -m` only, so the
network namespace, `/proc/sys` and kernel modules are the host's (tested: same namespace id, `nf_conntrack_acct`
writable). It stubs only `systemctl`, `apt-get`, `add-apt-repository`, `logger`, `runuser` and `journalctl`, and its
header says network changes "still happen for real". A server installer loads nft tables and runs `iptables`, `sysctl`,
`modprobe -r sctp` and `useradd`. Extending it needs `unshare -mn` with `lo` up (real `nft` only through `ip netns
exec`); stubs for `nft -f`, `iptables`, `ip6tables`, `sysctl`, `modprobe`, `rmmod`, `depmod`, `useradd`, `groupadd`,
`usermod`, `userdel`, `ufw`, `systemd-run`, `logrotate`; pre-fetched downloads or a veth pair; the flags
`--no-tetragon`, `--no-suricata`, `--no-kernel`; and the pre-flight rule that inside a container the installer refuses unless `--no-kernel` is given (then WARN, §7). Until then the
installers run only in the mock (with those flags) or a VM, never on a developer workstation.

### Test tiers

| Tier | Needs | Proves | Cannot prove |
|------|-------|--------|--------------|
| **L0** `make lint`, `make unit` | No root, seconds | Syntax, units, policy limits, parsers on forged lines, validators, limits | Kernel, firewall, load |
| **L1** `sudo make test` | Real root, `unshare -n` | Generated nft rules load and behave; uninstall leaves no table | Log lines (none from a netns, tested); Tetragon |
| **L2** mock | Rootless Docker | Installs, enroll, spool, `rehome`, restore drill, bans from an attacker box; web and hub images, on 26.04 only today (a 24.04 variant through the `UBUNTU_TAG` and PHP version build args is planned), each running the enroll and mTLS round trip | Anything kernel-level: it shares the host kernel |
| **L3** VM matrix | VMs, before a release | Tetragon kills, SCTP block, kernel log lines, conntrack, performance, chaos | Hardware differences |

- **L0 unit tests.** Forged lines per source: a user name holding ` from 198.51.100.8 port 1 ssh2`, a fake `, client: `
  trailer, a request cutting the real trailer at 2048 bytes, an access line not starting with `$remote_addr`, lines over
  8 KiB, and 20,000 seeded mutations (no exception, bounded time, `src_ip` never a value found only after the real
  field). Validators get property tests: never-ban first, minimum prefixes, coverage caps, IPv6 by /64, overlapping
  CIDRs, a `bans.json` that is a symlink, FIFO or over 16 MiB. Also Debian version compare against `dpkg
  --compare-versions`, nginx fixtures (include depth 8, 500 files, an include outside `/etc/nginx`), golden JSON per
  hub route, the event id format `<epoch>:<seq>` (no host part), the alert file (repeats collapsed with a count, one "N suppressed" line above the per-minute cap, a first occurrence never dropped, `edr-notify` sending each alert once across a restart), and X.509 profiles: the CA, hub and client certificates are issued with the installer's exact `openssl` commands and verified under strict mode (`openssl verify -x509_strict`, TLS 1.3) on the local Python (3.12 and 3.14).
- **L1** extends `tests/firewall-netns.sh`: `inet edr` rules, interval merge, atomic replace, IPv6, never-ban first,
  `inet edr_dns` with the proxy exemption, `inet edr_isolate`; a burst of 20 `bans.json` writes in one second ends in
  the final state applied with `edr-bans.path` still active; the install-time SSH source and the remote address of an authenticated SSH session are never banned, while one still in pre-authentication is not exempt; `pause.json` (§4.7): `edr-bans` applies the empty state while `until` is in the future, ignores an expired file even with the timer stopped, and keeps the pause across a reboot, and `edr-dns-watch` deletes `inet edr_dns` and does not re-lock; the break-glass block (§4.7) leaves no kit table and no active rebuild unit; 50 fake hub
  bans trip the 20-new-bans breaker; `ufw reload` as well as `systemctl reload nftables` brings `inet edr` back within
  60 s. `setpriv --reuid nobody --regid nogroup --clear-groups nft -c -f FILE` fails ("Operation not permitted"), and `unshare -rn` fails
  under `kernel.apparmor_restrict_unprivileged_userns=1`, so it runs as real root.
- **L2 limits.** In the mock: nginx, php-fpm, units, nft sets and apply, `inet edr_dns` logic, `bigconn` **counting**,
  agent and hub, mTLS, `rehome`, uninstall; sysctls and conntrack only if `/proc/sys` is writable (probe, fail loudly).
  **Not** in the mock: the `edr-bigconn:` and `edr-dnslock:` **log lines**, Tetragon, the SCTP block, `IPAddressDeny` and
  `MemoryMax` unless the box shows them enforced, the kernel clock. So the kernel-journal reader takes
  `--kernel-log journal|FILE|FIFO` and the mock feeds it recorded lines; recorded Tetragon JSON is replayed likewise.
  The mock refuses rootful Docker without `MOCK_ALLOW_ROOTFUL=1` and adds an `attacker` box, a second hub and a lab app.
- **L3.** 24.04 GA kernel (6.8), 24.04 HWE (7.0), 26.04, and the kernel flavour DigitalOcean ships (confirm). First run
  4 GB (the full ruleset needs over 1 GB), then 2 GB to measure. **Manual** until multipass or qemu scripts are proven
  (`tests/vm-smoke.sh` is unproven and the VM tooling is not yet chosen (multipass or qemu); L3 stays manual until it is). Also the "confirm in the VM" items of §4 to §9
  and a >4 GiB single-connection transfer (or a test-only lower threshold) that must show `edr-bigconn:` on the hub.
- **The enforcement canary** (§4.3, §8): `/usr/libexec/edr/canary` run as the web user (`nobody` with `--no-web`) under policy `edr-canary` must die
  by SIGKILL and raise an event on each kernel in the matrix; `check.sh --live` and the post-upgrade self-test run the
  same command. During a `pause` the canary still dies (`edr-canary` is exempt, §4.7) while the other policies are held in monitor mode.

### Principle 1 acceptance (`tests/server-chaos.sh`, a variant of `tests/vm-smoke.sh`, two VMs)

Baseline: `wrk -t2 -c64 -d60s` (or `h2load`) on a static and a PHP endpoint, same droplet size, no kit, median of 3.
The idle kit must reach 95% of it. **Each fault gates the phase named in its column:** 0 failed requests and at least
80% of baseline (loose: VM timing is noisy) during the fault.

| Fault, one per run | Phase | Pass |
|--------------------|-------|------|
| `kill -9` Tetragon, agent, inventory in turn | P1a | Back within 60 s, at most 2 starts a minute, no bans lost |
| `kill -9` Suricata, `dnscrypt-proxy`, `edr-bans` in turn | P1b | As above, and `ethtool -k` unchanged |
| Disk filled to 95% | P1a | Site up; the guard acts; CRITICAL `health.disk_low` reaches `alerts.jsonl` (and the hub from P2) |
| Reboot x3 | P1a | The Tetragon policies and the agent back within 60 s |
| Reboot x3 | P1b | `inet edr` back within 30 s and `inet edr_dns` within 60 s |
| `systemctl reload nftables` | P1b | The same tables back within 60 s; alert on the reload |
| `apt full-upgrade` with a new nginx | P1a | apt exits 0; stale-binary report within 20 minutes (the inventory debounce, §4.5.1) |
| `apt full-upgrade` with a new Suricata | P1b | As above |
| DoH blocked 10 min | P1b | Lookups recover within 90 s; the lock re-arms itself (6 good probes, open at least 5 min) |
| Kernel upgrade without a loadable policy | P1a | HIGH `health.enforcement_gone` in `alerts.jsonl` within 5 min (§4.3) |
| Over-SSH install with a failing last step; an install nobody confirms | P1b | Session alive, state accurate; the unconfirmed install rolls back and exits 4 (§7) |
| Hub blocked 60 min under a ~50 events/s scan | P2 | Spool at most 50 MB, agent under 10% CPU, CRITICAL kept, delivered within 5 min |

Manual or nightly, **not gates:** memory squeeze (`stress-ng` to 90% plus the update timer: the OOM victim must be a
kit process, never `mysqld`, php-fpm, nginx or `sshd`), SYN flood at 5,000/s, nginx USR2 upgrade (master not killed).

**Upgrade test (L2, L3).** Install the previous tag, run the new `install.sh`: `local.conf`, `host-id` and identity
unchanged, new keys in `defaults.conf`, ban state kept, `install.sh --rollback` restores the old copy (an upgrade uses the same rollback timer and `--confirm` as an install, §7); then an agent built from the previous tag
(`AGENT_REF`) against the new hub. **Performance gate (L3):** replayed traffic against stored baselines for nginx p99,
Suricata RSS and drops, eve bytes an hour, agent CPU. **Clock:** `libfaketime` tests renewal at 30 days, the certificate-expiry WARNs of `check.sh` at 30, 14 and 7 days and its FAIL once expired (§8), and skewed
timestamps. "The site always wins" is proved only by the chaos suite.

---

## 12. Known limits and risks

What remains after the hardening in §4. Attackers and controls are in §13; the rails that protect the site are in §16.

| Attack path | Signal | Strength | Blind spot |
|-------------|--------|----------|------------|
| Exec payload (shell from php-fpm or nginx) | `nginx-exec`, `web-exec`, `suspicious-exec` | strong | `web-exec` enforces only from P2 |
| In-memory PHP implant, FastCGI to php-fpm | tripwire URLs, canary files (P3, §4.7), access ring | weak | No exec, file or new port: nothing fires |
| `.env` or `APP_KEY` theft, SQL injection, SSRF | `env-read` (P1a, log only; the config-cache rule is P3), metadata-address counter (P2) | weak | Read inside php-fpm by a legitimate binary |
| C2 or exfiltration on 80 or 443 | first-seen egress digest (P2), SNI and JA4 | weak | Allowed ports are allowed |
| DNS tunnelling, credential stuffing | query-log counters (P3), 4xx and 429 counters | weak | `127.0.0.53` lookups are not logged; slow stuffing |

- **The attacker who never execs.** Tetragon is strong for exec payloads and absent for in-memory ones. A worker that
  survives an `nginx-exec` kill keeps its in-memory state: the alert says "restart nginx" (§4.3), and a fork-watch hit
  followed by any web event is a hub rule (hub §4).
- **Hooks can be dodged.** A copy, hard link or bind mount is another binary, so the web policies key on the process
  tree; hooks sit on `security_*` and `tcp_connect`, not syscalls (§4.3). No capability exemption is used; `edr-check`
  requires `kernel.apparmor_restrict_unprivileged_userns=1`. `kernel.io_uring_disabled=2` is a manual hardening
  option that the kit never sets; test it against MariaDB first.
- **Root on the client.** Root can stop the agent, edit Tetragon, truncate logs and use the host's key; only the hub
  notices (heartbeat loss, gap events, a changed `local.conf` hash; §13, hub §4), and local mode cannot. NGINX2Root's
  SCTP bug gives an arbitrary kernel call ([Xint](https://xint.io/blog/nginx2root-remote-code-execution)), so the kit
  acts at the exec or SCTP-socket step; other kernel bugs are caught only later. The module block does not cover
  built-in SCTP, and no patch for Xint's bug was known on 19 Nov 2026.
- **IDS, not IPS.** The first malicious request gets through. With `stream.midstream: false` a flow open at Suricata's
  start is not inspected (§4.1).
- **IP bans.** Behind a CDN or proxy web-sourced and web-port Suricata bans turn off (`proxy_mode`, §4.2); a CDN stops
  the HTTP/2 bugs only if it terminates HTTP/2 and the origin is locked down (Appendix A.4). An on-path attacker can
  forge a TCP flow and get a customer banned, bounded by the never-ban list, the first TTL and the ban budget (§4.2).
  A third-party page can make a visitor's browser request a tripwire path, which counts as ban evidence for that
  visitor; the short TTL, the budget, the never-ban list and `[bans] auto_ban = observe` are the controls (§4.2, §14).
  IPv6 bans cover a /64; NAT addresses hit every user behind them.
- **DNS.** The lock covers the box's own lookups, not containers or WireGuard peers (§4.4). While the watchdog holds
  the lock open, plain DNS is back for a few minutes. DNSSEC is not validated on the box, and `dnscrypt-proxy` has no
  security support without Ubuntu Pro (universe).
- **Platform.** Tetragon enforcement is proved only by VM canaries per kernel (§4.3, §11); amd64 only. If Tetragon cannot run on a
  kernel, the fallback is the auditd rule from the NGINX2Root write-up, filtered by the agent to events whose parent is
  an nginx worker. Panel layouts such as Forge are discovered, not tested on a live host.
- **Operations.** Week one needs tuning (§17). A scan storm can fill the 35 MB `lo` lane in about 5 hours at the event
  budget ceiling (§4.5). A dead hub looks like a quiet fleet until the heartbeat or dead-man alert fires (hub §4).

---

## 13. Threat model

**Assets**, most important first:
- **The site's availability**, and the admin's SSH access. The kit must never cost either (§2, §16).
- **Host integrity and secrets:** root, the code, `.env` and `APP_KEY`, the database credentials.
- **Evidence:** events, logs, and the order they were seen in; the heartbeat that says the host is alive.
- **The client key** (`client.key`) and certificate: whoever holds them speaks as that host.
- **The ban sets**: a lever that can take the site or a customer offline.
- **On the hub:** the CA key, enrollment tokens and the backup (hub §2, §7).

**Trust boundaries.** The internet and the web user are untrusted. The agent is semi-trusted: unprivileged, and its
output (events, `bans.json`) is re-checked by the root helpers. Root on a droplet is trusted until it is not, and then
only the hub can tell. The hub is trusted for peers and, from P3, bans and feeds, and for nothing else (§2).

| Actor | Can do | Cannot do | Answered by |
|-------|--------|-----------|-------------|
| Remote web attacker | Scan, send exploits, forge log text (usernames, headers), hit tripwires; get a visitor banned by making that visitor's browser hit a tripwire path or by forging a TCP flow on path | Ban an arbitrary address by forging a log field; read HTTPS payloads on the wire (a limit) | Evidence an attacker cannot forge; the 1 h first TTL, ban budget and never-ban list bound the rest (§4.2, §12); hostile-field handling (§4.5); advisories and exposure checks (§4.5.1) |
| Code execution as a web user | Run PHP, read `.env`, write web files, connect out on allowed ports, talk FastCGI; run code that never execs (§12) | Keep an exec outside the allowlist alive once enforcing (the caller is killed; the kill is not a guarantee, §4.3); open SCTP; touch the agent's code, state or identity; reach the hub; stop Tetragon | `nginx-exec`, `web-exec`, `sctp-socket`, `web-write-code`, tamper watches (§4.3); canaries and tripwires (§4.7) |
| Root on one droplet | Stop the agent, unload Tetragon, wipe logs, forge events, impersonate that host with its key | Reach other hosts, change the hub's data about them, get the CA key, push bans fleet-wide beyond the per-host fleet-ban budget | Heartbeat loss and gap events, `host revoke`, serial pinning, host name taken from the certificate (hub §2, §4); clone detection (§4.6) |
| Compromised hub | Send peers and, from P3, bans and feed sets; read every event; stay silent about a compromise | Run commands, change files, thresholds, ignore rules or enforcement; silence local detection | Client-side bounds (§4.2); local-only settings (§14); local alert path and `policy_rev_applied` in the heartbeat as a second witness (§4.5, §4.7) |
| Network attacker between client and hub | Watch metadata, drop or delay traffic | Read or alter data; impersonate the hub; enrol a host | TLS 1.3 with the CA pinned by the token's hash, IP SAN, strict verification (§4.6); a silent link raises the missing-heartbeat alert |
| Stolen enrollment token | Enrol one new host before it expires | Reuse the token; take over an existing host's identity; stay unnoticed | Single use, 15 min default life, bound to a name and optional source address; only `--for HOST` reuses a host's identity; every enrolment audited and alerted (hub §2, §4.6) |
| Operator error | Ban the admin, install over SSH and lose the session, enforce a policy that kills part of the site, mistype a CIDR | Cause a permanent lockout or outage without a way back | Admin's SSH source never banned; timed rollback at install; monitor before enforce; ban budget and TTLs; `pause`; `--plan` (§7, §16) |

- **Never-ban does not mean never-alert.** Traffic from VPC neighbours, peers and allowlisted ranges still alerts
  (§4.2); an internal attacker is not banned, but is seen.
- **One shared admin identity** is the default; hub audit rows carry the operating-system user (hub §5, §15).
- **Hub fields are untrusted too.** The hub treats every client field as attacker text and escapes it on display
  (hub §5), because a rooted client can send anything under its own name.

**Out of scope.**
- Persistence below the kernel (rootkits, firmware) and a hostile hypervisor or DigitalOcean account.
- A stolen DigitalOcean API token or console session, which bypasses the host entirely.
- The supply chain of upstream packages and feeds beyond the pins, checksums and package signatures in §7 and §15.
- Compromise of the admin's workstation or of the SSH key.
- Volumetric denial of service, and application logic bugs with no host-level signal.

---

## 14. Configuration

**One file, local only.** `/etc/edr-agent/local.conf` holds every choice that changes what the kit detects, bans,
forwards or enforces. It is INI (standard-library `configparser`, no interpolation, duplicates are an error), `#`
comments, lists comma-separated, durations as `30s 10m 1h 7d`, sizes as `64M 4G`. Owner `root:edr-agent`, mode `0640`:
the agent and the root helpers read it, only root writes it, and `stack-tamper` watches it (§4.3). It holds no secrets
(the webhook URL is in `/etc/edr-agent/notify.url`, root `0600`).
- **The hub never changes it** (§2). The heartbeat carries a hash of the file and the hub shows a read-only view, so a
  change is visible, never remote.
- **Seeded once.** `install.sh` writes the file only if it is missing: a commented reference of every key at its
  default, plus the keys set by flags (`--admin-ip`, `--enforce`, `--allow-egress-port` and the rest of §7) and by
  `edr-agent discover`. Later runs never rewrite it. Defaults live in `/usr/local/lib/edr-agent/defaults.conf` (replaced
  on upgrade); `local.conf` overrides it key by key. Precedence: `local.conf`, then `defaults.conf`.
- **Guards are not keys.** The limits that protect the host from a hostile hub or agent (§4.2 Guards, including the
  never-ban literals) are constants in code: a key could be turned against them.

**Applying a change.** Edit as root, then run `edr-agent apply-config` (`--check` prints the diff and effective values
and changes nothing). It validates, renders, and only then swaps:
1. Parse strictly: unknown section or key, wrong type, value out of range, a CIDR that is not `ipaddress`-clean, a
   port outside 1 to 65535 or a path that is not absolute are refused with the key named.
2. Render into a staging directory: Tetragon policies from the placeholders (lint and `tetra` load check), the
   never-ban and ban inputs for `edr-bans`, the `IPAddressAllow=` drop-in and the `min_severity` credential for
   `edr-notify` (§4.7).
3. Swap atomically, reload what changed (policies, `edr-bans`, the agent) and print `changed: key old -> new` for each
   key. `apply-config` never restarts php-fpm by itself: when a policy that follows children changed it prints the
   exact reload command and the affected units and exits 0. `--reload-fpm` runs a graceful reload after a yes/no
   prompt (`--yes` skips the prompt).
A refusal keeps the running configuration and exits 3 (§15). The agent also re-reads the file at start; if it is
invalid it keeps the last good copy and raises `health.config_invalid` (HIGH), never stopping detection.

**Keys.** Section, key, default, where used. `discovered` means `edr-agent discover` writes it at install and after
`apply-config` (a missing value is never a guess).

| Key | Default | Where used |
|-----|---------|------------|
| `[sites] web_users`, `web_roots`, `nginx_bin`, `phpfpm_bins`, `php_cli_bins` | discovered; `--webroot` overrides roots | Policy placeholders (§4.3), never-ban (§4.2), drift (§4.5.1) |
| `[sites] vpc_cidr` | discovered from the VPC interface's connected route, or asked at install | The one source of the VPC range: `edr-home-net` writes `home-net.extra` from it (§4.1); never-ban (§4.2) and the DNS rules (§4.4) read it |
| `[bans] admin_ip` | install-time SSH source, plus `--admin-ip` | Never-ban (§4.2) |
| `[bans] allow_cidr` | empty | Operator allowlist, same as never-ban (§4.2) |
| `[bans] auto_ban` | `on` (`on`, `observe`, `off`) | Local triggers of §4.2; `observe` raises the alert but writes no ban |
| `[bans] hub_bans`, `feeds` | `on`, `on` (P3) | Apply hub bans and feeds (§4.2); in P2 the policy carries peers only |
| `[bans] proxy_mode` | `auto` (`auto`, `on`, `off`) | Web-sourced and Suricata web-port bans behind a proxy (§4.2) |
| `[bans] bigconn_bytes`, `bigconn_cap` | 4 GiB, `off` | Large-connection watch and opt-in cap (§4.2). `--bigconn-cap SIZE` seeds `bigconn_cap`; `bigconn_bytes` is set only here |
| `[thresholds] ssh_fail`, `tripwire`, `suricata`, `window_update`, `bigconn_repeat` | `5/10m`, `5/5m`, `3/10m`, `3/10m`, `2/1h` | Local auto-ban triggers (§4.2) |
| `[thresholds] suricata_sigs` | 2 per 10 min | Distinct signatures that also trigger a ban (§4.2) |
| `[thresholds] ban_budget_per_hour`, `ban_max_active` | 30, 1000 | Ban budget (§4.2) |
| `[thresholds] ban_ladder`, `ban_memory` | `1h,6h,24h,7d`, 14 days | Escalation (§4.2) |
| `[tetragon] enforce` | `nginx-exec,sctp-socket` (empty = observe-only) | Policies allowed to enforce once gated (§4.3) |
| `[tetragon] egress_ports` | empty; built-in list always applies | Extra `web-connect` ports, `--allow-egress-port` (§4.3) |
| `[tetragon] web_exec_allow` | empty (built-ins: php-fpm, nginx, `/usr/sbin/sendmail`) | `web-exec` allowlist, written by `edr-agent learn --accept` (§4.3) |
| `[suricata] lite`, `sslbl`, `home_net` | `off`, `off`, auto | Smaller rule set, optional ruleset source, HOME_NET override only (§4.1); the VPC range is `[sites] vpc_cidr` |
| `[kernel] sctp_block` | `on` | Module block, `--no-sctp-block` (§7) |
| `[kit] web`, `tetragon`, `suricata`, `kernel` | `on` each | `--no-web`, `--no-tetragon`, `--no-suricata`, `--no-kernel` write `off`. Off skips that component's policies, checks and pre-flight; `check.sh` does not FAIL for it (§7, §8) |
| `[diskguard] stop_suricata` | `on` | Stage 3 of the disk guard stops Suricata; `off` makes it alert only (§9) |
| `[dns] lockdown` | `on` | The `inet edr_dns` lock, `--no-dns-lockdown` (§4.4) |
| `[dns] lock_forwarded`, `block_doh_ips`, `vpc_dns` | `off`, `off`, `off` (`auto`) | Forward chain, DoH-address reject, VPC resolver rule (§4.4) |
| `[dns] resolve_check` | empty | Extra names for pre-flight and the watchdog probes (§4.4) |
| `[agent] redact`, `payload`, `args` | `on`, `hex-head` (or `off`), `redact` (or `drop`) | Redaction of forwarded text (§4.5, §18) |
| `[agent] event_budget_per_hour` | 2000 per source | Event budget for six sources; HIGH and CRITICAL bypass it (§4.5) |
| `[agent] access_ring_minutes`, `access_ring_lines` | 5, 20000 | In-memory access ring (§4.5) |
| `[agent] nginx_info_log`, `laravel_log` | `off`, empty (P4) | Opt-in extra log inputs (§4.5) |
| `[agent] login_route` | empty (P4) | Login-route path for the credential-stuffing counters (§4.5) |
| `[agent] sshd_password_auth` | discovered from `sshd -T` | Rating of a password login (§4.5) |
| `[agent] dns_telemetry` | `on` (P3; no effect before) | Query-log input; `off` is the local switch (§4.4, §18) |
| `[agent] rehome_confirm_timeout` | 300s | Wait for the new hub before rollback (§5) |
| `[notify] min_severity` | `HIGH` | `edr-notify` threshold; off until `notify.url` exists (§4.7) |
| `[response] auto_restart_nginx` | `false` | Opt-in restart after `nginx-exec` (P3, §4.7) |
| `[isolate] allow` | empty | Extra egress allowed by `isolate --all` (§4.7) |

Fixed values, not keys: the unit limits and timers (§4.1, §9), the DNS watchdog's probe and flap numbers (§4.4), the
10-minute rehome rollback timer (§5) and the 600 s install rollback timer (§7).

**What survives.**

| Item | Upgrade (§15) | Uninstall (§6) |
|------|---------------|----------------|
| `local.conf`, `notify.url` | kept; new keys appear in `defaults.conf` and `apply-config --check` lists them | removed; `--keep-config` keeps `local.conf` |
| Identity, `host-id`, spool, cursors, `seen.json`, ban memory | kept | state removed; `host-id` kept unless `--purge` |
| Tuning files (`drop.conf`, `modify.conf`, `disable.conf`), edited `tripwires.json` | kept; the shipped version is written beside as `.new` | removed |
| Installed code, units, policies | replaced; the previous copy is `edr-agent.prev` | removed |

---

## 15. Upgrades, versions and exit codes

**Kit upgrade.** There is no remote execution (§2), so the operator upgrades each host by hand, one host first.
1. Build the new tarball (`make dist`), upgrade the **hub first** (hub §17), then copy the tarball to one host and
   verify its hash as in §7. Run `./install.sh --plan` from the unpacked tree: it names every file that would change
   and every key added to `defaults.conf` (`local.conf` is never rewritten, §14).
2. Run `./install.sh` from the unpacked tree. It arms the same 600 s rollback timer and needs the same
   `install.sh --confirm` from a new SSH session as a first install (§7). A newer `VERSION` is an upgrade; an older one is refused without
   `--force`. The new tree is staged beside the old and swapped by rename; the old tree stays as
   `/usr/local/lib/edr-agent.prev`. Units are reloaded, `edr-agent` restarts once (spool and cursors kept, a
   `health.agent_start` event follows), `edr-bans` keeps the table and only re-applies if the state changed, and
   Tetragon policies are re-rendered and reloaded only if they differ. The heartbeat then carries the new version and
   hash (§4.5); the hub knows the hash from `agent-hashes.json`, which is why the hub goes first.
3. Wait at least one day on that host (the daily jobs run overnight), look at `edr-check` and the hub, then repeat on
   the next hosts with the same commands. There is no fleet loop in the kit.
4. **Roll back** with `/usr/local/lib/edr-agent/install.sh --rollback`: it undoes the last install or upgrade session
   from that session's manifest delta (§7). After an upgrade that is the swap back to `edr-agent.prev`, with the
   prior unit files and policies. An unconfirmed upgrade does the same by itself when the timer fires, and never
   replays an earlier session. State files carry a format version; a rollback past a state-format change
   refuses and says what to restore from. `local.conf`, identity, spool and tuning files are never touched (§14).

**Version skew with the hub.** The rule is in Appendix B and hub §17: a client may lag the hub by one version, never
the reverse. A client that gets 426 (protocol) or 422 `schema_too_old` (event field `v`) keeps its last policy, keeps spooling,
retries hourly, and `check.sh` WARNs (§8). Heartbeat replies carry `min_client_schema` so the dashboard lists laggards. An
agent hash the hub does not know is a HIGH alert, so a client upgraded before its hub is visible at once.

**Upgrading components safely.** Each is a change to the pin or the package, never a surprise from apt.

| Component | How it is upgraded | Check and way back |
|-----------|--------------------|--------------------|
| Tetragon | A kit release changes the version and every checksum together (§4.3); `install.sh` swaps it. The restart emits a blind window and policies reload | `edr-policy-check` and the canary (§8); `install.sh --rollback` restores the previous tree and reinstalls its pin (needs the download; confirm in the VM test) |
| Suricata | The OISF PPA is not in unattended-upgrades' origins, so it is upgraded by hand: `apt-get install --only-upgrade suricata` in a quiet period | `edr-check` runs `suricata -T` on the kit config through the memory guard; a kept conffile (`--force-confold`) keeps the kit yaml; if the new version rejects it the IDS is down, the site is not, and the unit state shows it. Pin `1:8.*` |
| Kernel | Ordinary apt, then a **planned reboot**: the agent sends a heartbeat with `shutdown: true` and the hub reads a new `boot_id` as planned (hub §4). Do one host first, and an HWE jump on the canary host | After boot `edr-policy-check` compares loaded policies, runs the canary, and the hub raises "enforcement gone" if a policy is missing. `edr-home-net` and `edr-bans` rebuild from state before traffic |
| dnscrypt-proxy | Package upgrade restarts it (a short stall; the watchdog covers it, §4.4) | `dnscrypt-proxy -check` first; inventory reports an untested version |
| Ubuntu release | Not supported in place. Uninstall, upgrade the OS, reinstall with a `--for HOST` token (§4.6) | |

**Exit codes.** Defined once here; every script and the agent CLI use them.

| Code | `install.sh` | `check.sh` | `edr-agent` CLI | `uninstall.sh` |
|------|--------------|------------|-----------------|----------------|
| 0 | Done (enrolled, or local mode by choice); `--plan` that would proceed | All PASS | Done | Final check PASS |
| 1 | not used | WARN only | `status`: warnings | not used |
| 2 | Failed; the step was undone | A FAIL | Failed (`rehome`: any failure not coded 3 or 4); `status`: a FAIL | Final check FAIL |
| 3 | Pre-flight refused; nothing changed (also `--plan` when refused) | not used | Refused: validation or a gate (`apply-config`, `learn`); `rehome` refused before anything changed | Nothing to remove |
| 4 | Rolled back: the timer fired (nobody confirmed), or `--rollback` finished | not used | `rehome` rolled back | not used |
| 5 | Installed, not enrolled (local mode; hub or token problem) | not used | `enroll`: not enrolled | not used |
| 64 | Usage error | Usage error | Usage error | Usage error |

Code 1 is a warning, not a failure: `make` and CI treat 0 and 1 as success of `check.sh`. Code 5 leaves a working
install and prints the exact `edr-agent enroll` line (§4.6). Scripts print the reason before they exit non-zero.

---

## 16. Safety rails

Every mechanism that keeps the kit from hurting the site or locking out the admin. This is an index: each rail is
defined once, in the section named. The test for each is a chaos or canary test in §11; the principle behind them is
§2 principle 1.

| Rail | Defined in |
|------|------------|
| Fail-open capture | §4.1 |
| Kernel kills the kit first | §4.1, §4.3, §9 |
| No boot gate | §4.3, §7 |
| Never-ban list | §4.2 |
| Ban evidence and budget | §4.2 |
| Hub guards on bans and feeds | §4.2 |
| Fleet ban dry run | hub §4 |
| Timeouts everywhere, bans lift on delete | §4.2 |
| `bigconn` stays log-only | §4.2 |
| Monitor before enforce | §4.3, §14 |
| `web-exec` learning | §4.3 |
| Fork-watch `Sigkill` (P3) | §4.3 |
| DNS watchdog | §4.4 |
| DNS pre-flight | §4.4, §7 |
| Timed rollback and confirmation at install | §7 |
| Rehome rollback | §5 |
| Kernel settings, recorded and reverted | §4.2, §7, §6 |
| Spool, log and event caps | §4.5, §9 |
| Disk guard | §9 |
| Restarts only by operator or guarded timer | §4.1, §4.3 |
| Kill switch (`edr-agent pause`, at most 24 h) | §4.7 |
| `maintenance` | §4.7 |
| `isolate` | §4.7 |
| Auto nginx restart (P3) | §4.7 |
| Identity fails open | §4.6 |
| Uninstall order | §6 |

- **Break-glass, no agent:** the commands are in §4.7, next to `pause`.
- **Chaos tests that prove principle 1:** §11. The memory squeeze and the SYN flood are not gates (manual or nightly),
  so the OOM-victim and conntrack rails are evidenced only when those runs are green.

---

## 17. Operations and runbooks

Commands run as root on the droplet unless they start with `edr-hub`; on a client they use the installed names `edr-agent`, `edr-check` and `edr-uninstall` (§7). Hub runbooks (restore, stolen CA or client key,
expired certificate) are hub §15; offboarding has a part on each side.

### Week one: tuning

Expect noise; record what you measure (the figures in §9 are estimates). `nginx-exec` stays in monitor for 24 h and
`sctp-socket` until its canary has run (§4.3).
1. **Day 0.** `edr-check --live` passes; `edr-agent status` shows each policy's mode.
2. **Suricata.** Count alerts by `alert.signature_id`; disable the irrelevant (`disable.conf`), re-check `drop.conf` (it
   decides which rules may ban, §4.1.1), add `rate_filter` for the noisiest SIDs. Watch `kernel_drops` (under 1%), memcap
   counters, conntrack use and the MPM cache size.
3. **Tetragon.** Read would-be-kill counts and `rate_limit_info`. Allow deploy tools and extra egress ports
   (`--allow-egress-port N` or `[tetragon] egress_ports`), then `edr-agent apply-config`.
4. **Day 7.** `edr-agent learn` prints tuples and "new in the last 72 h". Read them yourself (the week may include an
   attacker), `learn --accept`, add `web-exec` to `[tetragon] enforce`, `apply-config`, restart php-fpm, run the canary.

### Deploying on an enforcing host

What trips `web-exec`, and how to allow it, is in §4.3 (Normal Laravel behaviour). A new
site, pool or PHP version shows as coverage drift in `edr-check`: `edr-agent discover`, then `apply-config`. An nginx
USR2 upgrade is allowed. For a deploy that must run a blocked exec, `edr-agent maintenance --for 30m` (P3) tags and
digests events; before P3, `edr-agent pause --for 1h` holds the enforcing policies (all but `edr-canary`) in monitor mode, and also empties the ban sets and lifts the DNS lock (§4.7); `resume` ends it.

### A false ban and a lock-out

**A false ban.** `edr-agent bans` shows source, time left and evidence (`src_trust`: `tcp`, `claimed` or `none`, Appendix B).
- `sudo edr-agent unban ADDR` lifts it and records an allow entry so the ladder does not re-ban it. A hub ban (P3): `edr-hub
  unban CIDR`; `nft get element inet edr edr_feed4 { ADDR }` tells whether a feed holds the address. Crawlers and
  payment webhooks go in `allow_cidr` in `local.conf`, then `apply-config`.
- Many at once: `edr-agent pause --for 1h` empties every ban and feed set until `resume` or the end of the period (it survives a reboot); it also holds the enforcing policies, all but `edr-canary`, in monitor mode and lifts the DNS lock (§4.7). `edr-agent unban --all` clears local bans only (§4.2). If the CLI itself is unusable, use the break-glass block in §4.7. Behind a proxy `proxy_mode` must be on (§4.2).

**A lock-out (no SSH).** Rule out the installer's rollback timer (§7) and the cloud firewall first: the never-ban set covers
`admin_ip`, the install-time SSH source and the remote addresses of authenticated SSH sessions, so an expired `isolate` is likelier than a ban.
1. **Droplet Console** (browser). It connects over SSH, so cloud and host firewalls must accept SSH on sshd's port and
   allow outbound TCP to `169.254.169.254`
   ([DigitalOcean](https://docs.digitalocean.com/products/droplets/how-to/connect-with-console/)). Confirm in the VM
   test which source it uses and that it is never banned. Then `edr-agent pause` (it also lifts the DNS lock), `unban ADDR`, `nft delete table inet
   edr_isolate` if isolated; `resume` when fixed.
2. **Recovery Console** (VNC), when sshd or the network is gone. It needs password authentication, which a key-only
   droplet lacks: set a password for the admin account beforehand (pre-flight WARNs, §7). There, run the break-glass block in §4.7: it stops
   every timer and path unit that rebuilds or re-locks, then deletes `inet edr` and `inet edr_dns`. A DoH outage lifts the DNS lock itself in about a minute (§4.4).
3. Otherwise the recovery ISO and a snapshot, per DigitalOcean's recovery guide.

**Offboarding an operator.** Admin addresses are local and the hub never distributes them (§14). On each client remove
the operator's address from `[bans] admin_ip` and `allow_cidr` in `local.conf`, run `edr-agent apply-config`, confirm
with `edr-agent status`, and remove their key from `authorized_keys`. Hub §15 covers the hub side.

### A CRITICAL alert

| Kind | Meaning |
|------|---------|
| `tetragon.nginx-exec`, `web-exec`, `web-write-code`, uid-0 transition | Exploit reached exec or files; `Sigkill` stops the exec, not code already in a worker |
| `tetragon.sctp-socket` from a web tree, SCTP module load | NGINX2Root's root step: assume root |
| `edr.dnslock`, `edr-bans` refusal, `health.disk_low`, `health.diskguard` | A safeguard failed, not an attack by itself: fix it (§16), then look for a cause. After disk stage 3, free space and `systemctl start suricata` |

1. **Contain.** Patch first if `edr-agent status` shows the package vulnerable. Cut egress with `sudo edr-agent isolate
   --for 1h` (P3; web users only, `--all` for all but SSH, the hub and `isolate.allow`), or a Cloud Firewall outbound
   rule before P3. Do not restart nginx yet.
2. **Preserve evidence.** Snapshot the droplet (disk only); `sudo edr-agent collect` (P2; raw, sensitive, §18); copy
   `/var/log/tetragon/` and the nginx logs off the box (a root attacker can edit local logs; the hub holds the events).
3. **Restart nginx** (not reload) to drop the compromised worker; an unpatched host can be hit again.
4. **Rotate.** Assume `.env` was read: `APP_KEY` (plan for sessions and encrypted columns), database, mail, queue, cache,
   S3 and API secrets, deploy keys. Check every user's `authorized_keys`, cron, `/etc/ld.so.preload`, systemd units, new
   `.php` under the web root, new uid-0 accounts.
5. **Rebuild** from a clean image (code from git, data only restored) after a uid-0 transition, an SCTP or kernel step,
   persistence, or heartbeats stopping after the event; re-enroll with a token `--for HOST`. Root can stop Tetragon.

### The hub is away, and a kernel upgrade

**Hub away.** Nothing stops: bans keep applying and age out (hub-fed bans and feeds are P3; a feed ends 72 h after the last poll that carried it), enforcement is local.
Events spool (50 MB, `hi` lane for HIGH and CRITICAL) and replay at one batch a second. After 15 minutes
`edr-agent status` and the login summary say so; alerts reach `alerts.jsonl` and `edr-notify` (`edr-agent status
--alerts --since 7d`). Restore the hub (hub §7): with the Reserved IP moved clients reconnect alone, otherwise `rehome`
with `--for HOST` tokens (§5). The spool drop counters show blind spots.

**Kernel upgrade.** Procedure and automatic checks: §15. Keep the old kernel until `edr-check --live` passes and
`kernel_pending` clears. If a policy will not load, the agent raises HIGH `health.enforcement_gone` locally (the hub
raises it too): boot the old kernel from GRUB (Recovery Console without SSH) or wait for a Tetragon release; the site is
unaffected meanwhile.

---

## 18. Privacy and data handling

**What leaves the host** (to the hub; only the optional `edr-notify` reaches anything else): events (kind, severity,
summary and details; limits in Appendix B), visitor and attacker IP addresses, user names, URL paths, and process names
and arguments. A heartbeat adds unit states, package and listener inventory, counters and a hash of `local.conf`. A
HIGH or CRITICAL event with a source address also carries a slice of the in-memory access ring, never written to disk
(§4.5), so the operator can see the exploit request. IP addresses, user agents and query strings can be personal data;
the operator decides the legal basis and notices.

**What is redacted or never sent** is defined in §4.5 (Processing, steps 2 and 3, and the access ring): secrets in
arguments, headers and query parameters are masked on the client before anything is spooled; alert payloads are hex
only; cookies, referrers, `.env` contents and raw access and error logs are never stored or shipped.

**What the operator can switch off** (`local.conf`): `redact`, `payload`, `args`, `nginx_info_log`, `laravel_log` and
the DNS query-log input. Defaults are in §14, effects in §4.5 and §4.4. The alert sender is off until
`/etc/edr-agent/notify.url` exists; `[notify] min_severity` (§14) sets its threshold; it sends only kind, severity,
host and 200 characters, never excerpts (§4.7).

**Local data.** The spool, identity and `alerts.jsonl` are readable by `edr-agent` and root only. `edr-agent collect`
writes a raw, sensitive triage bundle that stays on the host until the operator moves it; delete it after use.

**On the hub.** Access, retention, webhook content and the backup are in hub §16 (retention in hub §3). The encrypted
backup holds event details, so keep a copy of its passphrase off the box (hub §7). There is no per-host purge command; the manual procedure is
in hub §16.

---

## Appendix A: NGINX2Root worked example

This appendix is the evidence behind the summary in §1; the components it names are in §4.2, §4.3 and §4.5.1.
Each of the five nginx bugs is a separate unauthenticated way in; commands then run with the worker's privileges
(the web user, `www-data` on a stock Ubuntu install). Statements marked "as of 19 Nov 2026" are point-in-time;
re-check them before relying on them.

### A.1 The bugs

| Bug | Way in needs | nginx.org affected |
|-----|--------------|--------------------|
| CVE-2026-123007, HTTP/2 flow control | HTTP/2 on. The most exposed ([Rapid7](https://github.com/sfewer-r7/CVE-2026-123007)) | 1.9.5–1.31.8 |
| CVE-2026-123633, HTTP/2 use-after-free | HTTP/2 plus an upstream (`proxy_pass`, `fastcgi_pass`, `grpc_pass`), worker low on `worker_connections` ([CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-123633)) | 1.19.7–1.31.8 |
| CVE-2026-123634, resolver use-after-free | `resolver` set, a `proxy_pass` containing a `$` variable, and either `mirror <uri>` or `ssi on` | 0.6.18–1.31.8 |
| CVE-2026-121810, HTTP/3 use-after-free | HTTP/3 (QUIC) plus an upstream. Not in noble's nginx 1.24, which has no HTTP/3 ([Ubuntu](https://ubuntu.com/security/CVE-2026-121810)) | 1.25.0–1.31.8 |
| CVE-2026-113425, mail proxy use-after-free | a `mail {}` block with `proxy on` plus `auth_http`; no credentials needed | 0.5.33–1.31.8 |
| Kernel SCTP send-path bug (Xint's; no CVE) | the `sctp` module loadable; Linux 4.15 or later | not applicable |

The ranges come from [nginx.org](https://nginx.org/en/security_advisories.html) and the preconditions from Xint.

- **Resolver bug.** The CVE record needs only a subrequest (SSI or `mirror`) that resolves the same variable name.
  Xint demonstrated it with `mirror_request_body off`; the default is `on`. Rate that form HIGH and the other
  forms MEDIUM. `edr-inventory` must not require `off` for a match (§4.5.1).
- **Public exploit code.** Rapid7's proof of concept is the only public full-RCE exploit. It ships profiles for a
  Debian 13 build only, so treat Ubuntu's 1.24 and 1.28 builds as exposed anyway. Censys also publishes crash and
  use-after-free reproductions for 123633, 123634 and 113425. Xint says its own unreleased exploit works on public
  clouds.
- **Exploitation as of 19 Nov 2026.** No in-the-wild exploitation reported and no entry in CISA KEV (catalog
  2026.11.18), per [Precursor](https://www.precursorsecurity.com/blog/nginx2root-critical-nginx-rce-vulnerabilities),
  CERT-EU, Censys and Tenable.
- **Two different SCTP kernel bugs.** (1) Xint's send-path bug: as of 19 Nov 2026 no CVE and no patch are known
  (Xint and Tenable); the site says a patch will come "in the coming weeks" ([site](https://nginx2root.com/)).
  (2) CVE-2026-64564, an ASCONF DEL-IP use-after-free in `sctp_process_asconf`, published 4 Aug 2026, Ubuntu
  priority Critical, already fixed in Ubuntu kernels ([Ubuntu](https://ubuntu.com/security/CVE-2026-64564)).
  The same module block mitigates both.
- **Earlier bug.** CVE-2026-42945 ("NGINX Rift", rewrite module, fixed in 1.30.1 and 1.31.0) leaves only the generic
  signals: a worker crash, then any exec by an nginx process other than its own binary upgrade (§4.3).

### A.2 Fixed versions

Upstream fixed the five bugs in **1.31.9 (mainline) and 1.30.7 (stable)** on 18 Nov 2026. Ubuntu fixed them in
[USN-9159-1](https://ubuntu.com/security/notices/USN-9159-1).

| Package | Release | Vulnerable when (dpkg version) | Also covers |
|---------|---------|-------------------------------|-------------|
| nginx (Ubuntu) | noble 24.04 | `< 1.24.0-2ubuntu7.20` | CVE-2026-118899 |
| nginx (Ubuntu) | resolute 26.04 | `< 1.28.3-2ubuntu1.13` | CVE-2026-118899, 120967, 123640 |
| linux, SCTP ASCONF (CVE-2026-64564) | noble, GA 6.8 | running kernel `< 6.8.0-147.147` | reboot needed |
| linux, SCTP ASCONF (CVE-2026-64564) | noble, HWE 7.0 | running kernel `< 7.0.0-38.38~24.04.4` | reboot needed |
| linux, SCTP ASCONF (CVE-2026-64564) | resolute | running kernel `< 7.0.0-38.38` | reboot needed |
| Xint SCTP send-path bug | all | no CVE or fix known as of 19 Nov 2026 | recheck weekly |

- **Compare per origin and release.** Versions are only comparable within the same Ubuntu release. An nginx.org
  version range says nothing about an Ubuntu package (Ubuntu's fixed `1.24.0-2ubuntu7.20` sorts below `1.30.7`).
  Only the table's own rows decide; an unknown origin or release is "unknown, check by hand", never "vulnerable".
  nginx.org's own packages are compared by upstream version against 1.30.7 or 1.31.9. No Ondřej nginx PPA exists
  (its `php` archive does, its `nginx` archive does not); other PPAs are shown as unknown origin.
- **The same releases fix more than five CVEs.** CVE-2026-118899 is an infinite loop reading a request body over
  TLS 1.3 (nginx 1.13.0–1.31.8): a denial of service that reaches any HTTPS site, Laravel included. It is why an old
  package matters even when none of the five features is in use. USN-9159-1 covers 118899 for noble and
  118899, 120967 and 123640 for resolute besides the five bugs; 125283 and 120993 are not in it (checked
  19 Nov 2026). Of the five, 121810 is in the resolute row only, because noble's 1.24 has no HTTP/3 (A.1).
- **Kernel check.** Take the running kernel's version from `/proc/version_signature` (format
  `Ubuntu 7.0.0-43.43-generic 7.0.14`) and compare with `dpkg --compare-versions` against the row for its flavour.
  The kernel is a reboot fix: the new package is not enough until the host runs it.
- **Initrd.** After blocking the module, `update-initramfs -u` is needed only where `lsinitramfs` shows `sctp` in
  the initrd (the module is not in it on the 26.04 reference host).

### A.3 What the kit sees, step by step

| Step | Signal | Source | Detects | Blocks |
|------|--------|--------|---------|--------|
| Vulnerable and exposed | package older than its fix; HTTP/2, h2c, HTTP/3, mail or resolver plus subrequest in the config | `edr-inventory` (§4.5.1) | strong | no |
| Delivery (HTTP/2 inside TLS) | nothing on the wire: TLS hides the frames ([Censys](https://censys.com/blog/nginx2root-simple-test)); ET Open has no rule ([ET](https://rules.emergingthreats.net/open/suricata-8.0.0/emerging-all.rules)); access logs miss `WINDOW_UPDATE` and `RST_STREAM` | none | none | no |
| Delivery over cleartext h2c | a plain-port listener with HTTP/2 is visible to Suricata (Censys's cleartext-h2c rule, SID 9007015, could apply) | Suricata | to confirm | no |
| Heap corruption (123007) | one :443 connection carrying gigabytes (volumes per stage: §4.2) | nft `edr-bigconn` (§4.2) | heuristic | no |
| Attempts and crashes | `exited on signal 11` or `6`, glibc heap-abort text, `could not cancel … resolving` (unpatched only), `client violated connection flow control` (`info` log, §4.5) | agent, nginx error log | weak ([CERT-EU](https://cert.europa.eu/publications/security-advisories/2026-022/)) | no |
| Commands run as the worker | any exec by an nginx process other than its own binary upgrade; Xint calls it the clearest sign | Tetragon `nginx-exec`, `web-exec` (§4.3) | strong | yes (enforce mode) |
| Payload, callback | `.php` writes, execs from `/tmp` or `/dev/shm`, unusual outbound port, refused DNS query from the web user | `web-write-code`, `suspicious-exec`, `web-connect`, DNS lock log | medium | partly |
| Root through SCTP | an SCTP socket opened; the `sctp` module loading | `sctp-socket`, `monitor-kernel-modules` (§4.3) | yes | yes (`sctp-socket` Sigkill; the module block in §7 is a second layer and does nothing if SCTP is built in) |
| Goes to root | uid 0 transition from a web process tree | Tetragon `privilege-escalation` | partial | no |
| Fix installed but not running | an nginx process (master or draining worker) still runs the old binary | `edr-inventory` | strong | no |

- **Old nginx process (`deleted_exe`, §4.5.1).** After the USN update the Ubuntu package does a binary upgrade (postinst runs
  `invoke-rc.d nginx upgrade`, falling back to `restart`; the init script's `upgrade_nginx` sends USR2, then QUIT to
  the old master; see the [Ubuntu packaging](https://git.launchpad.net/ubuntu/+source/nginx)). A restart is needed
  only while `edr-inventory` still reports an old process. A module-package trigger only reloads and never replaces
  the binary. Old workers keep existing HTTP/2 connections, still running the vulnerable code. The 1 h threshold is
  nginx's `keepalive_time` default. The `(deleted)` test is sound because dpkg replaces `/usr/sbin/nginx`.

### A.4 What the operator does

The kit reports exposure but never changes nginx's version or config. The installer and `edr-check` print the matching
row.

| Action | Covers | Notes |
|--------|--------|-------|
| Install the USN-9159-1 package, or nginx.org 1.30.7+ / 1.31.9+ | all five, plus 118899 | nginx.org builds: stable under `/packages/ubuntu/`, mainline under `/packages/mainline/ubuntu/` ([nginx.org](https://nginx.org/packages/mainline/ubuntu/pool/nginx/n/nginx/)) |
| Check that the old processes are gone; restart (`nginx -t && systemctl restart nginx`) only if any remain | all five | `nginx -s reload` never loads a new binary. See `deleted_exe` (§4.5.1) and the stale-binary note in A.3 above. |
| **Noble (1.24):** remove `http2` from every `listen` for that address:port | 123007, 123633 | `http2 off;` is a config error on 1.24 (no such directive); `nginx -t` first |
| **Resolute (1.28):** remove the `http2` parameter from every `listen` for that address:port, and put `http2 off;` in every server block sharing it (or in `http {}` if no site needs h2); `nginx -t` first | 123007, 123633 | A leftover `listen 443 ssl http2;` keeps HTTP/2 on whatever `http2 off;` says. Gives up gRPC and HTTP/2 clients ([site](https://nginx2root.com/)). Treat as a reachability mitigation only; it does not help against the other three ([Tenable](https://www.tenable.com/blog/nginx2root-cve-2026-123007-frequently-asked-questions-about-five-critical-nginx)). |
| Remove `quic` listens, set `http3 off;` and `add_header Alt-Svc 'clear' always;`, optionally drop UDP/443 | 121810 | Resolute only. Check with `ss -lunp 'sport = :443'` ([Xint](https://xint.io/blog/nginx2root-remote-code-execution)) |
| Use a fixed `upstream` group instead of a variable `proxy_pass` with `resolver` | 123634 | The real fix. `mirror_request_body on` is not a fix, although it stopped Xint's exploit. `mirror off;` is already the default. |
| Bind mail listeners to loopback (`listen 127.0.0.1:143;`) or firewall them to trusted IPs | 113425 | |
| `install sctp /bin/false` in `/etc/modprobe.d/` (the installer does this, §7) | both SCTP bugs | Does not unload a loaded module or affect built-in SCTP. Install the kernel update for CVE-2026-64564 and reboot. |
| A CDN or load balancer that terminates HTTP/2, talks HTTP/1.1 to nginx, and blocks direct access to the origin | 123007, 123633 | URL or body WAF rules and TLS passthrough do not help ([site](https://nginx2root.com/)). See the IP-ban caveat in §12. |

Check from outside that HTTP/2 is off, both ways:

    openssl s_client -connect HOST:443 -servername HOST -alpn h2 </dev/null 2>&1 | grep -F 'ALPN protocol: h2'
    curl -sI --http2-prior-knowledge http://HOST/ -o /dev/null -w '%{http_version}\n'

- No output from the first counts only if the TLS handshake itself succeeded ([site](https://nginx2root.com/)).
- The second finds cleartext h2c: a result of `2` means h2c is on. A `listen` without `ssl` that has the `http2`
  parameter, or `http2 on` in `http {}`, makes a plain port an h2c listener. Check every server block that shares
  the address and port; the directive is read from the default or the SNI-selected server.
- Confirm in the VM test that the h2c check returns `2` on a seeded h2c listener and `0` (curl exit 16) on a clean one.

Don't count on ASLR as a mitigation. The CVE records list "ASLR disabled or bypassed" as a condition for code
execution ([CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-123007)), but Rapid7 published a working proof of
concept and Censys reproduced code execution in a lab
([Censys](https://raw.githubusercontent.com/Censys-Research/nginx2root/main/evidence/cve-2026-123007/RCE-CONFIRMED.md)).

---

## Appendix B: Event schema

The one definition of an event, the severity scale and the kind names (agent: §4.5; hub: §3, Appendix A).

**Event fields** (JSON; times are RFC 3339 UTC strings with milliseconds and `Z`)

| Field | Type | Limit | Meaning |
|-------|------|-------|---------|
| `v` | int | | Schema version of this event (rule below) |
| `agent_ver` | string | 32 | Agent version |
| `boot_id` | string | 36 | `/proc/sys/kernel/random/boot_id` at the time of the event |
| `id` | string | 80 | `<epoch>:<seq>`, with no host part: `epoch` is 8 hex digits, `seq` is decimal. The hub takes the host from the certificate and keeps (host, `id`) unique |
| `epoch`, `seq` | int | | The two parts of `id`, sent as integers (`id` writes `epoch` in hex). `epoch` is a random 32-bit value chosen when the spool is created, and changes after any start without a clean-shutdown marker (§4.5); `seq` is a counter within it, persisted in blocks of 1000. A gap inside one epoch is loss |
| `ts` | string | | When the event happened, from the source's own time |
| `sev` | string | | One of INFO, LOW, MEDIUM, HIGH, CRITICAL |
| `kind` | string | 64 | Dotted name from the table below |
| `source` | string | 16 | `tetragon`, `suricata`, `nginx`, `journal`, `kernel`, `inventory`, `agent`, `canary` |
| `summary` | string | 256 | One line for humans, sanitised |
| `details` | object | 4 KiB | Kind-specific fields (each string at most 512); `args` at most 1024, `url` at most 512. A conforming client never sends a serialised event over 5 KiB (the hub refuses one over 10 KiB, hub §2); the agent trims `context` first, then `details`, and sets `truncated` |
| `src_ip`, `dst_ip` | string | | IP literals only; empty when the attribution rules (§4.5) do not allow one |
| `src_trust` | string | | `tcp`: an established flow, or an address the writing daemon recorded and the anchored rules of §4.5 extracted. `claimed`: a header, or any field those rules do not accept (everything when `real_ip` is configured). `none`: no address |
| `dst_port`, `proto` | int, string | | When the source knows them |
| `proc` | object | | `{binary, args, uid, parent}` for process events; arguments redacted |
| `community_id` | string | 64 | Suricata flow id, when present |
| `count`, `first_ts`, `last_ts` | int, string | | Set when repeats were collapsed (§4.5) |
| `context` | array | 4 KiB | Up to 20 redacted access-log entries for `src_ip`, on HIGH and CRITICAL only |
| `redacted`, `truncated` | bool | | Set when the agent removed or cut something |

**Severity scale** (defined here once; the client assigns it and the hub may re-rate it)

| Severity | Meaning |
|----------|---------|
| INFO | Normal fact worth keeping: a login, a reboot, an inventory result. Never notifies |
| LOW | Noise a person may want in a digest: a scanner hit, a failed login, a new source address |
| MEDIUM | Needs a look within a day: a crash, a new key, a stale or missing inventory result |
| HIGH | Needs attention now: evidence of an attempt that may have worked, or lost enforcement |
| CRITICAL | Assume compromise: a blocked exploit chain, a kernel step, a disabled safeguard. Repeats every 30 minutes, at most 3 times, until acknowledged (P3; hub §4) |

**Kind taxonomy**

| Kind | Source | Meaning |
|------|--------|---------|
| `tetragon.<policy>` | Tetragon | A policy hit (`nginx-exec`, `sctp-socket`, `web-exec`, `web-write-code`, `web-connect`, `env-read`, others) |
| `suricata.alert` | Suricata | A rule alert; severity from the rule |
| `nginx.crash` | nginx log | A worker exited on a signal |
| `nginx.marker.<name>` | nginx log | `resolver_cancel`, `conn_exhausted`, `conn_pressure`, `window_update` (§4.5) |
| `ssh.fail`, `ssh.login` | journal | A failed or accepted SSH login |
| `auth.sudo` | journal | A `sudo` use |
| `ban.local` | agent | The agent banned an address (§4.2). `details`: `{cidr, trigger, evidence, ttl_s, rung}`; `evidence` is `tcp` (established flow: Suricata TCP, bigconn) or `log` (an address the anchored rules of §4.5 extracted from an sshd or nginx log field); both carry `src_trust=tcp`, and fleet votes count only these (hub §4) |
| `inventory.<check>` | inventory | A result of an `edr-inventory` check (§4.5.1) |
| `inventory.stale` | agent | The inventory file is missing or over 2 hours old (§4.5) |
| `health.<what>` | agent | `agent_start`, `gap`, `blind_window`, `spool_dropped`, `high_flood`, `sandbox_ineffective`, `tetragon_unreadable`, `tetragon_ratelimit`, `enforcement_gone`, `log_format`, `diskguard`, others |
| `edr.bigconn`, `edr.dnslock`, `edr.egress` | kernel log | The kit's own nftables log lines (§4.2, §4.4) |
| `canary.<name>` | Tetragon, nginx log, agent | `file` (a decoy file was read, Tetragon), `tripwire` (a tripwire path was requested, access log), `policy_check` (INFO: the daily canary result from `edr-policy-check`, agent) |
| `tamper.<what>` | agent, Tetragon | `log_truncated`, writes to the kit's files, others |

**Who sets what**
- **Set by the hub** from the client certificate and its own clock, never from the body: the host identity (UUID and
  name), `received_at`, the clock skew, the corrected `ts`, the `replayed` flag, any re-rating of `sev`, and the
  address the connection came from.
- **Client claims** (everything else): `sev`, `kind`, `src_ip`, `src_trust`, `details`, `proc`, `context`, `count`.
  A compromised client can claim anything, so the hub validates types and limits, escapes every field on display, and
  never makes a fleet-wide decision on one host's claim alone (hub §4).

**Batch envelope.** `POST /v1/events`, gzipped JSON, header `X-EDR-Proto: 1`:

    {"batch_id": "<uuid>", "sent_at": "2026-11-19T10:15:03.120Z", "events": [ ... up to 500 ... ]}

`batch_id` is kept on retry; `sent_at` is stamped on every attempt. The version lives in each event's `v` and in
the `X-EDR-Proto` header. Reply codes: §4.5 and hub Appendix A.

**Schema-version rule.** Adding an optional field or a new `kind` does not change `v`; the hub ignores fields and
accepts kinds it does not know. Removing a field or changing its meaning bumps `v`. The hub accepts the current and
the previous version, answers 422 `schema_too_old` to older events (426 is for an old `X-EDR-Proto`), and upgrades go hub first, then clients (hub §17).

**Example**

    {"v": 1, "agent_ver": "0.1.0", "boot_id": "5b1c...", "id": "7c21b0e4:48213", "epoch": 2082582756, "seq": 48213,
     "ts": "2026-11-19T10:15:02.481Z", "sev": "CRITICAL", "kind": "tetragon.nginx-exec", "source": "tetragon",
     "summary": "nginx worker tried to exec /bin/sh (killed)",
     "proc": {"binary": "/bin/sh", "args": "-c id", "uid": 33, "parent": "/usr/sbin/nginx"},
     "src_trust": "none"}
