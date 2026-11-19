# server_client: design plan

Status: **design only, no code yet.** This document is the plan for the client half of a small, self-hosted
EDR for DigitalOcean web servers. The other half, the hub, is in [`../server_hub/PLAN.md`](../server_hub/PLAN.md).

**Paths:** `server_client/…`, `server_hub/…` and `mock/…` are relative to `server_edr_solution/`. Paths to the
laptop kit this reuses (`install.sh`, `check.sh`, `analyse.py`, `files/`, `tetragon/`, `controld/`, `watch/`,
`tests/`, `Makefile`) are relative to the repository root. A local Docker test bed is in [`../mock/`](../mock/README.md).

---

## 1. What it is

A hardened host kit for **DigitalOcean droplets running Ubuntu 24.04 or 26.04** that serve PHP/Laravel behind
nginx and php-fpm. It installs and tunes:

| Part | Job on a web server |
|------|---------------------|
| **Suricata (IDS)** | Inspects network traffic: scans, exploit attempts on plain HTTP, non-HTTP services, and outbound C2 or coin-miner traffic after a compromise. |
| **nftables ban sets** | Drop known-bad and recently-hostile IPs in the kernel, which is cheap and fails open. |
| **Tetragon** | Records what processes do, and kills an nginx worker that starts a program: php-fpm or nginx starting a shell, www-data writing `.php` files or connecting out, privilege escalation, persistence, tampering. **This is where most web-attack detection happens.** |
| **DNS over HTTPS** | `dnscrypt-proxy` (DoH only) plus the `DNSLOCK` firewall chain, so the box cannot be made to use plain DNS. |
| **`edr-agent`** | A sandboxed, standard-library-only Python process. It reads all of the above and sends compact telemetry to the hub over mutual TLS, then pulls bans and settings back. |

Installing it needs only the hub's address and a one-time token:

    sudo server_client/install.sh --hub 203.0.113.5:8443 --token <token>

Without `--hub`/`--token` it installs in local mode (alerts go to the journal) and can enroll later.

### Feasibility verdict

**Feasible and rational.** It is a lightweight, self-hosted cross between CrowdSec (shared IP bans) and
Wazuh/Falco (host telemetry), built mostly from parts this repo already has and tests. The new work is the
server tuning, the web-specific Tetragon policies, the agent and the hub.

### The one big limit: Suricata can't read HTTPS

nginx terminates TLS **after** the packet has passed Suricata, so for HTTPS traffic Suricata sees only
the encrypted stream: SNI, JA4 fingerprints, sizes and timing, not the URL or body. Exploit payloads
against nginx or PHP sent over HTTPS are **invisible to Suricata**. The design accepts that and
divides the work:

- **Tetragon** catches what an exploit *does*: a shell started from php-fpm, a webshell written, a reverse
  connection, a move to uid 0. That doesn't depend on seeing the request.
- **nginx's own logs** cover what the request *looked like*: a worker crash on signal 11 or 6, scanner paths,
  `.env` and `.git` probes, 4xx bursts. They do **not** record HTTP/2 control frames such as `WINDOW_UPDATE`
  and `RST_STREAM` ([site](https://nginx2root.com/)), so frame-level bugs like NGINX2Root's CVE-2026-123007
  leave at most a crash line, or a flow-control violation line on patched builds.
- **Suricata** covers IP reputation, scans, plain port 80, SSH, other exposed services, DNS, and outbound
  TLS from the box (C2 and miners, by SNI and JA4). It cannot see HTTP/2 frames inside TLS
  ([Censys](https://censys.com/blog/nginx2root-simple-test)), and QUIC encrypts its frames by design. The one network trace of CVE-2026-123007, a
  single connection carrying gigabytes, is counted in nftables instead (§4.2).

### Worked example: NGINX2Root

[NGINX2Root](https://nginx2root.com/) is Xint's name for **five independent nginx memory-safety bugs** and **one
unpatched Linux kernel SCTP bug**. The kernel bug turns code execution in an nginx worker into host root
([Xint](https://xint.io/blog/nginx2root-remote-code-execution)). Each nginx bug is a separate, unauthenticated way
in. Commands then run with the nginx worker's privileges (www-data on Ubuntu).

| Bug | Way in needs | nginx.org affected |
|-----|--------------|--------------------|
| CVE-2026-123007, HTTP/2 flow control | HTTP/2 on. The most exposed, and the only one with a public PoC ([Rapid7](https://github.com/sfewer-r7/CVE-2026-123007)) | 1.9.5–1.31.8 |
| CVE-2026-123633, HTTP/2 use-after-free | HTTP/2 plus `proxy_pass`/`fastcgi_pass`/`grpc_pass`, with the worker low on `worker_connections` ([CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-123633)) | 1.19.7–1.31.8 |
| CVE-2026-123634, resolver use-after-free | `resolver` plus a variable `proxy_pass` (e.g. `$host`) plus `mirror` with `mirror_request_body off`, or SSI | 0.6.18–1.31.8 |
| CVE-2026-121810, HTTP/3 use-after-free | HTTP/3 (QUIC) plus an upstream. Not in 24.04's nginx 1.24, which has no HTTP/3 ([Ubuntu](https://ubuntu.com/security/CVE-2026-121810)) | 1.25.0–1.31.8 |
| CVE-2026-113425, mail proxy use-after-free | a `mail {}` block with `proxy on` plus `auth_http`; no credentials needed | 0.5.33–1.31.8 |
| Kernel SCTP send path (no CVE, **no patch yet**) | the `sctp` module loadable; Linux 4.15 or later | — |

The ranges come from [nginx.org](https://nginx.org/en/security_advisories.html) and the preconditions from Xint.
Upstream fixed all five in **1.31.9 (mainline) and 1.30.7 (stable)** on 18 Nov 2026. Ubuntu fixed them in
[USN-9159-1](https://ubuntu.com/security/notices/USN-9159-1): noble `1.24.0-2ubuntu7.20`, resolute `1.28.3-2ubuntu1.13`.
As of 19 Nov 2026 no in-the-wild exploitation had been reported, and none of the CVEs was in CISA KEV
([Precursor](https://www.precursorsecurity.com/blog/nginx2root-critical-nginx-rce-vulnerabilities)).

| Step | Signal | Source | Strength |
|------|--------|--------|----------|
| Vulnerable and exposed | package older than its advisory; HTTP/2, HTTP/3, mail or resolver+mirror in the config | `edr-inventory` (§4.5.1) | strong |
| Delivery (HTTP/2 frames inside TLS) | **nothing on the wire.** TLS hides the frames ([Censys](https://censys.com/blog/nginx2root-simple-test)), ET Open has no rule ([ET](https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules)), and access logs don't fully record `WINDOW_UPDATE`/`RST_STREAM` ([site](https://nginx2root.com/)) | — | none |
| Heap corruption (CVE-2026-123007) | one :443 connection carrying gigabytes; Rapid7's exploit needs about 128 GB ([Rapid7](https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/)) | nft `edr-bigconn` (§4.2) | medium (heuristic) |
| Attempts and crashes | `exited on signal 11` or `6`, `double free detected`; `could not cancel … resolving` (unpatched only); on patched builds, `client violated connection flow control` (needs `info` logging, §4.5) | agent: nginx error log | weak: crashes are low-fidelity ([CERT-EU](https://cert.europa.eu/publications/security-advisories/2026-022/)) |
| Commands run as the worker | **any** exec by an nginx worker, which Xint calls the clearest sign of success | Tetragon `nginx-exec` (Sigkill), `web-exec` | strong |
| Payload, callback | `.php` writes, execs from `/tmp` or `/dev/shm`, an unusual outbound port, a refused DNS query from www-data | `web-write-code`, `suspicious-exec`, `web-connect`, DNSLOCK log | medium |
| Root through SCTP | an SCTP socket opened; the `sctp` module loading | modprobe block (§7); Tetragon `sctp-socket`, `monitor-kernel-modules` | blocked if SCTP is a module; detect-only if built in |
| Goes to root | uid 0 transition from a www-data process tree | Tetragon `privilege-escalation` | partial: a kernel exploit can blind eBPF |
| Fix installed but not running | an nginx process (master or a draining worker) still runs the pre-upgrade binary | `edr-inventory` | strong |

The earlier example, CVE-2026-42945 ("NGINX Rift"), follows the same chain and leaves the same signals.

### NGINX2Root: what the operator does

The kit reports exposure but never changes nginx's version or config. The installer and `check.sh` print the matching row.

| Action | Covers | Notes |
|--------|--------|-------|
| Install the USN-9159-1 package, or nginx.org 1.30.7+ / 1.31.9+ | all five | nginx.org builds: stable under `/packages/ubuntu/`, mainline under `/packages/mainline/ubuntu/` ([nginx.org](https://nginx.org/packages/mainline/ubuntu/pool/nginx/n/nginx/)). Whether Ondrej's PPA has the fix is unknown. |
| **Restart** nginx afterwards (`nginx -t && systemctl restart nginx`) | all five | `nginx -s reload` does not load the new binary. Old "worker process is shutting down" workers keep existing HTTP/2 and mail sessions ([Xint](https://xint.io/blog/nginx2root-remote-code-execution)). |
| `listen 443 ssl;` plus `http2 off;` (1.25.1+), or remove `http2` from `listen` (1.9.5–1.25.0); then wait for old HTTP/2 connections to end | 123007, 123633 only | Clients that need HTTP/2, such as gRPC, will break ([site](https://nginx2root.com/)). Does not help against the other three ([Tenable](https://www.tenable.com/blog/nginx2root-cve-2026-123007-frequently-asked-questions-about-five-critical-nginx)). |
| Remove `quic` listens, set `http3 off;` and `add_header Alt-Svc 'clear' always;`, optionally drop UDP/443 | 121810 | Check with `ss -lunp 'sport = :443'` ([Xint](https://xint.io/blog/nginx2root-remote-code-execution)) |
| Use a fixed `upstream` group instead of a variable `proxy_pass` with `resolver`; set `mirror off;` where mirroring isn't needed | 123634 | `mirror_request_body on` stopped Xint's exploit but does not fix the bug. SSI can also reach it. |
| Bind mail listeners to loopback (`listen 127.0.0.1:143;`) or firewall them to trusted IPs | 113425 | |
| `install sctp /bin/false` in `/etc/modprobe.d/` (the installer does this, §7) | kernel step | Does not unload a loaded module or affect built-in SCTP. Install the kernel fix when it ships. |
| A CDN or load balancer that terminates HTTP/2, talks HTTP/1.1 to nginx, and blocks direct access to the origin | 123007, 123633 | URL or body WAF rules don't help, and TLS passthrough doesn't help ([site](https://nginx2root.com/)). See the IP-ban caveat in §12. |

To check from outside that HTTP/2 is off:

    openssl s_client -connect HOST:443 -servername HOST -alpn h2 </dev/null 2>&1 | grep -F 'ALPN protocol: h2'

No output counts only if the TLS handshake itself succeeded ([site](https://nginx2root.com/)).

Don't count on ASLR as a mitigation. The CVE records list "ASLR disabled or bypassed" as a condition for code
execution ([CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-123007)), but Rapid7 published a working PoC and
Censys reproduced code execution in a lab
([Censys](https://raw.githubusercontent.com/Censys-Research/nginx2root/main/evidence/cve-2026-123007/RCE-CONFIRMED.md)).

---

## 2. Principles

1. **The website always wins.** Every part fails open: if Suricata, Tetragon, the agent or the hub goes
   down, nginx keeps serving. No packet is ever queued to user space. The deliberate exceptions act on
   processes and known-bad IPs, not on normal requests:
   - the Tetragon `Sigkill` policies: `nginx-exec` (a process forked from an nginx worker trying to start a
     program, which a healthy worker never does), `sctp-socket` (any process without `CAP_SYS_ADMIN`), and
     `web-exec` once `--enforce` is set;
   - the nftables ban sets, which are in-kernel and simply expire if the agent stops;
   - the opt-in `--cap-conn-bytes` drop (§4.2).
   Monitoring processes run at lower CPU priority than nginx and php-fpm.
2. **The client pulls; the hub never pushes.** The agent connects out to the hub. The hub never connects
   to clients, and there is **no remote command execution**. The most a compromised hub can do is send
   bans, and the client checks those against a list of addresses it will never ban (§4).
3. **Least privilege.** The agent runs as its own unprivileged user, with no capabilities, and can reach
   only the hub's IP. The two root steps, applying bans (`edr-bans`) and reading root-only state
   (`edr-inventory`), are separate small sandboxed units with fixed inputs and outputs.
4. **Bounded resources.** Every log and spool has a size cap and every service a CPU or memory budget
   (§9). The kit cannot fill the disk.
5. **The repo is the source of truth**, as for the laptop kits. Installers are re-runnable, test changes
   before committing them, and roll back on failure.

---

## 3. Architecture

```
 droplet (this kit)                                                hub (../server_hub)
 ┌──────────────────────────────────────────────────────────┐     ┌──────────────────────────┐
 │ nginx / php-fpm / Laravel                                 │     │ edr-hub  :8443 (mTLS)    │
 │                                                           │     │  SQLite, correlation,    │
 │ Suricata IDS (af-packet) ──► eve.json ──────┐             │     │  alerts, IP feeds        │
 │ Tetragon (server policies) ──► tetragon.log ┼─► edr-agent ├────►│ POST /v1/events          │
 │ nginx error.log / access.log ───────────────┘  (no root,  │◄────┤ GET  /v1/policy (bans)   │
 │                                               hub IP only)│     │                          │
 │ nftables inet edr {edr_ban*, edr_feed*} ◄── edr-bans ◄────┘     │ edr-hub-ui :8450 (local) │
 │ dnscrypt-proxy 127.0.2.1 (DoH) + DNSLOCK chain             │     └──────────────────────────┘
 └──────────────────────────────────────────────────────────┘
```

---

## 4. Components

### 4.1 Suricata, server profile

| Setting | Server value | Laptop kit, for comparison |
|---------|--------------|----------------------------|
| Mode | **af-packet IDS** on the public interface | NFQUEUE inline (`-q 0`), `fail-open: no` |
| Runmode / threads | `workers`, `threads: 1` (2 on 4+ vCPU) | default / `auto` |
| Priority | `Nice=10`, `CPUWeight=50` | default |
| `detect.profile` | `low` | `medium` |
| `mpm-algo` | `hs` (Hyperscan; DO CPUs have AVX2), `auto` as fallback | `auto` |
| Memcaps (≤ 2 GB droplet) | stream 32M, reassembly 128M, flow 64M | 64M / 256M / 128M |
| HOME_NET | Set once at install: public IPv4, the IPv6 /64, the VPC range | Recomputed by `suricata-home-net.sh` + NetworkManager hook |
| Rules | ~30–40k (§4.1.1) | ~110k |

Reuse from the laptop kit:

- The **candidate, test, commit or roll back** install pattern in `install.sh`: the `on_exit` trap
  (`install.sh:62-95`), `suricata -T` against the candidate (`install.sh:186`), then the move into place
  (`install.sh:203-204`).
- The systemd override's hardening and `Restart=always`/`RestartSec=1` from `files/suricata-override.conf`,
  minus `-q 0`.
- The daily, sandboxed rule update (`files/suricata-rules-update.{service,timer}`), which tests and
  reloads live.
- `files/suricata.apt-pin` and the OISF PPA logic (Suricata 8.x).
- `drop.conf`/`modify.conf`/`disable.conf` as the tuning surface. In IDS mode "drop" means "high priority alert",
  and the agent turns those into local bans (§4.2).

Not reused: `files/suricata-nfqueue-apply.sh`, `suricata-nfqueue.service`, `suricata-home-net.*` and
`90-suricata-home-net`, which are inline-mode and laptop specific.

#### 4.1.1 Ruleset

- **Sources:** `et/open`, `abuse.ch/sslbl-blacklist` (C2 certificates), `abuse.ch/urlhaus`.
- **Keep:** web_server, web_specific_apps (PHP, Laravel, WordPress-style exploits), exploit, attack_response,
  scan, malware, coinminer, hunting, ssh-related rules.
- **Disable:** games, chat, p2p, mobile_malware, scada, activex, retired, and the desktop-oriented policy and
  info categories.
- **Moved out of Suricata:** the IP-reputation groups (`ciarmy`, `compromised`, `drop`, Feodo IPs). As
  rules they cost memory and only alert; as nftables sets fed by the hub (§4.2) they cost almost
  nothing and actually block.
- **Expected:** ~30–40k rules, ~400–600 MB RSS, ~20 s load. `--lite` (1 GB droplets): ~15k rules, alerts only.

#### 4.1.2 eve.json output

| Type | Setting | Why |
|------|---------|-----|
| alert | on, payload ≤ 4 KiB, `community-id` | The core signal; the payload helps triage |
| drop, anomaly | on (anomaly app-layer only) | Rare and useful |
| http | on (port 80 only, extended) | Scanner and exploit visibility on plain HTTP |
| tls | on (SNI, JA4) | Outbound C2 and miner detection; inbound fingerprints |
| dns | on (queries the box makes) | Post-compromise lookups (should be rare: DoH) |
| ssh | on | Brute force and client fingerprints |
| stats | every 300 s | Health: kernel drops, memcaps |
| **flow, netflow, files, file-store** | **off** | On a busy web server these are most of the disk and CPU cost of logging |

### 4.2 Blocking: nftables ban sets

- **Table and sets**
  - A table of its own, `inet edr`, with a `filter` chain on the `input` hook at priority -200, so it runs
    before UFW and anything DigitalOcean adds, and never edits their rules.
    This is the same "chain of its own" approach as `SURICATA-NFQ`.
  - `edr_ban4` and `edr_ban6`: `flags interval, timeout`, so an entry can be an IP or a CIDR (the hub bans
    CIDRs) and each ban expires by itself.
  - `edr_feed4` and `edr_feed6`: `flags interval`, bulk CIDR feeds from the hub (FireHOL level1, Spamhaus
    DROP/EDROP, abuse.ch Feodo IPs). The feeds overlap and nft rejects overlapping intervals, so `edr-bans`
    merges each family with Python's `ipaddress.collapse_addresses()` before writing the script.
  - The rules are `ip saddr @edr_ban4 drop`, `ip saddr @edr_feed4 drop`, and the IPv6 equivalents. Per-set
    counters feed the heartbeat. The agent can't read nftables (that needs `CAP_NET_ADMIN`), so `edr-bans`
    writes `nft -j list table inet edr` counters and element counts to `/run/edr-bans/counters.json` after each
    apply and from a 60 s timer, and the agent reads that file.
- **How a ban is applied.** The unprivileged agent decides; root applies:
  1. The agent writes the full desired state to `/run/edr-agent/bans.json`.
  2. `edr-bans.path` (a systemd path unit) starts `edr-bans.service` (a root oneshot, sandboxed:
     `CapabilityBoundingSet=CAP_NET_ADMIN`, no network sockets except netlink, read-only filesystem).
  3. `edr-bans` **validates** every entry:
     - it parses as an IP or CIDR;
     - there are at most 10k bans and 200k feed CIDRs;
     - it does not **contain or overlap** any **never-ban** entry (a `/8` that includes the hub IP is refused): the hub IP, the `--admin-ip` CIDRs, `169.254.169.254`
       (DO metadata), the default gateway, RFC 1918/ULA/loopback/link-local, the VPC range, or the droplet's
       own addresses.
  4. It writes one nft script and applies it with `nft -f` (atomic: all or nothing).
- **Local auto-bans** work with no hub:
  - SSH brute force (Suricata `ssh` events plus `sshd` journal failures).
  - High-priority Suricata alerts from an external source.
  - nginx scanner bursts (§4.5).
  - Repeated NGINX2Root attempts: `client violated connection flow control: received WINDOW_UPDATE frame with
    window increment` from one IP 3 or more times in 10 minutes, and a repeat `edr-bigconn` from the same IP.
    Patched builds log the WINDOW_UPDATE line when they reject the exploit's window pattern; unpatched builds log
    it only for a plain window overflow, which the exploit avoids. It is logged at `info`, so this trigger needs
    the extra log described in §4.5 ([nginx source](https://raw.githubusercontent.com/nginx/nginx/release-1.31.9/src/http/v2/ngx_http_v2.c)).
  - The ban TTL starts at 1 h, then 6 h, then 24 h for repeat offenders, remembered for 7 days.
- **Large-connection watch (NGINX2Root, CVE-2026-123007).** Rapid7's public exploit needs about 128 GB of
  HTTP/2 data over one long-lived connection, roughly 17 minutes at 1 Gbit/s
  ([Rapid7](https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/)).
  A Laravel site almost never moves gigabytes over one client connection.
  - A second chain, `bigconn`, in `inet edr` at `priority filter`, which runs after conntrack at -200. A sysctl
    drop-in sets `net.netfilter.nf_conntrack_acct=1`. One rule logs each connection once, using a conntrack
    mark instead of a global rate limit (which would hide a second offender in the same minute):
    `tcp dport 443 ct bytes > 4294967296 ct mark and 0x100 == 0 ct mark set ct mark or 0x100 log prefix "edr-bigconn: "`.
  - It counts both directions (`ct bytes`), because the sources don't agree on which side of the
    connection carries the bulk of the data. Large legitimate downloads (backups, video) can trip it;
    allowlist those paths or IPs.
  - The agent reads these lines from the kernel journal (§4.5) and reports the source IP.
  - Off by default: `--cap-conn-bytes 16G` adds a separate rule with no rate limit,
    `tcp dport 443 ct bytes > CAP reject with tcp reset`. (A `limit` in front of a drop would only drop about one
    packet a minute.) That defeats Rapid7's
    strategy but not the bug, and other strategies may need less data.
  - The rule loads conntrack if nothing else has. Measure its memory cost in the VM test.
  - Log only by default, so it fails open; the opt-in cap is the only drop.
- **Uninstall and failure:** deleting the `inet edr` table removes every ban at once. If `edr-bans` fails,
  the last good state stays in place until each entry times out.

### 4.3 Tetragon, server policy set

Installed with the laptop kit's machinery: `tetragon/local_install.sh` and `tetragon/config.sh`, which pin
`TETRAGON_VERSION` (currently v1.7.1) and its checksums, plus the boot gate and the journal copy of policy
hits. **Check that this version supports Ubuntu 26.04's kernel (7.0) before relying on it.** BTF must be
present (`/sys/kernel/btf/vmlinux`).

New, web-specific policies in `server_client/tetragon/policies/`:

| Policy | Logs | Notes |
|--------|------|-------|
| `web-exec` | php-fpm, nginx or any www-data process exec'ing a shell, interpreter or network tool (`sh`, `bash`, `dash`, `curl`, `wget`, `nc`, `ncat`, `socat`, `python*`, `perl`, `base64`, `chmod`…) | The main PHP-to-shell and webshell detector. Per-site allowlist for legitimate `proc_open` use (ImageMagick, ffmpeg, wkhtmltopdf, git for deploy hooks). |
| `web-write-code` | www-data writing `*.php`, `*.phar`, `.htaccess`, `.user.ini` under the web roots | Excludes Laravel's `storage/framework/views` (compiled Blade) and `bootstrap/cache`. |
| `web-connect` | php-fpm or nginx opening outbound TCP to ports **other than** 80, 443, 3306, 5432, 6379, 11211, 25, 465, 587 | Catches reverse shells. Ports can be set per site. |
| `env-read` | Laravel `.env` files read by anything other than php-fpm, `php artisan` or their owner | SSH keys and `/etc/shadow` stay with the reused `sensitive-files` policy below. |
| `nginx-exec` | **any** `execve`/`execveat` by an nginx worker: `matchBinaries` = the nginx binary, and `matchCapabilities` Effective NotIn `CAP_SYS_ADMIN`, which leaves out the root master's re-exec during a binary upgrade | nginx workers never start programs. Xint calls a program started by a worker "the clearest sign" of a successful attack ([Xint](https://xint.io/blog/nginx2root-remote-code-execution)). No allowlist. On Ubuntu, nginx workers and php-fpm pools both run as www-data, so this policy keys on the binary, not on the uid as Xint's auditd rule does. **Ships with `Sigkill`.** |
| `sctp-socket` | `security_socket_create` with protocol 132 (`IPPROTO_SCTP`), from any process | Web droplets don't use SCTP, and NGINX2Root's root step goes through it. It matches both forms: protocol 132, and `SOCK_SEQPACKET` with protocol 0, which the kernel turns into SCTP when the module is loaded or built in. The hook fires before the kernel tries to load the module, so it also catches attempts when the module is blocked (§7) or SCTP is built in. **`Sigkill`** for processes without `CAP_SYS_ADMIN`; log only for root. |

Sketch of `sctp-socket` (confirm the hook and selector syntax against the pinned v1.7.1):

    kprobes:
    - call: security_socket_create
      syscall: false
      args: [{index: 0, type: int}, {index: 1, type: int}, {index: 2, type: int}]
      selectors:
      # explicit protocol 132 (IPPROTO_SCTP)
      - matchArgs: [{index: 2, operator: Equal, values: ["132"]}]
        matchCapabilities: [{type: Effective, operator: NotIn, values: ["CAP_SYS_ADMIN"]}]
        matchActions: [{action: Sigkill}]
      - matchArgs: [{index: 2, operator: Equal, values: ["132"]}]
      # implicit form: AF_INET/AF_INET6 + SOCK_SEQPACKET (5) + protocol 0
      - matchArgs: [{index: 0, operator: Equal, values: ["2", "10"]}, {index: 1, operator: Equal, values: ["5"]},
                    {index: 2, operator: Equal, values: ["0"]}]
        matchCapabilities: [{type: Effective, operator: NotIn, values: ["CAP_SYS_ADMIN"]}]
        matchActions: [{action: Sigkill}]
      - matchArgs: [{index: 0, operator: Equal, values: ["2", "10"]}, {index: 1, operator: Equal, values: ["5"]},
                    {index: 2, operator: Equal, values: ["0"]}]

The hook gets the type with `SOCK_NONBLOCK`/`SOCK_CLOEXEC` already masked off. Four selectors stay within
Tetragon's limit of five per hook (`make lint` checks it). Check the first-match semantics on the pinned version.

**Worker fork watch (log only).** `nginx-exec` kills the process that tries to exec. Payloads usually fork first
(`system()`, `popen`), so the forked child dies and the compromised worker survives; that is why the hub alert
says "restart nginx". nginx workers never fork, so a log-only hook on `security_task_alloc` for the nginx binary
(without `CAP_SYS_ADMIN`, ignoring `CLONE_THREAD` so its aio thread pool is not flagged) records the fork itself.
It ships log-only. Switch it to `Sigkill` (which would evict the worker) only after it has been quiet on real hosts.

Reused from `tetragon/policies/`:

| Policy | Change |
|--------|--------|
| `privilege-escalation`, `setuid-files`, `kernel-tampering`, `tetragon-tamper` | none |
| `sensitive-files` | keep `/etc/shadow`, sudoers, SSH host and user keys, cloud credentials; remove the desktop entries (browser profiles, keyrings, GPG). This keeps `tetragon/check.sh --canary` (a root read of `/etc/shadow`) working. |
| `monitor-kernel-modules` | Tag loads of `sctp` (and other protocol modules this host never uses) so the agent rates them HIGH. Xint published no kernel-side indicators for the SCTP bug, so watching for a module load is our inference, not a published IOC ([Xint](https://xint.io/blog/nginx2root-remote-code-execution)). |
| `persistence` | remove desktop autostart; add every user's `authorized_keys`, `/etc/ld.so.preload`, `/var/spool/cron` |
| `suspicious-exec` | add `/tmp` and `/var/tmp` (in addition to `/dev/shm` and fileless execs) |
| `stack-tamper` | point it at this kit's paths: Suricata, `/etc/edr-agent`, the `edr-*` units, nft and dnscrypt config |
| `tcp-listen` | keep, with nginx, php-fpm, sshd, mysqld, postgres, redis and the agent ignored |

Dropped: `device-access` (no devices on a droplet) and the all-process `tcp-connect` (far too noisy on a
web server; `web-connect` replaces it).

**Enforcement.** `nginx-exec` and `sctp-socket` ship with `Sigkill` in P1 (`install.sh --observe-only` turns
them back to logging). Neither can fire on a normal nginx/php-fpm/Laravel droplet. Sigkill kills the process
making the call: the worker itself, or a child it forked. When a worker dies, the master starts a new one.
Sigkill stops the exec, not code already running inside other workers, so the hub alert says "restart nginx". `web-exec` (php-fpm) ships
observe-only. `install.sh --enforce` switches it to Sigkill once a week of logs has shown no false positives.
That **stops** PHP-to-shell instead of reporting it.

**Volume control:**
- Keep the `PROCESS_EXIT` denylist line from `tetragon/export-denylist.jsonl`.
- Denylist the routine execs: `php artisan schedule:run` from cron, queue workers started by supervisor or
  systemd. Each line is tied to a root-owned parent, per the existing lint rule.
- `export-rate-limit` caps events per minute. Every policy keeps `rateLimit` per process.

### 4.4 DNS over HTTPS, without ctrld

- **Resolver:** `dnscrypt-proxy` (Ubuntu universe), with `doh_servers = true`, `dnscrypt_servers = false`,
  `require_dnssec = true`, a short list of chosen DoH servers (e.g. Quad9 and Cloudflare), listening on
  `127.0.2.1:53`. It runs in its own sandboxed unit.
- **System:** a systemd-resolved drop-in, `DNS=127.0.2.1` and `Domains=~.`, which overrides the DigitalOcean
  resolvers that netplan and cloud-init set. The stub at `127.0.0.53` stays, so nothing else changes.
- **Lockdown:** reuse the `DNSLOCK` chain from `controld/files/dns-lockdown.sh` (`build_filter`):
  - refuse 53 and 853 off-box, and 443 to public DoH resolver IPs;
  - change the cgroup exemption from `ctrld.service` to `dnscrypt-proxy.service`;
  - log each refusal before it happens: in the iptables chain, `-m limit --limit 6/min -j LOG --log-prefix
    "edr-dnslock: " --log-uid` ahead of each `REJECT`. The equivalent in nft is `log flags skuid`.
    A refused lookup owned by www-data means a web process tried to use a resolver of its own, which is a
    post-exploit sign ([Precursor](https://www.precursorsecurity.com/blog/nginx2root-critical-nginx-rce-vulnerabilities)).
    This only catches direct queries to an outside resolver. A payload that resolves through the system
    resolver (`127.0.0.53`) is allowed and not logged. The agent reads these lines from the kernel journal.
  - drop the captive-portal `pause`, which is laptop only.
- **Resolver list:** reuse `controld/files/doh-resolvers.conf` and `controld/files/dns-lockdown-rules.sh`
  for the Suricata SNI rules, **minus the hostnames and IPs of the DoH servers dnscrypt-proxy itself uses**,
  or the box would block its own resolver.
- **Fail-open check,** as in `controld/install.sh`: before locking, confirm that resolution works through
  `/etc/resolv.conf`. If it doesn't, don't lock, and report the problem. `--no-dns-lockdown` skips this part.

### 4.5 `edr-agent`

One Python file using only the standard library (`agent/edr-agent.py`), like `analyse.py`, so there is
nothing to `pip install`. Until it is enrolled it runs in **local mode**: everything below except the transport,
with alerts written to the journal. That is how P1 works with no hub.

**Inputs**

| Source | How | Becomes |
|--------|-----|---------|
| Tetragon `/var/log/tetragon/tetragon.log` | Tail; follow rotation by inode | Policy hits, fileless execs, execs by web users |
| Suricata `/var/log/suricata/eve.json` | Tail; on start, read back to the last checkpoint (the `ReverseFile` approach from `analyse.py`) | Alerts, drops, anomalies, SSH, outbound TLS of interest, stats |
| nginx `error.log` (and the `nginx` unit's journal) | Tail | Worker crashes (`exited on signal 11/6`, glibc's `double free detected`, which in Censys's lab appeared just after a successful command ([Censys](https://raw.githubusercontent.com/Censys-Research/nginx2root/main/evidence/cve-2026-123007/RCE-CONFIRMED.md))); upstream errors. NGINX2Root markers, with the `client:` IP where present. At nginx's default `error` level (Ubuntu's `nginx.conf` sets no level) only one reaches the log: `could not cancel … resolving` is ALERT on vulnerable builds and debug-only once fixed, so it means an **unpatched** host hit the CVE-2026-123634 path. The other two need a lower level: `client violated connection flow control: received WINDOW_UPDATE frame with window increment` is `info`, and `worker_connections are not enough, reusing connections` (CVE-2026-123633 pressure) is `warn` ([nginx source](https://raw.githubusercontent.com/nginx/nginx/release-1.31.9/src/http/v2/ngx_http_v2.c)). The kit never edits nginx config, so `check.sh` reads the effective `error_log` level and, if it is above `info`, WARNs and suggests adding `error_log /var/log/nginx/edr.log info;`, which the agent then tails too. |
| Kernel journal | `journalctl -k -f`, lines starting `edr-` | `edr-bigconn` (§4.2) and `edr-dnslock` (§4.4) events |
| nginx `access.log` | Tail, **counters only**, never raw lines | Per-IP 4xx rates, scanner paths, `.env`/`.git`/`wp-login` probes, scanner user agents |
| `sshd` (journal) | `journalctl -f` on `ssh.service` | Failed and accepted logins |
| Inventory (hourly, and after every apt run) | Reads `/run/edr-inventory/inventory.json` from the root `edr-inventory` oneshot (§4.5.1); plus `php -v`, `uname -r`, `/var/lib/update-notifier`, `/run/reboot-required` | Full package versions, nginx exposure, stale nginx binary, SCTP state, pending updates, reboot needed |
| Heartbeat (60 s) | Service states, disk, load, memory, Suricata kernel drops, nft counters (from `/run/edr-bans/counters.json`) | Health |

**Processing**
- Reuse from `watch/files/tetragon-notify.py`: `describe()` and `detail()` to summarise Tetragon events,
  the regex ignore list, `(policy, binary)` dedup and the burst limiter.
- Normalise everything to one event shape:
  `{ts, host, source, severity, kind, summary, details (≤ 4 KiB), community_id?, src_ip?}`.
- Severity is assigned on the client and can be re-rated by the hub.
- Local decisions: auto-bans (§4.2) and the disk guard (§9).

**Transport**
- `POST /v1/events`: batches of up to 500 events or 5 s, gzipped JSON, over **mutual TLS 1.3**: the
  hub CA is pinned (`/etc/edr-agent/ca.pem`) and the client presents its own certificate.
- Exponential backoff with jitter, capped at 5 minutes.
- **Spool** at `/var/lib/edr-agent/spool/`, capped at **50 MB**. When it is full, drop the oldest
  low-severity events first; HIGH and CRITICAL are kept the longest.
- `GET /v1/policy` every 60 s returns bans, feed sets, ignore rules and thresholds, with an ETag so an
  unchanged policy costs one small request.
- `POST /v1/heartbeat` every 60 s. A missing heartbeat is itself an alert on the hub.

**Sandbox** (`edr-agent.service`)

    User=edr-agent
    SupplementaryGroups=suricata adm          # eve.json, nginx logs
    CapabilityBoundingSet=
    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    PrivateTmp=yes
    PrivateDevices=yes
    ProtectKernelTunables=yes
    ProtectKernelModules=yes
    ProtectControlGroups=yes
    RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
    IPAddressDeny=any
    IPAddressAllow=<hub IP>                   # written by install/rehome into a drop-in
    MemoryDenyWriteExecute=yes
    SystemCallFilter=@system-service
    MemoryMax=128M
    CPUQuota=10%
    StateDirectory=edr-agent
    RuntimeDirectory=edr-agent
    ReadOnlyPaths=/var/log

The agent has no DNS (it talks to the hub by IP) and no capabilities.

**Access to Tetragon's log.** That log is root-only. Instead of giving the agent `CAP_DAC_READ_SEARCH`,
which could read `/etc/shadow`, the installer makes `/var/log/tetragon` `root:edr-agent` with mode
`2750` (setgid) and sets Tetragon's `export-file-perm` to `640`, so each new and rotated file is
group-readable by the agent only. **Check during implementation that Tetragon's rotation keeps the
group.**

**Tamper resistance:**
- The hub alerts if heartbeats stop.
- Tetragon's `stack-tamper` logs writes to the agent's code, config and units.
- The agent records its own SHA-256 in every heartbeat.

#### 4.5.1 `edr-inventory` (root oneshot)

`nginx -v` is not a vulnerability check. Ubuntu backports fixes without changing it (noble stays `1.24.0`), so
fixes are judged from full package versions ([Xint](https://xint.io/blog/nginx2root-remote-code-execution)). Several
checks need root, and the agent has none, so a small root unit does them and writes a fixed-schema JSON file that the
agent forwards. This is the same split as `edr-bans`.

| Field | How | Why |
|-------|-----|-----|
| `nginx_pkg` | `dpkg-query -W` for `nginx`, `nginx-core/full/light/extras`, plus the origin (Ubuntu, nginx.org, PPA) | The hub compares it with its advisory table (hub §4) |
| `nginx_build` | `nginx -V` (opens nothing): `--with-http_v2_module`, `--with-http_v3_module`, `--with-mail` | Which bug classes are compiled in |
| `nginx_exposure` | Parse `/etc/nginx` following `include`. Not `nginx -T`: even in test mode it opens every log file for writing and resolves upstream hostnames, which this sandbox rightly forbids: `http2 on` or `listen … http2`; `quic` or `http3 on`; `mail {}` with `proxy on` and `auth_http`; `resolver` with a `$`-variable `proxy_pass` plus `mirror` (and `mirror_request_body off`) or `ssi on` | Matches each CVE's precondition (§1) |
| `udp443` | `ss -lunp 'sport = :443'` | A QUIC listener the config check missed |
| `nginx_stale` | **any** nginx process (master or worker) whose `/proc/<pid>/exe` ends in `(deleted)`; supporting signal: a `worker process is shutting down` older than 1 h | Ubuntu's package attempts a live binary upgrade on `apt upgrade` (falling back to restart), but old workers keep their existing, possibly hostile, HTTP/2 connections; a manual `nginx -s reload` never loads a new binary ([site](https://nginx2root.com/), [Precursor](https://www.precursorsecurity.com/blog/nginx2root-critical-nginx-rce-vulnerabilities)) |
| `sctp` | loaded (`/sys/module/sctp`), blocked (`modprobe -n -v sctp` prints `install /bin/false`), built in (`CONFIG_IP_SCTP=y` in `/boot/config-$(uname -r)`) | NGINX2Root's root step. Built-in SCTP cannot be blocked. |
| `kernel_pending` | installed versus running kernel | The SCTP fix will arrive as a kernel update and needs a reboot |

It runs hourly on a timer and from an apt `DPkg::Post-Invoke` hook (`systemctl start --no-block edr-inventory`), so a
stale binary is reported minutes after an upgrade. Sandbox:
- `CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE`;
- `IPAddressDeny=any` and `RestrictAddressFamilies=AF_UNIX AF_NETLINK`;
- read-only filesystem except `/run/edr-inventory`;
- **not** `ProtectKernelModules=yes`, because `modprobe -n -v sctp` has to read `/lib/modules`.

### 4.6 Enrollment and identity

**The token.** The hub creates it (`edr-hub token create --name web1 --ttl 1h`) in the form
`id.secret.ca_sha256`. It is single-use, expires, and is stored hashed on the hub.

**Install-time enrollment:**
1. Generate an EC P-256 key and a CSR with the `openssl` CLI. The key is `0600 edr-agent` in `/etc/edr-agent/`.
2. Fetch the hub's CA without trusting it yet: open TLS with verification off and `GET /v1/ca` (PEM, no auth).
   Check that **the SHA-256 of its DER encoding equals the `ca_sha256` in the token** (the same value as
   `openssl x509 -outform DER | sha256sum`). Then reconnect with that CA pinned (`cafile`) and the hub's IP checked
   against the certificate's IP SAN, and only then send anything. A man-in-the-middle at install time can't pass
   this. (Python 3.12 on Ubuntu 24.04 can't read the server's chain from the handshake, so the CA is fetched
   explicitly.)
3. `POST /v1/enroll {token, csr, host_uuid, hostname, os, ips}`. The hub returns the signed client
   certificate (CN = host UUID, valid 1 year) and its CA.
4. Write `/etc/edr-agent/{hub.conf, ca.pem, client.pem, client.key}` and the `IPAddressAllow=` drop-in.

**Renewal.** The certificate is renewed automatically over the authenticated channel 30 days before
it expires.

**Host identity.** The host UUID is generated once and stored in `/var/lib/edr-agent/host-id`. It survives
re-runs of `install.sh`, `rehome`, and uninstall plus reinstall (uninstall keeps that one file unless `--purge`).

---

## 5. Moving to a new hub (`rehome`)

If the hub moves (new IP or port, or a new box altogether), each client moves with a new token from it:

    sudo edr-agent rehome --hub 198.51.100.7:8443 --token <new token>
    # or: sudo server_client/rehome.sh --hub … --token …
    # or: re-run install.sh with the new --hub/--token; on an installed client it only re-homes

**Sequence.** Nothing changes until the new hub is proven:

1. Generate a new key and CSR in a staging directory (`/etc/edr-agent/.staging`).
2. Fetch the new hub's CA with `GET /v1/ca`, check it against the token's `ca_sha256`, and reconnect with it
   pinned (as in §4.6).
3. `POST /v1/enroll`, keeping the existing host UUID.
4. Make a test call, `GET /v1/policy`, using the new certificate.
5. Atomically swap `hub.conf`, `ca.pem`, `client.pem` and `client.key` (rename), and rewrite the
   `IPAddressAllow=` drop-in for the new hub IP.
6. `systemctl daemon-reload`, then restart `edr-agent`, then confirm a heartbeat is accepted.

**Behaviour around the move:**
- **On failure** at any step, the staging directory is deleted and the agent carries on with the old hub.
  `rehome` exits non-zero with the reason.
- **The spool** is kept, so events queued during the move go to the new hub.
- **Bans** from the old hub stay until their TTLs run out; the new hub's policy replaces them at the next poll.
- **The old hub,** if it is still reachable, gets a best-effort `POST /v1/deregister`. If it isn't, it
  sees heartbeats stop, and its operator can mark the host "moved" or revoke it.
- **History.** If the hub was moved with `edr-hub backup`/`restore`, its CA is unchanged and so is the
  host UUID, so the fleet's history carries over. A brand-new hub simply starts fresh.

---

## 6. Uninstall

    sudo server_client/uninstall.sh            # asks first
    sudo server_client/uninstall.sh --yes --keep-logs
    sudo server_client/uninstall.sh --purge     # also forget this host's identity (host-id)
    # partial: --keep-suricata, --keep-tetragon, --keep-dns, --keep-sctp-block

**The order is chosen so the network never breaks:**
1. **Delete the `inet edr` nftables table,** which lifts all bans at once.
2. **Restore DNS:**
   - remove the `DNSLOCK` chain, its apply script and its boot unit;
   - remove the resolved drop-in and restart resolved;
   - **check that a lookup works**;
   - then stop and purge dnscrypt-proxy, with its sandbox drop-in.
3. Send `POST /v1/deregister` to the hub (best effort; a 5 s timeout).
4. Stop and remove `edr-agent`, `edr-bans.{path,service,timer}` and `edr-inventory.{service,timer}`, the apt hook,
   the conntrack sysctl drop-in, the journald drop-in (then restart journald), the 10-minute logrotate timer, the
   `edr-agent` user, `/etc/edr-agent` and `/var/lib/edr-agent` **except `host-id`** (removed too with `--purge`). Remove
   `/etc/modprobe.d/edr-sctp-block.conf` unless `--keep-sctp-block`, and say in the output that the kernel SCTP bug
   behind NGINX2Root has no patch yet ([site](https://nginx2root.com/)).
5. Remove Tetragon (reuse `tetragon/local_uninstall.sh`; add `--purge` unless `--keep-logs`).
6. Purge Suricata and its units and timers. Remove the OISF PPA **only if this kit added it**, as the
   root `uninstall.sh` does.
7. **Final check:** no `edr` table and no `DNSLOCK` chain left, DNS resolves, and nginx answers on
   `127.0.0.1`. Report PASS or FAIL.

---

## 7. Installer

    sudo server_client/install.sh [--hub IP:PORT --token TOKEN]
                                  [--admin-ip CIDR ...] [--lite] [--no-dns-lockdown]
                                  [--webroot /var/www] [--enforce]
                                  [--no-sctp-block] [--cap-conn-bytes SIZE] [--observe-only]

**Steps.** Each step is re-runnable; a step that fails rolls back its own changes and stops:

1. **Pre-flight.**
   - Ubuntu 24.04 or 26.04, systemd, amd64 or arm64.
   - `/sys/kernel/btf/vmlinux` present.
   - ≥ 2 GB RAM (≥ 1 GB with `--lite`) and ≥ 5 GB free disk.
   - The public interface found from the default route.
   - nginx and php-fpm detected (a warning only).
2. **nginx exposure report** (a warning only; the kit never changes nginx):
   - the installed nginx package against [USN-9159-1](https://ubuntu.com/security/notices/USN-9159-1) (noble
     `1.24.0-2ubuntu7.20`, resolute `1.28.3-2ubuntu1.13`). For nginx.org builds, vulnerable means below 1.30.7, or
     1.31.0 to 1.31.8 ([nginx.org](https://nginx.org/en/security_advisories.html));
   - a running binary older than the installed one ("restart, don't reload");
   - HTTP/2, HTTP/3, mail and resolver+mirror exposure, each with its row from §1 "what the operator does".
3. **Packages.**
   - The OISF PPA and `files/suricata.apt-pin`.
   - Install `suricata`, `nftables`, `dnscrypt-proxy`, `python3` and `openssl`.
4. **Suricata.** Build the candidate yaml, run `suricata-update`, test with `suricata -T`, commit or roll
   back; install the override, logrotate and timers.
5. **nftables.** Create the `inet edr` table, the `edr-bans` units and timer, the conntrack-accounting sysctl
   drop-in and the `bigconn` chain (§4.2).
6. **Kernel hardening (NGINX2Root).** Unless `--no-sctp-block`:
   - Write `/etc/modprobe.d/edr-sctp-block.conf` containing `install sctp /bin/false`
     ([Xint](https://xint.io/blog/nginx2root-remote-code-execution)).
   - The file doesn't unload a module that is already loaded. If `sctp` is loaded with no users, run
     `modprobe -r sctp`. If it is in use, WARN and leave it.
   - If `CONFIG_IP_SCTP=y` (built in), WARN that only the Tetragon `sctp-socket` policy applies.
7. **Tetragon.**
   - Install with `tetragon/local_install.sh`, using the server policies. That script needs small changes first
     (or a server wrapper that sets them): a `POLICY_DIR` override (it always renders `tetragon/policies`), a mode
     with no `WATCH_USER` (it refuses root, common on droplets), configurable export perm, size and backups (it
     hard-codes `600`, 50 MB x 40), and a way to skip the laptop-only viewer on :8099. `tetragon/check.sh` needs the
     same `POLICY_DIR` override, or its policy comparison WARNs. The values in this document override `config.sh`.
   - Set `export-file-max-size-mb 20` and `export-file-max-backups 5`, perm 640, and make the log directory setgid.
8. **DNS.** Configure dnscrypt-proxy, then the resolved drop-in, then check resolution, then `DNSLOCK`.
9. **Agent and inventory.** Create the user and install the agent and its unit; install the `edr-inventory`
   unit, timer and apt hook (§4.5.1).
10. **Enroll** (§4.6). Skipped if already enrolled to the same hub. A different hub means re-home (§5). Without
    `--hub`/`--token` the agent runs in **local mode**: the same tailing, local bans and inventory, with alerts
    written to the journal (`journalctl -t edr-agent`) instead of a hub. Enrolling later is `rehome`.
11. **Health.** Run `server_client/check.sh` and print PASS/WARN/FAIL per part.

**File layout (planned):**

    server_client/
    ├── PLAN.md               this document
    ├── install.sh            installer (above)
    ├── uninstall.sh          §6
    ├── rehome.sh             §5 (wraps edr-agent rehome)
    ├── check.sh              read-only health check, like the repo root's check.sh
    ├── agent/edr-agent.py    the agent (stdlib only)
    ├── files/                suricata-server.yaml, override, logrotate + timer, nft table (bans, feeds, bigconn),
    │                         edr-bans units, edr-inventory unit + timer + apt hook, edr-sctp-block.conf,
    │                         conntrack-acct sysctl, edr-agent.service, dnscrypt-proxy.toml + sandbox drop-in,
    │                         resolved and journald drop-ins, DNSLOCK apply script + boot unit (from controld/)
    └── tetragon/
        ├── policies/         web-exec, web-write-code, web-connect, env-read, nginx-exec (+ fork watch),
        │                     sctp-socket + the adapted ones
        └── export-denylist.jsonl

---

## 8. Health check (`check.sh`)

Read-only, PASS/WARN/FAIL, non-zero exit on any FAIL (same style as the repo root's `check.sh`). It checks:

- Suricata running in af-packet mode, its kernel drop percentage, rule age and that the last update succeeded.
- The `inet edr` table and its sets present, with entry counts.
- Tetragon running with every policy loaded (reuse `tetragon/check.sh`).
- dnscrypt-proxy answering, resolved pointing at it, `DNSLOCK` present, and that a plain DNS query to
  `9.9.9.9:53` **fails**.
- The agent running, its last successful send under 2 minutes ago, spool size, and the certificate's expiry.
- Disk use of each log against its budget.
- nginx: the package at or past its advisory fix (FAIL if vulnerable and the matching feature is exposed, WARN
  otherwise), and the running binary matching the installed one (FAIL if stale: "restart, reload is not enough").
- `sctp` not loaded and blocked (`modprobe -n -v sctp` shows `install /bin/false`). WARN if built in.
- `nginx-exec` and `sctp-socket` loaded with `Sigkill`.

`--live` triggers these canaries:
- the existing `tetragon/check.sh --canary`, which reads one byte of `/etc/shadow`;
- a harmless `web-exec` canary, `sudo -u www-data sh -c true`. The resulting event must reach the hub within 2 minutes.
- two SCTP canaries, `sudo -u www-data python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132)'`
  and the same with `socket.SOCK_SEQPACKET, 0`. Each must be killed by `sctp-socket`, and the events must reach the
  hub within 2 minutes.

Before the hub exists (P1), "reach the hub" means "appear in the journal".

---

## 9. Disk and CPU budgets

| Item | Cap | How |
|------|-----|-----|
| Suricata `eve.json` + `suricata.log` | ~250 MB | logrotate `size 50M`, `rotate 4`, `compress`, run by a **10-minute systemd timer** (stock logrotate runs daily, too late for a busy server); HUP after rotating |
| Tetragon | ~120 MB | Native rotation: `export-file-max-size-mb 20`, `export-file-max-backups 5`, compressed |
| Agent spool | 50 MB | Hard cap in code; oldest low-severity events dropped first |
| journald | 200 MB | `SystemMaxUse=200M` drop-in (journald may have none set) |
| nginx logs | unchanged | Ubuntu's own logrotate; the agent only reads them |
| **Total kit** | **≈ 620 MB** | |
| **Disk guard** | free < 10% | Agent sends a CRITICAL event, forces an early rotate, and switches Suricata to alert-only eve until space recovers |

| CPU / memory | Budget |
|--------------|--------|
| Suricata | 1 worker thread, `Nice=10`, `CPUWeight=50`; ~400–600 MB (lite ~250 MB) |
| Tetragon | eBPF in kernel plus ~100–150 MB user space; policies rate-limited per process |
| Agent | `CPUQuota=10%`, `MemoryMax=128M`; expected < 1% CPU, ~30 MB |
| dnscrypt-proxy | ~20 MB |

**Minimum droplet: 2 GB RAM.** 1 GB works with `--lite`.

---

## 10. Roadmap

| Phase | Client side | Useful by itself? |
|-------|-------------|-------------------|
| **P1** | Suricata server profile; nftables sets with local auto-bans and the `bigconn` watch; Tetragon server policies, with **`nginx-exec` and `sctp-socket` enforcing**; **SCTP module block**; **`edr-inventory`** (package fix status, NGINX2Root exposure, stale binary); DoH lockdown with refusal logging; `edr-agent` in **local mode** (tails the logs, makes the local ban decisions, writes alerts to the journal); budgets; `check.sh`; **`uninstall.sh`**. Alerts go to the journal. | Yes, with no hub |
| **P2** | `edr-agent` transport: enrollment, mTLS shipping, spool, heartbeat; inventory forwarded and rated on the hub against its advisory table; **`rehome`** | With the hub MVP |
| **P3** | Fleet bans and feed sets from the hub | With hub correlation |
| **P4** | Tetragon `Sigkill` for `web-exec` (php-fpm, `--enforce`); access-log analytics | |

---

## 11. Repo integration (for the implementation phases)

- **`Makefile`:** add every new script (as `server_edr_solution/server_client/…`) to `SH_FILES` and the agent to `PY_FILES`. `tests/lint.sh:30-32`
  fails on any shell script not listed there.
- **`tests/lint.sh`:** widen the policy glob (`tetragon/policies/*.yaml`, line 55) and the unit glob
  (line 151) to cover `server_edr_solution/server_client/`.
- **`tests/dry-run.sh`:** works unchanged with `server_client/install.sh`.
- **Server VM test:** a variant of `tests/vm-smoke.sh` with two multipass VMs (hub and client, 2 GB each).
  It covers install, enroll, canary to hub, re-home to a second hub, and uninstall leaving no rules behind.

## 12. Known limits and risks

- **HTTPS payloads are invisible to Suricata** (§1). Web-exploit coverage depends on Tetragon and nginx logs.
- **IDS, not IPS.** Suricata alerts. Blocking happens afterwards, by IP, through nftables, so the first
  malicious request of an attack gets through. Tetragon enforcement (`nginx-exec` and `sctp-socket`
  from P1, `web-exec` with `--enforce` in P4) is what can stop a successful exploit in its tracks.
- **IP bans assume direct traffic.** These droplets aren't behind a CDN or load balancer. If one is
  added later, IP bans must be turned off for that host or a CDN allowlist added, or real users get blocked.
- **Tetragon on Ubuntu 26.04** (kernel 7.0) has to be confirmed with the pinned version.
- **Tuning is expected in week one.** Per-site `proc_open` users, deploy tooling and queue workers will trip
  `web-exec` and `web-connect` until they are allowlisted.
- **No network signature for NGINX2Root.** Its HTTP/2 and QUIC frames are inside TLS. ET Open has no rule
  ([ET](https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules)). Censys described candidate
  Suricata rules (one validated only against cleartext h2c, the rest experimental), but its repo has no rule file as
  of 19 Nov 2026 ([Censys](https://censys.com/blog/nginx2root-simple-test)). Detection starts when the worker crashes or
  execs.
- **A kernel exploit can blind Tetragon.** NGINX2Root's SCTP bug gives an arbitrary kernel function call
  ([Xint](https://xint.io/blog/nginx2root-remote-code-execution)), so the kit must stop or report the chain at the
  exec or SCTP-socket step. A heartbeat lost right after either is treated as an attack (hub §4).
- **Crashes are a weak signal.** Exploitation against busy servers crashes workers more often than it gets code
  execution ([Precursor](https://www.precursorsecurity.com/blog/nginx2root-critical-nginx-rce-vulnerabilities)).
  A crash alone is not proof ([CERT-EU](https://cert.europa.eu/publications/security-advisories/2026-022/)).
- **ASLR is not something to rely on.** The CVE records name it as a condition, but a public PoC and a lab
  reproduction of code execution already exist (§1).
- **A CDN in front helps NGINX2Root but breaks IP bans.** It blocks the HTTP/2 bugs only if it terminates HTTP/2,
  talks HTTP/1.1 to nginx, and the origin is locked down ([site](https://nginx2root.com/)). Rapid7 says proxied
  HTTP/2 likely breaks their exploit
  ([Rapid7](https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/)).
- **If Tetragon can't run on 26.04,** fall back to Xint's auditd rule (`-S execve,execveat -F euid=<www-data uid>
  -k nginx_worker_exec`). On Ubuntu that uid is shared with php-fpm, so the agent must keep only events whose
  parent is an nginx worker.
- **Prior art:** CrowdSec covers shared IP bans, Wazuh full host EDR/SIEM, Falco runtime rules.
  Building this is worthwhile for a light, self-hosted setup under your own control. Borrow ideas
  (e.g. CrowdSec's scenario format) freely.
