# server_hub: design plan

Status: **design only, no code yet.** This document is the plan for the hub half of a small, self-hosted EDR
for DigitalOcean web servers. The client half is in [`../server_client/PLAN.md`](../server_client/PLAN.md), which
also covers the feasibility verdict, the threat model, the HTTPS-visibility limit and the NGINX2Root worked example.

**Paths:** `server_client/…`, `server_hub/…` and `mock/…` are relative to `server_edr_solution/`. Paths to the
laptop kit this reuses (`install.sh`, `check.sh`, `analyse.py`, `files/`, `tetragon/`, `controld/`, `watch/`,
`tests/`, `Makefile`) are relative to the repository root. A local Docker test bed is in [`../mock/`](../mock/README.md).

---

## 1. What it is

One locked-down box (a small droplet is enough for tens of clients). It:

- **receives** telemetry from enrolled clients over mutual TLS on a port you choose (default `8443`);
- **stores** it in SQLite, with retention and a size cap;
- **correlates** across the fleet, e.g. the same attacker hitting several droplets, or a webshell on one;
- **alerts** through a webhook (Slack, Discord, ntfy) or email;
- **hands out bans and IP feeds**, which clients pull and apply in their own nftables sets;
- **serves a local dashboard website on a separate port** (default `8450`), the way the Tetragon viewer runs on its own port;
- **enrolls** clients with one-time tokens, and lets them move to a new hub with a new token.

It does **not** use ctrld or anything else from `controld/`. It has its own installer and uninstaller,
written in the style of the existing ones.

```
                      clients (server_client)
         ┌─────────┐  ┌─────────┐  ┌─────────┐
         │ web-1   │  │ web-2   │  │ web-3   │   edr-agent: pulls policy, pushes events
         └────┬────┘  └────┬────┘  └────┬────┘
              └──── mTLS 1.3 :8443 ─────┘
                           │
 ┌─────────────────────────▼──────────────────────────────────┐
 │ hub                                                        │
 │  edr-hub.service    ingest API, enrollment, correlation,   │
 │                     alerts, feed fetcher, retention         │
 │        │  SQLite (WAL)  /var/lib/edr-hub/hub.db              │
 │        │  unix socket   /run/edr-hub/ctl.sock (writes)       │
 │  edr-hub-ui.service dashboard :8450, 127.0.0.1 by default    │
 │  nftables           SSH from admin IPs, :8443, (:8450 opt.)  │
 └────────────────────────────────────────────────────────────┘
          ▲
          └── you: ssh -L 8450:127.0.0.1:8450 hub, then open the URL in /etc/edr-hub/ui-url
```

### Security principles

1. **The hub never connects to clients and cannot run commands on them.** Clients pull. The only
   thing the hub can change on a client is its ban sets, and the client checks those against its own
   never-ban list. Taking over the hub does not give control of the fleet.
2. **Two processes, two ports.**
   - `edr-hub` faces the network and accepts only client certificates (plus enrollment).
   - `edr-hub-ui` is local by default and reads the database read-only.
   - A bug in one does not expose the other.
3. **Least privilege.** Both run as the unprivileged `edr-hub` user under a strict systemd sandbox. The CA
   private key is readable only by `edr-hub`, and only the main process loads it.
4. **Everything changed is audited:** bans, tokens, revocations and settings, whether done in the UI or the CLI.

---

## 2. Transport and enrollment

### Server
- Python standard library only: `ssl` on top of `http.server.ThreadingHTTPServer`. No `pip`. The `openssl` CLI
  is used for certificate work.
- **TLS per connection, never on the listening socket.** Wrapping the listener would run every handshake on the
  accept thread with no timeout, so one client that connects and sends nothing would stall all ingest. Instead:
  for each accepted socket, take the connection semaphore, set a 10 s socket timeout, wrap it with
  `do_handshake_on_connect=False` and run `do_handshake()` in that connection's thread.
- **TLS 1.3 only**, `CERT_OPTIONAL` at the handshake. TLS 1.3 sends the certificate request in the main handshake,
  so the per-route check below can rely on `getpeercert()`.
  - `/v1/enroll` and `/v1/ca` are the only routes that work without a client certificate.
  - Every other route requires a certificate signed by the hub CA, **not revoked**, and whose host is
    known. This is checked on every request against the `hosts` table.
- Limits:
  - a semaphore on concurrent connections (default 64);
  - a 10 s header timeout and a 30 s body timeout;
  - 1 MB compressed and 8 MB decompressed per request, decompressing as a stream (a gzip-bomb guard);
  - 500 events per batch;
  - per-host rate limits.

### API

| Route | Auth | Purpose |
|-------|------|---------|
| `GET /v1/ca` | none | The hub CA certificate (PEM). The client checks its SHA-256 against the token before trusting it (Python 3.12's `ssl` can't read the server's chain) |
| `POST /v1/enroll` | token | `{token, csr, host_uuid, hostname, os, ips}` → signed client certificate + CA |
| `POST /v1/events` | client certificate | Gzipped batch of normalised events |
| `POST /v1/heartbeat` | client certificate | Health, versions, budgets, agent SHA-256 |
| `GET /v1/policy` | client certificate | Bans, feed sets, ignore rules, thresholds (ETag; 304 when unchanged) |
| `POST /v1/renew` | client certificate | New certificate before expiry |
| `POST /v1/deregister` | client certificate | Client leaving (uninstall or rehome) |

### CA and certificates
- At install the CA is created with the `openssl` CLI: an EC P-384 key, valid 10 years, at
  `/var/lib/edr-hub/ca/`, mode `0600 edr-hub`.
- The hub's own server certificate is signed by it, with the hub's IP in the SAN. Clients connect by IP.
- Client certificates: CN = host UUID, valid 1 year, renewed by the client 30 days before expiry.
- Revoking a host (`edr-hub revoke <host>`) marks it in the database, and it is refused on its next request.
  No CRL distribution is needed, because the hub is the only relying party.

### Tokens
- `edr-hub token create --name web-1 [--ttl 1h]` prints the complete client command:

      sudo server_client/install.sh --hub 203.0.113.5:8443 --token 7Kq2.x9f…Pz.4a1c…e0

- The format is `id.secret.ca_sha256`.
  - `secret` is stored only as a SHA-256 hash.
  - `ca_sha256` lets the client check that it is talking to the right hub before it sends anything.
- Tokens are **single-use** and expire (1 h by default).
- Tokens can also be created from the dashboard, which shows the command with a copy button.

---

## 3. Storage and retention

SQLite in WAL mode, `/var/lib/edr-hub/hub.db`:

| Table | Holds |
|-------|-------|
| `hosts` | uuid, name, ips, os, versions, cert serial + expiry, state (active / moved / revoked), first and last seen |
| `events` | ts, host, source, severity, kind, summary, details (JSON), src_ip, community_id; indexed on (ts), (host, ts), (src_ip) |
| `heartbeats` | latest per host plus a 24 h history (downsampled) |
| `bans` | cidr, reason, source (local / fleet / manual / feed), created, expires, created_by |
| `feeds` | name, url, last fetch, entry count, checksum |
| `tokens` | id, hash, name, expires, used_by, used_at |
| `audit` | ts, actor (cli / ui / system), action, target, details |

- **Retention:** events are kept for 30 days (`--retention-days`), with a size cap (`--max-db-size`, default 2 GB).
  - When either limit is passed, the oldest INFO and LOW events are deleted first.
  - Pruning runs nightly and is followed by `PRAGMA incremental_vacuum`.
  - Audit records are kept for 1 year.
- **Writes** come only from `edr-hub`. The UI opens the file read-only (`mode=ro`) and sends changes over
  the control socket (§5; the CLI in §6 uses the same socket).

---

## 4. Correlation, alerts and response

### Rules (v1, deliberately simple and explicit)

| Rule | Severity | Action |
|------|----------|--------|
| Tetragon `nginx-exec`, `web-exec`, `web-write-code`, or a uid-0 transition in a www-data process tree | CRITICAL | Alert now. For `nginx-exec`, also say "restart nginx": Sigkill stops the exec, not code already running in the worker |
| Tetragon `sctp-socket`, or the `sctp` module loading, on a web host | CRITICAL from a www-data tree, else HIGH | Alert now: NGINX2Root's root step ([Xint](https://xint.io/blog/nginx2root-remote-code-execution)) |
| `env-read` from an unexpected program; `stack-tamper`; `tetragon-tamper` | HIGH | Alert |
| nginx worker crashes: ≥ 3 in 10 minutes on one host | HIGH | Alert; possible exploit attempts (NGINX2Root, CVE-2026-42945). Crashes alone are low-fidelity ([CERT-EU](https://cert.europa.eu/publications/security-advisories/2026-022/)) |
| `edr-bigconn`: one :443 connection past 4 GiB | MEDIUM; HIGH if a worker crash follows on that host within 30 min | Alert; the client bans the source IP on a repeat (client §4.2) |
| `client violated connection flow control: received WINDOW_UPDATE frame with window increment` from one IP, ≥ 3 in 10 minutes | MEDIUM | The client bans locally (client §4.2); fleet ban if seen on ≥ 2 hosts. On patched builds these are rejected exploit attempts. Logged only at `info` ([nginx source](https://raw.githubusercontent.com/nginx/nginx/release-1.31.9/src/http/v2/ngx_http_v2.c)), so a host at the default `error` level never reports it; `check.sh` warns |
| `could not cancel … resolving` | HIGH | Alert: logged at ALERT only by **unpatched** builds (the fix demotes it to debug), so it means an unpatched host hit the CVE-2026-123634 path |
| Same external IP with alerts on **≥ 2 hosts** within 1 h | MEDIUM | **Fleet ban**, TTL 6 h → 24 h → 7 d on repeats |
| Local auto-ban reported by any client | LOW | Raised to a fleet ban if a second host reports the same IP |
| No heartbeat for 5 minutes | HIGH; CRITICAL if within 30 min of `nginx-exec`, `sctp-socket` or a uid-0 transition | Alert (agent down, tampered with, or blinded) |
| Agent SHA-256 changed outside an upgrade | HIGH | Alert |
| Inventory: nginx package below its advisory fix **and** the matching feature exposed (see "Advisory data" below) | HIGH | Alert now; repeat daily until fixed |
| Inventory: old nginx processes still run the pre-upgrade binary (`/proc/<pid>/exe` is `(deleted)`) | HIGH | Alert: "restart nginx, or wait for the old workers to drain; a reload never loads a new binary" ([site](https://nginx2root.com/)) |
| Inventory: `sctp` loadable (not blocked, or built in) on a web host while the kernel bug is unpatched | MEDIUM | Daily digest |
| Inventory: other known-vulnerable packages, pending security updates over 7 days old, reboot required over 7 days | MEDIUM | Daily digest |
| Disk guard tripped on a client | CRITICAL | Alert |

**Per-host correlation:** several distinct signals on one host within 30 minutes (for example a worker crash,
then `web-exec`, then an unusual outbound connection) are grouped into one **incident**, raised one severity
level, and shown as a timeline. This is the same idea as the host scoring in `analyse.py`.

**NGINX2Root chain.** On one host within 30 minutes:
1. a worker crash, `edr-bigconn` or a flow-control violation;
2. then `nginx-exec` or `sctp-socket`;
3. then a uid-0 transition, `tetragon-tamper` or a lost heartbeat.

Together these make one CRITICAL incident named for the chain, even if step 1 is a single crash: in Censys's lab a
successful RCE left exactly one `signal 6`
([Censys](https://raw.githubusercontent.com/Censys-Research/nginx2root/main/evidence/cve-2026-123007/RCE-CONFIRMED.md)).

### IP feeds
- The hub fetches a few well-known IP blocklists daily: FireHOL level1, Spamhaus DROP/EDROP and the abuse.ch
  Feodo IP list.
- It checks them (parse, size limits, never-ban filtering) and sends them to clients as `edr_feed` sets in
  `/v1/policy`.
- Clients never fetch feeds themselves. That means one outbound fetch, one place to audit, and no extra
  network permissions for the agent.

### Advisory data for inventory rules

`nginx -v` can't show whether a distro build is fixed, because Ubuntu backports keep the version string
([Xint](https://xint.io/blog/nginx2root-remote-code-execution)). The hub therefore compares the full package version
reported by `edr-inventory` with `dpkg --compare-versions` against a small table shipped with the code
(`hub/advisories.json`, which local files in `/var/lib/edr-hub/advisories.d/` can override; they live with the
database so uninstall and backup keep them):

| Package | Release | Vulnerable when | Covers | Ref |
|---------|---------|-----------------|--------|-----|
| Ubuntu `nginx`, `nginx-core/full/light/extras` | noble (24.04) | < `1.24.0-2ubuntu7.20` | 123007, 123633, 123634, 113425 (121810 doesn't apply: no HTTP/3) | [USN-9159-1](https://ubuntu.com/security/notices/USN-9159-1), [CVE-2026-121810](https://ubuntu.com/security/CVE-2026-121810) |
| same | resolute (26.04) | < `1.28.3-2ubuntu1.13` | all five | [USN-9159-1](https://ubuntu.com/security/notices/USN-9159-1) |
| nginx.org `nginx` | any | < 1.30.7, or ≥ 1.31.0 and < 1.31.9 | all five | [nginx.org](https://nginx.org/en/security_advisories.html) |
| Linux kernel SCTP | all | no fix yet | NGINX2Root root step | [Xint](https://xint.io/blog/nginx2root-remote-code-execution) |

Each entry names the feature that makes it exploitable (HTTP/2, HTTP/3, mail, resolver+mirror). A host with a
vulnerable package but none of those features gets a MEDIUM digest line, not a HIGH alert. Ondrej's PPA has no
entry because its status is unknown, so those hosts show as "unknown: check by hand".

### Ban safety
- **A global never-ban list**, which the hub refuses to ban and every client independently refuses too:
  - the admin IPs;
  - the hub's own IP;
  - `169.254.169.254` (DigitalOcean metadata);
  - private, loopback and link-local ranges;
  - the enrolled clients' own IPs.
- Hard caps of 10k bans and 200k feed CIDRs.
- Every ban records its reason, source and expiry, and every ban and unban goes to `audit`.

### Alert delivery
- Webhook: Slack, Discord or ntfy, one template each. Optional SMTP.
- Settings: a minimum severity (default HIGH), deduplication per (host, kind) for 30 minutes, and a
  daily digest of MEDIUM.

---

## 5. Dashboard website (`edr-hub-ui`, its own port)

A local website, installed and running by default, separate from the client ingest port.

### Process and port
- `edr-hub-ui.service` on port **8450** by default (`--ui-port`).
- Modelled on the Tetragon viewer:
  - `tetragon/viewer/server.py`, served on `127.0.0.1:8099` with a token;
  - its hardened unit in `tetragon/local_install.sh` (around lines 396-421);
  - the login URL kept in a root-only file, as `/etc/tetragon/viewer-url` is.

### Access
- **Default:** bound to `127.0.0.1:8450` and not reachable from outside. Open it through an SSH tunnel:

      ssh -L 8450:127.0.0.1:8450 root@hub
      sudo cat /etc/edr-hub/ui-url     # http://127.0.0.1:8450/#token=… ; open once, the browser keeps it

- **Optional:** `--ui-bind <IP> --admin-ip <CIDR>` serves it over TLS (with the hub's certificate) on that IP,
  and nftables lets only the admin CIDRs reach the port.
- The token is exchanged for a session cookie (`HttpOnly; SameSite=Strict; Secure` when on TLS).
- Every change needs a CSRF token as well.
- Responses carry a strict `Content-Security-Policy` (no third-party origins).

### Pages
- One HTML page with inline JS and CSS. No CDN and no build step, served by the standard library.

| Page | Shows / does |
|------|--------------|
| **Fleet** | Every host: state, last heartbeat, health (Suricata, Tetragon, DNS, agent), versions, **NGINX2Root exposure** (package fixed?, HTTP/2, HTTP/3 or mail on, stale nginx binary, SCTP blocked), disk budget, open incidents |
| **Events** | Live feed (server-sent events) with severity, host, source and kind filters; click to see details |
| **Incidents** | Correlated groups with their timelines |
| **Host** | One host's timeline, inventory, bans it reported, certificate expiry. Actions: **revoke**, **mark moved** |
| **Bans** | Active bans and feeds, with source and expiry. Actions: **add**, **remove**, **extend** |
| **Enroll** | **Create a token** and copy the full `install.sh --hub … --token …` command; list unused or expired tokens |
| **Audit** | Every change, with who made it |
| **Settings** | Alert webhook, minimum severity, retention, never-ban list (read-only in v1; edit with the CLI) |

### How changes are made
- The UI process cannot write to the database.
- Changes (ban, unban, token, revoke) go as JSON to `/run/edr-hub/ctl.sock`, a unix socket owned by the main
  process. It validates them, applies them and audits them, just as for the CLI.

---

## 6. CLI (`edr-hub`)

    edr-hub status                          # service health, DB size, hosts up/down, feeds age
    edr-hub hosts [--all]                   # fleet table
    edr-hub events [--host H] [--since 1h] [--min-sev high] [--json]
    edr-hub incidents [--open]
    edr-hub token create --name web-1 [--ttl 1h] | list | delete ID
    edr-hub ban CIDR [--ttl 24h] [--reason …] | unban CIDR | bans
    edr-hub revoke HOST | mark-moved HOST
    edr-hub backup [--out FILE] | restore FILE
    edr-hub never-ban add|remove|list CIDR

The CLI talks to the control socket; only root and the `edr-hub` group can use it.

---

## 7. Moving the hub

- `edr-hub backup` writes a tarball readable only by root: the CA (key and certificate), the database
  (as an online SQLite backup), config and the never-ban list.
- `edr-hub restore FILE` on a new box runs after `server_hub/install.sh` and replaces its fresh state. The
  hub keeps its CA and its fleet history.
  - Restore always **reissues the hub's server certificate** from the restored CA with
    `subjectAltName=IP:<new public IP>` and a random 128-bit serial, then restarts `edr-hub`. Otherwise clients
    would reject the new box: either its certificate was signed by the discarded fresh CA, or it names the old IP.
  - It prints the CA's SHA-256, which is unchanged, so existing tokens and pins still match.
- Clients then move with a new token from the new hub:

      sudo edr-agent rehome --hub NEW_IP:PORT --token <token>

  - The client's host UUID is unchanged, so history continues.
  - The client checks the new hub against the token, enrolls, makes a test request, and only then switches.
    If anything fails it stays on the old hub (see `server_client/PLAN.md`, §5).
- **With no backup** (the old hub is lost), install a fresh hub and re-home every client with new tokens.
  History starts over.
- **Moved clients:** a client that re-homes to another hub sends `/v1/deregister` to the old one if it can.
  Otherwise its heartbeats stop, and the operator can mark it "moved" (which silences the missing-heartbeat
  alert) or revoke it.

---

## 8. Install

    sudo server_hub/install.sh [--port 8443] [--ui-port 8450] [--ui-bind 127.0.0.1]
                               [--admin-ip CIDR ...] [--public-ip IP]
                               [--retention-days 30] [--max-db-size 2G]

All settings that must survive a reinstall (never-ban list, webhook, retention, advisory overrides) live under
`/var/lib/edr-hub`. `/etc/edr-hub` holds only things the installer recreates, such as `ui-url`.

**Steps.** The installer is re-runnable; a re-run upgrades the code and keeps the CA, database and tokens:

1. **Pre-flight.** Ubuntu 24.04 or 26.04, systemd, `python3` ≥ 3.12, `openssl`, `nftables`; the public IP
   (from the default route, or `--public-ip`).
2. Create the `edr-hub` user and group, and `/var/lib/edr-hub` (`0700`) and `/etc/edr-hub` (`0750`).
3. **CA and server certificate,** only if they don't exist yet. Print the CA's SHA-256.
4. Install the code to `/usr/local/lib/edr-hub` (root-owned, as the laptop kit does with
   `/usr/local/lib/suricata-ips`) and the `edr-hub` CLI to `/usr/local/sbin`.
5. **Units** `edr-hub.service` and `edr-hub-ui.service`, both sandboxed. Shared settings:

       User=edr-hub
       CapabilityBoundingSet=            # + CAP_NET_BIND_SERVICE only if a port < 1024
       NoNewPrivileges=yes
       ProtectSystem=strict
       ProtectHome=yes
       PrivateTmp=yes
       PrivateDevices=yes
       ProtectKernelTunables=yes
       ProtectKernelModules=yes
       ProtectControlGroups=yes
       RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
       MemoryDenyWriteExecute=yes
       SystemCallFilter=@system-service
       MemoryMax=512M                    # UI: 128M

   Only `edr-hub.service` gets `StateDirectory=edr-hub` and `RuntimeDirectory=edr-hub`. systemd deletes a
   unit's runtime directory when that unit stops, so if the UI shared it, restarting the UI would delete
   `ctl.sock`. `edr-hub-ui.service` instead gets `Requires=` and `After=edr-hub.service`,
   `ReadOnlyPaths=/var/lib/edr-hub` and `InaccessiblePaths=/var/lib/edr-hub/ca`. It opens the database with
   `file:…?mode=ro`; `edr-hub` keeps the WAL files in place (no `TRUNCATE` checkpoint on close) so read-only
   readers keep working.

6. **Firewall.**
   - An `inet edr_hub` nftables table of its own: allow established, SSH from `--admin-ip` (or from anywhere,
     with a warning if none is given), the hub port, and the UI port only when `--ui-bind` isn't `127.0.0.1`.
   - It does not edit UFW. Recommend a DigitalOcean Cloud Firewall in front with the same rules.
7. Turn on `unattended-upgrades`, and set journald's `SystemMaxUse=200M`.
8. **Start and check.**
   - Start both services and wait for the API to answer.
   - Write the UI URL to `/etc/edr-hub/ui-url` (`0600 root`).
   - Print the first enrollment command (`edr-hub token create --name first`).

**Hub sizing:** 1 vCPU and 1–2 GB RAM is enough for ~50 clients.

**Optional:** install `server_client` on the hub as well (pointed at itself) to watch the hub with the same tools.

---

## 9. Uninstall

    sudo server_hub/uninstall.sh            # asks first; keeps data
    sudo server_hub/uninstall.sh --yes
    sudo server_hub/uninstall.sh --purge    # also deletes the database, the CA and backups

**Default:**
1. Write an automatic backup to `/var/backups/edr-hub-<date>.tar` (root-only).
2. Stop and disable both units and remove them.
3. Delete the `inet edr_hub` nftables table.
4. Remove `/usr/local/lib/edr-hub`, `/usr/local/sbin/edr-hub`, `/etc/edr-hub` (nothing persistent lives there)
   and the journald drop-in (then restart journald). unattended-upgrades is left on.
5. **Keep `/var/lib/edr-hub`** (database and CA), so running `install.sh` again brings back the same hub,
   and clients keep working without re-enrolling.

**`--purge`:** also deletes `/var/lib/edr-hub` and the automatic backups. It warns, and asks again, that every
enrolled client will then need a new token from a new hub (`rehome`).

The `edr-hub` user is removed in both cases. The script finishes by checking that no `edr_hub` table is
left and that nothing is listening on the two ports.

---

## 10. Planned layout

    server_hub/
    ├── PLAN.md               this document
    ├── install.sh            §8
    ├── uninstall.sh          §9
    ├── check.sh              read-only health: services, ports, cert expiry, DB size, feed age, hosts down
    ├── hub/
    │   ├── edr_hub.py        ingest API, enrollment, correlation, alerts, feeds, retention, control socket
    │   ├── edr_hub_ui.py     dashboard server (port 8450)
    │   ├── ui/index.html     the single-page dashboard
    │   ├── advisories.json   package advisory table for inventory rules (§4)
    │   └── edr-hub           CLI (Python)
    └── files/                edr-hub.service, edr-hub-ui.service, nft table, journald drop-in

---

## 11. Roadmap

| Phase | Hub side |
|-------|----------|
| **P1** | (client-only phase; no hub needed) |
| **P2 (MVP)** | Enrollment and tokens, mTLS ingest, SQLite and retention, heartbeats, webhook alerts, CLI, **dashboard on its own port**, `install.sh`, **`uninstall.sh`**, support for client `rehome`, **inventory rules with the advisory table (§4)** |
| **P3** | Fleet bans, IP feeds, incident correlation (including the NGINX2Root chain), `backup`/`restore` |
| **P4** | Policy distribution for Tetragon enforcement toggles and per-site allowlists; access-log analytics views |

## 12. Repo integration and testing (for the implementation phases)

- **`Makefile`:** add `server_edr_solution/server_hub/install.sh`, `uninstall.sh` and `check.sh` to `SH_FILES`, and the Python files to
  `PY_FILES` (`tests/lint.sh` fails on unlisted shell scripts).
- **`tests/lint.sh`:** add `server_edr_solution/server_hub/files/*.service` to the `systemd-analyze verify` globs.
- **`tests/dry-run.sh`:** works unchanged with `server_hub/install.sh`.
- **Two-VM test** (with the client):
  1. install the hub;
  2. create a token;
  3. install the client;
  4. run the canary and see it in `edr-hub events` and on the dashboard;
  5. ban an IP and see it in the client's nft set;
  6. back up and restore to a second hub VM, then `rehome` the client;
  7. uninstall both and confirm no tables or ports are left.
- **Unit tests** for the security-relevant parsing:
  - token validation and single use;
  - the gzip-bomb limit;
  - CIDR and never-ban validation;
  - refusing revoked certificates;
  - the CSRF check.

## 13. Open questions for implementation

- Python 3.12's `ssl` gives access to the peer certificate's serial and subject. Confirm per-request revocation
  lookups by serial are enough without a CRL.
- Choose the webhook format(s) that matter first (Slack, Discord, ntfy?).
- Decide whether the dashboard should allow editing settings in v1, or stay read-only apart from bans,
  tokens and revoke.
