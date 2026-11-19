# server_hub: design plan

Status: **design only, no code yet.** This is the plan for the hub half of a small, self-hosted EDR for DigitalOcean
web servers. The client half is in [`../server_client/PLAN.md`](../server_client/PLAN.md): the feasibility verdict and
the HTTPS-visibility limit (client §1), the threat model (client §13), the NGINX2Root example (client Appendix A).
This plan holds the hub's side of the contract; the API reference is Appendix A.

**Paths:** `server_client/…`, `server_hub/…`, `common/…` and `mock/…` are relative to `server_edr_solution/`. Paths to
the laptop kit this reuses (`install.sh`, `check.sh`, `analyse.py`, `files/`, `tetragon/`, `controld/`, `watch/`,
`tests/`, `Makefile`) are relative to the repository root. A local Docker test bed is in [`../mock/`](../mock/README.md).

**Contents**

- [1. What it is](#1-what-it-is)
- [2. Transport and enrollment](#2-transport-and-enrollment)
- [3. Storage and retention](#3-storage-and-retention)
- [4. Correlation, alerts and response](#4-correlation-alerts-and-response)
- [5. Dashboard website (`edr-hub-ui`, its own port)](#5-dashboard-website-edr-hub-ui-its-own-port)
- [6. CLI (`edr-hub`)](#6-cli-edr-hub)
- [7. Moving the hub](#7-moving-the-hub)
- [8. Install](#8-install)
- [9. Uninstall](#9-uninstall)
- [10. Planned layout](#10-planned-layout)
- [11. Roadmap](#11-roadmap)
- [12. Repo integration and testing (for the implementation phases)](#12-repo-integration-and-testing-for-the-implementation-phases)
- [13. Decisions and open questions](#13-decisions-and-open-questions)
- [14. Configuration](#14-configuration)
- [15. Operations and runbooks](#15-operations-and-runbooks)
- [16. Privacy and data handling](#16-privacy-and-data-handling)
- [17. Upgrades and compatibility](#17-upgrades-and-compatibility)
- [Appendix A: API reference](#appendix-a-api-reference)

---

## 1. What it is

One locked-down box (a small droplet is enough for tens of clients; sizing is in §3 and §8). It:

- **receives** telemetry from enrolled clients over mutual TLS 1.3 on a port you choose (default `8443`), and
  enrolls new clients on a second, short-lived port (default `8444`);
- **stores** it in SQLite with tiered retention and a size cap (§3);
- **correlates** across the fleet and per host: incidents, the NGINX2Root outcomes, a sudden silence (§4);
- **alerts** through a persistent outbox to ntfy or a Slack-compatible webhook (Discord and e-mail in P3);
- **hands out fleet peer addresses** (P2) **and bans and IP feeds** (P3) that clients pull; clients apply them in
  their own nftables sets, after their own never-ban checks;
- **serves a dashboard on its own loopback port** (default `8450`), reached by an SSH tunnel only in v1 (§5);
- **is its own CA**: enrolls clients with one-time tokens, and lets them move to a new hub (§2, §7);
- **backs itself up** (encrypted, scheduled) and **watches itself**, because a dead hub looks like a quiet fleet (§4).

It does **not** use ctrld or anything else from `controld/`. It has its own installer and uninstaller,
written in the style of the existing ones.

```
  clients (server_client): edr-agent pulls policy, pushes events
        │ 8443 fleet: TLS 1.3, client certificate required
        │ 8444 enrollment: token, open only while one is pending
 ┌──────▼────────────────────────────────────────────────────────┐
 │ hub                                                           │
 │  nftables inet edr_hub: SYN meter, SSH from admin IPs,        │
 │                         output drop for uid edr-hub           │
 │  edr-hub.service      ingest, enrollment, API, SQLite writer, │
 │                       correlation, CA key (until the signer)  │
 │      │  /var/lib/edr-hub/hub.db   (WAL, one writer)           │
 │      ├─ /run/edr-hub/ctl.sock  root CLI: every command        │
 │      ├─ /run/edr-hub/ui.sock   dashboard: whitelisted verbs   │
 │      └─ /run/edr-hub/out.sock  edr-hub-out: outbox, feed jobs │
 │  edr-hub-ui.service   dashboard 127.0.0.1:8450, reads the DB  │
 │  edr-hub-out.service  the only user with outbound access:     │
 │                       feeds, webhooks, dead-man ping          │
 │  edr-hub-ca.service   (P3) the only holder of the CA key      │
 └───────────────────────────────────────────────────────────────┘
        ▲
        └── you: ssh -L 8450:127.0.0.1:8450 hub, then `sudo edr-hub ui-login` and open the URL
```

### Security principles

1. **The hub never connects to clients and cannot run commands on them.** Clients pull. A compromised hub can send
   **fleet peer addresses to never ban** (and, from P3, **bans and feed sets**), and nothing else. It cannot run commands,
   change files, change thresholds, silence detections or switch enforcement: those are local to each client
   (client §14). Clients bound what it may send (client §4.2). What a hub takeover still costs is in client §13.
2. **Separate processes for separate jobs, four users** (`edr-hub`, `edr-hub-ui`, `edr-hub-out`, `edr-hub-ca` in
   P3): roles in §8 step 2, sandboxes in §8 step 4; the CA key is held by `edr-hub` until P3.
3. **Least privilege.** Strict systemd sandboxes (§8). `ca/` is `0700` and owned by the key holder only. Commands
   that change trust or settings are CLI only (§6), so a compromised dashboard cannot enrol a host, widen the
   never-ban list or silence alerts.
4. **Every client field is hostile.** Identity comes from the certificate, never from a body (§2). Every field is
   escaped where it is shown (§5) and sanitised where it is sent (§4, §6).
5. **Everything changed is audited** in a hash chain, and admin actions notify out of band (§4, §5).
6. **The site and the fleet do not depend on the hub.** Clients spool and keep working with no hub, and alert locally
   (client §4.7). Hub outages are detected by independent layers (§4).

---

## 2. Transport and enrollment

### Server
- Python standard library only: `ssl` on top of `http.server.ThreadingHTTPServer`; the `openssl` CLI for certificates.
  Python's documentation says it "only implements basic security checks"
  ([docs](https://docs.python.org/3/library/http.server.html)), so the design relies on mutual TLS, the limits
  below, the firewall caps (§8 step 5) and the sandbox (§8 step 4). Responses carry fixed headers only, never
  request text. A GET with a body is refused.
- **Two listeners.** SNI cannot switch the verify mode on one port (tested), so each has its own socket.

| Listener | Port | Client certificate | Serves | Bound |
|----------|------|--------------------|--------|-------|
| Fleet | `8443` (`--port`) | required (`CERT_REQUIRED`) | events, heartbeat, policy, renew, deregister | always |
| Enrollment | `8444` (`--enroll-port`) | none | `/v1/ca`, `/v1/enroll` | only while an unexpired, unused token exists |

  - The enrollment listener closes when the last token is used or expires. The installer uses it only for `/v1/ca`
    and `/v1/enroll` (see Tokens, below). A cert-less peer on 8443 fails the handshake and never reaches the parser.
- **TLS 1.3 only:** `minimum_version = TLSv1_3`, `num_tickets = 0`. A refused client certificate shows on the
  client's first read, not at connect (Appendix A).
- **Checked on every fleet request** against `hosts`: `notAfter` is in the future, the DER SHA-256 of the presented
  certificate equals the host's current or pending hash (CN and serial from `getpeercert()` are display values and go
  to `revoked.txt`), and the state allows the route (host states: Enrollment). Anything else is 403.
  A certificate from another CA fails the handshake. With tickets off and the per-request check, a resumed
  session cannot outlive a revocation. CN and serial from `getpeercert()` were tested on Python 3.14; re-check on 3.12.
- **Per connection, never on the listening socket.** Wrapping the listener would run every handshake on the accept
  thread. It only accepts, with `request_queue_size = 128` (the default 5 loses SYNs when the fleet reconnects
  after a hub restart; clients add jitter). Override `process_request()` only:
  1. take a slot with a **non-blocking** acquire; if none is free, close the socket at once;
  2. check the per-source cap (Limits), then start the connection thread;
  3. the thread wraps the socket with `do_handshake_on_connect=False`, registers it with the reaper, handshakes,
     and serves one request (HTTP/1.0, no keep-alive; about 3 ms of CPU each, so 50 clients are about 1% of a core).
- **Deadlines are wall-clock, not per-read timeouts.** `settimeout()` bounds each `recv()`, so one byte every
  second keeps a connection open for ever (tested: still connected after 15 s with a 2 s timeout). One reaper thread
  holds `(monotonic deadline, SSLSocket)` per live connection and calls `socket.socket.shutdown(ss, SHUT_RDWR)` on
  expired ones. It must hold the `SSLSocket`: the raw socket is detached after wrapping. Tested: a trickler was cut at 4 s.

### Limits

| Limit | Value | Over the limit |
|-------|-------|----------------|
| Handshake | 3 s from accept | cut by the reaper |
| Header block | 5 s, 8 KiB, 32 lines (request line included) | cut; 431 if the size is hit |
| Whole request | 15 s; 30 s for a body near 1 MiB; enrollment 5 s | cut |
| Slots, fleet / enrollment | 64 / 4 | socket closed at once |
| Slots per source | 4 per IPv4 address and per IPv6 /64, counted in `process_request` | socket closed |
| Requests per certificate | 4 at once, counted after the handshake | 429 |
| `Content-Length` | required; `Transfer-Encoding` and `Expect` refused | 411 / 400 |
| Body, compressed | 1 MiB (1,048,576 bytes) | 413 |
| Body, decompressed | 3 MiB | 413 |
| One event / events per batch | 10 KiB / 500; the batch is also bounded by the 3 MiB inflated cap. A conforming client never sends an event over 5 KiB (client Appendix B) | 413 |
| Requests parsing at once | 4 (second semaphore, held until the writer replies) | 503 + `Retry-After` |

- **Header budget:** wrap `self.rfile` in the handler and raise `http.client.LineTooLong` once 8 KiB or 32 lines
  are spent. Do not patch the `http.client` globals. The stdlib default is 100 lines of 64 KiB; 30 such
  connections took the server from 22 to 213 MiB (tested).
- **Decompression** is streaming: `zlib.decompressobj(31).decompress(data, 3 * 2**20 + 1)`; a longer result or a
  non-empty `unconsumed_tail` is 413 (a 1 GiB bomb gzips to about 1 MiB, tested). A stream that has not reached `eof`
  (truncated) or has non-empty `unused_data` is 400. `RecursionError`, `ValueError` and
  `UnicodeDecodeError` while parsing are 400.
- **Why these numbers (arithmetic, Python 3.14; re-measure on 3.12).** A legitimate batch is at most 3 MiB inflated
  (the client cuts a batch at 500 events or 3 MiB inflated, whichever comes first). Pre-auth: 64 slots x 8 KiB of headers = 0.5 MiB. Parsing: 4 x (1 MiB compressed + 3 MiB inflated +
  about 24 MiB of `json.loads` for 3 MiB of tiny objects) = about 112 MiB worst case. Base: about 25 MiB of Python,
  20 MiB of SQLite cache, about 65 MiB of thread stacks: about 220 MiB in all, under `MemoryHigh=400M` and
  `MemoryMax=512M` (`TasksMax=200`; §8 step 4).
- **Per-source new-connection meter** in the hub's own nftables table, on both ports: about 5 SYN per second per
  source, burst 10, IPv6 per /64, before any slot is used. The rule is in the §8 step 5 chain. Tested: 60 attempts at
  about 10 a second connect about 40 and drop about 20 (burst 10, refill 5 a second). A slow holder under 5 per second
  is stopped by the slot cap and the deadlines. A `ct count` cap was not tested; do not rely on it. A client replays
  its spool at one batch a second at most (client §4.5), so the meter never drops it.
- **Optional `--clients-only`** (P3, off by default): a root oneshot (`edr-hub-clients.service`, §8) fills an nftables set of enrolled client
  addresses, plus the address range given to `token create --source`, and 8443 accepts only that set. The enrollment port
  stays open while a token is pending, and with no clients enrolled 8443 stays open. The default is open plus the
  meter, because the set drifts when a client's address changes.
- **DigitalOcean Cloud Firewall equivalent:** an inbound rule for 8443 whose source is a droplet **tag** carried by
  every client droplet (DigitalOcean lists tags as firewall sources). The 8444 rule stays open, because a new droplet
  has no tag yet. Confirm the exact rule in the DigitalOcean docs.

### API

| Route | Listener | Auth | Purpose |
|-------|----------|------|---------|
| `GET /v1/ca` | enrollment | none | The hub CA certificate (PEM); details in Appendix A |
| `POST /v1/enroll` | enrollment | token | CSR in, signed client certificate and host UUID out |
| `POST /v1/events` | fleet | certificate | Gzipped batch of events |
| `POST /v1/heartbeat` | fleet | certificate | Health, versions, applied policy revision |
| `GET /v1/policy` | fleet | certificate | Never-ban peers and hub addresses; bans and feed sets from P3 (ETag; 304 when unchanged) |
| `POST /v1/renew` | fleet | certificate | New certificate before expiry |
| `POST /v1/deregister` | fleet | certificate | Client leaving (uninstall or rehome) |

Bodies, status codes and the client's action for each status: Appendix A.

- **Validation.** Schema and types are checked before storing; a batch is accepted or refused as a whole. Unknown
  keys are dropped; `details` must be an object. Every 4xx answer is `{"error", "code"}` with fixed text.
- **Identity comes from the certificate only.** The hub sets the host from the verified certificate and ignores any
  host named in a body. Event ids carry no host part. No route takes a host in the URL. Enrollment `hostname`,
  `os` and `ips` are display text. The never-ban list uses the TCP source address the hub saw, at most 2 per host,
  never a claimed `ips` value. Rules that count hosts count distinct certificate CNs (§4).
- **Rate limits** are keyed on the certificate CN.
  - LOW and INFO: a token bucket per host (`rate_low_per_hour`, §14), set above the client's 12,000 an hour ceiling (client §4.5). Over budget the batch is still accepted
    and the excess is only counted (reply `dropped_low=N`). Flood protection is the client's budget (client §4.5).
  - HIGH and CRITICAL are never dropped. They have a larger bucket (`rate_high_per_hour`, §14). Over it, or with the
    writer queue full, the hub answers 429 or 503 with `Retry-After` and stores nothing; the client keeps the batch.
- **Duplicates.** Every event has an `id`, `<epoch>:<seq>` (client Appendix B); the hub adds the host from the
  certificate and stores `UNIQUE(host, id)` with `INSERT OR IGNORE`. The reply
  counts `accepted` and `duplicate`, so a retry after a lost reply is harmless. A gap in `seq` within one epoch is loss.
- **Clock skew and old events.** The hub stamps `received_at` on every row and uses it for retention and the "within
  N minutes" rules. Each send carries `sent_at`, stamped at each attempt (a retry gets a new one, the same
  `batch_id`). `skew = received_at - sent_at` is stored per host; over 5 minutes raises a MEDIUM.
  - If |skew| > 30 s, `ts` is corrected by the skew, then clamped to `received_at + 5 minutes`.
  - An event older than 10 minutes after correction is flagged **replayed**. A replayed CRITICAL alerts once, labelled
    "delayed 3h12m". Replayed events never feed fleet bans or TTL escalation. They may chain with each other inside
    one replayed batch, so a chain from a hub outage is not lost.

### CA and certificates

The hub is its own CA and the only relying party. Certificate work uses the `openssl` CLI with **explicit
extension files** (`pki/strict/{ca,srv,cli}.ext`); `openssl` defaults differ between 3.0 (24.04) and 3.5 (26.04).

| | CA | Hub server | Client |
|---|---|---|---|
| Key, signature | EC P-384, SHA-384 | EC P-256 | EC P-256 (others refused) |
| basicConstraints | critical, `CA:TRUE,pathlen:0` | critical, `CA:FALSE` | critical, `CA:FALSE` |
| keyUsage | critical, `keyCertSign,cRLSign` | critical, `digitalSignature` | critical, `digitalSignature` |
| extendedKeyUsage | none | `serverAuth` | `clientAuth` |
| subjectAltName | none | every hub IP as `IP:` | none |
| Identifiers, lifetime | SKID, AKID; 10 years | SKID, AKID; 397 days | SKID, AKID; 365 days |

- **Why strict.** Python 3.13+ (26.04 has 3.14) makes `create_default_context()` strict, and a plain
  `openssl req -x509` CA has no keyUsage and is refused. 3.12 (24.04) is lenient, so the hub and every client set
  `VERIFY_X509_STRICT` explicitly and never clear it. A no-EKU certificate passes as a client certificate, so
  both EKUs are required.
- **How checked.** On Python 3.14.4 with OpenSSL 3.5.5 these profiles pass `openssl verify -x509_strict` and TLS 1.3
  mutual handshakes both ways; a no-keyUsage CA, a CN-only or DNS-only server certificate and a wrong EKU fail.
  Python 3.12 with OpenSSL 3.0 has **not** been run: unit tests handshake with both certificate types on 3.12 and
  3.14; the installer self-checks with `openssl verify -x509_strict`.
- **Signing procedure** (per request, under a signing semaphore of 2):
  1. Cap the CSR at 4 KiB, one PEM block; `openssl req -verify` proves key possession. Take only the public
     key and require EC `prime256v1`; subject and extensions in the CSR are never used.
  2. `openssl x509 -new -force_pubkey pub.pem -subj /CN=<uuid> -CA ca.pem -CAkey ca.key -sha384 -days 365
     -extfile cli.ext -set_serial 0x<15 random bytes, top bit cleared>`. Never `x509 -req`: it copies the subject.
  3. Run `openssl verify -x509_strict -purpose sslclient` on the result, then store serial and DER SHA-256.
  4. Every certificate, client and server, is issued with notBefore one day in the past, so clock skew on a fresh
     droplet does not refuse it. Nothing orders or judges certificates by `notBefore` (§7 uses serials). `openssl ca -startdate` does this; the VM test confirms the equivalent for
     `openssl x509 -new` on 3.0 and 3.5, or signing goes through `openssl ca`.
- **Lifetimes.** Clients renew 30 days before expiry (client §4.6). The hub's server certificate and key are
  `/var/lib/edr-hub/tls/server.pem` and `server.key` (owner `edr-hub`, key `0600`); they are not backed up, and
  `restore` reissues them (§7). The hub reissues the certificate at 30
  days left and when the address list changes, loading it into the live `SSLContext`; certificate expiry alerts
  are in §4 (Hub self-health; the CA alert starts with 2 years left). Replace the CA by year 8: new hub plus `rehome`, or (P3) a CA bundle in `/v1/renew`.
- **Addresses.** Clients connect by IP and only IP SANs match (tested). `--public-ip` is repeatable and stored in
  the hub config; the SAN holds every one (public, VPC, Reserved) and `restore` reissues from the list. Recommend
  a **Reserved IP** as the address clients enrol against: a replacement hub in the same region takes it over after
  `restore` with no client change ([DigitalOcean](https://docs.digitalocean.com/products/networking/reserved-ips/)).
  It is not on the NIC: pass it explicitly and bind `0.0.0.0`.
- **Revocation** also appends serial and DER hash to `ca/revoked.txt` (append-only, synced, loaded first, copied
  into every backup), so a restored older database cannot revive a revoked certificate (§7).
- **Signer split (P3, optional).** `edr-hub-ca.service` (user `edr-hub-ca`, key `0400`, socket 0660 group
  `edr-hub`, no network, about 100 lines) takes a public key and UUID and applies the fixed profile; the server
  SAN list comes from its own root-owned config. Until then ingest holds the key. An ingest compromise can still
  enrol new UUIDs (alerts stay) but cannot steal the CA key. Rejected: root-only signing, an offline CA.

### Tokens

- **Format** `id.secret.ca_sha256`: `secret` is 128 bits (`secrets.token_urlsafe(16)`), stored as SHA-256, compared
  with `hmac.compare_digest`; `ca_sha256` is the full 64 hex of the CA's DER. Made on the CLI only, shown once,
  printed as `--token-file` lines, ending in `sudo ./install.sh --hub IP:PORT --token-file FILE` to run from the
  unpacked tarball (client §4.6). The output also names the enrollment port (`--enroll-port`,
  default 8444); the installer uses it only for `/v1/ca` and `/v1/enroll`.
- **Lifetime and binding.** TTL 15 minutes by default, 24 hours at most. `--name` is the unique `hosts.name` (the
  client's hostname is a hint). `--source CIDR` is checked against the TCP peer; `--for HOST` binds an existing row.
- **Single use is atomic.** In `BEGIN IMMEDIATE`: `UPDATE tokens SET used_at=? WHERE id=? AND used_at IS NULL`,
  rowcount checked, in the transaction that signs and writes the host row, so a failed signing spends nothing.
  The token keeps the CSR SHA-256 and the certificate: the same token and CSR within 10 minutes return the same
  certificate (a lost reply costs nothing); anything else is a used token. Five wrong secrets burn an id.
- **Existing hosts.** The hub mints the UUID; a body `host_uuid` is a hint. A plain token creates a new host, and
  gets 409 `host_exists` if the hint matches a row in any state. Only `--for HOST` reuses a UUID. Re-enrollment, rehome and reinstall of a known host need `token create --for
  HOST`: the hub reissues under that UUID, sets the new serial and retires the old. **Bulk:** `--names web-1,web-2,...
  [--ttl 4h]` makes one name-bound token and install line per host; `--for` takes a comma list too.

### Enrollment

- **Order of checks** on `POST /v1/enroll` (port 8444, open only while a token is pending): body size cap, token
  id and secret compare (against a dummy hash for an unknown id, so timing leaks nothing), existing-host rules,
  and only then the CSR and `openssl`. Unknown id, wrong secret, expired and used return the same 401. Failures
  are limited to 5 a minute per source address and to a fixed global number a minute (set in code, in a bounded
  table). `GET /v1/ca` answers from memory
  with `Cache-Control: no-store`: no disk, no subprocess. The reply: UUID, certificate, CA, `hub_addresses` (bare IP literals) and `port` (the fleet port, a separate integer),
  expiry, state `pending`.
- **Every enrollment is audited and alerted HIGH** ("host X enrolled from IP Y, token made by Z"); the always-send
  rule is in §4 (Admin actions). The hub records `droplet_id` at
  enrollment and in heartbeats; two ids on one certificate, or a change from enrollment, raise a HIGH "possible clone".

**Host states** (the contract; runbooks are in §15):

| State | Set by | Certificate | Never-ban | Alerts |
|-------|--------|-------------|-----------|--------|
| `pending` | enrollment | valid | kept | none until first heartbeat; HIGH after 1 h |
| `active` | first accepted heartbeat | valid | kept | normal |
| `moved` | rehome `deregister`, `host HOST mark-moved` | revoked | removed | silenced; shown in Fleet |
| `retired` | `host HOST retire`, uninstall `deregister` | revoked | removed | silenced; out of Fleet and correlation |
| `revoked` | `host HOST revoke` | revoked | kept | rejected attempts counted and alerted |
| `orphan` | restore (§7) | valid until adopted | none | HIGH; events kept, no policy, no renew |

- A UUID in any state, `moved`, `retired` and `revoked` included, re-enrols only with `--for HOST`; a plain token
  with that UUID as its hint gets 409 `host_exists`.
- **Offboarding an operator:** the runbook is in §15 (hub first, then every client; admin addresses are local to
  each client, client §17). The audit actor is `SUDO_USER`; per-person accounts are out of v1.

---

## 3. Storage and retention

SQLite in WAL mode, `/var/lib/edr-hub/hub.db`, mode `0640`, group shared with the dashboard user (`UMask=0027`).

### Threads and the writer
- **One writer thread owns the only write connection.** Separate connections that read then write fail at once with
  "database is locked" (tested: 1,979 of 2,400 transactions; `BEGIN IMMEDIATE` gave 0). Handlers, the correlation
  engine (ticks every 10 s, cursor in `meta`) and `ctl.sock`, `ui.sock` and `out.sock` handlers
  put work on a bounded queue (256 items).
- The writer runs one `BEGIN IMMEDIATE ... COMMIT` per drained group. A handler replies only after the commit,
  because the client deletes its spool on that reply; so the writer uses `synchronous=FULL` (under WAL, `NORMAL` can
  lose a committed transaction on power loss; one fsync per group is cheap at this load). A full queue gives 503 with `Retry-After`.
- Token redemption, ban changes and revocation run inside that transaction (single use cannot be raced); a
  CRITICAL alert goes into `outbox` in the same transaction as its event.
- **Pragmas** on the writer, in this order: `auto_vacuum=INCREMENTAL` on the new file, before `journal_mode=WAL` and
  before the first `CREATE TABLE` (once WAL has written the header it is silently ignored; tested); then
  `journal_mode=WAL`, `synchronous=FULL`, `foreign_keys=ON`, `busy_timeout=5000`, `cache_size=-20000`, `mmap_size=0`,
  `temp_store=MEMORY`, `journal_size_limit=1048576` and `max_page_count` from `--max-db-size`. An existing database
  with `auto_vacuum` 0 needs `PRAGMA auto_vacuum=INCREMENTAL; VACUUM` once. `VACUUM INTO` keeps `auto_vacuum` but writes
  a journal-mode-delete file, so the hub sets WAL again at open after a restore. `wal_checkpoint(PASSIVE)` runs after
  each group commit and `TRUNCATE` nightly.

### Dashboard reader
- The dashboard opens `file:...?mode=ro` per request, fetches everything and closes. This works only while the hub's
  write connection is open: SQLite deletes `-wal` and `-shm` when the last connection closes cleanly, and a
  read-only reader then cannot open the file (tested). So the hub never closes its connection (shutdown is flush,
  checkpoint, `os._exit`), and a UI connection must never be the last one.
- If the open fails the UI answers 503 and retries ("hub down"). No read transaction may stay open between
  requests, the live feed included: a pinned reader blocks checkpoints (the WAL reached 36 MiB in the test).
- Files inherit the database's mode and group (tested), so `UMask=0027` and a shared group let `edr-hub-ui` read
  them; `ca/` stays `0700 edr-hub`. The server certificate `tls/server.pem` and key `server.key` (owner `edr-hub`, key `0600`) sit under `/var/lib/edr-hub/tls` and are not backed up (§2, §7).

### Tables

| Table | Holds |
|-------|-------|
| `hosts` | uuid, name, ips (display), os, versions, current and pending certificate DER SHA-256 (the check) and serial (display), expiry, `droplet_id` (first seen at enrollment), state (`pending`, `active`, `moved`, `retired`, `revoked`, `orphan`) and `state_since`, clock skew, last seen, last `seq` and epoch, `boot_id`, `agent_sha256`, `schema` |
| `events` | `id INTEGER PRIMARY KEY AUTOINCREMENT`, host, `event_id`, received_at, ts, source, severity, kind, summary, details, src_ip, `src_trust`, `dst_ip`, `dst_port`, `proto`, community_id, `epoch`, `seq`, `agent_ver`, count, first, last, replayed; `UNIQUE(host, event_id)`; columns follow the client Appendix B field names, except `severity` (from `sev`), `event_id` (from `id`, `<epoch>:<seq>`), and `first` and `last` (from `first_ts` and `last_ts`); `ts` is stored after skew correction (§2) and `src_trust` is `tcp`, `claimed` or `none`; indexes on (received_at), (host, received_at), (src_ip). `proc`, `context`, `boot_id`, `redacted` and `truncated` stay inside `details`, so no client field is dropped |
| `daily_counts` | day, host, source, kind, count: roll-up of LOW and INFO |
| `heartbeats`, `inventory` | latest heartbeat per host plus a 5-minute sample for 24 h; latest inventory per host is the heartbeat's `inventory` object (client §4.5.1; `unknown` kept as `unknown`). `inventory.<check>` events carry findings only |
| `bans`, `feeds` | bans: cidr, reason, source, created, expires, created_by; feeds: name, url, `status`, last fetch, count, checksum |
| `tokens` | id, hash, name, bound host, source address, expires, used_by, used_at, CSR SHA-256, issued certificate (for the 10-minute replay) |
| `incidents`, `incident_events` | id, host, opened, state (open / acknowledged / resolved), severity, chain, closed_by, note; event ids pinned against pruning |
| `outbox` | id, channel, payload, attempts, next_try, state |
| `login_codes` | hashes of single-use dashboard login codes, expiry, `used_at`. Dashboard sessions are never stored: they are held hashed in the dashboard's memory (§5) |
| `never_ban`, `settings_history`, `agent_hashes` | never-ban list (cidr, reason, added_by, ts); every settings change with who and when (secret keys recorded as "changed", never the value); local agent-hash overrides. Settings live in `/var/lib/edr-hub/settings.json` and secrets in `/etc/edr-hub/secrets.json` (§14), never in the database |
| `alert_state`, `ban_votes`, `maintenance` | alert dedup and storm state; fleet-ban votes (host, ip, evidence, ts); maintenance windows (host, until, set_by) |
| `audit`, `meta` | `audit`: the columns and the hash chain are defined in §5 (Audit); `meta`: `schema_version`, engine cursor, last prune and check times |

### Retention
Retention and the size cap use `received_at`, never the client `ts` (a clock set to 2030 would pin rows). Daily jobs
run at `daily_job_utc` (setting, default `03:00`).

| Data | Kept |
|------|------|
| INFO and LOW events | 7 days raw, then rolled into `daily_counts` (kept 1 year) and deleted |
| MEDIUM events | 30 days (`retention_days`, `--retention-days`) |
| HIGH and CRITICAL events | 180 days |
| Events pinned by an incident | while the incident exists, up to 10% of the cap; incidents 1 year after closing |
| `audit`, `settings_history` | 3 years |
| `tokens`, `login_codes`, `outbox` | 30 days after expiry, 1 day after expiry, 30 days after sent |

Collapsed events carry `count`, `first` and `last`; every rule sums `count`, not rows. HIGH and CRITICAL are never
collapsed or budgeted. `--max-db-size` defaults to 2 GB.

### Sizing (estimates; measure on the real fleet in week one)
Measured 875 B per row with three indexes; events per day (after client collapsing) are estimates, not fleet data.

| Events/day/host | 10 hosts, 7 d | 50 hosts, 7 d | 10 hosts, 30 d | 50 hosts, 30 d |
|-----------------|---------------|---------------|----------------|----------------|
| 1,000 | 0.06 GB | 0.3 GB | 0.26 GB | 1.3 GB |
| 5,000 | 0.3 GB | 1.5 GB | 1.3 GB | 6.6 GB |
| 30,000 | 1.8 GB | 9.2 GB | 7.9 GB | 39 GB |

- Real use falls between the 7-day and 30-day columns. At the 90% where pruning starts (1.8 GB), 30 days raw fits
  10 hosts at about 6,800 events a day or 50 hosts at about 1,370 (the full 2 GB gives about 7,600 and 1,500); beyond that the pressure order below applies. Without the client budget (client §4.5),
  500 events every 5 s is 8.6 million rows a day per host: the hub cap protects only the disk.

### Pruning
- **Pressure order:** LOW older than 7 days, then any LOW, then MEDIUM older than 14 days. Never HIGH or CRITICAL.
  Past the 10% pin bound, the oldest pinned LOW and MEDIUM rows are released.
- **Size** is `(page_count - freelist_count) x page_size + WAL`, not the file size, which does not shrink after
  deletes. Pruning starts at 90% of the cap, checked after each group commit and at the daily job.
- Deletes run in the writer in batches of 10,000 (tested: 200,000 rows in 2.2 s, worst batch 0.13 s). Between ingest
  batches it runs `PRAGMA incremental_vacuum(2000)` in a loop and **fetches every result**: without the fetch, or with
  `auto_vacuum=0`, nothing is freed (tested: 350 MB to 176 MB in 1.5 s). `check.sh` fails if `auto_vacuum` is 0.

### When the cap or the disk is reached
- `max_page_count` is a hard cap; the WAL (about 1 MiB after a checkpoint) sits on top. Inserts then fail with
  "database or disk is full" and deletes still work (tested). A full disk gives the same error.
- The writer runs one emergency prune (10,000 oldest LOW and INFO) and retries once. If still full, LOW and INFO get
  503 with `Retry-After`. HIGH and CRITICAL are alerted from memory and appended to `critical-overflow.jsonl`
  (20 MB bound), and the hub answers 200 only after that; if the append fails too the answer is 503 and the client
  keeps them. The file is replayed into the database when space returns. `edr-hub status` shows "storage full".

### Integrity and migrations
- `PRAGMA quick_check` runs weekly at the daily job and after an unclean start, on a read-only connection. A failure
  raises a CRITICAL from memory and stops writes; recovery is the last backup (§7), checked with `integrity_check`.
- Migrations and the known agent hashes (`agent-hashes.json`) are in §17; the hub refuses a database newer than its code.

---

## 4. Correlation, alerts and response

### Engine

- **Where and state.** One engine thread in `edr-hub.service` (the single writer, §3) ticks every 10 s and reads
  events with `id` above a cursor in the database. The cursor, `alert_state`, `incidents`, `outbox`, ban votes and
  maintenance windows are tables, so a restart loses nothing; windows are rebuilt from stored events at start.
  Delivery is `edr-hub-out`'s job, not the engine's.
- **Time.** Hub-side rules use `received_at`. Event windows use the event time, unless it is in the future or the
  host's skew is over 5 minutes, then `received_at`.
- **Start-up grace.** Agent-silent is not evaluated until 2 x the heartbeat interval + 5 minutes (7 minutes) after
  process start or any hub downtime, and per host until it has had one chance to reconnect. After an outage over
  10 minutes the hub sends one "hub was down from X to Y" alert, not one per host.
- **Late and out-of-order events.** A spool replay arrives in bursts with old times. Events are de-duplicated by
  (host, id) and keep both times; each tick re-checks the windows that new rows touch, so a late batch lands in the right
  incident. Events flagged replayed (older than 10 minutes after skew correction, §2) show as "late", page only if CRITICAL and never create a ban or a vote; over 1 hour the digest names the delay. A gap in a host's
  sequence numbers, or a rising spool drop counter, is a MEDIUM digest line: events were lost.
- **Timers.** Heartbeat 60 s, back-off capped at 60 s (client §4.5). Agent-silent: "late" at 4 minutes, HIGH at 5.

### Rules (v1, deliberately simple and explicit)

Severity scale: client Appendix B. INFO and LOW stay on the dashboard (LOW also in the daily digest), MEDIUM goes to
the digest, HIGH alerts now (`alert_min_severity`, §14), CRITICAL goes to every channel. Events are
attributed to the certificate CN, never to a name in the body. The "next step" opens the alert; the runbook is
`docs/RUNBOOK.md` (§15).

**Attacks on a host**

| Rule | Kind or field | Severity | Action and next step |
|------|---------------|----------|----------------------|
| A web-user process execs, writes code or becomes uid 0 | `tetragon.nginx-exec`, `tetragon.web-exec`, `tetragon.web-write-code`, `tetragon.privilege-escalation` from a web-user tree | CRITICAL | Patch if vulnerable, snapshot, then restart nginx (not reload): Sigkill stops the exec, not code already in the worker |
| An SCTP socket, or the `sctp` module loading | `tetragon.sctp-socket`, `tetragon.monitor-kernel-modules` (tag `sctp`) | CRITICAL from a web-user tree, else HIGH | NGINX2Root's root step ([Xint](https://xint.io/blog/nginx2root-remote-code-execution)) |
| `.env` read by an unexpected program; tampering; a decoy file read | `tetragon.env-read`, `tamper.*`, `canary.file` | HIGH | Assume `.env` was read: rotate `APP_KEY`, database and API secrets |
| nginx worker crashes: 3 in 10 minutes on one host | `nginx.crash` | HIGH | Possible exploit attempts; low fidelity alone ([CERT-EU](https://cert.europa.eu/publications/security-advisories/2026-022/)) |
| One :443 connection past 4 GiB | `edr.bigconn` | MEDIUM; HIGH if a crash follows in 30 min | The client bans the source on a repeat (client §4.2) |
| `client violated connection flow control: received WINDOW_UPDATE ...` from one IP, 3 in 10 minutes | `nginx.marker.window_update` | MEDIUM | Local ban. A rejected attempt on patched builds. Logged only at `info` ([nginx source](https://raw.githubusercontent.com/nginx/nginx/release-1.31.9/src/http/v2/ngx_http_v2.c)); `edr-check` warns if hidden |
| `could not cancel ... resolving` | `nginx.marker.resolver_cancel` | HIGH | Logged at ALERT only by **unpatched** builds (CVE-2026-123634): patch |
| Tripwire path hit (P1b): status 404, 403 or 444 / status 200 | `canary.tripwire` (`details` carry the status) | the client bans locally (client §4.2), LOW / HIGH | A 200 means the site serves it: no ban, check the site |
| New uid-0 account, `sudoers` or `authorized_keys` change (P1b) | `inventory.auth_state` | HIGH | Defined in client §4.5.1 |
| A tailed log file shrank (P1b) | `tamper.log_truncated` | HIGH | Defined in client §4.5 (Log shrink) |
| A new key or first root login, or a password login with password auth off (P2) | `ssh.login` | MEDIUM / HIGH | A new source address is a digest line. 14-day learning at LOW |
| Scanner or web signal from an address in the never-ban ranges | field `src_ip` in a never-ban range, on `suricata.alert`, `ssh.fail`, `canary.tripwire` or `tetragon.web-exec` | MEDIUM; CRITICAL for `web-exec` | Never banned. Load balancers are internal, so a hint only |

**Containment and loss of visibility.** Two outcomes are possible after the first signals.

| Rule | Kind or field | Severity | Action and next step |
|------|---------------|----------|----------------------|
| **Attempt contained**: a crash, `edr.bigconn` or flow-control line, then a killed `nginx-exec` or `sctp-socket`, within 30 min | `nginx.crash`, `edr.bigconn`, `nginx.marker.window_update`, then `tetragon.nginx-exec` or `tetragon.sctp-socket` | CRITICAL | Restart nginx; hunt for persistence (`authorized_keys`, cron, `ld.so.preload`); patch |
| **Worker survived the kill**: a fork-watch hit, then any web event from the same host within 10 min | `tetragon.fork-watch`, then `tetragon.web-exec`, `tetragon.web-write-code` or `tetragon.web-connect` | CRITICAL | Restart nginx (not reload); the hub tracks it as an open operator task, cleared when inventory shows worker start times newer than the hit |
| **Possible success**: those first signals, then within 30 min a heartbeat gap, `tamper.*`, or a heartbeat showing Tetragon unhealthy | hub-side heartbeat gap; `tamper.*`; heartbeat `tetragon` | CRITICAL | Treat the host as lost: snapshot, rebuild, rotate every secret it held. One `signal 6` was all a lab RCE left ([Censys](https://raw.githubusercontent.com/Censys-Research/nginx2root/main/evidence/cve-2026-123007/RCE-CONFIRMED.md)) |
| Enforcement gone: a policy set to enforce is disabled or missing in the heartbeat `tetragon` list, or the `kernel` changed without a passed canary, over 5 min after boot | `health.enforcement_gone`; heartbeat `tetragon` and `kernel` | HIGH | Read the heartbeat's policy list; restart Tetragon; run `edr-check` on the host |
| Agent silent (see "Engine"), unless in maintenance or retired | hub-side: time since the last heartbeat | HIGH; CRITICAL within 30 min of a rule above | Down, tampered with or blinded. Silent 14 days: a daily "retire it?" line, paging continues |
| Reboot: notice then a new boot id within 10 min / a new boot id with no notice | heartbeat `shutdown` and `boot_id` | INFO / MEDIUM; HIGH within 30 min of a Sigkill hit | Check the console. Over 10 min of silence after a notice is the real alert |
| Unknown or changed agent build | heartbeat `agent_sha256` and `agent_version` | HIGH | The hash is not in `agent-hashes.json` or a local `agent-hash add` override, or changed while the version did not (§17). Re-check the build; add it with `edr-hub agent-hash add SHA` if intended |
| Duplicate identity: one certificate from two droplet ids, or two live boot ids | heartbeat `droplet_id` and `boot_id` | HIGH | A clone or a stolen key. Clone: enrol it with a plain token (new UUID, client §4.6) and retire the old row only if its droplet is gone. Stolen key: `host HOST revoke`, then re-enrol the real host with a token made `--for HOST` |
| Disk guard tripped, or free space under 10%, on a client | `health.diskguard`, `health.disk_low` | CRITICAL | Sent from memory first, not from a spool on the full disk |
| A host lags `policy_rev_applied` by over 5 min, or reports `last_apply_error` | heartbeat `policy_rev_applied`, `last_apply_error` | MEDIUM | The host is not applying bans |
| A pause is in force (`edr-agent pause`, at most 24 h) | heartbeat `paused_until` in the future | MEDIUM, once per pause | Bans, feeds, enforcement (except `edr-canary`) and the DNS lock are off until it ends or `edr-agent resume` (client §4.7); shown on the Fleet page. A pause does not silence agent-silent |
| No daily canary result from a host in 26 h (P2) | absence of `canary.policy_check` | MEDIUM, once per host | The daily canary through `edr-policy-check` did not run (client §4.3) |
| `inet edr` absent for 2 min | heartbeat `nft` (`table_present` false) | HIGH | The `edr-bans` timer did not rebuild it |
| Conntrack use of 70% or more (90%: HIGH) | heartbeat `conntrack` (count, max) | MEDIUM | Raise `nf_conntrack_max` or check for a flood (client §4.2) |
| Suricata kernel drops over 1% in a window | heartbeat `suricata_drops` | MEDIUM | Client §4.1 |
| Suricata rules not updated for 3 days | `health.rules_stale` | MEDIUM | Client §4.1 |

**Inventory, coverage and fleet**

| Rule | Kind or field | Severity | Action and next step |
|------|---------------|----------|----------------------|
| Package below its fix **and** the feature exposed (see "Advisory data") | `inventory.nginx_pkg`, `inventory.nginx_exposure`, `inventory.security_pending` | HIGH; MEDIUM for the resolver bug when `mirror_request_body off` is not set | Repeat daily until fixed. A TLS listener alone: HIGH after 24 h |
| Old nginx processes run the pre-upgrade binary (`/proc/<pid>/exe` is `(deleted)`) | `inventory.deleted_exe` | HIGH | Restart nginx or let workers drain; a reload never loads a new binary ([site](https://nginx2root.com/)) |
| `sctp` loadable, running kernel below its fix, other updates pending or reboot required over 7 days | `inventory.sctp`, `inventory.kernel_pending`, `inventory.security_pending` | MEDIUM | Daily digest. The **running** kernel decides, not the package |
| A file under `public/` holds an `APP_KEY=` line (P1b) | `inventory.posture` (field `app_key_in_public`) | HIGH | Rotate `APP_KEY`, remove the file (client §4.5.1) |
| Coverage drift | `inventory.uncovered_webroots`, `inventory.uncovered_fpm_binaries`, `inventory.uncovered_pool_users` | MEDIUM | Daily digest. Re-run discovery (client §7) |
| Inventory file missing or over 2 hours old | `inventory.stale` | MEDIUM | The agent reports "unknown", never "clean" (client §4.5) |
| Same IP with qualifying evidence from 2 distinct host certificates in 1 h (P3) | hub-side: `ban.local` votes | MEDIUM | Fleet ban ("Fleet bans") |

**Admin actions** are notifications, not detections. They always send as HIGH, bypassing the minimum severity and
dedup: token created or used, re-enrolment, host revoked or retired, never-ban or settings changed, new dashboard
session (with its source), over 5 failed dashboard logins, and a ban of /16 or wider. A webhook change goes to the
old channel too. A message never holds a token secret.

**Hub self-health**, from the hub's daily job and the checks in "Watching the hub" (lifetimes are in §2):

| Rule | Kind or field | Severity | Action and next step |
|------|---------------|----------|----------------------|
| Client certificate under 30 days from expiry, unrenewed | heartbeat `cert_not_after` | LOW (digest) | An expired one cannot renew: `edr-agent enroll --token-file FILE` with a token made `--for HOST` (client §4.6) |
| Client certificate under 14 days, unrenewed | heartbeat `cert_not_after` | MEDIUM | The same |
| Client certificate under 7 days, unrenewed | heartbeat `cert_not_after` | HIGH | The same |
| Hub server certificate under 30 days (the automatic reissue failed) | server certificate `notAfter`, hub-side | MEDIUM | A lapse stops the whole fleet: `edr-hub reissue-cert` |
| Hub server certificate under 14 days | server certificate `notAfter`, hub-side | HIGH | The same |
| Hub server certificate under 7 days | server certificate `notAfter`, hub-side | HIGH | The same |
| CA under 2 years | `ca/ca.pem` `notAfter`, hub-side | MEDIUM | Replace the CA by year 8 (§2): CA rollover is a rehome of every client |
| CA under 1 year | `ca/ca.pem` `notAfter`, hub-side | HIGH | The same |
| A feed older than 2 days, or refused as anomalous | `feeds.status` | MEDIUM | Check the fetch (client entries expire on their timeout, client §4.2) |
| Advisory table over 90 days old | date of the advisory table, hub-side | MEDIUM | Update the hub release |
| Advisory table over 180 days old | date of the advisory table, hub-side | MEDIUM; status "unknown", never "fixed" | Update the hub release |
| Last good backup over 7 days old | `meta`, read from `/var/lib/edr-hub/last-backup` | HIGH | `edr-hub backup`; the marker is written by the backup job after a verified backup (§7, §8 step 8) |
| Database over 80% of its cap, WAL over 256 MB | hub-side checks (§3) | MEDIUM | A pinned reader keeps the WAL growing (§3) |
| Disk over 80% used | hub-side check | MEDIUM; HIGH at 90% | Thin the backups; see §15 |
| Outbox failing over 1 hour | `outbox` rows | dashboard and `edr-hub status` | The webhook cannot report its own failure |
| Engine cursor over 60 s behind | engine cursor in `meta` | HIGH | `edr-hub health` fails (see "Watching the hub") |

### Incident lifecycle

- **Open** on the first signal; key (host, chain). A new signal within 30 minutes extends it; a repeat only counts.
  Severity is the highest member; two distinct signal kinds in 30 minutes raise it one level (CRITICAL stays
  CRITICAL). The dashboard shows a timeline (as `analyse.py`'s host scoring does).
- **Acknowledged (P3).** `edr-hub ack ID [--for 4h]` or a dashboard button (UI-permitted, audited) records who and
  until when and stops repeats; a severity increase or new signal kind still alerts. An unacknowledged CRITICAL
  repeats every 30 minutes, 3 times at most; HIGH does not repeat.
- **Resolved** after 60 minutes with no signal, or by `edr-hub resolve ID`.

### Fleet bans

The only automatic action the hub takes, so the most limited. Fleet bans, the `ban`, `extend`, `unban` and `bans`
commands and the Bans page are P3; in P2 the policy document carries peers only.

- **Votes** are `ban.local` events counted by **distinct certificate CN**; a host's events about its own addresses
  are ignored; each host casts 20 votes a day at most, so one rooted host cannot burn the cap.
- **Evidence quality.** The client marks each `ban.local` event with `src_trust` (client Appendix B). Only `tcp`
  (an established flow, or an address the writing daemon recorded and the anchored rules of client §4.5 extracted) counts as a vote. A Suricata alert alone (UDP, QUIC, one SYN) can be forged by spoofing
  the victim's address: it raises an incident, never a vote.
- **Quorum** 2 votes from 2 certificates within 1 hour. **Ladder** the client's (client §4.2); IPv4 as /32, IPv6 as /64.
  **Budget** `fleet_ban_budget_per_hour` (§14), 10k in all; beyond it, HIGH once.
- **Dry run.** A new hub starts with `fleet_ban_mode = dry-run`: it shows "would ban" and sends none. Only the CLI
  sets `on`, after a week of would-be bans has been read.
- **Never banned.** The literal table (client §4.2), the hub, admin CIDRs (seeded by `--admin-ip`), entries added with
  `edr-hub never-ban add`, the optional crawler and payment list, and **peers** (the TCP source the hub saw, 2 per
  host at most: §2). The policy sends peers to every client, which checks them first.
  Never-ban does not mean never-alert.
- **Limits** are the client's (client §4.2); the client's checks are a second line. Hosts with `real_ip` set cast no web-sourced
  votes. All bans are audited.

### IP feeds

- **P3.** In P2 the `feeds` part of the policy document is empty.
- **Live lists only:** Spamhaus DROP (IPv4 and IPv6 JSON; skip the last, metadata, line) and FireHOL `dshield`. The feed names are `spamhaus_drop_v4`, `spamhaus_drop_v6` and `dshield`.
  EDROP is part of DROP.
  Feed and webhook URLs must be https and must not resolve to a private, loopback or `169.254.169.254` address.
  Fetch at most once a day, keep the Spamhaus attribution header, check each list's terms at build.
- **Carving.** Drop an entry that is not globally routable or lies inside a never-ban range; carve any never-ban
  range out of an entry that contains one (`address_exclude`); collapse. The client repeats it and reports leftovers.
- **Freshness and size.** The `feeds` row has a `status`. The last good copy is kept when a fetch fails to parse,
  is empty over a non-empty copy, changes size by over half, or loses over 5% of entries to carving. A feed whose last
  good fetch is older than 72 h is dropped from every policy document and `edr-hub status` shows it as dead; a
  fresh fetch brings it back.
- **On the client.** Feeds expire 72 h after the last successful policy poll (200, or 304 meaning unchanged) whose
  document contains that feed. A feed key absent from the document is removed at the next apply (absence is not
  "empty"). A dead hub therefore lets entries lapse; the hub does not re-send an unchanged list. The client
  enforces feed minimum prefixes /12 (IPv4) and /29 (IPv6), at most 2% of IPv4 coverage after never-ban carving,
  0.5% new coverage per update and 200,000 feed CIDRs in all (client §4.2).

### Policy document

- `GET /v1/policy` is a **full per-host document** `{rev, hub_time, hub_addresses, port, bans, feeds, peers}` (Appendix A); the ETag
  is that host's revision. In P2 only `peers` (and the hub addresses and port) are filled; `bans` and `feeds` are empty until P3. Ignore rules, thresholds and enforcement are local only (client §14).
- **Expiry is absolute** (`expires_at`). With `hub_time` the client computes the relative timeout nftables needs,
  `expires_at - hub_time`, so its own clock error cannot shift a ban.
- An unban is absence from the next document. Reasons never name other hosts. A rehome keeps local bans (client §5).
- The heartbeat carries `policy_rev_applied` and `last_apply_error` (Appendix A).

### Advisory data for inventory rules

**Status is computed on the client from apt** (`security_pending`, list age, held and phased counts; client
client §4.5.1), so it works with no hub and covers every package. The hub's table adds the exploitable feature, other
origins and "no fix yet". `nginx -v` cannot show a distro fix, because Ubuntu backports keep the version
([Xint](https://xint.io/blog/nginx2root-remote-code-execution)). The table is `common/advisories.json`; files in
`/var/lib/edr-hub/advisories.d/` override it and survive uninstall.

- **Rows are keyed by `(origin, os release)`** from `edr-inventory`. Ubuntu rows: `dpkg --compare-versions` on the
  full version. nginx.org: upstream version only (strip `-1~codename`). Any other origin or release gives
  "unknown: check by hand", never "vulnerable". Ondrej's PPA has no row. Unit tests: Ubuntu `1.24.0-2ubuntu7.20`
  must not match the nginx.org row; `1.30.7-1~noble` is fixed, `1.30.6-1~noble` vulnerable.

| Origin | Release | Vulnerable when | Also covers | Ref |
|--------|---------|-----------------|-------------|-----|
| Ubuntu `nginx`, `nginx-core/full/light/extras` | noble | < `1.24.0-2ubuntu7.20` | NGINX2Root CVEs (123007, 123633, 123634, 113425), 118899 | [USN-9159-1](https://ubuntu.com/security/notices/USN-9159-1) |
| same | resolute | < `1.28.3-2ubuntu1.13` | the same, 120967 (client-cert bypass), 121810 (HTTP/3 connection reuse), 123640 (ClientHello leak) | [USN-9159-1](https://ubuntu.com/security/notices/USN-9159-1) |
| nginx.org `nginx` | any | < 1.30.7, or >= 1.31.0 and < 1.31.9 | the same, 118899 | [nginx.org](https://nginx.org/en/security_advisories.html) |
| Kernel SCTP, CVE-2026-64564 (ASCONF) | noble GA 6.8 | running < `6.8.0-147.147` | patched; **reboot needed** | [CVE](https://ubuntu.com/security/CVE-2026-64564) |
| same | noble HWE 7.0 | running < `7.0.0-38.38~24.04.4` | same | same |
| same | resolute | running < `7.0.0-38.38` | same | same |
| Kernel SCTP, Xint send-path bug | all | no CVE or fix known as of 19 Nov 2026 | NGINX2Root root step; recheck weekly | [Xint](https://xint.io/blog/nginx2root-remote-code-execution) |

- 118899 is an endless loop reading a request body over TLS 1.3 (nginx 1.13.0 to 1.31.8), so it hits every HTTPS
  site. A TLS listener alone gives HIGH after 24 h; HTTP/2, HTTP/3, mail or resolver exposed, HIGH now; none, a digest.
- Kernel rows compare the **running** kernel from `/proc/version_signature` (`Ubuntu 7.0.0-43.43-generic 7.0.14`;
  confirm the field on both releases). On noble the series (6.8 or 7.0) picks GA or HWE.

### Alert delivery

- **Outbox.** The alert row is written to `outbox` in the same transaction as the event. `edr-hub-out` sends it
  (5 s timeout) and reports each result over `out.sock`; ingest never waits. Retries at 1, 5, 15 and 60
  minutes for 24 hours, honouring `Retry-After`. CRITICAL goes to every channel.
- **Storm control.** At most 20 messages per 10 minutes, then one "N alerts suppressed" summary. CRITICAL is exempt
  but limited to 1 per (host, kind) per 5 minutes. A severity increase bypasses dedup (per (host, kind), 30 min).
  The in-memory send queue holds 200 and drops the oldest with a counter; the outbox keeps the row.
- **Body.** Severity, host and public IP, kind, one line of meaning, the "next step", the incident id and the exact
  commands (`edr-hub incident 41`, `edr-hub ack 41`, the host command), so a 03:00 alert is actionable from a phone
  over SSH (Termius, Blink) or the DigitalOcean web console; the dashboard is not published for phones. One table
  in the hub code feeds alerts, runbook and dashboard. No secrets.
- **Escaping.** Every attacker field goes through the hub's sanitiser (same rules as client §4.5), is cut to 200
  characters and put in a code span (backticks replaced), so nothing auto-links or mentions anyone. Then per channel:

| Channel | Rule |
|---------|------|
| Slack-compatible | Escape `&`, `<`, `>` first; `unfurl_links` and `unfurl_media` false; no `link_names` |
| Discord (P3) | `allowed_mentions: {"parse": []}`; at most 2000 characters; a custom User-Agent (the default Python one is often blocked) |
| ntfy | JSON publish to the server root; fixed titles; never set `Click` or `Actions` from event data; bearer token; self-hosted or a long random topic |
| E-mail (P3) | `EmailMessage(policy=policy.SMTP)` (raises on CR or LF in a header); plain text; fixed subject plus validated host name; SMTPS or STARTTLS, `ssl.create_default_context()` |
| All HTTP | https only, default verification (`--webhook-ca` adds a private CA; no off switch), redirects refused |

- **Secrets.** The webhook URL, SMTP password and ntfy token are bearer secrets. They live in
  `/etc/edr-hub/secrets.json` (root, 0600; §8 step 2), which `edr-hub-out` receives with `LoadCredential=`. The
  root CLI process writes the file directly when a secret key is set from stdin (`edr-hub settings set webhook_url -`),
  never from argv and never over `ctl.sock`; `settings_history` records only that the key changed. Secrets are shown
  as host plus last 4 characters, scrubbed from logs and audit, and kept in the backup (§7).
- **Testing.** `edr-hub alert test [--channel NAME]` goes through the outbox and prints the result per channel. A
  failing channel is a red banner on the dashboard and in `edr-hub status`.

### Watching the hub

A dead hub looks like a quiet fleet. Four layers, none relying on the one before:

1. **Dead-man ping (recommended, P2).** With `deadman_url` set (empty by default) `edr-hub-out` sends a plain GET
   each minute, no body, no host identifiers (it tells a third party a hub exists). The external dead-man service alerts when pings
   stop, so a hub that is down, or restarted and not back within the service's grace period, is noticed even when the
   hub's own alerting is dead.
2. **Health.** `edr-hub health` (local CLI only) is 0 only if the writer committed or idled within 30 s and
   the engine cursor is current. `check.sh` uses it; there is no health route on any port.
3. **Watchdog.** `edr-hub.service` runs under the systemd watchdog, fed from the writer loop (idle tick
   included); `OnFailure=` has `edr-hub-out` send one direct message (§8 step 4).
4. **Clients.** After 15 minutes without hub contact an agent writes a recurring WARN to its journal and `edr-check` warns
   (client §4.7); its HIGH and CRITICAL events stay in the journal at priority `crit`. No webhook secret goes on a web server.

**Independent witness.** A taken-over hub writes its own audit and alerts. A client on the hub host runs in local
mode with `edr-notify`, not pointed at itself. Each agent journals every policy revision it applies, and
`edr-check` warns when its bans exceed a local ceiling. Monthly drill: compare `edr-agent bans` on one client with
`edr-hub bans`.

### Maintenance windows

`edr-hub host HOST maintenance --for 30m` (2 hours at most, as client §4.7; audited; INFO notification;
`edr-agent maintenance` (client P3) sets the same state in the heartbeat; `edr-hub host HOST maintenance --end` ends it early) silences **only** agent-silent and the reboot rule for that host. Attack rules still
alert. A planned reboot needs no window (a shutdown notice plus a new boot id is INFO).

---

## 5. Dashboard website (`edr-hub-ui`, its own port)

A local website, installed and running by default, separate from the client ingest port.

### Process and port
- `edr-hub-ui.service` on port **8450** (`--ui-port`), bound to `127.0.0.1`, as its own user `edr-hub-ui`: loopback
  only, no CA key, no write access to `/var/lib/edr-hub/`.
- **Reused from `tetragon/viewer/`:** the standard-library server, the Host allowlist, the constant-time compare
  and the unit's sandbox lines. **New code:** login and sessions, headers, Origin checks, POST over `ui.sock`, the
  change poller, caps and timeouts, rendering rules. The viewer has none of these (token in `localStorage` and in
  `/events?token=`, no headers, one unbounded thread per stream).
- **Unit:** the directives of `edr-hub-ui` are the UI column of the §8 step 4 table (`Wants=` and `After=edr-hub.service`;
  `AF_INET6`, with `IPAddressAllow=::1/128` added, only if `[::1]` is bound). It never shares `RuntimeDirectory=` with the hub, or a hub restart would delete
  `ctl.sock`. With the hub down the UI shows "hub down" and retries. It reads `hub.db` (0640, group `edr-hub-ui`), not
  `ca/` or `secrets.json`.

### Access
- **v1: SSH tunnel only.** `ui-url` holds the base URL, no secret:

      ssh -L 8450:127.0.0.1:8450 root@hub
      sudo edr-hub ui-login        # prints http://127.0.0.1:8450/#code=… ; valid 10 min, one use

- **No TLS mode in v1.** Serving the UI with the hub's certificate would put the ingest key in the UI process and
  teach operators to import a CA that also signs the fleet. After v1: a WireGuard or Tailscale bind, a name-constrained
  UI CA (needs DNS, email and URI subtrees too; tested), or a Let's Encrypt IP certificate
  ([GA 2026-01-15](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability)). The dashboard has no listening mode beyond loopback in v1.
- **Login:** `edr-hub ui-login` (root, `ctl.sock`) mints a 128-bit single-use code, stored hashed in `login_codes`
  (§3), valid 10 min.
  1. The page reads the fragment, calls `history.replaceState` at once, POSTs the code to `/api/login`.
  2. The UI redeems it over `ui.sock` (marked used, audited, notified with the source address).
  3. The reply is a 256-bit session token in page memory and `sessionStorage`, sent as `Authorization: Bearer`.
     **No cookie**: no cross-port cookie leak and no cookie CSRF.
- **Session:** idle 30 min, absolute 12 h, held hashed in UI memory only, never stored (a UI restart logs everyone
  out); Logout button
  and `POST /api/logout`; digests compared with `hmac.compare_digest`.
- **Failed logins:** at most 5 per minute in total, then 429; each is a journal line (no secrets) and a counter in
  the header; more than 5 a minute alerts (§4). The live feed uses `fetch()` with a stream reader, not
  `EventSource`, so no secret is ever in a URL query.

### Headers and request checks
- At start-up the server reads `index.html` once, keeps it in memory, hashes its single inline `<script>` and
  `<style>`, and sends:

      Content-Security-Policy: default-src 'none'; script-src 'sha256-<js>'; style-src 'sha256-<css>';
        connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'

  - The page has no `style=` attributes and no inline `on*=` handlers (use classes and `addEventListener`); a hash
    covers inline blocks only, so injected markup is blocked.
- Every response also has `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy`
  and `Cross-Origin-Resource-Policy: same-origin`, a restrictive `Permissions-Policy`, and `Cache-Control: no-store`
  on the API. No CORS, no HSTS.
- **Host:** exact allowlist with the port: `127.0.0.1:PORT`, `localhost:PORT`, `[::1]:PORT` if bound to IPv6. A
  missing Host is refused. A tunnel on another local port needs `--ui-host`.
- **POST:** an `Origin` equal to an allowed Host (`Sec-Fetch-Site: cross-site` is rejected), `Content-Type:
  application/json`, the bearer header, `Content-Length` at most 16 KiB; handler timeout 10 s. Unit tests: wrong
  Host or Origin gets 403, missing bearer 401.

### Rendering rules (every event field is attacker-influenced)
- Data enters the page only through `textContent` or `createElement`. No `innerHTML` with data, no data in
  attributes or `href` (URLs are text, never links), no data inside the HTML or script.
- Stream `event:` and `id:` are fixed names and numbers; `data:` is one-line `json.dumps` (default `ensure_ascii`).
- Ingest (§2) enforces closed vocabularies for `source` and `sev` (client Appendix B); `kind` must match `^[a-z0-9_.-]{1,64}$`, and an
  unknown kind is stored and shown as received (no rule fires on it). Host names match `^[a-z0-9]([a-z0-9-]{0,61})$`.
  Caps: `summary` 256 characters, each `details` string 512 (`args` 1024, `url` 512), `details` 4 KiB in all,
  serialised event 10 KiB, over which ingest refuses it (§2). A host's display name is the token's `--name`; the client-reported
  name shows as "reported (untrusted)".

### Pages
- One HTML page (no data in it), one inline script and style. No CDN, no build.

| Page | Shows / does |
|------|--------------|
| **Fleet** | Every host: state, heartbeat, health (Suricata, Tetragon, DNS lock, agent), versions, **NGINX2Root exposure**, disk budget, open incidents, and a note when a host is paused or in maintenance. Banners: hub down, alert delivery failing |
| **Events** | Live feed with severity, host, source and kind filters; a click loads the details |
| **Incidents** | Correlated groups with timelines. Action: **acknowledge** (P3) |
| **Host** | Timeline, inventory, ban counts by source (heartbeat) and `ban.local` events, certificate expiry, the `local.conf` hash; a read-only settings view (P4) of `local_conf_sha256` and the policy modes the heartbeat already carries (Appendix A). Actions: **mark moved**, **maintenance** (with expiry; **end maintenance** early) |
| **Bans** (P3) | Active bans and feeds, source, expiry. Actions: **ban**, **unban**, **extend** |
| **Enroll** | Token list: id, name, source binding, expiry, state. Creating is CLI only; the page shows the command |
| **Audit / Settings** | Every change with actor and outcome / read-only settings (webhook shown as host and last 4 characters) |

- **CLI only:** every row of the §6 socket table marked `no` for `ui.sock`; the reason is §1 principle 3.

### Live feed
- The WAL files exist because the hub never closes its connection (§3). `events.id` is `INTEGER PRIMARY KEY AUTOINCREMENT`: ids never repeat.
- One poller thread checks `PRAGMA data_version` once a second (tested: it changes after another connection
  commits), reads `events WHERE id > last`, and fans out through a bounded queue per client. A client that falls
  behind gets `event: reset` and is dropped. Rows are compact (fields at most 2 KiB); details load from
  `/api/event/<id>` on click.
- **Caps:** 8 streams, 2 per session (429 beyond; browsers allow 6 per origin); 15 s write timeout; a ping every
  15 s that re-checks the session; 15 min maximum per stream; the client resumes with `Last-Event-ID`.

### How changes are made
- The UI cannot write to the database. It sends JSON to `ui.sock`; the main process validates, applies, audits.
- Three sockets, group access from setgid directories: `ExecStartPre=+` sets the directory and `ExecStartPost=+` sets
  each socket's group and mode after it is bound (§8 step 2); the process never calls `chown` and has no
  `SupplementaryGroups=`. Sockets are created under `umask 0117`. The UI and out units retry until the post step has
  run.
  - **`ctl.sock`** (0600 `edr-hub`, reached by root) takes every command.
  - **`ui.sock`** (0660, group `edr-hub-ui`, `SO_PEERCRED` checked) takes the whitelist in the §6 table.
  - **`out.sock`** (0660, group `edr-hub-out`, `SO_PEERCRED` checked) takes only outbox items, feed jobs and their
    results for `edr-hub-out`; no admin verb.
    `edr-hub-out` gets only `secrets.json` by `LoadCredential=`; `outbox.take` and `feed.job` carry the channel, its
    non-secret options, `alert_min_severity`, the text of `webhook-ca.pem`, feed URLs and limits (§8 step 2).
- **Limits on all three:** one JSON line of at most 64 KiB, 5 s timeout, 8 concurrent connections; an unknown or
  non-whitelisted command is refused and audited.

### Audit
- Columns: `ts`, `actor_kind` (cli, ui, system, client), `actor_detail`, `action`, `target`, `outcome` (ok, denied,
  invalid, error), `details`, `prev_hash`, `hash`. The main process sets `actor_detail`:
  - CLI: `uid=0 pid=N` from `SO_PEERCRED` at accept, plus `loginuid=1000` read by the CLI from its own
    `/proc/self/loginuid` and sent with the request; it is CLI-supplied (`unknown` if absent), best effort. The hub
    cannot read another uid's loginuid under `ProtectProc=invisible` (§8).
  - UI: `ui session=<first 8 hex of the session hash> addr=<peer>`, UI-supplied and labelled so. With one shared
    admin identity in v1, the audit names a login uid or session, not a person.
- **Tamper evidence:** `hash = sha256(prev_hash || canonical_json(row))`; `edr-hub audit verify` checks the chain.
  The head hash goes into the daily digest and the journal; a root attacker on the hub defeats the chain, the
  off-box copy is the defence. The 3-year prune writes a `prune` row with the last deleted hash.
- Denied socket commands, bad UI logins and bad enrollment tokens are recorded. Unauthenticated-failure rows
  (`actor_kind = client` with outcome denied or invalid) are one row per source per minute with a count (1000
  sources a minute, then `other`), capped at 10,000 a day and then one summary row with the count; they are pruned
  after 30 days. Operator, system and enrollment-success rows keep the 3-year rule. The audit table counts against
  the database cap (§3), and the self-health alert fires at 80% of it.

---

## 6. CLI (`edr-hub`)

    edr-hub status                          # services, DB size, hosts up/down, feed age, alert delivery,
                                            #   backup age; prints the ui-login and incident commands
    edr-hub host list [--all] | HOST show      # fleet table / one host
    edr-hub host HOST revoke | retire | mark-moved | maintenance [--for 2h | --end]
    edr-hub host UUID adopt                 # orphan UUID after a restore (§7)
    edr-hub events [--host H] [--since 1h] [--min-sev high] [--json]
    edr-hub incidents [--open] | incident ID | ack ID [--for 4h] | resolve ID    # ack: P3
    edr-hub token create (--name web-1 | --names web-1,web-2,... | --for HOST[,HOST...]) [--ttl 1h] [--source CIDR]
                         | list | revoke ID
    edr-hub ui-login                        # one-time dashboard login URL (§5)
    edr-hub ban CIDR [--ttl 24h] [--reason …] | extend CIDR --ttl 24h | unban CIDR | bans    # P3
    edr-hub never-ban add|remove|list CIDR [--reason …]
    edr-hub settings get [KEY] | set KEY VALUE | set KEY -      # "-" reads the value from stdin
    edr-hub alert test [--channel NAME]
    edr-hub export events|audit|bans [--since 7d]    # P3; JSON lines
    edr-hub audit [--since 1d] | audit verify
    edr-hub backup [--out FILE] | restore FILE [--ca-key FILE] [--drill] | ca-export [--out FILE]    # P2
    edr-hub reissue-cert                    # new server certificate (§2, §15)
    edr-hub health                          # local health check, exit codes in §17
    edr-hub agent-hash add SHA              # add a known agent hash (§17)

- **Tokens:** rules in §2 (Tokens). `--names` makes one name-bound token and install line per host (`--ttl` 24 h at
  most); `--for` takes a comma list too. `list` shows id, name, source, expiry and state only.
- **Bans (P3):** in P2 the policy document carries peers only, so `ban`, `extend`, `unban` and `bans` (and their
  dashboard actions) start in P3 with fleet bans and feeds (§4).
- **Maintenance:** `--for` sets the window (2 hours at most, §4); `--end` closes it early. Neither touches a client
  pause (`edr-agent pause` and `resume`, client §4.7).
- **Retire and adopt:** `retire` sets the host to `retired` (certificate revoked, silenced, out of Fleet and
  correlation; §2); `adopt` takes an `orphan` UUID left by a restore back into service (§7).
- **Settings:** every key, its default and which keys are secrets are in §14. Non-secret keys are set over
  `ctl.sock`. A secret is set from stdin only (`settings set webhook_url -`), never from `argv`: the root CLI writes
  `/etc/edr-hub/secrets.json` (0600) directly, not over `ctl.sock`, and the settings history records only that it
  changed. Secrets are hidden from `status`, the UI, logs and audit details (host plus last 4 characters at most).
- **Backup and restore** are root-only file operations, not socket commands (§7): a backup holds the database,
  `settings.json` and the secrets but no CA key, so it is written 0600 and encrypted with the passphrase file
  `/etc/edr-hub/backup.pass` (schedule and restore: §7, §15). The CA key leaves only through `ca-export`, which asks for its own passphrase.
  `restore` refuses unless `edr-hub` is stopped; `restore --drill` skips the secrets (§7). `export` writes JSON
  lines (P3), with `ensure_ascii=True` as in the output rules below.

### Which socket takes which command
`ctl.sock` (root CLI) accepts every command. `ui.sock` (the dashboard) accepts only the rows marked UI. `out.sock`
(`edr-hub-out` only) accepts `outbox.take`, `outbox.result`, `feed.job` and `feed.result`; no admin verb is reachable
on it. Reads do not use a socket: the CLI and the UI open the database read-only.

| Command | `ctl.sock` | `ui.sock` | Limit on the UI |
|---------|:---:|:---:|-----------------|
| `ban`, `extend` (P3) | yes | yes | not wider than /16; not overlapping never-ban |
| `unban` (P3) | yes | yes | |
| `host … mark-moved`, `maintenance` (including `--end`) | yes | yes | maintenance has an expiry, at most 2 hours |
| `ack` (P3) | yes | yes | |
| `login.redeem` | no | yes | single-use code; failures counted (§5) |
| `host … revoke`, `retire`, `adopt`, `resolve` | yes | no | |
| `token create`, `list`, `revoke` | yes | no | |
| `never-ban`, `settings` (non-secret keys), `alert test`, `reissue-cert`, `agent-hash add` | yes | no | |
| `ui-login` (mint), `audit verify` | yes | no | |
| `backup`, `restore`, `ca-export`, `health` | no socket | no | root file access; `edr-hub` stopped for restore |

- Request limits, peer checks and refusal of unknown commands are in §5.

### Output safety
- One `clean()` serves the CLI and the alert senders: characters in Unicode categories Cc, Cf, Cs, Co, Cn, Zl and
  Zp (ESC, OSC 8 links, C1 CSI, bidi overrides, zero-width characters, DEL) become `\uXXXX`, then the text is
  truncated. Every attacker-influenced field passes through it before it reaches a terminal.
- `--json` keeps `ensure_ascii=True`, so those characters stay escaped. No colour when stdout is not a terminal.
- **Exit codes** are defined once, in §17.

---

## 7. Moving the hub

**Backups.** The hub makes an **encrypted backup on a schedule** and watches its age (§8 installs the timer,
§15 has the restore drill). The contract:
- **A backup holds** `hub.db` (an online copy made with `VACUUM INTO`), `settings.json`, `secrets.json`, the never-ban list, the
  hub address list, `ca/ca.pem` and `ca/revoked.txt`. **It holds no CA key and not the hub's server certificate and key** (restore reissues them). Its contents are still sensitive
  (event details, tokens' hashes), so it is encrypted before it leaves the process and verified by checksum
  before restore. After a verified backup the job writes `/var/lib/edr-hub/last-backup` (0644), which the daily job
  reads for the backup-age rule (§4). The encryption uses the passphrase file `/etc/edr-hub/backup.pass` (root, 0600; §14), shown once at
  install for storing off the box.
- **`edr-hub ca-export`** writes the CA key once, as PKCS#8 encrypted with a passphrase
  (`openssl pkcs8 -topk8 -v2 aes-256-cbc`), for off-box storage. Run it once after install and after any CA change;
  the passphrase is separate from `backup.pass` and is kept offline. A restore on a new box needs both. Without
  the CA key a backup restores history but not the CA, so every client must re-home (below).
- Integrity checks and the restore drill are in §3 and §15 (a drill box has `edr-hub-out` disabled before `restore`,
  and `restore --drill` skips the secrets). The hub never restores or starts empty by itself.

**Moving with a backup and the CA key.** `edr-hub restore FILE --ca-key FILE` runs on a new box after
`server_hub/install.sh`, with `edr-hub` stopped, and replaces the fresh state:
1. Decrypt, check the checksum, run `quick_check` on the database.
2. **Every token is marked invalid** (a restored database would otherwise revive redeemed ones).
3. Reissue the hub server certificate and key (`/var/lib/edr-hub/tls/server.pem` and `server.key`) from the restored CA, with a new random serial and the SAN from the stored
   address list plus any new `--public-ip`; print the CA SHA-256 (unchanged, so existing pins match).
   A fresh install prints a new one, and then old tokens and pins do not match.
4. Print the serials in `revoked.txt` and the database. A revocation made after the backup lives only in alerts
   and the audit of the lost box, so the operator re-revokes those serials by hand (`host HOST revoke`).
5. **Hosts enrolled after the backup** (and hosts renewed since) present a certificate the restored `hosts` table
   does not hold. Accept it only if the certificate is signed by the CA, is not in `revoked.txt`, and its
   serial is absent from the restored `hosts` table (the certificate's `notBefore` is not used). The host goes to state `orphan`: events kept,
   no policy, no renewal, a HIGH alert, until `edr-hub host UUID adopt`. Older certificates keep the restored
   state, so a host revoked before the backup stays out. A certificate issued and revoked since the backup is the
   one gap, and the serial list from step 4 covers it.

**Clients after a restore.**
- If the Reserved IP moved to the new box, clients change nothing and reconnect on their own.
- Otherwise each client re-homes with a token made `--for HOST` (a bulk list is allowed): `edr-agent rehome
  --hub NEW_IP:PORT --token-file FILE`. The UUID is unchanged, so history continues. The client checks the new hub
  against the token, enrolls, makes a test request, and switches only then (client §5).

**With no backup, or no CA key.** Install a fresh hub with a new CA and re-home every client with plain tokens
(new UUIDs; history starts over). Old pins and tokens do not match. Replacing the CA on purpose (year 8) or after theft:
runbook in §15 (CA compromise).

Decommissioning a host (uninstall, rehome, destroyed droplet, suspected compromise) is the §2 Host states
table; runbook in §15.

---

## 8. Install

    sudo server_hub/install.sh [--port 8443] [--enroll-port 8444] [--ui-port 8450]
                               [--admin-ip CIDR ...] [--public-ip IP ...] [--clients-only]
                               [--retention-days 30] [--max-db-size 2G] [--ui-host HOST:PORT ...]
                               [--webhook-ca FILE] [--plan] [--yes] [--force]
    sudo server_hub/install.sh --confirm       # from a new SSH session, after the firewall step (step 10)

Flags seed `/var/lib/edr-hub/settings.json` on the first run only. A re-run upgrades the code and keeps the CA,
database, tokens and settings; a flag named again (`--admin-ip` replaces the whole list) changes just that setting.
`--ui-host` and `--webhook-ca` are settings (§14). `--force` only permits a downgrade (§17). `--plan` prints what
would be written. Secrets (webhook, SMTP, ntfy, dead-man URL) are never flags: `edr-hub settings set KEY -` (§6).
The source of `$SSH_CONNECTION` joins `--admin-ip` automatically (the output says so). Over SSH the installer
re-runs itself under `systemd-run --unit=edr-hub-install`, so a dropped session does not stop it half-way. The
firewall is the only step that can lock you out, so it comes last (step 10). Exit codes: §17.
`/etc/edr-hub/manifest.jsonl` records every file written and prior value (§9).

1. **Pre-flight** (refuses before changing anything, except WARN):
   - Ubuntu 24.04 or 26.04, systemd, `python3` 3.12+, `openssl`, `nftables`, SQLite with `VACUUM INTO`.
   - Clock synchronised (`timedatectl`; tokens and certificate dates depend on it). SSH port from `sshd -T`.
   - Addresses: public, VPC and each `--public-ip`; WARN if no Reserved IP is passed (not on the NIC, §2).
   - Free disk at least the database cap plus `backup_keep` backups of that size (§14); WARN under 2x.
   - WARN: `ufw` active (the installer prints the `ufw allow` lines, never edits UFW); the admin account has no
     local password (the DigitalOcean Recovery Console needs one; confirm what the Droplet Console needs in the
     DigitalOcean docs); no admin address at all (SSH is then open to all).
2. **Users and directories.** Four system users, `nologin`, fixed names (§9 keeps them): `edr-hub` ingests and
   writes, `edr-hub-ui` is the dashboard, `edr-hub-out` makes every outbound connection (feeds, webhooks,
   dead-man ping), `edr-hub-ca` is the signer (P3).

   | Path | Owner:group, mode | Holds |
   |------|-------------------|-------|
   | `/var/lib/edr-hub` | `edr-hub:edr-hub-ui`, `2750` | `hub.db`, `-wal`, `-shm` (`0640`, group inherited), `settings.json`, `advisories.d/`, `webhook-ca.pem` (the `--webhook-ca` file, copied here by the installer; a public certificate), `last-backup` (`0644`, written by the backup job, §7) |
   | `/var/lib/edr-hub/ca` | `edr-hub`, `0700` | CA key and certificate, `revoked.txt` (P3: the key moves to `/var/lib/edr-hub-ca`, the signer's own `StateDirectory`, owner `edr-hub-ca`, `0400`; the certificate and `revoked.txt` stay here) |
   | `/var/lib/edr-hub/tls` | `edr-hub`, `0700` | Hub server certificate `server.pem` and key `server.key` (`0600`); reissued at runtime (§2), not backed up (§7), kept on uninstall (§9) |
   | `/var/backups/edr-hub` | `root`, `0700` | Encrypted backups (step 8) |
   | `/run/edr-hub` | `edr-hub:edr-hub`, `0711` | `ctl.sock` `0600` `edr-hub`; `ui.sock` `0660` group `edr-hub-ui`; `out.sock` `0660` group `edr-hub-out` (outbox and feed verbs only) |
   | `/etc/edr-hub` | `root:root`, `0750` | Firewall file, `ui-url` (`0600`), `manifest.jsonl`, `secrets.json` (webhook, SMTP, ntfy and dead-man secrets; written by the root CLI, §6) and `backup.pass` (the backup passphrase file; encrypts scheduled backups; shown once at install; not the `ca-export` passphrase), both `0600` |

   `edr-hub` has no access to `/etc/edr-hub`, so a hijacked ingest process cannot swap or read the secrets or the
   passphrase. `edr-hub-out` gets `secrets.json` only as a systemd credential; everything else it needs (the
   channel and its non-secret options, the text of `webhook-ca.pem`, feed URLs and limits) arrives inside the job
   it takes from `out.sock` (§5). One directory holds three sockets of three groups, so it needs traverse access for `edr-hub-ui` and
   `edr-hub-out`: `ExecStartPre=+` sets the directory mode and `ExecStartPost=+` sets each socket's group and mode
   once it is bound (confirm both in the VM test). Verbs per socket: §5, §6.
3. **CA and certificates,** only if absent (§2; the SAN holds every hub address). The installer runs
   `openssl verify -x509_strict` and prints the CA SHA-256. **Code:** root-owned copies in
   `/usr/local/lib/edr-hub`, the CLI in `/usr/local/sbin/edr-hub`.
4. **Units.** Shared directives for every hub unit (`UMask=0027` on `edr-hub`, `0077` on the others):
   `NoNewPrivileges=yes`, `CapabilityBoundingSet=` (empty), `ProtectSystem=strict`, `ProtectHome=yes`,
   `PrivateTmp=yes`, `PrivateDevices=yes`, `DevicePolicy=closed`, `ProtectKernelTunables=yes`,
   `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`, `ProtectClock=yes`,
   `ProtectHostname=yes`, `ProcSubset=pid`, `RestrictNamespaces=yes`,
   `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`,
   `SystemCallArchitectures=native`, `SystemCallFilter=@system-service` then `SystemCallFilter=~@privileged
   @resources`, `RemoveIPC=yes`, `KeyringMode=private`, `LogNamespace=edr-hub`. `ProtectProc=invisible` on every unit,
   `edr-hub` included: the CLI sends its own login uid, and the hub takes only uid and pid from `SO_PEERCRED` (§5). Per unit:

   | | `edr-hub` | `edr-hub-ui` | `edr-hub-out` | `edr-hub-ca` (P3) |
   |---|---|---|---|---|
   | Address families | INET INET6 UNIX | INET UNIX | INET INET6 UNIX | UNIX |
   | Network | inbound only (step 5) | `IPAddressDeny=any`, `IPAddressAllow=127.0.0.0/8` | outbound | `PrivateNetwork=yes` |
   | Limits | `MemoryHigh=400M`, `MemoryMax=512M`, `TasksMax=200` | `MemoryMax=128M`, `TasksMax=64` | same as UI | `MemoryMax=64M` |
   | Files | `ReadWritePaths=/var/lib/edr-hub` | `ReadOnlyPaths=` the state dir, `InaccessiblePaths=` `ca` and `tls` | `LoadCredential=` `secrets.json` from `/etc/edr-hub`; `StateDirectory=` for `channels.json` | `StateDirectory=edr-hub-ca` (the key and a copy of the CA certificate) |
   | Type | `notify`, `WatchdogSec=60`, `Restart=on-failure`, `StartLimitBurst=5` per 300 s; `After=edr-hub-nft.service` | `exec`, `Restart=on-failure`, `Wants=` and `After=edr-hub.service` | same as UI | `exec`, `Before=edr-hub.service` |

   - Only `edr-hub` has `RuntimeDirectory=edr-hub`, plus the `+` steps for the modes and groups above (the process must not `chown`: `@privileged` contains `@chown`). A UI-owned runtime directory would be
     deleted on a UI restart, taking `ctl.sock` with it. The UI uses `Wants=`, not `BindsTo=`: it shows "hub down".
   - No `PrivateUsers=`: `SO_PEERCRED` in a user namespace reports an unmapped peer such as root as 65534, which
     would break the per-uid verb limits (§5). Confirm in the VM test before adding it.
   - `OnFailure=edr-hub-failed.service` (oneshot as `edr-hub-out`, with the same `LoadCredential=` as `edr-hub-out`;
     it reads the channel and its non-secret options from `channels.json` in `edr-hub-out`'s `StateDirectory=`, which
     `edr-hub-out` rewrites from each job it takes) sends one message after repeated failures; a
     single restart is silent (the dead-man gap, §4). Only `systemd-analyze security --offline` has run on these
     units: confirm in the VM test that all start under the filter and `MemoryDenyWriteExecute`.
5. **Firewall rules.** The installer writes them now and loads them last (step 10). One table, `inet edr_hub`, in
   `/etc/edr-hub/edr-hub.nft`. The file begins with `table inet edr_hub` and `delete table inet edr_hub`, so loading it
   again (a re-run, an upgrade, the boot unit) replaces the table instead of appending every rule a second time. The input chain has policy **drop**, so every accept below must exist. The default-drop shape, the meter and the uid drop were each tested
   in a throwaway namespace; `nft -c` gates the whole file:

       set admin4 { type ipv4_addr; flags interval; }
       set admin6 { type ipv6_addr; flags interval; }
       set synmeter4 { type ipv4_addr; flags dynamic,timeout; timeout 1m; size 65536; }
       set synmeter6 { type ipv6_addr; flags dynamic,timeout; timeout 1m; size 65536; }
       chain input {
         type filter hook input priority -10; policy drop;
         iif lo accept                                   # dashboard, sockets, stub resolver
         ct state invalid drop
         ct state established,related accept
         icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
         icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem,
                       nd-neighbor-solicit, nd-neighbor-advert } accept     # nd-router-advert only if SLAAC
         icmp type echo-request limit rate 5/second accept
         icmpv6 type echo-request limit rate 5/second accept
         udp sport 67 udp dport 68 accept                # DHCP
         ip saddr @admin4 tcp dport 22 accept            # 22 = the `sshd -T` port; ip6 saddr @admin6 likewise
         tcp dport { 8443, 8444 } tcp flags & (syn | ack) == syn meta nfproto ipv4 add @synmeter4 { ip saddr limit rate over 5/second burst 10 packets } counter drop   # one line: nft rejects a newline after `{`
         tcp dport { 8443, 8444 } accept                 # with --clients-only (P3): 8443 only from @clients4/6, see below
       }                                       # the IPv6 meter rule is the same on @synmeter6, keyed by the /64 (§2)
       chain output {
         type filter hook output priority 0; policy accept;
         meta skuid "edr-hub" ct state new drop
       }

   - **The ingest user cannot start outbound connections.** `edr-hub` parses internet input and holds the CA key
     (until P3), so a hijacked process must not be able to call out. `IPAddressDeny=` cannot do it: it filters
     ingress too (systemd.resource-control). The rule drops new connections only, so replies to clients pass
     (tested: inbound reached the uid's listener, its own outbound connect timed out). Load the table after the
     users exist. Everything outbound is `edr-hub-out`.
   - With no admin address the installer emits `tcp dport 22 accept` in place of the two admin lines.
   - **`--clients-only` (P3).** The table gains the sets `clients4` and `clients6`, and the accept for 8443 is limited to
     them (8444 stays as it is). `edr-hub` writes the enrolled addresses and each pending token's `--source` range to
     `/run/edr-hub/clients.json`; a root oneshot, `edr-hub-clients.service` (started by a path unit on that file and by a
     60 s timer), validates IP literals only and fills the sets, treating the file as hostile exactly as the client's
     `edr-bans` treats its input (client §4.2). With no client enrolled the limit is not applied.
   - An accept here never overrides a drop in UFW or a DigitalOcean Cloud Firewall. Cloud Firewall: §2.
6. **Updates and reboots.** `unattended-upgrades` on, with `/etc/apt/apt.conf.d/52edr-hub` setting
   `Automatic-Reboot "false"`: reboot by hand when `/var/run/reboot-required` appears (start-up grace covers it, §4).
   `needrestart` does not restart services under `unattended-upgrades`: restart `edr-hub` after a `python3` or
   `openssl` update. The hub units log to the journal namespace `edr-hub`, capped by
   `/etc/systemd/journald@edr-hub.conf` (`SystemMaxUse=150M`, `RuntimeMaxUse=50M`; read it with `journalctl
   --namespace edr-hub`); the system journal is left alone.
7. **Dead-man ping** (P2, optional). `edr-hub settings set deadman_url -`; `edr-hub-out` then pings each minute
   (§4). The output says it tells a third party that a hub exists.
8. **Scheduled backups.** `edr-hub-backup.timer`, daily 02:15 UTC (`Persistent=yes`), runs `edr-hub backup` as root;
   format, passphrase handling and `ca-export` are §7. It keeps `backup_keep` copies (default 14, §14), free space
   checked first. The installer prints the passphrase once (store it off the box) and tells you to run
   `edr-hub ca-export`. Pull `/var/backups/edr-hub` to your own machine: no credentials go on the hub. Add a weekly
   DigitalOcean snapshot. The hub alerts at 7 days without a good backup (§4).
9. **Start.** Start `edr-hub`, `edr-hub-out`, `edr-hub-ui` and wait for `edr-hub health` (§4). On a first install the
   firewall is not loaded yet, so the listeners are open without it until step 10 (no host is enrolled and every
   route needs a client certificate or a token). A re-run keeps the loaded table until step 10 replaces it.
10. **Apply the firewall, then confirm (the last system-changing step).** `nft -c -f`, then `nft -f`, then the
    installer arms `systemd-run --on-active=300 --unit=edr-hub-fw-rollback nft delete table inet edr_hub`. The
    installer then waits. From a NEW SSH session run `sudo server_hub/install.sh --confirm` (within the 300 s): it
    cancels the timer and only then enables `edr-hub-nft.service` (oneshot, `Before=network-pre.target`, `nft -c`
    first), so the table survives a reboot. This is the rule over SSH. From the DigitalOcean console there is no
    timer and the service is enabled at once. If the timer fires first, the table
    is gone, the installer exits **4** and says so; `--confirm` after that changes nothing and tells you to re-run
    `install.sh`. If your address changes later, use the DigitalOcean console, then re-run with `--admin-ip NEW`.
    The installer then runs `check.sh`, writes the base UI URL to `/etc/edr-hub/ui-url`, and prints the CA SHA-256,
    the first enrolment command (`edr-hub token create --name first`), and the `edr-hub alert test` and
    `edr-hub ui-login` commands.

**Sizing.** 1 vCPU and 1 GB RAM for about 50 clients, which is tight: the three services are held near 650 MB by
`MemoryHigh`/`MemoryMax` (768 MB hard limit; 832 MB with the P3 signer), so use 2 GB above about 50 clients. Disk:
the 2 GB database cap, up to 14 backups of that size (compressed, usually far smaller), the 150 MB journal namespace
and the OS: 35 GB if the backups do not compress, otherwise 25 GB is enough while the database stays well below its
cap. Exit codes: §17. The hub host may also run `server_client` in local mode with `edr-notify` (client §4.7), never
pointed at itself.

---

## 9. Uninstall

    sudo server_hub/uninstall.sh            # asks first; keeps data
    sudo server_hub/uninstall.sh --yes
    sudo server_hub/uninstall.sh --purge    # also deletes the database, the CA, the backups and the users

**Default**, in this order:
1. **Final backup** to `/var/backups/edr-hub/` (encrypted, as in §7), if the database opens. If it does not, say so
   and carry on.
2. Stop and disable `edr-hub-backup.timer`, cancel any `edr-hub-fw-rollback` or `edr-hub-install` transient unit, then
   stop and disable `edr-hub-ui`, `edr-hub-out`, `edr-hub` (and `edr-hub-ca`, P3). Clients spool and retry meanwhile.
3. Disable `edr-hub-nft.service` and delete the `inet edr_hub` table. Do this after the services, so the ports are
   never open without the table.
4. Replay `/etc/edr-hub/manifest.jsonl`: remove the units, `/usr/local/lib/edr-hub` and `/usr/local/lib/edr-hub.prev`,
   `/usr/local/sbin/edr-hub`, the journal namespace configuration `/etc/systemd/journald@edr-hub.conf` (then
   `systemctl stop systemd-journald@edr-hub`) and `/etc/apt/apt.conf.d/52edr-hub`, and restore any prior value the
   manifest holds. A file the manifest does not list is left alone and printed. Then remove `/etc/edr-hub`
   except `secrets.json` and `backup.pass`.
5. **Keep `/var/lib/edr-hub`** (database, CA, server certificate and key in `tls/`, settings, `last-backup`), `/etc/edr-hub/secrets.json`, `/etc/edr-hub/backup.pass` and
   `/var/backups/edr-hub`, so running
   `install.sh` again brings back the same hub and clients keep working without re-enrolling.

**What stays.**
- **The four users and groups** (`edr-hub`, `edr-hub-ui`, `edr-hub-out`, `edr-hub-ca`) stay while data is kept. The
  files belong to a numeric uid, and a user created later could reuse it and read the CA key. A reinstall reuses the
  same names, and `install.sh` sets the state directory back to its own owners and modes (§8 step 2).
- **No package is removed.** `unattended-upgrades` stays on; the manifest lists any package the installer added.
- A DigitalOcean Cloud Firewall and the DNS or Reserved IP records are yours: remove them by hand.

**`--purge`** also deletes `/var/lib/edr-hub`, `/etc/edr-hub`, `/var/backups/edr-hub` and then the four users and groups. Before it
does anything it warns, in this order, that:
- the CA key is deleted, and a backup holds none (§7), so offer `edr-hub ca-export` first;
- every enrolled client then needs a new token from a new hub (`rehome`, client §5) and old pins will not match;
- the backups are deleted too, so copy off anything you want.

It asks twice. It finishes by checking that no `edr_hub` table is left, that nothing listens on the fleet,
enrollment and dashboard ports, and that no `edr-hub*` unit or process remains. A host still enrolled keeps alerting
locally (§4, Watching the hub); a client uninstall does not need the hub (client §6). Exit codes: the
`uninstall.sh` column of §17.

---

## 10. Planned layout

    server_hub/
    ├── PLAN.md               this document
    ├── install.sh            §8; re-runnable, doubles as the upgrade (§17)
    ├── uninstall.sh          §9
    ├── check.sh              read-only health: services, ports, certificate expiry, DB size, `auto_vacuum`, WAL
    │                         size, feed age, backup age, hosts down; exit codes in §17
    ├── docs/RUNBOOK.md       §15; the same "next step" table that feeds alerts and the dashboard (§4)
    ├── pki/strict/           explicit X.509 extension files `ca.ext`, `srv.ext`, `cli.ext` (§2)
    ├── hub/
    │   ├── edr_hub.py        ingest on both listeners, enrollment, SQLite writer, correlation engine,
    │   │                     `ctl.sock`, `ui.sock` and `out.sock` handlers, retention and integrity jobs
    │   ├── edr_hub_ui.py     dashboard server (port 8450)
    │   ├── edr_hub_out.py    feed fetcher, notifiers, dead-man ping: the only outbound code (§4)
    │   ├── edr_hub_ca.py     signer (P3, §2)
    │   ├── ui/index.html     the single-page dashboard
    │   ├── agent-hashes.json accepted agent hashes of this release, written by the release build (§17)
    │   └── edr-hub           CLI (Python)
    └── files/                units for the three services (four with the P3 signer), backup service and timer,
                              the failure-notice unit, nft table; the P3 root helper `edr-hub-clients` (service, path
                              and timer) that fills the `--clients-only` sets; the unit names are fixed in §8

    common/advisories.json    package and kernel advisory table, shared with the client's inventory (§4)

**Installed paths and modes:** §8 steps 2 and 3. Beyond that table: `critical-overflow.jsonl` and `advisories.d/` in
`/var/lib/edr-hub/`, the server certificate and key in `/var/lib/edr-hub/tls/` (§2), `last-backup` written by the
backup job (§7), `/etc/edr-hub/secrets.json` and `backup.pass` (§14), one previous code copy
`/usr/local/lib/edr-hub.prev` (§17) and, in P3, `/run/edr-hub-ca/sign.sock`. `ctl.sock`, `ui.sock` and `out.sock` are all in
`/run/edr-hub/` (§8 step 2). State survives uninstall and is what a backup covers (§7, §9).

---

## 11. Roadmap

The phases and their exit criteria are the client's (client §10); the hub is built so that each client phase has what
it needs. The test tiers are in §12.

| Phase | Hub side |
|-------|----------|
| **P1a, P1b** | No hub is needed: the client runs alone and reports to its own journal and local alert file |
| **P2 (MVP)** | Everything in §2 to §9, §15 and §17 not marked P3 or P4 (including **scheduled encrypted backup, `ca-export` and `restore`**, and `uninstall.sh`), plus: inventory rules with the advisory table (§4), maintenance windows, the rule "no canary in 26 h". The policy document carries peers only: bans and feeds are empty |
| **P3** | Fleet bans (`fleet_ban_mode` starts as dry-run), IP feeds, the `ban`, `extend`, `unban` and `bans` commands and the Bans page, incident acknowledgement and repeating CRITICAL alerts, Discord and e-mail notifiers, `export` (JSON lines), the signer split (`edr-hub-ca`), a CA bundle in `/v1/renew`, the `--clients-only` allowlist |
| **P4** | A read-only view of each client's local settings (the `local_conf_sha256` and policy modes that the heartbeat already carries), and ATT&CK technique ids on rules. Settings stay local to the client, so nothing is distributed |

**Exit criteria** are the client's, with these hub parts:
- **P2:** slow-client and flood tests pass (§12); a revoked, moved or retired certificate is refused; a 60-minute hub
  outage and a hub restart lose no HIGH or CRITICAL event (spool at most 50 MB, delivered within 5 minutes after); the
  restore drill (§12) works onto a second hub and a client `rehome`s to it; `ca-export` has been run and a restore with
  both secrets works; the previous client protocol version works against the new hub.
- **P3:** the two-host fleet-ban round trip takes under 2 minutes; a fleet ban never comes from a canary; the
  per-reporter budget and the dry-run week pass; the restore drill is repeated on the schedule the operator set (§15).
- **P4:** the settings view shows a changed `local.conf` hash and enforcement modes and offers no way to change them.

Two choices to keep: backup and restore are P2 because the uninstall's automatic backup and the "hub is lost" story
need them; the Bans page and fleet-ban rules are P3 because they need fleet bans.

---

## 12. Repo integration and testing (for the implementation phases)

The tiers (L0 lint and unit, L1 network namespace, L2 mock, L3 VM) and the lint changes are in client §11. The hub's
side:

- **`Makefile` and lint.** Add `server_edr_solution/server_hub/install.sh`, `uninstall.sh`, `check.sh` and any helper
  script to `SH_FILES`, and every Python file to `PY_FILES`, including `edr-hub`, which has no `.py` (the shebang scan
  matches `python3`). The units (`*.service`, `*.timer`, `*.socket`) join the `systemd-analyze verify` and `security
  --offline=true` globs. The advisory file gets a schema check. **`make unit`** runs the hub's unit tests with no root.
  The AST check allows only standard-library imports.
- **`tests/dry-run.sh`** is not used for `server_hub/install.sh` until it has a server mode (client §11): the hub
  installer also loads an nft table, creates four users and writes units and a journal namespace. Until then the hub installer is rehearsed in
  the mock or a VM.

### L0: unit tests (no root)

| Area | Cases |
|------|-------|
| Request parser and limits | Every row of the §2 Limits table; `RecursionError`, bad UTF-8 and non-object `details` (400) |
| Tokens and enrollment | Single use; expiry; the same answer for unknown, wrong, expired and used (401); source binding; a plain token whose `host_uuid` hint matches a row in any state gets 409 `host_exists`, and only `--for HOST` reuses a UUID; same token and CSR within 10 minutes returns the same certificate; the CSR's subject and extensions are ignored |
| Identity | Host taken from the certificate CN; a host named in a body is ignored and never causes a refusal; serial pinning for current and pending serials; revoked, moved, retired and superseded refused; `orphan` limits |
| X.509 profiles | `openssl verify -x509_strict` and a TLS 1.3 handshake with both certificate types on Python 3.12 and 3.14 (24.04 and 26.04 OpenSSL); a no-EKU certificate is not accepted as a client certificate |
| Validators | CIDR and never-ban (minimum prefix, UI ban cap); settings keys and the secrets split: a secret is written by the root CLI straight to `secrets.json`, never over `ctl.sock`, and the settings history records only that it changed |
| Storage | A duplicate (host, `id`) is `INSERT OR IGNORE` and counted, the host coming from the certificate; skew correction and the 5-minute clamp; replayed events never feed fleet bans; pruning order and HIGH and CRITICAL never pruned; roll-ups sum `count` |
| Rules and alerts | Every row of the §4 rule tables names a kind or heartbeat key that Appendix A or client Appendix B defines; a rule counts `sum(count)` and distinct certificate CNs; escaping per channel; the sanitiser on hostile fields; a canary never raises a fleet ban; the outbox retries and a failing channel is flagged |
| Dashboard and CLI | Host and Origin checks, single-use login codes, session expiry, CSP header, terminal-safe output, audit chain `verify` |

### L1: network namespace (root)

The `inet edr_hub` table in a throwaway namespace: the per-source SYN meter on 8443 and 8444, the IPv6 /64 form, `--clients-only` (P3), and the `meta skuid` rule that stops `edr-hub` starting outbound
connections.

### Slow-client and flood tests (L2, run against the real server)

Each row of the §2 Limits table and each flood rule in §2 and §3 gets a test that exceeds it by one. Beyond those:
- **Trickle.** One byte a second must be cut by the wall-clock reaper (a trickler was cut at 4 s in the design test), and
  30 connections of maximum-size headers must stay within the memory figure in §2.
- **Handshake and readers.** A client with no certificate on 8443 never reaches the parser; a held live feed must not
  let the WAL pass its alert bound.
- **Sockets.** After a start, the socket directory and each socket have the modes in §8, and the CLI still sends the
  caller's login uid although every unit has `ProtectProc=invisible`.
- **Queue.** With the writer queue full, CRITICAL is still alerted from memory and appended to `critical-overflow.jsonl`.

### Restore drill and compatibility (L2)

- **Restore drill.** Back up hub 1 and restore on hub 2 with the `edr-hub` service stopped: each outcome in the §7
  numbered list holds, then a client `rehome`s with a `--for HOST` token and keeps its UUID and history. The server certificate is reissued,
  not restored. A client certificate the restored database does not know (signed by the CA, not in `revoked.txt`,
  serial absent from `hosts`) makes the host `orphan`. A drill box has `edr-hub-out` disabled before `restore`, and
  `restore --drill` skips the secrets. Repeat with no CA key (new UUIDs) and onto an empty hub (a local ban survives).
- **Old agent, new hub.** An agent built from the previous git tag (`AGENT_REF`) sends heartbeats and events to the new
  hub: protocol N-1 is accepted and unknown fields are dropped; older gets 426, a schema below the previous one gets 422
  `schema_too_old`; the dashboard lists the lagging host. The hub refuses a database newer than its code. Before a schema migration the installer takes an encrypted backup and only then restarts the service; `restore` is the rollback.
- **Clock.** `libfaketime` on the agent: renewal at 30 days, a future timestamp clamped, an old one marked replayed.

### Two-VM flow (L3, with the client)

1. Install the hub and confirm the firewall with `install.sh --confirm` from a new SSH session (an unconfirmed install rolls back after 300 s and exits 4); open the dashboard through the SSH tunnel.
2. `token create --name web1`; install the client with `sudo ./install.sh --hub IP:PORT --token-file /root/edr.token` (client §7): the host is `pending`, then `active`.
3. Run the canary: the event is on `edr-hub events` and the dashboard within 2 minutes.
4. (P3) Ban an address on the hub: it appears in the client's nft set; remove it.
5. Revoke the host: the client is refused (403) and keeps spooling.
6. Block the hub for 60 minutes; the CRITICAL events arrive within 5 minutes of unblocking.
7. Back up, restore on a second hub VM, `rehome` the client; confirm the old hub is deregistered.
8. Uninstall both: no tables, units or ports (8443, 8444, 8450) remain, and no users unless the data was kept.

Memory and timing figures in §2 were taken on Python 3.14: re-measure on 3.12 (24.04) in this flow.

---

## 13. Decisions and open questions

### Decided

| Question | Decision |
|----------|----------|
| Revocation without a CRL | The DER SHA-256 lookup plus host state on every request is enough (§2) |
| Webhook formats | One `Notifier` interface. ntfy and Slack-style JSON in P2 (plain text is simplest to make safe); Discord and SMTP in P3 (§4) |
| Admin actions in the dashboard | Tokens, host revoke, never-ban, settings, backup: CLI only (§6 socket table); a UI compromise could otherwise enrol a rogue host or cut hosts off. The UI may only ban, unban and extend (P3), mark moved, set or end maintenance, and acknowledge (P3). Settings are read-only there |
| Dashboard access | SSH tunnel only in v1. No TLS mode in v1 (§5) |
| Operator identity | One shared admin identity in v1. Audit names the CLI login uid or the UI session (§5) |

### Defaults chosen for questions only the owner can settle
amd64 only; no swap file is created; ntfy and a Slack-compatible webhook first; no
hub-side enforcement of domain feeds; payload excerpts capped and redacted, with a local off switch; crawler and
payment-provider ranges are an optional local never-ban list the operator supplies.

### Still open for the owner
1. **Alert channel:** which of Slack, Discord, ntfy or e-mail do you use? It decides the P2 formatters.
2. **Remote access:** is the SSH tunnel enough for v1, or do you want a browser-reachable mode afterwards (options
   in §5)?
3. **Dead-man's switch:** is one outbound dependency on an external service (a healthchecks-style URL or an ntfy
   topic on another host) acceptable? It is off by default and optional (P2).
4. **Named operators:** is one shared admin identity enough, or do you need per-person accounts? That changes the
   audit and the dashboard login.
5. **Bans from the dashboard (P3):** is it acceptable that a compromised UI can ban up to a /16, with an alert, or
   should banning also be CLI only?
6. **Reserved IP:** will the hub get a Reserved IP (or a VPC address), so a hub move needs no client change?
7. **Slack and Discord details:** the escaping and mention rules in §4 are to be re-checked against their current
   documentation during implementation (not checked against their current documentation yet).

### To confirm during implementation
- The CSP and the rendering rules in a real browser (§5); the CSP rests on MDN, not on a browser test.
- Under the unit sandbox of §8 (`ReadOnlyPaths=`, group-only read on `-shm`), confirm the dashboard's `mode=ro` connection opens a WAL database while the hub holds its connection open.
- The IPv6 equivalent of the /16 cap on UI bans (not chosen yet).
- Python 3.12 (24.04) and 3.14 (26.04) both accept the CA and leaf profiles (§2); 3.12 is the more lenient.

---

## 14. Configuration

Three layers, and a re-run of the installer never resets a choice made later:
1. **Installer flags** seed missing keys. On a re-run a flag that is named again replaces that one key and the
   output says so; keys not named are kept, and secrets are never flags (§8). `install.sh --plan` prints what
   would change.
2. **`/var/lib/edr-hub/settings.json`** holds the plain keys below. `edr-hub settings get [KEY]` and `set KEY VALUE`
   (root, over `ctl.sock`) validate type and range, write it atomically, record who and when in `settings_history`
   and notify (§4). It never holds a secret, only the masked form (host and last 4 characters). The never-ban list
   is edited with `edr-hub never-ban` and lives in the database (§3). The dashboard shows both, read-only.
3. **`/etc/edr-hub/secrets.json`** (root, `0600`) holds the secrets in the second table. `edr-hub settings set KEY -`
   reads the value from stdin and the root CLI writes the file directly, so a secret never crosses `ctl.sock`. The
   CLI then tells the hub only that KEY changed: `settings_history` and the notice (§4) say "changed", never the
   value. `edr-hub-out` receives the file with `LoadCredential=` (§8 step 4) and the CLI restarts it so that the
   new value is read. An empty value switches that channel or ping off.

Client settings are never set from here; the hub shows them read-only (P4, client §14). Limits fixed in code are
named where they apply (§2 to §5).

**Plain keys**

| Key | Default | Flag | Where used |
|-----|---------|------|------------|
| `alert_min_severity` | `HIGH` | none | lowest severity sent as an alert; admin actions bypass it (§4) |
| `digest_time` | `07:00` UTC | none | daily digest of MEDIUM and LOW (§4) |
| `ntfy_url` | unset | none | ntfy server; the ntfy channel is on when this and `ntfy_topic` are set (§4) |
| `smtp_host`, `smtp_port`, `smtp_security` | unset, `587`, `starttls` (or `smtps`) | none | e-mail channel (P3, §4) |
| `smtp_user`, `smtp_from`, `smtp_to` | unset | none | e-mail channel (P3, §4) |
| `webhook_ca` | unset | `--webhook-ca FILE` | PEM file of a private CA for the https channels; its contents go to `edr-hub-out` inside each job; no key turns verification off (§4) |
| `fleet_ban_mode` | `dry-run` | none | `on` only by the CLI, after a week of "would ban" lines (P3, §4) |
| `fleet_ban_budget_per_hour` | `20` | none | cap on new fleet bans (P3, §4) |
| `retention_days` | `30` | `--retention-days` | MEDIUM events (§3) |
| `max_db_size` | `2G` | `--max-db-size` | size cap and pruning (§3) |
| `daily_job_utc` | `03:00` | none | prune, roll-up, integrity check, backup-age rule (§3, §4) |
| `rate_low_per_hour`, `rate_high_per_hour` | `15000`, `1000` | none | per-host token buckets for LOW and INFO, and for HIGH and CRITICAL (§2) |
| `backup_keep` | `14` | none | scheduled backups kept (§7, §8 step 8) |
| `ui_host` | the loopback names with `ui_port` | `--ui-host HOST:PORT` (repeatable) | Host allowlist for the dashboard; the dashboard binds loopback only in v1 (§5) |

**Installer-owned keys.** These shape the firewall and the certificate, so only `install.sh` changes them (a re-run
with the flag, under the safe apply of §8 step 10). `settings get` and the dashboard show them read-only.

| Key | Default | Flag | Where used |
|-----|---------|------|------------|
| `port`, `enroll_port`, `ui_port` | `8443`, `8444`, `8450` | `--port`, `--enroll-port`, `--ui-port` | fleet listener, enrollment listener, dashboard (§2, §5) |
| `admin_ip` | the address of the installing SSH session | `--admin-ip CIDR` (repeatable; replaces the list) | SSH allow rule (§8 step 5) |
| `public_ip` | the droplet's public and VPC addresses found at install, plus each `--public-ip` (a Reserved IP is never found: pass it, §2) | `--public-ip IP` (repeatable) | certificate SAN (§2) |
| `clients_only` | off | `--clients-only` | (P3) fleet port open only to enrolled clients (§2, §8) |

**Secrets** (all in `secrets.json`; none is ever a flag, shown in full, logged or audited)

| Key | Used for |
|-----|----------|
| `webhook_url` | Slack-compatible channel (§4) |
| `discord_url` | Discord channel (P3, §4) |
| `ntfy_topic`, `ntfy_token` | ntfy channel: a long random topic acts as a password (§4) |
| `smtp_password` | e-mail channel (P3, §4) |
| `deadman_url` | external ping each minute from `edr-hub-out`; unset means off (P2, optional, §4) |

A channel is on when its keys are set (`ntfy_token`, `smtp_user` and `smtp_password` are optional), and
`alert test --channel NAME` takes `webhook`, `ntfy`, `discord` or `email`. `settings get` shows a secret only in its
masked form.

Installer flags and defaults: the §8 synopsis. File owners and modes: the §8 step 2 table. The backup passphrase
file is `/etc/edr-hub/backup.pass` (root, `0600`; §7). The server certificate and key are
`/var/lib/edr-hub/tls/server.pem` and `server.key` (§2). `ca/` is `0700`, owned by the key holder (§2); the key
leaves only by `ca-export`, encrypted with its own passphrase and kept offline (§7). Neither the CA key nor the
server key is in a backup.

---

## 15. Operations and runbooks

Every alert carries the exact command (§4), so one person on a phone can act. `docs/RUNBOOK.md` holds the same text.

### Day to day
Commands are in §6. `edr-hub resolve ID` closes an incident; run `edr-hub alert test` after any channel change and
monthly.

### A 03:00 alert from a phone
1. SSH in (a phone SSH client or the DigitalOcean console) and run `sudo edr-hub incident ID`.
2. **HIGH, one signal:** read the events; acknowledge (P3) or leave it for the morning (a HIGH does not repeat; it stays open on the dashboard and in the
   daily digest).
3. **CRITICAL or "possible success":** treat the host as lost (§4). On the host `sudo edr-agent isolate --for 1h`
   (P3, client §4.7; before P3 use a Cloud Firewall outbound rule, client §17); in the DigitalOcean panel snapshot, then rebuild; `edr-hub host HOST revoke` (its key may be
   stolen); rotate every secret it held.
4. **A quiet day:** run `edr-hub status`. A red outbox banner means the webhook is failing; the dead-man service
   (§4) tells you the hub stopped.

### Disk full or database corrupt
- **Disk full** ("storage full" in `status`; LOW and INFO get 503; HIGH and CRITICAL go to `critical-overflow.jsonl`).
  Free space: copy `/var/backups/edr-hub` off and thin it, lower `retention_days`
  or `max_db_size` (`edr-hub settings set`). The writer prunes and replays the overflow file (§3). Never delete
  `-wal` or `-shm` by hand.
- **Corrupt:** see §3 Integrity. `systemctl stop edr-hub`, `edr-hub restore FILE --ca-key FILE` from the newest good
  backup (§7), keep the moved-aside file. Clients replay their spool. Hosts enrolled after that backup show as
  `orphan`: check each, then `edr-hub host UUID adopt`.

### Restore drill (quarterly; schedule it yourself, nothing reminds you)
On a scratch droplet: install the hub (§8), run `systemctl disable --now edr-hub-out`, then `edr-hub restore FILE
--drill --ca-key FILE` (with `edr-hub` stopped, §7). `--drill` skips the secrets, so the drill box has no webhook or
dead-man URL, and `edr-hub-out` is off so nothing posts to them. Check hosts, the CA SHA-256 and `quick_check` in
`edr-hub status`. Destroy the droplet.

### Certificates
- **Hub server certificate** reissues itself at 30 days left (§2). If an alert says otherwise, `edr-hub reissue-cert`.
  A lapse stops the whole fleet at once.
- **Client certificate** renews itself. One that expired (a stopped droplet) cannot: make a token `--for HOST` and
  run `edr-agent enroll --token-file FILE` on that host (client §4.6).

### Rotating secrets
- **Dashboard.** There is no standing token: `edr-hub ui-login` mints a single-use code (§5). `systemctl restart
  edr-hub-ui` ends every session (they live in its memory). The SSH key is the credential.
- **Webhook or SMTP.** Create the new secret at the provider, `edr-hub settings set webhook_url -` (stdin), run
  `edr-hub alert test`, revoke the old one. The change is also sent to the old channel (§4).

### An operator leaves (same day, hub first)
1. Remove their SSH key from the hub and every client; rotate webhook, SMTP, ntfy and dead-man secrets; revoke open
   tokens (`token list`); remove them from the DigitalOcean team and revoke their API tokens.
2. `sudo server_hub/install.sh --admin-ip <remaining>` (replaces the list; safe apply, §8 step 10) and
   `edr-hub never-ban remove CIDR`.
3. On every client remove their address from `admin_ip` and `allow_cidr` in `local.conf`, then `edr-agent
   apply-config` (client §14): admin addresses are local, so no hub command can do it.
4. `edr-hub reissue-cert`; review `edr-hub audit --since 30d` (the actor is `SUDO_USER`; per-person accounts are
   out of v1). If they held the `ca-export` file or its passphrase, the backup passphrase, or root on the hub, do the CA compromise
   runbook.

### CA compromise
1. Install a new hub with a new CA and a new address; do not restore the CA; leave the Reserved IP on the old hub.
2. On the new hub `edr-hub token create --names web-1,web-2,… --ttl 4h` (the hosts get new UUIDs and their history
   stays on the old hub, §7); `edr-agent rehome` each client (client §5). Until a client moves, the thief can pose as the old hub to it, but can only send
   bans, feeds and peers, which the client bounds (client §4.2).
3. Shut the old hub down, retire its droplet, rotate every hub secret.

### Stolen client key
Signs: events or policy requests for a host that is not behaving, or a host you no longer control.
1. `edr-hub host HOST revoke`. Its certificate is revoked at once (`revoked.txt`, §2); further attempts with that
   key are rejected, counted and alerted (§2, Host states).
2. Read what was sent in its name: `edr-hub events --host HOST --since 30d`. With the key a thief can send false
   events and heartbeats as that host and fetch its policy; it cannot reach any other host.
3. If the host is clean, make a token `--for HOST` and run `sudo edr-agent enroll --token-file FILE` on it
   (client §4.6): it makes a new key. If the host is not clean, treat it as lost (§4): snapshot, rebuild, then the same
   token. Either way the UUID and history continue.

### Decommissioning a client
Client uninstall retires the host (client §6); for a destroyed droplet run `edr-hub host HOST retire`. Either revokes
the certificate and drops its never-ban address (§2). Revoke its open tokens; remove its droplet tag.

### Year-two housekeeping

| When | Task |
|------|------|
| Monthly | `edr-hub audit verify`; the silent-hosts digest; from P3, `edr-agent bans` on one client against `edr-hub bans` |
| Quarterly | Restore drill; review `never-ban` and the admin list; feed and advisory age in `status` |
| After kernel, `python3`, `openssl` updates | Planned reboot or `systemctl restart edr-hub` (§8) |
| Yearly | Rotate webhook and dead-man URL; confirm the Reserved IP and snapshot schedule |
| Year 8 | Replace the CA (runbook above); at 10 years it expires and every client drops at once |

---

## 16. Privacy and data handling

The hub holds security telemetry about your servers and, through it, about the people who visit them. This lists what
exists so the operator can decide the notices and legal basis that apply; it is not legal advice.

| Data | Personal data it may hold | Kept |
|------|---------------------------|-----------|
| Events | Source IPs, user names from SSH lines, redacted process arguments and URLs, a 128-byte hex payload head | §3 Retention |
| `daily_counts` | Counts only | §3 Retention |
| Bans, feeds, peers | Banned addresses with a reason id; your own hosts' addresses | while active |
| `audit`, `settings_history` | Operator login uid, dashboard login and its source address (sessions themselves are never stored) | §3 Retention |
| Backups | A copy of all of it, encrypted with `/etc/edr-hub/backup.pass` | `backup_keep` copies (§14) |

- **Redacted before it arrives.** The client removes secrets from arguments, URLs and payloads, stores no cookies or
  referrers, never ships raw access-log lines and caps every field (client §4.5, §18). The hub still treats every
  field as hostile and caps every field (§5). The switches that reduce what leaves a host (`redact`, `payload`, `args`) are local to the client (client §14).
- **Who can read it.** Root on the hub; the `edr-hub` and `edr-hub-ui` users (the database is `0640`); anyone who can
  SSH to the hub and run `edr-hub ui-login`. v1 has one shared admin identity (§5). Backups are encrypted.
- **What leaves the hub.** Alert text goes to the channels you set up (webhook, ntfy, and in P3 Discord or e-mail): severity, host, kind, one line
  and an address, each field cut to 200 characters (§4). Feed fetches reveal only the hub's address. The optional
  dead-man ping carries no host identifiers. Nothing goes to the kit's authors or to any analytics service.
- **Export.** `edr-hub export` (P3, §6) writes what is held as JSON lines.
  Exports, off-box backups and alert history in Slack or ntfy are outside the hub's retention.
- **Deletion.** Retention deletes automatically; `uninstall.sh --purge` removes the database, the CA and the backups
  (§9). There is no purge command for one person or one host (client §18 points here). The manual procedure: stop
  `edr-hub`, delete the matching rows as root, run `VACUUM`, start it again; backups age out after `backup_keep`
  copies.

---

## 17. Upgrades and compatibility

**Order: hub first, then clients.** Clients cannot be pushed to, so the hub must understand the version they have and
the one they will have. Protocol and schema rules: Appendix A (Versioning). An old protocol gets 426, an old event
`v` (client Appendix B) gets 422 `schema_too_old`; the client keeps spooling in both cases. A client newer than the
hub is refused the same way (confirm the status code in the VM test). Hub and clients may run different Ubuntu releases.

**Upgrading the hub.** Re-run `install.sh` from the new release tarball (checksum verified).
1. Pre-flight, then stage the new code beside the old; keep one previous copy (`/usr/local/lib/edr-hub.prev`).
2. If the new code carries a newer schema than `meta.schema_version` (read from the database read-only), the
   installer, as root and before it touches the running service, runs `edr-hub backup` (§7): an encrypted backup
   in `/var/backups/edr-hub/`, with free space checked first. It prints the file name. If the backup fails, the
   installer stops with exit 3 and nothing has changed.
3. Swap, update units and restart; what a re-run keeps is in §8, and new settings keys get their defaults.
   Clients spool and retry with jitter.
4. Start-up migrates the database from `meta.schema_version`, one transaction per step. A database newer than the
   code is refused. If a migration fails the hub does not start; the installer puts the previous code back, leaves
   the hub stopped, prints the `restore` command for the backup of step 2 and exits 4 (below). The hub never
   restores by itself (§7).

**Known agent hashes.** Each hub release ships `agent-hashes.json`: the SHA-256 of the current and the previous agent
build. The hub reads it at start; `edr-hub agent-hash add SHA` records a local override (a patched build) in the `agent_hashes` table.
Any other `agent_sha256` in a heartbeat raises HIGH (§4). Because the hub is upgraded first, a rollout never trips the
alert. A client two releases behind does, which doubles as a lag signal; upgrade it or add its hash.

**Rollback.** Migrations only go forward and the hub refuses a newer database, so rolling back needs the matching data.
1. Stop `edr-hub`.
2. Run `install.sh --force` from the previous tarball (a downgrade is refused without it).
3. If the upgrade migrated the database, run `edr-hub restore FILE --ca-key FILE` with the backup that upgrade took
   (step 2 above, §7); it needs the `ca-export` file. If it did not, the database is already right and there is
   nothing to restore.
Events accepted after a migrating upgrade are lost from the database; HIGH and CRITICAL also went out as alerts. A
restore needs a hub version no older than the backup's.

**Exit codes** (the meanings match client §15, which is the authority; `check.sh` must not fail `make` or CI on 1):

| Code | `install.sh` | `uninstall.sh` | `check.sh` | `edr-hub` CLI |
|------|--------------|----------------|------------|---------------|
| 0 | done | final check PASS | all pass | done |
| 1 | not used | not used | warnings only | warnings only (`status`, `alert test` with a channel down) |
| 2 | failed | final check FAIL | any FAIL | failed (hub unreachable, `health` unhealthy, `audit verify` chain broken) |
| 3 | pre-flight refused, nothing changed | nothing to remove, or a prompt declined | not used | refused before changing anything (validation, never-ban overlap, restore while running) |
| 4 | failed after changes and rolled back: a migration failed, or the firewall rollback fired (§8 step 10) | not used | not used | not used |
| 64 | usage error | usage error | usage error | usage error |

---

## Appendix A: API reference

The contract between `edr-agent` and `edr-hub`. Limits and the reasons for them are in §2 (Limits); storage is in §3.

### Conventions
- **Transport.** HTTPS, TLS 1.3, one request per connection (HTTP/1.0). Fleet routes use port 8443 with a client
  certificate; `/v1/ca` and `/v1/enroll` use the enrollment port (8444 by default), open only while a token is pending.
- **No status for a bad certificate.** A missing, expired or untrusted client certificate fails the TLS handshake,
  so there is no HTTP status. With TLS 1.3 the client sees it on its first read after connecting. The client
  treats that as a rejected certificate only after 3 in a row (one is a network error). Only a revoked, moved,
  retired, superseded or unknown host gets 403 (an `orphan` host gets it only on policy and renew).
- **Versioning.** Every request sends `X-EDR-Proto: 1`. The hub supports the current protocol and the one before. A
  client outside that range gets 426 `proto_unsupported`. Each event carries `v` (an integer, client Appendix B); the
  hub accepts the current and previous `v` and answers 422 `schema_too_old` below that. Upgrade order: hub first, then
  clients. The heartbeat carries `schema` and `proto`, from which the hub lists lagging clients.
- **Time.** UTC RFC 3339 strings ending in `Z`, with milliseconds (`2026-11-19T03:00:00.000Z`). The hub stores epoch
  milliseconds. The exception is the policy document and heartbeat reply: `hub_time` and `expires_at` are integer
  epoch seconds on the hub clock.
- **Requests.** `Content-Length` is required. Bodies are JSON (`Content-Type: application/json`); `/v1/events` is gzip
  (`Content-Encoding: gzip`).
- **Errors.** Every 4xx and 5xx body is `{"error": "<fixed text>", "code": "<code>"}`, optionally with `"index"` (the
  first bad event in a batch). Responses carry fixed headers only. `Retry-After` is whole seconds.
- **Identity:** from the certificate only (§2).
- **Limits:** the §2 Limits table; the status for each is in the route entries and the Error codes table.

### Routes

#### `GET /v1/ca`
- **Listener and auth:** enrollment; none.
- **Response:** `200`, the CA certificate as PEM. The client checks its SHA-256 against the token before trusting it
  (Python 3.12's `ssl` cannot read the server's chain); see §2 Enrollment.
- **Statuses:** 429. With no token pending the connection is refused (the listener is closed).

#### `POST /v1/enroll`
- **Listener and auth:** enrollment; a token (`id.secret`). The order of checks and the token rules are in Tokens (§2).
- **Request:** `{"token", "csr", "host_uuid"?, "hostname", "os", "ips", "droplet_id"}`. `token` is `id.secret` (the
  client keeps the `ca_sha256` part). `host_uuid`, `hostname`, `os` and `ips` are hints for display; the hub mints the
  UUID and the token's name wins. `droplet_id` is stored with the host and compared with every heartbeat's.
- **Response:** `200 {"host_uuid", "certificate", "ca", "hub_addresses": ["203.0.113.5"], "port": 8443, "not_after",
  "state": "pending"}`. `hub_addresses` is a list of bare IP literals (IPv6 without brackets, at most 4); `port` is the
  fleet port, a separate integer. The same token and CSR within 10 minutes gets the
  same answer.
- **Statuses:** 400 bad body or CSR; 401 `invalid_token` (the same answer for unknown, wrong, expired and used);
  409 `host_exists` (a plain token whose `host_uuid` hint matches a row in any state: a known host needs a token made `--for HOST`);
  413; 429; 503.

#### `POST /v1/events`
- **Listener and auth:** fleet; certificate.
- **Request:** gzip of `{"batch_id", "sent_at", "events": [ ... ]}`. `batch_id` is the same on a retry; `sent_at`
  is stamped at every send. The event fields are in client Appendix B. The batch is accepted or refused as a whole. An event over 10 KiB (serialised), or a batch over 500 events, is refused with 413 (§2). Event ids are `<epoch>:<seq>` with no host part; the hub adds the host from the certificate.
- **Response:** `200 {"accepted": N, "duplicate": N, "dropped_low": N}`, sent only after the commit (§3).
- **Statuses:** 400 bad schema or JSON (`index` names the first bad event); 403; 411; 413 too large or too many;
  422 `schema_too_old`; 426; 429 (HIGH/CRITICAL bucket or abusive host); 431; 503 (writer queue full, storage full).

#### `POST /v1/heartbeat`
- **Listener and auth:** fleet; certificate.
- **Request keys.** This list is the authority for every heartbeat key; client §4.5 describes the content and uses
  these names: `sent_at`, `agent_version`, `agent_sha256`, `schema`, `proto`,
  `boot_id`, `uptime_s`, `kernel`, `droplet_id`, `seq` and `epoch`, `units`, `tetragon` (policy name, mode,
  would_be_kills), `nft` (`table_present`, set sizes, counters), `conntrack` (count, max, drop, early_drop), `dns_lock` (`state`: `locked`, `open`, `paused` or `flapping`; `since`; re-lock count, client §4.4), `disk`,
  `load`, `mem`, `suricata_drops`, `spool` (depth, drops by lane and source), `local_conf_sha256`, `cert_not_after`,
  `maintenance_until`, `paused_until` (the pause, client §4.7), `policy_rev_applied`, `last_apply_error`,
  `ban_counts`, `inventory` (client §4.5.1). The heartbeat sent at system shutdown carries `"shutdown": true`
  (client §4.5); a new `boot_id` within 10 minutes of it is a planned reboot. There is no `settings` key: the hub
  shows only `local_conf_sha256` and the policy modes in `tetragon`.
- **Response:** `200 {"hub_time", "policy_rev", "min_client_schema"}`. The client records the skew between `hub_time`
  and its own clock and warns above 60 s; `check.sh` WARNs when its `v` is below `min_client_schema`. The client may
  skip a policy poll when `policy_rev` equals its `policy_rev_applied`.
- **Statuses:** 400; 403; 413; 426; 429; 503. `agent_sha256` is checked against the hub's accepted hashes (§3, §4); the
  agent cannot declare an upgrade to mute that check.

#### `GET /v1/policy`
- **Listener and auth:** fleet; certificate. Optional `If-None-Match: "<rev>"`.
- **Response:** `304` when `rev` is unchanged. Otherwise `200` with `ETag: "<rev>"` and the whole per-host document
  `{"rev", "hub_time", "hub_addresses", "port", "bans": [{"cidr", "expires_at", "source", "reason_id"}], "feeds": {...}, "peers": [...]}`.
  `hub_addresses` and `port` are as in the enroll reply. From P3 the hub fills `bans` and `feeds`; in P2 both are
  empty and the client applies only `peers` and the hub addresses to its never-ban list (client §4.2).
  `expires_at` is epoch seconds on the hub clock; the client stores `now_local + (expires_at - hub_time)` as its
  absolute expiry. `feeds` is `{"<feed name>": ["198.51.100.0/24", ...]}` with no per-entry expiry. A feed key absent
  from the document is removed at the client's next apply (absence is not "empty"), and a feed's 72 h timer on the
  client is refreshed only by a poll whose document contains that feed (hub §4, client §4.2). `peers` is a list of
  single IP literals, at most 512. `source` and `reason_id` are closed vocabularies, never free text (table below).
  Unknown keys are ignored. An unban is absence from the next document. Bans and feeds are capped at 10,000 and
  200,000 entries. Reasons never name other hosts.
- **Statuses:** 403; 426; 429; 503.

#### `POST /v1/renew`
- **Listener and auth:** fleet; the current certificate, still valid.
- **Request:** `{"csr"}`. The hub fixes subject and extensions itself and ignores what the CSR asks for.
- **Response:** `200 {"certificate", "not_after"}`. The new serial is pending; the first request that presents it
  makes it current.
- **Statuses:** 400; 403; 413; 429; 503. A client whose certificate has already expired cannot renew: it enrolls again
  with a token made `--for HOST`.

#### `POST /v1/deregister`
- **Listener and auth:** fleet; certificate.
- **Request:** `{"reason": "uninstall" | "rehome"}`.
- **Response:** `200 {}`. The host becomes `retired` (uninstall) or `moved` (rehome); later requests with its
  certificate get 403 `host_retired` or `host_moved`.
- **Statuses:** 403; 429; 503.

### Closed vocabularies
The client validates these fields against the lists below and shows any other value as `unknown`; the lists below are the
only source, and the client compiles them in. They apply to the policy document.

| Field | Value | Meaning |
|-------|-------|---------|
| `source` | `fleet` | A fleet ban: quorum of votes (hub §4) |
| `source` | `operator` | A ban set by `edr-hub ban` or the dashboard |
| `reason_id` | `fleet_quorum` | Two distinct certificates reported the address with qualifying evidence |
| `reason_id` | `operator` | An operator's ban; the free-text reason stays on the hub |
| feed name | `spamhaus_drop_v4`, `spamhaus_drop_v6` | Spamhaus DROP, IPv4 and IPv6 lists |
| feed name | `dshield` | FireHOL `dshield` |

### What the client does for each status
All of this applies to every route unless a route above says otherwise. The agent never retries faster than the
table says, and caps any `Retry-After` at 1 hour.

| Status | Meaning | Client action |
|--------|---------|---------------|
| 200 (`/v1/events`) | Committed | Delete the batch from the spool |
| 200 / 304 (others) | Done / unchanged | Use it; the policy poll continues |
| 400, 413 on events | Batch refused | Split once (never resend unchanged); move events still refused to `spool/rejected/` (capped, counted in the heartbeat); carry on |
| 422 `schema_too_old` | Client schema too old | Keep spooling, retry hourly; `check.sh` WARNs; never split or reject |
| 400, 413 elsewhere | Request refused | Log it, keep the previous state, retry at the normal interval |
| 401 (`/v1/enroll`) | Token refused | Stop; tell the operator to make a new token |
| 403 `host_orphan` (policy, renew) | Host awaiting adoption | Keep sending events and local bans; retry policy and renew hourly; `check.sh` WARNs "adopt me on the hub" |
| Other 403; TLS failure on first read, 3 in a row | Certificate or host refused | Stop events, keep spooling, retry hourly; `check.sh` FAILs with the `code` |
| 409 (`/v1/enroll`) | UUID already enrolled | Stop; the operator makes a token `--for HOST` |
| 426 | Protocol unsupported | Keep the last policy, keep spooling, retry hourly; `check.sh` WARNs |
| 429, 503 | Slow down | Wait `Retry-After` (at most 1 hour), retry the same batch; no header: back off as 5xx |
| Other 5xx, timeout, refused | Hub trouble | Exponential backoff with full jitter; events cap at 5 minutes, heartbeat and policy at 60 s (client §4.5); keep spooling |
| 431, 411, 414 | Client bug | Log it, keep the previous state, retry at the normal interval; an events batch stays in the spool unsplit |

- **Spool replay** sends at most one batch per second (client §4.5). After a hub restart the agent adds jitter.
- **Bounds on what the hub may send.** Response body 16 MiB, headers 16 KiB, 30 s in total, parsed as a stream. A policy
  above the 10,000 and 200,000 caps is refused, not truncated, and reported in the heartbeat.
- A rejected batch never blocks newer events: after one split, what is still refused leaves the head of the spool.

### Error codes

| Code | Status | Meaning |
|------|--------|---------|
| `bad_request`, `bad_schema` | 400 | Malformed JSON, truncated or trailing gzip, wrong type, missing field |
| `length_required` | 411 | No `Content-Length` |
| `too_large` | 413 | Body, inflated body, an event over 10 KiB, or a batch over the limit |
| `schema_too_old` | 422 | Event `v` older than the previous one |
| `proto_unsupported` | 426 | `X-EDR-Proto` below or above the supported range |
| `header_too_large` | 431 | Header block over the §2 limit |
| `host_unknown`, `host_revoked`, `host_moved`, `host_retired`, `cert_superseded` | 403 | Host not allowed; events stop |
| `host_orphan` | 403 | Only on `/v1/policy` and `/v1/renew`; events are still accepted |
| `invalid_token` | 401 | Enrollment token refused |
| `host_exists` | 409 | Plain-token enrollment whose UUID hint matches a known host |
| `rate_limited` | 429 | Bucket or per-certificate limit, with `Retry-After` |
| `busy`, `storage_full` | 503 | Writer queue or storage full, with `Retry-After` |
