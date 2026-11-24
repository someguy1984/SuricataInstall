# server_edr_solution

A small, self-hosted EDR for DigitalOcean Ubuntu 24.04/26.04 web servers that run nginx, PHP and Laravel.
It is built from the laptop kits at the top of this repository.

**Status: the client and the hub are written for phases P1a, P1b and P2 (hub section 11, client section 10), and have
been installed, enrolled, checked and uninstalled in the mock (Ubuntu 26.04 containers, 2026-11-24). They have not run in
a VM or on a real host.**

| Folder | What it is |
|--------|------------|
| [`server_client/`](server_client/PLAN.md) | The droplet kit. Built: the installer (`install.sh`, `uninstall.sh`, `check.sh`) that installs from a checked tarball with `--hub IP:PORT --token-file FILE`, or with neither to run alone; the sandboxed Python agent (`agent/`, in-process modules and small root helpers: bans, inventory, disk guard, DNS watch, policy check); the nftables and systemd files; the Tetragon web policies; the Suricata and DNS-lock wiring. The plan also holds the threat model, the configuration and safety-rail tables, the runbooks, and NGINX2Root worked through as an example (Appendix A). |
| [`server_hub/`](server_hub/PLAN.md) | The hub. Built: mutual-TLS ingest and a separate short-lived enrollment port, tokens and our own CA, SQLite with tiered retention, correlation and incidents, the alert outbox and the outbound worker, the three local sockets and the `edr-hub` command line, the audit chain, encrypted backup, restore and CA export, a local dashboard reached through an SSH tunnel, and `install.sh`, `uninstall.sh` and `check.sh`. Fleet bans and IP feeds are P3 and are not built. The API both sides build from is the plan's Appendix A. |
| [`mock/`](mock/README.md) | A Docker test bed: two Ubuntu 26.04 boxes (hub, and web with nginx and PHP 8.5 serving `web.dev.local` on 80 and 443) on a private network. `./mock.sh up && ./mock.sh test` is the part that already worked before the installers existed. The steps that install both kits from their tarballs, enroll, check end to end and uninstall (`dist`, `install-hub`, `install-web`, `enroll`, `e2e`, `uninstall`) had their first run on 2026-11-24: all pass except two `e2e` checks. Its README says what it can and cannot test. |

**How to check it.** The installers have run in the mock only, never in a VM or on a real host.

- `make lint`: syntax and style of every shell and Python file, the Tetragon policies, the units, the release tarballs.
- `make unit`: the hub's and the agent's unit tests (no root, no network).
- `make unit-2404`: the same two suites and `e2e_local.py` on Python 3.12 (Ubuntu 24.04, OpenSSL 3.0) in a throwaway
  rootless Docker container (the first run builds the image; about 6 minutes).
- `sudo make test`: the firewall scripts and the server kit's three nftables tables in throwaway network namespaces.
- `python3 -I server_edr_solution/tests/e2e_local.py`: a real hub and a real agent on loopback in temporary directories,
  with the agent's sources fed from recorded input.
- `python3 -I server_edr_solution/tests/restore_drill_local.py [CHECK-ID ...]`: the restore drill (hub §7, §12: backup,
  `ca-export`, restore onto a new box, `--drill`, the original box, refusals, orphan hosts, the audit trail, a `--for`
  rehome onto the restored hub) and `edr-agent rehome` killed with SIGKILL at known steps, between real hubs and a
  real agent on loopback (client §5). About 5 minutes.
- `python3 -I server_edr_solution/tests/hub_flood.py`: the slow-client and flood tests (hub §12) against a real hub on
  loopback: every row of the §2 Limits table, trickle and memory, certificate-less clients, socket modes, a full
  database and a stalled writer, then a check that the hub still serves. About 75 seconds.
- `python3 -I server_edr_solution/tests/outage_local.py [--full]`: the hub-outage exit criterion (client §10, hub §11) with
  a real hub and a real agent on loopback: the hub away while the agent's sources get the scan load of an hour (a tenth
  of it by default, all of it with `--full`) with HIGH and CRITICAL markers in it; the spool stays under 50 MB, every
  marker reaches the hub once within 5 minutes of its return (also across `kill -9` of the hub), and the agent's CPU,
  memory and drop counters are reported.
- `server_edr_solution/mock/mock.sh`: the Docker route above, for the installers themselves.

**What has not been done.** No run in a VM yet. In the mock, two `mock.sh e2e` checks still fail (the recorded
Tetragon line does not reach the hub, and the spool check after a revoke times out: see `mock/README.md`), and the DNS
lock step is skipped there. The `--full` run of `outage_local.py` was started and not finished. The Tetragon policies have never been loaded into a kernel.
No installer has run on a real host. Development used Python 3.14 (OpenSSL 3.5). `make unit-2404` runs the hub and agent
unit suites and `e2e_local.py` on Python 3.12.3 with OpenSSL 3.0.13 (Ubuntu 24.04, in a Docker container, as an unprivileged user,
with `/tmp` on a tmpfs) and they pass; that run skips the tests that need root, `nft` or a network namespace, as
`make unit` does without root. Not run on 3.12: the restore drill, the flood and the outage scripts, the mock
(its 24.04 variant does not exist yet), any installer, and anything on a real 24.04 host. The memory and timing
figures in the hub plan (section 2) and the agent's CPU and memory figures are still from 3.14 only; they have not been
re-measured on 3.12. The phase exit criteria of client section 10 are not met.

**Layout.** `server_hub/hub/edr_hub.py` and `server_client/agent/edr-agent.py` are entry scripts: their logic is in
sibling modules (`hub_*.py` beside the hub, the `edragent/` package beside the agent), and the command-line tools
(`edr-hub`, the agent's helper scripts) are Python files with no `.py` suffix.

**Paths.** In the plans, `server_client/…`, `server_hub/…` and `mock/…` are relative to this folder. Paths to the
laptop kit they reuse (`suricata/` with its `install.sh`, `check.sh`, `analyse.py` and `files/`; `tetragon/`,
`controld/`, `watch/`, `tests/`, `Makefile`) are relative to the repository root.

## The design in eight lines

- **The website always wins.** Every part fails open. The few things that can block (ban sets, two Tetragon policies,
  the DNS lock) are listed in one table with what bounds each and how to switch it off (client §2, §16).
- **The client pulls; the hub never pushes.** A compromised hub can send bans, feed sets and peer addresses, and the
  client bounds even those. It cannot run commands, change settings or switch enforcement (client §13).
- **Nothing is assumed about the web user.** The installer discovers the web users, web roots and binary paths, so
  Forge-style hosts work, and reports drift when a site or PHP version is added later.
- **Policies that kill start in monitor mode.** A pre-flight and a canary gate the switch to enforce, per host.
- **Bans rest on evidence an attacker cannot forge**: an established TCP flow or a log field the daemon wrote, never
  a header. There is a ban budget, and the admin's own address cannot be banned.
- **The hub mints identity.** Tokens are never passed on the command line, a token cannot claim an existing host,
  and every enrollment is audited and alerted.
- **Least privilege throughout.** The agent has no capabilities and may talk only to the hub; root work is done by
  small helpers with fixed inputs; the hub runs as separate users and its ingest process cannot connect out.
- **Honest limits.** An attacker who never starts a program, C2 over port 443 and root on a client are stated as
  what they are (client §12).

## Order of work

Each phase starts only when the one before has met its exit criteria (client §10, hub §11).

| Phase | What ships | Needs the hub? |
|-------|------------|----------------|
| **P1a** | Thin core: Tetragon server policies, the SCTP module block, inventory from apt, the agent in local mode with a local alert path, health check, uninstall | no |
| **P1b** | Network side: Suricata, nftables bans and never-ban list, the large-connection watch, and last the DNS lock with its fail-open watchdog | no |
| **P2** | Hub MVP: enrollment, mutual-TLS transport, heartbeats, alerts, correlation rules and incidents, dashboard, backups, `rehome`; learning and optional enforcement of `web-exec`; the triage bundle (`collect`) | yes |
| **P3** | Fleet bans and IP feeds, incident acknowledgement and repeating CRITICAL alerts, local `isolate`, web-root integrity, and the DNS lock if it was moved out of P1b | yes |
| **P4** | Laravel log counters, ATT&CK ids on rules, a read-only view of each client's local settings | yes |

## Prior art

CrowdSec covers shared IP bans, Wazuh full host EDR and SIEM, Falco runtime rules. Building this is worthwhile for a
light, self-hosted setup under your own control. Borrow ideas (for example CrowdSec's scenario format) freely, and
run a WAF beside it if you need one: HTTPS request bodies are invisible to this kit.
