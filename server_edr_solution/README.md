# server_edr_solution

A small, self-hosted EDR for DigitalOcean Ubuntu 24.04/26.04 web servers that run nginx, PHP and Laravel.
It is built from the laptop kits at the top of this repository.

**Status: design and test bed. The client and hub themselves are not written yet.**

| Folder | What it is |
|--------|------------|
| [`server_client/`](server_client/PLAN.md) | The plan for the droplet kit: Suricata IDS, nftables bans, Tetragon web policies, DNS over HTTPS, and a sandboxed Python agent with small root helpers. It installs from a checked tarball with `--hub IP:PORT --token-file FILE`, or with neither to run alone. Also holds the threat model, the configuration and safety-rail tables, the runbooks, and NGINX2Root worked through as an example (Appendix A). |
| [`server_hub/`](server_hub/PLAN.md) | The plan for the hub: mutual-TLS ingest and a separate short-lived enrollment port, tokens, SQLite with tiered retention, correlation, alerts, fleet bans, encrypted backups, and a local dashboard reached through an SSH tunnel. The API both sides build from is its Appendix A. |
| [`mock/`](mock/README.md) | A working Docker test bed: two Ubuntu 26.04 boxes (hub, and web with nginx and PHP 8.5 serving `web.dev.local` on 80 and 443) on a private network. `./mock.sh up && ./mock.sh test`. Its README says what it can and cannot test. |

**Paths.** In the plans, `server_client/…`, `server_hub/…` and `mock/…` are relative to this folder. Paths to the
laptop kit they reuse (`install.sh`, `check.sh`, `analyse.py`, `files/`, `tetragon/`, `controld/`, `watch/`, `tests/`,
`Makefile`) are relative to the repository root.

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
| **P2** | Hub MVP: enrollment, mutual-TLS transport, heartbeats, alerts, dashboard, backups, `rehome`; learning and optional enforcement of `web-exec`; the triage bundle (`collect`) | yes |
| **P3** | Fleet bans and IP feeds, incident correlation, local `isolate`, web-root integrity | yes |
| **P4** | Laravel log counters, ATT&CK ids on rules, a read-only view of each client's local settings | yes |

## Prior art

CrowdSec covers shared IP bans, Wazuh full host EDR and SIEM, Falco runtime rules. Building this is worthwhile for a
light, self-hosted setup under your own control. Borrow ideas (for example CrowdSec's scenario format) freely, and
run a WAF beside it if you need one: HTTPS request bodies are invisible to this kit.
