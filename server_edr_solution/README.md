# server_edr_solution

A small, self-hosted EDR for DigitalOcean Ubuntu 24.04/26.04 web servers that run nginx, PHP and Laravel.
It is built from the laptop kits at the top of this repository.

**Status: design and test bed. The client and hub themselves are not written yet.**

| Folder | What it is |
|--------|------------|
| [`server_client/`](server_client/PLAN.md) | The plan for the droplet kit: Suricata IDS, nftables bans, Tetragon web policies, DNS over HTTPS, and a sandboxed Python agent. Installing it needs only `--hub IP:PORT --token`. Also covers NGINX2Root, worked through as an example. |
| [`server_hub/`](server_hub/PLAN.md) | The plan for the hub: mTLS ingest on a port you choose, enrollment tokens, SQLite, correlation, alerts, fleet bans, and a local dashboard on its own port. |
| [`mock/`](mock/README.md) | A working Docker test bed: two Ubuntu 26.04 boxes (hub, and web with nginx and PHP 8.5 serving `web.dev.local` on 80 and 443) on a private network. `./mock.sh up && ./mock.sh test`. |

Order of work, from the plans: P1 is the standalone client kit (useful with no hub). P2 is the hub MVP with
the dashboard, `rehome` and uninstall. P3 adds fleet bans and correlation. P4 adds enforcement and analytics.
