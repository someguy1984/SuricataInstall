# Mock environment

Two Ubuntu 26.04 "droplets" in Docker, on a private network, for trying the server EDR locally before
touching a real DigitalOcean box.

| Box | Private address | What runs | Reachable from this machine |
|-----|-----------------|-----------|-----------------------------|
| `hub` | `10.77.0.10` (`hub`, `hub.dev.local`) | A TLS 1.3 placeholder on `:8443` that stands in for `edr-hub` until `server_hub/` is built | no |
| `web` | `10.77.0.20` (`web`, `web.dev.local`) | nginx 1.28.3 (Ubuntu's USN-9159-1 fixed build) and PHP 8.5 FPM, serving a hello-world page for `web.dev.local` on `:80` and `:443` (HTTP/2, self-signed certificate) | `127.0.0.1:80`, `127.0.0.1:443` |

```
 this machine                       Docker
 ─────────────                      ──────────────────────────────────────────────────────────
 127.0.0.1:80/443 ───published───►  web 10.77.0.20 ──┐
                                                       ├── edr_vpc 10.77.0.0/24 (internal: no route out)
                                    hub 10.77.0.10 ──┘
                                    both ── edr_egress (a normal bridge: apt, rule and feed downloads)
```

`edr_vpc` plays the part of a DigitalOcean VPC: hub and web talk to each other there, and nothing else can
reach it. `edr_egress` gives both boxes the outbound internet access a droplet has.

Both boxes run **systemd as PID 1**, so services, timers and the journal behave as on a droplet, and the
`server_client` / `server_hub` installers can be run inside them once they exist. The whole repository is
mounted read-only at `/opt/SuricataInstall` in both.

## Use

    cd server_edr_solution/mock
    ./mock.sh up          # build and start; waits until both boxes are healthy
    ./mock.sh test        # 12 checks; exits non-zero on any failure
    ./mock.sh status      # containers and addresses
    ./mock.sh shell web   # root shell in a box (or: hub)
    ./mock.sh logs web    # follow a box's journal
    ./mock.sh down        # stop and remove; add --volumes to also forget the certificates

To use the site in a browser, add this line to `/etc/hosts` (the script doesn't change it for you):

    127.0.0.1 web.dev.local

Then open <http://web.dev.local> or <https://web.dev.local>. The certificate is self-signed, so the browser
warns once. Without touching `/etc/hosts`:

    curl --resolve web.dev.local:443:127.0.0.1 -k https://web.dev.local/

Port 80 serves the page as well, rather than redirecting to HTTPS, so Suricata has plain HTTP to inspect
(it can't read HTTPS). A real site would redirect.

## What `./mock.sh test` checks

- The page is served on `:80` and on `:443` over HTTP/2, by PHP 8.5, with a certificate naming `web.dev.local`.
- `/.env` is refused (403).
- Each box is Ubuntu 26.04 with systemd as PID 1 and every unit running.
- php8.5-fpm and nginx are active, and the nginx package is at least the USN-9159-1 fixed build (NGINX2Root).
- The web box reaches the hub placeholder at `10.77.0.10:8443` over TLS 1.3, and resolves `hub.dev.local`.
- The hub reaches `https://web.dev.local` over the private network.
- The hub publishes no ports to this machine.

## Docker requirements and safety

- **Rootless Docker** (what this machine uses) is the recommended setup. `mock.sh` finds the rootless socket
  by itself when `/var/run/docker.sock` doesn't exist.
  - Publishing ports 80 and 443 needs `net.ipv4.ip_unprivileged_port_start` to be 80 or lower. It is 80 here.
  - The boxes run `privileged` because systemd needs it. Under rootless Docker that privilege stays inside your
    user namespace.
- **Rootful Docker** works too, but there `privileged` means real root on the host. Only run it on a machine
  you are happy to give that to.
- Published ports are bound to `127.0.0.1` only, never to your LAN.

## What the mock can and can't test

Containers share this machine's kernel, so anything that changes the kernel itself belongs in a VM test
(see "Repo integration" in `../server_client/PLAN.md`), not here.

| Part of the plan | In the mock? |
|------------------|--------------|
| nginx, php-fpm, systemd units, timers, journald budgets | yes |
| Suricata in af-packet IDS mode on the box's own interfaces | yes |
| nftables ban sets, the `DNSLOCK` chain, the `bigconn` rule | yes, inside each box's own network namespace |
| dnscrypt-proxy and the resolved drop-in | yes |
| `edr-agent`, `edr-hub`, enrollment, mTLS, `rehome`, uninstall | yes; that is what the hub box is for |
| **Tetragon** (eBPF) | **no**. It would load into this machine's kernel, and under rootless Docker it can't load at all. |
| The `sctp` modprobe block, `nf_conntrack_acct` and other kernel settings | **no**. They are this machine's kernel settings. |

**Source addresses.** With rootless Docker, requests from this machine reach nginx from the `edr_egress` gateway
(`172.18.0.1` here), not `127.0.0.1`. The hub and web boxes are on private ranges, which the ban logic never bans. To test
bans end to end, the next step is a third "attacker" box on `edr_egress` with a public-looking address.

## Files

| File | Purpose |
|------|---------|
| `compose.yaml` | The two boxes, both networks, published ports, certificate volumes |
| `Dockerfile` | One shared `base` stage (Ubuntu 26.04 and systemd), then `hub` and `web` targets |
| `mock.sh` | `up`, `test`, `status`, `shell`, `logs`, `down` |
| `common/mock-tls.sh` | Creates a self-signed certificate on first boot, so no private key is baked into an image |
| `hub/*.service` | The certificate, and the `:8443` placeholder. Run `systemctl disable --now mock-hub-placeholder` before installing the real hub |
| `web/web.dev.local.conf`, `web/web.dev.local.common` | The nginx site: `:80`, and `:443` with HTTP/2 |
| `web/public/index.php` | The hello-world page |
