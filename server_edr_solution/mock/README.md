# Mock environment

Two Ubuntu 26.04 "droplets" in Docker, on a private network, for trying the server EDR locally before
touching a real DigitalOcean box. Ubuntu 24.04 is not covered here yet (see "Planned additions"); it is tested in
a VM.

> **WARNING: use rootless Docker only. The boxes run `privileged`, which on rootful Docker is real root on this
> machine.** The installers unload modules, set sysctls and write `/etc/modprobe.d`; on rootful Docker that
> changes the host, not the box, and a privileged container can remount the repository read-write. `cap_drop`
> cannot limit it (Docker ignores drops when privileged). Do not run the mock on rootful Docker on a machine you
> care about; until `mock.sh` refuses a rootful daemon, do not run it there at all. Use a throwaway VM instead.

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

`edr_vpc` plays the DigitalOcean VPC: hub and web talk there, and nothing else can reach it. `edr_egress`
gives both boxes the outbound internet access a droplet has.

Both boxes run **systemd as PID 1**, so services, timers and the journal behave as on a droplet, and the
installers can be run inside them once they exist. The whole repository is mounted read-only at
`/opt/SuricataInstall`. State lives in the container layer, so `up` after an image change erases an installed kit.

## Use

    cd server_edr_solution/mock
    ./mock.sh up          # build and start; waits until both boxes are healthy
    ./mock.sh test        # smoke test; exits non-zero on any failure
    ./mock.sh status      # containers and addresses
    ./mock.sh shell web   # root shell in a box (or: hub)
    ./mock.sh logs web    # follow a box's journal
    ./mock.sh down        # stop and remove; add --volumes to also forget the certificates

To use the site in a browser, add this line to `/etc/hosts` (the script doesn't change it for you):

    127.0.0.1 web.dev.local

Then open <http://web.dev.local> or <https://web.dev.local> (self-signed, so the browser warns once). Or:

    curl --resolve web.dev.local:443:127.0.0.1 -k https://web.dev.local/

Port 80 serves the page too, not a redirect, so Suricata has plain HTTP to inspect. A real site would redirect.

## What `./mock.sh test` checks

The list below is the summary; `mock.sh` is the authority on the exact checks and their count.

- The page is served on `:80` and on `:443` over HTTP/2, by PHP 8.5, with a certificate naming `web.dev.local`.
- `/.env` is refused (403).
- Each box is Ubuntu 26.04 with systemd as PID 1 and every unit running.
- php8.5-fpm and nginx are active, and the nginx package is at least the USN-9159-1 fixed build (NGINX2Root).
- The web box reaches the hub placeholder at `10.77.0.10:8443` over TLS 1.3, and resolves `hub.dev.local`.
- The hub reaches `https://web.dev.local` over the private network.
- The hub publishes no ports to this machine.

## Docker requirements and safety

- **Rootless Docker** (what this machine uses) is the only supported setup. `mock.sh` finds the rootless socket
  by itself when `/var/run/docker.sock` doesn't exist.
  - Publishing ports 80 and 443 needs `net.ipv4.ip_unprivileged_port_start` to be 80 or lower. It is 80 here.
  - The boxes run `privileged` because systemd needs it. Under rootless Docker that privilege stays inside your
    user namespace. Until `mock.sh` refuses a rootful daemon (see "Planned safety changes"), check the daemon
    yourself: `docker info -f '{{.SecurityOptions}}'` must list `rootless`.
- Published ports are bound to `127.0.0.1` only, never to your LAN.
- Installers must never flush nftables or iptables globally, only the kit's own table and chains. The box's
  iptables `nat` table holds Docker's `127.0.0.11` DNS rules, and a flush would break name resolution.

## Installer flags for the mock

Once `server_client/install.sh` and `server_hub/install.sh` exist, the mock runs them with these flags
(names as in `../server_client/PLAN.md` section 7 and `../server_hub/PLAN.md` section 8; confirm against the
installers when they are written). Nothing runs from a checkout: build the tarball with `make dist`, copy it into
the box and install from there (client section 7). The read-only repository mount is for reading only.

| Flag | Installer | Why the mock needs it |
|------|-----------|-----------------------|
| `--no-kernel` | client | Pre-flight refuses kernel steps inside a container unless this is given; with it the installer prints a WARN and skips `modprobe -r sctp`, non-network sysctls and other kernel-wide steps, which a container shares with this machine |
| `--no-tetragon` | client | Tetragon cannot load in a container (see the table below) |
| `--no-suricata` | client | When Suricata's af-packet cannot run on the veth, or to save memory |
| `--no-web` | client | On the hub box, which has no nginx |
| `--yes` | both | No prompts. The client install then confirms itself after its automated checks; the hub install waits for `install.sh --confirm` from a second shell (hub section 8) |
| `--plan` | both | Prints what would change; run it first and read it |

The hub installer has none of the `--no-*` flags. Its plan lists no sysctl or module change; its firewall is the
`inet edr_hub` nftables table, which lives in the box's own network namespace.

Without `--no-suricata`, Suricata, nftables, dnscrypt-proxy and the agent install normally. `--token-file`
supplies the enrolment token only once the real hub exists; until then the agent installs in local mode
(client section 7).

## What the mock can and can't test

Containers share this machine's kernel, so anything that changes the kernel itself belongs in a VM test
(see "Repo integration" in `../server_client/PLAN.md`), not here.

| Part of the plan | In the mock? |
|------------------|--------------|
| nginx, php-fpm, systemd units, timers, the kit's journal namespace and the disk guard | yes |
| Suricata in af-packet IDS mode on the box's own interfaces | yes for rules and alerts; set `checksum-checks: no` (veth offload); no performance numbers |
| nftables ban sets, ban apply, the `inet edr_dns` lock logic, `bigconn` counting | yes, inside each box's own network namespace |
| `nf_conntrack_acct` and other sysctls | yes, if `/proc/sys` is writable in the box (probe it; fail loudly if not) |
| nft and iptables `LOG` lines (`edr-bigconn:`, `edr-dnslock:`) and `journalctl -k` | **no**. A container's namespace emits none; test the kernel-log reader with recorded lines, and the real thing in a VM |
| The `sctp` modprobe block file and `modprobe -n -v sctp` | the file and its parse, yes; real blocking **no** (the modules are the host's) |
| dnscrypt-proxy | yes |
| systemd-resolved drop-in | only after installing systemd-resolved (the image has none), and `/etc/resolv.conf` is a Docker bind mount, so the installer must cope with it |
| `IPAddressDeny` / `IPAddressAllow` | **no**. Under rootless Docker systemd has no BPF firewall and silently does not enforce them |
| `MemoryMax`, `CPUQuota` | only if the box shows a real value in its `memory.max`; otherwise the limit is not enforced |
| `edr-agent` install, local mode, uninstall | yes, against the placeholder |
| Hub install, the `edr-hub` units, sockets and users, the `edr_hub` nftables table (load, rate meters, `--clients-only`) | yes, once the hub exists, inside the hub box's own network namespace. The `meta skuid` rule that stops `edr-hub` calling out is proven in a throwaway network namespace (client section 11, L1) and re-checked in a VM |
| Hub `IPAddressDeny` and `MemoryMax` limits | **no**, for the same reasons as the two rows above; the rest of the hub's sandbox (`ProtectProc`, `PrivateNetwork`, users, sockets) yes |
| Enrollment | **no**: needs the real hub (`:8444`, `/v1/ca`, `/v1/enroll`); the agent stays in local mode until then (client section 7) |
| mTLS (client certificate required) | **not yet**: the placeholder does not ask for a client certificate; it becomes `-Verify 1 -CAfile` once the real CA exists |
| `rehome` and restore | **not yet**: needs a second hub (see "Planned additions") |
| Local auto-bans from real source addresses | **not yet**: all traffic arrives from private addresses, which are never banned |
| Clock changes (certificate renewal at 30 days) | **no**. `CAP_SYS_TIME` does not move the shared clock; use `libfaketime` per service |
| **Tetragon** (eBPF) | **no**. It would load into this machine's kernel, and under rootless Docker it can't load at all. Replay recorded Tetragon JSON into the agent instead |

A pass in an "only if" row is not proof: a limit that is not enforced in the box must be reported, not ignored
(see the planned `mock.sh test` probe below).

**Source addresses.** Requests from this machine reach nginx from the `edr_egress` gateway (`172.18.0.1` here).
All box addresses are private, which the ban logic never bans (see "Planned additions").

## Planned safety changes

Not built yet; until they are, follow the warning at the top.

1. Replace `privileged` with `cap_add: [SYS_ADMIN, NET_ADMIN, NET_RAW, SYS_PTRACE, DAC_READ_SEARCH, SYSLOG]`, with
   no `SYS_MODULE` or `SYS_TIME`. Boot-test this variant first; it may need `systempaths=unconfined`, which is
   acceptable on rootless Docker only.
2. `mock.sh up` refuses a rootful daemon unless `MOCK_ALLOW_ROOTFUL=1` is set.
3. The client installer refuses to run kernel steps (modprobe, non-network sysctls, BPF, `/etc/modprobe.d`) when
   `systemd-detect-virt -cq` succeeds, unless `--no-kernel` is given; with the flag it skips them and prints a
   WARN. This is the real guard. The hub installer makes no such change.
4. The repository is mounted `:ro`.

## Planned additions

Not built yet. Each stays optional, in its own compose profile where it adds a box.

- `mock.sh test` probes `/proc/sys` writability, `memory.max` and BPF firewall support, and fails loudly (not
  skips) when a limit or sysctl row cannot be trusted.
- The hub placeholder asks for a client certificate (`-Verify 1 -CAfile`) once the real CA exists.
- An `attacker` box (curl, nmap, ssh client, h2load) on a new `edr_wan` network, using `198.18.77.0/24` as the
  droplet's "public" side with the web box's default route on it, for ban, scan and h2c tests.
- A 24.04 variant of both images (`UBUNTU_TAG` and a PHP version as Dockerfile build args: PHP 8.3 and
  Ubuntu's nginx 1.24 package), each running the enrolment and mTLS round trip. Hub tests on Python 3.12 (24.04)
  need it; until it exists they run in a VM.
- A second hub, `hub2` at `10.77.0.11`, for `rehome` and restore tests.
- `openssh-server` and `libfaketime` in the web image, and `sudo` or `runuser` for the canaries.
- A Laravel-like app: the Laravel nginx block (only `index.php` runs, catch-all `default_server` returning 444), a
  `www-data`-writable `storage/`, and a loopback-only `lab.php` that can exec, write, connect out and read env.
  A deliberately weak second vhost would test the inventory's nginx checks.
- IPv6 on `edr_wan`, with a prefix the never-ban list does not contain.
- `mock.sh snapshot|reset|residue`: start installer tests from a clean droplet quickly, and diff what an install
  and uninstall leave behind.

## Files

| File | Purpose |
|------|---------|
| `compose.yaml` | The two boxes, both networks, published ports, certificate volumes |
| `Dockerfile` | One shared `base` stage (Ubuntu 26.04 and systemd), then `hub` and `web` targets |
| `mock.sh` | `up`, `test`, `status`, `shell`, `logs`, `down` |
| `common/mock-tls.sh` | Creates a self-signed certificate on first boot, so no private key is baked into an image |
| `hub/*.service`, `web/mock-tls.service` | Certificate units, and the `:8443` placeholder. Run `systemctl disable --now mock-hub-placeholder` before installing the real hub |
| `web/web.dev.local.conf`, `web/web.dev.local.common` | The nginx site: `:80`, and `:443` with HTTP/2 |
| `web/public/index.php` | The hello-world page |
