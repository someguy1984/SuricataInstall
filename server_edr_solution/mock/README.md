# Mock environment

Two Ubuntu "droplets" in Docker, on a private network, for trying the server EDR locally before touching a real
DigitalOcean box. They are Ubuntu 26.04 by default; `MOCK_UBUNTU=24.04` builds both on 24.04 instead (nginx 1.24,
PHP 8.3, Python 3.12, systemd 255, OpenSSL 3.0). One release runs at a time, and every subcommand needs the same value.

> **WARNING: use rootless Docker only. The boxes run `privileged`, which on rootful Docker is real root on this
> machine.** The installers unload modules, set sysctls and write `/etc/modprobe.d`; on rootful Docker that
> changes the host, not the box, and a privileged container can remount the repository read-write. `cap_drop`
> cannot limit it (Docker ignores drops when privileged). `mock.sh` refuses a rootful daemon for that
> reason. `MOCK_ALLOW_ROOTFUL=1` overrides it: only ever in a throwaway VM.

| Box | Private address | What runs | Reachable from this machine |
|-----|-----------------|-----------|-----------------------------|
| `hub` | `10.77.0.10` (`hub`, `hub.dev.local`) | At first a TLS 1.3 placeholder on `:8443`. `./mock.sh install-hub` disables it and installs the real hub from the release tarball: fleet `:8443`, enrollment `:8444`, dashboard `127.0.0.1:8450`, the `inet edr_hub` table | no |
| `web` | `10.77.0.20` (`web`, `web.dev.local`) | nginx 1.28.3 (Ubuntu's USN-9159-1 fixed build) and PHP 8.5 FPM, serving a hello-world page for `web.dev.local` on `:80` and `:443` (HTTP/2, self-signed certificate), and sshd on `:22` (nothing connects to it; the client installer's `--yes` wants to see it listening). `./mock.sh install-web` installs the client from its tarball | `127.0.0.1:80`, `127.0.0.1:443` |

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
installers run inside them (`mock.sh install-hub`, `install-web`). The whole repository is mounted read-only at
`/opt/SuricataInstall`. State lives in the container layer, so `up` after an image change erases an installed kit.

## Use

    cd server_edr_solution/mock
    ./mock.sh up          # build and start; waits until both boxes are healthy
    ./mock.sh test        # smoke test; exits non-zero on any failure
    ./mock.sh status      # containers and addresses
    ./mock.sh shell web   # root shell in a box (or: hub)
    ./mock.sh logs web    # follow a box's journal
    ./mock.sh down        # stop and remove; add --volumes to also forget the certificates

With the real installers, in this order (see "Runs so far" below):

    ./mock.sh dist          # make dist on this machine; copy each tarball and a hash made here into its box
    ./mock.sh install-hub   # disable the placeholder; unpack, check the hash, install.sh --plan, install.sh --yes
    ./mock.sh install-web   # the client, local mode: --no-kernel --no-tetragon --droplet-id mock-web --yes
                            # (+ --no-suricata unless MOCK_SURICATA=1; MOCK_WEB_FLAGS="..." adds flags)
    ./mock.sh enroll        # token made on the hub box, carried to the web box in a file, edr-agent enroll
    ./mock.sh reboot        # restart both boxes; units, tables, the droplet id and the heartbeat must come back
    ./mock.sh e2e           # the checks below; every one PASS or FAIL, exit non-zero on a FAIL
    ./mock.sh uninstall     # edr-uninstall and the hub's uninstall.sh, the residue checks, the placeholder back

`up`, `test`, `status`, `shell`, `logs` and `down` work as before, and every subcommand that enters a box refuses a
rootful Docker daemon first. Nothing runs from the read-only checkout: the tarballs are copied into `/root/mock-dist`
in each box and unpacked there. The installed kits live in the container layer, so `down` forgets them.

To use the site in a browser, add this line to `/etc/hosts` (the script doesn't change it for you):

    127.0.0.1 web.dev.local

Then open <http://web.dev.local> or <https://web.dev.local> (self-signed, so the browser warns once). Or:

    curl --resolve web.dev.local:443:127.0.0.1 -k https://web.dev.local/

Port 80 serves the page too, not a redirect, so Suricata has plain HTTP to inspect. A real site would redirect.

## What `./mock.sh test` checks

The list below is the summary; `mock.sh` is the authority on the exact checks and their count.

- The page is served on `:80` and on `:443` over HTTP/2, by PHP 8.5, with a certificate naming `web.dev.local`.
- `/.env` is refused (403).
- The web box is Ubuntu 26.04 with systemd as PID 1 and every unit running; the hub box is checked through its placeholder (TLS 1.3 on :8443) only.
- php8.5-fpm and nginx are active, and the nginx package is at least the USN-9159-1 fixed build (NGINX2Root).
- The web box reaches the hub placeholder at `10.77.0.10:8443` over TLS 1.3, and resolves `hub.dev.local`.
- The hub reaches `https://web.dev.local` over the private network.
- The hub publishes no ports to this machine.

## What `./mock.sh e2e` checks

Run it after `install-hub`, `install-web` and `enroll`. `mock.sh` is the authority on the exact checks.

- The hub box: `edr-hub`, `edr-hub-out` and `edr-hub-ui` are active; `edr-hub health` exits 0; the table `inet edr_hub` is
  loaded; the hub box publishes no port to this machine.
- The web box: `edr-agent` is active; the host `web` was `pending` right after enrollment (or already `active`) and is
  `active` at the hub within 2 minutes.
- A `curl` from the hub box to `http://web.dev.local/.env` shows up as a `canary.tripwire` event in `edr-hub events --json`
  within 2 minutes, and a recorded Tetragon JSON line appended in the web box as a CRITICAL `tetragon.nginx-exec` event
  (Tetragon itself is not running: the line is a recording).
- `edr-check` on the web box and the hub's `check.sh` each exit 0 or 1.
- `edr-hub host web revoke` gives the agent a 403 (`edr-agent status` shows `host_revoked`) and it keeps spooling.

The Tetragon reader is off in a box installed with `--no-tetragon`, so `e2e` switches the reader on for the replay
(`[kit] tetragon = on` and a restart of the agent, no `apply-config`) and off again at the end.

`./mock.sh reboot` (after `enroll`, before `e2e`, which revokes the host) restarts both containers. That is a new
systemd boot with an empty `/run` on the same disk and the same kernel, not a kernel reboot. It checks that the hub's
three units, its table, `edr-hub health` and the backup timer are back; that `edr-agent`, the table `inet edr` (within
30 s), the kit's timers and path units, nginx and php-fpm are back; that `/run/edr-droplet-id` holds the stored id
again; that no unit failed in either box; and that the hub hears a heartbeat from the web box within 2 minutes.

`./mock.sh uninstall` then runs both uninstallers and checks that no kit table (`inet edr_hub`, `inet edr`, `inet edr_dns`,
`inet edr_isolate`), unit, listening port (8443, 8444, 8450) or process is left in either box, and puts the placeholder
back on `:8443`.

## Runs so far (2026-11-24, rootless Docker, from freshly built boxes each time)

`MOCK_HTTP_PORT=18080 MOCK_HTTPS_PORT=18443` was used, because port 80 was taken on the machine.

| Step | Ubuntu 26.04 | Ubuntu 24.04 |
|------|--------------|--------------|
| `up`, `test` | 12 of 12 | 12 of 12 |
| `dist`, `install-hub` | installed; the hub's `check.sh` 38 passed, 1 warning (no backup yet), 0 failed | the same |
| `install-web` | installed and confirmed; `edr-check` 25 passed, 0 failed (36 passed, 0 failed with `MOCK_SURICATA=1`) | the same |
| `enroll` | the host is `pending`, then `active` | the same |
| `reboot` | 13 of 13 | 13 of 13 |
| `e2e` | 15 of 15 (16 of 16 with `MOCK_SURICATA=1`) | the same |
| `uninstall` | both uninstallers exit 0; residue checks 15 of 15 (16 of 16 with `MOCK_SURICATA=1`) | the same |

Each release was run both without Suricata (the default) and with it (`MOCK_SURICATA=1`: Suricata 8.0.8 from the OISF
PPA, af-packet on the box's default-route interface, the full rule set, about 33,000 rules loaded). With Suricata,
`e2e` also sends one request from this machine through the published port for a path an Emerging Threats rule
alerts on, and expects a `suricata.alert` event at the hub; `uninstall` also checks that Suricata, which the kit
installed, is gone with its directories.

Not exercised in any run: the DNS step (`/etc/resolv.conf` is Docker's, not the resolved stub, so the installer skips
it and nothing is locked), Tetragon and every kernel step (`--no-tetragon`, `--no-kernel`). Suricata's performance and
memory figures mean nothing here (20 cores, no limit enforced).

What the runs found and fixed (each has a unit test where one could be written):

- **Hub installer:** it wrote its manifest before `/etc/edr-hub` existed, and installed a package without `apt-get update`.
- **Client installer:** `local.conf` lost its `edr-agent` group when a key was written, so the agent could not read
  it; a skipped DNS step was not recorded (so `check.sh` failed on it) and left the packaged dnscrypt-proxy units
  enabled, which then failed at every boot; a second `install.sh` did not restart the running agent.
- **Units:** `edr-droplet-id.service` (and, by the same rule, `edr-dns-watch.service`) failed at step NAMESPACE on a
  path that did not exist yet. After a reboot `/run/edr-droplet-id` came back empty on a host that relies on the
  stored id, because the sandboxed helper cannot read the agent's own directory: an unsandboxed `--seed` run now
  copies it first.
- **Suricata step (it had never run):** the generated `HOME_NET` include named the `vars:` mapping again, and
  Suricata empties a mapping that an include names again, so every other rule variable was gone and the rule set would
  not load: the include now holds one dotted key. The unit override left Suricata unable to read `/etc/suricata`
  (the package makes it `suricata:suricata 0750` and the override has no `CAP_DAC_OVERRIDE`): it now has the
  `suricata` group. Its capability list was two short for Suricata's own change of user (`CAP_SETPCAP`,
  `CAP_SYS_NICE`); the six it needs were measured. `/run/suricata` was gone after a reboot, so the command socket
  and every stop failed: the unit makes it at each start. `edr-home-net.service` could not write `/etc/suricata`
  and failed at every timer run. `edr-check` could not read `HOME_NET` back because the file's own `---` line was
  taken for a separator. The uninstaller left `/etc/suricata`, `/var/lib/suricata`, the logs and two units listed
  as failed.
- **`check.sh`:** it tested the packaged dnscrypt-proxy file, not the kit's. In a box installed with `--no-kernel`
  the agent's failed network-filter self-test is now a WARN, not a FAIL.
- **Client uninstaller:** it left `/var/lib/edr-bans`. On 24.04 (systemd 255) `systemctl disable --now A B C` does
  nothing when one unit file is missing, so the ban timer kept running and rebuilt the table the uninstaller had just
  deleted: units are now stopped and disabled one at a time.
- **The mock itself:** published ports can be moved; `enroll` can be run twice; the placeholder no longer needs
  `LoadCredential` (see the `LoadCredential` row of the table below).

## Docker requirements and safety

- **Rootless Docker** (what this machine uses) is the only supported setup. `mock.sh` finds the rootless socket
  by itself when `/var/run/docker.sock` doesn't exist.
  - Publishing ports 80 and 443 needs `net.ipv4.ip_unprivileged_port_start` to be 80 or lower. It is 80 here.
  - The boxes run `privileged` because systemd needs it. Under rootless Docker that privilege stays inside your
    user namespace. `mock.sh` checks that before it starts or enters a box (`docker info -f
    '{{.SecurityOptions}}'` must list `rootless`) and refuses otherwise; `down` always works.
- Published ports are bound to `127.0.0.1` only, never to your LAN.
- Installers must never flush nftables or iptables globally, only the kit's own table and chains. The box's
  iptables `nat` table holds Docker's `127.0.0.11` DNS rules, and a flush would break name resolution.

## Installer flags for the mock

`mock.sh install-hub` and `install-web` run the two installers with these flags (names as in
`../server_client/PLAN.md` section 7 and `../server_hub/PLAN.md` section 8, checked against the installers' usage text).
Nothing runs from a checkout: `mock.sh dist` builds the tarballs with `make dist` and copies them into the boxes, and the
installers run from the unpacked, hash-checked tree (client section 7). The read-only repository mount is for reading only.

| Flag | Installer | Why the mock needs it |
|------|-----------|-----------------------|
| `--no-kernel` | client | Pre-flight refuses kernel steps inside a container unless this is given; with it the installer prints a WARN and skips **every** kernel-wide step: module load and unload (`modprobe -r sctp`), the live SCTP block, all sysctls (network ones too), conntrack sizing and accounting, and BPF, which a container shares with this machine. Nothing the mock runs writes to the host kernel. The `/etc/modprobe.d` file is still written and its parse checked |
| `--droplet-id ID` | client | The mock is not a DigitalOcean droplet and has no metadata service, but `droplet_id` is required by the hub. The installer accepts this flag only when the metadata service does not answer (it refuses, exit 3, when it does); `edr-droplet-id.service` then writes that value (client section 4.6) |
| `--no-tetragon` | client | Tetragon cannot load in a container (see the table below) |
| `--no-suricata` | client | When Suricata's af-packet cannot run on the veth, or to save memory |
| `--no-web` | client | On the hub box, which has no nginx |
| `--yes` | both | No prompts. The client install then confirms itself after its automated checks, which include sshd listening on port 22 (the web image has `openssh-server` for that; without it the install is rolled back, exit 4); over SSH the hub install waits for `install.sh --confirm` from a second SSH session; in a `mock.sh` box there is no SSH session, so there is no timer and the firewall is enabled at once (hub section 8) |
| `--public-ip 10.77.0.10`, `--admin-ip 10.77.0.20/32`, `--max-db-size 256M`, and the three ports | hub | The address clients connect to goes into the server certificate; the web box is the one admin address; a small database cap keeps the disk pre-flight small for a container |
| `--plan` | both | Prints what would change; run it first and read it |

The hub installer has none of the `--no-*` flags. Its plan lists no sysctl or module change; its firewall is the
`inet edr_hub` nftables table, which lives in the box's own network namespace.

Without `--no-suricata`, Suricata, nftables, dnscrypt-proxy and the agent install normally; `mock.sh install-web` adds
`--no-suricata` unless `MOCK_SURICATA=1`. It installs the client in local mode (no `--hub`); `mock.sh enroll` then joins
the hub with `edr-agent enroll --token-file`, so the token is never on a command line.

## What the mock can and can't test

Containers share this machine's kernel, so anything that changes the kernel itself belongs in a VM test
(see "Repo integration" in `../server_client/PLAN.md`), not here.

| Part of the plan | In the mock? |
|------------------|--------------|
| nginx, php-fpm, systemd units, timers, the kit's journal namespace and the disk guard | yes |
| Suricata in af-packet IDS mode on the box's own interfaces | yes for rules and alerts; set `checksum-checks: no` (veth offload); no performance numbers |
| nftables ban sets, ban apply, the `inet edr_dns` lock logic, `bigconn` logic on recorded counters | yes, inside each box's own network namespace. Real `bigconn` byte counting needs `nf_conntrack_acct` (a sysctl): VM only |
| `nf_conntrack_acct`, conntrack sizing and every other sysctl | **no**. `--no-kernel` skips them all and nothing in the mock may write to the host kernel; a VM test covers them. `bigconn` is tested on recorded counters |
| nft and iptables `LOG` lines (`edr-bigconn:`, `edr-dnslock:`) and `journalctl -k` | **no**. A container's namespace emits none; test the kernel-log reader with recorded lines, and the real thing in a VM |
| The `sctp` modprobe block file and `modprobe -n -v sctp` | the file is written under `--no-kernel` and its parse checked, yes; the live block (`modprobe -r sctp`) and real blocking **no** (the modules are the host's) |
| dnscrypt-proxy | yes |
| systemd-resolved drop-in | only after installing systemd-resolved (the image has none), and `/etc/resolv.conf` is a Docker bind mount, so the installer must cope with it |
| `IPAddressDeny` / `IPAddressAllow` | **no**. Under rootless Docker systemd has no BPF firewall and silently does not enforce them |
| `MemoryMax`, `CPUQuota` | only if the box shows a real value in its `memory.max`; otherwise the limit is not enforced |
| `edr-agent` install, local mode, uninstall | yes (`install-web`, `uninstall`) |
| Hub install, the `edr-hub` units, sockets and users, the `edr_hub` nftables table (load, rate meters; `--clients-only` is not in this release) | yes, inside the hub box's own network namespace (`install-hub`). The `meta skuid` rule that stops `edr-hub` calling out is proven in a throwaway network namespace (hub section 12, L1) and re-checked in a VM |
| Hub `IPAddressDeny` and `MemoryMax` limits | **no**, for the same reasons as the two rows above; the rest of the hub's sandbox (`ProtectProc`, `PrivateNetwork`, users, sockets) yes |
| Enrollment (`:8444`, `/v1/ca`, `/v1/enroll`, a token carried in a file) | yes, against the real hub (`enroll`) |
| mTLS (client certificate required on `:8443`), heartbeats, events, the host going `pending` then `active`, revoke | yes, against the real hub (`e2e`) |
| `rehome` and restore | **not yet**: needs a second hub (see "Planned additions") |
| Local auto-bans from real source addresses | **not yet**: all traffic arrives from private addresses, which are never banned |
| `LoadCredential` (`edr-hub-out` and `edr-hub-failed` read `secrets.json` through it, `edr-notify` its URL and the alert file) | on 26.04 (systemd 259) yes. On 24.04 (systemd 255) **no**: under rootless Docker `$CREDENTIALS_DIRECTORY` is set but the directory does not exist (tested with a transient unit, with and without `DynamicUser`), so in a 24.04 box the hub has no webhook secret and sends no alert, and nothing reports that. A real 24.04 host is not affected; alert delivery on 24.04 needs the VM tier |
| Clock changes (certificate renewal at 30 days) | **no**. `CAP_SYS_TIME` does not move the shared clock; use `libfaketime` per service |
| **Tetragon** (eBPF) | **no**. It would load into this machine's kernel, and under rootless Docker it can't load at all. Replay recorded Tetragon JSON into the agent instead |

A pass in an "only if" row is not proof: a limit that is not enforced in the box must be reported, not ignored
(see the planned `mock.sh test` probe below).

**Source addresses.** Requests from this machine reach nginx from the `edr_egress` gateway (`172.18.0.1` here).
All box addresses are private, which the ban logic never bans (see "Planned additions").

## Planned safety changes

Not built yet. (`mock.sh` refusing a rootful daemon, and the client installer refusing kernel steps in a container
unless `--no-kernel` is given, were on this list and are in place.)

1. Replace `privileged` with `cap_add: [SYS_ADMIN, NET_ADMIN, NET_RAW, SYS_PTRACE, DAC_READ_SEARCH, SYSLOG]`, with
   no `SYS_MODULE` or `SYS_TIME`. Boot-test this variant first; it may need `systempaths=unconfined`, which is
   acceptable on rootless Docker only. The variant exists as `compose.caps.yaml` and is opt-in until it has been
   booted: `MOCK_CAPS=1 ./mock.sh up && MOCK_CAPS=1 ./mock.sh test`. When that passes it becomes the default.

## Planned additions

Not built yet. Each stays optional, in its own compose profile where it adds a box.

- `mock.sh test` probes `memory.max` and BPF firewall support, and fails loudly (not skips) when a limit row cannot be
  trusted. Sysctls are not probed: the client installer runs with `--no-kernel`, so no sysctl row is tested here.
- An `attacker` box (curl, nmap, ssh client, h2load) on a new `edr_wan` network, using `198.18.77.0/24` as the
  droplet's "public" side with the web box's default route on it, for ban, scan and h2c tests.
- A second hub, `hub2` at `10.77.0.11`, for `rehome` and restore tests.
- `libfaketime` in the web image, and `sudo` or `runuser` for the canaries. (`openssh-server` is in the image now.)
- A Laravel-like app: the Laravel nginx block (only `index.php` runs, catch-all `default_server` returning 444), a
  `www-data`-writable `storage/`, and a loopback-only `lab.php` that can exec, write, connect out and read env.
  A deliberately weak second vhost would test the inventory's nginx checks.
- IPv6 on `edr_wan`, with a prefix the never-ban list does not contain.
- `mock.sh snapshot|reset`: start installer tests from a clean droplet quickly, and diff what an install
  and uninstall leave behind (`mock.sh uninstall` already checks that no table, unit, port or process of the kits is left).

## Files

| File | Purpose |
|------|---------|
| `compose.yaml` | The two boxes, both networks, published ports, certificate volumes |
| `compose.caps.yaml` | Opt-in (`MOCK_CAPS=1`): the boxes with a capability list instead of `privileged`; not boot-tested yet |
| `Dockerfile` | One shared `base` stage (Ubuntu 26.04 or 24.04, and systemd), then `hub` and `web` targets (the web target also has `openssh-server`) |
| `mock.sh` | `up`, `test`, `status`, `shell`, `logs`, `down`; and, for the real installers, `dist`, `install-hub`, `install-web`, `enroll`, `reboot`, `e2e`, `uninstall` |
| `common/mock-tls.sh` | Creates a self-signed certificate on first boot, so no private key is baked into an image |
| `hub/*.service`, `web/mock-tls.service` | Certificate units, and the `:8443` placeholder. `mock.sh install-hub` disables the placeholder and `mock.sh uninstall` enables it again |
| `web/web.dev.local.conf`, `web/web.dev.local.common` | The nginx site: `:80`, and `:443` with HTTP/2 |
| `web/public/index.php` | The hello-world page |
