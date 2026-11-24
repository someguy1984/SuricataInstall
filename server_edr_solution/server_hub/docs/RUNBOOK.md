# edr-hub runbook

Every alert carries the exact command, so one person on a phone can act. This file holds the same text as the
alert bodies: the table in the last section is generated from `hub_rules.RULES` (the one table that feeds alerts,
this runbook and the dashboard), and a unit test fails when the two differ. Section numbers refer to
`server_hub/PLAN.md`; "client" means `server_client/PLAN.md`. Commands marked (P3) arrive in a later phase.

## Day to day

Commands are in PLAN section 6. `edr-hub resolve ID` closes an incident. Run `edr-hub alert test` after any
channel change and monthly. An incident also resolves itself after 60 minutes with no new signal.

## A 03:00 alert from a phone

1. SSH in (a phone SSH client or the DigitalOcean console) and run `sudo edr-hub incident ID`.
2. **HIGH, one signal:** read the events. Acknowledging is (P3); until then leave it for the morning. A HIGH does not
   repeat; it stays open on the dashboard and in the daily digest.
3. **CRITICAL or "possible success":** treat the host as lost (PLAN section 4). On the host run
   `sudo edr-agent isolate --for 1h` (P3; before P3 use a Cloud Firewall outbound rule, client section 17). In the
   DigitalOcean panel snapshot, then rebuild. Run `edr-hub host HOST revoke` (its key may be stolen) and rotate every
   secret it held.
4. **A quiet day:** run `edr-hub status`. A red outbox banner means the webhook is failing; the dead-man service
   (PLAN section 4) tells you the hub stopped.

## Disk full or database corrupt

- **Disk full** ("storage full" in `status`; LOW and INFO get 503; HIGH and CRITICAL go to `critical-overflow.jsonl`).
  Free space: copy `/var/backups/edr-hub` off and thin it, lower `retention_days` or `max_db_size`
  (`edr-hub settings set`). The writer prunes and replays the overflow file (PLAN section 3). Never delete `-wal` or
  `-shm` by hand.
- **Corrupt:** see PLAN section 3, Integrity. `systemctl stop edr-hub`, then `edr-hub restore FILE` from the newest
  good backup (PLAN section 7; add `--ca-key FILE` only if `ca/` was lost too; on a new box first put the backup's
  passphrase into `/etc/edr-hub/backup.pass`). Keep the moved-aside file. Clients
  replay their spool. Hosts enrolled after that backup show as `orphan`: check each, then `edr-hub host UUID adopt`.

## Restore drill

Quarterly; schedule it yourself, nothing reminds you. On a scratch droplet install the hub (PLAN section 8), run
`systemctl disable --now edr-hub-out`. Put the passphrase the backup was made with into `/etc/edr-hub/backup.pass`
(root, mode 0600; the install wrote a new one that cannot open the old backup, and `restore` has no option for it).
Then run `edr-hub restore FILE --drill --ca-key FILE` with `edr-hub` stopped (PLAN section 7). `--drill` skips the secrets, so the drill box has no webhook or dead-man URL, and `edr-hub-out` is
off so nothing posts to them. Check hosts, the CA SHA-256 and `quick_check` in `edr-hub status`. Destroy the droplet.

## Certificates

- **Hub server certificate** reissues itself at 30 days left (PLAN section 2). If an alert says otherwise, run
  `edr-hub reissue-cert`. A lapse stops the whole fleet at once.
- **Client certificate** renews itself. One that expired (a stopped droplet) cannot: make a token `--for HOST` and run
  `edr-agent enroll --token-file FILE` on that host (client section 4.6).

## Rotating secrets

- **Dashboard.** There is no standing token: `edr-hub ui-login` mints a single-use code (PLAN section 5).
  `systemctl restart edr-hub-ui` ends every session (they live in its memory). The SSH key is the credential.
- **Webhook or SMTP.** Create the new secret at the provider, run `edr-hub settings set webhook_url -` (value on
  stdin), run `edr-hub alert test`, then revoke the old secret. The change is also sent to the old channel.

## An operator leaves

Same day, hub first.

1. Remove their SSH key from the hub and every client. Rotate the webhook, SMTP, ntfy and dead-man secrets. Revoke open
   tokens (`token list`). Remove them from the DigitalOcean team and revoke their API tokens.
2. Run `sudo server_hub/install.sh --admin-ip <remaining>` (it replaces the list; safe apply, PLAN section 8 step 10)
   and `edr-hub never-ban remove CIDR`.
3. On every client remove their address from `admin_ip` and `allow_cidr` in `local.conf`, then run
   `edr-agent apply-config` (client section 14): admin addresses are local, so no hub command can do it.
4. Run `edr-hub reissue-cert` and review `edr-hub audit --since 30d` (the actor is `SUDO_USER`; per-person accounts
   are out of v1). If they held the `ca-export` file or its passphrase, the backup passphrase, or root on the hub, do
   the CA compromise runbook.

## CA compromise

1. Install a new hub with a new CA and a new address. Do not restore the CA. Leave the Reserved IP on the old hub.
2. On the new hub run `edr-hub token create --names web-1,web-2,... --ttl 4h` (the hosts get new UUIDs and their
   history stays on the old hub, PLAN section 7), then `edr-agent rehome` on each client (client section 5). Until a
   client moves, the thief can pose as the old hub to it, but can only send bans, feeds and peers, which the client
   bounds (client section 4.2).
3. Shut the old hub down, retire its droplet, rotate every hub secret.

## Stolen client key

Signs: events or policy requests for a host that is not behaving, or a host you no longer control.

1. `edr-hub host HOST revoke`. Its certificate is revoked at once (`revoked.txt`); further attempts with that key are
   rejected, counted and alerted (the `rejected` rule below).
2. Read what was sent in its name: `edr-hub events --host HOST --since 30d`. With the key a thief can send false events
   and heartbeats as that host and fetch its policy; it cannot reach any other host.
3. If the host is clean, make a token `--for HOST` and run `sudo edr-agent enroll --token-file FILE` on it (client
   section 4.6): it makes a new key. If the host is not clean, treat it as lost (PLAN section 4): snapshot, rebuild,
   then the same token. Either way the UUID and history continue.

## Decommissioning a client

Client uninstall retires the host (client section 6); for a destroyed droplet run `edr-hub host HOST retire`. Either
revokes the certificate and drops its never-ban address (PLAN section 2). Revoke its open tokens and remove its
droplet tag.

## Year-two housekeeping

| When | Task |
|------|------|
| Monthly | `edr-hub audit verify`; the silent-hosts digest; from P3, `edr-agent bans` on one client against `edr-hub bans` |
| Quarterly | Restore drill; review `never-ban` and the admin list; feed and advisory age in `status` |
| After kernel, `python3`, `openssl` updates | Planned reboot or `systemctl restart edr-hub` (PLAN section 8) |
| Yearly | Rotate webhook and dead-man URL; confirm the Reserved IP and snapshot schedule |
| Year 8 | Replace the CA (runbook above); at 10 years it expires and every client drops at once |

## What each alert means and what to do next

One row per rule of PLAN section 4. "Reads" names the event kinds (client Appendix B) and heartbeat keys
(hub Appendix A) a rule looks at, or the hub-side value it computes. Hub-made alerts carry the kind `hub.<name>`.

<!-- BEGIN RULES (generated from hub_rules.RULES; run: python3 hub_rules.py --update-runbook FILE) -->

#### Attacks on a host

| Rule | Reads | Severity | Meaning | Next step |
|------|-------|----------|---------|-----------|
| `web_exec` A web-user process execs, writes code or becomes uid 0 | `tetragon.nginx-exec`, `tetragon.web-exec`, `tetragon.web-write-code`, `tetragon.privilege-escalation` | CRITICAL | A process in the web user's tree ran a program, wrote code or became uid 0. | Patch if vulnerable, snapshot, then restart nginx (not reload): Sigkill stops the exec, not code already in the worker. |
| `sctp` An SCTP socket, or the sctp module loading | `tetragon.sctp-socket`, `tetragon.monitor-kernel-modules` | CRITICAL from a web-user tree, else HIGH | An SCTP socket was opened or the sctp module loaded: the root step of NGINX2Root. | Treat as the root step of NGINX2Root (https://xint.io/blog/nginx2root-remote-code-execution): snapshot, patch the kernel, block the module. |
| `dnslock` A plain-DNS refusal by the DNS lock | `edr.dnslock` | HIGH; MEDIUM when the destination is an nginx resolver of that host | The DNS lock refused a lookup that bypassed the local resolver. | nginx with an outside resolver makes these lookups legitimate: point it at 127.0.0.53 (client section 4.4). |
| `log_truncated` A tailed log file shrank | `tamper.log_truncated` | HIGH | A log file the agent tails became shorter: someone may be hiding traces. | Read the host's auth and nginx logs by hand; treat as tampering until explained (client section 4.5, Log shrink). |
| `secrets_read` A .env read by an unexpected program; tampering; a decoy file read | `tetragon.env-read`, `tamper.*`, `canary.file` | HIGH | A secrets file was read by an unexpected program, a kit file was tampered with, or a decoy file was read. | Assume .env was read: rotate APP_KEY, database and API secrets. |
| `nginx_crash` nginx worker crashes: 3 in 10 minutes on one host | `nginx.crash` | HIGH | nginx workers crashed three times (sum of count) within ten minutes. | Possible exploit attempts; low fidelity alone (https://cert.europa.eu/publications/security-advisories/2026-022/). Check the package and the exposure. |
| `bigconn` One :443 connection past 4 GiB | `edr.bigconn`, `nginx.crash` | MEDIUM; HIGH if a crash follows in 30 minutes | A single :443 connection carried more than 4 GiB: the heap-corruption stage of CVE-2026-123007. | The client bans the source on a repeat (client section 4.2). Check for a crash and for the nginx version. |
| `window_update` Flow-control violation from one IP, 3 in 10 minutes | `nginx.marker.window_update` | MEDIUM | nginx logged 'client violated connection flow control: received WINDOW_UPDATE' for one address. | Local ban. A rejected attempt on patched builds; logged only at info, so edr-check warns if the log is hidden. |
| `resolver_cancel` 'could not cancel ... resolving' | `nginx.marker.resolver_cancel` | HIGH | nginx logged the resolver cancel line that only unpatched builds write (CVE-2026-123634). | Patch nginx: this line is logged at ALERT only by unpatched builds. |
| `tripwire` Tripwire path hit | `canary.tripwire` | LOW (404, 403, 444); HIGH (200) | A tripwire path was requested. A 200 answer means the site serves that path. | The client bans locally. A 200 means the site serves the path: no ban, check the site. |
| `auth_state` New uid-0 account, sudoers or authorized_keys change | `inventory.auth_state` | HIGH | The account, sudoers or authorized_keys state of the host changed. | Compare with the change you made; if none, assume persistence (client section 4.5.1, auth_state). |
| `ssh_login` A new key or first root login, or a password login with password auth off | `ssh.login` | MEDIUM / HIGH | An SSH login that is new: a new key, a first root login, or a password where passwords are off. | A new source address is a digest line. Check that the login was yours; novelty stays LOW for the first 14 days. |
| `never_ban_hint` Scanner or web signal from an address in the never-ban ranges | `suricata.alert`, `ssh.fail`, `canary.tripwire` | MEDIUM | A scanner or web signal came from an address in the never-ban ranges. It is never banned. | A hint only: load balancers are internal. Check whether the address is really yours. |

#### Containment and loss of visibility

| Rule | Reads | Severity | Meaning | Next step |
|------|-------|----------|---------|-----------|
| `contained` Attempt contained: a crash, bigconn or flow-control line, then a killed exec or SCTP socket within 30 minutes | `nginx.crash`, `edr.bigconn`, `nginx.marker.window_update`, `tetragon.nginx-exec`, `tetragon.sctp-socket` | CRITICAL | Early signals of an nginx attack were followed within 30 minutes by a blocked exec or SCTP socket: the kill worked this time. | Restart nginx; hunt for persistence (authorized_keys, cron, ld.so.preload); patch. |
| `survived` Worker survived the kill: a fork-watch hit, then any web event within 10 minutes | `tetragon.fork-watch`, `tetragon.web-exec`, `tetragon.web-write-code`, `tetragon.web-connect` | CRITICAL | A fork-watch hit was followed by more web activity: the worker may still be running attacker code. | Restart nginx (not reload). The hub keeps an open operator task until inventory shows worker start times newer than the hit. |
| `possible_success` Possible success: first signals, then within 30 minutes a heartbeat gap, tamper or Tetragon unhealthy | `nginx.crash`, `edr.bigconn`, `nginx.marker.window_update`, `tetragon.nginx-exec`, `tetragon.sctp-socket`, `tetragon.fork-watch`, `tamper.*`, `tetragon`, `units`; hub-side: hub-side heartbeat gap | CRITICAL | Attack signals were followed within 30 minutes by silence, tampering or a Tetragon that is not healthy. | Treat the host as lost: snapshot, rebuild, rotate every secret it held (https://raw.githubusercontent.com/Censys-Research/nginx2root/main/evidence/cve-2026-123007/RCE-CONFIRMED.md). |
| `enforcement_gone` Enforcement gone | `health.enforcement_gone`, `tetragon`, `kernel` | HIGH | The client reports a policy set to enforce that is not loaded, or a kernel change without a passed canary. | Read the heartbeat's policy list (name, mode, would_be_kills); restart Tetragon; run edr-check on the host. |
| `agent_silent` Agent silent | hub-side: hosts.last_seen | HIGH; CRITICAL within 30 minutes of a rule above | No heartbeat for five minutes. | Down, tampered with or blinded. Silent 14 days: a daily 'retire it?' line, paging continues. |
| `reboot` Reboot: notice then a new boot id within 10 minutes / a new boot id with no notice | `shutdown`, `boot_id` | INFO / MEDIUM; HIGH within 30 minutes of a Sigkill hit | The host started with a new boot id. | Check the console. Over 10 minutes of silence after a notice is the real alert. |
| `agent_build` Unknown or changed agent build | `agent_sha256`, `agent_version` | HIGH | The agent's SHA-256 is not a known build, or it changed while the version did not. | Re-check the build; add it with 'edr-hub agent-hash add SHA' if intended. |
| `duplicate_identity` Duplicate identity: one certificate from two droplet ids, or two live boot ids | `droplet_id`, `boot_id` | HIGH | One certificate is used from two droplets, or two boot ids are live at once. | A clone or a stolen key. Clone: enrol it with a plain token (new UUID) and retire the old row only if its droplet is gone. Stolen key: 'edr-hub host HOST revoke', then re-enrol the real host with a token made --for HOST. |
| `disk` Disk guard tripped, or free space under 10% | `health.diskguard`, `health.disk_low`, `disk` | CRITICAL | The disk guard tripped or the disk has less than 10% free. | Sent from memory first, not from a spool on the full disk. Free space on the host; the client empties its low lane first. |
| `policy_lag` policy_rev_applied differs from policy_rev for over 5 minutes, or last_apply_error | `policy_rev_applied`, `last_apply_error`; hub-side: hosts.policy_rev, hosts.policy_rev_since | MEDIUM | The host has not applied the policy document the hub issued, or reports an apply error. | The host is not applying bans: check 'edr-agent status' and its journal. |
| `paused` A pause is in force | `paused_until` | MEDIUM, once per pause | Bans, feeds, enforcement (except edr-canary) and the DNS lock are off on this host until the pause ends. | Shown on the Fleet page. 'edr-agent resume' on the host ends it. A pause does not silence agent-silent. |
| `no_canary` No daily canary result from a host in 26 hours | `canary.policy_check` | MEDIUM, once per host | The daily canary through edr-policy-check did not report. | Run 'sudo systemctl status edr-policy-check.timer' on the host (client section 4.3). |
| `nft_absent` inet edr absent for 2 minutes | `nft` | HIGH | The edr nftables table is missing. | The edr-bans timer did not rebuild it: run 'sudo systemctl start edr-bans.service' and check its journal. |
| `conntrack` Conntrack use of 70% or more | `conntrack` | MEDIUM; HIGH at 90% | The connection tracking table is nearly full. | Raise nf_conntrack_max or check for a flood (client section 4.2). |
| `suricata_drops` Suricata kernel drops over 1% in a window | `suricata_drops` | MEDIUM | Suricata dropped more than 1% of the packets it was given. | See client section 4.1 (capture, memcap and threads). |
| `rules_stale` Suricata rules not updated for 3 days | `health.rules_stale` | MEDIUM | The Suricata ruleset has not been updated for three days. | See client section 4.1 (rule updates). |

#### Inventory and coverage

| Rule | Reads | Severity | Meaning | Next step |
|------|-------|----------|---------|-----------|
| `advisory_exposed` Package below its fix and the feature exposed | `inventory.nginx_pkg`, `inventory.nginx_exposure`, `inventory.security_pending`, `inventory` | HIGH; MEDIUM for the resolver bug when mirror_request_body off is not set | A package is older than the fix in the advisory table and the exposed feature is on. | Repeat daily until fixed. Install the fixed package, then restart nginx. A TLS listener alone: HIGH after 24 hours. |
| `deleted_exe` Old nginx processes run the pre-upgrade binary | `inventory.deleted_exe` | HIGH | Processes still run a binary that was replaced by an upgrade. | Restart nginx or let workers drain; a reload never loads a new binary (https://nginx2root.com/). |
| `kernel_pending` sctp loadable, running kernel below its fix, updates pending or reboot required over 7 days | `inventory.sctp`, `inventory.kernel_pending`, `inventory.security_pending` | MEDIUM | The running kernel is older than its fix, or security updates wait for a reboot. | Daily digest. The running kernel decides, not the package: plan a reboot. |
| `app_key_public` A file under public/ holds an APP_KEY= line | `inventory.posture` | HIGH | A file the web server may serve contains an APP_KEY line. | Rotate APP_KEY and remove the file (client section 4.5.1). |
| `coverage_drift` Coverage drift | `inventory.uncovered_webroots`, `inventory.uncovered_fpm_binaries`, `inventory.uncovered_pool_users` | MEDIUM | A web root, php-fpm binary or pool user is not covered by the policies. | Daily digest. Run 'edr-agent discover', then 'apply-config' (client section 4.3). |
| `inventory_stale` Inventory file missing or over 2 hours old | `inventory.stale` | MEDIUM | The agent could not give a fresh inventory. It reports 'unknown', never 'clean'. | Check that edr-inventory.service runs on the host (client section 4.5). |

#### Hub notices

| Rule | Reads | Severity | Meaning | Next step |
|------|-------|----------|---------|-----------|
| `admin_action` Admin action | hub-side: admin actions | HIGH (always sent) | An operator action changed trust, settings or secrets. | Check that you or a colleague did it: 'edr-hub audit --since 1d'. |
| `enroll` A host enrolled | hub-side: enrollment | HIGH (always sent) | A host was enrolled with a token. | Check that you made the token for this host: 'edr-hub token list', 'edr-hub audit --since 1d'. |
| `rejected` A revoked or superseded certificate was used | hub-side: 403 on the fleet listener | HIGH | A certificate that the hub no longer accepts was presented on the fleet port. | A stolen key or a stale client. See the 'stolen client key' runbook. |
| `pending_silent` A pending host never reported | hub-side: hosts.state, hosts.enrolled_at | HIGH | A host enrolled over an hour ago and has sent no heartbeat. | Check that the agent runs on the host; 'edr-hub host HOST retire' if the install was abandoned. |
| `orphan` A host awaits adoption | hub-side: hosts.state | HIGH | After a restore, the host's certificate is valid but the hub has no record of enrolling it. | Check the host, then 'edr-hub host UUID adopt'. |
| `skew` Host clock skew over 5 minutes | `sent_at`; hub-side: hosts.skew_ms | MEDIUM | The host's clock differs from the hub's by more than five minutes. | Fix NTP on the host. Event times are corrected, but the correction is only as good as the skew estimate. |
| `hub_down` The hub was down | hub-side: meta.engine_tick | HIGH | The hub was not running for more than ten minutes. | Read the journal for the cause. Clients spooled their events and replay them now. |
| `event_loss` Events were lost | `spool`, `seq`, `epoch` | MEDIUM (digest) | A gap in a host's sequence numbers, or a rising spool drop counter. | Check the host's disk and spool ('edr-agent status'). |
| `digest` Daily digest | hub-side: daily | MEDIUM and LOW | The daily summary of MEDIUM and LOW findings. | Read it; run 'edr-hub status' for the live state. |
| `crit_cap` More CRITICAL alerts from one host than the cap allows | hub-side: per-host CRITICAL cap | HIGH | One host sent more than 10 CRITICAL alerts in 30 minutes: the rest were held back for that host only. | Read the host's incidents ('edr-hub incidents --open', 'edr-hub events --host HOST --min-sev critical'): a host that floods CRITICAL events is broken or compromised. |
| `storm` Alerts suppressed by storm control | hub-side: alert storm control | HIGH | More than 20 messages in ten minutes: the rest were held back. | Run 'edr-hub incidents' and 'edr-hub status' for what is open. |
| `test_alert` Test alert | hub-side: edr-hub alert test | INFO | A test alert from 'edr-hub alert test'. | Nothing to do: the channel works. |
| `hub_failed` The hub service failed | hub-side: systemd OnFailure | HIGH | edr-hub.service failed several times in a row. | systemctl status edr-hub; journalctl --namespace edr-hub -u edr-hub. |

#### Hub self-health

| Rule | Reads | Severity | Meaning | Next step |
|------|-------|----------|---------|-----------|
| `client_cert_30` Client certificate under 30 days from expiry, unrenewed | `cert_not_after` | LOW (digest) | A client certificate expires within 30 days and has not renewed. | An expired one cannot renew: 'edr-agent enroll --token-file FILE' with a token made --for HOST (client section 4.6). |
| `client_cert_14` Client certificate under 14 days, unrenewed | `cert_not_after` | MEDIUM | A client certificate expires within 14 days and has not renewed. | The same: re-enrol with a token made --for HOST. |
| `client_cert_7` Client certificate under 7 days, unrenewed | `cert_not_after` | HIGH | A client certificate expires within seven days and has not renewed. | The same: re-enrol with a token made --for HOST. |
| `server_cert_30` Hub server certificate under 30 days | hub-side: tls/server.pem notAfter | MEDIUM | The hub's server certificate expires within 30 days: the automatic reissue failed. | A lapse stops the whole fleet: 'edr-hub reissue-cert'. |
| `server_cert_14` Hub server certificate under 14 days | hub-side: tls/server.pem notAfter | HIGH | The hub's server certificate expires within 14 days. | 'edr-hub reissue-cert' now. |
| `server_cert_7` Hub server certificate under 7 days | hub-side: tls/server.pem notAfter | HIGH | The hub's server certificate expires within seven days. | 'edr-hub reissue-cert' now. |
| `ca_2y` CA under 2 years | hub-side: ca/ca.pem notAfter | MEDIUM | The hub CA expires within two years. | Replace the CA by year 8: a CA rollover is a rehome of every client (CA compromise runbook). |
| `ca_1y` CA under 1 year | hub-side: ca/ca.pem notAfter | HIGH | The hub CA expires within a year. | Replace the CA now (CA compromise runbook, without the compromise). |
| `advisory_90` Advisory table over 90 days old | hub-side: advisories.json updated | MEDIUM | The advisory table shipped with this hub release is older than 90 days. | Update the hub release. |
| `advisory_180` Advisory table over 180 days old | hub-side: advisories.json updated | MEDIUM; status 'unknown', never 'fixed' | The advisory table is older than 180 days: no package is reported as fixed. | Update the hub release. |
| `backup_age` Last good backup over 7 days old | hub-side: meta.last_backup, last-backup marker | HIGH | No verified backup in seven days. | 'edr-hub backup'; the marker is written by the backup job after a verified backup. |
| `db_size` Database over 80% of its cap, WAL over 256 MB | hub-side: database size, WAL size | MEDIUM | The database is close to its size cap, or the WAL is large. | A pinned reader keeps the WAL growing: check for a stuck 'edr-hub-ui' request or CLI (PLAN section 3). |
| `disk_80` Disk over 80% used | hub-side: disk usage | MEDIUM; HIGH at 90% | The disk under the hub's state directory is filling up. | Thin the backups in /var/backups/edr-hub; see the 'disk full' runbook. |
| `outbox_failing` Outbox failing over 1 hour | hub-side: outbox rows | dashboard and edr-hub status | The alert channel has failed for over an hour. The webhook cannot report its own failure. | 'edr-hub alert test'; check the channel secret and the network from the hub. |
| `engine_cursor` Engine cursor over 60 seconds behind | hub-side: meta.engine_cursor, meta.engine_tick | HIGH | The correlation engine is not keeping up. | 'edr-hub health' fails; read the hub journal (PLAN section 4, Watching the hub). |

<!-- END RULES -->
