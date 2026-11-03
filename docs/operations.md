# Operations Runbook

## Terms

- Server: the host running `ssh-key-sync-server`.
- Client: a managed machine running `ssh-key-sync-client`.
- Public group: fetched anonymously from `/v1/keys/public`.
- Private group: fetched with a machine token from `/v1/keys`.
- Signing fingerprint: SHA-256 digest of the server's raw 32-byte public key.
- Managed file: `/etc/ssh/authorized_keys.d/root`.

## Prerequisites

On the server:

- HTTPS reverse proxy to `127.0.0.1:18080`.
- `/v1/` and `/xmlrpc/` routed to the Rust server.
- `X-Real-IP` set by the trusted proxy.
- Server configuration and signing key installed under `/etc/ssh-key-sync`.
- `ssh-key-sync-server.service` enabled.
- The `ssh-key-sync` service account and systemd unit installed.
- `curl`, `sha256sum`, and outbound HTTPS for automatic updates.

On a client:

- Root access and an open recovery session.
- Existing `authorized_keys` backed up.
- Outbound HTTPS access to the server.
- `sha256sum` and `curl`.
- systemd, or cron for older systems.
- A supported 64-bit x86 or ARM64 Linux architecture.

### Reverse Proxy Contract

The public proxy must route `/v1/` and `/xmlrpc/` to
`http://127.0.0.1:18080`, preserve the request method and body, and set
`X-Real-IP` to the observed client address. Do not trust client-supplied
source-address headers. The server ignores `X-Real-IP` unless the direct peer
is loopback.

A Caddy example is provided at [examples/Caddyfile](../examples/Caddyfile).
Caddy must have its admin API disabled unless deliberately used, and it must
overwrite rather than append `X-Real-IP`. The example exposes only the API
routes and returns `404` for everything else.

### Initial Server Bootstrap

The current release assumes an existing systemd server installation. A
reproducible package-based bootstrap is future work; perform these steps once:

1. Create the unprivileged account and protected configuration directory.
2. Generate `signing.key` and `signing.pub` under `/etc/ssh-key-sync`.
3. Create `server.toml` from [the example](../examples/server.toml), including
   the real `public_url`.
4. Make `server.toml` and `signing.key` readable by the
   `ssh-key-sync` group but not other users.
5. Follow the signed first-install bootstrap in
   [releases.md](releases.md) and install the binary with
   `install-server.sh --no-restart`.
6. Install [the server unit](../deploy/ssh-key-sync-server.service), run
   `systemctl daemon-reload`, and enable the service.
7. Install and validate the TLS proxy route before enrolling production
   clients.
8. Enable backup and auto-update timers only after the manual health checks
   succeed.

For first installations without reverse SSH access to the admin server, host
the reviewed bootstrap assets under the Caddy `/bootstrap/` route and set:

```toml
bootstrap_url = "https://keys.example.net/bootstrap/bootstrap.sh"
```

The bundle contains only the public release key, installer, and architecture-
specific verifier binaries. The TUI then generates copyable first-install
commands using that URL. Without `bootstrap_url`, the TUI warns that a fresh
installation still requires a manually supplied release verifier.

Set the starting auto-update choice for generated install commands with:

```toml
default_auto_update = true
```

The `U` toggle in the `I` and replacement command screens still overrides this
per-message, and the selected value is remembered for the rest of the TUI
session.

Use the following permission model:

```text
/etc/ssh-key-sync                          root:ssh-key-sync  0750
/etc/ssh-key-sync/server.toml              root:ssh-key-sync  0640
/etc/ssh-key-sync/signing.key              root:ssh-key-sync  0640
/etc/ssh-key-sync/signing.pub              root:root          0644
/var/lib/ssh-key-sync                     ssh-key-sync:ssh-key-sync 0755
/var/lib/ssh-key-sync/state.db            ssh-key-sync:ssh-key-sync 0600
```

The installed server must be able to read `server.toml` and `signing.key`.
Verify this as the service account before restarting:

```sh
runuser -u ssh-key-sync -- ssh-key-sync-server check-config \
  --config /etc/ssh-key-sync/server.toml
```

## Public-Group Installation

The client must already have the reviewed release trust anchor at
`/etc/ssh-key-sync/release.pub`. See [releases.md](releases.md) for the
first-install bootstrap.

Obtain the signing-key fingerprint from a trusted administrator:

```sh
sha256sum /etc/ssh-key-sync/signing.pub
```

Install and configure the client:

```sh
curl -fsSL \
  https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install.sh |
  sudo sh -s -- \
    --server https://keys.example.net \
    --signing-key-sha256 SIGNING_KEY_FINGERPRINT \
    --apply-ssh \
    --enable-timer
```

The command:

1. Downloads the latest static client, checksums, and signature.
2. Verifies the signature using `/etc/ssh-key-sync/release.pub`.
3. Verifies the archive against the signed checksums.
4. Installs or upgrades `/usr/local/bin/ssh-key-sync-client`.
5. Downloads `/v1/signing-key` and verifies its fingerprint.
6. Writes `/etc/ssh-key-sync/client.toml`.
7. Fetches and verifies the public key set without changing files.
8. Applies and validates the two-file `sshd` configuration.
9. Installs and enables the systemd timer, or prints the cron-only follow-up.

Verify:

```sh
ssh-key-sync-client sync --dry-run
ssh-key-sync-client inspect-sshd
systemctl status ssh-key-sync-client.service --no-pager
systemctl list-timers ssh-key-sync-client.timer --no-pager
```

On a cron-only host, verify `crontab -l` contains the managed
`ssh-key-sync-client` synchronization entry.

Open a new SSH session before closing recovery access.

## Private-Group Enrollment

Start enrollment on the client:

```sh
curl -fsSL \
  https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install.sh |
  sudo sh -s -- \
    --server https://keys.example.net \
    --signing-key-sha256 SIGNING_KEY_FINGERPRINT \
    --apply-ssh \
    --enroll hostname
```

The client prints a request ID and short code. Do not enable the timer yet.

Review requests on the server:

```sh
ssh-key-sync-server enrollment list
ssh-key-sync-server enrollment show REQUEST_ID
```

Approve into the intended group:

```sh
ssh-key-sync-server enrollment approve REQUEST_ID --group GROUP_NAME
```

Or deny:

```sh
ssh-key-sync-server enrollment deny REQUEST_ID
```

Denied or retired requests can be hidden without deleting their audit trail:

```sh
ssh-key-sync-server enrollment hide REQUEST_ID
```

Revoke and hide an old approved machine enrollment atomically:

```sh
ssh-key-sync-server enrollment retire REQUEST_ID
```

On the client:

```sh
ssh-key-sync-client enrollment-status --wait
ssh-key-sync-client sync --dry-run
ssh-key-sync-client sync
systemctl enable --now ssh-key-sync-client.timer
```

Verify a new SSH connection remains available.

For a cron-only host, install the synchronization entry after approval:

```sh
ssh-key-sync-client --config /etc/ssh-key-sync/client.toml install-cron
ssh-key-sync-client --config /etc/ssh-key-sync/client.toml install-cron --dry-run
```

## Client Upgrade

The existing configuration and token are preserved:

```sh
curl -fsSL \
  https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install.sh |
  sudo sh
```

Then run:

```sh
ssh-key-sync-client sync --dry-run
systemctl start ssh-key-sync-client.service
```

With auto-update enabled, the same update runs daily from
`ssh-key-sync-client-update.timer`, or from the managed cron entry on a
cron-only host.

## Editing Keys And Groups

Configuration edits are validated, backed up, written atomically, and loaded by
the running server within approximately two seconds.

```sh
ssh-key-sync-server key list
ssh-key-sync-server group add staging
ssh-key-sync-server group add-cidr staging 192.0.2.0/24
ssh-key-sync-server key add alice staging 'ssh-ed25519 AAAA... alice@example'
ssh-key-sync-server key assign alice staging
ssh-key-sync-server key remove alice SHA256:fingerprint
ssh-key-sync-server group remove staging
```

Create a group and assign existing owners atomically with repeated `--owner`
options:

```sh
ssh-key-sync-server group add SamplingLines \
  --owner mike \
  --owner martin
```

Without `--owner`, the CLI warns that the new group is empty. In the TUI,
creating a group switches directly to the Keys view so an owner can be selected
and assigned with `G`.

`group remove` and `key remove` reject unsafe changes through normal
configuration validation. A timestamped backup is created before each edit.

The unsigned compatibility route is opt-in per group:

```sh
ssh-key-sync-server group set-legacy GROUP_NAME true
ssh-key-sync-server group set-legacy GROUP_NAME false
```

Enable it only for groups still required by legacy XML-RPC clients.

## Terminal UI

Open the local administration interface with:

```sh
ssh-key-sync-server tui
```

The TUI refreshes pending enrollment state every two seconds, shows the pending
count, and emits a terminal bell when a new request arrives. Use `F5` to reload
the server configuration after an external edit.

| Key | Action |
| --- | --- |
| `Tab` | Move between enrollments, tokens, groups, and public keys |
| `A` | Approve an enrollment, add a group, or add a public key |
| `D` | Deny a pending enrollment |
| `R` | Revoke a selected token |
| `C` | Manage CIDRs for a selected group |
| `G` | Toggle a selected key owner's group assignments |
| `L` | Enable or disable legacy XML-RPC for a selected group |
| `P` | Start the guided hostname-replacement flow |
| `V` | Show the selected enrollment or token audit trail |
| `X` | Remove, retire, or hide the selected item after confirmation |
| `I` | Enter a hostname and generate copyable install commands |
| `U` | Toggle auto-update in the generated install commands |
| `Q` | Exit |

The key editor accepts terminal paste events. A group with active machine
tokens cannot be removed until those tokens are retired.

The Public Keys view displays the OpenSSH algorithm beside each owner and the
full SHA-256 fingerprint in the details panel. Generated install commands
default to manual updates; `U` toggles the optional daily auto-update flag.

## Server Upgrade

1. Validate the new build in Docker:

```sh
scripts/docker-test.sh
```

2. Back up:

```text
/usr/local/bin/ssh-key-sync-server
/etc/ssh-key-sync/server.toml
/var/lib/ssh-key-sync/state.db
```

3. Install the new binary.
4. Run:

```sh
ssh-key-sync-server check-config \
  --config /etc/ssh-key-sync/server.toml
systemctl restart ssh-key-sync-server.service
curl -fsS http://127.0.0.1:18080/v1/health
```

5. Confirm both `/v1/keys/public` and `/xmlrpc/` still respond.

The packaged server installer performs the download, checksum and configuration
checks, binary replacement, restart, and health check. If health does not
return within 15 seconds it restores the previous binary and restarts the
service:

```sh
curl -fsSL \
  https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install-server.sh |
  sudo sh
```

The database, server configuration, and signing key are never replaced.

For a release-specific install, replace `latest` with the reviewed tag and
verify its recorded version:

```sh
curl -fsSL \
  https://github.com/mjoconr/ssh-key-sync/releases/download/v0.5.1/SHA256SUMS
ssh-key-sync-server --version
```

The updater keeps the previous binary at
`/usr/local/bin/ssh-key-sync-server.before-upgrade`.

### Automatic Updates

Client and server upgrades are pull-based, signature-verified, and opt-in. The
installers can add a daily systemd timer, or a daily root cron entry on older
client systems without systemd:

```sh
# Client
curl -fsSL \
  https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install.sh |
  sudo sh -s -- --enable-auto-update

# Server
curl -fsSL \
  https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install-server.sh |
  sudo sh -s -- --enable-auto-update
```

The server updater validates the candidate configuration, restarts the
service, and restores the previous binary if the health check fails. Updates
do not modify the database, signing key, or either machine's client settings.

The updater verifies `SHA256SUMS.sig` against the local release public key,
then verifies every artifact against the signed checksums. It also rejects an
older version before restarting. See [releases.md](releases.md) for first-install
bootstrap and key rotation.

Automatic operating-system updates remain the operating system's
responsibility. On Debian or Ubuntu, configure `unattended-upgrades` for the
security archive. The optional reboot timer only requests a restart when
`/run/reboot-required` exists:

```sh
curl -fsSL \
  https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install-server.sh |
  sudo sh -s -- --enable-reboot-timer
```

Review the reboot window before enabling it on a server carrying mail, PBX, or
virtualization workloads.

Disable an application update timer with:

```sh
sudo systemctl disable --now ssh-key-sync-client-update.timer
sudo rm /etc/ssh-key-sync/client-auto-update
```

Use `ssh-key-sync-server-update.timer` and
`/etc/ssh-key-sync/auto-update` for a server. The reboot timer is independent
and can be removed with `systemctl disable --now ssh-key-sync-reboot.timer`.

### State Backups

SQLite snapshots can be created while the server is running. The backup uses
SQLite's online backup API, is written to a temporary file, and is atomically
renamed after the copy completes:

```sh
ssh-key-sync-server backup \
  --output-directory /var/lib/ssh-key-sync/backups \
  --retain 14
```

Enable the daily backup timer with the server installer:

```sh
curl -fsSL \
  https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install-server.sh |
  sudo sh -s -- --enable-backup-timer
```

Verify a snapshot before relying on it:

```sh
ssh-key-sync-server backup-verify \
  --input /var/lib/ssh-key-sync/backups/state-TIMESTAMP.db
```

The command runs SQLite's integrity check, verifies the required tables and
opens a temporary copy through the current schema migration.

To restore, keep an SSH recovery session open and stop the server:

```sh
systemctl stop ssh-key-sync-server.service
ssh-key-sync-server backup-restore \
  --input /var/lib/ssh-key-sync/backups/state-TIMESTAMP.db \
  --confirm
systemctl start ssh-key-sync-server.service
systemctl is-active ssh-key-sync-server.service
curl -fsS http://127.0.0.1:18080/v1/health
ssh-key-sync-server enrollment list
ssh-key-sync-server token list
```

Restore refuses to proceed while the service is active. It creates a
`state-before-restore-TIMESTAMP.db` snapshot first, preserves the destination
owner and mode, removes stale WAL/SHM sidecars, atomically replaces the state,
and verifies the restored file. Test the complete procedure against a
non-production copy. The rehearsal should prove:

1. restore refuses to run while `ssh-key-sync-server.service` is active;
2. a verified snapshot restores the older state;
3. the automatic pre-restore snapshot preserves the state that was replaced;
4. state ownership and mode remain correct; and
5. the service restarts and its loopback health check succeeds.

Backups contain token digests and audit data, not plaintext machine tokens, but
should still be protected as private data.

## Token Management

Set an optional token lifetime on a private group in `server.toml`:

```toml
[groups.restricted]
visibility = "private"
token_ttl_days = 90
```

The setting applies to enrollments approved after the configuration reloads.
Existing tokens remain valid until revoked, so enable a TTL before enrolling a
new machine. Values must be between 1 and 3650 days.

List tokens:

```sh
ssh-key-sync-server token list
```

Revoke a token:

```sh
ssh-key-sync-server token revoke TOKEN_ID
```

Revoked tokens can be hidden:

```sh
ssh-key-sync-server token hide TOKEN_ID
```

Revocation prevents that machine from fetching its group again. It does not
remove keys already present locally. To remove access immediately, also remove
the corresponding public-key assignment from the group configuration and
perform a successful sync using another authorized client.

To rotate a token without an access gap, use the Hostname Change replacement
flow below and approve the new enrollment into the same group. Complete a signed
sync and verify a new SSH session before retiring the old enrollment. Expired
tokens can be hidden after their expiry time.

## Hostname Change

Do not edit an active enrollment identity in place. Use replacement enrollment:

1. Change the operating system hostname locally and verify SSH.
2. Run client enrollment with the new name.
3. Approve the new request into the correct group.
4. Complete `enrollment-status --wait` and verify a sync.
5. Retire the previous enrollment and token with `enrollment retire`.
6. Hide the old request and revoked token if they should leave the active TUI.

This preserves an audit trail and keeps the old credential valid until the new
credential has been tested.

The administration view reports an identity conflict when a pending request
matches an active enrollment by name, hostname, or local address. Normal
approval refuses this state; use the TUI replacement flow (`P`) or the explicit
CLI option after verifying that the new request is the intended replacement:

```sh
ssh-key-sync-server enrollment approve REQUEST_ID \
  --group GROUP \
  --allow-identity-conflict
```

This acknowledges the conflict; it does not retire anything. The old enrollment
remains active until it is explicitly retired. This overlap is intentional so a
broken replacement cannot remove the working credential first. Use this option
only after confirming that both identities are legitimately distinct or that
the replacement has been verified.

## Legacy Clients

`POST /xmlrpc/` remains only for machines that cannot run the native HTTPS
client. It selects keys from the source CIDR and cannot distinguish two
machines behind the same NAT address. It is therefore not a replacement for
machine tokens.

Successful requests are recorded in the server journal with the selected group,
observed source address and key count. Caddy access logs use a filter that
removes `Authorization`, `Cookie` and inbound `X-Real-IP` headers. Review legacy
activity with:

```sh
sudo scripts/legacy-activity.sh '30 days ago'
sudo jq -r '
  select(.request.uri | startswith("/xmlrpc"))
  | [.ts, .request.client_ip, .request.method, .request.uri, .status]
  | @tsv
' /var/log/caddy/access.log
```

Choose an observation window before disabling `/xmlrpc/`. A zero successful
request count is necessary but not sufficient: confirm the inventory and allow
for monthly or rarely run cron clients.

For legacy cron-only systems:

1. Confirm the local cron job and its output path.
2. Keep the existing Proxmox or host-managed `authorized_keys` file.
3. Confirm the legacy URL, TLS behavior, and source network.
4. Record the machine in the migration inventory.
5. Replace the job only after the native client can reach the HTTPS endpoint.
6. Remove the legacy cron entry with a saved crontab backup.

Do not place bearer tokens in legacy request bodies, URLs, or plaintext HTTP.
Monitor `/xmlrpc/` request counts until the compatibility endpoint can be
retired.

Before migrating the proxy to the Rust compatibility endpoint:

1. Set `legacy_xmlrpc = true` only on groups used by current legacy clients.
2. Test direct Rust responses with the proxy's expected `X-Real-IP` value.
3. Confirm a missing or malformed header fails closed.
4. Compare the returned key set and XML formatting with the current endpoint.
5. Keep the PHP configuration available for rollback until a complete
   synchronization cycle has passed.

## Failure And Rollback

If key retrieval fails, the client leaves the managed file unchanged.

If `configure-sshd --apply` fails validation or reload, it restores the prior
configuration automatically. Manual backups:

```text
/etc/ssh/sshd_config.before-ssh-key-sync
/etc/ssh/sshd_config.d/20-ssh-key-sync.before-ssh-key-sync
```

If a client must be removed:

1. Disable `ssh-key-sync-client.timer` and the optional update timer, or remove
   the managed synchronization and update entries from root's crontab.
2. Revoke its machine token.
3. Restore the pre-install client or SSH configuration backup.
4. Confirm a new SSH connection.

## Checks

```sh
systemctl status ssh-key-sync-server.service --no-pager
systemctl status ssh-key-sync-client.service --no-pager
systemctl list-timers ssh-key-sync-client.timer --no-pager
journalctl -u ssh-key-sync-client.service --since "20 minutes ago"
curl -fsS https://keys.example.net/v1/health
journalctl -u ssh-key-sync-server-update.service --since "2 days ago"
journalctl -u ssh-key-sync-backup.service --since "2 days ago"
ls -lh /var/lib/ssh-key-sync/backups
```

## Monitoring

At minimum, monitor:

- HTTPS health from outside the server;
- failed `ssh-key-sync-client.service` runs;
- failed server update, backup, and reboot-check units;
- pending enrollment count and requests nearing expiry;
- active-token last-used time and unexpected source addresses;
- TLS certificate and reverse-proxy errors;
- SQLite backup age and count;
- GitHub Dependabot, CodeQL, secret-scanning, and security-advisory alerts.

The service does not currently publish metrics or send alerts itself. Use the
existing systemd journal and HTTP health endpoint with an external monitor.

