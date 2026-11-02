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

`group remove` and `key remove` reject unsafe changes through normal
configuration validation. A timestamped backup is created before each edit.

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
  https://github.com/mjoconr/ssh-key-sync/releases/download/v0.4.10/SHA256SUMS
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

Before restoring a snapshot, stop the server and keep an SSH recovery session
open:

```sh
systemctl stop ssh-key-sync-server.service
timestamp="$(date +%Y%m%dT%H%M%S)"
mv /var/lib/ssh-key-sync/state.db \
  "/var/lib/ssh-key-sync/state.db.before-restore-$timestamp"
for suffix in -wal -shm; do
  if [ -e "/var/lib/ssh-key-sync/state.db$suffix" ]; then
    mv "/var/lib/ssh-key-sync/state.db$suffix" \
      "/var/lib/ssh-key-sync/state.db$suffix.before-restore-$timestamp"
  fi
done
install -o ssh-key-sync -g ssh-key-sync -m 0600 \
  /var/lib/ssh-key-sync/backups/state-TIMESTAMP.db \
  /var/lib/ssh-key-sync/state.db
systemctl start ssh-key-sync-server.service
ssh-key-sync-server enrollment list
ssh-key-sync-server token list
curl -fsS http://127.0.0.1:18080/v1/health
```

Moving `state.db-wal` and `state.db-shm` aside prevents stale transactions from
being replayed against the restored database. Do not restore while the server
is running. Backups contain token digests and audit data, not plaintext machine
tokens, but should still be protected as private data.

## Token Management

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

## Legacy Clients

`POST /xmlrpc/` remains only for machines that cannot run the native HTTPS
client. It selects keys from the source CIDR and cannot distinguish two
machines behind the same NAT address. It is therefore not a replacement for
machine tokens.

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

