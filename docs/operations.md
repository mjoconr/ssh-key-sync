# Operations Runbook

## Terms

- Server: the host running `ssh-key-sync-server`.
- Client: a managed machine running `ssh-key-sync-client`.
- Public group: fetched anonymously from `/v1/keys/public`.
- Private group: fetched with a machine token from `/v1/keys`.
- Signing fingerprint: SHA-256 digest of the server's raw 32-byte public key.

## Prerequisites

On the server:

- HTTPS reverse proxy to `127.0.0.1:18080`.
- `/v1/` and `/xmlrpc/` routed to the Rust server.
- `X-Real-IP` set by the trusted proxy.
- Server configuration and signing key installed under `/etc/ssh-key-sync`.
- `ssh-key-sync-server.service` enabled.

On a client:

- Root access and an open recovery session.
- Existing `authorized_keys` backed up.
- Outbound HTTPS access to the server.
- `sha256sum`, `curl`, and systemd.

## Public-Group Installation

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

1. Downloads the latest static client and checksums.
2. Verifies the archive.
3. Installs or upgrades `/usr/local/bin/ssh-key-sync-client`.
4. Downloads `/v1/signing-key` and verifies its fingerprint.
5. Writes `/etc/ssh-key-sync/client.toml`.
6. Fetches and verifies the public key set without changing files.
7. Applies and validates the two-file `sshd` configuration.
8. Installs and enables the systemd timer.

Verify:

```sh
ssh-key-sync-client sync --dry-run
ssh-key-sync-client inspect-sshd
systemctl status ssh-key-sync-client.service --no-pager
systemctl list-timers ssh-key-sync-client.timer --no-pager
```

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
| `Q` | Exit |

The key editor accepts terminal paste events. A group with active machine
tokens cannot be removed until those tokens are retired.

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

### Automatic Updates

Client and server upgrades are pull-based, checksum-verified, and opt-in. The
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
open. Replace only `/var/lib/ssh-key-sync/state.db` with the selected snapshot,
preserve ownership by `ssh-key-sync`, start the service, and verify health plus
an enrollment or token listing. Backups contain token digests and audit data,
not plaintext machine tokens, but should still be protected as private data.

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

## Failure And Rollback

If key retrieval fails, the client leaves the managed file unchanged.

If `configure-sshd --apply` fails validation or reload, it restores the prior
configuration automatically. Manual backups:

```text
/etc/ssh/sshd_config.before-ssh-key-sync
/etc/ssh/sshd_config.d/20-ssh-key-sync.before-ssh-key-sync
```

If a client must be removed:

1. Disable `ssh-key-sync-client.timer`.
2. Revoke its machine token.
3. Restore the pre-install client or SSH configuration backup.
4. Confirm a new SSH connection.

## Checks

```sh
systemctl status ssh-key-sync-server.service --no-pager
systemctl status ssh-key-sync-client.service --no-pager
systemctl list-timers ssh-key-sync-client.timer --no-pager
journalctl -u ssh-key-sync-client.service --since "20 minutes ago"
```

