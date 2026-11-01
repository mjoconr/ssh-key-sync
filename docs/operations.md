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

