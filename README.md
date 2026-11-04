# SSH Key Sync

SSH Key Sync distributes approved OpenSSH public keys to independently managed
machines. Machines pull signed key sets; the service does not push commands or
configuration.

## Features

- Public groups and token-protected groups.
- CIDR-based group selection for the compatibility API.
- Ed25519-signed native responses bound to a client nonce.
- Static Linux i686, x86-64, and ARM64 client builds supporting old and
  current OpenSSH installations.
- Atomic `authorized_keys` replacement with empty-response protection.
- Separate managed and existing authorization files.
- Safe `sshd` changes with validation, reload, and rollback.
- systemd timers and cron-only client support.
- Optional signature-verified client and server auto-update timers.
- Online SQLite state backups with retention.
- Enrollment approval, token check-in status, audit history, and a terminal admin UI.
- i686, x86-64, and ARM64 release builds for client and server.
- Loopback-only cleartext binding, bounded requests, strict enrollment fields,
  and explicit opt-in for unauthenticated XML-RPC groups.

## Status

Version `0.6.19` is the current release. It provides signed key responses,
enrollment and machine-token workflows, validated key/group/CIDR edits, a
terminal administration interface, systemd and cron deployment, checksum-verified
and cryptographically signed optional auto-updates, SQLite backups, and
i686/x86-64/ARM64 static builds.

There is no web interface. See [releases.md](docs/releases.md) for release trust,
first-install bootstrap, fork signing keys, and key rotation.

## Install

```sh
curl -fsSL \
  https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install.sh |
  sudo sh
```

First installation requires a manually verified release bootstrap because no
installed binary exists to verify the first signature. Subsequent installers
verify a signed `SHA256SUMS` against
`/etc/ssh-key-sync/release.pub`; routine updates preserve configuration under
`/etc/ssh-key-sync`.

Static builds are published for `i686`, `x86_64`, and `aarch64`, including
Raspberry Pi systems.

Once the signed installer trust anchor is installed, configure a client with:

```sh
curl -fsSL https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install.sh |
  sudo sh -s -- \
    --server https://admin.example.net \
    --signing-key-sha256 <sha256> \
    --apply-ssh \
    --enable-timer
```

`--apply-ssh` uses the validated configuration and rollback behavior described
above. Add `--enroll HOSTNAME` instead of `--enable-timer` for a private group.
The enrollment command waits for approval, then installs the token, verifies a
real synchronized key response, and enables the schedule automatically. Use
`--no-wait` for a staged approval. Add `--enable-auto-update` to enable the
daily client upgrade timer.

### Enable Client Auto-Update Later

Re-run the client installer with `--enable-auto-update`. This preserves the
existing server URL, token, signing keys, and managed `authorized_keys` path:

```sh
curl -fsSL \
  https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install.sh |
  sudo sh -s -- --enable-auto-update
```

Do not use `install-server.sh` or a separate `install-client.sh` script for
this; the client auto-update timer is installed by `install.sh`.

Verify it:

```sh
systemctl is-enabled ssh-key-sync-client-update.timer
systemctl is-active ssh-key-sync-client-update.timer
systemctl list-timers ssh-key-sync-client-update.timer --no-pager
```

Once enabled, later runs of `install.sh` preserve auto-update even when the
flag is omitted. Disable it with:

```sh
sudo systemctl disable --now ssh-key-sync-client-update.timer
sudo rm /etc/ssh-key-sync/client-auto-update
```

See [releases.md](docs/releases.md) before the first installation or before
upgrading a pre-`v0.4.10` machine.

The installer uses the systemd timer when systemd is available. Otherwise it
uses the client's `install-cron` command after enrollment approval.

## Server

```sh
ssh-key-sync-server generate-keys --output /etc/ssh-key-sync
ssh-key-sync-server check-config --config /etc/ssh-key-sync/server.toml
ssh-key-sync-server serve --config /etc/ssh-key-sync/server.toml
```

Administrative terminal UI:

```sh
ssh-key-sync-server tui --config /etc/ssh-key-sync/server.toml
```

Install or upgrade a server binary from a published release with:

```sh
curl -fsSL \
  https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install-server.sh |
  sudo sh -s -- --enable-auto-update
```

Review [operations.md](docs/operations.md) before enabling the server update,
backup, or conditional reboot timers.

See [server.toml](examples/server.toml), [architecture.md](docs/architecture.md),
[Caddyfile](examples/Caddyfile), and [roadmap.md](docs/roadmap.md).

Machine tokens record their last successful key request. The TUI and
`ssh-key-sync-server token list` distinguish `connected`, `new`, `stale`,
`never-connected`, `expired`, and `revoked` machines. Set
`stale_after_hours` in `server.toml` or use the default of 48 hours.

## Client

```sh
ssh-key-sync-client --config /etc/ssh-key-sync/client.toml sync --dry-run
ssh-key-sync-client --config /etc/ssh-key-sync/client.toml sync
```

Before fetching keys, `sync` verifies that the configured managed file is
present in the effective `sshd` `AuthorizedKeysFile` list. If it is missing,
the command fails without changing keys and recommends `configure-sshd --apply`.
Set `require_effective_sshd = false` only for non-sshd consumers.

Preview and apply `sshd` changes:

```sh
ssh-key-sync-client --config /etc/ssh-key-sync/client.toml configure-sshd
ssh-key-sync-client --config /etc/ssh-key-sync/client.toml configure-sshd --apply
```

After native access has been verified, legacy `authorized_keys` files can be
quarantined without deleting their contents:

```sh
ssh-key-sync-client retire-legacy-authorized-keys
ssh-key-sync-client retire-legacy-authorized-keys --apply
```

The command verifies that the managed file is non-empty, valid, and effective,
then renames `.ssh/authorized_keys` and `.ssh/authorized_keys2` to timestamped
backup names that sshd does not read. Keep the current SSH session open while
verifying a new managed-key login. Do not run it on Proxmox hosts unless their
host-managed keys have been preserved elsewhere.

## Legacy XML-RPC

`POST /xmlrpc/` implements `ssh.getKeys` for existing clients. It uses the
server-observed client address and configured CIDR rules. It is a compatibility
interface for systems that cannot use the native HTTPS client; monitor its use
so it can be retired after those systems migrate.

## Development

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
scripts/docker-test.sh
scripts/clean-local-cache.sh
```

See [development.md](docs/development.md) and [security.md](docs/security.md).
Deployment procedures are in [operations.md](docs/operations.md).

## License

MIT
