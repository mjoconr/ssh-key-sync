# SSH Key Sync

SSH Key Sync distributes approved OpenSSH public keys to independently managed
machines. Machines pull signed key sets; the service does not push commands or
configuration.

## Features

- Public groups and token-protected groups.
- CIDR-based group selection for the compatibility API.
- Ed25519-signed native responses bound to a client nonce.
- Static Linux client supporting old and current OpenSSH installations.
- Atomic `authorized_keys` replacement with empty-response protection.
- Separate managed and existing authorization files.
- Safe `sshd` changes with validation, reload, and rollback.
- systemd timer deployment.

## Status

Version `0.2.x` provides key retrieval, installation, and machine enrollment.
Signed client self-updates and a web interface are not implemented yet.

## Install

```sh
curl -fsSL \
  https://github.com/mjoconr/ssh-key-sync/releases/latest/download/install.sh |
  sudo sh
```

The installer verifies `SHA256SUMS` and replaces only the client binary.
Configuration under `/etc/ssh-key-sync` is preserved.

For automated server configuration, pass the server URL and its signing-key
SHA-256 fingerprint:

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

## Server

```sh
ssh-key-sync-server generate-keys --output /etc/ssh-key-sync
ssh-key-sync-server check-config --config /etc/ssh-key-sync/server.toml
ssh-key-sync-server serve --config /etc/ssh-key-sync/server.toml
```

See [server.toml](examples/server.toml) and
[architecture.md](docs/architecture.md).

## Client

```sh
ssh-key-sync-client --config /etc/ssh-key-sync/client.toml sync --dry-run
ssh-key-sync-client --config /etc/ssh-key-sync/client.toml sync
```

Preview and apply `sshd` changes:

```sh
ssh-key-sync-client --config /etc/ssh-key-sync/client.toml configure-sshd
ssh-key-sync-client --config /etc/ssh-key-sync/client.toml configure-sshd --apply
```

## Legacy XML-RPC

`POST /xmlrpc/` implements `ssh.getKeys` for existing clients. It uses the
server-observed client address and configured CIDR rules.

## Development

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
scripts/docker-test.sh
```

See [development.md](docs/development.md) and [security.md](docs/security.md).
Deployment procedures are in [operations.md](docs/operations.md).

## License

MIT
