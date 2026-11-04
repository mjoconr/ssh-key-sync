# Signed Releases

SSH Key Sync has three separate key roles:

- deployment SSH response-signing key: signs fetched key sets;
- Caddy TLS key: protects HTTPS;
- project release key: signs application release checksums.

None of these keys should be reused.

## Official Trust Anchor

Official releases from `v0.4.10` onward are signed by:

```text
release-keys/release-v1.pub
SHA-256: 5e1476b3a1d8bde5580b2aed543666e337290feaaa55019669218c2ee72c9be5
```

Publish and compare this fingerprint through a second trusted channel. Do not
establish trust only by downloading the key and release from GitHub.

## Set Common Values

For the official project:

```sh
export SSH_KEY_SYNC_REPO="mjoconr/ssh-key-sync"
export SSH_KEY_SYNC_RELEASE_PUBLIC_KEY="release-keys/release-v1.pub"
```

For a fork, set `SSH_KEY_SYNC_REPO` to the fork and use the fork's public key.

Installers also read these optional variables:

| Variable | Purpose |
| --- | --- |
| `SSH_KEY_SYNC_VERSION` | Release tag instead of `latest` |
| `SSH_KEY_SYNC_SERVER_URL` | Client API URL |
| `SSH_KEY_SYNC_SIGNING_KEY_SHA256` | Expected SSH response-signing fingerprint |
| `SSH_KEY_SYNC_APPLY_SSH` | Set to `1` to apply validated `sshd` configuration |
| `SSH_KEY_SYNC_ENABLE_TIMER` | Set to `1` to enable the client sync timer |
| `SSH_KEY_SYNC_ENABLE_AUTO_UPDATE` | Set to `1` to enable app auto-update |
| `SSH_KEY_SYNC_HOSTNAME` | Enrollment name |
| `SSH_KEY_SYNC_RELEASE_PUBLIC_KEY` | Reviewed release public-key file |
| `SSH_KEY_SYNC_RELEASE_VERIFIER` | Trusted verifier executable |
| `SSH_KEY_SYNC_RELEASE_BASE` | Mirror URL for one fully assembled release |
| `SSH_KEY_SYNC_SERVER_CONFIG` | Server TOML path |
| `SSH_KEY_SYNC_HEALTH_URL` | Local health endpoint |
| `SSH_KEY_SYNC_ENABLE_BACKUP_TIMER` | Set to `1` to enable state backups |
| `SSH_KEY_SYNC_ENABLE_REBOOT_TIMER` | Set to `1` for conditional reboots |

## First Installation

There is no installed verifier on the first machine, so verify with a trusted
binary built from the reviewed tag:

```sh
export SSH_KEY_SYNC_VERSION="v0.5.1"
export SSH_KEY_SYNC_RELEASE_VERIFIER="$PWD/target/release/ssh-key-sync-server"
export SSH_KEY_SYNC_SERVER_URL="https://keys.example.net"
export SSH_KEY_SYNC_SIGNING_KEY_SHA256="SERVER_SIGNING_KEY_FINGERPRINT"

git switch --detach "$SSH_KEY_SYNC_VERSION"
cargo build --release -p ssh-key-sync-server

tmp="$(mktemp -d)"
gh release download "$SSH_KEY_SYNC_VERSION" --repo "$SSH_KEY_SYNC_REPO" --dir "$tmp"
cmp "$SSH_KEY_SYNC_RELEASE_PUBLIC_KEY" "$tmp/release.pub"

"$SSH_KEY_SYNC_RELEASE_VERIFIER" release-verify \
  --manifest "$tmp/SHA256SUMS" \
  --signature "$tmp/SHA256SUMS.sig" \
  --public-key "$tmp/release.pub"

sudo -E sh ./install.sh \
  --server "$SSH_KEY_SYNC_SERVER_URL" \
  --signing-key-sha256 "$SSH_KEY_SYNC_SIGNING_KEY_SHA256" \
  --apply-ssh \
  --enable-timer
```

The installer creates `/etc/ssh-key-sync/release.pub` from the supplied reviewed
key, verifies `SHA256SUMS.sig`, verifies every downloaded asset, and rejects a
downgrade.

For a first server installation, create `server.toml` and the service account,
then run:

```sh
export SSH_KEY_SYNC_SERVER_CONFIG="/etc/ssh-key-sync/server.toml"

sudo -E sh ./install-server.sh --no-restart
sudo install -m 0644 deploy/ssh-key-sync-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-key-sync-server.service

export SSH_KEY_SYNC_ENABLE_AUTO_UPDATE="1"
export SSH_KEY_SYNC_ENABLE_BACKUP_TIMER="1"
sudo -E sh ./install-server.sh
```

The second command installs the systemd unit before restart; it is not a
separate software version.

## Later Updates

The installed client or server is now the verifier:

```sh
curl -fsSL \
  "https://github.com/$SSH_KEY_SYNC_REPO/releases/latest/download/install.sh" |
  sudo -E sh
```

For the server:

```sh
curl -fsSL \
  "https://github.com/$SSH_KEY_SYNC_REPO/releases/latest/download/install-server.sh" |
  sudo -E sh
```

`SSH_KEY_SYNC_RELEASE_PUBLIC_KEY` and `SSH_KEY_SYNC_RELEASE_VERIFIER` are not
needed after the first signed installation.

Clear the version pin and bootstrap-only values when following `latest`:

```sh
unset SSH_KEY_SYNC_VERSION
unset SSH_KEY_SYNC_RELEASE_PUBLIC_KEY
unset SSH_KEY_SYNC_RELEASE_VERIFIER
```

## Create A Fork Release Key

Generate the key on a trusted workstation:

```sh
export SSH_KEY_SYNC_RELEASE_KEY="$HOME/.config/ssh-key-sync/release-v1.key"
export SSH_KEY_SYNC_RELEASE_PUBLIC_KEY="release-keys/release-v1.pub"

cargo run -p ssh-key-sync-server -- release-keygen --output .local/release-v1
install -d -m 0700 "$(dirname "$SSH_KEY_SYNC_RELEASE_KEY")"
install -m 0600 .local/release-v1/release.key "$SSH_KEY_SYNC_RELEASE_KEY"
install -m 0644 .local/release-v1/release.pub "$SSH_KEY_SYNC_RELEASE_PUBLIC_KEY"

cargo run -p ssh-key-sync-server -- release-fingerprint \
  --public-key "$SSH_KEY_SYNC_RELEASE_PUBLIC_KEY"
```

Commit only `release-keys/release-v1.pub`. Keep the private key offline with
mode `0600`; never commit it or put it in GitHub Actions.

## Rehearse Key Rotation

Run the isolated rotation and compromise test with a trusted server binary:

```sh
export SSH_KEY_SYNC_SERVER_BIN="/usr/local/bin/ssh-key-sync-server"
sudo -E scripts/rehearse-release-keys.sh
```

The rehearsal creates two temporary keys, verifies that the new trust anchor
rejects signatures from the old key, verifies a new-key signature, and confirms
that a malicious manifest signed by the retired key is rejected. It does not
modify `/etc/ssh-key-sync/release.pub`.

For a real planned rotation, publish and compare the new fingerprint through an
independent channel before replacing the installed trust anchor. For suspected
key compromise, treat every release signed by the old key as untrusted and
distribute the replacement fingerprint through a channel that does not depend
on the compromised release key.

## Publish A Signed Release

```sh
export SSH_KEY_SYNC_VERSION="v0.5.0"
export SSH_KEY_SYNC_REPO="OWNER/REPOSITORY"
export SSH_KEY_SYNC_RELEASE_KEY="$HOME/.config/ssh-key-sync/release-v1.key"
export SSH_KEY_SYNC_RELEASE_PUBLIC_KEY="release-keys/release-v1.pub"

git tag -a "$SSH_KEY_SYNC_VERSION" -m "$SSH_KEY_SYNC_VERSION"
git push origin "$SSH_KEY_SYNC_VERSION"
scripts/sign-release.sh "$SSH_KEY_SYNC_VERSION"
```

The tag workflow builds i686, x86-64, and ARM64 and creates a draft release.
`sign-release.sh` verifies every draft asset, signs `SHA256SUMS` with the
offline key, checks its own signature, uploads `SHA256SUMS.sig`, and publishes
the release as latest.

## Key Rotation

1. Generate a new pair such as `.local/release-v2`.
2. Publish its fingerprint through a trusted channel.
3. Sign one overlap release with both old and new keys.
4. Install the new public key as `/etc/ssh-key-sync/release.pub`.
5. Confirm one signed update, then retire the old key.

If the private key is lost, existing installations can still run but cannot
accept new updates until the new public key is installed out of band.

If the private key is compromised:

```sh
sudo systemctl disable --now ssh-key-sync-client-update.timer
sudo systemctl disable --now ssh-key-sync-server-update.timer
```

Then rebuild and re-sign from a reviewed clean commit, distribute the new
fingerprint independently, and audit installed versions.
