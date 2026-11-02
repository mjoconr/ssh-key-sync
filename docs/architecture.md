# Architecture

SSH Key Sync is a pull-only key distribution service. Clients request a key set
over HTTPS and install it locally.

## Components

- `ssh-key-sync-server` selects and signs key sets.
- `ssh-key-sync-client` verifies and installs key sets.
- `ssh-key-sync-core` contains shared configuration, CIDR, key, and signing code.
- The server includes a local ratatui administration interface and CLI.
- Enrollment and machine-token state is stored in SQLite.

The public server process listens on loopback. A TLS reverse proxy exposes only
the required HTTP paths. The server never connects to clients and never
executes remote configuration.

## Key Selection

Groups contain key owners, keys, and optional CIDRs. A key is selected when its
owner belongs to the requested group.

The native API supports:

- An explicit public default group without authentication.
- Non-public groups authenticated by a group or machine token.

The XML-RPC compatibility endpoint selects a group from the server-observed
source address, using the longest matching CIDR. If no CIDR matches, it uses the
default group.

Keys are parsed with the OpenSSH key format and deduplicated by fingerprint.
The administration interface displays the canonical OpenSSH algorithm, such as
`ssh-ed25519`, `ssh-rsa`, or `ecdsa-sha2-nistp256`, separately from the
SHA-256 fingerprint.

## Native API

```text
GET /v1/health
GET /v1/keys/public
GET /v1/keys                 Authorization: Bearer <token>
GET /v1/signing-key
POST /v1/enrollments
GET /v1/enrollments/{id}     Authorization: Bearer <request-secret>
```

Key requests require `X-Request-Nonce`. Enrollment status requests require the
one-time request secret. The response contains signed payload bytes and a
detached Ed25519 signature. Clients verify:

- Envelope and payload schema versions.
- Response signature.
- Request nonce.
- Issue and expiry times.
- SSH key syntax and fingerprints.

The public endpoint is unauthenticated and returns only the explicitly
configured default public group. A private request never falls back to that
group after token failure.

## Compatibility API

```text
POST /xmlrpc/
method: ssh.getKeys
```

The response is a newline-terminated key string inside XML-RPC. Existing cron
clients can continue using this endpoint. The TLS proxy must supply
`X-Real-IP`, and the server trusts that header only when the direct peer is
loopback.

## Enrollment

Clients generate a request secret and a private machine token. They submit only
their SHA-256 digests, hostname, name, and local interface addresses. An
administrator reviews pending requests through the server command line and
approves a request into an existing group. Approval activates the submitted
machine-token digest. The client polls with its request secret and stores its
local token with mode `0600`.

Enrollment requests expire after 15 minutes. The server limits each source
address to three requests per ten minutes and caps the pending queue at 100.
Each pending request receives a short code for out-of-band comparison.

Approved machine tokens can be revoked or hidden. Retiring an enrollment
revokes its token and hides the old record in one transaction. Audit records
remain in SQLite after records are hidden.

Token transport is pull-only: the plaintext machine token exists on the client
and is sent only as a bearer token to the native HTTPS endpoint. The server
stores only its SHA-256 digest. It records last-used time, source address, and
client version for active machine tokens.

### State Schema

The default state database is `/var/lib/ssh-key-sync/state.db`. It contains:

- enrollment requests, their status, group, expiry, and decision time;
- machine-token digests and lifecycle metadata;
- an append-oriented administrative audit table.

SQLite online backup creates a consistent snapshot without stopping the
server. The backup timer retains 14 timestamped snapshots by default.

## Client Installation

The client writes a dedicated file:

```text
/etc/ssh/authorized_keys.d/root
```

Existing authorization files remain untouched and are added alongside the
managed file using `AuthorizedKeysFile`.

Installation uses a lock, restrictive permissions, a temporary file in the same
directory, `fsync`, and atomic rename. Empty or invalid responses do not change
the active file.

`configure-sshd` validates changes with `sshd -t`. It prefers a drop-in file and
falls back to a marked block in `sshd_config` when includes are unavailable.
Failed validation restores the prior configuration.

The client requests keys with bounded connect and total timeouts, verifies the
response before opening the destination file for replacement, and refuses to
replace a symlink. Existing authorization files remain effective alongside the
managed file.

Cron-only hosts use the same binary and atomic installation path. The installer
adds a managed root crontab entry rather than requiring systemd.

## Administration

`ssh-key-sync-server tui` provides live views of enrollments, machine tokens,
groups, and public keys. It supports:

- approval, denial, retirement, hide, and audit actions;
- validated key, CIDR, and group-assignment edits with automatic reload;
- generated install commands with optional auto-update;
- a hostname-replacement workflow that keeps the old credential until the new
  credential has been verified.

Configuration edits preserve the existing owner and group, validate the full
configuration, create a timestamped backup, write to a temporary file in the
same directory, `fsync`, and atomically replace the active file.

## Deployment

The server runs as the unprivileged `ssh-key-sync` user with systemd filesystem,
namespace, memory-execution, and address-family restrictions. The TLS proxy
listens publicly and proxies `/v1/` and `/xmlrpc/` to loopback port `18080`.

Client synchronization runs from systemd every two hours with a randomized
delay, or from the equivalent managed cron entry on older systems. Optional
daily timers handle client/server upgrades and state backups. An optional
weekly reboot timer runs only when `/run/reboot-required` exists.

Release automation builds x86-64 and ARM64 static binaries on native GitHub
runners and publishes checksum-listed archives and units. The `check` job is
branch-protected; CodeQL currently runs on pull requests and the main branch.
Auto-update downloads validate the archive or unit against `SHA256SUMS` before
replacement.

