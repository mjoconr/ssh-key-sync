# Detailed Design

Status: implementation baseline. Protocol or state-machine changes require an
update here before code changes.

## Crate boundaries

Dependency direction is:

```text
ssh-key-sync-core
       ^       ^
       |       |
   server    client
```

`core` has no knowledge of HTTP frameworks, subprocesses, schedulers, or local
system services. It owns validated domain types and deterministic behavior that
must remain identical between client and server.

`server` owns HTTP parsing, authentication, state, logging, and configuration
reload. `client` owns transport, enrollment, filesystem replacement, `sshd`
inspection, and scheduling helpers.

## Core types

Raw strings are converted into typed values at deserialization boundaries:

- `GroupId`: validated, non-empty group identifier.
- `KeyLine`: a parsed OpenSSH public key plus its original canonical text.
- `KeyFingerprint`: `SHA256:` OpenSSH fingerprint.
- `TokenId` and `TokenDigest`: public identifier and one-way token digest.
- `RequestNonce`: exactly 32 random bytes, encoded base64url without padding.
- `RequestId`: random opaque enrollment identifier.
- `ProtocolVersion`: explicitly supported protocol schema number.
- `UnixTimestamp`: checked conversion to and from protocol integers.

Errors use `thiserror` enums in libraries. Binary boundaries may wrap library
errors with `anyhow` context. Errors crossing HTTP are mapped to a stable public
error code; internal paths and dependency errors are logged but not returned.

## Server configuration

The deployed configuration is TOML and is not committed to this repository.
The initial shape is:

```toml
schema_version = 1
listen = "127.0.0.1:8080"
signing_key_file = "/etc/ssh-key-sync/signing.key"
default_group = "public"

[groups.public]
visibility = "public"

[groups.displays]
visibility = "private"
cidrs = ["172.16.0.0/12"]

[keys.mike]
groups = ["public", "displays"]
keys = [
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGeneratedFixtureOnly",
]

[[tokens]]
id = "display-machines"
group = "displays"
digest = "sha256:lowercase-hex-digest"
```

The example values are placeholders and are not valid deployment credentials.
An importer validates and converts the legacy `<servers>` and `<pubkeys>`
configuration rather than retaining its parser as the primary format.

Configuration validation rejects unknown fields, zero or duplicate group IDs,
invalid CIDRs, malformed keys, duplicate key fingerprints, missing group
references, unsupported key types, empty private groups, ambiguous default
groups, and malformed token digests.

## Native protocol

The native protocol is JSON over HTTPS with a path-versioned prefix.

```text
GET /v1/health
GET /v1/keys/public
GET /v1/keys
```

`/v1/keys/public` returns the explicitly configured public default group.
`/v1/keys` requires:

```text
Authorization: Bearer <machine-or-group-token>
```

Both endpoints require:

```text
X-Request-Nonce: <base64url 32-byte nonce>
```

The response envelope contains the exact signed bytes, avoiding JSON
canonicalization differences between implementations:

```json
{
  "schema": 1,
  "payload": "<base64url JSON bytes>",
  "signature": "<base64url Ed25519 signature>"
}
```

Decoded payload:

```json
{
  "schema": 1,
  "nonce": "<copied request nonce>",
  "issued_at": 1760000000,
  "expires_at": 1760000300,
  "group": "public",
  "keys": [
    {
      "fingerprint": "SHA256:generated-fixture",
      "authorized_keys": "ssh-ed25519 AAAA... test@example"
    }
  ]
}
```

The Ed25519 signature covers the decoded payload bytes exactly. Clients verify
the signature, envelope schema, payload schema, nonce equality, timestamps,
group policy, key syntax, and fingerprint before installation.

Server errors use JSON with a stable code and request ID. The legacy XML-RPC
endpoint uses XML-RPC faults and preserves its historical response shape.

## Authentication decisions

- Public default retrieval requires no token.
- Restricted retrieval requires a group or machine token.
- Tokens are random at least 256 bits, shown once, and stored by the server only
  as SHA-256 digests. SHA-256 is sufficient because tokens have full entropy.
- Digest comparison is constant-time.
- Bearer tokens are accepted only over HTTPS.
- Legacy CIDR selection is confined to `/xmlrpc/`.
- A failed restricted request never falls back to the public group.

## Concurrency and reload

- HTTP work is asynchronous; blocking filesystem, process, and SQLite work runs
  in `spawn_blocking` or a dedicated synchronous path.
- The active configuration is an immutable snapshot behind an atomic pointer.
- Reloads parse and validate a complete new snapshot before swapping it.
- Failed reloads retain the previous snapshot and emit an error log.
- Writes from the admin CLI are serialized and never hold a lock across an
  `await`.
- Request handlers have bounded concurrency, body size, and elapsed time.

## Client state and file safety

The client keeps configuration under `/etc/ssh-key-sync/` and locks every sync
operation. Managed authorization data is written to:

```text
/etc/ssh/authorized_keys.d/root
```

The write algorithm is:

1. Reject a symlink at the destination or an unexpected destination directory.
2. Acquire an exclusive lock in the destination directory.
3. Create a new `0600` temporary file in that same directory.
4. Write the complete validated key set and call `flush` and `sync_all`.
5. Rename atomically over the managed destination.
6. Sync the directory and re-read the installed file to verify fingerprints.
7. Retain the previous known-good content for explicit rollback.

No failure before the final rename changes the active managed file.

## SSH integration state machine

`inspect-sshd` reports the effective `AuthorizedKeysFile` value from `sshd -T`.
It performs no writes.

`configure-sshd` follows this state machine:

1. Require root and an open recovery session warning.
2. Read the effective configuration.
3. Confirm the managed file is present, or create a scoped drop-in containing
   the existing effective paths plus the managed path.
4. Validate the complete configuration with `sshd -t`.
5. Reload the detected SSH service.
6. Re-run `sshd -T` and confirm both existing and managed paths are effective.
7. Restore the prior drop-in and reload on any failure.

If the platform does not include the drop-in path, the client reports the
required manual change rather than rewriting the primary `sshd_config`.

## Scheduling and upgrade state

The client is a short-lived process. Systemd and cron invoke the same `sync`
subcommand; no long-running client daemon exists.

Upgrade checks are a separate client pull operation. The server cannot trigger
an update. A signed manifest pins the version, protocol range, architecture,
size, and SHA-256 digest. Installation uses an atomic release-directory switch
and keeps one previous binary.

## Enrollment state

Enrollment requests, approved token records, and audit entries are stored in an
embedded SQLite database with restrictive permissions. Request and token
plaintext values are never stored. State schema migrations are forward-only and
run before the server starts when no live request holds the database lock.

The first implementation milestone does not expose enrollment until its request
expiry, approval, token delivery, and audit tests pass.

## Design review checklist

Before adding a feature:

- Define its trust boundary and failure behavior.
- Define whether an empty response is valid.
- Define timeout, size, and concurrency bounds.
- Document what persists and for how long.
- Define logging redaction and audit fields.
- Add a regression test for every new security invariant.
- Update this document before changing a protocol or on-disk state.

