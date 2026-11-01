# Architecture

SSH Key Sync is a pull-only key distribution service. Clients request a key set
over HTTPS and install it locally.

## Components

- `ssh-key-sync-server` selects and signs key sets.
- `ssh-key-sync-client` verifies and installs key sets.
- `ssh-key-sync-core` contains shared configuration, CIDR, key, and signing code.

The public server process listens on loopback. A TLS reverse proxy exposes only
the required HTTP paths.

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

## Native API

```text
GET /v1/health
GET /v1/keys/public
GET /v1/keys                 Authorization: Bearer <token>
GET /v1/signing-key
POST /v1/enrollments
GET /v1/enrollments/{id}
```

Key requests require `X-Request-Nonce`. The response contains signed payload
bytes and a detached Ed25519 signature. Clients verify:

- Envelope and payload schema versions.
- Response signature.
- Request nonce.
- Issue and expiry times.
- SSH key syntax and fingerprints.

## Compatibility API

```text
POST /xmlrpc/
method: ssh.getKeys
```

The response is a newline-terminated key string inside XML-RPC. Existing cron
clients can continue using this endpoint.

## Enrollment

Clients generate a request secret and a private machine token. They submit only
their SHA-256 digests, hostname, name, and local interface addresses. An
administrator reviews pending requests through the server command line and
approves a request into an existing group. Approval activates the submitted
machine-token digest. The client polls with its request secret and stores its
local token with mode `0600`.

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

## Deployment

The server and client use systemd units. Client timers run on an even-hour
calendar schedule with a randomized delay. The server runs as a dedicated
unprivileged user and does not initiate connections to clients.

