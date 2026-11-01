# Architecture

Status: design baseline; implementation details may change through reviewed
design updates.

## Goals

SSH Key Sync distributes centrally managed OpenSSH public keys to root accounts
on Unix-like machines. It replaces the legacy PHP implementation while
preserving enough of the XML-RPC interface for existing cron jobs to migrate
safely.

- Select keys by an authenticated machine identity or by network source address
  for legacy clients.
- Support legacy cron and modern systemd schedules.
- Preserve the current two-file SSH authorization model on Proxmox machines.
- Make installs, upgrades, and rollbacks atomic and scriptable.
- Allow independently managed machines to pull from one shared authority.
- Remain publishable as open source without containing deployment secrets.

## Non-goals

- General identity, account, or authorization management.
- Granting different Unix accounts to different people.
- Replacing Proxmox cluster key management.
- Central configuration management, remote command execution, or push deploys.
- Automatic discovery or enrollment of machines.
- Requiring a central agent to manage each host.
- A graphical administration application in the first implementation.

## Components

The repository builds three Rust crates:

- `core` owns validated domain types, configuration parsing, CIDR selection,
  key parsing, response models, and signing verification.
- `server` exposes the native API, legacy XML-RPC compatibility endpoint, and
  command-line configuration tools.
- `client` retrieves, verifies, and atomically installs keys. It also configures
  scheduling and SSH integration.

The client and server are separate binaries and release artifacts. They share a
repository so protocol compatibility and release versions cannot drift.

## Server data flow

1. Caddy terminates TLS and forwards an allowed request to a loopback-only
   server listener.
2. Native clients authenticate with a manually provisioned per-machine token.
   The token identifies a machine record and its assigned key groups.
3. Legacy clients are matched to a group using the most-specific source CIDR
   rule. The server obtains that address from a trusted proxy-controlled field.
4. Keys assigned to that group are normalized and deduplicated by SSH
   fingerprint.
5. The response is generated with a stable ordering and, on the native API,
   signed with an Ed25519 release key.
6. The legacy endpoint renders the compatible XML-RPC string and trailing
   newline.

The configuration file is the source of truth. It contains key groups,
CIDR-to-group rules, machine records, and token hashes. There is no
administration database in the initial design. Changes are validated before an
atomic replace and are reloaded only when valid.

Machine records are created one-to-one with a CLI command. The generated token
is displayed once and stored with mode `0600` on that machine. The server stores
only a digest of the token. Tokens can be rotated or revoked without changing
public keys or affecting other machines.

The client token belongs in root-only client configuration and is sent only in
the HTTP `Authorization` header. It is never accepted in a URL or query string.

Machine authentication is not intended to make public keys confidential. A
machine token selects and audits a key group. If the operator intentionally
exposes one signed default group to every client, native clients may use that
group without a token. Anonymous access must be explicit configuration; it must
not be an accidental fallback when token authentication or a CIDR match fails.

## Selection rules

- IPv4 and IPv6 CIDRs are supported through a dedicated CIDR type.
- A matching rule with the longest prefix wins.
- Native machine records select groups directly and therefore work behind NAT.
- A CIDR constraint can optionally be added to a machine record as an extra
  restriction, but is not required for authenticated native clients.
- A deliberately public default group can be used when every client should
  receive the same public key set, including clients behind changing NAT.
- An explicit default group is required in the new configuration format.
- The legacy importer records any implicit fallback rather than silently
  changing behavior.
- Equal-selector conflicts are configuration errors rather than relying on
  ordering.
- Public keys are deduplicated by their cryptographic fingerprint, not comment.
- An empty result is a valid server result only when the selected group is
  explicitly configured to permit it.

Public keys can normally be disclosed, but their contents are not unimportant:
an unauthenticated response becomes an authorization vulnerability if an
attacker can substitute another key. TLS or a signed response protects integrity
regardless of whether the key material itself is confidential.

Documentation examples use reserved ranges such as `192.0.2.0/24` and
`2001:db8::/32`.

## Interfaces

The legacy interface remains `POST /xmlrpc/` with method `ssh.getKeys`. It is a
compatibility surface and should eventually be deprecated after all known cron
clients are upgraded.

The native endpoint returns a versioned, signed key-set document over HTTPS.
The client authenticates with `Authorization: Bearer` using its per-machine
token.
The client verifies these fields before writing:

- Protocol schema version.
- Request nonce.
- Issued and expiry times.
- Selected group identifier.
- Key records and their fingerprints.
- Ed25519 signature generated by a key not present on the production server.

Signed HTTP is an optional fallback only for firewalled legacy networks. TLS and
VPN transports are preferred. An unsigned HTTP response must never update
`authorized_keys`. A reusable bearer token must not be sent over HTTP; that
fallback requires an SSH/VPN tunnel or a reviewed proof-of-possession scheme.

Legacy XML-RPC requests have no machine token. They continue to use the observed
source address. A NAT that changes which public address the server sees can
therefore select the wrong legacy group. Such machines must be upgraded to the
native client or have their deployed NAT address represented explicitly in the
legacy configuration.

## Client behavior

The default target is the root account. A sync operation:

1. Acquires an exclusive process and file lock.
2. Downloads a bounded response with explicit connect and total timeouts.
3. Verifies transport and response signature.
4. Verifies freshness, protocol version, and an acceptable installed version.
5. Parses every key and rejects malformed or unsupported records.
6. Refuses an empty result unless the server and local policy both allow it.
7. Writes a temporary file in the target directory with mode `0600`.
8. Flushes the file and directory, then atomically renames it.
9. Verifies the resulting content and fingerprints.

The previous known-good file is retained for rollback.

Machines are deliberately managed one-to-one. Installing the client and
enabling its schedule are explicit local operations. The server never initiates
a connection to a client and cannot remotely run upgrade or configuration
commands.

### SSH files and Proxmox

The client owns `/etc/ssh/authorized_keys.d/%u`. Proxmox retains ownership of
`/root/.ssh/authorized_keys`. Effective `AuthorizedKeysFile` configuration must
contain both files.

The installer must not overwrite `sshd_config` blindly. It will inspect the
effective configuration, create a narrowly scoped drop-in, preserve the
existing values, run `sshd -t`, reload only after validation, and restore the
previous configuration if validation fails.

### Scheduling

The same binary supports:

- A systemd oneshot service and persistent timer.
- Root cron using a stable compatibility command path.
- Manual invocation for dry runs and recovery.

Key-file changes do not require an SSH daemon reload. Only `sshd_config`
installation or mutation does.

## Distribution and updates

Immutable release tags such as `v0.1.0` identify source releases. Binaries for
each supported target architecture are release assets; machine roles and
operating-system differences are not tags.

The server hosts a signed update manifest containing version, protocol
compatibility, artifact hashes, and architecture-specific download paths.
Clients use a stable or canary channel and never downgrade automatically.
Upgrade checks may be run manually or by the client's local systemd timer. This
is a client pull operation, not a deployment pushed by the server.

Private GitHub release assets are not the client download endpoint because that
would require placing GitHub credentials on every managed machine. The deploy
pipeline mirrors verified artifacts to the service's download endpoint.

## Deployment model

Caddy is the preferred public reverse proxy because it performs TLS certificate
issuance and renewal without requiring Rust application code to manage
certificates. The server binds to loopback and runs as a dedicated unprivileged
user.

Package upgrades should be delivered through the host package manager where
possible. Automatic reboot requires separate maintenance-window and
reboot-required checks; it must not reboot on every update run.

