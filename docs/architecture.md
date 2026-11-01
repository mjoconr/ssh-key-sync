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

The key-selection configuration file is the source of truth for groups, CIDR
rules, keys, and machine assignments. Changes are validated before an atomic
replace and are reloaded only when valid. Pending enrollment requests, token
records, and the audit trail use an embedded local SQLite state database. This
state is not a central configuration service and is never pushed to clients.

Tokens may be scoped to a group or to one machine:

- A group token is shared by all machines that should receive the same key set.
  It is the simplest option for independently managed systems with no need for
  per-machine audit or revocation.
- A machine token identifies one host and is useful when machines need different
  groups or when individual revocation and audit are required.

The generated token is displayed once and stored with mode `0600` on each client.
The server stores only a digest. Rotating a group token affects every client in
that group; rotating a machine token affects only that machine.

The client token belongs in root-only client configuration and is sent only in
the HTTP `Authorization` header. It is never accepted in a URL or query string.

Token authentication is not intended to make public keys confidential. A token
selects a key group and optionally identifies a machine. If the operator intentionally
exposes one signed default group to every client, native clients may use that
group without a token. Anonymous access must be explicit configuration; it must
not be an accidental fallback when token authentication or a CIDR match fails.

## Enrollment requests

Enrollment is an approval workflow, not automatic trust:

1. The operator runs `ssh-key-sync-client enroll` on a new machine.
2. The client creates a high-entropy enrollment secret and sends a bounded
   request containing its suggested name, hostname claim, non-loopback interface
   addresses, client version, and the digest of that secret.
3. The server records a pending request with an expiry time and displays a short
   request code. The server also records the source address it observes after any
   NAT or trusted proxy. Hostname, observed source address, and client-reported
   local addresses are metadata only; none grants access.
4. An administrator reviews the request through the loopback-only CLI or UI.
   The administrator may approve it into a group, attach additional machine
   restrictions, or deny it.
5. Approval issues a unique machine token bound to the selected policy. The
   client polls using its enrollment secret and receives the token over HTTPS.
6. The client stores the token with mode `0600` and deletes the enrollment
   secret after successful completion.

Pending requests expire automatically and cannot retrieve non-public groups. An
explicitly public default group may be fetched before approval, allowing a new
machine to become useful while an optional restricted-group assignment is
pending. The queue is bounded and rate-limited to limit spam. The administrator
should verify the request code out-of-band when the machine or network path is
not already known.

The administrator view displays two separately labelled address groups:

```text
Observed by server:        203.0.113.44
Reported by client:
  ens18                     192.0.2.11/24
  ens19                     198.51.100.7/24
```

The client enumerates non-loopback interface addresses and should omit
unspecified, multicast, link-local, and transient container interfaces by
default. Interface names and prefix lengths are retained so the administrator
can distinguish host, VPN, and container networks. Address collection is bounded
to prevent oversized requests.

Client-reported addresses help the administrator recognize a machine and suggest
a CIDR restriction. They are never used as an authentication or authorization
decision, because an arbitrary request can claim any address. Verification still
requires out-of-band confirmation or the approved token after enrollment.

An approval targets an existing group or an explicitly created dedicated group.
Machine records may reference one or more groups and optional source CIDRs.
Ad-hoc key lists on individual enrollment records are avoided so configuration
remains reviewable.

Enrollment always issues a new unique machine token, even when several machines
use the same group. Shared group tokens remain available for manually
pre-provisioned fleets, but an existing token cannot be recovered from its
stored digest.

Enrollment can therefore begin in one of two modes:

- Public default mode fetches the signed default group anonymously. It may also
  submit an enrollment request for a restricted group assignment.
- Restricted mode waits for approval before fetching keys.

The client configuration must state the selected mode explicitly. It must not
silently downgrade from a failed restricted request to the public default group.

Example administrative commands:

```text
ssh-key-sync-server enrollment list
ssh-key-sync-server enrollment show <request-id>
ssh-key-sync-server enrollment approve <request-id> --group displays
ssh-key-sync-server enrollment approve <request-id> --group displays \
  --allow-cidr 192.0.2.0/24
ssh-key-sync-server enrollment deny <request-id>
```

These command names describe the intended interface; they are not implemented
yet. The optional UI uses the same local admin API and remains bound to loopback.

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

