# Security

## Assets

The critical asset is the integrity of the managed `authorized_keys` file. SSH
public keys are not confidential, but accepting an attacker-controlled key would
grant unauthorized access.

## Trust Boundaries

- Internet clients to the TLS proxy.
- TLS proxy to the loopback server.
- Server to its configuration, signing key, and SQLite state.
- Client to its filesystem and SSH daemon.
- Source repository and CI to release artifacts.
- GitHub release downloads to the installed client or server binary.

The service is pull-only. The server has no channel for executing commands or
changing configuration on clients.

## Controls

- Native responses are signed with Ed25519 and bound to a request nonce.
- Tokens are at least 256 random bits; the server stores only SHA-256 digests.
- Groups may set a bounded machine-token lifetime. Expired tokens cannot fetch
  keys and appear as expired in the administration CLI and TUI.
- Bearer tokens are not sent over plaintext HTTP.
- Enrollment requests expire after 15 minutes and are rate-limited by observed
  source address.
- The pending enrollment queue is capped to prevent unbounded growth.
- Public groups require explicit configuration.
- A private-group authentication failure never falls back to the public group.
- CIDR matching uses observed addresses from a trusted proxy path.
- XML-RPC source-CIDR selection is disabled per group unless explicitly
  enabled.
- Loopback proxy requests require one valid source-address header.
- The client rejects invalid signatures, expired responses, malformed keys,
  fingerprint mismatches, empty sets, and symlink destinations.
- Key files are written atomically with mode `0600`.
- Existing authorization files are preserved.
- `sshd` changes are validated and rolled back on failure.
- Effective `AuthorizedKeysFile` detection supports both current `sshd -T -C`
  output and legacy separate `AuthorizedKeysFile2` output.
- Client preflight falls back to `/var/run/sshd` on systems without `/run`.
- Server state snapshots use SQLite's online backup API, private permissions,
  atomic rename, and bounded retention.
- Restore verifies SQLite integrity and schema compatibility on a temporary
  copy, refuses to run while the service is active, creates a pre-restore
  snapshot, preserves destination ownership, and atomically replaces state.
- Server configuration edits preserve ownership, validate before activation,
  keep a timestamped backup, and replace atomically.
- Cleartext binding is loopback-only unless an explicit unsafe override is set.
- Signing-key files must be regular, non-symlink files inaccessible to other
  users.
- Enrollment state is bounded, expired unapproved rows are pruned, and the
  SQLite files are forced to mode `0600`.
- Request bodies, response concurrency, request duration, nonces, enrollment
  labels, hostnames, and interface addresses are bounded.
- Approval detects active enrollments that match the candidate by name,
  hostname, or local address. Conflicting replacements require the explicit
  replacement flow and retain the old token until the new session is verified.
- Unauthenticated metadata is stripped of terminal control characters before
  storage or display.
- Release artifacts include checksums and are built from a locked dependency set.
- Release checksums are signed by an offline Ed25519 key whose trust anchor is
  installed separately from the release-download origin.
- x86-64 and ARM64 release artifacts are built natively for their target
  architecture; i686 uses a pinned cross compiler.
- Dependency advisories, licenses, protected CI, CodeQL, secret scanning, and
  push protection are enabled.
- Legacy XML-RPC activity records the selected group, source and key count
  without request bodies. Proxy access logs remove authorization, cookie and
  forwarded-address headers.
- The optional reboot service runs only when the operating system has created
  `/run/reboot-required`.

## Release Trust

The installer verifies `SHA256SUMS.sig` with a locally pinned release public key
before reading checksums or executing a candidate binary. The release private
key is separate from TLS and SSH response-signing keys and is not available to
GitHub Actions.

First installation still requires an explicit bootstrap decision because no
installed binary exists to perform signature verification. The documented
bootstrap builds a verifier from reviewed source and compares the release-key
fingerprint through an independent channel.

See [releases.md](releases.md) for the complete update and rotation model.
See [public-exposure-audit.md](public-exposure-audit.md) for the current public
deployment review and remaining risks.

## Secrets

- The server signing private key must never leave the protected server config.
- Machine tokens are generated on clients and stored with mode `0600`.
- SQLite state contains token digests, not plaintext machine tokens.
- Public SSH keys are not secrets, but avoid publishing a mapping between
  personal identities and private infrastructure.
- Private deployment configs, addresses, logs, screenshots, and keys belong in
  ignored local storage, not this repository.

## Administrative Safety

- Keep an existing SSH session open while changing `sshd`.
- Keep Proxmox or host-managed keys in their existing files.
- Use replacement enrollment for hostname changes.
- Review pending request source addresses, hostnames, expiry, and short code.
- Retire the old identity only after a new key sync and SSH login succeed.
- Verify backup age and periodically test restoration on a non-production copy.

## Reporting

Use the repository's private security advisory feature. Do not open a public
issue for a vulnerability.

