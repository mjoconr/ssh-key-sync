# Security

## Assets

The critical asset is the integrity of the managed `authorized_keys` file. SSH
public keys are not confidential, but accepting an attacker-controlled key would
grant unauthorized access.

## Trust Boundaries

- Internet clients to the TLS proxy.
- TLS proxy to the loopback server.
- Server to its configuration and signing key.
- Client to its filesystem and SSH daemon.
- Source repository and CI to release artifacts.

## Controls

- Native responses are signed with Ed25519 and bound to a request nonce.
- Tokens are at least 256 random bits; the server stores only SHA-256 digests.
- Bearer tokens are not sent over plaintext HTTP.
- Public groups require explicit configuration.
- A private-group authentication failure never falls back to the public group.
- CIDR matching uses observed addresses from a trusted proxy path.
- The client rejects invalid signatures, expired responses, malformed keys,
  fingerprint mismatches, empty sets, and symlink destinations.
- Key files are written atomically with mode `0600`.
- Existing authorization files are preserved.
- `sshd` changes are validated and rolled back on failure.
- Release artifacts include checksums and are built from a locked dependency set.
- Dependency advisories and licenses are checked in CI.

## Reporting

Use the repository's private security advisory feature. Do not open a public
issue for a vulnerability.

