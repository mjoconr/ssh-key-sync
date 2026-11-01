# SSH Key Sync

Rust replacements for the legacy SSH public-key distribution service and client.

## Repository layout

- `crates/core` contains protocol types and shared key, group, and CIDR logic.
- `crates/server` builds the key-selection service.
- `crates/client` builds the portable client installed on target machines.

The client and server are separate binaries and release artifacts, but live in
one repository so that protocol changes and compatibility tests remain in sync.

The legacy XML-RPC endpoint is a compatibility interface, not the architectural
name of the project. New clients should use the native versioned protocol.

## Public repository policy

This repository is intended to remain safe to publish.

- Never commit credentials, tokens, private keys, certificates, or real client
  configuration.
- Keep production hostnames, addresses, group mappings, and machine names in
  deployment-managed configuration, not in this repository.
- Use documentation ranges such as `192.0.2.0/24` and `2001:db8::/32` in
  examples.
- Use generated, non-personal test fixtures for SSH public keys.
- Report vulnerabilities through GitHub's private security advisory feature.

Run `scripts/check-public-tree.sh` before the first push and after adding
fixtures or deployment files.


