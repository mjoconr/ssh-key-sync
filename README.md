# SSH Key Sync

Rust replacements for the legacy SSH public-key distribution service and client.

The project is currently at the design and scaffolding stage. No command shown
in the design documentation is considered available until it is implemented and
listed here.

SSH Key Sync is pull-only. It does not push commands, deploy configuration, or
require a central orchestration service. Each machine is installed individually
and remains responsible for its own schedule, network policy, and rollback.

## Repository layout

- `crates/core` contains protocol types and shared key, group, and CIDR logic.
- `crates/server` builds the key-selection service.
- `crates/client` builds the portable client installed on target machines.

The client and server are separate binaries and release artifacts, but live in
one repository so that protocol changes and compatibility tests remain in sync.

The legacy XML-RPC endpoint is a compatibility interface, not the architectural
name of the project. New clients should use the native versioned protocol.

## Documentation

- [Architecture](docs/architecture.md) describes components and trust boundaries.
- [Implementation plan](docs/implementation-plan.md) lists milestones and gates.
- [Development rules](docs/development.md) defines Rust and repository standards.
- [Security controls](docs/security.md) defines the threat model and invariants.
- [GitHub security setup](docs/github-security.md) tracks repository controls.
- [Contributing](CONTRIBUTING.md) describes the required local checks.

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

No open-source license has been selected yet. The repository should remain
private until the owner chooses a license and reviews all release tooling.


