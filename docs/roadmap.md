# Roadmap

This roadmap records work that is not part of the current stable release. It is
ordered by operational risk, not by feature appeal.

## Constraints

- Keep the deployment pull-only. Do not add remote command execution or a
  central configuration-management channel to the server.
- Keep legacy cron and non-systemd clients working until they have been
  inventoried and migrated.
- Keep release artifacts usable on i686, x86-64, and ARM64 Linux systems while
  preserving compatibility with old OpenSSH clients.
- Do not put deployment addresses, private keys, machine tokens, personal
  public keys, or production screenshots in this public repository.
- Automatic updates and reboots remain opt-in.

## Priority 0: Release Blocking

### Signed Release Provenance

This was implemented in `v0.4.10`. The installers verify a signed
`SHA256SUMS` against a separately installed release public key. Follow-up work:

- production key rotation remains a controlled operational event after the
  isolated rotation and compromise rehearsal;
- consider a second signature from a hardware-backed key;
- monitor failed signature and downgrade attempts.

### Backup Verification And Restore Tooling

Backup verification, stopped-service restore, automatic pre-restore snapshots,
and restore tests are implemented. Remaining work:

- repeat the restore rehearsal after state-schema or systemd-unit changes;
- optional encrypted off-host backup guidance.

### Token Expiry And Rotation

Optional per-group token lifetimes are implemented, and expiry is enforced by
the private key endpoint. The CLI and TUI show expiry and use the replacement
enrollment flow for rotation. Token check-in state is available as `connected`,
`new`, `stale`, or `never-connected`, with a configurable threshold and a
`--stale-only` CLI filter. Remaining work:

- per-token overrides in addition to group defaults;
- pre-expiry warnings and scheduled check-in reports;
- state-change notification delivery with deduplication through the monitoring
  interface.

### Dependency And Advisory Maintenance

The pending minor and major dependency updates are resolved. `ed25519-dalek`
v3 was checked against a signature produced by the previous implementation,
and the direct SHA-256 upgrade has a known-answer test. Continue to keep
cryptographic major upgrades isolated, review changed behavior, and run the
full Docker integration test. Merge only with zero unexplained CodeQL or
Dependabot findings.

Make the CodeQL result a required branch-protection check once the workflow has
proven stable. Add dependency review and keep the required status checks aligned
with the checks that block a release.

## Priority 1: Operational Reliability

### Enrollment Approval Policies

Add explicit, default-deny policies that can match:

- trusted source CIDRs;
- requested hostname or machine-name patterns;
- an explicitly selected group;
- a maximum pending age.

Approval must remain auditable. Add a dry-run/preview mode and require a
separate opt-in for each policy. CIDR trust alone must not silently authorize a
private group.

### Monitoring And Notifications

Legacy XML-RPC requests are now identifiable by group and source in the server
journal, with credential-filtered Caddy access logs and an operator summary
command. The service otherwise writes systemd journal entries but does not
publish metrics or notify an administrator. Add:

- a privacy-preserving metrics endpoint for pending requests, active/revoked
  tokens, last successful sync, backup age, and update results;
- webhook or email delivery for new enrollments, repeated failures, expiring
  tokens, missed backups, and pending reboots;
- alert deduplication and rate limits;
- a documented external health-check pattern.

### Update Channels And Rollout Control

All auto-updating hosts currently follow GitHub's latest release. Add:

- stable and canary channels;
- a channel manifest with version, minimum schema, and rollout status;
- per-configuration channel selection;
- staged rollout instructions and downgrade/rollback policy.

### Reverse-Proxy Packaging

The Caddy example in [examples/Caddyfile](../examples/Caddyfile) documents the
current route and source-address requirements. Continue to test and package it
for:

- `/v1/` and `/xmlrpc/` routing;
- request-body and header forwarding;
- source-address trust;
- TLS renewal;
- rate limits and access logging without tokens or request bodies.

### Fleet Migration And Legacy Retirement

Before removing `/xmlrpc/`:

1. Inventory every remaining legacy client and its TLS capability.
2. Record which systems use CIDR-derived groups.
3. Migrate active clients to native API tokens.
4. Monitor legacy request counts, source networks, and rejected requests.
5. Disable the compatibility route only after the request count has remained
   zero for an agreed observation window.

XML-RPC source selection now rejects addresses that do not match an explicit
CIDR on a legacy-enabled group. The `v0.7.0` release notes call out this
behavior change so operators can add missing CIDRs before upgrading.

Do not delete CIDR configuration until replacement tokens are active and tested.

## Priority 2: Hardening And Maintenance

- Add an administrative audit/event view across all subjects.
- Add explicit retention and pruning controls for hidden records and audit
  history.
- Add a server preflight command for file ownership, service-account access,
  signing-key readability, database permissions, proxy connectivity, and
  timers.
- Add package-manager or container-based server installation so the initial
  service account, unit, and directory setup are reproducible.
- Exercise systemd hardening and restore procedures in an older Debian/Ubuntu
  VM and on ARM64 hardware.
- Evaluate a web UI only after the security, provenance, and recovery gaps are
  closed. It is not required for the current one-to-one administration model.

## Release Gate

A release is ready only when:

- required CI, CodeQL, Dependabot, secret scanning, and private advisories are
  reviewed;
- all architecture builds pass;
- Docker integration tests pass;
- release checksums and architecture are independently checked;
- backup/update rollback behavior is understood;
- operations and security documentation match the shipped behavior.
