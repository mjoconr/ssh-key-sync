# Roadmap

This roadmap records work that is not part of the current stable release. It is
ordered by operational risk, not by feature appeal.

## Constraints

- Keep the deployment pull-only. Do not add remote command execution or a
  central configuration-management channel to the server.
- Keep legacy cron and non-systemd clients working until they have been
  inventoried and migrated.
- Keep release artifacts usable on current x86-64 and ARM64 Linux systems while
  preserving compatibility with old OpenSSH clients.
- Do not put deployment addresses, private keys, machine tokens, personal
  public keys, or production screenshots in this public repository.
- Automatic updates and reboots remain opt-in.

## Priority 0: Release Blocking

### Signed Release Provenance

The installers currently verify `SHA256SUMS`, but the archive and checksum come
from the same GitHub release origin. Add one of:

- a detached signature over the release manifest using an offline release key;
- Sigstore/cosign verification; or
- GitHub build-provenance attestations verified by the installer.

The verification root must be independent of the release-download origin. Add
failure tests and document key rotation and compromise recovery.

### Backup Verification And Restore Tooling

Backups are created atomically, but restoration is currently manual. Add:

- `backup verify` using SQLite integrity and schema checks;
- `backup restore --input FILE --confirm` with a stopped-service check;
- automatic pre-restore backup and rollback;
- an integration test that restores state and completes a token request;
- optional encrypted off-host backup guidance.

### Token Expiry And Rotation

Approved machine tokens currently remain valid until revoked. Add:

- optional expiry policies per group and token;
- planned rotation with an overlap window;
- explicit last-used visibility and stale-token reporting;
- pre-expiry warnings and audit entries;
- tests proving expired and revoked tokens cannot fetch private groups.

### Dependency And Advisory Maintenance

Resolve the pending major dependency updates deliberately, especially
`ed25519-dalek` and `sha2`. Keep each major upgrade in its own pull request,
review changed cryptographic behavior, and run the full Docker integration
test. Merge only with zero unexplained CodeQL or Dependabot findings.

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

The service currently exposes health and writes systemd journal entries but
does not publish metrics or notify an administrator. Add:

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

Document and test a supported proxy configuration for:

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
4. Monitor legacy request counts and source networks.
5. Disable the compatibility route only after the request count has remained
   zero for an agreed observation window.

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
- both native architecture builds pass;
- Docker integration tests pass;
- release checksums and architecture are independently checked;
- backup/update rollback behavior is understood;
- operations and security documentation match the shipped behavior.
