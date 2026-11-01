# Implementation Plan

Each phase must leave the repository public-safe and pass all required checks.

## Phase 0: engineering baseline

Done:

- Separate client, server, and shared-core crates in one repository.
- Pinned Rust toolchain and workspace lint policy.
- Public-tree checks and pre-commit hook.
- CI, dependency update automation, and security documentation.

Exit gate: documented architecture, threat model, and clean repository history.

Product boundary: this is a pull-only key authority for independently managed
machines. It is not a general configuration-management or remote-deployment
system.

## Phase 1: core domain and compatibility

- Define validated types for groups, CIDRs, public keys, fingerprints, protocol
  versions, and response documents.
- Implement the native configuration parser with reserved documentation values.
- Implement a legacy configuration importer.
- Implement most-specific CIDR matching and deterministic key ordering.
- Create golden fixtures from the legacy PHP interface without real keys.
- Add unit, property, and compatibility tests.

Exit gate: identical normalized key selection and XML-RPC rendering for all
approved fixtures.

## Phase 2: server

- Add configuration validation CLI and safe reload.
- Implement the native signed response endpoint.
- Implement the legacy `/xmlrpc/` endpoint.
- Add request-size, timeout, trusted-proxy, and rate-limit controls.
- Add structured logging without sensitive material.
- Run behind Caddy on loopback.

Exit gate: side-by-side response comparison passes; invalid configuration cannot
replace the last good version; rollback to PHP remains available.

## Phase 3: client dry run and sync

- Add portable HTTPS transport with embedded roots and bounded responses.
- Verify signatures and freshness.
- Implement key validation, empty-response protection, locking, and atomic file
  replacement.
- Add `inspect`, `sync --dry-run`, and `status` commands.
- Add failure and rollback tests.

Exit gate: no failure mode can truncate the existing key file.

## Phase 4: SSH and service installation

- Implement Proxmox-aware two-file discovery.
- Add dry-run and apply modes for `sshd` configuration.
- Validate with `sshd -t`; support rollback.
- Add systemd service/timer and legacy cron installation.
- Preserve stable command paths for old machines.

Exit gate: test on a snapshot or clone of the PVR frontend, then the master, then
the mail host, retaining an active recovery session throughout.

## Phase 5: distribution and self-upgrade

- Build static client artifacts for each supported architecture.
- Create signed update manifests and checksums.
- Add stable/canary channels, atomic upgrades, and one-version rollback.
- Mirror artifacts to the service download endpoint.
- Create the first immutable Git tag and GitHub Release only when install and
  rollback are proven.

Exit gate: a canary client upgrades and rolls back without changing its key file.

## Phase 6: production cutover

- Move TLS termination to Caddy or retain nginx until Caddy staging passes.
- Install the Rust server in parallel with PHP.
- Compare responses from known network locations.
- Switch the XML-RPC upstream, monitor, then remove PHP-FPM.
- Enable controlled package upgrades and maintenance-window reboots.

Exit gate: old cron clients, native systemd clients, Proxmox hosts, and the
public HTTPS path all pass; recovery is documented and exercised.

