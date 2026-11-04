# Public Exposure Review

Reviewed release: `v0.6.20`

This review covers the code and deployment shape that make SSH Key Sync safe to
expose through a public HTTPS reverse proxy. It is not a penetration test or a
replacement for dependency and deployment monitoring.

## What Must Remain Secure

SSH public keys are not login secrets. The security boundary is the integrity of
the managed `authorized_keys` files: an attacker who can add a key can gain root
SSH access. The server, its signing key, proxy and release path must therefore be
protected even if the public keys themselves are disclosed.

Inventory data still deserves protection. Hostnames, addresses, group membership,
token digests and request history describe private infrastructure even though
they do not grant SSH access.

## Current Controls

- Native key responses are signed with Ed25519, bound to a client nonce, and
  limited to a five-minute validity window. The client verifies the signature,
  nonce, expiry, schema and key fingerprints before replacing a file.
- Private requests fail closed when a token is missing or invalid. They do not
  fall back to a public group.
- `authorized_keys` is replaced atomically with mode `0600`. Empty sets and
  symlink destinations are refused unless explicitly allowed.
- The Rust server binds to loopback unless an operator deliberately overrides
  that setting. The supplied Caddy example exposes only `/v1/` and the legacy
  XML-RPC paths.
- A loopback proxy request must contain exactly one valid `X-Real-IP` header.
  The supplied Caddy example overwrites it with the observed client address.
- Enrollment and XML-RPC bodies are limited to 16 KiB and 64 KiB respectively.
  Requests have a 15-second timeout and application concurrency is limited.
- Pending enrollment rows expire and are capped. Enrollment labels, hostnames,
  interface addresses, nonces and token digests are validated and bounded.
- Conflicting active enrollment identities are surfaced to the administrator
  and cannot be approved through the normal path.
- The server runs as an unprivileged account with a read-only filesystem view,
  no capabilities, no outbound network, resource limits and additional systemd
  hardening. The signing key must be a regular file that is not world-readable;
  the production example uses a dedicated service group so the account can read
  it without making it world-readable.
- State files and WAL sidecars are mode `0600`; the state directory is `0750`.
  Server responses use `Cache-Control: no-store`.
- Legacy XML-RPC source-CIDR selection is disabled per group unless that group
  explicitly enables the compatibility route.
- Release checksums are signed by an offline Ed25519 key. Installed updater
  scripts verify the new script and artifacts with the previously trusted
  verifier and refuse downgrades.

## Residual Risks

### Legacy XML-RPC

XML-RPC responses are unsigned and select a group from the observed source
address. A compromised server or server signing key can substitute keys for
native clients, but the legacy route adds a second path: a legacy client relies
on TLS and source selection rather than an independently signed key set.

Keep XML-RPC disabled unless a specific legacy group needs it. Migrate those
clients, monitor their source networks, and remove the route when its use is
zero. Do not describe CIDR matching as authentication.

### Public Proxy And Host Exposure

Caddy provides HTTPS and ACME. It does not make an incorrectly exposed Rust
listener safe. Confirm that:

- ports 80 and 443 are the only public HTTP listeners;
- the Rust listener is not reachable from the network;
- the Caddy admin API is disabled;
- Caddy overwrites `X-Real-IP` and removes any inbound copy;
- access logs omit `Authorization`, request bodies and other credentials; and
- the host firewall and systemd network restrictions remain effective.

The example in `examples/Caddyfile` is a starting point, not a deployment
inventory. Rate limits at the public edge are still recommended for availability
even though enrollment has application-level limits.

### Token Lifetime

Groups may set an optional token lifetime. Deployments that do not enable it
retain the previous behaviour, where approved machine tokens remain active until
revoked. A stolen token can read its group's public keys and reveal inventory
metadata, but it cannot make a native client install attacker-controlled keys
because the server response still needs the signing key. Pre-expiry warnings and
scheduled check-in notifications are still planned work. The CLI and TUI
currently report token check-in state without contacting clients.

### Release Bootstrap

The update design trusts a local release verifier and the pinned
`/etc/ssh-key-sync/release.pub`. The first installation has no such verifier, and
manually piping a newly downloaded installer into a shell executes that script
before it can prove its own integrity. Establish first trust with a verifier
built from reviewed source and compare the release-key fingerprint through a
second channel. Prefer the installed updater script for routine upgrades.

Release-key rotation and compromise recovery have been exercised with isolated
keys: the replacement trust anchor rejected the retired key, accepted the new
key, and rejected a malicious manifest signed by the retired key. A real
production rotation still requires independently confirmed fingerprints and
coordinated trust-anchor replacement.

### Availability

The server limits request size, concurrency and duration, and enrollment is
rate-limited per source address. Other read routes do not have a general
per-client rate limit. A public deployment should still use proxy rate limits
and external health monitoring appropriate to its traffic.

### Recovery And Dependencies

Backup creation and guarded restore are implemented, including integrity and
schema checks, a stopped-service requirement, and an automatic pre-restore
snapshot. The complete procedure has been rehearsed against a production-like
systemd instance, including active-service refusal, older-state restoration,
pre-restore recovery, permission checks, service restart, and health validation.
Repeat the rehearsal after schema or unit changes. Major dependency upgrades,
including cryptographic libraries, require deliberate review and the complete
integration suite.

### Old TLS Clients And Clock Skew

Do not add a cleartext public fallback for systems whose TLS stack is obsolete.
Use a trusted local mirror or migrate the system. Old machines must also maintain
reasonably accurate time or certificate validation can fail before a request is
made.

## Operational Checklist

1. Keep the Rust listener on loopback and test that it is unreachable remotely.
2. Publish only the intended Caddy routes; unknown paths must return `404`.
3. Disable Caddy's admin API and overwrite the forwarded client address.
4. Confirm signing-key, state and state-directory permissions.
5. Keep legacy XML-RPC off except for named migration groups.
6. Keep an independent SSH session open while changing `sshd`.
7. Verify a fresh SSH login before retiring an old key source or enrollment.
8. Review CI, CodeQL, Dependabot and security advisories before a release.
9. Test backup restoration and update rollback on non-production systems.
10. Do not commit deployment addresses, private keys, tokens or production
    configuration to this repository.

## Conclusion

Public SSH keys are safe to distribute. The controls above are about preserving
key-set integrity and preventing an attacker from using the service as a path to
server compromise. The largest remaining compatibility risk is the unsigned
legacy XML-RPC path, and the largest operational risks are proxy exposure,
long-lived tokens and untested recovery.
