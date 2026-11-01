# Security Design

## Security objectives

1. The client installs only keys originated by the trusted service.
2. A network or server failure cannot erase the last known-good key file.
3. A format upgrade cannot leave root SSH unusable.
4. Legacy Proxmox-managed authorization files remain intact.
5. Client update artifacts and metadata are authentic, fresh, and non-downgrade.
6. The public repository contains no operational secrets or private deployment
   details.

## Assets

- Integrity of root `authorized_keys`.
- Availability of the key service and root SSH login.
- Authenticity and freshness of fetched key sets.
- Authenticity of client release artifacts and update manifests.
- Administrative access to the server and release pipeline.

Public SSH keys are not confidential, but their integrity is critical. An
attacker who can substitute a response or update can obtain root access.

The principal security objective is therefore not to hide the key material. It
is to ensure that a machine writes exactly the operator-approved key set. Group
mapping and machine identity controls may still reveal infrastructure state or
limit which public sets are exposed, so they remain separately configurable.

## Trust boundaries

- Public internet to Caddy.
- Caddy to the loopback-only Rust server.
- Rust server to its root-managed configuration file.
- Client network to the key service.
- Client process to the filesystem and SSH daemon.
- GitHub CI to release artifacts.
- Offline signing environment to the deployed verification key.

## Required invariants

- Never authorize an untrusted key.
- Never write an empty `authorized_keys` file unless both server policy and local
  client policy explicitly permit it.
- Never fall back from failed HTTPS or signature verification to an unsigned
  result.
- Never accept a forwarded client address unless the request arrived from a
  configured trusted proxy.
- Never use the caller-supplied hostname as an authorization decision.
- Never let a client-supplied address override the observed network address.
- Never send a reusable machine bearer token over plaintext HTTP.
- Never store a plaintext machine token in server configuration or logs.
- Never modify Proxmox's `/root/.ssh/authorized_keys`.
- Never reload `sshd` with a configuration that failed `sshd -t`.
- Never update to an older client or protocol version automatically.
- Never place private signing keys, GitHub tokens, or deploy credentials in
  source, build artifacts, command-line arguments, or logs.

## Server controls

- Caddy provides HTTPS with current TLS versions and automatic certificate
  renewal. Obsolete TLS versions are not enabled for compatibility.
- The Rust process binds to loopback and runs as a dedicated system user.
- Request bodies, response generation, and configuration files have explicit
  size limits.
- CIDRs are validated at load time. Equal-precedence conflicts make the
  configuration invalid.
- Native authentication maps a high-entropy group or machine token to a token
  record. Only a digest is stored server-side, and comparisons use constant-time
  code.
- Group tokens are rotated as a group. Machine tokens can be rotated and revoked
  individually.
- An anonymous public group is allowed only through explicit configuration and
  never as a fallback after failed CIDR or token authentication.
- Configuration writes are serialized, validated, backed up, and atomically
  replaced. Invalid reloads preserve the last good in-memory configuration.
- SSH keys are parsed and canonicalized with an established OpenSSH key library.
- Response ordering is deterministic and key fingerprints are included in audit
  metadata.
- Dynamic rate limiting is applied at Caddy or the HTTP layer.
- Structured logs exclude full key material, tokens, and request bodies.

The source CIDR is a key-set filter, not proof of host identity. NAT, reverse
proxies, and moved addresses can change the selected group. More-specific
exceptions must be tested explicitly. Native clients are therefore identified
by their provisioned machine token rather than by network location.

## Client and filesystem controls

- The default target account is root.
- The client owns `/etc/ssh/authorized_keys.d/%u`; unrelated authorization files
  remain untouched.
- Effective `AuthorizedKeysFile` is inspected before adding the managed path.
- SSH configuration changes occur under an exclusive lock, include a backup, and
  are rolled back if `sshd -t` fails.
- The installer keeps an existing administrative session open while testing a
  new SSH configuration.
- Temporary and final key files are owned by the target account and mode `0600`.
- File writes are flushed and atomically renamed. Symlink traversal and
  destination-directory replacement are treated as failures.
- A failed download, timeout, signature failure, malformed response, or empty
  response leaves the previous file unchanged.

## Transport controls

HTTPS with the embedded WebPKI roots is the normal transport. A current static
Rust client avoids dependence on an old operating system's Python, OpenSSL, SNI,
or CA store.

Because public keys may intentionally be public, an anonymous group can be
served without machine authentication. The transport and response signatures
remain mandatory because replacing public keys is equivalent to granting
unauthorized access to the machines using them.

For firewalled networks where current TLS is unavailable, a separate listener
may serve signed manifests over HTTP. Access is restricted by network controls,
and every response is signed over the request nonce and complete response
document. Plain HTTP without signature verification is prohibited.

SSH-tunnel or VPN transport may be used where old clients already have a trusted
administrative path.

Machine bearer tokens are accepted only over HTTPS. For a legacy HTTP path they
must be protected inside an SSH or VPN tunnel, or replaced by a reviewed
challenge-response proof implemented by both client and server.

## Release and update controls

- The Ed25519 release-signing private key is kept offline or in a protected
  signing environment.
- The verification key is embedded in clients at build time.
- A signed manifest pins artifact SHA-256 hashes, versions, protocol ranges, and
  expiry.
- Clients reject signatures, hashes, architecture, version, and protocol range
  mismatches before installation.
- Downloads have bounded size and timeouts.
- Updates use an atomic release-directory or symlink switch and retain one
  previous good version.
- Stable and canary channels are separate. Test machines use canary first.
- Release builds use a committed lockfile and pinned toolchain.
- GitHub Actions are commit-pinned and receive read-only permissions by default.
- Release artifacts include checksums and build provenance.
- Dependency advisories and license policy are checked before release.

## Repository controls

- Production configuration lives outside this repository.
- `.gitignore`, the pre-commit hook, and CI reject common secret filenames and
  private-key or token material.
- Test fixtures use generated SSH keys and documentation network ranges.
- Security reports use GitHub private advisories.
- Before making the repository public, review the full Git history and ensure a
  suitable license is selected.

## Operational controls

- Keep a tested recovery path that does not depend on the key service.
- Back up server configuration before migration.
- Test changes on a clone or snapshot before the PVE master or mail host.
- Run TLS certificate tests against the Let's Encrypt staging environment before
  production issuance.
- Automatic OS upgrades may restart services. Reboot only when required and
  during a maintenance window with package-lock and recovery checks.
- Treat automatic reboot of a Proxmox host separately from rebooting a guest VM.

## Residual risks

- Source CIDR matching selects a group but does not independently authenticate a
  machine.
- A stolen native token can retrieve its configured public key set until the
  token is revoked. This is primarily a group-mapping exposure because SSH public
  keys are not confidential.
- A compromised trusted network can obtain that network's public key set.
- A compromised signing environment can authorize malicious client updates.
- Anyone with root on a managed machine can modify its installed keys and client.
- Signed HTTP protects integrity and authenticity, not confidentiality.

