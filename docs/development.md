# Development Rules

These rules apply to all code, tests, scripts, documentation, and release
tooling.

## Rust baseline

- Edition: Rust 2024.
- Minimum supported Rust version: 1.85 unless a reviewed change updates it.
- Development and release toolchain: pinned in `rust-toolchain.toml`.
- Dependencies are committed through `Cargo.lock`.
- New dependencies require a reason in the pull request, an active maintenance
  check, and review of their feature flags and transitive tree.

## Required local checks

```sh
scripts/check-public-tree.sh
cargo fmt --all -- --check
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

Run the public-tree check before every commit. It is installed as the repository
pre-commit hook by:

```sh
git config core.hooksPath .githooks
```

Before a release, also run the dependency advisory and license policy tooling
described in `deny.toml`. CI must enforce the same checks that are required for
release.

## Code rules

- Unsafe Rust is forbidden at workspace level.
- Public items have documentation comments; docs describe invariants and errors,
  not just restate type names.
- Production paths do not use `unwrap`, `expect`, panics, `todo!`, or
  `unimplemented!`. Return contextual errors instead.
- Library errors use specific error enums. Binary entry points may add context at
  the process boundary.
- Prefer typed domain values for normalized addresses, groups, key
  fingerprints, protocol versions, and signed manifests.
- Do not pass untrusted values to a shell. Execute programs with argument arrays.
- Network operations have request-size limits and explicit timeouts.
- File replacement is atomic and validated. Never truncate the destination in
  place.
- Temporary files use restrictive permissions and are created in the destination
  directory so rename stays on one filesystem.
- Logging defaults to metadata. Key material, request bodies, tokens, and private
  paths are redacted unless explicitly enabled for a documented diagnostic.
- Authentication tokens are never accepted in URLs or command-line arguments.
  Generated tokens are displayed once and written to root-only configuration.
- `unsafe`, direct FFI, or privileged subprocess use requires a separate design
  review even if the workspace lint is temporarily relaxed.

Tests may use `expect` to identify fixture failures, but should prefer assertion
messages and must not hide production failures.

## Testing rules

- Unit tests cover parsing, normalization, precedence, duplicate fingerprints,
  malformed keys, and configuration validation.
- Property tests cover arbitrary addresses and CIDRs; a match must agree with a
  reviewed reference implementation.
- Golden tests lock down legacy XML-RPC bytes, escaping, ordering, and trailing
  newline.
- Integration tests run the server on an ephemeral loopback port.
- Client filesystem tests use temporary directories and assert modes, atomic
  replacement, empty-response rejection, and rollback.
- Every security invariant in `docs/security.md` requires a regression test.
- No test may contact production infrastructure or use real credentials.

## Command-line rules

- Commands support `--help`, `--version`, `--config`, and `--dry-run` where
  meaningful.
- Exit status is meaningful for systemd and cron.
- Progress goes to stderr; machine-consumable output goes to stdout.
- Destructive or privileged actions print the exact target before changing it
  unless `--quiet` is explicitly supported.

## Public repository rules

- Use reserved or generated values in tests and examples.
- Do not add real machine names, addresses, public keys, configuration, tokens,
  host credentials, CI secrets, signing keys, or private certificates.
- Shell scripts are small, quoted, fail-fast, and avoid `eval`.
- Third-party GitHub Actions are pinned to immutable commit SHAs.
- Releases are built by CI from a signed or protected tag and have published
  checksums and provenance.

