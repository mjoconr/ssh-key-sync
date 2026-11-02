# Development

Rust 2024 is built with the toolchain pinned in `rust-toolchain.toml`.

## Checks

```sh
scripts/check-public-tree.sh
cargo fmt --all -- --check
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

Run the Docker integration test with:

```sh
scripts/docker-test.sh
```

Build static release binaries for the host architecture with:

```sh
TARGET_ARCH=x86_64 scripts/build-musl.sh
TARGET_ARCH=aarch64 scripts/build-musl.sh
```

The ARM64 build uses Docker Buildx and requires platform emulation when the
host is not ARM64.

Inspect and remove generated local build data with:

```sh
scripts/clean-local-cache.sh
scripts/clean-local-cache.sh --apply
scripts/clean-local-cache.sh --apply --include-local-artifacts
```

The script is a dry run unless `--apply` is supplied. `target/` is always
reported; `.local/linux-bin/` is removed only when explicitly requested.

Workflow changes must pass:

```sh
go run github.com/rhysd/actionlint/cmd/actionlint@latest .github/workflows/*.yml
```

CI also runs the public-tree guard, dependency policy, tests, Clippy,
documentation checks, and CodeQL analysis.

## Rust Guidelines

- Do not use `unsafe`.
- Document public APIs.
- Return errors instead of panicking in runtime paths.
- Use typed values at parsing boundaries.
- Bound network request sizes and durations.
- Execute subprocesses with argument arrays, never a shell string.
- Keep production logging free of keys, tokens, and request bodies.
- Add a regression test for every security fix.
- Preserve audit history when implementing hide or retire operations.
- Update the operations and security documentation with behavior changes.

Tests use generated or non-personal keys and documentation address ranges.

## Releases

Push an immutable semantic-version tag:

```sh
git tag -a v0.5.0 -m "v0.5.0"
git push origin v0.5.0
```

The release workflow builds static x86-64 and ARM64 Linux clients and servers
on matching native GitHub runners, generates `SHA256SUMS`, and publishes both
installers and all archives. Every release is explicitly marked latest so
out-of-order background jobs cannot change which version `/releases/latest/`
resolves to.

Before creating a tag:

1. Run every local check plus `scripts/docker-test.sh`.
2. Confirm no open Dependabot, CodeQL, secret-scanning, or private advisory
   issue is being shipped.
3. Confirm the version in `Cargo.toml` matches the intended tag.
4. Merge through a protected pull request and wait for the required `check` job
   and CodeQL analysis.
5. Create and push an annotated immutable tag.
6. Wait for both native architecture jobs and the release job to pass.
7. Verify `SHA256SUMS`, the ARM64 binary architecture, and the latest-release
   redirect.
8. Deploy through the packaged updater and verify health before closing the
   release.

Major dependency upgrades are not merged solely because Dependabot opened them.
Review API changes, run the integration suite, and keep unrelated major
upgrades in separate pull requests.

Current priorities and deferred work are tracked in
[roadmap.md](roadmap.md).

