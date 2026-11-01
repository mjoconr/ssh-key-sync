# Development

Rust 2024 is built with the toolchain pinned in `rust-toolchain.toml`.

## Checks

```sh
scripts/check-public-tree.sh
cargo fmt --all -- --check
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

## Rust Guidelines

- Do not use `unsafe`.
- Document public APIs.
- Return errors instead of panicking in runtime paths.
- Use typed values at parsing boundaries.
- Bound network request sizes and durations.
- Execute subprocesses with argument arrays, never a shell string.
- Keep production logging free of keys, tokens, and request bodies.
- Add a regression test for every security fix.

Tests use generated or non-personal keys and documentation address ranges.

## Releases

Push an immutable semantic-version tag:

```sh
git tag -a v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

The release workflow builds static x86-64 and ARM64 Linux clients and servers
on matching native GitHub runners, generates `SHA256SUMS`, and publishes both
installers and all archives. Every release is explicitly marked latest so
out-of-order background jobs cannot change which version `/releases/latest/`
resolves to.

