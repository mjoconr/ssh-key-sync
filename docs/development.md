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

The release workflow builds the static x86_64 Linux client, generates
`SHA256SUMS`, and publishes the installer and client archive.

