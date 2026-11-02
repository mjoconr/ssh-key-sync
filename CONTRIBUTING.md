# Contributing

Read [docs/development.md](docs/development.md) and
[docs/security.md](docs/security.md) before changing code.

## Local checks

Run all checks before committing:

```sh
scripts/check-public-tree.sh
cargo fmt --all -- --check
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
scripts/docker-test.sh
go run github.com/rhysd/actionlint/cmd/actionlint@latest .github/workflows/*.yml
```

Install the repository hook once per clone:

```sh
git config core.hooksPath .githooks
```

## Pull requests

Describe the security impact of a change, including how it handles malformed
input, network failure, partial writes, and rollback. Add tests for each fixed
bug and for every new security invariant.

Update the README, architecture, operations, security, and development docs
when behavior, configuration, deployment, or trust assumptions change. Keep
major security or operational work aligned with [docs/roadmap.md](docs/roadmap.md).

Do not add production configuration, infrastructure addresses, personal public
keys, credentials, signing keys, or release private keys to the repository.

Do not open a public issue for a suspected vulnerability. Follow
[SECURITY.md](SECURITY.md) and use a private security advisory.

