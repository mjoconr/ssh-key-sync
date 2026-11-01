# GitHub Security Configuration

GitHub is the source and build-integrity service. Production configuration,
client configuration, and release signing keys do not belong in this
repository.

## Enabled controls

- Dependabot version updates for Cargo and GitHub Actions.
- Dependabot vulnerability alerts.
- Dependabot automated security update pull requests.
- `cargo-deny` advisory, license, source, and dependency bans in CI.
- Commit-pinned third-party GitHub Actions.
- Read-only default workflow token permissions.
- Public-tree secret checks in CI and the local pre-commit hook.
- CODEOWNERS review routing for the repository owner.
- Private vulnerability reporting instructions in `SECURITY.md`.

## Notification setup

Repository owners should watch the repository with **Security alerts** enabled
and ensure GitHub's **Security alert** and **Actions** notifications are enabled
in their personal notification settings. The repository API cannot configure
these personal notification preferences.

Failed CI, Dependabot alerts, code-scanning alerts, and private security
advisories must be reviewed before a release.

## Controls activated when the repository becomes public

User-owned private repositories do not currently provide the free secret
scanning, CodeQL, or private vulnerability reporting features used by this
project. Before changing visibility:

1. Re-scan the complete Git history for credentials and infrastructure details.
2. Choose and add an appropriate source license.
3. Enable secret scanning and push protection.
4. Enable CodeQL advanced setup for Rust.
5. Enable private vulnerability reporting and verify the Security tab link.
6. Confirm that the issue contact link opens the private advisory form.
7. Review Actions permissions and confirm workflows still use read-only tokens.
8. Review all release assets and tags for accidental local or private data.

The `SECURITY.md` and issue-template policies are already present so these
controls are immediately useful once the repository is public.

