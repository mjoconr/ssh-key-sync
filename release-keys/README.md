# Release signing keys

`release-v1.pub` is the trust anchor for the official `mjoconr/ssh-key-sync`
release channel starting with `v0.4.10`.

SHA-256 fingerprint of the raw 32-byte public key:

```text
5e1476b3a1d8bde5580b2aed543666e337290feaaa55019669218c2ee72c9be5
```

The private key is not stored in this repository or in GitHub Actions. The
maintainer copy is `.local/release-v1/release.key`; it is used by
`scripts/sign-release.sh` to sign the exact `SHA256SUMS` file before a draft
release is published.

A fork must generate its own release key, replace or supplement this public
key, publish the fingerprint through a trusted channel, and install that public
key on managed systems before enabling auto-update.
