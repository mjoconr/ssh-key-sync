#!/usr/bin/env bash

set -euo pipefail

repo="${SSH_KEY_SYNC_REPO:-$(gh repo view --json nameWithOwner --jq '.nameWithOwner')}"
tag="${1:-}"
signing_key="${SSH_KEY_SYNC_RELEASE_KEY:-.local/release-v1/release.key}"
public_key="${SSH_KEY_SYNC_RELEASE_PUBLIC_KEY:-release-keys/release-v1.pub}"

if [[ -z "$tag" ]]; then
    echo "Usage: scripts/sign-release.sh TAG" >&2
    echo "Set SSH_KEY_SYNC_RELEASE_KEY to override $signing_key" >&2
    exit 2
fi
[[ -f "$signing_key" ]] || {
    echo "Release signing key is missing: $signing_key" >&2
    exit 1
}
[[ -f "$public_key" ]] || {
    echo "Release public key is missing: $public_key" >&2
    exit 1
}

key_mode="$(stat -c '%a' "$signing_key" 2>/dev/null || stat -f '%Lp' "$signing_key")"
if (( 8#$key_mode & 8#077 )); then
    echo "Release signing key permissions are too broad: $key_mode" >&2
    exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

state="$(gh release view "$tag" --repo "$repo" --json isDraft --jq '.isDraft')"
[[ "$state" == "true" ]] || {
    echo "Release $tag is not a draft" >&2
    exit 1
}

gh release download "$tag" --repo "$repo" --dir "$tmp"
cmp "$public_key" "$tmp/release.pub" || {
    echo "Release public key does not match $public_key" >&2
    exit 1
}
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmp" && sha256sum -c SHA256SUMS)
else
    (cd "$tmp" && shasum -a 256 -c SHA256SUMS)
fi

cargo run --quiet --locked --release -p ssh-key-sync-server -- \
    release-sign \
    --key "$signing_key" \
    --manifest "$tmp/SHA256SUMS" \
    --output "$tmp/SHA256SUMS.sig"

cargo run --quiet --locked --release -p ssh-key-sync-server -- \
    release-verify \
    --manifest "$tmp/SHA256SUMS" \
    --signature "$tmp/SHA256SUMS.sig" \
    --public-key "$public_key"

gh release upload "$tag" "$tmp/SHA256SUMS.sig" --repo "$repo" --clobber
gh release edit "$tag" --repo "$repo" --draft=false --latest
echo "Published signed release $tag"
