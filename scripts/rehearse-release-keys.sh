#!/usr/bin/env bash

set -euo pipefail

server="${SSH_KEY_SYNC_SERVER_BIN:-/usr/local/bin/ssh-key-sync-server}"
[[ -x "$server" ]] || {
    echo "Set SSH_KEY_SYNC_SERVER_BIN to an executable ssh-key-sync-server" >&2
    exit 1
}

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT HUP INT TERM

"$server" release-keygen --output "$root/key-a"
"$server" release-keygen --output "$root/key-b"
chmod 0600 "$root/key-a/release.key" "$root/key-b/release.key"

printf 'release-key rotation rehearsal\n' > "$root/manifest"
"$server" release-sign \
    --key "$root/key-a/release.key" \
    --manifest "$root/manifest" \
    --output "$root/a.sig"
"$server" release-verify \
    --manifest "$root/manifest" \
    --signature "$root/a.sig" \
    --public-key "$root/key-a/release.pub"

printf 'key_a_fingerprint='
"$server" release-fingerprint --public-key "$root/key-a/release.pub"
printf 'key_b_fingerprint='
"$server" release-fingerprint --public-key "$root/key-b/release.pub"

if "$server" release-verify \
    --manifest "$root/manifest" \
    --signature "$root/a.sig" \
    --public-key "$root/key-b/release.pub" >/dev/null 2>&1
then
    echo "unexpected: key B accepted a signature from key A" >&2
    exit 1
fi
echo "old_signature_rejected_by_new_trust=ok"

# Planned rotation: promote B only after independent fingerprint confirmation.
install -m 0644 "$root/key-b/release.pub" "$root/trusted-release.pub"
"$server" release-sign \
    --key "$root/key-b/release.key" \
    --manifest "$root/manifest" \
    --output "$root/b.sig"
"$server" release-verify \
    --manifest "$root/manifest" \
    --signature "$root/b.sig" \
    --public-key "$root/trusted-release.pub"
echo "new_key_signature_accepted=ok"

# Compromise rehearsal: the retired key signs a different manifest.
printf 'malicious manifest signed by retired key\n' > "$root/malicious"
"$server" release-sign \
    --key "$root/key-a/release.key" \
    --manifest "$root/malicious" \
    --output "$root/malicious.sig"
if "$server" release-verify \
    --manifest "$root/malicious" \
    --signature "$root/malicious.sig" \
    --public-key "$root/trusted-release.pub" >/dev/null 2>&1
then
    echo "unexpected: retired compromised key was accepted" >&2
    exit 1
fi
echo "retired_compromised_key_rejected=ok"
echo "release_key_rehearsal=passed"
