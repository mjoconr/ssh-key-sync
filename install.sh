#!/bin/sh

set -eu

repo="mjoconr/ssh-key-sync"
version="${VERSION:-latest}"

usage() {
    echo "Usage: install.sh [--version VERSION]"
    echo "Set GH_TOKEN when installing from a private repository."
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            version="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done

case "$(uname -m)" in
    x86_64|amd64) target="x86_64-unknown-linux-musl" ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ "$version" = "latest" ]; then
    base="https://github.com/$repo/releases/latest/download"
else
    base="https://github.com/$repo/releases/download/$version"
fi
asset="ssh-key-sync-client-$target.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

download() {
    if [ -n "${GH_TOKEN:-}" ]; then
        curl -fsSL -H "Authorization: Bearer $GH_TOKEN" "$1" -o "$2"
    else
        curl -fsSL "$1" -o "$2"
    fi
}

download "$base/$asset" "$tmp/$asset"
download "$base/SHA256SUMS" "$tmp/SHA256SUMS"

expected="$(awk -v file="$asset" '$2 == file { print $1 }' "$tmp/SHA256SUMS")"
[ -n "$expected" ] || { echo "No checksum for $asset" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp/$asset" | awk '{ print $1 }')"
else
    actual="$(shasum -a 256 "$tmp/$asset" | awk '{ print $1 }')"
fi
[ "$actual" = "$expected" ] || { echo "Checksum verification failed" >&2; exit 1; }

tar -xzf "$tmp/$asset" -C "$tmp"
install -d -m 0755 /usr/local/bin
install -m 0755 "$tmp/ssh-key-sync-client" /usr/local/bin/ssh-key-sync-client.new
mv -f /usr/local/bin/ssh-key-sync-client.new /usr/local/bin/ssh-key-sync-client

echo "Installed /usr/local/bin/ssh-key-sync-client"
echo "Existing /etc/ssh-key-sync configuration has been preserved."

