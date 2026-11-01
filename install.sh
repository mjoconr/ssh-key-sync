#!/bin/sh

set -eu

repo="mjoconr/ssh-key-sync"
version="${VERSION:-latest}"
server_url=""
signing_key_sha256=""
apply_ssh=0
enable_timer=0
enroll_name=""

usage() {
    echo "Usage: install.sh [options]"
    echo "  --version VERSION"
    echo "  --server URL"
    echo "  --signing-key-sha256 HEX"
    echo "  --apply-ssh"
    echo "  --enable-timer"
    echo "  --enroll NAME"
    echo "Set GH_TOKEN when installing from a private repository."
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            version="$2"
            shift 2
            ;;
        --server)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            server_url="$2"
            shift 2
            ;;
        --signing-key-sha256)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            signing_key_sha256="$2"
            shift 2
            ;;
        --apply-ssh)
            apply_ssh=1
            shift
            ;;
        --enable-timer)
            enable_timer=1
            shift
            ;;
        --enroll)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            enroll_name="$2"
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

if [ -z "$server_url" ]; then
    exit 0
fi
[ -n "$signing_key_sha256" ] || {
    echo "--signing-key-sha256 is required with --server" >&2
    exit 2
}
case "$server_url" in
    https://*) ;;
    *) echo "--server must use HTTPS" >&2; exit 2 ;;
esac

curl -fsSL "$server_url/v1/signing-key" -o "$tmp/signing.pub"
if command -v sha256sum >/dev/null 2>&1; then
    key_sha256="$(sha256sum "$tmp/signing.pub" | awk '{ print $1 }')"
else
    key_sha256="$(shasum -a 256 "$tmp/signing.pub" | awk '{ print $1 }')"
fi
[ "$key_sha256" = "$signing_key_sha256" ] || {
    echo "Signing-key fingerprint mismatch" >&2
    exit 1
}

install -d -m 0750 /etc/ssh-key-sync
install -m 0644 "$tmp/signing.pub" /etc/ssh-key-sync/signing.pub
{
    echo "schema_version = 1"
    echo "server_url = \"$server_url\""
    echo "verifying_key_file = \"/etc/ssh-key-sync/signing.pub\""
    echo "authorized_keys_file = \"/etc/ssh/authorized_keys.d/root\""
    if [ -n "$enroll_name" ]; then
        echo "token_file = \"/etc/ssh-key-sync/token\""
    fi
    echo "allow_empty = false"
} > /etc/ssh-key-sync/client.toml
chmod 0600 /etc/ssh-key-sync/client.toml

if [ -n "$enroll_name" ]; then
    if [ "$apply_ssh" -eq 1 ]; then
        /usr/local/bin/ssh-key-sync-client \
            --config /etc/ssh-key-sync/client.toml \
            configure-sshd --apply
    fi
    /usr/local/bin/ssh-key-sync-client \
        --config /etc/ssh-key-sync/client.toml \
        enroll --name "$enroll_name"
    echo "Wait for administrator approval, then run:"
    echo "  ssh-key-sync-client --config /etc/ssh-key-sync/client.toml enrollment-status --wait"
    exit 0
fi

/usr/local/bin/ssh-key-sync-client \
    --config /etc/ssh-key-sync/client.toml sync --dry-run

if [ "$apply_ssh" -eq 1 ]; then
    /usr/local/bin/ssh-key-sync-client \
        --config /etc/ssh-key-sync/client.toml \
        configure-sshd --apply
fi

if [ "$enable_timer" -eq 1 ]; then
    download "$base/ssh-key-sync-client.service" "$tmp/ssh-key-sync-client.service"
    download "$base/ssh-key-sync-client.timer" "$tmp/ssh-key-sync-client.timer"
    for file in ssh-key-sync-client.service ssh-key-sync-client.timer; do
        expected="$(awk -v file="$file" '$2 == file { print $1 }' "$tmp/SHA256SUMS")"
        actual="$(sha256sum "$tmp/$file" | awk '{ print $1 }')"
        [ "$actual" = "$expected" ] || { echo "Checksum verification failed for $file" >&2; exit 1; }
    done
    install -m 0644 "$tmp/ssh-key-sync-client.service" /etc/systemd/system/
    install -m 0644 "$tmp/ssh-key-sync-client.timer" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now ssh-key-sync-client.timer
fi

