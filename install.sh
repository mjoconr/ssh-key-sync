#!/bin/sh

set -eu

repo="mjoconr/ssh-key-sync"
version="${VERSION:-latest}"
server_url=""
signing_key_sha256=""
apply_ssh=0
enable_timer=0
enable_auto_update=0
enroll_name=""

usage() {
    echo "Usage: install.sh [options]"
    echo "  --version VERSION"
    echo "  --server URL"
    echo "  --signing-key-sha256 HEX"
    echo "  --apply-ssh"
    echo "  --enable-timer"
    echo "  --enable-auto-update"
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
        --enable-auto-update)
            enable_auto_update=1
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
    aarch64|arm64) target="aarch64-unknown-linux-musl" ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ -f /etc/ssh-key-sync/client-auto-update ]; then
    enable_auto_update=1
fi

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

verify_download() {
    file="$1"
    expected="$(awk -v file="$file" '$2 == file { print $1 }' "$tmp/SHA256SUMS")"
    [ -n "$expected" ] || { echo "No checksum for $file" >&2; exit 1; }
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$tmp/$file" | awk '{ print $1 }')"
    else
        actual="$(shasum -a 256 "$tmp/$file" | awk '{ print $1 }')"
    fi
    [ "$actual" = "$expected" ] || {
        echo "Checksum verification failed for $file" >&2
        exit 1
    }
}

install_client_auto_update() {
    download "$base/install.sh" "$tmp/install.sh"
    download "$base/ssh-key-sync-client-update.service" "$tmp/ssh-key-sync-client-update.service"
    download "$base/ssh-key-sync-client-update.timer" "$tmp/ssh-key-sync-client-update.timer"
    verify_download install.sh
    verify_download ssh-key-sync-client-update.service
    verify_download ssh-key-sync-client-update.timer
    install -d -m 0755 /usr/local/lib/ssh-key-sync
    install -d -m 0750 /etc/ssh-key-sync
    install -m 0755 "$tmp/install.sh" /usr/local/lib/ssh-key-sync/install.sh
    : > /etc/ssh-key-sync/client-auto-update
    if [ "$use_systemd" -eq 1 ]; then
        install -m 0644 "$tmp/ssh-key-sync-client-update.service" /etc/systemd/system/
        install -m 0644 "$tmp/ssh-key-sync-client-update.timer" /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable --now ssh-key-sync-client-update.timer
        echo "Enabled ssh-key-sync-client-update.timer"
        return
    fi
    command -v crontab >/dev/null 2>&1 || {
        echo "crontab is required for auto-update on non-systemd hosts" >&2
        exit 1
    }
    existing="$(crontab -l 2>/dev/null || true)"
    update_command="/usr/local/lib/ssh-key-sync/install.sh >/dev/null 2>&1"
    rendered="$(
        printf '%s\n' "$existing" |
            awk -v command="$update_command" 'index($0, command) == 0'
        printf '37 4 * * * %s\n' "$update_command"
    )"
    if [ -n "$existing" ] && [ ! -e /root/crontab.before-ssh-key-sync-update ]; then
        printf '%s\n' "$existing" > /root/crontab.before-ssh-key-sync-update
        chmod 0600 /root/crontab.before-ssh-key-sync-update
    fi
    printf '%s\n' "$rendered" | crontab -
    echo "Enabled daily client auto-update through cron"
}

download "$base/$asset" "$tmp/$asset"
download "$base/SHA256SUMS" "$tmp/SHA256SUMS"

verify_download "$asset"

tar -xzf "$tmp/$asset" -C "$tmp"
install -d -m 0755 /usr/local/bin
install -m 0755 "$tmp/ssh-key-sync-client" /usr/local/bin/ssh-key-sync-client.new
mv -f /usr/local/bin/ssh-key-sync-client.new /usr/local/bin/ssh-key-sync-client

echo "Installed /usr/local/bin/ssh-key-sync-client"
echo "Existing /etc/ssh-key-sync configuration has been preserved."

use_systemd=0
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    use_systemd=1
fi

if [ "$enable_auto_update" -eq 1 ]; then
    install_client_auto_update
fi

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

if [ "$use_systemd" -eq 1 ] && { [ "$enable_timer" -eq 1 ] || [ -n "$enroll_name" ]; }; then
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
fi

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
    if [ "$use_systemd" -eq 1 ]; then
        echo "Then enable the timer:"
        echo "  systemctl enable --now ssh-key-sync-client.timer"
    else
        echo "Systemd is unavailable; after approval install cron with:"
        echo "  ssh-key-sync-client --config /etc/ssh-key-sync/client.toml install-cron"
    fi
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
    if [ "$use_systemd" -eq 1 ]; then
        systemctl enable --now ssh-key-sync-client.timer
    else
        /usr/local/bin/ssh-key-sync-client \
            --config /etc/ssh-key-sync/client.toml \
            install-cron
    fi
fi

