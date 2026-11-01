#!/bin/sh

set -eu

repo="mjoconr/ssh-key-sync"
version="${VERSION:-latest}"
config="/etc/ssh-key-sync/server.toml"
service="ssh-key-sync-server.service"
health_url="http://127.0.0.1:18080/v1/health"

usage() {
    echo "Usage: install-server.sh [options]"
    echo "  --version VERSION       Release tag, or latest (default)"
    echo "  --config PATH           Server config (default: $config)"
    echo "  --service NAME          systemd unit (default: $service)"
    echo "  --health-url URL        Local health endpoint"
    echo "  --no-restart            Install and validate without restarting"
    echo "Set GH_TOKEN when downloading from a private repository."
}

restart=1
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            version="$2"
            shift 2
            ;;
        --config)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            config="$2"
            shift 2
            ;;
        --service)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            service="$2"
            shift 2
            ;;
        --health-url)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            health_url="$2"
            shift 2
            ;;
        --no-restart)
            restart=0
            shift
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

[ "$(id -u)" -eq 0 ] || {
    echo "Run install-server.sh as root" >&2
    exit 1
}
[ -r "$config" ] || {
    echo "Server config is not readable: $config" >&2
    exit 1
}

case "$(uname -m)" in
    x86_64|amd64) target="x86_64-unknown-linux-musl" ;;
    aarch64|arm64) target="aarch64-unknown-linux-musl" ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ "$version" = "latest" ]; then
    base="https://github.com/$repo/releases/latest/download"
else
    base="https://github.com/$repo/releases/download/$version"
fi
asset="ssh-key-sync-server-$target.tar.gz"

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
actual="$(sha256sum "$tmp/$asset" | awk '{ print $1 }')"
[ "$actual" = "$expected" ] || { echo "Checksum verification failed" >&2; exit 1; }

tar -xzf "$tmp/$asset" -C "$tmp"
candidate="$tmp/ssh-key-sync-server"
test -x "$candidate" || { echo "Server binary is missing from archive" >&2; exit 1; }
"$candidate" check-config --config "$config"

if [ "$restart" -eq 0 ]; then
    install -m 0755 "$candidate" /usr/local/bin/ssh-key-sync-server
    echo "Installed /usr/local/bin/ssh-key-sync-server without restarting $service"
    exit 0
fi

command -v systemctl >/dev/null 2>&1 || {
    echo "systemctl is required to restart $service" >&2
    exit 1
}

backup="/usr/local/bin/ssh-key-sync-server.before-upgrade"
install -m 0755 /usr/local/bin/ssh-key-sync-server "$backup"
install -m 0755 "$candidate" /usr/local/bin/ssh-key-sync-server.new
mv -f /usr/local/bin/ssh-key-sync-server.new /usr/local/bin/ssh-key-sync-server

rollback() {
    echo "Health check failed; restoring the previous server binary" >&2
    install -m 0755 "$backup" /usr/local/bin/ssh-key-sync-server
    systemctl restart "$service" || true
}

systemctl restart "$service"
attempt=1
while [ "$attempt" -le 15 ]; do
    if curl -fsS --max-time 2 "$health_url" >/dev/null 2>&1; then
        echo "Installed $("$candidate" --version)"
        echo "Service healthy: $health_url"
        exit 0
    fi
    sleep 1
    attempt=$((attempt + 1))
done

rollback
exit 1
