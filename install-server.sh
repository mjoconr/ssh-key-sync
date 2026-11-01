#!/bin/sh

set -eu

repo="mjoconr/ssh-key-sync"
version="${VERSION:-latest}"
config="/etc/ssh-key-sync/server.toml"
service="ssh-key-sync-server.service"
health_url="http://127.0.0.1:18080/v1/health"
enable_auto_update=0
enable_reboot_timer=0
enable_backup_timer=0

usage() {
    echo "Usage: install-server.sh [options]"
    echo "  --version VERSION       Release tag, or latest (default)"
    echo "  --config PATH           Server config (default: $config)"
    echo "  --service NAME          systemd unit (default: $service)"
    echo "  --health-url URL        Local health endpoint"
    echo "  --no-restart            Install and validate without restarting"
    echo "  --enable-auto-update    Enable the daily server upgrade timer"
    echo "  --enable-reboot-timer   Reboot weekly only when updates require it"
    echo "  --enable-backup-timer   Back up enrollment and token state daily"
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
        --enable-auto-update)
            enable_auto_update=1
            shift
            ;;
        --enable-reboot-timer)
            enable_reboot_timer=1
            shift
            ;;
        --enable-backup-timer)
            enable_backup_timer=1
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
if [ "$restart" -eq 0 ] &&
    { [ "$enable_auto_update" -eq 1 ] ||
      [ "$enable_reboot_timer" -eq 1 ] ||
      [ "$enable_backup_timer" -eq 1 ]; }
then
    echo "--no-restart cannot be combined with automation enable flags" >&2
    exit 2
fi

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

verify_download() {
    file="$1"
    expected="$(awk -v file="$file" '$2 == file { print $1 }' "$tmp/SHA256SUMS")"
    [ -n "$expected" ] || { echo "No checksum for $file" >&2; exit 1; }
    actual="$(sha256sum "$tmp/$file" | awk '{ print $1 }')"
    [ "$actual" = "$expected" ] || {
        echo "Checksum verification failed for $file" >&2
        exit 1
    }
}

install_server_automation() {
    command -v systemctl >/dev/null 2>&1 || {
        echo "systemctl is required for server update and reboot timers" >&2
        exit 1
    }
    for file in \
        install-server.sh \
        ssh-key-sync-server-update.service \
        ssh-key-sync-server-update.timer \
        ssh-key-sync-reboot.service \
        ssh-key-sync-reboot.timer \
        ssh-key-sync-backup.service \
        ssh-key-sync-backup.timer
    do
        download "$base/$file" "$tmp/$file"
        verify_download "$file"
    done
    install -d -m 0755 /usr/local/lib/ssh-key-sync
    install -m 0755 "$tmp/install-server.sh" /usr/local/lib/ssh-key-sync/install-server.sh
    install -m 0644 "$tmp/ssh-key-sync-server-update.service" /etc/systemd/system/
    install -m 0644 "$tmp/ssh-key-sync-server-update.timer" /etc/systemd/system/
    install -m 0644 "$tmp/ssh-key-sync-reboot.service" /etc/systemd/system/
    install -m 0644 "$tmp/ssh-key-sync-reboot.timer" /etc/systemd/system/
    install -m 0644 "$tmp/ssh-key-sync-backup.service" /etc/systemd/system/
    install -m 0644 "$tmp/ssh-key-sync-backup.timer" /etc/systemd/system/
    systemctl daemon-reload
    if [ "$enable_auto_update" -eq 1 ]; then
        : > /etc/ssh-key-sync/auto-update
        systemctl enable --now ssh-key-sync-server-update.timer
        echo "Enabled ssh-key-sync-server-update.timer"
    fi
    if [ "$enable_reboot_timer" -eq 1 ]; then
        : > /etc/ssh-key-sync/reboot-timer
        systemctl enable --now ssh-key-sync-reboot.timer
        echo "Enabled ssh-key-sync-reboot.timer"
    fi
    if [ "$enable_backup_timer" -eq 1 ]; then
        : > /etc/ssh-key-sync/backup-timer
        systemctl enable --now ssh-key-sync-backup.timer
        echo "Enabled ssh-key-sync-backup.timer"
    fi
}

if [ -f /etc/ssh-key-sync/auto-update ]; then
    enable_auto_update=1
fi
if [ -f /etc/ssh-key-sync/reboot-timer ]; then
    enable_reboot_timer=1
fi
if [ -f /etc/ssh-key-sync/backup-timer ]; then
    enable_backup_timer=1
fi

download "$base/$asset" "$tmp/$asset"
download "$base/SHA256SUMS" "$tmp/SHA256SUMS"

verify_download "$asset"

tar -xzf "$tmp/$asset" -C "$tmp"
candidate="$tmp/ssh-key-sync-server"
test -x "$candidate" || { echo "Server binary is missing from archive" >&2; exit 1; }
"$candidate" check-config --config "$config"

if [ "$restart" -eq 0 ]; then
    install -m 0755 "$candidate" /usr/local/bin/ssh-key-sync-server
    if [ "$enable_auto_update" -eq 1 ] ||
        [ "$enable_reboot_timer" -eq 1 ] ||
        [ "$enable_backup_timer" -eq 1 ]
    then
        install_server_automation
    fi
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

if ! systemctl restart "$service"; then
    rollback
    exit 1
fi
attempt=1
while [ "$attempt" -le 15 ]; do
    if curl -fsS --max-time 2 "$health_url" >/dev/null 2>&1; then
        echo "Installed $("$candidate" --version)"
        echo "Service healthy: $health_url"
        break
    fi
    sleep 1
    attempt=$((attempt + 1))
done

if [ "$attempt" -gt 15 ]; then
    rollback
    exit 1
fi

if [ "$enable_auto_update" -eq 1 ] ||
    [ "$enable_reboot_timer" -eq 1 ] ||
    [ "$enable_backup_timer" -eq 1 ]
then
    install_server_automation
fi
