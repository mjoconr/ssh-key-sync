#!/usr/bin/env bash

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

target_arch="${TARGET_ARCH:-x86_64}"
case "$target_arch" in
    x86_64) docker_platform="linux/amd64" ;;
    aarch64) docker_platform="linux/arm64" ;;
    *) echo "Unsupported TARGET_ARCH: $target_arch" >&2; exit 2 ;;
esac

output_dir=".local/linux-bin/$target_arch"
image="ssh-key-sync-musl:local-$target_arch"
container="ssh-key-sync-musl-build-$$"
mkdir -p "$output_dir"

cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

docker build \
    --platform "$docker_platform" \
    --file tests/docker/Dockerfile.musl \
    --tag "$image" \
    .
docker create --name "$container" "$image" /ssh-key-sync-client --version >/dev/null
docker cp "$container:/ssh-key-sync-client" "$output_dir/ssh-key-sync-client"
docker cp "$container:/ssh-key-sync-server" "$output_dir/ssh-key-sync-server"
chmod 0755 "$output_dir/ssh-key-sync-client" "$output_dir/ssh-key-sync-server"
file "$output_dir/ssh-key-sync-client" "$output_dir/ssh-key-sync-server"
