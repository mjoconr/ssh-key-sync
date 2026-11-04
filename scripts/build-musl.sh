#!/usr/bin/env bash

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

target_arch="${TARGET_ARCH:-x86_64}"
case "$target_arch" in
    x86_64) docker_platform="linux/amd64" ;;
    i686) docker_platform="linux/amd64" ;;
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

if [[ "$target_arch" == "i686" ]]; then
    image="ghcr.io/rust-cross/cargo-zigbuild:0.19"
    docker run --rm \
        --platform linux/amd64 \
        --name "$container" \
        -v "$repo_root:/project" \
        -v "$repo_root/$output_dir:/out" \
        -w /project \
        -e CARGO_TARGET_DIR=/target \
        "$image" \
        sh -eu -c '
            rustup target add i686-unknown-linux-musl
            cargo zigbuild --locked --release \
                --target i686-unknown-linux-musl \
                -p ssh-key-sync-client \
                -p ssh-key-sync-server
            install -m 0755 \
                /target/i686-unknown-linux-musl/release/ssh-key-sync-client \
                /target/i686-unknown-linux-musl/release/ssh-key-sync-server \
                /out/
        '
    file "$output_dir/ssh-key-sync-client" "$output_dir/ssh-key-sync-server"
    exit 0
fi

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
