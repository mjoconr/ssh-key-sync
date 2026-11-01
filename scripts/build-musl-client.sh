#!/usr/bin/env bash

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

mkdir -p .local/linux-bin
docker build --file tests/docker/Dockerfile.musl --tag ssh-key-sync-client-musl:local .
docker create --name ssh-key-sync-client-musl ssh-key-sync-client-musl:local \
    /ssh-key-sync-client --version >/dev/null
docker cp ssh-key-sync-client-musl:/ssh-key-sync-client .local/linux-bin/ssh-key-sync-client-musl
docker rm ssh-key-sync-client-musl >/dev/null
chmod 0755 .local/linux-bin/ssh-key-sync-client-musl
file .local/linux-bin/ssh-key-sync-client-musl
