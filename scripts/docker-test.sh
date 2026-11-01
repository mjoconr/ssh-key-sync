#!/usr/bin/env bash

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

docker build --file tests/docker/Dockerfile --tag ssh-key-sync-test:local .
docker run --rm ssh-key-sync-test:local
