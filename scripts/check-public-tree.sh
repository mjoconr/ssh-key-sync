#!/usr/bin/env bash

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

failed=0

report() {
    printf 'public-tree check: %s\n' "$1" >&2
    failed=1
}

while IFS= read -r file; do
    case "$file" in
        ./.env.example)
            continue
            ;;
        ./.env|./.env.*|*.key|*.pem|*.p12|*.pfx|*.jks|*.keystore|*.ovpn|*.local.toml|*.local.yaml|*.local.yml|*/id_rsa|*/id_rsa.*|*/id_ecdsa|*/id_ecdsa.*|*/id_ed25519|*/id_ed25519.*)
            report "sensitive filename: $file"
            continue
            ;;
    esac

    if rg -q --no-messages -- '-----BEGIN ([A-Z0-9]+ )?PRIVATE KEY-----' "$file"; then
        report "private-key material: $file"
    fi

    if rg -q --no-messages -- '(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[0-9A-Z]{16})' "$file"; then
        report "credential-like token: $file"
    fi
done < <(
    find . \
        -path './.git' -prune -o \
        -path './target' -prune -o \
        -path './dist' -prune -o \
        -path './releases' -prune -o \
        -type f -print
)

if (( failed != 0 )); then
    printf '%s\n' 'public-tree check failed; remove the reported data from the working tree.' >&2
    exit 1
fi

printf '%s\n' 'public-tree check passed.'

