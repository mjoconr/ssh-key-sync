#!/usr/bin/env bash

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
apply=0
include_local_artifacts=0

usage() {
    echo "Usage: scripts/clean-local-cache.sh [options]"
    echo "  --apply                    Delete the reported caches"
    echo "  --include-local-artifacts Remove .local/linux-bin release binaries"
    echo
    echo "Without --apply, the script only reports reclaimable space."
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --apply)
            apply=1
            shift
            ;;
        --include-local-artifacts)
            include_local_artifacts=1
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

cd "$repo_root"

size_of() {
    if [[ -e "$1" ]]; then
        du -sh "$1" | awk '{ print $1 }'
    else
        echo "absent"
    fi
}

target_path="$repo_root/target"
local_artifacts="$repo_root/.local/linux-bin"

echo "Repository:            $(size_of "$repo_root")"
echo "Rust build cache:      $(size_of "$target_path")  (target/)"
if [[ "$include_local_artifacts" -eq 1 ]]; then
    echo "Local release binaries: $(size_of "$local_artifacts")  (.local/linux-bin/)"
fi

if [[ "$apply" -eq 0 ]]; then
    echo
    echo "Dry run. Re-run with --apply to delete these generated files."
    exit 0
fi

if [[ -d "$target_path" ]]; then
    cargo clean
fi

if [[ "$include_local_artifacts" -eq 1 ]] &&
    [[ "$local_artifacts" == "$repo_root/.local/linux-bin" ]] &&
    [[ -d "$local_artifacts" ]]; then
    rm -rf -- "$local_artifacts"
fi

echo
echo "Cleanup complete. Repository size: $(size_of "$repo_root")"
