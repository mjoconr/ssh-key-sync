#!/usr/bin/env bash

set -euo pipefail

since="${1:-30 days ago}"

echo "Successful legacy XML-RPC key requests since: $since"
journalctl \
    -u ssh-key-sync-server.service \
    --since "$since" \
    --no-pager \
    -o cat 2>/dev/null |
    sed -nE \
        's/.*legacy XML-RPC key request group="?([^" ]+)"? source_ip=([^ ]+) client_name=([^ ]+) key_count=([0-9]+).*/\1\t\2\t\3\t\4 keys/p' |
    sort |
    uniq -c |
    sort -nr || true

echo
echo "Requests rejected because the source had no enabled legacy group"
journalctl \
    -u ssh-key-sync-server.service \
    --since "$since" \
    --no-pager \
    -o cat 2>/dev/null |
    grep -c 'legacy XML-RPC request without an enabled group' || true

echo
echo "Requests allowed only by the legacy default-group fallback"
journalctl \
    -u ssh-key-sync-server.service \
    --since "$since" \
    --no-pager \
    -o cat 2>/dev/null |
    grep -Ec 'selection="?default_fallback"?' || true
