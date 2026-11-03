#!/usr/bin/env bash

set -euo pipefail

test_root="$(mktemp -d)"
server_pid=""

cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$test_root"
}
trap cleanup EXIT

cd "$test_root"
ssh-key-sync-server generate-keys --output keys
test "$(stat -c '%a' keys/signing.key)" = "600"
test "$(stat -c '%a' keys/signing.pub)" = "644"

ssh-key-sync-server release-keygen --output release-keys
test "$(stat -c '%a' release-keys/release.key)" = "600"
test "$(stat -c '%a' release-keys/release.pub)" = "644"
printf 'test release manifest\n' > release-manifest
ssh-key-sync-server release-sign \
    --key release-keys/release.key \
    --manifest release-manifest \
    --output release-manifest.sig
ssh-key-sync-client release-verify \
    --manifest release-manifest \
    --signature release-manifest.sig \
    --public-key release-keys/release.pub
printf 'tampered release manifest\n' > release-manifest.tampered
if ssh-key-sync-client release-verify \
    --manifest release-manifest.tampered \
    --signature release-manifest.sig \
    --public-key release-keys/release.pub
then
    echo "invalid release signature was accepted" >&2
    exit 1
fi

token="docker-test-token"
token_digest="sha256:$(printf '%s' "$token" | sha256sum | cut -d' ' -f1)"

cat > server.toml <<EOF
schema_version = 1
listen = "127.0.0.1:18080"
signing_key_file = "$test_root/keys/signing.key"
default_group = "public"
require_forwarded_client_ip = false

[groups.public]
visibility = "public"
legacy_xmlrpc = true

[groups.restricted]
visibility = "private"
legacy_xmlrpc = true

[keys.example]
groups = ["public", "restricted"]
keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti docker-test"]

[[tokens]]
id = "docker-test"
group = "restricted"
digest = "$token_digest"
EOF

cat > public-client.toml <<EOF
schema_version = 1
server_url = "http://127.0.0.1:18080"
verifying_key_file = "$test_root/keys/signing.pub"
authorized_keys_file = "$test_root/public_authorized_keys"
allow_empty = false
require_effective_sshd = false
EOF

cat > restricted-client.toml <<EOF
schema_version = 1
server_url = "http://127.0.0.1:18080"
verifying_key_file = "$test_root/keys/signing.pub"
authorized_keys_file = "$test_root/restricted_authorized_keys"
token_file = "$test_root/token"
allow_empty = false
require_effective_sshd = false
EOF

cat > sshd-client.toml <<EOF
schema_version = 1
server_url = "http://127.0.0.1:18080"
verifying_key_file = "$test_root/keys/signing.pub"
authorized_keys_file = "/etc/ssh/authorized_keys.d/root"
allow_empty = false
EOF

ssh-key-sync-server check-config --config server.toml
ssh-key-sync-server serve --config server.toml >server.log 2>&1 &
server_pid=$!

for _ in $(seq 1 30); do
    if curl --fail --silent http://127.0.0.1:18080/v1/health >/dev/null; then
        break
    fi
    sleep 0.2
done
curl --fail --silent http://127.0.0.1:18080/v1/health | grep -qx 'ok'
curl --silent --dump-header - --output /dev/null \
    http://127.0.0.1:18080/v1/health | grep -qi '^cache-control: no-store'

mkdir -p /run/sshd /etc/ssh/authorized_keys.d
if ssh-key-sync-client --config sshd-client.toml sync --dry-run \
    >sshd-preflight.out 2>sshd-preflight.err
then
    echo "sync accepted an ineffective sshd configuration" >&2
    exit 1
fi
grep -q 'managed authorized_keys path is not effective in sshd' sshd-preflight.err

head -c 20000 /dev/zero | tr '\0' ' ' > oversized-enrollment.json
status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --header 'Content-Type: application/json' \
    --data-binary @oversized-enrollment.json \
    http://127.0.0.1:18080/v1/enrollments)"
test "$status" = "413"

ssh-key-sync-client --config public-client.toml sync --dry-run
test ! -e public_authorized_keys
ssh-key-sync-client --config public-client.toml sync
test "$(stat -c '%a' public_authorized_keys)" = "600"
grep -q 'docker-test$' public_authorized_keys

enrollment_output="$(ssh-key-sync-client --config restricted-client.toml enroll --name docker-test)"
printf '%s\n' "$enrollment_output"
request_id="$(printf '%s\n' "$enrollment_output" | awk '/^request:/ { print $2 }')"
test -n "$request_id"
test "$(stat -c '%a' pending-enrollment.json)" = "600"

ssh-key-sync-client --config restricted-client.toml enrollment-status | grep -q 'status: pending'
ssh-key-sync-server enrollment list --config server.toml | grep -q "$request_id"
ssh-key-sync-server enrollment approve "$request_id" --group restricted --config server.toml
ssh-key-sync-client --config restricted-client.toml enrollment-status | grep -q 'approved for group restricted'
test "$(stat -c '%a' token)" = "600"

ssh-key-sync-server backup --config server.toml --output-directory "$test_root/backups" --retain 2
backup_file="$(find "$test_root/backups" -maxdepth 1 -name 'state-*.db' -print -quit)"
test -n "$backup_file"
test "$(stat -c '%a' "$backup_file")" = "600"
ssh-key-sync-server backup-verify --input "$backup_file"

ssh-key-sync-client --config restricted-client.toml sync
grep -q 'docker-test$' restricted_authorized_keys
ssh-key-sync-server token list --config server.toml \
    | grep -q 'client=ssh-key-sync-client/'

ssh-key-sync-client --config sshd-client.toml configure-sshd
test ! -e /etc/ssh/sshd_config.d/20-ssh-key-sync.conf
ssh-key-sync-client --config sshd-client.toml configure-sshd --apply --no-reload
sshd -T -C user=root,host=localhost,addr=127.0.0.1 \
    | grep '^authorizedkeysfile ' \
    | grep -F '/etc/ssh/authorized_keys.d/root'
ssh-key-sync-client --config sshd-client.toml sync --dry-run \
    | grep -q 'verified group public'

curl --fail --silent \
    --header 'Content-Type: text/xml' \
    --data-binary '<?xml version="1.0"?><methodCall><methodName>ssh.getKeys</methodName><params><param><value><string>localhost</string></value></param></params></methodCall>' \
    http://127.0.0.1:18080/xmlrpc/ \
    | grep -q 'docker-test'
grep -q 'legacy XML-RPC key request' server.log
grep -Eq 'group="?public"?' server.log
grep -q 'source_ip=127.0.0.1' server.log

ssh-key-sync-server generate-keys --output wrong-keys
sed "s#keys/signing.pub#wrong-keys/signing.pub#" public-client.toml > bad-client.toml
if ssh-key-sync-client --config bad-client.toml sync --dry-run; then
    echo "invalid signature was accepted" >&2
    exit 1
fi

echo "Docker integration test passed."

