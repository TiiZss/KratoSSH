#!/bin/bash

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

TMP_DIR="$(mktemp -d)"
SSH_ETC_DIR="$TMP_DIR/etc/ssh"
MOCK_BIN="$TMP_DIR/bin"

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

mkdir -p "$SSH_ETC_DIR/sshd_config.d" "$MOCK_BIN"

cat > "$MOCK_BIN/sshd" <<'EOF'
#!/bin/bash
if [ "$1" = "-t" ]; then
    exit 0
fi
if [ "$1" = "-T" ]; then
    cat <<'OUT'
kexalgorithms curve25519-sha256,diffie-hellman-group16-sha512
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
macs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
hostkeyalgorithms ssh-ed25519,rsa-sha2-512
pubkeyacceptedalgorithms ssh-ed25519,rsa-sha2-512
casignaturealgorithms ssh-ed25519,rsa-sha2-512
gssapikexalgorithms gss-curve25519-sha256-
OUT
    exit 0
fi
exit 0
EOF

cat > "$MOCK_BIN/systemctl" <<'EOF'
#!/bin/bash
if [ "$1" = "is-active" ] && [ "$2" = "--quiet" ]; then
    exit 0
fi
exit 0
EOF

chmod +x "$MOCK_BIN/sshd" "$MOCK_BIN/systemctl"

cat > "$SSH_ETC_DIR/sshd_config" <<'EOF'
Port 22
Include /tmp/placeholder
Include /etc/ssh/sshd_config.d/*.conf
EOF

cat > "$SSH_ETC_DIR/sshd_config.d/00-kratossh-hardening.conf" <<'EOF'
# BEGIN KratoSSH Hardening
Ciphers chacha20-poly1305@openssh.com
# END KratoSSH Hardening
EOF

touch "$SSH_ETC_DIR/ssh_host_rsa_key" "$SSH_ETC_DIR/ssh_host_ed25519_key"

export PATH="$MOCK_BIN:$PATH"
export SSH_ETC_DIR

# shellcheck source=../lib/utils.sh
source "$REPO_DIR/lib/utils.sh"
# shellcheck source=../lib/audit.sh
source "$REPO_DIR/lib/audit.sh"

echo "Running verify_hardening_state success case..."
verify_output="$(verify_hardening_state 2>&1)"
verify_status=$?

if [ "$verify_status" -ne 0 ]; then
    echo "$verify_output"
    echo "verify_hardening_state should have succeeded"
    exit 1
fi

echo "$verify_output" | grep -Fq '[overall] PASS' || {
    echo "$verify_output"
    echo "PASS summary not found in verify output"
    exit 1
}

rm -f "$SSH_ETC_DIR/ssh_host_ed25519_key"

echo "Running verify_hardening_state failure case..."
set +e
verify_output="$(verify_hardening_state 2>&1)"
verify_status=$?
set -e

if [ "$verify_status" -eq 0 ]; then
    echo "$verify_output"
    echo "verify_hardening_state should have failed when a host key is missing"
    exit 1
fi

echo "$verify_output" | grep -Fq '[keys]    FAIL' || {
    echo "$verify_output"
    echo "Key failure summary not found in verify output"
    exit 1
}

echo "$verify_output" | grep -Fq '[overall] FAIL' || {
    echo "$verify_output"
    echo "FAIL summary not found in verify output"
    exit 1
}

echo "verify_hardening_state functional tests passed."