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
port 2222
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

cat > "$MOCK_BIN/python3" <<'EOF'
#!/bin/bash
printf 'PYTHON3_ARGS:'
printf ' %s' "$@"
printf '\n'
exit 0
EOF

chmod +x "$MOCK_BIN/sshd" "$MOCK_BIN/systemctl" "$MOCK_BIN/python3"

cat > "$SSH_ETC_DIR/sshd_config" <<'EOF'
Port 22
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

echo "Running CLI --verify test..."
verify_output="$(bash "$REPO_DIR/KratoSSH.sh" --verify 2>&1)"
verify_status=$?

if [ "$verify_status" -ne 0 ]; then
    echo "$verify_output"
    echo "KratoSSH --verify should have succeeded"
    exit 1
fi

echo "$verify_output" | grep -Fq '[overall] PASS' || {
    echo "$verify_output"
    echo "CLI verify output missing PASS summary"
    exit 1
}

echo "Running CLI --audit test..."
audit_output="$(bash "$REPO_DIR/KratoSSH.sh" --audit 2>&1)"
audit_status=$?

if [ "$audit_status" -ne 0 ]; then
    echo "$audit_output"
    echo "KratoSSH --audit should have succeeded"
    exit 1
fi

echo "$audit_output" | grep -Fq 'Audit mode enabled (read-only): no hardening changes will be applied.' || {
    echo "$audit_output"
    echo "CLI audit output missing read-only message"
    exit 1
}

echo "$audit_output" | grep -Fq 'Detected custom SSH port: 2222' || {
    echo "$audit_output"
    echo "CLI audit output missing detected port message"
    exit 1
}

echo "$audit_output" | grep -Fq 'PYTHON3_ARGS:' || {
    echo "$audit_output"
    echo "CLI audit output missing mocked python3 execution"
    exit 1
}

echo "$audit_output" | grep -Fq 'localhost -p 2222' || {
    echo "$audit_output"
    echo "CLI audit output missing expected audit target arguments"
    exit 1
}

echo "CLI functional tests passed."