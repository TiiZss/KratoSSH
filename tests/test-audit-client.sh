#!/bin/bash

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

TMP_DIR="$(mktemp -d)"
MOCK_BIN="$TMP_DIR/bin"
HOME_DIR="$TMP_DIR/home"

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

mkdir -p "$MOCK_BIN" "$HOME_DIR/.ssh"

cat > "$MOCK_BIN/id" <<'EOF'
#!/bin/bash
if [ "$1" = "-u" ]; then
    echo 0
    exit 0
fi
exit 0
EOF

chmod +x "$MOCK_BIN/id"

export PATH="$MOCK_BIN:$PATH"
export HOME="$HOME_DIR"
export KRATOSSH_TEST_OS_NAME="Ubuntu"
export KRATOSSH_TEST_OS_VERSION="22"

echo "Running --audit-client OpenSSH success test..."
cat > "$HOME_DIR/.ssh/config" <<'EOF'
Host *
    KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
    ForwardAgent no
    ForwardX11 no
    Compression no
EOF

set +e
ok_output="$(bash "$REPO_DIR/KratoSSH.sh" --audit-client --client-app openssh 2>&1)"
ok_status=$?
set -e

if [ "$ok_status" -ne 0 ]; then
    echo "$ok_output"
    echo "Expected --audit-client openssh to succeed"
    exit 1
fi

echo "Running --audit-client OpenSSH failure test..."
cat > "$HOME_DIR/.ssh/config" <<'EOF'
Host *
    KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
    ForwardAgent yes
    ForwardX11 no
    Compression no
EOF

set +e
bad_output="$(bash "$REPO_DIR/KratoSSH.sh" --audit-client --client-app openssh 2>&1)"
bad_status=$?
set -e

if [ "$bad_status" -eq 0 ]; then
    echo "$bad_output"
    echo "Expected --audit-client openssh to fail when ForwardAgent is insecure"
    exit 1
fi

echo "$bad_output" | grep -Fq 'ForwardAgent no missing or insecure' || {
    echo "$bad_output"
    echo "Expected ForwardAgent failure message was not found"
    exit 1
}

echo "--audit-client tests passed."
