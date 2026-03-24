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

mkdir -p "$MOCK_BIN" "$HOME_DIR/.putty/sessions"

cat > "$MOCK_BIN/id" <<'EOF'
#!/bin/bash
if [ "$1" = "-u" ]; then
    echo 0
    exit 0
fi
exit 0
EOF

cat > "$MOCK_BIN/powershell.exe" <<'EOF'
#!/bin/bash
printf 'POWERSHELL_ARGS:'
printf ' %s' "$@"
printf '\n'
exit 0
EOF

chmod +x "$MOCK_BIN/id" "$MOCK_BIN/powershell.exe"

cat > "$HOME_DIR/.putty/sessions/default-session" <<'EOF'
HostName=localhost
PortNumber=22
EOF

export PATH="$MOCK_BIN:$PATH"
export HOME="$HOME_DIR"
export KRATOSSH_TEST_OS_NAME="Ubuntu"
export KRATOSSH_TEST_OS_VERSION="22"

echo "Running PuTTY client hardening test..."
putty_output="$(bash "$REPO_DIR/KratoSSH.sh" --auto --type client --client-app putty 2>&1)"
putty_status=$?

if [ "$putty_status" -ne 0 ]; then
    echo "$putty_output"
    echo "PuTTY client hardening should have succeeded"
    exit 1
fi

grep -Fq 'Cipher=chacha20,aes,blowfish,3des,WARN' "$HOME_DIR/.putty/sessions/default-session" || {
    echo "$putty_output"
    echo "PuTTY session was not updated with hardened Cipher list"
    exit 1
}

grep -Fq 'KEX=ecdh,dh-gex-sha256,dh-group14-sha1,rsa,WARN' "$HOME_DIR/.putty/sessions/default-session" || {
    echo "$putty_output"
    echo "PuTTY session was not updated with hardened KEX list"
    exit 1
}

grep -Fq 'HostKey=ed25519,ecdsa,rsa,dsa,WARN' "$HOME_DIR/.putty/sessions/default-session" || {
    echo "$putty_output"
    echo "PuTTY session was not updated with hardened HostKey list"
    exit 1
}

echo "Running Bitvise client hardening test..."
bitvise_output="$(bash "$REPO_DIR/KratoSSH.sh" --auto --type client --client-app bitvise 2>&1)"
bitvise_status=$?

if [ "$bitvise_status" -ne 0 ]; then
    echo "$bitvise_output"
    echo "Bitvise client hardening should have succeeded"
    exit 1
fi

echo "$bitvise_output" | grep -Fq 'POWERSHELL_ARGS:' || {
    echo "$bitvise_output"
    echo "Bitvise flow did not execute powershell wrapper"
    exit 1
}

echo "$bitvise_output" | grep -Fq 'windows/bitvise_hardening.ps1' || {
    echo "$bitvise_output"
    echo "Bitvise flow did not call the expected hardening script"
    exit 1
}

echo "Third-party client hardening tests passed."
