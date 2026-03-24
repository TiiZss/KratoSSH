#!/bin/bash

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

TMP_DIR="$(mktemp -d)"
MOCK_BIN="$TMP_DIR/bin"
SSH_ETC_DIR="$TMP_DIR/etc/ssh"

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

mkdir -p "$MOCK_BIN" "$SSH_ETC_DIR"

cat > "$MOCK_BIN/id" <<'EOF'
#!/bin/bash
if [ "$1" = "-u" ]; then
    echo 0
    exit 0
fi
exit 0
EOF

cat > "$MOCK_BIN/sshd" <<'EOF'
#!/bin/bash
if [ "$1" = "-t" ]; then
    exit 0
fi
if [ "$1" = "-T" ]; then
    echo 'port 22'
    exit 0
fi
exit 0
EOF

cat > "$MOCK_BIN/systemctl" <<'EOF'
#!/bin/bash
exit 0
EOF

cat > "$MOCK_BIN/python3" <<'EOF'
#!/bin/bash
exit 0
EOF

chmod +x "$MOCK_BIN/id" "$MOCK_BIN/sshd" "$MOCK_BIN/systemctl" "$MOCK_BIN/python3"

cat > "$SSH_ETC_DIR/sshd_config" <<'EOF'
Port 22
EOF

export PATH="$MOCK_BIN:$PATH"
export SSH_ETC_DIR

echo "Running unsupported distro/version fail-fast tests..."

export KRATOSSH_TEST_OS_NAME="Ubuntu"
export KRATOSSH_TEST_OS_VERSION="13"

set +e
ubuntu_output="$(bash "$REPO_DIR/KratoSSH.sh" --fix 2>&1)"
ubuntu_status=$?
set -e

if [ "$ubuntu_status" -eq 0 ]; then
    echo "$ubuntu_output"
    echo "Unsupported Ubuntu version should fail"
    exit 1
fi

echo "$ubuntu_output" | grep -Fq 'Crypto hardening failed for Ubuntu 13' || {
    echo "$ubuntu_output"
    echo "Expected propagated failure message for Ubuntu 13 not found"
    exit 1
}

export KRATOSSH_TEST_OS_NAME="Debian"
export KRATOSSH_TEST_OS_VERSION="9"

set +e
debian_output="$(bash "$REPO_DIR/KratoSSH.sh" --fix 2>&1)"
debian_status=$?
set -e

if [ "$debian_status" -eq 0 ]; then
    echo "$debian_output"
    echo "Unsupported Debian version should fail"
    exit 1
fi

echo "$debian_output" | grep -Fq 'Crypto hardening failed for Debian 9' || {
    echo "$debian_output"
    echo "Expected propagated failure message for Debian 9 not found"
    exit 1
}

echo "Unsupported distro/version fail-fast tests passed."
