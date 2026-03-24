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
export KRATOSSH_TEST_OS_NAME="Ubuntu"
export KRATOSSH_TEST_OS_VERSION="22"

echo "Running CLI argument validation tests..."

set +e
missing_fix_port_output="$(bash "$REPO_DIR/KratoSSH.sh" --fix --fix-port 2>&1)"
missing_fix_port_status=$?
set -e

if [ "$missing_fix_port_status" -eq 0 ]; then
    echo "$missing_fix_port_output"
    echo "Expected failure for --fix-port without value"
    exit 1
fi

echo "$missing_fix_port_output" | grep -Fq 'Option --fix-port requires a value.' || {
    echo "$missing_fix_port_output"
    echo "Missing expected error message for --fix-port"
    exit 1
}

set +e
missing_client_app_output="$(bash "$REPO_DIR/KratoSSH.sh" --auto --type client --client-app 2>&1)"
missing_client_app_status=$?
set -e

if [ "$missing_client_app_status" -eq 0 ]; then
    echo "$missing_client_app_output"
    echo "Expected failure for --client-app without value"
    exit 1
fi

echo "$missing_client_app_output" | grep -Fq 'Option --client-app requires a value.' || {
    echo "$missing_client_app_output"
    echo "Missing expected error message for --client-app"
    exit 1
}

set +e
invalid_client_app_output="$(bash "$REPO_DIR/KratoSSH.sh" --auto --type client --client-app invalidapp 2>&1)"
invalid_client_app_status=$?
set -e

if [ "$invalid_client_app_status" -eq 0 ]; then
    echo "$invalid_client_app_output"
    echo "Expected failure for unsupported client app"
    exit 1
fi

echo "$invalid_client_app_output" | grep -Fq "Unknown client app 'invalidapp'" || {
    echo "$invalid_client_app_output"
    echo "Missing expected unsupported app error"
    exit 1
}

echo "CLI argument validation tests passed."
