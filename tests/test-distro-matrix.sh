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

mkdir -p "$MOCK_BIN" "$SSH_ETC_DIR/sshd_config.d"

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
    cat <<'OUT'
port 22
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
exit 0
EOF

cat > "$MOCK_BIN/python3" <<'EOF'
#!/bin/bash
exit 0
EOF

chmod +x "$MOCK_BIN/id" "$MOCK_BIN/sshd" "$MOCK_BIN/systemctl" "$MOCK_BIN/python3"

cat > "$SSH_ETC_DIR/sshd_config" <<'EOF'
Port 22
Include /etc/ssh/sshd_config.d/*.conf
EOF

cat > "$SSH_ETC_DIR/moduli" <<'EOF'
0 2 4 6 4096 8
EOF

export PATH="$MOCK_BIN:$PATH"
export SSH_ETC_DIR

run_case() {
    local os_name="$1"
    local os_version="$2"
    local expected="$3"

    export KRATOSSH_TEST_OS_NAME="$os_name"
    export KRATOSSH_TEST_OS_VERSION="$os_version"

    set +e
    output="$(bash "$REPO_DIR/KratoSSH.sh" --fix --dry-run --fast 2>&1)"
    status=$?
    set -e

    if [ "$expected" = "ok" ] && [ "$status" -ne 0 ]; then
        echo "$output"
        echo "Expected success for $os_name $os_version"
        exit 1
    fi

    if [ "$expected" = "fail" ] && [ "$status" -eq 0 ]; then
        echo "$output"
        echo "Expected fail-fast for $os_name $os_version"
        exit 1
    fi
}

echo "Running distro family matrix tests..."

# Supported families
run_case "Ubuntu" "22" "ok"
run_case "Debian" "12" "ok"
run_case "Rocky Linux" "9" "ok"
run_case "Fedora Linux" "36" "ok"
run_case "Alpine Linux" "3" "ok"
run_case "Red Hat Enterprise Linux" "9" "ok"
run_case "Red Hat Enterprise Linux" "10" "ok"
run_case "Red Hat Enterprise Linux" "8" "ok"

# Normalized aliases
run_case "Linux Mint" "21" "ok"
run_case "Kali GNU/Linux" "2024" "ok"
run_case "Parrot Security" "6" "ok"
run_case "AlmaLinux" "9" "ok"
run_case "Oracle Linux Server" "9" "ok"

# Unsupported boundaries
run_case "Ubuntu" "13" "fail"
run_case "Debian" "9" "fail"
run_case "Fedora Linux" "35" "fail"
run_case "Red Hat Enterprise Linux" "7" "fail"

echo "Distro family matrix tests passed."
