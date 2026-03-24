#!/bin/bash

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

TMP_DIR="$(mktemp -d)"
MOCK_BIN="$TMP_DIR/bin"

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

mkdir -p "$MOCK_BIN"

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
SSH_DIR="${SSH_ETC_DIR:-/etc/ssh}"
main_config="$SSH_DIR/sshd_config"
dropin_config="$SSH_DIR/sshd_config.d/00-kratossh-hardening.conf"

if [ "$1" = "-t" ] && [ "$2" = "-f" ]; then
    file_to_check="$3"
elif [ "$1" = "-t" ]; then
    file_to_check="$main_config"
else
    exit 0
fi

if grep -q 'INVALID' "$file_to_check" 2>/dev/null; then
    exit 1
fi

if [ -f "$dropin_config" ] && grep -q 'INVALID' "$dropin_config" 2>/dev/null; then
    exit 1
fi

if [ "${KRATOSSH_TEST_FAIL_VALIDATE:-false}" = "true" ] && [ "$1" = "-t" ]; then
    if [ -f "$dropin_config" ]; then
        exit 1
    fi
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
if [ "$1" = "restart" ]; then
    if [ "${KRATOSSH_TEST_FAIL_RESTART:-false}" = "true" ]; then
        exit 1
    fi
    exit 0
fi
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

cat > "$MOCK_BIN/ssh-keygen" <<'EOF'
#!/bin/bash
out_file=""
while [ $# -gt 0 ]; do
    if [ "$1" = "-f" ]; then
        out_file="$2"
        shift 2
        continue
    fi
    shift
done

if [ -n "$out_file" ]; then
    mkdir -p "$(dirname "$out_file")"
    : > "$out_file"
    : > "${out_file}.pub"
fi
exit 0
EOF

chmod +x "$MOCK_BIN/id" "$MOCK_BIN/sshd" "$MOCK_BIN/systemctl" "$MOCK_BIN/python3" "$MOCK_BIN/ssh-keygen"

init_ssh_tree() {
    local ssh_dir="$1"

    mkdir -p "$ssh_dir/sshd_config.d"

    cat > "$ssh_dir/sshd_config" <<'EOF'
Port 22
# Baseline config without Include for preflight coverage
EOF

    cat > "$ssh_dir/moduli" <<'EOF'
0 2 4 6 4096 8
EOF
}

export PATH="$MOCK_BIN:$PATH"
export KRATOSSH_TEST_OS_NAME="Ubuntu"
export KRATOSSH_TEST_OS_VERSION="22"

echo "Running CLI --fix test..."
SSH_ETC_DIR="$TMP_DIR/success/etc/ssh"
export SSH_ETC_DIR
unset KRATOSSH_TEST_FAIL_VALIDATE
init_ssh_tree "$SSH_ETC_DIR"

fix_output="$(bash "$REPO_DIR/KratoSSH.sh" --fix 2>&1)"
fix_status=$?

if [ "$fix_status" -ne 0 ]; then
    echo "$fix_output"
    echo "KratoSSH --fix should have succeeded"
    exit 1
fi

grep -Fq 'Include /etc/ssh/sshd_config.d/*.conf' "$SSH_ETC_DIR/sshd_config" || {
    echo "$fix_output"
    echo "Fix mode did not enable Include in sshd_config"
    exit 1
}

grep -Fq 'BEGIN KratoSSH Hardening' "$SSH_ETC_DIR/sshd_config.d/00-kratossh-hardening.conf" || {
    echo "$fix_output"
    echo "Fix mode did not write KratoSSH hardening drop-in"
    exit 1
}

[ -f "$SSH_ETC_DIR/ssh_host_rsa_key" ] || {
    echo "$fix_output"
    echo "Fix mode did not create RSA host key"
    exit 1
}

[ -f "$SSH_ETC_DIR/ssh_host_ed25519_key" ] || {
    echo "$fix_output"
    echo "Fix mode did not create ED25519 host key"
    exit 1
}

echo "$fix_output" | grep -Fq 'Auto-mode: Applying standard Crypto Hardening only.' || {
    echo "$fix_output"
    echo "Fix mode output missing auto-mode message"
    exit 1
}

echo "$fix_output" | grep -Fq 'Running PRE-HARDENING Audit...' || {
    echo "$fix_output"
    echo "Fix mode output missing pre-audit"
    exit 1
}

echo "$fix_output" | grep -Fq 'Running POST-HARDENING Audit...' || {
    echo "$fix_output"
    echo "Fix mode output missing post-audit"
    exit 1
}

echo "Running CLI --fix rollback test..."
SSH_ETC_DIR="$TMP_DIR/failure/etc/ssh"
export SSH_ETC_DIR
export KRATOSSH_TEST_FAIL_VALIDATE=true
init_ssh_tree "$SSH_ETC_DIR"

before_main="$(cat "$SSH_ETC_DIR/sshd_config")"

set +e
fix_fail_output="$(bash "$REPO_DIR/KratoSSH.sh" --fix 2>&1)"
fix_fail_status=$?
set -e

if [ "$fix_fail_status" -eq 0 ]; then
    echo "$fix_fail_output"
    echo "KratoSSH --fix should have failed when sshd validation is rejected"
    exit 1
fi

after_main="$(cat "$SSH_ETC_DIR/sshd_config")"

if [ "$before_main" != "$after_main" ]; then
    echo "$fix_fail_output"
    echo "Main sshd_config changed despite rollback on failed --fix"
    exit 1
fi

if [ -f "$SSH_ETC_DIR/sshd_config.d/00-kratossh-hardening.conf" ]; then
    echo "$fix_fail_output"
    echo "Hardening drop-in should not remain after failed --fix"
    exit 1
fi

echo "$fix_fail_output" | grep -Fq 'Crypto hardening failed for Ubuntu 22' || {
    echo "$fix_fail_output"
    echo "Failure output missing propagated crypto hardening error"
    exit 1
}

echo "Running CLI --fix restart failure test..."
SSH_ETC_DIR="$TMP_DIR/restart-failure/etc/ssh"
export SSH_ETC_DIR
unset KRATOSSH_TEST_FAIL_VALIDATE
export KRATOSSH_TEST_FAIL_RESTART=true
init_ssh_tree "$SSH_ETC_DIR"

set +e
fix_restart_output="$(bash "$REPO_DIR/KratoSSH.sh" --fix 2>&1)"
fix_restart_status=$?
set -e

if [ "$fix_restart_status" -eq 0 ]; then
    echo "$fix_restart_output"
    echo "KratoSSH --fix should have failed when SSH service restart fails"
    exit 1
fi

echo "$fix_restart_output" | grep -Fq 'Failed to restart SSH service with detected service manager.' || {
    echo "$fix_restart_output"
    echo "Restart failure output missing explicit service restart error"
    exit 1
}

echo "$fix_restart_output" | grep -Fq 'Crypto hardening failed for Ubuntu 22' || {
    echo "$fix_restart_output"
    echo "Restart failure output missing propagated crypto hardening error"
    exit 1
}

echo "CLI fix functional tests passed."