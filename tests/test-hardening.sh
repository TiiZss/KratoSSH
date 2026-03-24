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

exit 0
EOF

chmod +x "$MOCK_BIN/sshd"

cat > "$SSH_ETC_DIR/sshd_config" <<'EOF'
Port 22
# Baseline main config without Include
EOF

export PATH="$MOCK_BIN:$PATH"
export SSH_ETC_DIR
export DRY_RUN=false
export FAST_MODE=false
export FORCE_REGENERATE=false

# shellcheck source=../lib/utils.sh
source "$REPO_DIR/lib/utils.sh"
# shellcheck source=../lib/hardening.sh
source "$REPO_DIR/lib/hardening.sh"

echo "Running apply_atomic_sshd_config success case..."
apply_atomic_sshd_config $'Ciphers chacha20-poly1305@openssh.com\nMACs hmac-sha2-256-etm@openssh.com' "KratoSSH Hardening"

grep -Fq 'Include /etc/ssh/sshd_config.d/*.conf' "$SSH_ETC_DIR/sshd_config" || {
    echo "Include directive was not added to main sshd_config"
    exit 1
}

grep -Fq 'BEGIN KratoSSH Hardening' "$SSH_ETC_DIR/sshd_config.d/00-kratossh-hardening.conf" || {
    echo "Hardening block was not written to drop-in config"
    exit 1
}

echo "Running apply_atomic_sshd_config rollback case..."
before_main="$(cat "$SSH_ETC_DIR/sshd_config")"
before_dropin="$(cat "$SSH_ETC_DIR/sshd_config.d/00-kratossh-hardening.conf")"

set +e
apply_atomic_sshd_config $'INVALID yes' "KratoSSH Hardening"
status=$?
set -e

if [ "$status" -eq 0 ]; then
    echo "apply_atomic_sshd_config should have failed for invalid config"
    exit 1
fi

after_main="$(cat "$SSH_ETC_DIR/sshd_config")"
after_dropin="$(cat "$SSH_ETC_DIR/sshd_config.d/00-kratossh-hardening.conf")"

if [ "$before_main" != "$after_main" ]; then
    echo "Main config changed after rollback failure"
    exit 1
fi

if [ "$before_dropin" != "$after_dropin" ]; then
    echo "Drop-in config changed after rollback failure"
    exit 1
fi

echo "apply_atomic_sshd_config functional tests passed."