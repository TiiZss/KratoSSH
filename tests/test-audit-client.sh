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

trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

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

# Mock powershell.exe: exits 2 (path missing) - fast deterministic tests
cat > "$MOCK_BIN/powershell.exe" <<'EOF'
#!/bin/bash
exit 2
EOF
chmod +x "$MOCK_BIN/powershell.exe"

export PATH="$MOCK_BIN:$PATH"
export HOME="$HOME_DIR"
export KRATOSSH_TEST_OS_NAME="Ubuntu"
export KRATOSSH_TEST_OS_VERSION="22"

echo "Running --audit-client OpenSSH success test..."
cat > "$HOME_DIR/.ssh/config" <<'EOF'
# BEGIN KratoSSH macOS hardening
Host *
    KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
    ForwardAgent no
    ForwardX11 no
    Compression no
    RekeyLimit 1G 60m
# END KratoSSH macOS hardening
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

echo "Running --audit-client non-strict missing-source test..."
# SecureCRT has no Windows registry fallback, so "source missing" is deterministic
set +e
missing_soft_output="$(bash "$REPO_DIR/KratoSSH.sh" --audit-client --client-app securecrt 2>&1)"
missing_soft_status=$?
set -e

if [ "$missing_soft_status" -ne 0 ]; then
    echo "$missing_soft_output"
    echo "Expected non-strict missing source to succeed"
    exit 1
fi

echo "Running --audit-client strict missing-source test..."
set +e
missing_strict_output="$(bash "$REPO_DIR/KratoSSH.sh" --audit-client --client-app securecrt --strict 2>&1)"
missing_strict_status=$?
set -e

if [ "$missing_strict_status" -eq 0 ]; then
    echo "$missing_strict_output"
    echo "Expected strict missing source to fail"
    exit 1
fi

echo "$missing_strict_output" | grep -Fq 'strict mode' || {
    echo "$missing_strict_output"
    echo "Expected strict mode message was not found"
    exit 1
}

echo "Running --audit-client all --strict test..."
set +e
all_strict_output="$(bash "$REPO_DIR/KratoSSH.sh" --audit-client --client-app all --strict 2>&1)"
all_strict_status=$?
set -e

if [ "$all_strict_status" -eq 0 ]; then
    echo "$all_strict_output"
    echo "Expected --audit-client all --strict to fail when sources are missing"
    exit 1
fi

# ── --json output mode test ──────────────────────────────────────────────────
echo "Running --audit-client --json output test..."

# Recreate .ssh dir — earlier subprocess tests may have removed it
mkdir -p "$HOME_DIR/.ssh"

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
json_output="$(bash "$REPO_DIR/KratoSSH.sh" --audit-client --client-app openssh --json 2>/dev/null)"
json_status=$?
set -e

if [ "$json_status" -ne 0 ]; then
    echo "$json_output"
    echo "Expected --audit-client --json to succeed on hardened openssh config"
    exit 1
fi

# Must start with '[' and end with ']'
if ! printf '%s' "$json_output" | grep -q '^\['; then
    echo "$json_output"
    echo "--json output does not start with '['"
    exit 1
fi

# Must contain at least one object with 'status':'pass'
if ! printf '%s' "$json_output" | grep -q '"status":"pass"'; then
    echo "$json_output"
    echo "--json output contains no pass entries"
    exit 1
fi

# Must contain 'client' field
if ! printf '%s' "$json_output" | grep -q '"client":"openssh"'; then
    echo "$json_output"
    echo "--json output missing client field 'openssh'"
    exit 1
fi

# Human-readable log must NOT appear in stdout when --json is active
if printf '%s' "$json_output" | grep -q '\[OK\]'; then
    echo "$json_output"
    echo "--json stdout contains human-readable [OK] log lines, expected clean JSON only"
    exit 1
fi

# ── --json fail case contains 'fail' status ──────────────────────────────────
echo "Running --audit-client --json fail status test..."

cat > "$HOME_DIR/.ssh/config" <<'EOF'
Host *
    KexAlgorithms curve25519-sha256
    Ciphers chacha20-poly1305@openssh.com
    MACs hmac-sha2-256-etm@openssh.com
    ForwardAgent yes
    ForwardX11 no
    Compression no
EOF

set +e
json_fail_output="$(bash "$REPO_DIR/KratoSSH.sh" --audit-client --client-app openssh --json 2>/dev/null)"
set -e

if ! printf '%s' "$json_fail_output" | grep -q '"status":"fail"'; then
    echo "$json_fail_output"
    echo "Expected at least one fail entry in JSON output for insecure ForwardAgent"
    exit 1
fi

# ── --json-pretty deterministic ordering test ────────────────────────────────
echo "Running --audit-client --json-pretty deterministic ordering test..."

# Ensure openssh checks are in a passing state before auditing all clients.
cat > "$HOME_DIR/.ssh/config" <<'EOF'
# BEGIN KratoSSH macOS hardening
Host *
    KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
    ForwardAgent no
    ForwardX11 no
    Compression no
    RekeyLimit 1G 60m
# END KratoSSH macOS hardening
EOF

set +e
pretty_all_1="$(bash "$REPO_DIR/KratoSSH.sh" --audit-client --client-app all --json-pretty 2>/dev/null)"
pretty_status_1=$?
pretty_all_2="$(bash "$REPO_DIR/KratoSSH.sh" --audit-client --client-app all --json-pretty 2>/dev/null)"
pretty_status_2=$?
set -e

if [ "$pretty_status_1" -ne 0 ] || [ "$pretty_status_2" -ne 0 ]; then
    echo "$pretty_all_1"
    echo "$pretty_all_2"
    echo "Expected --json-pretty all to succeed in non-strict mode"
    exit 1
fi

# Must be pretty (multi-line object list with indentation)
if ! printf '%s' "$pretty_all_1" | grep -q '^  {"client":'; then
    echo "$pretty_all_1"
    echo "--json-pretty output is not indented pretty JSON"
    exit 1
fi

# Must be deterministic between identical runs
if [ "$pretty_all_1" != "$pretty_all_2" ]; then
    echo "$pretty_all_1"
    echo "---"
    echo "$pretty_all_2"
    echo "--json-pretty output is not deterministic between runs"
    exit 1
fi

# Sorted by line: first client should be bitvise in current client set
first_client_line="$(printf '%s\n' "$pretty_all_1" | grep '"client":' | head -n 1)"
echo "$first_client_line" | grep -Fq '"client":"bitvise"' || {
    echo "$pretty_all_1"
    echo "--json-pretty output is not sorted deterministically"
    exit 1
}

# ── SecureCRT Windows path discovery test ────────────────────────────────────
echo "Running --audit-client SecureCRT Windows path discovery test..."

# Simulate a %APPDATA%\VanDyke\Config\Sessions directory with a hardened .ini
mkdir -p "$TMP_DIR/win_appdata/VanDyke/Config/Sessions"
cat > "$TMP_DIR/win_appdata/VanDyke/Config/Sessions/default.ini" <<'EOF'
Cipher List=ChaCha20-Poly1305
Forward Agent=00000000
EOF

# Mock powershell.exe: returns win path for ApplicationData, exit 2 otherwise
cat > "$MOCK_BIN/powershell.exe" <<ENDMOCK
#!/bin/bash
args="\$*"
if printf '%s' "\$args" | grep -q "ApplicationData"; then
    printf '%s\r\n' "${TMP_DIR}/win_appdata"
    exit 0
fi
exit 2
ENDMOCK
chmod +x "$MOCK_BIN/powershell.exe"

# Mock wslpath to convert win paths to the same TMP_DIR equivalents
cat > "$MOCK_BIN/wslpath" <<ENDWSL
#!/bin/bash
# Convert backslash path to forward slash, stripping drive
arg="\${*: -1}"
echo "\${arg//\\\\//}"
ENDWSL
chmod +x "$MOCK_BIN/wslpath"

set +e
scrt_output="$(bash "$REPO_DIR/KratoSSH.sh" --audit-client --client-app securecrt 2>&1)"
scrt_status=$?
set -e

if [ "$scrt_status" -ne 0 ]; then
    echo "$scrt_output"
    echo "Expected SecureCRT Windows path discovery to pass"
    exit 1
fi

# Restore fast mock powershell.exe for remaining tests
cat > "$MOCK_BIN/powershell.exe" <<'EOF'
#!/bin/bash
exit 2
EOF
chmod +x "$MOCK_BIN/powershell.exe"
rm -f "$MOCK_BIN/wslpath"

# ── Termius Windows path discovery test ──────────────────────────────────────
echo "Running --audit-client Termius Windows path discovery test..."

mkdir -p "$TMP_DIR/win_appdata/Termius"
cat > "$TMP_DIR/win_appdata/Termius/storage.json" <<'EOF'
{
  "hosts": [
    {
      "ciphers": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
      "forward_agent": false
    }
  ]
}
EOF

cat > "$MOCK_BIN/powershell.exe" <<ENDMOCK
#!/bin/bash
args="\$*"
if printf '%s' "\$args" | grep -q "ApplicationData"; then
    printf '%s\r\n' "${TMP_DIR}/win_appdata"
    exit 0
fi
if printf '%s' "\$args" | grep -q "LocalApplicationData"; then
    printf '%s\r\n' "${TMP_DIR}/win_localappdata"
    exit 0
fi
exit 2
ENDMOCK
chmod +x "$MOCK_BIN/powershell.exe"

cat > "$MOCK_BIN/wslpath" <<ENDWSL
#!/bin/bash
arg="\${*: -1}"
echo "\${arg//\\\\//}"
ENDWSL
chmod +x "$MOCK_BIN/wslpath"

set +e
termius_output="$(bash "$REPO_DIR/KratoSSH.sh" --audit-client --client-app termius 2>&1)"
termius_status=$?
set -e

if [ "$termius_status" -ne 0 ]; then
    echo "$termius_output"
    echo "Expected Termius Windows path discovery to pass"
    exit 1
fi

# Restore fast mocks
cat > "$MOCK_BIN/powershell.exe" <<'EOF'
#!/bin/bash
exit 2
EOF
chmod +x "$MOCK_BIN/powershell.exe"
rm -f "$MOCK_BIN/wslpath"

# ── --summary mode test ───────────────────────────────────────────────────────
echo "Running --audit-client --summary mode test..."

# Ensure openssh config is hardened for a pass result
mkdir -p "$HOME_DIR/.ssh"
cat > "$HOME_DIR/.ssh/config" <<'EOF'
# BEGIN KratoSSH macOS hardening
Host *
    KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
    ForwardAgent no
    ForwardX11 no
    Compression no
    RekeyLimit 1G 60m
# END KratoSSH macOS hardening
EOF

set +e
summary_output="$(bash "$REPO_DIR/KratoSSH.sh" --audit-client --client-app openssh --summary 2>&1)"
summary_status=$?
set -e

if [ "$summary_status" -ne 0 ]; then
    echo "$summary_output"
    echo "Expected --summary to succeed on hardened openssh config"
    exit 1
fi

if ! printf '%s' "$summary_output" | grep -q 'CLIENT'; then
    echo "$summary_output"
    echo "--summary output missing CLIENT header"
    exit 1
fi

if ! printf '%s' "$summary_output" | grep -q 'openssh'; then
    echo "$summary_output"
    echo "--summary output missing openssh row"
    exit 1
fi

echo "--audit-client tests passed."
