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

grep -Fq 'AgentFwd=0' "$HOME_DIR/.putty/sessions/default-session" || {
    echo "$putty_output"
    echo "PuTTY session AgentFwd was not disabled"
    exit 1
}

grep -Fq 'X11Forward=0' "$HOME_DIR/.putty/sessions/default-session" || {
    echo "$putty_output"
    echo "PuTTY session X11Forward was not disabled"
    exit 1
}

grep -Fq 'RekeyBytes=1g' "$HOME_DIR/.putty/sessions/default-session" || {
    echo "$putty_output"
    echo "PuTTY session RekeyBytes was not set"
    exit 1
}

grep -Fq 'RekeyTime=60' "$HOME_DIR/.putty/sessions/default-session" || {
    echo "$putty_output"
    echo "PuTTY session RekeyTime was not set"
    exit 1
}

grep -Fq 'Compression=0' "$HOME_DIR/.putty/sessions/default-session" || {
    echo "$putty_output"
    echo "PuTTY session Compression was not disabled"
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

# ── macOS SSH config hardening test ──────────────────────────────────────────
echo "Running macOS SSH config hardening test..."

# Fake uname so apply_macos_ssh_hardening thinks it's on Darwin
cat > "$MOCK_BIN/uname" <<'EOF'
#!/bin/bash
if [ "$1" = "-s" ]; then
    echo Darwin
    exit 0
fi
uname_real=$(command -v uname)
"$uname_real" "$@"
EOF
chmod +x "$MOCK_BIN/uname"

mkdir -p "$HOME_DIR/.ssh"

macos_output="$(HOME="$HOME_DIR" bash "$REPO_DIR/KratoSSH.sh" --auto --type client --client-app macos-ssh 2>&1)"
macos_status=$?

if [ "$macos_status" -ne 0 ]; then
    echo "$macos_output"
    echo "macOS SSH hardening should have succeeded"
    exit 1
fi

grep -Fq 'KexAlgorithms' "$HOME_DIR/.ssh/config" || {
    echo "$macos_output"
    echo "macOS ssh config missing KexAlgorithms block"
    exit 1
}

grep -Fq 'ForwardAgent no' "$HOME_DIR/.ssh/config" || {
    echo "$macos_output"
    echo "macOS ssh config does not disable ForwardAgent"
    exit 1
}

grep -Fq 'RekeyLimit 1G 60m' "$HOME_DIR/.ssh/config" || {
    echo "$macos_output"
    echo "macOS ssh config missing RekeyLimit"
    exit 1
}

# Idempotency: running again must not duplicate the block
HOME="$HOME_DIR" bash "$REPO_DIR/KratoSSH.sh" --auto --type client --client-app macos-ssh > /dev/null 2>&1 || true
block_count="$(grep -c 'BEGIN KratoSSH macOS hardening' "$HOME_DIR/.ssh/config" || true)"
if [ "$block_count" -ne 1 ]; then
    echo "macOS SSH config idempotency failed: found $block_count KratoSSH blocks (expected 1)"
    exit 1
fi

# ── SecureCRT Linux INI session test ─────────────────────────────────────────
echo "Running SecureCRT Linux client hardening test..."

mkdir -p "$HOME_DIR/.vandyke/SecureCRT/Config/Sessions"
cat > "$HOME_DIR/.vandyke/SecureCRT/Config/Sessions/myserver.ini" <<'EOF'
Cipher List=3des
Forward Agent=ffffffff
EOF

securecrt_output="$(HOME="$HOME_DIR" bash "$REPO_DIR/KratoSSH.sh" --auto --type client --client-app securecrt 2>&1)"
securecrt_status=$?

if [ "$securecrt_status" -ne 0 ]; then
    echo "$securecrt_output"
    echo "SecureCRT Linux client hardening should have succeeded"
    exit 1
fi

grep -Fq 'ChaCha20-Poly1305' "$HOME_DIR/.vandyke/SecureCRT/Config/Sessions/myserver.ini" || {
    echo "$securecrt_output"
    echo "SecureCRT session Cipher List was not updated"
    exit 1
}

grep -Fq 'Forward Agent=00000000' "$HOME_DIR/.vandyke/SecureCRT/Config/Sessions/myserver.ini" || {
    echo "$securecrt_output"
    echo "SecureCRT session Forward Agent was not disabled"
    exit 1
}

# ── SecureCRT Windows/WSL fallback test ──────────────────────────────────────
echo "Running SecureCRT Windows fallback test..."

# Remove the Linux session dir so the Windows path is taken
rm -rf "$HOME_DIR/.vandyke"

securecrt_win_output="$(HOME="$HOME_DIR" bash "$REPO_DIR/KratoSSH.sh" --auto --type client --client-app securecrt 2>&1)"
securecrt_win_status=$?

if [ "$securecrt_win_status" -ne 0 ]; then
    echo "$securecrt_win_output"
    echo "SecureCRT Windows fallback should have succeeded"
    exit 1
fi

echo "$securecrt_win_output" | grep -Fq 'windows/securecrt_hardening.ps1' || {
    echo "$securecrt_win_output"
    echo "SecureCRT Windows fallback did not call securecrt_hardening.ps1"
    exit 1
}

# ── WinSCP Linux INI test ────────────────────────────────────────────────
echo "Running WinSCP Linux INI client hardening test..."

mkdir -p "$HOME_DIR/.config"
cat > "$HOME_DIR/.config/winscp.ini" <<'EOF'
[Configuration]
[Sessions\myserver]
HostName=192.0.2.1

EOF

winscp_output="$(HOME="$HOME_DIR" bash "$REPO_DIR/KratoSSH.sh" --auto --type client --client-app winscp 2>&1)"
winscp_status=$?

if [ "$winscp_status" -ne 0 ]; then
    echo "$winscp_output"
    echo "WinSCP Linux client hardening should have succeeded"
    exit 1
fi

grep -Fq 'KexList=ecdh' "$HOME_DIR/.config/winscp.ini" || {
    echo "$winscp_output"
    echo "WinSCP INI KexList was not set"
    exit 1
}

grep -Fq 'AgentFwd=0' "$HOME_DIR/.config/winscp.ini" || {
    echo "$winscp_output"
    echo "WinSCP INI AgentFwd was not disabled"
    exit 1
}

# ── WinSCP Windows fallback test ────────────────────────────────────────────
echo "Running WinSCP Windows fallback test..."

rm -f "$HOME_DIR/.config/winscp.ini"

winscp_win_output="$(HOME="$HOME_DIR" bash "$REPO_DIR/KratoSSH.sh" --auto --type client --client-app winscp 2>&1)"
winscp_win_status=$?

if [ "$winscp_win_status" -ne 0 ]; then
    echo "$winscp_win_output"
    echo "WinSCP Windows fallback should have succeeded"
    exit 1
fi

echo "$winscp_win_output" | grep -Fq 'windows/winscp_hardening.ps1' || {
    echo "$winscp_win_output"
    echo "WinSCP Windows fallback did not call winscp_hardening.ps1"
    exit 1
}

# ── Termius Linux JSON test ────────────────────────────────────────────────
echo "Running Termius Linux JSON client hardening test..."

mkdir -p "$HOME_DIR/.config/Termius"
cat > "$HOME_DIR/.config/Termius/storage.json" <<'EOF'
{"hosts":[{"id":"aaa","label":"myserver","address":"192.0.2.1"}],"groups":[]}
EOF

termius_output="$(HOME="$HOME_DIR" bash "$REPO_DIR/KratoSSH.sh" --auto --type client --client-app termius 2>&1)"
termius_status=$?

if [ "$termius_status" -ne 0 ]; then
    echo "$termius_output"
    echo "Termius Linux client hardening should have succeeded"
    exit 1
fi

grep -Fq 'chacha20-poly1305' "$HOME_DIR/.config/Termius/storage.json" || {
    echo "$termius_output"
    echo "Termius storage.json cipher was not updated"
    exit 1
}

grep -Fq '"forward_agent": false' "$HOME_DIR/.config/Termius/storage.json" || {
    echo "$termius_output"
    echo "Termius storage.json forward_agent was not disabled"
    exit 1
}

# ── Termius Windows fallback test ───────────────────────────────────────────
echo "Running Termius Windows fallback test..."

rm -f "$HOME_DIR/.config/Termius/storage.json"

termius_win_output="$(HOME="$HOME_DIR" bash "$REPO_DIR/KratoSSH.sh" --auto --type client --client-app termius 2>&1)"
termius_win_status=$?

if [ "$termius_win_status" -ne 0 ]; then
    echo "$termius_win_output"
    echo "Termius Windows fallback should have succeeded"
    exit 1
fi

echo "$termius_win_output" | grep -Fq 'windows/termius_hardening.ps1' || {
    echo "$termius_win_output"
    echo "Termius Windows fallback did not call termius_hardening.ps1"
    exit 1
}

echo "Third-party client hardening tests passed."
