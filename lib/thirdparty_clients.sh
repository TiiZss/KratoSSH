#!/bin/bash

#--------------------------------------------------------------------------------
# Third-party SSH Client Hardening (PuTTY / Bitvise)
#--------------------------------------------------------------------------------

function _run_windows_hardening_script() {
    local script_path="$1"

    if ! command -v powershell.exe >/dev/null 2>&1; then
        log_warn "powershell.exe not found. Windows client hardening is only available from Windows/WSL environments."
        return 1
    fi

    if [ ! -f "$script_path" ]; then
        log_error "Windows hardening script not found: $script_path"
        return 1
    fi

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would execute powershell.exe -File $script_path"
        return 0
    fi

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$script_path"
}

function _ensure_kv_setting() {
    local file="$1"
    local key="$2"
    local value="$3"

    if grep -q "^${key}=" "$file" 2>/dev/null; then
        # Use # delimiter to avoid escaping commas and slashes in values.
        sed -i "s#^${key}=.*#${key}=${value}#" "$file"
    else
        printf '%s=%s\n' "$key" "$value" >> "$file"
    fi
}

function apply_putty_hardening() {
    local script_dir="$1"
    local putty_dir="$HOME/.putty/sessions"

    # Linux and macOS PuTTY sessions (Homebrew on macOS uses the same ~/.putty/sessions/ path)
    if [ -d "$putty_dir" ]; then
        local platform="Linux"
        if [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
            platform="macOS"
        fi
        log_info "Detected $platform PuTTY sessions at $putty_dir"

        if [ "$DRY_RUN" = true ]; then
            log_info "[DRY-RUN] Would harden PuTTY session files under $putty_dir"
            return 0
        fi

        local backup_dir="$putty_dir/backup_kratossh_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$backup_dir"
        cp -a "$putty_dir"/* "$backup_dir"/ 2>/dev/null || true

        local session_file
        local hardened=0
        for session_file in "$putty_dir"/*; do
            [ -f "$session_file" ] || continue
            # Algorithm preferences
            _ensure_kv_setting "$session_file" "Cipher"      "chacha20,aes,blowfish,3des,WARN"
            _ensure_kv_setting "$session_file" "KEX"         "ecdh,dh-gex-sha256,dh-group14-sha1,rsa,WARN"
            _ensure_kv_setting "$session_file" "HostKey"     "ed25519,ecdsa,rsa,dsa,WARN"
            # Per-session security settings (mirrors windows/putty_hardening.ps1)
            _ensure_kv_setting "$session_file" "AgentFwd"    "0"
            _ensure_kv_setting "$session_file" "X11Forward"  "0"
            _ensure_kv_setting "$session_file" "Compression" "0"
            _ensure_kv_setting "$session_file" "RekeyBytes"  "1g"
            _ensure_kv_setting "$session_file" "RekeyTime"   "60"
            hardened=$((hardened + 1))
        done

        if [ "$hardened" -eq 0 ]; then
            log_warn "No PuTTY session files were found to harden."
        else
            log_success "Hardened $hardened PuTTY session file(s) ($platform, algorithms + per-session settings). Backup: $backup_dir"
        fi
        return 0
    fi

    # Windows/WSL PuTTY sessions
    _run_windows_hardening_script "$script_dir/windows/putty_hardening.ps1"
}

function apply_bitvise_hardening() {
    local script_dir="$1"

    # Bitvise is Windows-first; run PowerShell profile hardening when available.
    _run_windows_hardening_script "$script_dir/windows/bitvise_hardening.ps1"
}

function apply_macos_ssh_hardening() {
    local ssh_config="$HOME/.ssh/config"
    local ssh_dir="$HOME/.ssh"

    if [ "$(uname -s 2>/dev/null)" != "Darwin" ]; then
        log_warn "apply_macos_ssh_hardening called on a non-Darwin system. Skipping."
        return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would write macOS SSH client config at $ssh_config"
        return 0
    fi

    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"

    # Backup existing config
    if [ -f "$ssh_config" ]; then
        local backup="${ssh_config}.kratossh_$(date +%Y%m%d_%H%M%S).bak"
        cp "$ssh_config" "$backup"
        log_info "Backed up $ssh_config to $backup"
    fi

    # Write a KratoSSH block. If the file already has a KratoSSH block, replace it.
    local block_start='# BEGIN KratoSSH macOS hardening'
    local block_end='# END KratoSSH macOS hardening'

    local tmp
    tmp="$(mktemp)"

    if [ -f "$ssh_config" ] && grep -q "$block_start" "$ssh_config"; then
        # Remove old block
        awk "
            /^${block_start}$/ { skip=1 }
            !skip { print }
            /^${block_end}$/ { skip=0 }
        " "$ssh_config" > "$tmp"
    elif [ -f "$ssh_config" ]; then
        cp "$ssh_config" "$tmp"
    else
        touch "$tmp"
    fi

    cat >> "$tmp" <<'SSHBLOCK'
# BEGIN KratoSSH macOS hardening
Host *
    KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
    MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
    HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
    PubkeyAcceptedKeyTypes ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
    ForwardAgent no
    ForwardX11 no
    Compression no
    ServerAliveInterval 120
    ServerAliveCountMax 3
    RekeyLimit 1G 60m
# END KratoSSH macOS hardening
SSHBLOCK

    mv "$tmp" "$ssh_config"
    chmod 600 "$ssh_config"
    log_success "macOS SSH client config hardened at $ssh_config"
}

function apply_securecrt_hardening() {
    local script_dir="$1"

    # On Linux/macOS: patch INI-style session files under ~/.vandyke/SecureCRT/Config/Sessions/
    local session_dir="$HOME/.vandyke/SecureCRT/Config/Sessions"
    if [ -d "$session_dir" ]; then
        log_info "Detected SecureCRT session files at $session_dir"

        if [ "$DRY_RUN" = true ]; then
            log_info "[DRY-RUN] Would harden SecureCRT session files under $session_dir"
            return 0
        fi

        local backup_dir="$session_dir/backup_kratossh_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$backup_dir"
        cp -r "$session_dir"/*.ini "$backup_dir"/ 2>/dev/null || true

        local session_file
        local hardened=0
        for session_file in "$session_dir"/*.ini; do
            [ -f "$session_file" ] || continue
            _ensure_kv_setting "$session_file" "Cipher List" "ChaCha20-Poly1305,AES-256-GCM,AES-128-GCM,AES-256-CTR,AES-192-CTR,AES-128-CTR"
            _ensure_kv_setting "$session_file" "MAC List" "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com"
            _ensure_kv_setting "$session_file" "Kex List" "curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256"
            _ensure_kv_setting "$session_file" "Host Key List" "ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
            _ensure_kv_setting "$session_file" "Forward Agent" "00000000"
            _ensure_kv_setting "$session_file" "Forward X11" "00000000"
            hardened=$((hardened + 1))
        done

        if [ "$hardened" -eq 0 ]; then
            log_warn "No SecureCRT .ini session files were found to harden."
        else
            log_success "Hardened $hardened SecureCRT session file(s). Backup: $backup_dir"
        fi
        return 0
    fi

    # On Windows/WSL: use PowerShell to patch registry and .ini profiles
    _run_windows_hardening_script "$script_dir/windows/securecrt_hardening.ps1"
}

function apply_winscp_hardening() {
    local script_dir="$1"

    # Linux/macOS: patch the portable winscp.ini if present
    local ini_candidates=(
        "$HOME/.config/winscp.ini"
        "$HOME/.local/share/winscp.ini"
    )

    local ini_path
    for ini_path in "${ini_candidates[@]}"; do
        [ -f "$ini_path" ] || continue

        log_info "Detected WinSCP INI at $ini_path"

        if [ "$DRY_RUN" = true ]; then
            log_info "[DRY-RUN] Would harden WinSCP INI at $ini_path"
            return 0
        fi

        local backup="${ini_path}.kratossh_$(date +%Y%m%d_%H%M%S).bak"
        cp "$ini_path" "$backup"
        log_info "Backed up $ini_path to $backup"

        # Process each [Sessions\<name>] section: patch or append algorithm keys
        local tmp
        tmp="$(mktemp)"
        local in_session=0
        local session_keys_done=0

        while IFS= read -r line; do
            if [[ "$line" =~ ^\[Sessions\\ ]]; then
                in_session=1
                session_keys_done=0
                printf '%s\n' "$line" >> "$tmp"
                continue
            fi
            if [[ "$line" =~ ^\[ ]] && [[ ! "$line" =~ ^\[Sessions\\ ]]; then
                in_session=0
            fi

            if [ "$in_session" -eq 1 ]; then
                # Skip existing algorithm lines (will be re-appended at end of section)
                if [[ "$line" =~ ^(KexList|CipherList|MacList|HostKeyList|AgentFwd)= ]]; then
                    continue
                fi
                # At blank line ending a section, inject hardened values first
                if [ -z "$line" ] && [ "$session_keys_done" -eq 0 ]; then
                    printf 'KexList=ecdh,dh-gex-sha256,dh-group16-sha512,dh-group18-sha512\n' >> "$tmp"
                    printf 'CipherList=chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr\n' >> "$tmp"
                    printf 'MacList=hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com\n' >> "$tmp"
                    printf 'HostKeyList=ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n' >> "$tmp"
                    printf 'AgentFwd=0\n' >> "$tmp"
                    session_keys_done=1
                fi
            fi
            printf '%s\n' "$line" >> "$tmp"
        done < "$ini_path"

        mv "$tmp" "$ini_path"
        log_success "WinSCP INI hardened at $ini_path"
        return 0
    done

    # Windows/WSL: registry + portable INI via PowerShell
    _run_windows_hardening_script "$script_dir/windows/winscp_hardening.ps1"
}

function apply_termius_hardening() {
    local script_dir="$1"

    # Linux/macOS: patch the Termius storage.json vault directly
    local storage_candidates=(
        "$HOME/.config/Termius/storage.json"
        "$HOME/.termius/storage.json"
        "$HOME/Library/Application Support/Termius/storage.json"
    )

    local storage_path
    for storage_path in "${storage_candidates[@]}"; do
        [ -f "$storage_path" ] || continue

        log_info "Detected Termius storage at $storage_path"

        if [ "$DRY_RUN" = true ]; then
            log_info "[DRY-RUN] Would harden Termius storage at $storage_path"
            return 0
        fi

        if ! command -v python3 >/dev/null 2>&1; then
            log_error "python3 is required to patch Termius storage.json but was not found."
            return 1
        fi

        local backup="${storage_path}.kratossh_$(date +%Y%m%d_%H%M%S).bak"
        cp "$storage_path" "$backup"
        log_info "Backed up $storage_path to $backup"

        python3 - "$storage_path" <<'PYEOF'
import sys, json

path = sys.argv[1]
with open(path, encoding='utf-8') as f:
    vault = json.load(f)

kex    = 'curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512'
cipher = 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr'
mac    = 'hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com'
hostkey = 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256'

patched = 0
for key in ('hosts', 'groups'):
    for node in vault.get(key, []):
        cfg = node.setdefault('ssh_config', {})
        cfg['kex_algorithms']     = kex
        cfg['ciphers']            = cipher
        cfg['macs']               = mac
        cfg['host_key_algorithms']= hostkey
        cfg['forward_agent']      = False
        cfg['forward_x11']        = False
        patched += 1

with open(path, 'w', encoding='utf-8') as f:
    json.dump(vault, f, indent=2, ensure_ascii=False)

print(f'[KratoSSH] Patched {patched} Termius node(s) in {path}')
PYEOF
        log_success "Termius storage hardened at $storage_path"
        return 0
    done

    # Windows/WSL: PowerShell JSON patch
    _run_windows_hardening_script "$script_dir/windows/termius_hardening.ps1"
}
