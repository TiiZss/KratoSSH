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
