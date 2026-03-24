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
