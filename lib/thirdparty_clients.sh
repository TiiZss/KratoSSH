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

function apply_mobaxterm_hardening() {
    local script_dir="$1"

    # Linux/macOS: patch MobaXterm.ini if present in standard locations
    local ini_candidates=(
        "$HOME/.config/MobaXterm/MobaXterm.ini"
        "$HOME/.MobaXterm/MobaXterm.ini"
    )

    local ini_path
    for ini_path in "${ini_candidates[@]}"; do
        [ -f "$ini_path" ] || continue

        log_info "Detected MobaXterm INI at $ini_path"

        if [ "$DRY_RUN" = true ]; then
            log_info "[DRY-RUN] Would harden MobaXterm INI at $ini_path"
            return 0
        fi

        local backup="${ini_path}.kratossh_$(date +%Y%m%d_%H%M%S).bak"
        cp "$ini_path" "$backup"
        log_info "Backed up $ini_path to $backup"

        # Process [SSH*] sections: patch SSH_Kex, SSH_Cipher, SSH_MAC,
        # SSH_HostKey, SSH_AgentFwd
        local tmp
        tmp="$(mktemp)"
        local in_ssh=0

        while IFS= read -r line; do
            if [[ "$line" =~ ^\[SSH ]]; then
                in_ssh=1
                printf '%s\n' "$line" >> "$tmp"
                continue
            fi
            if [[ "$line" =~ ^\[ ]] && [[ ! "$line" =~ ^\[SSH ]]; then
                in_ssh=0
            fi

            if [ "$in_ssh" -eq 1 ]; then
                if [[ "$line" =~ ^SSH_Kex= ]]; then
                    printf 'SSH_Kex=curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n' >> "$tmp"
                    continue
                fi
                if [[ "$line" =~ ^SSH_Cipher= ]]; then
                    printf 'SSH_Cipher=chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr\n' >> "$tmp"
                    continue
                fi
                if [[ "$line" =~ ^SSH_MAC= ]]; then
                    printf 'SSH_MAC=hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com\n' >> "$tmp"
                    continue
                fi
                if [[ "$line" =~ ^SSH_HostKey= ]]; then
                    printf 'SSH_HostKey=ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n' >> "$tmp"
                    continue
                fi
                if [[ "$line" =~ ^SSH_AgentFwd= ]]; then
                    printf 'SSH_AgentFwd=0\n' >> "$tmp"
                    continue
                fi
            fi
            printf '%s\n' "$line" >> "$tmp"
        done < "$ini_path"

        mv "$tmp" "$ini_path"
        log_success "MobaXterm INI hardened at $ini_path"
        return 0
    done

    # Windows/WSL: PowerShell INI patcher
    _run_windows_hardening_script "$script_dir/windows/mobaxterm_hardening.ps1"
}

# Returns a sorted space-separated list of all supported --client-app values
function list_supported_clients() {
    printf 'bitvise macos-ssh mobaxterm openssh putty securecrt termius winscp\n'
}

function _audit_expect_grep() {
    local file="$1"
    local pattern="$2"
    local label="$3"

    if grep -Eiq "$pattern" "$file"; then
        log_success "[AUDIT] $label"
        _audit_json_record "$label" "pass"
        return 0
    fi

    log_error "[AUDIT] $label missing or insecure"
    _audit_json_record "$label" "fail"
    return 1
}

function _audit_missing_source() {
    local message="$1"
    if [ "${AUDIT_CLIENT_STRICT:-false}" = true ]; then
        log_error "[AUDIT] $message (strict mode)"
        _audit_json_record "$message" "fail"
        return 1
    fi
    log_warn "[AUDIT] $message"
    _audit_json_record "$message" "warn"
    return 0
}

function _audit_json_record() {
    local label="$1"
    local status="$2"  # pass | fail | warn
    [ "${AUDIT_JSON:-false}" = true ] || return 0
    [ -n "${_AUDIT_JSON_TMP:-}" ] || return 0
    local clean_label="${label//\"/\\\"}"
    local clean_client="${_AUDIT_CURRENT_CLIENT:-unknown}"
    printf '{"client":"%s","check":"%s","status":"%s"}\n' \
        "$clean_client" "$clean_label" "$status" >> "$_AUDIT_JSON_TMP"
}

function _audit_windows_registry_any_match() {
    local path="$1"
    local value_name="$2"
    local pattern="$3"
    local label="$4"

    if ! command -v powershell.exe >/dev/null 2>&1; then
        _audit_missing_source "Windows registry unavailable for $label (powershell.exe not found)"
        return $?
    fi

    # Exit codes: 0=match found, 1=no match, 2=path missing
    local ps_status
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \
        "$p='$path'; if(-not (Test-Path $p)){exit 2}; $ok=$false; Get-ChildItem -Path $p -ErrorAction SilentlyContinue | ForEach-Object { $v=(Get-ItemProperty -Path $_.PSPath -Name '$value_name' -ErrorAction SilentlyContinue).$value_name; if($v -and ($v -match '$pattern')) { $ok=$true } }; if($ok){exit 0}else{exit 1}" \
        >/dev/null 2>&1
    ps_status=$?

    if [ "$ps_status" -eq 0 ]; then
        log_success "[AUDIT] $label"
        _audit_json_record "$label" "pass"
        return 0
    fi

    if [ "$ps_status" -eq 2 ]; then
        _audit_missing_source "Windows registry path not found for $label ($path)"
        return $?
    fi

    log_error "[AUDIT] $label missing or insecure"
    _audit_json_record "$label" "fail"
    return 1
}

function _audit_windows_registry_value_match() {
    local path="$1"
    local value_name="$2"
    local pattern="$3"
    local label="$4"

    if ! command -v powershell.exe >/dev/null 2>&1; then
        _audit_missing_source "Windows registry unavailable for $label (powershell.exe not found)"
        return $?
    fi

    local ps_status
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \
        "$p='$path'; if(-not (Test-Path $p)){exit 2}; $v=(Get-ItemProperty -Path $p -Name '$value_name' -ErrorAction SilentlyContinue).$value_name; if($v -and ($v -match '$pattern')){exit 0}else{exit 1}" \
        >/dev/null 2>&1
    ps_status=$?

    if [ "$ps_status" -eq 0 ]; then
        log_success "[AUDIT] $label"
        _audit_json_record "$label" "pass"
        return 0
    fi

    if [ "$ps_status" -eq 2 ]; then
        _audit_missing_source "Windows registry path not found for $label ($path)"
        return $?
    fi

    log_error "[AUDIT] $label missing or insecure"
    _audit_json_record "$label" "fail"
    return 1
}

function audit_client_openssh() {
    local cfg="$HOME/.ssh/config"
    local fail=0

    if [ ! -f "$cfg" ]; then
        log_error "[AUDIT] OpenSSH client config not found at $cfg"
        return 1
    fi

    _audit_expect_grep "$cfg" '^[[:space:]]*KexAlgorithms[[:space:]].*curve25519-sha256' 'OpenSSH KexAlgorithms' || fail=1
    _audit_expect_grep "$cfg" '^[[:space:]]*Ciphers[[:space:]].*(chacha20-poly1305@openssh.com|aes256-gcm@openssh.com)' 'OpenSSH Ciphers' || fail=1
    _audit_expect_grep "$cfg" '^[[:space:]]*MACs[[:space:]].*hmac-sha2-256-etm@openssh.com' 'OpenSSH MACs' || fail=1
    _audit_expect_grep "$cfg" '^[[:space:]]*ForwardAgent[[:space:]]+no' 'OpenSSH ForwardAgent no' || fail=1
    _audit_expect_grep "$cfg" '^[[:space:]]*ForwardX11[[:space:]]+no' 'OpenSSH ForwardX11 no' || fail=1
    _audit_expect_grep "$cfg" '^[[:space:]]*Compression[[:space:]]+no' 'OpenSSH Compression no' || fail=1

    return $fail
}

# Checks one property across ALL PuTTY registry sessions.
# $1=registry base path  $2=property name  $3=regex pattern  $4=label
# Returns 0=all match, 1=some fail, 2=path missing, 3=no sessions
function _audit_putty_reg_prop() {
    local reg="$1" prop="$2" pattern="$3" label="$4"
    local ps_status
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \
        "\$p='$reg'; if(-not(Test-Path \$p)){exit 2}; \$s=@(Get-ChildItem -Path \$p -EA SilentlyContinue); if(\$s.Count -eq 0){exit 3}; \$ok=\$true; \$s|ForEach-Object{\$v=(Get-ItemProperty -Path \$_.PSPath -Name '$prop' -EA SilentlyContinue).$prop; if(-not(\$v -match '$pattern')){\$ok=\$false}}; if(\$ok){exit 0}else{exit 1}" \
        >/dev/null 2>&1
    ps_status=$?
    case "$ps_status" in
        0) log_success "[AUDIT] $label (all sessions)"; _audit_json_record "$label (all sessions)" "pass"; return 0 ;;
        2) _audit_missing_source "PuTTY registry path not found ($reg)"; return $? ;;
        3) log_warn "[AUDIT] No PuTTY registry sessions found"; _audit_json_record "$label" "warn"; return 0 ;;
        *) log_error "[AUDIT] $label missing or insecure"; _audit_json_record "$label (all sessions)" "fail"; return 1 ;;
    esac
}

function audit_client_putty() {
    local dir="$HOME/.putty/sessions"
    local fail=0
    local count=0
    local file

    if [ ! -d "$dir" ]; then
        # Windows/WSL: check HKCU registry sessions
        if command -v powershell.exe >/dev/null 2>&1; then
            local putty_reg='HKCU:\Software\SimonTatham\PuTTY\Sessions'
            _audit_putty_reg_prop "$putty_reg" 'Cipher' 'chacha20|aes' 'PuTTY registry Cipher' || fail=1
            _audit_putty_reg_prop "$putty_reg" 'KEX' 'ecdh' 'PuTTY registry KEX' || fail=1
            _audit_putty_reg_prop "$putty_reg" 'AgentFwd' '^0$' 'PuTTY registry AgentFwd=0' || fail=1
            return $fail
        fi
        _audit_missing_source "PuTTY sessions not found at $dir and Windows registry unavailable"
        return $?
    fi

    for file in "$dir"/*; do
        [ -f "$file" ] || continue
        count=$((count + 1))
        _audit_expect_grep "$file" '^Cipher=chacha20,aes,blowfish,3des,WARN$' "PuTTY Cipher ($file)" || fail=1
        _audit_expect_grep "$file" '^KEX=ecdh,dh-gex-sha256,dh-group14-sha1,rsa,WARN$' "PuTTY KEX ($file)" || fail=1
        _audit_expect_grep "$file" '^HostKey=ed25519,ecdsa,rsa,dsa,WARN$' "PuTTY HostKey ($file)" || fail=1
        _audit_expect_grep "$file" '^AgentFwd=0$' "PuTTY AgentFwd=0 ($file)" || fail=1
    done

    if [ "$count" -eq 0 ]; then
        log_warn "[AUDIT] No PuTTY session files found under $dir"
        return 0
    fi

    return $fail
}

function audit_client_macos_ssh() {
    local cfg="$HOME/.ssh/config"
    local fail=0

    if [ ! -f "$cfg" ]; then
        log_error "[AUDIT] macOS SSH config not found at $cfg"
        return 1
    fi

    _audit_expect_grep "$cfg" '^# BEGIN KratoSSH macOS hardening$' 'macOS SSH KratoSSH block present' || fail=1
    _audit_expect_grep "$cfg" '^[[:space:]]*RekeyLimit[[:space:]]+1G[[:space:]]+60m' 'macOS SSH RekeyLimit 1G 60m' || fail=1
    _audit_expect_grep "$cfg" '^[[:space:]]*ForwardAgent[[:space:]]+no' 'macOS SSH ForwardAgent no' || fail=1

    return $fail
}

function audit_client_securecrt() {
    local dir="$HOME/.vandyke/SecureCRT/Config/Sessions"
    local file
    local fail=0
    local count=0

    if [ ! -d "$dir" ]; then
        _audit_missing_source "SecureCRT sessions not found at $dir"
        return $?
    fi

    for file in "$dir"/*.ini; do
        [ -f "$file" ] || continue
        count=$((count + 1))
        _audit_expect_grep "$file" '^Cipher List=ChaCha20-Poly1305' "SecureCRT Cipher List ($file)" || fail=1
        _audit_expect_grep "$file" '^Forward Agent=00000000$' "SecureCRT Forward Agent disabled ($file)" || fail=1
    done

    if [ "$count" -eq 0 ]; then
        log_warn "[AUDIT] No SecureCRT .ini session files found under $dir"
        return 0
    fi

    return $fail
}

function audit_client_winscp() {
    local file="$HOME/.config/winscp.ini"
    local fail=0

    if [ -f "$file" ]; then
        _audit_expect_grep "$file" '^KexList=ecdh' 'WinSCP KexList present' || fail=1
        _audit_expect_grep "$file" '^AgentFwd=0$' 'WinSCP AgentFwd=0' || fail=1
        return $fail
    fi

    # Windows registry-read fallback
    _audit_windows_registry_any_match 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions' 'KexList' 'ecdh|curve25519' 'WinSCP registry KexList' || fail=1
    _audit_windows_registry_any_match 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions' 'AgentFwd' '^0$' 'WinSCP registry AgentFwd=0' || fail=1
    return $fail
}

function audit_client_termius() {
    local file="$HOME/.config/Termius/storage.json"
    local fail=0

    if [ ! -f "$file" ]; then
        _audit_missing_source "Termius storage not found at $file"
        return $?
    fi

    _audit_expect_grep "$file" '"ciphers"[[:space:]]*:[[:space:]]*".*chacha20-poly1305@openssh.com' 'Termius ciphers include chacha20-poly1305' || fail=1
    _audit_expect_grep "$file" '"forward_agent"[[:space:]]*:[[:space:]]*false' 'Termius forward_agent disabled' || fail=1
    return $fail
}

function audit_client_mobaxterm() {
    local file="$HOME/.config/MobaXterm/MobaXterm.ini"
    local fail=0

    if [ -f "$file" ]; then
        _audit_expect_grep "$file" '^SSH_Kex=curve25519-sha256' 'MobaXterm SSH_Kex hardened' || fail=1
        _audit_expect_grep "$file" '^SSH_AgentFwd=0$' 'MobaXterm SSH_AgentFwd disabled' || fail=1
        return $fail
    fi

    # Windows registry-read fallback (best-effort)
    _audit_windows_registry_value_match 'HKCU:\Software\Mobatek\MobaXterm' 'SSH_Kex' 'curve25519|group16|group18' 'MobaXterm registry SSH_Kex' || fail=1
    _audit_windows_registry_value_match 'HKCU:\Software\Mobatek\MobaXterm' 'SSH_AgentFwd' '^0$' 'MobaXterm registry SSH_AgentFwd=0' || fail=1
    return $fail
}

function audit_client_bitvise() {
    local fail=0
    _audit_windows_registry_value_match 'HKCU:\Software\Bitvise\BvSshClient\Settings' 'PreferredKex' 'curve25519|group16|group18' 'Bitvise PreferredKex' || fail=1
    _audit_windows_registry_value_match 'HKCU:\Software\Bitvise\BvSshClient\Settings' 'PreferredCiphers' 'chacha20|aes256-gcm|aes128-gcm' 'Bitvise PreferredCiphers' || fail=1
    return $fail
}

function audit_client_hardening() {
    local app="$1"
    local fail=0
    local c

    # Suppress logo and banner in JSON mode to keep stdout clean for CI parsing
    if [ "${AUDIT_JSON:-false}" = true ]; then
        export KRATOSSH_SUPPRESS_LOGO=1
    fi

    # Initialise JSON temp file when JSON output mode is active
    _AUDIT_JSON_TMP=""
    if [ "${AUDIT_JSON:-false}" = true ]; then
        _AUDIT_JSON_TMP="$(mktemp)"
    fi

    _audit_one() {
        local target="$1"
        _AUDIT_CURRENT_CLIENT="$target"
        case "$target" in
            openssh) audit_client_openssh || return 1 ;;
            putty) audit_client_putty || return 1 ;;
            bitvise) audit_client_bitvise || return 1 ;;
            securecrt) audit_client_securecrt || return 1 ;;
            macos-ssh) audit_client_macos_ssh || return 1 ;;
            winscp) audit_client_winscp || return 1 ;;
            termius) audit_client_termius || return 1 ;;
            mobaxterm) audit_client_mobaxterm || return 1 ;;
            *)
                log_error "[AUDIT] Unknown client app '$target'"
                return 1
                ;;
        esac
        return 0
    }

    # In JSON mode redirect human-readable stdout to stderr; JSON goes to stdout at end.
    if [ "${AUDIT_JSON:-false}" = true ]; then
        {
            if [ "$app" = "all" ]; then
                for c in $(list_supported_clients); do
                    log_info "[AUDIT] Checking client profile: $c"
                    _audit_one "$c" || fail=1
                done
            else
                _audit_one "$app" || fail=1
            fi
        } >&2
    else
        if [ "$app" = "all" ]; then
            for c in $(list_supported_clients); do
                log_info "[AUDIT] Checking client profile: $c"
                _audit_one "$c" || fail=1
            done
        else
            _audit_one "$app" || fail=1
        fi
    fi

    # Emit JSON array to stdout if requested
    if [ "${AUDIT_JSON:-false}" = true ] && [ -n "${_AUDIT_JSON_TMP:-}" ] && [ -f "$_AUDIT_JSON_TMP" ]; then
        local lines=()
        while IFS= read -r line; do
            lines+=("$line")
        done < "$_AUDIT_JSON_TMP"
        rm -f "$_AUDIT_JSON_TMP"
        printf '[\n'
        local i
        for i in "${!lines[@]}"; do
            if [ "$i" -lt $(( ${#lines[@]} - 1 )) ]; then
                printf '  %s,\n' "${lines[$i]}"
            else
                printf '  %s\n' "${lines[$i]}"
            fi
        done
        printf ']\n'
    fi

    if [ "$fail" -eq 0 ]; then
        if [ "${AUDIT_JSON:-false}" = true ]; then
            log_success "Client audit completed: no failed checks." >&2
        else
            log_success "Client audit completed: no failed checks."
        fi
        return 0
    fi

    log_error "Client audit completed: one or more checks failed."
    return 1
}
