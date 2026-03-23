#!/bin/bash

#--------------------------------------------------------------------------------
# SSH Hardening Configuration Constants
#--------------------------------------------------------------------------------
# As per ssh-audit.com hardening guides
SSH_KEX="sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256"
SSH_CIPHERS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
SSH_MACS="hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com"
SSH_HOST_KEYS="sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256"

# Intermediate algorithm sets (no sntrup761) — OpenSSH 7.6-8.4 era
SSH_KEX_COMPAT="curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256"
SSH_HOST_KEYS_COMPAT="ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com"
# Legacy algorithm sets — OpenSSH 6.x era
SSH_KEX_LEGACY="curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"

function restart_ssh() {
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would validate config and restart SSH service."
        return 0
    fi
    log_info "Validating SSH configuration..."
    if sshd -t; then
        log_success "Configuration is valid."
        log_info "Restarting SSH service..."
        if command -v systemctl &> /dev/null; then
            systemctl restart sshd || systemctl restart ssh || log_warn "Failed to restart SSH via systemctl"
        elif command -v rc-service &> /dev/null; then
            rc-service sshd restart || rc-service ssh restart || log_warn "Failed to restart SSH via rc-service"
        elif command -v service &> /dev/null; then
            service ssh restart || service sshd restart || log_warn "Failed to restart SSH via service"
        else
            log_warn "Could not detect service manager to restart SSH. Please restart manually."
        fi
    else
        log_error "SSH configuration is INVALID. Not restarting service to prevent lockout."
        log_error "Please check /etc/ssh/sshd_config and restore backup if needed."
        return 1
    fi
}

function regeneratekeys(){
	# Backup existing keys
    local backup_dir="/etc/ssh/backup_keys_$(date +%Y%m%d_%H%M%S)"
    log_info "Backing up existing SSH keys to ${backup_dir}..."
    mkdir -p "$backup_dir"
    chmod 700 "$backup_dir"
    
    if ls /etc/ssh/ssh_host_* &> /dev/null; then
        mv /etc/ssh/ssh_host_* "$backup_dir/" || die "Failed to backup keys."
    fi
    
    # Backup Rotation: Keep only last 5
    local -a existing_backups
    mapfile -t existing_backups < <(ls -dt /etc/ssh/backup_keys_* 2>/dev/null)
    if [ "${#existing_backups[@]}" -gt 5 ]; then
        log_info "Rotating backups (keeping last 5)..."
        printf '%s\0' "${existing_backups[@]:5}" | xargs -0 rm -rf
    fi

	# Re-generate the RSA and ED25519 keys
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would generate new RSA (4096 bits) and ED25519 keys."
        return 0
    fi
    log_info "Generating new RSA (4096 bits) and ED25519 keys..."
	ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -q || die "Failed to generate RSA key"
	ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q || die "Failed to generate ED25519 key"
    
    log_success "New keys generated successfully."
}

function removemoduli() {
	# Remove small Diffie-Hellman moduli
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would filter small Diffie-Hellman moduli."
        return 0
    fi
    log_info "Filtering small Diffie-Hellman moduli (< 3071 bits)..."
	if [ -f /etc/ssh/moduli ]; then
        local tmp_moduli
        tmp_moduli=$(mktemp /etc/ssh/moduli.safe.XXXXXX) || { log_error "Failed to create temp file for moduli"; return 1; }
        awk '$5 >= 3071' /etc/ssh/moduli > "$tmp_moduli"
        mv "$tmp_moduli" /etc/ssh/moduli
        log_success "Moduli filtered."
    else
        log_warn "/etc/ssh/moduli not found. Skipping."
    fi
}

function generomoduli() {
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would generate new 4096-bit DH moduli (5-30 min operation)."
        return 0
    fi
    local tmp_all tmp_safe
    tmp_all=$(mktemp /tmp/moduli.all.XXXXXX) || { log_error "Failed to create temp file for moduli generation"; return 1; }
    tmp_safe=$(mktemp /tmp/moduli.safe.XXXXXX) || { rm -f "$tmp_all"; log_error "Failed to create temp file for moduli screening"; return 1; }

    ssh-keygen -G "$tmp_all" -b 4096 || { rm -f "$tmp_all" "$tmp_safe"; die "Failed to generate moduli candidates"; }
    ssh-keygen -T "$tmp_safe" -f "$tmp_all" || { rm -f "$tmp_all" "$tmp_safe"; die "Failed to screen moduli"; }
    mv "$tmp_safe" /etc/ssh/moduli
    rm -f "$tmp_all"
}

function moduli() {
  if [ -f "/etc/ssh/moduli" ]; then
    # Filtrado ultra-rápido si ya existe
    removemoduli
  else
    if [ "$FAST_MODE" = true ]; then
      log_warn "/etc/ssh/moduli no existe. Saltando la generación por --fast."
    else
      log_warn "/etc/ssh/moduli no existe. Comenzando generación de 4096-bits..."
      log_warn "¡ATENCIÓN! Esto puede tardar entre 5 y 30 minutos dependiendo de la CPU."
      generomoduli
      removemoduli
    fi
  fi
}

function apply_atomic_sshd_config() {
    local content="$1"
    local block_name="${2:-KratoSSH Hardening}" # Default to "KratoSSH Hardening" if not specified
    local config_file="/etc/ssh/sshd_config"
    
    # Secure temp file creation
    local temp_config
    if ! temp_config=$(mktemp) || [ -z "$temp_config" ]; then
        log_error "Failed to create temporary file via mktemp"
        return 1
    fi
    TEMP_CONFIG="$temp_config" # Expose for trap cleanup
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would apply the following config to $config_file (Block: $block_name):"
        echo -e "$content"
        rm -f "$temp_config"
        return 0
    fi

    # Create backup before any modifications, then rotate (keep last 5)
    cp "$config_file" "${config_file}.bak.$(date +%Y%m%d_%H%M%S)"
    mapfile -t _sshd_baks < <(ls -t "${config_file}.bak."* 2>/dev/null)
    if [ "${#_sshd_baks[@]}" -gt 5 ]; then
        printf '%s\0' "${_sshd_baks[@]:5}" | xargs -0 rm -f
    fi

    # Prepare new config
    cp "$config_file" "$temp_config"
    
    # Remove existing block if present to avoid duplication/conflict
    # We use a temporary file for sed to avoid issues
    if grep -q "$block_name" "$temp_config"; then
        sed -i "/# BEGIN $block_name/,/# END $block_name/d" "$temp_config"
    fi
    
    echo -e "\n# BEGIN $block_name\n$content\n# END $block_name" >> "$temp_config"

    # Validate
    log_info "Validating new configuration..."
    if sshd -t -f "$temp_config"; then
        log_success "New configuration is valid. Applying..."
        cp "$temp_config" "$config_file"
        rm -f "$temp_config"
        TEMP_CONFIG=""
    else
        log_error "New configuration is INVALID. Aborting changes."
        log_error "You can inspect the failed config at $temp_config"
        TEMP_CONFIG="" # Clear trap var so it isn't deleted on exit if we want to preserve it
        return 1
    fi
}

function apply_server_hardening() {
    local kex="$1"
    local ciphers="$2"
    local macs="$3"
    local hostkeys="$4"
    local extra="$5"

    local config_block=""
    [ -n "$kex" ] && config_block+="KexAlgorithms $kex\n\n"
    [ -n "$ciphers" ] && config_block+="Ciphers $ciphers\n\n"
    [ -n "$macs" ] && config_block+="MACs $macs\n\n"
    [ -n "$hostkeys" ] && config_block+="HostKeyAlgorithms $hostkeys\n\nCASignatureAlgorithms $hostkeys\n\nHostbasedAcceptedAlgorithms $hostkeys\n\nPubkeyAcceptedAlgorithms $hostkeys\n\n"
    
    # Strictly define HostKeys to prevent OpenSSH from loading weak default keys (e.g. ECDSA/DSA)
    config_block+="HostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n\n"

    [ -n "$extra" ] && config_block+="$extra\n\n"
    
    # Defaults common to all (GSSAPI)
    config_block+="GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n"

    apply_atomic_sshd_config "$config_block"
}

function apply_client_hardening() {
    local ciphers="$1"
    local kex="$2"
    local macs="$3"
    local hostkeys="$4"

    local config_file="$HOME/.ssh/config"
    mkdir -p -m 0700 "$HOME/.ssh"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would update $config_file with hardened ciphers."
        return 0
    fi

    # Backup existing config before modifying
    if [ -f "$config_file" ]; then
        cp "$config_file" "${config_file}.bak.$(date +%Y%m%d_%H%M%S)"
    fi

    # Remove existing KratoSSH block if present (ensures update, not skip)
    if grep -q "BEGIN KratoSSH Hardening" "$config_file" 2>/dev/null; then
        sed -i '/# BEGIN KratoSSH Hardening/,/# END KratoSSH Hardening/d' "$config_file"
    fi

    echo -e "\n# BEGIN KratoSSH Hardening\nHost *\n Ciphers $ciphers\n KexAlgorithms $kex\n MACs $macs\n HostKeyAlgorithms $hostkeys\n CASignatureAlgorithms $hostkeys\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n HostbasedAcceptedAlgorithms $hostkeys\n PubkeyAcceptedAlgorithms $hostkeys\n# END KratoSSH Hardening" >> "$config_file"
    log_success "Updated client config at $config_file"
}

function restore_backup() {
    log_info "Looking for backups..."
    local latest_backup=$(ls -dt /etc/ssh/backup_keys_* 2>/dev/null | head -1)
    
    if [ -z "$latest_backup" ]; then
        log_error "No backups found."
        return 1
    fi
    
    log_info "Restoring keys from $latest_backup..."
    cp "$latest_backup"/* /etc/ssh/
    log_success "Keys restored from $latest_backup."
}
