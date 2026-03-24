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
    local main_config
    local restarted=false

    main_config="$(ssh_main_config)"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would validate config and restart SSH service."
        return 0
    fi
    log_info "Validating SSH configuration..."
    if sshd -t -f "$main_config"; then
        log_success "Configuration is valid."
        log_info "Restarting SSH service..."
        if command -v systemctl &> /dev/null; then
            if systemctl restart sshd || systemctl restart ssh; then
                restarted=true
            fi
        elif command -v rc-service &> /dev/null; then
            if rc-service sshd restart || rc-service ssh restart; then
                restarted=true
            fi
        elif command -v service &> /dev/null; then
            if service ssh restart || service sshd restart; then
                restarted=true
            fi
        else
            log_error "Could not detect service manager to restart SSH. Please restart manually."
            return 1
        fi

        if [ "$restarted" != true ]; then
            log_error "Failed to restart SSH service with detected service manager."
            return 1
        fi
    else
        log_error "SSH configuration is INVALID. Not restarting service to prevent lockout."
        log_error "Please check $main_config and restore backup if needed."
        return 1
    fi
}

function regeneratekeys(){
    local ssh_dir
    local rsa_key
    local ed25519_key
    local backup_dir

    ssh_dir="$(ssh_etc_dir)"
    rsa_key="$(ssh_host_key_path ssh_host_rsa_key)"
    ed25519_key="$(ssh_host_key_path ssh_host_ed25519_key)"
    backup_dir="${ssh_dir}/backup_keys_$(date +%Y%m%d_%H%M%S)"

    # Skip rotation unless explicitly forced.
    if [ "$FORCE_REGENERATE" != "true" ] && [ -f "$rsa_key" ] && [ -f "$ed25519_key" ]; then
        log_info "Host keys already exist. Skipping regeneration (use --force-regenerate to rotate)."
        return 0
    fi

	# Backup existing keys
    log_info "Backing up existing SSH keys to ${backup_dir}..."
    mkdir -p "$backup_dir"
    chmod 700 "$backup_dir"
    
    if ls "$ssh_dir"/ssh_host_* &> /dev/null; then
        mv "$ssh_dir"/ssh_host_* "$backup_dir/" || die "Failed to backup keys."
    fi
    
    # Backup Rotation: Keep only last 5
    local -a existing_backups
    mapfile -t existing_backups < <(ls -dt "$ssh_dir"/backup_keys_* 2>/dev/null)
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
	ssh-keygen -t rsa -b 4096 -f "$rsa_key" -N "" -q || die "Failed to generate RSA key"
	ssh-keygen -t ed25519 -f "$ed25519_key" -N "" -q || die "Failed to generate ED25519 key"
    
    log_success "New keys generated successfully."
}

function removemoduli() {
	local ssh_dir
	local moduli_file

	ssh_dir="$(ssh_etc_dir)"
	moduli_file="${ssh_dir}/moduli"

	# Remove small Diffie-Hellman moduli
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would filter small Diffie-Hellman moduli."
        return 0
    fi
    log_info "Filtering small Diffie-Hellman moduli (< 3071 bits)..."
	if [ -f "$moduli_file" ]; then
        local tmp_moduli
        tmp_moduli=$(mktemp "$ssh_dir/moduli.safe.XXXXXX") || { log_error "Failed to create temp file for moduli"; return 1; }
        awk '$5 >= 3071' "$moduli_file" > "$tmp_moduli"
        mv "$tmp_moduli" "$moduli_file"
        log_success "Moduli filtered."
    else
        log_warn "$moduli_file not found. Skipping."
    fi
}

function generomoduli() {
    local ssh_dir
    local moduli_file

    ssh_dir="$(ssh_etc_dir)"
    moduli_file="${ssh_dir}/moduli"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would generate new 4096-bit DH moduli (5-30 min operation)."
        return 0
    fi
    local tmp_all tmp_safe
    tmp_all=$(mktemp /tmp/moduli.all.XXXXXX) || { log_error "Failed to create temp file for moduli generation"; return 1; }
    tmp_safe=$(mktemp /tmp/moduli.safe.XXXXXX) || { rm -f "$tmp_all"; log_error "Failed to create temp file for moduli screening"; return 1; }

    ssh-keygen -G "$tmp_all" -b 4096 || { rm -f "$tmp_all" "$tmp_safe"; die "Failed to generate moduli candidates"; }
    ssh-keygen -T "$tmp_safe" -f "$tmp_all" || { rm -f "$tmp_all" "$tmp_safe"; die "Failed to screen moduli"; }
    mv "$tmp_safe" "$moduli_file"
    rm -f "$tmp_all"
}

function moduli() {
    local moduli_file
    moduli_file="$(ssh_etc_dir)/moduli"
    if [ -f "$moduli_file" ]; then
        # Filtrado ultra-rápido si ya existe
        removemoduli
    else
        if [ "$FAST_MODE" = true ]; then
            log_warn "$moduli_file no existe. Saltando la generación por --fast."
        else
            log_warn "$moduli_file no existe. Comenzando generación de 4096-bits..."
            log_warn "¡ATENCIÓN! Esto puede tardar entre 5 y 30 minutos dependiendo de la CPU."
            generomoduli
            removemoduli
        fi
    fi
}

function apply_atomic_sshd_config() {
    local content="$1"
    local block_name="${2:-KratoSSH Hardening}" # Default to "KratoSSH Hardening" if not specified
    local main_config
    local include_glob
    local target_config=""
    local clean_main=false
    local use_dropin=false
    local include_required=false
    local include_added=false
    local temp_config=""
    local temp_main=""
    local old_target_backup=""
    local backup_stamp

    main_config="$(ssh_main_config)"
    include_glob="$(ssh_include_glob)"
    target_config="$main_config"

    # Check for drop-in support and whether Include needs to be enabled.
    if [ -d "$(ssh_dropin_dir)" ]; then
        if awk -v inc="$include_glob" 'tolower($1)=="include" && $2==inc {found=1} END{exit !found}' "$main_config" 2>/dev/null; then
            use_dropin=true
        else
            include_required=true
        fi
    fi
    
    # Secure temp file creation
    if ! temp_config=$(mktemp) || [ -z "$temp_config" ]; then
        log_error "Failed to create temporary file via mktemp"
        return 1
    fi
    TEMP_CONFIG="$temp_config" # Expose for trap cleanup
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would apply the following config to $target_config (Block: $block_name):"
        echo -e "$content"
        rm -f "$temp_config"
        return 0
    fi

    # Create backup of main config before modifying
    backup_stamp="$(date +%Y%m%d_%H%M%S)"
    cp "$main_config" "${main_config}.bak.${backup_stamp}" 2>/dev/null || touch "${main_config}.bak.${backup_stamp}"
    mapfile -t _sshd_baks < <(ls -t "${main_config}.bak."* 2>/dev/null)
    if [ "${#_sshd_baks[@]}" -gt 5 ]; then
        printf '%s\0' "${_sshd_baks[@]:5}" | xargs -0 rm -f
    fi

    if [ "$include_required" = true ]; then
        if ! temp_main=$(mktemp) || [ -z "$temp_main" ]; then
            log_error "Failed to create temporary file for Include preflight"
            TEMP_CONFIG=""
            return 1
        fi

        cp "$main_config" "$temp_main"
        printf '\nInclude %s\n' "$include_glob" >> "$temp_main"

        if ! sshd -t -f "$temp_main"; then
            log_error "Unable to enable Include $include_glob safely."
            log_error "You can inspect the failed config at $temp_main"
            TEMP_CONFIG=""
            return 1
        fi

        cp "$temp_main" "$main_config"
        chmod 644 "$main_config"
        rm -f "$temp_main"
        temp_main=""
        include_added=true
        use_dropin=true
        log_info "Enabled Include $include_glob in $main_config"
    fi

    if [ "$use_dropin" = true ]; then
        target_config="$(ssh_hardening_dropin)"
        clean_main=true
    fi

    if [ "$target_config" = "$main_config" ]; then
        # Prepare new config by copying main
        cp "$main_config" "$temp_config"
        
        # Remove existing block if present to avoid duplication/conflict
        if grep -q "# BEGIN $block_name" "$temp_config"; then
            sed -i "/# BEGIN $block_name/,/# END $block_name/d" "$temp_config"
        fi
        
        # Insert at the TOP of the file to ensure precedence
        local tmp2
        tmp2=$(mktemp)
        echo -e "# BEGIN $block_name\n$content\n# END $block_name\n" > "$tmp2"
        cat "$temp_config" >> "$tmp2"
        mv "$tmp2" "$temp_config"
    else
        # Using a drop-in file
        if [ -f "$target_config" ]; then
            cp "$target_config" "$temp_config"
            if grep -q "# BEGIN $block_name" "$temp_config"; then
                sed -i "/# BEGIN $block_name/,/# END $block_name/d" "$temp_config"
            fi
            printf '\n# BEGIN %s\n%s\n# END %s\n' "$block_name" "$content" "$block_name" >> "$temp_config"
        else
            echo -e "# BEGIN $block_name\n$content\n# END $block_name" > "$temp_config"
        fi

        if [ -f "$target_config" ]; then
            old_target_backup=$(mktemp) || {
                log_error "Failed to create backup temp for existing drop-in config"
                TEMP_CONFIG=""
                return 1
            }
            cp "$target_config" "$old_target_backup" || {
                log_error "Failed to back up existing drop-in config"
                rm -f "$old_target_backup"
                TEMP_CONFIG=""
                return 1
            }
        fi
    fi

    # Validate
    log_info "Validating new configuration..."
    if [ "$target_config" != "$main_config" ]; then
        cp "$temp_config" "$target_config"
        chmod 644 "$target_config"
        
        if ! sshd -t; then
            log_error "New configuration is INVALID. Aborting changes."
            if [ "$include_added" = true ]; then
                cp "${main_config}.bak.${backup_stamp}" "$main_config" 2>/dev/null
            fi
            if [ -n "$old_target_backup" ]; then
                cp "$old_target_backup" "$target_config"
            else
                rm -f "$target_config"
            fi
            log_error "You can inspect the failed config at $temp_config"
            rm -f "$old_target_backup"
            TEMP_CONFIG=""
            return 1
        fi

        if [ "$clean_main" = true ] && grep -q "# BEGIN $block_name" "$main_config" 2>/dev/null; then
            if ! temp_main=$(mktemp) || [ -z "$temp_main" ]; then
                log_error "Failed to create temporary file for main config cleanup"
                if [ "$include_added" = true ]; then
                    cp "${main_config}.bak.${backup_stamp}" "$main_config" 2>/dev/null
                fi
                if [ -n "$old_target_backup" ]; then
                    cp "$old_target_backup" "$target_config"
                else
                    rm -f "$target_config"
                fi
                rm -f "$old_target_backup"
                TEMP_CONFIG=""
                return 1
            fi

            cp "$main_config" "$temp_main"
            sed -i "/# BEGIN $block_name/,/# END $block_name/d" "$temp_main"

            if ! sshd -t -f "$temp_main"; then
                log_error "Main config cleanup produced invalid configuration. Rolling back."
                if [ "$include_added" = true ]; then
                    cp "${main_config}.bak.${backup_stamp}" "$main_config" 2>/dev/null
                fi
                if [ -n "$old_target_backup" ]; then
                    cp "$old_target_backup" "$target_config"
                else
                    rm -f "$target_config"
                fi
                rm -f "$temp_main" "$old_target_backup"
                TEMP_CONFIG=""
                return 1
            fi

            cp "$temp_main" "$main_config"
            chmod 644 "$main_config"
            rm -f "$temp_main"
            temp_main=""

            if ! sshd -t; then
                log_error "Post-cleanup validation failed. Restoring backups."
                cp "${main_config}.bak.${backup_stamp}" "$main_config" 2>/dev/null
                if [ -n "$old_target_backup" ]; then
                    cp "$old_target_backup" "$target_config"
                else
                    rm -f "$target_config"
                fi
                rm -f "$old_target_backup"
                TEMP_CONFIG=""
                return 1
            fi
        fi

        log_success "New configuration is valid. Applying..."
        rm -f "$old_target_backup"
        rm -f "$temp_config"
        TEMP_CONFIG=""
        return 0
    else
        if sshd -t -f "$temp_config"; then
            log_success "New configuration is valid. Applying..."
            cp "$temp_config" "$target_config"
            chmod 644 "$target_config"
            rm -f "$temp_config"
            TEMP_CONFIG=""
            return 0
        else
            log_error "New configuration is INVALID. Aborting changes."
            log_error "You can inspect the failed config at $temp_config"
            TEMP_CONFIG=""
            return 1
        fi
    fi

}

function apply_server_hardening() {
    local kex="$1"
    local ciphers="$2"
    local macs="$3"
    local hostkeys="$4"
    local extra="$5"
    local hostkey_file
    local hostkey_lines=""

    local config_block=""
    [ -n "$kex" ] && config_block+="KexAlgorithms $kex\n\n"
    [ -n "$ciphers" ] && config_block+="Ciphers $ciphers\n\n"
    [ -n "$macs" ] && config_block+="MACs $macs\n\n"
    [ -n "$hostkeys" ] && config_block+="HostKeyAlgorithms $hostkeys\n\nCASignatureAlgorithms $hostkeys\n\nHostbasedAcceptedAlgorithms $hostkeys\n\nPubkeyAcceptedAlgorithms $hostkeys\n\n"
    
    # Only configure HostKey entries that exist to avoid invalid configs.
    for hostkey_file in "$(ssh_host_key_path ssh_host_rsa_key)" "$(ssh_host_key_path ssh_host_ed25519_key)"; do
        if [ -f "$hostkey_file" ] || [ "$DRY_RUN" = true ]; then
            hostkey_lines+="HostKey $hostkey_file\n"
        fi
    done
    if [ -n "$hostkey_lines" ]; then
        config_block+="$hostkey_lines\n"
    else
        log_warn "No host key files found in $(ssh_etc_dir). HostKey directives were not added."
    fi

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
    local ssh_dir
    local latest_backup

    ssh_dir="$(ssh_etc_dir)"
    log_info "Looking for backups..."
    latest_backup=$(ls -dt "$ssh_dir"/backup_keys_* 2>/dev/null | head -1)
    
    if [ -z "$latest_backup" ]; then
        log_error "No backups found."
        return 1
    fi
    
    log_info "Restoring keys from $latest_backup..."
    cp "$latest_backup"/* "$ssh_dir"/
    log_success "Keys restored from $latest_backup."
}
