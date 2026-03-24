#!/bin/bash

#########################
# Audit Functions       #
#########################

_AUDIT_UPDATED=false

function audit_system() {
    log_info "Starting SSH Audit..."
    
    # Check for python3
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required for auditing but not found. Please install python3."
        return 1
    fi

    # Determine script location
    # Since this is sourced, BASH_SOURCE[0] is this file. We need the root dir.
    # Assuming lib/audit.sh is sourced by KratoSSH.sh in the root.
    # We can rely on SCRIPT_DIR being defined in the main script OR verify path relative to this file.
    
    local lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local root_dir="$(dirname "$lib_dir")"
    local audit_script="$root_dir/ssh-audit/ssh-audit.py"
    
    # Check if bundled script exists
    if [ ! -f "$audit_script" ]; then
        log_error "Bundled ssh-audit not found at $audit_script."
        log_error "Please verify usage of the full repository."
        return 1
    fi

    # Auto-update if it's a git repo (only once per session)
    if [ -d "$root_dir/ssh-audit/.git" ] && [ "$_AUDIT_UPDATED" = false ]; then
        _AUDIT_UPDATED=true
        log_info "Checking for ssh-audit updates..."
        if [ "$DRY_RUN" = true ]; then
             log_info "[DRY-RUN] Would run 'git pull' in $root_dir/ssh-audit"
        else
            # Save current directory
            pushd "$root_dir/ssh-audit" > /dev/null
            if timeout 10 git pull --quiet; then
                log_success "ssh-audit updated successfully."
            else
                log_warn "Failed to update ssh-audit (or timed out). Continuing with current version."
            fi
            popd > /dev/null
        fi
    fi
    
    log_info "Running audit against localhost..."
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would run: python3 $audit_script localhost"
        return 0
    fi
    
    local ssh_port=22
    local main_config
    main_config="$(ssh_main_config)"
    if command -v sshd &>/dev/null; then
        local parsed_port=$(sshd -T 2>/dev/null | grep -i '^port ' | awk '{print $2}' | head -n 1)
        if [ -n "$parsed_port" ] && [[ "$parsed_port" =~ ^[0-9]+$ ]]; then
            ssh_port=$parsed_port
        fi
    else
        local config_port=$(grep -i '^Port ' "$main_config" 2>/dev/null | awk '{print $2}' | head -n 1)
        if [ -n "$config_port" ] && [[ "$config_port" =~ ^[0-9]+$ ]]; then
            ssh_port=$config_port
        fi
    fi

    # Use the bundled script which handles paths correctly
    if [ "$ssh_port" != "22" ]; then
        log_info "Detected custom SSH port: $ssh_port"
    fi
    python3 "$audit_script" localhost -p "$ssh_port"
}

function verify_hardening_state() {
    local failures=0
    local config_failures=0
    local key_failures=0
    local crypto_failures=0
    local service_failures=0
    local ssh_dir
    local main_config
    local dropin_dir
    local dropin_config
    local include_glob
    local rsa_key
    local ed25519_key

    ssh_dir="$(ssh_etc_dir)"
    main_config="$(ssh_main_config)"
    dropin_dir="$(ssh_dropin_dir)"
    dropin_config="$(ssh_hardening_dropin)"
    include_glob="$(ssh_include_glob)"
    rsa_key="$(ssh_host_key_path ssh_host_rsa_key)"
    ed25519_key="$(ssh_host_key_path ssh_host_ed25519_key)"

    log_info "Starting post-hardening verification..."

    if [ ! -f "$main_config" ]; then
        log_error "Main SSH config not found: $main_config"
        return 1
    fi

    log_info "[verify:config] Checking SSH config layout..."
    if [ -d "$dropin_dir" ]; then
        if awk -v inc="$include_glob" 'tolower($1)=="include" && $2==inc {found=1} END{exit !found}' "$main_config" 2>/dev/null; then
            log_success "Include for sshd_config.d is present in main config."
        else
            log_warn "Include for sshd_config.d is missing in main config."
            failures=$((failures + 1))
            config_failures=$((config_failures + 1))
        fi
    else
        log_info "No sshd_config.d directory present; main config-only mode."
    fi

    if [ -f "$dropin_config" ]; then
        log_success "KratoSSH drop-in config found: $dropin_config"
        if grep -q "BEGIN KratoSSH Hardening" "$dropin_config" 2>/dev/null; then
            log_success "KratoSSH hardening block marker present in drop-in file."
        else
            log_warn "Drop-in exists but block marker was not found."
            config_failures=$((config_failures + 1))
            failures=$((failures + 1))
        fi
    else
        log_warn "KratoSSH drop-in config not found at $dropin_config"
    fi

    log_info "[verify:keys] Checking host key files..."
    if [ -f "$rsa_key" ]; then
        log_success "RSA host key exists."
    else
        log_warn "RSA host key missing: $rsa_key"
        failures=$((failures + 1))
        key_failures=$((key_failures + 1))
    fi

    if [ -f "$ed25519_key" ]; then
        log_success "ED25519 host key exists."
    else
        log_warn "ED25519 host key missing: $ed25519_key"
        failures=$((failures + 1))
        key_failures=$((key_failures + 1))
    fi

    log_info "[verify:crypto] Checking active SSH crypto configuration..."
    if command -v sshd &>/dev/null; then
        if sshd -t 2>/dev/null; then
            log_success "sshd -t validation passed."
        else
            log_error "sshd -t validation failed."
            failures=$((failures + 1))
            crypto_failures=$((crypto_failures + 1))
        fi

        log_info "Effective SSH crypto settings:"
        sshd -T 2>/dev/null | grep -Ei '^(kexalgorithms|ciphers|macs|hostkeyalgorithms|pubkeyacceptedalgorithms|casignaturealgorithms|gssapikexalgorithms) ' || log_warn "Could not read effective crypto settings from sshd -T"
    else
        log_warn "sshd command not found; skipping syntax/effective config checks."
        failures=$((failures + 1))
        crypto_failures=$((crypto_failures + 1))
    fi

    log_info "[verify:service] Checking SSH service state..."
    if command -v systemctl &>/dev/null; then
        if systemctl is-active --quiet sshd || systemctl is-active --quiet ssh; then
            log_success "SSH service is active."
        else
            log_warn "SSH service is not active according to systemctl."
            failures=$((failures + 1))
            service_failures=$((service_failures + 1))
        fi
    else
        log_info "systemctl not available; skipping service state check."
    fi

    printf '\nVerification summary:\n'
    printf '  [config]  %s\n' "$( [ "$config_failures" -eq 0 ] && echo PASS || echo FAIL )"
    printf '  [keys]    %s\n' "$( [ "$key_failures" -eq 0 ] && echo PASS || echo FAIL )"
    printf '  [crypto]  %s\n' "$( [ "$crypto_failures" -eq 0 ] && echo PASS || echo FAIL )"
    printf '  [service] %s\n' "$( [ "$service_failures" -eq 0 ] && echo PASS || echo FAIL )"
    printf '  [overall] %s\n\n' "$( [ "$failures" -eq 0 ] && echo PASS || echo FAIL )"

    if [ "$failures" -gt 0 ]; then
        log_warn "Verification completed with $failures issue(s)."
        return 1
    fi

    log_success "Verification completed successfully with no critical issues."
    return 0
}

#########################
# Cron Audit Functions  #
#########################

function install_cron_audit() {
    local schedule="${1:-0 3 * * *}"
    local email="${2:-}"
    local script_path="${3:-$(realpath "${BASH_SOURCE[0]}" 2>/dev/null || echo '/usr/local/bin/KratoSSH.sh')}"
    local cron_file="/etc/cron.d/kratossh-audit"
    local log_file="/var/log/kratossh-audit.log"
    local cmd

    if [ -n "$email" ]; then
        cmd="$script_path --audit --auto 2>&1 | tee -a $log_file | mail -s 'KratoSSH Audit \$(hostname) \$(date +%F)' $email"
    else
        cmd="$script_path --audit --auto >> $log_file 2>&1"
    fi

    if [ "${DRY_RUN:-false}" = true ]; then
        log_info "[DRY-RUN] Would write cron job to $cron_file:"
        printf '  SHELL=/bin/bash\n'
        printf '  PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n'
        printf '  %s %s\n' "$schedule" "root $cmd"
        return 0
    fi

    if [ "$(id -u)" -ne 0 ]; then
        log_error "Installing a system cron job requires root. Use --dry-run to preview."
        return 1
    fi

    printf 'SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n%s root %s\n' \
        "$schedule" "$cmd" > "$cron_file"
    chmod 644 "$cron_file"
    log_success "Cron job installed at $cron_file (schedule: \"$schedule\")"
    [ -n "$email" ] && log_info "Reports will be emailed to: $email"
    return 0
}

function remove_cron_audit() {
    local cron_file="/etc/cron.d/kratossh-audit"

    if [ "${DRY_RUN:-false}" = true ]; then
        log_info "[DRY-RUN] Would remove $cron_file"
        return 0
    fi

    if [ "$(id -u)" -ne 0 ]; then
        log_error "Removing a system cron job requires root. Use --dry-run to preview."
        return 1
    fi

    if [ -f "$cron_file" ]; then
        rm -f "$cron_file"
        log_success "KratoSSH cron job removed: $cron_file"
    else
        log_warn "No KratoSSH cron job found at $cron_file"
    fi
    return 0
}
