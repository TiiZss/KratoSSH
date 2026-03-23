#!/bin/bash

#--------------------------------------------------------------------------------
# Authentication & Access Hardening
#--------------------------------------------------------------------------------

function apply_auth_hardening() {
    local root_login="${1:-no}"
    local pass_auth="${2:-no}"
    local empty_pass="${3:-no}"
    local max_tries="${4:-3}"
    local max_sessions="${5:-2}"
    local allow_groups="${6:-ssh-users}"

    log_info "Applying Authentication Hardening..."

    local config="PermitRootLogin $root_login\n"
    config+="PasswordAuthentication $pass_auth\n"
    config+="PermitEmptyPasswords $empty_pass\n"
    config+="MaxAuthTries $max_tries\n"
    config+="MaxSessions $max_sessions\n"
    
    if [ -n "$allow_groups" ]; then
        config+="AllowGroups $allow_groups\n"
        # Check if group exists, if not create it?
        # Maybe just warn if it doesn't exist
        if ! getent group "$allow_groups" >/dev/null; then
             log_warn "Group '$allow_groups' does not exist. Please create it or you might be locked out!"
             # groupadd "$allow_groups" # Optional: auto-create? Better to just warn.
        fi
    fi

    apply_atomic_sshd_config "$config" "KratoSSH Auth"
}
