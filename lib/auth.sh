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
        
        if ! getent group "$allow_groups" >/dev/null; then
             log_warn "Group '$allow_groups' does not exist. Please create it or you might be locked out!"
        else
             local current_user="${SUDO_USER:-$USER}"
             if [ -n "$current_user" ] && [ "$current_user" != "root" ]; then
                 if ! id -nG "$current_user" | grep -qw "$allow_groups"; then
                     log_warn "WARNING: User '$current_user' is not in '$allow_groups'."
                     log_warn "You could be locked out. Attempting to add '$current_user' to '$allow_groups'..."
                     if [ "$DRY_RUN" = false ]; then
                         usermod -aG "$allow_groups" "$current_user" || log_warn "Failed to add user to group. Fix manually!"
                     else
                         log_info "[DRY-RUN] Would add $current_user to $allow_groups"
                     fi
                 fi
             fi
        fi
    fi

    apply_atomic_sshd_config "$config" "KratoSSH Auth"
}
