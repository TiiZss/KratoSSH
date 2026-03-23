#!/bin/bash

#--------------------------------------------------------------------------------
# Multi-Factor Authentication (Google Authenticator)
#--------------------------------------------------------------------------------

function install_mfa_pkg() {
    log_info "Installing Google Authenticator..."
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would install libpam-google-authenticator via package manager."
        return 0
    fi

    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y libpam-google-authenticator
    elif command -v dnf &>/dev/null; then
        dnf install -y google-authenticator
    elif command -v yum &>/dev/null; then
        yum install -y google-authenticator
    else
        log_error "Unsupported package manager. Please install libpam-google-authenticator manually."
        return 1
    fi
}

function configure_pam() {
    local pam_file="/etc/pam.d/sshd"
    log_info "Configuring PAM for Google Authenticator..."

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would backup and edit $pam_file to include pam_google_authenticator.so"
        return 0
    fi

    if ! grep -q "pam_google_authenticator.so" "$pam_file"; then
        # Backup before modifying
        cp "$pam_file" "${pam_file}.bak.$(date +%Y%m%d_%H%M%S)"

        # On Debian/Ubuntu based systems, it's safer to insert it right after standard auth
        # nullok ensures users that haven't set it up don't get locked out initially.
        if grep -q "@include common-auth" "$pam_file"; then
            safe_sed '/@include common-auth/a auth required pam_google_authenticator.so nullok' "$pam_file"
        else
            echo "auth required pam_google_authenticator.so nullok" >> "$pam_file"
        fi
        log_success "Updated $pam_file"
    else
        log_info "PAM already configured for Google Authenticator."
    fi
}

function apply_mfa_hardening() {
    log_info "Applying MFA Hardening..."
    
    # 1. Install Package
    if ! install_mfa_pkg; then
         log_error "Failed to install MFA package. Aborting MFA setup."
         return 1
    fi

    # 2. Configure PAM
    configure_pam

    # 3. Configure SSHD
    # Detect OpenSSH version: ChallengeResponseAuthentication was renamed to
    # KbdInteractiveAuthentication in OpenSSH 8.7 (released 2021-08-20).
    local openssh_major
    openssh_major=$(ssh -V 2>&1 | grep -oP 'OpenSSH_\K[0-9]+')
    local kbd_directive
    if [ "${openssh_major:-0}" -ge 9 ]; then
        kbd_directive="KbdInteractiveAuthentication yes"
    else
        kbd_directive="ChallengeResponseAuthentication yes"
    fi
    local config="${kbd_directive}\n"
    config+="AuthenticationMethods publickey,keyboard-interactive\n"
    config+="UsePAM yes\n"

    apply_atomic_sshd_config "$config" "KratoSSH MFA"

    log_warn "IMPORTANT: You MUST run 'google-authenticator' for each user!"
}
