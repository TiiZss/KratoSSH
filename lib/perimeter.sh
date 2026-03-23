#!/bin/bash

#--------------------------------------------------------------------------------
# Perimeter Protection (Port & Firewall)
#--------------------------------------------------------------------------------

function configure_firewall() {
    local port="$1"
    log_info "Configuring Firewall for port $port..."

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would open port $port in ufw/firewalld."
        return 0
    fi

    if command -v ufw &>/dev/null; then
        if ufw status | grep -q "Status: active"; then
             ufw limit "$port/tcp"
             ufw reload
             log_success "UFW configured with rate-limiting (limit)."
        else
             log_warn "UFW is installed but inactive. Not applying rules."
        fi
    elif command -v firewall-cmd &>/dev/null; then
        if systemctl is-active firewalld &>/dev/null; then
            firewall-cmd --permanent --add-port="$port/tcp"
            firewall-cmd --reload
            log_success "Firewalld configured."
        else
             log_warn "Firewalld is installed but inactive. Not applying rules."
        fi
    else
        log_warn "No supported firewall detected (ufw/firewalld) or active. Please open port $port manually."
    fi
}

function configure_selinux() {
    local port="$1"
    if command -v getenforce &>/dev/null && [ "$(getenforce)" != "Disabled" ]; then
        log_info "Configuring SELinux for port $port..."
        if [ "$DRY_RUN" = true ]; then
            log_info "[DRY-RUN] Would run semanage port -a -t ssh_port_t -p tcp $port"
            return 0
        fi

        if command -v semanage &>/dev/null; then
            semanage port -a -t ssh_port_t -p tcp "$port" || \
            semanage port -m -t ssh_port_t -p tcp "$port" || \
            log_warn "Failed to update SELinux port context."
        else
            log_warn "SELinux is enforcing but 'semanage' not found. Please install policycoreutils-python/python3."
        fi
    fi
}

function apply_perimeter_hardening() {
    local new_port="${1:-22}"

    # Validate port number
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        log_error "Puerto inválido: '$new_port'. Debe ser un número entre 1 y 65535."
        return 1
    fi

    log_info "Applying Perimeter Protection..."

    if [ "$new_port" -eq 22 ]; then
        log_info "Port 22 selected. Skipping firewall/SELinux changes (assuming default)."
    else
        # 1. Configure System (Firewall/SELinux) BEFORE changing SSH config to avoid lockout
        configure_firewall "$new_port"
        configure_selinux "$new_port"
        
        # 2. Update SSH Config
        apply_atomic_sshd_config "Port $new_port" "KratoSSH Perimeter"
    fi
}
