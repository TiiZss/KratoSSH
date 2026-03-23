#!/bin/bash

#--------------------------------------------------------------------------------
# Network & Protocol Hardening
#--------------------------------------------------------------------------------

function apply_network_hardening() {
    local x11="${1:-no}"
    local tcp="${2:-no}"
    local stream="${3:-no}"
    local alive_interval="${4:-300}"
    local alive_count="${5:-0}"

    log_info "Applying Network Hardening..."

    # Note: Protocol directive was removed in OpenSSH 7.6; SSH1 is disabled by default.
    local config="X11Forwarding $x11\n"
    config+="AllowTcpForwarding $tcp\n"
    config+="AllowStreamLocalForwarding $stream\n"
    config+="ClientAliveInterval $alive_interval\n"
    config+="ClientAliveCountMax $alive_count\n"

    apply_atomic_sshd_config "$config" "KratoSSH Network"
}
