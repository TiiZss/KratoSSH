#!/bin/bash

#--------------------------------------------------------------------------------
# Distribution Specific Hardening Functions
#--------------------------------------------------------------------------------

function Ubuntu() {
	version_num=$1
	if [ "$version_num" -lt 14 ]; then
		log_error "Tu versión de Ubuntu ($version_num) es demasiado antigua."
        return 1
	fi
    
    log_success "Tu versión de Ubuntu ($version_num) es compatible."

    if [ "$version_num" -ge 21 ]; then
        regeneratekeys || return 1
        moduli || return 1
        apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS" || return 1
    elif [ "$version_num" -ge 19 ]; then
        regeneratekeys || return 1
        moduli || return 1
        apply_server_hardening \
            "$SSH_KEX_COMPAT" \
            "$SSH_CIPHERS" \
            "$SSH_MACS" \
            "$SSH_HOST_KEYS_COMPAT" || return 1
    elif [ "$version_num" -ge 17 ]; then
        regeneratekeys || return 1
        moduli || return 1
        # Disable DSA and ECDSA
        safe_sed 's/^HostKey \/etc\/ssh\/ssh_host_\(dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
        apply_server_hardening \
            "$SSH_KEX_COMPAT" \
            "$SSH_CIPHERS" \
            "$SSH_MACS" \
            "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com" || return 1
    elif [ "$version_num" -ge 15 ]; then
        regeneratekeys || return 1
        moduli || return 1
        safe_sed 's/^HostKey \/etc\/ssh\/ssh_host_\(rsa\|dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
        apply_server_hardening \
            "$SSH_KEX_LEGACY" \
            "$SSH_CIPHERS" \
            "$SSH_MACS" || return 1
    elif [ "$version_num" -ge 14 ]; then
        regeneratekeys || return 1
        moduli || return 1
        safe_sed 's/^HostKey \/etc\/ssh\/ssh_host_\(dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
        apply_server_hardening \
            "$SSH_KEX_LEGACY" \
            "$SSH_CIPHERS" \
            "$SSH_MACS" || return 1
    else
        log_error "Estas en Ubuntu version $version_num y no se ha implementado nada para ello todavía."
        return 1
    fi
    #Restart OpenSSH server
    restart_ssh || return 1
}

function Debian() {
	version_num=$1
	if [ $version_num -lt 10 ]; then
		log_error "Tu versión de Debian ($version_num) es demasiado antigua."
        return 1
	fi
    
    log_success "Tu versión de Debian ($version_num) es compatible."

    if [ "$version_num" -ge 12 ]; then
        regeneratekeys || return 1
        moduli || return 1
        apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS" "RequiredRSASize 3072" || return 1
    elif [ "$version_num" -eq 11 ]; then
        regeneratekeys || return 1
        moduli || return 1
        apply_server_hardening \
            "$SSH_KEX_COMPAT" \
            "$SSH_CIPHERS" \
            "$SSH_MACS" \
            "$SSH_HOST_KEYS_COMPAT" || return 1
    elif [ "$version_num" -eq 10 ]; then
        regeneratekeys || return 1
        moduli || return 1
        apply_server_hardening \
            "$SSH_KEX_COMPAT" \
            "$SSH_CIPHERS" \
            "$SSH_MACS" \
            "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" || return 1
    else
        log_error "Estas en Debian version $version_num y no se ha implementado nada para ello todavía."
        return 1
    fi
    restart_ssh || return 1
}

function CentOS() {
	version_num=$1
	if [ $version_num -lt 7 ]; then
		log_error "Tu versión de CentOS ($version_num) es demasiado antigua."
        return 1
	fi
    
    log_success "Tu versión de CentOS ($version_num) es compatible."

    case $version_num in
        "8")
            regeneratekeys || return 1
            if [ "$DRY_RUN" = false ]; then
                local ssh_group
                ssh_group=$(get_ssh_keys_group)
                if [ -n "$ssh_group" ]; then
                    chgrp "$ssh_group" /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
                    chmod g+r /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
                fi
            else
                 log_info "[DRY-RUN] Would chgrp/chmod keys"
            fi

            moduli || return 1
            safe_sed 's/^HostKey \/etc\/ssh\/ssh_host_ecdsa_key$/\#HostKey \/etc\/ssh\/ssh_host_ecdsa_key/g' /etc/ssh/sshd_config

            # Restrict via crypto-policies
            if [ "$DRY_RUN" = false ]; then
                cp /etc/crypto-policies/back-ends/opensshserver.config /etc/crypto-policies/back-ends/opensshserver.config.orig
                echo -e "CRYPTO_POLICY='-oCiphers=chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr -oMACs=hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com -oGSSAPIKexAlgorithms=gss-curve25519-sha256- -oKexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256 -oHostKeyAlgorithms=ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512 -oPubkeyAcceptedKeyTypes=ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512'" > /etc/crypto-policies/back-ends/opensshserver.config
            else
                log_info "[DRY-RUN] Would update /etc/crypto-policies/back-ends/opensshserver.config"
            fi
            ;;

        "7")
            # Disable automatic re-generation of RSA & ECDSA keys
            if [ "$DRY_RUN" = false ]; then
                mkdir -p /etc/systemd/system/sshd-keygen.service.d
                cat << EOF > /etc/systemd/system/sshd-keygen.service.d/kratossh_hardening.conf
[Unit]
ConditionFileNotEmpty=
ConditionFileNotEmpty=!/etc/ssh/ssh_host_ed25519_key
EOF
                systemctl daemon-reload
            else
                 log_info "[DRY-RUN] Would update systemd sshd-keygen config"
            fi

            # Re-generate the ED25519 key (backup existing keys first via regeneratekeys)
            regeneratekeys || return 1
            if [ "$DRY_RUN" = false ]; then
                local ssh_group
                ssh_group=$(get_ssh_keys_group)
                if [ -n "$ssh_group" ]; then
                    chgrp "$ssh_group" /etc/ssh/ssh_host_ed25519_key
                    chmod g+r /etc/ssh/ssh_host_ed25519_key
                fi
            else
                 log_info "[DRY-RUN] Would regenerate ED25519 key for CentOS 7"
            fi

            moduli || return 1
            safe_sed 's/^HostKey \/etc\/ssh\/ssh_host_\(rsa\|dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

            apply_server_hardening \
                "$SSH_KEX_COMPAT" \
                "$SSH_CIPHERS" \
                "$SSH_MACS" || return 1
        ;;

        *)
            log_error "Estas en CentOS version $version_num y no se ha implementado nada para ello todavía."
            return 1
        ;;
    esac
    restart_ssh || return 1
}

function Amazon() {
	version_num=$1
	if [ $version_num -lt 2023 ]; then
		log_error "Tu versión de Amazon Linux ($version_num) es demasiado antigua."
        return 1
	fi
    
    log_success "Tu versión de Amazon Linux ($version_num) es compatible."

    case $version_num in
        "2023")
            regeneratekeys || return 1
            moduli || return 1
            
            if [ "$DRY_RUN" = false ]; then
                 echo -e "KexAlgorithms $SSH_KEX\n\nCiphers $SSH_CIPHERS\n\nMACs $SSH_MACS\n\nHostKeyAlgorithms $SSH_HOST_KEYS\n\nCASignatureAlgorithms $SSH_HOST_KEYS\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms $SSH_HOST_KEYS\n\nPubkeyAcceptedAlgorithms $SSH_HOST_KEYS\n\n" > /etc/crypto-policies/back-ends/opensshserver.config
            else
                 log_info "[DRY-RUN] Would update /etc/crypto-policies/back-ends/opensshserver.config"
            fi
        ;;

        *)
            log_error "Estas en Amazon Linux version $version_num y no se ha implementado nada para ello todavía"
            return 1
        ;;
    esac
    restart_ssh || return 1
}

function Rocky() {
	version_num=$1
	if [ $version_num -lt 9 ]; then
		log_error "Tu versión de Rocky Linux ($version_num) es demasiado antigua."
        return 1
	fi
    
    log_success "Tu versión de Rocky Linux ($version_num) es compatible."

    case $version_num in
        "10" | "9")
            regeneratekeys || return 1
            moduli || return 1
            apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS" "RequiredRSASize 3072" || return 1
        ;;

        *)
            log_error "Estas en Rocky Linux version $version_num y no se ha implementado nada para ello todavía"
            return 1
        ;;
    esac
    restart_ssh || return 1
}

function UCore() {
	version_num=$1
	if [ $version_num -lt 16 ]; then
		log_error "Tu versión de Ubuntu Core ($version_num) es demasiado antigua."
        return 1
	fi
    
    log_success "Tu versión de Ubuntu Core ($version_num) es compatible."

    case $version_num in
        "18" | "17")
            if [ "$DRY_RUN" = false ]; then
                ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key -N "" -q
                ssh-keygen -t ed25519 -f ssh_host_ed25519_key -N "" -q
                echo "Be sure to upload the following 4 files to the target device's /etc/ssh directory: ssh_host_ed25519_key, ssh_host_ed25519_key.pub, ssh_host_rsa_key, ssh_host_rsa_key.pub"
            else
                log_info "[DRY-RUN] Would generate keys in CWD"
            fi

            moduli || return 1
            
            # Using custom extra arg for HostKeys in config
            apply_server_hardening \
                "$SSH_KEX_COMPAT" \
                "$SSH_CIPHERS" \
                "$SSH_MACS" \
                "" \
                "" || return 1
        ;;

        "16")
            if [ "$DRY_RUN" = false ]; then
                ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key -N "" -q
                ssh-keygen -t ed25519 -f ssh_host_ed25519_key -N "" -q
                echo "Be sure to upload the following 4 files to the target device's /etc/ssh directory: ssh_host_ed25519_key, ssh_host_ed25519_key.pub, ssh_host_rsa_key, ssh_host_rsa_key.pub"
            else
                 log_info "[DRY-RUN] Would generate keys and filter moduli"
            fi
            moduli || return 1

            safe_sed 's/^MACs \(.*\)$/\#MACs \1/g' /etc/ssh/sshd_config
            apply_server_hardening "" "" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" "" || return 1
        ;;

        *)
            log_error "Estas en Ubuntu Core version $version_num y no se ha implementado nada para ello todavía"
            return 1
        ;;
    esac
    restart_ssh || return 1
}

function pfSense() {
	version_num=$1
	if [ $version_num -lt 2 ]; then
		log_error "Tu versión de pfSense ($version_num) es demasiado antigua."
        return 1
	fi
    
    log_success "Tu versión de pfSense ($version_num) es compatible."

    case $version_num in
        "2")
            regeneratekeys || return 1
            moduli || return 1
            
            if [ "$DRY_RUN" = false ]; then
                sed -i.bak 's/^MACs \(.*\)$/\#MACs \1/g' /etc/ssh/sshd_config && rm /etc/ssh/sshd_config.bak
            else
                 log_info "[DRY-RUN] Would backup and sed sshd_config"
            fi
            
            apply_server_hardening "" "" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" "" || return 1
        ;;

        *)
            log_error "Estas en pfSense version $version_num y no se ha implementado nada para ello todavía"
            return 1
        ;;
    esac
    restart_ssh || return 1
}

function OpenBSD() {
	version_num=$1
	if [ $version_num -lt 6 ]; then
		log_error "Tu versión de OpenBSD ($version_num) es demasiado antigua."
        return 1
	fi
    
    log_success "Tu versión de OpenBSD ($version_num) es compatible."

    case $version_num in
        "6" | "7" | "8")
            regeneratekeys || return 1
            moduli || return 1
            
            # Merged HostKey logic into apply_server_hardening
            apply_server_hardening \
                "$SSH_KEX_COMPAT" \
                "$SSH_CIPHERS" \
                "$SSH_MACS" \
                "ssh-ed25519" || return 1
        ;;

        *)
            log_error "Estas en OpenBSD version $version_num y no se ha implementado nada para ello todavía"
            return 1
        ;;
    esac
    restart_ssh || return 1
}

function UbuntuC() {
	version_num=$1
	if [ "$version_num" -lt 14 ]; then
		log_error "Tu versión de Ubuntu ($version_num) es demasiado antigua."
        return 1
	fi

    log_success "Tu versión de Ubuntu ($version_num) es compatible."

    case $version_num in
        "25" | "24" | "23" | "22" | "21")
            apply_client_hardening "$SSH_CIPHERS" "$SSH_KEX" "$SSH_MACS" "$SSH_HOST_KEYS"
        ;;

        "20" | "19")
            apply_client_hardening \
                "$SSH_CIPHERS" \
                "$SSH_KEX_COMPAT" \
                "$SSH_MACS" \
                "$SSH_HOST_KEYS_COMPAT"
        ;;

        "18" | "17")
            apply_client_hardening \
                "$SSH_CIPHERS" \
                "$SSH_KEX_COMPAT" \
                "$SSH_MACS" \
                "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512"
        ;;

        "16" | "15")
            apply_client_hardening \
                "$SSH_CIPHERS" \
                "$SSH_KEX_LEGACY" \
                "$SSH_MACS" \
                "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512"
        ;;

        *)
            log_error "Estas en Ubuntu version $version_num y no se ha implementado nada para ello todavía."
            return 1
        ;;
    esac
}

function DebianC() {
	version_num=$1
	if [ $version_num -lt 12 ]; then
		log_error "Tu versión de Debian ($version_num) es demasiado antigua."
        return 1
	fi

    log_success "Tu versión de Debian ($version_num) es compatible."

    case $version_num in
        "13" | "12")
            apply_client_hardening "$SSH_CIPHERS" "$SSH_KEX" "$SSH_MACS" "$SSH_HOST_KEYS"
        ;;

        *)
            log_error "Estas en Debian version $version_num y no se ha implementado nada para ello todavía."
            return 1
        ;;
    esac
}

function AmazonC() {
	version_num=$1
	if [ $version_num -lt 2023 ]; then
		log_error "Tu versión de Amazon Linux ($version_num) es demasiado antigua."
        return 1
	fi

    log_success "Tu versión de Amazon Linux ($version_num) es compatible."

    case $version_num in
        "2023")
            apply_client_hardening "$SSH_CIPHERS" "$SSH_KEX" "$SSH_MACS" "$SSH_HOST_KEYS"
        ;;

        *)
            log_error "Estas en Amazon Linux version $version_num y no se ha implementado nada para ello todavía"
            return 1
        ;;
    esac
}

function RockyC() {
	version_num=$1
	if [ $version_num -lt 9 ]; then
		log_error "Tu versión de Rocky Linux ($version_num) es demasiado antigua."
        return 1
	fi

    log_success "Tu versión de Rocky Linux ($version_num) es compatible."

    case $version_num in
        "10" | "9")
            apply_client_hardening "$SSH_CIPHERS" "$SSH_KEX" "$SSH_MACS" "$SSH_HOST_KEYS"
        ;;

        *)
            log_error "Estas en Rocky Linux version $version_num y no se ha implementado nada para ello todavía"
            return 1
        ;;
    esac
}

function Fedora() {
    version_num=$1
    if [ "$version_num" != "rolling" ] && { [ -z "$version_num" ] || ! [ "$version_num" -ge 36 ] 2>/dev/null; }; then
        log_error "Tu versión de Fedora ($version_num) es demasiado antigua. Se requiere Fedora 36+."
        return 1
    fi

    log_success "Tu versión de Fedora ($version_num) es compatible."

    regeneratekeys || return 1
    if [ "$DRY_RUN" = false ]; then
        local ssh_group
        ssh_group=$(get_ssh_keys_group)
        if [ -n "$ssh_group" ]; then
            chgrp "$ssh_group" /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
            chmod g+r /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
        fi
    else
        log_info "[DRY-RUN] Would chgrp/chmod keys"
    fi

    moduli || return 1
    apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS" "RequiredRSASize 3072" || return 1
    restart_ssh || return 1
}

function openSUSE() {
    version_num=$1
    log_success "Aplicando SSH Hardening para openSUSE ($version_num)..."

    regeneratekeys || return 1
    moduli || return 1
    apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS" || return 1
    restart_ssh || return 1
}

function Arch() {
    version_num=$1
    log_success "Aplicando SSH Hardening para Arch Linux (rolling release)..."

    regeneratekeys || return 1
    moduli || return 1
    apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS" "RequiredRSASize 3072" || return 1
    restart_ssh || return 1
}

function FedoraC() {
    version_num=$1
    log_success "Tu versión de Fedora ($version_num) es compatible."
    apply_client_hardening "$SSH_CIPHERS" "$SSH_KEX" "$SSH_MACS" "$SSH_HOST_KEYS"
}

function openSUSEC() {
    version_num=$1
    log_success "Aplicando SSH Client Hardening para openSUSE ($version_num)..."
    apply_client_hardening "$SSH_CIPHERS" "$SSH_KEX" "$SSH_MACS" "$SSH_HOST_KEYS"
}

function ArchC() {
    version_num=$1
    log_success "Aplicando SSH Client Hardening para Arch Linux (rolling)..."
    apply_client_hardening "$SSH_CIPHERS" "$SSH_KEX" "$SSH_MACS" "$SSH_HOST_KEYS"
}

function Alpine() {
    version_num=$1
    log_success "Aplicando SSH Hardening para Alpine Linux ($version_num)..."

    regeneratekeys || return 1
    moduli || return 1
    apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS" "RequiredRSASize 3072" || return 1
    restart_ssh || return 1
}

function AlpineC() {
    version_num=$1
    log_success "Aplicando SSH Client Hardening para Alpine Linux ($version_num)..."
    apply_client_hardening "$SSH_CIPHERS" "$SSH_KEX" "$SSH_MACS" "$SSH_HOST_KEYS"
}

function RHEL() {
    version_num=$1
    if [ "$version_num" -lt 8 ]; then
        log_error "Tu versión de RHEL ($version_num) es demasiado antigua. Se requiere RHEL 8+."
        return 1
    fi

    log_success "Tu versión de RHEL ($version_num) es compatible."

    case $version_num in
        "10" | "9")
            regeneratekeys || return 1
            moduli || return 1
            apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS" "RequiredRSASize 3072" || return 1
            ;;

        "8")
            regeneratekeys || return 1
            if [ "$DRY_RUN" = false ]; then
                local ssh_group
                ssh_group=$(get_ssh_keys_group)
                if [ -n "$ssh_group" ]; then
                    chgrp "$ssh_group" /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
                    chmod g+r /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
                fi
            else
                log_info "[DRY-RUN] Would chgrp/chmod keys"
            fi
            moduli || return 1
            if [ "$DRY_RUN" = false ]; then
                cp /etc/crypto-policies/back-ends/opensshserver.config \
                   /etc/crypto-policies/back-ends/opensshserver.config.orig
                echo "CRYPTO_POLICY='-oCiphers=chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr -oMACs=hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com -oGSSAPIKexAlgorithms=gss-curve25519-sha256- -oKexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256 -oHostKeyAlgorithms=ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512 -oPubkeyAcceptedKeyTypes=ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512'" \
                    > /etc/crypto-policies/back-ends/opensshserver.config
            else
                log_info "[DRY-RUN] Would update /etc/crypto-policies/back-ends/opensshserver.config"
            fi
            ;;

        *)
            log_error "Estas en RHEL version $version_num y no se ha implementado nada para ello todavía."
            return 1
            ;;
    esac
    restart_ssh || return 1
}

function RHELC() {
    version_num=$1
    if [ "$version_num" -lt 8 ]; then
        log_error "Tu versión de RHEL ($version_num) es demasiado antigua. Se requiere RHEL 8+."
        return 1
    fi

    log_success "Tu versión de RHEL ($version_num) es compatible."
    apply_client_hardening "$SSH_CIPHERS" "$SSH_KEX" "$SSH_MACS" "$SSH_HOST_KEYS"
}
