#!/bin/bash

#--------------------------------------------------------------------------------
# Distribution Specific Hardening Functions
#--------------------------------------------------------------------------------

function Ubuntu() {
	version_num=$1
	if [ "$version_num" -lt 14 ]; then
		log_error "Tu versión de Ubuntu ($version_num) es demasiado antigua."
        return
	fi
    
    log_success "Tu versión de Ubuntu ($version_num) es compatible."

    if [ "$version_num" -ge 21 ]; then
        regeneratekeys
        moduli
        # Enable RSA and ED25519 keys
        safe_sed 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
        apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS"
    elif [ "$version_num" -ge 19 ]; then
        regeneratekeys
        moduli
        safe_sed 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
        apply_server_hardening \
            "$SSH_KEX_COMPAT" \
            "$SSH_CIPHERS" \
            "$SSH_MACS" \
            "$SSH_HOST_KEYS_COMPAT"
    elif [ "$version_num" -ge 17 ]; then
        regeneratekeys
        moduli
        # Disable DSA and ECDSA
        safe_sed 's/^HostKey \/etc\/ssh\/ssh_host_\(dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
        apply_server_hardening \
            "$SSH_KEX_COMPAT" \
            "$SSH_CIPHERS" \
            "$SSH_MACS" \
            "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com"
    elif [ "$version_num" -ge 15 ]; then
        regeneratekeys
        moduli
        safe_sed 's/^HostKey \/etc\/ssh\/ssh_host_\(rsa\|dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
        apply_server_hardening \
            "$SSH_KEX_LEGACY" \
            "$SSH_CIPHERS" \
            "$SSH_MACS"
    elif [ "$version_num" -ge 14 ]; then
        regeneratekeys
        moduli
        safe_sed 's/^HostKey \/etc\/ssh\/ssh_host_\(dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
        apply_server_hardening \
            "$SSH_KEX_LEGACY" \
            "$SSH_CIPHERS" \
            "$SSH_MACS"
    else
        log_warn " Estas en Ubuntu version $(version) y no se ha implementado nada para ello todavía."
    fi
    #Restart OpenSSH server
    restart_ssh
}

function Debian() {
	version_num=$1
	if [ $version_num -lt 10 ]; then
		log_error "Tu versión de Debian ($version_num) es demasiado antigua."
        return
	fi
    
    log_success "Tu versión de Debian ($version_num) es compatible."

    if [ "$version_num" -ge 12 ]; then
        regeneratekeys
        moduli
        apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS" "RequiredRSASize 3072"
    elif [ "$version_num" -eq 11 ]; then
        regeneratekeys
        safe_sed 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
        moduli
        apply_server_hardening \
            "$SSH_KEX_COMPAT" \
            "$SSH_CIPHERS" \
            "$SSH_MACS" \
            "$SSH_HOST_KEYS_COMPAT"
    elif [ "$version_num" -eq 10 ]; then
        regeneratekeys
        safe_sed 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
        moduli
        apply_server_hardening \
            "$SSH_KEX_COMPAT" \
            "$SSH_CIPHERS" \
            "$SSH_MACS" \
            "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com"
    else
        log_warn " Estas en Debian version $(version_num) y no se ha implementado nada para ello todavía."
    fi
    restart_ssh
}

function CentOS() {
	version_num=$1
	if [ $version_num -lt 7 ]; then
		log_error "Tu versión de CentOS ($version_num) es demasiado antigua."
        return
	fi
    
    log_success "Tu versión de CentOS ($version_num) es compatible."

    case $version_num in
        "8")
            regeneratekeys
            if [ "$DRY_RUN" = false ]; then
                chgrp ssh_keys /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
                chmod g+r /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
            else
                 log_info "[DRY-RUN] Would chgrp/chmod keys"
            fi

            moduli
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
            regeneratekeys
            if [ "$DRY_RUN" = false ]; then
                chgrp ssh_keys /etc/ssh/ssh_host_ed25519_key
                chmod g+r /etc/ssh/ssh_host_ed25519_key
            else
                 log_info "[DRY-RUN] Would regenerate ED25519 key for CentOS 7"
            fi

            moduli
            safe_sed 's/^HostKey \/etc\/ssh\/ssh_host_\(rsa\|dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

            apply_server_hardening \
                "$SSH_KEX_COMPAT" \
                "$SSH_CIPHERS" \
                "$SSH_MACS"
        ;;

        *)
            echo -e " Estas en CentOS version $(version) y no se ha implementado nada para ello todavía."
        ;;
    esac
    restart_ssh
}

function Amazon() {
	version_num=$1
	if [ $version_num -lt 2023 ]; then
		log_error "Tu versión de Amazon Linux ($version_num) es demasiado antigua."
        return
	fi
    
    log_success "Tu versión de Amazon Linux ($version_num) es compatible."

    case $version_num in
        "2023")
            regeneratekeys
            moduli
            
            if [ "$DRY_RUN" = false ]; then
                 echo -e "KexAlgorithms $SSH_KEX\n\nCiphers $SSH_CIPHERS\n\nMACs $SSH_MACS\n\nHostKeyAlgorithms $SSH_HOST_KEYS\n\nCASignatureAlgorithms $SSH_HOST_KEYS\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms $SSH_HOST_KEYS\n\nPubkeyAcceptedAlgorithms $SSH_HOST_KEYS\n\n" > /etc/crypto-policies/back-ends/opensshserver.config
            else
                 log_info "[DRY-RUN] Would update /etc/crypto-policies/back-ends/opensshserver.config"
            fi
        ;;

        *)
            echo -e "Estas en Amazon Linux version $(version) y no se ha implementado nada para ello todavía"
        ;;
    esac
    restart_ssh
}

function Rocky() {
	version_num=$1
	if [ $version_num -lt 9 ]; then
		log_error "Tu versión de Rocky Linux ($version_num) es demasiado antigua."
        return
	fi
    
    log_success "Tu versión de Rocky Linux ($version_num) es compatible."

    case $version_num in
        "10" | "9")
            regeneratekeys
            moduli
            apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS" "RequiredRSASize 3072"
        ;;

        *)
            echo -e "Estas en Rocky Linux version $(version) y no se ha implementado nada para ello todavía"
        ;;
    esac
    restart_ssh
}

function UCore() {
	version_num=$1
	if [ $version_num -lt 16 ]; then
		log_error "Tu versión de Ubuntu Core ($version_num) es demasiado antigua."
        return
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

            moduli
            
            # Using custom extra arg for HostKeys in config
            apply_server_hardening \
                "$SSH_KEX_COMPAT" \
                "$SSH_CIPHERS" \
                "$SSH_MACS" \
                "" \
                "HostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key"
        ;;

        "16")
            if [ "$DRY_RUN" = false ]; then
                ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key -N "" -q
                ssh-keygen -t ed25519 -f ssh_host_ed25519_key -N "" -q
                echo "Be sure to upload the following 4 files to the target device's /etc/ssh directory: ssh_host_ed25519_key, ssh_host_ed25519_key.pub, ssh_host_rsa_key, ssh_host_rsa_key.pub"
            else
                 log_info "[DRY-RUN] Would generate keys and filter moduli"
            fi
            moduli

            safe_sed 's/^MACs \(.*\)$/\#MACs \1/g' /etc/ssh/sshd_config
            apply_server_hardening "" "" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" ""
        ;;

        *)
            echo -e "Estas en Ubuntu Core version $(version) y no se ha implementado nada para ello todavía"
        ;;
    esac
    restart_ssh
}

function pfSense() {
	version_num=$1
	if [ $version_num -lt 2 ]; then
		log_error "Tu versión de pfSense ($version_num) es demasiado antigua."
        return
	fi
    
    log_success "Tu versión de pfSense ($version_num) es compatible."

    case $version_num in
        "2")
            regeneratekeys
            moduli
            
            if [ "$DRY_RUN" = false ]; then
                sed -i.bak 's/^MACs \(.*\)$/\#MACs \1/g' /etc/ssh/sshd_config && rm /etc/ssh/sshd_config.bak
            else
                 log_info "[DRY-RUN] Would backup and sed sshd_config"
            fi
            
            apply_server_hardening "" "" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" ""
        ;;

        *)
            echo -e "Estas en pfSense version $(version_num) y no se ha implementado nada para ello todavía"
        ;;
    esac
    restart_ssh
}

function OpenBSD() {
	version_num=$1
	if [ $version_num -lt 6 ]; then
		log_error "Tu versión de OpenBSD ($version_num) es demasiado antigua."
        return
	fi
    
    log_success "Tu versión de OpenBSD ($version_num) es compatible."

    case $version_num in
        "6" | "7" | "8")
            regeneratekeys
            moduli
            
            # Merged HostKey logic into apply_server_hardening
            apply_server_hardening \
                "$SSH_KEX_COMPAT" \
                "$SSH_CIPHERS" \
                "$SSH_MACS" \
                "ssh-ed25519"
        ;;

        *)
            echo -e "Estas en OpenBSD version $(version_num) y no se ha implementado nada para ello todavía"
        ;;
    esac
    restart_ssh
}

function UbuntuC() {
	version_num=$1
	if [ "$version_num" -lt 14 ]; then
		log_error "Tu versión de Ubuntu ($version_num) es demasiado antigua."
        return
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
            echo -e " Estas en Ubuntu version $(version_num) y no se ha implementado nada para ello todavía."
        ;;
    esac
}

function DebianC() {
	version_num=$1
	if [ $version_num -lt 12 ]; then
		log_error "Tu versión de Debian ($version_num) es demasiado antigua."
        return
	fi

    log_success "Tu versión de Debian ($version_num) es compatible."

    case $version_num in
        "13" | "12")
            apply_client_hardening "$SSH_CIPHERS" "$SSH_KEX" "$SSH_MACS" "$SSH_HOST_KEYS"
        ;;

        *)
            echo -e " Estas en Debian version $(version_num) y no se ha implementado nada para ello todavía."
        ;;
    esac
}

function AmazonC() {
	version_num=$1
	if [ $version_num -lt 2023 ]; then
		log_error "Tu versión de Amazon Linux ($version_num) es demasiado antigua."
        return
	fi

    log_success "Tu versión de Amazon Linux ($version_num) es compatible."

    case $version_num in
        "2023")
            apply_client_hardening "$SSH_CIPHERS" "$SSH_KEX" "$SSH_MACS" "$SSH_HOST_KEYS"
        ;;

        *)
            echo -e "Estas en Amazon Linux version $(version_num) y no se ha implementado nada para ello todavía"
        ;;
    esac
}

function RockyC() {
	version_num=$1
	if [ $version_num -lt 9 ]; then
		log_error "Tu versión de Rocky Linux ($version_num) es demasiado antigua."
        return
	fi

    log_success "Tu versión de Rocky Linux ($version_num) es compatible."

    case $version_num in
        "10" | "9")
            apply_client_hardening "$SSH_CIPHERS" "$SSH_KEX" "$SSH_MACS" "$SSH_HOST_KEYS"
        ;;

        *)
            echo -e "Estas en Rocky Linux version $(version_num) y no se ha implementado nada para ello todavía"
        ;;
    esac
}
