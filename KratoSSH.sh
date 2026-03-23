#!/bin/bash
#--------------------------------------------------------------------------------                  
# ████████╗██╗██╗███████╗███████╗███████╗
# ╚══██╔══╝██║██║╚══███╔╝██╔════╝██╔════╝
#    ██║   ██║██║  ███╔╝ ███████╗███████╗
#    ██║   ██║██║ ███╔╝  ╚════██║╚════██║
#    ██║   ██║██║███████╗███████║███████║
#    ╚═╝   ╚═╝╚═╝╚══════╝╚══════╝╚══════╝
# Based on https://www.ssh-audit.com/hardening_guides.html
# Made by TiiZss people: TiiZss, Cryoox
#--------------------------------------------------------------------------------                  

#General Vars
#General Vars
iamroot=false
DRY_RUN=false
AUTO_MODE=false
TARGET_TYPE=""

#Tmux vars
session_name="kratossh"
tmux_main_window="kratossh-Main"
no_hardcore_exit=0

#########################
# Text Style            #
#########################
TDefault="\e[0m"
TBold="\e[1m"
TUnderline="\e[2m"

#########################
# Text Colors           #
#########################
#########################
# Text Colors           #
#########################
TDefault="\e[0m"
TBlack="\e[0;30m"
TRed="\e[0;31m"
TGreen="\e[0;32m"
TYellow="\e[0;33m"
TBlue="\e[0;34m"
TMagenta="\e[0;35m"
TCian="\e[0;36m"
TWhite="\e[0;37m"

#########################
# Background Colors     #
#########################
#BGDefault="\e[4m"
BGBlack="\e[40m"
BGRed="\e[41m"
BGGreen="\e[42m"
BGYellow="\e[43m"
BGBlue="\e[44m"
BGCian="\e[45m"
BGMagenta="\e[46m"
BGWhite="\e[47m"

#--------------------------------------------------------------------------------
# SSH Hardening Configuration Constants
#--------------------------------------------------------------------------------
# As per ssh-audit.com hardening guides
SSH_KEX="sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256"
SSH_CIPHERS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
SSH_MACS="hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com"
SSH_HOST_KEYS="sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256"


#--------------------------------------------------------------------------------
# Logging Helper Functions
#--------------------------------------------------------------------------------
function log_info() {
    echo -e "${TBlue}[INFO] [$(date +'%H:%M:%S')]${TDefault} $1"
}

function log_success() {
    echo -e "${TGreen}[OK]   [$(date +'%H:%M:%S')]${TDefault} $1"
}

function log_warn() {
    echo -e "${TYellow}[WARN] [$(date +'%H:%M:%S')]${TDefault} $1"
}

function log_error() {
    echo -e "${TRed}[ERR]  [$(date +'%H:%M:%S')]${TDefault} $1" >&2
}

function die() {
    log_error "$1"
    exit 1
}

function print_date () {
	# Portable: date -r works on both GNU and BSD
	fecha_creacion=$(date -r "$0" 2>/dev/null || stat -c %y "$0" 2>/dev/null || date)
	echo "$fecha_creacion"
}

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

function display_logo() { 
	echo -e " ---------------------------------------------------------------------------------"
	echo -e "   __    __                      __                 ______    ______   __    __   "
	echo -e "  |  \  /  \  TiiZss            |  \               /      \  /      \ |  \  |  \  "
	echo -e "  | ## /  ##  ______   ______  _| ##_     ______  |  ######\|  ######\| ##  | ##  "
	echo -e "  | ##/  ##  /      \ |      \|   ## \   /      \ | ##___\##| ##___\##| ##__| ##  "
	echo -e "  | ##  ##  |  ######\ \######\ ######  |  ######\ \##    \  \##    \ | ##    ##  "
	echo -e "  | #####\  | ##   \##/      ## | ## __ | ##  | ## _\######\ _\######\| ########  "
	echo -e "  | ## \##\ | ##     |  ####### | ##|  \| ##__/ ##|  \__| ##|  \__| ##| ##  | ##  "
	echo -e "  | ##  \##\| ##      \##    ##  \##  ## \##    ## \##    ## \##    ##| ##  | ##  "
	echo -e "   \##   \## \##       \#######   \####   \######   \######   \######  \##   \##  "
	echo -e "                                                                                  "
	echo -e " Script for hardening SSH Crypto functions v.$(print_date)                        "
	echo -e " ---------------------------------------------------------------------------------"
}

function checkroot() {
	if [[ "$(id -u)" -eq 0 ]]; then
		# El usuario es root
		# Ejecutar comandos como root
		#echo "Ejecutando comandos como root..."
		iamroot=true
		# ...
	else
		# El usuario no es root
		echo "Necesitas ejecutar este script como root."
		echo "Utiliza 'sudo' o 'su' para elevar privilegios."
		iamroot=false
		exit 1
	fi
}

function regeneratekeys(){
	# Backup existing keys
    local backup_dir="/etc/ssh/backup_keys_$(date +%Y%m%d_%H%M%S)"
    log_info "Backing up existing SSH keys to ${backup_dir}..."
    mkdir -p "$backup_dir"
    
    if ls /etc/ssh/ssh_host_* &> /dev/null; then
        mv /etc/ssh/ssh_host_* "$backup_dir/" || die "Failed to backup keys."
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
        awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
        mv /etc/ssh/moduli.safe /etc/ssh/moduli
        log_success "Moduli filtered."
    else
        log_warn "/etc/ssh/moduli not found. Skipping."
    fi
}

function apply_atomic_sshd_config() {
    local content="$1"
    local config_file="/etc/ssh/sshd_config"
    local temp_config="/tmp/sshd_config.new.$(date +%s)"
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would apply the following config to $config_file:"
        echo -e "$content"
        return 0
    fi

    # Create backup before any modifications
    cp "$config_file" "${config_file}.bak.$(date +%Y%m%d_%H%M%S)"

    # Prepare new config
    cp "$config_file" "$temp_config"
    
    # Remove existing block if present to avoid duplication/conflict
    # We use a temporary file for sed to avoid issues
    if grep -q "KratoSSH Hardening" "$temp_config"; then
        sed -i '/# BEGIN KratoSSH Hardening/,/# END KratoSSH Hardening/d' "$temp_config"
    fi
    
    echo -e "\n# BEGIN KratoSSH Hardening\n$content\n# END KratoSSH Hardening" >> "$temp_config"

    # Validate
    log_info "Validating new configuration..."
    if sshd -t -f "$temp_config"; then
        log_success "New configuration is valid. Applying..."
        cp "$temp_config" "$config_file"
        rm -f "$temp_config"
    else
        log_error "New configuration is INVALID. Aborting changes."
        log_error "You can inspect the failed config at $temp_config"
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
    
    if ! grep -q "KratoSSH Hardening" "$config_file" 2>/dev/null; then
         echo -e "\n# BEGIN KratoSSH Hardening\nHost *\n Ciphers $ciphers\n KexAlgorithms $kex\n MACs $macs\n HostKeyAlgorithms $hostkeys\n CASignatureAlgorithms $hostkeys\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n HostbasedAcceptedAlgorithms $hostkeys\n PubkeyAcceptedAlgorithms $hostkeys\n# END KratoSSH Hardening" >> "$config_file"
         log_success "Updated client config at $config_file"
    else
         log_warn "KratoSSH config already in client config. Skipping."
    fi
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
    
    # Ideally we would restore sshd_config here too if we backed it up.
}

function generomoduli() {
	ssh-keygen -G /etc/ssh/moduli.all -b 4096
	ssh-keygen -T /etc/ssh/moduli.safe -f /etc/ssh/moduli.all
	mv /etc/ssh/moduli.safe /etc/ssh/moduli
	rm /etc/ssh/moduli.all
}

function moduli() {
  # Comprobar si existe el archivo /etc/ssh/moduli
  if [ ! -f "/etc/ssh/moduli" ]; then
    # El archivo no existe, ejecutar acciones
    echo "El archivo /etc/ssh/moduli no existe. Vamos a crearlo."
	generomoduli
  fi
  removemoduli
}

function safe_sed() {
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would run sed: $@"
        return 0
    fi
    # GNU sed uses -i without argument; BSD sed requires -i ''
    if sed --version 2>/dev/null | grep -q GNU; then
        sed -i "$@"
    else
        sed -i '' "$@"
    fi
}

function get_ssh_keys_group() {
    if getent group ssh_keys &>/dev/null; then
        echo "ssh_keys"
    elif getent group ssh &>/dev/null; then
        echo "ssh"
    else
        echo ""
    fi
}

function Ubuntu() {
	version_num=$1
	if [ "$version_num" -lt 14 ]; then
		log_error "Tu versión de Ubuntu ($version_num) es demasiado antigua."
        return
	fi
    
    log_success "Tu versión de Ubuntu ($version_num) es compatible."

    case $version_num in
        "25" | "24" | "23" | "22" | "21")
            regeneratekeys
            moduli
            # Enable RSA and ED25519 keys
            safe_sed 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
            apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS"
        ;;

        "20" | "19")
            regeneratekeys
            moduli
            safe_sed 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
            apply_server_hardening \
                "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256" \
                "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" \
                "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" \
                "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com"
        ;;

        "18" | "17")
            regeneratekeys
            moduli
            # Disable DSA and ECDSA
            safe_sed 's/^HostKey \/etc\/ssh\/ssh_host_\(dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
            apply_server_hardening \
                "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256" \
                "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" \
                "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" \
                "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com"
        ;;

        "16" | "15")
            rm /etc/ssh/ssh_host_* 2>/dev/null
            ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
            moduli
            safe_sed 's/^HostKey \/etc\/ssh\/ssh_host_\(rsa\|dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
            apply_server_hardening \
                "curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" \
                "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" \
                "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com"
        ;;

        "14")
            regeneratekeys
            moduli
            safe_sed 's/^HostKey \/etc\/ssh\/ssh_host_\(dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
            apply_server_hardening \
                "curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" \
                "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" \
                "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com"
        ;;

        Default)
            echo -e " Estas en Ubuntu version $(version) y no se ha implementado nada para ello todavía."
        ;;
    esac
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

    case $version_num in
        "13" | "12")
            regeneratekeys
            moduli
            apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS" "RequiredRSASize 3072"
        ;;

        "11")
            rm -f /etc/ssh/ssh_host_* 2>/dev/null
            regeneratekeys
            safe_sed 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
            moduli
            apply_server_hardening \
                "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256" \
                "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" \
                "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" \
                "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com"
        ;;

        "10")
            regeneratekeys
            safe_sed 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
            moduli
            apply_server_hardening \
                "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256" \
                "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" \
                "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" \
                "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com"
        ;;

        Default)
            echo -e " Estas en Debian version $(version_num) y no se ha implementado nada para ello todavía."
        ;;
    esac
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
                local ssh_group
                ssh_group=$(get_ssh_keys_group)
                if [ -n "$ssh_group" ]; then
                    chgrp "$ssh_group" /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
                    chmod g+r /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
                fi
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

            # Re-generate the ED25519 key
            if [ "$DRY_RUN" = false ]; then
                rm -f /etc/ssh/ssh_host_*
                ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
                local ssh_group
                ssh_group=$(get_ssh_keys_group)
                if [ -n "$ssh_group" ]; then
                    chgrp "$ssh_group" /etc/ssh/ssh_host_ed25519_key
                    chmod g+r /etc/ssh/ssh_host_ed25519_key
                fi
            else
                 log_info "[DRY-RUN] Would regenerate ED25519 key for CentOS 7"
            fi

            moduli
            safe_sed 's/^HostKey \/etc\/ssh\/ssh_host_\(rsa\|dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

            apply_server_hardening \
                "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256" \
                "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" \
                "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com"
        ;;

        Default)
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

        Default)
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

        Default)
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
                "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256" \
                "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" \
                "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" \
                "" \
                "HostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key"
        ;;

        "16")
            if [ "$DRY_RUN" = false ]; then
                ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key -N "" -q
                ssh-keygen -t ed25519 -f ssh_host_ed25519_key -N "" -q
                echo "Be sure to upload the following 4 files to the target device's /etc/ssh directory: ssh_host_ed25519_key, ssh_host_ed25519_key.pub, ssh_host_rsa_key, ssh_host_rsa_key.pub"
            
                awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
                mv /etc/ssh/moduli.safe /etc/ssh/moduli
            else
                 log_info "[DRY-RUN] Would generate keys and filter moduli"
            fi

            safe_sed 's/^MACs \(.*\)$/\#MACs \1/g' /etc/ssh/sshd_config
            apply_server_hardening "" "" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" ""
        ;;

        Default)
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

        Default)
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
                "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256" \
                "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" \
                "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" \
                "ssh-ed25519"
        ;;

        Default)
            echo -e "Estas en OpenBSD version $(version_num) y no se ha implementado nada para ello todavía"
        ;;
    esac
    restart_ssh
}

function Fedora() {
    version_num=$1
    if [ "$version_num" != "rolling" ] && { [ -z "$version_num" ] || ! [ "$version_num" -ge 36 ] 2>/dev/null; }; then
        log_error "Tu versión de Fedora ($version_num) es demasiado antigua. Se requiere Fedora 36+."
        return
    fi

    log_success "Tu versión de Fedora ($version_num) es compatible."

    regeneratekeys
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

    moduli
    apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS" "RequiredRSASize 3072"
    restart_ssh
}

function openSUSE() {
    version_num=$1
    log_success "Aplicando SSH Hardening para openSUSE ($version_num)..."

    regeneratekeys
    moduli
    apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS"
    restart_ssh
}

function Arch() {
    version_num=$1
    log_success "Aplicando SSH Hardening para Arch Linux (rolling release)..."

    regeneratekeys
    moduli
    apply_server_hardening "$SSH_KEX" "$SSH_CIPHERS" "$SSH_MACS" "$SSH_HOST_KEYS" "RequiredRSASize 3072"
    restart_ssh
}

# Funciones para SSH Hardening de cliente

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
                "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" \
                "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256" \
                "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" \
                "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"
        ;;

        "18" | "17")
            apply_client_hardening \
                "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" \
                "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256" \
                "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" \
                "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512"
        ;;

        "16" | "15")
             apply_client_hardening \
                "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" \
                "curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" \
                "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" \
                "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512"
        ;;

        Default)
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

        Default)
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

        Default)
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

        Default)
            echo -e "Estas en Rocky Linux version $(version_num) y no se ha implementado nada para ello todavía"
        ;;
    esac
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

function detect_os() {
    if [ -f "/etc/os-release" ]; then
		name=$(cat /etc/os-release | grep -i "^NAME" | cut -d "=" -f 2 | tr -d '"')
		version=$(cat /etc/os-release | grep -i "VERSION_ID" | cut -d "=" -f 2 | tr -d '"')
	elif [ -f "/etc/version" ]; then
		name="pfSense"
		version=$()
	else
		name="OpenBSD"
		version=$(uname -r)
	fi

	# Convertir la versión a un número entero
	if [[ $version == *"."* ]]; then
		version_num=${version%%.*}
	else
		version_num=$version
	fi

	#Corta name si tiene un espacio y filtra algunas distros que tienen la misma instalación. La salida "Debian GNU/Linux" la dejaría en "Debian"
	if [[ $name == *"Red"* ]]; then
		name="CentOS"
	elif [[ $name == *"Mint"* ]]; then
		name="Ubuntu"
		case $version_num in
			"18")
				version_num="16"
				log_info "Estas usando Linux Mint 18, que tiene el mismo SSH Hardening que $name $version_num"
			;;
			"19")
				version_num="18"
				log_info "Estas usando Linux Mint 19, que tiene el mismo SSH Hardening que $name $version_num"
			;;
			"20")
				version_num="20"
				log_info "Estas usando Linux Mint 20, que tiene el mismo SSH Hardening que $name $version_num"
			;;
			"21")
				version_num="22"
				log_info "Estas usando Linux Mint 21, que tiene el mismo SSH Hardening que $name $version_num"
			;;
			"22" | "23")
				version_num="24"
				log_info "Estas usando Linux Mint 22/23, que tiene el mismo SSH Hardening que $name $version_num"
			;;
			Default)
				log_error "Tu versión ($version_num) de Linux Mint no tiene SSH Hardening todavía"
				exit 1
			;;
		esac
	elif [[ $name == *"Ubuntu Core"* ]]; then
		name="UCore"
	elif [[ $name == *"Kali"* ]]; then
		name="Debian"
		case $version_num in
			"2020" | "2021")
				version_num="10"
				log_info "Estas usando Kali Linux 2020/2021, que tiene el mismo SSH Hardening que $name $version_num"
			;;
			"2022")
				version_num="11"
				log_info "Estas usando Kali Linux 2022, que tiene el mismo SSH Hardening que $name $version_num"
			;;
			"2023" | "2024" | "2025")
				version_num="12" 
				log_info "Estas usando Kali Linux 2023+, que tiene el mismo SSH Hardening que $name $version_num"
			;;
			Default)
				log_error "Tu versión ($version_num) de Kali Linux no tiene SSH Hardening todavía"
				exit 1
			;;
		esac
	elif [[ $name == *"Parrot"* ]]; then
		name="Debian"
		case $version_num in
			"4")
				version_num="10"
				log_info "Estas usando Parrot OS 4, que tiene el mismo SSH Hardening que $name $version_num"
			;;
			"5")
				version_num="11"
				log_info "Estas usando Parrot OS 5, que tiene el mismo SSH Hardening que $name $version_num"
			;;
			"6" | "7")
				version_num="12"
				log_info "Estas usando Parrot OS 6+, que tiene el mismo SSH Hardening que $name $version_num"
			;;
			Default)
				log_error "Tu versión ($version_num) de Parrot OS no tiene SSH Hardening todavía"
				exit 1
			;;
		esac
	elif [[ $name == *"AlmaLinux"* ]]; then
		log_info "Detectado AlmaLinux, usando configuración de Rocky Linux $version_num"
		name="Rocky"
	elif [[ $name == *"Oracle"* ]]; then
		log_info "Detectado Oracle Linux, usando configuración de Rocky Linux $version_num"
		name="Rocky"
	elif [[ $name == *"Fedora"* ]]; then
		name="Fedora"
	elif [[ $name == *"openSUSE"* ]] || [[ $name == *"SUSE"* ]]; then
		if [[ $name == *"Tumbleweed"* ]] || [ "${version_num:-0}" -gt 20000 ] 2>/dev/null; then
			version_num="tumbleweed"
		fi
		name="openSUSE"
	elif [[ $name == *"Arch"* ]] || [[ $name == *"Manjaro"* ]] || [[ $name == *"EndeavourOS"* ]] || [[ $name == *"Garuda"* ]]; then
		name="Arch"
		version_num="rolling"
	elif [[ $name == *"Pop"* ]]; then
		log_info "Detectado Pop!_OS, usando configuración de Ubuntu $version_num"
		name="Ubuntu"
	elif [[ $name == *"elementary"* ]]; then
		local orig_version="$version_num"
		case $version_num in
			"5") version_num="18" ;;
			"6") version_num="20" ;;
			"7") version_num="22" ;;
			*)   version_num="22" ;;
		esac
		log_info "Detectado elementary OS $orig_version, usando configuración de Ubuntu $version_num"
		name="Ubuntu"
	elif [[ $name == *"Zorin"* ]]; then
		local orig_version="$version_num"
		case $version_num in
			"16") version_num="20" ;;
			"17") version_num="22" ;;
			*)    version_num="22" ;;
		esac
		log_info "Detectado Zorin OS $orig_version, usando configuración de Ubuntu $version_num"
		name="Ubuntu"
	elif [[ $name == *"MX"* ]]; then
		log_info "Detectado MX Linux, usando configuración de Debian $version_num"
		name="Debian"
	elif [[ $name == *"Raspbian"* ]]; then
		log_info "Detectado Raspbian, usando configuración de Debian $version_num"
		name="Debian"
	fi

	if [[ $name == *" "* ]]; then
		name=${name%% *}
	fi
}

function run_hardening() {
    local target_fn="$name"
    local target_type="$1"
    
    if [ "$target_type" == "client" ]; then
        target_fn+="C"
        log_info "Applying Client Hardening for $name $version_num..."
        if [ "$AUTO_MODE" = false ]; then
            echo -en " ${TBlue}[?]${TDefault} Confirm apply client hardening? (y/n) "
            read -r resp
            [[ ! "$resp" =~ ^[yY] ]] && log_info "Aborted by user." && exit 0
        fi
        $target_fn "$version_num"
    else
        log_info "Applying Server Hardening for $name $version_num..."
        if [ "$AUTO_MODE" = false ]; then
            echo -en " ${TBlue}[?]${TDefault} Confirm apply server hardening? (y/n) "
            read -r resp
            [[ ! "$resp" =~ ^[yY] ]] && log_info "Aborted by user." && exit 0
        fi
        $target_fn "$version_num"
    fi
}

function run_interactive() {
	echo -en " ${TBlue}[?]${TDefault} ¿Estás instalandolo para un servidor o cliente? (C/S) "
	read -r respuestaclienteservidor
	if [[ "$respuestaclienteservidor" =~ ^[cC]$ ]]; then
        run_hardening "client"
	elif [[ "$respuestaclienteservidor" =~ ^[sS]$ ]]; then
		run_hardening "server"
	else
		log_error "Responde con 'C' o 'S'"
		exit 1
	fi
}

function audit_system() {
    log_info "Starting SSH Audit..."
    
    # Check for python3
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required for auditing but not found. Please install python3."
        return 1
    fi

    local audit_script="/tmp/ssh-audit.py"
    local audit_url="https://raw.githubusercontent.com/jtesta/ssh-audit/master/src/ssh_audit/ssh_audit.py"
    
    # Download if not present or empty
    if [ ! -s "$audit_script" ]; then
        log_info "Downloading ssh-audit.py..."
        if [ "$DRY_RUN" = true ]; then
             log_info "[DRY-RUN] Would download $audit_url to $audit_script"
             # Mock existence for dry-run flow if needed, or just return
             return 0
        fi

        if command -v curl &> /dev/null; then
            curl -sSL "$audit_url" -o "$audit_script" || { log_error "Failed to download ssh-audit via curl"; return 1; }
        elif command -v wget &> /dev/null; then
            wget -q "$audit_url" -O "$audit_script" || { log_error "Failed to download ssh-audit via wget"; return 1; }
        else
            log_error "Neither curl nor wget found. Cannot download ssh-audit."
            return 1
        fi
    fi
    
    log_info "Running audit against localhost..."
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would run: python3 $audit_script localhost"
        return 0
    fi
    
    python3 "$audit_script" localhost
}

#########################
# Main Execution Logic  #
#########################

# Parse Args
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--restore)
            restore_backup
            exit 0
            ;;
        -d|--dry-run)
            DRY_RUN=true
            log_warn "DRY RUN MODE ACTIVATED. No changes will be made."
            shift
            ;;
        -t|--type)
            TARGET_TYPE="$2"
            shift 2
            ;;
        -a|--auto)
            AUTO_MODE=true
            shift
            ;;
        --audit)
            audit_system
            exit $?
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "  -d, --dry-run     Simulate changes"
            echo "  -a, --auto        Skip confirmation prompts"
            echo "  -t, --type [C|S]  Specify Client (C) or Server (S)"
            echo "  -r, --restore     Restore from backup"
            echo "  --audit           Run security audit on localhost"
            exit 0
            ;;
        *)
            log_error "Unknown argument: $1"
            exit 1
            ;;
    esac
done

display_logo
checkroot
detect_os

if [ -n "$TARGET_TYPE" ]; then
    if [[ "$TARGET_TYPE" =~ ^[cC][lL][iI][eE][nN][tT]$ ]] || [[ "$TARGET_TYPE" =~ ^[cC]$ ]]; then
        run_hardening "client"
    elif [[ "$TARGET_TYPE" =~ ^[sS][eE][rR][vV][eE][rR]$ ]] || [[ "$TARGET_TYPE" =~ ^[sS]$ ]]; then
        run_hardening "server"
    else
        log_error "Invalid target type: $TARGET_TYPE. Use 'client'/'C' or 'server'/'S'."
        exit 1
    fi
else
    # Interactive mode
    run_interactive
fi

