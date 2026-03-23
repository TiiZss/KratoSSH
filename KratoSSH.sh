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
iamroot=false
DRY_RUN=false
AUTO_MODE=false
TARGET_TYPE=""
FAST_MODE=false

# Source Libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/utils.sh" || { echo "Failed to load lib/utils.sh"; exit 1; }
source "$SCRIPT_DIR/lib/hardening.sh" || { echo "Failed to load lib/hardening.sh"; exit 1; }
source "$SCRIPT_DIR/lib/audit.sh" || { echo "Failed to load lib/audit.sh"; exit 1; }
source "$SCRIPT_DIR/lib/distros.sh" || { echo "Failed to load lib/distros.sh"; exit 1; }
source "$SCRIPT_DIR/lib/auth.sh" || { echo "Failed to load lib/auth.sh"; exit 1; }
source "$SCRIPT_DIR/lib/network.sh" || { echo "Failed to load lib/network.sh"; exit 1; }
source "$SCRIPT_DIR/lib/mfa.sh" || { echo "Failed to load lib/mfa.sh"; exit 1; }
source "$SCRIPT_DIR/lib/perimeter.sh" || { echo "Failed to load lib/perimeter.sh"; exit 1; }
source "$SCRIPT_DIR/lib/menu.sh" || { echo "Failed to load lib/menu.sh"; exit 1; }

function detect_os() {
    if [ -f "/etc/os-release" ]; then
		. /etc/os-release
		name="${NAME}"
		version="${VERSION_ID}"
	elif [ -f "/etc/version" ]; then
		name="pfSense"
		version=$(cat /etc/version)
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
            "22")
				version_num="24"
				log_info "Estas usando Linux Mint 22, que tiene el mismo SSH Hardening que $name $version_num"
			;;
			*)
				echo -e "Estas en Linux Mint version $version_num y no se ha implementado nada para ello todavía"
				exit 1
			;;
		esac
	elif [[ $name == *"Kali"* ]]; then
		name="Debian"
        # Kali rolling is often simpler to treat as recent Debian
        version_num="12"
        log_info "Estas usando Kali Linux, aplicando SSH Hardening de $name $version_num"
    elif [[ $name == *"Fedora"* ]]; then
        name="CentOS"
        log_info "Estas usando Fedora, aplicando SSH Hardening de CentOS..."
    elif [[ $name == *"AlmaLinux"* ]]; then
        name="CentOS"
        log_info "Estas usando AlmaLinux, aplicando SSH Hardening de CentOS..."
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
			*)
				log_error "Tu versión ($version_num) de Parrot OS no tiene SSH Hardening todavía"
				exit 1
			;;
		esac
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
        # -- SERVER HARDENING FLOW --
        log_info "Applying Server Hardening for $name $version_num..."
        
        # 1. Configuration Phase
        # Defaults
        DO_CRYPTO=true
        DO_AUTH=false
        DO_NET=false
        DO_MFA=false
        DO_PERIM=false
        
        if [ "$AUTO_MODE" = false ]; then
            # Launch Interactive Menu to set DO_* variables
            configure_interactive
        else
            # AUTO MODE: Defaults to Classic KratoSSH (Crypto Only) or we could enable all?
            # Sticking to Crypto Only for safety in auto unless flags added later.
            log_info "Auto-mode: Applying standard Crypto Hardening only."
        fi
        
        # 2. Pre-Audit
        log_info "Running PRE-HARDENING Audit..."
        audit_system || log_warn "Pre-audit encountered issues. Continuing..."
        
        # 3. Execution Phase
        
        # Crypto
        if [ "$DO_CRYPTO" = true ]; then
            $target_fn "$version_num"
        else
            log_info "Skipping Crypto Hardening (not selected)."
        fi
        
        # Auth
        if [ "$DO_AUTH" = true ]; then
            # Default strict settings: Root=no, Pass=no, Empty=no, Tries=3, Sessions=2
            apply_auth_hardening "no" "no" "no" "3" "2" "$AUTH_GROUP"
        fi
        
        # Network
        if [ "$DO_NET" = true ]; then
            apply_network_hardening "no" "no" "no" "300" "0"
        fi
        
        # MFA
        if [ "$DO_MFA" = true ]; then
            apply_mfa_hardening
        fi
        
        # Perimeter
        if [ "$DO_PERIM" = true ]; then
            apply_perimeter_hardening "$PERIM_PORT"
        fi
        
        # 4. Post-Audit
        log_info "Running POST-HARDENING Audit..."
        audit_system || log_warn "Post-audit encountered issues."
    fi
}

function run_interactive() {
    # If using menu logic, we ask Client vs Server first?
    # Menu system is designed for Server hardening suite.
    # We'll keep the top level simple.
    
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

#########################
# Main Execution Logic  #
#########################

# Parse Args
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--restore)
            checkroot
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
            # audit_system doesn't strictly need root if only auditing local port
            audit_system
            exit $?
            ;;
        --fast)
            FAST_MODE=true
            log_info "Fast mode enabled: Skipping moduli generation."
            shift
            ;;
        -h|--help)
            display_logo
            echo "Usage: $0 [OPTIONS]"
            echo "  -d, --dry-run       Simulate changes without applying"
            echo "  -a, --auto          Skip confirmation prompts"
            echo "  -t, --type [C|S]    Specify Client (C) or Server (S)"
            echo "  -r, --restore       Restore SSH keys from latest backup"
            echo "  --audit             Run security audit on localhost"
            echo "  --fast              Skip time-consuming moduli generation"
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
        log_error "Unknown target type: $TARGET_TYPE (use server or client)"
        exit 1
    fi
else
    # Default interactive
    run_interactive
fi
