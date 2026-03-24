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
FORCE_REGENERATE=false
FIX_PORT=""
CLIENT_APP="openssh"
AUDIT_CLIENT=false
AUDIT_CLIENT_STRICT=false
AUDIT_JSON=false
AUDIT_JSON_PRETTY=false
AUDIT_SUMMARY=false

function require_option_value() {
    local option_name="$1"
    local option_value="$2"

    if [ -z "$option_value" ] || [[ "$option_value" == -* ]]; then
        log_error "Option $option_name requires a value."
        exit 1
    fi
}

function normalize_client_app() {
    local app
    app="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
    printf '%s' "$app"
}

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
source "$SCRIPT_DIR/lib/thirdparty_clients.sh" || { echo "Failed to load lib/thirdparty_clients.sh"; exit 1; }

trap cleanup EXIT INT TERM

function detect_os() {
    if [ -n "${KRATOSSH_TEST_OS_NAME:-}" ] && [ -n "${KRATOSSH_TEST_OS_VERSION:-}" ]; then
        name="$KRATOSSH_TEST_OS_NAME"
        version="$KRATOSSH_TEST_OS_VERSION"
    elif [ -f "/etc/alpine-release" ]; then
        name="Alpine"
        version=$(cat /etc/alpine-release)
    elif [ -f "/etc/os-release" ]; then
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
	if [[ $name == *"Red Hat"* ]]; then
		name="RHEL"
		log_info "Detectado Red Hat Enterprise Linux $version_num"
	elif [[ $name == *"Red"* ]]; then
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
        name="Fedora"
    elif [[ $name == *"AlmaLinux"* ]]; then
        log_info "Detectado AlmaLinux, usando configuración de Rocky Linux $version_num"
        name="Rocky"
    elif [[ $name == *"Oracle"* ]]; then
        log_info "Detectado Oracle Linux, usando configuración de Rocky Linux $version_num"
        name="Rocky"
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
        case "$CLIENT_APP" in
            openssh)
                target_fn+="C"
                log_info "Applying OpenSSH client hardening for $name $version_num..."
                if [ "$AUTO_MODE" = false ]; then
                    echo -en " ${TBlue}[?]${TDefault} Confirm apply OpenSSH client hardening? (y/n) "
                    read -r resp
                    [[ ! "$resp" =~ ^[yY] ]] && log_info "Aborted by user." && exit 0
                fi
                if ! $target_fn "$version_num"; then
                    die "Client hardening failed for $name $version_num"
                fi
                ;;
            putty)
                log_info "Applying PuTTY client hardening profile..."
                if ! apply_putty_hardening "$SCRIPT_DIR"; then
                    die "PuTTY client hardening failed"
                fi
                ;;
            bitvise)
                log_info "Applying Bitvise client hardening profile..."
                if ! apply_bitvise_hardening "$SCRIPT_DIR"; then
                    die "Bitvise client hardening failed"
                fi
                ;;
            securecrt)
                log_info "Applying SecureCRT client hardening profile..."
                if ! apply_securecrt_hardening "$SCRIPT_DIR"; then
                    die "SecureCRT client hardening failed"
                fi
                ;;
            macos-ssh)
                log_info "Applying macOS native SSH config hardening..."
                if ! apply_macos_ssh_hardening; then
                    die "macOS SSH config hardening failed"
                fi
                ;;
            winscp)
                log_info "Applying WinSCP client hardening profile..."
                if ! apply_winscp_hardening "$SCRIPT_DIR"; then
                    die "WinSCP client hardening failed"
                fi
                ;;
            termius)
                log_info "Applying Termius client hardening profile..."
                if ! apply_termius_hardening "$SCRIPT_DIR"; then
                    die "Termius client hardening failed"
                fi
                ;;
            mobaxterm)
                log_info "Applying MobaXterm client hardening profile..."
                if ! apply_mobaxterm_hardening "$SCRIPT_DIR"; then
                    die "MobaXterm client hardening failed"
                fi
                ;;
            *)
                die "Unknown client app '$CLIENT_APP' (valid: $(list_supported_clients))"
                ;;
        esac
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
        STRICT_MFA=false
        
        if [ "$AUTO_MODE" = false ]; then
            # Launch Interactive Menu to set DO_* variables
            configure_interactive
            if [ -n "$FIX_PORT" ]; then
                DO_PERIM=true
                PERIM_PORT="$FIX_PORT"
                log_info "Override: perimeter correction enabled on port $PERIM_PORT."
            fi
        else
            # AUTO MODE: Defaults to Classic KratoSSH (Crypto Only) or we could enable all?
            # Sticking to Crypto Only for safety in auto unless flags added later.
            log_info "Auto-mode: Applying standard Crypto Hardening only."
            if [ -n "$FIX_PORT" ]; then
                DO_PERIM=true
                PERIM_PORT="$FIX_PORT"
                log_info "Auto-mode: perimeter correction enabled on port $PERIM_PORT."
            fi
        fi
        
        # 2. Pre-Audit
        log_info "Running PRE-HARDENING Audit..."
        audit_system || log_warn "Pre-audit encountered issues. Continuing..."
        
        # 3. Execution Phase
        
        # Crypto
        if [ "$DO_CRYPTO" = true ]; then
            if ! $target_fn "$version_num"; then
                die "Crypto hardening failed for $name $version_num"
            fi
        else
            log_info "Skipping Crypto Hardening (not selected)."
        fi
        
        # Auth
        if [ "$DO_AUTH" = true ]; then
            # Default strict settings: Root=no, Pass=no, Empty=no, Tries=3, Sessions=2
            apply_auth_hardening "no" "no" "no" "3" "2" "$AUTH_GROUP" || die "Authentication hardening failed"
        fi
        
        # Network
        if [ "$DO_NET" = true ]; then
            apply_network_hardening "no" "no" "no" "300" "0" || die "Network hardening failed"
        fi
        
        # MFA
        if [ "$DO_MFA" = true ]; then
            apply_mfa_hardening "$STRICT_MFA" || die "MFA hardening failed"
        fi
        
        # Perimeter
        if [ "$DO_PERIM" = true ]; then
            apply_perimeter_hardening "$PERIM_PORT" || die "Perimeter hardening failed"
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
            log_info "Audit mode enabled (read-only): no hardening changes will be applied."
            audit_system
            exit $?
            ;;
        --audit-client)
            AUDIT_CLIENT=true
            shift
            ;;
        --strict)
            AUDIT_CLIENT_STRICT=true
            shift
            ;;
        --json)
            AUDIT_JSON=true
            shift
            ;;
        --json-pretty)
            AUDIT_JSON=true
            AUDIT_JSON_PRETTY=true
            shift
            ;;
        --summary)
            AUDIT_SUMMARY=true
            shift
            ;;
        --verify)
            # verify_hardening_state performs local post-hardening checks
            verify_hardening_state
            exit $?
            ;;
        --fix)
            TARGET_TYPE="server"
            AUTO_MODE=true
            shift
            ;;
        --fix-port)
            require_option_value "--fix-port" "${2:-}"
            FIX_PORT="$2"
            shift 2
            ;;
        --list-clients)
            list_supported_clients
            exit 0
            ;;
        --client-app)
            require_option_value "--client-app" "${2:-}"
            CLIENT_APP="$(normalize_client_app "$2")"
            shift 2
            ;;
        --fast)
            FAST_MODE=true
            log_info "Fast mode enabled: Skipping moduli generation."
            shift
            ;;
        --force-regenerate)
            FORCE_REGENERATE=true
            log_warn "Force key regeneration enabled. Existing host keys will be rotated."
            shift
            ;;
        -h|--help)
            display_logo
            echo "Usage: $0 [OPTIONS]"
            echo "  -d, --dry-run       Simulate changes without applying"
            echo "  -a, --auto          Skip confirmation prompts"
            echo "  -t, --type [C|S]    Specify Client (C) or Server (S)"
            echo "  -r, --restore       Restore SSH keys from latest backup"
            echo "  --audit             Run read-only security audit on localhost"
            echo "  --audit-client      Run read-only client profile audit (use with --client-app [APP] or all)"
            echo "  --strict            With --audit-client, fail when profile sources are missing/unavailable"
            echo "  --json              With --audit-client, emit JSON array to stdout (human log to stderr)"
            echo "  --json-pretty       With --audit-client, emit stable sorted pretty JSON for deterministic CI diffs"
            echo "  --summary           With --audit-client, print a per-client pass/fail/warn count table"
            echo "  --verify            Run post-hardening verification checks"
            echo "  --fix               Apply server crypto hardening (auto server mode)"
            echo "  --fix-port [PORT]   With --fix, also set SSH port and perimeter rules"
            echo "  --client-app [APP]  Client app (with --type client): $(list_supported_clients)"
            echo "  --list-clients      Print all supported client-app values and exit"
            echo "  --fast              Skip time-consuming moduli generation"
            echo "  --force-regenerate  Force host key rotation during hardening"
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
CLIENT_APP="$(normalize_client_app "$CLIENT_APP")"

if [ "$AUDIT_CLIENT" = true ]; then
    audit_client_hardening "$CLIENT_APP"
    exit $?
fi

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
