#!/bin/bash

#--------------------------------------------------------------------------------
# Interactive Menu System
#--------------------------------------------------------------------------------

function prompt_checklist() {
    # Check for whiptail or dialog
    local tool=""
    if command -v whiptail &>/dev/null; then
        tool="whiptail"
    elif command -v dialog &>/dev/null; then
        tool="dialog"
    fi

    if [ -n "$tool" ]; then
        # GUI Menu
        local selections
        selections=$($tool --title "KratoSSH Hardening Suite" \
            --checklist "Select hardening modules to apply (Space to toggle, Enter to confirm):" \
            20 78 6 \
            "CRYPTO" "Modern Encryption (Ciphers/Kex)" ON \
            "AUTH" "Authentication & Access (Root/Pass/Groups)" OFF \
            "NET" "Network & Protocol (Timeouts/Forwarding)" OFF \
            "MFA" "Multi-Factor Authentication (Google Auth)" OFF \
            "PERIM" "Perimeter Protection (Port/Firewall)" OFF \
            3>&1 1>&2 2>&3)
        
        # Exit if cancelled
        if [ $? -ne 0 ]; then
            log_info "Menu cancelled by user."
            exit 0
        fi
        
        # Remove quotes
        echo "$selections" | tr -d '"'
    else
        # Text Fallback
        echo "----------------------------------------------------"
        echo " KratoSSH Hardening Suite (Interactive Mode)"
        echo "----------------------------------------------------"
        echo "No 'whiptail' or 'dialog' found. Using text mode."
        echo ""
        echo "Select modules to apply (y/n):"
        
        local choices=""
        
        echo -n "Apply Modern Encryption (Crypto)? [Y/n]: "
        read -r resp
        [[ "$resp" =~ ^[yY] || -z "$resp" ]] && choices+="CRYPTO "
        
        echo -n "Apply Authentication & Access Policies? [y/N]: "
        read -r resp
        [[ "$resp" =~ ^[yY] ]] && choices+="AUTH "

        echo -n "Apply Network & Protocol Policies? [y/N]: "
        read -r resp
        [[ "$resp" =~ ^[yY] ]] && choices+="NET "

        echo -n "Apply Multi-Factor Authentication (MFA)? [y/N]: "
        read -r resp
        [[ "$resp" =~ ^[yY] ]] && choices+="MFA "

        echo -n "Apply Perimeter Protection (Port/Firewall)? [y/N]: "
        read -r resp
        [[ "$resp" =~ ^[yY] ]] && choices+="PERIM "

        echo "$choices"
    fi
}

function configure_interactive() {
    local selections=$(prompt_checklist)
    
    # Defaults
    DO_CRYPTO=false
    DO_AUTH=false
    DO_NET=false
    DO_MFA=false
    DO_PERIM=false
    
    # Process Selections
    if [[ "$selections" == *"CRYPTO"* ]]; then DO_CRYPTO=true; fi
    if [[ "$selections" == *"AUTH"* ]]; then DO_AUTH=true; fi
    if [[ "$selections" == *"NET"* ]]; then DO_NET=true; fi
    if [[ "$selections" == *"MFA"* ]]; then DO_MFA=true; fi
    if [[ "$selections" == *"PERIM"* ]]; then DO_PERIM=true; fi

    if [ "$DO_CRYPTO" = false ] && [ "$DO_AUTH" = false ] && [ "$DO_NET" = false ] && [ "$DO_MFA" = false ] && [ "$DO_PERIM" = false ]; then
        log_warn "No modules selected. Exiting."
        exit 0
    fi
    
    # Collect Configuration for Selected Modules
    
    # AUTH
    if [ "$DO_AUTH" = true ]; then
        echo -en " ${TBlue}[?]${TDefault} Allow specific group only? (Enter for 'ssh-users', type group name, or 'skip'): "
        read -r group_resp
        if [ "$group_resp" == "skip" ]; then 
            AUTH_GROUP=""
        elif [ -n "$group_resp" ]; then 
            AUTH_GROUP="$group_resp"
        else
            AUTH_GROUP="ssh-users"
        fi
    fi

    # PERIMETER
    if [ "$DO_PERIM" = true ]; then
        echo -en " ${TBlue}[?]${TDefault} Enter new SSH Port (default 22): "
        read -r port_resp
        PERIM_PORT="${port_resp:-22}"
    fi
    
    # MFA
    if [ "$DO_MFA" = true ]; then
        echo -en " ${TBlue}[?]${TDefault} Install and configure Google Authenticator MFA? (y/n) "
        read -r mfa_resp
        if [[ ! "$mfa_resp" =~ ^[yY] ]]; then
            DO_MFA=false
        fi
    fi
    
    log_info "Configuration Complete."
}
