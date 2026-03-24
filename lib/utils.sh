#!/bin/bash

#########################
# Text Style & Colors   #
#########################
TDefault="\e[0m"
TBold="\e[1m"
TUnderline="\e[2m"

TBlack="\e[0;30m"
TRed="\e[0;31m"
TGreen="\e[0;32m"
TYellow="\e[0;33m"
TBlue="\e[0;34m"
TMagenta="\e[0;35m"
TCian="\e[0;36m"
TWhite="\e[0;37m"

BGBlack="\e[40m"
BGRed="\e[41m"
BGGreen="\e[42m"
BGYellow="\e[43m"
BGBlue="\e[44m"
BGCian="\e[45m"
BGMagenta="\e[46m"
BGWhite="\e[47m"

#########################
# Logging Helper Functions
#########################
function log_info() {
    printf "${TBlue}[INFO] [%(%H:%M:%S)T]${TDefault} %s\n" -1 "$1"
}

function log_success() {
    printf "${TGreen}[OK]   [%(%H:%M:%S)T]${TDefault} %s\n" -1 "$1"
}

function log_warn() {
    printf "${TYellow}[WARN] [%(%H:%M:%S)T]${TDefault} %s\n" -1 "$1"
}

function log_error() {
    printf "${TRed}[ERR]  [%(%H:%M:%S)T]${TDefault} %s\n" -1 "$1" >&2
}

function die() {
    log_error "$1"
    exit 1
}

function print_date () {
	# Portable: date -r works on both GNU and BSD
	date -r "$0" 2>/dev/null || stat -c %y "$0" 2>/dev/null || date
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

function ssh_etc_dir() {
    echo "${SSH_ETC_DIR:-/etc/ssh}"
}

function ssh_main_config() {
    echo "$(ssh_etc_dir)/sshd_config"
}

function ssh_dropin_dir() {
    echo "$(ssh_etc_dir)/sshd_config.d"
}

function ssh_include_glob() {
    echo "${SSH_INCLUDE_GLOB:-/etc/ssh/sshd_config.d/*.conf}"
}

function ssh_hardening_dropin() {
    echo "$(ssh_dropin_dir)/00-kratossh-hardening.conf"
}

function ssh_host_key_path() {
    local key_name="$1"
    echo "$(ssh_etc_dir)/${key_name}"
}

function display_logo() { 
	echo -e " ---------------------------------------------------------------------------------"
	echo -e "   __    __                      __                 ______    ______   __    __   "
	echo -e "  |  \  /  \  TiiZss            |  \               /      \  /      \ |  \  |  \  "
	echo -e "  | ## /  ##  ______   ______  _| ##_     ______  |  ######\|  ######\| ##  | ##  "
	echo -e "  | ##/  ##  /      \ |      \|   ## \   /      \ | ##___\##| ##___\##| ##__| ##  "
	echo -e "  | ##  ##  |  ######\ \######\ ######  |  ######\ \##    \  \##    \ | ##    ##  "
	echo -e "  | ## \##\ | ##     |  ####### | ##|  \| ##__/ ##|  \__| ##|  \__| ##| ##  | ##  "
	echo -e "  | ##  \##\| ##      \##    ##  \##  ## \##    ## \##    ## \##    ##| ##  | ##  "
	echo -e "   \##   \## \##       \#######   \####   \######   \######   \######  \##   \##  "
	echo -e "                                                                                  "
	echo -e " Script for hardening SSH Crypto functions v.$(print_date)                        "
	echo -e " ---------------------------------------------------------------------------------"
}

function checkroot() {
	if [[ "$(id -u)" -eq 0 ]]; then
		iamroot=true
	else
		echo "Necesitas ejecutar este script como root."
		echo "Utiliza 'sudo' o 'su' para elevar privilegios."
		iamroot=false
		exit 1
	fi
}

function cleanup() {
    if [ -n "${TEMP_CONFIG:-}" ] && [ -f "${TEMP_CONFIG:-}" ]; then
        rm -f "$TEMP_CONFIG"
    fi
}
