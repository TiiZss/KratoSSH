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
TDefault="\e[0;0m"
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

function print_date () {
	# Obtener la fecha de creación del script
	fecha_creacion=$(stat -c %y "$0")

	# Imprimir la fecha de creación
	echo "$fecha_creacion"
}

function display_logo() { 
	echo -e " --------------------------------------------------------------------------------"
	echo -e "  __    __                      __                 ______    ______   __    __   "
	echo -e " |  \  /  \  TiiZss            |  \               /      \  /      \ |  \  |  \  "
	echo -e " | ## /  ##  ______   ______  _| ##_     ______  |  ######\|  ######\| ##  | ##  "
	echo -e " | ##/  ##  /      \ |      \|   ## \   /      \ | ##___\##| ##___\##| ##__| ##  "
	echo -e " | ##  ##  |  ######\ \######\ ######  |  ######\ \##    \  \##    \ | ##    ##  "
	echo -e " | #####\  | ##   \##/      ## | ## __ | ##  | ## _\######\ _\######\| ########  "
	echo -e " | ## \##\ | ##     |  ####### | ##|  \| ##__/ ##|  \__| ##|  \__| ##| ##  | ##  "
	echo -e " | ##  \##\| ##      \##    ##  \##  ## \##    ## \##    ## \##    ##| ##  | ##  "
	echo -e "  \##   \## \##       \#######   \####   \######   \######   \######  \##   \##  "
	echo -e "                                                                                 "
	echo -e " Script for hardening SSH Crypto functions v.$(print_date)                       "
	echo -e " --------------------------------------------------------------------------------"
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

function Ubuntu() {
	version_num=$1
	# Evaluar la versión
	if [ "$version_num" -lt 14 ]; then
		echo "Tu versión de Ubuntu ($version_num) es demasiado antigua."
		echo "Te recomendamos actualizar a una versión más reciente."
	else
		echo "Tu versión de Ubuntu ($version_num) es compatible."

		case $version_num in
					"24" | "23" | "22" | "21")
						# Ubuntu 22.04 LTS Server
						# Re-generate the RSA and ED25519 keys
						rm /etc/ssh/ssh_host_*
						ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
						ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

						# Remove small Diffie-Hellman moduli
						awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
						mv /etc/ssh/moduli.safe /etc/ssh/moduli

						# Enable the RSA and ED25519 keys
						sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

						# Restrict supported key exchange, cipher, and MAC algorithms
						echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256" > /etc/ssh/sshd_config.d/kratossh_hardening.conf
					;;

					"20" | "19")
						# Ubuntu 20.04 LTS Server
						# Re-generate the RSA and ED25519 keys
						rm /etc/ssh/ssh_host_*
						ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
						ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

						# Remove small Diffie-Hellman moduli
						awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
						mv /etc/ssh/moduli.safe /etc/ssh/moduli

						# Enable the RSA and ED25519 keys
						sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

						# Restrict supported key exchange, cipher, and MAC algorithms
						echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" > /etc/ssh/sshd_config.d/kratossh_hardening.conf
					;;

					"18" | "17")
						# Ubuntu 18.04 LTS Server
						# Re-generate the RSA and ED25519 keys
						rm /etc/ssh/ssh_host_*
						ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
						ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

						# Remove small Diffie-Hellman moduli
						awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
						mv /etc/ssh/moduli.safe /etc/ssh/moduli

						# Disable the DSA and ECDSA host keys
						sed -i 's/^HostKey \/etc\/ssh\/ssh_host_\(dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

						# Restrict supported key exchange, cipher, and MAC algorithms
						echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com" >> /etc/ssh/sshd_config
					;;

					"16" | "15")
						# Ubuntu 16.04 LTS Server
						# Re-generate ED25519 key
						rm /etc/ssh/ssh_host_*
						ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

						# Remove small Diffie-Hellman moduli
						awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
						mv /etc/ssh/moduli.safe /etc/ssh/moduli

						# Disable the RSA, DSA, and ECDSA host keys
						sed -i 's/^HostKey \/etc\/ssh\/ssh_host_\(rsa\|dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

						# Restrict supported key exchange, cipher, and MAC algorithms
						echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
					;;

					"14")
						# Ubuntu 14.04 LTS Server
						# Re-generate ED25519 key
						rm /etc/ssh/ssh_host_*
						ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
						ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

						# Remove small Diffie-Hellman moduli
						awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
						mv /etc/ssh/moduli.safe /etc/ssh/moduli

						# Disable the DSA and ECDSA host keys
						sed -i 's/^HostKey \/etc\/ssh\/ssh_host_\(dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

						# Restrict supported key exchange, cipher, and MAC algorithms
						echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
					;;

					Default)
						echo -e " Estas en Ubuntu version $(version) y no se ha implementado nada para ello todavía."
					;;
				esac
		#Restart OpenSSH server
		service ssh restart
	fi
}

function Debian() {
	version_num=$1
	# Evaluar la versión
	if [ $version_num -lt 10 ]; then
		echo "Tu versión de Debian ($version_num) es demasiado antigua."
		echo "Te recomendamos actualizar a una versión más reciente."
	else
		echo "Tu versión de Debian ($version_num) es compatible."

		case $version_num in
					"12")
						# Debian 12 (Bookworm)
						# Re-generate the RSA and ED25519 keys
						rm /etc/ssh/ssh_host_*
						ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
						ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

						# Remove small Diffie-Hellman moduli
						awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
						mv /etc/ssh/moduli.safe /etc/ssh/moduli

						# Restrict supported key exchange, cipher, and MAC algorithms
						echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\n KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nRequiredRSASize 3072\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n" > /etc/ssh/sshd_config.d/kratossh_hardening.conf
					;;

					"11")
						# Debian 11 (Bullseye)
						# Re-generate the RSA and ED25519 keys
						rm -f /etc/ssh/ssh_host_*
						ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
						ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

						# Enable the RSA and ED25519 keys
						sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

						# Remove small Diffie-Hellman moduli
						awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
						mv -f /etc/ssh/moduli.safe /etc/ssh/moduli

						# Restrict supported key exchange, cipher, and MAC algorithms
						echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" > /etc/ssh/sshd_config.d/kratossh_hardening.conf
					;;

					"10")
						# Debian 10 (Buster)
						# Re-generate the RSA and ED25519 keys
						rm -f /etc/ssh/ssh_host_*
						ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
						ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""


						# Enable the RSA and ED25519 keys
						sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

						# Remove small Diffie-Hellman moduli
						awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
						mv -f /etc/ssh/moduli.safe /etc/ssh/moduli

						# Restrict supported key exchange, cipher, and MAC algorithms
						echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" >> /etc/ssh/sshd_config
					;;

					Default)
						echo -e " Estas en Debian version $(version) y no se ha implementado nada para ello todavía."
					;;
				esac
		#Restart OpenSSH server
		service ssh restart
	fi
}

function CentOS() {
	version_num=$1
	# Evaluar la versión
	if [ $version_num -lt 7 ]; then
		echo "Tu versión de CentOS ($version_num) es demasiado antigua."
		echo "Te recomendamos actualizar a una versión más reciente."
	else
		echo "Tu versión de CentOS ($version_num) es compatible."

		case $version_num in
					"8")
						# CentOS 8
						# Re-generate the RSA and ED25519 keys
						rm -f /etc/ssh/ssh_host_*
						ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
						ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
						chgrp ssh_keys /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
						chmod g+r /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key

						# Remove small Diffie-Hellman moduli
						awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
						mv -f /etc/ssh/moduli.safe /etc/ssh/moduli

						# Disable ECDSA host key
						sed -i 's/^HostKey \/etc\/ssh\/ssh_host_ecdsa_key$/\#HostKey \/etc\/ssh\/ssh_host_ecdsa_key/g' /etc/ssh/sshd_config

						# Restrict supported key exchange, cipher, and MAC algorithms
						cp /etc/crypto-policies/back-ends/opensshserver.config /etc/crypto-policies/back-ends/opensshserver.config.orig
						echo -e "CRYPTO_POLICY='-oCiphers=chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr -oMACs=hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com -oGSSAPIKexAlgorithms=gss-curve25519-sha256- -oKexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256 -oHostKeyAlgorithms=ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512 -oPubkeyAcceptedKeyTypes=ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512'" > /etc/crypto-policies/back-ends/opensshserver.config
						;;

					"7")
						# CentOS 7
						# Disable automatic re-generation of RSA & ECDSA keys
						mkdir -p /etc/systemd/system/sshd-keygen.service.d
						cat << EOF > /etc/systemd/system/sshd-keygen.service.d/kratossh_hardening.conf
						[Unit]
						ConditionFileNotEmpty=
						ConditionFileNotEmpty=!/etc/ssh/ssh_host_ed25519_key
EOF
						systemctl daemon-reload

						# Re-generate the ED25519 key
						rm -f /etc/ssh/ssh_host_*
						ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
						chgrp ssh_keys /etc/ssh/ssh_host_ed25519_key
						chmod g+r /etc/ssh/ssh_host_ed25519_key

						# Remove small Diffie-Hellman moduli
						awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
						mv -f /etc/ssh/moduli.safe /etc/ssh/moduli

						# Disable the RSA, DSA, and ECDSA host keys
						sed -i 's/^HostKey \/etc\/ssh\/ssh_host_\(rsa\|dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

						# Restrict supported key exchange, cipher, and MAC algorithms
						echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
					;;

					Default)
						echo -e " Estas en CentOS version $(version) y no se ha implementado nada para ello todavía."
					;;
				esac
		#Restart OpenSSH server
		systemctl restart sshd.service
	fi
}

function Amazon() {
	version_num=$1
	# Evaluar la versión
	if [ $version_num -lt 2023 ]; then
		echo "Tu versión de Amazon Linux ($version_num) es demasiado antigua."
		echo "Te recomendamos actualizar a una versión más reciente."
	else
		echo "Tu versión de Amazon Linux ($version_num) es compatible."

		case $version_num in
					"2023")
						# Amazon Linux 2023
						# Re-generate the RSA and ED25519 keys
						rm -f /etc/ssh/ssh_host_*
						ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
						ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

						# Remove small Diffie-Hellman moduli
						awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
						mv -f /etc/ssh/moduli.safe /etc/ssh/moduli

						# Restrict supported key exchange, cipher, and MAC algorithms
						echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n" > /etc/crypto-policies/back-ends/opensshserver.config
					;;

					Default)
						echo -e "Estas en Amazon Linux version $(version) y no se ha implementado nada para ello todavía"
					;;
				esac
		#Restart OpenSSH server
		systemctl restart sshd
	fi
}

function Rocky() {
	version_num=$1
	# Evaluar la versión
	if [ $version_num -lt 9 ]; then
		echo "Tu versión de Rocky Linux ($version_num) es demasiado antigua."
		echo "Te recomendamos actualizar a una versión más reciente."
	else
		echo "Tu versión de Rocky Linux ($version_num) es compatible."

		case $version_num in
					"9")
						# Rocky Linux 9
						# Re-generate the RSA and ED25519 keys
						rm -f /etc/ssh/ssh_host_*
						ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
						ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

						# Remove small Diffie-Hellman moduli
						awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
						mv -f /etc/ssh/moduli.safe /etc/ssh/moduli

						# Restrict supported key exchange, cipher, and MAC algorithms
						echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nRequiredRSASize 3072\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n" > /etc/crypto-policies/back-ends/opensshserver.config
					;;

					Default)
						echo -e "Estas en Rocky Linux version $(version) y no se ha implementado nada para ello todavía"
					;;
				esac
		#Restart OpenSSH server
		systemctl restart sshd
	fi
}

function UCore() {
	version_num=$1
	# Evaluar la versión
	if [ $version_num -lt 16 ]; then
		echo "Tu versión de Ubuntu Core ($version_num) es demasiado antigua."
		echo "Te recomendamos actualizar a una versión más reciente."
	else
		echo "Tu versión de Ubuntu Core ($version_num) es compatible."

		case $version_num in
					"18" | "17")
						# Ubuntu Core 18
						# Re-generate the RSA and ED25519 keys
						ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key -N ""
						ssh-keygen -t ed25519 -f ssh_host_ed25519_key -N ""
						echo "Be sure to upload the following 4 files to the target device's /etc/ssh directory: ssh_host_ed25519_key, ssh_host_ed25519_key.pub, ssh_host_rsa_key, ssh_host_rsa_key.pub"

						# Remove small Diffie-Hellman moduli
						awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
						mv /etc/ssh/moduli.safe /etc/ssh/moduli

						# Restrict supported key exchange, cipher, and MAC algorithms
						echo -e "\n# Only enable RSA and ED25519 host keys.\nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
					;;

					"16")
						# Ubuntu Core 16
						# Re-generate the RSA and ED25519 keys
						ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key -N ""
						ssh-keygen -t ed25519 -f ssh_host_ed25519_key -N ""
						echo "Be sure to upload the following 4 files to the target device's /etc/ssh directory: ssh_host_ed25519_key, ssh_host_ed25519_key.pub, ssh_host_rsa_key, ssh_host_rsa_key.pub"

						# Remove small Diffie-Hellman moduli
						awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
						mv /etc/ssh/moduli.safe /etc/ssh/moduli

						# Restrict supported key exchange, cipher, and MAC algorithms
						sed -i 's/^MACs \(.*\)$/\#MACs \1/g' /etc/ssh/sshd_config
						echo -e "\n# Restrict MAC algorithms, as per sshaudit.com hardening guide.\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
					;;

					Default)
						echo -e "Estas en Ubuntu Core version $(version) y no se ha implementado nada para ello todavía"
					;;
				esac
		#Restart OpenSSH server
		service ssh reload
	fi
}

function pfSense() {
	version_num=$1
	# Evaluar la versión
	if [ $version_num -lt 2 ]; then
		echo "Tu versión de pfSense ($version_num) es demasiado antigua."
		echo "Te recomendamos actualizar a una versión más reciente."
	else
		echo "Tu versión de pfSense ($version_num) es compatible."

		case $version_num in
					"2")
						# pfSense 2
						# Re-generate the RSA and ED25519 keys
						rm /etc/ssh/ssh_host_*
						ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
						ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" 

						# Remove small Diffie-Hellman moduli
						awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
						mv -f /etc/ssh/moduli.safe /etc/ssh/moduli

						# Restrict supported key exchange, cipher, and MAC algorithms
						sed -i.bak 's/^MACs \(.*\)$/\#MACs \1/g' /etc/ssh/sshd_config && rm /etc/ssh/sshd_config.bak
						echo "" | echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
					;;

					Default)
						echo -e "Estas en pfSense version $(version_num) y no se ha implementado nada para ello todavía"
					;;
				esac
		#Restart OpenSSH server
		service sshd onerestart
	fi
}

function OpenBSD() {
	version_num=$1
	# Evaluar la versión
	if [ $version_num -lt 6 ]; then
		echo "Tu versión de OpenBSD ($version_num) es demasiado antigua."
		echo "Te recomendamos actualizar a una versión más reciente."
	else
		echo "Tu versión de OpenBSD ($version_num) es compatible."

		case $version_num in
					"9")
						# OpenBSD 6
						# Re-generate the RSA and ED25519 keys
						rm /etc/ssh/ssh_host_*
						ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
						ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" 

						# Create custom Diffie-Hellman groups
						ssh-keygen -G /etc/ssh/moduli -b 3072

						# Disable the DSA and ECDSA host keys
						echo -e "\n# Restrict host keys to ED25519 and RSA only.\nHostKeyAlgorithms ssh-ed25519\n" >> /etc/ssh/sshd_config

						# Restrict supported key exchange, cipher, and MAC algorithms
						echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
					;;

					Default)
						echo -e "Estas en OpenBSD version $(version_num) y no se ha implementado nada para ello todavía"
					;;
				esac
		#Restart OpenSSH server
		kill -HUP `cat /var/run/sshd.pid`
	fi
}

# Funciones para SSH Hardening de cliente

function UbuntuC() {
	version_num=$1
	# Evaluar la versión
	if [ "$version_num" -lt 14 ]; then
		echo "Tu versión de Ubuntu ($version_num) es demasiado antigua."
		echo "Te recomendamos actualizar a una versión más reciente."
	else
		echo "Tu versión de Ubuntu ($version_num) es compatible."

		case $version_num in
					"23" | "22" | "21")
						# Ubuntu 22.04 LTS Server
						mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n" >> ~/.ssh/config
					;;

					"20" | "19")
						# Ubuntu 20.04 LTS Server
						mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com\n" >> ~/.ssh/config
					;;

					"18" | "17")
						# Ubuntu 18.04 LTS Server
						mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512\n" >> ~/.ssh/config
					;;

					"16" | "15")
						# Ubuntu 16.04 LTS Server
						mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512\n" >> ~/.ssh/config
					;;

					Default)
						echo -e " Estas en Ubuntu version $(version_num) y no se ha implementado nada para ello todavía."
					;;
				esac
	fi
}

function DebianC() {
	version_num=$1
	# Evaluar la versión
	if [ $version_num -lt 12 ]; then
		echo "Tu versión de Debian ($version_num) es demasiado antigua."
		echo "Te recomendamos actualizar a una versión más reciente."
	else
		echo "Tu versión de Debian ($version_num) es compatible."

		case $version_num in
					"12")
						# Debian 12 (Bookworm)
						mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n" >> ~/.ssh/config
					;;

					Default)
						echo -e " Estas en Debian version $(version_num) y no se ha implementado nada para ello todavía."
					;;
				esac
	fi
}

function AmazonC() {
	version_num=$1
	# Evaluar la versión
	if [ $version_num -lt 2023 ]; then
		echo "Tu versión de Amazon Linux ($version_num) es demasiado antigua."
		echo "Te recomendamos actualizar a una versión más reciente."
	else
		echo "Tu versión de Amazon Linux ($version_num) es compatible."

		case $version_num in
					"2023")
						# Amazon Linux 2023
						mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n" >> ~/.ssh/config
					;;

					Default)
						echo -e "Estas en Amazon Linux version $(version_num) y no se ha implementado nada para ello todavía"
					;;
				esac
	fi
}

function RockyC() {
	version_num=$1
	# Evaluar la versión
	if [ $version_num -lt 9 ]; then
		echo "Tu versión de Rocky Linux ($version_num) es demasiado antigua."
		echo "Te recomendamos actualizar a una versión más reciente."
	else
		echo "Tu versión de Rocky Linux ($version_num) es compatible."

		case $version_num in
					"9")
						# Rocky Linux 9
						mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n" >> ~/.ssh/config
					;;

					Default)
						echo -e "Estas en Rocky Linux version $(version_num) y no se ha implementado nada para ello todavía"
					;;
				esac
	fi
}

function choosefunction() {
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
				echo "Estas usando Linux Mint 18, que tiene el mismo SSH Hardening que $name $version_num"
			;;

			"19")
				version_num="18"
				echo "Estas usando Linux Mint 19, que tiene el mismo SSH Hardening que $name $version_num"
			;;

			"20")
				version_num="20"
				echo "Estas usando Linux Mint 20, que tiene el mismo SSH Hardening que $name $version_num"
			;;

			"21")
				version_num="22"
				echo "Estas usando Linux Mint 22, que tiene el mismo SSH Hardening que $name $version_num"
			;;

			Default)
				echo "Tu versión ($version_num) de Linux Mint no tiene SSH Hardening todavía"
				echo "Saliendo..."
				exit 0
			;;
		esac
	elif [[ $name == *"Ubuntu Core"* ]]; then
		name="UCore"
	elif [[ $name == *"Kali"* ]]; then
		name="Debian"
		case $version_num in
			"2020" | "2021")
				version_num="10"
				echo "Estas usando Kali Linux 2020/2021, que tiene el mismo SSH Hardening que $name $version_num"
			;;

			"2022")
				version_num="11"
				echo "Estas usando Kali Linux 2022, que tiene el mismo SSH Hardening que $name $version_num"
			;;

			"2023" | "2024")
				version_num="12"
				echo "Estas usando Kali Linux 2023/2024, que tiene el mismo SSH Hardening que $name $version_num"
			;;

			Default)
				echo "Tu versión ($version_num) de Kali Linux no tiene SSH Hardening todavía"
				echo "Saliendo..."
				exit 0
			;;
		esac
	elif [[ $name == *"Parrot"* ]]; then
		name="Debian"
		case $version_num in
			"4")
				version_num="10"
				echo "Estas usando Parrot OS 4, que tiene el mismo SSH Hardening que $name $version_num"
			;;

			"5")
				version_num="11"
				echo "Estas usando Parrot OS 5, que tiene el mismo SSH Hardening que $name $version_num"
			;;

			"6")
				version_num="12"
				echo "Estas usando Parrot OS 6, que tiene el mismo SSH Hardening que $name $version_num"
			;;

			Default)
				echo "Tu versión ($version_num) de Parrot OS no tiene SSH Hardening todavía"
				echo "Saliendo..."
				exit 0
			;;
		esac
	fi

	if [[ $name == *" "* ]]; then
		name=${name%% *}
	fi

	echo -en "¿Estás instalandolo para un servidor o cliente? Responde con 'C' para cliente o 'S' para servidor (C/S) "
	read -r respuestaclienteservidor
	if [[ "$respuestaclienteservidor" =~ ^[cC]$ ]]; then
		echo "SSH Hardening para $name $version_num (Client)"
		namec=$name
		name+="C"
	elif [[ "$respuestaclienteservidor" =~ ^[sS]$ ]]; then
		echo "SSH Hardening para $name $version_num (Server)"
	else
		echo "Responde con 'C' o 'S'"
		echo "Saliendo..."
		exit 0
	fi

	# Ver si la función existe
	if type -t "$name" >/dev/null; then
		# La función existe, ejecutarla
		if [[ "$respuestaclienteservidor" =~ ^[cC]$ ]]; then
			echo -e " La distribucion que utilizas es $namec y tengo una función para actualizar los algoritmos de cifrado que utiliza el servidor SSH para esa distribución."
		else
			echo -e " La distribucion que utilizas es $name y tengo una función para actualizar los algoritmos de cifrado que utiliza el servidor SSH para esa distribución."
		fi
		echo -en " ¿Quieres actualizarlos? (S/N) "
		read -r respuesta
		if [[ "$respuesta" =~ ^[sS]$ ]]; then
			echo -e " Pues vamos a ello ..."
			$name "$version_num"
		else
			echo -e "Saliendo del script..."
			exit 0
		fi
	else
		# La función no existe, mostrar un mensaje de error
		echo -e "Error: La función '$name' correspondiente para tu distribución no existe."
		echo -e "Saliendo del script..."
		exit 0
	fi
}

#########################
# Main switch case      #
#########################
iamroot=false
display_logo
checkroot
choosefunction