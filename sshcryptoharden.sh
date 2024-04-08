#!/bin/bash
#https://www.ssh-audit.com/hardening_guides.html

iamroot=false

#Tmux vars
session_name="sshcryptoharden"
tmux_main_window="sshcryptoharden-Main"
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
	echo -e "                                                                        TiiZss   "
	echo -e " ███████╗███████╗██╗  ██╗    ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗  "
	echo -e " ██╔════╝██╔════╝██║  ██║    ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║  "
	echo -e " ███████╗███████╗███████║    ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║  "
	echo -e " ╚════██║╚════██║██╔══██║    ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║  "
	echo -e " ███████║███████║██║  ██║    ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║  "
	echo -e " ╚══════╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝  "
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
	version=$(cat /etc/os-release | grep -i "VERSION_ID" | cut -d "=" -f 2)
	
	# Convertir la versión a un número entero
	version_num=${version%.*}
	
	# Evaluar la versión
	if [[ "$version_num" -lt 14 ]]; then
		echo "Tu versión de Ubuntu ($version) es demasiado antigua."
		echo "Te recomendamos actualizar a una versión más reciente."
	else
		echo "Tu versión de Ubuntu ($version) es compatible."
		# Re-generate the RSA and ED25519 keys
		rm /etc/ssh/ssh_host_*
		ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
		ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

		# Remove small Diffie-Hellman moduli
		awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
		mv /etc/ssh/moduli.safe /etc/ssh/moduli

		# Enable the RSA and ED25519 keys
		# Enable the RSA and ED25519 HostKey directives in the /etc/ssh/sshd_config file:
		sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

		# Restrict supported key exchange, cipher, and MAC algorithms
		case $(version_num) in
					"23" | "22" | "21")
						echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf
					;;
					
					"20" | "19")
						# Ubuntu 20.04 LTS Server
						echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf
					;;
					
					"18" | "17")
						# Ubuntu 18.04 LTS Server
						echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com" >> /etc/ssh/sshd_config
					;;
					
					"16" | "15" | "14")
						# Ubuntu 16.04 LTS Server
						echo -e "\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
					;;
					
					Default)
						echo -e " Estas en Ubuntu version $(version) y no se ha implmentado nada para ello todavía."
					;;
				esac
		#Restart OpenSSH server
		service ssh restart
	fi
	
}

function chosefunction() {
	name=$(cat /etc/os-release | grep -i "^NAME" | cut -d "=" -f 2 | tr -d '"')
	#name=${name,,}
	if type -t "$name" >/dev/null; then
		# La función existe, ejecutarla
		echo -e " La distribucion que utilizas es $name y tengo una función para actualizar los algoritmos de cifrado que utiliza el servidor SSH para esa distribución."
		echo -en " ¿Quieres actualizarlos? (S/N) "
		read -r respuesta
		if [[ "$respuesta" =~ ^[sS]$ ]]; then
			echo -e " Pues vamos a ello ..." 
			$name
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
display_logo
checkroot
chosefunction

