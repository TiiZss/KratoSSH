# KratoSSH - CryptoHarden

[![Version](https://img.shields.io/github/v/tag/TiiZss/KratoSSH?label=version)](https://github.com/TiiZss/KratoSSH/releases)
[![Built with Bash](https://img.shields.io/badge/built%20with-GNU%20Bash-4EAA25?logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/github/license/TiiZss/KratoSSH)](https://github.com/TiiZss/KratoSSH/blob/main/LICENSE)
[![Downloads](https://img.shields.io/github/downloads/TiiZss/KratoSSH/total)](https://github.com/TiiZss/KratoSSH/releases)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg?logo=paypal)](https://www.paypal.com/donate/?business=AC5N3XX2KGY2S&no_recurring=0&item_name=Seguir+con+el+desarrollo+de+la+herramienta&currency_code=EUR)

![KratoSSH - CryptoHarden](./KratoSSH.png)
Bash script to harden an SSH server and allow only strong encryption algorithms to be accepted by the server, as well as being able to harden the SSH connection if you use it as a client.<br />
Working and tested on Ubuntu 20.04/22.04, Debian 10/11/12, CentOS 8, Rocky Linux 9 and WSL<br /><br />
  
Available for SSH server on:
* Debian 10/11/12
* Ubuntu 14.04 to 24.04
* Ubuntu Core 16/18
* Rocky Linux 9
* Amazon Linux 2023
* CentOS 7/8
* RedHat Enterprise Linux 7/8
* OpenBSD 6.2
* pfSense 2.4
* Alpine Linux

Available for SSH client on:
* Debian 12
* Ubuntu 16.04/18.04/20.04/22.04
* Linux Mint 18/19/20/21
* Rocky Linux 9
* Amazon Linux 2023
* Alpine Linux

## How To
You can use this script directly without downloading it or you can download and run it.

### Without download
You have to be root or use sudo to run it
```
curl -sL https://raw.githubusercontent.com/TiiZss/KratoSSH/main/KratoSSH.sh | bash -s
```
### With download
#### 1) Clone the repo
Clone this repo, or download it any way you prefer
```
git clone https://github.com/TiiZss/KratoSSH.git
cd KratoSSH
chmod +x KratoSSH.sh
```
#### Usage
You have to be root or use sudo to run it
```
./KratoSSH.sh [OPTIONS]
```

### Options
* `-d, --dry-run`: Simulate changes without modifying any files.
* `-a, --auto`: Run in non-interactive mode (requires `--type`).
* `-t, --type [server|client]`: Specify operation type for auto mode.
* `--audit`: Run a security audit against localhost using `ssh-audit` (automatically detects custom SSH ports).
* `-r, --restore`: Restore SSH host keys from backup.

### Examples

**Interactive Mode (Default)**
```bash
./KratoSSH.sh
```

**Dry Run (Check what would happen)**
```bash
./KratoSSH.sh --dry-run
```

**Automated Server Hardening**
```bash
./KratoSSH.sh --auto --type server
```

**Security Audit**
```bash
./KratoSSH.sh --audit
```

## Next machines / steps
* Include other distributions
