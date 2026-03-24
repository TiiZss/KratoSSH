# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2026-03-24] - v20260324_1515
### Added
- **CLI**: Added `--audit-client` for read-only client profile inspection by `--client-app`.
- **Testing**: Added `tests/test-audit-client.sh` and integrated it into `tests/test-syntax.sh`.
- **Docs**: Added a new `mosh + tmux guidance` section in README with SSH/tmux snippets and recommended workflow.

### Changed
- **README**: Updated options list to include `--audit-client`, `--list-clients`, and the expanded `--client-app` model.
- **Client audit**: Added read-only audits for OpenSSH, PuTTY, macOS SSH block, SecureCRT, WinSCP, Termius, and MobaXterm profiles.

## [2026-03-24] - v20260324_1430
### Added
- **Client hardening**: Added `--client-app mobaxterm` — on Linux/macOS patches `[SSH*]` sections in `MobaXterm.ini` (`SSH_Kex`, `SSH_Cipher`, `SSH_MAC`, `SSH_HostKey`, `SSH_AgentFwd=0`); on Windows/WSL delegates to `windows/mobaxterm_hardening.ps1` which locates the INI in `%APPDATA%\MobaXterm\`, `Documents\MobaXterm\`, and beside the executable.
- **CLI**: Added `--list-clients` flag: prints all supported `--client-app` values (`bitvise macos-ssh mobaxterm openssh putty securecrt termius winscp`) and exits 0.
- **Testing**: Added MobaXterm Linux INI tests (`SSH_Kex`, `SSH_AgentFwd`), MobaXterm Windows fallback test, and `--list-clients` completeness test (checks all 8 clients are listed).

### Changed
- **CLI**: Help text for `--client-app` now dynamically lists all supported values via `list_supported_clients()`.
- **README**: Updated client hardening matrix with MobaXterm rows. Updated Next steps.
### Added
- **Client hardening**: Added `--client-app winscp` — on Linux/macOS patches per-session keys (`KexList`, `CipherList`, `MacList`, `HostKeyList`, `AgentFwd`) in portable `winscp.ini` under `~/.config/` or `~/.local/share/`; on Windows/WSL delegates to `windows/winscp_hardening.ps1` which patches `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions` registry keys and any portable `WinSCP.ini` files.
- **Client hardening**: Added `--client-app termius` — on Linux/macOS uses python3 to patch `storage.json` setting `kex_algorithms`, `ciphers`, `macs`, `host_key_algorithms`, `forward_agent: false`, `forward_x11: false` on all hosts and groups; on Windows/WSL delegates to `windows/termius_hardening.ps1` which does the same via PowerShell `ConvertFrom-Json`/`ConvertTo-Json`.
- **Testing**: Added WinSCP Linux INI tests, WinSCP Windows fallback test, Termius Linux JSON tests (cipher, forward_agent), and Termius Windows fallback test to `test-client-apps.sh`.

### Changed
- **CLI**: `--client-app` now accepts `openssh`, `putty`, `bitvise`, `securecrt`, `macos-ssh`, `winscp`, `termius`.
- **README**: Updated client hardening matrix with WinSCP and Termius rows. Updated Next steps.
### Added
- **Client hardening**: Added `--client-app macos-ssh` — writes a hardened `Host *` block to `~/.ssh/config` on macOS (Darwin) with strong KexAlgorithms, Ciphers, MACs, HostKeyAlgorithms, `ForwardAgent no`, `ForwardX11 no`, `Compression no`, and `RekeyLimit 1G 60m`. Idempotent: re-running replaces the existing KratoSSH block without duplicating it.
- **Client hardening**: Added `--client-app securecrt` — patches per-session `.ini` files under `~/.vandyke/SecureCRT/Config/Sessions/` on Linux/macOS, and falls back to `windows/securecrt_hardening.ps1` on Windows/WSL. The PowerShell script locates VanDyke config in both legacy and modern paths, backs up the full config tree, and patches `Cipher List`, `MAC List`, `Kex List`, `Host Key List`, `Forward Agent`, and `Forward X11` in every session file.
- **Testing**: Added macOS SSH config tests (KexAlgorithms, ForwardAgent, RekeyLimit, idempotency), SecureCRT Linux INI tests (cipher update, ForwardAgent disable), and SecureCRT Windows fallback test to `test-client-apps.sh`.

### Changed
- **CLI**: `--client-app` now accepts `openssh`, `putty`, `bitvise`, `securecrt`, and `macos-ssh`.
- **README**: Updated client hardening matrix with macOS SSH and SecureCRT rows. Updated Next steps.
### Added
- **CLI**: Added `--fix-port [PORT]` to combine crypto hardening with perimeter port correction in `--fix` mode.
- **CLI**: Added `--client-app [openssh|putty|bitvise]` to select client hardening target explicitly.
- **Client hardening**: Added initial PuTTY and Bitvise client hardening support through Linux session-file updates (PuTTY) and PowerShell scripts for Windows/WSL.
- **Testing**: Added functional tests for third-party client hardening (`putty` and `bitvise`) and integrated them into the smoke suite.
- **Testing**: Added distro family matrix tests (supported families, normalized aliases, and unsupported boundaries).

### Fixed
- **Safety**: Updated atomic drop-in writes so multiple KratoSSH blocks (e.g., crypto + perimeter) can coexist without overwriting each other.
- **Reliability**: Unsupported distro/version paths now fail fast with non-zero exit codes instead of returning silent success.
- **Reliability**: Unsupported distro/version paths now fail fast with non-zero exit codes instead of returning silent success.
- **CLI**: Added strict argument validation for `--fix-port` and `--client-app` to prevent missing-value parsing errors.
- **Testing**: Added regression tests to enforce fail-fast behavior for unsupported distro/version combinations.
- **Testing**: Added regression tests for CLI option validation and unsupported client-app handling.

## [2026-03-24] - v20260324_1105
### Added
- **CLI**: Added `--fix` to apply server crypto hardening in non-interactive mode and `--verify` to run post-hardening verification with PASS/FAIL block summaries.
- **Testing**: Added local shell test coverage for syntax, CLI audit/verify flows, fix mode, and transactional rollback scenarios.
- **CI**: Added a GitHub Actions workflow to run Bash smoke tests and `shellcheck` on pushes and pull requests.

### Fixed
- **Audit**: Clarified `--audit` as a read-only mode and ensured custom SSH port detection remains effective through the CLI path.
- **Safety**: Made SSH configuration writes transactional, including automatic `Include /etc/ssh/sshd_config.d/*.conf` preflight with rollback on validation failure.
- **Safety**: Prevented false-success results in distro hardening handlers by propagating failures from key generation, config application, and SSH restart steps.
- **Safety**: Made SSH service restart failures fatal in server hardening flows, preventing successful exits when the daemon could not be restarted.
- **Security**: Made host key regeneration idempotent by default and only rotate keys when explicitly requested with `--force-regenerate`.
- **Reliability**: Fixed `cleanup` and hardening internals to behave correctly under `set -u`, which was exposed by the new shell test suite.
- **Reliability**: Centralized Include directive handling via helpers to remove duplicated hardcoded values and keep runtime/test behavior aligned.

## [2026-03-23] - v20260323_2022
### Fixed
- **Security**: Hardened host key loading by strictly injecting `HostKey` paths directly into `sshd_config`, preventing OS services like `sshd-keygen` from generating and loading weak default keys (e.g. ECDSA/DSA) leading to ssh-audit red flags.

## [2026-03-23] - v20260323_2013
### Fixed
- **Audit**: Fixed `ssh-audit` integration failing when the SSH server operates on a custom or automatically changed port by actively parsing the local configuration to extract that port.

## [2026-03-23] - v20260323_1905
### Added
- **Compatibility**: Added full SSH server and client hardening support for Alpine Linux.
- **Compatibility**: Added detection for the OpenRC init system (`rc-service`).
- **Security**: Added strict MFA enforcement option to remove the `nullok` PAM flag.
- **Safety**: Added safeguards to prevent administrator lockout when using restrict groups in Authentication hardening.
- **Robustness**: Added a timeout constraint to the `ssh-audit` auto-update function to prevent hangs on restricted networks.

## [2026-01-22] - v20260122_1200
### Added
- **Integration**: Added `ssh-audit` integration. Use `--audit` to automatically check local configuration security.
- **CLI Automation**: Added `--dry-run`, `--auto`, and `--type` flags for non-interactive and safe execution.
- **Safety**: Implemented atomic configuration writing (`apply_atomic_sshd_config`) to prevent partial config applications.
- **Safety**: Added `safe_sed` helper to respect dry-run mode.
- **Logging**: Added timestamps to all log messages.
- **Code**: Unified server and client hardening logic to reduce duplication and improve maintainability.
- **Refactor**: Updated all distribution functions (`Ubuntu`, `Debian`, `CentOS`, `Rocky`, `pfsense`, etc.) to use the new unified helpers.





## [2024-04-17] - v20240417_1332
### Added
- Initial project files uploaded.
- README enhancements.

## [2024-04-08] - v202404082036
### Added
- First tagged version.

### Removed
- Removed legacy scripts `sshcryptoharden.sh` and `SSHCriptoHarden.png` in favor of new branding.
