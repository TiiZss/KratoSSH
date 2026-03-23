# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
