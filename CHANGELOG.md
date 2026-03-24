# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
