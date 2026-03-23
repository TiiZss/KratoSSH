#!/bin/bash

#########################
# Audit Functions       #
#########################

_AUDIT_UPDATED=false

function audit_system() {
    log_info "Starting SSH Audit..."
    
    # Check for python3
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required for auditing but not found. Please install python3."
        return 1
    fi

    # Determine script location
    # Since this is sourced, BASH_SOURCE[0] is this file. We need the root dir.
    # Assuming lib/audit.sh is sourced by KratoSSH.sh in the root.
    # We can rely on SCRIPT_DIR being defined in the main script OR verify path relative to this file.
    
    local lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local root_dir="$(dirname "$lib_dir")"
    local audit_script="$root_dir/ssh-audit/ssh-audit.py"
    
    # Check if bundled script exists
    if [ ! -f "$audit_script" ]; then
        log_error "Bundled ssh-audit not found at $audit_script."
        log_error "Please verify usage of the full repository."
        return 1
    fi

    # Auto-update if it's a git repo (only once per session)
    if [ -d "$root_dir/ssh-audit/.git" ] && [ "$_AUDIT_UPDATED" = false ]; then
        _AUDIT_UPDATED=true
        log_info "Checking for ssh-audit updates..."
        if [ "$DRY_RUN" = true ]; then
             log_info "[DRY-RUN] Would run 'git pull' in $root_dir/ssh-audit"
        else
            # Save current directory
            pushd "$root_dir/ssh-audit" > /dev/null
            if timeout 10 git pull --quiet; then
                log_success "ssh-audit updated successfully."
            else
                log_warn "Failed to update ssh-audit (or timed out). Continuing with current version."
            fi
            popd > /dev/null
        fi
    fi
    
    log_info "Running audit against localhost..."
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would run: python3 $audit_script localhost"
        return 0
    fi
    
    # Use the bundled script which handles paths correctly
    python3 "$audit_script" localhost
}
