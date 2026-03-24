Param()

$ErrorActionPreference = 'Stop'

Write-Host '[KratoSSH] Starting SecureCRT hardening...'

$backupDir = Join-Path $env:USERPROFILE (".kratossh-backups\securecrt-" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# ── Locate SecureCRT config root ──────────────────────────────────────────────
# SecureCRT 9+ stores config under %APPDATA%\VanDyke\SecureCRT\Config\
# Older installs may use %APPDATA%\VanDyke\Config\SecureCRT\
$candidateDirs = @(
    (Join-Path $env:APPDATA 'VanDyke\SecureCRT\Config'),
    (Join-Path $env:APPDATA 'VanDyke\Config\SecureCRT')
)

$configRoot = $candidateDirs | Where-Object { Test-Path $_ } | Select-Object -First 1
$sessionDir  = if ($configRoot) { Join-Path $configRoot 'Sessions' } else { $null }

# ── Backup ────────────────────────────────────────────────────────────────────
if ($configRoot -and (Test-Path $configRoot)) {
    try {
        # xcopy preserves subdirectory structure
        & xcopy /E /I /Y /Q $configRoot $backupDir | Out-Null
    } catch {
        Write-Warning "[KratoSSH] Could not back up SecureCRT config: $_"
    }
}

# ── Algorithm values ─────────────────────────────────────────────────────────
$cipherList  = 'ChaCha20-Poly1305,AES-256-GCM,AES-128-GCM,AES-256-CTR,AES-192-CTR,AES-128-CTR'
$macList     = 'hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com'
$kexList     = 'curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256'
$hostKeyList = 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256'

# Helper: set a key=value line in an INI-style .ini file (SecureCRT session format)
function Set-IniValue {
    param(
        [string] $FilePath,
        [string] $Key,
        [string] $Value
    )
    $lines  = [System.IO.File]::ReadAllLines($FilePath, [System.Text.Encoding]::UTF8)
    $found  = $false
    $output = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $lines) {
        if ($line -match "^\s*${Key}\s*=") {
            $output.Add("${Key}=${Value}")
            $found = $true
        } else {
            $output.Add($line)
        }
    }
    if (-not $found) {
        $output.Add("${Key}=${Value}")
    }
    [System.IO.File]::WriteAllLines($FilePath, $output, [System.Text.Encoding]::UTF8)
}

# ── Patch per-session .ini files ──────────────────────────────────────────────
$patchedSessions = 0
if ($sessionDir -and (Test-Path $sessionDir)) {
    Get-ChildItem -Path $sessionDir -Recurse -Filter '*.ini' | ForEach-Object {
        try {
            Set-IniValue -FilePath $_.FullName -Key 'Cipher List'    -Value $cipherList
            Set-IniValue -FilePath $_.FullName -Key 'MAC List'       -Value $macList
            Set-IniValue -FilePath $_.FullName -Key 'Kex List'       -Value $kexList
            Set-IniValue -FilePath $_.FullName -Key 'Host Key List'  -Value $hostKeyList
            Set-IniValue -FilePath $_.FullName -Key 'Forward Agent'  -Value '00000000'
            Set-IniValue -FilePath $_.FullName -Key 'Forward X11'    -Value '00000000'
            $patchedSessions++
            Write-Host "[KratoSSH] Patched SecureCRT session: $($_.Name)"
        } catch {
            Write-Warning "[KratoSSH] Could not patch $($_.FullName): $_"
        }
    }
    Write-Host "[KratoSSH] Patched $patchedSessions SecureCRT session file(s) in $sessionDir"
} else {
    Write-Host '[KratoSSH] No SecureCRT session directory found; no session files were patched.'
}

Write-Host "[KratoSSH] SecureCRT hardening complete. Backup: $backupDir"
