Param()

$ErrorActionPreference = 'Stop'

Write-Host '[KratoSSH] Starting PuTTY hardening...'

$sessionRoot = 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
$backupDir = Join-Path $env:USERPROFILE (".kratossh-backups\putty-" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

try {
    reg export "HKCU\Software\SimonTatham\PuTTY\Sessions" (Join-Path $backupDir 'putty-sessions.reg') /y | Out-Null
} catch {
    Write-Warning '[KratoSSH] Could not export PuTTY session registry backup with reg.exe.'
}

if (-not (Test-Path $sessionRoot)) {
    Write-Warning '[KratoSSH] No PuTTY sessions were found in registry.'
    exit 0
}

$kex = 'ecdh,dh-gex-sha256,dh-group14-sha1,rsa,WARN'
$cipher = 'chacha20,aes,blowfish,3des,WARN'
$hostKey = 'ed25519,ecdsa,rsa,dsa,WARN'

$hardened = 0
Get-ChildItem -Path $sessionRoot | ForEach-Object {
    $s = $_.PSPath

    # Algorithm preferences per session
    Set-ItemProperty -Path $s -Name 'KEX'     -Type String -Value $kex
    Set-ItemProperty -Path $s -Name 'Cipher'  -Type String -Value $cipher
    Set-ItemProperty -Path $s -Name 'HostKey' -Type String -Value $hostKey

    # Per-session security hardening
    # Disable forwarding to reduce attack surface
    Set-ItemProperty -Path $s -Name 'AgentFwd'      -Type DWord -Value 0
    Set-ItemProperty -Path $s -Name 'X11Forward'    -Type DWord -Value 0
    Set-ItemProperty -Path $s -Name 'GSSAPIFwdTrust' -Type DWord -Value 0

    # Disable compression (prevents CRIME-like attacks on interactive sessions)
    Set-ItemProperty -Path $s -Name 'Compression' -Type DWord -Value 0

    # Re-key after 1 GiB of data or 60 minutes, whichever comes first
    Set-ItemProperty -Path $s -Name 'RekeyBytes' -Type String -Value '1g'
    Set-ItemProperty -Path $s -Name 'RekeyTime'  -Type String -Value '60'

    # Warn on host key change (0=no, 1=add new, 2=warn-on-change)
    Set-ItemProperty -Path $s -Name 'HostKeyWarning' -Type DWord -Value 2

    $hardened++
}

Write-Host "[KratoSSH] Hardened $hardened PuTTY session(s) (algorithms + per-session settings). Backup: $backupDir"
