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
    Set-ItemProperty -Path $_.PSPath -Name 'KEX' -Type String -Value $kex
    Set-ItemProperty -Path $_.PSPath -Name 'Cipher' -Type String -Value $cipher
    Set-ItemProperty -Path $_.PSPath -Name 'HostKey' -Type String -Value $hostKey
    $hardened++
}

Write-Host "[KratoSSH] Hardened $hardened PuTTY session(s). Backup: $backupDir"
