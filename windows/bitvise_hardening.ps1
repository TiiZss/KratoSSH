Param()

$ErrorActionPreference = 'Stop'

Write-Host '[KratoSSH] Starting Bitvise hardening...'

$bitviseRoot = 'HKCU:\Software\Bitvise'
$settingsPath = 'HKCU:\Software\Bitvise\BvSshClient\Settings'
$backupDir = Join-Path $env:USERPROFILE (".kratossh-backups\bitvise-" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

if (Test-Path $bitviseRoot) {
    try {
        reg export "HKCU\Software\Bitvise" (Join-Path $backupDir 'bitvise.reg') /y | Out-Null
    } catch {
        Write-Warning '[KratoSSH] Could not export Bitvise registry backup with reg.exe.'
    }
} else {
    Write-Warning '[KratoSSH] Bitvise registry root not found. Creating default settings key.'
}

New-Item -Path $settingsPath -Force | Out-Null

# These preference keys are best-effort defaults for modern algorithms.
Set-ItemProperty -Path $settingsPath -Name 'PreferredKex' -Type String -Value 'curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512'
Set-ItemProperty -Path $settingsPath -Name 'PreferredCiphers' -Type String -Value 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr'
Set-ItemProperty -Path $settingsPath -Name 'PreferredMacs' -Type String -Value 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com'
Set-ItemProperty -Path $settingsPath -Name 'PreferredHostKeyAlgorithms' -Type String -Value 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256'

Write-Host "[KratoSSH] Bitvise hardening settings applied. Backup: $backupDir"
