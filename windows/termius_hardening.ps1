Param()

$ErrorActionPreference = 'Stop'

Write-Host '[KratoSSH] Starting Termius hardening...'

$backupDir = Join-Path $env:USERPROFILE (".kratossh-backups\termius-" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# ── Locate Termius storage.json ───────────────────────────────────────────────
$candidates = @(
    (Join-Path $env:APPDATA 'Termius\storage.json'),
    (Join-Path $env:LOCALAPPDATA 'Termius\storage.json')
)

$storagePath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $storagePath) {
    Write-Host '[KratoSSH] Termius storage.json not found. No changes made.'
    exit 0
}

# Backup
Copy-Item $storagePath (Join-Path $backupDir 'storage.json') -Force
Write-Host "[KratoSSH] Backed up Termius storage to $backupDir\storage.json"

# ── Parse and patch JSON ──────────────────────────────────────────────────────
$json = [System.IO.File]::ReadAllText($storagePath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json

# Termius vault structure: .groups[] and .hosts[] each may have a .ssh_config child
$strongKex    = 'curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512'
$strongCipher = 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr'
$strongMac    = 'hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com'
$strongHostKey = 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256'

function Set-TermiusSshConfig {
    param($node)
    if ($null -eq $node) { return }
    if (-not $node.PSObject.Properties['ssh_config']) {
        $node | Add-Member -NotePropertyName 'ssh_config' -NotePropertyValue ([PSCustomObject]@{}) -Force
    }
    $cfg = $node.ssh_config
    $cfg | Add-Member -NotePropertyName 'kex_algorithms'    -NotePropertyValue $strongKex     -Force
    $cfg | Add-Member -NotePropertyName 'ciphers'           -NotePropertyValue $strongCipher  -Force
    $cfg | Add-Member -NotePropertyName 'macs'              -NotePropertyValue $strongMac     -Force
    $cfg | Add-Member -NotePropertyName 'host_key_algorithms'-NotePropertyValue $strongHostKey -Force
    $cfg | Add-Member -NotePropertyName 'forward_agent'     -NotePropertyValue $false        -Force
    $cfg | Add-Member -NotePropertyName 'forward_x11'       -NotePropertyValue $false        -Force
}

$patched = 0
if ($json.PSObject.Properties['hosts']) {
    foreach ($host in $json.hosts) {
        Set-TermiusSshConfig $host
        $patched++
    }
}

if ($json.PSObject.Properties['groups']) {
    foreach ($group in $json.groups) {
        Set-TermiusSshConfig $group
        $patched++
    }
}

# Write back with UTF-8 no-BOM, 2-space indent
$patched | Out-Null
$outputJson = $json | ConvertTo-Json -Depth 20 -Compress:$false
[System.IO.File]::WriteAllText($storagePath, $outputJson, (New-Object System.Text.UTF8Encoding $false))

Write-Host "[KratoSSH] Patched $patched Termius node(s) in $storagePath"
Write-Host "[KratoSSH] Termius hardening complete. Backup: $backupDir"
