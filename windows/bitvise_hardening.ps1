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

Write-Host "[KratoSSH] Bitvise global settings applied. Backup: $backupDir"

# --- Per-profile algorithm enforcement ---
# Bitvise SSH Client 9+ stores profiles as XML files under %APPDATA%\Bitvise SSH Client\Profiles\
$profileDir = Join-Path $env:APPDATA 'Bitvise SSH Client\Profiles'
$patchedProfiles = 0

if (Test-Path $profileDir) {
    Get-ChildItem -Path $profileDir -Filter '*.bscp' | ForEach-Object {
        $profilePath = $_.FullName
        try {
            [xml]$xml = Get-Content -Path $profilePath -Encoding UTF8
            $changed = $false

            # Helper: set a named setting element value, or create it if missing
            $setField = {
                Param($parent, [string]$key, [string]$value)
                $node = $parent.SelectSingleNode("setting[@key='$key']")
                if ($null -eq $node) {
                    $node = $xml.CreateElement('setting')
                    $node.SetAttribute('key', $key)
                    $parent.AppendChild($node) | Out-Null
                }
                if ($node.InnerText -ne $value) {
                    $node.InnerText = $value
                    return $true
                }
                return $false
            }

            $algFields = @{
                'kexAlgorithms'        = 'curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512'
                'encAlgorithmsC2S'     = 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr'
                'encAlgorithmsS2C'     = 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr'
                'macAlgorithmsC2S'     = 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com'
                'macAlgorithmsS2C'     = 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com'
                'hostKeyAlgorithms'    = 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256'
            }

            # Find the <session> or root settings container
            $containers = $xml.SelectNodes('//c2Params | //session | //BvSshClientProfile')
            if ($containers.Count -eq 0) { $containers = @($xml.DocumentElement) }

            foreach ($container in $containers) {
                foreach ($k in $algFields.Keys) {
                    $result = & $setField $container $k $algFields[$k]
                    if ($result) { $changed = $true }
                }
            }

            if ($changed) {
                $xml.Save($profilePath)
                $patchedProfiles++
                Write-Host "[KratoSSH] Patched Bitvise profile: $($_.Name)"
            }
        } catch {
            Write-Warning "[KratoSSH] Could not patch profile $($_.Name): $_"
        }
    }
    Write-Host "[KratoSSH] Patched $patchedProfiles Bitvise profile(s) in $profileDir"
} else {
    Write-Host '[KratoSSH] No Bitvise profile directory found; only global registry settings were applied.'
}
