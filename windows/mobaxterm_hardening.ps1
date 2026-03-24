Param()

$ErrorActionPreference = 'Stop'

Write-Host '[KratoSSH] Starting MobaXterm hardening...'

$backupDir = Join-Path $env:USERPROFILE (".kratossh-backups\mobaxterm-" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# ── Algorithm values ─────────────────────────────────────────────────────────
$kexList     = 'curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256'
$cipherList  = 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'
$macList     = 'hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com'
$hostKeyList = 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256'

# ── Locate MobaXterm INI ──────────────────────────────────────────────────────
# MobaXterm stores sessions in MobaXterm.ini next to the executable, or in
# %APPDATA%\MobaXterm\MobaXterm.ini for installed builds.
$candidateInis = @(
    (Join-Path $env:APPDATA 'MobaXterm\MobaXterm.ini'),
    (Join-Path $env:USERPROFILE 'Documents\MobaXterm\MobaXterm.ini')
)

# Also check beside the executable if it's on PATH
$exePath = (Get-Command 'MobaXterm.exe' -ErrorAction SilentlyContinue)?.Source
if ($exePath) {
    $candidateInis += (Join-Path ([System.IO.Path]::GetDirectoryName($exePath)) 'MobaXterm.ini')
}

$iniPaths = $candidateInis | Where-Object { Test-Path $_ }

if (-not $iniPaths) {
    Write-Host '[KratoSSH] No MobaXterm.ini found. No changes made.'
    exit 0
}

# Helper: patch an INI file in-place
function Patch-MobaIni {
    param([string]$FilePath)

    Copy-Item $FilePath (Join-Path $backupDir ([System.IO.Path]::GetFileName($FilePath))) -Force

    $lines     = [System.IO.File]::ReadAllLines($FilePath, [System.Text.Encoding]::UTF8)
    $output    = [System.Collections.Generic.List[string]]::new()
    $inSsh     = $false
    $injected  = @{}

    foreach ($line in $lines) {
        # MobaXterm session sections look like [SSH_<n>] or [Sessions]
        if ($line -match '^\[SSH') {
            $inSsh    = $true
            $injected = @{}
            $output.Add($line)
            continue
        }
        if ($line -match '^\[' -and $line -notmatch '^\[SSH') {
            # Before leaving an SSH section inject any missing keys
            if ($inSsh) {
                foreach ($kv in @(
                    @('SSH_Kex',     $kexList),
                    @('SSH_Cipher',  $cipherList),
                    @('SSH_MAC',     $macList),
                    @('SSH_HostKey', $hostKeyList),
                    @('SSH_AgentFwd','0')
                )) {
                    if (-not $injected[$kv[0]]) {
                        $output.Add("$($kv[0])=$($kv[1])")
                    }
                }
            }
            $inSsh = $false
            $output.Add($line)
            continue
        }
        if ($inSsh) {
            $patched = $false
            foreach ($kv in @(
                @('SSH_Kex',     $kexList),
                @('SSH_Cipher',  $cipherList),
                @('SSH_MAC',     $macList),
                @('SSH_HostKey', $hostKeyList),
                @('SSH_AgentFwd','0')
            )) {
                if ($line -match "^$($kv[0])\s*=") {
                    $output.Add("$($kv[0])=$($kv[1])")
                    $injected[$kv[0]] = $true
                    $patched = $true
                    break
                }
            }
            if (-not $patched) { $output.Add($line) }
        } else {
            $output.Add($line)
        }
    }
    [System.IO.File]::WriteAllLines($FilePath, $output, [System.Text.Encoding]::UTF8)
    Write-Host "[KratoSSH] Patched MobaXterm INI: $FilePath"
}

foreach ($ini in $iniPaths) {
    Patch-MobaIni -FilePath $ini
}

Write-Host "[KratoSSH] MobaXterm hardening complete. Backup: $backupDir"
