Param()

$ErrorActionPreference = 'Stop'

Write-Host '[KratoSSH] Starting WinSCP hardening...'

$backupDir = Join-Path $env:USERPROFILE (".kratossh-backups\winscp-" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# ── Algorithm values ─────────────────────────────────────────────────────────
$kexList    = 'ecdh,dh-gex-sha256,dh-group14-sha256,dh-group16-sha512,dh-group18-sha512'
$cipherList = 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'
$macList    = 'hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com'
$hostKeyList = 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256'

# ── Registry: WinSCP 2 sessions ───────────────────────────────────────────────
$winscpRoot = 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions'
$patchedSessions = 0

if (Test-Path $winscpRoot) {
    # Export registry hive as backup
    $regBackup = Join-Path $backupDir 'WinSCP2_Sessions.reg'
    try {
        & reg export "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" $regBackup /y 2>&1 | Out-Null
        Write-Host "[KratoSSH] Registry backup saved to $regBackup"
    } catch {
        Write-Warning "[KratoSSH] Could not export registry backup: $_"
    }

    Get-ChildItem -Path $winscpRoot | ForEach-Object {
        $sessionPath = $_.PSPath
        try {
            Set-ItemProperty -Path $sessionPath -Name 'KexList'    -Value $kexList     -Type String
            Set-ItemProperty -Path $sessionPath -Name 'CipherList'  -Value $cipherList  -Type String
            Set-ItemProperty -Path $sessionPath -Name 'MacList'     -Value $macList     -Type String
            Set-ItemProperty -Path $sessionPath -Name 'HostKeyList' -Value $hostKeyList -Type String
            # Disable agent forwarding and X11 forwarding
            Set-ItemProperty -Path $sessionPath -Name 'AgentFwd'    -Value 0            -Type DWord
            Set-ItemProperty -Path $sessionPath -Name 'AddressFamily' -Value 0          -Type DWord
            $patchedSessions++
            Write-Host "[KratoSSH] Hardened WinSCP registry session: $($_.PSChildName)"
        } catch {
            Write-Warning "[KratoSSH] Could not patch session $($_.PSChildName): $_"
        }
    }
    Write-Host "[KratoSSH] Patched $patchedSessions WinSCP registry session(s)"
} else {
    Write-Host '[KratoSSH] No WinSCP registry sessions found under HKCU\Software\Martin Prikryl\WinSCP 2\Sessions'
}

# ── INI file (portable WinSCP) ────────────────────────────────────────────────
# WinSCP portable stores settings in winscp.ini next to the executable.
# Also check %APPDATA%\WinSCP\WinSCP.ini (some installer variants).
$iniCandidates = @(
    (Join-Path $env:APPDATA 'WinSCP\WinSCP.ini'),
    (Join-Path ([System.IO.Path]::GetDirectoryName((Get-Command winscp.exe -ErrorAction SilentlyContinue)?.Source ?? '')) 'WinSCP.ini')
) | Where-Object { $_ -and (Test-Path $_) }

foreach ($iniPath in $iniCandidates) {
    try {
        Copy-Item $iniPath (Join-Path $backupDir ([System.IO.Path]::GetFileName($iniPath))) -Force
        $lines  = [System.IO.File]::ReadAllLines($iniPath, [System.Text.Encoding]::UTF8)
        $output = [System.Collections.Generic.List[string]]::new()
        $inSession = $false
        $touched = @{}
        foreach ($line in $lines) {
            if ($line -match '^\[Sessions\\') { $inSession = $true; $touched = @{} }
            if ($line -match '^\[' -and $line -notmatch '^\[Sessions\\') { $inSession = $false }
            if ($inSession) {
                $patched = $false
                foreach ($kv in @(
                    @('KexList', $kexList),
                    @('CipherList', $cipherList),
                    @('MacList', $macList),
                    @('HostKeyList', $hostKeyList),
                    @('AgentFwd', '0'),
                    @('AddressFamily', '0')
                )) {
                    if ($line -match "^$($kv[0])=") {
                        $output.Add("$($kv[0])=$($kv[1])")
                        $touched[$kv[0]] = $true
                        $patched = $true
                        break
                    }
                }
                if (-not $patched) { $output.Add($line) }
            } else {
                $output.Add($line)
            }
        }
        [System.IO.File]::WriteAllLines($iniPath, $output, [System.Text.Encoding]::UTF8)
        Write-Host "[KratoSSH] Patched WinSCP INI file: $iniPath"
    } catch {
        Write-Warning "[KratoSSH] Could not patch WinSCP INI $iniPath: $_"
    }
}

Write-Host "[KratoSSH] WinSCP hardening complete. Backup: $backupDir"
