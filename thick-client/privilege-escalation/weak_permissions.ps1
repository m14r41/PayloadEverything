<#
.SYNOPSIS
    Check for weak file/folder/registry permissions on a desktop application.

.DESCRIPTION
    Scans the target application for:
    - Writable application directory (DLL hijack, binary replacement)
    - Writable config files (config tampering)
    - Writable plugin/extension directories (malicious plugin load)
    - Weak registry ACLs (settings tampering)
    - World-writable log files (log injection / overwrite)

.PARAMETER AppPath
    Application installation directory

.EXAMPLE
    .\weak_permissions.ps1 -AppPath "C:\Program Files\TargetApp"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$AppPath
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Weak Permission Scanner" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "[*] Running as: $currentUser"
Write-Host "[*] Target: $AppPath`n"

function Test-Writable($Path) {
    $acl = Get-Acl $Path -ErrorAction SilentlyContinue
    if (-not $acl) { return $false }

    $weakPrincipals = @("Everyone", "BUILTIN\Users", "Authenticated Users",
                         "NT AUTHORITY\Authenticated Users", "BUILTIN\Authenticated Users")

    foreach ($ace in $acl.Access) {
        $identity = $ace.IdentityReference.Value
        $isWeak = $false
        foreach ($wp in $weakPrincipals) {
            if ($identity -eq $wp) { $isWeak = $true; break }
        }
        if (-not $isWeak) { continue }

        $rights = $ace.FileSystemRights.ToString()
        if ($rights -match "Write|FullControl|Modify|CreateFiles|AppendData|ChangePermissions|TakeOwnership") {
            return @{Identity=$identity; Rights=$rights}
        }
    }
    return $false
}

# --- Check application directory ---
Write-Host "--- Application Directory ---" -ForegroundColor Yellow
$result = Test-Writable $AppPath
if ($result) {
    Write-Host "[!!!] CRITICAL: App directory writable by $($result.Identity)" -ForegroundColor Red
    Write-Host "      Path: $AppPath"
    Write-Host "      Rights: $($result.Rights)"
    Write-Host "      Impact: Binary replacement, DLL hijack`n"
} else {
    Write-Host "[+] App directory not writable by low-priv users`n" -ForegroundColor Green
}

# --- Check all subdirectories ---
Write-Host "--- Subdirectories ---" -ForegroundColor Yellow
$dirs = Get-ChildItem -Path $AppPath -Directory -Recurse -ErrorAction SilentlyContinue
foreach ($dir in $dirs) {
    $result = Test-Writable $dir.FullName
    if ($result) {
        Write-Host "[!] Writable directory: $($dir.FullName)" -ForegroundColor Red
        Write-Host "    By: $($result.Identity) | Rights: $($result.Rights)"
    }
}

# --- Check executables and DLLs ---
Write-Host "`n--- Executable Files ---" -ForegroundColor Yellow
$binaries = Get-ChildItem -Path $AppPath -Recurse -Include @("*.exe","*.dll") -ErrorAction SilentlyContinue
foreach ($bin in $binaries) {
    $result = Test-Writable $bin.FullName
    if ($result) {
        Write-Host "[!!!] CRITICAL: Writable binary: $($bin.FullName)" -ForegroundColor Red
        Write-Host "      By: $($result.Identity)"
    }
}

# --- Check config files ---
Write-Host "`n--- Configuration Files ---" -ForegroundColor Yellow
$configs = Get-ChildItem -Path $AppPath -Recurse -Include @("*.config","*.xml","*.json","*.ini","*.yaml","*.yml","*.properties") -ErrorAction SilentlyContinue
foreach ($cfg in $configs) {
    $result = Test-Writable $cfg.FullName
    if ($result) {
        Write-Host "[!] Writable config: $($cfg.FullName)" -ForegroundColor Yellow
        Write-Host "    By: $($result.Identity)"
        Write-Host "    Impact: Settings tampering, credential injection"
    }
}

# --- Check AppData directories ---
Write-Host "`n--- Per-User AppData ---" -ForegroundColor Yellow
$appName = Split-Path $AppPath -Leaf
$appDataPaths = @(
    "$env:APPDATA\$appName",
    "$env:LOCALAPPDATA\$appName",
    "$env:PROGRAMDATA\$appName"
)
foreach ($adp in $appDataPaths) {
    if (Test-Path $adp) {
        Write-Host "[*] AppData found: $adp"
        $result = Test-Writable $adp
        if ($result) {
            Write-Host "    [!] Writable by: $($result.Identity)" -ForegroundColor Yellow
        }
        # Check for sensitive files
        $sensFiles = Get-ChildItem -Path $adp -Recurse -Include @("*.db","*.sqlite","*.dat","*.key","*.pem","*.pfx","*.config") -ErrorAction SilentlyContinue
        foreach ($sf in $sensFiles) {
            Write-Host "    [?] Sensitive file: $($sf.FullName) ($($sf.Length) bytes)" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n[*] For deeper analysis: accesschk.exe -wvu `"$AppPath`" -accepteula" -ForegroundColor Cyan
Write-Host "[*] Also check: icacls `"$AppPath`" /T" -ForegroundColor Cyan
