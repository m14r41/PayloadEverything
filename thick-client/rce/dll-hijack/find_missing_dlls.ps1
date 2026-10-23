<#
.SYNOPSIS
    Find DLL hijack opportunities in a target application.

.DESCRIPTION
    Method 1: Use Process Monitor (Sysinternals) — most reliable
    Method 2: Static analysis of PE imports vs. actual DLL locations
    Method 3: Check for DLLs loaded from writable paths

.PARAMETER TargetExe
    Path to the target application executable

.EXAMPLE
    .\find_missing_dlls.ps1 -TargetExe "C:\Program Files\VulnApp\app.exe"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetExe
)

$ErrorActionPreference = "Stop"

Write-Host "`n[*] DLL Hijack Finder for VAPT" -ForegroundColor Cyan
Write-Host "[*] Target: $TargetExe`n"

# --- Method 1: Procmon Instructions ---
Write-Host "=== METHOD 1: Process Monitor (Recommended) ===" -ForegroundColor Yellow
Write-Host @"
1. Download Sysinternals Process Monitor (procmon64.exe)
2. Set these filters:
   - Process Name | is | $(Split-Path $TargetExe -Leaf)
   - Result       | is | NAME NOT FOUND
   - Path         | ends with | .dll
3. Launch the target application
4. Look for DLLs searched in the application directory first (before System32)
5. Those are your hijack candidates

Procmon filter XML (import via Filter > Load):
"@

$procName = [System.IO.Path]::GetFileNameWithoutExtension($TargetExe)
Write-Host @"

<procmon>
  <filter>
    <column>ProcessName</column><relation>is</relation><value>$procName.exe</value><action>Include</action>
  </filter>
  <filter>
    <column>Result</column><relation>is</relation><value>NAME NOT FOUND</value><action>Include</action>
  </filter>
  <filter>
    <column>Path</column><relation>ends with</relation><value>.dll</value><action>Include</action>
  </filter>
</procmon>
"@

# --- Method 2: Static PE Import Analysis ---
Write-Host "`n=== METHOD 2: Static Import Analysis ===" -ForegroundColor Yellow

$appDir = Split-Path $TargetExe -Parent
$sysDir = [System.Environment]::SystemDirectory
$winDir = [System.Environment]::GetFolderPath("Windows")

# Check if dumpbin is available
$dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
if ($dumpbin) {
    Write-Host "[+] Using dumpbin to list imports..."
    $imports = & dumpbin.exe /imports $TargetExe | Select-String "\.dll" | ForEach-Object {
        ($_ -split "\s+")[-1]
    } | Where-Object { $_ -match "\.dll$" } | Sort-Object -Unique

    foreach ($dll in $imports) {
        $inAppDir = Test-Path (Join-Path $appDir $dll)
        $inSysDir = Test-Path (Join-Path $sysDir $dll)
        $inWinDir = Test-Path (Join-Path $winDir $dll)

        if (-not $inAppDir -and -not $inSysDir -and -not $inWinDir) {
            Write-Host "  [!] MISSING: $dll — potential phantom DLL hijack" -ForegroundColor Red
        }
        elseif (-not $inAppDir -and ($inSysDir -or $inWinDir)) {
            Write-Host "  [?] CANDIDATE: $dll — not in app dir, loaded from system" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "  [-] dumpbin.exe not found. Install Visual Studio Build Tools or use:" -ForegroundColor Gray
    Write-Host "      python -c `"import pefile; pe=pefile.PE('$TargetExe'); [print(e.dll.decode()) for e in pe.DIRECTORY_ENTRY_IMPORT]`""
}

# --- Method 3: Writable Path Check ---
Write-Host "`n=== METHOD 3: Writable Path Check ===" -ForegroundColor Yellow
Write-Host "[*] Checking if application directory is writable by current user..."

$testFile = Join-Path $appDir ".vapt_write_test_$(Get-Random)"
try {
    [System.IO.File]::WriteAllText($testFile, "test")
    Remove-Item $testFile -Force
    Write-Host "  [!] App directory IS WRITABLE: $appDir" -ForegroundColor Red
    Write-Host "      -> DLL hijack is feasible for any DLL loaded from this path"
} catch {
    Write-Host "  [+] App directory is NOT writable (good): $appDir" -ForegroundColor Green
    Write-Host "      -> Check for per-user install locations or side-loading paths"
}

# --- Method 4: Known Vulnerable DLL Names ---
Write-Host "`n=== METHOD 4: Known Commonly Hijacked DLLs ===" -ForegroundColor Yellow
$knownDlls = @(
    "VERSION.dll", "USERENV.dll", "WINMM.dll", "WTSAPI32.dll",
    "dwmapi.dll", "UxTheme.dll", "PROPSYS.dll", "ntmarta.dll",
    "CRYPTSP.dll", "profapi.dll", "secur32.dll", "netapi32.dll",
    "IPHLPAPI.dll", "samcli.dll", "wship6.dll", "WINHTTP.dll",
    "mpr.dll", "OLEACC.dll", "DSOUND.dll", "d3d9.dll",
    "windowscodecs.dll", "TextInputFramework.dll", "sspicli.dll"
)

Write-Host "[*] Checking if known hijackable DLLs are absent from app directory..."
foreach ($dll in $knownDlls) {
    $inApp = Test-Path (Join-Path $appDir $dll)
    if (-not $inApp) {
        $inSys = Test-Path (Join-Path $sysDir $dll)
        if ($inSys) {
            Write-Host "  [?] $dll — not in app dir, exists in System32 (test with procmon)" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n[*] Done. Use procmon for definitive results." -ForegroundColor Cyan
