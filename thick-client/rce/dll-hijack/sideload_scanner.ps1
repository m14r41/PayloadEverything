<#
.SYNOPSIS
    DLL Sideloading Scanner — Find signed executables vulnerable to DLL sideloading.

.DESCRIPTION
    Scans application directories for signed Microsoft/vendor executables
    that load DLLs from their directory (sideloading). These are valuable
    because they bypass application whitelisting (AppLocker, WDAC).

    MITRE ATT&CK: T1574.002 — DLL Side-Loading

.PARAMETER Path
    Application directory to scan

.PARAMETER Deep
    Also check DLL import tables with dumpbin

.EXAMPLE
    .\sideload_scanner.ps1 -Path "C:\Program Files\TargetApp"
    .\sideload_scanner.ps1 -Path "C:\Program Files\TargetApp" -Deep
#>

param(
    [Parameter(Mandatory)]
    [string]$Path,
    [switch]$Deep
)

Write-Host "`n[*] DLL Sideloading Scanner`n" -ForegroundColor Cyan

# Known DLLs that are commonly sideloaded
$sideloadTargets = @(
    "VERSION.dll", "WINMM.dll", "USERENV.dll", "WTSAPI32.dll", "DBGHELP.dll",
    "CRYPTSP.dll", "CRYPTBASE.dll", "PROPSYS.dll", "dwmapi.dll", "UxTheme.dll",
    "WINSTA.dll", "NETAPI32.dll", "SAMCLI.dll", "WLDAP32.dll", "cscapi.dll",
    "profapi.dll", "MSASN1.dll", "LINKINFO.dll", "ntshrui.dll", "srvcli.dll",
    "WKSCLI.dll", "BROWCLI.dll", "sxs.dll", "mpr.dll", "IMM32.dll",
    "COMCTL32.dll", "SHFOLDER.dll", "SHLWAPI.dll", "WINHTTP.dll"
)

$signedExes = @()
$sideloadable = @()

# Find all executables
$exeFiles = Get-ChildItem -Path $Path -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue

foreach ($exe in $exeFiles) {
    # Check if signed
    $sig = Get-AuthenticodeSignature $exe.FullName -ErrorAction SilentlyContinue
    if (-not $sig -or $sig.Status -ne "Valid") { continue }

    $signer = $sig.SignerCertificate.Subject
    $signedExes += [PSCustomObject]@{
        Path = $exe.FullName
        Signer = $signer
    }

    Write-Host "[SIGNED] $($exe.Name) — $signer" -ForegroundColor Cyan

    # Check which target DLLs are NOT present in the exe's directory
    $exeDir = $exe.DirectoryName
    foreach ($dll in $sideloadTargets) {
        $dllPath = Join-Path $exeDir $dll
        if (-not (Test-Path $dllPath)) {
            # Check if the exe actually imports this DLL
            if ($Deep) {
                $dumpbin = & dumpbin /imports $exe.FullName 2>$null
                if ($dumpbin -match [regex]::Escape($dll)) {
                    Write-Host "  [SIDELOAD] $dll — imported but not in app dir" -ForegroundColor Red
                    $sideloadable += [PSCustomObject]@{
                        Exe = $exe.FullName
                        Signer = $signer
                        DLL = $dll
                        Verified = $true
                    }
                }
            } else {
                # Without dumpbin, just flag common targets
                $sideloadable += [PSCustomObject]@{
                    Exe = $exe.FullName
                    Signer = $signer
                    DLL = $dll
                    Verified = $false
                }
            }
        }
    }
}

# Summary
Write-Host "`n=== RESULTS ===" -ForegroundColor Yellow
Write-Host "Signed executables found: $($signedExes.Count)"

if ($sideloadable.Count -gt 0) {
    Write-Host "Potential sideload targets: $($sideloadable.Count)" -ForegroundColor Red
    Write-Host "`nTop sideloading candidates:" -ForegroundColor Yellow

    $sideloadable | Group-Object Exe | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
        $first = $_.Group[0]
        Write-Host "`n  EXE: $($first.Exe)"
        Write-Host "  Signer: $($first.Signer)"
        Write-Host "  DLLs: $($_.Group.DLL -join ', ')"
    }

    Write-Host "`n[*] To exploit:" -ForegroundColor Yellow
    Write-Host "  1. Copy signed exe to writable directory"
    Write-Host "  2. Place malicious DLL (same name) alongside it"
    Write-Host "  3. Execute — bypasses AppLocker because exe is signed"
    Write-Host "  4. The DLL should proxy exports to the real DLL"
    Write-Host "     Use generate_proxy_def.py to create the .def file"
} else {
    Write-Host "No obvious sideloading targets found" -ForegroundColor Green
    Write-Host "[*] Use Procmon for dynamic analysis — see find_missing_dlls.ps1"
}
