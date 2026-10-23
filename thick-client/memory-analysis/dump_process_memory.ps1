<#
.SYNOPSIS
    Dump and search process memory for sensitive data.

.DESCRIPTION
    Thick clients often hold credentials, tokens, encryption keys, and
    sensitive data in plaintext memory. This tool dumps process memory
    and searches for common credential patterns.

    OWASP Thick Client: TC9 — Sensitive Data in Memory
    Severity: HIGH — credentials should be zeroed after use.

    Tools needed for full analysis:
    - This script (basic pattern search)
    - Process Hacker / x64dbg (interactive memory inspection)
    - Volatility (full memory forensics)
    - strings (Sysinternals) for binary string extraction

.PARAMETER ProcessName
    Target process name (without .exe)

.PARAMETER PID
    Target process ID

.PARAMETER DumpToFile
    Save full memory dump to file (requires procdump or comsvcs.dll)

.EXAMPLE
    .\dump_process_memory.ps1 -ProcessName "TargetApp"
    .\dump_process_memory.ps1 -PID 1234 -DumpToFile
#>

param(
    [string]$ProcessName,
    [int]$PID = 0,
    [switch]$DumpToFile
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Process Memory Credential Scanner" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Resolve process
if ($ProcessName) {
    $proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $proc) {
        Write-Host "[-] Process not found: $ProcessName" -ForegroundColor Red
        return
    }
    $PID = $proc.Id
} elseif ($PID -gt 0) {
    $proc = Get-Process -Id $PID -ErrorAction SilentlyContinue
    if (-not $proc) {
        Write-Host "[-] PID not found: $PID" -ForegroundColor Red
        return
    }
} else {
    Write-Host "Usage: -ProcessName <name> or -PID <id>"
    return
}

Write-Host "[*] Target: $($proc.ProcessName) (PID: $PID)"
Write-Host "[*] Path: $($proc.Path)"
Write-Host "[*] Memory: $([math]::Round($proc.WorkingSet64 / 1MB, 2)) MB`n"

# ============================================================
# Method 1: Full memory dump via comsvcs.dll (for offline analysis)
# ============================================================
if ($DumpToFile) {
    Write-Host "--- Creating Full Memory Dump ---" -ForegroundColor Yellow
    $dumpPath = ".\${ProcessName}_${PID}.dmp"

    # Method A: ProcDump (Sysinternals)
    $procdump = Get-Command procdump.exe -ErrorAction SilentlyContinue
    if ($procdump) {
        Write-Host "[*] Using ProcDump..."
        & procdump.exe -ma $PID $dumpPath -accepteula
    } else {
        # Method B: comsvcs.dll MiniDump
        Write-Host "[*] Using comsvcs.dll MiniDump..."
        Write-Host "[*] Command: rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $PID $dumpPath full"
        try {
            & rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $PID $dumpPath full
        } catch {
            Write-Host "[-] Dump failed. Try running as Administrator." -ForegroundColor Red
        }
    }

    if (Test-Path $dumpPath) {
        $dumpSize = [math]::Round((Get-Item $dumpPath).Length / 1MB, 2)
        Write-Host "[+] Dump saved: $dumpPath ($dumpSize MB)" -ForegroundColor Green
        Write-Host "[*] Analyze with:"
        Write-Host "    strings.exe -n 8 $dumpPath | findstr /i password"
        Write-Host "    strings.exe -n 8 $dumpPath | findstr /i token"
        Write-Host "    strings.exe -n 8 $dumpPath | findstr /i `"Data Source`""
    }
}

# ============================================================
# Method 2: Live memory string search via ReadProcessMemory
# ============================================================
Write-Host "`n--- Live Memory Pattern Search ---" -ForegroundColor Yellow

$searchPatterns = @(
    @{Name="Password field";     Pattern="password"},
    @{Name="Connection string";  Pattern="Data Source="},
    @{Name="Connection string";  Pattern="Server="},
    @{Name="SQL credential";     Pattern="User Id="},
    @{Name="Bearer token";       Pattern="Bearer "},
    @{Name="JWT token";          Pattern="eyJ"},
    @{Name="Basic auth";         Pattern="Basic "},
    @{Name="API key";            Pattern="api[_-]?key"},
    @{Name="Private key";        Pattern="-----BEGIN"},
    @{Name="AWS key";            Pattern="AKIA"},
    @{Name="MongoDB URI";        Pattern="mongodb://"},
    @{Name="HTTP auth";          Pattern="Authorization:"}
)

# Use strings approach via temp file for speed
Write-Host "[*] Extracting strings from process memory..."
Write-Host "[*] Note: For full analysis, use Process Hacker > Properties > Memory tab`n"

# Read process modules and search readable memory
$modules = $proc.Modules
Write-Host "[*] Loaded modules: $($modules.Count)"

$findings = @()

foreach ($mod in $modules) {
    try {
        $modPath = $mod.FileName
        if (-not $modPath) { continue }
        if ($modPath -match "\\Windows\\System32\\" -or $modPath -match "\\Windows\\SysWOW64\\") { continue }

        $bytes = [System.IO.File]::ReadAllBytes($modPath)
        $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
        $unicode = [System.Text.Encoding]::Unicode.GetString($bytes)

        foreach ($sp in $searchPatterns) {
            if ($ascii -imatch $sp.Pattern -or $unicode -imatch $sp.Pattern) {
                $finding = "[!] $($sp.Name) pattern found in module: $($mod.ModuleName)"
                Write-Host $finding -ForegroundColor Red
                $findings += $finding
            }
        }
    } catch {}
}

# ============================================================
# Method 3: Check for common credential management issues
# ============================================================
Write-Host "`n--- Credential Management Checks ---" -ForegroundColor Yellow

# Check if SecureString is used (good) vs plaintext string (bad)
Write-Host "[*] Decompile the app with dnSpy/ILSpy and search for:"
Write-Host "    - System.String fields storing passwords (BAD)"
Write-Host "    - SecureString usage (BETTER, but still extractable)"
Write-Host "    - RtlZeroMemory / SecureZeroMemory after use (GOOD)"
Write-Host "    - CryptProtectMemory usage (GOOD)"

# Check if process has debug privileges
try {
    $handle = [System.Diagnostics.Process]::GetProcessById($PID).Handle
    if ($handle) {
        Write-Host "[!] Process handle obtainable — memory is readable" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[+] Cannot get process handle — process may be protected" -ForegroundColor Green
}

# ============================================================
# Summary
# ============================================================
Write-Host "`n--- Recommendations ---" -ForegroundColor Cyan
Write-Host @"
Manual steps for thorough analysis:
1. Open Process Hacker > Select process > Properties > Memory
2. Search memory for: password, token, key, secret, connectionstring
3. Use x64dbg: Attach > Memory Map > Search for patterns
4. Check if credentials persist after logout (they shouldn't)
5. Check if credentials are cleared after session timeout

Tools:
  - Process Hacker: https://processhacker.sourceforge.io/
  - x64dbg: https://x64dbg.com/
  - ProcDump: https://docs.microsoft.com/sysinternals/downloads/procdump
  - Strings: https://docs.microsoft.com/sysinternals/downloads/strings
  - WinDbg: !address -summary, s -a 0 L?ffffffff "password"
"@

if ($findings.Count -gt 0) {
    Write-Host "`n[!] $($findings.Count) potential credential patterns found!" -ForegroundColor Red
} else {
    Write-Host "`n[*] No patterns found in module files. Check live heap memory with Process Hacker." -ForegroundColor Yellow
}
