# Windows Persistence

Techniques for maintaining access across reboots and user logons.

> **MITRE ATT&CK**: T1547, T1053, T1546

## Files

| File | Description |
|------|-------------|
| [`registry_persistence.ps1`](registry_persistence.ps1) | Registry-based persistence — Run/RunOnce, Winlogon Shell/Userinit, IFEO debugger, AppInit_DLLs, COM hijack, SilentProcessExit, ScreenSaver. Plant + Detect functions (T1547.001, T1547.004, T1546.012, T1546.010, T1546.015) |
| [`scheduled_task_persist.ps1`](scheduled_task_persist.ps1) | Scheduled task persistence — on logon, startup, idle, event trigger, recurring interval, hidden task in Microsoft folders. XML templates. Plant + Detect + Cleanup (T1053.005) |
| [`wmi_persist.ps1`](wmi_persist.ps1) | WMI event subscription persistence — EventFilter + CommandLineEventConsumer + ActiveScriptEventConsumer + Binding. Startup, interval, process-start triggers. Plant + Detect + Cleanup (T1546.003) |
| [`startup_persist.md`](startup_persist.md) | Complete reference of ALL Windows startup/persistence locations — registry keys, startup folders, services, scheduled tasks, WMI, GPO scripts, BITS jobs, Office add-ins, browser extensions, print monitors, netsh helpers, screensaver |

## Quick Start

```powershell
# Dot-source the scripts
. .\registry_persistence.ps1
. .\scheduled_task_persist.ps1
. .\wmi_persist.ps1

# Detect all existing persistence
Detect-AllRegistryPersistence
Detect-SuspiciousTasks
Detect-WMIPersistence
```
