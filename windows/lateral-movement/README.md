# Windows Lateral Movement

Techniques for moving between systems in a Windows/AD environment.

> **MITRE ATT&CK**: T1021, T1047, T1053, T1569

## Files

| File | Description |
|------|-------------|
| [`lateral_movement.md`](lateral_movement.md) | Complete reference — PsExec, WMI (wmic + CIM), WinRM, DCOM (MMC20/ShellWindows/ShellBrowserWindow), RDP, SMB file transfer, SCM, scheduled tasks. Commands for each with OPSEC notes and decision matrix |
| [`winrm_exec.ps1`](winrm_exec.ps1) | WinRM lateral movement toolkit — remote command execution, interactive sessions, file upload/download, credential spraying, multi-host execution (T1021.006) |

## Quick Start

```powershell
# Enable WinRM for testing
. .\winrm_exec.ps1
Enable-WinRMRemoting

# Remote command execution
Invoke-WinRMCommand -Target dc01 -Command "whoami" -Username "domain\admin" -Password "Password1"

# Interactive session
Enter-WinRMSession -Target dc01
```
