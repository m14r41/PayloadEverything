# Windows Security Testing

Comprehensive payload and tool collection for Windows and Active Directory penetration testing.

> **Framework**: MITRE ATT&CK for Enterprise — Windows Platform

## Directory Structure

| Folder | Description | Key Files |
|--------|-------------|-----------|
| [`enumeration/`](enumeration/) | Local and AD enumeration | `windows_enum.ps1`, `ad_enum.ps1` |
| [`privilege-escalation/`](privilege-escalation/) | Local privilege escalation | `uac_bypass.ps1`, `service_exploits.ps1`, `potato_attacks.md`, `alwaysinstallelevated.md` |
| [`persistence/`](persistence/) | Windows persistence mechanisms | `registry_persistence.ps1`, `scheduled_task_persist.ps1`, `wmi_persist.ps1`, `startup_persist.md` |
| [`credential-harvesting/`](credential-harvesting/) | Credential extraction | `mimikatz_commands.md`, `lsass_dump.ps1`, `sam_extract.md`, `credential_search.ps1` |
| [`lateral-movement/`](lateral-movement/) | Remote execution methods | `lateral_movement.md`, `winrm_exec.ps1` |
| [`defense-evasion/`](defense-evasion/) | Security control bypass | `amsi_bypass.ps1`, `etw_bypass.ps1`, `applocker_bypass.md`, `defender_evasion.md` |
| [`active-directory/`](active-directory/) | AD-specific attacks | `kerberos_attacks.md`, `ad_attacks.ps1`, `bloodhound_queries.md` |
| [`network/`](network/) | Network attacks & interception | `network_attacks.md`, `proxy_intercept.md` |
| [`testing-steps/`](testing-steps/) | Assessment methodology | `windows_checklist.md` |

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|-----------|
| Reconnaissance | T1082 System Info, T1087 Account Discovery, T1016 Network Config |
| Privilege Escalation | T1548.002 UAC Bypass, T1574 Hijack Execution Flow, T1068 Exploitation |
| Credential Access | T1003 OS Credential Dumping, T1558 Kerberos Attacks, T1552 Unsecured Credentials |
| Lateral Movement | T1021 Remote Services, T1047 WMI, T1053 Scheduled Task, T1550 Use Alternate Auth |
| Persistence | T1547 Boot/Logon Autostart, T1053 Scheduled Task, T1546.003 WMI Event Subscription |
| Defense Evasion | T1562 Impair Defenses, T1218 System Binary Proxy, T1027 Obfuscation |
| Domain Attacks | T1003.006 DCSync, T1222 ACL Modification, T1484 GPO Modification, T1187 Forced Auth |

## Quick Start

```powershell
# 1. Enumerate local system
. .\enumeration\windows_enum.ps1
Invoke-FullEnum

# 2. Enumerate Active Directory
. .\enumeration\ad_enum.ps1
Invoke-ADEnumFull

# 3. Check for privilege escalation paths
. .\privilege-escalation\service_exploits.ps1
Find-AllServiceExploits

# 4. Search for stored credentials
. .\credential-harvesting\credential_search.ps1
Search-AllCredentials

# 5. Bypass security controls
. .\defense-evasion\amsi_bypass.ps1
Bypass-AmsiMemoryPatch
```
