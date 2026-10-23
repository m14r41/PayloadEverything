# Windows Enumeration

Local and Active Directory enumeration scripts for the initial reconnaissance phase.

## Files

| File | Description |
|------|-------------|
| [`windows_enum.ps1`](windows_enum.ps1) | Comprehensive local enumeration — system info, users/groups, network, services, scheduled tasks, installed software, PowerShell history, firewall, hotfixes, shares, named pipes, writable directories, AV/EDR detection |
| [`ad_enum.ps1`](ad_enum.ps1) | Active Directory enumeration — domain info, users, groups, computers, GPOs, trusts, SPNs, delegation (unconstrained/constrained/RBCD), password policy, AdminSDHolder, LAPS, DCSync rights. Uses native LDAP (no modules required) |

## Quick Start

```powershell
# Local enumeration
.\windows_enum.ps1
.\windows_enum.ps1 -OutFile C:\temp\local_enum.txt

# AD enumeration
.\ad_enum.ps1
.\ad_enum.ps1 -Domain corp.local -OutFile C:\temp\ad_enum.txt
```
