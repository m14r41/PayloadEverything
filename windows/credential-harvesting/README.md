# Windows Credential Harvesting

Extract credentials from LSASS, SAM, registry, configuration files, and more.

> **MITRE ATT&CK**: T1003, T1552, T1555, T1558

## Files

| File | Description |
|------|-------------|
| [`mimikatz_commands.md`](mimikatz_commands.md) | Complete Mimikatz reference — logonpasswords, WDigest, SAM dump, DCSync, Golden/Silver tickets, DPAPI, vault, token manipulation, skeleton key, certificates (T1003, T1558) |
| [`lsass_dump.ps1`](lsass_dump.ps1) | Multiple LSASS dump methods — comsvcs.dll, ProcDump, MiniDumpWriteDump API, Task Manager, Shadow Copy, reg save. Functions for each approach (T1003.001) |
| [`sam_extract.md`](sam_extract.md) | SAM/SYSTEM/SECURITY and NTDS.dit extraction — reg save, VSS, esentutl, ntdsutil, DCSync, CrackMapExec. Offline cracking with hashcat modes (T1003.002, T1003.003) |
| [`credential_search.ps1`](credential_search.ps1) | Automated credential hunting — PowerShell history, IIS web.config, unattend.xml, GPP cpassword, Wi-Fi passwords, .NET connection strings, registry (PuTTY/WinSCP/VNC/AutoLogon), Sticky Notes, KeePass, browser DBs, Credential Manager (T1552) |

## Quick Start

```powershell
# Search for stored credentials everywhere
.\credential_search.ps1

# Dot-source LSASS dump functions
. .\lsass_dump.ps1
Dump-ComsvcsMethod -OutPath "C:\temp\lsass.dmp"

# Offline extraction
# mimikatz: sekurlsa::minidump lsass.dmp ; sekurlsa::logonpasswords
# pypykatz: pypykatz lsa minidump lsass.dmp
```
