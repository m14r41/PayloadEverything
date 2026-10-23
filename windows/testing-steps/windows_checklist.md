# Windows Security Assessment Checklist

Step-by-step checklist for Windows and Active Directory penetration testing.

## Phase 1: Reconnaissance & Enumeration

### Local System Enumeration
- [ ] System information (OS version, architecture, hotfixes)
- [ ] Current user context and privileges (`whoami /all`)
- [ ] Local users and group memberships
- [ ] Network configuration (interfaces, routes, DNS, ARP)
- [ ] Running processes and services
- [ ] Installed software and versions
- [ ] Scheduled tasks
- [ ] Firewall rules
- [ ] Named pipes and shares
- [ ] PowerShell command history
- [ ] AV/EDR detection and status

### Active Directory Enumeration
- [ ] Domain information (name, functional level, domain controllers)
- [ ] Password policy and lockout settings
- [ ] Domain Admins / Enterprise Admins / Schema Admins
- [ ] All domain users (enabled, description, last logon)
- [ ] Kerberoastable accounts (users with SPNs)
- [ ] AS-REP Roastable accounts (no pre-auth)
- [ ] Delegation settings (unconstrained, constrained, RBCD)
- [ ] Domain computers and OS versions
- [ ] Domain trusts and foreign memberships
- [ ] Group Policy Objects
- [ ] LAPS deployment status
- [ ] AdminSDHolder protected objects

### Tools
```
windows_enum.ps1    → Local enumeration
ad_enum.ps1         → AD enumeration
SharpHound          → BloodHound data collection
```

## Phase 2: Privilege Escalation

### Local Privilege Escalation
- [ ] UAC bypass (fodhelper, eventvwr, CMSTP, sdclt, computerdefaults)
- [ ] Unquoted service paths
- [ ] Writable service binaries
- [ ] Weak service DACLs (ChangeConfig, Start, Stop)
- [ ] DLL hijacking opportunities (writable PATH directories)
- [ ] AlwaysInstallElevated (MSI privilege escalation)
- [ ] Stored credentials (Credential Manager, DPAPI)
- [ ] Scheduled tasks running as SYSTEM with writable paths
- [ ] Potato attacks (service accounts with SeImpersonate)
- [ ] Registry autorun with writable paths
- [ ] Named pipe impersonation

### Tools
```
uac_bypass.ps1          → UAC bypass functions
service_exploits.ps1    → Service misconfiguration scanner
potato_attacks.md       → Potato attack reference
alwaysinstallelevated.md → MSI escalation
```

## Phase 3: Credential Harvesting

### In-Memory Credentials
- [ ] LSASS dump (comsvcs.dll, ProcDump, MiniDumpWriteDump)
- [ ] Mimikatz logonpasswords
- [ ] WDigest plaintext passwords (enable if needed)
- [ ] Kerberos tickets from memory

### On-Disk Credentials
- [ ] SAM/SYSTEM/SECURITY registry hives
- [ ] NTDS.dit extraction (Shadow Copy, ntdsutil)
- [ ] Group Policy Preferences (cpassword)
- [ ] Unattend.xml / sysprep files
- [ ] IIS web.config connection strings
- [ ] .NET machine.config connection strings

### Stored Credentials
- [ ] PowerShell command history
- [ ] PuTTY/WinSCP saved sessions
- [ ] VNC passwords (registry)
- [ ] Auto-logon credentials (registry)
- [ ] Wi-Fi passwords
- [ ] Browser saved passwords (SQLite DBs)
- [ ] KeePass databases
- [ ] Sticky Notes database

### Kerberos Attacks
- [ ] Kerberoasting (extract and crack TGS tickets)
- [ ] AS-REP Roasting (crack TGTs for no-preauth accounts)
- [ ] Targeted Kerberoasting (set SPN → Kerberoast)

### Tools
```
mimikatz_commands.md    → Mimikatz reference
lsass_dump.ps1          → LSASS dump methods
sam_extract.md          → SAM/NTDS extraction
credential_search.ps1   → Automated credential search
kerberos_attacks.md     → Kerberos attack reference
```

## Phase 4: Lateral Movement

### Remote Execution Methods
- [ ] PsExec / SMB exec (creates service, drops binary)
- [ ] WMI process creation (no binary on disk)
- [ ] WinRM / PowerShell remoting
- [ ] DCOM execution (MMC20, ShellBrowserWindow, ShellWindows)
- [ ] Scheduled task creation (remote)
- [ ] Service Control Manager (remote service creation)
- [ ] RDP (interactive access)
- [ ] SMB file copy + remote execution

### Pass-the-X
- [ ] Pass-the-Hash (NTLM hash authentication)
- [ ] Pass-the-Ticket (Kerberos ticket injection)
- [ ] Overpass-the-Hash (hash → Kerberos TGT)

### Tools
```
lateral_movement.md → Lateral movement reference
winrm_exec.ps1     → WinRM toolkit
kerberos_attacks.md → PtH/PtT/OPtH reference
```

## Phase 5: Persistence

### Registry Persistence
- [ ] Run/RunOnce keys (HKLM + HKCU)
- [ ] Winlogon Shell/Userinit
- [ ] Image File Execution Options (debugger)
- [ ] AppInit_DLLs
- [ ] COM object hijacking
- [ ] SilentProcessExit monitoring
- [ ] ScreenSaver executable

### Task-Based Persistence
- [ ] Scheduled tasks (logon, startup, idle, event triggers)
- [ ] Hidden scheduled tasks (in Microsoft subfolders)
- [ ] WMI event subscriptions (EventFilter + Consumer + Binding)

### Other Persistence
- [ ] Startup folder items
- [ ] Service creation (auto-start)
- [ ] DLL search order hijacking
- [ ] Accessibility features backdoor (sethc, utilman)
- [ ] Golden ticket (krbtgt hash persistence)
- [ ] Skeleton key (domain-wide master password)
- [ ] AdminSDHolder modification
- [ ] DCSync rights grant

### Tools
```
registry_persistence.ps1    → Registry persistence
scheduled_task_persist.ps1  → Task-based persistence
wmi_persist.ps1             → WMI event subscriptions
startup_persist.md          → All persistence locations
```

## Phase 6: Defense Evasion

### Bypass Security Controls
- [ ] AMSI bypass (amsiInitFailed, memory patch, downgrade)
- [ ] ETW bypass (EtwEventWrite patch)
- [ ] ScriptBlock logging disable (registry + in-memory)
- [ ] Module logging and transcription disable
- [ ] AppLocker bypass (LOLBAS: MSBuild, InstallUtil, Mshta, etc.)
- [ ] Windows Defender evasion (exclusions, in-memory execution)
- [ ] Constrained Language Mode bypass

### Tools
```
amsi_bypass.ps1        → AMSI bypass techniques
etw_bypass.ps1         → ETW and logging bypass
applocker_bypass.md    → AppLocker/WDAC bypass
defender_evasion.md    → Defender evasion reference
```

## Phase 7: Active Directory Attacks

### Domain Escalation
- [ ] DCSync attack (extract all domain hashes)
- [ ] ACL abuse chains (GenericAll → DA)
- [ ] GPO abuse (writable GPO → code execution)
- [ ] LAPS password extraction
- [ ] Coercion attacks (PrinterBug, PetitPotam)
- [ ] Shadow Credentials (msDS-KeyCredentialLink)
- [ ] Delegation abuse (unconstrained, constrained, RBCD)

### Domain Persistence
- [ ] Golden Ticket (forge TGT with krbtgt hash)
- [ ] Silver Ticket (forge TGS with service hash)
- [ ] Diamond Ticket (modify legitimate TGT)
- [ ] Skeleton Key (in-memory master password)
- [ ] AdminSDHolder persistence
- [ ] DCSync rights backdoor

### Cross-Trust Attacks
- [ ] Trust enumeration and foreign membership
- [ ] SID History injection
- [ ] Cross-forest ticket forging (with SID filtering bypass)

### Tools
```
ad_attacks.ps1         → AD attack automation
bloodhound_queries.md  → BloodHound Cypher queries
kerberos_attacks.md    → Kerberos ticket attacks
```

## Phase 8: Data Exfiltration & Cleanup

### Data Collection
- [ ] Identify sensitive files (finance, PII, credentials, source code)
- [ ] ShareFinder / file share enumeration
- [ ] Database access and extraction
- [ ] Email access (OWA, Exchange, Graph API)

### Cleanup
- [ ] Remove all tools and payloads
- [ ] Remove persistence mechanisms
- [ ] Clear event logs for testing commands only
- [ ] Document all changes made to systems
- [ ] Verify cleanup completeness

## MITRE ATT&CK Mapping

| Phase | Techniques |
|-------|-----------|
| Reconnaissance | T1082, T1087, T1016, T1049, T1033 |
| Privilege Escalation | T1548.002, T1574, T1053, T1068 |
| Credential Access | T1003, T1558, T1552 |
| Lateral Movement | T1021, T1047, T1053, T1550 |
| Persistence | T1547, T1053, T1546.003, T1098 |
| Defense Evasion | T1562, T1218, T1027, T1059 |
| Domain Attacks | T1003.006, T1222, T1484, T1187 |
