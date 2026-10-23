# Memory Analysis — Sensitive Data in Process Memory

Dump and search process memory for credentials, tokens, and encryption keys.

**OWASP**: TC9 — Sensitive Data in Memory  
**Severity**: HIGH

## Files

| File | Description |
|------|-------------|
| [`dump_process_memory.ps1`](dump_process_memory.ps1) | Dumps process memory (procdump/comsvcs.dll), searches loaded modules for credential patterns, generates analysis guidance |
| [`credential_patterns.yar`](credential_patterns.yar) | YARA rules for scanning memory dumps — JWT, passwords, connection strings, OAuth, AWS keys, private keys, NTLM hashes, session cookies |

## Usage

```powershell
# Live pattern scan
.\dump_process_memory.ps1 -ProcessName "TargetApp"

# Full memory dump to file for offline analysis
.\dump_process_memory.ps1 -ProcessName "TargetApp" -DumpToFile
```

## Testing Procedure

1. Login to the application with known test credentials
2. Dump memory → search for the credentials you entered
3. **Finding**: credentials visible in memory after login
4. Logout of the application
5. Dump memory again → search for the same credentials
6. **Finding**: credentials persist after logout (should be zeroed)
7. Wait for session timeout → check again

## Offline Analysis (after `-DumpToFile`)

```bash
# Search with Sysinternals strings
strings.exe -n 8 TargetApp.dmp | findstr /i "password"
strings.exe -n 8 TargetApp.dmp | findstr /i "token"
strings.exe -n 8 TargetApp.dmp | findstr /i "Data Source"

# WinDbg
!address -summary
s -a 0 L?ffffffff "password"
```

## Tools

- **Process Hacker** — GUI memory inspection (Properties > Memory > Search)
- **x64dbg** — Attach > Memory Map > Search
- **ProcDump** (Sysinternals) — Full memory dump
- **WinDbg** — Advanced memory forensics
