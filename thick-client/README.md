# Thick Client / Desktop Application Payloads

Payloads, discovery scripts, and testing procedures for Windows desktop (thick client) application security assessments.

> Maps to: [OWASP Thick Client Top 10](https://owasp.org/www-project-thick-client-top-10/)

## Attack Categories

### Code Execution

| Folder | OWASP | Severity | Description |
|--------|-------|----------|-------------|
| [calc-pop/](calc-pop/) | — | PoC | Proof-of-execution payloads (DLL, CHM, shellcode) |
| [rce/dll-hijack/](rce/dll-hijack/) | TC6 | HIGH-CRIT | DLL search-order hijacking + proxy DLL templates |
| [rce/chm/](rce/chm/) | TC6 | HIGH | Compiled HTML Help command execution |
| [rce/process-injection/](rce/process-injection/) | TC6 | HIGH | CreateRemoteThread, DLL injection, APC injection |
| [reverse-shell/](reverse-shell/) | TC6 | CRIT | TCP callback shells — DLL, PowerShell, msfvenom |

### Data Security

| Folder | OWASP | Severity | Description |
|--------|-------|----------|-------------|
| [insecure-storage/](insecure-storage/) | TC2 | CRIT | Credential extraction from configs, registry, DPAPI |
| [memory-analysis/](memory-analysis/) | TC9 | HIGH | Dump process memory, search for credentials/tokens |
| [network-mitm/](network-mitm/) | TC7 | CRIT | SSL intercept, cert pinning bypass, MitM setup |

### Privilege & Authorization

| Folder | OWASP | Severity | Description |
|--------|-------|----------|-------------|
| [privilege-escalation/](privilege-escalation/) | TC3 | CRIT | Service exploits, weak ACLs, scheduled tasks |
| [binary-patching/](binary-patching/) | TC3/TC5 | CRIT | Auth/license bypass via dnSpy, Ghidra, x64dbg |

### Import Feature / File Parsing

| Folder | OWASP | Severity | Description |
|--------|-------|----------|-------------|
| [import-feature/](import-feature/) | TC6/TC10 | HIGH-CRIT | .sln, zip slip, XXE, DCL, DDE, deserialization |

### Application-Specific

| Folder | OWASP | Severity | Description |
|--------|-------|----------|-------------|
| [electron-cef/](electron-cef/) | TC6 | CRIT | Electron/CEF: XSS→RCE, nodeIntegration, preload |
| [com-hijack/](com-hijack/) | TC6 | HIGH | COM CLSID hijacking, named pipe abuse |

### Methodology

| Folder | Description |
|--------|-------------|
| [testing-steps/](testing-steps/) | Full 15-section VAPT checklist with step-by-step procedures |

## Prerequisites

| Tool | Purpose | Required For |
|------|---------|-------------|
| MinGW-w64 or Visual Studio Build Tools | Compile C payloads | DLL, process injection |
| HTML Help Workshop | Compile .chm files | CHM payloads |
| Python 3.8+ | Run generators | Import feature payloads |
| dnSpy | .NET decompile + patch | Binary patching |
| Ghidra / x64dbg | Native binary analysis | Binary patching |
| Burp Suite | HTTP/HTTPS proxy | Network MitM |
| Process Monitor (Sysinternals) | Runtime monitoring | DLL hijack discovery |
| Process Hacker | Memory inspection | Memory analysis |
| Strings (Sysinternals) | Binary string extraction | Credential extraction |

## Typical Assessment Workflow

```
1. Reconnaissance
   +-- Identify technology stack (.NET, Java, C++, Electron?)
   +-- Run discovery scripts (find_missing_dlls.ps1, service_exploits.ps1)
   +-- Check file permissions (weak_permissions.ps1)

2. Static Analysis
   +-- Decompile with dnSpy/Ghidra
   +-- Search for hardcoded credentials (extract_credentials.ps1)
   +-- Analyze import/export file handling

3. Dynamic Analysis
   +-- Set up Burp proxy / Wireshark capture
   +-- Monitor with Process Monitor for DLL loads
   +-- Dump and search process memory

4. Exploitation
   +-- DLL hijack with calc-pop PoC, escalate to reverse shell
   +-- Test import features with crafted files
   +-- Patch authentication/authorization if client-side

5. Reporting
   +-- Follow checklist in testing-steps/
   +-- Document with screenshots, commands, CVSS scores
```

## Compilation Cheat Sheet

```bash
# 64-bit DLL (most common)
x86_64-w64-mingw32-gcc -shared -o payload.dll source.c -lws2_32

# 32-bit DLL
i686-w64-mingw32-gcc -shared -o payload32.dll source.c -lws2_32

# EXE (process injection tools)
x86_64-w64-mingw32-gcc -o tool.exe source.c

# MSVC alternative
cl /LD source.c /Fe:payload.dll ws2_32.lib
```
