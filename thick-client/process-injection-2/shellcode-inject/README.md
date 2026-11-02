# shellcode-inject

Three shellcode-based injection variants. All non-reverse-shell — each demonstrates a specific flavour of shellcode delivery into another process.

```
sc_injector.cpp / .exe       msfvenom shellcode (notepad) via CreateRemoteThread
sc_infloop.cpp  / .exe       2-byte jmp $ shellcode — target stays alive forever
                             for Process Hacker / System Informer inspection
pop_notepad_dll.cpp / .dll   DLL variant — DllMain spawns notepad via WinExec
```

## When to use which

| File | Payload | Target survives? | Good for |
|---|---|---|---|
| `sc_injector.exe` | msfvenom `windows/x64/exec CMD=notepad.exe EXITFUNC=process` | No — ExitProcess kills target | quick visual proof that shellcode fired |
| `sc_infloop.exe` | hand-crafted 2-byte `EB FE` (jmp $) | **Yes forever** (thread spins at 100% CPU) | inspecting the injected thread + RWX region in System Informer |
| `pop_notepad_dll.dll` | DLL spawns notepad from `DllMain` thread | Yes | demonstrating DLL injection without the extra effort of ../reverse-shell/revshell_pure_dll |

All three are **loaded via `pop.exe --dll`** (for the DLL variant) or run standalone with a PID argument (for the EXE variants).

## Usage

```powershell
# shellcode -> target (msfvenom notepad; target process will exit after)
sc_injector.exe <PID>

# infinite-loop shellcode -> target (great for Process Hacker inspection)
sc_infloop.exe <PID>

# DLL -> target (spawns notepad; target survives)
..\pop.exe <PID> --dll shellcode-inject\pop_notepad_dll.dll
```

## Build

**Windows (MSVC)** — "x64 Native Tools Command Prompt for VS 2022":

```
cl /EHsc /O2 /nologo sc_injector.cpp /OUT:sc_injector.exe
cl /EHsc /O2 /nologo sc_infloop.cpp  /OUT:sc_infloop.exe
cl /LD /EHsc /O2 /nologo pop_notepad_dll.cpp /OUT:pop_notepad_dll.dll
```

**Linux (one-liner)**:

```bash
sudo apt install -y mingw-w64 && \
  x86_64-w64-mingw32-g++ -O2 -s -o sc_injector.exe sc_injector.cpp && \
  x86_64-w64-mingw32-g++ -O2 -s -o sc_infloop.exe sc_infloop.cpp && \
  x86_64-w64-mingw32-g++ -shared -O2 -s -o pop_notepad_dll.dll pop_notepad_dll.cpp -Wl,--subsystem,windows,--kill-at
```

## Customize

Swap the shellcode bytes at the top of `sc_injector.cpp` with your own msfvenom output:

```bash
msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f c
```

Change `EXITFUNC=thread` so the target survives after the payload runs.

## Legal

Authorized testing only.
