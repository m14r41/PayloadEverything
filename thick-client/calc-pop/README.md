# calc-pop — Proof of Code Execution

Pop `calc.exe` as a non-destructive proof that arbitrary code execution is achieved. Use these as the first-stage PoC before escalating to a reverse shell.

## Files

| File | Type | Description |
|------|------|-------------|
| [`dll_calc.c`](dll_calc.c) | C (DLL) | DLL that launches calc on load via `DllMain` + exported functions |
| [`chm_calc.html`](chm_calc.html) | HTML | CHM source — ActiveX `ShortCut` object triggers calc |
| [`chm_project.hhp`](chm_project.hhp) | HHP | HTML Help Workshop project file to compile the CHM |
| [`shellcode_calc.py`](shellcode_calc.py) | Python | x64/x86 calc shellcode in C, Python, C#, or raw format |

## Build

```bash
# DLL (64-bit)
x86_64-w64-mingw32-gcc -shared -o calc.dll dll_calc.c

# DLL (32-bit)
i686-w64-mingw32-gcc -shared -o calc32.dll dll_calc.c

# CHM
hhc.exe chm_project.hhp

# Shellcode formats
python -I shellcode_calc.py --format c --arch x64
python -I shellcode_calc.py --format python --arch x86
python -I shellcode_calc.py --format csharp --arch x64
python -I shellcode_calc.py --format raw --arch x64 > shellcode.bin
```

## When to Use

- First PoC for DLL hijack — place `calc.dll` as the hijacked DLL name
- First PoC for process injection — use the shellcode output
- First PoC for CHM exploitation — compile and deliver `payload.chm`
- Replace with reverse shell DLL once execution is confirmed
