# DLL Hijack — Search-Order Hijacking

Exploit Windows DLL search order to load a malicious DLL when the target application starts.

**MITRE ATT&CK**: T1574.001 — DLL Search Order Hijacking  
**Severity**: HIGH to CRITICAL (CRITICAL if service runs as SYSTEM)

## Files

| File | Description |
|------|-------------|
| [`dll_hijack_template.c`](dll_hijack_template.c) | Proxy DLL template — forwards calls to the real DLL while executing payload. Avoids crashing the app. |
| [`find_missing_dlls.ps1`](find_missing_dlls.ps1) | Discovery script — finds hijackable DLLs via procmon filters, PE import analysis, writable path checks, known DLL list |
| [`exports.def`](exports.def) | Pre-built .def export forwarding for VERSION.dll (with WINMM.dll and USERENV.dll variants commented) |
| [`generate_proxy_def.py`](generate_proxy_def.py) | Auto-generate .def export forwarding files for ANY DLL using pefile |
| [`sideload_scanner.ps1`](sideload_scanner.ps1) | Find signed executables vulnerable to DLL sideloading — bypasses AppLocker/WDAC |

## How It Works

1. Windows searches for DLLs in this order: app directory → system directory → Windows directory → PATH
2. If the app loads a DLL not present in its own directory, placing one there makes it load first
3. A "proxy" DLL runs your payload then forwards all function calls to the real DLL

## Step-by-Step

### 1. Discover Hijackable DLLs
```powershell
# Automated discovery
.\find_missing_dlls.ps1 -TargetExe "C:\Program Files\TargetApp\app.exe"
```
Or use Process Monitor manually:
- Filter: `Process Name = app.exe`, `Result = NAME NOT FOUND`, `Path ends with .dll`

### 2. Build Payload
```bash
# Simple calc PoC (from calc-pop/)
x86_64-w64-mingw32-gcc -shared -o VERSION.dll ../../../calc-pop/dll_calc.c

# Proxy DLL (app keeps working)
# Edit dll_hijack_template.c: change ORIG_DLL name and add proxy exports
x86_64-w64-mingw32-gcc -shared -o VERSION.dll dll_hijack_template.c

# Reverse shell
x86_64-w64-mingw32-gcc -shared -o VERSION.dll ../../reverse-shell/dll_revshell.c -lws2_32
```

### 3. Deploy and Test
1. Copy the real DLL as `<name>_orig.dll` (only needed for proxy template)
2. Place your payload DLL as `<name>.dll` in the app directory
3. Launch the application
4. calc.exe should pop / reverse shell should connect

## Common Hijackable DLLs

`VERSION.dll`, `USERENV.dll`, `WINMM.dll`, `WTSAPI32.dll`, `dwmapi.dll`, `UxTheme.dll`, `PROPSYS.dll`, `ntmarta.dll`, `CRYPTSP.dll`, `profapi.dll`

## What to Document

- DLL name and full path where it was placed
- Whether the application directory is writable by non-admin users
- Which user context the DLL loaded in
- Whether the application continued to function (proxy vs non-proxy)
