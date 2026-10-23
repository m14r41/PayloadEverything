# COM Hijacking

Hijack Windows COM objects by registering a malicious DLL under HKCU for CLSIDs the target app uses.

**MITRE ATT&CK**: T1546.015 — Component Object Model Hijacking  
**Severity**: HIGH (persistence), CRITICAL (if loaded by a SYSTEM service)

## Files

| File | Description |
|------|-------------|
| [`com_hijack_template.c`](com_hijack_template.c) | COM DLL with proper class factory implementation — loads as a valid COM object while executing payload |
| [`find_com_targets.ps1`](find_com_targets.ps1) | Discovery script — finds phantom COM objects, CLSIDs without HKCU override, writable COM DLLs, named pipes |
| [`com_persistence.ps1`](com_persistence.ps1) | COM persistence automation — discover hijackable CLSIDs, generate Procmon filters, plant/clean HKCU overrides |

## How It Works

1. Windows resolves COM CLSIDs via registry: **HKCU takes precedence over HKLM**
2. If a CLSID exists only in HKLM, creating it in HKCU with our DLL makes the app load ours
3. Our DLL runs payload on load, optionally proxying to the real COM object

## Step-by-Step

### 1. Discover Targets
```powershell
.\find_com_targets.ps1 -ProcessName "TargetApp"
```
Or use Process Monitor: filter `RegOpenKey` + `InprocServer32` + `NAME NOT FOUND`

### 2. Build Payload
```bash
x86_64-w64-mingw32-gcc -shared -o payload.dll com_hijack_template.c -lole32
```

### 3. Register Hijack
```cmd
reg add "HKCU\Software\Classes\CLSID\{TARGET-CLSID}\InprocServer32" /ve /d "C:\path\to\payload.dll" /f
reg add "HKCU\Software\Classes\CLSID\{TARGET-CLSID}\InprocServer32" /v ThreadingModel /d "Both" /f
```

### 4. Trigger
Restart the target application — our DLL loads instead of the legitimate COM object.

## Bonus: Named Pipe Enumeration

The discovery script also lists named pipes on the system — these are IPC attack surface. Test with `accesschk.exe` for weak permissions on pipes the target app creates.
