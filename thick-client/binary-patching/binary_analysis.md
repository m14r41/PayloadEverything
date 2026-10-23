# Binary Patching / Reverse Engineering — Auth & License Bypass

> OWASP Thick Client: TC3 — Improper Authorization, TC5 — Improper Authentication
> Severity: CRITICAL — bypassing authentication/authorization client-side

## Tools Required

| Tool | Purpose |
|------|---------|
| **dnSpy** | .NET decompiler + debugger + live patching |
| **ILSpy** | .NET decompiler (read-only, faster) |
| **x64dbg / x32dbg** | Native debugger (C/C++ apps) |
| **Ghidra** | Disassembler / decompiler (any binary) |
| **IDA Pro** | Disassembler (commercial) |
| **Process Hacker** | Process inspection, memory, handles |
| **CFF Explorer** | PE header analysis |
| **de4dot** | .NET deobfuscation |
| **Reflexil** | IL code editing (ILSpy plugin) |

---

## 1. .NET Applications (Most Desktop Thick Clients)

### Identify .NET
```powershell
# Check if .NET assembly
[System.Reflection.Assembly]::LoadFile("C:\path\to\app.exe").GetName()

# Or check PE headers for CLR directory
dumpbin /headers app.exe | findstr "CLR"
```

### Decompile with dnSpy
```
1. Open dnSpy → File → Open → target.exe and its DLLs
2. Browse namespaces for:
   - Login / Authentication classes
   - License / Registration classes
   - Authorization / Role checks
   - Crypto / Encryption methods
3. Search (Ctrl+Shift+K) for:
   - "password", "authenticate", "login", "isAdmin"
   - "license", "trial", "expired", "registered"
   - "role", "authorize", "permission", "isAllowed"
```

### Patch Authentication Bypass
```
1. In dnSpy, find the authentication method:
   bool ValidateUser(string username, string password) { ... }

2. Right-click method → Edit Method Body (C#)
3. Change to:
   return true;

4. File → Save Module → save patched binary
5. Replace original with patched version
6. Test: any credentials should now work
```

### Patch License Check
```
1. Find license validation:
   bool IsLicensed() { ... }
   bool CheckExpiration() { ... }

2. Patch to always return true (or false for expiration)

3. Common patterns:
   - DateTime comparison → patch to return far-future date
   - Registry key check → patch to skip check
   - Server validation → patch to skip HTTP call and return success
   - Hardware ID → patch to accept any value
```

### Patch Role/Authorization Check
```
1. Find authorization logic:
   bool HasPermission(string role) { ... }
   bool IsAdmin() { ... }

2. Patch to always return true
3. Test: access admin-only features as regular user
4. Document: which features became accessible
```

---

## 2. Native Applications (C/C++)

### x64dbg — Runtime Patching
```
1. Attach x64dbg to the running process
2. Set breakpoints on:
   - Conditional jumps after password comparison (CMP + JE/JNE)
   - API calls: CompareStringW, lstrcmpW, CryptVerifySignature
   - Network calls: send(), recv(), WSASend()
3. Flip the conditional jump:
   JE → JNE (or vice versa) to bypass the check
4. Right-click → Patches → export patched binary
```

### Common x64dbg Patterns
```
; Login check pattern
CALL    ComparePassword         ; Compare input with stored password
TEST    EAX, EAX               ; Check result
JNE     LoginFailed             ; Jump if not equal → patch to JE or NOP

; License check pattern
CALL    CheckLicenseFile
TEST    EAX, EAX
JE      TrialExpired            ; Jump if zero (unlicensed) → NOP the jump

; Feature gate pattern
CMP     [UserRole], 1           ; 1 = admin
JNE     AccessDenied            ; → patch to NOP (always allow)
```

### Ghidra — Static Analysis
```
1. Open Ghidra → New Project → Import binary
2. Auto-analyze
3. Search strings (Search → For Strings):
   - "Invalid password"
   - "License expired"
   - "Access denied"
   - "Unauthorized"
4. Find XREF to these strings → trace back to the conditional check
5. Document the logic for your report
```

---

## 3. Java / Electron Applications

### Java Thick Clients
```bash
# Decompile JAR
jd-gui app.jar
# or
jadx -d output/ app.jar

# Search for auth logic
grep -r "authenticate\|password\|isAdmin\|checkLicense" output/

# Patch: modify .class file and repackage JAR
javac -cp app.jar PatchedClass.java
jar uf app.jar com/app/PatchedClass.class
```

### Electron Applications
```bash
# Electron apps bundle Node.js — the source is in asar archive
# Extract:
npx asar extract resources/app.asar ./extracted

# Find auth logic:
grep -r "password\|authenticate\|isAdmin\|license" ./extracted/

# Modify the JavaScript source
# Repack:
npx asar pack ./extracted resources/app.asar

# Or directly edit: some apps load from resources/app/ without asar
```

---

## 4. Common Test Cases

### Authentication Bypass
- [ ] Patch client-side password validation to always return true
- [ ] Modify "remember me" token to elevate privileges
- [ ] Bypass MFA check by patching the verification method
- [ ] Skip server certificate validation to MitM auth requests
- [ ] Modify authentication request/response in transit

### Authorization Bypass
- [ ] Patch role check to always return admin
- [ ] Modify user role in local storage/config/registry
- [ ] Access admin UI elements hidden by client-side logic
- [ ] Call admin API endpoints directly (captured via proxy)
- [ ] Modify feature flags in config to enable hidden features

### License Bypass
- [ ] Patch license validation to always return valid
- [ ] Modify trial expiration date in registry/config
- [ ] Block license server communication (hosts file)
- [ ] Replay captured license activation response
- [ ] Patch hardware ID check to accept any machine

### Business Logic
- [ ] Modify transaction amounts in client-side memory
- [ ] Skip client-side validation (input length, format, range)
- [ ] Reorder/replay API calls to bypass workflow restrictions
- [ ] Modify hidden form fields or parameters
- [ ] Access other users' data by modifying user ID in requests

---

## 5. Reporting Template

```
Title: Client-Side Authentication Bypass via Binary Patching
Severity: CRITICAL
CVSS: 9.8

Description:
The application performs authentication validation entirely on the client
side. By decompiling the .NET assembly with dnSpy and modifying the
ValidateUser() method in [Assembly.dll] to always return true, an attacker
can bypass authentication completely.

Steps to Reproduce:
1. Open target.exe in dnSpy
2. Navigate to Namespace.AuthService.ValidateUser()
3. Edit method body → change to "return true;"
4. Save patched assembly
5. Replace original DLL
6. Launch application — any credentials accepted

Impact:
Complete authentication bypass. Attacker gains full access to the
application without valid credentials.

Recommendation:
- Perform all authentication server-side
- Implement integrity checks on client binaries (code signing)
- Use certificate pinning for server communication
- Implement server-side session validation
```
