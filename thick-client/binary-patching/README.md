# Binary Patching — Authentication & Authorization Bypass

Reverse engineer and patch desktop application binaries to bypass authentication, authorization, and licensing.

**OWASP**: TC3 (Authorization), TC5 (Authentication)  
**Severity**: CRITICAL

## Files

| File | Description |
|------|-------------|
| [`binary_analysis.md`](binary_analysis.md) | Complete guide — .NET (dnSpy), native (x64dbg/Ghidra), Java (jd-gui), Electron (asar extract). Includes patching techniques, common patterns, test cases, and reporting template. |
| [`dotnet_patch_scripts.py`](dotnet_patch_scripts.py) | Automated .NET IL patching — 7 patterns (auth bypass, license bypass, role bypass, debug enable, SSL bypass, integrity removal, logging disable) with dnSpy steps and CIL bytes |

## Tool Requirements

| App Type | Decompiler | Debugger | Patcher |
|----------|-----------|----------|---------|
| .NET | dnSpy, ILSpy | dnSpy | dnSpy (Edit Method Body) |
| C/C++ | Ghidra, IDA | x64dbg | x64dbg (Patches > Export) |
| Java | jd-gui, jadx | — | Recompile + repackage JAR |
| Electron | Built-in (JS) | Chrome DevTools | Edit source + repack asar |

## Quick Test Workflow

### .NET Application
```
1. Open in dnSpy → find ValidateUser() or IsAuthenticated()
2. Edit Method Body → change to: return true;
3. Save Module → replace original
4. Test: any credentials work → CRITICAL finding
```

### Native Application
```
1. Attach x64dbg → find string "Invalid password" or "Access denied"
2. Trace XREF back to the conditional jump (JE/JNE after CMP)
3. Flip the jump or NOP it out
4. Export patched binary
```

## Key Finding: Client-Side Only Validation

If patching the binary bypasses authentication entirely (no server-side check), that is a **CRITICAL** finding. The fix must be server-side validation.
