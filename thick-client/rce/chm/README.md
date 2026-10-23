# CHM — Compiled HTML Help Exploitation

Execute commands via `.chm` (Compiled HTML Help) files using embedded ActiveX objects.

**Severity**: HIGH  
**Prereq**: HTML Help Workshop (`hhc.exe`) to compile

## Files

| File | Description |
|------|-------------|
| [`chm_rce.html`](chm_rce.html) | HTML source with multiple ActiveX command execution methods |
| [`build_chm.ps1`](build_chm.ps1) | PowerShell build script — compiles HTML into `.chm` |

## How It Works

CHM files can embed ActiveX `ShortCut` objects (`clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11`) that execute arbitrary commands when the help page loads.

## Step-by-Step

### 1. Edit the Payload
Edit `chm_rce.html` — change `calc.exe` to your command (or leave as PoC).

### 2. Compile
```powershell
.\build_chm.ps1 -HtmlFile chm_rce.html -OutputChm help.chm -Title "Application Help"
```
Or manually: `hhc.exe project.hhp`

### 3. Deliver
- Replace existing `.chm` in the app's help directory
- Place in a writable path the app reads help from
- Include in a `.zip` import package
- Trigger via the application's Help menu / F1

## Attack Scenarios

- App loads `.chm` from a user-writable directory
- App opens `.chm` files from imported archives
- App registers `.chm` file association and user is tricked into opening one
