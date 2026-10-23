# Windows Traffic Interception

Set up proxy interception for Windows applications.

---

## 1. System Proxy Configuration

```powershell
# Set system proxy (Internet Options / WinINET)
netsh winhttp set proxy proxy-server="http=127.0.0.1:8080;https=127.0.0.1:8080"

# Verify
netsh winhttp show proxy

# Reset
netsh winhttp reset proxy

# PowerShell proxy for current session
[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy("http://127.0.0.1:8080")
$env:HTTP_PROXY = "http://127.0.0.1:8080"
$env:HTTPS_PROXY = "http://127.0.0.1:8080"
```

---

## 2. CA Certificate Installation

```powershell
# Import Burp/mitmproxy CA certificate
certutil -addstore -f "ROOT" burp_ca.der

# Verify
certutil -store ROOT | findstr /i "portswigger"

# Remove when done
certutil -delstore ROOT "PortSwigger CA"

# For Java applications (separate trust store)
keytool -importcert -alias burp -keystore "%JAVA_HOME%\lib\security\cacerts" -storepass changeit -file burp_ca.der -noprompt
```

---

## 3. Proxifier

For applications that ignore the system proxy:

- Set per-application proxy rules
- Force specific processes through Burp/mitmproxy
- Useful for thick client testing, game clients, custom protocols

---

## 4. Application-Specific Proxy

### .NET Applications
```xml
<!-- In app.config or web.config -->
<system.net>
    <defaultProxy>
        <proxy proxyaddress="http://127.0.0.1:8080" bypassonlocal="false" />
    </defaultProxy>
</system.net>
```

### Electron Applications
```powershell
# Via command line
& "C:\Path\To\ElectronApp.exe" --proxy-server="http://127.0.0.1:8080" --ignore-certificate-errors

# Via environment
$env:ELECTRON_EXTRA_LAUNCH_ARGS = "--proxy-server=http://127.0.0.1:8080"
```

### Java Applications
```powershell
java -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=8080 `
     -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=8080 `
     -jar target-app.jar
```

### Python Applications
```powershell
$env:REQUESTS_CA_BUNDLE = "C:\path\to\burp_ca.pem"
$env:SSL_CERT_FILE = "C:\path\to\burp_ca.pem"
python target_script.py
```

---

## 5. PowerShell with Proxy

```powershell
# Invoke-WebRequest through proxy
Invoke-WebRequest -Uri "https://target.com/api" -Proxy "http://127.0.0.1:8080" -ProxyUseDefaultCredentials

# WebClient
$wc = New-Object System.Net.WebClient
$wc.Proxy = New-Object System.Net.WebProxy("http://127.0.0.1:8080")
$wc.DownloadString("https://target.com/api")
```

---

## 6. Fiddler (Windows-Native Proxy)

- Auto-configures system proxy on start
- Decrypts HTTPS traffic (installs its own CA)
- FiddlerScript for custom request/response manipulation
- AutoResponder for serving modified responses

---

## 7. Certificate Pinning Bypass

```powershell
# Frida (if applicable)
frida -f target.exe -l ssl_bypass.js --no-pause

# For .NET applications — patch ServerCertificateValidationCallback
# Inject: ServicePointManager.ServerCertificateValidationCallback = (s, cert, chain, err) => true;

# For WinHTTP
# Registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp
# Disable certificate revocation check
```

---

## Testing Matrix

| Traffic Type | Interception Method |
|-------------|-------------------|
| HTTP/HTTPS (WinINET) | System proxy + Burp |
| HTTP/HTTPS (WinHTTP) | netsh winhttp set proxy |
| HTTP/HTTPS (custom) | Proxifier / Fiddler |
| Non-HTTP TCP | TCP proxy (socat, custom) |
| .NET HTTPS | app.config proxy + Burp CA |
| Java HTTPS | JVM proxy args + Java keystore |
| Electron | CLI flags + Burp CA |
| Certificate pinned | Frida / runtime patching |
