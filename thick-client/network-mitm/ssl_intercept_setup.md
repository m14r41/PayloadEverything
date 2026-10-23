# MitM / SSL Interception — Thick Client Network Testing

> OWASP Thick Client: TC7 — Insecure Communication
> Severity: CRITICAL (plaintext), HIGH (weak TLS, no cert validation)

## 1. Traffic Interception Setup

### Burp Suite (HTTP/HTTPS Proxy)
```
1. Burp Suite > Proxy > Options > Add listener on 127.0.0.1:8080
2. Export Burp CA cert: Proxy > Options > Import/Export CA Certificate > DER
3. Import cert into Windows trusted root store:
   certutil -addstore root burp_ca.der
4. Set system proxy or app-specific proxy to 127.0.0.1:8080
```

### System-Wide Proxy (forces all HTTP/HTTPS through Burp)
```powershell
# Set system proxy
netsh winhttp set proxy 127.0.0.1:8080

# Or via registry
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "127.0.0.1:8080"

# Reset when done
netsh winhttp reset proxy
```

### Proxifier (for apps that ignore system proxy)
```
1. Install Proxifier: https://www.proxifier.com/
2. Profile > Proxy Servers > Add: 127.0.0.1:8080 HTTPS
3. Profile > Proxification Rules > Add rule for target.exe > route through proxy
4. This forces ALL traffic from the app through Burp
```

### Echo Mirage (legacy thick client interceptor)
```
1. Launch Echo Mirage
2. Inject into running process or launch target through it
3. Intercept TCP/UDP traffic at socket level
4. Modify packets in real-time
```

## 2. Non-HTTP Protocol Interception

### Wireshark (passive capture)
```
1. Capture on loopback or relevant interface
2. Filter: tcp.port == <app_port> or process name
3. Check for plaintext protocols:
   - Unencrypted SQL (1433/3306/5432)
   - LDAP (389 vs 636)
   - SMTP (25/587)
   - Custom TCP protocols
```

### TCP Proxy (for custom protocols)
```python
# Simple TCP MitM proxy — relay and log traffic
# python -I tcp_proxy.py --listen-port 4444 --target-host real.server.com --target-port 1433

import socket, threading, sys

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4444
TARGET_HOST = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
TARGET_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 1433

def relay(src, dst, label):
    while True:
        data = src.recv(4096)
        if not data: break
        print(f"[{label}] {len(data)} bytes: {data[:100]}")
        dst.send(data)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", LISTEN_PORT))
srv.listen(5)
print(f"[*] Listening on :{LISTEN_PORT} -> {TARGET_HOST}:{TARGET_PORT}")

while True:
    client, addr = srv.accept()
    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote.connect((TARGET_HOST, TARGET_PORT))
    threading.Thread(target=relay, args=(client, remote, "C->S"), daemon=True).start()
    threading.Thread(target=relay, args=(remote, client, "S->C"), daemon=True).start()
```

## 3. Certificate Pinning Bypass

### .NET Applications (most common for thick clients)
```csharp
// What to look for in decompiled code (dnSpy):
ServicePointManager.ServerCertificateValidationCallback
// or
HttpClientHandler.ServerCertificateCustomValidationCallback

// Bypass: Patch with dnSpy to always return true
// Or use Fiddler with CertMaker plugin
```

### Runtime Patching with Frida (advanced)
```javascript
// frida -p <PID> -l bypass_pinning.js

// .NET SSL bypass
var mono = Process.getModuleByName("clr.dll");
// Hook ServerCertificateValidationCallback to return true

// WinHTTP bypass
var winhttp = Module.getBaseAddress("winhttp.dll");
// Hook WinHttpSetOption with WINHTTP_OPTION_SECURITY_FLAGS
```

### Hosts File Redirect (if app resolves DNS)
```
# C:\Windows\System32\drivers\etc\hosts
# Redirect app's server to your proxy
127.0.0.1   api.targetapp.com
127.0.0.1   update.targetapp.com
```

## 4. What to Test

### Plaintext Communication (CRITICAL)
- [ ] Any traffic sent over unencrypted HTTP
- [ ] Credentials sent in plaintext TCP
- [ ] SQL connections without TLS (MSSQL, MySQL, PostgreSQL)
- [ ] LDAP (port 389) instead of LDAPS (port 636)
- [ ] SMTP without STARTTLS
- [ ] Custom protocols without encryption

### Weak TLS Configuration (HIGH)
- [ ] TLS 1.0 / TLS 1.1 (deprecated)
- [ ] Weak cipher suites (RC4, DES, 3DES, NULL, EXPORT)
- [ ] SSLv3 support
- [ ] Self-signed certificates accepted
- [ ] Expired certificates accepted
- [ ] Wrong hostname certificates accepted

### No Certificate Validation (CRITICAL)
- [ ] App accepts Burp CA without importing it (no validation at all!)
- [ ] App accepts self-signed certificates
- [ ] App doesn't check certificate hostname
- [ ] No certificate pinning for sensitive operations

### Sensitive Data in Transit (HIGH)
- [ ] Credentials in URL parameters (GET requests)
- [ ] Session tokens in URL parameters
- [ ] Sensitive data in HTTP headers visible to proxies
- [ ] API keys transmitted without encryption

## 5. Testing Commands

```powershell
# Check what ports the app is connecting to
netstat -ano | findstr <PID>

# Check TLS version of a connection
# Use Wireshark filter: ssl.handshake.version

# Test SSL/TLS configuration of the server
# nmap --script ssl-enum-ciphers -p <port> <server>
# testssl.sh <server>:<port>
```
