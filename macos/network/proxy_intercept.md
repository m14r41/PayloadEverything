# macOS Traffic Interception

Set up proxy interception for macOS applications and system traffic.

---

## 1. Burp Suite / mitmproxy Setup

### System Proxy Configuration
```bash
# Set HTTP proxy
sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8080

# Set HTTPS proxy
sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8080

# Verify
networksetup -getwebproxy "Wi-Fi"
networksetup -getsecurewebproxy "Wi-Fi"

# Disable when done
sudo networksetup -setwebproxystate "Wi-Fi" off
sudo networksetup -setsecurewebproxystate "Wi-Fi" off
```

### Install Proxy CA Certificate
```bash
# Export Burp CA (from Burp: Proxy → Options → Import/Export CA → DER)
# Or download from http://burp while proxy is active

# Install to system trust store
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain burp_ca.der

# Verify installation
security find-certificate -c "PortSwigger" /Library/Keychains/System.keychain

# Remove when done
sudo security delete-certificate -c "PortSwigger" /Library/Keychains/System.keychain
```

### mitmproxy Quick Start
```bash
# Install
pip3 install mitmproxy

# Run transparent proxy
mitmproxy --listen-port 8080

# Run with web interface
mitmweb --listen-port 8080

# Run in dump mode (CLI)
mitmdump --listen-port 8080 -w traffic.flow

# Filter specific hosts
mitmproxy --listen-port 8080 --set "view_filter=~d target.com"
```

---

## 2. Proxifier (for Apps Ignoring System Proxy)

Many macOS apps (especially Electron, Java, native) ignore the system proxy.

```bash
# Option 1: Proxifier ($40, but works reliably)
# Set rules per application to force through proxy

# Option 2: proxychains-ng
brew install proxychains-ng
# Edit /usr/local/etc/proxychains.conf:
#   socks4 127.0.0.1 1080
proxychains4 /Applications/TargetApp.app/Contents/MacOS/TargetApp

# Option 3: Environment variables (some apps respect these)
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
/Applications/TargetApp.app/Contents/MacOS/TargetApp
```

---

## 3. pfctl Packet Forwarding (Transparent Proxy)

```bash
# Create pf rules for transparent interception
cat > /tmp/pf_proxy.conf << 'EOF'
# Redirect outbound HTTP/HTTPS to local proxy
rdr pass on lo0 proto tcp from any to any port 80 -> 127.0.0.1 port 8080
rdr pass on lo0 proto tcp from any to any port 443 -> 127.0.0.1 port 8443
EOF

# Enable pf rules
sudo pfctl -f /tmp/pf_proxy.conf
sudo pfctl -e

# Disable when done
sudo pfctl -d

# Run mitmproxy in transparent mode
mitmproxy --mode transparent --listen-port 8080
```

---

## 4. Application-Specific Interception

### Java Applications
```bash
# Java uses its own trust store, not the system keychain
# Import proxy CA into Java truststore
sudo keytool -importcert -alias burp -keystore "$JAVA_HOME/lib/security/cacerts" \
    -storepass changeit -file burp_ca.der -noprompt

# Set Java proxy
java -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=8080 \
     -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=8080 \
     -jar target-app.jar
```

### Electron Applications
```bash
# Electron uses Chromium's network stack
# Set proxy via command line flags
/Applications/ElectronApp.app/Contents/MacOS/ElectronApp \
    --proxy-server="http://127.0.0.1:8080" \
    --ignore-certificate-errors

# Or set environment variable
ELECTRON_EXTRA_LAUNCH_ARGS="--proxy-server=http://127.0.0.1:8080" \
    open /Applications/ElectronApp.app
```

### Python Applications
```bash
# Python respects these env vars
export REQUESTS_CA_BUNDLE=/path/to/burp_ca.pem
export SSL_CERT_FILE=/path/to/burp_ca.pem
python3 target_script.py
```

---

## 5. curl and wget with Proxy

```bash
# curl with proxy
curl -x http://127.0.0.1:8080 https://target.com/api/endpoint

# curl with proxy + ignore cert errors
curl -x http://127.0.0.1:8080 -k https://target.com/api/endpoint

# curl using proxy CA
curl -x http://127.0.0.1:8080 --cacert burp_ca.pem https://target.com/api/endpoint

# wget with proxy
wget -e use_proxy=yes -e http_proxy=http://127.0.0.1:8080 https://target.com/file

# Permanent curl proxy config
echo 'proxy = "http://127.0.0.1:8080"' >> ~/.curlrc
```

---

## 6. Certificate Pinning Bypass

### Frida SSL Bypass
```bash
# Use Frida to bypass certificate pinning in macOS apps
frida -f /Applications/TargetApp.app/Contents/MacOS/TargetApp \
    -l ssl_bypass.js --no-pause

# Generic macOS SSL bypass hooks:
# - SecTrustEvaluateWithError → return true
# - NSURLSessionDelegate certificate challenge → trust all
# - ATS (App Transport Security) bypass
```

### Disable ATS (App Transport Security)
```bash
# Check if app has ATS exceptions in Info.plist
defaults read /Applications/TargetApp.app/Contents/Info.plist NSAppTransportSecurity 2>/dev/null

# If ATS is enforced and you can modify the app:
# Add to Info.plist:
# <key>NSAppTransportSecurity</key>
# <dict>
#     <key>NSAllowsArbitraryLoads</key>
#     <true/>
# </dict>
# Then re-sign: codesign -f -s - /Applications/TargetApp.app
```

---

## Testing Matrix

| Traffic Type | Interception Method |
|-------------|-------------------|
| HTTP/HTTPS (respects system proxy) | Burp Suite via system proxy |
| HTTP/HTTPS (ignores system proxy) | Proxifier or pfctl transparent |
| Non-HTTP TCP | TCP proxy (netcat, socat, custom) |
| mTLS (client certificate) | Extract client cert, configure in proxy |
| Certificate pinned | Frida SSL bypass |
| UDP | Wireshark capture only |
| WebSocket | Burp Suite (native support) |
