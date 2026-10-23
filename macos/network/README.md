# macOS Network Security

Network attacks and traffic interception techniques specific to macOS.

## Files

| File | Description |
|------|-------------|
| [`network_attacks.md`](network_attacks.md) | macOS network attacks — mDNS/Bonjour exploitation, AirDrop abuse, Wi-Fi deauth, Bluetooth, DNS spoofing, proxy manipulation, LLMNR poisoning, Handoff/Continuity |
| [`proxy_intercept.md`](proxy_intercept.md) | Traffic interception — Burp/mitmproxy setup, system proxy, CA install, Proxifier, pfctl transparent proxy, Electron/Java/Python proxy, cert pinning bypass |

## Quick Start

```bash
# Enumerate Bonjour services on the network
dns-sd -B _services._dns-sd._udp local.

# Set system proxy for Burp
sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8080
sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8080

# Install Burp CA
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain burp_ca.der
```
