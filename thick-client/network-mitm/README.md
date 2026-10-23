# Network MitM — SSL/TLS Interception

Intercept, inspect, and modify network traffic from desktop applications.

**OWASP**: TC7 — Insecure Communication  
**Severity**: CRITICAL (plaintext/no cert validation), HIGH (weak TLS)

## Files

| File | Description |
|------|-------------|
| [`ssl_intercept_setup.md`](ssl_intercept_setup.md) | Complete setup guide — Burp Suite proxy, Proxifier (for apps ignoring system proxy), Wireshark, TCP proxy for custom protocols, certificate pinning bypass (Frida/.NET), hosts file redirect |
| [`frida_windows_ssl_bypass.js`](frida_windows_ssl_bypass.js) | Frida script — bypass SSL/TLS cert validation in WinHTTP, WinInet, CryptoAPI, OpenSSL, Schannel, Java, .NET thick clients |
| [`tcp_proxy.py`](tcp_proxy.py) | TCP MitM proxy for non-HTTP protocols — hex dump, TLS stripping, traffic modification, format detection, logging |

## Quick Start

1. **Set up Burp Suite** on `127.0.0.1:8080`
2. **Export & install** Burp CA cert into Windows trusted root store
3. **Set system proxy** or use Proxifier to force traffic through Burp
4. **Launch the application** and observe traffic in Burp

### Critical First Test
If traffic appears in Burp **without** importing the CA cert → the app performs **no certificate validation** (CRITICAL finding).

## What to Test

| Finding | Severity | How to Check |
|---------|----------|-------------|
| Plaintext HTTP traffic | CRITICAL | Visible in Burp without TLS |
| No certificate validation | CRITICAL | Traffic interceptable without installing proxy CA |
| Self-signed cert accepted | HIGH | Use Burp default cert |
| Weak TLS (1.0/1.1) | HIGH | Check Wireshark: `ssl.handshake.version` |
| Credentials in URL parameters | HIGH | Check GET requests in Burp |
| Update channel over HTTP | CRITICAL | Monitor for update checks |
| Unencrypted SQL connections | CRITICAL | Wireshark on port 1433/3306/5432 |

## For Apps That Ignore System Proxy

Use **Proxifier** to intercept at the socket level, or **Echo Mirage** for legacy apps. See `ssl_intercept_setup.md` for detailed instructions.
