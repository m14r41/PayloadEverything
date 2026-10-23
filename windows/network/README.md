# Windows Network Security

Network attacks and traffic interception for Windows and Active Directory environments.

## Files

| File | Description |
|------|-------------|
| [`network_attacks.md`](network_attacks.md) | Network attacks — LLMNR/NBT-NS/mDNS poisoning (Responder, Inveigh), NTLM relay, SMB relay, Kerberoasting, AS-REP roasting, Pass-the-Hash, Pass-the-Ticket, IPv6 attacks (mitm6), ARP spoofing, ADIDNS poisoning |
| [`proxy_intercept.md`](proxy_intercept.md) | Traffic interception — system proxy, WinHTTP, CA certificate install, Proxifier, .NET/Java/Electron/Python proxy, Fiddler, certificate pinning bypass |

## Quick Start

```powershell
# Run Inveigh (LLMNR/NBT-NS poisoner from Windows)
Import-Module .\Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y

# Set system proxy for Burp
netsh winhttp set proxy proxy-server="http=127.0.0.1:8080;https=127.0.0.1:8080"

# Install Burp CA
certutil -addstore -f "ROOT" burp_ca.der
```
