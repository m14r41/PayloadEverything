# PayloadEverything

A comprehensive, organized payload library for Vulnerability Assessment and Penetration Testing (VAPT) across all application types.

> **Authorization Required** — Use these payloads ONLY on systems you have explicit written authorization to test.

## Modules

| Module | Status | Description |
|--------|--------|-------------|
| [Thick Client](thick-client/) | Active | Desktop/thick client — DLL hijack, process injection, CHM, import exploits, privilege escalation, credential extraction, binary patching, Electron/CEF, COM hijacking, reverse shells, token manipulation |
| [Web Application](web-application/) | Active | OWASP Top 10 — XSS, SQLi, SSRF, SSTI, LFI, command injection, file upload/webshells, XXE, JWT attacks, CORS PoC, open redirect, deserialization |
| [Mobile Application](mobile-application/) | Active | Android & iOS — SSL pinning bypass, root/jailbreak bypass, local storage extraction, Frida scripts, intent abuse, biometric bypass, crypto hooks |
| [API](api/) | Active | REST/GraphQL — BOLA, broken auth, JWT attacks, BFLA, mass assignment, rate limiting, GraphQL injection, NoSQL injection, SSRF, wordlists |
| [Linux](linux/) | Active | Linux OS — kernel exploits, SUID/sudo/capabilities abuse, container escape, cron/systemd persistence, credential harvesting, log tampering, network tunneling |
| [macOS](macos/) | Active | macOS — TCC bypass, dylib hijack, sudo exploits, LaunchAgent/Daemon persistence, keychain/browser creds, Gatekeeper/SIP bypass, mDNS/AirDrop attacks |
| [Windows](windows/) | Active | Windows/AD — UAC bypass, token abuse, service exploits, registry/WMI/scheduled task persistence, Mimikatz/LSASS/SAM, AMSI/AppLocker/ETW bypass, Kerberos attacks, lateral movement |

## Project Structure

```
PayloadEverything/
|
+-- thick-client/                  # Desktop / thick client applications
|   +-- calc-pop/                  # Proof-of-execution payloads (calc.exe)
|   +-- rce/                       # Remote code execution
|   |   +-- dll-hijack/            # DLL hijacking, proxy DLL, sideloading scanner
|   |   +-- chm/                   # Compiled HTML Help weaponization
|   |   +-- process-injection/     # Classic, DLL, APC, hollowing, shellcode runner
|   +-- reverse-shell/             # DLL, PowerShell, C#, MSBuild, msfvenom shells
|   +-- import-feature/            # File-import attack surface
|   |   +-- deserialization/       # .NET (ysoserial.net) + Java (ysoserial) deser
|   +-- insecure-storage/          # Credentials, DPAPI, tokens, Windows vault
|   +-- memory-analysis/           # Process dump + YARA credential patterns
|   +-- network-mitm/              # SSL intercept, Frida bypass, TCP proxy
|   +-- privilege-escalation/      # Services, pipes, tokens, registry persistence
|   +-- binary-patching/           # dnSpy/.NET patching scripts, Ghidra, x64dbg
|   +-- electron-cef/              # Electron XSS→RCE payloads, config audit
|   +-- com-hijack/                # COM hijacking, persistence, discovery
|   +-- testing-steps/             # Full VAPT checklist (15 sections)
|
+-- web-application/               # Web application payloads
|   +-- xss/                       # 80+ XSS payloads (basic, WAF bypass, DOM, blind)
|   +-- sqli/                      # 60+ SQLi payloads (UNION, blind, time, NoSQL)
|   +-- ssrf/                      # Cloud metadata, protocol smuggling, IP bypass
|   +-- ssti/                      # 12 template engines with detection + RCE
|   +-- lfi/                       # Path traversal, PHP wrappers, log poisoning
|   +-- command-injection/         # OS command injection + filter bypass
|   +-- file-upload/               # Webshells (PHP/ASPX/JSP/Python) + bypass tips
|   +-- xxe/                       # XML external entity payloads
|   +-- auth-bypass/               # JWT attacks toolkit + common secrets
|   +-- cors/                      # CORS misconfiguration PoC
|   +-- open-redirect/             # 40+ redirect payloads
|   +-- deserialization/           # Java ysoserial, .NET, PHP, Python pickle
|
+-- mobile-application/            # Mobile application payloads
|   +-- android/
|   |   +-- ssl-pinning-bypass/    # Universal Frida SSL bypass + objection
|   |   +-- root-detection-bypass/ # Frida root detection bypass
|   |   +-- local-storage/         # SharedPrefs, SQLite, KeyStore extraction
|   |   +-- intent-abuse/          # Exported component enumeration + exploitation
|   |   +-- frida-scripts/         # Method tracer, biometric bypass
|   |   +-- testing-steps/         # 12-section Android checklist
|   +-- ios/
|   |   +-- ssl-pinning-bypass/    # iOS SSL bypass (NSURLSession, AFNetworking, etc.)
|   |   +-- jailbreak-detection-bypass/  # 12-section jailbreak bypass
|   |   +-- keychain-extraction/   # Full keychain dump with SecItem hooks
|   |   +-- local-storage/         # NSUserDefaults, CoreData, plist, SQLite
|   |   +-- frida-scripts/         # CCCrypt, SecKey, CryptoKit hooks
|   |   +-- testing-steps/         # 12-section iOS checklist
|   +-- setup_guide.md             # Frida/objection/Burp/ADB setup
|
+-- api/                           # API security testing payloads
|   +-- bola/                      # Broken Object Level Authorization patterns
|   +-- broken-auth/               # JWT attacks, auth bypass headers, common secrets
|   +-- bfla/                      # Broken Function Level Authorization
|   +-- mass-assignment/           # Mass assignment payloads (JSON)
|   +-- rate-limit/                # Rate limiting bypass techniques
|   +-- graphql/                   # Introspection, injection, batching
|   +-- ssrf/                      # API-specific SSRF payloads
|   +-- injection/                 # NoSQL injection payloads
|   +-- wordlists/                 # API endpoints + parameter wordlists
|   +-- testing-steps/             # API security checklist
|
+-- linux/                         # Linux OS security testing
|   +-- enumeration/               # System enumeration (OS, kernel, users, SUID, capabilities)
|   +-- privilege-escalation/      # SUID/GTFOBins, sudo CVEs, kernel exploits, capabilities, cron abuse
|   +-- persistence/               # Cron, systemd, SSH backdoors, LD_PRELOAD, shell profiles
|   +-- credential-harvesting/     # Shadow, SSH keys, history, cloud creds, memory extraction
|   +-- defense-evasion/           # Log tampering, AV evasion, firewall bypass, tunneling
|   +-- container-escape/          # Docker socket, privileged mode, cgroup escape, K8s pods
|   +-- network/                   # ARP/DNS spoofing, LLMNR poisoning, NFS, port forwarding
|   +-- testing-steps/             # Full Linux VAPT checklist
|
+-- macos/                         # macOS security testing
|   +-- enumeration/               # System enumeration (SIP, Gatekeeper, TCC, FileVault)
|   +-- privilege-escalation/      # TCC bypass, dylib hijack, sudo exploits, installer abuse
|   +-- persistence/               # LaunchAgent/Daemon, login items, cron, authorization plugins
|   +-- credential-harvesting/     # Keychain dump, browser creds, credential search
|   +-- defense-evasion/           # Gatekeeper bypass, SIP check, TCC manipulation
|   +-- network/                   # mDNS/Bonjour, AirDrop, Wi-Fi, proxy interception
|   +-- testing-steps/             # 12-section macOS VAPT checklist
|
+-- windows/                       # Windows / Active Directory security testing
|   +-- enumeration/               # Local + AD enumeration (PowerShell + CMD)
|   +-- privilege-escalation/      # UAC bypass, service exploits, token abuse, Potato attacks
|   +-- persistence/               # Registry, scheduled tasks, WMI, startup folder
|   +-- credential-harvesting/     # Mimikatz, LSASS dump, SAM extract, credential search
|   +-- defense-evasion/           # AMSI bypass, AppLocker bypass, Defender evasion, ETW patch
|   +-- active-directory/          # Kerberos attacks, BloodHound queries, AD exploitation
|   +-- lateral-movement/          # WinRM, PSExec, WMI, DCOM, Pass-the-Hash/Ticket
|   +-- network/                   # LLMNR/NTLM relay, SMB relay, Kerberoasting, IPv6
|   +-- testing-steps/             # Full Windows VAPT checklist
```

## Quick Start

### Prerequisites
- **Python 3.8+** for generator scripts
- **Thick Client**: dnSpy, Ghidra, Burp Suite, Process Monitor, Process Hacker, Frida
- **Web**: Burp Suite, browser, Python (for JWT/payload generators)
- **Mobile**: Frida, objection, adb, Burp Suite, rooted Android / jailbroken iOS
- **API**: Burp Suite, curl, Python (for JWT attacks), GraphQL clients
- **Linux**: LinPEAS, pspy, GTFOBins reference, chisel/ligolo-ng, Responder
- **macOS**: Frida, Objective-See tools, chainbreaker, Burp Suite, mitmproxy
- **Windows**: Mimikatz, Rubeus, SharpCollection, Seatbelt, winPEAS, BloodHound, Impacket

### Build a DLL Payload
```bash
# 64-bit
x86_64-w64-mingw32-gcc -shared -o payload.dll source.c -lws2_32

# 32-bit
i686-w64-mingw32-gcc -shared -o payload.dll source.c -lws2_32
```

### Run a Python Generator
```bash
# Always use -I flag (isolated mode) for safety
python -I script.py --help
```

## How Each Folder Works

Every folder in this project follows the same pattern:

```
category/
+-- README.md              # What it is, when to use it, how to test
+-- payload_file.c         # Source code (compile yourself)
+-- generator_script.py    # Generates payloads with options
+-- helper_script.ps1      # Discovery/enumeration automation
```

- **README.md** — Start here. Explains the attack vector, prerequisites, step-by-step testing, and what to document.
- **Source files** — Compile with the commands in the README.
- **Generators** — Run with `python -I` for parameterized payload creation.
- **Discovery scripts** — Run first to find what's exploitable before using payloads.

## OWASP References

| Module | Framework |
|--------|-----------|
| Thick Client | [OWASP Thick Client Top 10](https://owasp.org/www-project-thick-client-top-10/) |
| Web Application | [OWASP Top 10](https://owasp.org/www-project-top-ten/) |
| Mobile | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) |
| API | [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) |
| Windows | [MITRE ATT&CK Windows](https://attack.mitre.org/matrices/enterprise/windows/) |
| Linux | [MITRE ATT&CK Linux](https://attack.mitre.org/matrices/enterprise/linux/) |
| macOS | [MITRE ATT&CK macOS](https://attack.mitre.org/matrices/enterprise/macos/) |

## Contributing

To add a new payload category:
1. Create a folder under the appropriate module
2. Add a `README.md` following the template (see any existing folder)
3. Include source code, generators, and testing steps
4. Update the module's README and this master README

## Disclaimer

This project is intended for authorized security testing, CTF competitions, and educational purposes only. The authors are not responsible for misuse. Always obtain proper authorization before testing.

## License

MIT
