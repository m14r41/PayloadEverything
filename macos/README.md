# macOS Security Payloads

> **Status**: Active

Payloads, scripts, and testing methodology for macOS security assessments, mapped to the [MITRE ATT&CK macOS Matrix](https://attack.mitre.org/matrices/enterprise/macos/).

## Directory Structure

| Folder | File | Description |
|--------|------|-------------|
| [enumeration/](enumeration/) | [`macos_enum.sh`](enumeration/macos_enum.sh) | Full system enumeration — SIP, Gatekeeper, FileVault, users, TCC, LaunchAgents, keychains, SSH, network, processes, MDM |
| | [`tcc_enum.sh`](enumeration/tcc_enum.sh) | TCC database enumeration — FDA, camera, mic, screen recording, accessibility grants, bypass opportunities |
| [privilege-escalation/](privilege-escalation/) | [`tcc_bypass.md`](privilege-escalation/tcc_bypass.md) | TCC bypass — terminal inheritance, Finder automation, direct DB modification, MDM profiles, CVE-based bypasses |
| | [`dylib_hijack.md`](privilege-escalation/dylib_hijack.md) | dylib hijacking — @rpath, DYLD_INSERT_LIBRARIES, Electron apps, framework hijacking |
| | [`sudo_exploits.md`](privilege-escalation/sudo_exploits.md) | sudo exploitation — NOPASSWD, timestamp abuse, GTFOBins for macOS, authorization database |
| | [`installer_abuse.md`](privilege-escalation/installer_abuse.md) | Package installer exploitation — malicious .pkg, productbuild, preinstall/postinstall scripts |
| [persistence/](persistence/) | [`launch_agent_persist.sh`](persistence/launch_agent_persist.sh) | LaunchAgent/LaunchDaemon persistence — 5 trigger types, stealthy labels, install/remove/list |
| | [`login_items.md`](persistence/login_items.md) | Login Items — AppleScript, SMLoginItem, Login Hook, Folder Actions, shell profiles |
| | [`cron_persistence.sh`](persistence/cron_persistence.sh) | Cron/periodic/at persistence — crontab, periodic scripts, at jobs |
| | [`authorization_plugin.md`](persistence/authorization_plugin.md) | Authorization plugin — runs as root at login, high stealth, Objective-C template |
| [credential-harvesting/](credential-harvesting/) | [`keychain_dump.sh`](credential-harvesting/keychain_dump.sh) | Keychain extraction — metadata dump, passwords, Wi-Fi, certificates, offline analysis |
| | [`browser_creds.md`](credential-harvesting/browser_creds.md) | Browser credentials — Safari, Chrome, Firefox, Brave, Edge locations + Chrome decryption script |
| | [`credential_search.sh`](credential-harvesting/credential_search.sh) | Credential hunting — shell history, SSH keys, cloud creds, .env, git, Docker, npm, databases |
| [defense-evasion/](defense-evasion/) | [`gatekeeper_bypass.md`](defense-evasion/gatekeeper_bypass.md) | Gatekeeper bypass — quarantine removal, no-quarantine downloads, CLI execution, ad-hoc signing |
| | [`sip_check.sh`](defense-evasion/sip_check.sh) | SIP assessment — status, protected paths, kext policy, NVRAM, AMFI, debugging restrictions |
| | [`tcc_manipulation.md`](defense-evasion/tcc_manipulation.md) | TCC manipulation — fake dialogs, direct DB writes, MDM profiles, synthetic events |
| [network/](network/) | [`network_attacks.md`](network/network_attacks.md) | Network attacks — mDNS/Bonjour, AirDrop, Wi-Fi, Bluetooth, DNS spoofing, LLMNR, Handoff |
| | [`proxy_intercept.md`](network/proxy_intercept.md) | Traffic interception — Burp/mitmproxy, system proxy, pfctl, Proxifier, cert pinning bypass |
| [testing-steps/](testing-steps/) | [`macos_checklist.md`](testing-steps/macos_checklist.md) | 12-section VAPT checklist with commands for every category |

## MITRE ATT&CK Mapping

| Technique | ID | Folder |
|-----------|----|--------|
| Dylib Hijacking | T1574.004 | [privilege-escalation/](privilege-escalation/) |
| Abuse Elevation Control | T1548 | [privilege-escalation/](privilege-escalation/) |
| Launch Agent / Daemon | T1543.001/004 | [persistence/](persistence/) |
| Login Items | T1547.015 | [persistence/](persistence/) |
| Scheduled Task (Cron) | T1053.003 | [persistence/](persistence/) |
| Gatekeeper Bypass | T1553.001 | [defense-evasion/](defense-evasion/) |
| Disable or Modify Tools | T1562.001 | [defense-evasion/](defense-evasion/) |
| Keychain | T1555.001 | [credential-harvesting/](credential-harvesting/) |
| Credentials from Browsers | T1555.003 | [credential-harvesting/](credential-harvesting/) |
| mDNS/DNS Poisoning | T1557 | [network/](network/) |
| Installer Packages | T1546.016 | [privilege-escalation/](privilege-escalation/) |

## Quick Start

```bash
# System enumeration
chmod +x enumeration/macos_enum.sh enumeration/tcc_enum.sh
./enumeration/macos_enum.sh
./enumeration/tcc_enum.sh

# Privilege escalation check
sudo -l
csrutil status

# Credential hunt
chmod +x credential-harvesting/keychain_dump.sh credential-harvesting/credential_search.sh
./credential-harvesting/keychain_dump.sh dump-metadata
./credential-harvesting/credential_search.sh

# Persistence install (user-level)
chmod +x persistence/launch_agent_persist.sh
./persistence/launch_agent_persist.sh install-agent
```

## Tools

| Tool | Purpose |
|------|---------|
| Frida | Dynamic instrumentation / SSL bypass |
| Burp Suite / mitmproxy | Traffic interception |
| Responder | mDNS/LLMNR poisoning |
| chainbreaker | Offline keychain analysis |
| LaZagne | Multi-source credential extraction |
| Wireshark | Packet capture |
| Process Monitor (procmon for macOS) | File/network/process monitoring |
| Objective-See tools | macOS-specific security tools |

## Prerequisites

- **Python 3.8+** for scripts and tools
- **Frida** (`pip3 install frida-tools`)
- **Homebrew** recommended for tool installation
- **Xcode CLI tools** (`xcode-select --install`)
- Root/admin access for system-level assessments
