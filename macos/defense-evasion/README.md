# macOS Defense Evasion

Techniques to bypass macOS security controls: Gatekeeper, SIP, TCC, and code signing.

**MITRE ATT&CK**: T1553.001 (Gatekeeper), T1562.001 (Disable Security Tools)

## Files

| File | Description |
|------|-------------|
| [`gatekeeper_bypass.md`](gatekeeper_bypass.md) | Gatekeeper bypass — quarantine removal, download without quarantine (curl/wget/git), CLI execution, ad-hoc signing, DMG mounting, Safari auto-open |
| [`sip_check.sh`](sip_check.sh) | SIP assessment — status check, protected paths, writable paths, kext policy, NVRAM boot-args, AMFI, debugging restrictions |
| [`tcc_manipulation.md`](tcc_manipulation.md) | TCC manipulation — fake permission dialogs, direct TCC.db modification, MDM profiles, AppleScript inheritance, synthetic events, reset commands |

## Quick Start

```bash
chmod +x sip_check.sh

# Full SIP assessment
./sip_check.sh

# Quick Gatekeeper check
spctl --status
xattr -l /path/to/downloaded/file

# Check TCC grants
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
    "SELECT service, client, auth_value FROM access WHERE auth_value=2;"
```
