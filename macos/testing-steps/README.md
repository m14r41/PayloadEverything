# macOS Testing Steps

Comprehensive VAPT methodology and checklist for macOS assessments.

## Files

| File | Description |
|------|-------------|
| [`macos_checklist.md`](macos_checklist.md) | 12-section checklist — system config (SIP/Gatekeeper/FileVault/Firewall), users, TCC/privacy, privilege escalation, persistence, credentials, network, app security, MDM, defense evasion, logging, evidence collection |

## Checklist Sections

| # | Section | Maps To |
|---|---------|---------|
| 1 | System Configuration | [`defense-evasion/sip_check.sh`](../defense-evasion/sip_check.sh) |
| 2 | User Enumeration | [`enumeration/macos_enum.sh`](../enumeration/macos_enum.sh) |
| 3 | TCC and Privacy | [`enumeration/tcc_enum.sh`](../enumeration/tcc_enum.sh) |
| 4 | Privilege Escalation | [`privilege-escalation/`](../privilege-escalation/) |
| 5 | Persistence Mechanisms | [`persistence/`](../persistence/) |
| 6 | Credential Storage | [`credential-harvesting/`](../credential-harvesting/) |
| 7 | Network Security | [`network/`](../network/) |
| 8 | Application Security | [`defense-evasion/gatekeeper_bypass.md`](../defense-evasion/gatekeeper_bypass.md) |
| 9 | MDM / Configuration Profiles | [`enumeration/macos_enum.sh`](../enumeration/macos_enum.sh) |
| 10 | Defense Evasion | [`defense-evasion/`](../defense-evasion/) |
| 11 | Logging and Monitoring | [`testing-steps/macos_checklist.md`](macos_checklist.md) |
| 12 | Evidence Collection | [`testing-steps/macos_checklist.md`](macos_checklist.md) |
