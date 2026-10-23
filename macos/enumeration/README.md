# macOS Enumeration

Comprehensive system and security configuration enumeration for macOS targets.

## Files

| File | Description |
|------|-------------|
| [`macos_enum.sh`](macos_enum.sh) | Full system enumeration — SIP, Gatekeeper, FileVault, Firewall, users, TCC, LaunchAgents/Daemons, keychains, SSH keys, network, processes, ports, kexts, MDM, cron |
| [`tcc_enum.sh`](tcc_enum.sh) | TCC database enumeration — Full Disk Access, camera, microphone, screen recording, accessibility, automation grants, bypass opportunity identification |

## Quick Start

```bash
chmod +x macos_enum.sh tcc_enum.sh

# Full system enumeration (outputs to timestamped directory)
./macos_enum.sh

# TCC-focused enumeration
./tcc_enum.sh

# Run with sudo for additional findings
sudo ./macos_enum.sh
```
