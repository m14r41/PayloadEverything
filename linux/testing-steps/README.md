# Linux Testing Steps

Comprehensive security assessment checklist for Linux systems.

## Files

| File | Description |
|------|-------------|
| [`linux_checklist.md`](linux_checklist.md) | Full Linux VAPT checklist — system info, users, sudo/SUID/capabilities, cron, services, network, file permissions, credentials, containers, logs, persistence, evidence collection |

## Usage

Use the checklist during engagements to ensure full coverage:

1. Work through each section systematically
2. Check off items as you complete them
3. Record findings with commands and output
4. Cross-reference with scripts in other folders for exploitation

## Related Scripts

| Folder | Scripts |
|--------|---------|
| `../enumeration/` | `linux_enum.sh` — automated system enumeration |
| `../privilege-escalation/` | SUID, sudo, capabilities, cron, kernel, PATH, writable file scripts |
| `../persistence/` | Cron, systemd, SSH, LD_PRELOAD, bashrc persistence scripts |
| `../credential-harvesting/` | `credential_hunt.sh`, `memory_creds.sh` |
| `../container-escape/` | `docker_escape.sh`, `container_breakout.md` |
| `../network/` | `network_attacks.md`, `port_forward.md` |
