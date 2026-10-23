# Linux Credential Harvesting

Automated tools for finding credentials, tokens, and secrets on Linux hosts.

## Files

| File | Description |
|------|-------------|
| [`credential_hunt.sh`](credential_hunt.sh) | Automated credential search — shadow file, SSH keys, history, MySQL/PostgreSQL/Redis/MongoDB configs, .env files, git creds, AWS/GCP/Azure CLI, Docker, KeePass, process environments |
| [`memory_creds.sh`](memory_creds.sh) | Memory credential extraction — /proc/PID/mem strings, gdb dumps, swap analysis, core dumps, process environment scanning |

## Quick Start

```bash
# Full credential hunt (saves to file)
chmod +x credential_hunt.sh
./credential_hunt.sh /tmp/creds.txt

# Scan specific process memory
chmod +x memory_creds.sh
./memory_creds.sh --scan apache2
./memory_creds.sh --scan mysql

# Dump process memory for offline analysis
./memory_creds.sh --dump <PID>

# Search swap for passwords
./memory_creds.sh --swap

# Scan all process environments
./memory_creds.sh --environ
```
