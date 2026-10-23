# Insecure Storage — Credential Extraction

Find and extract credentials stored insecurely by desktop applications.

**OWASP**: TC2 — Improper Credential Storage  
**Severity**: CRITICAL

## Files

| File | Description |
|------|-------------|
| [`extract_credentials.ps1`](extract_credentials.ps1) | Automated scanner — checks config files, registry, SQLite databases, binary strings, DPAPI blobs, Windows Credential Manager |
| [`dpapi_decrypt.ps1`](dpapi_decrypt.ps1) | DPAPI decryption helper — decrypts blobs protected with `CryptProtectData` (same-user context) |
| [`token_extractor.ps1`](token_extractor.ps1) | Extract OAuth/JWT/session tokens from config files, Electron LevelDB/IndexedDB, .NET user.config, Java prefs, registry |
| [`windows_credential_dump.ps1`](windows_credential_dump.ps1) | Dump Windows Credential Manager (API + cmdkey), saved RDP creds, Wi-Fi passwords, browser password DB locations |

## Usage

```powershell
# Full automated scan
.\extract_credentials.ps1 -AppPath "C:\Program Files\TargetApp" -AppName "TargetApp"

# Decrypt a specific DPAPI blob
.\dpapi_decrypt.ps1 -FilePath "C:\Users\user\AppData\Local\App\cred.dat"
.\dpapi_decrypt.ps1 -Base64 "AQAAAA..."
.\dpapi_decrypt.ps1 -RegistryPath "HKCU:\Software\App" -ValueName "Password"
```

## What the Scanner Checks

1. **Config files** — Scans `.config`, `.xml`, `.json`, `.ini`, `.yaml` for password/token/connectionstring patterns
2. **Registry** — Walks HKCU/HKLM keys for the app, checks for sensitive value names and base64 values
3. **SQLite databases** — Finds `.sqlite`/`.db`/`.sdf` files in the app directory
4. **Binary strings** — Searches `.exe`/`.dll` for hardcoded connection strings, API keys, JWTs
5. **DPAPI** — Locates DPAPI-encrypted blobs in AppData (decryptable as same user = insecure)
6. **Credential Manager** — Checks `cmdkey /list` for app-related entries

## Why DPAPI is Not Secure Storage

DPAPI with `CurrentUser` scope means **any process running as that user can decrypt the data**. A malware or attacker with user-level access decrypts everything. The finding is HIGH/CRITICAL unless additional entropy is used.
