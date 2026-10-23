# Windows Active Directory Attacks

Comprehensive Active Directory attack reference for authorized penetration testing.

> **MITRE ATT&CK**: T1558, T1003.006, T1222, T1484, T1187, T1087.002

## Files

| File | Description |
|------|-------------|
| [`kerberos_attacks.md`](kerberos_attacks.md) | Kerberos attacks — Kerberoasting, AS-REP Roasting, Golden/Silver/Diamond tickets, Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, Unconstrained/Constrained/RBCD delegation abuse (T1558) |
| [`ad_attacks.ps1`](ad_attacks.ps1) | AD attack automation — DCSync rights discovery, ACL abuse (GenericAll, WriteDacl, ForceChangePassword), GPO abuse, LAPS password extraction, coercion attacks (PrinterBug, PetitPotam), trust exploitation, Shadow Credentials (T1003.006, T1222, T1484) |
| [`bloodhound_queries.md`](bloodhound_queries.md) | Custom BloodHound Cypher queries — DA paths, Kerberoasting targets, delegation, ACL abuse chains, credential paths, GPO abuse, trust enumeration, post-compromise situational awareness (T1087.002) |

## Quick Start

```powershell
# Load AD attack functions
. .\ad_attacks.ps1

# Find DCSync-capable principals
Find-DCsyncRights

# Find exploitable ACLs
Find-InterestingACLs

# Read LAPS passwords
Get-LAPSPasswords
```
