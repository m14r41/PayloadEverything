# Linux Security Testing

Payloads, scripts, and references for Linux OS-level vulnerability assessment and penetration testing.

## Structure

| Folder | Description |
|--------|-------------|
| [`enumeration/`](enumeration/) | System enumeration — OS, kernel, users, sudo, SUID, capabilities, cron, writable dirs, processes, network, SSH, containers |
| [`privilege-escalation/`](privilege-escalation/) | Privilege escalation — SUID/GTFOBins, sudo CVEs, capabilities, cron abuse, kernel exploits, PATH hijacking, writable files |
| [`persistence/`](persistence/) | Persistence mechanisms — cron, systemd services/timers, SSH backdoors, LD_PRELOAD, shell profile modification |
| [`credential-harvesting/`](credential-harvesting/) | Credential harvesting — shadow, SSH keys, history, database configs, .env, cloud CLI creds, Docker, memory extraction |
| [`container-escape/`](container-escape/) | Container escape — Docker socket, privileged mode, capabilities, cgroup escape, Kubernetes pod escape |
| [`defense-evasion/`](defense-evasion/) | Defense evasion — log tampering, AV/EDR evasion, fileless execution, firewall bypass, DNS/ICMP/HTTP tunneling |
| [`network/`](network/) | Network attacks — ARP/DNS spoofing, LLMNR/NBT-NS poisoning, SSH MitM, SSL stripping, NFS, Redis, port forwarding, tunneling |
| [`testing-steps/`](testing-steps/) | Testing checklist — full Linux VAPT assessment workflow |

## MITRE ATT&CK Mapping

| Technique | ID | Covered In |
|-----------|----|------------|
| System Information Discovery | T1082 | enumeration |
| Permission Groups Discovery | T1069 | enumeration |
| Abuse Elevation Control | T1548 | privilege-escalation |
| Exploitation for Privilege Escalation | T1068 | privilege-escalation |
| Scheduled Task/Job: Cron | T1053.003 | privilege-escalation, persistence |
| Create or Modify System Process | T1543 | persistence |
| Account Manipulation: SSH Keys | T1098.004 | persistence |
| Hijack Execution Flow: LD_PRELOAD | T1574.006 | persistence |
| Credentials from Password Stores | T1555 | credential-harvesting |
| Unsecured Credentials | T1552 | credential-harvesting |
| OS Credential Dumping: /etc/passwd | T1003.008 | credential-harvesting |
| Escape to Host | T1611 | container-escape |
| Indicator Removal | T1070 | defense-evasion |
| Impair Defenses | T1562 | defense-evasion |
| Protocol Tunneling | T1572 | defense-evasion |
| Man-in-the-Middle | T1557 | network |
| Network Sniffing | T1040 | network |

## Quick Start

```bash
# 1. Enumerate the system
chmod +x enumeration/linux_enum.sh
./enumeration/linux_enum.sh

# 2. Check for quick privilege escalation wins
chmod +x privilege-escalation/suid_exploit.sh
./privilege-escalation/suid_exploit.sh --scan

chmod +x privilege-escalation/capabilities_privesc.sh
./privilege-escalation/capabilities_privesc.sh

chmod +x privilege-escalation/cron_privesc.sh
./privilege-escalation/cron_privesc.sh

# 3. Hunt for credentials
chmod +x credential-harvesting/credential_hunt.sh
./credential-harvesting/credential_hunt.sh

# 4. If in a container, assess escape potential
chmod +x container-escape/docker_escape.sh
./container-escape/docker_escape.sh
```

## Tools Reference

| Tool | Purpose |
|------|---------|
| [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) | Automated Linux privilege escalation enumeration |
| [pspy](https://github.com/DominicBreuker/pspy) | Process monitoring without root |
| [GTFOBins](https://gtfobins.github.io/) | Unix binaries that can be exploited for privilege escalation |
| [Responder](https://github.com/lgandx/Responder) | LLMNR/NBT-NS/mDNS poisoner |
| [chisel](https://github.com/jpillora/chisel) | TCP/UDP tunnel over HTTP |
| [ligolo-ng](https://github.com/nicocha30/ligolo-ng) | Advanced tunneling framework |
| [CDK](https://github.com/cdk-team/CDK) | Container penetration toolkit |
