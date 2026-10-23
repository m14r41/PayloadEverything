# Linux Privilege Escalation

Enumeration scripts, exploitation tools, and references for local privilege escalation on Linux.

## Files

| File | Description |
|------|-------------|
| [`suid_exploit.sh`](suid_exploit.sh) | SUID/SGID scanner — finds SUID binaries, cross-references 40+ GTFOBins entries, shows exploitation commands |
| [`sudo_exploits.md`](sudo_exploits.md) | Sudo misconfiguration reference — CVE-2021-3156, CVE-2019-14287, LD_PRELOAD, NOPASSWD GTFOBins for 40+ binaries |
| [`capabilities_privesc.sh`](capabilities_privesc.sh) | Linux capabilities scanner — finds dangerous capabilities (CAP_SETUID, CAP_SYS_ADMIN, etc.) with exploitation commands |
| [`cron_privesc.sh`](cron_privesc.sh) | Cron exploitation — enumerate all cron sources, writable scripts, PATH hijacking, wildcard injection, process monitor |
| [`kernel_exploits.md`](kernel_exploits.md) | Kernel exploit reference — DirtyPipe, DirtyCow, PwnKit, Baron Samedit, OverlayFS, GameOver(lay) with version checks and PoCs |
| [`path_hijack.sh`](path_hijack.sh) | PATH/library hijacking — writable PATH dirs, SUID relative commands, RPATH abuse, missing shared libraries |
| [`writable_files.sh`](writable_files.sh) | Writable file scanner — /etc/passwd, shadow, sudoers, services, shared libraries, SSH dirs, cron scripts |

## MITRE ATT&CK References

| Technique | ID | Script |
|-----------|----|--------|
| Exploitation for Privilege Escalation | T1068 | `kernel_exploits.md` |
| Abuse Elevation Control Mechanism: Sudo | T1548.003 | `sudo_exploits.md` |
| Setuid and Setgid | T1548.001 | `suid_exploit.sh` |
| Hijack Execution Flow: PATH | T1574.007 | `path_hijack.sh` |
| Hijack Execution Flow: LD_PRELOAD | T1574.006 | `path_hijack.sh`, `sudo_exploits.md` |
| Scheduled Task/Job: Cron | T1053.003 | `cron_privesc.sh` |
| File and Directory Permissions Modification | T1222.002 | `writable_files.sh` |

## Quick Start

```bash
# Full SUID scan with GTFOBins cross-reference
chmod +x suid_exploit.sh && ./suid_exploit.sh

# Check sudo misconfigs
sudo -l
# Then reference sudo_exploits.md for exploitation

# Capabilities scan
chmod +x capabilities_privesc.sh && ./capabilities_privesc.sh

# Cron enumeration + 2-minute process monitor
chmod +x cron_privesc.sh && ./cron_privesc.sh --monitor

# Writable critical files
chmod +x writable_files.sh && ./writable_files.sh
```
