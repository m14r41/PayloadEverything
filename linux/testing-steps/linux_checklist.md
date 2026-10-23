# Linux Security Assessment Checklist

## 1. System Information

```bash
uname -a                           # Kernel version
cat /etc/os-release                # OS distribution
cat /proc/version                  # Kernel build info
hostnamectl                        # Full system info
uptime                             # System uptime
```

- [ ] Record kernel version — check for DirtyPipe, DirtyCow, PwnKit, OverlayFS
- [ ] Record distro version — check for distro-specific CVEs
- [ ] Check if SELinux/AppArmor is enforcing: `getenforce`, `aa-status`

## 2. User Enumeration

```bash
id                                 # Current user context
whoami && groups                   # User and group memberships
cat /etc/passwd                    # All users
awk -F: '$3 == 0 {print}' /etc/passwd  # UID 0 accounts
getent group sudo                  # Sudo group members
getent group wheel                 # Wheel group members
last -a | head -20                 # Recent logins
w                                  # Currently logged in
```

- [ ] Identify all users with shell access
- [ ] Check for multiple UID 0 accounts
- [ ] Check /etc/shadow readability: `ls -la /etc/shadow`
- [ ] Test if /etc/passwd is writable

## 3. Sudo / SUID / Capabilities

```bash
# Sudo
sudo -l                            # Current user's sudo rights
sudo -V | head -1                  # Sudo version (CVE checks)
cat /etc/sudoers 2>/dev/null       # Sudoers config

# SUID/SGID
find / -perm -4000 -type f 2>/dev/null   # SUID binaries
find / -perm -2000 -type f 2>/dev/null   # SGID binaries

# Capabilities
getcap -r / 2>/dev/null            # All binaries with capabilities
```

- [ ] Check sudo -l for NOPASSWD entries
- [ ] Check sudo version for CVE-2021-3156 (< 1.9.5p2), CVE-2019-14287 (< 1.8.28)
- [ ] Cross-reference SUID binaries with GTFOBins
- [ ] Check for custom/unusual SUID binaries outside /usr
- [ ] Look for dangerous capabilities: CAP_SETUID, CAP_SYS_ADMIN, CAP_DAC_OVERRIDE

## 4. Cron / Scheduled Tasks

```bash
crontab -l                         # User crontab
cat /etc/crontab                   # System crontab
ls -la /etc/cron.d/                # Drop-in crons
ls -la /etc/cron.{hourly,daily,weekly,monthly}/
cat /var/spool/cron/crontabs/*     # All user crontabs
systemctl list-timers --all        # Systemd timers
atq                                # At jobs
```

- [ ] Check for writable cron scripts
- [ ] Check crontab PATH for hijackable directories
- [ ] Look for wildcard usage in cron commands (tar, rsync, chown)
- [ ] Monitor processes for hidden cron jobs: use pspy or `./cron_privesc.sh --monitor`

## 5. Service Enumeration

```bash
systemctl list-units --type=service --state=running
ss -tlnp                           # Listening TCP services
ss -ulnp                           # Listening UDP services
ps auxf                            # Process tree
```

- [ ] Identify services running as root
- [ ] Check for unquoted service paths
- [ ] Check service binary/directory permissions
- [ ] Look for services with writable configs

## 6. Network Services

```bash
ss -tlnp                           # All listening services
ip a                               # Network interfaces
ip route                           # Routing table
cat /etc/resolv.conf               # DNS config
iptables -L -n                     # Firewall rules
cat /etc/hosts                     # Host file entries
```

- [ ] Test internal services (databases, caches, APIs) for default/no credentials
- [ ] Check for NFS exports with `no_root_squash`: `showmount -e`, `cat /etc/exports`
- [ ] Check Redis (6379), memcached (11211), MongoDB (27017) for no-auth access
- [ ] Look for SNMP with default community strings
- [ ] Check for rsync open modules

## 7. File Permissions

```bash
# Critical file permissions
ls -la /etc/passwd /etc/shadow /etc/sudoers
find / -writable -type f 2>/dev/null | grep -vE '/proc|/sys|/dev|/tmp'
find / -writable -type d 2>/dev/null | grep -vE '/proc|/sys|/dev|/tmp'

# Writable PATH directories
echo $PATH | tr ':' '\n' | while read d; do [ -w "$d" ] && echo "WRITABLE: $d"; done

# SUID in writable directories
find / -perm -4000 -type f -exec sh -c 'dir=$(dirname "{}"); [ -w "$dir" ] && echo "SUID in writable dir: {}"' \; 2>/dev/null
```

- [ ] Check /etc/passwd, /etc/shadow, /etc/sudoers for write access
- [ ] Check for writable shared libraries
- [ ] Check for writable systemd service files
- [ ] Check writable PATH directories

## 8. Credential Storage

```bash
# Shell history
find /home /root -name '.*history' -readable 2>/dev/null -exec grep -liE 'password|passwd|secret|token' {} \;

# Config files
grep -rlsiE 'password|passwd|secret|api_key|token' /etc/ /opt/ /var/www/ 2>/dev/null | head -20

# SSH keys
find / -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null

# Cloud credentials
cat ~/.aws/credentials ~/.config/gcloud/application_default_credentials.json ~/.azure/accessTokens.json 2>/dev/null

# .env files
find / -name '.env' -readable 2>/dev/null | grep -v proc
```

- [ ] Check history files for passwords in commands
- [ ] Search for database config files with credentials
- [ ] Look for SSH private keys with weak permissions
- [ ] Check for cloud CLI credentials (AWS, GCP, Azure)
- [ ] Search for .env files with secrets
- [ ] Check Docker config for registry auth: `~/.docker/config.json`
- [ ] Look for KeePass databases: `find / -name '*.kdbx'`

## 9. Container Security

```bash
# Detection
[ -f /.dockerenv ] && echo "Docker container"
grep -qE 'docker|lxc|kubepods' /proc/1/cgroup && echo "Container cgroup"
ls -la /var/run/docker.sock        # Docker socket

# Container capabilities
cat /proc/self/status | grep Cap
```

- [ ] Check if inside a container
- [ ] Check for mounted Docker socket
- [ ] Check if container is privileged
- [ ] Check for dangerous capabilities (CAP_SYS_ADMIN, CAP_SYS_PTRACE)
- [ ] Check for host filesystem mounts
- [ ] Check Kubernetes service account token permissions

## 10. Log Analysis

```bash
cat /var/log/auth.log | tail -50       # Authentication logs
cat /var/log/syslog | tail -50         # System logs
journalctl -xe                         # Systemd journal
cat /var/log/apache2/error.log         # Web server errors
dmesg | tail -30                       # Kernel messages
```

- [ ] Check auth.log for failed login patterns
- [ ] Look for log rotation configuration weaknesses
- [ ] Check if logs are writable (log poisoning potential)

## 11. Persistence Review

```bash
# Check all persistence locations
crontab -l                             # User cron
cat /etc/crontab /etc/cron.d/*         # System cron
systemctl list-unit-files --type=service | grep enabled
cat /etc/profile /etc/bash.bashrc      # System-wide shell init
cat ~/.bashrc ~/.bash_profile ~/.profile # User shell init
cat /etc/ld.so.preload                 # Preloaded libraries
ls /etc/profile.d/                     # Profile drop-ins
```

- [ ] Review user and system crontabs for suspicious entries
- [ ] Check enabled systemd services for non-standard ones
- [ ] Inspect shell profile files for backdoors
- [ ] Check /etc/ld.so.preload for loaded libraries
- [ ] Check /etc/profile.d/ for suspicious scripts
- [ ] Look for SSH authorized_keys modifications

## 12. Evidence Collection

```bash
# Capture system state
date > /tmp/evidence_$(hostname).txt
id >> /tmp/evidence.txt
uname -a >> /tmp/evidence.txt
ip a >> /tmp/evidence.txt
ps auxf >> /tmp/evidence.txt
ss -tlnp >> /tmp/evidence.txt

# Screenshot terminal output
script /tmp/session_capture.txt   # records all terminal I/O
```

- [ ] Document each finding with: command used, output, severity, CVSS
- [ ] Save proof-of-concept output
- [ ] Record timestamps for all activities
- [ ] Collect hashes/credentials found (store securely)
- [ ] Note any changes made to the system
