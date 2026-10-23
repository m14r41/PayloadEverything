#!/bin/bash
# Linux Enumeration Script for VAPT
# Usage: chmod +x linux_enum.sh && ./linux_enum.sh [output_file]

OUTPUT="${1:-/tmp/linux_enum_$(date +%Y%m%d_%H%M%S).txt}"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

header() { echo -e "\n${GREEN}=== $1 ===${NC}"; echo -e "\n=== $1 ===" >> "$OUTPUT"; }
finding() { echo -e "${RED}[!] $1${NC}"; echo "[!] $1" >> "$OUTPUT"; }
info() { echo -e "${YELLOW}[*] $1${NC}"; echo "[*] $1" >> "$OUTPUT"; }

run() {
    echo -e "\n--- $1 ---" >> "$OUTPUT"
    eval "$2" 2>/dev/null >> "$OUTPUT"
}

echo "Linux Enumeration — $(date)" | tee "$OUTPUT"
echo "Output: $OUTPUT"

# ── OS / Kernel ──
header "OS & Kernel Information"
run "Hostname" "hostname -f 2>/dev/null || hostname"
run "OS Release" "cat /etc/os-release 2>/dev/null || cat /etc/*-release 2>/dev/null"
run "Kernel" "uname -a"
run "Kernel Version" "cat /proc/version"
run "Architecture" "uname -m"
run "Uptime" "uptime"

KERNEL=$(uname -r)
info "Kernel: $KERNEL — check for DirtyPipe (< 5.16.11), DirtyCow (< 4.8.3), PwnKit, OverlayFS"

# ── Users & Groups ──
header "Users & Groups"
run "Current User" "id"
run "Who" "w 2>/dev/null; who 2>/dev/null"
run "Last Logins" "last -a 2>/dev/null | head -20"
run "Users with Shell" "grep -v '/nologin\|/false' /etc/passwd"
run "Users with UID 0" "awk -F: '\$3 == 0 {print}' /etc/passwd"
run "Groups" "cat /etc/group"
run "Sudo Group Members" "getent group sudo 2>/dev/null; getent group wheel 2>/dev/null"
run "Password File Permissions" "ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null"

if [ -r /etc/shadow ]; then
    finding "/etc/shadow is READABLE by current user"
    run "Shadow File" "cat /etc/shadow"
fi

# ── Sudo ──
header "Sudo Configuration"
run "Sudo Version" "sudo -V 2>/dev/null | head -1"
run "Sudo -l" "sudo -l 2>/dev/null"
run "Sudoers (if readable)" "cat /etc/sudoers 2>/dev/null"
run "Sudoers.d" "ls -la /etc/sudoers.d/ 2>/dev/null; cat /etc/sudoers.d/* 2>/dev/null"

SUDO_VER=$(sudo -V 2>/dev/null | head -1 | grep -oP '[\d.]+')
if [ -n "$SUDO_VER" ]; then
    info "Sudo version: $SUDO_VER — check CVE-2021-3156 (< 1.9.5p2), CVE-2019-14287 (< 1.8.28)"
fi

# ── SUID / SGID ──
header "SUID / SGID Binaries"
run "SUID Files" "find / -perm -4000 -type f 2>/dev/null"
run "SGID Files" "find / -perm -2000 -type f 2>/dev/null"

SUID_BINS=$(find / -perm -4000 -type f 2>/dev/null)
GTFO_LIST="nmap vim find bash python python3 perl ruby less more nano cp mv wget curl nc netcat socat php node lua awk gdb env strace ltrace docker"
for bin in $GTFO_LIST; do
    if echo "$SUID_BINS" | grep -qw "$bin"; then
        finding "SUID binary found: $(echo "$SUID_BINS" | grep -w "$bin") — check GTFOBins"
    fi
done

# ── Capabilities ──
header "Linux Capabilities"
run "Binaries with Capabilities" "getcap -r / 2>/dev/null"

DANGEROUS_CAPS="cap_setuid cap_setgid cap_dac_override cap_dac_read_search cap_sys_admin cap_sys_ptrace cap_net_raw cap_chown cap_fowner"
for cap in $DANGEROUS_CAPS; do
    FOUND=$(getcap -r / 2>/dev/null | grep -i "$cap")
    if [ -n "$FOUND" ]; then
        finding "Dangerous capability: $FOUND"
    fi
done

# ── Cron Jobs ──
header "Cron Jobs & Scheduled Tasks"
run "User Crontab" "crontab -l 2>/dev/null"
run "System Crontab" "cat /etc/crontab 2>/dev/null"
run "Cron Directories" "ls -la /etc/cron* 2>/dev/null"
run "Cron.d" "cat /etc/cron.d/* 2>/dev/null"
run "Spool Crons" "ls -la /var/spool/cron/crontabs/ 2>/dev/null"
run "Systemd Timers" "systemctl list-timers --all 2>/dev/null"
run "At Jobs" "atq 2>/dev/null"

for f in $(grep -rlsE '^[^#]' /etc/crontab /etc/cron.d/ /var/spool/cron/ 2>/dev/null | sort -u); do
    SCRIPTS=$(grep -oP '/\S+' "$f" 2>/dev/null)
    for s in $SCRIPTS; do
        if [ -f "$s" ] && [ -w "$s" ]; then
            finding "Writable cron script: $s (from $f)"
        fi
    done
done

# ── Writable Directories & Files ──
header "Writable Locations"
run "World-Writable Dirs" "find / -writable -type d 2>/dev/null | grep -v proc | head -30"
run "World-Writable Files" "find / -writable -type f 2>/dev/null | grep -vE '/proc|/sys|/dev' | head -30"
run "Writable /etc Files" "find /etc -writable -type f 2>/dev/null"

for f in /etc/passwd /etc/shadow /etc/sudoers /etc/crontab; do
    if [ -w "$f" ]; then
        finding "WRITABLE: $f"
    fi
done

# ── Running Processes ──
header "Running Processes"
run "All Processes" "ps auxf 2>/dev/null || ps aux"
run "Processes as Root" "ps aux | grep '^root' | head -20"
run "Listening Services" "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"

# ── Network ──
header "Network Configuration"
run "Interfaces" "ip a 2>/dev/null || ifconfig 2>/dev/null"
run "Routes" "ip route 2>/dev/null || route -n 2>/dev/null"
run "DNS" "cat /etc/resolv.conf"
run "ARP Table" "ip neigh 2>/dev/null || arp -a 2>/dev/null"
run "Active Connections" "ss -anp 2>/dev/null || netstat -anp 2>/dev/null"
run "Iptables Rules" "iptables -L -n 2>/dev/null"
run "NFS Exports" "cat /etc/exports 2>/dev/null"
run "NFS Shares" "showmount -e localhost 2>/dev/null"

if grep -q "no_root_squash" /etc/exports 2>/dev/null; then
    finding "NFS export with no_root_squash found"
fi

# ── SSH ──
header "SSH Configuration"
run "SSH Config" "cat /etc/ssh/sshd_config 2>/dev/null | grep -vE '^#|^$'"
run "SSH Keys (current user)" "ls -la ~/.ssh/ 2>/dev/null; cat ~/.ssh/authorized_keys 2>/dev/null"
run "SSH Keys (all users)" "find /home -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null"
run "SSH Known Hosts" "cat ~/.ssh/known_hosts 2>/dev/null | head -10"
run "SSH Agent" "ssh-add -l 2>/dev/null"

PRIV_KEYS=$(find / -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null | grep -v '/proc')
if [ -n "$PRIV_KEYS" ]; then
    finding "Private keys found: $PRIV_KEYS"
fi

# ── Sensitive Files ──
header "Sensitive Files & Credentials"
run "History Files" "find /home /root -name '.*history' -exec ls -la {} \; 2>/dev/null"
run "Config Files with Passwords" "grep -rlsiE 'password|passwd|pwd|secret|api_key|token|credential' /etc/ /opt/ /var/www/ 2>/dev/null | head -20"
run "Env Files" "find / -name '.env' -o -name '.env.local' -o -name '.env.production' 2>/dev/null | grep -v proc"
run "Database Configs" "find / -name 'wp-config.php' -o -name 'settings.py' -o -name 'database.yml' -o -name 'db.php' -o -name 'config.php' 2>/dev/null | head -10"
run "Backup Files" "find / -name '*.bak' -o -name '*.old' -o -name '*.backup' -o -name '*~' 2>/dev/null | grep -vE '/proc|/sys' | head -20"
run "AWS Credentials" "cat ~/.aws/credentials 2>/dev/null; cat ~/.aws/config 2>/dev/null"
run "GCP Credentials" "cat ~/.config/gcloud/credentials.db 2>/dev/null; ls ~/.config/gcloud/ 2>/dev/null"
run "Azure Credentials" "cat ~/.azure/accessTokens.json 2>/dev/null"
run "Docker Config" "cat ~/.docker/config.json 2>/dev/null"
run "Git Credentials" "find / -name '.git-credentials' 2>/dev/null; git config --global --list 2>/dev/null"
run "KeePass Databases" "find / -name '*.kdbx' 2>/dev/null"

# ── Installed Software ──
header "Installed Software"
run "Package Manager" "which apt dpkg yum rpm pacman 2>/dev/null"
run "Installed Packages (dpkg)" "dpkg -l 2>/dev/null | tail -30"
run "Installed Packages (rpm)" "rpm -qa 2>/dev/null | tail -30"
run "Compilers" "which gcc cc g++ make 2>/dev/null"
run "Interpreters" "which python python3 perl ruby php node 2>/dev/null"
run "Useful Tools" "which wget curl nc ncat socat nmap gdb strace ltrace tcpdump 2>/dev/null"

# ── Docker / Container ──
header "Container / Virtualization"
run "Docker" "docker ps -a 2>/dev/null; docker images 2>/dev/null"
run "Docker Socket" "ls -la /var/run/docker.sock 2>/dev/null"
run "Container Check" "cat /proc/1/cgroup 2>/dev/null | head -5"
run ".dockerenv" "ls -la /.dockerenv 2>/dev/null"
run "LXC/LXD" "lxc list 2>/dev/null"

if [ -S /var/run/docker.sock ]; then
    finding "Docker socket accessible — potential container escape"
fi
if [ -f /.dockerenv ]; then
    info "Running inside a Docker container"
fi

# ── PATH Analysis ──
header "PATH Analysis"
run "Current PATH" "echo \$PATH"
IFS=':' read -ra PATHS <<< "$PATH"
for p in "${PATHS[@]}"; do
    if [ -w "$p" ]; then
        finding "Writable PATH directory: $p"
    fi
done

# ── Environment Variables ──
header "Environment Variables"
run "Environment" "env | grep -viE 'LS_COLORS|LESS_TERMCAP'"

# ── Filesystems ──
header "Mounted Filesystems"
run "Mounts" "mount | column -t 2>/dev/null || mount"
run "Fstab" "cat /etc/fstab 2>/dev/null"
run "Disk Usage" "df -h 2>/dev/null"

echo -e "\n${GREEN}Enumeration complete. Output saved to: $OUTPUT${NC}"
