#!/bin/bash
# macOS Enumeration Script — Comprehensive System Assessment
# Usage: chmod +x macos_enum.sh && ./macos_enum.sh [output_dir]
# Requires: Standard macOS tools. Some checks need root for full results.

set -euo pipefail

OUTPUT_DIR="${1:-./macos_enum_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTPUT_DIR"

log() { echo "[*] $1"; }
warn() { echo "[!] $1"; }
header() { echo -e "\n========================================"; echo " $1"; echo "========================================"; }

exec > >(tee "$OUTPUT_DIR/full_report.txt") 2>&1

header "macOS ENUMERATION — $(date)"
log "Output directory: $OUTPUT_DIR"
log "Running as: $(whoami) (UID: $(id -u))"

# ── System Information ──
header "SYSTEM INFORMATION"
sw_vers
echo ""
uname -a
echo ""
system_profiler SPSoftwareDataType SPHardwareDataType 2>/dev/null
echo ""
log "Hostname: $(hostname)"
log "Serial: $(system_profiler SPHardwareDataType 2>/dev/null | awk '/Serial/{print $NF}')"
log "Architecture: $(uname -m)"

# ── Security Configuration ──
header "SECURITY CONFIGURATION"

log "SIP Status:"
csrutil status 2>/dev/null || warn "Cannot check SIP (requires recovery mode for full info)"

log "Gatekeeper Status:"
spctl --status 2>/dev/null || warn "Cannot check Gatekeeper"

log "FileVault Status:"
fdesetup status 2>/dev/null || warn "Cannot check FileVault (may need root)"

log "Firewall Status:"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || warn "Cannot check firewall"
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null
/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>/dev/null

log "XProtect version:"
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A2 "XProtect" | head -5

log "Firmware password:"
firmwarepasswd -check 2>/dev/null || warn "Cannot check firmware password (needs root)"

log "Secure Boot:"
nvram 94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy 2>/dev/null || echo "  Cannot read (normal on non-Apple Silicon)"

# ── Users and Groups ──
header "USERS AND GROUPS"

log "Local users:"
dscl . list /Users | grep -v '^_'

log "Admin group members:"
dscl . read /Groups/admin GroupMembership 2>/dev/null

log "Users with UID >= 500 (interactive):"
dscl . list /Users UniqueID | awk '$2 >= 500 {print}'

log "Currently logged in:"
who
echo ""
w

log "Last logins:"
last -10 2>/dev/null

log "User home directories:"
ls -la /Users/

# ── TCC Database ──
header "TCC (Transparency, Consent, and Control)"

log "User TCC database:"
TCC_DB="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
if [ -f "$TCC_DB" ]; then
    sqlite3 "$TCC_DB" "SELECT client, service, auth_value, auth_reason FROM access ORDER BY service;" 2>/dev/null || warn "Cannot read user TCC.db (FDA required)"
else
    warn "User TCC.db not found at expected path"
fi

log "System TCC database (requires root/FDA):"
if [ -f "/Library/Application Support/com.apple.TCC/TCC.db" ]; then
    sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" "SELECT client, service, auth_value FROM access ORDER BY service;" 2>/dev/null || warn "Cannot read system TCC.db"
fi

# ── Installed Applications ──
header "INSTALLED APPLICATIONS"

log "Applications in /Applications:"
ls -1 /Applications/ 2>/dev/null

log "Homebrew packages:"
brew list 2>/dev/null || echo "  Homebrew not installed"

log "pip packages (user):"
pip3 list --user 2>/dev/null || echo "  pip3 not available or no user packages"

log "Developer tools:"
xcode-select -p 2>/dev/null && echo "  Xcode CLI tools installed" || echo "  No Xcode CLI tools"

# ── LaunchAgents / LaunchDaemons ──
header "LAUNCH AGENTS AND DAEMONS"

log "User LaunchAgents:"
ls -la ~/Library/LaunchAgents/ 2>/dev/null || echo "  None"

log "System LaunchAgents:"
ls -la /Library/LaunchAgents/ 2>/dev/null || echo "  None"

log "System LaunchDaemons:"
ls -la /Library/LaunchDaemons/ 2>/dev/null || echo "  None"

log "Apple LaunchDaemons (non-Apple entries = suspicious):"
ls /System/Library/LaunchDaemons/ 2>/dev/null | grep -v "com.apple" || echo "  All Apple-signed"

log "Currently loaded launch services:"
launchctl list 2>/dev/null | head -50

log "Non-Apple loaded services:"
launchctl list 2>/dev/null | grep -v "com.apple" | grep -v "PID" || echo "  None"

# ── Login Items ──
header "LOGIN ITEMS"

log "Current user login items:"
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || warn "Cannot query login items"

log "Login items plist:"
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm 2>/dev/null || echo "  Cannot read backgrounditems"

# ── Keychain Information ──
header "KEYCHAIN INFORMATION"

log "Keychain list:"
security list-keychains

log "Default keychain:"
security default-keychain

log "Keychain files:"
ls -la ~/Library/Keychains/ 2>/dev/null

log "System keychain entries (generic passwords — titles only):"
security dump-keychain 2>/dev/null | grep "\"svce\"" | head -20 || warn "Cannot dump keychain (user interaction may be required)"

# ── SSH Keys ──
header "SSH KEYS"

log "SSH directory:"
ls -la ~/.ssh/ 2>/dev/null || echo "  No .ssh directory"

log "SSH config:"
cat ~/.ssh/config 2>/dev/null || echo "  No SSH config"

log "Known hosts (first 10):"
head -10 ~/.ssh/known_hosts 2>/dev/null || echo "  No known_hosts"

log "SSH agent keys:"
ssh-add -l 2>/dev/null || echo "  No keys in agent"

log "Authorized keys:"
cat ~/.ssh/authorized_keys 2>/dev/null || echo "  No authorized_keys"

# ── Network Configuration ──
header "NETWORK CONFIGURATION"

log "Network interfaces:"
ifconfig 2>/dev/null | grep -E "^[a-z]|inet "

log "DNS servers:"
scutil --dns 2>/dev/null | grep "nameserver" | sort -u

log "Routing table:"
netstat -rn 2>/dev/null | head -20

log "ARP table:"
arp -a 2>/dev/null

log "Proxy settings:"
scutil --proxy 2>/dev/null

log "Wi-Fi info:"
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null || warn "airport utility not found"

log "Saved Wi-Fi networks:"
networksetup -listpreferredwirelessnetworks en0 2>/dev/null || echo "  Cannot list"

# ── Running Processes ──
header "RUNNING PROCESSES"

log "Processes (sorted by CPU):"
ps aux --sort=-%cpu 2>/dev/null | head -30 || ps aux | head -30

log "Processes running as root:"
ps aux | awk '$1 == "root" {print}' | head -20

log "Non-Apple processes:"
ps aux | grep -v "/System/" | grep -v "/usr/libexec/" | grep -v "grep" | head -30

# ── Open Ports and Connections ──
header "OPEN PORTS AND CONNECTIONS"

log "Listening ports:"
lsof -i -P -n | grep LISTEN 2>/dev/null || netstat -an | grep LISTEN

log "Established connections:"
lsof -i -P -n | grep ESTABLISHED 2>/dev/null | head -20

log "All network connections:"
netstat -an 2>/dev/null | head -30

# ── Environment Variables ──
header "ENVIRONMENT VARIABLES"
env | sort

# ── Kernel Extensions ──
header "KERNEL EXTENSIONS"

log "Loaded kexts (non-Apple):"
kextstat 2>/dev/null | grep -v "com.apple" || echo "  Cannot list kexts or none loaded"

log "System extensions:"
systemextensionsctl list 2>/dev/null || echo "  Cannot list system extensions"

# ── Authorization Database ──
header "AUTHORIZATION DATABASE"

log "Authorization rights (interesting entries):"
security authorizationdb read system.privilege.admin 2>/dev/null | head -20
echo ""
security authorizationdb read com.apple.system-extensions.admin 2>/dev/null | head -10

# ── MDM Enrollment ──
header "MDM ENROLLMENT"

log "MDM profiles:"
profiles list 2>/dev/null || warn "Cannot list profiles (may need root)"

log "MDM enrollment status:"
profiles status -type enrollment 2>/dev/null || echo "  Cannot check enrollment"

log "Configuration profiles:"
ls -la /var/db/ConfigurationProfiles/ 2>/dev/null || echo "  Cannot access"

# ── Cron Jobs ──
header "SCHEDULED TASKS"

log "Current user crontab:"
crontab -l 2>/dev/null || echo "  No crontab"

log "System crontab:"
cat /etc/crontab 2>/dev/null || echo "  No /etc/crontab"

log "Periodic scripts:"
ls -la /etc/periodic/daily/ 2>/dev/null
ls -la /etc/periodic/weekly/ 2>/dev/null
ls -la /etc/periodic/monthly/ 2>/dev/null

log "At jobs:"
atq 2>/dev/null || echo "  No at jobs"

# ── Interesting Files ──
header "INTERESTING FILES"

log "World-writable directories in /Applications:"
find /Applications -type d -perm -002 2>/dev/null | head -10 || echo "  None found"

log "SUID binaries:"
find / -perm -4000 -type f 2>/dev/null | head -20

log "SGID binaries:"
find / -perm -2000 -type f 2>/dev/null | head -20

log "Recently modified files in /etc:"
find /etc -mtime -7 -type f 2>/dev/null | head -10

log ".bash_history / .zsh_history:"
wc -l ~/.bash_history 2>/dev/null || echo "  No .bash_history"
wc -l ~/.zsh_history 2>/dev/null || echo "  No .zsh_history"

# ── Summary ──
header "ENUMERATION COMPLETE"
log "Full report saved to: $OUTPUT_DIR/full_report.txt"
log "Review findings and escalate based on:"
log "  - SIP disabled → full system access"
log "  - TCC grants → FDA/accessibility/screen recording abuse"
log "  - Non-Apple LaunchAgents/Daemons → persistence review"
log "  - Writable directories → dylib hijack / binary replacement"
log "  - SUID binaries → privilege escalation"
log "  - MDM profiles → policy bypass opportunities"
