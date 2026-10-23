#!/bin/bash
# TCC (Transparency, Consent, and Control) Enumeration
# Usage: chmod +x tcc_enum.sh && ./tcc_enum.sh
# TCC controls access to: camera, microphone, location, contacts, calendars,
# photos, Full Disk Access, screen recording, accessibility, and more.
# Some checks require Full Disk Access or root.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log() { echo -e "[*] $1"; }
found() { echo -e "${RED}[!] $1${NC}"; }
safe() { echo -e "${GREEN}[+] $1${NC}"; }
warn() { echo -e "${YELLOW}[?] $1${NC}"; }

header() { echo -e "\n${YELLOW}════════════════════════════════════════${NC}"; echo -e "${YELLOW} $1${NC}"; echo -e "${YELLOW}════════════════════════════════════════${NC}"; }

header "TCC ENUMERATION — $(date)"

# ── TCC Database Locations ──
USER_TCC="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
SYSTEM_TCC="/Library/Application Support/com.apple.TCC/TCC.db"

header "TCC DATABASE ACCESS"

# Service name mapping
declare -A TCC_SERVICES
TCC_SERVICES=(
    ["kTCCServiceAccessibility"]="Accessibility"
    ["kTCCServiceAddressBook"]="Contacts"
    ["kTCCServiceCalendar"]="Calendar"
    ["kTCCServiceCamera"]="Camera"
    ["kTCCServiceMicrophone"]="Microphone"
    ["kTCCServicePhotos"]="Photos"
    ["kTCCServiceScreenCapture"]="Screen Recording"
    ["kTCCServiceSystemPolicyAllFiles"]="Full Disk Access"
    ["kTCCServiceSystemPolicySysAdminFiles"]="Administer Files"
    ["kTCCServiceSystemPolicyDesktopFolder"]="Desktop Folder"
    ["kTCCServiceSystemPolicyDocumentsFolder"]="Documents Folder"
    ["kTCCServiceSystemPolicyDownloadsFolder"]="Downloads Folder"
    ["kTCCServiceSystemPolicyNetworkVolumes"]="Network Volumes"
    ["kTCCServiceSystemPolicyRemovableVolumes"]="Removable Volumes"
    ["kTCCServiceAppleEvents"]="Automation (Apple Events)"
    ["kTCCServiceListenEvent"]="Input Monitoring"
    ["kTCCServicePostEvent"]="Synthetic Input"
    ["kTCCServiceLocation"]="Location Services"
    ["kTCCServiceMediaLibrary"]="Media & Apple Music"
    ["kTCCServiceSpeechRecognition"]="Speech Recognition"
    ["kTCCServiceBluetoothAlways"]="Bluetooth"
    ["kTCCServiceFileProviderPresence"]="File Provider"
    ["kTCCServiceDeveloperTool"]="Developer Tools"
    ["kTCCServiceEndpointSecurityClient"]="Endpoint Security"
)

# auth_value: 0=denied, 1=unknown, 2=allowed, 3=limited
auth_decode() {
    case "$1" in
        0) echo "DENIED";;
        1) echo "UNKNOWN";;
        2) echo "ALLOWED";;
        3) echo "LIMITED";;
        *) echo "VALUE:$1";;
    esac
}

# ── User TCC Database ──
header "USER TCC DATABASE"
if [ -f "$USER_TCC" ]; then
    log "Reading: $USER_TCC"

    log "All user TCC grants:"
    sqlite3 "$USER_TCC" "SELECT service, client, auth_value, auth_reason, last_modified FROM access ORDER BY service;" 2>/dev/null | while IFS='|' read -r service client auth reason modified; do
        auth_text=$(auth_decode "$auth")
        service_name="${TCC_SERVICES[$service]:-$service}"
        if [ "$auth" = "2" ]; then
            found "  $service_name → $client [$auth_text]"
        else
            echo "  $service_name → $client [$auth_text]"
        fi
    done || warn "Cannot read user TCC.db — may need Full Disk Access"
else
    warn "User TCC.db not found"
fi

# ── System TCC Database ──
header "SYSTEM TCC DATABASE"
if [ -f "$SYSTEM_TCC" ]; then
    log "Reading: $SYSTEM_TCC (requires root or FDA)"

    sqlite3 "$SYSTEM_TCC" "SELECT service, client, auth_value FROM access ORDER BY service;" 2>/dev/null | while IFS='|' read -r service client auth; do
        auth_text=$(auth_decode "$auth")
        service_name="${TCC_SERVICES[$service]:-$service}"
        if [ "$auth" = "2" ]; then
            found "  $service_name → $client [$auth_text]"
        fi
    done || warn "Cannot read system TCC.db — need root or FDA"
fi

# ── High-Value TCC Grants ──
header "HIGH-VALUE TCC GRANTS"

log "Apps with Full Disk Access:"
sqlite3 "$USER_TCC" "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2;" 2>/dev/null || echo "  Cannot check"
sqlite3 "$SYSTEM_TCC" "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2;" 2>/dev/null || true

log "Apps with Accessibility:"
sqlite3 "$USER_TCC" "SELECT client FROM access WHERE service='kTCCServiceAccessibility' AND auth_value=2;" 2>/dev/null || echo "  Cannot check"

log "Apps with Screen Recording:"
sqlite3 "$USER_TCC" "SELECT client FROM access WHERE service='kTCCServiceScreenCapture' AND auth_value=2;" 2>/dev/null || echo "  Cannot check"

log "Apps with Camera access:"
sqlite3 "$USER_TCC" "SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;" 2>/dev/null || echo "  Cannot check"

log "Apps with Microphone access:"
sqlite3 "$USER_TCC" "SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;" 2>/dev/null || echo "  Cannot check"

log "Apps with Automation (Apple Events):"
sqlite3 "$USER_TCC" "SELECT client, indirect_object_identifier FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;" 2>/dev/null || echo "  Cannot check"

log "Apps with Input Monitoring:"
sqlite3 "$USER_TCC" "SELECT client FROM access WHERE service='kTCCServiceListenEvent' AND auth_value=2;" 2>/dev/null || echo "  Cannot check"

# ── TCC Bypass Opportunities ──
header "TCC BYPASS OPPORTUNITIES"

log "Checking for known TCC bypass vectors..."

# Check for FDA apps that can be abused
FDA_APPS=$(sqlite3 "$USER_TCC" "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2;" 2>/dev/null || true)

if echo "$FDA_APPS" | grep -qi "terminal\|iterm\|warp"; then
    found "Terminal app has FDA — child processes inherit TCC grants"
fi

if echo "$FDA_APPS" | grep -qi "finder"; then
    found "Finder has FDA — AppleScript via Finder can access protected files"
fi

# Check for Accessibility apps (can send synthetic events)
ACC_APPS=$(sqlite3 "$USER_TCC" "SELECT client FROM access WHERE service='kTCCServiceAccessibility' AND auth_value=2;" 2>/dev/null || true)

if [ -n "$ACC_APPS" ]; then
    warn "Apps with Accessibility can inject synthetic clicks/keystrokes"
    echo "$ACC_APPS" | while read -r app; do
        echo "  → $app"
    done
fi

# Check for Automation grants (Apple Events)
AUTO_APPS=$(sqlite3 "$USER_TCC" "SELECT client, indirect_object_identifier FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;" 2>/dev/null || true)

if echo "$AUTO_APPS" | grep -qi "system events\|finder"; then
    found "Automation grant to System Events/Finder — can control UI elements"
fi

# Check if SSH has FDA
if echo "$FDA_APPS" | grep -qi "sshd-keygen-wrapper\|ssh"; then
    found "SSH daemon has FDA — remote file access to protected directories"
fi

# Check for Endpoint Security clients
ES_APPS=$(sqlite3 "$SYSTEM_TCC" "SELECT client FROM access WHERE service='kTCCServiceEndpointSecurityClient' AND auth_value=2;" 2>/dev/null || true)
if [ -n "$ES_APPS" ]; then
    log "Endpoint Security clients (EDR/AV):"
    echo "$ES_APPS" | while read -r app; do echo "  → $app"; done
fi

# ── TCC Database Integrity ──
header "TCC DATABASE INTEGRITY"

log "User TCC.db permissions:"
ls -la "$USER_TCC" 2>/dev/null || echo "  Cannot check"

log "System TCC.db permissions:"
ls -la "$SYSTEM_TCC" 2>/dev/null || echo "  Cannot check"

log "TCC.db directory permissions:"
ls -la "$(dirname "$USER_TCC")" 2>/dev/null || echo "  Cannot check"

# Check if TCC can be modified (SIP off)
if csrutil status 2>/dev/null | grep -q "disabled"; then
    found "SIP is DISABLED — TCC.db can be directly modified!"
    found "  sqlite3 '$SYSTEM_TCC' \"INSERT INTO access VALUES('kTCCServiceSystemPolicyAllFiles','com.attacker.app',0,2,4,1,NULL,NULL,0,'UNUSED',NULL,0,$(date +%s));\""
fi

# ── MDM TCC Profiles ──
header "MDM-MANAGED TCC"

log "Configuration profiles with TCC payloads:"
profiles list 2>/dev/null | grep -i "privacy\|tcc\|consent" || echo "  No TCC-related profiles found (or cannot list)"

header "ENUMERATION COMPLETE"
log "Key findings to investigate:"
log "  1. Apps with FDA → can they be leveraged for file access?"
log "  2. Apps with Accessibility → synthetic event injection?"
log "  3. Automation grants → control other apps via Apple Events?"
log "  4. SIP status → direct TCC.db modification possible?"
log "  5. MDM profiles → centrally managed TCC grants?"
