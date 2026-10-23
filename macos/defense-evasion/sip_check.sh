#!/bin/bash
# macOS SIP (System Integrity Protection) Assessment
# Usage: chmod +x sip_check.sh && ./sip_check.sh
# MITRE ATT&CK: T1562.001 — Disable or Modify Tools

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

found() { echo -e "${RED}[!] $1${NC}"; }
safe() { echo -e "${GREEN}[+] $1${NC}"; }
warn() { echo -e "${YELLOW}[?] $1${NC}"; }
log() { echo "[*] $1"; }

echo "═══════════════════════════════════════"
echo " SIP ASSESSMENT — $(date)"
echo "═══════════════════════════════════════"

# ── SIP Status ──
echo ""
log "System Integrity Protection Status:"
SIP_STATUS=$(csrutil status 2>/dev/null)
echo "  $SIP_STATUS"

if echo "$SIP_STATUS" | grep -q "disabled"; then
    found "SIP IS DISABLED — Full system access possible"
    found "  → Can modify /System, /usr (except /usr/local)"
    found "  → Can attach debugger to system processes"
    found "  → Can load unsigned kernel extensions"
    found "  → Can modify TCC database directly"
    found "  → DYLD_INSERT_LIBRARIES works on all processes"
elif echo "$SIP_STATUS" | grep -q "Custom Configuration"; then
    warn "SIP has CUSTOM configuration — some protections may be disabled"
else
    safe "SIP is ENABLED (full protection)"
fi

# ── SIP-Protected Paths ──
echo ""
log "SIP-Protected Paths (read-only when SIP is on):"
SIP_PATHS=(
    "/System"
    "/usr"
    "/bin"
    "/sbin"
    "/var"
)

for path in "${SIP_PATHS[@]}"; do
    if [ -w "$path" ] 2>/dev/null; then
        found "  WRITABLE: $path"
    else
        safe "  Protected: $path"
    fi
done

# ── Writable Despite SIP ──
echo ""
log "Paths writable even with SIP enabled:"
WRITABLE_PATHS=(
    "/usr/local"
    "/Library"
    "/Applications"
    "/Users"
    "/private/tmp"
    "/private/var/tmp"
    "/opt"
)

for path in "${WRITABLE_PATHS[@]}"; do
    if [ -d "$path" ] && [ -w "$path" ] 2>/dev/null; then
        warn "  Writable: $path"
    fi
done

# ── Kernel Extension Loading ──
echo ""
log "Kernel Extension Policy:"

if csrutil status 2>/dev/null | grep -q "Kext Signing.*disabled"; then
    found "Kext signing is DISABLED — unsigned kernel extensions can load"
else
    safe "Kext signing is enabled"
fi

log "Loaded non-Apple kexts:"
kextstat 2>/dev/null | grep -v "com.apple" | tail -n +2 || echo "  None or cannot list"

log "System extensions:"
systemextensionsctl list 2>/dev/null || echo "  Cannot list"

# ── NVRAM Check ──
echo ""
log "NVRAM boot-args (may indicate SIP was disabled):"
nvram boot-args 2>/dev/null || echo "  No boot-args set (normal)"

# Check for csr-active-config
log "SIP NVRAM config:"
nvram csr-active-config 2>/dev/null || echo "  Default (normal when SIP is fully enabled)"
# Values: 0x0 or absent = full SIP, 0x77 = fully disabled, other = partial

# ── Filesystem Flags ──
echo ""
log "Signed System Volume (SSV):"
if mount | grep -q "read-only"; then
    safe "System volume is mounted read-only (SSV active)"
else
    warn "System volume may be writable"
fi

log "Root filesystem mount:"
mount | grep " / " || true

# ── SIP-Excluded Processes ──
echo ""
log "Processes with SIP exclusions (can access protected paths):"
echo "  Built-in exclusions include:"
echo "    - /usr/libexec/mdworker_shared (Spotlight)"
echo "    - /usr/libexec/mds (Metadata Server)"
echo "    - /usr/bin/csrutil (SIP management)"
echo "    - Apple signed system processes"

# ── Debugging Restrictions ──
echo ""
log "Debugging restrictions:"

if csrutil status 2>/dev/null | grep -q "Debugging Restrictions.*disabled"; then
    found "Debugging restrictions DISABLED — can attach to system processes"
else
    safe "Debugging restrictions enabled (cannot ptrace system processes)"
fi

log "Can we attach debugger to a system process?"
if lldb -p 1 -o "quit" 2>&1 | grep -q "error"; then
    safe "Cannot debug PID 1 (launchd) — debugging restrictions active"
else
    found "CAN debug PID 1 — debugging restrictions may be off"
fi 2>/dev/null || true

# ── AMFI (Apple Mobile File Integrity) ──
echo ""
log "AMFI Status:"
if nvram boot-args 2>/dev/null | grep -q "amfi_get_out_of_my_way"; then
    found "AMFI is DISABLED via boot-args"
else
    safe "AMFI is active (code signing enforcement)"
fi

# ── Sealed System Volume ──
echo ""
log "Sealed System Volume check:"
diskutil apfs listCryptoUsers / 2>/dev/null | head -5 || echo "  Cannot check"

# ── Summary ──
echo ""
echo "═══════════════════════════════════════"
echo " ASSESSMENT SUMMARY"
echo "═══════════════════════════════════════"

if echo "$SIP_STATUS" | grep -q "disabled"; then
    found "FINDING: SIP is disabled — CRITICAL"
    echo "  Impact: Full system modification, TCC bypass, kext loading, debugger attachment"
    echo "  CVSS: 9.8 (if remotely exploitable) / 7.8 (local)"
elif echo "$SIP_STATUS" | grep -q "Custom"; then
    warn "FINDING: SIP has custom configuration — HIGH"
    echo "  Impact: Some SIP protections are disabled, assess which ones"
else
    safe "SIP is fully enabled — standard macOS security posture"
    echo "  Note: Exploitation must work within SIP constraints"
    echo "  Focus on: TCC bypass, dylib hijacking in user-writable paths, LaunchAgent persistence"
fi
