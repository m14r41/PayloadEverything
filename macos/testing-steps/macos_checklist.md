# macOS Security Assessment Checklist

Complete VAPT methodology for macOS systems and applications.

---

## 1. System Configuration

```bash
# SIP status
csrutil status

# Gatekeeper
spctl --status

# FileVault
fdesetup status

# Firewall
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# macOS version and patch level
sw_vers
softwareupdate -l    # Pending updates

# Secure Boot (Apple Silicon)
nvram 94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy 2>/dev/null

# Firmware password
sudo firmwarepasswd -check 2>/dev/null

# XProtect version
system_profiler SPInstallHistoryDataType | grep -A2 XProtect
```

**Findings:**
- [ ] SIP disabled → CRITICAL
- [ ] Gatekeeper disabled → HIGH
- [ ] FileVault not enabled → HIGH
- [ ] Firewall disabled → MEDIUM
- [ ] Missing security updates → HIGH (depends on CVE)
- [ ] No firmware password → LOW (physical access needed)

---

## 2. User Enumeration

```bash
# List local users
dscl . list /Users | grep -v '^_'
dscl . list /Users UniqueID | awk '$2 >= 500'

# Admin group
dscl . read /Groups/admin GroupMembership

# Logged in users
who
w
last -10

# Password policy
pwpolicy -getaccountpolicies 2>/dev/null

# Screen lock settings
defaults read com.apple.screensaver askForPassword
defaults read com.apple.screensaver askForPasswordDelay
```

**Findings:**
- [ ] Multiple admin accounts → MEDIUM
- [ ] No screen lock / long delay → MEDIUM
- [ ] Weak password policy → MEDIUM

---

## 3. TCC and Privacy

```bash
# User TCC grants
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
    "SELECT service, client, auth_value FROM access WHERE auth_value=2 ORDER BY service;"

# System TCC grants (requires root/FDA)
sudo sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \
    "SELECT service, client, auth_value FROM access WHERE auth_value=2 ORDER BY service;"

# Check for excessive TCC grants
# Focus on: FDA, Accessibility, Screen Recording, Camera, Microphone
```

**Findings:**
- [ ] Terminal/iTerm has FDA → HIGH (child processes inherit)
- [ ] Unnecessary Accessibility grants → MEDIUM
- [ ] Excessive Automation grants → MEDIUM
- [ ] TCC bypass possible (SIP off) → CRITICAL

---

## 4. Privilege Escalation

```bash
# sudo configuration
sudo -l
grep -v "^#" /etc/sudoers 2>/dev/null

# SUID/SGID binaries
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Writable application directories
find /Applications -maxdepth 2 -type d -writable 2>/dev/null
ls -la ~/Applications/*/Contents/Frameworks/ 2>/dev/null

# dylib hijack opportunities
# Check for @rpath dylibs in user-writable app directories
for app in /Applications/*.app ~/Applications/*.app; do
    binary="$app/Contents/MacOS/$(defaults read "$app/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
    if [ -f "$binary" ]; then
        otool -L "$binary" 2>/dev/null | grep "@rpath" && echo "  → $app"
    fi
done 2>/dev/null

# Check for DYLD_INSERT_LIBRARIES vulnerability
# (non-hardened, non-SIP-protected binaries)
codesign -dvvv /Applications/TargetApp.app 2>&1 | grep "flags"
```

**Findings:**
- [ ] NOPASSWD sudo entries → HIGH-CRITICAL
- [ ] sudo timestamp not per-TTY → MEDIUM
- [ ] SUID binaries exploitable → HIGH
- [ ] Writable application directories → HIGH
- [ ] dylib hijack possible → HIGH

---

## 5. Persistence Mechanisms

```bash
# LaunchAgents/Daemons (non-Apple)
ls ~/Library/LaunchAgents/ | grep -v com.apple
ls /Library/LaunchAgents/ | grep -v com.apple
ls /Library/LaunchDaemons/ | grep -v com.apple

# Login items
osascript -e 'tell application "System Events" to get name of every login item'

# Login/Logout hooks
defaults read com.apple.loginwindow LoginHook 2>/dev/null
defaults read com.apple.loginwindow LogoutHook 2>/dev/null

# Cron jobs
crontab -l 2>/dev/null
cat /etc/crontab 2>/dev/null
ls /etc/periodic/daily/ /etc/periodic/weekly/ /etc/periodic/monthly/ 2>/dev/null

# Kernel extensions
kextstat | grep -v com.apple

# Authorization plugins
ls /Library/Security/SecurityAgentPlugins/

# Folder Actions
ls ~/Library/Scripts/Folder\ Action\ Scripts/ 2>/dev/null

# Shell profiles
cat ~/.zshrc ~/.zshenv ~/.zprofile ~/.bash_profile 2>/dev/null | grep -v "^#" | grep -v "^$"
```

**Findings:**
- [ ] Suspicious LaunchAgents/Daemons → severity depends on context
- [ ] Login hooks present → MEDIUM
- [ ] Unknown authorization plugins → HIGH
- [ ] Suspicious shell profile entries → HIGH

---

## 6. Credential Storage

```bash
# Keychain metadata
security dump-keychain 2>/dev/null | grep "svce\|acct" | head -30

# Wi-Fi passwords (admin required)
networksetup -listpreferredwirelessnetworks en0

# Browser Safe Storage keys
for svc in "Chrome Safe Storage" "Brave Safe Storage" "Microsoft Edge Safe Storage"; do
    security find-generic-password -s "$svc" 2>/dev/null && echo "  Found: $svc"
done

# SSH keys
ls -la ~/.ssh/
for key in ~/.ssh/id_*; do
    [ -f "$key" ] && head -1 "$key" | grep -q "PRIVATE KEY" && ! head -5 "$key" | grep -q "ENCRYPTED" && echo "UNENCRYPTED: $key"
done 2>/dev/null

# Cloud credentials
ls ~/.aws/credentials ~/.config/gcloud/ ~/.azure/ 2>/dev/null

# Git credentials
cat ~/.git-credentials 2>/dev/null
```

**Findings:**
- [ ] Plaintext passwords in keychain → HIGH
- [ ] Unencrypted SSH keys → HIGH
- [ ] Cloud credentials on disk → HIGH
- [ ] Git credentials in plaintext → MEDIUM

---

## 7. Network Security

```bash
# Listening services
lsof -i -P -n | grep LISTEN

# Firewall rules
/usr/libexec/ApplicationFirewall/socketfilterfw --listapps

# Proxy settings
networksetup -getwebproxy "Wi-Fi"
scutil --proxy

# DNS configuration
scutil --dns | grep nameserver

# VPN configuration
scutil --nc list

# ARP table
arp -a

# mDNS/Bonjour services
dns-sd -B _services._dns-sd._udp local. &
sleep 3 && kill %1
```

**Findings:**
- [ ] Unnecessary listening services → MEDIUM
- [ ] No firewall or permissive rules → MEDIUM
- [ ] Insecure DNS (no DoH/DoT) → LOW
- [ ] Open network shares → HIGH

---

## 8. Application Security

```bash
# Installed applications
ls /Applications/
system_profiler SPApplicationsDataType | grep -E "Location:|Version:" | head -20

# Check code signing
codesign -dvvv /Applications/TargetApp.app 2>&1

# Check entitlements
codesign -d --entitlements - /Applications/TargetApp.app 2>/dev/null

# Check for hardened runtime
codesign -dvvv /Applications/TargetApp.app 2>&1 | grep "flags"

# Electron apps
find /Applications -name "electron.asar" 2>/dev/null
find /Applications -name "Electron Framework" 2>/dev/null

# Application sandbox check
codesign -d --entitlements - /Applications/TargetApp.app 2>/dev/null | grep "sandbox"
```

**Findings:**
- [ ] Unsigned applications → MEDIUM
- [ ] No hardened runtime → HIGH (DYLD_INSERT_LIBRARIES possible)
- [ ] Excessive entitlements → depends on entitlement
- [ ] Electron with nodeIntegration → CRITICAL (XSS = RCE)

---

## 9. MDM / Configuration Profiles

```bash
# List installed profiles
profiles list 2>/dev/null
sudo profiles list 2>/dev/null

# MDM enrollment
profiles status -type enrollment 2>/dev/null

# Configuration profile details
ls /var/db/ConfigurationProfiles/ 2>/dev/null

# DEP (Device Enrollment Program) check
profiles -e 2>/dev/null
```

**Findings:**
- [ ] No MDM → depends on policy
- [ ] Weak MDM restrictions → MEDIUM
- [ ] MDM bypass possible → HIGH

---

## 10. Defense Evasion Assessment

```bash
# Gatekeeper bypass potential
# Download file via curl (no quarantine)
curl -o /tmp/test_binary https://example.com/file
xattr -l /tmp/test_binary  # Should have no quarantine

# Check if unsigned code can run
spctl --assess -v /tmp/test_binary

# AMFI check
nvram boot-args 2>/dev/null | grep amfi

# Check for disabled protections
csrutil status
```

---

## 11. Logging and Monitoring

```bash
# Unified Log status
log show --last 5m --predicate 'process == "loginwindow"' | head -5

# OpenBSM audit
praudit /dev/auditpipe 2>/dev/null || echo "OpenBSM not accessible"

# Audit policy
cat /etc/security/audit_control 2>/dev/null

# Check for EDR/AV
ps aux | grep -iE "sentinel|crowdstrike|falcon|carbon|malware|sophos|kaspersky|norton"
ls /Library/Extensions/ | grep -v com.apple
kextstat | grep -v com.apple
```

**Findings:**
- [ ] No centralized logging → MEDIUM
- [ ] Audit logging disabled → MEDIUM
- [ ] No EDR/AV installed → depends on policy

---

## 12. Evidence Collection

```bash
# System info
sw_vers > evidence/system_info.txt
uname -a >> evidence/system_info.txt
csrutil status >> evidence/system_info.txt

# Screenshots
screencapture evidence/desktop.png

# Process list
ps auxeww > evidence/processes.txt

# Network connections
lsof -i -P -n > evidence/network.txt

# File timeline (last 24h modifications)
find / -mtime -1 -type f 2>/dev/null > evidence/recent_files.txt

# Unified Log export
log collect --output evidence/system_logs.logarchive

# Keychain metadata
security dump-keychain > evidence/keychain_meta.txt 2>/dev/null
```
