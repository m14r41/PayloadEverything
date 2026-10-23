# iOS VAPT Testing Checklist
# Quick reference with commands for each test area

# ============================================================
# SETUP
# ============================================================
# List installed apps
ideviceinstaller -l

# Extract IPA from device (jailbroken)
ssh root@<device_ip> "find /var/containers/Bundle/Application -name '*.app' | grep target"
scp -r root@<device_ip>:/var/containers/Bundle/Application/<UUID>/Target.app ./

# Decrypt IPA (if encrypted)
frida-ios-dump -u <udid> -o target.ipa com.target.app
# Or: clutch -d com.target.app

# Extract from IPA
unzip target.ipa -d target_extracted
# Binary: target_extracted/Payload/Target.app/Target

# Check binary protections
otool -l Target | grep -A4 LC_ENCRYPTION_INFO
otool -l Target | grep PIE
otool -l Target | grep -i stack
codesign -dvvv Target.app

# Class dump
class-dump Target > classes.h
# Or use dsdump for Swift: dsdump --swift Target

# ============================================================
# 1. SSL PINNING BYPASS
# ============================================================
frida -U -l ios_ssl_bypass.js -f com.target.app --no-pause

# Objection
objection -g com.target.app explore --startup-command "ios sslpinning disable"

# Check Info.plist for ATS
plutil -p target_extracted/Payload/Target.app/Info.plist | grep -A20 NSAppTransportSecurity

# Proxy setup
# 1. Set iOS Wi-Fi proxy to Burp IP:8080
# 2. Install Burp CA: http://burp → Download CA → Settings → Profile Downloaded
# 3. Trust CA: Settings → General → About → Certificate Trust Settings → Enable

# ============================================================
# 2. JAILBREAK DETECTION BYPASS
# ============================================================
frida -U -l jailbreak_bypass.js -f com.target.app --no-pause
objection -g com.target.app explore --startup-command "ios jailbreak disable"

# Check what detection is used
grep -rE "jail|Cydia|fork|sysctl|canOpenURL.*cydia|IOSSecuritySuite" classes.h

# ============================================================
# 3. LOCAL STORAGE ANALYSIS
# ============================================================
# App data directory (jailbroken)
ssh root@<device_ip>
ls /var/mobile/Containers/Data/Application/<UUID>/

# NSUserDefaults (plist files)
find /var/mobile/Containers/Data/Application/<UUID>/ -name "*.plist" -exec plutil -p {} \;

# Keychain extraction
frida -U -l dump_keychain.js -f com.target.app --no-pause
# Or: keychain-dumper (jailbroken device)
keychain-dumper -a

# SQLite databases
find /var/mobile/Containers/Data/Application/<UUID>/ -name "*.db" -o -name "*.sqlite"
sqlite3 app.db ".tables"
sqlite3 app.db "SELECT * FROM credentials;"

# Check for sensitive data in files
grep -rni "password\|token\|secret\|api.key\|bearer" /var/mobile/Containers/Data/Application/<UUID>/

# Frida storage dump
frida -U -l ios_storage_dump.js -f com.target.app --no-pause

# Cookies
plutil -p /var/mobile/Containers/Data/Application/<UUID>/Library/Cookies/Cookies.binarycookies

# Cache
ls /var/mobile/Containers/Data/Application/<UUID>/Library/Caches/

# ============================================================
# 4. BINARY ANALYSIS
# ============================================================
# Strings in binary
strings Target | grep -iE "password|token|secret|api|key|http"

# Check for debug symbols
nm Target | head -50

# Check for hardcoded URLs
strings Target | grep -E "^https?://"

# Swift metadata
swift-demangle < <(strings Target | grep '_T')

# Check for unsafe APIs
strings Target | grep -E "UIPasteboard|NSLog|printf|sprintf"

# ============================================================
# 5. NETWORK TRAFFIC ANALYSIS
# ============================================================
# Proxy configured via Wi-Fi settings
# Monitor in Burp Suite

# Check for cleartext traffic
strings Target | grep "http://" | grep -v "https"

# Check ATS exceptions
plutil -p Info.plist | grep -A5 "NSExceptionDomains"

# ============================================================
# 6. CRYPTO ANALYSIS
# ============================================================
frida -U -l ios_crypto_hooks.js -f com.target.app --no-pause

# Check for weak crypto
strings Target | grep -iE "DES|RC4|MD5|SHA1|ECB|kCCAlgorithmDES"
grep -rE "CCCrypt|SecKey|kSecAttr|CommonCrypto" classes.h

# ============================================================
# 7. IPC & URL SCHEME ANALYSIS
# ============================================================
# List URL schemes
plutil -p Info.plist | grep -A5 CFBundleURLSchemes

# Test URL schemes
# On device: open 'targetapp://deeplink?param=value'
# Frida: ObjC.classes.UIApplication.sharedApplication().openURL_(ObjC.classes.NSURL.URLWithString_('targetapp://test'))

# Universal Links
cat target_extracted/Payload/Target.app/.well-known/apple-app-site-association 2>/dev/null
# Check entitlements
codesign -d --entitlements :- Target.app

# Check for custom pasteboard usage
grep -E "UIPasteboard|generalPasteboard" classes.h

# ============================================================
# 8. BIOMETRIC BYPASS
# ============================================================
# Check implementation
grep -E "LAContext|BiometricAuthentication|evaluatePolicy|touchIDAuthentication" classes.h

# Frida bypass
objection -g com.target.app explore -c "ios ui biometrics_bypass"

# ============================================================
# 9. RUNTIME MANIPULATION
# ============================================================
# Objection exploration
objection -g com.target.app explore

# List classes
ios hooking list classes
ios hooking search classes auth
ios hooking search classes login

# Watch methods
ios hooking watch class TargetApp.AuthManager
ios hooking watch method "-[AuthManager validateToken:]" --dump-args --dump-return

# Set return value
ios hooking set return_value "-[AuthManager isAuthenticated]" true

# ============================================================
# 10. LOGGING & SCREENSHOTS
# ============================================================
# Check for sensitive logging
idevicesyslog | grep -i com.target.app | grep -iE "password|token|key|secret"

# Screenshot protection
# Background the app and check recent apps for content visibility
# Check for: UIApplication.shared.ignoreSnapshotOnNextApplicationLaunch()

# Check snapshot cache
ls /var/mobile/Containers/Data/Application/<UUID>/Library/SplashBoard/Snapshots/

# ============================================================
# 11. THIRD-PARTY LIBRARIES
# ============================================================
# Check for known vulnerable libraries
strings Target | grep -E "AFNetworking|Alamofire|Firebase|Realm|CocoaPods"
cat Podfile 2>/dev/null
cat Cartfile 2>/dev/null

# Check embedded frameworks
ls target_extracted/Payload/Target.app/Frameworks/

# ============================================================
# 12. DATA PROTECTION & ENCRYPTION
# ============================================================
# Check file protection classes
objection -g com.target.app explore -c "ios nsurlcredentialstorage dump"
objection -g com.target.app explore -c "ios cookies get"

# Check keychain access groups
codesign -d --entitlements :- Target.app | grep -A5 keychain-access-groups

# ============================================================
# REPORT TEMPLATE
# ============================================================
# For each finding:
#   - Vulnerability title
#   - OWASP Mobile Top 10 mapping (M1-M10)
#   - CVSS score
#   - Steps to reproduce
#   - Evidence (screenshot / Frida output)
#   - Impact
#   - Remediation
