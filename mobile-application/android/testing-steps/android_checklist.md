# Android VAPT Testing Checklist
# Quick reference with commands for each test area

# ============================================================
# SETUP
# ============================================================
# Install target APK
adb install target.apk

# Extract APK from device
adb shell pm path com.target.app
adb pull /data/app/.../base.apk ./target.apk

# Decompile
apktool d target.apk -o target_decompiled
jadx -d target_src target.apk

# Check debuggable flag
aapt dump badging target.apk | grep -i debug
adb shell run-as com.target.app id   # works if debuggable

# ============================================================
# 1. SSL PINNING BYPASS
# ============================================================
# Frida universal bypass
frida -U -l universal_ssl_bypass.js -f com.target.app --no-pause

# Objection
objection -g com.target.app explore --startup-command "android sslpinning disable"

# Check network_security_config.xml
cat target_decompiled/res/xml/network_security_config.xml

# Install Burp CA as system cert (requires root)
openssl x509 -inform DER -in burp.der -out burp.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1)
adb push burp.pem /system/etc/security/cacerts/${HASH}.0
adb shell chmod 644 /system/etc/security/cacerts/${HASH}.0

# ============================================================
# 2. ROOT DETECTION BYPASS
# ============================================================
frida -U -l root_bypass.js -f com.target.app --no-pause
objection -g com.target.app explore --startup-command "android root disable"

# Check what root detection library is used
grep -rE "RootBeer|rootcheck|SafetyNet|isRooted|isDeviceRooted" target_src/

# ============================================================
# 3. LOCAL STORAGE ANALYSIS
# ============================================================
# SharedPreferences
adb shell run-as com.target.app cat shared_prefs/*.xml

# SQLite databases
adb shell run-as com.target.app ls databases/
adb pull /data/data/com.target.app/databases/app.db
sqlite3 app.db ".tables"
sqlite3 app.db "SELECT * FROM users;"

# External storage (world-readable)
adb shell ls /sdcard/Android/data/com.target.app/
adb shell find /sdcard -name "*.db" -o -name "*.sqlite" -o -name "*.key" 2>/dev/null

# Frida storage dump
frida -U -l extract_storage.js -f com.target.app --no-pause

# Check for hardcoded secrets in source
grep -rnE "(api[_-]?key|secret|password|token|private[_-]?key)" target_src/ --include="*.java" --include="*.kt"
grep -rnE "(BEGIN (RSA |EC )?PRIVATE KEY)" target_src/

# ============================================================
# 4. EXPORTED COMPONENT ABUSE
# ============================================================
# List exported components
adb shell dumpsys package com.target.app | grep -E "exported=true"

# Launch activities
adb shell am start -n com.target.app/.AdminActivity
adb shell am start -a android.intent.action.VIEW -d "appscheme://callback?token=test"

# Query content providers
adb shell content query --uri "content://com.target.app.provider/users"

# Broadcast injection
adb shell am broadcast -a com.target.app.PUSH --es "url" "https://evil.com"

# Full enumeration script
./exported_components.sh com.target.app

# ============================================================
# 5. NETWORK TRAFFIC ANALYSIS
# ============================================================
# Set proxy
adb shell settings put global http_proxy 192.168.1.100:8080

# Remove proxy
adb shell settings put global http_proxy :0

# Capture traffic without proxy (tcpdump on device)
adb shell tcpdump -i any -w /sdcard/capture.pcap
adb pull /sdcard/capture.pcap

# Check for cleartext traffic
grep -r "http://" target_src/ --include="*.java" --include="*.kt" | grep -v "https://"
grep -r "cleartextTrafficPermitted" target_decompiled/

# ============================================================
# 6. CRYPTO ANALYSIS
# ============================================================
# Trace all crypto operations
frida -U -l method_tracer.js -f com.target.app --no-pause

# Check for weak crypto in source
grep -rnE "(DES|RC4|MD5|SHA-1|ECB|PKCS1Padding)" target_src/ --include="*.java"
grep -rnE "SecretKeySpec|PBEKeySpec|KeyGenerator" target_src/ --include="*.java"
grep -rnE "Random\(\)|Math\.random|setSeed" target_src/ --include="*.java"

# ============================================================
# 7. WEBVIEW ANALYSIS
# ============================================================
# Check WebView settings in source
grep -rnE "setJavaScriptEnabled|addJavascriptInterface|setAllowFileAccess|setAllowUniversalAccessFromFileURLs" target_src/

# Remote Chrome debugging (if WebView is debuggable)
# Open chrome://inspect in Chrome browser

# Test for XSS in WebView
adb shell am start -n com.target.app/.WebViewActivity --es "url" "javascript:alert(document.cookie)"

# ============================================================
# 8. BIOMETRIC BYPASS
# ============================================================
frida -U -l bypass_biometric.js -f com.target.app --no-pause

# Check biometric implementation
grep -rnE "BiometricPrompt|FingerprintManager|authenticate" target_src/

# ============================================================
# 9. BINARY PROTECTIONS
# ============================================================
# Check for code obfuscation
ls target_decompiled/smali/*/a/a/a.smali 2>/dev/null  # ProGuard indicator

# Check for anti-tampering
grep -rnE "signature|PackageInfo|checkSignature|Integrity" target_src/

# Check for anti-debugging
grep -rnE "isDebuggerConnected|Debug\.isDebuggerConnected|ptrace" target_src/
grep -rnE "TracerPid" target_src/

# Check for emulator detection
grep -rnE "goldfish|sdk_gphone|generic|emulator|Andy|nox|BlueStacks" target_src/

# ============================================================
# 10. LOGGING & BACKUP
# ============================================================
# Capture logcat for sensitive data
adb logcat | grep -iE "(password|token|key|secret|bearer|session)" &
# Exercise the app, then check output

# Check backup flag
aapt dump badging target.apk | grep -i "allowBackup"
# If allowBackup=true:
adb backup -f backup.ab com.target.app
java -jar abe.jar unpack backup.ab backup.tar
tar xf backup.tar

# Check for sensitive data in logs
adb logcat -d | grep -i com.target.app | grep -iE "(token|pass|key|auth|session|credit|ssn)"

# ============================================================
# 11. INTENT SNIFFING / CLIPBOARD
# ============================================================
# Monitor intents
adb shell dumpsys activity broadcasts | grep com.target.app

# Monitor clipboard
objection -g com.target.app explore -c "android clipboard monitor"

# ============================================================
# 12. TAPJACKING / OVERLAY ATTACK
# ============================================================
# Check if app protects against tapjacking
grep -rnE "filterTouchesWhenObscured|FLAG_WINDOW_IS_OBSCURED" target_src/

# ============================================================
# REPORT TEMPLATE (findings per section)
# ============================================================
# For each finding:
#   - Vulnerability title
#   - OWASP Mobile Top 10 mapping (M1-M10)
#   - CVSS score
#   - Steps to reproduce
#   - Evidence (screenshot / log output)
#   - Impact
#   - Remediation
