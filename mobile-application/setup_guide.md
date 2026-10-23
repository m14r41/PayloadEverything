# Mobile VAPT Environment Setup Guide
# Tools, configuration, and workflow for Android & iOS testing

# ============================================================
# 1. FRIDA — Dynamic Instrumentation Framework
# ============================================================
# Install Frida (host)
pip install frida-tools

# Install Frida server on Android
#   Download from: https://github.com/frida/frida/releases
#   Match architecture: frida-server-<version>-android-<arch>
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# Install Frida on iOS (jailbroken)
#   Add repo: https://build.frida.re
#   Install: Frida from Cydia/Sileo

# Verify connection
frida-ls-devices
frida-ps -U                    # List running processes
frida-ps -Ua                   # List running apps
frida-ps -Uai                  # List all installed apps

# Common Frida commands
frida -U -l script.js -f com.target.app --no-pause    # Spawn and inject
frida -U -l script.js -n "App Name"                    # Attach to running
frida -U -l script.js --realm=emulated -f com.app      # Emulator

# ============================================================
# 2. OBJECTION — Runtime Mobile Exploration
# ============================================================
# Install
pip install objection

# Usage
objection -g com.target.app explore
objection -g com.target.app explore --startup-command "android sslpinning disable"
objection patchapk --source target.apk    # Patch APK with Frida gadget (no root)

# Key commands inside objection
# env                                      — App paths
# android sslpinning disable              — Bypass SSL pinning
# android root disable                    — Bypass root detection
# ios sslpinning disable                  — iOS SSL bypass
# ios jailbreak disable                   — iOS jailbreak bypass
# android/ios hooking list classes         — List classes
# android/ios hooking search classes auth  — Search classes
# sqlite connect <path>                   — Open SQLite DB
# memory search "password"                — Search memory

# ============================================================
# 3. BURP SUITE — HTTP/HTTPS Proxy
# ============================================================
# Android proxy setup:
#   1. Settings → Wi-Fi → Long press → Modify → Advanced → Manual proxy
#   2. Set host to your IP, port 8080
#   3. Install CA: http://burp on device browser → Download CA
#   4. Settings → Security → Install from storage → Select cacert.der
#
# Android system CA (root required, Android 7+):
openssl x509 -inform DER -in cacert.der -out cacert.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1)
cp cacert.pem ${HASH}.0
adb remount
adb push ${HASH}.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/${HASH}.0
adb reboot

# iOS proxy setup:
#   1. Settings → Wi-Fi → (i) → Configure Proxy → Manual
#   2. Set host to your IP, port 8080
#   3. Open http://burp → Download CA Certificate
#   4. Settings → Profile Downloaded → Install
#   5. Settings → General → About → Certificate Trust Settings → Enable

# ============================================================
# 4. ADB — Android Debug Bridge
# ============================================================
# Device connection
adb devices                     # List devices
adb connect <ip>:5555           # Connect wirelessly
adb -s <serial> shell           # Specific device

# App management
adb install target.apk
adb install -r target.apk       # Reinstall keeping data
adb uninstall com.target.app
adb shell pm list packages       # List all packages
adb shell pm path com.target.app # Get APK path

# Data access
adb shell run-as com.target.app ls   # Access app data (debug apps)
adb pull /data/data/com.target.app/  # Pull app data (root)

# Logcat
adb logcat | grep com.target.app
adb logcat -c                   # Clear log
adb logcat *:E                  # Errors only

# Intent testing
adb shell am start -n com.target.app/.MainActivity
adb shell am start -a android.intent.action.VIEW -d "scheme://host"

# ============================================================
# 5. ANDROID DECOMPILATION TOOLS
# ============================================================
# APKTool — Resource decompilation
pip install apktool
apktool d target.apk -o output_dir
apktool b output_dir -o modified.apk

# JADX — Java decompilation
# Download from: https://github.com/skylot/jadx/releases
jadx -d output_src target.apk
jadx-gui target.apk              # GUI mode

# Dex2Jar + JD-GUI
d2j-dex2jar target.apk
jd-gui target-dex2jar.jar

# Sign modified APK
keytool -genkey -v -keystore test.keystore -alias test -keyalg RSA -keysize 2048 -validity 10000
apksigner sign --ks test.keystore --ks-key-alias test modified.apk
# Or: jarsigner -keystore test.keystore modified.apk test

# ============================================================
# 6. iOS TOOLS (requires macOS + jailbroken device)
# ============================================================
# SSH to jailbroken device
ssh root@<device_ip>            # Default password: alpine

# Class-dump
class-dump /path/to/binary > classes.h

# Clutch — Decrypt IPAs
clutch -d com.target.app

# Cycript (older iOS)
cycript -p <pid>

# ios-deploy
ios-deploy --list               # List connected devices
ios-deploy --bundle target.app  # Install and launch

# ideviceinstaller (libimobiledevice)
ideviceinstaller -l             # List apps
idevicesyslog                   # System log

# ============================================================
# 7. NETWORK TOOLS
# ============================================================
# Proxifier / ProxyDroid (Android)
#   Route all traffic through proxy (not just HTTP)

# Wireshark
adb shell tcpdump -i any -w /sdcard/capture.pcap
adb pull /sdcard/capture.pcap
wireshark capture.pcap

# mitmproxy (alternative to Burp)
pip install mitmproxy
mitmproxy --listen-port 8080

# ============================================================
# 8. EMULATOR SETUP
# ============================================================
# Android (Genymotion recommended for root testing)
#   - Genymotion: https://www.genymotion.com/
#   - Android Studio emulator with Google APIs (no Play Store = root easier)
#   - ARM translation for x86 emulator if needed

# iOS Simulator (limited, no jailbreak testing)
#   - Xcode → Simulator (no real device features)
#   - Corellium (cloud-based jailbroken iOS): https://corellium.com/

# ============================================================
# 9. RECOMMENDED WORKFLOW
# ============================================================
# Android:
#   1. Install APK on rooted device/emulator
#   2. Start Frida server
#   3. Configure Burp proxy
#   4. Run SSL pinning bypass: frida -U -l universal_ssl_bypass.js -f com.target.app --no-pause
#   5. Run root detection bypass: frida -U -l root_bypass.js -f com.target.app --no-pause
#   6. Decompile with jadx and review source
#   7. Test each checklist item from android_checklist.txt
#   8. Extract storage: frida -U -l extract_storage.js -f com.target.app --no-pause
#   9. Test exported components: ./exported_components.sh com.target.app
#  10. Document findings

# iOS:
#   1. Install IPA on jailbroken device
#   2. Start Frida
#   3. Configure Burp proxy
#   4. Run SSL bypass: frida -U -l ios_ssl_bypass.js -f com.target.app --no-pause
#   5. Run jailbreak bypass: frida -U -l jailbreak_bypass.js -f com.target.app --no-pause
#   6. Dump classes: class-dump binary > classes.h
#   7. Extract keychain: frida -U -l dump_keychain.js -f com.target.app --no-pause
#   8. Test each checklist item from ios_checklist.txt
#   9. Extract storage: frida -U -l ios_storage_dump.js -f com.target.app --no-pause
#  10. Document findings
