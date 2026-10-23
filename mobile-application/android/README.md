# Android Application Security Payloads

Frida scripts, shell tools, and checklists for Android VAPT engagements.

## Payload Files

| Category | File | Description |
|----------|------|-------------|
| SSL Pinning Bypass | [`universal_ssl_bypass.js`](ssl-pinning-bypass/universal_ssl_bypass.js) | 10-method Frida bypass: TrustManager, OkHttp3 (3 overloads), OkHttp2, HttpsURLConnection, WebViewClient, Apache HttpClient, Conscrypt (2 variants), Network Security Config, TrustManagerImpl, Flutter |
| SSL Pinning Bypass | [`objection_commands.md`](ssl-pinning-bypass/objection_commands.md) | Full objection command reference: SSL, root, storage, SQLite, hooking, memory, crypto, biometrics |
| Root Detection Bypass | [`root_bypass.js`](root-detection-bypass/root_bypass.js) | 9-section bypass: File.exists (35 paths), Runtime.exec, ProcessBuilder, Build.TAGS, SystemProperties, PackageManager (20+ packages), RootBeer (12 methods), native fopen/access, SafetyNet |
| Local Storage | [`extract_storage.js`](local-storage/extract_storage.js) | SharedPreferences read/write hooks, SQLite query logging, File I/O monitoring, KeyStore extraction, AccountManager hooks |
| Intent Abuse | [`exported_components.sh`](intent-abuse/exported_components.sh) | 10-section shell script: component enumeration, activity launch, service binding, broadcast injection, content provider SQLi/traversal, deep links, pending intents, StrandHogg, drozer |
| Frida Scripts | [`method_tracer.js`](frida-scripts/method_tracer.js) | Universal tracer: Cipher/SecretKeySpec/IvParameterSpec/MessageDigest/Mac, OkHttp requests, WebView URLs, JSONObject/Gson, Base64, android.util.Log |
| Frida Scripts | [`bypass_biometric.js`](frida-scripts/bypass_biometric.js) | BiometricPrompt (AndroidX + framework), FingerprintManager, BiometricManager, KeyguardManager, CryptoObject extraction, Samsung PASS |
| Testing Steps | [`android_checklist.md`](testing-steps/android_checklist.md) | 12-section checklist: SSL, root, storage, components, network, crypto, WebView, biometric, binary protections, logging, intents, tapjacking |

## OWASP Mobile Top 10 Mapping

| OWASP # | Vulnerability | Covered By |
|---------|--------------|------------|
| M1 | Improper Credential Usage | [`extract_storage.js`](local-storage/extract_storage.js), [`method_tracer.js`](frida-scripts/method_tracer.js) |
| M3 | Insecure Authentication/Authorization | [`bypass_biometric.js`](frida-scripts/bypass_biometric.js), [`exported_components.sh`](intent-abuse/exported_components.sh) |
| M5 | Insecure Communication | [`universal_ssl_bypass.js`](ssl-pinning-bypass/universal_ssl_bypass.js) |
| M7 | Insufficient Binary Protections | [`root_bypass.js`](root-detection-bypass/root_bypass.js) |
| M8 | Security Misconfiguration | [`exported_components.sh`](intent-abuse/exported_components.sh) |
| M9 | Insecure Data Storage | [`extract_storage.js`](local-storage/extract_storage.js) |
| M10 | Insufficient Cryptography | [`method_tracer.js`](frida-scripts/method_tracer.js) |

## Quick Start

```bash
# Start Frida server on device
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# Bypass SSL + root detection
frida -U -l ssl-pinning-bypass/universal_ssl_bypass.js -f com.target.app --no-pause
frida -U -l root-detection-bypass/root_bypass.js -f com.target.app --no-pause

# Full storage extraction
frida -U -l local-storage/extract_storage.js -f com.target.app --no-pause

# Exported component audit
chmod +x intent-abuse/exported_components.sh
./intent-abuse/exported_components.sh com.target.app
```
