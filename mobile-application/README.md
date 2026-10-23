# Mobile Application Security Payloads

Frida scripts, bypass tools, and testing checklists for Android and iOS VAPT engagements, mapped to the [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/).

## Directory Structure

| Folder | File | Description |
|--------|------|-------------|
| | [`setup_guide.md`](setup_guide.md) | Complete environment setup (Frida, objection, Burp, ADB) |
| [android/](android/) | | |
| | [`universal_ssl_bypass.js`](android/ssl-pinning-bypass/universal_ssl_bypass.js) | 10-method Frida SSL bypass (OkHttp3, TrustManager, Conscrypt, Flutter...) |
| | [`objection_commands.md`](android/ssl-pinning-bypass/objection_commands.md) | Full objection command reference |
| | [`root_bypass.js`](android/root-detection-bypass/root_bypass.js) | 9-section bypass (File.exists, RootBeer, SafetyNet, native hooks) |
| | [`extract_storage.js`](android/local-storage/extract_storage.js) | SharedPreferences, SQLite, FileI/O, KeyStore, AccountManager hooks |
| | [`exported_components.sh`](android/intent-abuse/exported_components.sh) | Component enumeration, intent injection, content provider abuse, drozer |
| | [`method_tracer.js`](android/frida-scripts/method_tracer.js) | Crypto, HTTP, WebView, JSON, Base64, Log tracer |
| | [`bypass_biometric.js`](android/frida-scripts/bypass_biometric.js) | BiometricPrompt, FingerprintManager, KeyguardManager bypass |
| | [`android_checklist.md`](android/testing-steps/android_checklist.md) | 12-section checklist with commands |
| [ios/](ios/) | | |
| | [`ios_ssl_bypass.js`](ios/ssl-pinning-bypass/ios_ssl_bypass.js) | 9-method bypass (NSURLSession, AFNetworking, Alamofire, TrustKit, BoringSSL) |
| | [`jailbreak_bypass.js`](ios/jailbreak-detection-bypass/jailbreak_bypass.js) | 12-section bypass (file checks, canOpenURL, fork, stat, IOSSecuritySuite, dyld) |
| | [`dump_keychain.js`](ios/keychain-extraction/dump_keychain.js) | SecItemCopyMatching/Add/Update/Delete hooks + full keychain dump |
| | [`ios_storage_dump.js`](ios/local-storage/ios_storage_dump.js) | NSUserDefaults, CoreData, plist, clipboard, SQLite, cookies hooks |
| | [`ios_crypto_hooks.js`](ios/frida-scripts/ios_crypto_hooks.js) | CCCrypt, CCHmac, CC_SHA*, SecKey, CryptoKit, SecRandom hooks |
| | [`ios_checklist.md`](ios/testing-steps/ios_checklist.md) | 12-section checklist with commands |

## OWASP Mobile Top 10 Mapping

| # | Vulnerability | Android Scripts | iOS Scripts |
|---|--------------|----------------|-------------|
| M1 | Improper Credential Usage | [`extract_storage.js`](android/local-storage/extract_storage.js) | [`dump_keychain.js`](ios/keychain-extraction/dump_keychain.js), [`ios_storage_dump.js`](ios/local-storage/ios_storage_dump.js) |
| M2 | Inadequate Supply Chain Security | [`android_checklist.md`](android/testing-steps/android_checklist.md) | [`ios_checklist.md`](ios/testing-steps/ios_checklist.md) |
| M3 | Insecure Authentication/Authorization | [`bypass_biometric.js`](android/frida-scripts/bypass_biometric.js), [`exported_components.sh`](android/intent-abuse/exported_components.sh) | [`jailbreak_bypass.js`](ios/jailbreak-detection-bypass/jailbreak_bypass.js) |
| M4 | Insufficient Input/Output Validation | [`exported_components.sh`](android/intent-abuse/exported_components.sh) | [`ios_checklist.md`](ios/testing-steps/ios_checklist.md) |
| M5 | Insecure Communication | [`universal_ssl_bypass.js`](android/ssl-pinning-bypass/universal_ssl_bypass.js) | [`ios_ssl_bypass.js`](ios/ssl-pinning-bypass/ios_ssl_bypass.js) |
| M6 | Inadequate Privacy Controls | [`extract_storage.js`](android/local-storage/extract_storage.js), [`method_tracer.js`](android/frida-scripts/method_tracer.js) | [`ios_storage_dump.js`](ios/local-storage/ios_storage_dump.js) |
| M7 | Insufficient Binary Protections | [`root_bypass.js`](android/root-detection-bypass/root_bypass.js) | [`jailbreak_bypass.js`](ios/jailbreak-detection-bypass/jailbreak_bypass.js) |
| M8 | Security Misconfiguration | [`exported_components.sh`](android/intent-abuse/exported_components.sh) | [`ios_checklist.md`](ios/testing-steps/ios_checklist.md) |
| M9 | Insecure Data Storage | [`extract_storage.js`](android/local-storage/extract_storage.js) | [`dump_keychain.js`](ios/keychain-extraction/dump_keychain.js), [`ios_storage_dump.js`](ios/local-storage/ios_storage_dump.js) |
| M10 | Insufficient Cryptography | [`method_tracer.js`](android/frida-scripts/method_tracer.js) | [`ios_crypto_hooks.js`](ios/frida-scripts/ios_crypto_hooks.js) |

## Quick Start

```bash
# Android — SSL bypass + root bypass + intercept traffic
frida -U -l android/ssl-pinning-bypass/universal_ssl_bypass.js -f com.target.app --no-pause
frida -U -l android/root-detection-bypass/root_bypass.js -f com.target.app --no-pause

# iOS — SSL bypass + jailbreak bypass
frida -U -l ios/ssl-pinning-bypass/ios_ssl_bypass.js -f com.target.app --no-pause
frida -U -l ios/jailbreak-detection-bypass/jailbreak_bypass.js -f com.target.app --no-pause

# Full setup instructions
cat setup_guide.md
```

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| Frida | Dynamic instrumentation | `pip install frida-tools` |
| Objection | Runtime exploration | `pip install objection` |
| Burp Suite | HTTP proxy | burpsuite.net |
| ADB | Android debugging | Android SDK |
| JADX | Java decompilation | github.com/skylot/jadx |
| class-dump | ObjC header extraction | Via Homebrew or Cydia |
