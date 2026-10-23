# iOS Application Security Payloads

Frida scripts and checklists for iOS VAPT engagements.

## Payload Files

| Category | File | Description |
|----------|------|-------------|
| SSL Pinning Bypass | [`ios_ssl_bypass.js`](ssl-pinning-bypass/ios_ssl_bypass.js) | 9-method Frida bypass: NSURLSession, NSURLConnection, AFNetworking (v2/v3), Alamofire/ServerTrustManager, TrustKit, WKWebView, SecTrust (Evaluate/EvaluateWithError), BoringSSL, Flutter iOS |
| Jailbreak Detection Bypass | [`jailbreak_bypass.js`](jailbreak-detection-bypass/jailbreak_bypass.js) | 12-section bypass: NSFileManager (50+ paths), canOpenURL (cydia/sileo/zbra/filza), fork(), system(), stat/lstat/access, fopen, sandbox write test, IOSSecuritySuite (10 methods), dlopen/dlsym, dyld image list, DYLD_INSERT_LIBRARIES, sysctl P_TRACED |
| Keychain Extraction | [`dump_keychain.js`](keychain-extraction/dump_keychain.js) | SecItemCopyMatching/Add/Update/Delete hooks with full dict dumping, hex+UTF8 decode, protection class logging, delayed full keychain enumeration (GenericPassword, InternetPassword, Certificate, Key, Identity) |
| Local Storage | [`ios_storage_dump.js`](local-storage/ios_storage_dump.js) | NSUserDefaults read/write, NSFileManager operations, CoreData fetch/save, plist/NSKeyedArchiver write, UIPasteboard clipboard monitoring, native SQLite (open/exec/prepare), NSURLCache, NSHTTPCookieStorage |
| Crypto Hooks | [`ios_crypto_hooks.js`](frida-scripts/ios_crypto_hooks.js) | CCCrypt (AES/DES/3DES/RC4/Blowfish with key+IV+data logging), CCHmac, CC_SHA256/SHA1/MD5/SHA512, SecKeyCreateSignature/Encrypt/Decrypt, SecRandomCopyBytes, CryptoKit (AES.GCM, ChaChaPoly) |
| Testing Steps | [`ios_checklist.md`](testing-steps/ios_checklist.md) | 12-section checklist: SSL, jailbreak, storage, binary analysis, network, crypto, IPC/URL schemes, biometric, runtime manipulation, logging/screenshots, third-party libs, data protection |

## OWASP Mobile Top 10 Mapping

| OWASP # | Vulnerability | Covered By |
|---------|--------------|------------|
| M1 | Improper Credential Usage | [`dump_keychain.js`](keychain-extraction/dump_keychain.js), [`ios_storage_dump.js`](local-storage/ios_storage_dump.js) |
| M3 | Insecure Authentication/Authorization | [`jailbreak_bypass.js`](jailbreak-detection-bypass/jailbreak_bypass.js) |
| M5 | Insecure Communication | [`ios_ssl_bypass.js`](ssl-pinning-bypass/ios_ssl_bypass.js) |
| M7 | Insufficient Binary Protections | [`jailbreak_bypass.js`](jailbreak-detection-bypass/jailbreak_bypass.js) |
| M9 | Insecure Data Storage | [`dump_keychain.js`](keychain-extraction/dump_keychain.js), [`ios_storage_dump.js`](local-storage/ios_storage_dump.js) |
| M10 | Insufficient Cryptography | [`ios_crypto_hooks.js`](frida-scripts/ios_crypto_hooks.js) |

## Quick Start

```bash
# Bypass SSL + jailbreak detection
frida -U -l ssl-pinning-bypass/ios_ssl_bypass.js -f com.target.app --no-pause
frida -U -l jailbreak-detection-bypass/jailbreak_bypass.js -f com.target.app --no-pause

# Dump keychain
frida -U -l keychain-extraction/dump_keychain.js -f com.target.app --no-pause

# Full storage extraction
frida -U -l local-storage/ios_storage_dump.js -f com.target.app --no-pause

# Trace all crypto operations
frida -U -l frida-scripts/ios_crypto_hooks.js -f com.target.app --no-pause
```
