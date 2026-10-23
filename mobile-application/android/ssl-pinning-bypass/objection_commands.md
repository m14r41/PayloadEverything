# Objection Commands — Android VAPT Quick Reference
# Start: objection -g com.target.app explore
# With spawn: objection -g com.target.app explore --startup-command "android sslpinning disable"

# ============================================================
# SSL Pinning
# ============================================================
android sslpinning disable
# Disables SSL pinning by hooking TrustManager, OkHttp, etc.

# ============================================================
# Root Detection
# ============================================================
android root disable
android root simulate
# Disables common root detection checks

# ============================================================
# Storage / Data
# ============================================================
env
# Show app data directories, cache, external storage paths

android keystore list
android keystore clear
# List and clear Android KeyStore entries

android clipboard monitor
# Monitor clipboard for sensitive data

# SharedPreferences
sqlite connect /data/data/com.target.app/shared_prefs/
ls /data/data/com.target.app/shared_prefs/
android hooking watch class android.app.SharedPreferencesImpl

# SQLite databases
sqlite connect /data/data/com.target.app/databases/app.db
.tables
select * from users;

# ============================================================
# Activity / Intent Abuse
# ============================================================
android intent launch_activity com.target.app.admin.AdminActivity
# Launch exported or non-exported activities

android hooking list activities
android hooking list services
android hooking list receivers
# Enumerate components

# ============================================================
# Hooking / Tracing
# ============================================================
android hooking list classes
# List all loaded classes

android hooking search classes auth
android hooking search classes login
android hooking search classes crypto
android hooking search classes password
# Search for interesting classes

android hooking list class_methods com.target.app.auth.LoginManager
# List methods of a class

android hooking watch class com.target.app.auth.LoginManager
# Watch all methods of a class (log args + return values)

android hooking watch class_method com.target.app.auth.LoginManager.validatePassword --dump-args --dump-return
# Watch specific method with full output

android hooking set return_value com.target.app.auth.LoginManager.isLoggedIn true
# Force a method to return a specific value

# ============================================================
# File System
# ============================================================
ls /data/data/com.target.app/
file download /data/data/com.target.app/databases/app.db ./app.db
file download /data/data/com.target.app/shared_prefs/config.xml ./config.xml
file upload ./payload.so /data/data/com.target.app/lib/

# ============================================================
# Memory
# ============================================================
memory list modules
memory search "password" --string
memory dump all dump.bin
# Search and dump process memory

# ============================================================
# Crypto Hooks
# ============================================================
android hooking watch class javax.crypto.Cipher --dump-args
android hooking watch class javax.crypto.spec.SecretKeySpec --dump-args
android hooking watch class java.security.MessageDigest --dump-args
# Monitor all crypto operations

# ============================================================
# Bypass Biometrics
# ============================================================
android hooking watch class android.hardware.fingerprint.FingerprintManager --dump-args
android hooking watch class androidx.biometric.BiometricPrompt --dump-args

# ============================================================
# Jobs Management
# ============================================================
jobs list
jobs kill <id>
# Manage running hooks
