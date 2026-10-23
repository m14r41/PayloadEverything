/*
 * Universal Android SSL Pinning Bypass — Frida Script
 *
 * Usage:
 *   frida -U -l universal_ssl_bypass.js -f com.target.app --no-pause
 *   frida -U -l universal_ssl_bypass.js -n "Target App"
 *
 * Bypasses:
 *   - OkHttp3 CertificatePinner
 *   - Custom X509TrustManager
 *   - HttpsURLConnection default SSLContext
 *   - WebViewClient SSL errors
 *   - Apache HttpClient (legacy)
 *   - Retrofit (via OkHttp)
 *   - Volley (via HurlStack / TrustManager)
 *   - Conscrypt / BoringSSL provider
 *   - Network Security Config runtime override
 */

Java.perform(function () {
    var TAG = "[SSL-Bypass]";

    // ============================================================
    // 1. TrustManager — Bypass custom X509TrustManager
    //    Covers: most apps with custom cert validation
    // ============================================================
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        var TrustManagerImpl = Java.registerClass({
            name: "com.vapt.TrustAllManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) { },
                checkServerTrusted: function (chain, authType) { },
                getAcceptedIssuers: function () { return []; }
            }
        });

        var TrustManagers = [TrustManagerImpl.$new()];
        var sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(null, TrustManagers, null);
        SSLContext.getInstance.overload("java.lang.String").implementation = function (protocol) {
            var ctx = this.getInstance(protocol);
            ctx.init(null, TrustManagers, null);
            return ctx;
        };
        console.log(TAG + " TrustManager bypass loaded");
    } catch (e) {
        console.log(TAG + " TrustManager hook error: " + e);
    }

    // ============================================================
    // 2. OkHttp3 CertificatePinner
    //    Covers: OkHttp3, Retrofit2
    // ============================================================
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCertificates) {
            console.log(TAG + " OkHttp3 pin bypassed for: " + hostname);
        };
    } catch (e) { }

    // OkHttp3 CertificatePinner$check$okhttp (Kotlin variant)
    try {
        var CertificatePinner2 = Java.use("okhttp3.CertificatePinner");
        CertificatePinner2["check$okhttp"].implementation = function (hostname, fn) {
            console.log(TAG + " OkHttp3 Kotlin pin bypassed for: " + hostname);
        };
    } catch (e) { }

    // OkHttp3 legacy overload
    try {
        var CertPinner3 = Java.use("okhttp3.CertificatePinner");
        CertPinner3.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function (hostname, certs) {
            console.log(TAG + " OkHttp3 legacy pin bypassed for: " + hostname);
        };
    } catch (e) { }

    // ============================================================
    // 3. OkHttp (v2.x) CertificatePinner
    // ============================================================
    try {
        var OkHttp2Pinner = Java.use("com.squareup.okhttp.CertificatePinner");
        OkHttp2Pinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCerts) {
            console.log(TAG + " OkHttp2 pin bypassed for: " + hostname);
        };
    } catch (e) { }

    // ============================================================
    // 4. HttpsURLConnection — Default SSLSocketFactory
    //    Covers: apps using java.net.HttpsURLConnection
    // ============================================================
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultSSLSocketFactory.implementation = function (factory) {
            console.log(TAG + " HttpsURLConnection setDefaultSSLSocketFactory intercepted");
            var sslCtx = Java.use("javax.net.ssl.SSLContext").getInstance("TLS");
            var TrustAllManager = Java.registerClass({
                name: "com.vapt.TrustAllManager2",
                implements: [Java.use("javax.net.ssl.X509TrustManager")],
                methods: {
                    checkClientTrusted: function (chain, authType) { },
                    checkServerTrusted: function (chain, authType) { },
                    getAcceptedIssuers: function () { return []; }
                }
            });
            sslCtx.init(null, [TrustAllManager.$new()], null);
            this.setDefaultSSLSocketFactory(sslCtx.getSocketFactory());
        };
        HttpsURLConnection.setSSLSocketFactory.implementation = function (factory) {
            console.log(TAG + " HttpsURLConnection setSSLSocketFactory intercepted");
        };
    } catch (e) { }

    // Bypass hostname verifier
    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HttpsURLConnection");
        HostnameVerifier.setDefaultHostnameVerifier.implementation = function (verifier) {
            console.log(TAG + " Hostname verifier bypassed");
        };
        HostnameVerifier.setHostnameVerifier.implementation = function (verifier) {
            console.log(TAG + " Instance hostname verifier bypassed");
        };
    } catch (e) { }

    // ============================================================
    // 5. WebViewClient — Accept all SSL errors
    //    Covers: Hybrid apps, in-app browsers
    // ============================================================
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            console.log(TAG + " WebView SSL error bypassed: " + error.toString());
            handler.proceed();
        };
    } catch (e) { }

    // ============================================================
    // 6. Apache HttpClient (legacy, Android < 6)
    //    Covers: apps using org.apache.http
    // ============================================================
    try {
        var AbstractVerifier = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
        AbstractVerifier.verify.overload("java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;", "boolean").implementation = function (host, cns, subjectAlts, strictMode) {
            console.log(TAG + " Apache HttpClient verify bypassed for: " + host);
        };
    } catch (e) { }

    // ============================================================
    // 7. Conscrypt / BoringSSL TrustManager
    //    Covers: apps using Google's Conscrypt provider
    // ============================================================
    try {
        var ConscryptTrustManager = Java.use("com.google.android.gms.org.conscrypt.Platform");
        ConscryptTrustManager.checkServerTrusted.implementation = function (chain, authType, engine) {
            console.log(TAG + " Conscrypt checkServerTrusted bypassed");
        };
    } catch (e) { }

    try {
        var PlatformImpl = Java.use("org.conscrypt.Platform");
        PlatformImpl.checkServerTrusted.overload("javax.net.ssl.X509ExtendedTrustManager", "[Ljava.security.cert.X509Certificate;", "java.lang.String", "org.conscrypt.AbstractConscryptSocket").implementation = function (tm, chain, authType, socket) {
            console.log(TAG + " Conscrypt platform check bypassed");
        };
    } catch (e) { }

    // ============================================================
    // 8. Network Security Config — Runtime override
    //    Covers: Android 7+ network_security_config.xml
    // ============================================================
    try {
        var NetworkSecurityConfig = Java.use("android.security.net.config.NetworkSecurityConfig");
        NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function () {
            console.log(TAG + " Cleartext traffic permitted (NSC override)");
            return true;
        };
    } catch (e) { }

    try {
        var ManifestConfig = Java.use("android.security.net.config.ManifestConfigSource$DefaultConfigSource");
        ManifestConfig.getDefaultConfig.implementation = function () {
            console.log(TAG + " NSC default config overridden");
            return this.getDefaultConfig();
        };
    } catch (e) { }

    // ============================================================
    // 9. TrustManagerImpl (Android system class)
    //    Covers: System-level certificate validation
    // ============================================================
    try {
        var TrustManagerImplSys = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImplSys.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log(TAG + " TrustManagerImpl.verifyChain bypassed for: " + host);
            return untrustedChain;
        };
    } catch (e) { }

    // ============================================================
    // 10. Flutter / Dart SSL Bypass (common in modern apps)
    // ============================================================
    try {
        var module = Process.findModuleByName("libflutter.so");
        if (module) {
            var ssl_verify_func = Module.findExportByName("libflutter.so", "ssl_crypto_x509_session_verify_cert_chain");
            if (ssl_verify_func) {
                Interceptor.attach(ssl_verify_func, {
                    onLeave: function (retval) {
                        retval.replace(0x1);
                        console.log(TAG + " Flutter SSL verify bypassed");
                    }
                });
            }
            // Alternative: patch ssl_verify_peer_cert
            var pattern = "FF C3 20 19"; // arm64 pattern for handshake verification return
            Memory.scan(module.base, module.size, pattern, {
                onMatch: function (address, size) {
                    console.log(TAG + " Flutter pattern found at: " + address);
                }
            });
        }
    } catch (e) { }

    console.log(TAG + " === SSL Pinning Bypass Active ===");
});
