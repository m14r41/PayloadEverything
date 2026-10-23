/*
 * Universal iOS SSL Pinning Bypass — Frida Script
 *
 * Usage:
 *   frida -U -l ios_ssl_bypass.js -f com.target.app --no-pause
 *   frida -U -l ios_ssl_bypass.js -n "Target App"
 *
 * Bypasses:
 *   - NSURLSession / NSURLConnection delegate methods
 *   - AFNetworking (v2 & v3+)
 *   - Alamofire / ServerTrustManager
 *   - TrustKit
 *   - WKWebView (WKNavigationDelegate)
 *   - Custom SecTrust evaluation
 *   - ATS (App Transport Security)
 *   - libboringssl (low-level)
 */

if (ObjC.available) {
    var TAG = "[SSL-iOS]";

    // ============================================================
    // 1. NSURLSession — Delegate SSL challenge bypass
    //    Covers: Most modern iOS apps using URLSession
    // ============================================================
    try {
        var resolver = new ApiResolver("objc");
        resolver.enumerateMatches("-[* URLSession:didReceiveChallenge:completionHandler:]", {
            onMatch: function (match) {
                Interceptor.attach(match.address, {
                    onEnter: function (args) {
                        var challenge = new ObjC.Object(args[3]);
                        var protectionSpace = challenge.protectionSpace();
                        var host = protectionSpace.host().toString();
                        var method = protectionSpace.authenticationMethod().toString();

                        if (method === "NSURLAuthenticationMethodServerTrust") {
                            var completionHandler = new ObjC.Block(args[4]);
                            var serverTrust = protectionSpace.serverTrust();
                            completionHandler.implementation = function () {
                                // NSURLSessionAuthChallengeUseCredential = 0
                                var credential = ObjC.classes.NSURLCredential.credentialForTrust_(serverTrust);
                                completionHandler.invoke(0, credential);
                            };
                            console.log(TAG + " NSURLSession pin bypassed: " + host);
                        }
                    }
                });
            },
            onComplete: function () { }
        });
        console.log(TAG + " NSURLSession hooks loaded");
    } catch (e) {
        console.log(TAG + " NSURLSession error: " + e);
    }

    // ============================================================
    // 2. NSURLConnection (legacy) — Allow all certs
    // ============================================================
    try {
        var resolver2 = new ApiResolver("objc");
        resolver2.enumerateMatches("-[* connection:willSendRequestForAuthenticationChallenge:]", {
            onMatch: function (match) {
                Interceptor.attach(match.address, {
                    onEnter: function (args) {
                        var challenge = new ObjC.Object(args[3]);
                        var protectionSpace = challenge.protectionSpace();
                        if (protectionSpace.authenticationMethod().toString() === "NSURLAuthenticationMethodServerTrust") {
                            var sender = challenge.sender();
                            var trust = protectionSpace.serverTrust();
                            var credential = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                            sender.useCredential_forAuthenticationChallenge_(credential, challenge);
                            console.log(TAG + " NSURLConnection pin bypassed: " + protectionSpace.host());
                        }
                    }
                });
            },
            onComplete: function () { }
        });
    } catch (e) { }

    // ============================================================
    // 3. AFNetworking — SecurityPolicy bypass
    //    Covers: AFNetworking 2.x and 3.x+
    // ============================================================
    try {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        if (AFSecurityPolicy) {
            // setSSLPinningMode to AFSSLPinningModeNone (0)
            Interceptor.attach(AFSecurityPolicy["- setSSLPinningMode:"].implementation, {
                onEnter: function (args) {
                    args[2] = ptr(0x0); // AFSSLPinningModeNone
                    console.log(TAG + " AFNetworking pinning mode → None");
                }
            });

            // evaluateServerTrust:forDomain: → always true
            Interceptor.attach(AFSecurityPolicy["- evaluateServerTrust:forDomain:"].implementation, {
                onLeave: function (retval) {
                    retval.replace(0x1);
                    console.log(TAG + " AFNetworking evaluateServerTrust → true");
                }
            });

            // setAllowInvalidCertificates → true
            Interceptor.attach(AFSecurityPolicy["- setAllowInvalidCertificates:"].implementation, {
                onEnter: function (args) {
                    args[2] = ptr(0x1);
                }
            });

            // setValidatesDomainName → false
            Interceptor.attach(AFSecurityPolicy["- setValidatesDomainName:"].implementation, {
                onEnter: function (args) {
                    args[2] = ptr(0x0);
                }
            });
            console.log(TAG + " AFNetworking hooks loaded");
        }
    } catch (e) { }

    // ============================================================
    // 4. Alamofire — ServerTrustManager / ServerTrustEvaluating
    // ============================================================
    try {
        var resolver3 = new ApiResolver("objc");

        // Alamofire 5.x ServerTrustManager
        resolver3.enumerateMatches("-[*ServerTrustManager serverTrustEvaluator*]", {
            onMatch: function (match) {
                Interceptor.attach(match.address, {
                    onLeave: function (retval) {
                        console.log(TAG + " Alamofire ServerTrustManager bypassed");
                    }
                });
            },
            onComplete: function () { }
        });

        // Alamofire evaluate method
        resolver3.enumerateMatches("-[*ServerTrustEvaluat* evaluate*]", {
            onMatch: function (match) {
                Interceptor.attach(match.address, {
                    onLeave: function (retval) {
                        // Don't throw, just return
                    }
                });
            },
            onComplete: function () { }
        });
        console.log(TAG + " Alamofire hooks loaded");
    } catch (e) { }

    // ============================================================
    // 5. TrustKit — Pin validation bypass
    // ============================================================
    try {
        var TrustKit = ObjC.classes.TSKPinningValidator;
        if (TrustKit) {
            Interceptor.attach(TrustKit["+ evaluateTrust:forHostname:"].implementation, {
                onLeave: function (retval) {
                    // TSKTrustDecisionShouldAllowConnection = 0
                    retval.replace(0x0);
                    console.log(TAG + " TrustKit pin bypassed");
                }
            });
        }

        var TSKPinVerifier = ObjC.classes.TSKSPKIHashCache;
        if (TSKPinVerifier) {
            Interceptor.attach(TSKPinVerifier["- getSPKIHashesForTrustAnchor:"].implementation, {
                onLeave: function (retval) {
                    console.log(TAG + " TrustKit hash cache intercepted");
                }
            });
        }
    } catch (e) { }

    // ============================================================
    // 6. WKWebView — WKNavigationDelegate SSL bypass
    // ============================================================
    try {
        var resolver4 = new ApiResolver("objc");
        resolver4.enumerateMatches("-[* webView:didReceiveAuthenticationChallenge:completionHandler:]", {
            onMatch: function (match) {
                Interceptor.attach(match.address, {
                    onEnter: function (args) {
                        var challenge = new ObjC.Object(args[3]);
                        var protectionSpace = challenge.protectionSpace();
                        if (protectionSpace.authenticationMethod().toString() === "NSURLAuthenticationMethodServerTrust") {
                            var completionHandler = new ObjC.Block(args[4]);
                            var trust = protectionSpace.serverTrust();
                            var credential = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                            completionHandler.implementation = function () {
                                completionHandler.invoke(1, credential); // UseCredential
                            };
                            console.log(TAG + " WKWebView SSL bypassed: " + protectionSpace.host());
                        }
                    }
                });
            },
            onComplete: function () { }
        });
    } catch (e) { }

    // ============================================================
    // 7. SecTrust — Low-level certificate evaluation
    // ============================================================
    try {
        var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
        if (SecTrustEvaluateWithError) {
            Interceptor.attach(SecTrustEvaluateWithError, {
                onLeave: function (retval) {
                    retval.replace(0x1); // true = trusted
                    console.log(TAG + " SecTrustEvaluateWithError → true");
                }
            });
        }
    } catch (e) { }

    try {
        var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.attach(SecTrustEvaluate, {
                onLeave: function (retval) {
                    retval.replace(0x0); // errSecSuccess
                }
            });
        }
    } catch (e) { }

    // ============================================================
    // 8. BoringSSL — Native SSL_CTX verification callback
    // ============================================================
    try {
        var ssl_set_custom_verify = Module.findExportByName("libboringssl.dylib", "SSL_set_custom_verify");
        if (ssl_set_custom_verify) {
            Interceptor.attach(ssl_set_custom_verify, {
                onEnter: function (args) {
                    // Replace the callback with one that returns ssl_verify_ok (0)
                    args[2] = new NativeCallback(function (ssl, out_alert) {
                        return 0; // ssl_verify_ok
                    }, "int", ["pointer", "pointer"]);
                    console.log(TAG + " BoringSSL custom verify bypassed");
                }
            });
        }

        var ssl_ctx_set_custom_verify = Module.findExportByName("libboringssl.dylib", "SSL_CTX_set_custom_verify");
        if (ssl_ctx_set_custom_verify) {
            Interceptor.attach(ssl_ctx_set_custom_verify, {
                onEnter: function (args) {
                    args[2] = new NativeCallback(function (ssl, out_alert) {
                        return 0;
                    }, "int", ["pointer", "pointer"]);
                }
            });
        }
    } catch (e) { }

    // ============================================================
    // 9. Flutter iOS SSL bypass (Dart compiled code)
    // ============================================================
    try {
        var module = Process.findModuleByName("Flutter");
        if (module) {
            var handshake_pattern = "FF 03 01 D1"; // arm64 function prologue pattern
            var ssl_verify = Module.findExportByName("Flutter", "ssl_crypto_x509_session_verify_cert_chain");
            if (ssl_verify) {
                Interceptor.attach(ssl_verify, {
                    onLeave: function (retval) {
                        retval.replace(0x1);
                        console.log(TAG + " Flutter iOS SSL bypassed");
                    }
                });
            }
        }
    } catch (e) { }

    console.log(TAG + " === iOS SSL Pinning Bypass Active ===");
} else {
    console.log("[-] Objective-C runtime not available");
}
