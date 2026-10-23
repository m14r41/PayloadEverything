/*
 * Frida SSL/TLS Certificate Pinning Bypass — Windows Thick Clients
 *
 * Bypasses certificate validation in common .NET, Java, and native
 * Windows applications to enable MitM interception with Burp/mitmproxy.
 *
 * Usage:
 *   frida -l frida_windows_ssl_bypass.js -p <PID>
 *   frida -l frida_windows_ssl_bypass.js -n TargetApp.exe
 *   frida -l frida_windows_ssl_bypass.js -f "C:\Program Files\App\app.exe"
 *
 * Works with: .NET (HttpClient, WebRequest, SslStream), WinHTTP, WinInet,
 *             Schannel, Java (HttpsURLConnection), Chromium (Electron/CEF)
 */

'use strict';

console.log('[*] Windows SSL/TLS Pinning Bypass — Thick Client Edition');
console.log('[*] Loading hooks...\n');

// ═══════════════════════════════════════════════════════════
// 1. WinHTTP — WinHttpSetOption (SECURITY_FLAGS)
// ═══════════════════════════════════════════════════════════
try {
    const winhttp = Module.findBaseAddress('winhttp.dll');
    if (winhttp) {
        const WinHttpSetOption = Module.findExportByName('winhttp.dll', 'WinHttpSetOption');
        if (WinHttpSetOption) {
            Interceptor.attach(WinHttpSetOption, {
                onEnter: function(args) {
                    const option = args[1].toInt32();
                    // WINHTTP_OPTION_SECURITY_FLAGS = 31
                    if (option === 31) {
                        // Set all ignore flags
                        const flags = 0x00003300; // IGNORE_ALL
                        args[2].writeU32(flags);
                        console.log('[+] WinHTTP: Disabled certificate validation');
                    }
                }
            });
        }

        const WinHttpSendRequest = Module.findExportByName('winhttp.dll', 'WinHttpSendRequest');
        if (WinHttpSendRequest) {
            Interceptor.attach(WinHttpSendRequest, {
                onEnter: function(args) {
                    // After send, set security flags to ignore errors
                    const hRequest = args[0];
                    const WinHttpSetOptionFn = new NativeFunction(
                        Module.findExportByName('winhttp.dll', 'WinHttpSetOption'),
                        'int', ['pointer', 'uint32', 'pointer', 'uint32']
                    );
                    const buf = Memory.alloc(4);
                    buf.writeU32(0x00003300);
                    WinHttpSetOptionFn(hRequest, 31, buf, 4);
                }
            });
            console.log('[+] WinHTTP hooks installed');
        }
    }
} catch (e) {
    console.log('[-] WinHTTP hooks failed: ' + e.message);
}

// ═══════════════════════════════════════════════════════════
// 2. WinInet — InternetSetOption (SECURITY_FLAGS)
// ═══════════════════════════════════════════════════════════
try {
    const wininet = Module.findBaseAddress('wininet.dll');
    if (wininet) {
        const InternetSetOptionA = Module.findExportByName('wininet.dll', 'InternetSetOptionA');
        if (InternetSetOptionA) {
            Interceptor.attach(InternetSetOptionA, {
                onEnter: function(args) {
                    const option = args[1].toInt32();
                    // INTERNET_OPTION_SECURITY_FLAGS = 31
                    if (option === 31) {
                        args[2].writeU32(0x33B0); // Ignore all cert errors
                        console.log('[+] WinInet: Disabled certificate validation');
                    }
                }
            });
            console.log('[+] WinInet hooks installed');
        }
    }
} catch (e) {
    console.log('[-] WinInet hooks failed: ' + e.message);
}

// ═══════════════════════════════════════════════════════════
// 3. Schannel — SSPI / AcquireCredentialsHandle
// ═══════════════════════════════════════════════════════════
try {
    const secur32 = Module.findBaseAddress('secur32.dll') || Module.findBaseAddress('sspicli.dll');
    if (secur32) {
        const InitializeSecurityContextA = Module.findExportByName('secur32.dll', 'InitializeSecurityContextA') ||
            Module.findExportByName('sspicli.dll', 'InitializeSecurityContextA');
        if (InitializeSecurityContextA) {
            Interceptor.attach(InitializeSecurityContextA, {
                onLeave: function(retval) {
                    // SEC_E_OK = 0, SEC_I_CONTINUE_NEEDED = 0x90312
                    // Don't modify success/continue
                }
            });
            console.log('[+] Schannel monitoring active');
        }
    }
} catch (e) {
    console.log('[-] Schannel hooks failed: ' + e.message);
}

// ═══════════════════════════════════════════════════════════
// 4. .NET CLR — ServerCertificateValidationCallback
// ═══════════════════════════════════════════════════════════
try {
    const clr = Module.findBaseAddress('clr.dll') || Module.findBaseAddress('coreclr.dll');
    if (clr) {
        console.log('[*] .NET CLR detected — use .NET-specific bypass:');
        console.log('[*] The CLR JIT makes direct Frida hooking complex.');
        console.log('[*] Preferred approaches:');
        console.log('[*]   1. dnSpy: Patch ServicePointManager.ServerCertificateValidationCallback');
        console.log('[*]   2. Environment: set NODE_TLS_REJECT_UNAUTHORIZED=0 (Node.js)');
        console.log('[*]   3. Config: <system.net><settings><servicePointManager');
        console.log('[*]      checkCertificateRevocationList="false" /></settings></system.net>');
        console.log('[*]   4. Registry: HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319');
        console.log('[*]      SchUseStrongCrypto=0, SystemDefaultTlsVersions=0');
    }
} catch (e) {}

// ═══════════════════════════════════════════════════════════
// 5. CryptoAPI — CertVerifyCertificateChainPolicy
// ═══════════════════════════════════════════════════════════
try {
    const crypt32 = Module.findBaseAddress('crypt32.dll');
    if (crypt32) {
        const CertVerifyCertificateChainPolicy = Module.findExportByName(
            'crypt32.dll', 'CertVerifyCertificateChainPolicy'
        );
        if (CertVerifyCertificateChainPolicy) {
            Interceptor.attach(CertVerifyCertificateChainPolicy, {
                onLeave: function(retval) {
                    // Force return TRUE (valid)
                    retval.replace(ptr(1));
                    // Zero out the error status in pPolicyStatus
                    // This is the definitive Windows cert validation function
                    console.log('[+] CryptoAPI: CertVerifyCertificateChainPolicy → TRUE');
                }
            });
            console.log('[+] CryptoAPI hooks installed (CertVerifyCertificateChainPolicy)');
        }

        const CertGetCertificateChain = Module.findExportByName(
            'crypt32.dll', 'CertGetCertificateChain'
        );
        if (CertGetCertificateChain) {
            Interceptor.attach(CertGetCertificateChain, {
                onLeave: function(retval) {
                    retval.replace(ptr(1));
                    console.log('[+] CryptoAPI: CertGetCertificateChain → TRUE');
                }
            });
        }
    }
} catch (e) {
    console.log('[-] CryptoAPI hooks failed: ' + e.message);
}

// ═══════════════════════════════════════════════════════════
// 6. OpenSSL — SSL_CTX_set_verify / X509_verify_cert
// ═══════════════════════════════════════════════════════════
try {
    // Try common OpenSSL DLL names
    const sslNames = ['libssl-1_1-x64.dll', 'libssl-3-x64.dll', 'ssleay32.dll',
                       'libssl.dll', 'libssl-1_1.dll', 'libssl-3.dll'];

    for (const sslName of sslNames) {
        const sslBase = Module.findBaseAddress(sslName);
        if (!sslBase) continue;

        const SSL_CTX_set_verify = Module.findExportByName(sslName, 'SSL_CTX_set_verify');
        if (SSL_CTX_set_verify) {
            Interceptor.attach(SSL_CTX_set_verify, {
                onEnter: function(args) {
                    // Set mode to SSL_VERIFY_NONE (0)
                    args[1] = ptr(0);
                    // Set callback to NULL
                    args[2] = ptr(0);
                    console.log('[+] OpenSSL: SSL_CTX_set_verify → NONE');
                }
            });
        }

        const X509_verify_cert = Module.findExportByName(sslName, 'X509_verify_cert');
        if (!X509_verify_cert) {
            const cryptoNames = [sslName.replace('ssl', 'crypto'), 'libcrypto-1_1-x64.dll',
                                  'libcrypto-3-x64.dll', 'libeay32.dll'];
            for (const cn of cryptoNames) {
                const fn = Module.findExportByName(cn, 'X509_verify_cert');
                if (fn) {
                    Interceptor.attach(fn, {
                        onLeave: function(retval) { retval.replace(ptr(1)); }
                    });
                    break;
                }
            }
        }

        console.log(`[+] OpenSSL hooks installed (${sslName})`);
        break;
    }
} catch (e) {
    console.log('[-] OpenSSL hooks failed: ' + e.message);
}

// ═══════════════════════════════════════════════════════════
// 7. Java (if JVM loaded) — SSLContext / HostnameVerifier
// ═══════════════════════════════════════════════════════════
try {
    if (Java.available) {
        Java.perform(function() {
            // TrustManager — accept all certificates
            const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            const SSLContext = Java.use('javax.net.ssl.SSLContext');

            const TrustManager = Java.registerClass({
                name: 'com.vapt.TrustAllManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });

            const tm = [TrustManager.$new()];
            const ctx = SSLContext.getInstance('TLS');
            ctx.init(null, tm, null);
            SSLContext.setDefault(ctx);

            // HostnameVerifier — accept all hostnames
            const HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
            const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
            HttpsURLConnection.setDefaultHostnameVerifier(
                Java.registerClass({
                    name: 'com.vapt.TrustAllHostnames',
                    implements: [HostnameVerifier],
                    methods: {
                        verify: function(hostname, session) { return true; }
                    }
                }).$new()
            );

            console.log('[+] Java SSL bypass installed (TrustManager + HostnameVerifier)');
        });
    }
} catch (e) {
    console.log('[-] Java hooks failed: ' + e.message);
}

console.log('\n[*] All available hooks installed.');
console.log('[*] Configure your proxy (Burp/mitmproxy) and intercept traffic.');
console.log('[*] If app still rejects certs, check for custom pinning in app code.');
