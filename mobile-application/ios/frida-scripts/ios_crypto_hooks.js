/*
 * iOS Crypto Operation Hooks — Frida Script
 *
 * Usage:
 *   frida -U -l ios_crypto_hooks.js -f com.target.app --no-pause
 *
 * Hooks:
 *   - CommonCrypto (CCCrypt, CCHmac, CC_SHA*, CC_MD5)
 *   - Security framework (SecKey operations, ECDSA, RSA)
 *   - CryptoKit (AES.GCM, ChaChaPoly, SHA256, HMAC)
 *   - Random number generation (SecRandomCopyBytes, arc4random)
 */

var TAG = "[Crypto-iOS]";

// ============================================================
// 1. CCCrypt — AES/DES/3DES/RC4/Blowfish encrypt/decrypt
// ============================================================
try {
    var CCCrypt = Module.findExportByName("libSystem.B.dylib", "CCCrypt");
    if (CCCrypt) {
        Interceptor.attach(CCCrypt, {
            onEnter: function (args) {
                this.op = args[0].toInt32();       // 0=encrypt, 1=decrypt
                this.alg = args[1].toInt32();      // 0=AES, 1=DES, 2=3DES, 3=CAST, 4=RC4, 5=RC2, 6=Blowfish
                this.options = args[2].toInt32();   // 1=PKCS7, 2=ECB
                this.key = args[3];
                this.keyLen = args[4].toInt32();
                this.iv = args[5];
                this.dataIn = args[6];
                this.dataInLen = args[7].toInt32();
                this.dataOut = args[8];
                this.dataOutAvail = args[9].toInt32();
                this.dataOutMoved = args[10];

                var algNames = ["AES", "DES", "3DES", "CAST", "RC4", "RC2", "Blowfish"];
                var opNames = ["ENCRYPT", "DECRYPT"];
                var optStr = "";
                if (this.options & 1) optStr += "PKCS7 ";
                if (this.options & 2) optStr += "ECB ";
                if (!optStr) optStr = "CBC ";

                console.log(TAG + " CCCrypt " + opNames[this.op] + " " + (algNames[this.alg] || "ALG" + this.alg) +
                    " " + optStr + "keyLen=" + this.keyLen + " dataLen=" + this.dataInLen);
                console.log(TAG + "   Key: " + hexDump(this.key, this.keyLen));
                if (!this.iv.isNull()) {
                    console.log(TAG + "   IV:  " + hexDump(this.iv, 16));
                }
                console.log(TAG + "   In:  " + hexDump(this.dataIn, Math.min(this.dataInLen, 64)));
                tryUtf8(this.dataIn, this.dataInLen, "In");
            },
            onLeave: function (retval) {
                if (retval.toInt32() === 0) { // kCCSuccess
                    var outLen = this.dataOutMoved.readUInt();
                    console.log(TAG + "   Out: " + hexDump(this.dataOut, Math.min(outLen, 64)) + " (" + outLen + " bytes)");
                    tryUtf8(this.dataOut, outLen, "Out");
                } else {
                    console.log(TAG + "   CCCrypt FAILED: " + retval.toInt32());
                }
            }
        });
        console.log(TAG + " CCCrypt hook loaded");
    }
} catch (e) { console.log(TAG + " CCCrypt error: " + e); }

// ============================================================
// 2. CCHmac — HMAC computation
// ============================================================
try {
    var CCHmac = Module.findExportByName("libSystem.B.dylib", "CCHmac");
    if (CCHmac) {
        Interceptor.attach(CCHmac, {
            onEnter: function (args) {
                var alg = args[0].toInt32(); // 0=SHA1, 1=MD5, 2=SHA256, 3=SHA384, 4=SHA512, 5=SHA224
                var algNames = ["SHA1", "MD5", "SHA256", "SHA384", "SHA512", "SHA224"];
                var keyLen = args[2].toInt32();
                var dataLen = args[4].toInt32();
                this.macOut = args[5];
                this.algName = algNames[alg] || "ALG" + alg;

                console.log(TAG + " CCHmac " + this.algName + " keyLen=" + keyLen + " dataLen=" + dataLen);
                console.log(TAG + "   Key:  " + hexDump(args[1], keyLen));
                console.log(TAG + "   Data: " + hexDump(args[3], Math.min(dataLen, 64)));
                tryUtf8(args[3], dataLen, "Data");

                // Hash output sizes
                this.outLen = {"SHA1": 20, "MD5": 16, "SHA256": 32, "SHA384": 48, "SHA512": 64, "SHA224": 28}[this.algName] || 32;
            },
            onLeave: function (retval) {
                console.log(TAG + "   HMAC: " + hexDump(this.macOut, this.outLen));
            }
        });
        console.log(TAG + " CCHmac hook loaded");
    }
} catch (e) { }

// ============================================================
// 3. Hash functions — CC_SHA256, CC_SHA1, CC_MD5
// ============================================================
["CC_SHA256", "CC_SHA1", "CC_MD5", "CC_SHA512"].forEach(function (name) {
    try {
        var func = Module.findExportByName("libSystem.B.dylib", name);
        if (func) {
            Interceptor.attach(func, {
                onEnter: function (args) {
                    this.data = args[0];
                    this.len = args[1].toInt32();
                    this.out = args[2];
                    console.log(TAG + " " + name + " len=" + this.len);
                    console.log(TAG + "   Data: " + hexDump(this.data, Math.min(this.len, 64)));
                    tryUtf8(this.data, this.len, "Data");
                },
                onLeave: function (retval) {
                    var hashLen = {"CC_SHA256": 32, "CC_SHA1": 20, "CC_MD5": 16, "CC_SHA512": 64}[name] || 32;
                    console.log(TAG + "   Hash: " + hexDump(this.out, hashLen));
                }
            });
        }
    } catch (e) { }
});

// ============================================================
// 4. SecKey — RSA/EC key operations
// ============================================================
try {
    var SecKeyCreateSignature = Module.findExportByName("Security", "SecKeyCreateSignature");
    if (SecKeyCreateSignature) {
        Interceptor.attach(SecKeyCreateSignature, {
            onEnter: function (args) {
                this.algorithm = new ObjC.Object(args[1]).toString();
                var data = new ObjC.Object(args[2]);
                console.log(TAG + " SecKeyCreateSignature algo=" + this.algorithm + " dataLen=" + data.length());
            },
            onLeave: function (retval) {
                if (!retval.isNull()) {
                    var sig = new ObjC.Object(retval);
                    console.log(TAG + "   Signature len=" + sig.length());
                }
            }
        });
    }

    var SecKeyCreateEncryptedData = Module.findExportByName("Security", "SecKeyCreateEncryptedData");
    if (SecKeyCreateEncryptedData) {
        Interceptor.attach(SecKeyCreateEncryptedData, {
            onEnter: function (args) {
                var algo = new ObjC.Object(args[1]).toString();
                var data = new ObjC.Object(args[2]);
                console.log(TAG + " SecKeyEncrypt algo=" + algo + " plainLen=" + data.length());
            },
            onLeave: function (retval) {
                if (!retval.isNull()) {
                    var encrypted = new ObjC.Object(retval);
                    console.log(TAG + "   Encrypted len=" + encrypted.length());
                }
            }
        });
    }

    var SecKeyCreateDecryptedData = Module.findExportByName("Security", "SecKeyCreateDecryptedData");
    if (SecKeyCreateDecryptedData) {
        Interceptor.attach(SecKeyCreateDecryptedData, {
            onEnter: function (args) {
                var algo = new ObjC.Object(args[1]).toString();
                console.log(TAG + " SecKeyDecrypt algo=" + algo);
            },
            onLeave: function (retval) {
                if (!retval.isNull()) {
                    var decrypted = new ObjC.Object(retval);
                    console.log(TAG + "   Decrypted len=" + decrypted.length());
                    if (decrypted.length() < 200) {
                        var bytes = decrypted.bytes();
                        tryUtf8(bytes, decrypted.length(), "Plaintext");
                    }
                }
            }
        });
    }
    console.log(TAG + " SecKey hooks loaded");
} catch (e) { }

// ============================================================
// 5. SecRandomCopyBytes — Random number generation
// ============================================================
try {
    var SecRandomCopyBytes = Module.findExportByName("Security", "SecRandomCopyBytes");
    if (SecRandomCopyBytes) {
        Interceptor.attach(SecRandomCopyBytes, {
            onEnter: function (args) {
                this.count = args[1].toInt32();
                this.bytes = args[2];
            },
            onLeave: function (retval) {
                if (retval.toInt32() === 0) {
                    console.log(TAG + " SecRandom " + this.count + " bytes: " + hexDump(this.bytes, Math.min(this.count, 32)));
                }
            }
        });
    }
} catch (e) { }

// ============================================================
// 6. CryptoKit (Swift) — via Objective-C bridge
// ============================================================
if (ObjC.available) {
    try {
        var resolver = new ApiResolver("objc");

        // AES.GCM seal/open
        resolver.enumerateMatches("*[*AES*GCM* seal*]", {
            onMatch: function (match) {
                Interceptor.attach(match.address, {
                    onEnter: function () { console.log(TAG + " CryptoKit AES.GCM.seal"); }
                });
            },
            onComplete: function () { }
        });

        resolver.enumerateMatches("*[*AES*GCM* open*]", {
            onMatch: function (match) {
                Interceptor.attach(match.address, {
                    onEnter: function () { console.log(TAG + " CryptoKit AES.GCM.open"); }
                });
            },
            onComplete: function () { }
        });

        // ChaChaPoly
        resolver.enumerateMatches("*[*ChaChaPoly* seal*]", {
            onMatch: function (match) {
                Interceptor.attach(match.address, {
                    onEnter: function () { console.log(TAG + " CryptoKit ChaChaPoly.seal"); }
                });
            },
            onComplete: function () { }
        });
    } catch (e) { }
}

// ============================================================
// Helpers
// ============================================================
function hexDump(ptr, len) {
    if (ptr.isNull()) return "(null)";
    var hex = "";
    var maxLen = Math.min(len, 64);
    for (var i = 0; i < maxLen; i++) {
        var b = ptr.add(i).readU8().toString(16);
        hex += (b.length === 1 ? "0" : "") + b;
    }
    return hex + (len > 64 ? "... (" + len + " bytes)" : "");
}

function tryUtf8(ptr, len, label) {
    if (ptr.isNull() || len > 500 || len <= 0) return;
    try {
        var str = ptr.readUtf8String(len);
        if (str && /^[\x20-\x7E\r\n\t]+$/.test(str)) {
            console.log(TAG + "   " + label + " (UTF8): \"" + str.substring(0, 200) + "\"");
        }
    } catch (e) { }
}

console.log(TAG + " === iOS Crypto Hooks Active ===");
