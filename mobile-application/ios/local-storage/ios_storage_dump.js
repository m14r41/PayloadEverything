/*
 * iOS Local Storage Extraction — Frida Script
 *
 * Usage:
 *   frida -U -l ios_storage_dump.js -f com.target.app --no-pause
 *
 * Features:
 *   - NSUserDefaults read/write monitoring
 *   - NSFileManager file operations
 *   - CoreData / NSManagedObjectContext
 *   - Plist file read/write
 *   - UIPasteboard (clipboard) monitoring
 *   - SQLite database operations
 *   - NSURLCache / response caching
 *   - Cookie storage (NSHTTPCookieStorage)
 */

if (ObjC.available) {
    var TAG = "[Storage-iOS]";

    // ============================================================
    // 1. NSUserDefaults — Monitor all read/write operations
    // ============================================================
    try {
        var NSUserDefaults = ObjC.classes.NSUserDefaults;

        // String values
        Interceptor.attach(NSUserDefaults["- stringForKey:"].implementation, {
            onEnter: function (args) { this.key = new ObjC.Object(args[2]).toString(); },
            onLeave: function (retval) {
                if (!retval.isNull()) {
                    var val = new ObjC.Object(retval).toString();
                    console.log(TAG + " UserDefaults.string(\"" + this.key + "\") = \"" + val.substring(0, 200) + "\"");
                }
            }
        });

        // Object values (catches dictionaries, arrays, data)
        Interceptor.attach(NSUserDefaults["- objectForKey:"].implementation, {
            onEnter: function (args) { this.key = new ObjC.Object(args[2]).toString(); },
            onLeave: function (retval) {
                if (!retval.isNull()) {
                    var obj = new ObjC.Object(retval);
                    var desc = obj.toString();
                    if (desc.length > 300) desc = desc.substring(0, 300) + "...";
                    console.log(TAG + " UserDefaults.object(\"" + this.key + "\") = " + desc);
                }
            }
        });

        // Bool
        Interceptor.attach(NSUserDefaults["- boolForKey:"].implementation, {
            onEnter: function (args) { this.key = new ObjC.Object(args[2]).toString(); },
            onLeave: function (retval) {
                console.log(TAG + " UserDefaults.bool(\"" + this.key + "\") = " + retval);
            }
        });

        // Write operations
        Interceptor.attach(NSUserDefaults["- setObject:forKey:"].implementation, {
            onEnter: function (args) {
                var val = args[2].isNull() ? "nil" : new ObjC.Object(args[2]).toString();
                var key = new ObjC.Object(args[3]).toString();
                if (val.length > 300) val = val.substring(0, 300) + "...";
                console.log(TAG + " UserDefaults.set(\"" + key + "\", " + val + ")");
            }
        });

        Interceptor.attach(NSUserDefaults["- setBool:forKey:"].implementation, {
            onEnter: function (args) {
                var key = new ObjC.Object(args[3]).toString();
                console.log(TAG + " UserDefaults.setBool(\"" + key + "\", " + args[2] + ")");
            }
        });
        console.log(TAG + " NSUserDefaults hooks loaded");
    } catch (e) {
        console.log(TAG + " NSUserDefaults error: " + e);
    }

    // ============================================================
    // 2. NSFileManager — File read/write/create operations
    // ============================================================
    try {
        var NSFileManager = ObjC.classes.NSFileManager;

        Interceptor.attach(NSFileManager["- contentsAtPath:"].implementation, {
            onEnter: function (args) {
                var path = new ObjC.Object(args[2]).toString();
                if (path.indexOf("Documents") !== -1 || path.indexOf("Library") !== -1 ||
                    path.indexOf("tmp") !== -1 || path.indexOf(".db") !== -1 ||
                    path.indexOf(".plist") !== -1 || path.indexOf("Caches") !== -1) {
                    console.log(TAG + " FileRead: " + path);
                }
            }
        });

        Interceptor.attach(NSFileManager["- createFileAtPath:contents:attributes:"].implementation, {
            onEnter: function (args) {
                var path = new ObjC.Object(args[2]).toString();
                console.log(TAG + " FileCreate: " + path);
            }
        });
        console.log(TAG + " NSFileManager hooks loaded");
    } catch (e) { }

    // ============================================================
    // 3. CoreData — NSManagedObjectContext operations
    // ============================================================
    try {
        var MOC = ObjC.classes.NSManagedObjectContext;

        Interceptor.attach(MOC["- executeFetchRequest:error:"].implementation, {
            onEnter: function (args) {
                var request = new ObjC.Object(args[2]);
                console.log(TAG + " CoreData fetch: entity=" + request.entityName() +
                    " predicate=" + (request.predicate() ? request.predicate().toString() : "nil"));
            },
            onLeave: function (retval) {
                if (!retval.isNull()) {
                    var results = new ObjC.Object(retval);
                    console.log(TAG + "   CoreData results: " + results.count() + " objects");
                }
            }
        });

        Interceptor.attach(MOC["- save:"].implementation, {
            onEnter: function (args) {
                var inserted = this.insertedObjects().count();
                var updated = this.updatedObjects().count();
                var deleted = this.deletedObjects().count();
                console.log(TAG + " CoreData save: inserted=" + inserted + " updated=" + updated + " deleted=" + deleted);
            }
        });
    } catch (e) { }

    // ============================================================
    // 4. Plist — NSDictionary/NSArray write to file
    // ============================================================
    try {
        var NSDictionary = ObjC.classes.NSDictionary;
        Interceptor.attach(NSDictionary["- writeToFile:atomically:"].implementation, {
            onEnter: function (args) {
                var path = new ObjC.Object(args[2]).toString();
                console.log(TAG + " Plist write: " + path);
                var dict = new ObjC.Object(this);
                var desc = dict.toString();
                if (desc.length < 500) console.log(TAG + "   Content: " + desc);
            }
        });

        // NSKeyedArchiver
        var NSKeyedArchiver = ObjC.classes.NSKeyedArchiver;
        if (NSKeyedArchiver["+ archivedDataWithRootObject:requiringSecureCoding:error:"]) {
            Interceptor.attach(NSKeyedArchiver["+ archivedDataWithRootObject:requiringSecureCoding:error:"].implementation, {
                onEnter: function (args) {
                    var obj = new ObjC.Object(args[2]);
                    console.log(TAG + " NSKeyedArchiver: " + obj.$className);
                }
            });
        }
    } catch (e) { }

    // ============================================================
    // 5. UIPasteboard — Clipboard monitoring
    // ============================================================
    try {
        var UIPasteboard = ObjC.classes.UIPasteboard;

        Interceptor.attach(UIPasteboard["- setString:"].implementation, {
            onEnter: function (args) {
                var str = new ObjC.Object(args[2]).toString();
                console.log(TAG + " Clipboard WRITE: \"" + str.substring(0, 200) + "\"");
            }
        });

        Interceptor.attach(UIPasteboard["- string"].implementation, {
            onLeave: function (retval) {
                if (!retval.isNull()) {
                    var str = new ObjC.Object(retval).toString();
                    console.log(TAG + " Clipboard READ: \"" + str.substring(0, 200) + "\"");
                }
            }
        });

        // Data copy
        Interceptor.attach(UIPasteboard["- setData:forPasteboardType:"].implementation, {
            onEnter: function (args) {
                var type = new ObjC.Object(args[3]).toString();
                var data = new ObjC.Object(args[2]);
                console.log(TAG + " Clipboard DATA: type=" + type + " len=" + data.length());
            }
        });
    } catch (e) { }

    // ============================================================
    // 6. SQLite — Direct database operations
    // ============================================================
    try {
        var sqlite3_open = Module.findExportByName("libsqlite3.dylib", "sqlite3_open");
        var sqlite3_exec = Module.findExportByName("libsqlite3.dylib", "sqlite3_exec");
        var sqlite3_prepare_v2 = Module.findExportByName("libsqlite3.dylib", "sqlite3_prepare_v2");

        if (sqlite3_open) {
            Interceptor.attach(sqlite3_open, {
                onEnter: function (args) {
                    var path = args[0].readUtf8String();
                    console.log(TAG + " SQLite open: " + path);
                }
            });
        }

        if (sqlite3_exec) {
            Interceptor.attach(sqlite3_exec, {
                onEnter: function (args) {
                    var sql = args[1].readUtf8String();
                    if (sql) console.log(TAG + " SQLite exec: " + sql.substring(0, 300));
                }
            });
        }

        if (sqlite3_prepare_v2) {
            Interceptor.attach(sqlite3_prepare_v2, {
                onEnter: function (args) {
                    var sql = args[1].readUtf8String();
                    if (sql) console.log(TAG + " SQLite prepare: " + sql.substring(0, 300));
                }
            });
        }
        console.log(TAG + " SQLite hooks loaded");
    } catch (e) { }

    // ============================================================
    // 7. NSURLCache — Response caching
    // ============================================================
    try {
        var NSURLCache = ObjC.classes.NSURLCache;
        Interceptor.attach(NSURLCache["- storeCachedResponse:forRequest:"].implementation, {
            onEnter: function (args) {
                var request = new ObjC.Object(args[3]);
                console.log(TAG + " URLCache store: " + request.URL().toString());
            }
        });
    } catch (e) { }

    // ============================================================
    // 8. NSHTTPCookieStorage — Cookie monitoring
    // ============================================================
    try {
        var CookieStorage = ObjC.classes.NSHTTPCookieStorage;
        Interceptor.attach(CookieStorage["- setCookie:"].implementation, {
            onEnter: function (args) {
                var cookie = new ObjC.Object(args[2]);
                console.log(TAG + " Cookie SET: " + cookie.name() + "=" + cookie.value() +
                    " domain=" + cookie.domain() + " secure=" + cookie.isSecure() +
                    " httpOnly=" + cookie.isHTTPOnly());
            }
        });

        // Dump existing cookies on load
        setTimeout(function () {
            try {
                var store = CookieStorage.sharedHTTPCookieStorage();
                var cookies = store.cookies();
                if (cookies && cookies.count() > 0) {
                    console.log(TAG + " === Existing Cookies ===");
                    for (var i = 0; i < cookies.count(); i++) {
                        var c = cookies.objectAtIndex_(i);
                        console.log(TAG + "   " + c.name() + "=" + c.value() +
                            " (" + c.domain() + " secure=" + c.isSecure() + ")");
                    }
                }
            } catch (e) { }
        }, 2000);
    } catch (e) { }

    console.log(TAG + " === iOS Storage Extraction Active ===");
} else {
    console.log("[-] Objective-C runtime not available");
}
