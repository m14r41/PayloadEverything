/*
 * Android Local Storage Extraction — Frida Script
 *
 * Usage:
 *   frida -U -l extract_storage.js -f com.target.app --no-pause
 *
 * Features:
 *   - Dump all SharedPreferences files and values
 *   - Hook SQLiteDatabase queries (log SQL + results)
 *   - Monitor file I/O for sensitive data access
 *   - Extract Android KeyStore keys and metadata
 *   - Hook AccountManager for stored accounts
 */

Java.perform(function () {
    var TAG = "[Storage]";

    // ============================================================
    // 1. SharedPreferences — Dump all stored values
    // ============================================================
    try {
        var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
        SharedPreferencesImpl.getString.implementation = function (key, defValue) {
            var val = this.getString(key, defValue);
            console.log(TAG + " SharedPref.getString(\"" + key + "\") = \"" + val + "\"");
            return val;
        };
        SharedPreferencesImpl.getInt.implementation = function (key, defValue) {
            var val = this.getInt(key, defValue);
            console.log(TAG + " SharedPref.getInt(\"" + key + "\") = " + val);
            return val;
        };
        SharedPreferencesImpl.getBoolean.implementation = function (key, defValue) {
            var val = this.getBoolean(key, defValue);
            console.log(TAG + " SharedPref.getBoolean(\"" + key + "\") = " + val);
            return val;
        };
        SharedPreferencesImpl.getLong.implementation = function (key, defValue) {
            var val = this.getLong(key, defValue);
            console.log(TAG + " SharedPref.getLong(\"" + key + "\") = " + val);
            return val;
        };

        // Monitor writes
        var Editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        Editor.putString.implementation = function (key, value) {
            console.log(TAG + " SharedPref.putString(\"" + key + "\", \"" + value + "\")");
            return this.putString(key, value);
        };
        Editor.putInt.implementation = function (key, value) {
            console.log(TAG + " SharedPref.putInt(\"" + key + "\", " + value + ")");
            return this.putInt(key, value);
        };
        Editor.putBoolean.implementation = function (key, value) {
            console.log(TAG + " SharedPref.putBoolean(\"" + key + "\", " + value + ")");
            return this.putBoolean(key, value);
        };
        console.log(TAG + " SharedPreferences hooks loaded");
    } catch (e) {
        console.log(TAG + " SharedPreferences hook error: " + e);
    }

    // Dump all SharedPreferences on load
    try {
        var Context = Java.use("android.content.Context");
        var ActivityThread = Java.use("android.app.ActivityThread");
        var app = ActivityThread.currentApplication();
        if (app) {
            var dataDir = app.getApplicationInfo().dataDir.value;
            var prefsDir = dataDir + "/shared_prefs";
            var File = Java.use("java.io.File");
            var dir = File.$new(prefsDir);
            if (dir.exists()) {
                var files = dir.listFiles();
                if (files) {
                    console.log(TAG + " === SharedPreferences Files ===");
                    for (var i = 0; i < files.length; i++) {
                        console.log(TAG + "   " + files[i].getName());
                    }
                }
            }
        }
    } catch (e) { }

    // ============================================================
    // 2. SQLite — Log all queries and results
    // ============================================================
    try {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

        SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function (sql, args) {
            var argsStr = args ? Java.use("java.util.Arrays").toString(args) : "null";
            console.log(TAG + " SQL rawQuery: " + sql + " args=" + argsStr);
            var cursor = this.rawQuery(sql, args);
            return cursor;
        };

        SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function (sql) {
            console.log(TAG + " SQL execSQL: " + sql);
            return this.execSQL(sql);
        };

        SQLiteDatabase.execSQL.overload("java.lang.String", "[Ljava.lang.Object;").implementation = function (sql, bindArgs) {
            var argsStr = bindArgs ? Java.use("java.util.Arrays").toString(bindArgs) : "null";
            console.log(TAG + " SQL execSQL: " + sql + " args=" + argsStr);
            return this.execSQL(sql, bindArgs);
        };

        SQLiteDatabase.query.overload("java.lang.String", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "java.lang.String", "java.lang.String").implementation = function (table, cols, sel, selArgs, group, having, order) {
            console.log(TAG + " SQL query: table=" + table + " selection=" + sel);
            return this.query(table, cols, sel, selArgs, group, having, order);
        };

        SQLiteDatabase.insert.implementation = function (table, nullCol, values) {
            console.log(TAG + " SQL insert: table=" + table + " values=" + values.toString());
            return this.insert(table, nullCol, values);
        };

        SQLiteDatabase.update.overload("java.lang.String", "android.content.ContentValues", "java.lang.String", "[Ljava.lang.String;").implementation = function (table, values, where, whereArgs) {
            console.log(TAG + " SQL update: table=" + table + " where=" + where + " values=" + values.toString());
            return this.update(table, values, where, whereArgs);
        };

        // Log database opens
        SQLiteDatabase.openOrCreateDatabase.overload("java.lang.String", "android.database.sqlite.SQLiteDatabase$CursorFactory").implementation = function (path, factory) {
            console.log(TAG + " DB opened: " + path);
            return this.openOrCreateDatabase(path, factory);
        };

        console.log(TAG + " SQLite hooks loaded");
    } catch (e) {
        console.log(TAG + " SQLite hook error: " + e);
    }

    // ============================================================
    // 3. File I/O — Monitor read/write of sensitive files
    // ============================================================
    try {
        var FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload("java.io.File").implementation = function (file) {
            var path = file.getAbsolutePath();
            if (path.indexOf("shared_prefs") !== -1 || path.indexOf("databases") !== -1 ||
                path.indexOf(".key") !== -1 || path.indexOf("token") !== -1 ||
                path.indexOf("password") !== -1 || path.indexOf("cred") !== -1 ||
                path.indexOf(".db") !== -1 || path.indexOf("config") !== -1) {
                console.log(TAG + " FileRead: " + path);
            }
            return this.$init(file);
        };

        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload("java.io.File", "boolean").implementation = function (file, append) {
            var path = file.getAbsolutePath();
            console.log(TAG + " FileWrite: " + path + (append ? " (append)" : ""));
            return this.$init(file, append);
        };
        console.log(TAG + " File I/O hooks loaded");
    } catch (e) { }

    // ============================================================
    // 4. KeyStore — Extract keys and metadata
    // ============================================================
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.getKey.implementation = function (alias, password) {
            var key = this.getKey(alias, password);
            console.log(TAG + " KeyStore.getKey(\"" + alias + "\") → " + (key ? key.getClass().getName() + " algo=" + key.getAlgorithm() : "null"));
            if (key) {
                try {
                    var encoded = key.getEncoded();
                    if (encoded) {
                        var hex = "";
                        for (var i = 0; i < Math.min(encoded.length, 32); i++) {
                            var b = (encoded[i] & 0xFF).toString(16);
                            hex += (b.length === 1 ? "0" : "") + b;
                        }
                        console.log(TAG + "   Key bytes (first 32): " + hex + (encoded.length > 32 ? "..." : ""));
                    }
                } catch (e) {
                    console.log(TAG + "   Key not extractable (hardware-backed)");
                }
            }
            return key;
        };

        KeyStore.getCertificate.implementation = function (alias) {
            var cert = this.getCertificate(alias);
            console.log(TAG + " KeyStore.getCertificate(\"" + alias + "\") → " + (cert ? cert.getType() : "null"));
            return cert;
        };

        // List all aliases when keystore loads
        KeyStore.load.overload("java.io.InputStream", "[C").implementation = function (stream, password) {
            this.load(stream, password);
            try {
                var aliases = this.aliases();
                console.log(TAG + " === KeyStore Aliases ===");
                while (aliases.hasMoreElements()) {
                    var alias = aliases.nextElement();
                    console.log(TAG + "   " + alias + " (isKey=" + this.isKeyEntry(alias) + ")");
                }
            } catch (e) { }
        };
        console.log(TAG + " KeyStore hooks loaded");
    } catch (e) { }

    // ============================================================
    // 5. AccountManager — Stored accounts
    // ============================================================
    try {
        var AccountManager = Java.use("android.accounts.AccountManager");
        AccountManager.getAccounts.implementation = function () {
            var accounts = this.getAccounts();
            console.log(TAG + " === AccountManager Accounts ===");
            for (var i = 0; i < accounts.length; i++) {
                console.log(TAG + "   " + accounts[i].type + ": " + accounts[i].name);
            }
            return accounts;
        };
        AccountManager.peekAuthToken.implementation = function (account, authTokenType) {
            var token = this.peekAuthToken(account, authTokenType);
            console.log(TAG + " AuthToken(" + account.name + ", " + authTokenType + ") = " + token);
            return token;
        };
        console.log(TAG + " AccountManager hooks loaded");
    } catch (e) { }

    console.log(TAG + " === Storage Extraction Active ===");
});
