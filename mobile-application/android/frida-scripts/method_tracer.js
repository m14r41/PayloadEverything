/*
 * Universal Android Method Tracer — Frida Script
 *
 * Usage:
 *   frida -U -l method_tracer.js -f com.target.app --no-pause
 *
 * Auto-hooks:
 *   - Crypto operations (AES, RSA, HMAC, MessageDigest)
 *   - HTTP requests (URL, HttpURLConnection, OkHttp)
 *   - SharedPreferences read/write
 *   - WebView URL loading
 *   - JSON parsing (org.json, Gson)
 *   - Base64 encode/decode
 *   - Logging (android.util.Log)
 */

Java.perform(function () {
    var TAG = "[Tracer]";

    // ============================================================
    // 1. Crypto — AES/DES/RSA/HMAC encryption/decryption
    // ============================================================
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.getInstance.overload("java.lang.String").implementation = function (transform) {
            console.log(TAG + " Cipher.getInstance(\"" + transform + "\")");
            return this.getInstance(transform);
        };
        Cipher.doFinal.overload("[B").implementation = function (input) {
            var result = this.doFinal(input);
            var mode = this.getOpmode ? "" : "";
            console.log(TAG + " Cipher.doFinal mode=" + this.getOpmode() +
                " algo=" + this.getAlgorithm() +
                " in_len=" + input.length + " out_len=" + result.length);
            console.log(TAG + "   Input:  " + bytesToHex(input, 64));
            console.log(TAG + "   Output: " + bytesToHex(result, 64));
            try {
                console.log(TAG + "   Input (UTF8):  " + Java.use("java.lang.String").$new(input, "UTF-8"));
            } catch (e) { }
            try {
                console.log(TAG + "   Output (UTF8): " + Java.use("java.lang.String").$new(result, "UTF-8"));
            } catch (e) { }
            return result;
        };
    } catch (e) { }

    // SecretKeySpec — capture encryption keys
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
            console.log(TAG + " SecretKeySpec(algo=" + algo + " key=" + bytesToHex(key, 64) + ")");
            return this.$init(key, algo);
        };
    } catch (e) { }

    // IvParameterSpec — capture IVs
    try {
        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        IvParameterSpec.$init.overload("[B").implementation = function (iv) {
            console.log(TAG + " IvParameterSpec(iv=" + bytesToHex(iv, 64) + ")");
            return this.$init(iv);
        };
    } catch (e) { }

    // MessageDigest — hashing
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.digest.overload("[B").implementation = function (input) {
            var result = this.digest(input);
            console.log(TAG + " MessageDigest.digest(algo=" + this.getAlgorithm() + ")");
            console.log(TAG + "   Input: " + bytesToHex(input, 64));
            console.log(TAG + "   Hash:  " + bytesToHex(result, 64));
            return result;
        };
        MessageDigest.digest.overload().implementation = function () {
            var result = this.digest();
            console.log(TAG + " MessageDigest.digest(algo=" + this.getAlgorithm() + ") = " + bytesToHex(result, 64));
            return result;
        };
    } catch (e) { }

    // Mac — HMAC
    try {
        var Mac = Java.use("javax.crypto.Mac");
        Mac.doFinal.overload("[B").implementation = function (input) {
            var result = this.doFinal(input);
            console.log(TAG + " Mac.doFinal(algo=" + this.getAlgorithm() + ")");
            console.log(TAG + "   Input: " + bytesToHex(input, 64));
            console.log(TAG + "   HMAC:  " + bytesToHex(result, 64));
            return result;
        };
    } catch (e) { }

    // ============================================================
    // 2. HTTP — URL connections and OkHttp requests
    // ============================================================
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            var conn = this.openConnection();
            console.log(TAG + " URL.openConnection: " + this.toString());
            return conn;
        };
    } catch (e) { }

    // OkHttp3 Call.execute / enqueue
    try {
        var RealCall = Java.use("okhttp3.internal.connection.RealCall");
        RealCall.execute.implementation = function () {
            var request = this.request();
            console.log(TAG + " OkHttp " + request.method() + " " + request.url().toString());
            var headers = request.headers();
            for (var i = 0; i < headers.size(); i++) {
                console.log(TAG + "   " + headers.name(i) + ": " + headers.value(i));
            }
            var response = this.execute();
            console.log(TAG + "   → " + response.code() + " " + response.message());
            return response;
        };
    } catch (e) { }

    try {
        var RealCall2 = Java.use("okhttp3.RealCall");
        RealCall2.execute.implementation = function () {
            var request = this.request();
            console.log(TAG + " OkHttp " + request.method() + " " + request.url().toString());
            var response = this.execute();
            console.log(TAG + "   → " + response.code());
            return response;
        };
    } catch (e) { }

    // ============================================================
    // 3. WebView — URL loading
    // ============================================================
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            console.log(TAG + " WebView.loadUrl: " + url);
            return this.loadUrl(url);
        };
        WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (url, headers) {
            console.log(TAG + " WebView.loadUrl: " + url + " (with headers)");
            return this.loadUrl(url, headers);
        };
        WebView.loadDataWithBaseURL.implementation = function (baseUrl, data, mimeType, encoding, historyUrl) {
            console.log(TAG + " WebView.loadDataWithBaseURL: base=" + baseUrl + " data_len=" + (data ? data.length : 0));
            if (data && data.length < 500) console.log(TAG + "   Data: " + data);
            return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
        };
        WebView.addJavascriptInterface.implementation = function (obj, name) {
            console.log(TAG + " WebView.addJavascriptInterface: " + name + " → " + obj.getClass().getName());
            return this.addJavascriptInterface(obj, name);
        };
    } catch (e) { }

    // ============================================================
    // 4. JSON parsing — org.json and Gson
    // ============================================================
    try {
        var JSONObject = Java.use("org.json.JSONObject");
        JSONObject.$init.overload("java.lang.String").implementation = function (json) {
            if (json.length < 2000) {
                console.log(TAG + " JSONObject parse: " + json.substring(0, Math.min(json.length, 500)));
            } else {
                console.log(TAG + " JSONObject parse: (len=" + json.length + ")");
            }
            return this.$init(json);
        };
        JSONObject.getString.implementation = function (key) {
            var val = this.getString(key);
            if (key.toLowerCase().indexOf("token") !== -1 || key.toLowerCase().indexOf("key") !== -1 ||
                key.toLowerCase().indexOf("secret") !== -1 || key.toLowerCase().indexOf("pass") !== -1 ||
                key.toLowerCase().indexOf("auth") !== -1) {
                console.log(TAG + " JSONObject.getString(\"" + key + "\") = \"" + val + "\" [SENSITIVE]");
            }
            return val;
        };
    } catch (e) { }

    try {
        var Gson = Java.use("com.google.gson.Gson");
        Gson.fromJson.overload("java.lang.String", "java.lang.Class").implementation = function (json, classOfT) {
            console.log(TAG + " Gson.fromJson → " + classOfT.getName());
            if (json && json.length < 500) console.log(TAG + "   " + json);
            return this.fromJson(json, classOfT);
        };
        Gson.toJson.overload("java.lang.Object").implementation = function (src) {
            var result = this.toJson(src);
            console.log(TAG + " Gson.toJson ← " + src.getClass().getName());
            if (result.length < 500) console.log(TAG + "   " + result);
            return result;
        };
    } catch (e) { }

    // ============================================================
    // 5. Base64 — Encode/Decode
    // ============================================================
    try {
        var Base64 = Java.use("android.util.Base64");
        Base64.encodeToString.overload("[B", "int").implementation = function (input, flags) {
            var result = this.encodeToString(input, flags);
            console.log(TAG + " Base64.encode: " + result.substring(0, Math.min(result.length, 100)));
            try {
                var plain = Java.use("java.lang.String").$new(input, "UTF-8");
                if (plain.length < 200) console.log(TAG + "   Plain: " + plain);
            } catch (e) { }
            return result;
        };
        Base64.decode.overload("java.lang.String", "int").implementation = function (str, flags) {
            var result = this.decode(str, flags);
            console.log(TAG + " Base64.decode input: " + str.substring(0, Math.min(str.length, 100)));
            try {
                var decoded = Java.use("java.lang.String").$new(result, "UTF-8");
                if (decoded.length < 200) console.log(TAG + "   Decoded: " + decoded);
            } catch (e) { }
            return result;
        };
    } catch (e) { }

    // ============================================================
    // 6. Android Log — Capture log output for sensitive data
    // ============================================================
    try {
        var Log = Java.use("android.util.Log");
        var origD = Log.d.overload("java.lang.String", "java.lang.String");
        origD.implementation = function (tag, msg) {
            if (msg.toLowerCase().indexOf("token") !== -1 || msg.toLowerCase().indexOf("password") !== -1 ||
                msg.toLowerCase().indexOf("secret") !== -1 || msg.toLowerCase().indexOf("key=") !== -1) {
                console.log(TAG + " Log.d [SENSITIVE] tag=" + tag + " msg=" + msg);
            }
            return origD.call(this, tag, msg);
        };
        var origE = Log.e.overload("java.lang.String", "java.lang.String");
        origE.implementation = function (tag, msg) {
            console.log(TAG + " Log.e tag=" + tag + " msg=" + msg);
            return origE.call(this, tag, msg);
        };
    } catch (e) { }

    // ============================================================
    // Helper: bytes to hex
    // ============================================================
    function bytesToHex(bytes, maxLen) {
        if (!bytes) return "null";
        var hex = "";
        var len = Math.min(bytes.length, maxLen || 64);
        for (var i = 0; i < len; i++) {
            var b = (bytes[i] & 0xFF).toString(16);
            hex += (b.length === 1 ? "0" : "") + b;
        }
        return hex + (bytes.length > len ? "... (" + bytes.length + " bytes)" : "");
    }

    console.log(TAG + " === Method Tracer Active ===");
});
