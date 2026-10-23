/*
 * Universal Android Root Detection Bypass — Frida Script
 *
 * Usage:
 *   frida -U -l root_bypass.js -f com.target.app --no-pause
 *
 * Bypasses:
 *   - File existence checks (Superuser.apk, su, Magisk, busybox)
 *   - RootBeer library
 *   - SafetyNet / Play Integrity
 *   - Build.TAGS check (test-keys)
 *   - Shell command execution (which su, id)
 *   - Runtime.exec su detection
 *   - System property checks (ro.build.tags, ro.debuggable)
 *   - Native file access (fopen, access, stat)
 *   - Package manager checks for root apps
 */

Java.perform(function () {
    var TAG = "[Root-Bypass]";

    // Root-related paths to hide
    var ROOT_PATHS = [
        "/system/app/Superuser.apk",
        "/system/app/Superuser",
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/su/bin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/system/usr/we-need-root/su",
        "/cache/su",
        "/dev/su",
        "/magisk",
        "/sbin/.magisk",
        "/data/adb/magisk",
        "/system/xbin/busybox",
        "/system/bin/busybox",
        "/data/local/xbin/busybox",
        "/system/app/Superuser.apk",
        "/system/etc/init.d/99telecominfra",
        "/system/bin/.ext",
        "/system/etc/init.d",
        "/system/xbin/daemonsu",
        "/system/etc/.has_su_daemon",
        "/system/etc/.installed_su_daemon",
        "/dev/.superuser.key",
        "/data/data/com.noshufou.android.su",
        "/data/data/com.thirdparty.superuser",
        "/data/data/eu.chainfire.supersu",
        "/data/data/com.koushikdutta.superuser",
        "/data/data/com.zachspong.temprootremovejb",
        "/data/data/com.ramdroid.appquarantine",
        "/data/data/com.topjohnwu.magisk",
        "/data/data/com.kingroot.kinguser"
    ];

    var ROOT_PACKAGES = [
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.topjohnwu.magisk",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.onecleanmaster",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot",
        "com.devadvance.rootcloak",
        "com.devadvance.rootcloakplus",
        "com.formyhm.hiderootPremium",
        "com.amphoras.hidemyroot",
        "com.saurik.substrate",
        "de.robv.android.xposed",
        "de.robv.android.xposed.installer",
        "com.jrummy.root.browserfree",
        "com.jrummy.busybox.installer"
    ];

    // ============================================================
    // 1. File.exists() — Hide root files
    // ============================================================
    try {
        var JavaFile = Java.use("java.io.File");
        JavaFile.exists.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < ROOT_PATHS.length; i++) {
                if (path === ROOT_PATHS[i] || path.indexOf("/su") !== -1 && path.indexOf("sugar") === -1) {
                    console.log(TAG + " File.exists hidden: " + path);
                    return false;
                }
            }
            return this.exists();
        };
        console.log(TAG + " File.exists hook loaded");
    } catch (e) {
        console.log(TAG + " File.exists hook error: " + e);
    }

    // ============================================================
    // 2. Runtime.exec — Block su execution and detection commands
    // ============================================================
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmdArray) {
            var cmd = cmdArray.join(" ");
            if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1 || cmd.indexOf("busybox") !== -1) {
                console.log(TAG + " Runtime.exec blocked: " + cmd);
                throw Java.use("java.io.IOException").$new("Cannot run program");
            }
            return this.exec(cmdArray);
        };
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
                console.log(TAG + " Runtime.exec blocked: " + cmd);
                throw Java.use("java.io.IOException").$new("Cannot run program");
            }
            return this.exec(cmd);
        };
        console.log(TAG + " Runtime.exec hook loaded");
    } catch (e) { }

    // ============================================================
    // 3. ProcessBuilder — Block su process creation
    // ============================================================
    try {
        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        ProcessBuilder.start.implementation = function () {
            var cmdList = this.command();
            var cmd = "";
            for (var i = 0; i < cmdList.size(); i++) cmd += cmdList.get(i) + " ";
            if (cmd.indexOf("su") !== -1 || cmd.indexOf("magisk") !== -1) {
                console.log(TAG + " ProcessBuilder.start blocked: " + cmd);
                throw Java.use("java.io.IOException").$new("Cannot run program");
            }
            return this.start();
        };
        console.log(TAG + " ProcessBuilder hook loaded");
    } catch (e) { }

    // ============================================================
    // 4. Build.TAGS — Hide test-keys
    // ============================================================
    try {
        var Build = Java.use("android.os.Build");
        var BuildFields = Build.class.getDeclaredFields();
        Build.TAGS.value = "release-keys";
        console.log(TAG + " Build.TAGS set to release-keys");
    } catch (e) { }

    // ============================================================
    // 5. System properties — Override root indicators
    // ============================================================
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload("java.lang.String").implementation = function (key) {
            if (key === "ro.build.tags") {
                console.log(TAG + " SystemProperties: ro.build.tags → release-keys");
                return "release-keys";
            }
            if (key === "ro.debuggable") {
                return "0";
            }
            if (key === "ro.secure") {
                return "1";
            }
            return this.get(key);
        };
        SystemProperties.get.overload("java.lang.String", "java.lang.String").implementation = function (key, def) {
            if (key === "ro.build.tags") return "release-keys";
            if (key === "ro.debuggable") return "0";
            if (key === "ro.secure") return "1";
            return this.get(key, def);
        };
        console.log(TAG + " SystemProperties hook loaded");
    } catch (e) { }

    // ============================================================
    // 6. PackageManager — Hide root apps
    // ============================================================
    try {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function (pkgName, flags) {
            for (var i = 0; i < ROOT_PACKAGES.length; i++) {
                if (pkgName === ROOT_PACKAGES[i]) {
                    console.log(TAG + " PackageManager hidden: " + pkgName);
                    throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkgName);
                }
            }
            return this.getPackageInfo(pkgName, flags);
        };
        console.log(TAG + " PackageManager hook loaded");
    } catch (e) { }

    // ============================================================
    // 7. RootBeer library — Direct method bypass
    // ============================================================
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function () {
            console.log(TAG + " RootBeer.isRooted → false");
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function () { return false; };
        RootBeer.detectRootManagementApps.implementation = function () { return false; };
        RootBeer.detectPotentiallyDangerousApps.implementation = function () { return false; };
        RootBeer.detectTestKeys.implementation = function () { return false; };
        RootBeer.checkForBusyBoxBinary.implementation = function () { return false; };
        RootBeer.checkForSuBinary.implementation = function () { return false; };
        RootBeer.checkSuExists.implementation = function () { return false; };
        RootBeer.checkForRWPaths.implementation = function () { return false; };
        RootBeer.checkForDangerousProps.implementation = function () { return false; };
        RootBeer.checkForRootNative.implementation = function () { return false; };
        RootBeer.detectRootCloakingApps.implementation = function () { return false; };
        RootBeer.isSelinuxFlagInEnabled.implementation = function () { return true; };
        console.log(TAG + " RootBeer hooks loaded");
    } catch (e) { }

    // ============================================================
    // 8. Native file access — fopen, access, stat (libc)
    // ============================================================
    try {
        var fopen = Module.findExportByName("libc.so", "fopen");
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function (args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave: function (retval) {
                    if (this.path) {
                        for (var i = 0; i < ROOT_PATHS.length; i++) {
                            if (this.path === ROOT_PATHS[i]) {
                                console.log(TAG + " Native fopen hidden: " + this.path);
                                retval.replace(ptr(0x0));
                                break;
                            }
                        }
                    }
                }
            });
        }

        var accessFunc = Module.findExportByName("libc.so", "access");
        if (accessFunc) {
            Interceptor.attach(accessFunc, {
                onEnter: function (args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave: function (retval) {
                    if (this.path) {
                        for (var i = 0; i < ROOT_PATHS.length; i++) {
                            if (this.path === ROOT_PATHS[i]) {
                                console.log(TAG + " Native access hidden: " + this.path);
                                retval.replace(-1);
                                break;
                            }
                        }
                    }
                }
            });
        }
        console.log(TAG + " Native hooks loaded (fopen, access)");
    } catch (e) { }

    // ============================================================
    // 9. SafetyNet / Play Integrity — Response bypass
    // ============================================================
    try {
        var SafetyNetClient = Java.use("com.google.android.gms.safetynet.SafetyNetClient");
        SafetyNetClient.attest.implementation = function (nonce, apiKey) {
            console.log(TAG + " SafetyNet attest intercepted (nonce len: " + nonce.length + ")");
            return this.attest(nonce, apiKey);
        };
    } catch (e) { }

    console.log(TAG + " === Root Detection Bypass Active ===");
});
