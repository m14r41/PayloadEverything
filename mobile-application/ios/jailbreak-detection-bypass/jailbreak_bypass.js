/*
 * Universal iOS Jailbreak Detection Bypass — Frida Script
 *
 * Usage:
 *   frida -U -l jailbreak_bypass.js -f com.target.app --no-pause
 *
 * Bypasses:
 *   - File existence checks (Cydia, Sileo, Substitute, checkra1n)
 *   - canOpenURL (cydia://)
 *   - fork() / system() detection
 *   - Sandbox integrity (symlink, /private/var)
 *   - stat/access/lstat native calls
 *   - IOSSecuritySuite library
 *   - NSFileManager file existence
 *   - dlopen/dlsym checks
 *   - Environment variable detection
 *   - dyld image list checks
 */

if (ObjC.available) {
    var TAG = "[JB-Bypass]";

    // Jailbreak-related paths to hide
    var JB_PATHS = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Installer.app",
        "/Applications/blackra1n.app",
        "/Applications/FakeCarrier.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/SBSettings.app",
        "/Applications/WinterBoard.app",
        "/Applications/Snoop-itConfig.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/usr/libexec/cydia",
        "/usr/sbin/sshd",
        "/usr/bin/sshd",
        "/usr/bin/ssh",
        "/usr/libexec/sftp-server",
        "/var/cache/apt",
        "/var/lib/apt",
        "/var/lib/cydia",
        "/var/log/syslog",
        "/etc/apt",
        "/etc/apt/sources.list.d/cydia.list",
        "/private/var/tmp/cydia.log",
        "/private/var/lib/apt",
        "/private/var/stash",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/bin/bash",
        "/bin/sh",
        "/usr/bin/ssh",
        "/usr/local/bin/cycript",
        "/usr/lib/libcycript.dylib",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        "/var/checkra1n.dmg",
        "/var/binpack",
        "/.installed_unc0ver",
        "/.bootstrapped_electra",
        "/usr/lib/libjailbreak.dylib",
        "/jb/lzma",
        "/jb/offsets.plist",
        "/usr/share/jailbreak/injectme.plist",
        "/Library/Frameworks/CydiaSubstrate.framework",
        "/usr/lib/substrate",
        "/usr/lib/TweakInject"
    ];

    var JB_SCHEMES = ["cydia://", "sileo://", "zbra://", "filza://", "undecimus://"];

    // ============================================================
    // 1. NSFileManager — fileExistsAtPath
    // ============================================================
    try {
        var NSFileManager = ObjC.classes.NSFileManager;
        Interceptor.attach(NSFileManager["- fileExistsAtPath:"].implementation, {
            onEnter: function (args) {
                this.path = new ObjC.Object(args[2]).toString();
            },
            onLeave: function (retval) {
                for (var i = 0; i < JB_PATHS.length; i++) {
                    if (this.path === JB_PATHS[i]) {
                        retval.replace(0x0);
                        console.log(TAG + " fileExistsAtPath hidden: " + this.path);
                        return;
                    }
                }
            }
        });

        Interceptor.attach(NSFileManager["- fileExistsAtPath:isDirectory:"].implementation, {
            onEnter: function (args) {
                this.path = new ObjC.Object(args[2]).toString();
            },
            onLeave: function (retval) {
                for (var i = 0; i < JB_PATHS.length; i++) {
                    if (this.path === JB_PATHS[i]) {
                        retval.replace(0x0);
                        return;
                    }
                }
            }
        });
        console.log(TAG + " NSFileManager hooks loaded");
    } catch (e) {
        console.log(TAG + " NSFileManager error: " + e);
    }

    // ============================================================
    // 2. canOpenURL — Block cydia:// and other JB schemes
    // ============================================================
    try {
        var UIApplication = ObjC.classes.UIApplication;
        Interceptor.attach(UIApplication["- canOpenURL:"].implementation, {
            onEnter: function (args) {
                this.url = new ObjC.Object(args[2]).toString();
            },
            onLeave: function (retval) {
                for (var i = 0; i < JB_SCHEMES.length; i++) {
                    if (this.url.indexOf(JB_SCHEMES[i]) !== -1) {
                        retval.replace(0x0);
                        console.log(TAG + " canOpenURL hidden: " + this.url);
                        return;
                    }
                }
            }
        });
        console.log(TAG + " canOpenURL hook loaded");
    } catch (e) { }

    // ============================================================
    // 3. fork() — Return -1 (fail) to fake non-jailbroken
    // ============================================================
    try {
        var fork = Module.findExportByName("libSystem.B.dylib", "fork");
        if (fork) {
            Interceptor.attach(fork, {
                onLeave: function (retval) {
                    retval.replace(-1);
                    console.log(TAG + " fork() → -1");
                }
            });
        }
    } catch (e) { }

    // ============================================================
    // 4. system() — Return non-zero (fail)
    // ============================================================
    try {
        var system = Module.findExportByName("libSystem.B.dylib", "system");
        if (system) {
            Interceptor.attach(system, {
                onEnter: function (args) {
                    this.cmd = args[0].readUtf8String();
                },
                onLeave: function (retval) {
                    if (this.cmd === null || this.cmd === "") {
                        retval.replace(0x0); // system(NULL) = 0 means no shell
                        console.log(TAG + " system(NULL) → 0");
                    }
                }
            });
        }
    } catch (e) { }

    // ============================================================
    // 5. stat / lstat / access — Native file checks
    // ============================================================
    try {
        ["stat", "lstat", "access"].forEach(function (funcName) {
            var func = Module.findExportByName("libSystem.B.dylib", funcName);
            if (func) {
                Interceptor.attach(func, {
                    onEnter: function (args) {
                        this.path = args[0].readUtf8String();
                    },
                    onLeave: function (retval) {
                        if (this.path) {
                            for (var i = 0; i < JB_PATHS.length; i++) {
                                if (this.path === JB_PATHS[i]) {
                                    retval.replace(-1);
                                    console.log(TAG + " " + funcName + " hidden: " + this.path);
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        console.log(TAG + " Native stat/lstat/access hooks loaded");
    } catch (e) { }

    // ============================================================
    // 6. fopen — Hide jailbreak files
    // ============================================================
    try {
        var fopen = Module.findExportByName("libSystem.B.dylib", "fopen");
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function (args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave: function (retval) {
                    if (this.path) {
                        for (var i = 0; i < JB_PATHS.length; i++) {
                            if (this.path === JB_PATHS[i]) {
                                retval.replace(ptr(0x0));
                                console.log(TAG + " fopen hidden: " + this.path);
                                return;
                            }
                        }
                    }
                }
            });
        }
    } catch (e) { }

    // ============================================================
    // 7. Sandbox integrity — write test bypass
    // ============================================================
    try {
        var NSString = ObjC.classes.NSString;
        Interceptor.attach(NSString["- writeToFile:atomically:encoding:error:"].implementation, {
            onEnter: function (args) {
                this.path = new ObjC.Object(args[2]).toString();
            },
            onLeave: function (retval) {
                if (this.path && (this.path.indexOf("/private/") === 0 || this.path === "/")) {
                    retval.replace(0x0); // Write failed = sandbox intact
                    console.log(TAG + " Sandbox write test hidden: " + this.path);
                }
            }
        });
    } catch (e) { }

    // ============================================================
    // 8. IOSSecuritySuite — Direct method bypass
    // ============================================================
    try {
        var resolver = new ApiResolver("objc");
        var suiteMethods = [
            "amIJailbroken",
            "amIJailbrokenWithFailMessage",
            "amIRunInEmulator",
            "amIDebugged",
            "amIReverseEngineered",
            "amIProxied",
            "amITampered",
            "isParentPidUnexpected",
            "hasBreakpointAt",
            "amIRuntimeHooked"
        ];
        suiteMethods.forEach(function (method) {
            try {
                resolver.enumerateMatches("+[*SecuritySuite " + method + "*]", {
                    onMatch: function (match) {
                        Interceptor.attach(match.address, {
                            onLeave: function (retval) {
                                retval.replace(0x0);
                                console.log(TAG + " IOSSecuritySuite." + method + " → false");
                            }
                        });
                    },
                    onComplete: function () { }
                });
            } catch (e) { }
        });
        console.log(TAG + " IOSSecuritySuite hooks loaded");
    } catch (e) { }

    // ============================================================
    // 9. dlopen / dlsym — Block substrate/injection checks
    // ============================================================
    try {
        var dlopen = Module.findExportByName(null, "dlopen");
        if (dlopen) {
            Interceptor.attach(dlopen, {
                onEnter: function (args) {
                    this.lib = args[0].readUtf8String();
                },
                onLeave: function (retval) {
                    if (this.lib && (this.lib.indexOf("Substrate") !== -1 ||
                        this.lib.indexOf("cycript") !== -1 ||
                        this.lib.indexOf("frida") !== -1 ||
                        this.lib.indexOf("SSLKillSwitch") !== -1)) {
                        retval.replace(ptr(0x0));
                        console.log(TAG + " dlopen hidden: " + this.lib);
                    }
                }
            });
        }
    } catch (e) { }

    // ============================================================
    // 10. dyld — _dyld_image_count / _dyld_get_image_name
    // ============================================================
    try {
        var dyld_get_image_name = Module.findExportByName(null, "_dyld_get_image_name");
        if (dyld_get_image_name) {
            Interceptor.attach(dyld_get_image_name, {
                onLeave: function (retval) {
                    var name = retval.readUtf8String();
                    if (name && (name.indexOf("Substrate") !== -1 ||
                        name.indexOf("substitute") !== -1 ||
                        name.indexOf("TweakInject") !== -1 ||
                        name.indexOf("cycript") !== -1 ||
                        name.indexOf("frida") !== -1 ||
                        name.indexOf("SSLKillSwitch") !== -1)) {
                        retval.replace(Memory.allocUtf8String("/usr/lib/system/libsystem_c.dylib"));
                        console.log(TAG + " dyld image hidden: " + name);
                    }
                }
            });
        }
    } catch (e) { }

    // ============================================================
    // 11. Environment variable check (DYLD_INSERT_LIBRARIES)
    // ============================================================
    try {
        var getenv = Module.findExportByName("libSystem.B.dylib", "getenv");
        if (getenv) {
            Interceptor.attach(getenv, {
                onEnter: function (args) {
                    this.key = args[0].readUtf8String();
                },
                onLeave: function (retval) {
                    if (this.key === "DYLD_INSERT_LIBRARIES") {
                        retval.replace(ptr(0x0));
                        console.log(TAG + " getenv DYLD_INSERT_LIBRARIES → null");
                    }
                }
            });
        }
    } catch (e) { }

    // ============================================================
    // 12. sysctl — Anti-debug / process check
    // ============================================================
    try {
        var sysctl = Module.findExportByName("libSystem.B.dylib", "sysctl");
        if (sysctl) {
            Interceptor.attach(sysctl, {
                onEnter: function (args) {
                    this.mib = args[0];
                    this.oldp = args[2];
                },
                onLeave: function (retval) {
                    // Clear P_TRACED flag in kinfo_proc
                    try {
                        var flag_offset = 32; // offsetof(kinfo_proc, kp_proc.p_flag) on arm64
                        var flags = this.oldp.add(flag_offset).readU32();
                        var P_TRACED = 0x00000800;
                        if ((flags & P_TRACED) !== 0) {
                            this.oldp.add(flag_offset).writeU32(flags & ~P_TRACED);
                            console.log(TAG + " sysctl P_TRACED cleared");
                        }
                    } catch (e) { }
                }
            });
        }
    } catch (e) { }

    console.log(TAG + " === Jailbreak Detection Bypass Active ===");
} else {
    console.log("[-] Objective-C runtime not available");
}
