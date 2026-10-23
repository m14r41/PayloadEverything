"""
.NET Binary Patching — Automated IL patching for common VAPT scenarios.

Uses Mono.Cecil (via Python subprocess to a C# helper) or direct CIL byte
manipulation for common bypass patterns found in thick-client assessments.

This script generates dnSpy/ILSpy patch instructions and CIL byte sequences
for common bypass scenarios.

Usage:
    python -I dotnet_patch_scripts.py --list
    python -I dotnet_patch_scripts.py --pattern auth_bypass --class "AuthManager" --method "ValidateUser"
    python -I dotnet_patch_scripts.py --pattern license_bypass --assembly "TargetApp.exe"
    python -I dotnet_patch_scripts.py --scan "TargetApp.exe"
"""

import argparse
import os
import struct
import sys

PATCH_PATTERNS = {
    "auth_bypass": {
        "desc": "Force authentication methods to always return true",
        "target": "Methods returning bool (IsAuthenticated, ValidateUser, CheckCredentials)",
        "il_patch": [
            "nop",           # clear any parameter loads
            "ldc.i4.1",     # push true (1) onto stack
            "ret",          # return
        ],
        "hex_original": None,  # varies
        "hex_patched": "00 17 2A",  # nop, ldc.i4.1, ret
        "dnspy_steps": [
            "1. Open target assembly in dnSpy",
            "2. Navigate to the auth class (e.g., AuthManager.ValidateUser)",
            "3. Right-click method body → Edit IL Instructions",
            "4. Clear all instructions",
            "5. Add: ldc.i4.1 (push true)",
            "6. Add: ret (return)",
            "7. File → Save Module",
        ],
    },
    "license_bypass": {
        "desc": "Bypass license validation (IsLicensed, CheckLicense, ValidateLicense)",
        "target": "License check methods returning bool",
        "il_patch": [
            "ldc.i4.1",     # push true
            "ret",
        ],
        "hex_patched": "17 2A",
        "dnspy_steps": [
            "1. Search for 'license', 'trial', 'expired', 'registration'",
            "2. Find the bool-returning validation method",
            "3. Edit IL: replace body with ldc.i4.1 + ret",
            "4. Also check for date comparisons (DateTime.Now)",
            "5. Patch any expiry check to return false (ldc.i4.0 + ret)",
            "6. Save Module",
        ],
    },
    "role_bypass": {
        "desc": "Bypass role/permission checks (IsAdmin, HasPermission, CheckRole)",
        "target": "Authorization methods returning bool",
        "il_patch": [
            "ldc.i4.1",
            "ret",
        ],
        "hex_patched": "17 2A",
        "dnspy_steps": [
            "1. Search for 'admin', 'role', 'permission', 'authorize'",
            "2. Find the authorization method",
            "3. Edit IL: replace body with ldc.i4.1 + ret",
            "4. Also check for enum comparisons (UserRole.Admin)",
            "5. For enum returns: ldc.i4 <admin_value> + ret",
            "6. Save Module",
        ],
    },
    "debug_enable": {
        "desc": "Enable debug/diagnostic features hidden in production",
        "target": "IsDebug, IsDevMode, EnableDiagnostics properties",
        "il_patch": [
            "ldc.i4.1",
            "ret",
        ],
        "hex_patched": "17 2A",
        "dnspy_steps": [
            "1. Search for 'debug', 'diagnostic', 'devmode', 'verbose'",
            "2. Find boolean properties/methods",
            "3. Patch getter to return true",
            "4. Also check app.config for debug switches",
            "5. Look for #if DEBUG blocks that may reveal functionality",
        ],
    },
    "ssl_bypass": {
        "desc": "Disable SSL certificate validation",
        "target": "ServerCertificateValidationCallback, CertificatePolicy",
        "il_patch": [
            "ldc.i4.1",
            "ret",
        ],
        "hex_patched": "17 2A",
        "dnspy_steps": [
            "1. Search for 'ServerCertificateValidation', 'RemoteCertificate'",
            "2. Find the callback delegate method",
            "3. Patch to return true (accept all certs)",
            "4. Alternative: add to Main(): ServicePointManager.ServerCertificateValidationCallback = (a,b,c,d) => true;",
            "5. This enables Burp/mitmproxy interception",
        ],
    },
    "remove_integrity": {
        "desc": "Remove strong-name signature and integrity checks",
        "target": "Assembly strong name, tamper detection",
        "il_patch": [],
        "hex_patched": None,
        "dnspy_steps": [
            "1. Remove [assembly: AssemblyKeyFile] attribute",
            "2. Clear the public key from AssemblyDef.PublicKey",
            "3. Set HasPublicKey = false",
            "4. Search for checksum/hash validation methods",
            "5. Patch any file hash comparison to return true",
            "6. Remove Authenticode signature: signtool remove /s target.exe",
        ],
    },
    "disable_logging": {
        "desc": "Disable security audit logging (for stealth during pentest)",
        "target": "Log, Audit, Telemetry methods",
        "il_patch": [
            "ret",  # immediate return, skip all logging
        ],
        "hex_patched": "2A",
        "dnspy_steps": [
            "1. Search for 'audit', 'log', 'telemetry', 'analytics'",
            "2. Find methods that send data to server",
            "3. Patch: add 'ret' as first instruction (skip method body)",
            "4. Also check for HTTP POST calls reporting to telemetry endpoints",
        ],
    },
}

SEARCH_TERMS = {
    "auth": ["Authenticate", "Login", "ValidateUser", "CheckCredentials", "VerifyPassword",
             "IsAuthenticated", "SignIn", "Logon"],
    "license": ["IsLicensed", "CheckLicense", "ValidateLicense", "IsTrialExpired",
                "ActivationStatus", "LicenseKey", "IsRegistered", "DaysRemaining"],
    "role": ["IsAdmin", "HasPermission", "CheckRole", "IsAuthorized", "CanAccess",
             "UserRole", "RoleManager", "Authorize"],
    "crypto": ["Encrypt", "Decrypt", "AES", "DES", "RSA", "Hash", "HMAC", "SHA",
               "CryptoStream", "PasswordDeriveBytes", "Rfc2898"],
    "network": ["HttpClient", "WebRequest", "RestClient", "ApiCall", "SendRequest",
                "WebSocket", "TcpClient"],
    "storage": ["ConnectionString", "AppSettings", "Registry", "SaveCredentials",
                "SecureString", "ProtectedData", "DataProtection"],
}


def list_patterns():
    print(f"\n{'Pattern':<20} Description")
    print("=" * 80)
    for name, info in sorted(PATCH_PATTERNS.items()):
        print(f"{name:<20} {info['desc']}")
    print(f"\nTotal: {len(PATCH_PATTERNS)} patch patterns")


def show_pattern(pattern_name: str, class_name: str = None, method_name: str = None):
    if pattern_name not in PATCH_PATTERNS:
        print(f"[-] Unknown pattern: {pattern_name}")
        list_patterns()
        return

    p = PATCH_PATTERNS[pattern_name]
    print(f"\n=== {pattern_name.upper()} ===")
    print(f"Description: {p['desc']}")
    print(f"Target: {p['target']}")

    if class_name or method_name:
        print(f"\nTarget: {class_name or '?'}.{method_name or '?'}")

    if p["il_patch"]:
        print(f"\nIL Patch Instructions:")
        for i, instr in enumerate(p["il_patch"]):
            print(f"  IL_{i:04X}: {instr}")

    if p["hex_patched"]:
        print(f"\nHex bytes: {p['hex_patched']}")

    print(f"\ndnSpy Steps:")
    for step in p["dnspy_steps"]:
        print(f"  {step}")

    # Generate PowerShell binary patch command
    if p["hex_patched"] and class_name and method_name:
        hex_bytes = p["hex_patched"].replace(" ", "")
        print(f"\nQuick binary patch (PowerShell):")
        print(f"  # Find the method token in the assembly first")
        print(f"  # Then patch the method body bytes:")
        print(f'  $bytes = [System.IO.File]::ReadAllBytes("target.exe")')
        print(f'  # Locate method body offset using dnSpy or ILDasm')
        print(f'  # $offset = 0x????  # method body offset')
        print(f'  # $bytes[$offset] = 0x{hex_bytes[:2]}  # first patched byte')
        print(f'  # [System.IO.File]::WriteAllBytes("target_patched.exe", $bytes)')


def scan_assembly(assembly_path: str):
    print(f"\n[*] Scan suggestions for: {assembly_path}")
    print(f"[*] Use these search terms in dnSpy/ILSpy:\n")

    for category, terms in sorted(SEARCH_TERMS.items()):
        print(f"  [{category.upper()}]")
        for term in terms:
            print(f"    - Search: {term}")
        print()

    print("dnSpy Quick Search Commands:")
    print("  Ctrl+Shift+K — Search assemblies (method names, strings)")
    print("  Edit → Search Assemblies → search for each term above")
    print()
    print("ILDasm command-line search:")
    print(f'  ildasm /text "{assembly_path}" | findstr /i "password auth license"')
    print()
    print("strings extraction:")
    print(f'  strings "{assembly_path}" | findstr /i "password token secret key"')


def main():
    parser = argparse.ArgumentParser(description=".NET binary patching scripts")
    parser.add_argument("--list", action="store_true", help="List all patch patterns")
    parser.add_argument("--pattern", "-p", help="Patch pattern to use")
    parser.add_argument("--class", "-c", dest="class_name", help="Target class name")
    parser.add_argument("--method", "-m", help="Target method name")
    parser.add_argument("--assembly", "-a", help="Target assembly path")
    parser.add_argument("--scan", "-s", help="Scan assembly for interesting targets")
    args = parser.parse_args()

    if args.list:
        list_patterns()
    elif args.scan:
        scan_assembly(args.scan)
    elif args.pattern:
        show_pattern(args.pattern, args.class_name, args.method)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
