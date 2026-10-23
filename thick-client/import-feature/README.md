# Import Feature — File Parsing Attack Surface

Payloads targeting desktop application file import/open features. When an app imports a file, it parses it — and parsers have vulnerabilities.

**OWASP**: TC6, TC10  
**Severity**: HIGH to CRITICAL

## Files

| File | Attack Vector | Targets |
|------|--------------|---------|
| [`sln_payload.py`](sln_payload.py) | MSBuild pre/post-build events in .sln/.csproj/.vcxproj | IDEs, build systems, project importers |
| [`zip_slip.py`](zip_slip.py) | Path traversal in ZIP extraction (Zip Slip) | Any app that imports .zip archives |
| [`xml_xxe.py`](xml_xxe.py) | XXE in XML parsers (7 variants + SVG + XSLT) | Any app parsing XML, SVG, config files |
| [`dcl_payload.py`](dcl_payload.py) | AutoLISP/DCL command execution | AutoCAD, CAD viewers |
| [`csv_dde_injection.py`](csv_dde_injection.py) | DDE/formula injection in CSV exports | Apps that export to CSV/XLSX |
| [`common_import_formats.md`](common_import_formats.md) | Reference table of 40+ import formats and attack vectors | Assessment planning |
| [deserialization/](deserialization/) | .NET deserialization via ysoserial.net | .NET thick clients |

## Usage Pattern

```bash
# Generate payloads
python -I sln_payload.py --output mal_project --cmd calc.exe
python -I zip_slip.py --output traversal.zip --type all
python -I xml_xxe.py --output xxe_payloads/ --type all
python -I dcl_payload.py --output cad_payloads/ --type all
python -I csv_dde_injection.py --output dde_payloads/ --type all
```

## Testing Approach

1. Identify every "Import", "Open", "Load" feature in the application
2. Check what file formats are accepted
3. Cross-reference with `common_import_formats.md` for known attack vectors
4. Generate appropriate payloads
5. Import through the application and observe behavior
