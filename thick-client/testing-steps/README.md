# Testing Steps — VAPT Desktop Checklist

Comprehensive methodology for desktop/thick client application penetration testing.

## Files

| File | Description |
|------|-------------|
| [`vapt_desktop_checklist.md`](vapt_desktop_checklist.md) | 15-section checklist covering: DLL hijack, CHM, process injection, file imports, reverse shells, credential storage, memory analysis, MitM, privilege escalation, binary patching, Electron/CEF, COM hijack, DDE injection, post-exploitation, evidence collection |

## Checklist Sections

| # | Section | Maps To |
|---|---------|---------|
| 1 | DLL Hijacking / Sideloading | `rce/dll-hijack/` |
| 2 | CHM Exploitation | `rce/chm/` |
| 3 | Process Injection | `rce/process-injection/` |
| 4 | File Import Feature Testing | `import-feature/` |
| 5 | Reverse Shell Confirmation | `reverse-shell/` |
| 6 | Insecure Credential Storage | `insecure-storage/` |
| 7 | Sensitive Data in Memory | `memory-analysis/` |
| 8 | Insecure Communication / MitM | `network-mitm/` |
| 9 | Privilege Escalation | `privilege-escalation/` |
| 10 | Binary Patching / Auth Bypass | `binary-patching/` |
| 11 | Electron/CEF Attacks | `electron-cef/` |
| 12 | COM Hijacking | `com-hijack/` |
| 13 | CSV/DDE Formula Injection | `import-feature/csv_dde_injection.py` |
| 14 | Post-Exploitation Checks | — |
| 15 | Evidence Collection | — |

## How to Use

Follow the checklist section by section during an assessment. Each section links to the corresponding payload directory with build commands, test steps, and expected results.
