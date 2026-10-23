# rce — Remote Code Execution

Code execution techniques against desktop applications. Each subdirectory targets a different attack vector.

## Subdirectories

| Folder | Technique | Severity |
|--------|-----------|----------|
| [dll-hijack/](dll-hijack/) | DLL search-order hijacking — app loads attacker's DLL instead of legitimate one | HIGH-CRITICAL |
| [chm/](chm/) | Compiled HTML Help — ActiveX command execution via `.chm` files | HIGH |
| [process-injection/](process-injection/) | Inject shellcode/DLLs into running processes (3 techniques) | HIGH |

## Which to Use First

1. **DLL Hijack** — Easiest; just place a DLL in the right path. Start here.
2. **CHM** — If the app uses `.chm` help files or has a help import feature.
3. **Process Injection** — When you need to execute code in the context of a running process (e.g., to inherit its privileges or network access).
