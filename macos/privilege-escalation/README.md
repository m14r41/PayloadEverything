# macOS Privilege Escalation

Techniques for escalating privileges on macOS systems.

**MITRE ATT&CK**: T1548 (Abuse Elevation), T1574.004 (Dylib Hijacking)

## Files

| File | Description |
|------|-------------|
| [`tcc_bypass.md`](tcc_bypass.md) | TCC bypass — terminal inheritance, Finder automation, direct TCC.db modification, MDM profiles, plugin injection, synthetic clicks, CVE-based bypasses |
| [`dylib_hijack.md`](dylib_hijack.md) | dylib hijacking — @rpath/@loader_path, DYLD_INSERT_LIBRARIES, Electron apps, framework hijacking, install_name_tool manipulation |
| [`sudo_exploits.md`](sudo_exploits.md) | sudo exploitation — enumeration, timestamp abuse, Touch ID bypass, CVE-2019-18634, GTFOBins for macOS, authorization database, env variable abuse |
| [`installer_abuse.md`](installer_abuse.md) | Package installer exploitation — malicious .pkg with root scripts, productbuild, plugin injection, update interception, authorization rights |

## Quick Test

```bash
# Check for easy wins
sudo -l                                           # NOPASSWD entries?
csrutil status                                    # SIP disabled?
sudo -n id 2>/dev/null && echo "SUDO CACHED"      # Cached credentials?
ls -la ~/Applications/*/Contents/Frameworks/ 2>/dev/null  # Writable frameworks?
```
