<#
.SYNOPSIS
    Comprehensive Windows local enumeration for VAPT engagements.
.DESCRIPTION
    Gathers system info, users, groups, network, services, scheduled tasks,
    installed software, PowerShell history, firewall rules, hotfixes,
    environment variables, shares, named pipes, and writable directories.
.PARAMETER OutFile
    Optional path to save results to a file.
.EXAMPLE
    .\windows_enum.ps1
    .\windows_enum.ps1 -OutFile C:\temp\enum.txt
#>
param(
    [string]$OutFile
)

function Write-Banner {
    param([string]$Title)
    $sep = "=" * 70
    Write-Output "`n$sep"
    Write-Output "  $Title"
    Write-Output "$sep`n"
}

$results = & {

Write-Banner "SYSTEM INFORMATION"
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    Write-Output "Hostname       : $($env:COMPUTERNAME)"
    Write-Output "Domain         : $($cs.Domain)"
    Write-Output "OS             : $($os.Caption) $($os.Version)"
    Write-Output "Build          : $($os.BuildNumber)"
    Write-Output "Architecture   : $($os.OSArchitecture)"
    Write-Output "Install Date   : $($os.InstallDate)"
    Write-Output "Last Boot      : $($os.LastBootUpTime)"
    Write-Output "System Dir     : $($os.SystemDirectory)"
    Write-Output "Logon Server   : $($env:LOGONSERVER)"
    Write-Output "Current User   : $($env:USERDOMAIN)\$($env:USERNAME)"
    $priv = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Output "Is Admin       : $priv"
    Write-Output "Integrity      : $(whoami /groups | Select-String 'Mandatory Label')"
} catch { Write-Output "[!] Error gathering system info: $_" }

Write-Banner "CURRENT USER PRIVILEGES"
try {
    whoami /priv | Where-Object { $_ -match "Se" }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "LOCAL USERS"
try {
    Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
        Format-Table Name, Disabled, PasswordRequired, PasswordChangeable, SID -AutoSize
} catch { Write-Output "[!] Error: $_" }

Write-Banner "LOCAL GROUPS"
try {
    Get-CimInstance Win32_Group -Filter "LocalAccount=True" |
        Format-Table Name, Description -AutoSize
} catch { Write-Output "[!] Error: $_" }

Write-Banner "LOCAL ADMINS"
try {
    net localgroup Administrators 2>$null
} catch { Write-Output "[!] Error: $_" }

Write-Banner "NETWORK CONFIGURATION"
try {
    Get-NetIPAddress -ErrorAction SilentlyContinue |
        Where-Object { $_.AddressFamily -eq 'IPv4' } |
        Format-Table InterfaceAlias, IPAddress, PrefixLength -AutoSize
    Write-Output "`nDNS Servers:"
    Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
        Where-Object { $_.ServerAddresses } |
        Format-Table InterfaceAlias, ServerAddresses -AutoSize
    Write-Output "`nRouting Table:"
    Get-NetRoute -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -ne '0.0.0.0/0' -and $_.DestinationPrefix -notmatch '^ff' } |
        Select-Object -First 20 |
        Format-Table DestinationPrefix, NextHop, InterfaceAlias -AutoSize
    Write-Output "`nARP Table:"
    Get-NetNeighbor -ErrorAction SilentlyContinue |
        Where-Object { $_.State -ne 'Unreachable' } |
        Format-Table IPAddress, LinkLayerAddress, State, InterfaceAlias -AutoSize
} catch { Write-Output "[!] Error: $_" }

Write-Banner "LISTENING PORTS"
try {
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Sort-Object LocalPort |
        ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Port    = $_.LocalPort
                Address = $_.LocalAddress
                PID     = $_.OwningProcess
                Process = $proc.ProcessName
            }
        } | Format-Table -AutoSize
} catch { Write-Output "[!] Error: $_" }

Write-Banner "ESTABLISHED CONNECTIONS"
try {
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                LocalAddr  = "$($_.LocalAddress):$($_.LocalPort)"
                RemoteAddr = "$($_.RemoteAddress):$($_.RemotePort)"
                PID        = $_.OwningProcess
                Process    = $proc.ProcessName
            }
        } | Format-Table -AutoSize
} catch { Write-Output "[!] Error: $_" }

Write-Banner "SERVICES (Non-Default)"
try {
    Get-CimInstance Win32_Service |
        Where-Object { $_.PathName -and $_.PathName -notmatch 'C:\\Windows\\system32\\svchost' } |
        Select-Object Name, StartMode, State, @{N='RunAs';E={$_.StartName}}, PathName |
        Format-Table -AutoSize -Wrap
} catch { Write-Output "[!] Error: $_" }

Write-Banner "UNQUOTED SERVICE PATHS"
try {
    Get-CimInstance Win32_Service |
        Where-Object {
            $_.PathName -and
            $_.PathName -notmatch '^"' -and
            $_.PathName -notmatch '^C:\\Windows\\' -and
            $_.PathName -match '\s'
        } |
        Select-Object Name, PathName, StartMode, @{N='RunAs';E={$_.StartName}} |
        Format-Table -AutoSize -Wrap
} catch { Write-Output "[!] Error: $_" }

Write-Banner "SCHEDULED TASKS (Non-Microsoft)"
try {
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.Author -notmatch 'Microsoft' -and $_.TaskPath -notmatch '\\Microsoft\\' } |
        ForEach-Object {
            $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Name    = $_.TaskName
                Path    = $_.TaskPath
                State   = $_.State
                RunAs   = $_.Principal.UserId
                Action  = ($_.Actions | ForEach-Object { $_.Execute }) -join '; '
                LastRun = $info.LastRunTime
            }
        } | Format-Table -AutoSize -Wrap
} catch { Write-Output "[!] Error: $_" }

Write-Banner "INSTALLED SOFTWARE"
try {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty $paths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Sort-Object DisplayName |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Format-Table -AutoSize
} catch { Write-Output "[!] Error: $_" }

Write-Banner "POWERSHELL HISTORY"
try {
    $histPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $histPath) {
        Write-Output "[+] History file: $histPath"
        Write-Output "[+] Last 50 commands:"
        Get-Content $histPath -Tail 50
    } else {
        Write-Output "[-] No PowerShell history found at $histPath"
    }
    $otherUsers = Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue
    foreach ($h in $otherUsers) {
        Write-Output "`n[+] Found history: $($h.FullName)"
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "FIREWALL STATUS"
try {
    Get-NetFirewallProfile -ErrorAction SilentlyContinue |
        Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize
} catch { Write-Output "[!] Error: $_" }

Write-Banner "FIREWALL RULES (Allow Inbound, Non-Default)"
try {
    Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayGroup -notmatch 'Core Networking|File and Printer' } |
        Select-Object -First 30 DisplayName, Profile, Direction, Action |
        Format-Table -AutoSize
} catch { Write-Output "[!] Error: $_" }

Write-Banner "HOTFIXES"
try {
    Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue |
        Select-Object -First 20 HotFixID, Description, InstalledOn |
        Format-Table -AutoSize
} catch { Write-Output "[!] Error: $_" }

Write-Banner "ENVIRONMENT VARIABLES (Interesting)"
try {
    $interesting = @('PATH','TEMP','TMP','APPDATA','LOCALAPPDATA','PROGRAMFILES','PROGRAMFILES(X86)',
                     'USERPROFILE','HOMEDRIVE','HOMEPATH','LOGONSERVER','USERDOMAIN','PROCESSOR_ARCHITECTURE')
    foreach ($v in $interesting) {
        $val = [Environment]::GetEnvironmentVariable($v)
        if ($val) { Write-Output "${v} = $val" }
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "NETWORK SHARES"
try {
    Get-SmbShare -ErrorAction SilentlyContinue |
        Format-Table Name, Path, Description -AutoSize
    Write-Output "`nMapped Drives:"
    Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayRoot } |
        Format-Table Name, DisplayRoot -AutoSize
} catch { Write-Output "[!] Error: $_" }

Write-Banner "NAMED PIPES"
try {
    Get-ChildItem \\.\pipe\ -ErrorAction SilentlyContinue |
        Select-Object -First 50 Name |
        Format-Table -AutoSize
} catch { Write-Output "[!] Error: $_" }

Write-Banner "WRITABLE DIRECTORIES (Common Paths)"
try {
    $testPaths = @(
        "C:\",
        "C:\Windows\Temp",
        "C:\Windows\Tasks",
        "C:\Windows\Tracing",
        "C:\Windows\System32\spool\drivers\color",
        "$env:TEMP",
        "$env:USERPROFILE"
    )
    foreach ($p in $testPaths) {
        if (Test-Path $p) {
            $acl = Get-Acl $p -ErrorAction SilentlyContinue
            $writable = $acl.Access | Where-Object {
                $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                $_.IdentityReference -match 'Users|Everyone|Authenticated'
            }
            if ($writable) {
                Write-Output "[+] WRITABLE: $p"
                $writable | ForEach-Object { Write-Output "    $($_.IdentityReference) : $($_.FileSystemRights)" }
            }
        }
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "ANTIVIRUS / EDR"
try {
    Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue |
        Format-Table displayName, pathToSignedProductExe -AutoSize
    Write-Output "`nRunning security processes:"
    $secProcs = @('MsMpEng','MsSense','SenseIR','SenseCncProxy','cb','CbDefense',
                  'CylanceSvc','CSFalconService','CSFalconContainer','bdagent',
                  'kavtray','avp','savservice','SEPMasterService')
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -in $secProcs } |
        Format-Table ProcessName, Id, Path -AutoSize
} catch { Write-Output "[!] Error: $_" }

Write-Banner "DPAPI MASTER KEYS"
try {
    $dpapi = "$env:APPDATA\Microsoft\Protect"
    if (Test-Path $dpapi) {
        Write-Output "[+] DPAPI master key directory: $dpapi"
        Get-ChildItem $dpapi -Recurse -ErrorAction SilentlyContinue |
            Format-Table Name, Length, LastWriteTime -AutoSize
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "RECENTLY MODIFIED FILES (Last 7 days, user profile)"
try {
    Get-ChildItem $env:USERPROFILE -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and $_.Extension -match '\.(txt|xml|config|json|ini|ps1|bat|cmd|log)$' } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 30 FullName, Length, LastWriteTime |
        Format-Table -AutoSize -Wrap
} catch { Write-Output "[!] Error: $_" }

} *>&1

if ($OutFile) {
    $results | Out-File -FilePath $OutFile -Encoding utf8
    Write-Host "[+] Results saved to $OutFile"
} else {
    $results
}
