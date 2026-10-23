<#
.SYNOPSIS
    Active Directory enumeration using native PowerShell (no modules required).
.DESCRIPTION
    Enumerates domain info, users, groups, computers, GPOs, trusts, SPNs,
    delegation, ACLs, password policy, AdminSDHolder, and LAPS.
    Falls back to LDAP/ADSI when AD modules are unavailable.
.PARAMETER Domain
    Target domain (default: current domain).
.PARAMETER OutFile
    Optional path to save results.
.EXAMPLE
    .\ad_enum.ps1
    .\ad_enum.ps1 -Domain corp.local -OutFile C:\temp\ad_enum.txt
#>
param(
    [string]$Domain,
    [string]$OutFile
)

function Write-Banner {
    param([string]$Title)
    $sep = "=" * 70
    Write-Output "`n$sep"
    Write-Output "  $Title"
    Write-Output "$sep`n"
}

function Get-LDAPSearch {
    param(
        [string]$Filter,
        [string[]]$Properties = @("*"),
        [string]$SearchBase
    )
    $searcher = New-Object DirectoryServices.DirectorySearcher
    if ($SearchBase) {
        $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$SearchBase")
    } elseif ($Domain) {
        $dn = ($Domain -split '\.' | ForEach-Object { "DC=$_" }) -join ','
        $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$dn")
    }
    $searcher.Filter = $Filter
    $searcher.PageSize = 1000
    foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
    try { $searcher.FindAll() } catch { Write-Output "[!] LDAP query failed: $_"; @() }
}

$results = & {

Write-Banner "DOMAIN INFORMATION"
try {
    $domObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    Write-Output "Domain Name       : $($domObj.Name)"
    Write-Output "Forest Name       : $($domObj.Forest.Name)"
    Write-Output "Domain Controllers:"
    foreach ($dc in $domObj.DomainControllers) {
        Write-Output "  $($dc.Name) [$($dc.IPAddress)] - $($dc.OSVersion)"
    }
    Write-Output "Forest Func Level : $($domObj.Forest.ForestModeLevel)"
    Write-Output "Domain Func Level : $($domObj.DomainModeLevel)"
    $rootDSE = [ADSI]"LDAP://RootDSE"
    Write-Output "Naming Context    : $($rootDSE.defaultNamingContext)"
    Write-Output "Schema            : $($rootDSE.schemaNamingContext)"
    Write-Output "Config            : $($rootDSE.configurationNamingContext)"
} catch { Write-Output "[!] Not domain-joined or cannot reach DC: $_" }

Write-Banner "PASSWORD POLICY"
try {
    $policy = Get-LDAPSearch -Filter "(objectClass=domain)" -Properties @(
        "minPwdLength","maxPwdAge","minPwdAge","pwdHistoryLength",
        "lockoutThreshold","lockoutDuration","lockoutObservationWindow","pwdProperties"
    )
    foreach ($p in $policy) {
        $props = $p.Properties
        Write-Output "Min Password Length  : $($props['minpwdlength'][0])"
        $maxAge = [TimeSpan]::FromTicks([Math]::Abs($props['maxpwdage'][0]))
        Write-Output "Max Password Age     : $($maxAge.Days) days"
        Write-Output "Password History     : $($props['pwdhistorylength'][0])"
        Write-Output "Lockout Threshold    : $($props['lockoutthreshold'][0])"
        $lockDur = [TimeSpan]::FromTicks([Math]::Abs($props['lockoutduration'][0]))
        Write-Output "Lockout Duration     : $($lockDur.TotalMinutes) minutes"
        $complexity = if ($props['pwdproperties'][0] -band 1) { "Enabled" } else { "Disabled" }
        Write-Output "Complexity Required  : $complexity"
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "DOMAIN ADMINS"
try {
    $daMembers = Get-LDAPSearch -Filter "(&(objectCategory=group)(cn=Domain Admins))" -Properties @("member")
    foreach ($g in $daMembers) {
        foreach ($m in $g.Properties['member']) {
            $user = Get-LDAPSearch -Filter "(distinguishedName=$m)" -Properties @("sAMAccountName","adminCount","lastLogonTimestamp")
            foreach ($u in $user) {
                $lastLogon = if ($u.Properties['lastlogontimestamp']) {
                    [DateTime]::FromFileTime($u.Properties['lastlogontimestamp'][0]).ToString('yyyy-MM-dd')
                } else { "Never" }
                Write-Output "  $($u.Properties['samaccountname'][0])  (adminCount=$($u.Properties['admincount'][0]))  LastLogon=$lastLogon"
            }
        }
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "ENTERPRISE ADMINS"
try {
    $eaMembers = Get-LDAPSearch -Filter "(&(objectCategory=group)(cn=Enterprise Admins))" -Properties @("member")
    foreach ($g in $eaMembers) {
        foreach ($m in $g.Properties['member']) {
            Write-Output "  $($m -replace ',.*$','' -replace '^CN=','')"
        }
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "ALL USERS (Enabled)"
try {
    $users = Get-LDAPSearch -Filter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
        -Properties @("sAMAccountName","description","adminCount","pwdLastSet","lastLogonTimestamp","servicePrincipalName","userAccountControl")
    $count = 0
    foreach ($u in $users) {
        $props = $u.Properties
        $spn = if ($props['serviceprincipalname'].Count -gt 0) { "YES" } else { "-" }
        $uac = [int]$props['useraccountcontrol'][0]
        $noPreAuth = if ($uac -band 0x400000) { "NO_PREAUTH" } else { "-" }
        $pwdSet = if ($props['pwdlastset'][0] -gt 0) {
            [DateTime]::FromFileTime($props['pwdlastset'][0]).ToString('yyyy-MM-dd')
        } else { "Never" }
        Write-Output "  $($props['samaccountname'][0]) | SPN=$spn | $noPreAuth | PwdSet=$pwdSet | Desc=$($props['description'][0])"
        $count++
    }
    Write-Output "`n[*] Total enabled users: $count"
} catch { Write-Output "[!] Error: $_" }

Write-Banner "KERBEROASTABLE ACCOUNTS (Users with SPNs)"
try {
    $spnUsers = Get-LDAPSearch -Filter "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
        -Properties @("sAMAccountName","servicePrincipalName","adminCount","memberOf","pwdLastSet")
    foreach ($u in $spnUsers) {
        $props = $u.Properties
        $pwdSet = if ($props['pwdlastset'][0] -gt 0) {
            [DateTime]::FromFileTime($props['pwdlastset'][0]).ToString('yyyy-MM-dd')
        } else { "Never" }
        Write-Output "[!] $($props['samaccountname'][0]) | AdminCount=$($props['admincount'][0]) | PwdSet=$pwdSet"
        foreach ($s in $props['serviceprincipalname']) { Write-Output "    SPN: $s" }
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "AS-REP ROASTABLE (No Pre-Auth)"
try {
    $noPreAuth = Get-LDAPSearch -Filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
        -Properties @("sAMAccountName","memberOf")
    foreach ($u in $noPreAuth) {
        Write-Output "[!] $($u.Properties['samaccountname'][0])"
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "UNCONSTRAINED DELEGATION"
try {
    $unconstrained = Get-LDAPSearch -Filter "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(primaryGroupID=516)))" `
        -Properties @("sAMAccountName","dNSHostName","userAccountControl")
    foreach ($u in $unconstrained) {
        Write-Output "[!] $($u.Properties['samaccountname'][0]) ($($u.Properties['dnshostname'][0]))"
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "CONSTRAINED DELEGATION"
try {
    $constrained = Get-LDAPSearch -Filter "(msDS-AllowedToDelegateTo=*)" `
        -Properties @("sAMAccountName","msDS-AllowedToDelegateTo","userAccountControl")
    foreach ($u in $constrained) {
        Write-Output "[!] $($u.Properties['samaccountname'][0])"
        foreach ($d in $u.Properties['msds-allowedtodelegateto']) {
            Write-Output "    -> $d"
        }
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "RESOURCE-BASED CONSTRAINED DELEGATION (RBCD)"
try {
    $rbcd = Get-LDAPSearch -Filter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" `
        -Properties @("sAMAccountName","msDS-AllowedToActOnBehalfOfOtherIdentity")
    foreach ($u in $rbcd) {
        Write-Output "[!] $($u.Properties['samaccountname'][0]) has RBCD configured"
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "COMPUTERS"
try {
    $computers = Get-LDAPSearch -Filter "(objectCategory=computer)" `
        -Properties @("sAMAccountName","dNSHostName","operatingSystem","operatingSystemVersion","lastLogonTimestamp")
    $count = 0
    foreach ($c in $computers) {
        $props = $c.Properties
        $lastLogon = if ($props['lastlogontimestamp']) {
            [DateTime]::FromFileTime($props['lastlogontimestamp'][0]).ToString('yyyy-MM-dd')
        } else { "Never" }
        Write-Output "  $($props['dnshostname'][0]) | $($props['operatingsystem'][0]) $($props['operatingsystemversion'][0]) | Last=$lastLogon"
        $count++
    }
    Write-Output "`n[*] Total computers: $count"
} catch { Write-Output "[!] Error: $_" }

Write-Banner "DOMAIN TRUSTS"
try {
    $trusts = Get-LDAPSearch -Filter "(objectClass=trustedDomain)" `
        -Properties @("name","trustDirection","trustType","trustAttributes")
    foreach ($t in $trusts) {
        $dir = switch ([int]$t.Properties['trustdirection'][0]) {
            1 { "Inbound" }
            2 { "Outbound" }
            3 { "Bidirectional" }
            default { "Unknown" }
        }
        Write-Output "  $($t.Properties['name'][0]) | Direction=$dir | Type=$($t.Properties['trusttype'][0])"
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "GROUP POLICY OBJECTS"
try {
    $gpos = Get-LDAPSearch -Filter "(objectClass=groupPolicyContainer)" `
        -Properties @("displayName","gPCFileSysPath","versionNumber")
    foreach ($g in $gpos) {
        Write-Output "  $($g.Properties['displayname'][0])"
        Write-Output "    Path: $($g.Properties['gpcfilesyspath'][0])"
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "LAPS (Local Administrator Password Solution)"
try {
    $laps = Get-LDAPSearch -Filter "(&(objectCategory=computer)(ms-MCS-AdmPwd=*))" `
        -Properties @("sAMAccountName","ms-MCS-AdmPwd","ms-MCS-AdmPwdExpirationTime")
    if ($laps.Count -gt 0) {
        Write-Output "[+] LAPS passwords readable by current user:"
        foreach ($c in $laps) {
            Write-Output "  $($c.Properties['samaccountname'][0]) : $($c.Properties['ms-mcs-admpwd'][0])"
        }
    } else {
        Write-Output "[-] No LAPS passwords readable (may not be deployed or insufficient permissions)"
    }
    $schemaLaps = Get-LDAPSearch -Filter "(name=ms-MCS-AdmPwd)" `
        -Properties @("name") -SearchBase ($([ADSI]"LDAP://RootDSE").schemaNamingContext.ToString())
    if ($schemaLaps.Count -gt 0) {
        Write-Output "[*] LAPS schema attribute exists (LAPS is deployed)"
    } else {
        Write-Output "[-] LAPS schema attribute not found (LAPS not deployed)"
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "ADMINSDHOLDER PROTECTED OBJECTS"
try {
    $adminSD = Get-LDAPSearch -Filter "(&(objectCategory=person)(adminCount=1))" `
        -Properties @("sAMAccountName","memberOf")
    foreach ($u in $adminSD) {
        Write-Output "  $($u.Properties['samaccountname'][0])"
    }
} catch { Write-Output "[!] Error: $_" }

Write-Banner "USERS WITH DCSYNC RIGHTS"
try {
    $rootDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext.ToString()
    $domainObj = [ADSI]"LDAP://$rootDN"
    $acl = $domainObj.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
    $dsyncGuids = @(
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"   # DS-Replication-Get-Changes-All
    )
    $acl | Where-Object {
        $_.ActiveDirectoryRights -match 'ExtendedRight' -and
        ($_.ObjectType.ToString() -in $dsyncGuids -or $_.ObjectType.ToString() -eq "00000000-0000-0000-0000-000000000000")
    } | ForEach-Object {
        Write-Output "[!] $($_.IdentityReference) has DCSync rights ($($_.ObjectType))"
    }
} catch { Write-Output "[!] Error: $_" }

} *>&1

if ($OutFile) {
    $results | Out-File -FilePath $OutFile -Encoding utf8
    Write-Host "[+] Results saved to $OutFile"
} else {
    $results
}
