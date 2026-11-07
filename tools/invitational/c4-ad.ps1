# c4-ad.ps1 -- C4 Active Directory dump for the domain controller.
#
# Observe only: reads AD through the ActiveDirectory and GroupPolicy modules
# and writes only under $InvRoot. The archive name carries SENSITIVE because
# account descriptions and ACLs belong in the private Nextcloud folder only.
#
# Usage (elevated PowerShell on a DC):
#   powershell -NoProfile -ExecutionPolicy Bypass -File c4-ad.ps1

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'lib.ps1')

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Output 'c4: ActiveDirectory module not found; nothing written (run on a domain controller)'
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

$script:InvRoot = 'C:\ProgramData\phylax-inv'
Inv-Init -Cid c4 | Out-Null

# Users: the fields answer the account and SPN questions without touching
# password material.
Inv-Run -Name users -Script {
    Get-ADUser -Filter * -Properties * |
        Select-Object SamAccountName, Enabled, Description, ServicePrincipalName,
            PasswordLastSet, PasswordNeverExpires, LastLogonDate, adminCount,
            @{Name = 'MemberOf'; Expression = { ($_.MemberOf | Sort-Object) -join ';' }},
            UserAccountControl, whenCreated |
        Export-Csv -LiteralPath (Join-Path $script:InvOut 'users.csv') -NoTypeInformation -Encoding UTF8
}

Inv-Run -Name groups -Script {
    Get-ADGroup -Filter * -Properties * |
        Select-Object Name, SamAccountName, GroupCategory, GroupScope, DistinguishedName,
            Description, ManagedBy, whenCreated,
            @{Name = 'Member'; Expression = { ($_.Member | Sort-Object) -join ';' }},
            @{Name = 'MemberOf'; Expression = { ($_.MemberOf | Sort-Object) -join ';' }} |
        Export-Csv -LiteralPath (Join-Path $script:InvOut 'groups.csv') -NoTypeInformation -Encoding UTF8
}

Inv-Run -Name computers -Script {
    Get-ADComputer -Filter * -Properties * |
        Select-Object Name, SamAccountName, Enabled, OperatingSystem,
            OperatingSystemVersion, LastLogonDate, PasswordLastSet, Description,
            DistinguishedName, whenCreated,
            @{Name = 'MemberOf'; Expression = { ($_.MemberOf | Sort-Object) -join ';' }} |
        Export-Csv -LiteralPath (Join-Path $script:InvOut 'computers.csv') -NoTypeInformation -Encoding UTF8
}

Inv-Run -Name ou -Script {
    Get-ADOrganizationalUnit -Filter * -Properties * |
        Select-Object Name, DistinguishedName, Description,
            ProtectedFromAccidentalDeletion, ManagedBy, whenCreated |
        Export-Csv -LiteralPath (Join-Path $script:InvOut 'ou.csv') -NoTypeInformation -Encoding UTF8
}

# Privileged members, recursive. A missing optional group is recorded as an
# error row and the remaining groups are still queried.
Inv-Run -Name privileged -Script {
    $groups = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
        'Account Operators', 'Backup Operators', 'DnsAdmins', 'Server Operators',
        'Print Operators', 'Group Policy Creator Owners'
    )
    $rows = foreach ($g in $groups) {
        try {
            Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop |
                Select-Object @{Name = 'Group'; Expression = { $g }},
                    Name, SamAccountName, objectClass, distinguishedName
        } catch {
            [pscustomobject]@{
                Group = $g
                Name = 'ERROR: ' + $_.Exception.Message
                SamAccountName = ''
                objectClass = ''
                distinguishedName = ''
            }
        }
    }
    $rows | Export-Csv -LiteralPath (Join-Path $script:InvOut 'privileged.csv') -NoTypeInformation -Encoding UTF8
}

# Duplicate group names (the ~500 duplicate groups report).
Inv-Run -Name duplicates -Script {
    Get-ADGroup -Filter * -Properties Name, DistinguishedName |
        Group-Object Name |
        Where-Object { $_.Count -gt 1 } |
        Select-Object Name, Count,
            @{Name = 'DistinguishedNames'; Expression = {
                ($_.Group | ForEach-Object { $_.DistinguishedName }) -join ';'
            }} |
        Export-Csv -LiteralPath (Join-Path $script:InvOut 'duplicates.csv') -NoTypeInformation -Encoding UTF8
}

Inv-Run -Name krbtgt -Script {
    Get-ADUser -Identity krbtgt -Properties PasswordLastSet |
        Format-List SamAccountName, PasswordLastSet
}

Inv-Run -Name domain -Script {
    $domain = Get-ADDomain
    $forest = Get-ADForest
    $lines = @()
    $lines += '=== Get-ADDomain ==='
    $lines += ($domain | Format-List * | Out-String)
    $lines += '=== Get-ADForest ==='
    $lines += ($forest | Format-List * | Out-String)
    $lines += '=== functional levels ==='
    $lines += ('DomainMode: ' + $domain.DomainMode)
    $lines += ('ForestMode: ' + $forest.ForestMode)
    $lines += '=== Recycle Bin (Get-ADOptionalFeature) ==='
    $lines += (Get-ADOptionalFeature -Filter * |
        Select-Object Name, FeatureScope, EnabledScopes |
        Format-List | Out-String)
    $lines
}

Inv-Run -Name pwpolicy -Script {
    $lines = @()
    $lines += '=== Get-ADDefaultDomainPasswordPolicy ==='
    $lines += (Get-ADDefaultDomainPasswordPolicy | Format-List * | Out-String)
    $lines += '=== Get-ADFineGrainedPasswordPolicy ==='
    $lines += (Get-ADFineGrainedPasswordPolicy -Filter * | Format-List * | Out-String)
    $lines
}

Inv-Run -Name gpo -Script {
    Get-GPOReport -All -ReportType Xml |
        Out-File -LiteralPath (Join-Path $script:InvOut 'gpo.xml') -Encoding utf8
}

Inv-Run -Name acl -Script {
    $dn = (Get-ADDomain).DistinguishedName
    & dsacls $dn
}

# Hardening values live in different hives; a missing value records its exit
# code and does not fail the item.
Inv-Run -Name hardening -Script {
    $checks = @(
        @{ Path = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Value = 'LmCompatibilityLevel' },
        @{ Path = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Value = 'LDAPServerIntegrity' },
        @{ Path = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Value = 'RequireSignOrSeal' },
        @{ Path = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Value = 'FullSecureChannelProtection' },
        @{ Path = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Value = 'RequireSecuritySignature' },
        @{ Path = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Value = 'RestrictAnonymous' }
    )
    $ErrorActionPreference = 'Continue' # a missing value is stderr from reg.exe, not a failure
    foreach ($c in $checks) {
        Write-Output ('=== ' + $c.Value)
        & reg query $c.Path /v $c.Value 2>&1
        Write-Output ('exit: ' + $LASTEXITCODE)
    }
    $global:LASTEXITCODE = 0
}

Inv-Run -Name repl -Script {
    Write-Output '=== repadmin /replsummary'
    & repadmin /replsummary 2>&1
    Write-Output '=== nltest /dclist:'
    & nltest /dclist: 2>&1
    $global:LASTEXITCODE = 0
}

$sensitive = @(
    'SENSITIVE: this archive contains Active Directory user, group and computer',
    'inventory, GPO, password-policy and ACL data. Account descriptions and',
    'group membership can carry secrets. Upload it only to the private',
    'Nextcloud folder, never to the shared Invitational folder.'
)
$sensitive | Out-File -LiteralPath (Join-Path $script:InvOut 'SENSITIVE.txt') -Encoding utf8

$packed = Inv-Pack
$archive = ($packed -split ' ')[0]
if (-not $archive) {
    Write-Output 'c4: packing failed'
    exit 1
}
$marked = $archive -replace '\.zip$', '-SENSITIVE.zip'
Rename-Item -LiteralPath $archive -NewName (Split-Path -Leaf $marked)
$bytes = (Get-Item -LiteralPath $marked).Length
$sha = (Get-FileHash -LiteralPath $marked -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output ($marked + ' ' + $bytes + ' ' + $sha)
