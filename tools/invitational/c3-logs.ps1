# c3-logs.ps1 -Label mid|end [-SinceHours 5] -- C3 log bulk copy for Windows.
#
# Exports the Windows event channels offline analysis needs (data doc C3:
# Security, System, Sysmon, PowerShell, WinRM and Directory Service on a DC) for
# the last few hours, then copies the SQL Server, IIS and DNS text logs when the
# host has them. Observe only: exports and copies land under $InvRoot, nothing
# on the host is changed. Run it from an elevated PowerShell (wevtutil needs
# admin for Security).
#
# shortcut: zip caps at 2 GB, switch to tar.exe if an evtx set exceeds it

[CmdletBinding()]
param(
    [ValidateSet('mid', 'end')]
    [string]$Label = 'mid',
    [int]$SinceHours = 5
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

. (Join-Path $PSScriptRoot 'lib.ps1')

$script:InvRoot = 'C:\ProgramData\phylax-inv'
Inv-Init -Cid ('c3-' + $Label) | Out-Null

$ms = [int64]$SinceHours * 3600 * 1000
$script:C3Query = '*[System[TimeCreated[timediff(@SystemTime) <= ' + $ms + ']]]'
$script:C3Name = ''
$script:C3Channel = ''
$script:C3Pattern = ''
$script:C3Sub = ''

$channels = @(
    'Security'
    'System'
    'Application'
    'Microsoft-Windows-Sysmon/Operational'
    'Microsoft-Windows-PowerShell/Operational'
    'Microsoft-Windows-WinRM/Operational'
)

# The Directory Service channel exists only on a domain controller.
& wevtutil gl 'Directory Service' 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    $channels += 'Directory Service'
}

foreach ($channel in $channels) {
    $script:C3Channel = $channel
    $script:C3Name = 'evtx-' + ($channel -replace '[^A-Za-z0-9]+', '-')
    Inv-Run -Name $script:C3Name -Script {
        $dest = Join-Path $script:InvOut ($script:C3Name + '.evtx')
        & wevtutil epl $script:C3Channel $dest ('/q:' + $script:C3Query) /ow:true
    }
}

# Copy-Matching: every file under a wildcard path into a subdirectory of the run.
function Copy-Matching {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Sub
    )

    $script:C3Name = $Name
    $script:C3Pattern = $Pattern
    $script:C3Sub = $Sub
    Inv-Run -Name $Name -Script {
        $items = @(Get-ChildItem -Path $script:C3Pattern -Recurse -File -ErrorAction SilentlyContinue)
        if ($items.Count -eq 0) {
            Write-Output ('no files match ' + $script:C3Pattern)
            return
        }
        $dest = Join-Path $script:InvOut $script:C3Sub
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        foreach ($item in $items) {
            $target = Join-Path $dest $item.Name
            $n = 1
            while (Test-Path -LiteralPath $target) {
                $n = $n + 1
                $target = Join-Path $dest ([System.IO.Path]::GetFileNameWithoutExtension($item.Name) + '-' + $n + $item.Extension)
            }
            Copy-Item -LiteralPath $item.FullName -Destination $target -Force
        }
        Write-Output ($items.Count.ToString() + ' files copied from ' + $script:C3Pattern)
    }
}

Copy-Matching -Name 'sql-errorlog' -Pattern 'C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Log\ERRORLOG*' -Sub 'sql'
Copy-Matching -Name 'iis-logs' -Pattern 'C:\inetpub\logs\LogFiles\*' -Sub 'iis'
Copy-Matching -Name 'dns-logs' -Pattern 'C:\Windows\System32\dns\*.log' -Sub 'dns'

Inv-Pack
