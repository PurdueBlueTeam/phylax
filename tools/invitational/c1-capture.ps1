# c1-capture.ps1 -Action start|stop|status -- raw packet capture for Windows (C1).
# Observe only: writes under $InvRoot only, and start/stop touch only pktmon's
# own capture state. Run it from an elevated PowerShell (pktmon needs admin).
#
# shortcut: etl is converted to pcap offline (pktmon etl2pcap needs build 2004+),
# upgrade if the Server 2019 image lacks it

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('start', 'stop', 'status')]
    [string]$Action
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'lib.ps1')

$script:InvRoot = 'C:\ProgramData\phylax-inv'
$pcapDir = Join-Path $script:InvRoot 'pcap'
$etl = Join-Path $pcapDir ($env:COMPUTERNAME + '.etl')
$drops = Join-Path $pcapDir 'drops.txt'

function Test-Pktmon {
    if (-not (Get-Command pktmon -ErrorAction SilentlyContinue)) {
        Write-Output 'c1: pktmon not found; nothing captured'
        exit 1
    }
}

function Start-Capture {
    New-Item -ItemType Directory -Path $pcapDir -Force | Out-Null

    $running = @(Get-Process -Name pktmon -ErrorAction SilentlyContinue)
    if ($running.Count -gt 0) {
        Write-Output 'c1: already running; stop it first'
        exit 1
    }

    Test-Pktmon
    Inv-Init -Cid c1 | Out-Null
    & pktmon start --capture --pkt-size 256 --file-name $etl --file-size 100 --log-mode multi-file
    if ($LASTEXITCODE -ne 0) {
        Write-Output ('c1: pktmon start failed with ' + $LASTEXITCODE)
        exit $LASTEXITCODE
    }
    Write-Output ('c1: started capture to ' + $etl)
}

function End-Capture {
    Test-Pktmon
    New-Item -ItemType Directory -Path $pcapDir -Force | Out-Null
    & pktmon counters | Out-File -LiteralPath $drops -Encoding utf8
    & pktmon stop
    Write-Output ('c1: stopped; counters in ' + $drops)
}

function Show-Status {
    Test-Pktmon
    if (Test-Path -LiteralPath $pcapDir) {
        Get-ChildItem -LiteralPath $pcapDir | ForEach-Object {
            Write-Output ($_.Name + ' ' + $_.Length)
        }
    } else {
        Write-Output ('capture directory: absent (' + $pcapDir + ')')
    }

    if (Test-Path -LiteralPath $drops) {
        Write-Output '-- drops.txt --'
        Get-Content -LiteralPath $drops
    }
}

switch ($Action) {
    'start' { Start-Capture }
    'stop' { End-Capture }
    'status' { Show-Status }
}
