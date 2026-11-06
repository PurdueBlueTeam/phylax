# c2-sampler.ps1 -Action start|stop -- one resource row per interval (E14, O3).
#
# Appends to $InvRoot\sampler.csv:
#   utc,cpu_pct,mem_avail_mb,disk_free_pct
# Observe only: it writes the CSV and its own pid file, nothing else.
#
#   INV_INTERVAL  seconds between rows (default 60)
#
# 'loop' is internal: the hidden worker that 'start' spawns.
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File c2-sampler.ps1 -Action start

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('start', 'stop', 'loop')]
    [string]$Action
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'lib.ps1')

$script:InvRoot = 'C:\ProgramData\phylax-inv'
$csv = Join-Path $script:InvRoot 'sampler.csv'
$pidFile = Join-Path $script:InvRoot 'sampler.pid'
$header = 'utc,cpu_pct,mem_avail_mb,disk_free_pct'
$interval = 60
if ($env:INV_INTERVAL) {
    $interval = [int]$env:INV_INTERVAL
}

# One CSV row on stdout. A missing counter records -1 rather than aborting.
function Get-SampleRow {
    $cpu = -1
    try {
        $sample = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop
        $cpu = [int]$sample.CounterSamples[0].CookedValue
    } catch {
        $cpu = -1
    }

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $memMb = [int]($os.FreePhysicalMemory / 1024)

    $freePct = 0
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
    if ($disk -and $disk.Size -gt 0) {
        $freePct = [int](100 * $disk.FreeSpace / $disk.Size)
    }

    '{0},{1},{2},{3}' -f (Inv-Utc), $cpu, $memMb, $freePct
}

function Get-PidValue {
    if (-not (Test-Path -LiteralPath $pidFile)) {
        return $null
    }
    $first = Get-Content -LiteralPath $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1
    $n = 0
    if ($first -and [int]::TryParse([string]$first, [ref]$n)) {
        return $n
    }
    return $null
}

function Test-Alive {
    param([int]$Id)
    return [bool](Get-Process -Id $Id -ErrorAction SilentlyContinue)
}

function Start-Sampler {
    New-Item -ItemType Directory -Path $script:InvRoot -Force | Out-Null
    $old = Get-PidValue
    if ($old -and (Test-Alive -Id $old)) {
        Write-Output ('c2-sampler: already running (pid ' + $old + ')')
        exit 1
    }
    if (-not (Test-Path -LiteralPath $csv)) {
        Set-Content -LiteralPath $csv -Value $header -Encoding ASCII # inv:ro: our own sampler csv under InvRoot
    }
    # shortcut: pid file only, no service, upgrade if the sampler must survive logoff
    $worker = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-Action', 'loop') -WindowStyle Hidden -PassThru
    Set-Content -LiteralPath $pidFile -Value ([string]$worker.Id) -Encoding ASCII # inv:ro: our own pid file under InvRoot
    Write-Output ('c2-sampler: started (pid ' + $worker.Id + ', csv ' + $csv + ', interval ' + $interval + 's)')
}

function End-Sampler {
    $old = Get-PidValue
    if (-not $old) {
        Write-Output ('c2-sampler: not running (no ' + $pidFile + ')')
        exit 1
    }
    if (Test-Alive -Id $old) {
        Stop-Process -Id $old -Force -ErrorAction SilentlyContinue # inv:ro: stops only our own sampler process
    }
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue # inv:ro: our own pid file under InvRoot
    Write-Output ('c2-sampler: stopped (csv ' + $csv + ')')
}

function Invoke-Loop {
    for (;;) {
        Add-Content -LiteralPath $csv -Value (Get-SampleRow) -Encoding ASCII # inv:ro: our own sampler csv under InvRoot
        Start-Sleep -Seconds $interval
    }
}

switch ($Action) {
    'start' { Start-Sampler }
    'stop' { End-Sampler }
    'loop' { Invoke-Loop }
}
