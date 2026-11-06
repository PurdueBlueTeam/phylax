# Shared helpers for the Invitational Windows collectors. Observe only: every
# helper writes under $script:InvRoot, never to the host's configuration or
# service state.

Set-StrictMode -Version 2.0

function Inv-Utc {
    [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Inv-Init {
    param([Parameter(Mandatory = $true)][string]$Cid)

    if (-not $script:InvRoot) {
        $script:InvRoot = 'C:\ProgramData\phylax-inv'
    }
    $script:InvHost = $env:COMPUTERNAME
    $script:InvCid = $Cid
    $script:InvStamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")

    $parent = Join-Path $script:InvRoot $script:InvHost
    New-Item -ItemType Directory -Path $parent -Force | Out-Null

    $base = Join-Path $parent ($Cid + '-' + $script:InvStamp)
    $out = $base
    $n = 1
    while (Test-Path -LiteralPath $out) {
        $n = $n + 1
        $out = $base + '-' + $n
    }
    New-Item -ItemType Directory -Path $out -Force | Out-Null
    $script:InvOut = $out

    $meta = @()
    $meta += 'utc: ' + (Inv-Utc)
    $meta += 'host: ' + $script:InvHost
    $meta += 'os: ' + [System.Environment]::OSVersion.VersionString
    $ntp = 'ntp: unavailable'
    try {
        $status = & w32tm /query /status 2>$null
        $offset = $status | Select-String -Pattern 'Source|Offset|Clock' | Select-Object -First 1
        if ($offset) {
            $ntp = 'w32tm: ' + $offset.ToString().Trim()
        }
    } catch {
        $ntp = 'ntp: unavailable'
    }
    $meta += $ntp
    Set-Content -LiteralPath (Join-Path $script:InvOut '_meta.txt') -Value $meta -Encoding ASCII

    return $script:InvOut
}

function Inv-Run {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Script
    )

    $path = Join-Path $script:InvOut ($Name + '.txt')
    $start = Get-Date
    $code = 0
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    try {
        $global:LASTEXITCODE = 0
        & $Script *>&1 | Out-File -LiteralPath $path -Encoding utf8
        if ($global:LASTEXITCODE -ne 0) {
            $code = $global:LASTEXITCODE
        }
    } catch {
        $_ | Out-String | Out-File -LiteralPath $path -Append -Encoding utf8
        $code = 1
    } finally {
        $ErrorActionPreference = $oldPreference
    }
    $secs = [int]((Get-Date) - $start).TotalSeconds
    Add-Content -LiteralPath (Join-Path $script:InvOut '_index.tsv') -Value ($Name + "`t" + $code + "`t" + $secs) -Encoding ASCII
    return
}

# shortcut: Compress-Archive caps at 2 GB, switch to tar.exe if an evtx set exceeds it
function Inv-Pack {
    $base = Join-Path $script:InvRoot ($script:InvHost + '-' + $script:InvCid + '-' + $script:InvStamp)
    $archive = $base + '.zip'
    $n = 1
    while (Test-Path -LiteralPath $archive) {
        $n = $n + 1
        $archive = $base + '-' + $n + '.zip'
    }
    Compress-Archive -LiteralPath $script:InvOut -DestinationPath $archive -CompressionLevel Optimal
    $bytes = (Get-Item -LiteralPath $archive).Length
    $sha = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Output ($archive + ' ' + $bytes + ' ' + $sha)
}
