# e.ps1 -Ctl CTL -HostName HOST [-Agent] -- console enrollment for Windows hosts.
#
# Typed as (CTL is the controller host:port serving the kit over HTTP):
#   powershell -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\phylax-kit\invitational\e.ps1 -Ctl 172.20.240.5:8000 -HostName win11-wkst -Agent
# or, after e.sh has fetched the kit once:
#   powershell -File C:\ProgramData\phylax-kit\invitational\e.ps1 -Ctl 172.20.240.5:8000 -HostName win11-wkst -Agent
#
# Without -Agent only the collector kit is fetched and extracted. Every step
# prints a UTC line, so the console transcript doubles as a timeline.
# shortcut: the first typed line is far over 70 characters; Windows hosts fetch
# the kit once with e.sh from WSL/Git Bash or carry it on the injected media if
# Task 15 finds no way to type it on the console.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Ctl,
    [Parameter(Mandatory = $true)][string]$HostName,
    [switch]$Agent
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$base = $Ctl
if ($base -notmatch '^https?://') {
    $base = "http://$base"
}

$kit = 'C:\ProgramData\phylax-kit'
$bin = 'C:\ProgramData\phylax-bin'

function Get-InvUtc {
    (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Write-Step {
    param([string]$Text)
    Write-Host "$(Get-InvUtc) $Text"
}

New-Item -ItemType Directory -Force -Path $kit | Out-Null
Write-Step "kit: downloading $base/kit.tgz"
Invoke-WebRequest -UseBasicParsing -Uri "$base/kit.tgz" -OutFile "$kit\kit.tgz"

Write-Step "kit: extracting into $kit"
& tar.exe -xzf "$kit\kit.tgz" -C $kit
if ($LASTEXITCODE -ne 0) {
    Write-Step "error: tar.exe failed with $LASTEXITCODE"
    exit 1
}

if ($Agent) {
    New-Item -ItemType Directory -Force -Path $bin | Out-Null
    Write-Step "agent: downloading $base/phylax.exe"
    Invoke-WebRequest -UseBasicParsing -Uri "$base/phylax.exe" -OutFile "$bin\phylax.exe"
    Write-Step "agent: downloading $base/$HostName.json"
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$HostName.json" -OutFile "$bin\$HostName.json"

    Write-Step "agent: install --bootstrap $bin\$HostName.json"
    & "$bin\phylax.exe" agent install --bootstrap "$bin\$HostName.json"
    if ($LASTEXITCODE -ne 0) {
        Write-Step "error: agent install failed with $LASTEXITCODE"
        exit 1
    }
}

Write-Step "done: kit in $kit"
