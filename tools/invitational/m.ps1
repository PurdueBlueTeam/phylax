# m.ps1 TEXT... -- append one line to the Invitational ops timeline (C6) on a
# Windows host: UTC<TAB>COMPUTERNAME<TAB>TEXT in
# $env:INV_TIMELINE, else C:\ProgramData\phylax-inv\timeline.txt. With no
# arguments it prints the last 5 lines. Observe only: the timeline is the only
# file written, and it lives under InvRoot.

Set-StrictMode -Version 2.0

if ($env:INV_ROOT) {
    $script:InvRoot = $env:INV_ROOT
} else {
    $script:InvRoot = 'C:\ProgramData\phylax-inv'
}
if ($env:INV_TIMELINE) {
    $script:InvTimeline = $env:INV_TIMELINE
} else {
    $script:InvTimeline = Join-Path $script:InvRoot 'timeline.txt'
}

if ($args.Count -eq 0) {
    if (Test-Path -LiteralPath $script:InvTimeline) {
        Get-Content -LiteralPath $script:InvTimeline -Tail 5
    }
    exit 0
}

$parent = Split-Path -Parent $script:InvTimeline
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
$line = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') + "`t" + $env:COMPUTERNAME + "`t" + ($args -join ' ')
Add-Content -LiteralPath $script:InvTimeline -Value $line -Encoding ASCII # inv:ro: writes only the timeline under InvRoot
Write-Output $line
