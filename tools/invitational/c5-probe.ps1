# c5-probe.ps1 [-TargetsFile PATH] [-MirrorsFile PATH] -- C5 reachability and
# internet probe for Windows (read only, connect-only).
#
# The Windows side of c5-probe.sh: answers E18 (which scored host:port is
# reachable from this host class) and E15 (is the internet reachable, how fast,
# is TLS intercepted, what does the path look like). It opens TCP connections
# only, sends an unauthenticated WinRM OPTIONS and does HTTP GETs: no payload
# reaches a scored port and nothing on the host is changed.
#
#   -TargetsFile  lines "host port [label]"; default is the 2027 scored set
#   -MirrorsFile  one hostname per line; default is the mirror list
#
# Outputs in $InvOut: targets.txt, mirrors.txt, ports.csv, winrm.txt, http.csv,
# tls.txt, dns.csv, trace.txt, and one archive from Inv-Pack.

[CmdletBinding()]
param(
    [string]$TargetsFile = '',
    [string]$MirrorsFile = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

. (Join-Path $PSScriptRoot 'lib.ps1')

$script:InvRoot = 'C:\ProgramData\phylax-inv'
Inv-Init -Cid 'c5' | Out-Null

# The scored services in the 2027 manifest (manifest/2027/services.yml,
# scored: true). Regenerate from `phylax manifest load` when the team packet
# changes. ICMP checks have no port and are not probed here.
$script:C5Targets = @(
    '# Scored services in the 2027 manifest; regenerate from `phylax manifest load`.',
    '172.20.240.10 22 rocky-ecom-ssh',
    '172.20.240.10 80 rocky-ecom-http',
    '172.20.240.10 443 rocky-ecom-https',
    '172.20.240.15 22 ubuntu-email-ssh',
    '172.20.240.15 25 ubuntu-email-smtp',
    '172.20.240.15 80 ubuntu-email-webmail',
    '172.20.240.15 110 ubuntu-email-pop3',
    '172.20.240.15 143 ubuntu-email-imap',
    '172.20.240.20 22 debian-splunk-ssh',
    '172.20.240.20 8000 debian-splunk-web',
    '172.20.240.20 8089 debian-splunk-mgmt',
    '172.20.240.100 53 ad-dns',
    '172.20.240.100 5985 ad-winrm',
    '172.20.240.120 445 mssql-smb',
    '172.20.240.120 1433 mssql-sql',
    '172.20.240.120 3389 mssql-rdp'
)

# Internet mirrors from data question E15 (Debian, Ubuntu, Rocky, Microsoft,
# GitHub). One hostname per line.
$script:C5Mirrors = @(
    '# Internet mirrors from data question E15.',
    'deb.debian.org',
    'archive.ubuntu.com',
    'security.ubuntu.com',
    'mirror.rockylinux.org',
    'download.windowsupdate.com',
    'github.com'
)

# Inv-WriteFile / Inv-AppendLine: every file this script writes is under $InvOut.
function Inv-WriteFile {
    param([Parameter(Mandatory = $true)][string]$Name, [string[]]$Value = @())
    Set-Content -LiteralPath (Join-Path $script:InvOut $Name) -Value $Value -Encoding ASCII
}

function Inv-AppendLine {
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][string]$Value)
    Add-Content -LiteralPath (Join-Path $script:InvOut $Name) -Value $Value -Encoding ASCII
}

# Read-Rows PATH: the file without blank and comment lines.
function Read-Rows {
    param([Parameter(Mandatory = $true)][string]$Path)
    $rows = @()
    foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) {
            continue
        }
        $rows += $trimmed
    }
    return $rows
}

# Test-PortOpen: connect only, 3 s bound. Returns result, ms, exit code.
function Test-PortOpen {
    param(
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][int]$Port
    )

    $client = New-Object System.Net.Sockets.TcpClient
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $result = 'closed'
    $code = 1
    try {
        $pending = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if ($pending.AsyncWaitHandle.WaitOne(3000, $false)) {
            $client.EndConnect($pending)
            $result = 'open'
            $code = 0
        } else {
            $result = 'timeout'
            $code = 124
        }
    } catch {
        $result = 'closed'
        $code = 1
    } finally {
        $watch.Stop()
        $client.Close()
    }
    return @($result, [int]$watch.ElapsedMilliseconds, $code)
}

if ($TargetsFile -ne '' -and (Test-Path -LiteralPath $TargetsFile)) {
    Copy-Item -LiteralPath $TargetsFile -Destination (Join-Path $script:InvOut 'targets.txt') -Force
} else {
    Inv-WriteFile -Name 'targets.txt' -Value $script:C5Targets
}
if ($MirrorsFile -ne '' -and (Test-Path -LiteralPath $MirrorsFile)) {
    Copy-Item -LiteralPath $MirrorsFile -Destination (Join-Path $script:InvOut 'mirrors.txt') -Force
} else {
    Inv-WriteFile -Name 'mirrors.txt' -Value $script:C5Mirrors
}

$targetRows = @(Read-Rows (Join-Path $script:InvOut 'targets.txt'))
$mirrorRows = @(Read-Rows (Join-Path $script:InvOut 'mirrors.txt'))

# ports.csv: every target, connect only.
Inv-WriteFile -Name 'ports.csv' -Value @('host,port,result,ms')
foreach ($row in $targetRows) {
    $parts = @($row -split '\s+')
    if ($parts.Count -lt 2) {
        continue
    }
    $port = 0
    if (-not [int]::TryParse($parts[1], [ref]$port)) {
        continue
    }
    $probe = Test-PortOpen -TargetHost $parts[0] -Port $port
    Inv-AppendLine -Name 'ports.csv' -Value ($parts[0] + ',' + $port + ',' + $probe[0] + ',' + $probe[1])
}

# winrm.txt: the unauthenticated OPTIONS exchange for WinRM targets (E18).
$winrmRows = @()
foreach ($row in $targetRows) {
    $parts = @($row -split '\s+')
    if ($parts.Count -ge 2 -and ($parts[1] -eq '5985' -or $parts[1] -eq '5986')) {
        $winrmRows += $row
    }
}
Inv-WriteFile -Name 'winrm.txt' -Value @()
if ($winrmRows.Count -eq 0) {
    Inv-AppendLine -Name 'winrm.txt' -Value 'no WinRM target (5985/5986)'
} else {
    foreach ($row in $winrmRows) {
        $parts = @($row -split '\s+')
        $scheme = 'http'
        if ($parts[1] -eq '5986') {
            $scheme = 'https'
        }
        $uri = $scheme + '://' + $parts[0] + ':' + $parts[1] + '/wsman'
        Inv-AppendLine -Name 'winrm.txt' -Value ('== ' + $uri + ' ==')
        try {
            $response = Invoke-WebRequest -Uri $uri -Method Options -UseBasicParsing -TimeoutSec 5
            Inv-AppendLine -Name 'winrm.txt' -Value ('status: ' + [int]$response.StatusCode)
            Inv-AppendLine -Name 'winrm.txt' -Value ($response.Headers.ToString())
        } catch {
            Inv-AppendLine -Name 'winrm.txt' -Value ('error: ' + $_.Exception.Message)
            if ($_.Exception -is [System.Net.WebException]) {
                $web = $_.Exception
                if ($web.Response) {
                    Inv-AppendLine -Name 'winrm.txt' -Value ('status: ' + [int]$web.Response.StatusCode)
                    Inv-AppendLine -Name 'winrm.txt' -Value ('www-authenticate: ' + $web.Response.Headers['WWW-Authenticate'])
                }
            }
        }
        Inv-AppendLine -Name 'winrm.txt' -Value ''
    }
}

# http.csv: one GET per mirror. shortcut: Invoke-WebRequest has no size cap and
# only dns + total are timed (connect and tls stay 0); upgrade if a mirror
# serves a large index or per-phase timings matter.
Inv-WriteFile -Name 'http.csv' -Value @('url,code,dns_s,connect_s,tls_s,total_s,bytes')
foreach ($mirror in $mirrorRows) {
    $url = 'https://' + $mirror + '/'
    $code = 0
    $bytes = 0
    $dnsSeconds = 0.0
    $totalSeconds = 0.0
    $timer = $null
    try {
        $dnsWatch = [System.Diagnostics.Stopwatch]::StartNew()
        [void][System.Net.Dns]::GetHostAddresses($mirror)
        $dnsWatch.Stop()
        $dnsSeconds = [math]::Round($dnsWatch.Elapsed.TotalSeconds, 6)
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 60
        $timer.Stop()
        $totalSeconds = [math]::Round($timer.Elapsed.TotalSeconds, 6)
        $code = [int]$response.StatusCode
        $bytes = $response.RawContentLength
        if ($bytes -lt 0) {
            $bytes = 0
        }
    } catch {
        if ($timer) {
            $timer.Stop()
            $totalSeconds = [math]::Round($timer.Elapsed.TotalSeconds, 6)
        }
        if ($_.Exception -is [System.Net.WebException]) {
            $web = $_.Exception
            if ($web.Response) {
                $code = [int]$web.Response.StatusCode
            }
        }
    }
    Inv-AppendLine -Name 'http.csv' -Value ($url + ',' + $code + ',' + $dnsSeconds + ',0,0,' + $totalSeconds + ',' + $bytes)
}

# tls.txt: is there a proxy or TLS interception (E15)?
$tlsNames = @('github.com')
foreach ($mirror in $mirrorRows) {
    if ($tlsNames -notcontains $mirror) {
        $tlsNames += $mirror
    }
}
$validation = [System.Net.Security.RemoteCertificateValidationCallback] { $true }
Inv-WriteFile -Name 'tls.txt' -Value @()
foreach ($name in $tlsNames) {
    $hostPort = $name + ':443'
    Inv-AppendLine -Name 'tls.txt' -Value ('== ' + $hostPort + ' ==')
    $tcp = $null
    $stream = $null
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $connect = $tcp.ConnectAsync($name, 443)
        if (-not $connect.Wait(5000)) {
            throw 'connect timeout'
        }
        $stream = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, $validation)
        $stream.AuthenticateAsClient($name)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($stream.RemoteCertificate)
        Inv-AppendLine -Name 'tls.txt' -Value ('issuer: ' + $cert.Issuer)
        Inv-AppendLine -Name 'tls.txt' -Value ('subject: ' + $cert.Subject)
        Inv-AppendLine -Name 'tls.txt' -Value ('notBefore: ' + $cert.NotBefore.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
        Inv-AppendLine -Name 'tls.txt' -Value ('notAfter: ' + $cert.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
    } catch {
        Inv-AppendLine -Name 'tls.txt' -Value ('error: ' + $_.Exception.Message)
    } finally {
        if ($stream) {
            $stream.Close()
        }
        if ($tcp) {
            $tcp.Close()
        }
    }
}

# dns.csv: resolution time per mirror name and github.com (E15).
Inv-WriteFile -Name 'dns.csv' -Value @('name,ms')
foreach ($name in $tlsNames) {
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        [void](Resolve-DnsName -Name $name -ErrorAction Stop)
    } catch {
        $null = $_
    }
    $watch.Stop()
    Inv-AppendLine -Name 'dns.csv' -Value ($name + ',' + [int]$watch.ElapsedMilliseconds)
}

# trace.txt: the path to the first mirror, bounded to 15 hops.
$script:C5First = ''
if ($mirrorRows.Count -gt 0) {
    $script:C5First = $mirrorRows[0]
}
if ($script:C5First -eq '') {
    Inv-WriteFile -Name 'trace.txt' -Value @('trace: no mirror to trace')
} else {
    Inv-Run -Name 'trace' -Script { & tracert -d -h 15 -w 2000 $script:C5First }
}

Inv-Pack
