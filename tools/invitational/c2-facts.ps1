# c2-facts.ps1 -- C2 Windows host facts collector (read-only).
#
# Answers the environment questions E2-E5, E7, E8, E10, E11, E14, E17, E19-E20,
# O4, O5 from docs/impl/invitational-data.md: one timestamped directory of plain
# text plus one zip. Observe only: it reads what is there (Get-* queries, list
# and show dumps) and never changes it. Password hashes are never read; accounts
# come from the local account cmdlets only.
#
# Run it from an elevated PowerShell 5.1. Every step records its exit code in
# _index.tsv and the collector keeps going when a cmdlet or product is absent.
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File c2-facts.ps1

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'lib.ps1')

Inv-Init -Cid c2 | Out-Null

# E2: build, patch level and boot image.
Inv-Run -Name computerinfo -Script { Get-ComputerInfo }
Inv-Run -Name systeminfo -Script { & systeminfo.exe }
Inv-Run -Name hotfix -Script { Get-HotFix | Sort-Object InstalledOn }
Inv-Run -Name build -Script {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
        Select-Object ProductName, DisplayVersion, CurrentBuild, UBR, EditionID, InstallDate
}

# E3: installed products from both Uninstall keys (32- and 64-bit views).
Inv-Run -Name software -Script {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |
        Select-Object DisplayName, DisplayVersion, Publisher |
        Sort-Object DisplayName
}

Inv-Run -Name features -Script {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        Get-WindowsFeature
    } else {
        'Get-WindowsFeature: not available on this build'
    }
}

# E5: services, listeners and startup items.
Inv-Run -Name services -Script {
    Get-Service | Select-Object Name, Status, StartType | Sort-Object Name
}
Inv-Run -Name listeners -Script {
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, OwningProcess, @{Name = 'Process'; Expression = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } } |
        Sort-Object LocalPort
}
Inv-Run -Name firewallprofile -Script { Get-NetFirewallProfile }
Inv-Run -Name tasks -Script { Get-ScheduledTask | Select-Object TaskPath, TaskName, State }

# E7: local accounts and the local administrators group.
Inv-Run -Name localusers -Script {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description
}
Inv-Run -Name localadmins -Script {
    Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
}

# E8: effective audit policy, Defender state, AppLocker, Sysmon, PowerShell logging.
Inv-Run -Name auditpol -Script { & auditpol.exe /get /category:* }
Inv-Run -Name defender -Script {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        Get-MpComputerStatus
        Get-MpPreference
        Get-MpThreatDetection -ErrorAction SilentlyContinue
    } else {
        'Defender module not available'
    }
}
Inv-Run -Name applocker -Script {
    if (Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue) {
        Get-AppLockerPolicy -Effective
    } else {
        'AppLocker module not available'
    }
}
Inv-Run -Name sysmon -Script {
    Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
    Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
}
Inv-Run -Name psloging -Script { # inv:ro: reads the three policy keys only
    $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    foreach ($k in @('ScriptBlockLogging', 'ModuleLogging', 'Transcription')) {
        $path = Join-Path $base $k
        if (Test-Path -LiteralPath $path) {
            Write-Output ('== ' + $path)
            Get-ItemProperty -Path $path
        } else {
            Write-Output ('== ' + $path + ': absent')
        }
    }
}

# E10: SMB, RDP and NTP effective configuration (read only).
Inv-Run -Name smb -Script {
    Get-SmbServerConfiguration
    Get-SmbShare
}
Inv-Run -Name rdp -Script {
    & reg query 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections # inv:ro: query only
    & reg query 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' /v UserAuthentication # inv:ro: query only
}
Inv-Run -Name ntp -Script {
    & w32tm.exe /query /status
    & w32tm.exe /query /configuration
}

# E5/E8: log channels with their size and record count (no events are exported).
Inv-Run -Name eventlogs -Script {
    Get-WinEvent -ListLog Security, System, Application, 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue |
        Select-Object LogName, IsEnabled, FileSize, MaximumSizeInBytes, RecordCount
}

# E11: topology as the host sees it.
Inv-Run -Name network -Script {
    Get-NetIPConfiguration
    & ipconfig.exe /all
    Get-DnsClientServerAddress
}

# E14/E20: disk, memory and boot profile.
Inv-Run -Name disk -Script { Get-Volume }
Inv-Run -Name memory -Script {
    Get-CimInstance -ClassName Win32_OperatingSystem |
        Select-Object TotalVisibleMemorySize, FreePhysicalMemory, TotalVirtualMemorySize, FreeVirtualMemory
}
Inv-Run -Name boot -Script {
    Get-CimInstance -ClassName Win32_OperatingSystem |
        Select-Object LastBootUpTime, LocalDateTime, SystemDrive, SystemDirectory
}

# E3/E10: SQL Server and IIS, when the product is installed.
Inv-Run -Name mssql -Script {
    Get-Service -Name 'MSSQL*' -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
    $inst = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
    if (Test-Path -LiteralPath $inst) {
        Get-ItemProperty -Path $inst
    } else {
        'SQL Server instance names key: absent'
    }
}
Inv-Run -Name iis -Script {
    if (Get-Command Get-WebBinding -ErrorAction SilentlyContinue) {
        Get-WebBinding
    } else {
        'WebAdministration module not available'
    }
}

# E17: sizes only, of the data the golden backup has to carry.
Inv-Run -Name datasizes -Script {
    $paths = @('C:\inetpub', 'D:\') + @(
        Get-ChildItem -Path 'C:\Program Files\Microsoft SQL Server' -Directory -Filter 'MSSQL*' -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName 'MSSQL\DATA' }
    )
    foreach ($p in $paths) {
        if (-not (Test-Path -LiteralPath $p)) {
            Write-Output ($p + ': absent')
            continue
        }
        $sum = (Get-ChildItem -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        if (-not $sum) { $sum = 0 }
        Write-Output ('{0}: {1} bytes' -f $p, $sum)
    }
}

Inv-Pack
