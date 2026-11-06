# Applies the lab's addressing to this machine's adapters, for the machines
# the lab sets up itself (winlab/provision.py lab_addressed), by MAC address,
# from facts.json: a static address, prefix, default gateway and DNS servers
# for every adapter the lab file gives an address, DHCP for the others. Runs
# at first boot (stage0) and at every start of the agent, reading the facts
# the host rewrote for this start, so a change in the lab file reaches the
# machine at its next start; a change the student made by hand holds until
# then, as it would on a machine any hypervisor hands a configuration to.
# Nothing that is already right is touched.
#
# The default gateway goes on the adapter facing the Internet (a wan segment)
# when the machine has one, else on its first adapter; a second inside
# adapter gets no default route (the roles add the routes it needs).

$ErrorActionPreference = 'Continue'
$Root = 'C:\winlab'
$LogPath = Join-Path $Root 'network.log'
$DataLabel = 'WLDATA'

function Write-NetLog($msg) {
    $line = "{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    try { Add-Content -Path $LogPath -Value $line -Encoding utf8 } catch {}
}

function Normalize-Mac($mac) {
    if ($null -eq $mac) { return '' }
    return ([string]$mac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
}

# The winlab data volume is rebuilt by the host at every start: its facts
# are the current ones. Fall back to the copy stage0 made.
$facts = Join-Path $Root 'facts.json'
try {
    $vol = Get-Volume -ErrorAction SilentlyContinue |
        Where-Object { $_.FileSystemLabel -eq $DataLabel -and $_.DriveLetter }
    if ($vol) {
        $src = "$($vol.DriveLetter):\facts.json"
        if (Test-Path $src) {
            New-Item -ItemType Directory -Path $Root -Force | Out-Null
            Copy-Item -Path $src -Destination $facts -Force
        }
    }
} catch {}
if (-not (Test-Path $facts)) {
    Write-NetLog 'no facts.json: nothing to apply'
    exit 0
}

try {
    $f = Get-Content -Path $facts -Raw -Encoding utf8 | ConvertFrom-Json
} catch {
    Write-NetLog "facts.json unreadable: $($_.Exception.Message)"
    exit 0
}
# A machine the student sets up (every machine but the ones that are not the
# student's: another company's gateway, the Internet's hosts) has nothing set
# here: its adapters keep whatever the student typed in or leased, across
# every start, as on a PC fresh out of the box.
if ([string]$f.addressing -eq 'student') {
    Write-NetLog 'addresses are set by hand on this machine: nothing to apply'
    exit 0
}
$nics = @($f.nics)
if ($nics.Count -eq 0) { exit 0 }

# Which adapter carries the default route.
$defaultNic = $null
foreach ($n in $nics) { if ($n.wan -and $n.ip) { $defaultNic = $n; break } }
if ($null -eq $defaultNic) { $defaultNic = $nics[0] }

$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
foreach ($n in $nics) {
    $want = Normalize-Mac $n.mac
    $ad = $adapters | Where-Object { (Normalize-Mac $_.MacAddress) -eq $want } | Select-Object -First 1
    if ($null -eq $ad) {
        Write-NetLog "nic $($n.index) ($($n.mac)): no adapter with that address yet"
        continue
    }
    $idx = $ad.ifIndex
    $ipif = Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($null -eq $ipif) { continue }

    if (-not $n.ip -or $n.dhcp) {
        if ($ipif.Dhcp -ne 'Enabled') {
            Write-NetLog "$($ad.Name): back to DHCP"
            Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.PrefixOrigin -eq 'Manual' } |
                Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
            Remove-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
            Set-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -Dhcp Enabled -ErrorAction SilentlyContinue
            Set-DnsClientServerAddress -InterfaceIndex $idx -ResetServerAddresses -ErrorAction SilentlyContinue
        }
        continue
    }

    $ip = [string]$n.ip
    $plen = [int]$n.prefix
    $gw = if ($n.index -eq $defaultNic.index -and $n.gateway) { [string]$n.gateway } else { '' }
    $have = @(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.PrefixOrigin -ne 'WellKnown' })
    $right = $have | Where-Object { $_.IPAddress -eq $ip -and $_.PrefixLength -eq $plen }
    $routes = @(Get-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue)
    $gwRight = if ($gw) { @($routes | Where-Object { $_.NextHop -eq $gw }).Count -gt 0 } else { $routes.Count -eq 0 }

    if (-not $right -or -not $gwRight) {
        $msg = "$($ad.Name): $ip/$plen"
        if ($gw) { $msg += " via $gw" } else { $msg += ' (no default route)' }
        Write-NetLog $msg
        if ($ipif.Dhcp -eq 'Enabled') {
            Set-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -Dhcp Disabled -ErrorAction SilentlyContinue
        }
        $routes | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        $have | Where-Object { -not ($_.IPAddress -eq $ip -and $_.PrefixLength -eq $plen) } |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        if (-not $right) {
            try {
                if ($gw) {
                    New-NetIPAddress -InterfaceIndex $idx -IPAddress $ip -PrefixLength $plen -DefaultGateway $gw -ErrorAction Stop | Out-Null
                } else {
                    New-NetIPAddress -InterfaceIndex $idx -IPAddress $ip -PrefixLength $plen -ErrorAction Stop | Out-Null
                }
            } catch {
                Write-NetLog "$($ad.Name): address failed: $($_.Exception.Message)"
            }
        } elseif ($gw) {
            try {
                New-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -NextHop $gw -ErrorAction Stop | Out-Null
            } catch {
                Write-NetLog "$($ad.Name): default route failed: $($_.Exception.Message)"
            }
        }
    }

    $dns = @($n.dns | Where-Object { $_ })
    if ($dns.Count -gt 0) {
        $cur = @((Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
        if (($cur -join ',') -ne ($dns -join ',')) {
            Write-NetLog "$($ad.Name): dns $($dns -join ', ')"
            Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $dns -ErrorAction SilentlyContinue
        }
    }
}
Write-NetLog 'applied'
