# winlab in-guest agent.
#
# Control travels over COM1, not the network: the lab's NICs are isolated from
# the host, and Windows has an in-box serial driver so nothing needs injecting.
# Host speaks to the matching QEMU chardev on 127.0.0.1.
#
# Request   {"id":N,"shell":"powershell|cmd","b64":"<base64 utf8 command>"}
# Response  {"id":N,"rc":N,"out":"<base64>","err":"<base64>","host":"NAME"}

$ErrorActionPreference = 'Stop'
$LogPath = 'C:\winlab\agent.log'

function Write-Log($msg) {
    $line = "{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    try { Add-Content -Path $LogPath -Value $line -Encoding utf8 } catch {}
}

function To-B64($text) {
    if ($null -eq $text) { return '' }
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$text))
}

function From-B64($b64) {
    if ([string]::IsNullOrEmpty($b64)) { return '' }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
}

function Open-Port {
    for ($i = 0; $i -lt 60; $i++) {
        try {
            $p = New-Object System.IO.Ports.SerialPort 'COM1', 115200, 'None', 8, 'One'
            $p.ReadTimeout = 400
            $p.WriteTimeout = 15000
            $p.NewLine = "`n"
            $p.Open()
            return $p
        } catch {
            Start-Sleep -Seconds 2
        }
    }
    throw 'COM1 never became available'
}

function Invoke-Payload($shell, $command) {
    $out = New-Object Text.StringBuilder
    $err = New-Object Text.StringBuilder
    $rc = 0
    try {
        if ($shell -eq 'cmd') {
            $tmp = [IO.Path]::GetTempFileName() + '.cmd'
            Set-Content -Path $tmp -Value $command -Encoding ascii
            $raw = & cmd.exe /c $tmp 2>&1
            $rc = $LASTEXITCODE
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        } else {
            $raw = Invoke-Expression $command 2>&1
            $rc = 0
        }
        foreach ($item in @($raw)) {
            if ($item -is [Management.Automation.ErrorRecord]) {
                [void]$err.AppendLine($item.ToString())
            } elseif ($null -ne $item) {
                [void]$out.AppendLine(($item | Out-String).TrimEnd())
            }
        }
    } catch {
        $rc = 1
        [void]$err.AppendLine($_.Exception.Message)
    }
    return @{ rc = $rc; out = $out.ToString(); err = $err.ToString() }
}

New-Item -ItemType Directory -Path 'C:\winlab' -Force | Out-Null
Write-Log 'agent starting'

# The lab's addressing for this start (static addresses by MAC from the
# facts the host just rewrote; a no-op when nothing changed).
try {
    & (Join-Path $PSScriptRoot 'apply-network.ps1') 2>&1 | Out-Null
    Write-Log 'network applied'
} catch {
    Write-Log "network apply failed: $($_.Exception.Message)"
}

$port = Open-Port
Write-Log 'COM1 open'

# Unsolicited banner so the host can tell the machine finished provisioning
# without having to poll a command through.
$banner = @{
    event = 'ready'
    host  = $env:COMPUTERNAME
    os    = (Get-CimInstance Win32_OperatingSystem).Caption
    agent = 1
} | ConvertTo-Json -Compress
$port.WriteLine($banner)

while ($true) {
    $line = $null
    try {
        $line = $port.ReadLine()
    } catch [TimeoutException] {
        continue
    } catch {
        Write-Log "read error: $($_.Exception.Message)"
        Start-Sleep -Milliseconds 500
        try { $port.Close() } catch {}
        $port = Open-Port
        continue
    }

    if ([string]::IsNullOrWhiteSpace($line)) { continue }

    $id = 0
    try {
        $req = $line | ConvertFrom-Json
        $id = [int]$req.id
        $shell = if ($req.shell) { [string]$req.shell } else { 'powershell' }
        $command = From-B64 $req.b64
        Write-Log "exec #$id ($shell): $($command.Substring(0, [Math]::Min(120, $command.Length)))"
        $result = Invoke-Payload $shell $command
    } catch {
        $result = @{ rc = 1; out = ''; err = "agent could not parse request: $($_.Exception.Message)" }
    }

    $resp = @{
        id   = $id
        rc   = $result.rc
        out  = To-B64 $result.out
        err  = To-B64 $result.err
        host = $env:COMPUTERNAME
    } | ConvertTo-Json -Compress

    try {
        $port.WriteLine($resp)
    } catch {
        Write-Log "write error: $($_.Exception.Message)"
    }
}
