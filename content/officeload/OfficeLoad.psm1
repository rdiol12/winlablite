# OfficeLoad: start winlab's load engine from inside the network you built.
#
# Start-OfficeLoad leaves a request in C:\ProgramData\winlab\load on this
# machine. winlab reads it through the machine's own agent (the same serial
# channel it uses for everything else: there is no network path out of the
# lab), looks around your network read-only (the domain, its domain
# controllers, the file, print, web, SQL, Remote Desktop and WSUS servers,
# mail, the PCs and the staff), and starts the staff's working day on what
# it found. Its answer comes back into the same folder, where
# Get-OfficeLoad reads it. Nothing in your network is configured for you:
# the load only uses what you built.

$script:LoadDir = Join-Path $env:ProgramData 'winlab\load'
$script:Request = Join-Path $script:LoadDir 'request.json'
$script:Status = Join-Path $script:LoadDir 'status.json'

function Test-LoadAdmin {
    $me = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
    $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-LoadFolder {
    # Only SYSTEM (winlab's agent) and the administrators can open the folder:
    # a request may carry the staff's first sign-in secret until winlab takes it.
    if (-not (Test-LoadAdmin)) {
        throw 'Run PowerShell as administrator: the load folder is readable by administrators only.'
    }
    if (-not (Test-Path -LiteralPath $script:LoadDir)) {
        $null = New-Item -ItemType Directory -Path $script:LoadDir -Force
    }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $id = New-Object System.Security.Principal.SecurityIdentifier $sid
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule ($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $script:LoadDir -AclObject $acl
}

function Read-LoadStatus {
    if (-not (Test-Path -LiteralPath $script:Status)) { return $null }
    try { return (Get-Content -LiteralPath $script:Status -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}

function Format-LoadStatus {
    param($Status)
    if ($null -eq $Status) {
        'winlab has not answered yet. Is the winlab desktop running this lab? It looks for requests about every half minute.'
        return
    }
    $Status.message
    if ($Status.started) { '  Started from {0} by {1} at {2} (lab time)' -f $Status.from, $Status.by, $Status.started }
    if ($Status.state -eq 'running') {
        '  Load level {0}, profile {1}; {2} of {3} staff in now, {4} open helpdesk ticket(s) from staff' -f $Status.level, $Status.profile, $Status.in_now, $Status.staff, $Status.tickets
    }
    foreach ($l in @($Status.found)) { if ($l) { '  found: ' + $l } }
    foreach ($l in @($Status.missing)) { if ($l) { '  none:  ' + $l } }
    if ($Status.updated) { '  (winlab wrote this at {0}, lab time)' -f $Status.updated }
}

function Send-LoadRequest {
    param([hashtable]$Body, [switch]$NoWait, [int]$TimeoutSec = 300)
    Initialize-LoadFolder
    $id = [guid]::NewGuid().ToString()
    $Body['id'] = $id
    $Body['computer'] = $env:COMPUTERNAME
    $Body['user'] = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
    $Body['written'] = (Get-Date).ToString('s')
    $tmp = Join-Path $script:LoadDir 'request.tmp'
    [IO.File]::WriteAllText($tmp, ($Body | ConvertTo-Json -Compress))
    Move-Item -LiteralPath $tmp -Destination $script:Request -Force
    $Body.Clear()
    if ($NoWait) {
        'Request left for winlab. Get-OfficeLoad shows its answer once winlab has picked it up.'
        return
    }
    $until = (Get-Date).AddSeconds($TimeoutSec)
    $st = $null
    while ((Get-Date) -lt $until) {
        $st = Read-LoadStatus
        $done = $st -and $st.ack -eq $id -and $st.state -ne 'discovering'
        if ($done) { break }
        $what = 'Waiting for winlab to pick up the request'
        if ($st -and $st.ack -eq $id) { $what = 'winlab is looking around your network' }
        Write-Progress -Activity 'Office load' -Status $what
        Start-Sleep -Seconds 3
    }
    Write-Progress -Activity 'Office load' -Completed
    if (-not ($st -and $st.ack -eq $id)) {
        'winlab has not picked the request up yet. It is still waiting in ' + $script:LoadDir + '; Get-OfficeLoad shows the answer later.'
        return
    }
    Format-LoadStatus $st
}

function Start-OfficeLoad {
    <#
    .SYNOPSIS
    Starts winlab's load engine on the network you built: staff sign in, save, print, mail and browse.
    .DESCRIPTION
    winlab finds the domain, its domain controllers, the file, print, web, SQL, Remote Desktop and
    WSUS servers, mail and the PCs from this machine (read-only), takes the staff from a group or an
    OU, and starts their working day. You are asked once for the first password you gave the staff
    accounts; winlab keeps it only in this lab's folder on the host PC. Press Enter to skip it.
    .EXAMPLE
    Start-OfficeLoad -StaffGroup 'G-Staff' -Level busy
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('quiet', 'normal', 'busy')][string]$Level = 'normal',
        [Alias('Profile')][ValidateSet('office', 'flat', 'round')][string]$LoadProfile = 'office',
        [ValidateSet('normal', 'busyday')][string]$Pace = 'normal',
        [string]$StaffGroup = '',
        [string]$StaffOU = '',
        [switch]$Shifts,
        [switch]$NoServerJobs,
        [switch]$Rediscover,
        [switch]$SkipPassword,
        [switch]$NoWait,
        [int]$TimeoutSec = 300
    )
    $body = @{ action = 'start'; level = $Level; profile = $LoadProfile; pace = $Pace; group = $StaffGroup;
               ou = $StaffOU; shifts = [bool]$Shifts; server_jobs = (-not $NoServerJobs); rediscover = [bool]$Rediscover }
    if (-not $SkipPassword) {
        $s = Read-Host -AsSecureString "The staff accounts' first password (Enter to skip: winlab keeps the ones it has)"
        if ($s.Length -gt 0) {
            $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
            try { $body['signin'] = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringBSTR($b))) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
        }
    }
    Send-LoadRequest -Body $body -NoWait:$NoWait -TimeoutSec $TimeoutSec
}

function Stop-OfficeLoad {
    <#
    .SYNOPSIS
    Sends the staff home: winlab's load engine stops until Start-OfficeLoad runs again.
    #>
    [CmdletBinding()]
    param([switch]$NoWait, [int]$TimeoutSec = 120)
    Send-LoadRequest -Body @{ action = 'stop' } -NoWait:$NoWait -TimeoutSec $TimeoutSec
}

function Get-OfficeLoad {
    <#
    .SYNOPSIS
    Shows what winlab's load engine is doing: who started it, what it found, who is in.
    .PARAMETER Raw
    The status as an object instead of text.
    #>
    [CmdletBinding()]
    param([switch]$Raw)
    $st = Read-LoadStatus
    if ($Raw) { return $st }
    Format-LoadStatus $st
}

Export-ModuleMember -Function Start-OfficeLoad, Stop-OfficeLoad, Get-OfficeLoad
