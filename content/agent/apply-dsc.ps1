# Applies the node's generated DSC configuration (C:\winlab\node.dsc.ps1), or
# with -Status reports whether the machine matches it. The role runner on the
# host drives this over the serial agent and parses the WINLAB:DSC line.
#
# Flow: install the resource modules from dsc-modules.zip (fetched by the host
# at bootstrap, never bundled), compile the MOFs, push the LCM settings, then
# Start-DscConfiguration -Wait. A resource that needs a reboot (promotion,
# domain join) makes the LCM reboot; this process dies with the machine, the
# runner waits for the agent to return, and the LCM finishes the pending
# configuration on its own. -Status then waits for the LCM to go idle and runs
# Test-DscConfiguration, which is the single definition of "configured".
#
# Windows PowerShell 5.1 only.

param(
    [switch] $Status
)

$ErrorActionPreference = 'Stop'
$root = 'C:\winlab'
$log = "$root\dsc.log"

function Log($msg) {
    $line = "{0}  [dsc] {1}" -f (Get-Date -Format 'HH:mm:ss'), $msg
    Write-Output $line
    Add-Content -Path $log -Value $line -Encoding utf8
}

function Install-LabModules {
    $zip = "$root\dsc-modules.zip"
    if (-not (Test-Path $zip)) { throw "dsc-modules.zip missing from $root (run 'winlab bootstrap' on the host)" }
    $dest = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
    $stamp = "$root\dsc\modules.installed"
    $fresh = (Test-Path $stamp) -and ((Get-Item $stamp).LastWriteTime -ge (Get-Item $zip).LastWriteTime)
    if ($fresh) { Log 'resource modules already installed'; return }
    Log "installing resource modules into $dest"
    New-Item -ItemType Directory -Path "$root\dsc" -Force | Out-Null
    Expand-Archive -Path $zip -DestinationPath $dest -Force
    Set-Content -Path $stamp -Value (Get-Date -Format o) -Encoding ascii
}

function Wait-LcmIdle($seconds = 3600) {
    for ($i = 0; $i -lt $seconds; $i += 10) {
        $lcm = Get-DscLocalConfigurationManager
        if ($lcm.LCMState -in 'Idle', 'PendingConfiguration') { return $lcm.LCMState }
        if ($i % 120 -eq 0) { Log "LCM is $($lcm.LCMState); waiting" }
        Start-Sleep -Seconds 10
    }
    throw "LCM still busy after $seconds seconds"
}

function Write-StatusLine {
    $state = Wait-LcmIdle
    $t = Test-DscConfiguration -Detailed -ErrorAction Stop
    $report = [ordered]@{
        in_desired_state = [bool]$t.InDesiredState
        lcm_state        = [string]$state
        drift            = @($t.ResourcesNotInDesiredState | ForEach-Object { $_.ResourceId })
        ok               = @($t.ResourcesInDesiredState | ForEach-Object { $_.ResourceId })
    }
    Write-Output ('WINLAB:DSC ' + ($report | ConvertTo-Json -Compress))
}

New-Item -ItemType Directory -Path "$root\dsc" -Force | Out-Null

if ($Status) {
    Write-StatusLine
    return
}

Install-LabModules

$config = "$root\node.dsc.ps1"
if (-not (Test-Path $config)) { throw "generated configuration missing: $config" }
Remove-Item -Path "$root\dsc\mof", "$root\dsc\lcm" -Recurse -Force -ErrorAction SilentlyContinue
Log 'compiling configuration'
& $config | ForEach-Object { Log $_ }

Log 'applying LCM settings'
Set-DscLocalConfigurationManager -Path "$root\dsc\lcm" -Force | Out-Null

Log 'applying configuration (the LCM may reboot the machine)'
# Verbose carries the per-resource trace, which is what you read when a role
# fails; it goes to the log, not the serial line.
Start-DscConfiguration -Path "$root\dsc\mof" -Wait -Force -Verbose *>> $log
Log 'Start-DscConfiguration returned'

Write-StatusLine
