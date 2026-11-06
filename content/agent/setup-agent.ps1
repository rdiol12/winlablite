# Installs the serial agent as a startup task so control survives the many
# reboots that AD DS promotion and domain joins require.

$ErrorActionPreference = 'Continue'
$Root = 'C:\winlab'
$Agent = Join-Path $Root 'winlab-agent.ps1'
$TaskName = 'winlab-agent'

Write-Output "setup-agent: installing $TaskName"

# Lab machines are throwaway and must never stall provisioning behind a prompt.
powershell -NoProfile -Command "Set-ExecutionPolicy Bypass -Scope LocalMachine -Force" 2>&1 |
    Out-Null

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Agent`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount `
    -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force | Out-Null
    Write-Output 'setup-agent: task registered'
} catch {
    Write-Output "setup-agent: task registration failed: $($_.Exception.Message)"
}

# Turn off the things that make an unattended lab machine stop and wait.
try {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\ServerManager' `
        -Name 'DoNotOpenServerManagerAtLogon' -Value 1 -Force -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Force |
        Out-Null
    powercfg /change standby-timeout-ac 0 2>&1 | Out-Null
    powercfg /change monitor-timeout-ac 0 2>&1 | Out-Null
} catch {}

# The lab's addressing, before the agent and the roles need the network.
try {
    & (Join-Path $Root 'apply-network.ps1') 2>&1 | Out-Null
    Write-Output 'setup-agent: network applied'
} catch {
    Write-Output "setup-agent: network apply failed: $($_.Exception.Message)"
}

try {
    Start-ScheduledTask -TaskName $TaskName
    Write-Output 'setup-agent: task started'
} catch {
    Write-Output "setup-agent: start failed: $($_.Exception.Message)"
}
