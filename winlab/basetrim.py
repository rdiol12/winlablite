r"""What a Windows base does to itself right before it is sealed, so every
clone starts small: no hibernation file, a pagefile that starts at 512 MB,
the component store cleaned, system files compressed (Compact OS), caches
emptied, and the free space handed back to the disk with a retrim so the
qcow2 drops it. Each step is logged to C:\winlab\trim-base.log and a step
that this edition refuses (Compact OS is documented for client Windows)
is skipped, never fatal. The script rides on the preparation data disk;
winlab-stage0.cmd copies it to C:\winlab before it runs.
"""
from __future__ import annotations

FILE = "winlab-trim-base.ps1"
LOG = r"C:\winlab\trim-base.log"

SCRIPT = r"""# winlab: shrink this installation before it becomes a base image.
$ErrorActionPreference = 'Continue'
$log = 'C:\winlab\trim-base.log'
function Step($name, $block) {
    "$(Get-Date -Format s) $name" | Add-Content $log
    try { & $block 2>&1 | Out-String | Add-Content $log }
    catch { "  skipped: $($_.Exception.Message)" | Add-Content $log }
}
Step 'hibernation off' { powercfg.exe /hibernate off }
Step 'pagefile 512 MB, growing to 2 GB' {
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.AutomaticManagedPagefile) {
        $cs | Set-CimInstance -Property @{ AutomaticManagedPagefile = $false }
    }
    $pf = Get-CimInstance Win32_PageFileSetting
    if ($pf) { $pf | Set-CimInstance -Property @{ InitialSize = 512; MaximumSize = 2048 } }
    else { New-CimInstance -ClassName Win32_PageFileSetting -Property @{ Name = 'C:\pagefile.sys'; InitialSize = 512; MaximumSize = 2048 } | Out-Null }
}
Step 'component store cleanup' { Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase }
Step 'compact OS' { compact.exe /CompactOS:always }
Step 'caches' {
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    foreach ($d in @("$env:WINDIR\SoftwareDistribution\Download", "$env:WINDIR\Temp", $env:TEMP, "$env:WINDIR\Logs\CBS")) {
        if (Test-Path $d) { Get-ChildItem $d -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
Step 'retrim free space' { Optimize-Volume -DriveLetter C -ReTrim -ErrorAction Stop }
"$(Get-Date -Format s) done" | Add-Content $log
"""


def command() -> str:
    """The FirstLogonCommands line that runs the script (it must stay under
    the 259 characters an unattend command line allows)."""
    return f"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\winlab\\{FILE}"
