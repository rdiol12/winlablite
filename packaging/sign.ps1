# Signs one file with Authenticode, so SmartScreen and Windows show the
# publisher instead of "Unknown publisher". build-exe.ps1 calls it for
# winlab.exe, and Inno Setup calls it (as the sign tool "winlabsign") for the
# installer and its uninstaller.
#
#   powershell -ExecutionPolicy Bypass -File packaging\sign.ps1 <file>
#
# One of three certificate routes, from the environment (or the parameters):
#   WINLAB_SIGN_COMMAND     any signing command, {file} is replaced by the file:
#                           Azure Trusted Signing, a cloud HSM, a vendor tool
#   WINLAB_SIGN_THUMBPRINT  a certificate in the Windows certificate store
#                           (a USB token or EV certificate shows up there)
#   WINLAB_SIGN_PFX         a .pfx file, with WINLAB_SIGN_PASSWORD
# WINLAB_SIGN_TIMESTAMP overrides the RFC 3161 timestamp server.
#
# Exit codes: 0 signed, 2 no certificate configured (nothing done), 1 failed.

param(
    [Parameter(Mandatory = $true, Position = 0)] [string] $File,
    [string] $Command = $env:WINLAB_SIGN_COMMAND,
    [string] $Thumbprint = $env:WINLAB_SIGN_THUMBPRINT,
    [string] $Pfx = $env:WINLAB_SIGN_PFX,
    [string] $Password = $env:WINLAB_SIGN_PASSWORD,
    [string] $TimestampUrl = $(if ($env:WINLAB_SIGN_TIMESTAMP) { $env:WINLAB_SIGN_TIMESTAMP } else { 'http://timestamp.digicert.com' })
)

$ErrorActionPreference = 'Stop'

function Find-SignTool {
    $found = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    if (-not $found) { $found = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source }
    return $found
}

if (-not (Test-Path $File)) { Write-Host "sign: no such file $File"; exit 1 }
if (-not ($Command -or $Thumbprint -or $Pfx)) {
    Write-Host "sign: no certificate configured; $File left unsigned"
    exit 2
}

$signtool = Find-SignTool
if ($Command) {
    $line = $Command.Replace('{file}', ('"{0}"' -f $File))
    Write-Host "sign: $([IO.Path]::GetFileName($File)) with the configured command"
    & cmd.exe /c $line
} else {
    if (-not $signtool) { Write-Host 'sign: signtool.exe not found: install the Windows SDK or put signtool on PATH'; exit 1 }
    $how = @('sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $TimestampUrl)
    if ($Thumbprint) { $how += @('/sha1', $Thumbprint) }
    else { $how += @('/f', $Pfx); if ($Password) { $how += @('/p', $Password) } }
    Write-Host "sign: $([IO.Path]::GetFileName($File)) with signtool"
    & $signtool @how $File
}
if ($LASTEXITCODE -ne 0) { Write-Host "sign: signing $File failed ($LASTEXITCODE)"; exit 1 }

if ($signtool) {
    & $signtool verify /pa /q $File
    if ($LASTEXITCODE -ne 0) { Write-Host "sign: the signature on $File does not verify"; exit 1 }
}
exit 0
