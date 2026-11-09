# winlab console host: the Command Prompt and PowerShell windows on the
# desktop reach this machine through its COM3 serial port, never the network.
# The host itself is winlab-term.cs beside this script (compiled here with
# Add-Type); setup-term.ps1 runs it as a startup task under SYSTEM so it can
# sign the student in with the account they type.
#
#   -Com COM3          the serial port (the default)
#   -Listen ip:port    a loopback TCP listener instead (the CI smoke test only)
#   -Test              no sign-in: sessions run as this script's own account

param(
    [string] $Com = 'COM3',
    [string] $Listen = '',
    [switch] $Test,
    [string] $Log = 'C:\winlab\term.log'
)

$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot 'winlab-term.cs'

Add-Type -TypeDefinition ([IO.File]::ReadAllText($source)) -Language CSharp

$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
# .NET's SHA-256, not Get-FileHash: that cmdlet comes from a module, and a
# powershell.exe started from PowerShell 7 inherits a module path where it is missing.
$sha = [Security.Cryptography.SHA256]::Create()
try { $digest = $sha.ComputeHash([IO.File]::ReadAllBytes($source)) } finally { $sha.Dispose() }
[WinlabTerm.Host]::Build = ([BitConverter]::ToString($digest) -replace '-', '').Substring(0, 16).ToLowerInvariant()
[WinlabTerm.Host]::OsName = [string] $os.Caption
[WinlabTerm.Host]::Computer = $env:COMPUTERNAME
[WinlabTerm.Host]::DomainDns = $(if ($cs.PartOfDomain) { [string] $cs.Domain } else { '' })
[WinlabTerm.Host]::TestMode = [bool] $Test
[WinlabTerm.Host]::LogPath = $Log

[WinlabTerm.Host]::Run($Com, $Listen)
