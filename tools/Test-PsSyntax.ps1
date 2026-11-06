# Parses every .ps1 under content/ and packaging/ with the running PowerShell
# and fails on any syntax error. Run it under powershell.exe (5.1): that is the
# version the in-guest agent uses to run roles.

param(
    # Extra directories to parse, e.g. the generated DSC configurations.
    [string[]] $Extra = @()
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dirs = @((Join-Path $root 'content'), (Join-Path $root 'packaging')) + $Extra
$files = Get-ChildItem -Path $dirs -Filter *.ps1 -Recurse
$bad = 0
foreach ($f in $files) {
    $tokens = $null; $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $f.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    foreach ($e in $errors) {
        $bad++
        Write-Output ("{0}:{1}: {2}" -f $f.FullName.Substring($root.Length + 1),
            $e.Extent.StartLineNumber, $e.Message)
    }
}
Write-Output "$($files.Count) scripts parsed with PowerShell $($PSVersionTable.PSVersion), $bad error(s)"
if ($bad) { exit 1 }
