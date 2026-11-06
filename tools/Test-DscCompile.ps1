# Compiles every generated winlab DSC configuration to MOF under Windows
# PowerShell 5.1, with a stand-in facts.json, so unknown resources and
# misspelled properties fail in CI instead of inside a lab machine.
#
# Needs the fetched modules on $env:PSModulePath (./runtime/psmodules).

param(
    [Parameter(Mandatory)] [string] $Dir
)

$ErrorActionPreference = 'Stop'
$root = 'C:\winlab'
New-Item -ItemType Directory -Path $root -Force | Out-Null
# The password is a throwaway generated here: the MOF is discarded, and a
# literal would trip secret scanners for nothing.
$throwaway = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ })
@{
    lab = @{ name = 'ci'; domain = 'corp.lab'; netbios = 'CORP'; admin_password = $throwaway }
} | ConvertTo-Json | Set-Content -Path "$root\facts.json" -Encoding utf8

$files = Get-ChildItem -Path $Dir -Filter *.dsc.ps1
$bad = 0
foreach ($f in $files) {
    Remove-Item -Path "$root\dsc" -Recurse -Force -ErrorAction SilentlyContinue
    try {
        $out = & $f.FullName 2>&1
        $mof = Get-ChildItem -Path "$root\dsc\mof" -Filter *.mof -ErrorAction Stop
        $meta = Get-ChildItem -Path "$root\dsc\lcm" -Filter *.meta.mof -ErrorAction Stop
        if (-not $mof -or -not $meta) { throw 'no MOF produced' }
        Write-Output ("ok    {0}: {1}" -f $f.Name, ($out | Select-Object -Last 1))
    } catch {
        $bad++
        Write-Output ("FAIL  {0}: {1}" -f $f.Name, $_.Exception.Message)
        $out | ForEach-Object { Write-Output "      $_" }
    }
}
Write-Output "$($files.Count) configurations compiled, $bad failed"
if ($bad) { exit 1 }
