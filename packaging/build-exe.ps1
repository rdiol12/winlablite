# Builds winlab.exe and its installer: CPython + the winlab package + the
# content pack in one file, so a customer installs nothing else. Run on a
# Windows build machine:
#
#   powershell -ExecutionPolicy Bypass -File packaging\build-exe.ps1
#   powershell -ExecutionPolicy Bypass -File packaging\build-exe.ps1 -Edition core
#
# -Edition core builds winlab core, the cut-down first release (winlab/edition.py):
# one lab (ad-ds-basics), its lessons and drills, no licence, no paid packs.
# Its files are named winlab-core-<version>-setup.exe and -win64.zip.
#
# Output
#   dist\winlab.exe                      the product
#   dist\winlab-<version>-setup.exe      the installer customers run (needs
#                                        Inno Setup 6.3+, free, on the build machine)
#   dist\winlab-<version>-win64.zip      portable: exe + winlab-start.exe + README, LICENSING, CURRICULUM, EULA (+ translations)
#
# What is and is not inside the exe (see LICENSING.md):
#   in   CPython (PSF), winlab (yours), content pack (yours), PyInstaller's
#        bootloader (GPL with the bootloader exception, which permits this).
#   out  QEMU, the DSC resource modules, Microsoft media. 'winlab bootstrap'
#        (or Setup's Get everything ready) fetches the first two on the
#        customer's machine; the third they download themselves. The vendor
#        license server is excluded too.
#
# The portable exe lays the content pack out next to itself (content\) and
# creates runtime\, var\ and images\ there. The installed exe keeps them in
# the data folder chosen at installation (winlab-home.txt); see winlab/paths.py.

param(
    [string] $Python = 'python',
    [switch] $SkipZip,
    [switch] $SkipInstaller,
    # Code signing (SmartScreen trusts a signed exe from a known publisher).
    # packaging\sign.ps1 does the signing; it takes a sign command, a
    # certificate-store thumbprint or a .pfx from the environment (see there).
    # -SignPfx/-SignPassword, or WINLAB_SIGN_PFX_BASE64 + WINLAB_SIGN_PASSWORD
    # (how CI receives a .pfx from repository secrets), feed the .pfx route.
    # With no certificate the build is left unsigned and says so.
    [string] $SignPfx = '',
    [string] $SignPassword = '',
    [string] $TimestampUrl = 'http://timestamp.digicert.com',
    # The name in Apps & features; the legal name on the certificate once signed.
    [string] $Publisher = 'winlab',
    # Test builds only: skip compiling the licensing and decryption modules
    # to native code (packaging\protect.py). A release never sets this.
    [switch] $NoProtect,
    # full: the whole app. core: winlab core (see the top of this file).
    [ValidateSet('full', 'core')] [string] $Edition = 'full'
)

$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 turns any stderr line from a native program into a
# terminating error under 'Stop', so a mere warning (PyInstaller's "running as
# admin" notice, pip's update notice) would end the build. Native tools run
# through this with 'Continue'; their exit codes are checked by hand.
function Invoke-Native([scriptblock]$Command) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Command } finally { $ErrorActionPreference = $saved }
}
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$version = Invoke-Native { & $Python -c "import winlab; print(winlab.__version__)" }
if ($LASTEXITCODE -ne 0) { throw 'cannot import winlab; run from a checkout with Python 3.11+' }
Write-Host "winlab exe build  version $version  edition $Edition" -ForegroundColor Cyan
$prefix = if ($Edition -eq 'core') { 'winlab-core' } else { 'winlab' }
Write-Host "  repo: $root"

# 1. PyInstaller, installed into the build environment only (never shipped
#    as a module; its bootloader is what wraps the exe).
# find_spec prints nothing, so the probe never trips over stderr.
Invoke-Native { & $Python -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('PyInstaller') else 1)" }
if ($LASTEXITCODE -ne 0) {
    Write-Host '  installing PyInstaller into the build environment...'
    Invoke-Native { & $Python -m pip install --upgrade pyinstaller }
    if ($LASTEXITCODE -ne 0) { throw 'pip install pyinstaller failed' }
}

# 2. The exe icon: winlab's own drawing, rendered by winlab itself (no image
#    library, nothing checked in as a binary). Explorer, the taskbar and the
#    Start menu show it; the desktop's browser tab gets the same icon at run time.
$icoDir = Join-Path $root 'build'
New-Item -ItemType Directory -Force -Path $icoDir | Out-Null
$ico = Join-Path $icoDir 'winlab.ico'
Invoke-Native { & $Python -m winlab icon $ico }
if ($LASTEXITCODE -ne 0) { throw 'winlab icon failed' }

# 2b. The paid labs ship encrypted: the release workflow runs
#     'winlab content-pack build content\packs\labs-full.wlpack --strip' first.
#     A local build without that step ships every lab as a plain file.
#     winlab core has no paid labs: it ships only its own content, staged into
#     build\content-core, and a one-word edition.txt in the bundle.
$contentDir = Join-Path $root 'content'
$editionData = @()
if ($Edition -eq 'core') {
    $contentDir = Join-Path $root 'build\content-core'
    & $Python -c "import sys; from pathlib import Path; from winlab import edition; print('  content: core', edition.stage(Path(sys.argv[1]), Path(sys.argv[2])))" (Join-Path $root 'content') $contentDir
    if ($LASTEXITCODE -ne 0) { throw 'staging the core content failed' }
    # The trial's labs, lessons, answers and their translations go into one
    # encrypted pack; its key is written as winlab\licensing\trialkey.py,
    # compiled below with the rest of the package and deleted after the build.
    $out = Invoke-Native { & $Python (Join-Path $PSScriptRoot 'trialpack.py') $contentDir }
    if ($LASTEXITCODE -ne 0) { throw 'encrypting the trial content failed (packaging\trialpack.py)' }
    $out | ForEach-Object { Write-Host "  $_" }
    if ($NoProtect) { Write-Host '  NOTE: -NoProtect leaves the pack key as bytecode; never for a release' -ForegroundColor Yellow }
    $editionFile = Join-Path $root 'build\edition.txt'
    [IO.File]::WriteAllText($editionFile, 'core')
    $editionData = @('--add-data', "$editionFile;.")
} elseif (-not (Test-Path (Join-Path $root 'content\packs\labs-full.wlpack'))) {
    Write-Host '  content: NOT encrypted (no content\packs\labs-full.wlpack); fine for a test build, never for a release' -ForegroundColor Yellow
}

# 2c. The licensing, decryption, update-signature and seal modules are
#     compiled to native code with Cython (Apache 2.0, build machine only),
#     so the exe carries no bytecode of them to decompile. PyInstaller then
#     packs that compiled copy of the package instead of the checkout.
$pkgPath = $root
$hidden = @()
if (-not $NoProtect) {
    # find_spec prints nothing: a traceback on stderr is a terminating error
    # under $ErrorActionPreference = 'Stop', so `import Cython` cannot probe.
    Invoke-Native { & $Python -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('Cython') else 1)" }
    if ($LASTEXITCODE -ne 0) {
        Write-Host '  installing Cython into the build environment...'
        Invoke-Native { & $Python -m pip install 'cython==3.1.2' setuptools }
        if ($LASTEXITCODE -ne 0) { throw 'pip install cython failed' }
    }
    $pkgPath = Join-Path $root 'build\protected'
    $out = Invoke-Native { & $Python (Join-Path $PSScriptRoot 'protect.py') $pkgPath }
    if ($LASTEXITCODE -ne 0) { throw 'compiling the protected modules failed (packaging\protect.py)' }
    foreach ($line in $out) {
        if ($line -like 'hidden-import: *') { $hidden += @('--hidden-import', $line.Substring(15)) }
        else { Write-Host "  $line" }
    }
} else {
    Write-Host '  protect: skipped (-NoProtect); the code ships as bytecode' -ForegroundColor Yellow
}

# 3. Build. --add-data ships the content pack and the dashboard page inside
#    the exe; everything winlab writes goes next to the exe at run time.
#    (SOURCE;DEST: ';' is the Windows separator. Keep each element a single
#    string literal: inside @(...) the comma binds tighter than '+'.)
$piArgs = @(
    '--name', 'winlab',
    '--onefile', '--console', '--clean', '--noconfirm',
    '--icon', $ico,
    '--paths', $pkgPath,
    '--distpath', (Join-Path $root 'dist'),
    '--workpath', (Join-Path $root 'build\pyinstaller'),
    '--specpath', (Join-Path $root 'build\pyinstaller'),
    '--add-data', "$contentDir;content",
    '--add-data', "$root\winlab\webui_page.html;winlab",
    '--collect-submodules', 'winlab',
    '--exclude-module', 'winlab.licensing.server',
    (Join-Path $PSScriptRoot 'winlab_entry.py')
) + $hidden + $editionData
Invoke-Native { & $Python -m PyInstaller @piArgs }
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed' }

if (-not $NoProtect) {
    # Proof that PyInstaller packed the compiled copy: no protected module may
    # appear as Python source in its tables of contents.
    $leaks = Get-ChildItem (Join-Path $root 'build\pyinstaller') -Recurse -Filter '*.toc' |
        Select-String -SimpleMatch -Pattern 'licensing\client.py', 'licensing\trialkey.py', 'winlab\content.py', 'winlab\packs.py', 'winlab\webui.py', 'winlab\edition.py'
    if ($leaks) { throw "a protected module was packed as bytecode: $($leaks[0].Line.Trim())" }
    Write-Host '  protect: the whole winlab package is native code in the exe' -ForegroundColor Green
}
# The pack key lives only inside the exe.
Remove-Item (Join-Path $root 'winlab\licensing\trialkey.py') -Force -ErrorAction SilentlyContinue

$exe = Join-Path $root 'dist\winlab.exe'
if (-not (Test-Path $exe)) { throw "expected $exe" }
$mb = (Get-Item $exe).Length / 1MB
Write-Host ("  built: {0} ({1:N1} MB)" -f $exe, $mb) -ForegroundColor Green

# 3b. winlab-start.exe: what the shortcuts run, so no console window opens
#     beside the app (packaging\launcher\winlab-start.cs). Compiled with the
#     C# compiler that is part of Windows' own .NET Framework 4.
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "the C# compiler of .NET Framework 4 is missing ($csc)" }
$starter = Join-Path $root 'dist\winlab-start.exe'
Invoke-Native { & $csc /nologo /target:winexe /optimize+ "/win32icon:$ico" "/out:$starter" `
                  (Join-Path $PSScriptRoot 'launcher\winlab-start.cs') }
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $starter)) { throw 'compiling winlab-start.exe failed' }
Write-Host ("  built: {0} ({1:N0} KB, starts winlab without a console window)" -f $starter, ((Get-Item $starter).Length / 1KB)) -ForegroundColor Green

# 4. Sign the exe when a certificate is available (packaging\sign.ps1).
$pfxTemp = ''
if (-not $SignPfx -and $env:WINLAB_SIGN_PFX_BASE64) {
    $pfxTemp = Join-Path $env:TEMP ("winlab-sign-{0}.pfx" -f [guid]::NewGuid())
    [IO.File]::WriteAllBytes($pfxTemp, [Convert]::FromBase64String($env:WINLAB_SIGN_PFX_BASE64))
    $SignPfx = $pfxTemp
}
# The installer's sign tool runs sign.ps1 as a child process: it reads these.
if ($SignPfx) { $env:WINLAB_SIGN_PFX = $SignPfx }
if ($SignPassword) { $env:WINLAB_SIGN_PASSWORD = $SignPassword }
if (-not $env:WINLAB_SIGN_TIMESTAMP) { $env:WINLAB_SIGN_TIMESTAMP = $TimestampUrl }
$signScript = Join-Path $PSScriptRoot 'sign.ps1'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $signScript $exe
$signed = $LASTEXITCODE -eq 0
if ($signed) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $signScript $starter
    if ($LASTEXITCODE -ne 0) { throw 'signing winlab-start.exe failed' }
}
if ($LASTEXITCODE -eq 2) {
    Write-Host '  signed: no (set WINLAB_SIGN_COMMAND, WINLAB_SIGN_THUMBPRINT or WINLAB_SIGN_PFX(_BASE64); SmartScreen will warn)' -ForegroundColor Yellow
} elseif (-not $signed) {
    throw 'signing failed'
} else {
    Write-Host '  signed: yes' -ForegroundColor Green
}

# 5. The installer (Inno Setup: free, commercial use allowed; a build tool,
#    only its setup stub ships). Signed with the same certificate as the exe.
if (-not $SkipInstaller) {
    $iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
              "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $iscc) { $iscc = (Get-Command iscc.exe -ErrorAction SilentlyContinue).Source }
    if (-not $iscc) {
        Write-Host '  setup: skipped (install Inno Setup 6.3 or later from jrsoftware.org, or pass -SkipInstaller)' -ForegroundColor Yellow
    } else {
        $isccArgs = @("/DAppVersion=$version", "/DRepoDir=$root", "/DDistDir=$(Join-Path $root 'dist')",
                      "/DIconFile=$ico", "/DPublisher=$Publisher", "/DOutputName=$prefix-$version-setup")
        if ($signed) {
            # $q is Inno's quote and $f the file it signs.
            $isccArgs += @('/DSIGN', ('/Swinlabsign=powershell.exe -NoProfile -ExecutionPolicy Bypass -File $q' + $signScript + '$q $f'))
        }
        Invoke-Native { & $iscc @isccArgs (Join-Path $PSScriptRoot 'winlab.iss') }
        if ($LASTEXITCODE -ne 0) { throw 'Inno Setup failed' }
        $setup = Join-Path $root "dist\$prefix-$version-setup.exe"
        if (-not (Test-Path $setup)) { throw "expected $setup" }
        Write-Host ("  setup: {0} ({1:N1} MB)" -f $setup, ((Get-Item $setup).Length / 1MB)) -ForegroundColor Green
    }
}
if ($pfxTemp) { Remove-Item $pfxTemp -Force -ErrorAction SilentlyContinue; Remove-Item Env:\WINLAB_SIGN_PFX -ErrorAction SilentlyContinue }

# 6. The portable distributable: the exe plus the documents a buyer should read.
if (-not $SkipZip) {
    $zip = Join-Path $root "dist\$prefix-$version-win64.zip"
    Remove-Item $zip -ErrorAction SilentlyContinue
    $docs = @("$root\README.md", "$root\LICENSING.md", "$root\CURRICULUM.md") + @(Get-ChildItem "$root\EULA*.txt" | ForEach-Object FullName)
    Compress-Archive -Path (@($exe, $starter) + $docs) -DestinationPath $zip
    Write-Host "  zip  : $zip" -ForegroundColor Green
}

Write-Host ''
Write-Host '  test : .\dist\winlab.exe doctor'
Write-Host '  ship : the setup (the zip is the portable copy). Replace the vendor public key in'
Write-Host '         winlab\licensing\keys.py before building, and sign (packaging\sign.ps1) so'
Write-Host '         SmartScreen trusts the exe and the setup.'
# The native tools' exit codes were checked above; CI reads $LASTEXITCODE.
exit 0
