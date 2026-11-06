@echo off
rem Runs once at first logon from the winlab data volume. %~d0 is that drive.
setlocal

set WLDST=C:\winlab
if not exist "%WLDST%" mkdir "%WLDST%"

copy /y "%~d0\*.ps1"   "%WLDST%\" >nul 2>&1
copy /y "%~d0\*.json"  "%WLDST%\" >nul 2>&1
copy /y "%~d0\*.cmd"   "%WLDST%\" >nul 2>&1
copy /y "%~d0\*.zip"   "%WLDST%\" >nul 2>&1
copy /y "%~d0\*.msi"   "%WLDST%\" >nul 2>&1

> "%WLDST%\stage0.log" echo stage0 started %DATE% %TIME% from %~d0

powershell -NoProfile -ExecutionPolicy Bypass -File "%WLDST%\setup-agent.ps1" ^
  >> "%WLDST%\stage0.log" 2>&1

endlocal
