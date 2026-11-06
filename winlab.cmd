@echo off
REM winlab launcher. Double-click, or run from any terminal: winlab <command>
REM Uses winlab.exe when it sits next to this file, else the winlab package
REM with an installed Python. Works wherever you copy the winlab folder.
setlocal
set "WINLAB_HOME=%~dp0"

if exist "%WINLAB_HOME%winlab.exe" (
    set RUN="%WINLAB_HOME%winlab.exe"
) else (
    set "PYTHONPATH=%WINLAB_HOME%;%PYTHONPATH%"
    where py >nul 2>&1 && (set "RUN=py -m winlab") || (set "RUN=python -m winlab")
)

if "%~1"=="" (
    REM No arguments: show help and keep the window open when double-clicked.
    %RUN% --help
    echo.
    echo Try:  winlab doctor   ^|   winlab lab up ad-ds-basics   ^|   winlab gui ad-ds-basics
    pause
    goto :eof
)

%RUN% %*
