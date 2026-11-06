@echo off
REM Double-click to open the winlab desktop for the default lab in its own window.
REM Edit LAB below to change which lab it opens.
setlocal
set "WINLAB_HOME=%~dp0"
set "LAB=ad-ds-basics"

if exist "%WINLAB_HOME%winlab.exe" (
    set RUN="%WINLAB_HOME%winlab.exe"
) else (
    set "PYTHONPATH=%WINLAB_HOME%;%PYTHONPATH%"
    where py >nul 2>&1 && (set "RUN=py -m winlab") || (set "RUN=python -m winlab")
)

echo Starting the winlab dashboard for "%LAB%" ...
echo winlab opens in its own window (Edge or Chrome app mode) at http://127.0.0.1:8780
echo Close this window to stop the dashboard (labs keep running).
%RUN% gui %LAB%
pause
