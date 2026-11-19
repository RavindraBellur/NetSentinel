@echo off
setlocal
cd /d "%~dp0"
title NetSentinel - start at login

net session >nul 2>&1
if errorlevel 1 (
  echo   This needs Administrator rights.
  echo   Right click this file and choose "Run as administrator".
  pause
  exit /b 1
)

echo   Registering NetSentinel to start when this user logs in ...
schtasks /Create /TN "NetSentinel" /TR "\"%CD%\run.bat\"" /SC ONLOGON /RL HIGHEST /F
if errorlevel 1 (
  echo   Could not register the task.
) else (
  echo.
  echo   Done. NetSentinel will scan the network and open the dashboard
  echo   at http://127.0.0.1:8777 every time you log in.
  echo   Remove it later with autostart_remove.bat
)
pause
