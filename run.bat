@echo off
setlocal
cd /d "%~dp0"
title Prahari

if not exist ".venv\Scripts\python.exe" (
  echo   First run - setting things up, please wait ...
  call install.bat
  if not exist ".venv\Scripts\python.exe" exit /b 1
)

echo ============================================================
echo   Prahari is starting.
echo   It will scan this network and open the dashboard.
echo   Keep this window open. Close it or press Ctrl+C to stop.
echo ============================================================
echo.

".venv\Scripts\python.exe" netsentinel.py %*

echo.
echo   Prahari stopped.
pause
