@echo off
setlocal
cd /d "%~dp0"
title NetSentinel - dashboard (LAN)

if not exist ".venv\Scripts\python.exe" (
  echo   First run - setting things up, please wait ...
  call install.bat
  if not exist ".venv\Scripts\python.exe" exit /b 1
)

echo ============================================================
echo   NetSentinel dashboard, shared on this network
echo.
echo   It scans this network, then opens the dashboard here and
echo   prints the address your laptop / phone can open.
echo.
echo   Sign-in is required on the LAN: the first run prints an admin
echo   password in this window (change it in Settings).
echo ============================================================
echo.

".venv\Scripts\python.exe" netsentinel.py --lan %*

echo.
echo   NetSentinel stopped.
pause
