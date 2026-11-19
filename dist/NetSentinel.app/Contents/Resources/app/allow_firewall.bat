@echo off
setlocal
cd /d "%~dp0"
title NetSentinel - firewall rule

rem Lets other devices on your network (your laptop, phone, tablet) open the
rem NetSentinel dashboard. Run once. Administrator rights required.

net session >nul 2>&1
if errorlevel 1 (
  echo   This needs Administrator rights.
  echo   Right click this file and choose "Run as administrator".
  pause
  exit /b 1
)

echo   Adding firewall rule for the dashboard ports 8777-8788 ...
netsh advfirewall firewall delete rule name="NetSentinel Dashboard" >nul 2>&1
netsh advfirewall firewall add rule name="NetSentinel Dashboard" dir=in action=allow ^
  protocol=TCP localport=8777-8788 profile=private,domain description="NetSentinel local dashboard"
if errorlevel 1 (
  echo   Could not add the rule.
) else (
  echo.
  echo   Done. Start with dashboard_lan.bat, then open the address it prints
  echo   from your laptop, e.g. http://192.168.1.24:8777/
)
pause
