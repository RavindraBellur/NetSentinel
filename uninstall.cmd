@echo off
rem ===========================================================================
rem  Uninstall Prahari.
rem    uninstall.cmd          removes the app, shortcuts and scheduled task
rem    uninstall.cmd /purge   also deletes config, history and users
rem ===========================================================================
setlocal EnableDelayedExpansion
title Prahari - uninstall

set "TARGET=%~dp0"
set "TARGET=%TARGET:~0,-1%"
set "PURGE="
for %%A in (%*) do if /I "%%A"=="/purge" set "PURGE=1"

echo ============================================================
echo   Removing Prahari from "%TARGET%"
echo ============================================================
echo.

choice /c YN /m "Continue"
if errorlevel 2 exit /b 0

echo   Stopping the scheduled task ...
schtasks /Delete /TN "Prahari" /F >nul 2>&1
schtasks /Delete /TN "NetSentinel" /F >nul 2>&1

echo   Removing firewall rules ...
net session >nul 2>&1 && (
  netsh advfirewall firewall delete rule name="Prahari Dashboard" >nul 2>&1
  netsh advfirewall firewall delete rule name="Prahari Flow Syslog" >nul 2>&1
)

echo   Removing shortcuts ...
del /q "%USERPROFILE%\Desktop\Prahari.lnk" >nul 2>&1
del /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Prahari.lnk" >nul 2>&1

if defined PURGE (
  echo   Deleting configuration, history and users ...
  rmdir /s /q "%USERPROFILE%\.netsentinel" >nul 2>&1
)

echo   Deleting program files ...
rem the .venv and everything next to this script, but not the script itself
for /d %%D in ("%TARGET%\*") do rmdir /s /q "%%D" >nul 2>&1
del /q "%TARGET%\*.py" "%TARGET%\*.bat" "%TARGET%\*.cmd" "%TARGET%\*.md" ^
       "%TARGET%\*.txt" "%TARGET%\*.ico" "%TARGET%\*.png" >nul 2>&1
cd /d "%TEMP%"
rmdir /s /q "%TARGET%" >nul 2>&1

echo.
echo   Done. Python itself was not removed (other programs may use it).
if not defined PURGE echo   Config and history kept in %%USERPROFILE%%\.netsentinel
pause
