@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title Prahari - installer

echo ============================================================
echo   Prahari 1.32.1 - installer
echo ============================================================
echo.

rem ---- 1. find Python -------------------------------------------------------
set PY=
where py >nul 2>nul && set PY=py -3
if "%PY%"=="" (where python >nul 2>nul && set PY=python)
if "%PY%"=="" (
  echo   Python was not found on this PC.
  echo.
  echo   Install Python 3.9 or newer from https://www.python.org/downloads/windows/
  echo   IMPORTANT: tick "Add python.exe to PATH" on the first installer screen.
  echo   Then run this file again.
  echo.
  pause
  exit /b 1
)
for /f "tokens=*" %%v in ('%PY% -c "import sys;print(sys.version.split()[0])"') do set PYVER=%%v
echo   Python found: %PY%  ^(version %PYVER%^)
echo.

rem ---- 2. virtual environment ----------------------------------------------
if exist ".venv\Scripts\python.exe" (
  echo   Existing environment found - reusing it.
) else (
  echo   Creating a private Python environment in .venv ...
  %PY% -m venv .venv
  if errorlevel 1 (
    echo   Could not create the environment. Try running this file as Administrator.
    pause
    exit /b 1
  )
)
set VPY=.venv\Scripts\python.exe

echo   Updating pip ...
"%VPY%" -m pip install --upgrade pip --quiet --disable-pip-version-check
echo.
echo   Installing optional extras ^(scapy for traffic capture, psutil for NIC rates^) ...
"%VPY%" -m pip install -r requirements.txt --quiet --disable-pip-version-check
if errorlevel 1 (
  echo   Extras failed to install - that is fine, Prahari runs without them.
) else (
  echo   Extras installed.
)

rem ---- 3. quick self test ---------------------------------------------------
echo.
echo   Self test ...
"%VPY%" -c "import sys;sys.path.insert(0,'.');import netscan.netinfo,netscan.snmp,netscan.webui;print('   core modules OK')"
if errorlevel 1 (
  echo   Self test failed. Please send the text above for support.
  pause
  exit /b 1
)

echo.
echo ============================================================
rem ---- optional: Tailscale (private remote access, no port-forward) ------
if not "%~1"=="" (
  echo.
  echo   Setting up Tailscale ...
  "%VPY%" netsentinel.py --install-tailscale %*
)

echo   Installed. Double click  run.bat  to start scanning.
echo ============================================================
echo.
echo   Optional, for per-device internet usage:
echo     * Enable SNMP ^(community: public^) on your router / switch, or
echo     * Install Npcap from https://npcap.com  and run Prahari
echo       as Administrator so it can count packets per device.
echo.
echo   To start automatically at login, right click
echo   autostart_install.bat  and choose "Run as administrator".
echo.
pause
