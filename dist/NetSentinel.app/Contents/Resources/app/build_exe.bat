@echo off
setlocal
cd /d "%~dp0"
title NetSentinel - build EXE

echo ============================================================
echo   Build NetSentinel.exe  ^(single file, no Python needed after^)
echo ============================================================
echo.

if not exist ".venv\Scripts\python.exe" (
  echo   Run install.bat first.
  pause
  exit /b 1
)

".venv\Scripts\python.exe" -m pip install --upgrade pyinstaller --quiet --disable-pip-version-check
if errorlevel 1 (
  echo   Could not install PyInstaller. Check your internet connection.
  pause
  exit /b 1
)

echo   Building ... this takes a minute or two.
".venv\Scripts\pyinstaller.exe" --onefile --name NetSentinel --console --icon netsentinel.ico ^
  --add-data "netscan;netscan" ^
  --hidden-import netscan.netinfo --hidden-import netscan.discovery ^
  --hidden-import netscan.fingerprint --hidden-import netscan.monitor ^
  --hidden-import netscan.snmp --hidden-import netscan.oui ^
  --hidden-import netscan.store --hidden-import netscan.scanner ^
  --hidden-import netscan.webui --hidden-import netscan.report --hidden-import netscan.remote --hidden-import netscan.poll ^
  --hidden-import netscan.netflow --hidden-import netscan.syslogrx --hidden-import netscan.alerts ^
  --hidden-import netscan.auth --hidden-import netscan.diagnose --hidden-import netscan.settings --hidden-import netscan.wan --hidden-import netscan.sites --hidden-import netscan.agent ^
  --hidden-import netscan.oidc --hidden-import netscan.tlsutil --hidden-import netscan.apitokens --hidden-import netscan.netguard ^
  --hidden-import netscan.totp --hidden-import netscan.certs --hidden-import netscan.heartbeat --hidden-import netscan.fleet --hidden-import netscan.tailnet ^
  netsentinel.py

if exist "dist\NetSentinel.exe" (
  echo.
  echo   Done:  dist\NetSentinel.exe
  echo   Copy that single file anywhere and run it. For packet capture it
  echo   still needs Npcap installed and "Run as administrator".
) else (
  echo.
  echo   Build failed - see the messages above.
)
pause
