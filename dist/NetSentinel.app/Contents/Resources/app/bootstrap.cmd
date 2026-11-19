@echo off
rem ===========================================================================
rem  NetSentinel bootstrap - installs everything, then starts the app.
rem
rem  Called by NetSentinel-Setup.exe (the single-file installer) or run by hand.
rem  It will, in order:
rem     1. copy the app to %LOCALAPPDATA%\NetSentinel  (or update it in place)
rem     2. find Python 3.9+ - if it is missing, download and install it silently
rem     3. create a private environment and install the two optional extras
rem     4. add a desktop shortcut, a Start-menu entry and an uninstaller
rem     5. open the firewall for the dashboard (when running as Administrator)
rem     6. start NetSentinel
rem
rem  Options:  /autostart   also start at every login (needs Administrator)
rem            /no-run      install only
rem            /allusers    install under ProgramData (needs Administrator)
rem ===========================================================================
setlocal EnableDelayedExpansion
title NetSentinel - setup

set "SRC=%~dp0"
set "SRC=%SRC:~0,-1%"
set "TARGET=%LOCALAPPDATA%\NetSentinel"
set "LOG=%TEMP%\netsentinel-setup.log"
set "PYVER=3.12.9"
set "PYURL=https://www.python.org/ftp/python/%PYVER%/python-%PYVER%-amd64.exe"
set "AUTOSTART="
set "NORUN="

for %%A in (%*) do (
  if /I "%%A"=="/autostart" set "AUTOSTART=1"
  if /I "%%A"=="/no-run" set "NORUN=1"
  if /I "%%A"=="/allusers" set "TARGET=%ProgramData%\NetSentinel"
)

echo ============================================================
echo   NetSentinel setup
echo ============================================================
echo.

rem ---- 0. am I elevated? -----------------------------------------------
set "ELEVATED="
net session >nul 2>&1 && set "ELEVATED=1"

rem ---- 1. copy the app -------------------------------------------------
if exist "%SRC%\NetSentinel-app.zip" (
  echo   [1/6] Unpacking the application to "%TARGET%" ...
  if not exist "%TARGET%" mkdir "%TARGET%" >nul 2>&1
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "try { Expand-Archive -LiteralPath '%SRC%\NetSentinel-app.zip' -DestinationPath '%TARGET%' -Force; exit 0 } catch { Write-Host $_.Exception.Message; exit 1 }"
  if errorlevel 1 (
    echo   Could not unpack the archive. Aborting.
    pause
    exit /b 1
  )
) else (
  echo   [1/6] Using the application files next to this script ...
  if /I not "%SRC%"=="%TARGET%" (
    if not exist "%TARGET%" mkdir "%TARGET%" >nul 2>&1
    xcopy "%SRC%\*" "%TARGET%\" /E /I /Y /Q /EXCLUDE:"%SRC%\install.exclude" >nul 2>&1
  )
)

cd /d "%TARGET%"
if not exist "netsentinel.py" (
  echo   The application files are missing from "%TARGET%".
  pause
  exit /b 1
)
echo   NetSentinel files are in "%TARGET%"
echo.

rem ---- 2. Python -------------------------------------------------------
echo   [2/6] Looking for Python 3.9 or newer ...
set "PY="
call :findpython
if defined PY goto :havepython

echo   Python is not installed - downloading it from python.org (one time) ...
where curl >nul 2>&1
if not errorlevel 1 (
  curl -L --fail --silent --show-error -o "%TEMP%\python-setup.exe" "%PYURL%" >>"%LOG%" 2>&1
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "try { Invoke-WebRequest -Uri '%PYURL%' -OutFile '%TEMP%\python-setup.exe' -UseBasicParsing; exit 0 } catch { Write-Host $_.Exception.Message; exit 1 }"
)
if not exist "%TEMP%\python-setup.exe" (
  echo   Download failed. Install Python 3.9+ from https://www.python.org/downloads/windows/
  echo   then run this setup again.
  pause
  exit /b 1
)
echo   Installing Python silently (2-3 minutes, no clicks needed) ...
"%TEMP%\python-setup.exe" /quiet InstallAllUsers=0 PrependPath=1 Include_launcher=1 Include_pip=1 Include_test=0 Shortcuts=1
del /q "%TEMP%\python-setup.exe" >nul 2>&1

rem refresh PATH for this session
set "PATH=%LOCALAPPDATA%\Programs\Python\Python312;%LOCALAPPDATA%\Programs\Python\Python312\Scripts;%PATH%"
call :findpython
if not defined PY (
  echo   Python was installed but is not visible yet. Close this window and run
  echo   NetSentinel from the desktop shortcut - it will finish the setup.
  pause
  exit /b 1
)

:havepython
echo   Using Python: "%PY%"
"%PY%" -c "import sys;print('   version',sys.version.split()[0])"
echo.

rem ---- 3. private environment + extras ---------------------------------
echo   [3/6] Preparing the application environment ...
if not exist ".venv\Scripts\python.exe" (
  "%PY%" -m venv .venv
  if errorlevel 1 (
    echo   Could not create the environment. Try running this as Administrator.
    pause
    exit /b 1
  )
)
".venv\Scripts\python.exe" -m pip install --upgrade pip --quiet --disable-pip-version-check >>"%LOG%" 2>&1
".venv\Scripts\python.exe" -m pip install -r requirements.txt --quiet --disable-pip-version-check >>"%LOG%" 2>&1
if errorlevel 1 (
  echo   Optional extras could not be installed - NetSentinel runs without them.
) else (
  echo   Optional extras installed ^(traffic capture, NIC rates^).
)
".venv\Scripts\python.exe" -c "import sys;sys.path.insert(0,'.');import netscan.webui,netscan.poll,netscan.netflow,netscan.wan,netscan.sites;print('   core modules OK')"
if errorlevel 1 (
  echo   Self test failed. See "%LOG%".
  pause
  exit /b 1
)
echo.

rem ---- 3b. optional Tailscale -------------------------------------------
if not "%~1"=="" (
  echo   Setting up Tailscale ^(private remote access, no port-forward^) ...
  ".venv\Scripts\python.exe" netsentinel.py --install-tailscale %*
  echo.
)

rem ---- 4. shortcuts + uninstaller --------------------------------------
echo   [4/6] Creating shortcuts ...
set "LNK=%USERPROFILE%\Desktop\NetSentinel.lnk"
set "STARTMENU=%APPDATA%\Microsoft\Windows\Start Menu\Programs"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$w=New-Object -ComObject WScript.Shell;" ^
  "$s=$w.CreateShortcut('%LNK%');$s.TargetPath='%TARGET%\run.bat';$s.WorkingDirectory='%TARGET%';$s.IconLocation='%TARGET%\netsentinel.ico';$s.Description='NetSentinel network console';$s.Save();" ^
  "$m=$w.CreateShortcut('%STARTMENU%\NetSentinel.lnk');$m.TargetPath='%TARGET%\run.bat';$m.WorkingDirectory='%TARGET%';$m.IconLocation='%TARGET%\netsentinel.ico';$m.Save()" >nul 2>&1
echo   Desktop and Start-menu shortcuts created.
echo.

rem ---- 5. firewall + optional autostart --------------------------------
echo   [5/6] Network access ...
if defined ELEVATED (
  netsh advfirewall firewall delete rule name="NetSentinel Dashboard" >nul 2>&1
  netsh advfirewall firewall add rule name="NetSentinel Dashboard" dir=in action=allow ^
    protocol=TCP localport=8777-8788 profile=private,domain description="NetSentinel dashboard" >nul 2>&1
  netsh advfirewall firewall delete rule name="NetSentinel Flow Syslog" >nul 2>&1
  netsh advfirewall firewall add rule name="NetSentinel Flow Syslog" dir=in action=allow ^
    protocol=UDP localport=2055,6343,5514 profile=private,domain description="NetSentinel flow and syslog" >nul 2>&1
  echo   Firewall opened for the dashboard ^(8777-8788^) and flow/syslog ^(2055, 6343, 5514^).
  if defined AUTOSTART (
    schtasks /Create /TN "NetSentinel" /TR "\"%TARGET%\run.bat\"" /SC ONLOGON /RL HIGHEST /F >nul 2>&1
    if not errorlevel 1 echo   NetSentinel will start at every login.
  )
) else (
  echo   Not running as Administrator - skipped the firewall rule and autostart.
  echo   If other PCs must open the dashboard, run allow_firewall.bat as Administrator.
)
echo.

rem ---- 6. run ----------------------------------------------------------
echo   [6/6] Starting NetSentinel ...
echo.
if defined NORUN (
  echo   Installed. Start it from the desktop shortcut.
  pause
  exit /b 0
)
start "" /D "%TARGET%" "%TARGET%\run.bat"
timeout /t 3 >nul
exit /b 0

rem ---------------------------------------------------------------------
:findpython
set "PY="
py -3 -c "import sys;raise SystemExit(0 if sys.version_info>=(3,9) else 1)" >nul 2>&1 && set "PY=py -3"
if not defined PY (
  python -c "import sys;raise SystemExit(0 if sys.version_info>=(3,9) else 1)" >nul 2>&1 && set "PY=python"
)
if not defined PY (
  for %%D in ("%LOCALAPPDATA%\Programs\Python\Python313\python.exe" ^
               "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" ^
               "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" ^
               "%ProgramFiles%\Python313\python.exe" ^
               "%ProgramFiles%\Python312\python.exe" ^
               "%ProgramFiles%\Python311\python.exe") do (
    if exist %%D set "PY=%%~D"
  )
)
exit /b 0
