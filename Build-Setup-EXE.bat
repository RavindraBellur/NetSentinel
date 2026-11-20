@echo off
rem ===========================================================================
rem  Build ONE self-contained installer:  dist\Prahari-Setup.exe
rem
rem  Uses only what Windows already has (PowerShell + IExpress + makecab), so
rem  nothing has to be downloaded to build it. The result is a single .exe that
rem  unpacks the app, downloads Python automatically if the PC does not have it,
rem  installs the extras, makes shortcuts and starts the app.
rem ===========================================================================
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title Prahari - build setup exe

set "VER=1.33.0"
set "DIST=%CD%\dist"
set "STAGE=%DIST%\staging"
set "OUT=%DIST%\Prahari-Setup-%VER%.exe"

echo ============================================================
echo   Building Prahari-Setup.exe  (version %VER%)
echo ============================================================
echo.

where iexpress >nul 2>&1
if errorlevel 1 (
  echo   iexpress.exe was not found. It ships with Windows, so this is unusual.
  echo   Use build_exe.bat instead (single Prahari.exe via PyInstaller).
  pause
  exit /b 1
)

if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%STAGE%" >nul 2>&1

rem ---- 1. pack the application ------------------------------------------
echo   [1/4] Packing the application ...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$items = @('netscan','netsentinel.py','run.bat','README.md','requirements.txt'," ^
  " 'netsentinel.ico','dashboard_lan.bat','open_dashboard.bat','allow_firewall.bat'," ^
  " 'enable_rdp.bat','uninstall.cmd','screenshot.png');" ^
  "$have = $items | Where-Object { Test-Path $_ };" ^
  "Compress-Archive -Path $have -DestinationPath '%STAGE%\Prahari-app.zip' -Force"
if not exist "%STAGE%\Prahari-app.zip" (
  echo   Could not create the archive.
  pause
  exit /b 1
)

rem ---- 2. stage the bootstrap -------------------------------------------
echo   [2/4] Staging the installer files ...
copy /y "bootstrap.cmd" "%STAGE%\bootstrap.cmd" >nul
copy /y "netsentinel.ico" "%STAGE%\netsentinel.ico" >nul 2>&1

rem ---- 3. write the IExpress directive --------------------------------
echo   [3/4] Writing the installer directive ...
> "%STAGE%\setup.sed" (
  echo [Version]
  echo Class=IEXPRESS
  echo SEDVersion=3
  echo [Options]
  echo PackagePurpose=InstallApp
  echo ShowInstallProgramWindow=1
  echo HideExtractAnimation=0
  echo UseLongFileName=1
  echo InsideCompressed=0
  echo CAB_FixedSize=0
  echo CAB_ResvCodeSigning=0
  echo RebootMode=N
  echo InstallPrompt=
  echo DisplayLicense=
  echo FinishMessage=
  echo TargetName=%OUT%
  echo FriendlyName=Prahari %VER% setup
  echo AppLaunched=bootstrap.cmd
  echo PostInstallCmd=<None>
  echo AdminQuietInstCmd=
  echo UserQuietInstCmd=
  echo SourceFiles=SourceFiles
  echo [Strings]
  echo FILE0=Prahari-app.zip
  echo FILE1=bootstrap.cmd
  echo [SourceFiles]
  echo SourceFiles0=%STAGE%\
  echo [SourceFiles0]
  echo %%FILE0%%=
  echo %%FILE1%%=
)

rem ---- 4. build --------------------------------------------------------
echo   [4/4] Building the exe (a minute) ...
iexpress /N /Q "%STAGE%\setup.sed"
if exist "%OUT%" (
  echo.
  echo   Done:  %OUT%
  for %%F in ("%OUT%") do echo   Size:  %%~zF bytes
  echo.
  echo   Copy that single file to any Windows PC and run it. It will:
  echo     - unpack Prahari to %%LOCALAPPDATA%%\Prahari
  echo     - download and install Python silently only if it is missing
  echo     - install the optional extras, make shortcuts, start the app
  echo.
  echo   For the autostart task and firewall rule, right-click the setup and
  echo   choose "Run as administrator".
) else (
  echo.
  echo   IExpress did not produce the exe. Check the messages above.
)
pause
