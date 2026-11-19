@echo off
rem ===========================================================================
rem  Sign the build with your code-signing certificate.
rem
rem  An enterprise will not deploy unsigned executables, and SmartScreen blocks
rem  them. You need a code-signing certificate (OV or EV) issued to your company -
rem  that is a purchase, not a download.
rem
rem  Usage:
rem    set PFX=C:\certs\netsentinel.pfx
rem    set PFX_PASSWORD=yourpassword
rem    sign_build.bat
rem
rem  Signs: dist\NetSentinel.exe and dist\NetSentinel-Setup-*.exe
rem  Timestamping keeps the signature valid after the certificate expires.
rem ===========================================================================
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title NetSentinel - sign build

if "%PFX%"=="" (
  echo   Set PFX to the path of your .pfx code-signing certificate first, e.g.
  echo     set PFX=C:\certs\netsentinel.pfx
  echo     set PFX_PASSWORD=yourpassword
  echo     sign_build.bat
  pause
  exit /b 1
)
if not exist "%PFX%" (
  echo   Certificate not found: %PFX%
  pause
  exit /b 1
)

set "SIGNTOOL="
for /f "delims=" %%P in ('where signtool 2^>nul') do set "SIGNTOOL=%%P"
if "%SIGNTOOL%"=="" (
  for %%D in ("%ProgramFiles(x86)%\Windows Kits\10\bin" "%ProgramFiles%\Windows Kits\10\bin") do (
    if exist %%D for /f "delims=" %%P in ('dir /b /s "%%~D\signtool.exe" 2^>nul') do set "SIGNTOOL=%%P"
  )
)

echo ============================================================
echo   Signing the build
echo ============================================================
echo.

if "%SIGNTOOL%"=="" (
  echo   signtool.exe was not found ^(it ships with the Windows SDK^).
  echo   Falling back to PowerShell Authenticode signing ...
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$pw=ConvertTo-SecureString -String '%PFX_PASSWORD%' -PlainText -Force;" ^
    "$c=Get-PfxCertificate -FilePath '%PFX%';" ^
    "Get-ChildItem 'dist\*.exe' | ForEach-Object {" ^
    "  $s=Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $c " ^
    "     -TimestampServer 'http://timestamp.digicert.com';" ^
    "  Write-Host ('  ' + $_.Name + ' -> ' + $s.Status) }"
) else (
  echo   Using %SIGNTOOL%
  for %%F in (dist\*.exe) do (
    "%SIGNTOOL%" sign /fd SHA256 /f "%PFX%" /p "%PFX_PASSWORD%" ^
      /tr http://timestamp.digicert.com /td SHA256 "%%F"
    if errorlevel 1 (
      echo   FAILED to sign %%F
    ) else (
      echo   signed %%F
    )
  )
)

echo.
echo   Verifying ...
if not "%SIGNTOOL%"=="" (
  for %%F in (dist\*.exe) do "%SIGNTOOL%" verify /pa "%%F"
) else (
  powershell -NoProfile -Command "Get-ChildItem 'dist\*.exe' | ForEach-Object {" ^
    " $_.Name + ': ' + (Get-AuthenticodeSignature $_.FullName).Status }"
)
echo.
echo   Also run:  python sbom.py     (regenerates sbom.json for the security review)
pause
