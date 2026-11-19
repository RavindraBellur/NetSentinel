@echo off
setlocal
title Enable Remote Desktop on this PC

rem ---------------------------------------------------------------------------
rem  Run this ON THE PC YOU WANT TO CONTROL (not on the scanning PC), once,
rem  as Administrator. After this, Prahari's "Remote Desktop (RDP)" button
rem  can connect to it.
rem
rem  Requirements on this PC:
rem    * Windows Pro / Enterprise / Education (Home has no RDP server)
rem    * the account you log in with has a password
rem    * "Allow remote connections" in System properties
rem ---------------------------------------------------------------------------

net session >nul 2>&1
if errorlevel 1 (
  echo   This needs Administrator rights.
  echo   Right click this file and choose "Run as administrator".
  pause
  exit /b 1
)

echo   This will enable Remote Desktop on THIS PC:
echo     %COMPUTERNAME%
echo.

choice /c YN /m "Continue"
if errorlevel 2 goto :cancelled

echo   Allowing Remote Desktop connections ...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f >nul

echo   Requiring Network Level Authentication (safer) ...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f >nul

echo   Opening the firewall for Remote Desktop ...
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes >nul

echo   Adding %USERNAME% to the Remote Desktop Users group ...
net localgroup "Remote Desktop Users" "%USERNAME%" /add >nul 2>&1

echo.
echo   Done. This PC can now be controlled with Remote Desktop.
ipconfig | findstr /i "IPv4"
echo.
echo   Use that address in Prahari's remote panel, or run:  mstsc /v:THAT-IP
echo.
echo   Remember: the account needs a password, and both PCs must be on the
echo   same network (or connected by VPN).
pause
exit /b 0

:cancelled
echo   Nothing was changed.
pause
exit /b 1
