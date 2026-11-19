@echo off
setlocal
title Prahari - remove autostart
schtasks /Delete /TN "Prahari" /F
schtasks /Delete /TN "NetSentinel" /F
echo.
echo   Autostart removed.
pause
