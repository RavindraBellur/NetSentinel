@echo off
setlocal
title NetSentinel - remove autostart
schtasks /Delete /TN "NetSentinel" /F
echo.
echo   Autostart removed.
pause
