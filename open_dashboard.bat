@echo off
setlocal
title NetSentinel - open dashboard

rem Opens the dashboard in your default browser. Use this if you closed the
rem window but NetSentinel is still running in its console window.

start "" "http://127.0.0.1:8777/"
echo   Opening http://127.0.0.1:8777/
echo.
echo   If the page does not load, NetSentinel is not running - start it with
echo   run.bat (this PC only) or dashboard_lan.bat (whole network).
timeout /t 4 >nul
