@echo off
REM =============================================================
REM  CyberShield AI  -  serve.bat
REM  Double-click this file to start the local server and open
REM  the app in your browser. No installation needed.
REM  (This is just a wrapper for serve.ps1)
REM =============================================================
echo.
echo Starting CyberShield AI local server...
echo.
powershell -ExecutionPolicy Bypass -File "%~dp0serve.ps1"
pause
