@echo off
rem sign.bat -- thin wrapper, real logic in sign.ps1
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sign.ps1" -Driver memkit_drv.sys
exit /b %errorlevel%
