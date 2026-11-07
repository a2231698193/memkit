@echo off
rem install.bat -- register and start the driver (requires admin + testsigning)
rem
rem Preconditions:
rem   1. Run as Administrator
rem   2. bcdedit /set testsigning on  + reboot  (for unsigned/dev-signed drivers)
rem   3. memkit_drv.sys in this directory, signed with a cert in the trust store
rem
rem NOTE: The service name "MemkitDrv" and the device name read from
rem       Parameters\DeviceName must match what the user-mode side expects.
setlocal

if not exist memkit_drv.sys goto no_sys

echo [1/4] copy driver to System32\drivers
copy /y memkit_drv.sys "%SystemRoot%\System32\drivers\memkit_drv.sys" >nul
if errorlevel 1 goto copy_fail

echo [2/4] create service
sc create MemkitDrv type= kernel start= demand ^
   binPath= "%SystemRoot%\System32\drivers\memkit_drv.sys" DisplayName= "MemkitDrv"
if errorlevel 1 (
  sc query MemkitDrv >nul 2>&1
  if errorlevel 1 goto svc_fail
  echo       service already exists, continuing
)

echo [3/4] set random device name
py -3 -c "import secrets,string;print(''.join(secrets.choice(string.ascii_lowercase+string.digits) for _ in range(12)))" > "%TEMP%\wvm_name.txt"
set /p DEVNAME=<"%TEMP%\wvm_name.txt"
del "%TEMP%\wvm_name.txt"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MemkitDrv\Parameters" /v DeviceName /t REG_SZ /d "%DEVNAME%" /f >nul
if errorlevel 1 goto reg_fail

echo [4/4] start service
sc start MemkitDrv
if errorlevel 1 goto start_fail

echo.
echo [OK] driver loaded. Device name: %DEVNAME%
echo      user-mode must use: \.\Global\%DEVNAME%_DRV
exit /b 0

:no_sys
echo [ERR] memkit_drv.sys not found
exit /b 1
:copy_fail
echo [ERR] copy failed
exit /b 1
:svc_fail
echo [ERR] sc create failed
exit /b 1
:reg_fail
echo [ERR] registry write failed
exit /b 1
:start_fail
echo [ERR] sc start failed -- check testsigning is on and signature is valid
exit /b 1
