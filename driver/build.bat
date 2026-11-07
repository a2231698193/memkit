@echo off
rem build.bat -- kernel driver build (no vcvars dependency)
rem
rem NOTE: paths contain "(x86)". cmd breaks on parentheses inside
rem "if (...)" blocks, so this script uses goto instead of blocks.
setlocal

set "MSVC_VER=14.44.35207"
set "WDK_VER=10.0.26100.0"
set "MSVC=D:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\%MSVC_VER%"
set "WDK=C:\Program Files (x86)\Windows Kits\10"

if not exist "%MSVC%\bin\HostX64\x64\cl.exe" goto no_cl
if not exist "%WDK%\Include\%WDK_VER%\km\ntddk.h" goto no_wdk
goto build

:no_cl
echo [ERR] cl.exe not found under MSVC dir
exit /b 1

:no_wdk
echo [ERR] WDK km headers not found
exit /b 1

:build
set "PATH=%MSVC%\bin\HostX64\x64;%PATH%"
set "INCLUDE=%MSVC%\include;%WDK%\Include\%WDK_VER%\km;%WDK%\Include\%WDK_VER%\shared;%WDK%\Include\%WDK_VER%\ucrt"
set "LIB=%MSVC%\lib\x64;%WDK%\Lib\%WDK_VER%\km\x64;%WDK%\Lib\%WDK_VER%\um\x64"

cl /nologo /c /utf-8 /W4 /O2 /GS- /GR- /Zl ^
   /D_AMD64_ /D_WIN64 /DNT /D_WIN32_WINNT=0x0A00 ^
   memkit_drv.c /Fomemkit_drv.obj
if errorlevel 1 goto fail

link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:GsDriverEntry ^
     /MACHINE:X64 /NODEFAULTLIB /OPT:REF /OPT:ICF ^
     /OUT:memkit_drv.sys memkit_drv.obj ^
     ntoskrnl.lib hal.lib wdmsec.lib BufferOverflowK.lib
if errorlevel 1 goto fail

rem Strip build artifacts that leak toolchain identity:
rem   * Rich header (MSVC ????? + ??????)

py -3 "%~dp0/../tools/strip_pe.py" memkit_drv.sys
if errorlevel 1 goto fail

rem ORDER MATTERS: strip runs BEFORE sign. Signing appends a certificate blob
rem and hashes the whole file; mutating bytes afterwards voids the signature.
rem Signing is opt-in via MEMKIT_SIGN=1 (CI sets it).
if not "%MEMKIT_SIGN%"=="1" goto skip_sign
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sign.ps1" -Driver memkit_drv.sys
if errorlevel 1 goto fail

:skip_sign
echo [OK] memkit_drv.sys
exit /b 0

:fail
echo [ERR] build failed
exit /b 1
