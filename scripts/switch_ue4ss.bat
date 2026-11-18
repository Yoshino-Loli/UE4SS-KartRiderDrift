@echo off
setlocal enabledelayedexpansion
rem ============================================================
rem  UE4SS version switcher
rem    cap  -> UE4SS 2.5.2  (stable, packet capture)
rem    mod  -> UE4SS 4.0.0  (patched build: bounds-check fix, Lua / SDK dump)
rem  Folders: ue4ss = active, ue4ss.other = inactive
rem ============================================================
set "HERE=%~dp0"
set "ACTIVE=%HERE%ue4ss"
set "OTHER=%HERE%ue4ss.other"

if /i "%~1"=="status" goto :status
if /i "%~1"=="cap"    set "WANT=2.5.2" & goto :switch
if /i "%~1"=="mod"    set "WANT=4.0.0" & goto :switch
goto :usage

:switch
tasklist /fi "imagename eq KartDrift-Win64-Shipping.exe" /nh 2>nul | "%SystemRoot%\System32\findstr.exe" /i "KartDrift" >nul
if not errorlevel 1 (
    echo [X] Game is running. Close it first.
    exit /b 1
)

set "CUR="
if exist "%ACTIVE%\.version" set /p CUR=<"%ACTIVE%\.version"
if not defined CUR (
    echo [X] Cannot detect current version ^(missing ue4ss\.version^)
    exit /b 1
)
if "%CUR%"=="%WANT%" (
    echo [=] Already on %WANT%
    exit /b 0
)

set "OTHERV="
if exist "%OTHER%\.version" set /p OTHERV=<"%OTHER%\.version"
if not "%OTHERV%"=="%WANT%" (
    echo [X] ue4ss.other is version "%OTHERV%", expected "%WANT%"
    echo     Rename folders manually or reinstall that version.
    exit /b 1
)

ren "%ACTIVE%" "ue4ss.swap"
if errorlevel 1 ( echo [X] rename active failed & exit /b 1 )
ren "%OTHER%"  "ue4ss"
if errorlevel 1 ( echo [X] rename other failed & ren "%HERE%ue4ss.swap" "ue4ss" & exit /b 1 )
ren "%HERE%ue4ss.swap" "ue4ss.other"
if errorlevel 1 ( echo [X] rename swap failed & exit /b 1 )

echo [OK] Switched: %CUR% -^> %WANT%
echo      Active folder now: ue4ss ^(v%WANT%^)
exit /b 0

:status
set "CUR=?"
if exist "%ACTIVE%\.version" set /p CUR=<"%ACTIVE%\.version"
set "OTHERV=?"
if exist "%OTHER%\.version" set /p OTHERV=<"%OTHER%\.version"
echo Active   ue4ss        = %CUR%
echo Inactive ue4ss.other  = %OTHERV%
if "%CUR%"=="2.5.2" echo Mode: cap  ^(stable, packet capture^)
if "%CUR%"=="4.0.0" echo Mode: mod  ^(patched build, Lua / SDK dump^)
exit /b 0

:usage
echo Usage: switch_ue4ss.bat [cap^|mod^|status]
echo   cap     UE4SS 2.5.2 - stable, for packet capture
echo   mod     UE4SS 4.0.0 - patched build, Lua / SDK dump
echo   status  show current mode
exit /b 1
