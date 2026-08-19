@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo =========================================
echo   Dulcis POS - Full System Restore
echo =========================================
echo.
echo  This restores a full-system backup .zip created by
echo  backup_full_system.bat into a NEW folder next to this one,
echo  so it never overwrites your current live system by accident.
echo.

set "SOURCE_DIR=%~dp0..\Dulcis_Full_System_Backups"

if not exist "%SOURCE_DIR%" (
    echo  [ERROR] No backup folder found at:
    echo  %SOURCE_DIR%
    pause
    exit /b 1
)

echo  Available backups in %SOURCE_DIR%:
echo.
set /a i=0
for /f "delims=" %%F in ('dir /b /o-d "%SOURCE_DIR%\DulcisPOS_FullBackup_*.zip" 2^>nul') do (
    set /a i+=1
    set "file!i!=%%F"
    echo   !i!. %%F
)

if !i! EQU 0 (
    echo  No backup archives found.
    pause
    exit /b 1
)

echo.
set /p CHOICE="Enter the number of the backup to restore: "
set "SELECTED=!file%CHOICE%!"

if "!SELECTED!"=="" (
    echo  Invalid selection.
    pause
    exit /b 1
)

set "RESTORE_DEST=%~dp0..\Dulcis_POS_Restored_%CHOICE%"

echo.
echo  Restoring "!SELECTED!"
echo  into: %RESTORE_DEST%
echo.
set /p CONFIRM="Proceed? (Y/N): "
if /i not "!CONFIRM!"=="Y" (
    echo  Cancelled.
    pause
    exit /b 0
)

powershell -NoProfile -Command ^
  "Expand-Archive -Path '%SOURCE_DIR%\!SELECTED!' -DestinationPath '%RESTORE_DEST%' -Force"

echo.
echo =========================================
echo   Restore complete.
echo   Restored copy is at:
echo   %RESTORE_DEST%
echo.
echo   Review it, then replace your live project
echo   folder manually once you're satisfied.
echo =========================================
echo.
pause
