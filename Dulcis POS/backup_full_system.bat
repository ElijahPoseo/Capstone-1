@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo =========================================
echo   Dulcis POS - Full System Backup
echo =========================================
echo.

REM ── Configuration ──────────────────────────────────────────────
REM Where full backups are stored (one level above the project, like the DB backups)
set "DEST_DIR=%~dp0..\Dulcis_Full_System_Backups"
REM How many full backups to keep (older ones auto-deleted)
set "MAX_BACKUPS=14"

if not exist "%DEST_DIR%" mkdir "%DEST_DIR%"

REM ── Build timestamp: YYYY-MM-DD_HHMM ───────────────────────────
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set "dt=%%I"
set "STAMP=%dt:~0,4%-%dt:~4,2%-%dt:~6,2%_%dt:~8,2%%dt:~10,2%"

set "ARCHIVE_NAME=DulcisPOS_FullBackup_%STAMP%.zip"
set "ARCHIVE_PATH=%DEST_DIR%\%ARCHIVE_NAME%"

echo [1/3] Compressing project folder...
echo       (this may take a moment)

REM Zip everything in this folder EXCEPT __pycache__ (disposable cache)
powershell -NoProfile -Command ^
  "$src = '%~dp0'; " ^
  "$dest = '%ARCHIVE_PATH%'; " ^
  "$items = Get-ChildItem -Path $src -Force | Where-Object { $_.Name -ne '__pycache__' }; " ^
  "Compress-Archive -Path $items.FullName -DestinationPath $dest -Force"

if not exist "%ARCHIVE_PATH%" (
    echo.
    echo  [ERROR] Backup failed - archive was not created.
    pause
    exit /b 1
)

echo [2/3] Backup saved:
echo       %ARCHIVE_PATH%

echo [3/3] Cleaning up old backups (keeping newest %MAX_BACKUPS%)...
powershell -NoProfile -Command ^
  "$files = Get-ChildItem -Path '%DEST_DIR%' -Filter 'DulcisPOS_FullBackup_*.zip' | Sort-Object LastWriteTime -Descending; " ^
  "if ($files.Count -gt %MAX_BACKUPS%) { $files | Select-Object -Skip %MAX_BACKUPS% | Remove-Item -Force }"

echo.
echo =========================================
echo   Full system backup complete.
echo =========================================
echo.
pause
