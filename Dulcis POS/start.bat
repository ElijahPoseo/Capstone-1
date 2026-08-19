@echo off
cd /d "%~dp0"

echo ===================================
echo  Dulcis POS — Starting up...
echo ===================================

REM Install / update dependencies silently
echo [1/3] Checking dependencies...
pip install -r requirements.txt -q --no-warn-script-location 2>nul

REM Check if pywin32 is available (for Windows printer support)
python -c "import win32print" 2>nul && (
    echo [2/3] Windows printer support: OK
) || (
    echo [2/3] Installing Windows printer support...
    pip install pywin32 -q 2>nul
)

echo [3/3] Starting POS server...
start pythonw app_complete.py

echo.
timeout /t 4 /nobreak >nul
start http://127.0.0.1:5000

echo.
echo  ✅  POS is running at http://127.0.0.1:5000
echo  🖨   Printer setup: http://127.0.0.1:5000/printer-settings
echo  👤  Login: admin / Admin@123!
echo.
echo  To stop: close the pythonw window in Task Manager
echo.
timeout /t 5 /nobreak >nul
exit
