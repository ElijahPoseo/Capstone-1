@echo off
cd /d "%~dp0"
start pythonw app_complete.py
echo.
echo ===================================
echo  Dulcis POS is starting...
echo ===================================
echo.
timeout /t 4 /nobreak >nul
start http://127.0.0.1:5000
echo ✅ Browser opened!
echo 👤 Login: admin / Admin@123!
echo.
echo Closing in 3 seconds...
timeout /t 3 /nobreak >nul
exit