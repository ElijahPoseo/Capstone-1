@echo off
title Dulcis POS - Stopping
color 0C

echo.
echo  =========================================
echo    DULCIS ^& CAFE — Stopping POS System
echo  =========================================
echo.

echo  Stopping POS server...
taskkill /IM pythonw.exe /F >nul 2>&1
taskkill /IM python.exe /F >nul 2>&1

timeout /t 1 /nobreak >nul

echo  Freeing port 5000...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5000 ^| findstr LISTENING 2^>nul') do (
    taskkill /PID %%a /F >nul 2>&1
)

echo.
echo  =========================================
echo    POS Stopped. Port 5000 is now free.
echo  =========================================
echo.
pause
