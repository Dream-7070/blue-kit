@echo off
cd /d "%~dp0"
title blue-kit web UI
echo ============================================
echo   blue-kit web UI ishga tushmoqda...
echo   Brauzer ochiladi: http://localhost:8000
echo.
echo   BU OYNANI YOPMANG - server shu yerda ishlaydi.
echo   To'xtatish: oynani yoping yoki Ctrl+C.
echo ============================================
echo.
start "" http://localhost:8000
bk.exe web
pause
