@echo off
setlocal
cd /d "%~dp0"
set BK="%~dp0bk.exe"
set S=%~dp0data\samples

echo ============================================
echo   blue-kit -- yangi noutbukda tekshiruv
echo ============================================
echo.

set FAIL=0

echo [1/9] KB bazasi...
%BK% kb id T1548.003 >nul 2>&1
if errorlevel 1 (echo     XATO - kb.sqlite topilmadi yoki buzuq & set FAIL=1) else (echo     OK)

echo [2/9] ATT^&CK validatsiyasi...
%BK% kb validate T1053.003 >nul 2>&1
if errorlevel 1 (echo     XATO & set FAIL=1) else (echo     OK)

echo [3/9] Log analiz ^(namuna CSV^)...
%BK% logs analyze "%S%\win_phishing.csv" >nul 2>&1
if errorlevel 1 (echo     XATO & set FAIL=1) else (echo     OK)

echo [4/9] Shovqin filtri ^(noise.yaml bundle^)...
%BK% logs analyze "%S%\noise_check.log" 2>nul | findstr /C:"Noise suppressed" >nul
if errorlevel 1 (echo     XATO - noise.yaml exe ichiga kirmagan & set FAIL=1) else (echo     OK)

echo [5/9] Email skaner ^(brands.yaml bundle^)...
%BK% mail scan "%S%\mail\phish_sample.eml" 2>nul | findstr /C:"PHISHING" >nul
if errorlevel 1 (echo     XATO - brands.yaml exe ichiga kirmagan & set FAIL=1) else (echo     OK)

echo [6/9] Responder triage...
%BK% resp triage "%S%\resp\current_win.json" --baseline "%S%\resp\baseline_win.json" >nul 2>&1
if errorlevel 1 (echo     XATO & set FAIL=1) else (echo     OK)

echo [7/9] SIEM so'rov generatori ^(Sentinel jadval xaritasi^)...
%BK% siem query net-port-scan --siem sentinel 2>nul | findstr /C:"SourceIP" >nul
if errorlevel 1 (echo     XATO - siem moduli yo'q yoki maydon xaritasi buzuq & set FAIL=1) else (echo     OK)

echo [8/9] IR attack chain ^(modul bundle^)...
%BK% ir chain "%S%\win_phishing.csv" >nul 2>&1
if errorlevel 1 (echo     XATO - bluekit.ir exe ichiga kirmagan & set FAIL=1) else (echo     OK)

echo [9/9] C2 Hunt beacons ^(modul bundle^)...
%BK% hunt beacons "%S%\practice\web_linux.csv" >nul 2>&1
if errorlevel 1 (echo     XATO - bluekit.hunt exe ichiga kirmagan & set FAIL=1) else (echo     OK)

echo.
if "%FAIL%"=="1" (
  echo ============================================
  echo   NATIJA: XATOLAR BOR -- yuqoriga qarang
  echo ============================================
) else (
  echo ============================================
  echo   NATIJA: HAMMASI JOYIDA
  echo ============================================
)
echo.
echo Qolgan qo'lda tekshiruv: WEB-UI.bat ishga tushsin va brauzer ochilsin.
echo.
pause
