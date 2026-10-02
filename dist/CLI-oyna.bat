@echo off
cd /d "%~dp0"
title blue-kit CLI
echo blue-kit CLI. Misollar:
echo   bk.exe kb validate T1070.001
echo   bk.exe logs analyze data\samples\practice\web_linux.csv --out r.html --json-out o.json
echo   bk.exe resp triage data\samples\practice\snapshot_linux.json --from-logs o.json
echo   bk.exe --help
echo.
cmd /k
