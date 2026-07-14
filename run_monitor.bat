@echo off
setlocal
set "PROJ=E:/cnskycn/Documents/agent-egress-monitor"
set "PY=E:/Users/cnskycn/.workbuddy/binaries/python/envs/default/Scripts/python.exe"
set "MODE=%~1"

if "%MODE%"=="selftest" (
    echo [SELFTEST] running self-test, no elevation needed
    cd /d "%PROJ%"
    "%PY%" cli/main.py selftest
    pause
    goto :eof
)

if "%MODE%"=="monitor" (
    if "%~2"=="--demo" (
        echo [DEMO] output preview only, no elevation
        cd /d "%PROJ%"
        "%PY%" cli/main.py monitor --demo
        pause
        goto :eof
    )
    goto :elevated
)

if "%MODE%"=="dashboard" goto :elevated
if "%MODE%"=="tray" goto :elevated
if "%MODE%"=="mitm" goto :elevated

echo Usage: run_monitor.bat [selftest ^| monitor ^| dashboard ^| tray ^| mitm] [options]
echo.
echo   selftest              Phase 0 self-test
echo   monitor               CLI live capture
echo   monitor --demo        Preview output format
echo   dashboard             Web UI dashboard (browser auto-opens)
echo   tray                  System tray icon (background, right-click menu)
echo   mitm                  MITM deep mode (canary+fp content scanning)
echo.
echo Options: --iface WLAN --only-proc codebuddy --known-only --to-file log
pause
goto :eof

:elevated
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] running %MODE% with administrator privileges
    cd /d "%PROJ%"
    "%PY%" cli/main.py %MODE% %2 %3 %4 %5 %6 %7 %8 %9
) else (
    echo [INFO] not administrator - requesting elevation for live capture...
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d ""%PROJ%"" && ""%PY%"" cli/main.py %MODE% %2 %3 %4 %5 %6 %7 %8 %9' -Verb RunAs"
)
endlocal
