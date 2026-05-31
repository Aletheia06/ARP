@echo off
cd /d "%~dp0"

rem Sending ARP/NDP needs admin rights; if not elevated, relaunch via UAC.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Administrator rights required, requesting elevation...
    if "%~1"=="" (
        powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    ) else (
        powershell -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    )
    exit /b
)

rem Usage: double-click = limit the default device from config.
rem        limit.bat 192.168.31.38 = limit that specific IP.
python net_control.py start %*
pause
