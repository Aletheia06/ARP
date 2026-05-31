@echo off
cd /d "%~dp0"

rem Restoring the ARP/NDP tables also needs admin rights.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Administrator rights required, requesting elevation...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

python net_control.py stop
pause
