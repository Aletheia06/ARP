@echo off
cd /d "%~dp0"

rem Sending ARP/ICMPv6 scan packets needs admin rights (Npcap).
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Administrator rights required, requesting elevation...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

rem Shows the device list immediately, then type numbers to resolve names
rem on demand (phones included, via mDNS). The IPv6 column is filled automatically.
rem For an automatic full name resolve instead, use:  python scan.py --resolve-names
python scan.py --interactive
pause
