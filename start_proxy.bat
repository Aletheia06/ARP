@echo off
cd /d "%~dp0"
python parent_proxy_control.py serve
pause
