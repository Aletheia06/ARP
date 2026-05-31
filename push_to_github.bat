@echo off
cd /d "%~dp0"
git status --short
git add .
git commit -m "Update project"
git push -u origin main
pause
