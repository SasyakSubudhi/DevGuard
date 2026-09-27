@echo off
setlocal
cd /d "%~dp0"
python monitor_regression.py %*
exit /b %errorlevel%
