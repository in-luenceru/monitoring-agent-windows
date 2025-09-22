@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0MonitoringAgentControl.ps1" start
exit /b %ERRORLEVEL%