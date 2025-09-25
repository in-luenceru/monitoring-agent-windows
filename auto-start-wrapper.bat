@echo off
cd /d "%~dp0"

REM Enhanced Auto-Start Wrapper for Monitoring Agent
REM Uses the new MonitoringAgentAutoStart.ps1 script for better reliability

REM Check if enhanced auto-start script exists
if exist "%~dp0MonitoringAgentAutoStart.ps1" (
    echo [INFO] Using enhanced auto-start script...
    pwsh -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0MonitoringAgentAutoStart.ps1" startup
) else (
    echo [WARN] Enhanced auto-start script not found, using fallback...
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0MonitoringAgentControl.ps1" start
)

exit /b %ERRORLEVEL%