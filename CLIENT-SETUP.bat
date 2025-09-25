@echo off
REM =======================================
REM Monitoring Agent Client Setup Script
REM =======================================

echo.
echo =======================================
echo MONITORING AGENT CLIENT SETUP
echo =======================================
echo.
echo This script will configure automatic startup for your monitoring services.
echo.
pause

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Administrator privileges confirmed.
    echo.
) else (
    echo ERROR: This script must be run as Administrator.
    echo.
    echo Right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

REM Run the setup command
echo Configuring auto-startup...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0MonitoringAgentControl.ps1" setup

if %errorlevel% == 0 (
    echo.
    echo =======================================
    echo SETUP COMPLETED SUCCESSFULLY
    echo =======================================
    echo.
    echo Auto-startup has been configured successfully.
    echo Your monitoring services will start automatically after system restarts.
    echo.
) else (
    echo.
    echo =======================================
    echo SETUP FAILED
    echo =======================================
    echo.
    echo Please check the logs and try again.
    echo Make sure you are running as Administrator.
)

echo.
pause