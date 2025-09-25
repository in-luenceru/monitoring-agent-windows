#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Monitoring Agent Service Manager
    
.DESCRIPTION
    Comprehensive service management for the Monitoring Agent.
    Handles Windows service installation, configuration, and management
    for auto-startup scenarios including system restart, shutdown, and sleep/wake.
    
.AUTHOR
    Custom Security Solutions
    
.VERSION
    1.0.0
    
.NOTES
    Requires Administrator privileges
    Uses NSSM (Non-Sucking Service Manager) for robust service management
#>

# Script Configuration
$Script:AgentPath = $PSScriptRoot
$Script:ServiceName = "MonitoringAgentWatchdog"
$Script:ServiceDisplayName = "Monitoring Agent Watchdog"
$Script:ServiceDescription = "Automatically restarts the Monitoring Agent when it stops unexpectedly. Ensures continuous monitoring after system restart, shutdown, or sleep/wake events."
$Script:WatchdogScript = Join-Path $AgentPath "MonitoringAgentWatchdog.ps1"
$Script:NssmExe = Join-Path $AgentPath "nssm.exe"
$Script:LogFile = Join-Path $AgentPath "logs\service-manager.log"

# Ensure logs directory exists
$LogDir = Split-Path $Script:LogFile -Parent
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Logging function
function Write-ServiceLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    try {
        Add-Content -Path $Script:LogFile -Value $logEntry -Encoding UTF8
        
        # Color coding for console output
        $color = switch ($Level) {
            "SUCCESS" { "Green" }
            "WARN" { "Yellow" }
            "ERROR" { "Red" }
            default { "White" }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
    catch {
        Write-Host "Failed to write to log: $_" -ForegroundColor Red
    }
}

# Check if running as administrator
function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check if NSSM is available
function Test-NssmAvailable {
    if (Test-Path $Script:NssmExe) {
        return $true
    }
    
    Write-ServiceLog "NSSM not found at: $Script:NssmExe" "ERROR"
    Write-ServiceLog "Please ensure nssm.exe is in the agent directory" "ERROR"
    return $false
}

# Get service status
function Get-ServiceStatus {
    try {
        $service = Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            return @{
                Exists = $true
                Status = $service.Status
                StartType = $service.StartType
                DisplayName = $service.DisplayName
            }
        }
        else {
            return @{
                Exists = $false
                Status = "NotInstalled"
                StartType = "Unknown"
                DisplayName = "Not Installed"
            }
        }
    }
    catch {
        Write-ServiceLog "Error checking service status: $_" "ERROR"
        return @{
            Exists = $false
            Status = "Error"
            StartType = "Unknown"
            DisplayName = "Error"
        }
    }
}

# Install the service
function Install-MonitoringService {
    Write-ServiceLog "Installing Monitoring Agent Service..." "INFO"
    
    if (!(Test-NssmAvailable)) {
        return $false
    }
    
    try {
        # Check if service already exists
        $serviceStatus = Get-ServiceStatus
        if ($serviceStatus.Exists) {
            Write-ServiceLog "Service already exists. Use 'Reinstall-MonitoringService' to reinstall." "WARN"
            return $false
        }
        
        # Install service using NSSM
        Write-ServiceLog "Creating service with NSSM..." "INFO"
        $installArgs = @(
            "install",
            $Script:ServiceName,
            "powershell.exe",
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$Script:WatchdogScript`""
        )
        
        $result = & $Script:NssmExe $installArgs
        if ($LASTEXITCODE -ne 0) {
            Write-ServiceLog "NSSM install failed with exit code: $LASTEXITCODE" "ERROR"
            return $false
        }
        
        # Configure service settings
        Write-ServiceLog "Configuring service settings..." "INFO"
        
        # Set service description
        & $Script:NssmExe "set" $Script:ServiceName "Description" $Script:ServiceDescription
        
        # Set service display name
        & $Script:NssmExe "set" $Script:ServiceName "DisplayName" $Script:ServiceDisplayName
        
        # Set startup type to automatic
        & $Script:NssmExe "set" $Script:ServiceName "Start" "SERVICE_AUTO_START"
        
        # Set recovery actions
        & $Script:NssmExe "set" $Script:ServiceName "AppRestartDelay" "5000"  # 5 seconds
        & $Script:NssmExe "set" $Script:ServiceName "AppExit" "Default" "Restart"
        
        # Set working directory
        & $Script:NssmExe "set" $Script:ServiceName "AppDirectory" $Script:AgentPath
        
        # Configure logging
        $serviceLogDir = Join-Path $Script:AgentPath "logs"
        if (!(Test-Path $serviceLogDir)) {
            New-Item -ItemType Directory -Path $serviceLogDir -Force | Out-Null
        }
        
        $stdoutLog = Join-Path $serviceLogDir "service-stdout.log"
        $stderrLog = Join-Path $serviceLogDir "service-stderr.log"
        
        & $Script:NssmExe "set" $Script:ServiceName "AppStdout" $stdoutLog
        & $Script:NssmExe "set" $Script:ServiceName "AppStderr" $stderrLog
        & $Script:NssmExe "set" $Script:ServiceName "AppRotateFiles" "1"
        & $Script:NssmExe "set" $Script:ServiceName "AppRotateOnline" "1"
        & $Script:NssmExe "set" $Script:ServiceName "AppRotateSeconds" "86400"  # Rotate daily
        & $Script:NssmExe "set" $Script:ServiceName "AppRotateBytes" "10485760"  # 10MB
        
        Write-ServiceLog "Service installed successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-ServiceLog "Error installing service: $_" "ERROR"
        return $false
    }
}

# Uninstall the service
function Uninstall-MonitoringService {
    Write-ServiceLog "Uninstalling Monitoring Agent Service..." "INFO"
    
    if (!(Test-NssmAvailable)) {
        return $false
    }
    
    try {
        # Check if service exists
        $serviceStatus = Get-ServiceStatus
        if (!$serviceStatus.Exists) {
            Write-ServiceLog "Service is not installed" "WARN"
            return $true
        }
        
        # Stop service if running
        if ($serviceStatus.Status -eq "Running") {
            Write-ServiceLog "Stopping service before uninstall..." "INFO"
            Stop-MonitoringService | Out-Null
            Start-Sleep -Seconds 5
        }
        
        # Remove service
        $result = & $Script:NssmExe "remove" $Script:ServiceName "confirm"
        if ($LASTEXITCODE -ne 0) {
            Write-ServiceLog "NSSM uninstall failed with exit code: $LASTEXITCODE" "ERROR"
            return $false
        }
        
        Write-ServiceLog "Service uninstalled successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-ServiceLog "Error uninstalling service: $_" "ERROR"
        return $false
    }
}

# Start the service
function Start-MonitoringService {
    Write-ServiceLog "Starting Monitoring Agent Service..." "INFO"
    
    try {
        $serviceStatus = Get-ServiceStatus
        if (!$serviceStatus.Exists) {
            Write-ServiceLog "Service is not installed. Install it first." "ERROR"
            return $false
        }
        
        if ($serviceStatus.Status -eq "Running") {
            Write-ServiceLog "Service is already running" "INFO"
            return $true
        }
        
        Start-Service -Name $Script:ServiceName
        Start-Sleep -Seconds 3
        
        $newStatus = Get-ServiceStatus
        if ($newStatus.Status -eq "Running") {
            Write-ServiceLog "Service started successfully" "SUCCESS"
            return $true
        }
        else {
            Write-ServiceLog "Service failed to start (Status: $($newStatus.Status))" "ERROR"
            return $false
        }
    }
    catch {
        Write-ServiceLog "Error starting service: $_" "ERROR"
        return $false
    }
}

# Stop the service
function Stop-MonitoringService {
    Write-ServiceLog "Stopping Monitoring Agent Service..." "INFO"
    
    try {
        $serviceStatus = Get-ServiceStatus
        if (!$serviceStatus.Exists) {
            Write-ServiceLog "Service is not installed" "WARN"
            return $true
        }
        
        if ($serviceStatus.Status -eq "Stopped") {
            Write-ServiceLog "Service is already stopped" "INFO"
            return $true
        }
        
        Stop-Service -Name $Script:ServiceName -Force
        Start-Sleep -Seconds 3
        
        $newStatus = Get-ServiceStatus
        if ($newStatus.Status -eq "Stopped") {
            Write-ServiceLog "Service stopped successfully" "SUCCESS"
            return $true
        }
        else {
            Write-ServiceLog "Service failed to stop (Status: $($newStatus.Status))" "ERROR"
            return $false
        }
    }
    catch {
        Write-ServiceLog "Error stopping service: $_" "ERROR"
        return $false
    }
}

# Restart the service
function Restart-MonitoringService {
    Write-ServiceLog "Restarting Monitoring Agent Service..." "INFO"
    
    if (Stop-MonitoringService) {
        Start-Sleep -Seconds 2
        return Start-MonitoringService
    }
    return $false
}

# Reinstall the service (uninstall + install)
function Reinstall-MonitoringService {
    Write-ServiceLog "Reinstalling Monitoring Agent Service..." "INFO"
    
    if (Uninstall-MonitoringService) {
        Start-Sleep -Seconds 2
        return Install-MonitoringService
    }
    return $false
}

# Show service status
function Show-ServiceStatus {
    $serviceStatus = Get-ServiceStatus
    
    Write-Host "`n=== MONITORING AGENT SERVICE STATUS ===" -ForegroundColor Cyan
    Write-Host "Service Name: $Script:ServiceName" -ForegroundColor White
    Write-Host "Display Name: $($serviceStatus.DisplayName)" -ForegroundColor White
    Write-Host "Status: $($serviceStatus.Status)" -ForegroundColor $(if ($serviceStatus.Status -eq "Running") { "Green" } elseif ($serviceStatus.Status -eq "Stopped") { "Yellow" } else { "Red" })
    Write-Host "Start Type: $($serviceStatus.StartType)" -ForegroundColor White
    Write-Host "Installed: $($serviceStatus.Exists)" -ForegroundColor $(if ($serviceStatus.Exists) { "Green" } else { "Red" })
    
    if ($serviceStatus.Exists) {
        try {
            $service = Get-Service -Name $Script:ServiceName
            Write-Host "Can Stop: $($service.CanStop)" -ForegroundColor White
            Write-Host "Can Shutdown: $($service.CanShutdown)" -ForegroundColor White
        }
        catch {
            Write-ServiceLog "Error getting extended service info: $_" "WARN"
        }
    }
    
    # Check if watchdog script exists
    Write-Host "`n=== WATCHDOG SCRIPT STATUS ===" -ForegroundColor Cyan
    Write-Host "Script Path: $Script:WatchdogScript" -ForegroundColor White
    Write-Host "Script Exists: $(Test-Path $Script:WatchdogScript)" -ForegroundColor $(if (Test-Path $Script:WatchdogScript) { "Green" } else { "Red" })
    
    # Check if NSSM exists
    Write-Host "`n=== NSSM STATUS ===" -ForegroundColor Cyan
    Write-Host "NSSM Path: $Script:NssmExe" -ForegroundColor White
    Write-Host "NSSM Available: $(Test-Path $Script:NssmExe)" -ForegroundColor $(if (Test-Path $Script:NssmExe) { "Green" } else { "Red" })
    
    Write-Host ""
}

# Interactive menu
function Show-ServiceMenu {
    while ($true) {
        Clear-Host
        Write-Host "=== MONITORING AGENT SERVICE MANAGER ===" -ForegroundColor Cyan
        Write-Host "Agent Path: $Script:AgentPath" -ForegroundColor Gray
        Write-Host ""
        
        Show-ServiceStatus
        
        Write-Host "=== AVAILABLE ACTIONS ===" -ForegroundColor Cyan
        Write-Host "1. Install Service (Auto-startup)" -ForegroundColor White
        Write-Host "2. Uninstall Service" -ForegroundColor White
        Write-Host "3. Start Service" -ForegroundColor White
        Write-Host "4. Stop Service" -ForegroundColor White
        Write-Host "5. Restart Service" -ForegroundColor White
        Write-Host "6. Reinstall Service" -ForegroundColor White
        Write-Host "7. Refresh Status" -ForegroundColor White
        Write-Host "8. Show Service Logs" -ForegroundColor White
        Write-Host "9. Exit" -ForegroundColor White
        Write-Host ""
        
        $choice = Read-Host "Select option (1-9)"
        
        switch ($choice) {
            "1" {
                Install-MonitoringService | Out-Null
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "2" {
                Write-Host "`nAre you sure you want to uninstall the service? (y/N): " -ForegroundColor Yellow -NoNewline
                $confirm = Read-Host
                if ($confirm -eq "y" -or $confirm -eq "Y") {
                    Uninstall-MonitoringService | Out-Null
                }
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "3" {
                Start-MonitoringService | Out-Null
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "4" {
                Stop-MonitoringService | Out-Null
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "5" {
                Restart-MonitoringService | Out-Null
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "6" {
                Write-Host "`nAre you sure you want to reinstall the service? (y/N): " -ForegroundColor Yellow -NoNewline
                $confirm = Read-Host
                if ($confirm -eq "y" -or $confirm -eq "Y") {
                    Reinstall-MonitoringService | Out-Null
                }
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "7" {
                # Just refresh - the loop will show updated status
            }
            "8" {
                Show-ServiceLogs
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "9" {
                Write-ServiceLog "Service Manager exiting" "INFO"
                exit 0
            }
            default {
                Write-Host "`nInvalid option. Please select 1-9." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    }
}

# Show service logs
function Show-ServiceLogs {
    Clear-Host
    Write-Host "=== SERVICE LOGS ===" -ForegroundColor Cyan
    
    $logsToShow = @(
        @{ Name = "Service Manager Log"; Path = $Script:LogFile },
        @{ Name = "Watchdog Log"; Path = (Join-Path $Script:AgentPath "watchdog.log") },
        @{ Name = "Service STDOUT"; Path = (Join-Path $Script:AgentPath "logs\service-stdout.log") },
        @{ Name = "Service STDERR"; Path = (Join-Path $Script:AgentPath "logs\service-stderr.log") }
    )
    
    foreach ($log in $logsToShow) {
        Write-Host "`n--- $($log.Name) ---" -ForegroundColor Yellow
        if (Test-Path $log.Path) {
            try {
                $content = Get-Content $log.Path -Tail 10 -ErrorAction SilentlyContinue
                if ($content) {
                    $content | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
                }
                else {
                    Write-Host "Log file is empty" -ForegroundColor Gray
                }
            }
            catch {
                Write-Host "Error reading log: $_" -ForegroundColor Red
            }
        }
        else {
            Write-Host "Log file not found: $($log.Path)" -ForegroundColor Red
        }
    }
}

# Main execution
function Main {
    # Check admin rights
    if (!(Test-AdminRights)) {
        Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
        Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
        exit 1
    }
    
    Write-ServiceLog "Monitoring Agent Service Manager started" "INFO"
    
    # Handle command line arguments
    if ($args.Count -gt 0) {
        switch ($args[0].ToLower()) {
            "install" {
                if (Install-MonitoringService) { exit 0 } else { exit 1 }
            }
            "uninstall" {
                if (Uninstall-MonitoringService) { exit 0 } else { exit 1 }
            }
            "start" {
                if (Start-MonitoringService) { exit 0 } else { exit 1 }
            }
            "stop" {
                if (Stop-MonitoringService) { exit 0 } else { exit 1 }
            }
            "restart" {
                if (Restart-MonitoringService) { exit 0 } else { exit 1 }
            }
            "reinstall" {
                if (Reinstall-MonitoringService) { exit 0 } else { exit 1 }
            }
            "status" {
                Show-ServiceStatus
                exit 0
            }
            default {
                Write-Host "Usage: .\MonitoringAgentServiceManager.ps1 [install|uninstall|start|stop|restart|reinstall|status]" -ForegroundColor Yellow
                Write-Host "  install     - Install the service for auto-startup" -ForegroundColor Gray
                Write-Host "  uninstall   - Remove the service" -ForegroundColor Gray
                Write-Host "  start       - Start the service" -ForegroundColor Gray
                Write-Host "  stop        - Stop the service" -ForegroundColor Gray
                Write-Host "  restart     - Restart the service" -ForegroundColor Gray
                Write-Host "  reinstall   - Reinstall the service" -ForegroundColor Gray
                Write-Host "  status      - Show service status" -ForegroundColor Gray
                Write-Host "Or run without parameters for interactive mode." -ForegroundColor Gray
                exit 1
            }
        }
    }
    else {
        # Start interactive menu
        Show-ServiceMenu
    }
}

# Execute main function
Main @args