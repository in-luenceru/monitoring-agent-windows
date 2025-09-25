#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Monitoring Agent Auto-Startup Setup
    
.DESCRIPTION
    Complete setup script for configuring the Monitoring Agent with auto-startup capabilities.
    Handles service installation, configuration, and verification for reliable startup after
    system restart, shutdown, or sleep/wake scenarios.
    
.AUTHOR
    Custom Security Solutions
    
.VERSION
    1.0.0
    
.NOTES
    Requires Administrator privileges
    One-time setup script for auto-startup configuration
#>

# Script Configuration
$Script:AgentPath = $PSScriptRoot
$Script:ServiceManager = Join-Path $AgentPath "MonitoringAgentServiceManager.ps1"
$Script:AgentControl = Join-Path $AgentPath "MonitoringAgentControl.ps1"
$Script:WatchdogScript = Join-Path $AgentPath "MonitoringAgentWatchdog.ps1"
$Script:SetupLog = Join-Path $AgentPath "logs\auto-startup-setup.log"

# Ensure logs directory exists
$LogDir = Split-Path $Script:SetupLog -Parent
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Logging function
function Write-SetupLog {
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
        Add-Content -Path $Script:SetupLog -Value $logEntry -Encoding UTF8
        
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

# Check prerequisites
function Test-Prerequisites {
    Write-SetupLog "Checking prerequisites..." "INFO"
    
    $issues = @()
    
    # Check if agent executable exists
    $agentExe = Join-Path $Script:AgentPath "monitoring-agent.exe"
    if (!(Test-Path $agentExe)) {
        $issues += "Missing monitoring-agent.exe"
    }
    
    # Check if configuration exists
    $configFile = Join-Path $Script:AgentPath "ossec.conf"
    if (!(Test-Path $configFile)) {
        $issues += "Missing ossec.conf configuration file"
    }
    
    # Check if NSSM exists
    $nssmExe = Join-Path $Script:AgentPath "nssm.exe"
    if (!(Test-Path $nssmExe)) {
        $issues += "Missing nssm.exe (required for service management)"
    }
    
    # Check if required scripts exist
    $requiredScripts = @($Script:AgentControl, $Script:ServiceManager, $Script:WatchdogScript)
    foreach ($script in $requiredScripts) {
        if (!(Test-Path $script)) {
            $issues += "Missing script: $(Split-Path $script -Leaf)"
        }
    }
    
    if ($issues.Count -gt 0) {
        Write-SetupLog "Prerequisites check failed:" "ERROR"
        foreach ($issue in $issues) {
            Write-SetupLog "  - $issue" "ERROR"
        }
        return $false
    }
    
    Write-SetupLog "All prerequisites satisfied" "SUCCESS"
    return $true
}

# Test agent configuration
function Test-AgentConfiguration {
    Write-SetupLog "Testing agent configuration..." "INFO"
    
    try {
        $configFile = Join-Path $Script:AgentPath "ossec.conf"
        $configContent = Get-Content $configFile -Raw
        
        # Check for client configuration
        if ($configContent -match '<client>[\s\S]*<server>[\s\S]*<address>([^<]+)</address>') {
            $serverAddress = $matches[1].Trim()
            if ($serverAddress -eq "127.0.0.1" -or $serverAddress -eq "localhost") {
                Write-SetupLog "Warning: Agent configured for localhost. Ensure this is correct." "WARN"
            }
            else {
                Write-SetupLog "Agent configured for server: $serverAddress" "INFO"
            }
        }
        else {
            Write-SetupLog "Warning: No server configuration found in ossec.conf" "WARN"
        }
        
        # Check for client keys
        $clientKeys = Join-Path $Script:AgentPath "client.keys"
        if (Test-Path $clientKeys) {
            $keyContent = Get-Content $clientKeys -ErrorAction SilentlyContinue
            if ($keyContent -and $keyContent.Trim() -ne "") {
                Write-SetupLog "Client keys file exists and has content" "SUCCESS"
            }
            else {
                Write-SetupLog "Warning: Client keys file is empty" "WARN"
            }
        }
        else {
            Write-SetupLog "Warning: Client keys file not found" "WARN"
        }
        
        return $true
    }
    catch {
        Write-SetupLog "Error testing agent configuration: $_" "ERROR"
        return $false
    }
}

# Setup auto-startup service
function Setup-AutoStartupService {
    Write-SetupLog "Setting up auto-startup service..." "INFO"
    
    try {
        # First, stop any existing service
        Write-SetupLog "Checking for existing service..." "INFO"
        $result = & $Script:ServiceManager "status"
        
        # Install/reinstall the service
        Write-SetupLog "Installing monitoring agent service..." "INFO"
        $installResult = & $Script:ServiceManager "install"
        if ($LASTEXITCODE -ne 0) {
            Write-SetupLog "Service installation failed" "ERROR"
            return $false
        }
        
        # Start the service
        Write-SetupLog "Starting monitoring agent service..." "INFO"
        $startResult = & $Script:ServiceManager "start"
        if ($LASTEXITCODE -ne 0) {
            Write-SetupLog "Service start failed" "ERROR"
            return $false
        }
        
        Write-SetupLog "Auto-startup service configured successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-SetupLog "Error setting up auto-startup service: $_" "ERROR"
        return $false
    }
}

# Verify setup
function Test-AutoStartupSetup {
    Write-SetupLog "Verifying auto-startup setup..." "INFO"
    
    try {
        # Check service status
        $service = Get-Service -Name "MonitoringAgentWatchdog" -ErrorAction SilentlyContinue
        if (!$service) {
            Write-SetupLog "Service not found" "ERROR"
            return $false
        }
        
        if ($service.Status -ne "Running") {
            Write-SetupLog "Service is not running (Status: $($service.Status))" "ERROR"
            return $false
        }
        
        if ($service.StartType -ne "Automatic") {
            Write-SetupLog "Service is not set to automatic start (StartType: $($service.StartType))" "ERROR"
            return $false
        }
        
        Write-SetupLog "Service verification successful" "SUCCESS"
        Write-SetupLog "  - Status: $($service.Status)" "INFO"
        Write-SetupLog "  - Start Type: $($service.StartType)" "INFO"
        Write-SetupLog "  - Display Name: $($service.DisplayName)" "INFO"
        
        # Test agent process
        Write-SetupLog "Checking if monitoring agent process is running..." "INFO"
        $agentProcess = Get-Process -Name "monitoring-agent" -ErrorAction SilentlyContinue
        if ($agentProcess) {
            Write-SetupLog "Monitoring agent process is running (PID: $($agentProcess[0].Id))" "SUCCESS"
        }
        else {
            Write-SetupLog "Monitoring agent process not found - may be starting up" "WARN"
        }
        
        return $true
    }
    catch {
        Write-SetupLog "Error verifying setup: $_" "ERROR"
        return $false
    }
}

# Show final status and instructions
function Show-SetupResults {
    Write-Host "`n" + "="*70 -ForegroundColor Cyan
    Write-Host "MONITORING AGENT AUTO-STARTUP SETUP COMPLETE" -ForegroundColor Cyan
    Write-Host "="*70 -ForegroundColor Cyan
    
    # Service status
    try {
        $service = Get-Service -Name "MonitoringAgentWatchdog" -ErrorAction SilentlyContinue
        if ($service) {
            Write-Host "`nSERVICE STATUS:" -ForegroundColor Yellow
            Write-Host "  Name: $($service.Name)" -ForegroundColor White
            Write-Host "  Display Name: $($service.DisplayName)" -ForegroundColor White
            Write-Host "  Status: $($service.Status)" -ForegroundColor $(if ($service.Status -eq "Running") { "Green" } else { "Red" })
            Write-Host "  Start Type: $($service.StartType)" -ForegroundColor White
        }
    }
    catch {
        Write-Host "`nService status unavailable" -ForegroundColor Red
    }
    
    # Agent process status
    try {
        $agentProcess = Get-Process -Name "monitoring-agent" -ErrorAction SilentlyContinue
        Write-Host "`nAGENT PROCESS STATUS:" -ForegroundColor Yellow
        if ($agentProcess) {
            Write-Host "  Process: Running (PID: $($agentProcess[0].Id))" -ForegroundColor Green
            Write-Host "  Start Time: $($agentProcess[0].StartTime)" -ForegroundColor White
        }
        else {
            Write-Host "  Process: Not Running" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "  Process: Status Unknown" -ForegroundColor Yellow
    }
    
    Write-Host "`nAUTO-STARTUP CONFIGURATION:" -ForegroundColor Yellow
    Write-Host "  ✓ Service installed for automatic startup" -ForegroundColor Green
    Write-Host "  ✓ Will start after system restart" -ForegroundColor Green
    Write-Host "  ✓ Will start after system shutdown/reboot" -ForegroundColor Green
    Write-Host "  ✓ Will restart agent if it stops unexpectedly" -ForegroundColor Green
    Write-Host "  ✓ Handles sleep/wake scenarios" -ForegroundColor Green
    
    Write-Host "`nMANAGEMENT COMMANDS:" -ForegroundColor Yellow
    Write-Host "  Start Agent:   .\MonitoringAgentControl.ps1 start" -ForegroundColor White
    Write-Host "  Stop Agent:    .\MonitoringAgentControl.ps1 stop" -ForegroundColor White
    Write-Host "  Agent Status:  .\MonitoringAgentControl.ps1 status" -ForegroundColor White
    Write-Host "  Service Menu:  .\MonitoringAgentServiceManager.ps1" -ForegroundColor White
    
    Write-Host "`nLOG FILES:" -ForegroundColor Yellow
    Write-Host "  Setup Log:     logs\auto-startup-setup.log" -ForegroundColor White
    Write-Host "  Watchdog Log:  watchdog.log" -ForegroundColor White
    Write-Host "  Agent Log:     ossec.log" -ForegroundColor White
    Write-Host "  Service Logs:  logs\service-*.log" -ForegroundColor White
    
    Write-Host "`nIMPORTANT NOTES:" -ForegroundColor Yellow
    Write-Host "  • The agent will now start automatically with Windows" -ForegroundColor White
    Write-Host "  • The watchdog service monitors and restarts the agent if needed" -ForegroundColor White
    Write-Host "  • Use the service manager for advanced service operations" -ForegroundColor White
    Write-Host "  • Check logs if you experience any issues" -ForegroundColor White
    
    Write-Host "`n" + "="*70 -ForegroundColor Cyan
}

# Main setup process
function Start-AutoStartupSetup {
    Write-Host "="*70 -ForegroundColor Cyan
    Write-Host "MONITORING AGENT AUTO-STARTUP SETUP" -ForegroundColor Cyan
    Write-Host "="*70 -ForegroundColor Cyan
    Write-Host "This script will configure your monitoring agent for automatic startup" -ForegroundColor White
    Write-Host "after system restart, shutdown, or sleep/wake events." -ForegroundColor White
    Write-Host ""
    
    Write-SetupLog "=== Auto-Startup Setup Started ===" "INFO"
    Write-SetupLog "Agent Path: $Script:AgentPath" "INFO"
    Write-SetupLog "PowerShell Version: $($PSVersionTable.PSVersion)" "INFO"
    Write-SetupLog "Running as: $(whoami)" "INFO"
    
    $success = $true
    
    # Step 1: Check prerequisites
    Write-Host "Step 1: Checking prerequisites..." -ForegroundColor Cyan
    if (!(Test-Prerequisites)) {
        $success = $false
    }
    
    # Step 2: Test agent configuration
    if ($success) {
        Write-Host "`nStep 2: Testing agent configuration..." -ForegroundColor Cyan
        if (!(Test-AgentConfiguration)) {
            $success = $false
        }
    }
    
    # Step 3: Setup auto-startup service
    if ($success) {
        Write-Host "`nStep 3: Setting up auto-startup service..." -ForegroundColor Cyan
        if (!(Setup-AutoStartupService)) {
            $success = $false
        }
        
        # Give service time to start
        Write-Host "Waiting for service to initialize..." -ForegroundColor Gray
        Start-Sleep -Seconds 10
    }
    
    # Step 4: Verify setup
    if ($success) {
        Write-Host "`nStep 4: Verifying setup..." -ForegroundColor Cyan
        if (!(Test-AutoStartupSetup)) {
            $success = $false
        }
    }
    
    # Show results
    if ($success) {
        Write-SetupLog "Auto-startup setup completed successfully" "SUCCESS"
        Show-SetupResults
    }
    else {
        Write-SetupLog "Auto-startup setup failed" "ERROR"
        Write-Host "`nSETUP FAILED" -ForegroundColor Red
        Write-Host "Please check the setup log for details: $Script:SetupLog" -ForegroundColor Yellow
        Write-Host "You can also run the service manager manually: .\MonitoringAgentServiceManager.ps1" -ForegroundColor Yellow
    }
    
    Write-SetupLog "=== Auto-Startup Setup Finished ===" "INFO"
    return $success
}

# Main execution
function Main {
    # Check admin rights
    if (!(Test-AdminRights)) {
        Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
        Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
        exit 1
    }
    
    # Handle command line arguments
    if ($args.Count -gt 0) {
        switch ($args[0].ToLower()) {
            "setup" {
                if (Start-AutoStartupSetup) { exit 0 } else { exit 1 }
            }
            "verify" {
                if (Test-AutoStartupSetup) { exit 0 } else { exit 1 }
            }
            "prereq" {
                if (Test-Prerequisites) { exit 0 } else { exit 1 }
            }
            default {
                Write-Host "Usage: .\SetupAutoStartup.ps1 [setup|verify|prereq]" -ForegroundColor Yellow
                Write-Host "  setup   - Complete auto-startup setup" -ForegroundColor Gray
                Write-Host "  verify  - Verify existing setup" -ForegroundColor Gray
                Write-Host "  prereq  - Check prerequisites only" -ForegroundColor Gray
                Write-Host "Or run without parameters for interactive setup." -ForegroundColor Gray
                exit 1
            }
        }
    }
    else {
        # Interactive setup
        if (Start-AutoStartupSetup) { exit 0 } else { exit 1 }
    }
}

# Execute main function
Main @args