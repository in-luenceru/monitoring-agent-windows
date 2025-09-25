#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Monitoring Agent Watchdog Service - Standalone Continuous Monitoring
    
.DESCRIPTION
    This script provides continuous watchdog monitoring for the Monitoring Agent and Suricata IDS.
    It runs as a separate process and monitors service health, automatically restarting failed services.
    
.PARAMETER Install
    Install the watchdog as a Windows service
    
.PARAMETER Uninstall
    Uninstall the watchdog service
    
.PARAMETER Start
    Start the watchdog monitoring
    
.PARAMETER Stop
    Stop the watchdog monitoring
    
.PARAMETER Status
    Show watchdog status
    
.AUTHOR
    Custom Security Solutions
    
.VERSION
    1.0.0
#>

param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Start,
    [switch]$Stop,
    [switch]$Status,
    [int]$CheckInterval = 30,
    [switch]$Console
)

# Script Configuration
$Script:AgentPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:ServiceName = "MonitoringAgentWatchdog"
$Script:ServiceDisplayName = "Monitoring Agent Watchdog Service"
$Script:ServiceDescription = "Monitors and automatically restarts Monitoring Agent and Suricata Network IDS services"
$Script:WatchdogPidFile = Join-Path $AgentPath "state\watchdog-service.pid"
$Script:LogFile = Join-Path $AgentPath "logs\watchdog-service.log"
$Script:AutoStartScript = Join-Path $AgentPath "MonitoringAgentAutoStart.ps1"

# Service configuration
$Script:WatchdogConfig = @{
    CheckInterval = $CheckInterval
    MaxRestartAttempts = 3
    RestartCooldown = 120
    ServiceTimeout = 30
    LogRetention = 7  # days
}

#region Logging Functions
function Write-WatchdogLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $ProcessId = [System.Diagnostics.Process]::GetCurrentProcess().Id
    $LogEntry = "[$Timestamp] [WatchdogService:$ProcessId] [$Level] $Message"
    
    # Ensure logs directory exists
    $LogDir = Split-Path $Script:LogFile -Parent
    if (!(Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    
    # Write to log file
    try {
        Add-Content -Path $Script:LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Continue silently if unable to write to log
    }
    
    # Also output to console if running interactively
    if ($Console -or [Environment]::UserInteractive) {
        switch ($Level) {
            "INFO"    { Write-Host $LogEntry -ForegroundColor Cyan }
            "WARN"    { Write-Host $LogEntry -ForegroundColor Yellow }
            "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
            "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
            "DEBUG"   { Write-Host $LogEntry -ForegroundColor Gray }
        }
    }
}

function Start-LogRotation {
    try {
        $cutoffDate = (Get-Date).AddDays(-$Script:WatchdogConfig.LogRetention)
        
        # Rotate main log if it gets too large (>10MB)
        if ((Test-Path $Script:LogFile) -and (Get-Item $Script:LogFile).Length -gt 10MB) {
            $archiveName = "$($Script:LogFile).$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            Move-Item -Path $Script:LogFile -Destination $archiveName
            Write-WatchdogLog "Rotated log file to $archiveName" "INFO"
        }
        
        # Clean old log files
        $logDir = Split-Path $Script:LogFile -Parent
        Get-ChildItem -Path $logDir -Filter "watchdog-service.log.*" | 
            Where-Object { $_.CreationTime -lt $cutoffDate } |
            Remove-Item -Force
            
    }
    catch {
        Write-WatchdogLog "Error rotating logs: $_" "ERROR"
    }
}
#endregion

#region Utility Functions
function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ServiceStatus {
    try {
        $service = Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            return @{
                Installed = $true
                Running = ($service.Status -eq 'Running')
                Status = $service.Status
                StartType = $service.StartType
            }
        }
    }
    catch {
        # Continue silently
    }
    
    return @{
        Installed = $false
        Running = $false
        Status = "Not Installed"
        StartType = "Unknown"
    }
}

function Test-ProcessFromWorkspace {
    param([int]$ProcessId, [string]$ProcessName)
    
    try {
        $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        if ($process -and $process.ExecutablePath) {
            $processDir = Split-Path $process.ExecutablePath -Parent
            $normalizedWorkspace = [System.IO.Path]::GetFullPath($Script:AgentPath).TrimEnd('\')
            $normalizedProcessDir = [System.IO.Path]::GetFullPath($processDir).TrimEnd('\')
            
            return $normalizedProcessDir -eq $normalizedWorkspace
        }
    }
    catch {
        # Continue silently
    }
    
    return $false
}
#endregion

#region Service Management Functions
function Install-WatchdogService {
    Write-WatchdogLog "Installing watchdog service..." "INFO"
    
    try {
        # Check if NSSM is available
        $nssmPath = Join-Path $Script:AgentPath "nssm.exe"
        if (!(Test-Path $nssmPath)) {
            Write-WatchdogLog "NSSM not found at $nssmPath" "ERROR"
            return $false
        }
        
        # Remove existing service if it exists
        $existingService = Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue
        if ($existingService) {
            Write-WatchdogLog "Removing existing service..." "INFO"
            Stop-Service -Name $Script:ServiceName -Force -ErrorAction SilentlyContinue
            & $nssmPath remove $Script:ServiceName confirm | Out-Null
            Start-Sleep -Seconds 2
        }
        
        # Install new service
        Write-WatchdogLog "Installing service with NSSM..." "INFO"
        
        $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue)?.Source ?? (Get-Command powershell -ErrorAction SilentlyContinue)?.Source
        if (!$pwshPath) {
            Write-WatchdogLog "PowerShell executable not found" "ERROR"
            return $false
        }
        
        $serviceArgs = @(
            "-NoProfile"
            "-ExecutionPolicy", "Bypass"
            "-WindowStyle", "Hidden"
            "-File", "`"$($MyInvocation.MyCommand.Path)`""
            "-Start"
            "-CheckInterval", $Script:WatchdogConfig.CheckInterval
        )
        
        # Install service
        & $nssmPath install $Script:ServiceName $pwshPath ($serviceArgs -join " ") | Out-Null
        
        # Configure service
        & $nssmPath set $Script:ServiceName DisplayName $Script:ServiceDisplayName | Out-Null
        & $nssmPath set $Script:ServiceName Description $Script:ServiceDescription | Out-Null
        & $nssmPath set $Script:ServiceName Start SERVICE_AUTO_START | Out-Null
        & $nssmPath set $Script:ServiceName AppDirectory $Script:AgentPath | Out-Null
        & $nssmPath set $Script:ServiceName AppStdout $Script:LogFile | Out-Null
        & $nssmPath set $Script:ServiceName AppStderr $Script:LogFile | Out-Null
        & $nssmPath set $Script:ServiceName AppRotateFiles 1 | Out-Null
        & $nssmPath set $Script:ServiceName AppRotateOnline 1 | Out-Null
        & $nssmPath set $Script:ServiceName AppRotateBytes 10485760 | Out-Null  # 10MB
        
        Write-WatchdogLog "Watchdog service installed successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-WatchdogLog "Error installing watchdog service: $_" "ERROR"
        return $false
    }
}

function Uninstall-WatchdogService {
    Write-WatchdogLog "Uninstalling watchdog service..." "INFO"
    
    try {
        $nssmPath = Join-Path $Script:AgentPath "nssm.exe"
        
        # Stop service if running
        $service = Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -eq 'Running') {
                Write-WatchdogLog "Stopping watchdog service..." "INFO"
                Stop-Service -Name $Script:ServiceName -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
            }
            
            # Remove service
            if (Test-Path $nssmPath) {
                & $nssmPath remove $Script:ServiceName confirm | Out-Null
            }
            
            Write-WatchdogLog "Watchdog service uninstalled successfully" "SUCCESS"
        } else {
            Write-WatchdogLog "Watchdog service is not installed" "INFO"
        }
        
        return $true
    }
    catch {
        Write-WatchdogLog "Error uninstalling watchdog service: $_" "ERROR"
        return $false
    }
}

function Start-WatchdogService {
    Write-WatchdogLog "Starting watchdog service..." "INFO"
    
    try {
        $service = Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            Start-Service -Name $Script:ServiceName
            Write-WatchdogLog "Watchdog service started successfully" "SUCCESS"
            return $true
        } else {
            Write-WatchdogLog "Watchdog service is not installed" "ERROR"
            return $false
        }
    }
    catch {
        Write-WatchdogLog "Error starting watchdog service: $_" "ERROR"
        return $false
    }
}

function Stop-WatchdogService {
    Write-WatchdogLog "Stopping watchdog service..." "INFO"
    
    try {
        $service = Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            Stop-Service -Name $Script:ServiceName -Force
            Write-WatchdogLog "Watchdog service stopped successfully" "SUCCESS"
            return $true
        } else {
            Write-WatchdogLog "Watchdog service is not running" "INFO"
            return $true
        }
    }
    catch {
        Write-WatchdogLog "Error stopping watchdog service: $_" "ERROR"
        return $false
    }
}

function Show-WatchdogStatus {
    $serviceStatus = Get-ServiceStatus
    
    Write-Host "`n=== WATCHDOG SERVICE STATUS ===" -ForegroundColor Cyan
    Write-Host "Service Installed: " -NoNewline -ForegroundColor White
    Write-Host $serviceStatus.Installed -ForegroundColor $(if ($serviceStatus.Installed) { "Green" } else { "Red" })
    
    if ($serviceStatus.Installed) {
        Write-Host "Service Status: " -NoNewline -ForegroundColor White
        Write-Host $serviceStatus.Status -ForegroundColor $(if ($serviceStatus.Running) { "Green" } else { "Red" })
        Write-Host "Start Type: " -NoNewline -ForegroundColor White
        Write-Host $serviceStatus.StartType -ForegroundColor White
    }
    
    # Check for running watchdog processes
    $watchdogProcesses = Get-Process -Name "pwsh" -ErrorAction SilentlyContinue | 
        Where-Object { $_.MainModule.FileName -like "*pwsh.exe" }
    
    Write-Host "Active Processes: " -NoNewline -ForegroundColor White
    if ($watchdogProcesses) {
        Write-Host "$($watchdogProcesses.Count) PowerShell processes detected" -ForegroundColor Yellow
    } else {
        Write-Host "No PowerShell processes detected" -ForegroundColor Gray
    }
    
    # Show recent log entries
    Write-Host "`n--- Recent Log Entries ---" -ForegroundColor White
    if (Test-Path $Script:LogFile) {
        Get-Content -Path $Script:LogFile -Tail 10 | ForEach-Object {
            Write-Host $_ -ForegroundColor Gray
        }
    } else {
        Write-Host "No log file found" -ForegroundColor Gray
    }
    
    Write-Host ""
}
#endregion

#region Monitoring Functions
function Get-MonitoringAgentStatus {
    try {
        $processes = Get-Process -Name "monitoring-agent" -ErrorAction SilentlyContinue
        
        if ($processes) {
            foreach ($process in $processes) {
                if (Test-ProcessFromWorkspace -ProcessId $process.Id -ProcessName "monitoring-agent") {
                    return @{
                        Running = $true
                        ProcessId = $process.Id
                        StartTime = $process.StartTime
                        WorkingSet = $process.WorkingSet64
                    }
                }
            }
        }
        
        return @{ Running = $false; ProcessId = $null }
    }
    catch {
        Write-WatchdogLog "Error checking agent status: $_" "ERROR"
        return @{ Running = $false; ProcessId = $null }
    }
}

function Get-SuricataStatus {
    try {
        $suricataControl = Join-Path $Script:AgentPath "suricata\SuricataControl.ps1"
        if (!(Test-Path $suricataControl)) {
            return @{ Available = $false; Running = $false }
        }
        
        $processes = Get-Process -Name "suricata" -ErrorAction SilentlyContinue
        
        if ($processes) {
            foreach ($process in $processes) {
                if (Test-ProcessFromWorkspace -ProcessId $process.Id -ProcessName "suricata") {
                    return @{
                        Available = $true
                        Running = $true
                        ProcessId = $process.Id
                        StartTime = $process.StartTime
                    }
                }
            }
        }
        
        return @{ Available = $true; Running = $false; ProcessId = $null }
    }
    catch {
        Write-WatchdogLog "Error checking Suricata status: $_" "ERROR"
        return @{ Available = $true; Running = $false; ProcessId = $null }
    }
}

function Test-ServiceHealth {
    param([string]$ServiceName)
    
    try {
        switch ($ServiceName) {
            "MonitoringAgent" {
                $status = Get-MonitoringAgentStatus
                if ($status.Running) {
                    $process = Get-Process -Id $status.ProcessId -ErrorAction SilentlyContinue
                    if ($process -and !$process.HasExited) {
                        $runningTime = (Get-Date) - $process.StartTime
                        return $runningTime.TotalSeconds -ge 30
                    }
                }
            }
            
            "Suricata" {
                $status = Get-SuricataStatus
                if ($status.Available -and $status.Running) {
                    $process = Get-Process -Id $status.ProcessId -ErrorAction SilentlyContinue
                    if ($process -and !$process.HasExited) {
                        $runningTime = (Get-Date) - $process.StartTime
                        return $runningTime.TotalSeconds -ge 30
                    }
                }
            }
        }
    }
    catch {
        Write-WatchdogLog "Health check failed for $ServiceName`: $($_)" "ERROR"
    }
    
    return $false
}

function Restart-Service {
    param([string]$ServiceName)
    
    Write-WatchdogLog "Restarting $ServiceName..." "INFO"
    
    try {
        $startArgs = @(
            "-NoProfile"
            "-ExecutionPolicy", "Bypass"
            "-File", $Script:AutoStartScript
            "startup"
            "-NoWait"
        )
        
        $process = Start-Process -FilePath "pwsh.exe" -ArgumentList $startArgs -WorkingDirectory $Script:AgentPath -WindowStyle Hidden -PassThru -Wait
        
        if ($process.ExitCode -eq 0) {
            Start-Sleep -Seconds 5
            
            # Verify restart
            $healthy = Test-ServiceHealth -ServiceName $ServiceName
            if ($healthy) {
                Write-WatchdogLog "$ServiceName restarted successfully" "SUCCESS"
                return $true
            } else {
                Write-WatchdogLog "$ServiceName restart verification failed" "ERROR"
            }
        } else {
            Write-WatchdogLog "$ServiceName restart command failed with exit code: $($process.ExitCode)" "ERROR"
        }
    }
    catch {
        Write-WatchdogLog "Error restarting $ServiceName`: $($_)" "ERROR"
    }
    
    return $false
}

function Start-WatchdogMonitoring {
    Write-WatchdogLog "Starting watchdog monitoring service..." "INFO"
    
    # Save PID
    try {
        $currentPid = [System.Diagnostics.Process]::GetCurrentProcess().Id
        Set-Content -Path $Script:WatchdogPidFile -Value $currentPid -Force
    }
    catch {
        Write-WatchdogLog "Failed to save watchdog PID: $_" "WARN"
    }
    
    $checkCount = 0
    $lastRestartTime = @{}
    $restartCounts = @{}
    
    # Initialize restart tracking
    $lastRestartTime["MonitoringAgent"] = (Get-Date).AddMinutes(-10)
    $lastRestartTime["Suricata"] = (Get-Date).AddMinutes(-10)
    $restartCounts["MonitoringAgent"] = 0
    $restartCounts["Suricata"] = 0
    
    while ($true) {
        try {
            $checkCount++
            $currentTime = Get-Date
            
            Write-WatchdogLog "Health check #$checkCount" "DEBUG"
            
            # Check Monitoring Agent
            if (!(Test-ServiceHealth -ServiceName "MonitoringAgent")) {
                Write-WatchdogLog "Monitoring Agent is unhealthy" "WARN"
                
                $timeSinceLastRestart = ($currentTime - $lastRestartTime["MonitoringAgent"]).TotalSeconds
                if ($timeSinceLastRestart -ge $Script:WatchdogConfig.RestartCooldown -and 
                    $restartCounts["MonitoringAgent"] -lt $Script:WatchdogConfig.MaxRestartAttempts) {
                    
                    if (Restart-Service -ServiceName "MonitoringAgent") {
                        $lastRestartTime["MonitoringAgent"] = $currentTime
                        $restartCounts["MonitoringAgent"]++
                    }
                }
            }
            
            # Check Suricata
            $suricataStatus = Get-SuricataStatus
            if ($suricataStatus.Available) {
                if (!(Test-ServiceHealth -ServiceName "Suricata")) {
                    Write-WatchdogLog "Suricata is unhealthy" "WARN"
                    
                    $timeSinceLastRestart = ($currentTime - $lastRestartTime["Suricata"]).TotalSeconds
                    if ($timeSinceLastRestart -ge $Script:WatchdogConfig.RestartCooldown -and 
                        $restartCounts["Suricata"] -lt $Script:WatchdogConfig.MaxRestartAttempts) {
                        
                        if (Restart-Service -ServiceName "Suricata") {
                            $lastRestartTime["Suricata"] = $currentTime
                            $restartCounts["Suricata"]++
                        }
                    }
                }
            }
            
            # Reset hourly counters
            foreach ($serviceName in @("MonitoringAgent", "Suricata")) {
                if (($currentTime - $lastRestartTime[$serviceName]).TotalHours -ge 1) {
                    $restartCounts[$serviceName] = 0
                }
            }
            
            # Rotate logs periodically
            if ($checkCount % 100 -eq 0) {
                Start-LogRotation
            }
            
            Start-Sleep -Seconds $Script:WatchdogConfig.CheckInterval
        }
        catch {
            Write-WatchdogLog "Error in monitoring loop: $_" "ERROR"
            Start-Sleep -Seconds $Script:WatchdogConfig.CheckInterval
        }
    }
}
#endregion

#region Main Execution
function Main {
    if (!(Test-AdminRights)) {
        Write-Host "This script requires administrator privileges" -ForegroundColor Red
        exit 1
    }
    
    # Handle parameters
    if ($Install) {
        $result = Install-WatchdogService
        exit $(if ($result) { 0 } else { 1 })
    }
    
    if ($Uninstall) {
        $result = Uninstall-WatchdogService
        exit $(if ($result) { 0 } else { 1 })
    }
    
    if ($Start -and !$Console) {
        # Starting as service
        Start-WatchdogMonitoring
        exit 0
    }
    
    if ($Start -and $Console) {
        # Starting in console mode
        Write-Host "Starting watchdog in console mode (Ctrl+C to stop)..." -ForegroundColor Green
        Start-WatchdogMonitoring
        exit 0
    }
    
    if ($Stop) {
        $result = Stop-WatchdogService
        exit $(if ($result) { 0 } else { 1 })
    }
    
    if ($Status) {
        Show-WatchdogStatus
        exit 0
    }
    
    # Default: Show help
    Write-Host @"
Monitoring Agent Watchdog Service

Usage:
    .\MonitoringAgentWatchdog.ps1 -Install      Install watchdog service
    .\MonitoringAgentWatchdog.ps1 -Uninstall    Uninstall watchdog service
    .\MonitoringAgentWatchdog.ps1 -Start         Start watchdog service
    .\MonitoringAgentWatchdog.ps1 -Stop          Stop watchdog service
    .\MonitoringAgentWatchdog.ps1 -Status        Show service status
    .\MonitoringAgentWatchdog.ps1 -Start -Console  Start in console mode

Options:
    -CheckInterval <seconds>    Monitoring check interval (default: 30)
    -Console                   Run in console mode (for debugging)

"@ -ForegroundColor White
    exit 0
}

# Execute main function
Main
#endregion