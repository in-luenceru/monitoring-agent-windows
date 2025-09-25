#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enhanced Monitoring Agent Auto-Startup Script with Watchdog Functionality
    
.DESCRIPTION
    This script provides robust auto-startup functionality for the Monitoring Agent and Suricata IDS.
    Features:
    - Intelligent startup with retries and backoff
    - Continuous watchdog monitoring
    - Service health checks and automatic recovery
    - Comprehensive logging and error handling
    - System event monitoring for startup triggers
    
.PARAMETER Mode
    Operation mode: 'startup' for initial startup, 'watchdog' for continuous monitoring
    
.PARAMETER Duration
    Watchdog monitoring duration in minutes (0 for infinite)
    
.AUTHOR
    Custom Security Solutions
    
.VERSION
    2.0.0
#>

param(
    [ValidateSet("startup", "watchdog", "test")]
    [string]$Mode = "startup",
    
    [int]$Duration = 0,
    
    [switch]$NoWait
)

# Script Configuration
$Script:AgentPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:AgentExe = Join-Path $AgentPath "monitoring-agent.exe"
$Script:SuricataPath = Join-Path $AgentPath "suricata"
$Script:SuricataControl = Join-Path $SuricataPath "SuricataControl.ps1"
$Script:LogFile = Join-Path $AgentPath "logs\auto-startup.log"
$Script:WatchdogPidFile = Join-Path $AgentPath "state\watchdog.pid"
$Script:ControlScript = Join-Path $AgentPath "MonitoringAgentControl.ps1"

# Watchdog Configuration
$Script:WatchdogConfig = @{
    CheckInterval = 30          # Check every 30 seconds
    StartupRetries = 5          # Maximum startup retry attempts
    RetryDelay = 60             # Delay between retries (seconds)
    HealthCheckTimeout = 10     # Health check timeout (seconds)
    RestartCooldown = 120       # Minimum time between restarts (seconds)
    MaxRestartAttempts = 3      # Maximum restart attempts per hour
}

# Startup delays for different scenarios
$Script:StartupDelays = @{
    SystemBoot = 45             # Delay after system boot
    UserLogon = 15              # Delay after user logon
    ServiceRecovery = 30        # Delay for service recovery
    WakeFromSleep = 20          # Delay after wake from sleep
}

# Global state tracking
$Script:LastRestartTime = @{}
$Script:RestartCounts = @{}
$Script:WatchdogRunning = $false

#region Logging Functions
function Write-AutoStartupLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $ProcessId = [System.Diagnostics.Process]::GetCurrentProcess().Id
    $LogEntry = "[$Timestamp] [PID:$ProcessId] [$Level] [$Mode] $Message"
    
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
    if ([Environment]::UserInteractive) {
        switch ($Level) {
            "INFO"    { Write-Host $LogEntry -ForegroundColor Cyan }
            "WARN"    { Write-Host $LogEntry -ForegroundColor Yellow }
            "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
            "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
            "DEBUG"   { Write-Host $LogEntry -ForegroundColor Gray }
        }
    }
}

function Write-EventLog {
    param(
        [string]$Message,
        [string]$EventType = "Information"
    )
    
    try {
        # Create event source if it doesn't exist
        if (!(Get-EventLog -LogName Application -Source "MonitoringAgent" -ErrorAction SilentlyContinue)) {
            New-EventLog -LogName Application -Source "MonitoringAgent" -ErrorAction SilentlyContinue
        }
        
        Write-EventLog -LogName Application -Source "MonitoringAgent" -EventId 1000 -EntryType $EventType -Message $Message -ErrorAction SilentlyContinue
    }
    catch {
        # Continue silently if unable to write to event log
    }
}
#endregion

#region Utility Functions
function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SystemUptime {
    try {
        $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
        return (Get-Date) - $bootTime
    }
    catch {
        return [TimeSpan]::Zero
    }
}

function Test-NetworkConnectivity {
    try {
        # Test basic network connectivity
        $result = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        return $result
    }
    catch {
        return $false
    }
}

function Wait-ForSystemReady {
    param([int]$MaxWaitSeconds = 300)
    
    Write-AutoStartupLog "Waiting for system to be ready..." "INFO"
    $startTime = Get-Date
    
    while (((Get-Date) - $startTime).TotalSeconds -lt $MaxWaitSeconds) {
        # Check if network is available
        if (Test-NetworkConnectivity) {
            Write-AutoStartupLog "System is ready (network connectivity confirmed)" "SUCCESS"
            return $true
        }
        
        Write-AutoStartupLog "Waiting for network connectivity..." "DEBUG"
        Start-Sleep -Seconds 5
    }
    
    Write-AutoStartupLog "System readiness timeout after $MaxWaitSeconds seconds" "WARN"
    return $false
}

function Get-ProcessWorkingDirectory {
    param([int]$ProcessId)
    
    try {
        $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        if ($process) {
            # Try to get the executable path and derive working directory
            $executablePath = $process.ExecutablePath
            if ($executablePath) {
                return Split-Path $executablePath -Parent
            }
        }
    }
    catch {
        # Continue silently
    }
    
    return $null
}

function Test-ProcessFromWorkspace {
    param([int]$ProcessId, [string]$ProcessName)
    
    try {
        $workingDir = Get-ProcessWorkingDirectory -ProcessId $ProcessId
        if ($workingDir) {
            $normalizedWorkspace = [System.IO.Path]::GetFullPath($Script:AgentPath).TrimEnd('\')
            $normalizedWorkingDir = [System.IO.Path]::GetFullPath($workingDir).TrimEnd('\')
            
            return $normalizedWorkingDir -eq $normalizedWorkspace
        }
    }
    catch {
        # Continue silently
    }
    
    return $false
}
#endregion

#region Service Status Functions
function Get-MonitoringAgentStatus {
    try {
        # Get all monitoring-agent processes
        $processes = Get-Process -Name "monitoring-agent" -ErrorAction SilentlyContinue
        
        if ($processes) {
            foreach ($process in $processes) {
                # Check if this process is from our workspace
                if (Test-ProcessFromWorkspace -ProcessId $process.Id -ProcessName "monitoring-agent") {
                    return @{
                        Running = $true
                        ProcessId = $process.Id
                        StartTime = $process.StartTime
                        WorkingSet = $process.WorkingSet64
                        FromWorkspace = $true
                    }
                }
            }
        }
        
        return @{
            Running = $false
            ProcessId = $null
            StartTime = $null
            WorkingSet = 0
            FromWorkspace = $false
        }
    }
    catch {
        Write-AutoStartupLog "Error checking agent status: $($_.Exception.Message)" "ERROR"
        return @{
            Running = $false
            ProcessId = $null
            StartTime = $null
            WorkingSet = 0
            FromWorkspace = $false
        }
    }
}

function Get-SuricataStatus {
    try {
        if (!(Test-Path $Script:SuricataControl)) {
            return @{
                Available = $false
                Running = $false
                ProcessId = $null
                StartTime = $null
            }
        }
        
        # Get Suricata processes
        $processes = Get-Process -Name "suricata" -ErrorAction SilentlyContinue
        
        if ($processes) {
            foreach ($process in $processes) {
                # Check if this process is from our workspace
                if (Test-ProcessFromWorkspace -ProcessId $process.Id -ProcessName "suricata") {
                    return @{
                        Available = $true
                        Running = $true
                        ProcessId = $process.Id
                        StartTime = $process.StartTime
                        WorkingSet = $process.WorkingSet64
                        FromWorkspace = $true
                    }
                }
            }
        }
        
        return @{
            Available = $true
            Running = $false
            ProcessId = $null
            StartTime = $null
            WorkingSet = 0
            FromWorkspace = $false
        }
    }
    catch {
        Write-AutoStartupLog "Error checking Suricata status: $($_.Exception.Message)" "ERROR"
        return @{
            Available = $true
            Running = $false
            ProcessId = $null
            StartTime = $null
            WorkingSet = 0
            FromWorkspace = $false
        }
    }
}

function Test-ServiceHealth {
    param([string]$ServiceName)
    
    $isHealthy = $false
    
    try {
        switch ($ServiceName) {
            "MonitoringAgent" {
                $status = Get-MonitoringAgentStatus
                if ($status.Running -and $status.FromWorkspace) {
                    # Test if process is responsive (basic health check)
                    $process = Get-Process -Id $status.ProcessId -ErrorAction SilentlyContinue
                    if ($process -and !$process.HasExited) {
                        # Check if process has been running for at least 30 seconds (startup completion)
                        $runningTime = (Get-Date) - $process.StartTime
                        if ($runningTime.TotalSeconds -ge 30) {
                            $isHealthy = $true
                        }
                    }
                }
            }
            
            "Suricata" {
                $status = Get-SuricataStatus
                if ($status.Available -and $status.Running -and $status.FromWorkspace) {
                    $process = Get-Process -Id $status.ProcessId -ErrorAction SilentlyContinue
                    if ($process -and !$process.HasExited) {
                        $runningTime = (Get-Date) - $process.StartTime
                        if ($runningTime.TotalSeconds -ge 30) {
                            $isHealthy = $true
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-AutoStartupLog "Health check failed for $ServiceName`: $($_.Exception.Message)" "ERROR"
        $isHealthy = $false
    }
    
    return $isHealthy
}
#endregion

#region Service Management Functions
function Start-MonitoringAgentWithRetry {
    param([int]$MaxRetries = 3)
    
    Write-AutoStartupLog "Starting Monitoring Agent with retry logic..." "INFO"
    
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Write-AutoStartupLog "Startup attempt $attempt/$MaxRetries" "INFO"
        
        try {
            # Check if already running
            $status = Get-MonitoringAgentStatus
            if ($status.Running -and $status.FromWorkspace) {
                Write-AutoStartupLog "Monitoring Agent already running (PID: $($status.ProcessId))" "SUCCESS"
                return $true
            }
            
            # Use the control script to start the agent
            $startArgs = @(
                "-NoProfile"
                "-ExecutionPolicy", "Bypass"
                "-File", $Script:ControlScript
                "start"
            )
            
            Write-AutoStartupLog "Executing: pwsh.exe $($startArgs -join ' ')" "DEBUG"
            
            $process = Start-Process -FilePath "pwsh.exe" -ArgumentList $startArgs -WorkingDirectory $Script:AgentPath -WindowStyle Hidden -PassThru -Wait
            
            if ($process.ExitCode -eq 0) {
                # Wait for agent to fully start
                Start-Sleep -Seconds 5
                
                # Verify the agent started
                $newStatus = Get-MonitoringAgentStatus
                if ($newStatus.Running -and $newStatus.FromWorkspace) {
                    Write-AutoStartupLog "Monitoring Agent started successfully (PID: $($newStatus.ProcessId))" "SUCCESS"
                    Write-EventLog "Monitoring Agent started successfully" "Information"
                    return $true
                } else {
                    Write-AutoStartupLog "Agent start command completed but agent is not running" "WARN"
                }
            } else {
                Write-AutoStartupLog "Agent start command failed with exit code: $($process.ExitCode)" "ERROR"
            }
        }
        catch {
            Write-AutoStartupLog "Error during startup attempt $attempt`: $($_.Exception.Message)" "ERROR"
        }
        
        if ($attempt -lt $MaxRetries) {
            $delay = $Script:WatchdogConfig.RetryDelay
            Write-AutoStartupLog "Waiting $delay seconds before retry..." "INFO"
            Start-Sleep -Seconds $delay
        }
    }
    
    Write-AutoStartupLog "Failed to start Monitoring Agent after $MaxRetries attempts" "ERROR"
    Write-EventLog "Failed to start Monitoring Agent after $MaxRetries attempts" "Error"
    return $false
}

function Start-SuricataWithRetry {
    param([int]$MaxRetries = 3)
    
    $suricataStatus = Get-SuricataStatus
    if (!$suricataStatus.Available) {
        Write-AutoStartupLog "Suricata is not available in this installation" "INFO"
        return $true  # Not an error if Suricata is not installed
    }
    
    Write-AutoStartupLog "Starting Suricata Network IDS with retry logic..." "INFO"
    
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Write-AutoStartupLog "Suricata startup attempt $attempt/$MaxRetries" "INFO"
        
        try {
            # Check if already running
            $status = Get-SuricataStatus
            if ($status.Running -and $status.FromWorkspace) {
                Write-AutoStartupLog "Suricata already running (PID: $($status.ProcessId))" "SUCCESS"
                return $true
            }
            
            # Use the control script to start Suricata
            $startArgs = @(
                "-NoProfile"
                "-ExecutionPolicy", "Bypass"
                "-File", $Script:ControlScript
                "start-suricata"
            )
            
            Write-AutoStartupLog "Executing Suricata start: pwsh.exe $($startArgs -join ' ')" "DEBUG"
            
            $process = Start-Process -FilePath "pwsh.exe" -ArgumentList $startArgs -WorkingDirectory $Script:AgentPath -WindowStyle Hidden -PassThru -Wait
            
            if ($process.ExitCode -eq 0) {
                # Wait for Suricata to fully start
                Start-Sleep -Seconds 5
                
                # Verify Suricata started
                $newStatus = Get-SuricataStatus
                if ($newStatus.Running -and $newStatus.FromWorkspace) {
                    Write-AutoStartupLog "Suricata started successfully (PID: $($newStatus.ProcessId))" "SUCCESS"
                    Write-EventLog "Suricata Network IDS started successfully" "Information"
                    return $true
                } else {
                    Write-AutoStartupLog "Suricata start command completed but Suricata is not running" "WARN"
                }
            } else {
                Write-AutoStartupLog "Suricata start command failed with exit code: $($process.ExitCode)" "ERROR"
            }
        }
        catch {
            Write-AutoStartupLog "Error during Suricata startup attempt $attempt`: $($_.Exception.Message)" "ERROR"
        }
        
        if ($attempt -lt $MaxRetries) {
            $delay = $Script:WatchdogConfig.RetryDelay
            Write-AutoStartupLog "Waiting $delay seconds before Suricata retry..." "INFO"
            Start-Sleep -Seconds $delay
        }
    }
    
    Write-AutoStartupLog "Failed to start Suricata after $MaxRetries attempts" "ERROR"
    Write-EventLog "Failed to start Suricata Network IDS after $MaxRetries attempts" "Warning"
    return $false
}

function Start-AllServices {
    Write-AutoStartupLog "Starting all monitoring services using unified start command..." "INFO"
    
    # Use the integrated start command which handles both agent and Suricata
    for ($attempt = 1; $attempt -le $Script:WatchdogConfig.StartupRetries; $attempt++) {
        Write-AutoStartupLog "Startup attempt $attempt/$($Script:WatchdogConfig.StartupRetries)" "INFO"
        
        try {
            $startArgs = @(
                "-NoProfile"
                "-ExecutionPolicy", "Bypass" 
                "-File", $Script:ControlScript
                "start"
            )
            
            # Use the same PowerShell executable that the task scheduler is using
            $powershellExe = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            
            Write-AutoStartupLog "Executing unified start: $powershellExe $($startArgs -join ' ')" "DEBUG"
            
            $process = Start-Process -FilePath $powershellExe -ArgumentList $startArgs -WorkingDirectory $Script:AgentPath -WindowStyle Hidden -PassThru -Wait
            
            if ($process.ExitCode -eq 0) {
                Write-AutoStartupLog "All services started successfully" "SUCCESS"
                return $true
            } else {
                Write-AutoStartupLog "Start command failed with exit code: $($process.ExitCode)" "WARN"
            }
        }
        catch {
            Write-AutoStartupLog "Error during startup attempt $attempt`: $($_.Exception.Message)" "ERROR"
        }
        
        if ($attempt -lt $Script:WatchdogConfig.StartupRetries) {
            Write-AutoStartupLog "Waiting $($Script:WatchdogConfig.RetryDelay) seconds before retry..." "INFO"
            Start-Sleep -Seconds $Script:WatchdogConfig.RetryDelay
        }
    }
    
    Write-AutoStartupLog "Failed to start services after $($Script:WatchdogConfig.StartupRetries) attempts" "ERROR"
    return $false
}
#endregion

#region Watchdog Functions
function Start-WatchdogService {
    param([int]$DurationMinutes = 0)
    
    Write-AutoStartupLog "Starting watchdog service..." "INFO"
    Write-EventLog "Monitoring Agent Watchdog Service started" "Information"
    
    # Save watchdog PID
    try {
        $currentPid = [System.Diagnostics.Process]::GetCurrentProcess().Id
        Set-Content -Path $Script:WatchdogPidFile -Value $currentPid -Force
        Write-AutoStartupLog "Watchdog PID ($currentPid) saved to $Script:WatchdogPidFile" "DEBUG"
    }
    catch {
        Write-AutoStartupLog "Failed to save watchdog PID: $($_.Exception.Message)" "WARN"
    }
    
    $Script:WatchdogRunning = $true
    $startTime = Get-Date
    $checkCount = 0
    
    # Initialize restart tracking
    $Script:LastRestartTime["MonitoringAgent"] = Get-Date
    $Script:LastRestartTime["Suricata"] = Get-Date
    $Script:RestartCounts["MonitoringAgent"] = 0
    $Script:RestartCounts["Suricata"] = 0
    
    Write-AutoStartupLog "Watchdog monitoring started (Duration: $(if ($DurationMinutes -gt 0) { "$DurationMinutes minutes" } else { "infinite" }))" "SUCCESS"
    
    while ($Script:WatchdogRunning) {
        $checkCount++
        $currentTime = Get-Date
        
        # Check if we should stop (duration limit)
        if ($DurationMinutes -gt 0 -and ($currentTime - $startTime).TotalMinutes -ge $DurationMinutes) {
            Write-AutoStartupLog "Watchdog duration limit reached ($DurationMinutes minutes)" "INFO"
            break
        }
        
        Write-AutoStartupLog "Watchdog check #$checkCount" "DEBUG"
        
        # Monitor Monitoring Agent
        if (!(Test-ServiceHealth -ServiceName "MonitoringAgent")) {
            Write-AutoStartupLog "Monitoring Agent health check failed" "WARN"
            
            if (Test-RestartAllowed -ServiceName "MonitoringAgent") {
                Write-AutoStartupLog "Attempting to restart Monitoring Agent..." "INFO"
                
                if (Start-MonitoringAgentWithRetry -MaxRetries 2) {
                    $Script:LastRestartTime["MonitoringAgent"] = $currentTime
                    $Script:RestartCounts["MonitoringAgent"]++
                    Write-AutoStartupLog "Monitoring Agent restarted successfully by watchdog" "SUCCESS"
                    Write-EventLog "Monitoring Agent was restarted by watchdog service" "Warning"
                } else {
                    Write-AutoStartupLog "Watchdog failed to restart Monitoring Agent" "ERROR"
                    Write-EventLog "Watchdog failed to restart Monitoring Agent" "Error"
                }
            } else {
                Write-AutoStartupLog "Restart not allowed for Monitoring Agent (cooldown or max attempts)" "WARN"
            }
        }
        
        # Monitor Suricata (if available)
        $suricataStatus = Get-SuricataStatus
        if ($suricataStatus.Available) {
            if (!(Test-ServiceHealth -ServiceName "Suricata")) {
                Write-AutoStartupLog "Suricata health check failed" "WARN"
                
                if (Test-RestartAllowed -ServiceName "Suricata") {
                    Write-AutoStartupLog "Attempting to restart Suricata..." "INFO"
                    
                    if (Start-SuricataWithRetry -MaxRetries 2) {
                        $Script:LastRestartTime["Suricata"] = $currentTime
                        $Script:RestartCounts["Suricata"]++
                        Write-AutoStartupLog "Suricata restarted successfully by watchdog" "SUCCESS"
                        Write-EventLog "Suricata Network IDS was restarted by watchdog service" "Warning"
                    } else {
                        Write-AutoStartupLog "Watchdog failed to restart Suricata" "ERROR"
                        Write-EventLog "Watchdog failed to restart Suricata Network IDS" "Error"
                    }
                } else {
                    Write-AutoStartupLog "Restart not allowed for Suricata (cooldown or max attempts)" "WARN"
                }
            }
        }
        
        # Reset hourly restart counters
        Reset-HourlyCounters
        
        # Sleep until next check
        Start-Sleep -Seconds $Script:WatchdogConfig.CheckInterval
    }
    
    Write-AutoStartupLog "Watchdog service stopped" "INFO"
    Write-EventLog "Monitoring Agent Watchdog Service stopped" "Information"
    
    # Clean up watchdog PID file
    try {
        Remove-Item -Path $Script:WatchdogPidFile -Force -ErrorAction SilentlyContinue
    }
    catch {
        # Continue silently
    }
}

function Test-RestartAllowed {
    param([string]$ServiceName)
    
    $currentTime = Get-Date
    $lastRestart = $Script:LastRestartTime[$ServiceName]
    $restartCount = $Script:RestartCounts[$ServiceName]
    
    # Check cooldown period
    $timeSinceLastRestart = ($currentTime - $lastRestart).TotalSeconds
    if ($timeSinceLastRestart -lt $Script:WatchdogConfig.RestartCooldown) {
        Write-AutoStartupLog "Service $ServiceName is in restart cooldown ($(($Script:WatchdogConfig.RestartCooldown - $timeSinceLastRestart).ToString('F0')) seconds remaining)" "DEBUG"
        return $false
    }
    
    # Check maximum restart attempts per hour
    if ($restartCount -ge $Script:WatchdogConfig.MaxRestartAttempts) {
        Write-AutoStartupLog "Service $ServiceName has reached maximum restart attempts ($restartCount) for this hour" "WARN"
        return $false
    }
    
    return $true
}

function Reset-HourlyCounters {
    $currentTime = Get-Date
    
    foreach ($serviceName in @("MonitoringAgent", "Suricata")) {
        if ($Script:LastRestartTime.ContainsKey($serviceName)) {
            $lastRestart = $Script:LastRestartTime[$serviceName]
            if (($currentTime - $lastRestart).TotalHours -ge 1) {
                $Script:RestartCounts[$serviceName] = 0
                Write-AutoStartupLog "Reset restart counter for $serviceName" "DEBUG"
            }
        }
    }
}

function Stop-WatchdogService {
    Write-AutoStartupLog "Stopping watchdog service..." "INFO"
    $Script:WatchdogRunning = $false
}

function Test-WatchdogRunning {
    try {
        if (Test-Path $Script:WatchdogPidFile) {
            $watchdogPid = Get-Content -Path $Script:WatchdogPidFile -ErrorAction SilentlyContinue
            if ($watchdogPid) {
                $process = Get-Process -Id $watchdogPid -ErrorAction SilentlyContinue
                if ($process -and $process.ProcessName -eq "pwsh") {
                    return @{
                        Running = $true
                        ProcessId = $watchdogPid
                        StartTime = $process.StartTime
                    }
                }
            }
        }
    }
    catch {
        # Continue silently
    }
    
    return @{
        Running = $false
        ProcessId = $null
        StartTime = $null
    }
}
#endregion

#region Startup Mode Functions
function Start-SystemBootup {
    Write-AutoStartupLog "=== SYSTEM BOOT STARTUP MODE ===" "INFO"
    
    $uptime = Get-SystemUptime
    Write-AutoStartupLog "System uptime: $($uptime.ToString('hh\:mm\:ss'))" "INFO"
    
    # Wait for system to be ready
    if ($uptime.TotalMinutes -lt 2) {
        Write-AutoStartupLog "Recent boot detected, waiting for system readiness..." "INFO"
        Start-Sleep -Seconds $Script:StartupDelays.SystemBoot
        
        if (!(Wait-ForSystemReady -MaxWaitSeconds 300)) {
            Write-AutoStartupLog "System readiness timeout, proceeding with startup anyway..." "WARN"
        }
    }
    
    # Start services
    $success = Start-AllServices
    
    if ($success) {
        Write-AutoStartupLog "System boot startup completed successfully" "SUCCESS"
        
        # Start watchdog if requested
        if (!$NoWait) {
            Write-AutoStartupLog "Starting watchdog service..." "INFO"
            Start-WatchdogService -DurationMinutes $Duration
        }
    } else {
        Write-AutoStartupLog "System boot startup failed" "ERROR"
    }
    
    return $success
}

function Start-UserLogon {
    Write-AutoStartupLog "=== USER LOGON STARTUP MODE ===" "INFO"
    
    # Brief delay for user logon
    Start-Sleep -Seconds $Script:StartupDelays.UserLogon
    
    # Check if services are already running (might have been started by boot trigger)
    $agentStatus = Get-MonitoringAgentStatus
    $suricataStatus = Get-SuricataStatus
    
    if ($agentStatus.Running -and (!$suricataStatus.Available -or $suricataStatus.Running)) {
        Write-AutoStartupLog "Services already running from boot startup" "INFO"
        return $true
    }
    
    # Start services
    $success = Start-AllServices
    
    if ($success) {
        Write-AutoStartupLog "User logon startup completed successfully" "SUCCESS"
    } else {
        Write-AutoStartupLog "User logon startup failed" "ERROR"
    }
    
    return $success
}

function Start-TestMode {
    Write-AutoStartupLog "=== TEST MODE ===" "INFO"
    
    # Check current status
    $agentStatus = Get-MonitoringAgentStatus
    $suricataStatus = Get-SuricataStatus
    $watchdogStatus = Test-WatchdogRunning
    
    Write-AutoStartupLog "Current Status:" "INFO"
    Write-AutoStartupLog "  Monitoring Agent: $(if ($agentStatus.Running) { "Running (PID: $($agentStatus.ProcessId))" } else { "Stopped" })" "INFO"
    Write-AutoStartupLog "  Suricata: $(if ($suricataStatus.Available) { if ($suricataStatus.Running) { "Running (PID: $($suricataStatus.ProcessId))" } else { "Stopped" } } else { "Not Available" })" "INFO"
    Write-AutoStartupLog "  Watchdog: $(if ($watchdogStatus.Running) { "Running (PID: $($watchdogStatus.ProcessId))" } else { "Stopped" })" "INFO"
    
    # Test service health
    Write-AutoStartupLog "Testing service health..." "INFO"
    $agentHealthy = Test-ServiceHealth -ServiceName "MonitoringAgent"
    Write-AutoStartupLog "  Monitoring Agent Health: $(if ($agentHealthy) { "HEALTHY" } else { "UNHEALTHY" })" "INFO"
    
    if ($suricataStatus.Available) {
        $suricataHealthy = Test-ServiceHealth -ServiceName "Suricata"
        Write-AutoStartupLog "  Suricata Health: $(if ($suricataHealthy) { "HEALTHY" } else { "UNHEALTHY" })" "INFO"
    }
    
    # Test network connectivity
    $networkConnected = Test-NetworkConnectivity
    Write-AutoStartupLog "  Network Connectivity: $(if ($networkConnected) { "CONNECTED" } else { "DISCONNECTED" })" "INFO"
    
    Write-AutoStartupLog "Test mode completed" "SUCCESS"
    return $true
}
#endregion

#region Main Execution
function Main {
    # Ensure running as administrator
    if (!(Test-AdminRights)) {
        Write-AutoStartupLog "This script requires administrator privileges" "ERROR"
        exit 1
    }
    
    # Ensure required files exist
    if (!(Test-Path $Script:AgentExe)) {
        Write-AutoStartupLog "Agent executable not found: $Script:AgentExe" "ERROR"
        exit 1
    }
    
    if (!(Test-Path $Script:ControlScript)) {
        Write-AutoStartupLog "Control script not found: $Script:ControlScript" "ERROR"
        exit 1
    }
    
    Write-AutoStartupLog "Monitoring Agent Auto-Startup v2.0.0 - Mode: $Mode" "INFO"
    Write-AutoStartupLog "Working Directory: $Script:AgentPath" "DEBUG"
    Write-AutoStartupLog "Command Line: $($MyInvocation.Line)" "DEBUG"
    
    try {
        switch ($Mode.ToLower()) {
            "startup" {
                # Determine startup type based on system uptime
                $uptime = Get-SystemUptime
                if ($uptime.TotalMinutes -lt 5) {
                    Start-SystemBootup
                } else {
                    Start-UserLogon
                }
            }
            
            "watchdog" {
                Write-AutoStartupLog "=== WATCHDOG MODE ===" "INFO"
                Start-WatchdogService -DurationMinutes $Duration
            }
            
            "test" {
                Start-TestMode
            }
            
            default {
                Write-AutoStartupLog "Invalid mode: $Mode" "ERROR"
                exit 1
            }
        }
    }
    catch {
        Write-AutoStartupLog "Fatal error in main execution: $($_.Exception.Message)" "ERROR"
        Write-EventLog "Fatal error in Monitoring Agent Auto-Startup: $($_.Exception.Message)" "Error"
        exit 1
    }
}

# Handle Ctrl+C gracefully in watchdog mode
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    if ($Script:WatchdogRunning) {
        Write-AutoStartupLog "Received shutdown signal, stopping watchdog..." "INFO"
        Stop-WatchdogService
    }
}

# Execute main function
Main
#endregion