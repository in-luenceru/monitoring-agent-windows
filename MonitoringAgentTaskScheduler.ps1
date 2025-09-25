#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Monitoring Agent Task Scheduler Auto-Startup
    
.DESCRIPTION
    Alternative auto-startup solution using Windows Task Scheduler.
    Creates scheduled tasks for reliable startup after system restart,
    shutdown, or sleep/wake events. More reliable than Windows Services
    for user-mode applications.
    
.AUTHOR
    Custom Security Solutions
    
.VERSION
    1.0.0
    
.NOTES
    Requires Administrator privileges
    Uses Windows Task Scheduler for auto-startup management
#>

# Script Configuration
$Script:AgentPath = $PSScriptRoot
$Script:TaskName = "MonitoringAgentAutoStart"
$Script:WatchdogTaskName = "MonitoringAgentWatchdog"
$Script:AgentControl = Join-Path $AgentPath "MonitoringAgentControl.ps1"
$Script:WatchdogScript = Join-Path $AgentPath "MonitoringAgentWatchdog.ps1"
$Script:TaskLog = Join-Path $AgentPath "logs\task-scheduler.log"

# Ensure logs directory exists
$LogDir = Split-Path $Script:TaskLog -Parent
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Logging function
function Write-TaskLog {
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
        Add-Content -Path $Script:TaskLog -Value $logEntry -Encoding UTF8
        
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

# Install Task Scheduler based auto-startup
function Install-TaskSchedulerAutoStart {
    Write-TaskLog "Installing Task Scheduler auto-startup..." "INFO"
    
    try {
        # Remove existing tasks if they exist
        Remove-TaskSchedulerAutoStart | Out-Null
        
        # Create the startup task
        Write-TaskLog "Creating agent startup task..." "INFO"
        
        $startupAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Script:AgentControl`" start"
        
        $startupTriggers = @(
            New-ScheduledTaskTrigger -AtStartup
            New-ScheduledTaskTrigger -AtLogOn
        )
        
        $startupSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartOnIdle -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Hours 0)
        
        $startupPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        $startupTask = New-ScheduledTask -Action $startupAction -Trigger $startupTriggers -Settings $startupSettings -Principal $startupPrincipal -Description "Automatically starts the Monitoring Agent at system startup and user logon"
        
        Register-ScheduledTask -TaskName $Script:TaskName -InputObject $startupTask -Force | Out-Null
        
        Write-TaskLog "Agent startup task created successfully" "SUCCESS"
        
        # Create the watchdog task
        Write-TaskLog "Creating agent watchdog task..." "INFO"
        
        $watchdogAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Script:WatchdogScript`""
        
        $watchdogTrigger = New-ScheduledTaskTrigger -AtStartup
        
        $watchdogSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartOnIdle -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Hours 0) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
        
        $watchdogPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        $watchdogTask = New-ScheduledTask -Action $watchdogAction -Trigger $watchdogTrigger -Settings $watchdogSettings -Principal $watchdogPrincipal -Description "Monitors and restarts the Monitoring Agent if it stops unexpectedly"
        
        Register-ScheduledTask -TaskName $Script:WatchdogTaskName -InputObject $watchdogTask -Force | Out-Null
        
        Write-TaskLog "Watchdog task created successfully" "SUCCESS"
        
        # Start the watchdog task
        Write-TaskLog "Starting watchdog task..." "INFO"
        Start-ScheduledTask -TaskName $Script:WatchdogTaskName
        
        Write-TaskLog "Task Scheduler auto-startup installed successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-TaskLog "Error installing Task Scheduler auto-startup: $_" "ERROR"
        return $false
    }
}

# Remove Task Scheduler auto-startup
function Remove-TaskSchedulerAutoStart {
    Write-TaskLog "Removing Task Scheduler auto-startup..." "INFO"
    
    try {
        $tasksRemoved = 0
        
        # Remove startup task
        $startupTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
        if ($startupTask) {
            Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false
            Write-TaskLog "Removed startup task: $Script:TaskName" "INFO"
            $tasksRemoved++
        }
        
        # Remove watchdog task
        $watchdogTask = Get-ScheduledTask -TaskName $Script:WatchdogTaskName -ErrorAction SilentlyContinue
        if ($watchdogTask) {
            Unregister-ScheduledTask -TaskName $Script:WatchdogTaskName -Confirm:$false
            Write-TaskLog "Removed watchdog task: $Script:WatchdogTaskName" "INFO"
            $tasksRemoved++
        }
        
        if ($tasksRemoved -gt 0) {
            Write-TaskLog "Task Scheduler auto-startup removed successfully" "SUCCESS"
        }
        else {
            Write-TaskLog "No scheduled tasks found to remove" "INFO"
        }
        
        return $true
    }
    catch {
        Write-TaskLog "Error removing Task Scheduler auto-startup: $_" "ERROR"
        return $false
    }
}

# Check Task Scheduler auto-startup status
function Get-TaskSchedulerStatus {
    try {
        $startupTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
        $watchdogTask = Get-ScheduledTask -TaskName $Script:WatchdogTaskName -ErrorAction SilentlyContinue
        
        return @{
            StartupTask = if ($startupTask) { 
                @{
                    Exists = $true
                    State = $startupTask.State
                    Enabled = $startupTask.Settings.Enabled
                    LastRunTime = (Get-ScheduledTaskInfo -TaskName $Script:TaskName -ErrorAction SilentlyContinue).LastRunTime
                    NextRunTime = (Get-ScheduledTaskInfo -TaskName $Script:TaskName -ErrorAction SilentlyContinue).NextRunTime
                }
            } else {
                @{ Exists = $false }
            }
            WatchdogTask = if ($watchdogTask) {
                @{
                    Exists = $true
                    State = $watchdogTask.State
                    Enabled = $watchdogTask.Settings.Enabled
                    LastRunTime = (Get-ScheduledTaskInfo -TaskName $Script:WatchdogTaskName -ErrorAction SilentlyContinue).LastRunTime
                    NextRunTime = (Get-ScheduledTaskInfo -TaskName $Script:WatchdogTaskName -ErrorAction SilentlyContinue).NextRunTime
                }
            } else {
                @{ Exists = $false }
            }
        }
    }
    catch {
        Write-TaskLog "Error getting task scheduler status: $_" "ERROR"
        return @{
            StartupTask = @{ Exists = $false; Error = $_.Exception.Message }
            WatchdogTask = @{ Exists = $false; Error = $_.Exception.Message }
        }
    }
}

# Start scheduled tasks
function Start-ScheduledTasks {
    Write-TaskLog "Starting scheduled tasks..." "INFO"
    
    try {
        $started = 0
        
        # Start startup task
        $startupTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
        if ($startupTask) {
            if ($startupTask.State -ne "Running") {
                Start-ScheduledTask -TaskName $Script:TaskName
                Write-TaskLog "Started startup task" "SUCCESS"
                $started++
            }
            else {
                Write-TaskLog "Startup task already running" "INFO"
            }
        }
        
        # Start watchdog task
        $watchdogTask = Get-ScheduledTask -TaskName $Script:WatchdogTaskName -ErrorAction SilentlyContinue
        if ($watchdogTask) {
            if ($watchdogTask.State -ne "Running") {
                Start-ScheduledTask -TaskName $Script:WatchdogTaskName
                Write-TaskLog "Started watchdog task" "SUCCESS"
                $started++
            }
            else {
                Write-TaskLog "Watchdog task already running" "INFO"
            }
        }
        
        if ($started -eq 0) {
            Write-TaskLog "No tasks needed to be started" "INFO"
        }
        
        return $true
    }
    catch {
        Write-TaskLog "Error starting scheduled tasks: $_" "ERROR"
        return $false
    }
}

# Stop scheduled tasks
function Stop-ScheduledTasks {
    Write-TaskLog "Stopping scheduled tasks..." "INFO"
    
    try {
        $stopped = 0
        
        # Stop startup task
        $startupTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
        if ($startupTask -and $startupTask.State -eq "Running") {
            Stop-ScheduledTask -TaskName $Script:TaskName
            Write-TaskLog "Stopped startup task" "SUCCESS"
            $stopped++
        }
        
        # Stop watchdog task
        $watchdogTask = Get-ScheduledTask -TaskName $Script:WatchdogTaskName -ErrorAction SilentlyContinue
        if ($watchdogTask -and $watchdogTask.State -eq "Running") {
            Stop-ScheduledTask -TaskName $Script:WatchdogTaskName
            Write-TaskLog "Stopped watchdog task" "SUCCESS"
            $stopped++
        }
        
        if ($stopped -eq 0) {
            Write-TaskLog "No running tasks found to stop" "INFO"
        }
        
        return $true
    }
    catch {
        Write-TaskLog "Error stopping scheduled tasks: $_" "ERROR"
        return $false
    }
}

# Show Task Scheduler status
function Show-TaskSchedulerStatus {
    $status = Get-TaskSchedulerStatus
    
    Write-Host "`n=== TASK SCHEDULER AUTO-STARTUP STATUS ===" -ForegroundColor Cyan
    
    # Startup Task Status
    Write-Host "`n--- Startup Task ---" -ForegroundColor Yellow
    Write-Host "Task Name: $Script:TaskName" -ForegroundColor White
    if ($status.StartupTask.Exists) {
        Write-Host "Status: Installed" -ForegroundColor Green
        Write-Host "State: $($status.StartupTask.State)" -ForegroundColor $(if ($status.StartupTask.State -eq "Ready") { "Green" } elseif ($status.StartupTask.State -eq "Running") { "Yellow" } else { "Red" })
        Write-Host "Enabled: $($status.StartupTask.Enabled)" -ForegroundColor $(if ($status.StartupTask.Enabled) { "Green" } else { "Red" })
        if ($status.StartupTask.LastRunTime) {
            Write-Host "Last Run: $($status.StartupTask.LastRunTime)" -ForegroundColor White
        }
        if ($status.StartupTask.NextRunTime) {
            Write-Host "Next Run: $($status.StartupTask.NextRunTime)" -ForegroundColor White
        }
    }
    else {
        Write-Host "Status: Not Installed" -ForegroundColor Red
    }
    
    # Watchdog Task Status
    Write-Host "`n--- Watchdog Task ---" -ForegroundColor Yellow
    Write-Host "Task Name: $Script:WatchdogTaskName" -ForegroundColor White
    if ($status.WatchdogTask.Exists) {
        Write-Host "Status: Installed" -ForegroundColor Green
        Write-Host "State: $($status.WatchdogTask.State)" -ForegroundColor $(if ($status.WatchdogTask.State -eq "Ready") { "Green" } elseif ($status.WatchdogTask.State -eq "Running") { "Yellow" } else { "Red" })
        Write-Host "Enabled: $($status.WatchdogTask.Enabled)" -ForegroundColor $(if ($status.WatchdogTask.Enabled) { "Green" } else { "Red" })
        if ($status.WatchdogTask.LastRunTime) {
            Write-Host "Last Run: $($status.WatchdogTask.LastRunTime)" -ForegroundColor White
        }
        if ($status.WatchdogTask.NextRunTime) {
            Write-Host "Next Run: $($status.WatchdogTask.NextRunTime)" -ForegroundColor White
        }
    }
    else {
        Write-Host "Status: Not Installed" -ForegroundColor Red
    }
    
    Write-Host ""
}

# Interactive menu
function Show-TaskSchedulerMenu {
    while ($true) {
        Clear-Host
        Write-Host "=== MONITORING AGENT TASK SCHEDULER MANAGER ===" -ForegroundColor Cyan
        Write-Host "Agent Path: $Script:AgentPath" -ForegroundColor Gray
        Write-Host ""
        
        Show-TaskSchedulerStatus
        
        Write-Host "=== AVAILABLE ACTIONS ===" -ForegroundColor Cyan
        Write-Host "1. Install Task Scheduler Auto-Startup" -ForegroundColor White
        Write-Host "2. Remove Task Scheduler Auto-Startup" -ForegroundColor White
        Write-Host "3. Start Scheduled Tasks" -ForegroundColor White
        Write-Host "4. Stop Scheduled Tasks" -ForegroundColor White
        Write-Host "5. Refresh Status" -ForegroundColor White
        Write-Host "6. Show Task Logs" -ForegroundColor White
        Write-Host "7. Exit" -ForegroundColor White
        Write-Host ""
        
        $choice = Read-Host "Select option (1-7)"
        
        switch ($choice) {
            "1" {
                Install-TaskSchedulerAutoStart | Out-Null
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "2" {
                Write-Host "`nAre you sure you want to remove the auto-startup tasks? (y/N): " -ForegroundColor Yellow -NoNewline
                $confirm = Read-Host
                if ($confirm -eq "y" -or $confirm -eq "Y") {
                    Remove-TaskSchedulerAutoStart | Out-Null
                }
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "3" {
                Start-ScheduledTasks | Out-Null
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "4" {
                Stop-ScheduledTasks | Out-Null
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "5" {
                # Just refresh - the loop will show updated status
            }
            "6" {
                Show-TaskLogs
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "7" {
                Write-TaskLog "Task Scheduler Manager exiting" "INFO"
                exit 0
            }
            default {
                Write-Host "`nInvalid option. Please select 1-7." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    }
}

# Show task logs
function Show-TaskLogs {
    Clear-Host
    Write-Host "=== TASK SCHEDULER LOGS ===" -ForegroundColor Cyan
    
    $logsToShow = @(
        @{ Name = "Task Manager Log"; Path = $Script:TaskLog },
        @{ Name = "Watchdog Log"; Path = (Join-Path $Script:AgentPath "watchdog.log") },
        @{ Name = "Agent Control Log"; Path = (Join-Path $Script:AgentPath "logs\agent-control.log") }
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
    
    # Show Windows Task Scheduler logs
    Write-Host "`n--- Windows Task Scheduler Events ---" -ForegroundColor Yellow
    try {
        $taskEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 10 -ErrorAction SilentlyContinue | Where-Object {$_.Message -like "*MonitoringAgent*"}
        if ($taskEvents) {
            $taskEvents | ForEach-Object {
                Write-Host "[$($_.TimeCreated)] $($_.LevelDisplayName): $($_.Message)" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "No recent task scheduler events found" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "Unable to read task scheduler events: $_" -ForegroundColor Red
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
    
    Write-TaskLog "Monitoring Agent Task Scheduler Manager started" "INFO"
    
    # Handle command line arguments
    if ($args.Count -gt 0) {
        switch ($args[0].ToLower()) {
            "install" {
                if (Install-TaskSchedulerAutoStart) { exit 0 } else { exit 1 }
            }
            "remove" {
                if (Remove-TaskSchedulerAutoStart) { exit 0 } else { exit 1 }
            }
            "start" {
                if (Start-ScheduledTasks) { exit 0 } else { exit 1 }
            }
            "stop" {
                if (Stop-ScheduledTasks) { exit 0 } else { exit 1 }
            }
            "status" {
                Show-TaskSchedulerStatus
                exit 0
            }
            default {
                Write-Host "Usage: .\MonitoringAgentTaskScheduler.ps1 [install|remove|start|stop|status]" -ForegroundColor Yellow
                Write-Host "  install  - Install Task Scheduler auto-startup" -ForegroundColor Gray
                Write-Host "  remove   - Remove Task Scheduler auto-startup" -ForegroundColor Gray
                Write-Host "  start    - Start scheduled tasks" -ForegroundColor Gray
                Write-Host "  stop     - Stop scheduled tasks" -ForegroundColor Gray
                Write-Host "  status   - Show task status" -ForegroundColor Gray
                Write-Host "Or run without parameters for interactive mode." -ForegroundColor Gray
                exit 1
            }
        }
    }
    else {
        # Start interactive menu
        Show-TaskSchedulerMenu
    }
}

# Execute main function
Main @args