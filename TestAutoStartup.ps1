#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Monitoring Agent Auto-Startup Test and Validation Script
    
.DESCRIPTION
    This script tests and validates the enhanced auto-startup functionality for the Monitoring Agent.
    It performs comprehensive tests to ensure proper startup behavior after system restarts.
    
.AUTHOR
    Custom Security Solutions
    
.VERSION
    1.0.0
#>

param(
    [switch]$Full,
    [switch]$Quick,
    [switch]$Repair,
    [switch]$Verbose
)

# Script Configuration
$Script:AgentPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:ControlScript = Join-Path $AgentPath "MonitoringAgentControl.ps1"
$Script:AutoStartScript = Join-Path $AgentPath "MonitoringAgentAutoStart.ps1"
$Script:WatchdogScript = Join-Path $AgentPath "MonitoringAgentWatchdog.ps1"
$Script:TestLogFile = Join-Path $AgentPath "logs\auto-startup-test.log"

# Test Configuration
$Script:TestConfig = @{
    TaskName = "MonitoringAgentAutoStart"
    WatchdogServiceName = "MonitoringAgentWatchdog"
    TestTimeout = 300  # 5 minutes
    HealthCheckDelay = 30  # 30 seconds
}

#region Logging Functions
function Write-TestLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG", "TEST")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [TEST] [$Level] $Message"
    
    # Ensure logs directory exists
    $LogDir = Split-Path $Script:TestLogFile -Parent
    if (!(Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    
    # Write to log file
    try {
        Add-Content -Path $Script:TestLogFile -Value $LogEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Continue silently if unable to write to log
    }
    
    # Output to console with colors
    switch ($Level) {
        "INFO"    { Write-Host $LogEntry -ForegroundColor Cyan }
        "WARN"    { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
        "DEBUG"   { if ($Verbose) { Write-Host $LogEntry -ForegroundColor Gray } }
        "TEST"    { Write-Host $LogEntry -ForegroundColor Magenta }
    }
}
#endregion

#region Utility Functions
function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PowerShellExe {
    $pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($pwshCmd) { return $pwshCmd.Source }

    $winPwCmd = Get-Command powershell.exe -ErrorAction SilentlyContinue
    if ($winPwCmd) { return $winPwCmd.Source }

    return $null
}

function Test-RequiredFiles {
    $requiredFiles = @(
        $Script:ControlScript,
        $Script:AutoStartScript
    )
    
    $missing = @()
    foreach ($file in $requiredFiles) {
        if (!(Test-Path $file)) {
            $missing += $file
        }
    }
    
    return @{
        AllPresent = ($missing.Count -eq 0)
        Missing = $missing
    }
}

function Wait-ForCondition {
    param(
        [scriptblock]$Condition,
        [int]$TimeoutSeconds = 60,
        [int]$IntervalSeconds = 5,
        [string]$Description = "condition"
    )
    
    $startTime = Get-Date
    Write-TestLog "Waiting for $Description (timeout: $TimeoutSeconds seconds)..." "DEBUG"
    
    while (((Get-Date) - $startTime).TotalSeconds -lt $TimeoutSeconds) {
        if (& $Condition) {
            Write-TestLog "$Description met successfully" "DEBUG"
            return $true
        }
        
        Start-Sleep -Seconds $IntervalSeconds
    }
    
    Write-TestLog "Timeout waiting for $Description" "WARN"
    return $false
}
#endregion

#region Test Functions
function Test-ScheduledTaskConfiguration {
    Write-TestLog "Testing scheduled task configuration..." "TEST"
    
    try {
        $task = Get-ScheduledTask -TaskName $Script:TestConfig.TaskName -ErrorAction SilentlyContinue
        
        if (!$task) {
            Write-TestLog "FAIL: Scheduled task '$($Script:TestConfig.TaskName)' not found" "ERROR"
            return $false
        }
        
        Write-TestLog "✓ Scheduled task exists" "SUCCESS"
        
        # Check task state
        if ($task.State -ne "Ready") {
            Write-TestLog "WARN: Task state is '$($task.State)' (expected 'Ready')" "WARN"
        } else {
            Write-TestLog "✓ Task state is Ready" "SUCCESS"
        }
        
        # Check triggers
        $triggers = $task.Triggers
        $hasStartupTrigger = $triggers | Where-Object { $_.CimClass.CimClassName -eq "MSFT_TaskBootTrigger" }
        $hasLogonTrigger = $triggers | Where-Object { $_.CimClass.CimClassName -eq "MSFT_TaskLogonTrigger" }
        
        if ($hasStartupTrigger) {
            Write-TestLog "✓ Boot trigger configured" "SUCCESS"
        } else {
            Write-TestLog "FAIL: Boot trigger missing" "ERROR"
            return $false
        }
        
        if ($hasLogonTrigger) {
            Write-TestLog "✓ Logon trigger configured" "SUCCESS"
        } else {
            Write-TestLog "FAIL: Logon trigger missing" "ERROR"
            return $false
        }
        
        # Check action
        $action = $task.Actions[0]
        if ($action.Execute -match "pwsh|powershell") {
            Write-TestLog "✓ Task action uses PowerShell" "SUCCESS"
        } else {
            Write-TestLog "WARN: Task action doesn't use PowerShell: $($action.Execute)" "WARN"
        }
        
        # Check if action references the correct script
        if ($action.Arguments -match "MonitoringAgentAutoStart\.ps1") {
            Write-TestLog "✓ Task references enhanced auto-start script" "SUCCESS"
        } else {
            Write-TestLog "WARN: Task doesn't reference enhanced auto-start script" "WARN"
        }
        
        return $true
    }
    catch {
        Write-TestLog "ERROR: Failed to test scheduled task: $_" "ERROR"
        return $false
    }
}

function Test-WatchdogService {
    Write-TestLog "Testing watchdog service..." "TEST"
    
    try {
        $service = Get-Service -Name $Script:TestConfig.WatchdogServiceName -ErrorAction SilentlyContinue
        
        if (!$service) {
            Write-TestLog "INFO: Watchdog service not installed (optional)" "INFO"
            return $true  # Not required for basic functionality
        }
        
        Write-TestLog "✓ Watchdog service exists" "SUCCESS"
        
        if ($service.Status -eq "Running") {
            Write-TestLog "✓ Watchdog service is running" "SUCCESS"
        } else {
            Write-TestLog "WARN: Watchdog service is not running ($($service.Status))" "WARN"
        }
        
        if ($service.StartType -eq "Automatic") {
            Write-TestLog "✓ Watchdog service set to automatic start" "SUCCESS"
        } else {
            Write-TestLog "WARN: Watchdog service start type is '$($service.StartType)'" "WARN"
        }
        
        return $true
    }
    catch {
        Write-TestLog "ERROR: Failed to test watchdog service: $_" "ERROR"
        return $false
    }
}

function Test-AutoStartScriptFunctionality {
    Write-TestLog "Testing auto-start script functionality..." "TEST"
    
    try {
        $pwshPath = Get-PowerShellExe
        if (!$pwshPath) {
            Write-TestLog "ERROR: PowerShell executable not found" "ERROR"
            return $false
        }
        
        # Test script syntax
        Write-TestLog "Checking auto-start script syntax..." "DEBUG"
        $syntaxResult = & $pwshPath -NoProfile -NoLogo -Command "try { . '$Script:AutoStartScript'; Write-Output 'OK' } catch { Write-Output `$_.Exception.Message }"
        
        if ($syntaxResult -eq "OK") {
            Write-TestLog "✓ Auto-start script syntax is valid" "SUCCESS"
        } else {
            Write-TestLog "ERROR: Auto-start script syntax error: $syntaxResult" "ERROR"
            return $false
        }
        
        # Test script in test mode
        Write-TestLog "Running auto-start script in test mode..." "DEBUG"
        $testArgs = @(
            "-NoProfile"
            "-ExecutionPolicy", "Bypass"
            "-File", $Script:AutoStartScript
            "test"
        )
        
        $testProcess = Start-Process -FilePath $pwshPath -ArgumentList $testArgs -WorkingDirectory $Script:AgentPath -WindowStyle Hidden -PassThru -Wait
        
        if ($testProcess.ExitCode -eq 0) {
            Write-TestLog "✓ Auto-start script test mode passed" "SUCCESS"
        } else {
            Write-TestLog "WARN: Auto-start script test mode failed (exit code: $($testProcess.ExitCode))" "WARN"
        }
        
        return $true
    }
    catch {
        Write-TestLog "ERROR: Failed to test auto-start script: $_" "ERROR"
        return $false
    }
}

function Test-ServiceStatus {
    Write-TestLog "Testing current service status..." "TEST"
    
    try {
        # Get current status using the control script
        $pwshPath = Get-PowerShellExe
        if (!$pwshPath) {
            Write-TestLog "ERROR: PowerShell executable not found" "ERROR"
            return $false
        }
        
        $statusArgs = @(
            "-NoProfile"
            "-ExecutionPolicy", "Bypass"
            "-File", $Script:ControlScript
            "status"
        )
        
        Write-TestLog "Getting service status..." "DEBUG"
        $statusProcess = Start-Process -FilePath $pwshPath -ArgumentList $statusArgs -WorkingDirectory $Script:AgentPath -WindowStyle Hidden -PassThru -Wait
        
        if ($statusProcess.ExitCode -eq 0) {
            Write-TestLog "✓ Status command executed successfully" "SUCCESS"
        } else {
            Write-TestLog "WARN: Status command failed (exit code: $($statusProcess.ExitCode))" "WARN"
        }
        
        # Check for running processes
        $agentProcesses = Get-Process -Name "monitoring-agent" -ErrorAction SilentlyContinue
        $suricataProcesses = Get-Process -Name "suricata" -ErrorAction SilentlyContinue
        
        Write-TestLog "Current process status:" "INFO"
        Write-TestLog "  Monitoring Agent processes: $($agentProcesses.Count)" "INFO"
        Write-TestLog "  Suricata processes: $($suricataProcesses.Count)" "INFO"
        
        return $true
    }
    catch {
        Write-TestLog "ERROR: Failed to test service status: $_" "ERROR"
        return $false
    }
}

function Test-StartupSimulation {
    Write-TestLog "Testing startup simulation..." "TEST"
    
    try {
        $pwshPath = Get-PowerShellExe
        if (!$pwshPath) {
            Write-TestLog "ERROR: PowerShell executable not found" "ERROR"
            return $false
        }
        
        # Stop services first
        Write-TestLog "Stopping services for startup test..." "DEBUG"
        $stopArgs = @(
            "-NoProfile"
            "-ExecutionPolicy", "Bypass"
            "-File", $Script:ControlScript
            "stop"
        )
        
        $stopProcess = Start-Process -FilePath $pwshPath -ArgumentList $stopArgs -WorkingDirectory $Script:AgentPath -WindowStyle Hidden -PassThru -Wait
        Start-Sleep -Seconds 5
        
        # Simulate startup
        Write-TestLog "Simulating system startup..." "DEBUG"
        $startupArgs = @(
            "-NoProfile"
            "-ExecutionPolicy", "Bypass"
            "-File", $Script:AutoStartScript
            "startup"
            "-NoWait"
        )
        
        $startupProcess = Start-Process -FilePath $pwshPath -ArgumentList $startupArgs -WorkingDirectory $Script:AgentPath -WindowStyle Hidden -PassThru -Wait
        
        if ($startupProcess.ExitCode -eq 0) {
            Write-TestLog "✓ Startup simulation completed" "SUCCESS"
        } else {
            Write-TestLog "ERROR: Startup simulation failed (exit code: $($startupProcess.ExitCode))" "ERROR"
            return $false
        }
        
        # Wait for services to start
        Write-TestLog "Waiting for services to start..." "DEBUG"
        Start-Sleep -Seconds $Script:TestConfig.HealthCheckDelay
        
        # Verify services started
        $agentProcesses = Get-Process -Name "monitoring-agent" -ErrorAction SilentlyContinue
        if ($agentProcesses) {
            Write-TestLog "✓ Monitoring Agent started after simulation" "SUCCESS"
        } else {
            Write-TestLog "ERROR: Monitoring Agent did not start after simulation" "ERROR"
            return $false
        }
        
        return $true
    }
    catch {
        Write-TestLog "ERROR: Failed startup simulation: $_" "ERROR"
        return $false
    }
}

function Repair-AutoStartup {
    Write-TestLog "Repairing auto-startup configuration..." "INFO"
    
    try {
        $pwshPath = Get-PowerShellExe
        if (!$pwshPath) {
            Write-TestLog "ERROR: PowerShell executable not found" "ERROR"
            return $false
        }
        
        # Reinstall auto-startup tasks
        Write-TestLog "Reinstalling auto-startup tasks..." "INFO"
        $installArgs = @(
            "-NoProfile"
            "-ExecutionPolicy", "Bypass"
            "-Command", "& '$Script:ControlScript' stop; `$status = Get-AgentStatus; if (`$status.AutoStartupEnabled) { Remove-AutoStartupTasks; }; Install-AutoStartupTasks; Start-AutoStartupTasks"
        )
        
        $installProcess = Start-Process -FilePath $pwshPath -ArgumentList $installArgs -WorkingDirectory $Script:AgentPath -WindowStyle Hidden -PassThru -Wait
        
        if ($installProcess.ExitCode -eq 0) {
            Write-TestLog "✓ Auto-startup tasks reinstalled" "SUCCESS"
        } else {
            Write-TestLog "ERROR: Failed to reinstall auto-startup tasks" "ERROR"
            return $false
        }
        
        # Install watchdog service if available
        if (Test-Path $Script:WatchdogScript) {
            Write-TestLog "Installing watchdog service..." "INFO"
            
            $watchdogArgs = @(
                "-NoProfile"
                "-ExecutionPolicy", "Bypass"
                "-File", $Script:WatchdogScript
                "-Install"
            )
            
            $watchdogProcess = Start-Process -FilePath $pwshPath -ArgumentList $watchdogArgs -WorkingDirectory $Script:AgentPath -WindowStyle Hidden -PassThru -Wait
            
            if ($watchdogProcess.ExitCode -eq 0) {
                Write-TestLog "✓ Watchdog service installed" "SUCCESS"
                
                # Start watchdog service
                $startWatchdogArgs = @(
                    "-NoProfile"
                    "-ExecutionPolicy", "Bypass"
                    "-File", $Script:WatchdogScript
                    "-Start"
                )
                
                Start-Process -FilePath $pwshPath -ArgumentList $startWatchdogArgs -WorkingDirectory $Script:AgentPath -WindowStyle Hidden -PassThru -Wait | Out-Null
            } else {
                Write-TestLog "WARN: Failed to install watchdog service" "WARN"
            }
        }
        
        Write-TestLog "Auto-startup repair completed" "SUCCESS"
        return $true
    }
    catch {
        Write-TestLog "ERROR: Auto-startup repair failed: $_" "ERROR"
        return $false
    }
}

function Start-QuickTest {
    Write-TestLog "=== QUICK AUTO-STARTUP TEST ===" "TEST"
    
    $results = @{
        FilesPresent = Test-RequiredFiles
        TaskConfig = Test-ScheduledTaskConfiguration
        ScriptTest = Test-AutoStartScriptFunctionality
        ServiceStatus = Test-ServiceStatus
    }
    
    # Summary
    Write-TestLog "=== QUICK TEST RESULTS ===" "INFO"
    $passed = 0
    $total = 0
    
    foreach ($testName in $results.Keys) {
        $total++
        if ($results[$testName]) {
            $passed++
            Write-TestLog "✓ ${testName}: PASSED" "SUCCESS"
        } else {
            Write-TestLog "✗ ${testName}: FAILED" "ERROR"
        }
    }
    
    Write-TestLog "Quick test completed: $passed/$total tests passed" "INFO"
    return ($passed -eq $total)
}

function Start-FullTest {
    Write-TestLog "=== COMPREHENSIVE AUTO-STARTUP TEST ===" "TEST"
    
    $results = @{
        FilesPresent = Test-RequiredFiles
        TaskConfig = Test-ScheduledTaskConfiguration
        WatchdogService = Test-WatchdogService
        ScriptTest = Test-AutoStartScriptFunctionality
        ServiceStatus = Test-ServiceStatus
        StartupSimulation = Test-StartupSimulation
    }
    
    # Summary
    Write-TestLog "=== FULL TEST RESULTS ===" "INFO"
    $passed = 0
    $total = 0
    
    foreach ($testName in $results.Keys) {
        $total++
        if ($results[$testName]) {
            $passed++
            Write-TestLog "✓ ${testName}: PASSED" "SUCCESS"
        } else {
            Write-TestLog "✗ ${testName}: FAILED" "ERROR"
        }
    }
    
    Write-TestLog "Full test completed: $passed/$total tests passed" "INFO"
    
    if ($passed -lt $total) {
        Write-TestLog "Some tests failed. Consider running with -Repair to fix issues." "WARN"
    }
    
    return ($passed -eq $total)
}
#endregion

#region Main Execution
function Main {
    if (!(Test-AdminRights)) {
        Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
        exit 1
    }
    
    Write-TestLog "Monitoring Agent Auto-Startup Test Script v1.0.0" "INFO"
    Write-TestLog "Working Directory: $Script:AgentPath" "DEBUG"
    
    # Check required files
    $fileCheck = Test-RequiredFiles
    if (!$fileCheck.AllPresent) {
        Write-TestLog "ERROR: Missing required files:" "ERROR"
        foreach ($file in $fileCheck.Missing) {
            Write-TestLog "  - $file" "ERROR"
        }
        exit 1
    }
    
    $success = $false
    
    if ($Repair) {
        Write-TestLog "=== REPAIR MODE ===" "INFO"
        $success = Repair-AutoStartup
    }
    elseif ($Quick) {
        $success = Start-QuickTest
    }
    elseif ($Full) {
        $success = Start-FullTest
    }
    else {
        # Default: Quick test
        $success = Start-QuickTest
    }
    
    if ($success) {
        Write-TestLog "All tests completed successfully!" "SUCCESS"
        exit 0
    } else {
        Write-TestLog "Some tests failed. Check the log for details." "ERROR"
        exit 1
    }
}

# Execute main function
Main
#endregion