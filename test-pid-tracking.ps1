# Test script to verify auto-start PID tracking
param([string]$TestType = "manual")

Write-Host "=== PID Tracking Test ==="
Write-Host "Test Type: $TestType"
Write-Host "Current User: $env:USERNAME"
Write-Host "Current Time: $(Get-Date)"

# Check current agent status
$pidFile = "c:\Users\ANANDHU\Downloads\monitoring-agent-windows\monitoring-agent.pid"
$currentPid = $null

if (Test-Path $pidFile) {
    $currentPid = Get-Content $pidFile
    Write-Host "PID file contains: $currentPid"
    
    # Check if this process exists
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $currentPid" -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "Process $currentPid is running: $($process.Name)"
    } else {
        Write-Host "Process $currentPid is NOT running (stale PID file)"
    }
} else {
    Write-Host "No PID file found"
}

# Start the agent using the control script
Write-Host "`nStarting agent..."
try {
    $result = & "c:\Users\ANANDHU\Downloads\monitoring-agent-windows\MonitoringAgentControl.ps1" start
    Write-Host "Start command completed"
} catch {
    Write-Host "Error starting agent: $_"
}

# Check the PID file after start
Start-Sleep -Seconds 2
if (Test-Path $pidFile) {
    $newPid = Get-Content $pidFile
    Write-Host "`nAfter start - PID file contains: $newPid"
    
    # Check if this process exists
    $newProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $newPid" -ErrorAction SilentlyContinue
    if ($newProcess) {
        Write-Host "New process $newPid is running: $($newProcess.Name), started: $($newProcess.CreationDate)"
        Write-Host "TEST RESULT: PID tracking SUCCESSFUL"
    } else {
        Write-Host "New process $newPid is NOT running"
        Write-Host "TEST RESULT: PID tracking FAILED"
    }
} else {
    Write-Host "No PID file found after start"
    Write-Host "TEST RESULT: PID tracking FAILED"
}

Write-Host "`n=== Test Complete ==="