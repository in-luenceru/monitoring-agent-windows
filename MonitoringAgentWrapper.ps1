#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Monitoring Agent Process Wrapper
.DESCRIPTION
    Wrapper script that starts the monitoring agent with custom process identification
#>

param(
    [string[]]$ArgumentList = @()
)

$AgentPath = $PSScriptRoot
$OriginalAgent = Join-Path $AgentPath "monitoring-agent.exe"

if (!(Test-Path $OriginalAgent)) {
    Write-Error "Monitoring agent executable not found: $OriginalAgent"
    exit 1
}

# Set process title to hide original identity
$Host.UI.RawUI.WindowTitle = "Monitoring Agent Service"

try {
    # Start the agent process with custom environment
    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = $OriginalAgent
    $ProcessInfo.Arguments = ($ArgumentList -join ' ')
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.CreateNoWindow = $true
    $ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    
    # Set environment variables to influence process identification
    $ProcessInfo.EnvironmentVariables["MONITORING_AGENT"] = "1"
    $ProcessInfo.EnvironmentVariables["SERVICE_NAME"] = "MonitoringAgent"
    
    $Process = [System.Diagnostics.Process]::Start($ProcessInfo)
    
    if ($Process) {
        Write-Host "Monitoring Agent started successfully (PID: $($Process.Id))"
        
        # Save PID to file for management
        $PidFile = Join-Path $AgentPath "monitoring-agent.pid"
        Set-Content -Path $PidFile -Value $Process.Id
        
        # Wait for process to exit
        $Process.WaitForExit()
        exit $Process.ExitCode
    }
    else {
        Write-Error "Failed to start monitoring agent"
        exit 1
    }
}
catch {
    Write-Error "Error starting monitoring agent: $($_.Exception.Message)"
    exit 1
}
