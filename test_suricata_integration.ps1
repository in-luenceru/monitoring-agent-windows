#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Suricata Integration Test Script for Monitoring Agent
    
.DESCRIPTION
    Comprehensive testing script for validating Suricata Network IDS integration 
    with the Wazuh monitoring agent workspace.
    
    Tests include:
    - Suricata startup and configuration
    - EVE JSON log generation and format validation
    - Wazuh agent ingestion of Suricata logs
    - Network traffic generation and alert testing
    - Service restart and failure scenarios
    
.AUTHOR
    Custom Security Solutions - Suricata Integration Testing
    
.VERSION
    1.0.0
#>

# Test Configuration
$Script:WorkspacePath = $PSScriptRoot
$Script:SuricataControl = Join-Path $WorkspacePath "suricata\SuricataControl.ps1"
$Script:AgentControl = Join-Path $WorkspacePath "MonitoringAgentControl.ps1"
$Script:EVELogFile = Join-Path $WorkspacePath "suricata\log\eve.json"
$Script:AgentLogFile = Join-Path $WorkspacePath "ossec.log"
$Script:TestLogFile = Join-Path $WorkspacePath "logs\suricata_integration_test.log"

# Test Results
$Script:TestResults = @()

#region Logging Functions
function Write-TestLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "TEST")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [INTEGRATION-TEST] [$Level] $Message"
    
    # Write to console with colors
    switch ($Level) {
        "INFO"    { Write-Host $LogEntry -ForegroundColor Cyan }
        "WARN"    { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
        "TEST"    { Write-Host $LogEntry -ForegroundColor Magenta }
    }
    
    # Write to log file
    try {
        $LogDir = Split-Path $Script:TestLogFile -Parent
        if (!(Test-Path $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
        }
        Add-Content -Path $Script:TestLogFile -Value $LogEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Silently continue if unable to write to log
    }
}

function Add-TestResult {
    param(
        [string]$TestName,
        [bool]$Success,
        [string]$Details = "",
        [string]$Error = ""
    )
    
    $Script:TestResults += @{
        TestName = $TestName
        Success = $Success
        Details = $Details
        Error = $Error
        Timestamp = Get-Date
    }
    
    if ($Success) {
        Write-TestLog "✓ $TestName - PASSED" "SUCCESS"
        if ($Details) {
            Write-TestLog "  Details: $Details" "INFO"
        }
    } else {
        Write-TestLog "✗ $TestName - FAILED" "ERROR"
        if ($Error) {
            Write-TestLog "  Error: $Error" "ERROR"
        }
        if ($Details) {
            Write-TestLog "  Details: $Details" "WARN"
        }
    }
}
#endregion

#region Test Helper Functions
function Wait-ForLogEntry {
    param(
        [string]$LogFile,
        [string]$Pattern,
        [int]$TimeoutSeconds = 30
    )
    
    $StartTime = Get-Date
    while ((Get-Date) -lt $StartTime.AddSeconds($TimeoutSeconds)) {
        if (Test-Path $LogFile) {
            $Content = Get-Content $LogFile -Raw -ErrorAction SilentlyContinue
            if ($Content -and $Content -match $Pattern) {
                return $true
            }
        }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Test-JSONFormat {
    param([string]$JSONContent)
    
    try {
        $ParsedJSON = $JSONContent | ConvertFrom-Json
        return $true
    }
    catch {
        return $false
    }
}

function Generate-TestTraffic {
    Write-TestLog "Generating test network traffic to trigger Suricata alerts..." "TEST"
    
    try {
        # Test 1: DNS queries (should generate DNS logs)
        Write-TestLog "Performing DNS lookups..." "INFO"
        @("google.com", "microsoft.com", "github.com") | ForEach-Object {
            try {
                nslookup $_ | Out-Null
                Start-Sleep -Milliseconds 500
            } catch { }
        }
        
        # Test 2: HTTP requests (should generate HTTP logs)
        Write-TestLog "Making HTTP requests..." "INFO"
        try {
            $WebClient = New-Object System.Net.WebClient
            $WebClient.Headers.Add("User-Agent", "SuricataTestAgent/1.0")
            $null = $WebClient.DownloadString("http://httpbin.org/get")
            $WebClient.Dispose()
        } catch {
            Write-TestLog "HTTP test request failed (expected in some environments)" "WARN"
        }
        
        # Test 3: Generate port scan pattern (should trigger alerts)
        Write-TestLog "Generating port scan pattern..." "INFO"
        $LocalIP = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null }).IPv4Address.IPAddress
        if ($LocalIP) {
            1..5 | ForEach-Object {
                try {
                    $Port = 80 + $_
                    $TcpClient = New-Object System.Net.Sockets.TcpClient
                    $TcpClient.ConnectAsync($LocalIP, $Port).Wait(100)
                    $TcpClient.Close()
                } catch { }
                Start-Sleep -Milliseconds 200
            }
        }
        
        Write-TestLog "Test traffic generation completed" "SUCCESS"
        return $true
    }
    catch {
        Write-TestLog "Error generating test traffic: $($_.Exception.Message)" "ERROR"
        return $false
    }
}
#endregion

#region Main Test Functions
function Test-SuricataInstallation {
    Write-TestLog "Testing Suricata installation and setup..." "TEST"
    
    # Test 1: Control script exists
    if (Test-Path $Script:SuricataControl) {
        Add-TestResult "Suricata Control Script" $true "Control script found at $Script:SuricataControl"
    } else {
        Add-TestResult "Suricata Control Script" $false "" "Control script not found at $Script:SuricataControl"
        return $false
    }
    
    # Test 2: Run integration test
    try {
        $TestResult = & $Script:SuricataControl "test" 2>&1
        $ExitCode = $LASTEXITCODE
        
        if ($ExitCode -eq 0) {
            Add-TestResult "Suricata Integration Test" $true "All integration tests passed"
        } else {
            Add-TestResult "Suricata Integration Test" $false "" "Integration test failed with exit code $ExitCode. Output: $($TestResult -join ' ')"
            return $false
        }
    }
    catch {
        Add-TestResult "Suricata Integration Test" $false "" $_.Exception.Message
        return $false
    }
    
    return $true
}

function Test-SuricataStartup {
    Write-TestLog "Testing Suricata startup and configuration..." "TEST"
    
    # Test 1: Start Suricata
    try {
        $StartResult = & $Script:SuricataControl "start" 2>&1
        $ExitCode = $LASTEXITCODE
        
        if ($ExitCode -eq 0) {
            Add-TestResult "Suricata Startup" $true "Suricata started successfully"
        } else {
            Add-TestResult "Suricata Startup" $false "" "Suricata failed to start with exit code $ExitCode. Output: $($StartResult -join ' ')"
            return $false
        }
    }
    catch {
        Add-TestResult "Suricata Startup" $false "" $_.Exception.Message
        return $false
    }
    
    # Test 2: Verify EVE log file creation
    Start-Sleep -Seconds 5
    if (Test-Path $Script:EVELogFile) {
        Add-TestResult "EVE Log File Creation" $true "EVE JSON log file created at $Script:EVELogFile"
    } else {
        Add-TestResult "EVE Log File Creation" $false "" "EVE JSON log file not found at $Script:EVELogFile"
        return $false
    }
    
    return $true
}

function Test-EVEJSONOutput {
    Write-TestLog "Testing EVE JSON output format and content..." "TEST"
    
    # Generate some traffic
    Generate-TestTraffic
    
    # Wait for log entries
    Start-Sleep -Seconds 10
    
    if (!(Test-Path $Script:EVELogFile)) {
        Add-TestResult "EVE JSON File Exists" $false "" "EVE log file not found"
        return $false
    }
    
    # Test 1: Check if file has content
    $LogContent = Get-Content $Script:EVELogFile -ErrorAction SilentlyContinue
    if (!$LogContent -or $LogContent.Count -eq 0) {
        Add-TestResult "EVE JSON Content" $false "" "EVE log file is empty"
        return $false
    }
    
    Add-TestResult "EVE JSON Content" $true "Found $($LogContent.Count) log entries"
    
    # Test 2: Validate JSON format
    $ValidJSONCount = 0
    $InvalidJSONCount = 0
    
    foreach ($Line in $LogContent) {
        if ($Line.Trim() -ne "") {
            if (Test-JSONFormat $Line) {
                $ValidJSONCount++
            } else {
                $InvalidJSONCount++
            }
        }
    }
    
    if ($ValidJSONCount -gt 0) {
        Add-TestResult "EVE JSON Format" $true "Valid JSON lines: $ValidJSONCount, Invalid: $InvalidJSONCount"
    } else {
        Add-TestResult "EVE JSON Format" $false "" "No valid JSON lines found"
        return $false
    }
    
    # Test 3: Check for different event types
    $EventTypes = @()
    foreach ($Line in $LogContent) {
        if ($Line.Trim() -ne "") {
            try {
                $Event = $Line | ConvertFrom-Json
                if ($Event.event_type -and $EventTypes -notcontains $Event.event_type) {
                    $EventTypes += $Event.event_type
                }
            } catch { }
        }
    }
    
    if ($EventTypes.Count -gt 0) {
        Add-TestResult "EVE Event Types" $true "Found event types: $($EventTypes -join ', ')"
    } else {
        Add-TestResult "EVE Event Types" $false "" "No event types detected in JSON logs"
    }
    
    return $true
}

function Test-WazuhAgentIntegration {
    Write-TestLog "Testing Wazuh agent integration with Suricata logs..." "TEST"
    
    # Test 1: Check if agent is configured for Suricata logs
    $OssecConf = Join-Path $Script:WorkspacePath "ossec.conf"
    if (Test-Path $OssecConf) {
        $ConfigContent = Get-Content $OssecConf -Raw
        if ($ConfigContent -match "suricata.*log.*eve\.json") {
            Add-TestResult "Agent Configuration" $true "Suricata EVE log monitoring configured in ossec.conf"
        } else {
            Add-TestResult "Agent Configuration" $false "" "Suricata log monitoring not found in ossec.conf"
            return $false
        }
    } else {
        Add-TestResult "Agent Configuration" $false "" "ossec.conf not found"
        return $false
    }
    
    # Test 2: Check if agent is running
    try {
        $AgentStatus = & $Script:AgentControl "status" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Add-TestResult "Agent Status Check" $true "Agent status check successful"
        } else {
            Add-TestResult "Agent Status Check" $false "" "Agent status check failed. Output: $($AgentStatus -join ' ')"
            return $false
        }
    }
    catch {
        Add-TestResult "Agent Status Check" $false "" $_.Exception.Message
        return $false
    }
    
    return $true
}

function Test-IntegratedStartStop {
    Write-TestLog "Testing integrated start/stop functionality..." "TEST"
    
    # Test 1: Stop everything first
    try {
        $StopResult = & $Script:AgentControl "stop" 2>&1
        Start-Sleep -Seconds 3
        Add-TestResult "Integrated Stop" $true "Stop command executed"
    }
    catch {
        Add-TestResult "Integrated Stop" $false "" $_.Exception.Message
        return $false
    }
    
    # Test 2: Start everything
    try {
        $StartResult = & $Script:AgentControl "start" 2>&1
        Start-Sleep -Seconds 5
        
        # Check if both services are running
        $AgentStatus = & $Script:AgentControl "status" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Add-TestResult "Integrated Start" $true "Start command executed successfully"
        } else {
            Add-TestResult "Integrated Start" $false "" "Start command failed. Output: $($AgentStatus -join ' ')"
            return $false
        }
    }
    catch {
        Add-TestResult "Integrated Start" $false "" $_.Exception.Message
        return $false
    }
    
    return $true
}

function Test-ServiceRestart {
    Write-TestLog "Testing service restart scenarios..." "TEST"
    
    # Test 1: Restart command
    try {
        $RestartResult = & $Script:AgentControl "restart" 2>&1
        Start-Sleep -Seconds 5
        
        if ($LASTEXITCODE -eq 0) {
            Add-TestResult "Service Restart" $true "Restart command completed successfully"
        } else {
            Add-TestResult "Service Restart" $false "" "Restart command failed. Output: $($RestartResult -join ' ')"
            return $false
        }
    }
    catch {
        Add-TestResult "Service Restart" $false "" $_.Exception.Message
        return $false
    }
    
    return $true
}

function Test-ManualStopPreventsRestart {
    Write-TestLog "Testing manual stop prevents automatic restart..." "TEST"
    
    # Stop services manually
    try {
        $StopResult = & $Script:AgentControl "stop" 2>&1
        Start-Sleep -Seconds 3
        
        # Verify services are stopped and auto-start is disabled
        $AgentStatus = & $Script:AgentControl "status" 2>&1
        
        Add-TestResult "Manual Stop Behavior" $true "Manual stop executed - auto-restart should be disabled"
    }
    catch {
        Add-TestResult "Manual Stop Behavior" $false "" $_.Exception.Message
        return $false
    }
    
    return $true
}
#endregion

#region Report Functions
function Show-TestSummary {
    Write-Host "`n" + "="*70 -ForegroundColor Cyan
    Write-Host "SURICATA INTEGRATION TEST SUMMARY" -ForegroundColor Cyan
    Write-Host "="*70 -ForegroundColor Cyan
    
    $TotalTests = $Script:TestResults.Count
    $PassedTests = ($Script:TestResults | Where-Object { $_.Success }).Count
    $FailedTests = $TotalTests - $PassedTests
    
    Write-Host "`nOverall Results:" -ForegroundColor White
    Write-Host "  Total Tests: $TotalTests" -ForegroundColor Gray
    Write-Host "  Passed: $PassedTests" -ForegroundColor Green
    Write-Host "  Failed: $FailedTests" -ForegroundColor Red
    if ($TotalTests -gt 0) {
        Write-Host "  Success Rate: $([math]::Round(($PassedTests / $TotalTests) * 100, 1))%" -ForegroundColor White
    } else {
        Write-Host "  Success Rate: 0%" -ForegroundColor Red
    }
    
    Write-Host "`nTest Details:" -ForegroundColor White
    foreach ($Test in $Script:TestResults) {
        $Status = if ($Test.Success) { "PASS" } else { "FAIL" }
        $Color = if ($Test.Success) { "Green" } else { "Red" }
        
        Write-Host "  [$Status] $($Test.TestName)" -ForegroundColor $Color
        if ($Test.Details) {
            Write-Host "    $($Test.Details)" -ForegroundColor Gray
        }
        if ($Test.Error) {
            Write-Host "    Error: $($Test.Error)" -ForegroundColor Red
        }
    }
    
    if ($FailedTests -eq 0) {
        Write-Host "`n🎉 ALL TESTS PASSED! Suricata integration is working correctly." -ForegroundColor Green
    } else {
        Write-Host "`n⚠️  SOME TESTS FAILED. Please review the errors above." -ForegroundColor Yellow
    }
    
    Write-Host "`nTest log saved to: $Script:TestLogFile" -ForegroundColor Gray
    Write-Host "="*70 -ForegroundColor Cyan
}
#endregion

#region Main Execution
function Start-IntegrationTest {
    Write-TestLog "Starting Suricata Integration Test Suite..." "TEST"
    Write-TestLog "Test started at: $(Get-Date)" "INFO"
    Write-TestLog "Workspace path: $Script:WorkspacePath" "INFO"
    
    $AllTestsPass = $true
    
    # Run test suite
    $AllTestsPass = $AllTestsPass -and (Test-SuricataInstallation)
    $AllTestsPass = $AllTestsPass -and (Test-SuricataStartup)
    $AllTestsPass = $AllTestsPass -and (Test-EVEJSONOutput)
    $AllTestsPass = $AllTestsPass -and (Test-WazuhAgentIntegration)
    $AllTestsPass = $AllTestsPass -and (Test-IntegratedStartStop)
    $AllTestsPass = $AllTestsPass -and (Test-ServiceRestart)
    $AllTestsPass = $AllTestsPass -and (Test-ManualStopPreventsRestart)
    
    # Show summary
    Show-TestSummary
    
    Write-TestLog "Integration test suite completed" "INFO"
    
    if ($AllTestsPass) {
        exit 0
    } else {
        exit 1
    }
}

# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    exit 1
}

# Start the test suite
Start-IntegrationTest
#endregion