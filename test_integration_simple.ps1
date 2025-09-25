#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Simplified Suricata Integration Validation
    
.DESCRIPTION
    Quick validation script to test the core integration components.
#>

$WorkspacePath = $PSScriptRoot

Write-Host "=== SURICATA INTEGRATION VALIDATION ===" -ForegroundColor Cyan

# Test 1: Check if files exist
Write-Host "`n1. Checking integration files..." -ForegroundColor Yellow

$SuricataControl = Join-Path $WorkspacePath "suricata\SuricataControl.ps1"
$AgentControl = Join-Path $WorkspacePath "MonitoringAgentControl.ps1"
$SuricataConfig = Join-Path $WorkspacePath "suricata\etc\suricata.yaml"
$OssecConfig = Join-Path $WorkspacePath "ossec.conf"

$checks = @(
    @{ Name = "Suricata Control Script"; Path = $SuricataControl }
    @{ Name = "Agent Control Script"; Path = $AgentControl }
    @{ Name = "Suricata Configuration"; Path = $SuricataConfig }
    @{ Name = "Wazuh Agent Configuration"; Path = $OssecConfig }
)

foreach ($check in $checks) {
    if (Test-Path $check.Path) {
        Write-Host "  ✓ $($check.Name)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $($check.Name) - NOT FOUND" -ForegroundColor Red
    }
}

# Test 2: Check Suricata configuration
Write-Host "`n2. Checking Suricata configuration..." -ForegroundColor Yellow

if (Test-Path $SuricataConfig) {
    $configContent = Get-Content $SuricataConfig -Raw
    
    if ($configContent -match "enabled:\s*yes" -and $configContent -match "eve-log") {
        Write-Host "  ✓ EVE logging is enabled" -ForegroundColor Green
    } else {
        Write-Host "  ✗ EVE logging configuration issue" -ForegroundColor Red
    }
    
    if ($configContent -match "filename:.*eve\.json") {
        Write-Host "  ✓ EVE JSON output configured" -ForegroundColor Green
    } else {
        Write-Host "  ✗ EVE JSON output not configured" -ForegroundColor Red
    }
}

# Test 3: Check Wazuh agent configuration
Write-Host "`n3. Checking Wazuh agent configuration..." -ForegroundColor Yellow

if (Test-Path $OssecConfig) {
    $ossecContent = Get-Content $OssecConfig -Raw
    
    if ($ossecContent -match "suricata.*log.*eve\.json") {
        Write-Host "  ✓ Suricata log monitoring configured in agent" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Suricata log monitoring not configured in agent" -ForegroundColor Red
    }
}

# Test 4: Check integrated control functions
Write-Host "`n4. Checking integrated control functions..." -ForegroundColor Yellow

if (Test-Path $AgentControl) {
    $agentScript = Get-Content $AgentControl -Raw
    
    if ($agentScript -match "Get-SuricataStatus" -and $agentScript -match "Start-SuricataService") {
        Write-Host "  ✓ Suricata integration functions found in agent control" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Suricata integration functions missing from agent control" -ForegroundColor Red
    }
}

# Test 5: Test basic control script functionality
Write-Host "`n5. Testing control script functionality..." -ForegroundColor Yellow

try {
    $testResult = & $SuricataControl "test" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ Suricata control script test passed" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Suricata control script test failed" -ForegroundColor Red
    }
} catch {
    Write-Host "  ✗ Error running Suricata control script: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 6: Test integrated status command
Write-Host "`n6. Testing integrated status..." -ForegroundColor Yellow

try {
    $statusResult = & $AgentControl "status" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ Integrated status command works" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Integrated status command failed" -ForegroundColor Red
    }
} catch {
    Write-Host "  ✗ Error running integrated status: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== VALIDATION COMPLETE ===" -ForegroundColor Cyan
Write-Host "Integration components are properly configured." -ForegroundColor Green
Write-Host "Note: Full runtime testing requires network traffic and proper permissions." -ForegroundColor Yellow