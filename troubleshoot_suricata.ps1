#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Suricata Integration Status and Troubleshooting Guide
    
.DESCRIPTION
    This script provides a comprehensive analysis of the Suricata integration 
    status and identifies specific issues that need to be resolved.
#>

$WorkspacePath = $PSScriptRoot

Write-Host "=== SURICATA INTEGRATION TROUBLESHOOTING ===" -ForegroundColor Yellow
Write-Host ""

# 1. Configuration Validation
Write-Host "1. Configuration Status:" -ForegroundColor Cyan

$configTest = $null
try {
    Set-Location "$WorkspacePath\suricata\bin"
    $configTest = & ".\suricata.exe" -T -c "..\etc\suricata.yaml" 2>&1
    $configSuccess = $LASTEXITCODE -eq 0
    Set-Location $WorkspacePath
    
    if ($configSuccess) {
        Write-Host "   ✓ Suricata configuration is VALID" -ForegroundColor Green
    } else {
        Write-Host "   ✗ Suricata configuration has ERRORS" -ForegroundColor Red
    }
} catch {
    Write-Host "   ✗ Error testing configuration: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. File System Status
Write-Host "`n2. File System Status:" -ForegroundColor Cyan

$checks = @{
    "Suricata Binary" = "$WorkspacePath\suricata\bin\suricata.exe"
    "Configuration File" = "$WorkspacePath\suricata\etc\suricata.yaml"
    "Classification Config" = "$WorkspacePath\suricata\etc\classification.config"
    "Rules Directory" = "$WorkspacePath\suricata\rules"
    "Log Directory" = "$WorkspacePath\suricata\log"
    "EVE JSON Log" = "$WorkspacePath\suricata\log\eve.json"
}

foreach ($check in $checks.GetEnumerator()) {
    if (Test-Path $check.Value) {
        Write-Host "   ✓ $($check.Key)" -ForegroundColor Green
    } else {
        Write-Host "   ✗ $($check.Key) - NOT FOUND" -ForegroundColor Red
    }
}

# 3. Network Interface Status
Write-Host "`n3. Network Interface Status:" -ForegroundColor Cyan

try {
    $interfaces = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    Write-Host "   Active Interfaces:" -ForegroundColor White
    foreach ($iface in $interfaces) {
        Write-Host "     - $($iface.Name): $($iface.InterfaceDescription)" -ForegroundColor Gray
    }
    
    if ($interfaces.Count -eq 0) {
        Write-Host "   ✗ No active network interfaces found" -ForegroundColor Red
    } else {
        Write-Host "   ✓ $($interfaces.Count) active interface(s) available" -ForegroundColor Green
    }
} catch {
    Write-Host "   ✗ Error checking network interfaces: $($_.Exception.Message)" -ForegroundColor Red
}

# 4. Npcap Status
Write-Host "`n4. Npcap and Packet Capture Status:" -ForegroundColor Cyan

# Check for Npcap DLLs
$npcapLocations = @(
    "$WorkspacePath\npcap\wpcap.dll",
    "$WorkspacePath\npcap\Packet.dll",
    "$WorkspacePath\suricata\bin\wpcap.dll",
    "$WorkspacePath\suricata\bin\packet.dll"
)

Write-Host "   Npcap DLL Locations:" -ForegroundColor White
foreach ($dll in $npcapLocations) {
    if (Test-Path $dll) {
        $fileInfo = Get-Item $dll
        Write-Host "     ✓ $dll ($($fileInfo.Length) bytes)" -ForegroundColor Green
    } else {
        Write-Host "     ✗ $dll - NOT FOUND" -ForegroundColor Red
    }
}

# Check for system-wide Npcap installation
$systemNpcap = "$env:SystemRoot\System32\wpcap.dll"
if (Test-Path $systemNpcap) {
    Write-Host "   ✓ System Npcap installation found" -ForegroundColor Green
} else {
    Write-Host "   ⚠ No system-wide Npcap installation detected" -ForegroundColor Yellow
}

# 5. Process Status
Write-Host "`n5. Process Status:" -ForegroundColor Cyan

$suricataProcs = Get-Process -Name "suricata" -ErrorAction SilentlyContinue
if ($suricataProcs) {
    Write-Host "   ✓ Suricata process(es) running:" -ForegroundColor Green
    foreach ($proc in $suricataProcs) {
        Write-Host "     - PID $($proc.Id): $($proc.ProcessName)" -ForegroundColor Gray
    }
} else {
    Write-Host "   ⚠ No Suricata processes currently running" -ForegroundColor Yellow
}

# 6. Log Analysis
Write-Host "`n6. Log File Analysis:" -ForegroundColor Cyan

$logFiles = @{
    "EVE JSON" = "$WorkspacePath\suricata\log\eve.json"
    "Suricata Main Log" = "$WorkspacePath\suricata\log\suricata.log"
    "Fast Log" = "$WorkspacePath\suricata\log\fast.log"
    "Stats Log" = "$WorkspacePath\suricata\log\stats.log"
}

foreach ($log in $logFiles.GetEnumerator()) {
    if (Test-Path $log.Value) {
        $fileInfo = Get-Item $log.Value
        if ($fileInfo.Length -gt 0) {
            Write-Host "   ✓ $($log.Key): $($fileInfo.Length) bytes" -ForegroundColor Green
        } else {
            Write-Host "   ⚠ $($log.Key): File exists but is empty" -ForegroundColor Yellow
        }
    } else {
        Write-Host "   ✗ $($log.Key): File not found" -ForegroundColor Red
    }
}

# 7. Recent Log Entries
if (Test-Path "$WorkspacePath\suricata\log\suricata.log") {
    Write-Host "`n7. Recent Suricata Log Entries:" -ForegroundColor Cyan
    $recentLogs = Get-Content "$WorkspacePath\suricata\log\suricata.log" -Tail 5 -ErrorAction SilentlyContinue
    if ($recentLogs) {
        foreach ($line in $recentLogs) {
            if ($line -match "Error|ERROR") {
                Write-Host "   ✗ $line" -ForegroundColor Red
            } elseif ($line -match "Warning|WARN") {
                Write-Host "   ⚠ $line" -ForegroundColor Yellow
            } else {
                Write-Host "   ℹ $line" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "   ⚠ No recent log entries found" -ForegroundColor Yellow
    }
}

# 8. Integration Status Summary
Write-Host "`n8. Integration Status Summary:" -ForegroundColor Cyan

$issues = @()
$warnings = @()

# Check critical issues
if (!(Test-Path "$WorkspacePath\suricata\bin\suricata.exe")) {
    $issues += "Suricata binary missing"
}

if (!(Test-Path "$WorkspacePath\suricata\etc\suricata.yaml")) {
    $issues += "Configuration file missing"
}

if (!$configSuccess) {
    $issues += "Configuration validation failed"
}

$activeInterfaces = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
if ($activeInterfaces.Count -eq 0) {
    $issues += "No active network interfaces"
}

# Check warnings
if (!(Test-Path "$env:SystemRoot\System32\wpcap.dll")) {
    $warnings += "No system-wide Npcap installation"
}

if (!(Test-Path "$WorkspacePath\suricata\log\eve.json") -or (Get-Item "$WorkspacePath\suricata\log\eve.json" -ErrorAction SilentlyContinue).Length -eq 0) {
    $warnings += "EVE JSON log is empty or missing"
}

if ($issues.Count -eq 0) {
    Write-Host "   ✓ No critical issues found" -ForegroundColor Green
} else {
    Write-Host "   ✗ Critical Issues:" -ForegroundColor Red
    foreach ($issue in $issues) {
        Write-Host "     - $issue" -ForegroundColor Red
    }
}

if ($warnings.Count -gt 0) {
    Write-Host "   ⚠ Warnings:" -ForegroundColor Yellow
    foreach ($warning in $warnings) {
        Write-Host "     - $warning" -ForegroundColor Yellow
    }
}

# 9. Recommendations
Write-Host "`n9. Recommended Actions:" -ForegroundColor Cyan

if ($issues.Count -eq 0 -and $warnings.Count -eq 0) {
    Write-Host "   🎉 Integration appears to be working correctly!" -ForegroundColor Green
    Write-Host "   Try generating network traffic and check EVE JSON log for events." -ForegroundColor White
} else {
    Write-Host "   📋 Next Steps:" -ForegroundColor White
    
    if ($issues -contains "Configuration validation failed") {
        Write-Host "     1. Fix configuration errors in suricata.yaml" -ForegroundColor Yellow
    }
    
    if ($warnings -contains "No system-wide Npcap installation") {
        Write-Host "     2. Consider installing Npcap system-wide for better compatibility" -ForegroundColor Yellow
    }
    
    if ($warnings -contains "EVE JSON log is empty or missing") {
        Write-Host "     3. Test Suricata startup and network traffic generation" -ForegroundColor Yellow
        Write-Host "        - Start Suricata: .\suricata\SuricataControl.ps1 start" -ForegroundColor Gray
        Write-Host "        - Generate traffic: ping google.com" -ForegroundColor Gray
        Write-Host "        - Check logs: Get-Content suricata\log\eve.json" -ForegroundColor Gray
    }
}

Write-Host "`n=== TROUBLESHOOTING COMPLETE ===" -ForegroundColor Yellow