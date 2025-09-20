# Test script for WazuhAgentControl.ps1 functions
# This script tests individual functions without requiring admin privileges

# Import the main script functions
. .\WazuhAgentControl.ps1 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

Write-Host "=== WAZUH AGENT CONTROL - FUNCTION TESTS ===" -ForegroundColor Cyan

# Test IP validation
Write-Host "`nTesting IP validation..." -ForegroundColor Yellow
$TestIPs = @("192.168.1.1", "10.0.0.1", "invalid-ip", "google.com", "127.0.0.1")
foreach ($IP in $TestIPs) {
    $IsValid = Test-IPAddress $IP
    $Color = if ($IsValid) { "Green" } else { "Red" }
    Write-Host "  $IP : $IsValid" -ForegroundColor $Color
}

# Test Base64 validation
Write-Host "`nTesting Base64 validation..." -ForegroundColor Yellow
$TestBase64 = @(
    "SGVsbG8gV29ybGQ=",  # Valid: "Hello World"
    "invalid-base64",     # Invalid
    "MDAxIERFU0tUT1AtSVZCUVQxVCBhbnkgNzBmZWE2NDc3MzNlMTMzOTI4NjQ4OWU5YjRmNmMxMzJkZjE4NmJiYWQxM2M3NGU0MzU3NzI2OGVjYWEwMTk5MA=="  # Valid client key
)
foreach ($String in $TestBase64) {
    $IsValid = Test-Base64 $String
    $Color = if ($IsValid) { "Green" } else { "Red" }
    $DisplayString = if ($String.Length -gt 20) { $String.Substring(0, 20) + "..." } else { $String }
    Write-Host "  $DisplayString : $IsValid" -ForegroundColor $Color
}

# Test Base64 conversion
Write-Host "`nTesting Base64 conversion..." -ForegroundColor Yellow
$TestString = "001 DESKTOP-TEST any 1234567890abcdef"
$Encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($TestString))
Write-Host "  Original: $TestString" -ForegroundColor White
Write-Host "  Encoded:  $Encoded" -ForegroundColor Cyan
try {
    $Decoded = ConvertFrom-Base64 $Encoded
    Write-Host "  Decoded:  $Decoded" -ForegroundColor Green
} catch {
    Write-Host "  Decode Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test hostname validation
Write-Host "`nTesting hostname validation..." -ForegroundColor Yellow
$TestHosts = @("localhost", "google.com", "invalid-hostname-12345", "127.0.0.1")
foreach ($Hostname in $TestHosts) {
    try {
        $IsValid = Test-Hostname $Hostname
        $Color = if ($IsValid) { "Green" } else { "Red" }
        Write-Host "  $Hostname : $IsValid" -ForegroundColor $Color
    } catch {
        Write-Host "  $Hostname : Error - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Test file existence
Write-Host "`nTesting file existence..." -ForegroundColor Yellow
$TestFiles = @("wazuh-agent.exe", "ossec.conf", "client.keys", "nonexistent-file.txt")
foreach ($File in $TestFiles) {
    $Exists = Test-Path $File
    $Color = if ($Exists) { "Green" } else { "Red" }
    Write-Host "  $File : $Exists" -ForegroundColor $Color
}

Write-Host "`n=== TESTS COMPLETED ===" -ForegroundColor Cyan