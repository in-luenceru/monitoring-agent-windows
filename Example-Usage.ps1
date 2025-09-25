# Example usage script for MonitoringAgentControl.ps1
# This demonstrates how to use the control script in different scenarios

Write-Host "=== MONITORING AGENT CONTROL - USAGE EXAMPLES ===" -ForegroundColor Cyan

Write-Host "`n1. CHECKING CURRENT STATUS" -ForegroundColor Yellow
Write-Host "Command: .\MonitoringAgentControl.ps1 status" -ForegroundColor Gray

Write-Host "`n2. STARTING THE AGENT" -ForegroundColor Yellow
Write-Host "Command: .\MonitoringAgentControl.ps1 start" -ForegroundColor Gray

Write-Host "`n3. STOPPING THE AGENT" -ForegroundColor Yellow
Write-Host "Command: .\MonitoringAgentControl.ps1 stop" -ForegroundColor Gray

Write-Host "`n4. RESTARTING THE AGENT" -ForegroundColor Yellow
Write-Host "Command: .\MonitoringAgentControl.ps1 restart" -ForegroundColor Gray

Write-Host "`n5. ENROLLMENT PROCESS" -ForegroundColor Yellow
Write-Host "Command: .\MonitoringAgentControl.ps1 enroll" -ForegroundColor Gray
Write-Host "This will guide you through:" -ForegroundColor White
Write-Host "  - Setting manager IP address" -ForegroundColor Gray
Write-Host "  - Configuring manager port" -ForegroundColor Gray
Write-Host "  - Adding client key (plain or base64)" -ForegroundColor Gray
Write-Host "  - Updating configuration files" -ForegroundColor Gray

Write-Host "`n6. INTERACTIVE MODE" -ForegroundColor Yellow
Write-Host "Command: .\MonitoringAgentControl.ps1" -ForegroundColor Gray
Write-Host "Launches the full interactive menu with all options" -ForegroundColor White

Write-Host "`n=== ENROLLMENT EXAMPLE ===" -ForegroundColor Cyan
Write-Host "Manager IP: 192.168.1.100" -ForegroundColor White
Write-Host "Manager Port: 1514" -ForegroundColor White
Write-Host "Sample Client Key:" -ForegroundColor White
Write-Host "001 DESKTOP-IVBQT1T any 70fea647733e1339286489e9b4f6c132df186bbad13c74e43577268ecaa01990" -ForegroundColor Gray

Write-Host "`n=== AUTOMATION EXAMPLE ===" -ForegroundColor Cyan
Write-Host @"
# PowerShell script to automate agent management
`$AgentScript = ".\MonitoringAgentControl.ps1"

# Check if agent is running
`$Status = & `$AgentScript status
if (`$LASTEXITCODE -ne 0) {
    Write-Host "Starting agent..."
    & `$AgentScript start
} else {
    Write-Host "Agent is already running"
}

# Restart agent for maintenance
Write-Host "Performing maintenance restart..."
& `$AgentScript restart
"@ -ForegroundColor Gray

Write-Host "`n=== IMPORTANT NOTES ===" -ForegroundColor Red
Write-Host "- Run PowerShell as Administrator" -ForegroundColor Yellow
Write-Host "- Ensure script is in Monitoring agent directory" -ForegroundColor Yellow
Write-Host "- Have manager IP and client key ready for enrollment" -ForegroundColor Yellow
Write-Host "- Check firewall settings for manager connectivity" -ForegroundColor Yellow

Write-Host "`nTo get started, run: .\MonitoringAgentControl.ps1" -ForegroundColor Green