#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Wazuh Windows Agent Control Script
    
.DESCRIPTION
    Professional control script for managing Wazuh Windows Agent
    Features:
    - Agent enrollment with manager IP and client key
    - Support for both plain text and base64 encoded client keys
    - Start, stop, restart, and status monitoring
    - Configuration file management
    - User-friendly interactive interface
    
.AUTHOR
    Custom Security Solutions
    
.VERSION
    1.0.0
    
.NOTES
    Requires Administrator privileges
#>

# Script Configuration
$Script:AgentPath = $PSScriptRoot
$Script:AgentExe = Join-Path $AgentPath "wazuh-agent.exe"
$Script:OssecConf = Join-Path $AgentPath "ossec.conf"
$Script:ClientKeys = Join-Path $AgentPath "client.keys"
$Script:LogFile = Join-Path $AgentPath "logs\agent-control.log"

# Ensure logs directory exists
$LogDir = Split-Path $Script:LogFile -Parent
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

#region Logging Functions
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Write to console with colors
    switch ($Level) {
        "INFO"    { Write-Host $LogEntry -ForegroundColor Cyan }
        "WARN"    { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
    }
    
    # Write to log file
    try {
        Add-Content -Path $Script:LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Silently continue if unable to write to log
    }
}
#endregion

#region Utility Functions
function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Base64 {
    param([string]$String)
    
    try {
        $null = [Convert]::FromBase64String($String)
        return $true
    }
    catch {
        return $false
    }
}

function ConvertFrom-Base64 {
    param([string]$Base64String)
    
    try {
        $bytes = [Convert]::FromBase64String($Base64String)
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    }
    catch {
        throw "Invalid Base64 string"
    }
}

function Backup-ConfigFile {
    param([string]$FilePath)
    
    if (Test-Path $FilePath) {
        $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $BackupPath = "$FilePath.backup_$Timestamp"
        Copy-Item $FilePath $BackupPath
        Write-Log "Backup created: $BackupPath" "INFO"
        return $BackupPath
    }
    return $null
}

function Test-IPAddress {
    param([string]$IP)
    
    try {
        $ipAddress = [System.Net.IPAddress]::Parse($IP)
        return $true
    }
    catch {
        return $false
    }
}

function Test-Hostname {
    param([string]$Hostname)
    
    try {
        $null = [System.Net.Dns]::GetHostEntry($Hostname)
        return $true
    }
    catch {
        return $false
    }
}
#endregion

#region Agent Control Functions
function Get-AgentStatus {
    Write-Log "Checking agent status..." "INFO"
    
    try {
        # Check if agent process is running
        $AgentProcess = Get-Process -Name "wazuh-agent" -ErrorAction SilentlyContinue
        
        if ($AgentProcess) {
            Write-Log "Agent process is running (PID: $($AgentProcess.Id))" "SUCCESS"
            
            # Check agent state file for connection status
            $StateFile = Join-Path $Script:AgentPath "wazuh-agent.state"
            if (Test-Path $StateFile) {
                $StateContent = Get-Content $StateFile -ErrorAction SilentlyContinue
                Write-Log "Agent state: $StateContent" "INFO"
            }
            
            # Check recent log entries for connectivity
            $LogPath = Join-Path $Script:AgentPath "logs\ossec.log"
            if (Test-Path $LogPath) {
                $RecentLogs = Get-Content $LogPath -Tail 5 -ErrorAction SilentlyContinue
                if ($RecentLogs -match "Connected to the server") {
                    Write-Log "Agent is connected to manager" "SUCCESS"
                    return @{
                        Running = $true
                        Connected = $true
                        ProcessId = $AgentProcess.Id
                    }
                }
                elseif ($RecentLogs -match "Unable to connect|Connection refused|Timeout") {
                    Write-Log "Agent is running but not connected to manager" "WARN"
                    return @{
                        Running = $true
                        Connected = $false
                        ProcessId = $AgentProcess.Id
                    }
                }
            }
            
            return @{
                Running = $true
                Connected = $null
                ProcessId = $AgentProcess.Id
            }
        }
        else {
            Write-Log "Agent is not running" "WARN"
            return @{
                Running = $false
                Connected = $false
                ProcessId = $null
            }
        }
    }
    catch {
        Write-Log "Error checking agent status: $($_.Exception.Message)" "ERROR"
        return @{
            Running = $false
            Connected = $false
            ProcessId = $null
        }
    }
}

function Start-WazuhAgent {
    Write-Log "Starting Wazuh agent..." "INFO"
    
    if (!(Test-Path $Script:AgentExe)) {
        Write-Log "Agent executable not found: $Script:AgentExe" "ERROR"
        return $false
    }
    
    try {
        $Status = Get-AgentStatus
        if ($Status.Running) {
            Write-Log "Agent is already running" "WARN"
            return $true
        }
        
        # Start the agent
        $Process = Start-Process -FilePath $Script:AgentExe -ArgumentList "start" -PassThru -NoNewWindow -Wait
        
        if ($Process.ExitCode -eq 0) {
            Start-Sleep -Seconds 3
            $NewStatus = Get-AgentStatus
            if ($NewStatus.Running) {
                Write-Log "Agent started successfully" "SUCCESS"
                return $true
            }
            else {
                Write-Log "Agent failed to start properly" "ERROR"
                return $false
            }
        }
        else {
            Write-Log "Agent failed to start (Exit Code: $($Process.ExitCode))" "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error starting agent: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Stop-WazuhAgent {
    Write-Log "Stopping Wazuh agent..." "INFO"
    
    try {
        $Status = Get-AgentStatus
        if (!$Status.Running) {
            Write-Log "Agent is not running" "WARN"
            return $true
        }
        
        # Try graceful shutdown first
        if (Test-Path $Script:AgentExe) {
            $Process = Start-Process -FilePath $Script:AgentExe -ArgumentList "stop" -PassThru -NoNewWindow -Wait
            Start-Sleep -Seconds 3
        }
        
        # Force kill if still running
        $AgentProcess = Get-Process -Name "wazuh-agent" -ErrorAction SilentlyContinue
        if ($AgentProcess) {
            $AgentProcess | Stop-Process -Force
            Write-Log "Agent process terminated forcefully" "WARN"
        }
        
        Start-Sleep -Seconds 2
        $NewStatus = Get-AgentStatus
        if (!$NewStatus.Running) {
            Write-Log "Agent stopped successfully" "SUCCESS"
            return $true
        }
        else {
            Write-Log "Failed to stop agent" "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error stopping agent: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Restart-WazuhAgent {
    Write-Log "Restarting Wazuh agent..." "INFO"
    
    if (Stop-WazuhAgent) {
        Start-Sleep -Seconds 2
        return Start-WazuhAgent
    }
    return $false
}
#endregion

#region Configuration Functions
function Update-OssecConfig {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ManagerIP,
        
        [Parameter(Mandatory=$false)]
        [string]$ManagerPort = "1514"
    )
    
    Write-Log "Updating ossec.conf with manager IP: $ManagerIP" "INFO"
    
    try {
        if (!(Test-Path $Script:OssecConf)) {
            Write-Log "ossec.conf not found: $Script:OssecConf" "ERROR"
            return $false
        }
        
        # Backup current config
        $BackupPath = Backup-ConfigFile $Script:OssecConf
        
        # Read current config
        $ConfigContent = Get-Content $Script:OssecConf -Raw
        
        # Update manager address
        $ConfigContent = $ConfigContent -replace '<address>.*?</address>', "<address>$ManagerIP</address>"
        $ConfigContent = $ConfigContent -replace '<port>.*?</port>', "<port>$ManagerPort</port>"
        
        # Write updated config
        Set-Content -Path $Script:OssecConf -Value $ConfigContent -Encoding UTF8
        
        Write-Log "ossec.conf updated successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error updating ossec.conf: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Update-ClientKeys {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ClientKey
    )
    
    Write-Log "Updating client.keys file" "INFO"
    
    try {
        # Backup current keys
        if (Test-Path $Script:ClientKeys) {
            $BackupPath = Backup-ConfigFile $Script:ClientKeys
        }
        
        # Write new client key
        Set-Content -Path $Script:ClientKeys -Value $ClientKey -Encoding UTF8
        
        Write-Log "client.keys updated successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error updating client.keys: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-UserInput {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Prompt,
        
        [Parameter(Mandatory=$false)]
        [bool]$Secure = $false,
        
        [Parameter(Mandatory=$false)]
        [string]$ValidationRegex = $null,
        
        [Parameter(Mandatory=$false)]
        [string]$ValidationErrorMessage = "Invalid input format"
    )
    
    do {
        if ($Secure) {
            $Input = Read-Host -Prompt $Prompt -AsSecureString
            $Input = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Input))
        }
        else {
            $Input = Read-Host -Prompt $Prompt
        }
        
        if ([string]::IsNullOrWhiteSpace($Input)) {
            Write-Host "Input cannot be empty. Please try again." -ForegroundColor Red
            continue
        }
        
        if ($ValidationRegex -and $Input -notmatch $ValidationRegex) {
            Write-Host $ValidationErrorMessage -ForegroundColor Red
            continue
        }
        
        return $Input.Trim()
    } while ($true)
}
#endregion

#region Enrollment Functions
function Start-AgentEnrollment {
    Write-Log "Starting agent enrollment process..." "INFO"
    
    Write-Host "`n=== WAZUH AGENT ENROLLMENT ===" -ForegroundColor Cyan
    Write-Host "This process will configure your agent to connect to a Wazuh manager.`n" -ForegroundColor Gray
    
    # Get Manager IP/Hostname
    do {
        $ManagerAddress = Get-UserInput -Prompt "Enter Wazuh Manager IP address or hostname"
        
        if (Test-IPAddress $ManagerAddress) {
            Write-Log "Valid IP address provided: $ManagerAddress" "SUCCESS"
            break
        }
        elseif (Test-Hostname $ManagerAddress) {
            Write-Log "Valid hostname provided: $ManagerAddress" "SUCCESS"
            break
        }
        else {
            Write-Host "Invalid IP address or hostname. Please try again." -ForegroundColor Red
        }
    } while ($true)
    
    # Get Manager Port (optional)
    Write-Host "`nManager port (default: 1514, press Enter to use default):" -ForegroundColor Gray
    $ManagerPort = Read-Host "Port"
    if ([string]::IsNullOrWhiteSpace($ManagerPort)) {
        $ManagerPort = "1514"
    }
    
    # Get Client Key
    Write-Host "`nClient Key Information:" -ForegroundColor Gray
    Write-Host "The client key should be in format: ID NAME IP KEY" -ForegroundColor Gray
    Write-Host "Example: 001 AGENT-001 any 1234567890abcdef..." -ForegroundColor Gray
    Write-Host "You can provide either plain text or base64 encoded key.`n" -ForegroundColor Gray
    
    $ClientKeyInput = Get-UserInput -Prompt "Enter client key" -Secure $true
    
    # Check if input is base64 encoded
    $ClientKey = $ClientKeyInput
    if (Test-Base64 $ClientKeyInput) {
        try {
            $DecodedKey = ConvertFrom-Base64 $ClientKeyInput
            Write-Host "`nDetected base64 encoded key. Do you want to use the decoded version? (y/n)" -ForegroundColor Yellow
            $UseDecoded = Read-Host
            if ($UseDecoded -eq 'y' -or $UseDecoded -eq 'Y') {
                $ClientKey = $DecodedKey
                Write-Log "Using decoded client key" "INFO"
            }
            else {
                Write-Log "Using original (base64) client key" "INFO"
            }
        }
        catch {
            Write-Log "Failed to decode base64 key, using as-is" "WARN"
        }
    }
    
    # Validate client key format
    if ($ClientKey -notmatch '^\d+\s+\S+\s+\S+\s+\S+') {
        Write-Host "Warning: Client key format may be invalid." -ForegroundColor Yellow
        Write-Host "Expected format: ID NAME IP KEY" -ForegroundColor Yellow
        $Continue = Read-Host "Continue anyway? (y/n)"
        if ($Continue -ne 'y' -and $Continue -ne 'Y') {
            Write-Log "Enrollment cancelled by user" "INFO"
            return $false
        }
    }
    
    # Show configuration summary
    Write-Host "`n=== ENROLLMENT SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Manager Address: $ManagerAddress" -ForegroundColor White
    Write-Host "Manager Port: $ManagerPort" -ForegroundColor White
    Write-Host "Client Key: [HIDDEN FOR SECURITY]" -ForegroundColor White
    
    $Confirm = Read-Host "`nProceed with enrollment? (y/n)"
    if ($Confirm -ne 'y' -and $Confirm -ne 'Y') {
        Write-Log "Enrollment cancelled by user" "INFO"
        return $false
    }
    
    # Stop agent if running
    $Status = Get-AgentStatus
    if ($Status.Running) {
        Write-Log "Stopping agent for configuration update..." "INFO"
        if (!(Stop-WazuhAgent)) {
            Write-Log "Failed to stop agent for enrollment" "ERROR"
            return $false
        }
    }
    
    # Update configuration files
    if (!(Update-OssecConfig -ManagerIP $ManagerAddress -ManagerPort $ManagerPort)) {
        Write-Log "Failed to update ossec.conf" "ERROR"
        return $false
    }
    
    if (!(Update-ClientKeys -ClientKey $ClientKey)) {
        Write-Log "Failed to update client.keys" "ERROR"
        return $false
    }
    
    Write-Log "Agent enrollment completed successfully!" "SUCCESS"
    
    # Ask if user wants to start the agent
    Write-Host "`nDo you want to start the agent now? (y/n)" -ForegroundColor Yellow
    $StartAgent = Read-Host
    if ($StartAgent -eq 'y' -or $StartAgent -eq 'Y') {
        if (Start-WazuhAgent) {
            Write-Host "`nAgent started successfully! Checking connection status..." -ForegroundColor Green
            Start-Sleep -Seconds 5
            Get-AgentStatus | Out-Null
        }
        else {
            Write-Host "`nFailed to start agent. Please check the logs." -ForegroundColor Red
        }
    }
    
    return $true
}
#endregion

#region Main Menu Functions
function Show-MainMenu {
    Clear-Host
    Write-Host @"

 ██╗    ██╗ █████╗ ███████╗██╗   ██╗██╗  ██╗
 ██║    ██║██╔══██╗╚══███╔╝██║   ██║██║  ██║
 ██║ █╗ ██║███████║  ███╔╝ ██║   ██║███████║
 ██║███╗██║██╔══██║ ███╔╝  ██║   ██║██╔══██║
 ╚███╔███╔╝██║  ██║███████╗╚██████╔╝██║  ██║
  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
                                             
      AGENT CONTROL CENTER v1.0.0
      
"@ -ForegroundColor Cyan

    # Show current status
    $Status = Get-AgentStatus
    Write-Host "Current Status:" -ForegroundColor White
    if ($Status.Running) {
        Write-Host "  Agent: " -NoNewline -ForegroundColor White
        Write-Host "RUNNING" -ForegroundColor Green
        Write-Host "  PID: $($Status.ProcessId)" -ForegroundColor Gray
        if ($Status.Connected -eq $true) {
            Write-Host "  Connection: " -NoNewline -ForegroundColor White
            Write-Host "CONNECTED" -ForegroundColor Green
        }
        elseif ($Status.Connected -eq $false) {
            Write-Host "  Connection: " -NoNewline -ForegroundColor White
            Write-Host "DISCONNECTED" -ForegroundColor Red
        }
        else {
            Write-Host "  Connection: " -NoNewline -ForegroundColor White
            Write-Host "UNKNOWN" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "  Agent: " -NoNewline -ForegroundColor White
        Write-Host "STOPPED" -ForegroundColor Red
    }
    
    Write-Host "`n" + "="*50 -ForegroundColor Gray
    Write-Host "MAIN MENU" -ForegroundColor Cyan
    Write-Host "="*50 -ForegroundColor Gray
    Write-Host "1. Enroll Agent (Configure Manager Connection)" -ForegroundColor White
    Write-Host "2. Start Agent" -ForegroundColor White
    Write-Host "3. Stop Agent" -ForegroundColor White
    Write-Host "4. Restart Agent" -ForegroundColor White
    Write-Host "5. Check Agent Status" -ForegroundColor White
    Write-Host "6. View Recent Logs" -ForegroundColor White
    Write-Host "7. Show Configuration" -ForegroundColor White
    Write-Host "8. Exit" -ForegroundColor White
    Write-Host "="*50 -ForegroundColor Gray
}

function Show-RecentLogs {
    Write-Host "`n=== RECENT AGENT LOGS ===" -ForegroundColor Cyan
    
    $LogPath = Join-Path $Script:AgentPath "logs\ossec.log"
    if (Test-Path $LogPath) {
        $RecentLogs = Get-Content $LogPath -Tail 20 -ErrorAction SilentlyContinue
        if ($RecentLogs) {
            $RecentLogs | ForEach-Object {
                if ($_ -match "ERROR|CRITICAL") {
                    Write-Host $_ -ForegroundColor Red
                }
                elseif ($_ -match "WARN") {
                    Write-Host $_ -ForegroundColor Yellow
                }
                elseif ($_ -match "Connected|Started") {
                    Write-Host $_ -ForegroundColor Green
                }
                else {
                    Write-Host $_ -ForegroundColor Gray
                }
            }
        }
        else {
            Write-Host "No recent logs found." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "Log file not found: $LogPath" -ForegroundColor Red
    }
    
    Write-Host "`nPress any key to continue..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey()
}

function Show-Configuration {
    Write-Host "`n=== CURRENT CONFIGURATION ===" -ForegroundColor Cyan
    
    # Show ossec.conf manager configuration
    if (Test-Path $Script:OssecConf) {
        $ConfigContent = Get-Content $Script:OssecConf -Raw
        if ($ConfigContent -match '<address>(.*?)</address>') {
            Write-Host "Manager Address: $($Matches[1])" -ForegroundColor White
        }
        if ($ConfigContent -match '<port>(.*?)</port>') {
            Write-Host "Manager Port: $($Matches[1])" -ForegroundColor White
        }
    }
    else {
        Write-Host "ossec.conf not found" -ForegroundColor Red
    }
    
    # Show client.keys (without exposing the actual key)
    if (Test-Path $Script:ClientKeys) {
        $KeyContent = Get-Content $Script:ClientKeys -ErrorAction SilentlyContinue
        if ($KeyContent) {
            $KeyParts = $KeyContent.Split(' ')
            if ($KeyParts.Length -ge 3) {
                Write-Host "Agent ID: $($KeyParts[0])" -ForegroundColor White
                Write-Host "Agent Name: $($KeyParts[1])" -ForegroundColor White
                Write-Host "Agent IP: $($KeyParts[2])" -ForegroundColor White
                Write-Host "Client Key: [CONFIGURED]" -ForegroundColor Green
            }
        }
        else {
            Write-Host "Client Key: [NOT CONFIGURED]" -ForegroundColor Red
        }
    }
    else {
        Write-Host "client.keys not found" -ForegroundColor Red
    }
    
    Write-Host "`nPress any key to continue..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey()
}

function Start-InteractiveMenu {
    while ($true) {
        Show-MainMenu
        
        $Choice = Read-Host "`nSelect an option (1-8)"
        
        switch ($Choice) {
            "1" {
                Start-AgentEnrollment
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "2" {
                Start-WazuhAgent
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "3" {
                Stop-WazuhAgent
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "4" {
                Restart-WazuhAgent
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "5" {
                Get-AgentStatus | Out-Null
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "6" {
                Show-RecentLogs
            }
            "7" {
                Show-Configuration
            }
            "8" {
                Write-Log "Exiting Wazuh Agent Control Center" "INFO"
                Write-Host "`nThank you for using Wazuh Agent Control Center!" -ForegroundColor Green
                exit 0
            }
            default {
                Write-Host "`nInvalid option. Please select 1-8." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    }
}
#endregion

#region Main Execution
function Main {
    # Check admin rights
    if (!(Test-AdminRights)) {
        Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
        Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
        exit 1
    }
    
    # Check if agent files exist
    if (!(Test-Path $Script:AgentExe)) {
        Write-Host "ERROR: Wazuh agent executable not found: $Script:AgentExe" -ForegroundColor Red
        Write-Host "Please ensure you're running this script from the Wazuh agent directory." -ForegroundColor Yellow
        exit 1
    }
    
    Write-Log "Wazuh Agent Control Center started" "INFO"
    
    # Handle command line arguments
    if ($args.Count -gt 0) {
        switch ($args[0].ToLower()) {
            "start" {
                exit (Start-WazuhAgent ? 0 : 1)
            }
            "stop" {
                exit (Stop-WazuhAgent ? 0 : 1)
            }
            "restart" {
                exit (Restart-WazuhAgent ? 0 : 1)
            }
            "status" {
                Get-AgentStatus | Out-Null
                exit 0
            }
            "enroll" {
                exit (Start-AgentEnrollment ? 0 : 1)
            }
            default {
                Write-Host "Usage: .\WazuhAgentControl.ps1 [start|stop|restart|status|enroll]" -ForegroundColor Yellow
                Write-Host "Or run without parameters for interactive mode." -ForegroundColor Gray
                exit 1
            }
        }
    }
    else {
        # Start interactive menu
        Start-InteractiveMenu
    }
}

# Execute main function
Main
#endregion