#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Monitoring Agent Windows Control Script
    
.DESCRIPTION
    Professional control script for managing Monitoring Agent Windows
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
$Script:AgentExe = Join-Path $AgentPath "monitoring-agent.exe"
$Script:OssecConf = Join-Path $AgentPath "ossec.conf"
$Script:ClientKeys = Join-Path $AgentPath "client.keys"
$Script:LogFile = Join-Path $AgentPath "logs\agent-control.log"
$Script:PidFile = Join-Path $AgentPath "monitoring-agent.pid"
$Script:AgentInfo = Join-Path $AgentPath ".agent_info"

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

function Clear-AgentDatabases {
    Write-Log "Cleaning up agent database files..." "INFO"
    
    try {
        $DatabasePaths = @(
            (Join-Path $Script:AgentPath "queue\fim\db"),
            (Join-Path $Script:AgentPath "queue\syscollector\db")
        )
        
        foreach ($DbPath in $DatabasePaths) {
            if (Test-Path $DbPath) {
                $DbFiles = Get-ChildItem -Path $DbPath -Filter "*.db*" -ErrorAction SilentlyContinue
                foreach ($DbFile in $DbFiles) {
                    try {
                        Write-Log "Removing database file: $($DbFile.FullName)" "INFO"
                        Remove-Item $DbFile.FullName -Force -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-Log "Could not remove $($DbFile.FullName): $($_.Exception.Message)" "WARN"
                    }
                }
            }
        }
        
        Write-Log "Database cleanup completed" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error during database cleanup: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Save-AgentPid {
    param([int]$ProcessId)
    
    try {
        Set-Content -Path $Script:PidFile -Value $ProcessId -Force
        Write-Log "Saved agent PID $ProcessId to file" "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to save PID: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-AgentPid {
    try {
        if (Test-Path $Script:PidFile) {
            $ProcessId = Get-Content $Script:PidFile -ErrorAction SilentlyContinue
            if ($ProcessId -and $ProcessId -match '^\d+$') {
                return [int]$ProcessId
            }
        }
        return $null
    }
    catch {
        Write-Log "Error reading PID file: $($_.Exception.Message)" "WARN"
        return $null
    }
}

function Remove-AgentPid {
    try {
        if (Test-Path $Script:PidFile) {
            Remove-Item $Script:PidFile -Force -ErrorAction SilentlyContinue
            Write-Log "Removed PID file" "INFO"
        }
        return $true
    }
    catch {
        Write-Log "Failed to remove PID file: $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Test-ProcessRunning {
    param([int]$ProcessId)
    
    try {
        $Process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        return ($null -ne $Process)
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
        # Check for monitoring-agent processes using Get-CimInstance for more detailed info
        $AgentProcesses = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'monitoring-agent.exe'" -ErrorAction SilentlyContinue
        
        if ($AgentProcesses) {
            # Filter processes that are actually from our workspace
            $WorkspaceProcesses = @()
            foreach ($proc in $AgentProcesses) {
                if ($proc.ExecutablePath -eq $Script:AgentExe) {
                    $WorkspaceProcesses += $proc
                }
            }
            
            if ($WorkspaceProcesses.Count -gt 0) {
                $MainProcess = $WorkspaceProcesses[0]
                $ProcessId = $MainProcess.ProcessId
                Write-Log "Found workspace agent process (PID: $ProcessId)" "SUCCESS"
                
                # Save the PID for future reference
                Save-AgentPid $ProcessId
                
                # Check agent state file for connection status
                $StateFile = Join-Path $Script:AgentPath "monitoring-agent.state"
                $Connected = $null
                
                if (Test-Path $StateFile) {
                    try {
                        $StateContent = Get-Content $StateFile -Raw -ErrorAction SilentlyContinue
                        Write-Log "Agent state file found" "INFO"
                        
                    } catch {
                        Write-Log "Could not read state file: $($_.Exception.Message)" "WARN"
                    }
             }
                
                return @{
                    Running = $true
                    Connected = $Connected
                    ProcessId = $ProcessId
                    ProcessCount = $WorkspaceProcesses.Count
                    WorkingDirectory = $MainProcess.CommandLine
                }
            } else {
                Write-Log "Found monitoring-agent processes but none from our workspace" "WARN"
            }
        }
        
        # No processes found - clean up any stale PID file
        Write-Log "No monitoring-agent processes found from workspace" "WARN"
        Remove-AgentPid
        
        return @{
            Running = $false
            Connected = $false
            ProcessId = $null
            ProcessCount = 0
            WorkingDirectory = $null
        }
    }
    catch {
        Write-Log "Error checking agent status: $($_.Exception.Message)" "ERROR"
        return @{
            Running = $false
            Connected = $false
            ProcessId = $null
            ProcessCount = 0
            WorkingDirectory = $null
            Error = $_.Exception.Message
        }
    }
}

function Start-MonitoringAgent {
    Write-Log "Starting Monitoring agent..." "INFO"
    
    try {
        $Status = Get-AgentStatus
        if ($Status.Running) {
            Write-Log "Agent is already running (PID: $($Status.ProcessId))" "WARN"
            return $true
        }
        
        if (!(Test-Path $Script:AgentExe)) {
            Write-Log "Agent executable not found: $Script:AgentExe" "ERROR"
            return $false
        }
        
        # Start the agent directly from our workspace
        Write-Log "Starting agent from workspace: $Script:AgentExe" "INFO"
        
        # Create startup info to run agent in background
        $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $StartInfo.FileName = $Script:AgentExe
        $StartInfo.Arguments = "start"
        $StartInfo.UseShellExecute = $false
        $StartInfo.CreateNoWindow = $true
        $StartInfo.WorkingDirectory = $Script:AgentPath
        $StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        
        # Start the process
        $Process = [System.Diagnostics.Process]::Start($StartInfo)
        if ($Process) {
            Write-Log "Agent start command executed (Launcher PID: $($Process.Id))" "INFO"
            $Process.WaitForExit(10000)  # Wait up to 10 seconds for start command to complete
            
            # The start command launches the actual daemon, so we need to find it
            Start-Sleep -Seconds 3
            
            # Find the actual agent daemon process
            $RetryCount = 0
            $MaxRetries = 10
            $AgentStarted = $false
            
            while ($RetryCount -lt $MaxRetries -and !$AgentStarted) {
                $NewStatus = Get-AgentStatus
                if ($NewStatus.Running) {
                    Write-Log "Agent daemon started successfully (PID: $($NewStatus.ProcessId))" "SUCCESS"
                    $AgentStarted = $true
                    
                    # Wait a bit more for full initialization
                    Start-Sleep -Seconds 2
                    
                    return $true
                } else {
                    $RetryCount++
                    Write-Log "Waiting for agent daemon to start... (attempt $RetryCount/$MaxRetries)" "INFO"
                    Start-Sleep -Seconds 2
                }
            }
            
            if (!$AgentStarted) {
                Write-Log "Agent daemon failed to start after $MaxRetries attempts" "ERROR"
                return $false
            }
        } else {
            Write-Log "Failed to execute agent start command" "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error starting agent: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Stop-MonitoringAgent {
    Write-Log "Stopping Monitoring agent..." "INFO"
    
    try {
        $Status = Get-AgentStatus
        if (!$Status.Running) {
            Write-Log "Agent is not running" "WARN"
            return $true
        }
        
        # First, try to gracefully stop the agent using Windows signals and CTRL+C
        Write-Log "Attempting graceful shutdown using Windows termination signals..." "INFO"
        try {
            # Get the agent process for graceful shutdown
            $AgentProcess = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'monitoring-agent.exe'" -ErrorAction SilentlyContinue | 
                Where-Object { $_.ExecutablePath -eq $Script:AgentExe }
            
            if ($AgentProcess) {
                $ProcessObj = Get-Process -Id $AgentProcess.ProcessId -ErrorAction SilentlyContinue
                if ($ProcessObj) {
                    Write-Log "Sending graceful shutdown signal to process $($AgentProcess.ProcessId)..." "INFO"
                    
                    # Method 1: Try AttachConsole and GenerateConsoleCtrlEvent for CTRL+C
                    try {
                        Add-Type -TypeDefinition @"
                            using System;
                            using System.Runtime.InteropServices;
                            public class Win32 {
                                [DllImport("kernel32.dll", SetLastError=true)]
                                public static extern bool AttachConsole(uint dwProcessId);
                                [DllImport("kernel32.dll", SetLastError=true)]
                                public static extern bool GenerateConsoleCtrlEvent(uint dwCtrlEvent, uint dwProcessGroupId);
                                [DllImport("kernel32.dll", SetLastError=true)]
                                public static extern bool FreeConsole();
                                public const uint CTRL_C_EVENT = 0;
                            }
"@ -ErrorAction SilentlyContinue
                        
                        if ([Win32]::AttachConsole($AgentProcess.ProcessId)) {
                            Write-Log "Attached to agent console, sending CTRL+C..." "INFO"
                            
                            if ([Win32]::GenerateConsoleCtrlEvent([Win32]::CTRL_C_EVENT, 0)) {
                                Write-Log "CTRL+C signal sent successfully" "SUCCESS"
                                
                                # Wait for graceful shutdown with timeout
                                $GracefulWait = 0
                                while (!$ProcessObj.HasExited -and $GracefulWait -lt 10) {
                                    Start-Sleep -Seconds 1
                                    $GracefulWait++
                                    Write-Log "Waiting for graceful shutdown... ($GracefulWait/10)" "INFO"
                                }
                                
                                if ($ProcessObj.HasExited) {
                                    Write-Log "Agent gracefully shut down via CTRL+C signal" "SUCCESS"
                                    [Win32]::FreeConsole()
                                    return $true
                                }
                            }
                            [Win32]::FreeConsole()
                        }
                    } catch {
                        Write-Log "CTRL+C method failed: $($_.Exception.Message)" "WARN"
                    }
                    
                    # Method 2: Try to close main window first (graceful shutdown for GUI apps)
                    if (!$ProcessObj.HasExited -and $ProcessObj.CloseMainWindow()) {
                        Write-Log "Sent close window signal successfully" "INFO"
                        
                        # Wait for graceful shutdown with timeout
                        $GracefulWait = 0
                        while (!$ProcessObj.HasExited -and $GracefulWait -lt 10) {
                            Start-Sleep -Seconds 1
                            $GracefulWait++
                            Write-Log "Waiting for graceful shutdown... ($GracefulWait/10)" "INFO"
                        }
                        
                        if ($ProcessObj.HasExited) {
                            Write-Log "Agent gracefully closed via CloseMainWindow signal" "SUCCESS"
                            return $true
                        }
                    }
                }
            }
        }
        catch {
            Write-Log "Graceful shutdown attempt failed: $($_.Exception.Message)" "WARN"
        }
        
        # Wait for graceful shutdown
        Start-Sleep -Seconds 5
        
        # Check if agent stopped gracefully
        $NewStatus = Get-AgentStatus
        if (!$NewStatus.Running) {
            Write-Log "Agent stopped gracefully" "SUCCESS"
            Remove-AgentPid
            return $true
        }
        
        # If graceful shutdown failed, force terminate processes
        Write-Log "Graceful shutdown failed, force terminating processes..." "WARN"
        
        # Get all monitoring-agent processes from our workspace
        $AgentProcesses = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'monitoring-agent.exe'" -ErrorAction SilentlyContinue
        
        if ($AgentProcesses) {
            foreach ($proc in $AgentProcesses) {
                if ($proc.ExecutablePath -eq $Script:AgentExe) {
                    try {
                        Write-Log "Force terminating workspace agent process (PID: $($proc.ProcessId))" "INFO"
                        
                        # Send a proper disconnect signal first by trying to terminate gracefully
                        $Process = Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
                        if ($Process) {
                            # Try CloseMainWindow first for graceful shutdown
                            if ($Process.CloseMainWindow()) {
                                Write-Log "Sent close signal to process $($proc.ProcessId)" "INFO"
                                $Process.WaitForExit(5000)  # Wait 5 seconds for graceful exit
                            }
                            
                            # If still running, force kill
                            if (!$Process.HasExited) {
                                Write-Log "Force killing process $($proc.ProcessId)" "WARN"
                                $Process.Kill()
                                $Process.WaitForExit(3000)  # Wait 3 seconds for termination
                            }
                            
                            Write-Log "Process $($proc.ProcessId) terminated" "SUCCESS"
                        }
                    }
                    catch {
                        Write-Log "Failed to terminate process $($proc.ProcessId): $($_.Exception.Message)" "ERROR"
                    }
                }
            }
        }
        
        # Clean up files
        Remove-AgentPid
        
        # Remove auto-enrollment info file
        if (Test-Path $Script:AgentInfo) {
            Remove-Item $Script:AgentInfo -Force -ErrorAction SilentlyContinue
            Write-Log "Removed .agent_info file" "INFO"
        }
        
        # Clear any cached connection state and force disconnect signal
        $StateFile = Join-Path $Script:AgentPath "monitoring-agent.state"
        if (Test-Path $StateFile) {
            try {
                # Update state to disconnected with timestamp
                $StateContent = Get-Content $StateFile -Raw -ErrorAction SilentlyContinue
                if ($StateContent) {
                    $StateContent = $StateContent -replace "status='connected'", "status='disconnected'"
                    $StateContent = $StateContent -replace "last_keepalive='\d+'", "last_keepalive='0'"
                    Set-Content $StateFile -Value $StateContent -Force
                    Write-Log "Updated agent state to disconnected with immediate effect" "INFO"
                }
            }
            catch {
                Write-Log "Could not update state file: $($_.Exception.Message)" "WARN"
            }
        }
        
        # Clear any persistent agent connection files to force clean disconnect
        $LogCollectorState = Join-Path $Script:AgentPath "monitoring-logcollector.state"
        if (Test-Path $LogCollectorState) {
            Remove-Item $LogCollectorState -Force -ErrorAction SilentlyContinue
            Write-Log "Cleared logcollector state" "INFO"
        }
        
        # Also check for any queue files that might indicate pending messages
        $QueueDir = Join-Path $Script:AgentPath "queue"
        if (Test-Path $QueueDir) {
            try {
                Get-ChildItem $QueueDir -Recurse -File | Where-Object { $_.Name -like "*pending*" -or $_.Name -like "*queue*" } | Remove-Item -Force -ErrorAction SilentlyContinue
                Write-Log "Cleared any pending queue files" "INFO"
            }
            catch {
                Write-Log "Could not clear queue files: $($_.Exception.Message)" "WARN"
            }
        }
        
        # Final verification
        Start-Sleep -Seconds 2
        $FinalStatus = Get-AgentStatus
        if (!$FinalStatus.Running) {
            Write-Log "Agent stopped successfully and should disconnect from manager" "SUCCESS"
            return $true
        }
        else {
            Write-Log "Failed to stop agent completely" "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error stopping agent: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Restart-MonitoringAgent {
    Write-Log "Restarting Monitoring agent..." "INFO"
    
    if (Stop-MonitoringAgent) {
        Start-Sleep -Seconds 2
        return Start-MonitoringAgent
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
    Write-Log "Client key to write: $ClientKey" "INFO"
    
    try {
        # Ensure the client key is properly formatted (no extra whitespace)
        $ClientKey = $ClientKey.Trim()
        
        # Backup current keys
        if (Test-Path $Script:ClientKeys) {
            $BackupPath = Backup-ConfigFile $Script:ClientKeys
            Write-Log "Backup created: $BackupPath" "INFO"
        }
        
        # Remove auto-enrollment file to prevent agent from auto-generating keys
        if (Test-Path $Script:AgentInfo) {
            Remove-Item $Script:AgentInfo -Force -ErrorAction SilentlyContinue
            Write-Log "Removed .agent_info file to disable auto-enrollment" "INFO"
        }
        
        # Remove existing client.keys file to avoid permission issues
        if (Test-Path $Script:ClientKeys) {
            Remove-Item $Script:ClientKeys -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
        }
        
        # Write new client key
        Set-Content -Path $Script:ClientKeys -Value $ClientKey -Encoding UTF8 -Force
        
        # Set restrictive permissions on client.keys to prevent tampering
        $Acl = Get-Acl $Script:ClientKeys
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")
        $Acl.SetAccessRule($AccessRule)
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")
        $Acl.SetAccessRule($AccessRule)
        $Acl.SetAccessRuleProtection($true,$false)
        Set-Acl -Path $Script:ClientKeys -AclObject $Acl
        
        # Verify the write was successful
        if (Test-Path $Script:ClientKeys) {
            $WrittenContent = Get-Content $Script:ClientKeys -Raw
            $WrittenContent = $WrittenContent.Trim()
            if ($WrittenContent -eq $ClientKey) {
                Write-Log "client.keys updated successfully" "SUCCESS"
                Write-Log "Verified content: $WrittenContent" "INFO"
                return $true
            }
            else {
                Write-Log "client.keys content verification failed" "ERROR"
                Write-Log "Expected: $ClientKey" "ERROR"
                Write-Log "Got: $WrittenContent" "ERROR"
                return $false
            }
        }
        else {
            Write-Log "client.keys file was not created" "ERROR"
            return $false
        }
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
            $UserInput = Read-Host -Prompt $Prompt -AsSecureString
            $UserInput = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($UserInput))
        }
        else {
            $UserInput = Read-Host -Prompt $Prompt
        }
        
        if ([string]::IsNullOrWhiteSpace($UserInput)) {
            Write-Host "Input cannot be empty. Please try again." -ForegroundColor Red
            continue
        }
        
        if ($ValidationRegex -and $UserInput -notmatch $ValidationRegex) {
            Write-Host $ValidationErrorMessage -ForegroundColor Red
            continue
        }
        
        return $UserInput.Trim()
    } while ($true)
}
#endregion

#region Enrollment Functions
function Start-AgentEnrollment {
    Write-Log "Starting agent enrollment process..." "INFO"
    
    Write-Host "`n=== MONITORING AGENT ENROLLMENT ===" -ForegroundColor Cyan
    Write-Host "Choose your enrollment method:`n" -ForegroundColor Gray
    
    Write-Host "1. Auto-Enrollment (Recommended)" -ForegroundColor Green
    Write-Host "   - Uses agent-auth.exe to automatically register with manager" -ForegroundColor Gray
    Write-Host "   - Requires manager IP, port, and agent name" -ForegroundColor Gray
    Write-Host "   - Manager automatically generates and assigns client key" -ForegroundColor Gray
    
    Write-Host "`n2. Manual Enrollment" -ForegroundColor Yellow
    Write-Host "   - Requires pre-generated client key from manager" -ForegroundColor Gray
    Write-Host "   - Client key must be obtained separately from manager" -ForegroundColor Gray
    Write-Host "   - Supports both plain text and base64 encoded keys" -ForegroundColor Gray
    
    do {
        $Choice = Read-Host "`nSelect enrollment method (1 for Auto, 2 for Manual)"
        switch ($Choice) {
            "1" {
                return Start-AgentAutoEnrollment
            }
            "2" {
                return Start-AgentManualEnrollment
            }
            default {
                Write-Host "Invalid choice. Please enter 1 or 2." -ForegroundColor Red
            }
        }
    } while ($true)
}

function Start-AgentManualEnrollment {
    Write-Log "Starting manual agent enrollment process..." "INFO"
    
    Write-Host "`n=== MONITORING AGENT MANUAL ENROLLMENT ===" -ForegroundColor Cyan
    Write-Host "This process will configure your agent to connect to a Monitoring manager using a pre-generated client key.`n" -ForegroundColor Gray
    
    # Get Manager IP/Hostname
    do {
        $ManagerAddress = Get-UserInput -Prompt "Enter Monitoring Manager IP address or hostname"
        
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
    
    $ClientKeyInput = Get-UserInput -Prompt "Enter client key" -Secure $false
    
    # Variables to track the key state
    $ClientKey = $ClientKeyInput
    $IsBase64Decoded = $false
    $OriginalKey = $ClientKeyInput
    
    # Check if input is base64 encoded
    if (Test-Base64 $ClientKeyInput) {
        try {
            $DecodedKey = ConvertFrom-Base64 $ClientKeyInput
            Write-Host "`nDetected base64 encoded key." -ForegroundColor Yellow
            Write-Host "Decoded key: $DecodedKey" -ForegroundColor Cyan
            Write-Host "Do you want to use the decoded version? (y/n)" -ForegroundColor Yellow
            $UseDecoded = Read-Host
            if ($UseDecoded -eq 'y' -or $UseDecoded -eq 'Y') {
                $ClientKey = $DecodedKey
                $IsBase64Decoded = $true
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
    if ($IsBase64Decoded) {
        Write-Host "Client Key (Original Base64): $OriginalKey" -ForegroundColor Gray
        Write-Host "Client Key (Decoded): $ClientKey" -ForegroundColor White
    }
    else {
        Write-Host "Client Key: $ClientKey" -ForegroundColor White
    }
    
    $Confirm = Read-Host "`nProceed with enrollment? (y/n)"
    if ($Confirm -ne 'y' -and $Confirm -ne 'Y') {
        Write-Log "Enrollment cancelled by user" "INFO"
        return $false
    }
    
    # Stop agent if running
    $Status = Get-AgentStatus
    if ($Status.Running) {
        Write-Log "Stopping agent for configuration update..." "INFO"
        if (!(Stop-MonitoringAgent)) {
            Write-Log "Failed to stop agent for enrollment" "ERROR"
            return $false
        }
        
        # Clean up database files to prevent startup issues
        Write-Log "Cleaning up database files..." "INFO"
        Clear-AgentDatabases
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
        if (Start-MonitoringAgent) {
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

function Start-AgentAutoEnrollment {
    Write-Log "Starting agent auto-enrollment process..." "INFO"
    
    Write-Host "`n=== MONITORING AGENT AUTO-ENROLLMENT ===" -ForegroundColor Cyan
    Write-Host "This process will automatically enroll your agent with the Monitoring manager using agent-auth.exe.`n" -ForegroundColor Gray
    
    # Get Manager IP/Hostname
    do {
        $ManagerAddress = Get-UserInput -Prompt "Enter Monitoring Manager IP address or hostname"
        
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
    Write-Host "`nManager Authentication Port Information:" -ForegroundColor Gray
    Write-Host "  • Default agent-auth port: 1515 (for enrollment/authentication)" -ForegroundColor Gray
    Write-Host "  • Default agent communication port: 1514 (for data transmission)" -ForegroundColor Gray
    Write-Host "  • Most Wazuh/OSSEC managers use port 1515 for enrollment" -ForegroundColor Gray
    Write-Host "`nManager port for enrollment (default: 1515, press Enter to use default):" -ForegroundColor Gray
    $ManagerPort = Read-Host "Port"
    if ([string]::IsNullOrWhiteSpace($ManagerPort)) {
        $ManagerPort = "1515"
    }
    
    # Validate port number
    try {
        $PortNumber = [int]$ManagerPort
        if ($PortNumber -lt 1 -or $PortNumber -gt 65535) {
            Write-Host "Invalid port number. Using default 1515." -ForegroundColor Yellow
            $ManagerPort = "1515"
        }
    }
    catch {
        Write-Host "Invalid port format. Using default 1515." -ForegroundColor Yellow
        $ManagerPort = "1515"
    }
    
    # Get Agent Name
    Write-Host "`nAgent Name Information:" -ForegroundColor Gray
    Write-Host "The agent name should be unique and descriptive (e.g., DESKTOP-HOSTNAME-DATE)." -ForegroundColor Gray
    Write-Host "Default suggestion: $($env:COMPUTERNAME)-$(Get-Date -Format 'yyyyMMdd-HHmmss')" -ForegroundColor Gray
    
    $DefaultAgentName = "$($env:COMPUTERNAME)-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Write-Host "`nAgent name (press Enter to use default: $DefaultAgentName):" -ForegroundColor Gray
    $AgentName = Read-Host "Agent Name"
    if ([string]::IsNullOrWhiteSpace($AgentName)) {
        $AgentName = $DefaultAgentName
    }
    
    # Validate agent name (no spaces, special characters that might cause issues)
    if ($AgentName -match '[<>:"/\\|?*\s]') {
        Write-Host "Warning: Agent name contains special characters that might cause issues." -ForegroundColor Yellow
        Write-Host "Recommended characters: letters, numbers, hyphens, underscores only." -ForegroundColor Yellow
        $Continue = Read-Host "Continue with this name anyway? (y/n)"
        if ($Continue -ne 'y' -and $Continue -ne 'Y') {
            Write-Log "Auto-enrollment cancelled by user due to agent name" "INFO"
            return $false
        }
    }
    
    # Get optional password if manager requires it
    Write-Host "`nAuthorization Password (optional - leave empty if manager doesn't require password):" -ForegroundColor Gray
    $AuthPassword = Read-Host "Password" -AsSecureString
    $AuthPasswordPlain = ""
    if ($AuthPassword.Length -gt 0) {
        $AuthPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($AuthPassword))
    }
    
    # Show configuration summary
    Write-Host "`n=== AUTO-ENROLLMENT SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Manager Address: $ManagerAddress" -ForegroundColor White
    Write-Host "Manager Port: $ManagerPort" -ForegroundColor White
    Write-Host "Agent Name: $AgentName" -ForegroundColor White
    if ($AuthPasswordPlain) {
        Write-Host "Authorization Password: [PROVIDED]" -ForegroundColor Green
    }
    else {
        Write-Host "Authorization Password: [NOT PROVIDED]" -ForegroundColor Gray
    }
    
    $Confirm = Read-Host "`nProceed with auto-enrollment? (y/n)"
    if ($Confirm -ne 'y' -and $Confirm -ne 'Y') {
        Write-Log "Auto-enrollment cancelled by user" "INFO"
        return $false
    }
    
    # Stop agent if running
    $Status = Get-AgentStatus
    if ($Status.Running) {
        Write-Log "Stopping agent for auto-enrollment..." "INFO"
        if (!(Stop-MonitoringAgent)) {
            Write-Log "Failed to stop agent for auto-enrollment" "ERROR"
            return $false
        }
        
        # Clean up database files to prevent startup issues
        Write-Log "Cleaning up database files..." "INFO"
        Clear-AgentDatabases
    }
    
    # Backup existing client.keys if it exists
    if (Test-Path $Script:ClientKeys) {
        $BackupPath = Backup-ConfigFile $Script:ClientKeys
        Write-Log "Backed up existing client.keys" "INFO"
    }
    
    # Build agent-auth command
    $AgentAuthExe = Join-Path $Script:AgentPath "agent-auth.exe"
    if (!(Test-Path $AgentAuthExe)) {
        Write-Log "agent-auth.exe not found: $AgentAuthExe" "ERROR"
        return $false
    }
    
    $AgentAuthArgs = @(
        "-m", $ManagerAddress,
        "-p", $ManagerPort,
        "-A", $AgentName
    )
    
    if ($AuthPasswordPlain) {
        $AgentAuthArgs += @("-P", $AuthPasswordPlain)
    }
    
    # Execute agent-auth
    Write-Log "Executing auto-enrollment with agent-auth.exe..." "INFO"
    Write-Log "Command: agent-auth.exe -m $ManagerAddress -p $ManagerPort -A `"$AgentName`"" "INFO"
    
    try {
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName = $AgentAuthExe
        $ProcessInfo.Arguments = $AgentAuthArgs -join " "
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.RedirectStandardOutput = $true
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.CreateNoWindow = $true
        $ProcessInfo.WorkingDirectory = $Script:AgentPath
        
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        
        # Start the process
        $Process.Start() | Out-Null
        
        # Read output
        $StdOut = $Process.StandardOutput.ReadToEnd()
        $StdErr = $Process.StandardError.ReadToEnd()
        
        # Wait for completion with timeout
        if (!$Process.WaitForExit(30000)) {  # 30 second timeout
            $Process.Kill()
            Write-Log "agent-auth.exe timed out after 30 seconds" "ERROR"
            return $false
        }
        
        $ExitCode = $Process.ExitCode
        
        Write-Log "agent-auth.exe completed with exit code: $ExitCode" "INFO"
        
        if ($StdOut) {
            Write-Log "agent-auth output: $StdOut" "INFO"
            Write-Host "Output: $StdOut" -ForegroundColor Cyan
        }
        
        if ($StdErr) {
            Write-Log "agent-auth errors: $StdErr" "WARN"
            if ($StdErr -notmatch "INFO|DEBUG") {
                Write-Host "Errors: $StdErr" -ForegroundColor Yellow
            }
        }
        
        if ($ExitCode -eq 0) {
            Write-Log "Auto-enrollment completed successfully!" "SUCCESS"
            
            # Verify client.keys was created/updated
            if (Test-Path $Script:ClientKeys) {
                $KeyContent = Get-Content $Script:ClientKeys -ErrorAction SilentlyContinue
                if ($KeyContent) {
                    Write-Log "client.keys file updated successfully" "SUCCESS"
                    
                    # Parse key info for display
                    $KeyParts = $KeyContent.Split(' ')
                    if ($KeyParts.Length -ge 3) {
                        Write-Host "`nEnrollment Details:" -ForegroundColor Green
                        Write-Host "  Agent ID: $($KeyParts[0])" -ForegroundColor White
                        Write-Host "  Agent Name: $($KeyParts[1])" -ForegroundColor White
                        Write-Host "  Agent IP: $($KeyParts[2])" -ForegroundColor White
                    }
                }
                else {
                    Write-Log "client.keys file is empty after enrollment" "ERROR"
                    return $false
                }
            }
            else {
                Write-Log "client.keys file not found after enrollment" "ERROR"
                return $false
            }
            
            # Update ossec.conf with manager address (use port 1514 for communication)
            if (!(Update-OssecConfig -ManagerIP $ManagerAddress -ManagerPort "1514")) {
                Write-Log "Failed to update ossec.conf - agent may not connect properly" "WARN"
            }
            
            Write-Host "`nAuto-enrollment completed successfully!" -ForegroundColor Green
            
            # Ask if user wants to start the agent
            Write-Host "`nDo you want to start the agent now? (y/n)" -ForegroundColor Yellow
            $StartAgent = Read-Host
            if ($StartAgent -eq 'y' -or $StartAgent -eq 'Y') {
                if (Start-MonitoringAgent) {
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
        else {
            Write-Log "Auto-enrollment failed with exit code: $ExitCode" "ERROR"
            if ($StdErr) {
                Write-Host "Error details: $StdErr" -ForegroundColor Red
                
                # Provide specific guidance based on error type
                if ($StdErr -match "Connection refused|SSL error" -and $StdErr -match "Maybe the port specified is incorrect") {
                    Write-Host "`nTROUBLESHOoting SUGGESTIONS:" -ForegroundColor Yellow
                    Write-Host "1. Verify the manager is running and accessible" -ForegroundColor White
                    Write-Host "2. Check if port $ManagerPort is the correct enrollment port" -ForegroundColor White
                    Write-Host "3. Common ports:" -ForegroundColor White
                    Write-Host "   • Port 1515: Standard Wazuh/OSSEC enrollment port" -ForegroundColor Gray
                    Write-Host "   • Port 1514: Agent communication port (not for enrollment)" -ForegroundColor Gray
                    Write-Host "4. Verify firewall allows connections to port $ManagerPort" -ForegroundColor White
                    Write-Host "5. Ensure the manager's authd service is running" -ForegroundColor White
                    
                    Write-Host "`nWould you like to try again with port 1515? (y/n)" -ForegroundColor Yellow
                    $RetryWithCorrectPort = Read-Host
                    if ($RetryWithCorrectPort -eq 'y' -or $RetryWithCorrectPort -eq 'Y') {
                        Write-Host "Retrying with port 1515..." -ForegroundColor Cyan
                        
                        # Retry with port 1515
                        $AgentAuthArgs = @(
                            "-m", $ManagerAddress,
                            "-p", "1515",
                            "-A", $AgentName
                        )
                        
                        if ($AuthPasswordPlain) {
                            $AgentAuthArgs += @("-P", $AuthPasswordPlain)
                        }
                        
                        Write-Log "Retrying enrollment with port 1515..." "INFO"
                        
                        try {
                            $ProcessInfo.Arguments = $AgentAuthArgs -join " "
                            $RetryProcess = New-Object System.Diagnostics.Process
                            $RetryProcess.StartInfo = $ProcessInfo
                            
                            $RetryProcess.Start() | Out-Null
                            $RetryStdOut = $RetryProcess.StandardOutput.ReadToEnd()
                            $RetryStdErr = $RetryProcess.StandardError.ReadToEnd()
                            
                            if (!$RetryProcess.WaitForExit(30000)) {
                                $RetryProcess.Kill()
                                Write-Log "Retry attempt timed out" "ERROR"
                                return $false
                            }
                            
                            $RetryExitCode = $RetryProcess.ExitCode
                            
                            if ($RetryExitCode -eq 0) {
                                Write-Log "Auto-enrollment successful on retry with port 1515!" "SUCCESS"
                                $StdOut = $RetryStdOut
                                $ExitCode = 0  # Set to success to continue with verification
                            }
                            else {
                                Write-Log "Retry also failed with exit code: $RetryExitCode" "ERROR"
                                if ($RetryStdErr) {
                                    Write-Host "Retry error: $RetryStdErr" -ForegroundColor Red
                                }
                                return $false
                            }
                        }
                        catch {
                            Write-Log "Error during retry: $($_.Exception.Message)" "ERROR"
                            return $false
                        }
                    }
                    else {
                        return $false
                    }
                }
                elseif ($StdErr -match "Invalid agent name" -or $StdErr -match "agent name") {
                    Write-Host "`nAgent name '$AgentName' may be invalid or already exists." -ForegroundColor Yellow
                    Write-Host "Try using a more unique name or check manager logs." -ForegroundColor White
                }
                elseif ($StdErr -match "password" -or $StdErr -match "authentication") {
                    Write-Host "`nManager may require an authorization password." -ForegroundColor Yellow
                    Write-Host "Contact your administrator for the enrollment password." -ForegroundColor White
                }
                else {
                    Write-Host "`nGeneral troubleshooting:" -ForegroundColor Yellow
                    Write-Host "1. Verify manager IP address is correct" -ForegroundColor White
                    Write-Host "2. Check network connectivity to the manager" -ForegroundColor White
                    Write-Host "3. Ensure manager's authd service is running" -ForegroundColor White
                    Write-Host "4. Check manager logs for more details" -ForegroundColor White
                }
            }
            return $false
        }
    }
    catch {
        Write-Log "Error during auto-enrollment: $($_.Exception.Message)" "ERROR"
        return $false
    }
}
#endregion

#region Main Menu Functions
function Show-MainMenu {
    Clear-Host
    Write-Host @"

 ███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗ 
 ████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗
 ██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝
 ██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗
 ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║
 ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                                                             
      AGENT CONTROL CENTER v1.0.0
      
"@ -ForegroundColor Cyan

    # Show current status
    $Status = Get-AgentStatus
    Write-Host "Current Status:" -ForegroundColor White
    if ($Status.Running) {
        Write-Host "  Agent: " -NoNewline -ForegroundColor White
        Write-Host "RUNNING" -ForegroundColor Green
        Write-Host "  PID: $($Status.ProcessId)" -ForegroundColor Gray
       
    }
    else {
        Write-Host "  Agent: " -NoNewline -ForegroundColor White
        Write-Host "STOPPED" -ForegroundColor Red
    }
    
    Write-Host "`n" + "="*50 -ForegroundColor Gray
    Write-Host "MAIN MENU" -ForegroundColor Cyan
    Write-Host "="*50 -ForegroundColor Gray
    Write-Host "1. Enroll Agent (Auto & Manual Options)" -ForegroundColor White
    Write-Host "2. Start Agent" -ForegroundColor White
    Write-Host "3. Stop Agent" -ForegroundColor White
    Write-Host "4. Restart Agent" -ForegroundColor White
    Write-Host "5. Check Agent Status" -ForegroundColor White
    Write-Host "6. View Recent Logs" -ForegroundColor White
    Write-Host "7. Show Configuration" -ForegroundColor White
    Write-Host "8. Clean Database Files" -ForegroundColor White
    Write-Host "9. Exit" -ForegroundColor White
    Write-Host "="*50 -ForegroundColor Gray
}

function Show-RecentLogs {
    Write-Host "`n=== RECENT AGENT LOGS ===" -ForegroundColor Cyan
    
    $LogPath = Join-Path $Script:AgentPath "ossec.log"
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
        
        $Choice = Read-Host "`nSelect an option (1-9)"
        
        switch ($Choice) {
            "1" {
                Start-AgentEnrollment
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "2" {
                Start-MonitoringAgent
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "3" {
                Stop-MonitoringAgent
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "4" {
                Restart-MonitoringAgent
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
                Write-Host "`n=== CLEANING DATABASE FILES ===" -ForegroundColor Cyan
                $AgentRunning = (Get-AgentStatus).Running
                if ($AgentRunning) {
                    Write-Host "Stopping agent before cleanup..." -ForegroundColor Yellow
                    Stop-MonitoringAgent | Out-Null
                }
                Clear-AgentDatabases
                if ($AgentRunning) {
                    Write-Host "Restarting agent..." -ForegroundColor Yellow
                    Start-MonitoringAgent | Out-Null
                }
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey()
            }
            "9" {
                Write-Log "Exiting Monitoring Agent Control Center" "INFO"
                Write-Host "`nThank you for using Monitoring Agent Control Center!" -ForegroundColor Green
                exit 0
            }
            default {
                Write-Host "`nInvalid option. Please select 1-9." -ForegroundColor Red
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
        Write-Host "ERROR: Monitoring agent executable not found: $Script:AgentExe" -ForegroundColor Red
        Write-Host "Please ensure you're running this script from the Monitoring agent directory." -ForegroundColor Yellow
        exit 1
    }
    
    Write-Log "Monitoring Agent Control Center started" "INFO"
    
    # Handle command line arguments
    if ($args.Count -gt 0) {
        switch ($args[0].ToLower()) {
            "start" {
                if (Start-MonitoringAgent) { exit 0 } else { exit 1 }
            }
            "stop" {
                if (Stop-MonitoringAgent) { exit 0 } else { exit 1 }
            }
            "restart" {
                if (Restart-MonitoringAgent) { exit 0 } else { exit 1 }
            }
            "status" {
                Get-AgentStatus | Out-Null
                exit 0
            }
            "enroll" {
                if (Start-AgentEnrollment) { exit 0 } else { exit 1 }
            }
            "auto-enroll" {
                if (Start-AgentAutoEnrollment) { exit 0 } else { exit 1 }
            }
            "manual-enroll" {
                if (Start-AgentManualEnrollment) { exit 0 } else { exit 1 }
            }
            "cleanup" {
                $AgentRunning = (Get-AgentStatus).Running
                if ($AgentRunning) {
                    Write-Host "Stopping agent for database cleanup..." -ForegroundColor Yellow
                    Stop-MonitoringAgent | Out-Null
                }
                $CleanupResult = Clear-AgentDatabases
                if ($AgentRunning) {
                    Write-Host "Restarting agent..." -ForegroundColor Yellow
                    Start-MonitoringAgent | Out-Null
                }
                if ($CleanupResult) { exit 0 } else { exit 1 }
            }
            default {
                Write-Host "Usage: .\MonitoringAgentControl.ps1 [start|stop|restart|status|enroll|auto-enroll|manual-enroll|cleanup]" -ForegroundColor Yellow
                Write-Host "  start        - Start the monitoring agent" -ForegroundColor Gray
                Write-Host "  stop         - Stop the monitoring agent" -ForegroundColor Gray
                Write-Host "  restart      - Restart the monitoring agent" -ForegroundColor Gray
                Write-Host "  status       - Check agent status" -ForegroundColor Gray
                Write-Host "  enroll       - Interactive enrollment (auto/manual choice)" -ForegroundColor Gray
                Write-Host "  auto-enroll  - Auto-enrollment using agent-auth.exe" -ForegroundColor Gray
                Write-Host "  manual-enroll- Manual enrollment with pre-generated key" -ForegroundColor Gray
                Write-Host "  cleanup      - Clean database files" -ForegroundColor Gray
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
Main @args
#endregion