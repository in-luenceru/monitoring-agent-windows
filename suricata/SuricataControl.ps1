#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Suricata Network IDS Control Script for Monitoring Agent Integration - Fixed Version
#>

# Script Configuration
$Script:WorkspacePath = Split-Path $PSScriptRoot -Parent
$Script:SuricataBin = Join-Path $PSScriptRoot "bin\suricata.exe"
$Script:SuricataConfig = Join-Path $PSScriptRoot "etc\suricata.yaml" 
$Script:SuricataLog = Join-Path $PSScriptRoot "log"
$Script:SuricataPidFile = Join-Path $Script:WorkspacePath "state\suricata.pid"
$Script:SuricataLogFile = Join-Path $Script:WorkspacePath "logs\suricata-control.log"

# Ensure directories exist
@($Script:SuricataLog, (Split-Path $Script:SuricataPidFile -Parent), (Split-Path $Script:SuricataLogFile -Parent)) | ForEach-Object {
    if (!(Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}

#region Logging Functions
function Write-SuricataLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [SURICATA] [$Level] $Message"
    
    # Write to console with colors
    switch ($Level) {
        "INFO"    { Write-Host $LogEntry -ForegroundColor Cyan }
        "WARN"    { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
    }
    
    # Write to log file
    try {
        Add-Content -Path $Script:SuricataLogFile -Value $LogEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Silently continue if unable to write to log
    }
}
#endregion

#region PID Management Functions
function Save-SuricataPid {
    param([int]$ProcessId)
    
    try {
        Set-Content -Path $Script:SuricataPidFile -Value $ProcessId -Force
        Write-SuricataLog "Saved Suricata PID $ProcessId to file" "INFO"
        return $true
    }
    catch {
        Write-SuricataLog "Failed to save PID: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-SuricataPid {
    try {
        if (Test-Path $Script:SuricataPidFile) {
            $ProcessId = Get-Content $Script:SuricataPidFile -ErrorAction SilentlyContinue
            if ($ProcessId -and $ProcessId -match '^\d+$') {
                return [int]$ProcessId
            }
        }
        return $null
    }
    catch {
        Write-SuricataLog "Error reading PID file: $($_.Exception.Message)" "WARN"
        return $null
    }
}

function Remove-SuricataPid {
    try {
        if (Test-Path $Script:SuricataPidFile) {
            Remove-Item $Script:SuricataPidFile -Force -ErrorAction SilentlyContinue
            Write-SuricataLog "Removed PID file" "INFO"
        }
        return $true
    }
    catch {
        Write-SuricataLog "Failed to remove PID file: $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Test-SuricataProcessRunning {
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

#region Network Interface Functions
function Get-AvailableNetworkInterfaces {
    try {
        $interfaces = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object Name, InterfaceIndex, InterfaceDescription
        
        if ($interfaces.Count -eq 0) {
            Write-SuricataLog "No active network interfaces found" "WARN"
            return @("any")  # Fallback to 'any'
        }
        
        Write-SuricataLog "Found $($interfaces.Count) active network interface(s)" "INFO"
        foreach ($iface in $interfaces) {
            Write-SuricataLog "  - $($iface.Name) (Index: $($iface.InterfaceIndex)): $($iface.InterfaceDescription)" "INFO"
        }
        
        # Prioritize Wi-Fi interfaces over virtual ones and return interface name
        $prioritizedInterfaces = @()
        
        # First, add Wi-Fi interfaces
        $wifiInterfaces = $interfaces | Where-Object { $_.Name -like "*Wi-Fi*" -or $_.InterfaceDescription -like "*Wi-Fi*" -or $_.InterfaceDescription -like "*Wireless*" }
        if ($wifiInterfaces) {
            $prioritizedInterfaces += $wifiInterfaces.Name
        }
        
        # Then add physical Ethernet interfaces
        $ethernetInterfaces = $interfaces | Where-Object { $_.Name -like "*Ethernet*" -and $_.InterfaceDescription -notlike "*Virtual*" -and $_.InterfaceDescription -notlike "*Hyper-V*" }
        if ($ethernetInterfaces) {
            $prioritizedInterfaces += $ethernetInterfaces.Name
        }
        
        # Finally add virtual interfaces as fallback
        $virtualInterfaces = $interfaces | Where-Object { $_.InterfaceDescription -like "*Virtual*" -or $_.InterfaceDescription -like "*Hyper-V*" }
        if ($virtualInterfaces) {
            $prioritizedInterfaces += $virtualInterfaces.Name
        }
        
        if ($prioritizedInterfaces.Count -gt 0) {
            return $prioritizedInterfaces
        } else {
            return $interfaces.Name
        }
    }
    catch {
        Write-SuricataLog "Error detecting network interfaces: $($_.Exception.Message)" "WARN"
        return @("any")  # Fallback to 'any'
    }
}
#endregion

#region Suricata Control Functions
function Get-SuricataStatus {
    try {
        $PidFromFile = Get-SuricataPid
        $ProcessRunning = $false
        $ProcessId = $null
        
        if ($PidFromFile) {
            $ProcessRunning = Test-SuricataProcessRunning $PidFromFile
            if ($ProcessRunning) {
                $ProcessId = $PidFromFile
            } else {
                # PID file is stale, remove it
                Write-SuricataLog "PID file contains stale process ID $PidFromFile - removing" "WARN"
                Remove-SuricataPid
                $PidFromFile = $null
            }
        }
        
        # If PID file doesn't match running process, find actual process
        if (!$ProcessRunning) {
            $SuricataProcesses = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'suricata.exe'" -ErrorAction SilentlyContinue
            $WorkspaceProcesses = $SuricataProcesses | Where-Object { $_.ExecutablePath -eq $Script:SuricataBin }
            
            if ($WorkspaceProcesses.Count -gt 0) {
                $ProcessRunning = $true
                $ProcessId = $WorkspaceProcesses[0].ProcessId
                
                # Update PID file with correct process ID
                Save-SuricataPid $ProcessId
            }
        }
        
        return @{
            Running = $ProcessRunning
            ProcessId = $ProcessId
            PidFromFile = $PidFromFile
            ConfigFile = $Script:SuricataConfig
            LogDirectory = $Script:SuricataLog
            EVELogFile = Join-Path $Script:SuricataLog "eve.json"
        }
    }
    catch {
        Write-SuricataLog "Error checking Suricata status: $($_.Exception.Message)" "ERROR"
        return @{
            Running = $false
            ProcessId = $null
            PidFromFile = $null
            Error = $_.Exception.Message
        }
    }
}

function Start-SuricataService {
    Write-SuricataLog "Starting Suricata Network IDS..." "INFO"
    
    try {
        $Status = Get-SuricataStatus
        if ($Status.Running) {
            Write-SuricataLog "Suricata is already running (PID: $($Status.ProcessId))" "WARN"
            return $true
        }
        
        if (!(Test-Path $Script:SuricataBin)) {
            Write-SuricataLog "Suricata executable not found: $Script:SuricataBin" "ERROR"
            return $false
        }
        
        if (!(Test-Path $Script:SuricataConfig)) {
            Write-SuricataLog "Suricata config file not found: $Script:SuricataConfig" "ERROR"
            return $false
        }
        
        # Detect network interfaces
        $Interfaces = Get-AvailableNetworkInterfaces
        $PrimaryInterface = $Interfaces[0]
        
        Write-SuricataLog "Using network interface: $PrimaryInterface" "INFO"
        Write-SuricataLog "Starting Suricata from workspace: $Script:SuricataBin" "INFO"
        
        # Set up environment for Npcap
        $OriginalPath = $env:PATH
        $WorkspaceBin = Split-Path $Script:SuricataBin -Parent
        $WorkspaceNpcap = Join-Path $Script:WorkspacePath "npcap"
        $SystemNpcap = "C:\Windows\System32\Npcap"
        
        # Add both workspace and system Npcap paths to PATH
        $env:PATH = "$WorkspaceBin;$WorkspaceNpcap;$SystemNpcap;$OriginalPath"
        
        try {
            # Prepare Suricata arguments - use WinDivert for Windows packet capture
            $SuricataArgs = @(
                "-c", "`"$Script:SuricataConfig`"",
                "--windivert", "true",
                "-l", "`"$Script:SuricataLog`"",
                "--init-errors-fatal"
            )
            
            Write-SuricataLog "Command: $Script:SuricataBin $($SuricataArgs -join ' ')" "INFO"
            Write-SuricataLog "Environment PATH includes: $WorkspaceNpcap, $SystemNpcap" "INFO"
            
            # Create startup info for background process
            $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
            $StartInfo.FileName = $Script:SuricataBin
            $StartInfo.Arguments = $SuricataArgs -join " "
            $StartInfo.UseShellExecute = $false
            $StartInfo.CreateNoWindow = $false
            $StartInfo.RedirectStandardOutput = $false
            $StartInfo.RedirectStandardError = $false
            $StartInfo.WorkingDirectory = (Split-Path $Script:SuricataBin -Parent)
            
            # Start the process
            $Process = [System.Diagnostics.Process]::Start($StartInfo)
            if ($Process) {
                Write-SuricataLog "Suricata start command executed (Process PID: $($Process.Id))" "INFO"
                
                # Save the PID immediately
                Save-SuricataPid $Process.Id
                
                # Wait a moment and check if process is still running
                Start-Sleep -Seconds 3
                
                if (!$Process.HasExited) {
                    Write-SuricataLog "Suricata process started successfully (PID: $($Process.Id))" "SUCCESS"
                    
                    # Verify EVE log file creation
                    Start-Sleep -Seconds 2
                    $EVELogFile = Join-Path $Script:SuricataLog "eve.json"
                    if (Test-Path $EVELogFile) {
                        Write-SuricataLog "EVE JSON log file created: $EVELogFile" "SUCCESS"
                    } else {
                        Write-SuricataLog "Waiting for EVE JSON log file creation..." "INFO"
                    }
                    
                    return $true
                } else {
                    Write-SuricataLog "Suricata process exited immediately. Check logs for errors." "ERROR"
                    return $false
                }
            } else {
                Write-SuricataLog "Failed to execute Suricata start command" "ERROR"
                return $false
            }
        }
        catch {
            Write-SuricataLog "Error in inner Suricata startup: $($_.Exception.Message)" "ERROR"
            return $false
        }
        finally {
            # Restore original PATH
            $env:PATH = $OriginalPath
        }
    }
    catch {
        Write-SuricataLog "Error starting Suricata: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Stop-SuricataService {
    Write-SuricataLog "Stopping Suricata Network IDS..." "INFO"
    
    try {
        $Status = Get-SuricataStatus
        if (!$Status.Running) {
            Write-SuricataLog "Suricata is not running" "WARN"
            Remove-SuricataPid
            return $true
        }
        
        # Try graceful shutdown first
        Write-SuricataLog "Attempting graceful shutdown of Suricata process (PID: $($Status.ProcessId))..." "INFO"
        
        try {
            $Process = Get-Process -Id $Status.ProcessId -ErrorAction SilentlyContinue
            if ($Process) {
                $Process.CloseMainWindow() | Out-Null
                
                # Wait for graceful shutdown
                $WaitTime = 10
                $Stopped = $Process.WaitForExit($WaitTime * 1000)
                
                if (!$Stopped) {
                    Write-SuricataLog "Force terminating Suricata process $($Status.ProcessId)" "WARN"
                    $Process.Kill()
                    $Process.WaitForExit(5000) | Out-Null
                }
                
                Write-SuricataLog "Suricata process $($Status.ProcessId) terminated" "SUCCESS"
            }
        }
        catch {
            Write-SuricataLog "Error during shutdown: $($_.Exception.Message)" "WARN"
        }
        
        # Remove PID file
        Remove-SuricataPid
        
        # Final check
        Start-Sleep -Seconds 3
        $FinalStatus = Get-SuricataStatus
        if (!$FinalStatus.Running) {
            Write-SuricataLog "Suricata stopped successfully" "SUCCESS"
            return $true
        } else {
            Write-SuricataLog "Suricata may still be running after stop attempt" "WARN"
            return $false
        }
    }
    catch {
        Write-SuricataLog "Error stopping Suricata: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Show-SuricataStatus {
    Write-Host ""
    Write-Host "=== SURICATA NETWORK IDS STATUS ===" -ForegroundColor Cyan
    
    $Status = Get-SuricataStatus
    
    if ($Status.Running) {
        Write-Host "Status: RUNNING" -ForegroundColor Green
        Write-Host "PID: $($Status.ProcessId)" -ForegroundColor Green
    } else {
        Write-Host "Status: STOPPED" -ForegroundColor Red
    }
    
    Write-Host "Config File: $($Status.ConfigFile)"
    Write-Host "Log Directory: $($Status.LogDirectory)"
    Write-Host "EVE Log File: $($Status.EVELogFile)"
    
    if (Test-Path $Status.EVELogFile) {
        $LogInfo = Get-Item $Status.EVELogFile
        Write-Host "EVE Log Size: $([math]::Round($LogInfo.Length / 1KB, 2)) KB"
        Write-Host "EVE Log Modified: $($LogInfo.LastWriteTime.ToString('MM/dd/yyyy HH:mm:ss'))"
    }
    
    Write-Host ("=" * 50)
}
#endregion

# Main execution logic
if ($args.Count -gt 0) {
    switch ($args[0].ToLower()) {
        "start" {
            if (Start-SuricataService) { exit 0 } else { exit 1 }
        }
        "stop" {
            if (Stop-SuricataService) { exit 0 } else { exit 1 }
        }
        "status" {
            Show-SuricataStatus
            exit 0
        }
        default {
            Write-Host "Usage: .\SuricataControl.ps1 [start|stop|status]" -ForegroundColor Yellow
            Write-Host "  start    - Start Suricata Network IDS" -ForegroundColor Gray
            Write-Host "  stop     - Stop Suricata Network IDS" -ForegroundColor Gray
            Write-Host "  status   - Show current status" -ForegroundColor Gray
            exit 1
        }
    }
} else {
    Show-SuricataStatus
}