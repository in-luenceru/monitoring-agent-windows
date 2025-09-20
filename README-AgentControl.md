# Monitoring Agent Control Center

A professional PowerShell script for managing Monitoring Agent Windows with comprehensive enrollment, configuration, and control capabilities.

## Features

- **Agent Enrollment**: Easy setup with manager IP and client key configuration
- **Base64 Support**: Handles both plain text and base64 encoded client keys
- **Agent Control**: Start, stop, restart, and status monitoring
- **Configuration Management**: Automatic backup and update of configuration files
- **User-Friendly Interface**: Interactive menu system with colored output
- **Production Ready**: Comprehensive logging, error handling, and validation
- **Command Line Support**: Can be used both interactively and via command line

## Requirements

- Windows PowerShell 5.1 or PowerShell Core 6+
- Administrator privileges
- Monitoring Agent installed in the same directory as the script

## Installation

1. Place the `MonitoringAgentControl.ps1` script in your Monitoring agent directory
2. Ensure you have the following files in the same directory:
   - `monitoring-agent.exe`
   - `ossec.conf`
   - `client.keys` (will be created during enrollment)

## Usage

### Interactive Mode (Recommended)

Run the script without parameters to launch the interactive menu:

```powershell
# Run as Administrator
.\MonitoringAgentControl.ps1
```

### Command Line Mode

For automation and scripting:

```powershell
# Start the agent
.\MonitoringAgentControl.ps1 start

# Stop the agent
.\MonitoringAgentControl.ps1 stop

# Restart the agent
.\MonitoringAgentControl.ps1 restart

# Check agent status
.\MonitoringAgentControl.ps1 status

# Start enrollment process
.\MonitoringAgentControl.ps1 enroll
```

## Interactive Menu Options

1. **Enroll Agent**: Configure connection to Monitoring manager
2. **Start Agent**: Start the Monitoring agent service
3. **Stop Agent**: Stop the Monitoring agent service
4. **Restart Agent**: Restart the agent service
5. **Check Agent Status**: View current agent status and connection
6. **View Recent Logs**: Display recent agent log entries
7. **Show Configuration**: Display current agent configuration
8. **Exit**: Close the control center

## Enrollment Process

The enrollment process guides you through:

1. **Manager Configuration**:
   - Enter Monitoring manager IP address or hostname
   - Specify manager port (default: 1514)

2. **Client Key Setup**:
   - Provide client key obtained from the manager
   - Supports both plain text and base64 encoded keys
   - Automatic format validation

3. **Configuration Update**:
   - Automatic backup of existing configuration
   - Update `ossec.conf` with manager details
   - Update `client.keys` with agent credentials

4. **Agent Startup**:
   - Option to start agent immediately after enrollment
   - Connection status verification

## Client Key Formats

### Plain Text Format
```
001 AGENT-NAME any 1234567890abcdef1234567890abcdef12345678
```

### Base64 Encoded Format
The script automatically detects and can decode base64 encoded keys.

## Configuration Files

### ossec.conf Updates
The script automatically updates:
- Manager IP address (`<address>`)
- Manager port (`<port>`)

### client.keys Format
```
ID NAME IP KEY
```
Example:
```
001 DESKTOP-IVBQT1T any 70fea647733e1339286489e9b4f6c132df186bbad13c74e43577268ecaa01990
```

## Logging

- **Console Output**: Colored status messages for easy reading
- **Log File**: Detailed logging to `logs\agent-control.log`
- **Backup Files**: Automatic configuration backups with timestamps

## Error Handling

The script includes comprehensive error handling for:
- Invalid IP addresses or hostnames
- Malformed client keys
- Configuration file access issues
- Agent startup/shutdown problems
- Network connectivity issues

## Status Indicators

### Agent Status
- **RUNNING**: Agent process is active
- **STOPPED**: Agent is not running
- **Connected**: Agent is communicating with manager
- **DISCONNECTED**: Agent cannot reach manager
- **UNKNOWN**: Connection status uncertain

### Connection Verification
The script checks:
- Agent process status
- Recent log entries for connectivity
- Agent state file information

## Security Features

- **Secure Input**: Client keys are hidden during input
- **Backup Protection**: Automatic configuration backups
- **Admin Validation**: Requires administrator privileges
- **Key Validation**: Validates client key format

## Troubleshooting

### Common Issues

1. **"Access Denied" Error**
   - Solution: Run PowerShell as Administrator

2. **"Agent executable not found"**
   - Solution: Ensure script is in the Monitoring agent directory

3. **"Connection failed"**
   - Check manager IP and port
   - Verify firewall settings
   - Confirm manager is running

4. **"Invalid client key"**
   - Verify key format (ID NAME IP KEY)
   - Check for extra spaces or characters
   - Ensure key was copied correctly from manager

### Log Locations

- **Agent Logs**: `logs\ossec.log`
- **Control Script Logs**: `logs\agent-control.log`
- **Configuration Backups**: `*.backup_YYYYMMDD_HHMMSS`

## Advanced Configuration

### Custom Manager Ports
The script supports custom manager ports. Standard ports:
- **1514**: Default Monitoring manager port
- **1515**: Alternative port for encrypted communications

### Network Validation
The script performs:
- IP address format validation
- Hostname resolution testing
- Base64 encoding detection

## Examples

### Example 1: First-time Setup
```powershell
# 1. Run the script as Administrator
.\MonitoringAgentControl.ps1

# 2. Select option 1 (Enroll Agent)
# 3. Enter manager IP: 192.168.1.100
# 4. Enter port: 1514 (or press Enter for default)
# 5. Enter client key from manager
# 6. Confirm configuration
# 7. Start agent when prompted
```

### Example 2: Automated Restart
```powershell
# Stop, wait, and start agent
.\MonitoringAgentControl.ps1 stop
Start-Sleep -Seconds 5
.\MonitoringAgentControl.ps1 start
```

### Example 3: Status Check in Script
```powershell
$Status = & .\MonitoringAgentControl.ps1 status
if ($LASTEXITCODE -eq 0) {
    Write-Host "Agent is running properly"
} else {
    Write-Host "Agent has issues"
}
```

## Support

For issues with the control script:
1. Check the log files for detailed error messages
2. Verify all prerequisites are met
3. Ensure proper file permissions
4. Review the Monitoring agent documentation

## Version History

- **v1.0.0**: Initial release with full functionality
  - Interactive menu system
  - Command line support
  - Base64 key support
  - Comprehensive logging
  - Production-ready error handling

## License

This script is provided as-is for managing Monitoring Agent Windows. Use in accordance with your organization's security policies.