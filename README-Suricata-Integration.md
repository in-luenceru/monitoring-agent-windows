# Suricata Network IDS Integration

## Overview

This document describes the complete integration of Suricata Network Intrusion Detection System (IDS) with the Wazuh monitoring agent workspace. The integration enables unified monitoring of both system-level and network-level security events through a single management interface.

## Integration Components

### 1. Suricata Installation
- **Location**: `suricata/` directory within workspace
- **Binary**: `suricata/bin/suricata.exe` (Version 8.0.0-beta1)
- **Configuration**: `suricata/etc/suricata.yaml` (workspace-customized)
- **Logs**: `suricata/log/` directory for all Suricata output

### 2. Control Scripts
- **Standalone Control**: `suricata/SuricataControl.ps1` - Independent Suricata management
- **Integrated Control**: `MonitoringAgentControl.ps1` - Unified agent + Suricata management
- **Test Scripts**: 
  - `test_suricata_integration.ps1` - Comprehensive integration testing
  - `test_integration_simple.ps1` - Quick validation script

### 3. Configuration Files
- **Suricata Config**: `suricata/etc/suricata.yaml` - Network IDS settings
- **Agent Config**: `ossec.conf` - Enhanced with Suricata log monitoring
- **Analysis Report**: `SURICATA_INTEGRATION_ANALYSIS.md` - Technical documentation

## Features

### Unified Management
```powershell
# Start both monitoring agent and Suricata IDS
.\MonitoringAgentControl.ps1 start

# Check status of both services
.\MonitoringAgentControl.ps1 status

# Stop both services
.\MonitoringAgentControl.ps1 stop

# Restart both services
.\MonitoringAgentControl.ps1 restart
```

### Individual Suricata Control
```powershell
# Standalone Suricata management
.\suricata\SuricataControl.ps1 start|stop|restart|status|test
```

### Network Traffic Monitoring
- **EVE JSON Logging**: Structured event output in JSON format
- **Real-time Analysis**: Live network traffic inspection
- **Alert Generation**: Intrusion detection and prevention alerts
- **Protocol Support**: DNS, HTTP, TLS, SSH, and more

### Integration Testing
```powershell
# Quick validation
.\test_integration_simple.ps1

# Comprehensive testing
.\test_suricata_integration.ps1
```

## Configuration Details

### Suricata Configuration
The `suricata/etc/suricata.yaml` file has been customized for workspace operation:

```yaml
# Key configurations:
default-log-dir: C:\Users\...\monitoring-agent-windows\suricata\log
outputs:
  - eve-log:
      enabled: yes
      filename: C:\Users\...\monitoring-agent-windows\suricata\log\eve.json
```

### Wazuh Agent Configuration
The `ossec.conf` file includes Suricata log monitoring:

```xml
<localfile>
  <location>suricata\log\eve.json</location>
  <log_format>json</log_format>
</localfile>
```

### Network Interface Detection
The system automatically detects and uses available network interfaces:
- Hyper-V Virtual Ethernet Adapters
- Physical Wi-Fi adapters
- VirtualBox adapters
- Other active network interfaces

## Technical Architecture

### Data Flow
1. **Network Traffic** → Suricata Engine
2. **Suricata Engine** → EVE JSON Log (`suricata/log/eve.json`)
3. **Wazuh Agent** → Monitors EVE JSON log
4. **Wazuh Agent** → Forwards alerts to Wazuh Manager
5. **Wazuh Manager** → Processes and correlates system + network events

### Process Management
- **PID Tracking**: Both services maintain PID files for process management
- **Graceful Shutdown**: Services stop cleanly with proper cleanup
- **Auto-restart Prevention**: Manual stops disable automatic restarts
- **Status Monitoring**: Real-time process status checking

### Log Management
- **EVE JSON Format**: Single-line JSON entries for each network event
- **Log Rotation**: Handled by Suricata's internal log management
- **Integration**: Wazuh agent automatically ingests and forwards logs

## Installation and Setup

### Prerequisites
1. **Administrator Privileges**: Required for network interface access
2. **Npcap Driver**: Packet capture library (included in workspace)
3. **Network Interfaces**: At least one active network interface
4. **PowerShell**: Version 5.1 or higher

### Verification Steps
1. Run integration validation:
   ```powershell
   .\test_integration_simple.ps1
   ```

2. Check individual components:
   ```powershell
   .\suricata\SuricataControl.ps1 test
   .\MonitoringAgentControl.ps1 status
   ```

3. Test unified control:
   ```powershell
   .\MonitoringAgentControl.ps1 start
   .\MonitoringAgentControl.ps1 status
   ```

## Troubleshooting

### Common Issues

#### 1. Suricata Not Starting
- **Check**: Administrator privileges
- **Check**: Network interface availability
- **Check**: Configuration file syntax
- **Solution**: Run `.\suricata\SuricataControl.ps1 test`

#### 2. No EVE Log File Created
- **Check**: Log directory permissions
- **Check**: Absolute paths in configuration
- **Check**: Network traffic generation
- **Solution**: Generate network activity (ping, web browsing)

#### 3. PID File Issues
- **Symptom**: "Already running" messages when service is stopped
- **Solution**: Clean PID files in `state/` directory
- **Command**: `Remove-Item state\suricata.pid -Force`

#### 4. Agent Not Forwarding Alerts
- **Check**: Wazuh agent connectivity to manager
- **Check**: EVE JSON log format validation
- **Check**: ossec.conf configuration
- **Solution**: Review agent logs for connection issues

### Log Locations
- **Suricata Logs**: `suricata/log/`
- **Agent Logs**: `ossec.log`
- **Integration Test Logs**: `logs/suricata_integration_test.log`
- **Control Script Logs**: Console output with timestamps

### Diagnostic Commands
```powershell
# Check processes
Get-Process -Name suricata, monitoring-agent -ErrorAction SilentlyContinue

# Check network interfaces
Get-NetAdapter | Where-Object {$_.Status -eq "Up"}

# Validate configuration
.\suricata\SuricataControl.ps1 test

# Check agent status
.\MonitoringAgentControl.ps1 status
```

## Performance Considerations

### Resource Usage
- **CPU**: Suricata uses 1-2% CPU during normal operation
- **Memory**: Approximately 2-10 MB RAM depending on traffic volume
- **Disk**: Log files grow based on network activity
- **Network**: Minimal impact on network performance

### Optimization Tips
1. **Interface Selection**: Use the most active network interface
2. **Rule Configuration**: Customize detection rules for your environment
3. **Log Rotation**: Monitor log file sizes and implement rotation
4. **Performance Tuning**: Adjust buffer sizes in suricata.yaml

## Security Considerations

### Permissions
- **Network Access**: Requires raw socket access for packet capture
- **File System**: Needs write access to log directories
- **Process Control**: Administrator rights for service management

### Data Protection
- **Log Security**: EVE JSON logs contain network metadata
- **Access Control**: Protect configuration files from unauthorized access
- **Encryption**: Network traffic analysis may reveal sensitive patterns

### Compliance
- **GDPR/Privacy**: Network monitoring may capture personal data
- **Data Retention**: Implement appropriate log retention policies
- **Audit Trail**: Maintain records of configuration changes

## Advanced Configuration

### Custom Rules
1. **Rule Location**: `suricata/rules/` directory
2. **Rule Format**: Suricata rule syntax
3. **Rule Updates**: Manual or automated rule management
4. **Testing**: Validate rules before deployment

### Performance Tuning
```yaml
# Example optimizations in suricata.yaml
threading:
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 0 ]
    - worker-cpu-set:
        cpu: [ "1-3" ]

# Buffer sizes
app-layer:
  protocols:
    http:
      request-buffer-size: 16kb
      response-buffer-size: 16kb
```

### Integration Extensions
- **Custom Alerting**: Enhanced alert processing
- **Dashboard Integration**: Visualization of network events
- **Threat Intelligence**: Integration with threat feeds
- **Automated Response**: Active response to network threats

## Maintenance

### Regular Tasks
1. **Log Monitoring**: Check log file sizes and rotation
2. **Performance Review**: Monitor CPU and memory usage
3. **Rule Updates**: Keep detection rules current
4. **Configuration Backup**: Maintain configuration backups

### Health Checks
```powershell
# Daily health check script
.\test_integration_simple.ps1
.\MonitoringAgentControl.ps1 status
```

### Updates and Patches
1. **Suricata Updates**: Follow official Suricata update procedures
2. **Configuration Merging**: Preserve custom configurations during updates
3. **Testing**: Validate functionality after updates
4. **Rollback Plan**: Maintain previous working configurations

## Support and Documentation

### Official Resources
- **Suricata Documentation**: https://docs.suricata.io/
- **Wazuh Documentation**: https://documentation.wazuh.com/
- **PowerShell Reference**: https://docs.microsoft.com/powershell/

### Custom Documentation
- **Technical Analysis**: `SURICATA_INTEGRATION_ANALYSIS.md`
- **Test Results**: `logs/suricata_integration_test.log`
- **Configuration Backups**: Versioned in workspace

### Contact Information
- **Integration Support**: Custom Security Solutions Team
- **Version**: 1.0.0 (September 2025)
- **Last Updated**: September 23, 2025

---

This integration provides a complete network security monitoring solution that enhances the existing system monitoring capabilities with real-time network intrusion detection and automated alert forwarding to the centralized Wazuh management platform.