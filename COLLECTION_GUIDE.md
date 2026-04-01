# CAT Tool Collection Guide

## Overview

The Compromise Assessment Tool (CAT) now includes **integrated forensic artifact collection** capabilities for both Windows and Linux systems. This allows you to collect, parse, and analyze artifacts in a single workflow.

## Collection Modes

### 1. Collect and Analyze (One-Step)
```bash
# Windows: Collect and analyze immediately
python cat.py --collect --os windows --analyze

# Linux: Collect and analyze immediately
python cat.py --collect --os linux --analyze

# With custom output locations
python cat.py --collect --os windows --analyze --collection-output ./artifacts --output ./reports
```

### 2. Collect Only
```bash
# Windows collection only
python cat.py --collect --os windows --collection-output ./windows_artifacts

# Linux collection only
python cat.py --collect --os linux --collection-output ./linux_artifacts

# Package into zip file
python cat.py --collect --os windows --package
```

### 3. Analyze Previously Collected
```bash
# Analyze artifacts collected earlier
python cat.py --collected-dir ./artifacts/hostname_20240115_143022

# Or specify Windows/Linux subdirectories
python cat.py --windows-artifacts ./artifacts/hostname_20240115_143022/Windows
```

## Windows Artifact Collection

### Artifacts Collected

| Artifact | Description | Collection Method |
|----------|-------------|-------------------|
| **Prefetch** | Program execution history | Copy C:\Windows\Prefetch\*.pf |
| **ShimCache** | Application compatibility cache | Copy Amcache.hve/RecentFileCache.bcf |
| **AmCache** | Program installation evidence | Copy Amcache.hve |
| **StartupItems** | Persistence locations | Copy Startup folders |
| **DLLs** | System32 DLL listing | Directory listing |
| **HostedServices** | Windows services | `sc query` command |
| **Executables** | System executables listing | Directory walk |
| **SecurityWELS** | Security event logs | Copy Security.evtx |
| **SystemWELS** | System event logs | Copy System.evtx |
| **BITSWELS** | Background Intelligent Transfer logs | Copy BITS-Client%4Operational.evtx |
| **PowerShellOperationalWELS** | PowerShell execution logs | Copy PowerShell%4Operational.evtx |
| **TaskSchedulerWELS** | Scheduled task events | Copy TaskScheduler%4Operational.evtx |
| **LocalTermServerWELS** | RDP local session events | Copy TerminalServices-LocalSessionManager |
| **RemoteTermServerWELS** | RDP connection events | Copy TerminalServices-RemoteConnectionManager |
| **WindowsPowerShellWELS** | Legacy PowerShell logs | Copy Windows PowerShell.evtx |
| **PrintSvcWELS** | Print service events | Copy PrintService%4Operational.evtx |
| **WMIWELS** | WMI activity logs | Copy WMI-Activity%4Operational.evtx |
| **Autoruns** | Startup programs | `wmic startup` command |
| **WERLogs** | Windows Error Reporting | Copy WER directory |
| **NamedPipesAudit** | Named pipe listing | PowerShell Get-ChildItem |
| **AppShimsAudit** | Application shims | Copy Amcache.hve |
| **GPOScriptsAudit** | Group Policy scripts | Copy GroupPolicy Scripts folders |
| **WindowsFirewall** | Firewall configuration | `netsh advfirewall` command |
| **CCMRUA** | SCCM client logs | Copy CCM\Logs directory |
| **DefenderWELS** | Windows Defender events | Copy Windows Defender%4Operational.evtx |
| **CertUtilCache** | Certificate utility cache | `certutil -urlcache` command |
| **OSInfo** | System information | `systeminfo` command |
| **MFT** | NTFS metadata | `fsutil fsinfo ntfsinfo` |
| **USBSTOR** | USB device history | Registry export of USBSTOR |
| **BrowsingHistory** | Browser data | Copy browser history files |
| **RunningProcesses** | Active processes | `wmic process` command |

### Windows Collection Examples

```powershell
# Basic collection (run as Administrator)
python cat.py --collect --os windows --analyze

# Collect specific artifacts only
python cat.py --collect --os windows --artifacts SecurityWELS PowerShellOperationalWELS

# Collect and package for transfer
python cat.py --collect --os windows --package --collection-output C:\Forensics

# Collection with full logging
python cat.py --collect --os windows --analyze --output C:\Cases\Case001
```

### Windows Collection Requirements

- **Administrator privileges** required for:
  - Accessing event logs (Security.evtx)
  - Reading registry hives
  - Querying service configurations
  - Accessing other users' profiles

- **PowerShell execution policy** may need adjustment:
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
  ```

## Linux Artifact Collection

### Artifacts Collected

| Artifact | Description | Collection Method |
|----------|-------------|-------------------|
| **Yumlog** | Package manager logs | Copy /var/log/yum.log, dnf.log |
| **ShellHistory** | User command history | Find and copy .bash_history, .zsh_history |
| **Crontab** | Scheduled tasks | Copy /etc/crontab, /etc/cron.* |
| **LastUserLogin** | Login history | `last -a` command |
| **AddUser** | User account info | Copy /etc/passwd, shadow, group, sudoers |
| **SSHLogin** | SSH authentication | Copy /var/log/auth.log, secure |
| **SudoCommands** | Privileged command usage | grep sudo from auth logs |
| **Netstat** | Network connections | `netstat -tulpn` command |
| **AuthorizedKeys** | SSH authorized keys | Find and copy authorized_keys files |
| **KnownHosts** | SSH known hosts | Find and copy known_hosts files |
| **Users** | User listing | `cat /etc/passwd` |
| **DockerContainers** | Container information | `docker ps`, `docker images` |
| **WebShells** | Web server data | Copy /var/log/apache2, nginx, /var/www |
| **MalShells** | Suspicious scripts | Find scripts in /tmp, /var/tmp, /dev/shm |
| **TmpListing** | Temporary directory listing | `ls -la` on temp directories |
| **Systemd** | System services | Copy /etc/systemd/system, /usr/lib/systemd |
| **PreloadCheck** | Library preload config | Copy /etc/ld.so.preload, ld.so.conf |
| **SyslogEvents** | System logs | Copy /var/log/syslog, messages, kern.log |
| **SecureEvents** | Security logs | Copy /var/log/secure, auth.log, audit.log |
| **OSInfo** | System information | uname, os-release, hostnamectl, etc. |

### Linux Collection Examples

```bash
# Basic collection (run as root for full access)
sudo python cat.py --collect --os linux --analyze

# Collect specific artifacts
sudo python cat.py --collect --os linux --artifacts ShellHistory SSHLogin

# Collect and package
sudo python cat.py --collect --os linux --package --collection-output /cases

# Non-root collection (limited)
python cat.py --collect --os linux --collection-output ~/artifacts
```

### Linux Collection Requirements

- **Root privileges** recommended for:
  - Accessing all system logs
  - Reading /etc/shadow
  - Accessing all user directories
  - Running netstat with process info
  - Accessing Docker info

- **Some artifacts accessible as regular user**:
  - Own shell history
  - Some system information commands
  - Public configuration files

## Collection Best Practices

### 1. Minimize System Impact

Based on forensic best practices [^41^] [^35^]:

```bash
# Run from external media when possible
# This avoids writing to the target system's disk
mount /dev/sdb1 /mnt/external
cd /mnt/external
python cat.py --collect --os linux --collection-output ./artifacts
```

### 2. Verify Collection Integrity

```bash
# After collection, verify the summary
cat collected_artifacts/hostname_timestamp/collection.log

# Check for errors
grep "ERROR" collected_artifacts/hostname_timestamp/collection.log

# Review summary
cat collected_artifacts/hostname_timestamp/Linux_collection_summary.json
```

### 3. Chain of Custody

```bash
# Generate hash of collection
sha256sum collected_artifacts/hostname_timestamp_forensics.zip > collection.sha256

# Include timestamp and case info
echo "Case: CASE-2024-001" >> collection.sha256
echo "Collector: Analyst Name" >> collection.sha256
echo "Date: $(date -Iseconds)" >> collection.sha256
```

### 4. Remote Collection

For remote systems, use established methods [^47^] [^65^]:

```bash
# Option 1: SSH to target and run
ssh user@target "python cat.py --collect --os linux" > artifacts.tar.gz

# Option 2: Copy script and execute
scp -r ca_tool/ user@target:/tmp/
ssh user@target "cd /tmp/ca_tool && sudo python cat.py --collect --os linux --package"
scp user@target:/tmp/ca_tool/*.zip ./

# Option 3: Using EDR live response (Defender, etc.)
# Upload cat.py to EDR library
# Execute via live response session
# Download results
```

## Automated Collection Scripts

### Windows Batch Script

```batch
@echo off
REM Windows_Forensic_Collection.bat
REM Run as Administrator

echo Starting forensic collection...

python cat.py --collect --os windows --analyze --package ^
    --collection-output C:\Forensics ^
    --output C:\Reports

if %ERRORLEVEL% == 2 (
    echo CRITICAL findings detected!
    echo Notify security team immediately.
) else if %ERRORLEVEL% == 1 (
    echo HIGH findings detected.
    echo Review required.
) else (
    echo Collection complete. No critical findings.
)

pause
```

### Linux Bash Script

```bash
#!/bin/bash
# linux_forensic_collection.sh
# Run with sudo

set -e

CASE_ID="${1:-CASE-$(date +%Y%m%d)}"
OUTPUT_DIR="/cases/${CASE_ID}"

echo "[+] Starting forensic collection for case: ${CASE_ID}"

# Create case directory
mkdir -p "${OUTPUT_DIR}"

# Run collection and analysis
python cat.py --collect --os linux --analyze --package     --collection-output "${OUTPUT_DIR}/artifacts"     --output "${OUTPUT_DIR}/reports"

EXIT_CODE=$?

# Handle exit codes
if [ $EXIT_CODE -eq 2 ]; then
    echo "[!] CRITICAL findings detected!"
    echo "[!] Immediate escalation required!"
    # Send alert (configure as needed)
    # mail -s "CRITICAL: ${CASE_ID}" security@company.com < report
elif [ $EXIT_CODE -eq 1 ]; then
    echo "[!] HIGH findings detected."
    echo "[!] Review required."
else
    echo "[+] Collection complete. No critical findings."
fi

# Generate hash
echo "[+] Generating integrity hash..."
cd "${OUTPUT_DIR}"
sha256sum *.zip > SHA256SUMS

echo "[+] Collection complete: ${OUTPUT_DIR}"
```

## Troubleshooting

### Windows Issues

**Problem**: Access denied to event logs
```powershell
# Solution: Run as Administrator
# Right-click PowerShell -> Run as Administrator
```

**Problem**: Execution policy prevents running
```powershell
# Solution: Set execution policy for current process
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
```

**Problem**: Some files locked by system
```
# This is normal for files like Registry hives
# CAT tool uses alternative collection methods
# Check collection.log for specific errors
```

### Linux Issues

**Problem**: Permission denied on logs
```bash
# Solution: Run with sudo
sudo python cat.py --collect --os linux
```

**Problem**: Command not found (netstat, etc.)
```bash
# Solution: Install net-tools or use alternatives
sudo apt-get install net-tools  # Debian/Ubuntu
sudo yum install net-tools      # RHEL/CentOS
```

**Problem**: Docker commands fail
```bash
# Non-root user needs docker group membership
# Or run with sudo
sudo python cat.py --collect --os linux
```

## Performance Considerations

### Collection Time Estimates

| System Type | Approximate Collection Time | Output Size |
|-------------|---------------------------|-------------|
| Windows Workstation | 5-15 minutes | 100MB-2GB |
| Windows Server | 10-30 minutes | 500MB-5GB |
| Linux Workstation | 3-10 minutes | 50MB-500MB |
| Linux Server | 5-20 minutes | 100MB-2GB |

### Factors Affecting Collection Time

- Event log sizes
- Number of user profiles
- Prefetch file count
- Browser history size
- Network speed (for remote)

## Security Considerations

⚠️ **IMPORTANT**: This tool is for **authorized forensic investigations only**.

1. **Authorization**: Ensure proper authorization before collecting
2. **Chain of Custody**: Document all collection steps
3. **Data Protection**: Secure collected artifacts
4. **Legal Compliance**: Follow applicable laws and regulations
5. **Minimize Footprint**: Run from external media when possible

## Integration with Existing Workflows

### With KAPE [^47^] [^67^]

```powershell
# CAT tool can supplement KAPE collections
# Run KAPE first, then CAT for analysis
kape.exe --tsource C: --target !SANS_Triage --tdest C:\kape_output
python cat.py --windows-artifacts C:\kape_output --output C:nalysis
```

### With Velociraptor [^41^]

```bash
# Deploy CAT via Velociraptor
# Create artifact that runs cat.py
# Collect results through Velociraptor
```

### With EDR (Defender, etc.) [^43^]

```powershell
# Upload cat.py to EDR library
# Execute via live response
run cat.py --collect --os windows --package
get collected_artifacts.zip
```

## Next Steps

After collection:

1. **Review Reports**: Check HTML report for findings
2. **Correlate Evidence**: Cross-reference multiple artifacts
3. **Timeline Analysis**: Use timestamps to reconstruct events
4. **Threat Hunting**: Look for additional IOCs
5. **Documentation**: Document findings and remediation

## Support

For issues or questions:
1. Check collection.log for detailed error messages
2. Verify system meets requirements
3. Review EXAMPLES.py for additional scenarios
4. Consult README.md for general usage
