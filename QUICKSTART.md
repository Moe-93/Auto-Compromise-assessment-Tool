# Quick Start Guide - Compromise Assessment Tool

## Installation

1. Ensure Python 3.8+ is installed:
   ```bash
   python --version
   ```

2. Download/clone the tool to your desired location

3. No additional dependencies required (uses Python standard library)

## Basic Usage

### 1. List Supported Artifacts
```bash
python cat.py --list-artifacts
```

### 2. Process Windows Artifacts
```bash
# Process all Windows artifacts in a directory
python cat.py --windows-artifacts /path/to/windows/artifacts

# With custom output directory
python cat.py --windows-artifacts C:\forensics\windows --output ./my_reports
```

### 3. Process Linux Artifacts
```bash
# Process all Linux artifacts in a directory
python cat.py --linux-artifacts /var/log

# With custom output directory
python cat.py --linux-artifacts /path/to/linux/logs --output ./investigation
```

### 4. Process Both Windows and Linux
```bash
python cat.py \
    --windows-artifacts /path/to/windows \
    --linux-artifacts /path/to/linux \
    --output ./combined_report
```

### 5. Process Single File
```bash
# Analyze a specific log file
python cat.py \
    --single-file /var/log/auth.log \
    --artifact-type sshlogin

# Analyze Windows Security Event Log
python cat.py \
    --single-file C:\logs\security.evtx \
    --artifact-type security_event_logs
```

## Artifact Collection

### Windows Artifacts to Collect
Use KAPE or similar tools to collect:
- `C:\Windows\System32\winevt\Logs\Security.evtx`
- `C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`
- `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx`
- `C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx`
- `C:\Windows\System32\winevt\Logs\System.evtx`
- `C:\Windows\Prefetch\*.pf`
- `C:\Windows\AppCompat\Programs\Amcache.hve`
- `C:\Windows\System32\config\SYSTEM` (for ShimCache)
- Registry hives for autoruns

### Linux Artifacts to Collect
- `/var/log/auth.log` or `/var/log/secure`
- `/var/log/syslog` or `/var/log/messages`
- `/var/log/cron` or `/var/log/crontab`
- `/var/log/yum.log`
- `~/.bash_history` (for each user)
- `~/.zsh_history` (for each user)
- `/etc/crontab`
- `/etc/cron.d/*`
- `/var/log/docker.log` (if applicable)
- Web server access logs (Apache/Nginx)

## Understanding Output

### Exit Codes
- `0` - No critical findings (still review report)
- `1` - High severity findings detected
- `2` - Critical findings detected (immediate action required)

### Report Files
After execution, check the `reports/` directory (or your specified output directory):

1. **HTML Report** (`compromise_assessment_report_YYYYMMDD_HHMMSS.html`)
   - Open in any web browser
   - Interactive dashboard with findings
   - MITRE ATT&CK matrix visualization
   - Severity-based color coding

2. **JSON Report** (`compromise_assessment_report_YYYYMMDD_HHMMSS.json`)
   - Machine-readable format
   - Import into SIEM or other tools
   - Contains all raw findings

## Example Workflow

### Incident Response Scenario
```bash
# 1. Collect artifacts from compromised system using KAPE or manual collection

# 2. Run the assessment
python cat.py \
    --windows-artifacts ./collected_windows_artifacts \
    --linux-artifacts ./collected_linux_artifacts \
    --output ./incident_2024_001

# 3. Review the HTML report
open ./incident_2024_001/compromise_assessment_report_*.html

# 4. Check exit code
echo $?  # 0 = OK, 1 = High findings, 2 = Critical findings

# 5. If critical findings, immediately escalate and begin containment
```

### Routine Audit
```bash
# Quick check of Linux authentication logs
python cat.py \
    --single-file /var/log/auth.log \
    --artifact-type sshlogin \
    --output ./audit_$(date +%Y%m%d)
```

## Interpreting Results

### Severity Levels
- **CRITICAL**: Immediate threat detected (malware, active intrusion)
- **HIGH**: Suspicious activity requiring investigation
- **MEDIUM**: Anomalous behavior, verify legitimacy
- **LOW**: Informational, potential security concern
- **INFO**: General information

### MITRE ATT&CK Mapping
Each finding includes:
- Technique ID (e.g., T1059.001)
- Technique Name
- Tactic (Execution, Persistence, etc.)
- Description of the technique

## Troubleshooting

### "No findings detected"
- Verify artifact files are not empty
- Check file permissions
- Ensure correct artifact type specified

### "Error parsing file"
- Check file encoding (should be UTF-8 or ASCII)
- Verify file is not corrupted
- Ensure correct artifact type for file format

### "Permission denied"
- Run with appropriate privileges
- Check file ownership and permissions

## Best Practices

1. **Always verify findings** - Automated detection can have false positives
2. **Correlate across artifacts** - Single findings may be benign, patterns indicate compromise
3. **Maintain chain of custody** - Document all steps in forensic process
4. **Regular assessments** - Run periodically for threat hunting
5. **Keep updated** - Update MITRE mappings as new techniques emerge

## Getting Help

1. Check README.md for detailed documentation
2. Review code comments for implementation details
3. Validate with known-good test data first
4. Cross-reference findings with MITRE ATT&CK framework

## Security Considerations

⚠️ **WARNING**: This tool is for authorized security assessments only.

- Always obtain proper authorization before analyzing systems
- Handle forensic artifacts securely
- Protect generated reports (contain sensitive system information)
- Follow your organization's incident response procedures
