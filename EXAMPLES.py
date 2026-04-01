#!/usr/bin/env python3
"""
CAT Tool Usage Examples
Comprehensive examples for different scenarios
"""

examples = """
================================================================================
COMPROMISE ASSESSMENT TOOL - USAGE EXAMPLES
================================================================================

EXAMPLE 1: BASIC WINDOWS ANALYSIS
---------------------------------
Analyze Windows forensic artifacts from a standard collection:

    python cat.py --windows-artifacts ./windows_forensics --output ./case_001

This will:
- Parse all Windows artifacts in the directory
- Detect suspicious activities and IOCs
- Map findings to MITRE ATT&CK
- Generate HTML and JSON reports in ./case_001/


EXAMPLE 2: BASIC LINUX ANALYSIS
-------------------------------
Analyze Linux system logs:

    python cat.py --linux-artifacts /var/log --output ./linux_audit

This will:
- Parse authentication logs, shell history, cron jobs
- Detect reverse shells, persistence mechanisms
- Identify privilege escalation attempts
- Map findings to MITRE ATT&CK


EXAMPLE 3: COMBINED WINDOWS AND LINUX ANALYSIS
----------------------------------------------
Analyze both Windows and Linux artifacts from a hybrid environment:

    python cat.py \
        --windows-artifacts ./windows_collection \
        --linux-artifacts ./linux_collection \
        --output ./hybrid_assessment

This provides a unified view of threats across your entire infrastructure.


EXAMPLE 4: SINGLE FILE ANALYSIS
-------------------------------
Quick analysis of a specific log file:

    # Analyze PowerShell operational log
    python cat.py \
        --single-file C:\Logs\PowerShell.evtx \
        --artifact-type powershell_operational_logs

    # Analyze SSH authentication log
    python cat.py \
        --single-file /var/log/auth.log \
        --artifact-type sshlogin

    # Analyze bash history
    python cat.py \
        --single-file /home/user/.bash_history \
        --artifact-type shell_history


EXAMPLE 5: INCIDENT RESPONSE TRIAGE
-----------------------------------
Rapid triage during an active incident:

    # Quick check of critical logs
    python cat.py \
        --single-file /var/log/auth.log \
        --artifact-type sshlogin \
        --output ./triage_$(date +%Y%m%d_%H%M%S)

    # Check exit code
    if [ $? -eq 2 ]; then
        echo "CRITICAL findings detected - escalate immediately!"
    elif [ $? -eq 1 ]; then
        echo "HIGH findings detected - requires investigation"
    fi


EXAMPLE 6: AUTOMATED SECURITY SCANNING
--------------------------------------
Integrate into automated security workflows:

    #!/bin/bash
    # daily_security_scan.sh

    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    REPORT_DIR="/security/reports/daily_$TIMESTAMP"

    python cat.py \
        --linux-artifacts /var/log \
        --output "$REPORT_DIR"

    EXIT_CODE=$?

    if [ $EXIT_CODE -eq 2 ]; then
        # Critical findings - send alert
        mail -s "CRITICAL: Security findings detected" \
            security-team@company.com < "$REPORT_DIR"/*.html
    elif [ $EXIT_CODE -eq 1 ]; then
        # High findings - log for review
        echo "$TIMESTAMP: High findings detected" >> /security/high_findings.log
    fi


EXAMPLE 7: FORENSIC INVESTIGATION
----------------------------------
Comprehensive forensic investigation:

    # Create case directory structure
    mkdir -p /cases/INC-2024-001/{evidence,reports,analysis}

    # Copy collected artifacts to evidence directory
    cp -r /collected/windows/* /cases/INC-2024-001/evidence/
    cp -r /collected/linux/* /cases/INC-2024-001/evidence/

    # Run assessment
    python cat.py \
        --windows-artifacts /cases/INC-2024-001/evidence/windows \
        --linux-artifacts /cases/INC-2024-001/evidence/linux \
        --output /cases/INC-2024-001/reports

    # Review findings
    firefox /cases/INC-2024-001/reports/*.html


EXAMPLE 8: THREAT HUNTING
-------------------------
Proactive threat hunting across the enterprise:

    #!/bin/bash
    # threat_hunt.sh

    SERVERS="web01 db01 mail01 file01"
    REPORT_BASE="/threat_hunt/$(date +%Y%m%d)"

    for server in $SERVERS; do
        echo "[*] Analyzing $server..."

        # Collect artifacts (requires SSH access)
        scp $server:/var/log/auth.log ./artifacts/$server/
        scp $server:/var/log/syslog ./artifacts/$server/

        # Analyze
        python cat.py \
            --linux-artifacts ./artifacts/$server \
            --output "$REPORT_BASE/$server"
    done

    # Aggregate results
    echo "Threat hunting complete. Review reports in $REPORT_BASE"


EXAMPLE 9: COMPLIANCE AUDIT
---------------------------
Regular compliance verification:

    # Check for unauthorized accounts
    python cat.py \
        --single-file /var/log/secure \
        --artifact-type secure_events \
        --output ./compliance_audit

    # Check for persistence mechanisms
    python cat.py \
        --single-file /etc/crontab \
        --artifact-type crontab \
        --output ./compliance_audit


EXAMPLE 10: MALWARE ANALYSIS SUPPORT
------------------------------------
Support malware analysis with forensic correlation:

    # Analyze prefetch for malware execution
    python cat.py \
        --single-file C:\Windows\Prefetch\MALWARE.EXE-*.pf \
        --artifact-type prefetch

    # Correlate with PowerShell activity
    python cat.py \
        --single-file C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx \
        --artifact-type powershell_operational_logs


EXAMPLE 11: CONTAINER SECURITY
------------------------------
Analyze Docker/container security:

    # Export Docker logs
    docker logs container_name > ./container_logs/docker.log 2>&1

    # Analyze
    python cat.py \
        --single-file ./container_logs/docker.log \
        --artifact-type dockercontainers \
        --output ./container_security


EXAMPLE 12: WEB APPLICATION SECURITY
------------------------------------
Analyze web server logs for webshells:

    # Apache logs
    python cat.py \
        --single-file /var/log/apache2/access.log \
        --artifact-type webshells \
        --output ./web_security

    # Nginx logs
    python cat.py \
        --single-file /var/log/nginx/access.log \
        --artifact-type webshells \
        --output ./web_security


EXAMPLE 13: POWERSHELL SECURITY AUDIT
-------------------------------------
Comprehensive PowerShell security analysis:

    # Analyze PowerShell logs with different focus areas
    python cat.py \
        --single-file C:\Logs\PowerShell-Operational.evtx \
        --artifact-type powershell_operational_logs \
        --output ./posh_audit

    # Look for:
    # - Encoded commands
    # - Download cradles
    # - Suspicious cmdlets (Invoke-Mimikatz, etc.)
    # - Bypass techniques


EXAMPLE 14: PRIVILEGE ESCALATION DETECTION
-------------------------------------------
Detect privilege escalation attempts:

    # Windows: Check for service installations
    python cat.py \
        --single-file C:\Logs\Security.evtx \
        --artifact-type security_event_logs

    # Linux: Check sudo usage
    python cat.py \
        --single-file /var/log/auth.log \
        --artifact-type sudocommands

    # Linux: Check for new users
    python cat.py \
        --single-file /var/log/secure \
        --artifact-type secure_events


EXAMPLE 15: LATERAL MOVEMENT DETECTION
--------------------------------------
Detect lateral movement attempts:

    # Windows: Check for remote authentication
    python cat.py \
        --single-file C:\Logs\Security.evtx \
        --artifact-type security_event_logs

    # Linux: Check SSH lateral movement
    python cat.py \
        --single-file /var/log/auth.log \
        --artifact-type sshlogin


EXAMPLE 16: PERSISTENCE MECHANISM HUNTING
-----------------------------------------
Hunt for persistence mechanisms:

    # Windows: Check all persistence locations
    python cat.py \
        --windows-artifacts ./forensics/windows \
        --output ./persistence_hunt

    # Linux: Check cron and systemd
    python cat.py \
        --single-file /etc/crontab \
        --artifact-type crontab

    python cat.py \
        --single-file /etc/systemd/system/suspicious.service \
        --artifact-type systemd


EXAMPLE 17: DATA EXFILTRATION DETECTION
---------------------------------------
Detect potential data exfiltration:

    # Check for large outbound transfers in firewall logs
    # Correlate with:
    python cat.py \
        --single-file /var/log/apache2/access.log \
        --artifact-type webshells

    # Look for compression/archiving activity in shell history
    python cat.py \
        --single-file /home/user/.bash_history \
        --artifact-type shell_history


EXAMPLE 18: SUPPLY CHAIN SECURITY
---------------------------------
Analyze for supply chain compromises:

    # Check yum/dnf logs for suspicious packages
    python cat.py \
        --single-file /var/log/yum.log \
        --artifact-type yumlog

    # Check for unauthorized software installations
    python cat.py \
        --windows-artifacts ./forensics/windows \
        --output ./supply_chain_check


EXAMPLE 19: CLOUD SECURITY (AWS/GCP/Azure)
------------------------------------------
Analyze cloud instance logs:

    # AWS EC2 Linux instances
    python cat.py \
        --linux-artifacts /var/log \
        --output ./cloud_security/aws

    # Azure Windows VMs
    python cat.py \
        --windows-artifacts C:\Azure\Logs \
        --output ./cloud_security/azure


EXAMPLE 20: ICS/SCADA SECURITY
------------------------------
Analyze industrial control systems:

    # Check for unauthorized modifications
    python cat.py \
        --single-file /var/log/scada/auth.log \
        --artifact-type sshlogin

    # Check for persistence in embedded Linux
    python cat.py \
        --single-file /etc/crontab \
        --artifact-type crontab


================================================================================
BEST PRACTICES
================================================================================

1. ALWAYS VERIFY FINDINGS
   - Automated tools can have false positives
   - Correlate findings across multiple artifacts
   - Validate in context of your environment

2. MAINTAIN CHAIN OF CUSTODY
   - Document all collection and analysis steps
   - Hash original artifacts before analysis
   - Store reports securely

3. REGULAR BASELINE ESTABLISHMENT
   - Run on known-good systems first
   - Establish baseline of normal activity
   - Compare future scans against baseline

4. INTEGRATION WITH SIEM
   - Use JSON output for SIEM ingestion
   - Correlate with network logs
   - Set up alerting for critical findings

5. CONTINUOUS MONITORING
   - Schedule regular scans
   - Track findings over time
   - Measure security posture improvements


================================================================================
TROUBLESHOOTING
================================================================================

Problem: No findings detected
Solution: Verify artifact files contain data and are not corrupted

Problem: Permission denied
Solution: Run with appropriate privileges or adjust file permissions

Problem: Encoding errors
Solution: Ensure files are UTF-8 or ASCII encoded

Problem: Large files causing memory issues
Solution: Process files individually using --single-file option


================================================================================
"""

if __name__ == "__main__":
    print(examples)
