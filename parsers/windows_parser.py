
"""
Windows Artifact Parser Module
Parses various Windows forensic artifacts and extracts IOCs
"""

import re
import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import hashlib

class WindowsArtifactParser:
    """Parser for Windows forensic artifacts"""

    def __init__(self, config):
        self.config = config
        self.findings = []

    def parse_prefetch(self, filepath: str) -> List[Dict]:
        """Parse Windows Prefetch files"""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Look for suspicious executables
            suspicious = self.config.MITRE_MAPPING["prefetch"]["suspicious_indicators"]
            for indicator in suspicious:
                if indicator.lower() in content.lower():
                    findings.append({
                        "artifact": "prefetch",
                        "severity": "MEDIUM",
                        "finding": f"Suspicious executable in Prefetch: {indicator}",
                        "details": f"Found reference to {indicator} in prefetch data",
                        "mitre_techniques": ["T1059", "T1204"],
                        "timestamp": datetime.now().isoformat()
                    })

            # Parse prefetch format (simplified)
            lines = content.split('\n')
            for line in lines:
                if '.exe' in line.lower() or '.dll' in line.lower():
                    if any(sus in line.lower() for sus in suspicious):
                        findings.append({
                            "artifact": "prefetch",
                            "severity": "HIGH",
                            "finding": f"Suspicious execution detected",
                            "details": line.strip(),
                            "mitre_techniques": ["T1059", "T1106"],
                            "timestamp": datetime.now().isoformat()
                        })

        except Exception as e:
            findings.append({
                "artifact": "prefetch",
                "severity": "ERROR",
                "finding": f"Error parsing prefetch: {str(e)}",
                "details": str(e),
                "mitre_techniques": [],
                "timestamp": datetime.now().isoformat()
            })

        return findings

    def parse_shimcache(self, filepath: str) -> List[Dict]:
        """Parse ShimCache (AppCompatCache) data"""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Look for execution from suspicious paths
            suspicious_paths = [
                r'\\temp\\', r'\\tmp\\', r'\\users\\.*\\temp',
                r'\\windows\\temp', r'\\programdata\\',
                r'\\appdata\\', r'\\public\\'
            ]

            for path_pattern in suspicious_paths:
                matches = re.finditer(path_pattern, content, re.IGNORECASE)
                for match in matches:
                    context = content[max(0, match.start()-50):min(len(content), match.end()+50)]
                    findings.append({
                        "artifact": "shimcache",
                        "severity": "HIGH",
                        "finding": f"Execution from suspicious path detected",
                        "details": context.strip(),
                        "mitre_techniques": ["T1547", "T1036"],
                        "timestamp": datetime.now().isoformat()
                    })

        except Exception as e:
            findings.append({
                "artifact": "shimcache",
                "severity": "ERROR",
                "finding": f"Error parsing shimcache: {str(e)}",
                "details": str(e),
                "mitre_techniques": [],
                "timestamp": datetime.now().isoformat()
            })

        return findings

    def parse_event_logs(self, filepath: str, log_type: str = "security") -> List[Dict]:
        """Parse Windows Event Logs"""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            if log_type == "security":
                findings.extend(self._analyze_security_logs(content))
            elif log_type == "powershell":
                findings.extend(self._analyze_powershell_logs(content))
            elif log_type == "task_scheduler":
                findings.extend(self._analyze_task_scheduler_logs(content))
            elif log_type == "wmi":
                findings.extend(self._analyze_wmi_logs(content))
            elif log_type == "defender":
                findings.extend(self._analyze_defender_logs(content))

        except Exception as e:
            findings.append({
                "artifact": log_type,
                "severity": "ERROR",
                "finding": f"Error parsing {log_type} logs: {str(e)}",
                "details": str(e),
                "mitre_techniques": [],
                "timestamp": datetime.now().isoformat()
            })

        return findings

    def _analyze_security_logs(self, content: str) -> List[Dict]:
        """Analyze Windows Security Event Logs for suspicious activity"""
        findings = []

        # Event ID patterns and their MITRE mappings
        event_patterns = {
            "4624": ("Successful Logon", "T1078", "MEDIUM"),
            "4625": ("Failed Logon", "T1110", "HIGH"),
            "4648": ("Explicit Credential Logon", "T1078", "MEDIUM"),
            "4672": ("Special Privileges Assigned", "T1078", "MEDIUM"),
            "4720": ("User Account Created", "T1136", "HIGH"),
            "4728": ("Member Added to Global Group", "T1098", "HIGH"),
            "4732": ("Member Added to Local Group", "T1098", "HIGH"),
            "4738": ("User Account Changed", "T1098", "MEDIUM"),
            "4740": ("User Account Locked Out", "T1110", "MEDIUM"),
            "4756": ("Member Added to Universal Group", "T1098", "HIGH"),
            "4768": ("Kerberos TGT Requested", "T1558", "LOW"),
            "4769": ("Kerberos TGS Requested", "T1558", "LOW"),
            "4771": ("Kerberos Pre-Auth Failed", "T1110", "MEDIUM"),
            "4776": ("NTLM Authentication", "T1003", "LOW"),
            "4788": ("SID History Added", "T1134", "CRITICAL"),
            "5136": ("Directory Service Modified", "T1098", "HIGH"),
            "7045": ("Service Installed", "T1543", "HIGH")
        }

        # Count events
        event_counts = {}
        for event_id, (description, technique, severity) in event_patterns.items():
            pattern = f"Event ID: {event_id}" if "Event ID" in content else f"{event_id}"
            count = content.count(pattern)
            if count > 0:
                event_counts[event_id] = count

        # Detect brute force attempts (many 4625 events)
        if event_counts.get("4625", 0) > 10:
            findings.append({
                "artifact": "security_event_logs",
                "severity": "CRITICAL",
                "finding": f"Possible Brute Force Attack: {event_counts['4625']} failed logon attempts",
                "details": "Multiple failed logon attempts detected",
                "mitre_techniques": ["T1110", "T1110.001"],
                "count": event_counts["4625"],
                "timestamp": datetime.now().isoformat()
            })

        # Detect privilege escalation
        if event_counts.get("4672", 0) > 5:
            findings.append({
                "artifact": "security_event_logs",
                "severity": "HIGH",
                "finding": f"Multiple privilege assignments detected: {event_counts['4672']} events",
                "details": "Unusual number of special privilege assignments",
                "mitre_techniques": ["T1078", "TA0004"],
                "count": event_counts["4672"],
                "timestamp": datetime.now().isoformat()
            })

        # Detect account creation
        if event_counts.get("4720", 0) > 0:
            findings.append({
                "artifact": "security_event_logs",
                "severity": "HIGH",
                "finding": f"New user account(s) created: {event_counts['4720']} events",
                "details": "New local user account creation detected",
                "mitre_techniques": ["T1136", "T1136.001"],
                "count": event_counts["4720"],
                "timestamp": datetime.now().isoformat()
            })

        # Detect group membership changes
        group_changes = event_counts.get("4728", 0) + event_counts.get("4732", 0) + event_counts.get("4756", 0)
        if group_changes > 0:
            findings.append({
                "artifact": "security_event_logs",
                "severity": "CRITICAL",
                "finding": f"Group membership changes detected: {group_changes} events",
                "details": "Users added to privileged groups",
                "mitre_techniques": ["T1098", "T1098.005"],
                "count": group_changes,
                "timestamp": datetime.now().isoformat()
            })

        # Detect service installation (common in malware)
        if event_counts.get("7045", 0) > 0:
            findings.append({
                "artifact": "security_event_logs",
                "severity": "CRITICAL",
                "finding": f"Service installation detected: {event_counts['7045']} events",
                "details": "New service installed - possible persistence mechanism",
                "mitre_techniques": ["T1543", "T1543.003"],
                "count": event_counts["7045"],
                "timestamp": datetime.now().isoformat()
            })

        return findings

    def _analyze_powershell_logs(self, content: str) -> List[Dict]:
        """Analyze PowerShell operational logs"""
        findings = []

        suspicious_patterns = [
            (r'-enc\s+[A-Za-z0-9+/=]{50,}', "Encoded PowerShell Command", "CRITICAL"),
            (r'-encodedcommand', "Encoded Command Parameter", "HIGH"),
            (r'invoke-expression|iex', "Invoke-Expression Usage", "HIGH"),
            (r'downloadstring|downloadfile', "Download Activity", "CRITICAL"),
            (r'invoke-mimikatz', "Mimikatz Invocation", "CRITICAL"),
            (r'bypass', "Execution Policy Bypass", "HIGH"),
            (r'noprofile', "No Profile Parameter", "MEDIUM"),
            (r'windowstyle\s+hidden', "Hidden Window", "HIGH"),
            (r'net\.webclient', "Web Client Usage", "MEDIUM"),
            (r'system\.net\.webrequest', "Web Request", "MEDIUM"),
            (r'frombase64string', "Base64 Decoding", "HIGH"),
            (r'bitsadmin', "BITSAdmin Usage", "MEDIUM"),
            (r'regsvr32', "Regsvr32 Execution", "HIGH"),
            (r'rundll32', "Rundll32 Execution", "MEDIUM")
        ]

        for pattern, description, severity in suspicious_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                context = content[max(0, match.start()-100):min(len(content), match.end()+100)]
                findings.append({
                    "artifact": "powershell_operational_logs",
                    "severity": severity,
                    "finding": f"Suspicious PowerShell: {description}",
                    "details": context.strip(),
                    "mitre_techniques": ["T1059.001", "T1027", "T1105"],
                    "timestamp": datetime.now().isoformat()
                })

        return findings

    def _analyze_task_scheduler_logs(self, content: str) -> List[Dict]:
        """Analyze Task Scheduler logs"""
        findings = []

        # Look for suspicious task creation
        if "Task Created" in content or "Task Registered" in content:
            suspicious_actions = ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32"]
            for action in suspicious_actions:
                if action in content.lower():
                    findings.append({
                        "artifact": "task_scheduler_logs",
                        "severity": "HIGH",
                        "finding": f"Scheduled task with suspicious action: {action}",
                        "details": f"Task scheduler created task executing {action}",
                        "mitre_techniques": ["T1053", "T1053.005"],
                        "timestamp": datetime.now().isoformat()
                    })

        return findings

    def _analyze_wmi_logs(self, content: str) -> List[Dict]:
        """Analyze WMI activity logs"""
        findings = []

        # Look for WMI event subscriptions (persistence)
        if "__EventFilter" in content or "__EventConsumer" in content or "__FilterToConsumerBinding" in content:
            findings.append({
                "artifact": "wmi_logs",
                "severity": "CRITICAL",
                "finding": "WMI Event Subscription detected",
                "details": "Possible WMI persistence mechanism",
                "mitre_techniques": ["T1546.003", "T1047"],
                "timestamp": datetime.now().isoformat()
            })

        # Look for remote WMI
        if "ProcessId" in content and any(x in content for x in ["wmic", "Invoke-WmiMethod"]):
            findings.append({
                "artifact": "wmi_logs",
                "severity": "MEDIUM",
                "finding": "Remote WMI execution detected",
                "details": "WMI used for remote command execution",
                "mitre_techniques": ["T1047"],
                "timestamp": datetime.now().isoformat()
            })

        return findings

    def _analyze_defender_logs(self, content: str) -> List[Dict]:
        """Analyze Windows Defender logs"""
        findings = []

        # Look for disabled real-time protection
        if "Real-Time Protection" in content and ("disabled" in content.lower() or "turned off" in content.lower()):
            findings.append({
                "artifact": "defender_logs",
                "severity": "CRITICAL",
                "finding": "Windows Defender Real-Time Protection disabled",
                "details": "Defender protection was disabled - possible defense evasion",
                "mitre_techniques": ["T1562.001"],
                "timestamp": datetime.now().isoformat()
            })

        # Look for added exclusions
        if "exclusion" in content.lower():
            findings.append({
                "artifact": "defender_logs",
                "severity": "HIGH",
                "finding": "Windows Defender exclusion added",
                "details": "Path or process added to Defender exclusions",
                "mitre_techniques": ["T1562.001"],
                "timestamp": datetime.now().isoformat()
            })

        # Look for threat detections
        if "Threat detected" in content or "Malware detected" in content:
            findings.append({
                "artifact": "defender_logs",
                "severity": "CRITICAL",
                "finding": "Malware detected by Windows Defender",
                "details": "Active malware infection detected",
                "mitre_techniques": ["T1204", "T1059"],
                "timestamp": datetime.now().isoformat()
            })

        return findings

    def parse_autoruns(self, filepath: str) -> List[Dict]:
        """Parse Autoruns output"""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    entry = row.get('Entry', '')
                    image_path = row.get('Image Path', '')
                    publisher = row.get('Publisher', '')

                    # Check for suspicious characteristics
                    if not publisher or publisher == '':
                        findings.append({
                            "artifact": "autoruns",
                            "severity": "MEDIUM",
                            "finding": f"Unsigned autorun entry: {entry}",
                            "details": f"Entry: {entry}, Path: {image_path}",
                            "mitre_techniques": ["T1547"],
                            "timestamp": datetime.now().isoformat()
                        })

                    # Check for suspicious paths
                    suspicious_paths = ['\\temp\\', '\\tmp\\', '\\users\\', '\\appdata\\']
                    if any(path in image_path.lower() for path in suspicious_paths):
                        findings.append({
                            "artifact": "autoruns",
                            "severity": "HIGH",
                            "finding": f"Autorun from suspicious path: {entry}",
                            "details": f"Entry: {entry}, Path: {image_path}",
                            "mitre_techniques": ["T1547", "T1036"],
                            "timestamp": datetime.now().isoformat()
                        })

        except Exception as e:
            findings.append({
                "artifact": "autoruns",
                "severity": "ERROR",
                "finding": f"Error parsing autoruns: {str(e)}",
                "details": str(e),
                "mitre_techniques": [],
                "timestamp": datetime.now().isoformat()
            })

        return findings

    def parse_mft(self, filepath: str) -> List[Dict]:
        """Parse Master File Table data"""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Look for suspicious file patterns
            suspicious_patterns = [
                (r'\\temp\\.*\.(exe|dll|bat|ps1)$', "Executable in temp directory", "HIGH"),
                (r'\\users\\.*\\appdata\\.*\.(exe|dll)$', "Executable in AppData", "HIGH"),
                (r'\\windows\\temp\\.*\.(exe|dll|bat)$', "Executable in Windows Temp", "HIGH"),
                (r'\\programdata\\.*\.(exe|dll|bat|ps1)$', "Executable in ProgramData", "MEDIUM"),
                (r'\\.*\\\$recycle\\', "Recycle Bin activity", "LOW"),
                (r'\\.*\\desktop\\.*\.(exe|dll|bat|ps1)$', "Executable on Desktop", "MEDIUM")
            ]

            for pattern, description, severity in suspicious_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    findings.append({
                        "artifact": "mft",
                        "severity": severity,
                        "finding": f"MFT: {description}",
                        "details": match.group(0),
                        "mitre_techniques": ["T1074", "T1036"],
                        "timestamp": datetime.now().isoformat()
                    })

        except Exception as e:
            findings.append({
                "artifact": "mft",
                "severity": "ERROR",
                "finding": f"Error parsing MFT: {str(e)}",
                "details": str(e),
                "mitre_techniques": [],
                "timestamp": datetime.now().isoformat()
            })

        return findings
