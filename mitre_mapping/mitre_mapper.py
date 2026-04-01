
"""
MITRE ATT&CK Mapper Module
Maps findings to MITRE ATT&CK framework and generates visualizations
"""

import json
from typing import Dict, List, Any
from collections import defaultdict

class MITREMapper:
    """Maps forensic findings to MITRE ATT&CK techniques"""

    def __init__(self, config):
        self.config = config
        self.technique_details = self._load_technique_details()

    def _load_technique_details(self) -> Dict:
        """Load detailed MITRE ATT&CK technique information"""
        return {
            # Execution Techniques
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1059.001", "T1059.003", "T1059.004", "T1059.005", "T1059.006", "T1059.007"]
            },
            "T1059.001": {
                "name": "PowerShell",
                "tactic": "Execution",
                "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
                "platforms": ["Windows"]
            },
            "T1059.004": {
                "name": "Unix Shell",
                "tactic": "Execution",
                "description": "Adversaries may abuse Unix shells to execute various commands or binaries.",
                "platforms": ["Linux", "macOS"]
            },
            "T1053": {
                "name": "Scheduled Task/Job",
                "tactic": "Execution",
                "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1053.002", "T1053.003", "T1053.005", "T1053.006", "T1053.007"]
            },
            "T1053.003": {
                "name": "Cron",
                "tactic": "Execution",
                "description": "Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution of malicious code.",
                "platforms": ["Linux", "macOS"]
            },
            "T1053.005": {
                "name": "Scheduled Task",
                "tactic": "Execution",
                "description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code.",
                "platforms": ["Windows"]
            },
            "T1053.006": {
                "name": "Systemd Timers",
                "tactic": "Execution",
                "description": "Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code.",
                "platforms": ["Linux"]
            },

            # Persistence Techniques
            "T1547": {
                "name": "Boot or Logon Autostart Execution",
                "tactic": "Persistence",
                "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1547.001", "T1547.004", "T1547.009", "T1547.012"]
            },
            "T1543": {
                "name": "Create or Modify System Process",
                "tactic": "Persistence",
                "description": "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads.",
                "platforms": ["Windows", "Linux"],
                "sub_techniques": ["T1543.002", "T1543.003", "T1543.004"]
            },
            "T1543.002": {
                "name": "Systemd Service",
                "tactic": "Persistence",
                "description": "Adversaries may create or modify systemd services to repeatedly execute malicious payloads.",
                "platforms": ["Linux"]
            },
            "T1543.003": {
                "name": "Windows Service",
                "tactic": "Persistence",
                "description": "Adversaries may create or modify Windows services to repeatedly execute malicious payloads.",
                "platforms": ["Windows"]
            },
            "T1546": {
                "name": "Event Triggered Execution",
                "tactic": "Persistence",
                "description": "Adversaries may establish persistence using system mechanisms that trigger execution based on specific events.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1546.003", "T1546.008", "T1546.011", "T1546.012"]
            },
            "T1546.003": {
                "name": "Windows Management Instrumentation Event Subscription",
                "tactic": "Persistence",
                "description": "Adversaries may establish persistence and elevate privileges by executing malicious content triggered by WMI event subscription.",
                "platforms": ["Windows"]
            },

            # Privilege Escalation
            "TA0004": {
                "name": "Privilege Escalation",
                "tactic": "Privilege Escalation",
                "description": "The adversary is trying to gain higher-level permissions.",
                "platforms": ["Windows", "Linux", "macOS"]
            },
            "T1548": {
                "name": "Abuse Elevation Control Mechanism",
                "tactic": "Privilege Escalation",
                "description": "Adversaries may circumvent mechanisms designed to control elevation privileges to gain higher-level permissions.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1548.001", "T1548.002", "T1548.003"]
            },
            "T1548.003": {
                "name": "Sudo and Sudo Caching",
                "tactic": "Privilege Escalation",
                "description": "Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges.",
                "platforms": ["Linux", "macOS"]
            },
            "T1055": {
                "name": "Process Injection",
                "tactic": "Privilege Escalation",
                "description": "Adversaries may inject code into processes in order to evade process-based defenses and elevate privileges.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1055.001", "T1055.002", "T1055.003", "T1055.004", "T1055.005", "T1055.008", "T1055.009", "T1055.011", "T1055.012", "T1055.013", "T1055.014", "T1055.015"]
            },

            # Defense Evasion
            "T1562": {
                "name": "Impair Defenses",
                "tactic": "Defense Evasion",
                "description": "Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1562.001", "T1562.002", "T1562.003", "T1562.004", "T1562.006", "T1562.007", "T1562.008", "T1562.009", "T1562.010", "T1562.011"]
            },
            "T1562.001": {
                "name": "Disable or Modify Tools",
                "tactic": "Defense Evasion",
                "description": "Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities.",
                "platforms": ["Windows", "Linux", "macOS"]
            },
            "T1562.004": {
                "name": "Disable or Modify System Firewall",
                "tactic": "Defense Evasion",
                "description": "Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage.",
                "platforms": ["Windows", "Linux", "macOS"]
            },
            "T1036": {
                "name": "Masquerading",
                "tactic": "Defense Evasion",
                "description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1036.003", "T1036.004", "T1036.005", "T1036.006", "T1036.007"]
            },
            "T1027": {
                "name": "Obfuscated Files or Information",
                "tactic": "Defense Evasion",
                "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1027.001", "T1027.002", "T1027.003", "T1027.004", "T1027.005", "T1027.006", "T1027.007", "T1027.008", "T1027.009", "T1027.010", "T1027.011"]
            },
            "T1070": {
                "name": "Indicator Removal",
                "tactic": "Defense Evasion",
                "description": "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1070.001", "T1070.002", "T1070.003", "T1070.004", "T1070.005", "T1070.006", "T1070.007", "T1070.008", "T1070.009"]
            },
            "T1070.002": {
                "name": "Clear Linux or Mac System Logs",
                "tactic": "Defense Evasion",
                "description": "Adversaries may clear system logs to hide evidence of an intrusion.",
                "platforms": ["Linux", "macOS"]
            },

            # Credential Access
            "T1003": {
                "name": "OS Credential Dumping",
                "tactic": "Credential Access",
                "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1003.001", "T1003.002", "T1003.003", "T1003.004", "T1003.005", "T1003.006", "T1003.007", "T1003.008"]
            },
            "T1003.001": {
                "name": "LSASS Memory",
                "tactic": "Credential Access",
                "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).",
                "platforms": ["Windows"]
            },
            "T1558": {
                "name": "Steal or Forge Kerberos Tickets",
                "tactic": "Credential Access",
                "description": "Adversaries may steal or forge Kerberos tickets to enable Pass the Ticket.",
                "platforms": ["Windows"],
                "sub_techniques": ["T1558.001", "T1558.002", "T1558.003", "T1558.004"]
            },
            "T1110": {
                "name": "Brute Force",
                "tactic": "Credential Access",
                "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1110.001", "T1110.002", "T1110.003", "T1110.004"]
            },
            "T1110.001": {
                "name": "Password Guessing",
                "tactic": "Credential Access",
                "description": "Adversaries with no prior knowledge of legitimate credentials may guess passwords to attempt access to accounts.",
                "platforms": ["Windows", "Linux", "macOS"]
            },

            # Discovery
            "T1083": {
                "name": "File and Directory Discovery",
                "tactic": "Discovery",
                "description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information.",
                "platforms": ["Windows", "Linux", "macOS"]
            },
            "T1047": {
                "name": "Windows Management Instrumentation",
                "tactic": "Execution",
                "description": "Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.",
                "platforms": ["Windows"]
            },

            # Lateral Movement
            "T1021": {
                "name": "Remote Services",
                "tactic": "Lateral Movement",
                "description": "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.005", "T1021.006", "T1021.007", "T1021.008"]
            },
            "T1021.004": {
                "name": "SSH",
                "tactic": "Lateral Movement",
                "description": "Adversaries may use Valid Accounts to log into remote machines using SSH.",
                "platforms": ["Linux", "macOS"]
            },
            "T1570": {
                "name": "Lateral Tool Transfer",
                "tactic": "Lateral Movement",
                "description": "Adversaries may transfer tools or other files between systems in a compromised environment.",
                "platforms": ["Windows", "Linux", "macOS"]
            },

            # Collection
            "T1074": {
                "name": "Data Staging",
                "tactic": "Collection",
                "description": "Adversaries may stage data collected from multiple sources in a central location or directory prior to Exfiltration.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1074.001", "T1074.002"]
            },

            # Command and Control
            "T1071": {
                "name": "Application Layer Protocol",
                "tactic": "Command and Control",
                "description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1071.001", "T1071.002", "T1071.003", "T1071.004"]
            },
            "T1572": {
                "name": "Protocol Tunneling",
                "tactic": "Command and Control",
                "description": "Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection.",
                "platforms": ["Windows", "Linux", "macOS"]
            },

            # Exfiltration
            "T1567": {
                "name": "Exfiltration Over Web Service",
                "tactic": "Exfiltration",
                "description": "Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1567.001", "T1567.002", "T1567.003", "T1567.004"]
            },

            # Initial Access
            "T1078": {
                "name": "Valid Accounts",
                "tactic": "Initial Access",
                "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1078.001", "T1078.002", "T1078.003", "T1078.004"]
            },
            "T1136": {
                "name": "Create Account",
                "tactic": "Persistence",
                "description": "Adversaries may create an account to maintain access to victim systems.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1136.001", "T1136.002", "T1136.003"]
            },
            "T1136.001": {
                "name": "Local Account",
                "tactic": "Persistence",
                "description": "Adversaries may create a local account to maintain access to victim systems.",
                "platforms": ["Windows", "Linux", "macOS"]
            },
            "T1098": {
                "name": "Account Manipulation",
                "tactic": "Persistence",
                "description": "Adversaries may manipulate accounts to maintain and/or elevate access to victim systems.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1098.001", "T1098.002", "T1098.003", "T1098.004", "T1098.005"]
            },
            "T1098.005": {
                "name": "Device Registration",
                "tactic": "Persistence",
                "description": "Adversaries may register devices to cloud accounts to maintain access to victim systems.",
                "platforms": ["Windows", "Linux", "macOS"]
            },
            "T1505": {
                "name": "Server Software Component",
                "tactic": "Persistence",
                "description": "Adversaries may abuse legitimate server software to establish persistence.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1505.001", "T1505.002", "T1505.003", "T1505.004", "T1505.005"]
            },
            "T1505.003": {
                "name": "Web Shell",
                "tactic": "Persistence",
                "description": "Adversaries may backdoor web servers with web shells to establish persistent access.",
                "platforms": ["Windows", "Linux", "macOS"]
            },
            "T1610": {
                "name": "Deploy Container",
                "tactic": "Execution",
                "description": "Adversaries may deploy a container into an environment to facilitate execution or evade defenses.",
                "platforms": ["Linux"]
            },
            "T1105": {
                "name": "Ingress Tool Transfer",
                "tactic": "Command and Control",
                "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.",
                "platforms": ["Windows", "Linux", "macOS"]
            },
            "T1204": {
                "name": "User Execution",
                "tactic": "Execution",
                "description": "An adversary may rely upon specific actions by a user in order to gain execution.",
                "platforms": ["Windows", "Linux", "macOS"],
                "sub_techniques": ["T1204.001", "T1204.002"]
            },
            "T1106": {
                "name": "Native API",
                "tactic": "Execution",
                "description": "Adversaries may interact with the native OS application programming interface (API) to execute behaviors.",
                "platforms": ["Windows", "macOS"]
            },
            "T1218": {
                "name": "System Binary Proxy Execution",
                "tactic": "Defense Evasion",
                "description": "Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries.",
                "platforms": ["Windows"],
                "sub_techniques": ["T1218.001", "T1218.002", "T1218.003", "T1218.004", "T1218.005", "T1218.007", "T1218.008", "T1218.009", "T1218.010", "T1218.011", "T1218.012", "T1218.013", "T1218.014"]
            },
            "T1134": {
                "name": "Access Token Manipulation",
                "tactic": "Defense Evasion",
                "description": "Adversaries may modify access tokens to operate under a different user or system security context.",
                "platforms": ["Windows"],
                "sub_techniques": ["T1134.001", "T1134.002", "T1134.003", "T1134.004", "T1134.005"]
            }
        }

    def map_findings(self, findings: List[Dict]) -> Dict:
        """Map findings to MITRE ATT&CK techniques and aggregate"""
        mapped_results = {
            "total_findings": len(findings),
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "techniques": defaultdict(lambda: {
                "count": 0,
                "findings": [],
                "tactic": "",
                "name": "",
                "description": ""
            }),
            "tactics": defaultdict(lambda: {
                "count": 0,
                "techniques": set()
            })
        }

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "ERROR": 0}

        for finding in findings:
            severity = finding.get("severity", "INFO")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Map to techniques
            techniques = finding.get("mitre_techniques", [])
            for tech_id in techniques:
                if tech_id.startswith("TA"):  # It is a tactic
                    continue

                tech_info = self.technique_details.get(tech_id, {})
                mapped_results["techniques"][tech_id]["count"] += 1
                mapped_results["techniques"][tech_id]["findings"].append(finding)
                mapped_results["techniques"][tech_id]["name"] = tech_info.get("name", "Unknown")
                mapped_results["techniques"][tech_id]["tactic"] = tech_info.get("tactic", "Unknown")
                mapped_results["techniques"][tech_id]["description"] = tech_info.get("description", "")

                # Update tactic counts
                tactic = tech_info.get("tactic", "Unknown")
                if tactic:
                    mapped_results["tactics"][tactic]["count"] += 1
                    mapped_results["tactics"][tactic]["techniques"].add(tech_id)

        mapped_results["critical_count"] = severity_counts["CRITICAL"]
        mapped_results["high_count"] = severity_counts["HIGH"]
        mapped_results["medium_count"] = severity_counts["MEDIUM"]
        mapped_results["low_count"] = severity_counts["LOW"]
        mapped_results["severity_distribution"] = severity_counts

        # Convert defaultdicts to regular dicts for JSON serialization
        mapped_results["techniques"] = dict(mapped_results["techniques"])
        mapped_results["tactics"] = dict(mapped_results["tactics"])

        return mapped_results

    def generate_attack_matrix(self, mapped_results: Dict) -> str:
        """Generate a text-based ATT&CK matrix representation"""
        tactics_order = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact"
        ]

        matrix = []
        matrix.append("=" * 120)
        matrix.append("MITRE ATT&CK MATRIX - DETECTED TECHNIQUES")
        matrix.append("=" * 120)
        matrix.append("")

        for tactic in tactics_order:
            tactic_data = mapped_results["tactics"].get(tactic, {"count": 0, "techniques": set()})
            if tactic_data["count"] > 0:
                matrix.append(f"\n[{tactic.upper()}]")
                matrix.append("-" * 80)

                for tech_id in tactic_data["techniques"]:
                    tech_data = mapped_results["techniques"].get(tech_id, {})
                    tech_name = tech_data.get("name", "Unknown")
                    count = tech_data.get("count", 0)
                    matrix.append(f"  {tech_id}: {tech_name} ({count} findings)")

        matrix.append("\n" + "=" * 120)
        return "\n".join(matrix)

    def get_technique_recommendations(self, technique_id: str) -> List[str]:
        """Get detection recommendations for a specific technique"""
        recommendations = {
            "T1059": [
                "Monitor command-line execution and script interpreters",
                "Enable PowerShell script block logging and transcription",
                "Use application whitelisting to prevent unauthorized script execution"
            ],
            "T1059.001": [
                "Enable PowerShell Constrained Language Mode",
                "Monitor for encoded PowerShell commands",
                "Implement AMSI (Antimalware Scan Interface) integration"
            ],
            "T1053": [
                "Monitor scheduled task creation and modification",
                "Review cron jobs regularly for unauthorized entries",
                "Alert on scheduled tasks executing from unusual locations"
            ],
            "T1547": [
                "Monitor registry run keys and startup folders",
                "Use Autoruns to identify persistence mechanisms",
                "Review WMI event subscriptions regularly"
            ],
            "T1003": [
                "Enable Credential Guard on Windows systems",
                "Monitor LSASS access and memory dumps",
                "Implement privileged access management solutions"
            ],
            "T1078": [
                "Implement multi-factor authentication",
                "Monitor for anomalous login patterns",
                "Review privileged account usage regularly"
            ],
            "T1110": [
                "Implement account lockout policies",
                "Monitor for multiple failed login attempts",
                "Use CAPTCHA or rate limiting on authentication interfaces"
            ],
            "T1562": [
                "Monitor security tool status and configuration",
                "Alert on firewall rule modifications",
                "Implement tamper protection on security solutions"
            ]
        }

        return recommendations.get(technique_id, [
            "Review MITRE ATT&CK documentation for specific detection guidance",
            "Implement comprehensive logging and monitoring",
            "Conduct regular threat hunting exercises"
        ])
