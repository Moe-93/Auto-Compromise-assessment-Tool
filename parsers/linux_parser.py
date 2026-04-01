
"""
Linux Artifact Parser Module
Parses various Linux forensic artifacts and extracts IOCs
"""

import re
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

class LinuxArtifactParser:
    """Parser for Linux forensic artifacts"""

    def __init__(self, config):
        self.config = config
        self.findings = []

    def parse_shell_history(self, filepath: str, shell_type: str = "bash") -> List[Dict]:
        """Parse shell history files (.bash_history, .zsh_history, etc.)"""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            suspicious_commands = self.config.MITRE_MAPPING["shell_history"]["suspicious_commands"]
            lines = content.split('\n')

            for line_num, line in enumerate(lines, 1):
                line_lower = line.lower().strip()
                if not line_lower:
                    continue

                for cmd in suspicious_commands:
                    if cmd.lower() in line_lower:
                        severity = "CRITICAL" if any(x in line_lower for x in ['nc -e', 'ncat -e', '/dev/tcp/', 'mimikatz', 'python -c']) else "HIGH"
                        findings.append({
                            "artifact": "shell_history",
                            "severity": severity,
                            "finding": f"Suspicious command in {shell_type} history",
                            "details": f"Line {line_num}: {line.strip()}",
                            "command": cmd,
                            "mitre_techniques": ["T1059.004", "T1059.001", "T1105"],
                            "timestamp": datetime.now().isoformat()
                        })
                        break

            # Check for download and execute patterns
            download_patterns = [
                (r'(wget|curl|fetch).*\|.*(bash|sh)', "Download and Pipe to Shell", "CRITICAL"),
                (r'(wget|curl).*\.sh.*chmod.*\+x', "Download script and make executable", "HIGH"),
                (r'python.*-m.*http\.server', "Python HTTP Server", "MEDIUM"),
                (r'python.*-m.*SimpleHTTPServer', "Python HTTP Server (legacy)", "MEDIUM")
            ]

            for pattern, description, severity in download_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    findings.append({
                        "artifact": "shell_history",
                        "severity": severity,
                        "finding": description,
                        "details": match.group(0),
                        "mitre_techniques": ["T1059.004", "T1105"],
                        "timestamp": datetime.now().isoformat()
                    })

        except Exception as e:
            findings.append({
                "artifact": "shell_history",
                "severity": "ERROR",
                "finding": f"Error parsing shell history: {str(e)}",
                "details": str(e),
                "mitre_techniques": [],
                "timestamp": datetime.now().isoformat()
            })

        return findings

    def parse_cron(self, filepath: str) -> List[Dict]:
        """Parse crontab files"""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Check for suspicious patterns
                suspicious_indicators = self.config.MITRE_MAPPING["crontab"]["suspicious_indicators"]

                for indicator in suspicious_indicators:
                    if indicator.lower() in line.lower():
                        severity = "CRITICAL" if any(x in line.lower() for x in ['nc -e', 'bash -i', 'sh -i', 'python -c', '/dev/tcp/']) else "HIGH"
                        findings.append({
                            "artifact": "crontab",
                            "severity": severity,
                            "finding": "Suspicious cron job detected",
                            "details": f"Line {line_num}: {line}",
                            "indicator": indicator,
                            "mitre_techniques": ["T1053.003"],
                            "timestamp": datetime.now().isoformat()
                        })
                        break

        except Exception as e:
            findings.append({
                "artifact": "crontab",
                "severity": "ERROR",
                "finding": f"Error parsing crontab: {str(e)}",
                "details": str(e),
                "mitre_techniques": [],
                "timestamp": datetime.now().isoformat()
            })

        return findings

    def parse_ssh_logs(self, filepath: str) -> List[Dict]:
        """Parse SSH authentication logs"""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Count failed login attempts
            failed_pattern = r'Failed password for.*from\s+(\d+\.\d+\.\d+\.\d+)'
            failed_matches = re.findall(failed_pattern, content)

            if len(failed_matches) > 10:
                # Group by IP
                ip_counts = {}
                for ip in failed_matches:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1

                for ip, count in ip_counts.items():
                    if count > 5:
                        findings.append({
                            "artifact": "sshlogin",
                            "severity": "CRITICAL",
                            "finding": f"SSH Brute Force Attack from {ip}",
                            "details": f"{count} failed login attempts from {ip}",
                            "source_ip": ip,
                            "attempts": count,
                            "mitre_techniques": ["T1110", "T1110.001", "T1021.004"],
                            "timestamp": datetime.now().isoformat()
                        })

            # Check for successful logins after failures
            success_pattern = r'Accepted.*from\s+(\d+\.\d+\.\d+\.\d+)'
            success_matches = re.findall(success_pattern, content)

            for ip in success_matches:
                if ip in ip_counts and ip_counts[ip] > 3:
                    findings.append({
                        "artifact": "sshlogin",
                        "severity": "HIGH",
                        "finding": f"Successful SSH login after brute force from {ip}",
                        "details": f"Successful authentication from {ip} after {ip_counts[ip]} failed attempts",
                        "source_ip": ip,
                        "mitre_techniques": ["T1078", "T1021.004"],
                        "timestamp": datetime.now().isoformat()
                    })

            # Check for suspicious SSH commands (tunnels, etc.)
            tunnel_pattern = r'ssh.*-(R|L)\s+\d+'
            if re.search(tunnel_pattern, content):
                findings.append({
                    "artifact": "sshlogin",
                    "severity": "MEDIUM",
                    "finding": "SSH tunneling detected",
                    "details": "SSH port forwarding/tunneling activity found",
                    "mitre_techniques": ["T1021.004", "T1572"],
                    "timestamp": datetime.now().isoformat()
                })

        except Exception as e:
            findings.append({
                "artifact": "sshlogin",
                "severity": "ERROR",
                "finding": f"Error parsing SSH logs: {str(e)}",
                "details": str(e),
                "mitre_techniques": [],
                "timestamp": datetime.now().isoformat()
            })

        return findings

    def parse_sudo_logs(self, filepath: str) -> List[Dict]:
        """Parse sudo command logs"""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check for privilege escalation attempts
            escalation_commands = [
                'sudo su', 'sudo -i', 'sudo /bin/bash', 'sudo /bin/sh',
                'sudo -u#-1', 'sudo -u#4294967295'
            ]

            for cmd in escalation_commands:
                if cmd in content.lower():
                    findings.append({
                        "artifact": "sudocommands",
                        "severity": "MEDIUM",
                        "finding": f"Privilege escalation command: {cmd}",
                        "details": f"User executed {cmd}",
                        "mitre_techniques": ["T1078", "T1548.003"],
                        "timestamp": datetime.now().isoformat()
                    })

            # Check for unusual sudo usage
            unusual_patterns = [
                (r'sudo.*nano.*\/(etc\/passwd|etc\/shadow)', "Editing sensitive files", "CRITICAL"),
                (r'sudo.*vim.*\/(etc\/passwd|etc\/shadow)', "Editing sensitive files", "CRITICAL"),
                (r'sudo.*chmod.*777', "Overly permissive chmod", "HIGH"),
                (r'sudo.*chmod\s+\+s', "Setting SUID bit", "HIGH"),
                (r'sudo.*useradd', "User account creation", "HIGH"),
                (r'sudo.*usermod.*-aG.*sudo', "Adding user to sudo group", "CRITICAL")
            ]

            for pattern, description, severity in unusual_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        "artifact": "sudocommands",
                        "severity": severity,
                        "finding": description,
                        "details": match.group(0),
                        "mitre_techniques": ["T1098", "T1548"],
                        "timestamp": datetime.now().isoformat()
                    })

        except Exception as e:
            findings.append({
                "artifact": "sudocommands",
                "severity": "ERROR",
                "finding": f"Error parsing sudo logs: {str(e)}",
                "details": str(e),
                "mitre_techniques": [],
                "timestamp": datetime.now().isoformat()
            })

        return findings

    def parse_syslog(self, filepath: str) -> List[Dict]:
        """Parse system logs (syslog)"""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check for log clearing
            if 'rsyslogd' in content and any(x in content.lower() for x in ['delete', 'truncate', '>' ]):
                findings.append({
                    "artifact": "syslog_events",
                    "severity": "CRITICAL",
                    "finding": "Possible log deletion detected",
                    "details": "Log file manipulation detected",
                    "mitre_techniques": ["T1070", "T1070.002"],
                    "timestamp": datetime.now().isoformat()
                })

            # Check for suspicious process execution
            suspicious_processes = [
                'nc -l', 'ncat -l', 'netcat -l',
                'python -m SimpleHTTPServer', 'python -m http.server',
                'socat', 'nc -e', 'ncat -e'
            ]

            for proc in suspicious_processes:
                if proc in content.lower():
                    findings.append({
                        "artifact": "syslog_events",
                        "severity": "HIGH",
                        "finding": f"Suspicious network process: {proc}",
                        "details": f"Process matching '{proc}' executed",
                        "mitre_techniques": ["T1059", "T1071"],
                        "timestamp": datetime.now().isoformat()
                    })

            # Check for service modifications
            service_patterns = [
                (r'systemd\[.*\]:.*Started.*service', "Service started", "MEDIUM"),
                (r'systemd\[.*\]:.*Created.*slice', "Systemd slice created", "LOW"),
                (r'CRON\[.*\]:.*CMD', "Cron job executed", "MEDIUM")
            ]

            for pattern, description, severity in service_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = content[max(0, match.start()-50):min(len(content), match.end()+50)]
                    findings.append({
                        "artifact": "syslog_events",
                        "severity": severity,
                        "finding": description,
                        "details": context.strip(),
                        "mitre_techniques": ["T1543"],
                        "timestamp": datetime.now().isoformat()
                    })

        except Exception as e:
            findings.append({
                "artifact": "syslog_events",
                "severity": "ERROR",
                "finding": f"Error parsing syslog: {str(e)}",
                "details": str(e),
                "mitre_techniques": [],
                "timestamp": datetime.now().isoformat()
            })

        return findings

    def parse_secure_log(self, filepath: str) -> List[Dict]:
        """Parse secure authentication logs"""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check for authentication failures
            auth_failure_pattern = r'authentication failure.*user=(\w+)'
            auth_failures = re.findall(auth_failure_pattern, content, re.IGNORECASE)

            if len(auth_failures) > 10:
                user_counts = {}
                for user in auth_failures:
                    user_counts[user] = user_counts.get(user, 0) + 1

                for user, count in user_counts.items():
                    if count > 5:
                        findings.append({
                            "artifact": "secure_events",
                            "severity": "HIGH",
                            "finding": f"Multiple authentication failures for user: {user}",
                            "details": f"{count} failed authentication attempts for {user}",
                            "username": user,
                            "attempts": count,
                            "mitre_techniques": ["T1110", "T1110.001"],
                            "timestamp": datetime.now().isoformat()
                        })

            # Check for user account changes
            user_change_patterns = [
                (r'useradd.*name=(\w+)', "User account created", "HIGH"),
                (r'usermod.*name=(\w+)', "User account modified", "MEDIUM"),
                (r'userdel.*name=(\w+)', "User account deleted", "HIGH"),
                (r'groupadd', "Group created", "MEDIUM"),
                (r'passwd.*changed', "Password changed", "LOW")
            ]

            for pattern, description, severity in user_change_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        "artifact": "secure_events",
                        "severity": severity,
                        "finding": description,
                        "details": match.group(0),
                        "mitre_techniques": ["T1136", "T1098"],
                        "timestamp": datetime.now().isoformat()
                    })

        except Exception as e:
            findings.append({
                "artifact": "secure_events",
                "severity": "ERROR",
                "finding": f"Error parsing secure log: {str(e)}",
                "details": str(e),
                "mitre_techniques": [],
                "timestamp": datetime.now().isoformat()
            })

        return findings

    def parse_docker_logs(self, filepath: str) -> List[Dict]:
        """Parse Docker container logs"""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check for privileged containers
            if '--privileged' in content or 'Privileged: true' in content:
                findings.append({
                    "artifact": "dockercontainers",
                    "severity": "HIGH",
                    "finding": "Privileged Docker container detected",
                    "details": "Container running with privileged flag",
                    "mitre_techniques": ["T1610"],
                    "timestamp": datetime.now().isoformat()
                })

            # Check for mounted root filesystem
            if '-v /:/' in content or 'Mounts.*\/:\/' in content:
                findings.append({
                    "artifact": "dockercontainers",
                    "severity": "CRITICAL",
                    "finding": "Docker container with root filesystem mount",
                    "details": "Container has host root filesystem mounted",
                    "mitre_techniques": ["T1610", "T1083"],
                    "timestamp": datetime.now().isoformat()
                })

            # Check for suspicious images
            suspicious_images = ['alpine', 'busybox', 'ubuntu', 'debian']
            for image in suspicious_images:
                if f'Image: {image}' in content or f'"Image": "{image}"' in content:
                    findings.append({
                        "artifact": "dockercontainers",
                        "severity": "LOW",
                        "finding": f"Common base image used: {image}",
                        "details": f"Container using {image} base image",
                        "mitre_techniques": ["T1610"],
                        "timestamp": datetime.now().isoformat()
                    })

        except Exception as e:
            findings.append({
                "artifact": "dockercontainers",
                "severity": "ERROR",
                "finding": f"Error parsing Docker logs: {str(e)}",
                "details": str(e),
                "mitre_techniques": [],
                "timestamp": datetime.now().isoformat()
            })

        return findings

    def parse_webshells(self, filepath: str) -> List[Dict]:
        """Parse web server logs for webshell indicators"""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Webshell indicators
            webshell_patterns = [
                (r'eval\s*\(', "PHP eval() function", "CRITICAL"),
                (r'exec\s*\(', "PHP exec() function", "CRITICAL"),
                (r'system\s*\(', "PHP system() function", "CRITICAL"),
                (r'passthru\s*\(', "PHP passthru() function", "CRITICAL"),
                (r'shell_exec\s*\(', "PHP shell_exec() function", "CRITICAL"),
                (r'base64_decode\s*\(', "Base64 decoding", "HIGH"),
                (r'gzinflate\s*\(', "Gzip inflation", "HIGH"),
                (r'str_rot13\s*\(', "ROT13 encoding", "MEDIUM"),
                (r'assert\s*\(', "PHP assert()", "CRITICAL"),
                (r'preg_replace.*\/e', "Dangerous preg_replace", "CRITICAL"),
                (r'file_put_contents.*\$_', "File upload via POST", "HIGH"),
                (r'move_uploaded_file', "File upload function", "MEDIUM")
            ]

            for pattern, description, severity in webshell_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = content[max(0, match.start()-100):min(len(content), match.end()+100)]
                    findings.append({
                        "artifact": "webshells",
                        "severity": severity,
                        "finding": f"Webshell indicator: {description}",
                        "details": context.strip(),
                        "mitre_techniques": ["T1505.003", "T1059"],
                        "timestamp": datetime.now().isoformat()
                    })

        except Exception as e:
            findings.append({
                "artifact": "webshells",
                "severity": "ERROR",
                "finding": f"Error parsing webshell data: {str(e)}",
                "details": str(e),
                "mitre_techniques": [],
                "timestamp": datetime.now().isoformat()
            })

        return findings

    def parse_systemd(self, filepath: str) -> List[Dict]:
        """Parse systemd service files"""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check for user services (persistence)
            if '[Install]' in content and 'WantedBy=default.target' in content:
                findings.append({
                    "artifact": "systemd",
                    "severity": "MEDIUM",
                    "finding": "User systemd service detected",
                    "details": "Service configured to start at user login",
                    "mitre_techniques": ["T1543.002"],
                    "timestamp": datetime.now().isoformat()
                })

            # Check for suspicious ExecStart commands
            suspicious_exec = [
                'nc -e', 'ncat -e', 'bash -i', 'sh -i',
                'python -c', 'python3 -c', 'perl -e',
                'curl.*\|', 'wget.*\|', 'fetch.*\|'
            ]

            for pattern in suspicious_exec:
                if pattern in content.lower():
                    findings.append({
                        "artifact": "systemd",
                        "severity": "CRITICAL",
                        "finding": f"Suspicious ExecStart command: {pattern}",
                        "details": "Service configured to execute reverse shell or download",
                        "mitre_techniques": ["T1543.002", "T1059"],
                        "timestamp": datetime.now().isoformat()
                    })

        except Exception as e:
            findings.append({
                "artifact": "systemd",
                "severity": "ERROR",
                "finding": f"Error parsing systemd files: {str(e)}",
                "details": str(e),
                "mitre_techniques": [],
                "timestamp": datetime.now().isoformat()
            })

        return findings
