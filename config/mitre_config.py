
"""
Compromise Assessment Tool Configuration
Maps forensic artifacts to MITRE ATT&CK techniques
"""

MITRE_MAPPING = {
    # Windows Artifacts
    "prefetch": {
        "description": "Prefetch files track program execution",
        "mitre_techniques": ["T1059", "T1204", "T1106"],  # Execution techniques
        "suspicious_indicators": [
            "powershell.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "regsvr32.exe",
            "rundll32.exe"
        ]
    },
    "shimcache": {
        "description": "ShimCache tracks executable compatibility",
        "mitre_techniques": ["T1547", "T1112", "T1546"],  # Persistence, Modify Registry
        "suspicious_indicators": ["unusual_paths", "temp_executables"]
    },
    "amcache": {
        "description": "AmCache tracks program installation and execution",
        "mitre_techniques": ["T1059", "T1547", "T1036"],  # Execution, Persistence, Masquerading
        "suspicious_indicators": ["recent_installs", "unusual_paths"]
    },
    "startup_items": {
        "description": "Programs configured to run at startup",
        "mitre_techniques": ["T1547"],  # Boot or Logon Autostart Execution
        "sub_techniques": ["T1547.001", "T1547.004", "T1547.009"],
        "suspicious_indicators": ["unknown_executables", "suspicious_registry_keys"]
    },
    "dlls": {
        "description": "Dynamic Link Libraries loaded",
        "mitre_techniques": ["T1055", "T1129", "T1073"],  # Process Injection, Execution through Module Load
        "suspicious_indicators": ["dll_hijacking", "unusual_dll_paths"]
    },
    "hosted_services": {
        "description": "Services hosted on the system",
        "mitre_techniques": ["T1543", "T1569"],  # Create or Modify System Process, System Services
        "suspicious_indicators": ["suspicious_service_names", "unusual_image_paths"]
    },
    "executables": {
        "description": "Executable files on system",
        "mitre_techniques": ["T1036", "T1059", "T1204"],  # Masquerading, Command and Scripting Interpreter
        "suspicious_indicators": ["double_extensions", "system_process_names_in_user_dirs"]
    },
    "security_event_logs": {
        "description": "Windows Security Event Logs",
        "mitre_techniques": ["T1078", "T1110", "T1003", "T1098"],  # Valid Accounts, Brute Force, Credential Dumping
        "event_ids": {
            "4624": "Successful Logon",
            "4625": "Failed Logon",
            "4648": "Explicit Credential Logon",
            "4672": "Special Privileges Assigned",
            "4720": "User Account Created",
            "4728": "Member Added to Security-Enabled Global Group",
            "4732": "Member Added to Security-Enabled Local Group",
            "4738": "User Account Changed",
            "4740": "User Account Locked Out",
            "4756": "Member Added to Security-Enabled Universal Group",
            "4768": "Kerberos Authentication Ticket Requested",
            "4769": "Kerberos Service Ticket Requested",
            "4771": "Kerberos Pre-Authentication Failed",
            "4776": "NTLM Authentication",
            "4788": "SID History Added to Account",
            "5136": "Directory Service Object Modified",
            "7045": "Service Installed"
        }
    },
    "powershell_operational_logs": {
        "description": "PowerShell operational logs",
        "mitre_techniques": ["T1059.001", "T1086"],  # PowerShell
        "suspicious_indicators": [
            "-enc", "-encodedcommand",
            "invoke-expression", "iex",
            "downloadstring", "downloadfile",
            "invoke-mimikatz",
            "bypass",
            "noprofile",
            "windowstyle hidden"
        ]
    },
    "task_scheduler_logs": {
        "description": "Task Scheduler operational logs",
        "mitre_techniques": ["T1053", "T1053.005"],  # Scheduled Task/Job
        "suspicious_indicators": ["suspicious_actions", "unusual_triggers"]
    },
    "wmi_logs": {
        "description": "WMI activity logs",
        "mitre_techniques": ["T1047", "T1546.003"],  # Windows Management Instrumentation
        "suspicious_indicators": ["wmi_event_subscription", "remote_wmi"]
    },
    "autoruns": {
        "description": "Autoruns entries",
        "mitre_techniques": ["T1547"],  # Boot or Logon Autostart Execution
        "suspicious_indicators": ["empty_publisher", "unusual_locations", "no_icon"]
    },
    "windows_firewall": {
        "description": "Windows Firewall configuration",
        "mitre_techniques": ["T1562.004", "T1021"],  # Impair Defenses: Disable or Modify System Firewall
        "suspicious_indicators": ["disabled_firewall", "suspicious_rules"]
    },
    "defender_logs": {
        "description": "Windows Defender logs",
        "mitre_techniques": ["T1562.001", "T1078"],  # Disable or Modify Tools
        "suspicious_indicators": ["disabled_defender", "exclusions_added", "threats_detected"]
    },
    "certutil_cache": {
        "description": "CertUtil cache and usage",
        "mitre_techniques": ["T1105", "T1027", "T1218"],  # Ingress Tool Transfer, Obfuscated Files
        "suspicious_indicators": ["urlcache", "decode", "encode", "download"]
    },
    "mft": {
        "description": "Master File Table",
        "mitre_techniques": ["T1074", "T1567", "T1036"],  # Data Staging, Exfiltration
        "suspicious_indicators": ["timestomping", "deleted_files", "suspicious_names"]
    },
    "usbstor": {
        "description": "USB storage device history",
        "mitre_techniques": ["T1091", "T1200"],  # Replication Through Removable Media
        "suspicious_indicators": ["unknown_devices", "recent_first_time_devices"]
    },

    # Linux Artifacts
    "yumlog": {
        "description": "YUM package manager logs",
        "mitre_techniques": ["T1543", "T1072"],  # Create or Modify System Process
        "suspicious_indicators": ["unusual_packages", "recent_installs"]
    },
    "shell_history": {
        "description": "Shell command history",
        "mitre_techniques": ["T1059.004", "T1059.001", "T1083"],  # Unix Shell, PowerShell, File and Directory Discovery
        "suspicious_commands": [
            "wget", "curl", "fetch",
            "chmod +x", "chmod 777",
            "nc -e", "ncat -e", "netcat",
            "python -m http.server",
            "python -m SimpleHTTPServer",
            "base64 -d", "base64 --decode",
            "eval(", "exec(",
            "/dev/tcp/", "/dev/udp/",
            "mkfifo",
            "iptables -F", "iptables --flush",
            "service.*stop", "systemctl.*stop",
            "crontab", "at ",
            "ssh.*-R", "ssh.*-L",
            "nohup", "disown"
        ]
    },
    "crontab": {
        "description": "Scheduled cron jobs",
        "mitre_techniques": ["T1053.003"],  # Cron
        "suspicious_indicators": [
            "*/1 * * * *",  # Every minute
            "@reboot",
            "wget", "curl", "fetch",
            "/tmp/", "/var/tmp/", "/dev/shm/",
            "bash -i", "sh -i", "python -c",
            "nc -e", "ncat -e"
        ]
    },
    "lastuserlogin": {
        "description": "User login history",
        "mitre_techniques": ["T1078", "T1110"],  # Valid Accounts, Brute Force
        "suspicious_indicators": ["failed_logins", "off_hours_login", "remote_logins"]
    },
    "sshlogin": {
        "description": "SSH login attempts",
        "mitre_techniques": ["T1021.004", "T1078", "T1110"],  # SSH, Valid Accounts
        "suspicious_indicators": ["brute_force_attempts", "successful_after_failures", "unusual_sources"]
    },
    "sudocommands": {
        "description": "Sudo command usage",
        "mitre_techniques": ["T1078", "T1548.003"],  # Valid Accounts, Sudo Caching
        "suspicious_indicators": ["unusual_sudo_usage", "privilege_escalation_attempts"]
    },
    "dockercontainers": {
        "description": "Docker container activity",
        "mitre_techniques": ["T1610", "T1059"],  # Deploy Container
        "suspicious_indicators": ["privileged_containers", "mounted_root", "unusual_images"]
    },
    "webshells": {
        "description": "Web shell detection",
        "mitre_techniques": ["T1505.003", "T1059"],  # Web Shell
        "suspicious_indicators": [
            "eval(", "exec(", "system(", "passthru(", "shell_exec(",
            "base64_decode", "str_rot13", "gzinflate",
            "assert(", "preg_replace.*e", "create_function",
            "file_put_contents", "fopen", "move_uploaded_file"
        ]
    },
    "systemd": {
        "description": "Systemd services and timers",
        "mitre_techniques": ["T1543.002", "T1053.006"],  # Systemd Service, Systemd Timer
        "suspicious_indicators": ["user_services", "suspicious_executables"]
    },
    "syslog_events": {
        "description": "System log events",
        "mitre_techniques": ["T1070", "T1083", "T1047"],  # Indicator Removal, File and Directory Discovery
        "suspicious_indicators": ["cleared_logs", "suspicious_processes"]
    },
    "secure_events": {
        "description": "Security-related events",
        "mitre_techniques": ["T1078", "T1110", "T1003"],  # Valid Accounts, Brute Force, OS Credential Dumping
        "suspicious_indicators": ["authentication_failures", "privilege_escalation"]
    }
}

# MITRE ATT&CK Tactics mapping
TACTICS_MAPPING = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Command and Control",
    "TA0011": "Exfiltration",
    "TA0012": "Impact",
    "TA0040": "Impact"
}

# Severity levels
SEVERITY = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}
