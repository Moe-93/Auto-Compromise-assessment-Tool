
#!/usr/bin/env python3
"""
Compromise Assessment Tool (CAT)
Main Application Entry Point

A comprehensive forensic analysis tool that collects, parses, and analyzes 
Windows and Linux artifacts, detects malicious activities, and maps findings 
to the MITRE ATT&CK framework.

Usage:
    # Collect and analyze in one step:
    python cat.py --collect --os windows --analyze
    python cat.py --collect --os linux --analyze

    # Analyze existing artifacts:
    python cat.py --windows-artifacts <path> --linux-artifacts <path>

    # Collect only:
    python cat.py --collect --os windows --output ./artifacts
"""

import argparse
import sys
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# Add project directories to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.mitre_config import MITRE_MAPPING, TACTICS_MAPPING, SEVERITY
from parsers.windows_parser import WindowsArtifactParser
from parsers.linux_parser import LinuxArtifactParser
from mitre_mapping.mitre_mapper import MITREMapper
from reports.report_generator import ReportGenerator
from collectors.artifact_collector import ArtifactCollector


class CompromiseAssessmentTool:
    """Main Compromise Assessment Tool class"""

    def __init__(self, output_dir: str = "reports"):
        self.windows_parser = WindowsArtifactParser(self)
        self.linux_parser = LinuxArtifactParser(self)
        self.mitre_mapper = MITREMapper(self)
        self.report_generator = ReportGenerator(output_dir)
        self.collector = None
        self.findings = []
        self.processed_files = []

    def collect_artifacts(self, os_type: str, output_dir: str = "collected_artifacts", 
                         specific_artifacts: List[str] = None) -> str:
        """
        Collect forensic artifacts from the system

        Args:
            os_type: 'windows' or 'linux'
            output_dir: Where to store collected artifacts
            specific_artifacts: List of specific artifacts to collect (None = all)

        Returns:
            Path to the collection directory
        """
        print("\n" + "="*80)
        print(f"ARTIFACT COLLECTION - {os_type.upper()}")
        print("="*80)

        self.collector = ArtifactCollector(output_dir=output_dir)

        if os_type.lower() == "windows":
            self.collector.collect_windows_artifacts(specific_artifacts)
        elif os_type.lower() == "linux":
            self.collector.collect_linux_artifacts(specific_artifacts)
        else:
            print(f"[!] Unsupported OS type: {os_type}")
            return None

        collection_dir = self.collector.get_collection_dir()
        print(f"\n[+] Collection complete: {collection_dir}")
        print(f"[+] Total files collected: {len(self.collector.collected_files)}")

        if self.collector.errors:
            print(f"[!] Errors encountered: {len(self.collector.errors)}")
            for error in self.collector.errors:
                print(f"    - {error}")

        return collection_dir

    def package_collection(self, output_file: str = None) -> str:
        """Package collected artifacts into a zip file"""
        if self.collector:
            return self.collector.package_collection(output_file)
        else:
            print("[!] No collection to package. Run collection first.")
            return None

    def process_windows_artifacts(self, artifacts_dir: str) -> List[Dict]:
        """Process all Windows artifacts in directory"""
        print(f"\n[+] Processing Windows artifacts from: {artifacts_dir}")
        findings = []

        if not os.path.exists(artifacts_dir):
            print(f"[!] Warning: Directory not found: {artifacts_dir}")
            return findings

        artifact_mapping = {
            "prefetch": ("*.pf", "*.txt"),
            "shimcache": ("*shimcache*", "*appcompatcache*"),
            "amcache": ("*amcache*",),
            "startup_items": ("*startup*", "*run*"),
            "security_event_logs": ("*security*", "*evtx*"),
            "powershell_operational_logs": ("*powershell*", "*ps*"),
            "task_scheduler_logs": ("*task*", "*scheduler*"),
            "wmi_logs": ("*wmi*",),
            "autoruns": ("*autoruns*", "*.csv"),
            "defender_logs": ("*defender*", "*windows defender*"),
            "mft": ("*mft*", "*$mft*"),
            "usbstor": ("*usb*", "*usbstor*"),
            "certutil_cache": ("*certutil*", "*cert*")
        }

        for artifact_type, patterns in artifact_mapping.items():
            for pattern in patterns:
                files = list(Path(artifacts_dir).glob(pattern))
                for file_path in files:
                    if file_path.is_file():
                        print(f"    [*] Processing {artifact_type}: {file_path.name}")
                        self.processed_files.append(str(file_path))

                        if artifact_type == "prefetch":
                            findings.extend(self.windows_parser.parse_prefetch(str(file_path)))
                        elif artifact_type == "shimcache":
                            findings.extend(self.windows_parser.parse_shimcache(str(file_path)))
                        elif artifact_type in ["security_event_logs", "powershell_operational_logs", 
                                               "task_scheduler_logs", "wmi_logs", "defender_logs"]:
                            log_type = artifact_type.replace("_logs", "").replace("_operational", "")
                            findings.extend(self.windows_parser.parse_event_logs(str(file_path), log_type))
                        elif artifact_type == "autoruns":
                            findings.extend(self.windows_parser.parse_autoruns(str(file_path)))
                        elif artifact_type == "mft":
                            findings.extend(self.windows_parser.parse_mft(str(file_path)))

        print(f"[+] Windows processing complete. Found {len(findings)} findings.")
        return findings

    def process_linux_artifacts(self, artifacts_dir: str) -> List[Dict]:
        """Process all Linux artifacts in directory"""
        print(f"\n[+] Processing Linux artifacts from: {artifacts_dir}")
        findings = []

        if not os.path.exists(artifacts_dir):
            print(f"[!] Warning: Directory not found: {artifacts_dir}")
            return findings

        artifact_mapping = {
            "shell_history": ("*history*", ".bash_history", ".zsh_history", ".sh_history"),
            "crontab": ("*cron*", "crontab", "cron.log"),
            "sshlogin": ("*auth*", "*secure*", "*sshd*"),
            "sudocommands": ("*sudo*",),
            "syslog_events": ("*syslog*", "messages"),
            "secure_events": ("*secure*", "*auth.log"),
            "dockercontainers": ("*docker*",),
            "webshells": ("*access*", "*error*", "*.log"),
            "systemd": ("*.service", "*systemd*"),
            "yumlog": ("*yum*",)
        }

        for artifact_type, patterns in artifact_mapping.items():
            for pattern in patterns:
                files = list(Path(artifacts_dir).glob(pattern))
                for file_path in files:
                    if file_path.is_file():
                        print(f"    [*] Processing {artifact_type}: {file_path.name}")
                        self.processed_files.append(str(file_path))

                        if artifact_type == "shell_history":
                            shell_type = "bash" if "bash" in file_path.name else "zsh" if "zsh" in file_path.name else "unknown"
                            findings.extend(self.linux_parser.parse_shell_history(str(file_path), shell_type))
                        elif artifact_type == "crontab":
                            findings.extend(self.linux_parser.parse_cron(str(file_path)))
                        elif artifact_type == "sshlogin":
                            findings.extend(self.linux_parser.parse_ssh_logs(str(file_path)))
                        elif artifact_type == "sudocommands":
                            findings.extend(self.linux_parser.parse_sudo_logs(str(file_path)))
                        elif artifact_type == "syslog_events":
                            findings.extend(self.linux_parser.parse_syslog(str(file_path)))
                        elif artifact_type == "secure_events":
                            findings.extend(self.linux_parser.parse_secure_log(str(file_path)))
                        elif artifact_type == "dockercontainers":
                            findings.extend(self.linux_parser.parse_docker_logs(str(file_path)))
                        elif artifact_type == "webshells":
                            findings.extend(self.linux_parser.parse_webshells(str(file_path)))
                        elif artifact_type == "systemd":
                            findings.extend(self.linux_parser.parse_systemd(str(file_path)))

        print(f"[+] Linux processing complete. Found {len(findings)} findings.")
        return findings

    def process_single_file(self, file_path: str, artifact_type: str, os_type: str = "auto") -> List[Dict]:
        """Process a single artifact file"""
        print(f"\n[+] Processing single file: {file_path}")
        findings = []

        if not os.path.exists(file_path):
            print(f"[!] Error: File not found: {file_path}")
            return findings

        self.processed_files.append(file_path)

        # Auto-detect OS type from artifact type if not specified
        if os_type == "auto":
            windows_types = ["prefetch", "shimcache", "amcache", "security_event_logs", 
                           "powershell_operational_logs", "task_scheduler_logs", "wmi_logs",
                           "autoruns", "defender_logs", "mft", "usbstor", "certutil_cache"]
            linux_types = ["shell_history", "crontab", "sshlogin", "sudocommands",
                         "syslog_events", "secure_events", "dockercontainers", 
                         "webshells", "systemd", "yumlog"]

            if artifact_type in windows_types:
                os_type = "windows"
            elif artifact_type in linux_types:
                os_type = "linux"

        # Route to appropriate parser
        if os_type == "windows":
            if artifact_type == "prefetch":
                findings = self.windows_parser.parse_prefetch(file_path)
            elif artifact_type == "shimcache":
                findings = self.windows_parser.parse_shimcache(file_path)
            elif artifact_type in ["security_event_logs", "powershell_operational_logs", 
                                   "task_scheduler_logs", "wmi_logs", "defender_logs"]:
                log_type = artifact_type.replace("_logs", "").replace("_operational", "")
                findings = self.windows_parser.parse_event_logs(file_path, log_type)
            elif artifact_type == "autoruns":
                findings = self.windows_parser.parse_autoruns(file_path)
            elif artifact_type == "mft":
                findings = self.windows_parser.parse_mft(file_path)

        elif os_type == "linux":
            if artifact_type == "shell_history":
                shell_type = "bash" if "bash" in file_path else "zsh" if "zsh" in file_path else "unknown"
                findings = self.linux_parser.parse_shell_history(file_path, shell_type)
            elif artifact_type == "crontab":
                findings = self.linux_parser.parse_cron(file_path)
            elif artifact_type == "sshlogin":
                findings = self.linux_parser.parse_ssh_logs(file_path)
            elif artifact_type == "sudocommands":
                findings = self.linux_parser.parse_sudo_logs(file_path)
            elif artifact_type == "syslog_events":
                findings = self.linux_parser.parse_syslog(file_path)
            elif artifact_type == "secure_events":
                findings = self.linux_parser.parse_secure_log(file_path)
            elif artifact_type == "dockercontainers":
                findings = self.linux_parser.parse_docker_logs(file_path)
            elif artifact_type == "webshells":
                findings = self.linux_parser.parse_webshells(file_path)
            elif artifact_type == "systemd":
                findings = self.linux_parser.parse_systemd(file_path)

        print(f"[+] Processing complete. Found {len(findings)} findings.")
        return findings

    def run_assessment(self, windows_dir: str = None, linux_dir: str = None, 
                      single_file: str = None, artifact_type: str = None,
                      collected_dir: str = None) -> Dict:
        """Run full compromise assessment"""
        print("\n" + "="*80)
        print("COMPROMISE ASSESSMENT TOOL (CAT)")
        print("Forensic Analysis with MITRE ATT&CK Mapping")
        print("="*80)

        start_time = datetime.now()
        all_findings = []

        # If collected_dir is provided, determine OS and process accordingly
        if collected_dir:
            if os.path.exists(os.path.join(collected_dir, "Windows")):
                windows_dir = os.path.join(collected_dir, "Windows")
            if os.path.exists(os.path.join(collected_dir, "Linux")):
                linux_dir = os.path.join(collected_dir, "Linux")

        # Process Windows artifacts
        if windows_dir:
            all_findings.extend(self.process_windows_artifacts(windows_dir))

        # Process Linux artifacts
        if linux_dir:
            all_findings.extend(self.process_linux_artifacts(linux_dir))

        # Process single file
        if single_file and artifact_type:
            all_findings.extend(self.process_single_file(single_file, artifact_type))

        self.findings = all_findings

        # Map to MITRE ATT&CK
        print("\n[+] Mapping findings to MITRE ATT&CK framework...")
        mapped_results = self.mitre_mapper.map_findings(all_findings)

        # Generate attack matrix
        attack_matrix = self.mitre_mapper.generate_attack_matrix(mapped_results)

        # Generate reports
        print("\n[+] Generating reports...")
        html_path = self.report_generator.generate_html_report(
            all_findings, mapped_results, attack_matrix, {}
        )
        json_path = self.report_generator.generate_json_report(
            all_findings, mapped_results
        )

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Print summary
        print("\n" + "="*80)
        print("ASSESSMENT SUMMARY")
        print("="*80)
        print(f"Total Findings:     {mapped_results['total_findings']}")
        print(f"Critical:           {mapped_results['critical_count']}")
        print(f"High:               {mapped_results['high_count']}")
        print(f"Medium:             {mapped_results['medium_count']}")
        print(f"Low:                {mapped_results['low_count']}")
        print(f"Files Processed:    {len(self.processed_files)}")
        print(f"Duration:           {duration:.2f} seconds")
        print("\nReports Generated:")
        print(f"  HTML: {html_path}")
        print(f"  JSON: {json_path}")
        print("="*80)

        return {
            "findings": all_findings,
            "mapped_results": mapped_results,
            "attack_matrix": attack_matrix,
            "reports": {
                "html": html_path,
                "json": json_path
            },
            "metadata": {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": duration,
                "files_processed": len(self.processed_files)
            }
        }


def print_banner():
    """Print application banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║           COMPROMISE ASSESSMENT TOOL (CAT) v2.0                  ║
    ║                                                                  ║
    ║     Collect, Parse & Analyze with MITRE ATT&CK Mapping           ║
    ║                 Create By Mohamed Jawarneh                       ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main entry point"""
    print_banner()

    parser = argparse.ArgumentParser(
        description="Compromise Assessment Tool - Collect, analyze forensic artifacts and map to MITRE ATT&CK",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect and analyze Windows artifacts
  python cat.py --collect --os windows --analyze

  # Collect and analyze Linux artifacts  
  python cat.py --collect --os linux --analyze

  # Collect only (no analysis)
  python cat.py --collect --os windows --output ./artifacts

  # Analyze existing Windows artifacts
  python cat.py --windows-artifacts /path/to/windows/artifacts

  # Analyze existing Linux artifacts
  python cat.py --linux-artifacts /path/to/linux/artifacts

  # Process both Windows and Linux
  python cat.py --windows-artifacts ./win --linux-artifacts ./lin

  # Process single file
  python cat.py --single-file /path/to/file.log --artifact-type security_event_logs
        """
    )

    # Collection arguments
    parser.add_argument(
        "--collect",
        action="store_true",
        help="Collect forensic artifacts from the local system"
    )

    parser.add_argument(
        "--os",
        choices=["windows", "linux", "auto"],
        default="auto",
        help="Operating system to collect from (default: auto-detect)"
    )

    parser.add_argument(
        "--artifacts",
        nargs="+",
        default=None,
        help="Specific artifacts to collect (default: collect all)"
    )

    parser.add_argument(
        "--package",
        action="store_true",
        help="Package collected artifacts into a zip file"
    )

    # Analysis arguments
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze artifacts after collection (use with --collect)"
    )

    parser.add_argument(
        "--collected-dir",
        type=str,
        help="Path to previously collected artifacts directory"
    )

    parser.add_argument(
        "--windows-artifacts",
        type=str,
        help="Directory containing Windows forensic artifacts"
    )

    parser.add_argument(
        "--linux-artifacts",
        type=str,
        help="Directory containing Linux forensic artifacts"
    )

    parser.add_argument(
        "--single-file",
        type=str,
        help="Process a single artifact file"
    )

    parser.add_argument(
        "--artifact-type",
        type=str,
        choices=[
            # Windows types
            "prefetch", "shimcache", "amcache", "startup_items", "dlls",
            "hosted_services", "executables", "security_event_logs",
            "system_event_logs", "bits_logs", "powershell_operational_logs",
            "task_scheduler_logs", "wmi_logs", "autoruns", "wer_logs",
            "windows_firewall", "defender_logs", "certutil_cache",
            "mft", "usbstor", "browsing_history",
            # Linux types
            "yumlog", "shell_history", "crontab", "lastuserlogin",
            "sshlogin", "sudocommands", "netstat", "authorized_keys",
            "known_hosts", "users", "dockercontainers", "webshells",
            "systemd", "syslog_events", "secure_events"
        ],
        help="Type of artifact (required with --single-file)"
    )

    parser.add_argument(
        "--output",
        type=str,
        default="reports",
        help="Output directory for reports (default: reports)"
    )

    parser.add_argument(
        "--collection-output",
        type=str,
        default="collected_artifacts",
        help="Output directory for collected artifacts (default: collected_artifacts)"
    )

    parser.add_argument(
        "--list-artifacts",
        action="store_true",
        help="List supported artifact types and exit"
    )

    args = parser.parse_args()

    # List supported artifacts
    if args.list_artifacts:
        print("\nSupported Windows Artifacts for Collection:")
        print("  - Prefetch, ShimCache, AmCache, StartupItems, DLLs")
        print("  - HostedServices, Executables, SecurityWELS, SystemWELS")
        print("  - BITSWELS, PowerShellOperationalWELS, TaskSchedulerWELS")
        print("  - LocalTermServerWELS, RemoteTermServerWELS, WindowsPowerShellWELS")
        print("  - PrintSvcWELS, WMIWELS, Autoruns, WERLogs, NamedPipesAudit")
        print("  - AppShimsAudit, GPOScriptsAudit, WindowsFirewall, CCMRUA")
        print("  - DefenderWELS, CertUtilCache, OSInfo, MFT, USBSTOR")
        print("  - BrowsingHistory, RunningProcesses")
        print("\nSupported Linux Artifacts for Collection:")
        print("  - Yumlog, ShellHistory, Crontab, LastUserLogin, AddUser")
        print("  - SSHLogin, SudoCommands, Netstat, AuthorizedKeys")
        print("  - KnownHosts, Users, DockerContainers, WebShells")
        print("  - MalShells, TmpListing, Systemd, PreloadCheck")
        print("  - SyslogEvents, SecureEvents, OSInfo")
        return

    # Validate arguments
    if not any([args.collect, args.windows_artifacts, args.linux_artifacts, 
                args.single_file, args.collected_dir]):
        parser.print_help()
        print("\n[!] Error: Must specify --collect, --collected-dir, --windows-artifacts, --linux-artifacts, or --single-file")
        sys.exit(1)

    if args.single_file and not args.artifact_type:
        parser.print_help()
        print("\n[!] Error: --artifact-type required with --single-file")
        sys.exit(1)

    # Run collection and/or analysis
    try:
        cat = CompromiseAssessmentTool(output_dir=args.output)

        # Collection mode
        if args.collect:
            # Auto-detect OS if not specified
            if args.os == "auto":
                import platform
                args.os = platform.system().lower()
                print(f"[+] Auto-detected OS: {args.os}")

            # Collect artifacts
            collection_dir = cat.collect_artifacts(
                os_type=args.os,
                output_dir=args.collection_output,
                specific_artifacts=args.artifacts
            )

            if not collection_dir:
                print("[!] Collection failed")
                sys.exit(1)

            # Package if requested
            if args.package:
                zip_path = cat.package_collection()
                print(f"[+] Packaged collection: {zip_path}")

            # Analyze if requested
            if args.analyze:
                print("\n[+] Starting analysis of collected artifacts...")
                results = cat.run_assessment(collected_dir=collection_dir)
            else:
                print("\n[+] Collection complete. Use --analyze to analyze collected artifacts.")
                print(f"    python cat.py --collected-dir {collection_dir} --analyze")
                sys.exit(0)

        # Analysis mode (existing artifacts)
        elif args.collected_dir:
            results = cat.run_assessment(collected_dir=args.collected_dir)
        else:
            results = cat.run_assessment(
                windows_dir=args.windows_artifacts,
                linux_dir=args.linux_artifacts,
                single_file=args.single_file,
                artifact_type=args.artifact_type
            )

        # Exit with error code if critical findings found
        if results["mapped_results"]["critical_count"] > 0:
            print("\n[!] CRITICAL findings detected - manual investigation required!")
            sys.exit(2)
        elif results["mapped_results"]["high_count"] > 0:
            print("\n[!] HIGH severity findings detected - review recommended")
            sys.exit(1)
        else:
            print("\n[+] Assessment complete - no critical findings")
            sys.exit(0)

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
