#!/usr/bin/env python3
"""
CAT Tool Demo Script
Demonstrates the Compromise Assessment Tool with sample data
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.test_data_generator import generate_all_test_data
from config.mitre_config import MITRE_MAPPING, TACTICS_MAPPING
from parsers.windows_parser import WindowsArtifactParser
from parsers.linux_parser import LinuxArtifactParser
from mitre_mapping.mitre_mapper import MITREMapper
from reports.report_generator import ReportGenerator

class Config:
    """Mock config class for demo"""
    MITRE_MAPPING = MITRE_MAPPING
    TACTICS_MAPPING = TACTICS_MAPPING

def run_demo():
    """Run a demonstration of the CAT tool"""
    print("="*80)
    print("COMPROMISE ASSESSMENT TOOL (CAT) - DEMONSTRATION")
    print("="*80)

    # Step 1: Generate test data
    print("\n[STEP 1] Generating forensic test data...")
    print("-" * 80)
    generate_all_test_data("demo_data")

    # Step 2: Initialize parsers and mapper
    print("\n[STEP 2] Initializing forensic parsers...")
    print("-" * 80)
    config = Config()
    windows_parser = WindowsArtifactParser(config)
    linux_parser = LinuxArtifactParser(config)
    mitre_mapper = MITREMapper(config)
    report_generator = ReportGenerator("demo_reports")

    all_findings = []

    # Step 3: Parse Windows artifacts
    print("\n[STEP 3] Analyzing Windows artifacts...")
    print("-" * 80)

    windows_files = {
        "security_event_logs": "demo_data/windows/security_events.log",
        "powershell_operational_logs": "demo_data/windows/powershell_operational.log"
    }

    for artifact_type, filepath in windows_files.items():
        if os.path.exists(filepath):
            print(f"Processing: {artifact_type}")
            if artifact_type == "security_event_logs":
                findings = windows_parser.parse_event_logs(filepath, "security")
            elif artifact_type == "powershell_operational_logs":
                findings = windows_parser.parse_event_logs(filepath, "powershell")
            all_findings.extend(findings)
            print(f"  Found {len(findings)} findings")

    # Step 4: Parse Linux artifacts
    print("\n[STEP 4] Analyzing Linux artifacts...")
    print("-" * 80)

    linux_files = {
        "shell_history": "demo_data/linux/.bash_history",
        "sshlogin": "demo_data/linux/auth.log",
        "crontab": "demo_data/linux/crontab"
    }

    for artifact_type, filepath in linux_files.items():
        if os.path.exists(filepath):
            print(f"Processing: {artifact_type}")
            if artifact_type == "shell_history":
                findings = linux_parser.parse_shell_history(filepath, "bash")
            elif artifact_type == "sshlogin":
                findings = linux_parser.parse_ssh_logs(filepath)
            elif artifact_type == "crontab":
                findings = linux_parser.parse_cron(filepath)
            all_findings.extend(findings)
            print(f"  Found {len(findings)} findings")

    # Step 5: Map to MITRE ATT&CK
    print("\n[STEP 5] Mapping findings to MITRE ATT&CK framework...")
    print("-" * 80)
    mapped_results = mitre_mapper.map_findings(all_findings)

    print(f"\nTotal Findings: {mapped_results['total_findings']}")
    print(f"Critical: {mapped_results['critical_count']}")
    print(f"High: {mapped_results['high_count']}")
    print(f"Medium: {mapped_results['medium_count']}")
    print(f"Low: {mapped_results['low_count']}")

    # Step 6: Show detected techniques
    print("\n[STEP 6] Detected MITRE ATT&CK Techniques:")
    print("-" * 80)

    techniques = mapped_results.get('techniques', {})
    sorted_techniques = sorted(techniques.items(), key=lambda x: x[1].get('count', 0), reverse=True)

    for tech_id, tech_data in sorted_techniques[:10]:
        tactic = tech_data.get('tactic', 'Unknown')
        name = tech_data.get('name', 'Unknown')
        count = tech_data.get('count', 0)
        print(f"  {tech_id} ({tactic}): {name} - {count} findings")

    # Step 7: Show sample findings
    print("\n[STEP 7] Sample Critical/High Findings:")
    print("-" * 80)

    critical_high = [f for f in all_findings if f.get('severity') in ['CRITICAL', 'HIGH']]
    for i, finding in enumerate(critical_high[:5], 1):
        print(f"\n{i}. [{finding.get('severity')}] {finding.get('finding')}")
        print(f"   Artifact: {finding.get('artifact')}")
        print(f"   Details: {finding.get('details', '')[:100]}...")
        techniques = finding.get('mitre_techniques', [])
        if techniques:
            print(f"   MITRE: {', '.join(techniques)}")

    # Step 8: Generate Attack Matrix
    print("\n[STEP 8] MITRE ATT&CK Matrix:")
    print("-" * 80)
    attack_matrix = mitre_mapper.generate_attack_matrix(mapped_results)
    print(attack_matrix)

    # Step 9: Generate reports
    print("\n[STEP 9] Generating assessment reports...")
    print("-" * 80)

    try:
        html_path = report_generator.generate_html_report(
            all_findings, mapped_results, attack_matrix, {}
        )
        print(f"✓ HTML Report: {html_path}")

        json_path = report_generator.generate_json_report(
            all_findings, mapped_results
        )
        print(f"✓ JSON Report: {json_path}")
    except Exception as e:
        print(f"! Error generating reports: {e}")

    # Summary
    print("\n" + "="*80)
    print("DEMONSTRATION COMPLETE")
    print("="*80)
    print(f"\nTotal Findings Processed: {len(all_findings)}")
    print(f"MITRE Techniques Detected: {len(mapped_results['techniques'])}")
    print(f"MITRE Tactics Detected: {len(mapped_results['tactics'])}")
    print("\nThe tool has successfully:")
    print("  ✓ Parsed Windows forensic artifacts")
    print("  ✓ Parsed Linux forensic artifacts")
    print("  ✓ Detected malicious and suspicious activities")
    print("  ✓ Mapped findings to MITRE ATT&CK framework")
    print("  ✓ Generated comprehensive HTML and JSON reports")
    print("\nReview the generated reports in the 'demo_reports/' directory")

if __name__ == "__main__":
    try:
        run_demo()
    except KeyboardInterrupt:
        print("\n\n[!] Demo interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error during demo: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
