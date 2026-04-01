
"""
Report Generator Module
Generates comprehensive HTML and JSON reports
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any

class ReportGenerator:
    """Generates comprehensive assessment reports"""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_html_report(self, findings: List[Dict], mapped_results: Dict, 
                            attack_matrix: str, system_info: Dict) -> str:
        """Generate comprehensive HTML report"""

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compromise Assessment Report</title>
    <style>
        :root {{
            --critical-color: #dc2626;
            --high-color: #ea580c;
            --medium-color: #ca8a04;
            --low-color: #16a34a;
            --info-color: #2563eb;
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-color: #e2e8f0;
            --border-color: #334155;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: var(--text-color);
            line-height: 1.6;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3);
            position: relative;
            overflow: hidden;
        }}

        header::before {{
            content: '';
            position: absolute;
            top: -50%;
            right: -10%;
            width: 500px;
            height: 500px;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            border-radius: 50%;
        }}

        h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            position: relative;
            z-index: 1;
        }}

        .subtitle {{
            font-size: 1.1rem;
            opacity: 0.9;
            position: relative;
            z-index: 1;
        }}

        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .card {{
            background: var(--card-bg);
            border-radius: 12px;
            padding: 24px;
            border: 1px solid var(--border-color);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}

        .card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.2);
        }}

        .card-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 16px;
        }}

        .card-title {{
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            opacity: 0.7;
        }}

        .card-value {{
            font-size: 2.5rem;
            font-weight: 700;
        }}

        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .critical {{ background: rgba(220, 38, 38, 0.2); color: #fca5a5; border: 1px solid var(--critical-color); }}
        .high {{ background: rgba(234, 88, 12, 0.2); color: #fdba74; border: 1px solid var(--high-color); }}
        .medium {{ background: rgba(202, 138, 4, 0.2); color: #fde047; border: 1px solid var(--medium-color); }}
        .low {{ background: rgba(22, 163, 74, 0.2); color: #86efac; border: 1px solid var(--low-color); }}
        .info {{ background: rgba(37, 99, 235, 0.2); color: #93c5fd; border: 1px solid var(--info-color); }}

        .section {{
            background: var(--card-bg);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
        }}

        .section-title {{
            font-size: 1.5rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .finding-item {{
            background: rgba(255, 255, 255, 0.03);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
            border-left: 4px solid transparent;
            transition: all 0.3s ease;
        }}

        .finding-item:hover {{
            background: rgba(255, 255, 255, 0.05);
            transform: translateX(5px);
        }}

        .finding-item.critical {{ border-left-color: var(--critical-color); }}
        .finding-item.high {{ border-left-color: var(--high-color); }}
        .finding-item.medium {{ border-left-color: var(--medium-color); }}
        .finding-item.low {{ border-left-color: var(--low-color); }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}

        .finding-title {{
            font-weight: 600;
            font-size: 1.1rem;
        }}

        .finding-details {{
            color: #94a3b8;
            font-size: 0.95rem;
            margin-bottom: 12px;
            font-family: 'Courier New', monospace;
            background: rgba(0,0,0,0.2);
            padding: 10px;
            border-radius: 6px;
            overflow-x: auto;
        }}

        .mitre-tags {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 12px;
        }}

        .mitre-tag {{
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            color: white;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
            text-decoration: none;
            transition: all 0.2s;
        }}

        .mitre-tag:hover {{
            transform: scale(1.05);
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.4);
        }}

        .matrix-container {{
            background: #0a0f1d;
            border-radius: 8px;
            padding: 20px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            white-space: pre;
            color: #10b981;
            border: 1px solid var(--border-color);
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}

        .stat-item {{
            text-align: center;
            padding: 20px;
            background: rgba(255,255,255,0.03);
            border-radius: 8px;
        }}

        .stat-value {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 5px;
        }}

        .stat-label {{
            font-size: 0.875rem;
            opacity: 0.7;
        }}

        .technique-card {{
            background: rgba(255,255,255,0.03);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
            border: 1px solid var(--border-color);
        }}

        .technique-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}

        .technique-id {{
            font-family: 'Courier New', monospace;
            font-weight: 700;
            color: #3b82f6;
        }}

        .technique-name {{
            font-weight: 600;
            font-size: 1.1rem;
        }}

        .technique-description {{
            color: #94a3b8;
            font-size: 0.95rem;
            margin-bottom: 10px;
        }}

        .technique-count {{
            background: #3b82f6;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
        }}

        .recommendations {{
            background: rgba(59, 130, 246, 0.1);
            border-left: 4px solid #3b82f6;
            padding: 20px;
            border-radius: 0 8px 8px 0;
            margin-top: 10px;
        }}

        .recommendations h4 {{
            margin-bottom: 10px;
            color: #3b82f6;
        }}

        .recommendations ul {{
            margin-left: 20px;
            color: #94a3b8;
        }}

        .recommendations li {{
            margin-bottom: 5px;
        }}

        @media (max-width: 768px) {{
            .summary-cards {{
                grid-template-columns: 1fr;
            }}

            h1 {{
                font-size: 1.8rem;
            }}

            .card-value {{
                font-size: 2rem;
            }}
        }}

        .footer {{
            text-align: center;
            padding: 30px;
            color: #64748b;
            font-size: 0.875rem;
            margin-top: 40px;
        }}

        .timestamp {{
            font-family: 'Courier New', monospace;
            color: #64748b;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Compromise Assessment Report</h1>
            <p class="subtitle">Comprehensive forensic analysis with MITRE ATT&CK mapping</p>
            <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        <div class="summary-cards">
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Total Findings</span>
                </div>
                <div class="card-value">{mapped_results['total_findings']}</div>
            </div>
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Critical</span>
                </div>
                <div class="card-value" style="color: var(--critical-color);">{mapped_results['critical_count']}</div>
            </div>
            <div class="card">
                <div class="card-header">
                    <span class="card-title">High</span>
                </div>
                <div class="card-value" style="color: var(--high-color);">{mapped_results['high_count']}</div>
            </div>
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Medium</span>
                </div>
                <div class="card-value" style="color: var(--medium-color);">{mapped_results['medium_count']}</div>
            </div>
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Low</span>
                </div>
                <div class="card-value" style="color: var(--low-color);">{mapped_results['low_count']}</div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">📊 Severity Distribution</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value" style="color: var(--critical-color);">{mapped_results['severity_distribution'].get('CRITICAL', 0)}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" style="color: var(--high-color);">{mapped_results['severity_distribution'].get('HIGH', 0)}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" style="color: var(--medium-color);">{mapped_results['severity_distribution'].get('MEDIUM', 0)}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" style="color: var(--low-color);">{mapped_results['severity_distribution'].get('LOW', 0)}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" style="color: var(--info-color);">{mapped_results['severity_distribution'].get('INFO', 0)}</div>
                    <div class="stat-label">Info</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">🎯 MITRE ATT&CK Matrix</h2>
            <div class="matrix-container">{attack_matrix}</div>
        </div>

        <div class="section">
            <h2 class="section-title">⚠️ Critical Findings</h2>
"""

        # Add critical findings
        critical_findings = [f for f in findings if f.get('severity') == 'CRITICAL']
        if critical_findings:
            for finding in critical_findings[:20]:  # Limit to first 20
                html_content += self._generate_finding_html(finding)
        else:
            html_content += '<p style="color: #64748b; text-align: center; padding: 40px;">No critical findings detected.</p>'

        html_content += """
        </div>

        <div class="section">
            <h2 class="section-title">🔴 High Severity Findings</h2>
"""

        # Add high findings
        high_findings = [f for f in findings if f.get('severity') == 'HIGH']
        if high_findings:
            for finding in high_findings[:20]:  # Limit to first 20
                html_content += self._generate_finding_html(finding)
        else:
            html_content += '<p style="color: #64748b; text-align: center; padding: 40px;">No high severity findings detected.</p>'

        html_content += """
        </div>

        <div class="section">
            <h2 class="section-title">📋 All Findings</h2>
"""

        # Add all findings sorted by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4, 'ERROR': 5}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'INFO'), 4))

        for finding in sorted_findings[:50]:  # Limit to first 50
            html_content += self._generate_finding_html(finding)

        html_content += """
        </div>

        <div class="section">
            <h2 class="section-title">🛡️ Detected Techniques</h2>
"""

        # Add technique details
        techniques = mapped_results.get('techniques', {})
        sorted_techniques = sorted(techniques.items(), key=lambda x: x[1].get('count', 0), reverse=True)

        for tech_id, tech_data in sorted_techniques[:15]:
            html_content += f"""
            <div class="technique-card">
                <div class="technique-header">
                    <div>
                        <span class="technique-id">{tech_id}</span>
                        <span class="technique-name">{tech_data.get('name', 'Unknown')}</span>
                    </div>
                    <span class="technique-count">{tech_data.get('count', 0)} findings</span>
                </div>
                <div class="technique-description">{tech_data.get('description', '')}</div>
                <div style="margin-top: 10px;">
                    <span style="color: #64748b; font-size: 0.875rem;">Tactic: </span>
                    <span style="color: #3b82f6; font-weight: 500;">{tech_data.get('tactic', 'Unknown')}</span>
                </div>
            </div>
"""

        html_content += f"""
        </div>

        <div class="footer">
            <p>Compromise Assessment Tool | Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p style="margin-top: 10px; opacity: 0.7;">This report maps forensic findings to the MITRE ATT&CK framework for comprehensive threat analysis.</p>
        </div>
    </div>
</body>
</html>
"""

        # Save HTML report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        html_path = os.path.join(self.output_dir, f"compromise_assessment_report_{timestamp}.html")
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return html_path

    def _generate_finding_html(self, finding: Dict) -> str:
        """Generate HTML for a single finding"""
        severity = finding.get('severity', 'INFO').lower()
        techniques = finding.get('mitre_techniques', [])

        mitre_tags = ''.join([
            f'<a href="https://attack.mitre.org/techniques/{tech}/" target="_blank" class="mitre-tag">{tech}</a>'
            for tech in techniques if not tech.startswith('TA')
        ])

        return f"""
        <div class="finding-item {severity}">
            <div class="finding-header">
                <span class="finding-title">{finding.get('finding', 'Unknown')}</span>
                <span class="severity-badge {severity}">{finding.get('severity', 'INFO')}</span>
            </div>
            <div class="finding-details">{finding.get('details', '')}</div>
            <div style="font-size: 0.875rem; color: #64748b;">
                Artifact: <span style="color: #94a3b8;">{finding.get('artifact', 'Unknown')}</span> | 
                Time: <span style="color: #94a3b8;">{finding.get('timestamp', '')}</span>
            </div>
            {f'<div class="mitre-tags">{mitre_tags}</div>' if mitre_tags else ''}
        </div>
"""

    def generate_json_report(self, findings: List[Dict], mapped_results: Dict) -> str:
        """Generate JSON report"""
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "Compromise Assessment Tool",
                "version": "1.0"
            },
            "summary": {
                "total_findings": mapped_results['total_findings'],
                "severity_distribution": mapped_results['severity_distribution'],
                "techniques_detected": len(mapped_results.get('techniques', {})),
                "tactics_detected": len(mapped_results.get('tactics', {}))
            },
            "findings": findings,
            "mitre_mapping": mapped_results
        }

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_path = os.path.join(self.output_dir, f"compromise_assessment_report_{timestamp}.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)

        return json_path
