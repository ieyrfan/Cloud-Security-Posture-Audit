#!/usr/bin/env python3
"""
Report Generator
Aggregates security scan results, compliance reports, and remediation data
into comprehensive audit documents.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from jinja2 import Template
except ImportError:
    print("Jinja2 not installed. Run: pip install jinja2")
    sys.exit(1)


class ReportGenerator:
    def __init__(self, environment: str):
        self.environment = environment
        self.timestamp = datetime.utcnow()
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)

    def generate(self, formats: List[str]) -> Dict[str, Any]:
        """Generate comprehensive report"""
        print(f"[*] Generating compliance report for environment: {self.environment}")

        # Collect all reports
        scan_data = self._collect_scan_results()
        compliance_data = self._collect_compliance_results()

        # Merge data
        report_data = self._merge_data(scan_data, compliance_data)

        # Generate in requested formats
        generated_files = []
        for fmt in formats:
            if fmt == 'json':
                generated_files.append(self._generate_json(report_data))
            elif fmt == 'md':
                generated_files.append(self._generate_markdown(report_data))
            elif fmt == 'html':
                generated_files.append(self._generate_html(report_data))
            else:
                print(f"    [!] Unknown format: {fmt}")

        return {
            "report_metadata": {
                "environment": self.environment,
                "generated_at": self.timestamp.isoformat(),
                "generated_files": generated_files
            },
            "data": report_data
        }

    def _collect_scan_results(self) -> Optional[Dict[str, Any]]:
        """Collect latest scan results"""
        scan_files = sorted(
            self.reports_dir.glob(f"security-audit-{self.environment}-*.json"),
            reverse=True
        )
        if scan_files:
            with open(scan_files[0]) as f:
                return json.load(f)
        return None

    def _collect_compliance_results(self) -> Optional[Dict[str, Any]]:
        """Collect latest compliance results"""
        compliance_files = sorted(
            self.reports_dir.glob(f"cis-compliance-{self.environment}-*.json"),
            reverse=True
        )
        if compliance_files:
            with open(compliance_files[0]) as f:
                return json.load(f)
        return None

    def _merge_data(self, scan_data: Optional[Dict], compliance_data: Optional[Dict]) -> Dict[str, Any]:
        """Merge scan and compliance data"""
        merged = {
            "environment": self.environment,
            "timestamp": self.timestamp.isoformat(),
            "scan": scan_data or {"status": "not_found"},
            "compliance": compliance_data or {"status": "not_found"},
            "summary": {
                "overall_score": 0.0,
                "scan_score": 0.0,
                "compliance_score": 0.0,
                "total_findings": 0,
                "passed": 0,
                "failed": 0,
                "status": "UNKNOWN"
            }
        }

        # Calculate scores
        if scan_data and scan_data.get("summary"):
            scan_summary = scan_data["summary"]
            merged["summary"]["passed"] = scan_summary.get("passed", 0)
            merged["summary"]["failed"] = scan_summary.get("total", 0)
            merged["summary"]["total_findings"] = merged["summary"]["failed"]
            merged["summary"]["scan_score"] = scan_data.get("compliance_score", 0.0)

        if compliance_data and compliance_data.get("compliance_score"):
            merged["summary"]["compliance_score"] = compliance_data["compliance_score"]

        # Overall score
        scores = [s for s in [
            merged["summary"]["scan_score"],
            merged["summary"]["compliance_score"]
        ] if s > 0]

        if scores:
            merged["summary"]["overall_score"] = round(sum(scores) / len(scores), 2)

        # Status
        if merged["summary"]["overall_score"] >= 90:
            merged["summary"]["status"] = "EXCELLENT"
        elif merged["summary"]["overall_score"] >= 80:
            merged["summary"]["status"] = "GOOD"
        elif merged["summary"]["overall_score"] >= 70:
            merged["summary"]["status"] = "NEEDS_IMPROVEMENT"
        elif merged["summary"]["overall_score"] >= 60:
            merged["summary"]["status"] = "WARNING"
        else:
            merged["summary"]["status"] = "CRITICAL"

        return merged

    def _generate_json(self, data: Dict[str, Any]) -> str:
        """Generate JSON report"""
        filename = f"reports/final-report-{self.environment}-{self.timestamp.strftime('%Y%m%d')}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"    [+] JSON: {filename}")
        return filename

    def _generate_markdown(self, data: Dict[str, Any]) -> str:
        """Generate Markdown report"""
        summary = data["summary"]
        filename = f"reports/final-report-{self.environment}-{self.timestamp.strftime('%Y%m%d')}.md"

        md = f"""# Cloud Security Posture Audit Report

## Executive Summary

**Environment:** {data['environment']}
**Generated:** {data['timestamp']}
**Report Type:** Comprehensive Security Assessment
**Benchmark:** CIS AWS Foundations Benchmark v1.2.0

## Compliance Score

| Metric | Value |
|--------|-------|
| **Overall Score** | **{summary['overall_score']}%** |
| Scan Score | {summary['scan_score']}% |
| Compliance Score | {summary['compliance_score']}% |
| **Status** | **{summary['status']}** |

## Security Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {summary.get('critical', 0)} |
| High | {summary.get('high', 0)} |
| Medium | {summary.get('medium', 0)} |
| Low | {summary.get('low', 0)} |
| **Total Findings** | **{summary['total_findings']}** |
| **Passed Controls** | **{summary['passed']}** |
| **Failed Controls** | **{summary['failed']}** |

## Detailed Findings

"""

        if data["scan"].get("findings"):
            md += "### Scan Results\n\n"
            md += "| Control | Name | Status | Severity | Remediation |\n"
            md += "|---------|------|--------|----------|-------------|\n"
            for finding in data["scan"]["findings"]:
                md += f"| {finding['control_id']} | {finding['control_name']} | **{finding['status']}** | {finding['severity']} | {finding['remediation']} |\n"

        if data["compliance"].get("checks"):
            md += "\n### CIS Compliance Checks\n\n"
            md += "| Control | Name | Category | Status | Points |\n"
            md += "|---------|------|----------|--------|--------|\n"
            for check in data["compliance"]["checks"]:
                md += f"| {check['control_id']} | {check['control_name']} | {check['category']} | **{check['status']}** | {check['points']} |\n"

        md += """
## Remediation Recommendations

### Priority 1: Critical (Immediate Action)
1. Review all critical findings immediately
2. Implement compensating controls if immediate fix is not possible
3. Document and track remediation progress

### Priority 2: High (24 hours)
1. Address high-risk misconfigurations
2. Enable security services (Config, GuardDuty, Security Hub)
3. Implement encryption and access controls

### Priority 3: Medium (7 days)
1. Enable versioning and logging
2. Harden IAM policies
3. Implement least privilege principles

### Priority 4: Low (Next Maintenance Window)
1. Optimize monitoring configurations
2. Update response plans
3. Enhance automation

## Next Steps

- [ ] Review findings with security team
- [ ] Prioritize remediation based on risk
- [ ] Update infrastructure as code
- [ ] Schedule re-scan after changes
- [ ] Update associated tickets/Jira with findings

---

*Generated by Cloud Security Posture Audit Pipeline*
"""

        with open(filename, 'w') as f:
            f.write(md)
        print(f"    [+] Markdown: {filename}")
        return filename

    def _generate_html(self, data: Dict[str, Any]) -> str:
        """Generate HTML report"""
        summary = data["summary"]
        filename = f"reports/final-report-{self.environment}-{self.timestamp.strftime('%Y%m%d')}.html"

        # Build findings table
        findings_table = ""
        if data.get("scan") and data["scan"].get("findings"):
            findings_table = "<table><tr><th>Control</th><th>Name</th><th>Status</th><th>Severity</th><th>Remediation</th></tr>"
            for finding in data["scan"]["findings"]:
                status_color = "green" if finding['status'] == 'PASS' else "red"
                severity_color = {"CRITICAL": "red", "HIGH": "orange", "MEDIUM": "gold", "LOW": "lightblue"}.get(finding['severity'], 'gray')
                findings_table += f"<tr><td>{finding['control_id']}</td><td>{finding['control_name']}</td>"
                findings_table += f"<td style='color: {status_color}'><b>{finding['status']}</b></td>"
                findings_table += f"<td><span class='badge badge-{finding['severity'].lower()}'>{finding['severity']}</span></td>"
                findings_table += f"<td>{finding['remediation']}</td></tr>"
            findings_table += "</table>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {data['environment']}</title>
    <style>
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 20px; background: #0d1117; color: #c9d1d9; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
        h2 {{ color: #8b949e; margin-top: 30px; }}
        .score-card {{ background: linear-gradient(135deg, #161b22, #21262d); border: 1px solid #30363d; border-radius: 8px; padding: 30px; margin: 20px 0; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
        .overall-score {{ font-size: 4em; font-weight: bold; text-align: center; color: #58a6ff; margin: 20px 0; }}
        .status {{ text-align: center; font-size: 1.2em; margin-top: -10px; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }}
        .badge-pass {{ background: #238636; color: white; }}
        .badge-fail {{ background: #da3633; color: white; }}
        .badge-critical {{ background: #da3633; color: white; }}
        .badge-high {{ background: #d29922; color: black; }}
        .badge-medium {{ background: #e3b341; color: black; }}
        .badge-low {{ background: #58a6ff; color: black; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th {{ background: #21262d; color: #c9d1d9; padding: 12px; text-align: left; font-weight: 600; }}
        td {{ padding: 10px; border-bottom: 1px solid #30363d; }}
        tr:hover {{ background: #161b22; }}
        .metric-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .metric-card {{ background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 20px; text-align: center; }}
        .metric-value {{ font-size: 2em; font-weight: bold; color: #58a6ff; }}
        .metric-label {{ color: #8b949e; font-size: 0.9em; margin-top: 5px; }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #30363d; color: #8b949e; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Cloud Security Posture Audit Report</h1>

        <div class="score-card">
            <div class="overall-score">{summary['overall_score']}%</div>
            <div class="status">Status: <b>{summary['status']}</b></div>
        </div>

        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">{summary['total_findings']}</div>
                <div class="metric-label">Total Findings</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary['passed']}</div>
                <div class="metric-label">Passed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary['failed']}</div>
                <div class="metric-label">Failed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary['scan_score']:.1f}%</div>
                <div class="metric-label">Scan Score</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary['compliance_score']:.1f}%</div>
                <div class="metric-label">Compliance</div>
            </div>
        </div>

        <h2>Detailed Findings</h2>
        <div class="card">
            {findings_table if findings_table else "<p>No findings data available.</p>"}
        </div>

        <div class="footer">
            <p>Generated by Cloud Security Posture Audit Pipeline | {data['timestamp']}</p>
            <p>Environment: {data['environment']}</p>
        </div>
    </div>
</body>
</html>
"""

        with open(filename, 'w') as f:
            f.write(html)
        print(f"    [+] HTML: {filename}")
        return filename


def main():
    parser = argparse.ArgumentParser(description='Security Report Generator')
    parser.add_argument('--format', nargs='+', default=['json', 'md', 'html'])
    parser.add_argument('--environment', default='prod')
    parser.add_argument('--template', help='Custom Jinja2 template file')

    args = parser.parse_args()

    generator = ReportGenerator(args.environment)
    result = generator.generate(args.format)

    print(f"\n[+] Reports generated successfully")
    print(f"    Files: {', '.join(result['report_metadata']['generated_files'])}")
    sys.exit(0)


if __name__ == '__main__':
    main()
