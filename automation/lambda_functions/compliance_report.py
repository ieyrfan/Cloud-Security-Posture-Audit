#!/usr/bin/env python3
"""
compliance_report.py - AWS Lambda function to generate compliance reports.

Triggered on a schedule (e.g., weekly via EventBridge). Aggregates findings
from AWS Security Hub, calculates compliance scores per CIS Control section,
uploads the report to S3, and sends a summary via SNS.

Requires: Python 3.11+, boto3, Security Hub enabled, S3 bucket, SNS topic

Environment Variables:
    REPORT_BUCKET       - (Required) S3 bucket for report uploads
    SNS_TOPIC_ARN       - (Required) SNS topic for summary notifications
    LOG_LEVEL           - (Optional) Logging level (default: INFO)
    SEVERITY_THRESHOLD  - (Optional) Minimum severity to include (default: MEDIUM)
"""

import json
import os
import logging
import sys
import csv
import io
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError, BotoCoreError

LOGGER = logging.getLogger(__name__)
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
    stream=sys.stdout,
)

REPORT_BUCKET = os.getenv("REPORT_BUCKET", "")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN", "")
SEVERITY_THRESHOLD = os.getenv("SEVERITY_THRESHOLD", "MEDIUM").upper()

if not REPORT_BUCKET:
    LOGGER.error("REPORT_BUCKET environment variable is required")
    sys.exit(1)

SECURITY_HUB = boto3.client("securityhub")
S3 = boto3.client("s3")
SNS = boto3.client("sns") if SNS_TOPIC_ARN else None

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}

CIS_SECTIONS = {
    "1": "Identity and Access Management",
    "2": "Storage (S3)",
    "3": "Logging and Monitoring",
    "4": "Networking (VPC)",
    "5": "Database (RDS, DynamoDB)",
    "6": "Encryption and Key Management",
    "7": "Compute (EC2, Lambda)",
}

CIS_SECTION_MAP = {
    "iam": "1", "password": "1", "mfa": "1", "access key": "1",
    "s3": "2", "bucket": "2",
    "cloudtrail": "3", "config": "3", "cloudwatch": "3", "vpc flow": "3",
    "vpc": "4", "security group": "4", "nacl": "4", "subnet": "4",
    "rds": "5", "dynamodb": "5", "redshift": "5",
    "kms": "6", "encryption": "6", "acm": "6",
    "ec2": "7", "lambda": "7", "autoscaling": "7", "elb": "7",
}

def _send_sns(subject: str, message: str) -> None:
    """Send a summary notification via SNS."""
    if not SNS:
        LOGGER.info("SNS not configured; skipping notification.")
        return
    try:
        SNS.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"Compliance Report: {subject}",
            Message=message[:100_000],
        )
        LOGGER.info("SNS notification sent successfully")
    except (ClientError, BotoCoreError) as exc:
        LOGGER.warning("Failed to send SNS notification: %s", exc)


def map_cis_section(title: str, description: str) -> str:
    """Map a finding title/description to a CIS section number."""
    combined = (title + " " + description).lower()
    for keyword, section in CIS_SECTION_MAP.items():
        if keyword in combined:
            return section
    return "unknown"


def fetch_security_hub_findings(threshold: str = "MEDIUM") -> List[Dict[str, Any]]:
    """Fetch all active findings from Security Hub within the lookback period."""
    findings: List[Dict[str, Any]] = []
    min_sev = SEVERITY_ORDER.get(threshold, 2)
    lookback = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    filters = {
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
        "UpdatedAt": [{"Start": lookback, "End": datetime.now(timezone.utc).isoformat()}],
        "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
    }
    paginator = SECURITY_HUB.get_paginator("get_findings")
    try:
        for page in paginator.paginate(Filters=filters, MaxResults=100):
            for f in page.get("Findings", []):
                label = f.get("Severity", {}).get("Label", "INFORMATIONAL")
                if SEVERITY_ORDER.get(label, 0) >= min_sev:
                    findings.append(f)
        LOGGER.info("Fetched %d findings (threshold: %s)", len(findings), threshold)
    except (ClientError, BotoCoreError) as exc:
        LOGGER.error("Failed to fetch findings: %s", exc)
        raise
    return findings


def calculate_compliance_scores(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Calculate compliance scores per CIS section."""
    scores: Dict[str, Dict[str, Any]] = {}
    for sid, sname in CIS_SECTIONS.items():
        scores[sid] = {"name": sname, "total": 0, "compliant": 0, "non_compliant": 0, "score": 100.0, "findings": []}
    scores["unknown"] = {"name": "Uncategorized", "total": 0, "compliant": 0, "non_compliant": 0, "score": 100.0, "findings": []}

    for finding in findings:
        title = finding.get("Title", "")
        description = finding.get("Description", "")
        section = map_cis_section(title, description)
        if section not in scores:
            section = "unknown"
        status = finding.get("Compliance", {}).get("Status", "FAILED")
        scores[section]["total"] += 1
        if status == "PASSED":
            scores[section]["compliant"] += 1
        else:
            scores[section]["non_compliant"] += 1
        scores[section]["findings"].append({
            "title": title,
            "severity": finding.get("Severity", {}).get("Label", "INFORMATIONAL"),
            "resource": finding.get("Resources", [{}])[0].get("Id", "unknown"),
            "account": finding.get("AwsAccountId", ""),
            "region": finding.get("Region", ""),
            "compliance_status": status,
            "control_id": next(iter(finding.get("Compliance", {}).get("RelatedRequirements", [])), ""),
        })

    for section in scores:
        if scores[section]["total"] > 0:
            scores[section]["score"] = round((scores[section]["compliant"] / scores[section]["total"]) * 100, 2)
    return scores


def generate_report(scores: Dict[str, Dict[str, Any]]) -> str:
    """Generate a comprehensive compliance report in markdown format."""
    now = datetime.now(timezone.utc)
    lines = [
        f"# AWS Compliance Report",
        f"**Generated**: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Severity Threshold**: {SEVERITY_THRESHOLD}",
        "",
        "## Overall Compliance Scores",
        "",
        "| CIS Section | Score | Compliant | Non-Compliant | Total |",
        "|------------|-------|-----------|---------------|-------|",
    ]
    total_compliant = sum(s["compliant"] for s in scores.values())
    total_findings = sum(s["total"] for s in scores.values())
    overall = round((total_compliant / total_findings * 100), 2) if total_findings > 0 else 100.0

    for sid in sorted(scores.keys()):
        s = scores[sid]
        if sid in CIS_SECTIONS:
            lines.append(f"| {sid}. {s['name']} | {s['score']:.1f}% | {s['compliant']} | {s['non_compliant']} | {s['total']} |")

    lines.extend([
        f"| **Overall** | **{overall:.1f}%** | **{total_compliant}** | **{total_findings - total_compliant}** | **{total_findings}** |",
        "",
        "## Findings by Severity",
        "",
    ])

    sev_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for s in scores.values():
        for finding in s["findings"]:
            sev = finding["severity"]
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
        if sev_counts.get(sev, 0) > 0:
            lines.append(f"- **{sev}**: {sev_counts[sev]}")

    lines.extend(["", "## Detailed Findings", ""])
    for sid in sorted(scores.keys()):
        s = scores[sid]
        if not s["findings"]:
            continue
        section_name = CIS_SECTIONS.get(sid, s["name"])
        lines.append(f"### Section {sid}: {section_name}")
        lines.append("")
        lines.append("| Title | Severity | Resource | Account | Region | Status |")
        lines.append("|-------|----------|----------|---------|--------|--------|")
        for finding in s["findings"]:
            short_resource = finding["resource"].split(":")[-1][:40] if ":" in finding["resource"] else finding["resource"][:40]
            lines.append(f"| {finding['title'][:50]} | {finding['severity']} | {short_resource} | {finding['account']} | {finding['region']} | {finding['compliance_status']} |")
        lines.append("")

    return "\n".join(lines)


