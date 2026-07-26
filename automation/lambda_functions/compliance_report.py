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
