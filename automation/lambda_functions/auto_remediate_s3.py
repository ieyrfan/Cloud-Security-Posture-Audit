#!/usr/bin/env python3
"""
auto_remediate_s3.py - AWS Lambda function for auto-remediation of S3 buckets
                      with public access.

Triggered by AWS Config rule compliance change events. Automatically applies
remediation actions to S3 buckets that are non-compliant with security best
practices: Block Public Access, encryption, versioning, and secure logging.

Requires: Python 3.11+, boto3, AWS Config + S3 permissions

Environment Variables:
    SNS_TOPIC_ARN       - (Optional) ARN for notification SNS topic
    LOG_LEVEL           - (Optional) Logging level (default: INFO)
    ENABLE_VERSIONING   - (Optional) "true"/"false" (default: true)
    DRY_RUN             - (Optional) "true"/"false" (default: false)
"""

import json
import os
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

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

SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN", "")
ENABLE_VERSIONING = os.getenv("ENABLE_VERSIONING", "true").lower() == "true"
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
ALLOWED_REGIONS = [r.strip() for r in os.getenv("ALLOWED_REGIONS", "").split(",") if r.strip()]

S3 = boto3.client("s3")
S3_CONTROL = boto3.client("s3control")
STS = boto3.client("sts")
CONFIG = boto3.client("config")
SNS = boto3.client("sns") if SNS_TOPIC_ARN else None

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _get_account_id() -> str:
    """Retrieve the current AWS account ID from STS."""
    try:
        return STS.get_caller_identity()["Account"]
    except (ClientError, BotoCoreError) as exc:
        LOGGER.error("Failed to get account ID: %s", exc)
        raise


def _send_notification(subject: str, message: str) -> None:
    """Send an SNS notification if the topic ARN is configured."""
    if not SNS:
        return
    try:
        SNS.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"AWS Remediation: {subject}",
            Message=message,
        )
        LOGGER.info("Notification sent to %s", SNS_TOPIC_ARN)
    except (ClientError, BotoCoreError) as exc:
        LOGGER.warning("Failed to send SNS notification: %s", exc)


def _put_cloudwatch_metric(metric_name: str, value: float, unit: str = "Count") -> None:
    """Emit a custom CloudWatch metric."""
    try:
        cw = boto3.client("cloudwatch")
        cw.put_metric_data(
            Namespace="CloudSecurity/S3Remediation",
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Value": value,
                    "Unit": unit,
                    "Timestamp": datetime.now(timezone.utc),
                }
            ],
        )
    except (ClientError, BotoCoreError) as exc:
        LOGGER.warning("Failed to emit CloudWatch metric: %s", exc)
