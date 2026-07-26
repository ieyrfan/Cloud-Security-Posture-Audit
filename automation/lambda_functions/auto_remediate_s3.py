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


def enable_block_public_access(bucket: str, region: str) -> Optional[str]:
    """Apply S3 Block Public Access at the bucket level."""
    if DRY_RUN:
        LOGGER.info("[DRY-RUN] Would enable BlockPublicAccess for %s", bucket)
        return None
    try:
        s3_regional = boto3.client("s3", region_name=region)
        s3_regional.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        LOGGER.info("BlockPublicAccess enabled for %s", bucket)
        _put_cloudwatch_metric("BlockPublicAccessRemediated", 1)
        return "BlockPublicAccess"
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        LOGGER.error("Failed to enable BlockPublicAccess for %s: %s", bucket, error_code)
        return None


def enable_bucket_encryption(bucket: str, region: str) -> Optional[str]:
    """Enable default SSE-S3 encryption on the bucket."""
    if DRY_RUN:
        LOGGER.info("[DRY-RUN] Would enable encryption for %s", bucket)
        return None
    try:
        s3_regional = boto3.client("s3", region_name=region)
        s3_regional.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256",
                        }
                    }
                ]
            },
        )
        LOGGER.info("Default encryption enabled for %s", bucket)
        _put_cloudwatch_metric("EncryptionRemediated", 1)
        return "Encryption"
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        LOGGER.error("Failed to enable encryption for %s: %s", bucket, error_code)
        return None


def enable_bucket_versioning(bucket: str, region: str) -> Optional[str]:
    """Enable versioning on the bucket."""
    if not ENABLE_VERSIONING:
        LOGGER.info("Versioning disabled by config, skipping %s", bucket)
        return None
    if DRY_RUN:
        LOGGER.info("[DRY-RUN] Would enable versioning for %s", bucket)
        return None
    try:
        s3_regional = boto3.client("s3", region_name=region)
        s3_regional.put_bucket_versioning(
            Bucket=bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )
        LOGGER.info("Versioning enabled for %s", bucket)
        _put_cloudwatch_metric("VersioningRemediated", 1)
        return "Versioning"
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        LOGGER.warning("Failed to enable versioning for %s: %s", bucket, error_code)
        return None


def enable_bucket_logging(bucket: str, region: str) -> Optional[str]:
    """Enable access logging on the bucket if a target bucket exists."""
    log_bucket = f"{bucket}-logs"
    if DRY_RUN:
        LOGGER.info("[DRY-RUN] Would enable logging for %s -> %s", bucket, log_bucket)
        return None
    try:
        s3_regional = boto3.client("s3", region_name=region)
        s3_regional.put_bucket_logging(
            Bucket=bucket,
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": log_bucket,
                    "TargetPrefix": f"{bucket}/",
                }
            },
        )
        LOGGER.info("Access logging enabled for %s -> %s", bucket, log_bucket)
        _put_cloudwatch_metric("LoggingRemediated", 1)
        return "Logging"
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "NoSuchBucket":
            LOGGER.warning("Log target bucket %s does not exist; skipping", log_bucket)
        else:
            LOGGER.error("Failed to enable logging for %s: %s", bucket, error_code)
        return None


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Main Lambda entry point triggered by AWS Config compliance change."""
    LOGGER.info("Lambda invoked with event: %s", json.dumps(event, default=str))
    _put_cloudwatch_metric("Invocations", 1)

    remediation_results: List[Dict[str, Any]] = []
    try:
        invoking_event_raw = event.get("invokingEvent", "{}")
        if isinstance(invoking_event_raw, str):
            invoking_event = json.loads(invoking_event_raw)
        else:
            invoking_event = invoking_event_raw

        compliance_type = invoking_event.get("complianceType", "")
        resource_id = invoking_event.get("resourceId", "")

        if compliance_type != "NON_COMPLIANT":
            LOGGER.info("Resource is compliant; no remediation needed.")
            return {"statusCode": 200, "body": json.dumps({"message": "Compliant, no action"})}

        region = invoking_event.get("awsRegion", os.getenv("AWS_REGION", "us-east-1"))
        if ALLOWED_REGIONS and region not in ALLOWED_REGIONS:
            LOGGER.warning("Region %s not in allowed list; skipping", region)
            return {"statusCode": 200, "body": json.dumps({"message": f"Region {region} not allowed"})}

        bucket_name = resource_id.split(":")[-1] if ":" in resource_id else resource_id
        if not bucket_name:
            LOGGER.error("Could not determine bucket name from event")
            return {"statusCode": 400, "body": json.dumps({"error": "Bucket name not found"})}

        actions_taken = []
        for remediate in [enable_block_public_access, enable_bucket_encryption,
                          enable_bucket_versioning, enable_bucket_logging]:
            action = remediate(bucket_name, region)
            if action:
                actions_taken.append(action)

        remediation_results.append({
            "bucket": bucket_name,
            "region": region,
            "status": "remediated" if actions_taken else "no_actions_applied",
            "actions_taken": actions_taken,
            "dry_run": DRY_RUN,
        })

        if actions_taken:
            _send_notification(
                subject=f"S3 Remediation Applied to {bucket_name}",
                message=(
                    f"Region: {region}\n"
                    f"Bucket: {bucket_name}\n"
                    f"Dry-Run: {DRY_RUN}\n"
                    f"Actions: {', '.join(actions_taken)}\n"
                    f"Timestamp: {datetime.now(timezone.utc).isoformat()}"
                ),
            )

        try:
            CONFIG.put_evaluations(
                Evaluations=[{
                    "ComplianceResourceType": "AWS::S3::Bucket",
                    "ComplianceResourceId": bucket_name,
                    "ComplianceType": "COMPLIANT",
                    "Annotation": f"Auto-remediated: {', '.join(actions_taken) if actions_taken else 'none_needed'}",
                    "OrderingTimestamp": datetime.now(timezone.utc),
                }],
                ResultToken=event.get("resultToken", ""),
            )
        except (ClientError, BotoCoreError) as exc:
            LOGGER.warning("Failed to update Config evaluation: %s", exc)

        _put_cloudwatch_metric("SuccessfulRemediations", len(actions_taken))
        return {
            "statusCode": 200,
            "body": json.dumps({"remediated": remediation_results, "dry_run": DRY_RUN}, default=str),
        }
    except (ClientError, BotoCoreError) as exc:
        error_msg = f"AWS API error: {exc}"
        LOGGER.error(error_msg, exc_info=True)
        _put_cloudwatch_metric("RemediationErrors", 1)
        _send_notification(subject="S3 Remediation Error", message=f"Error: {error_msg}")
        return {"statusCode": 500, "body": json.dumps({"error": error_msg})}
    except Exception as exc:
        error_msg = f"Unexpected error: {exc}"
        LOGGER.error(error_msg, exc_info=True)
        _put_cloudwatch_metric("RemediationErrors", 1)
        return {"statusCode": 500, "body": json.dumps({"error": error_msg})}


if __name__ == "__main__":
    test_event = {
        "configRuleName": "s3-bucket-public-read-prohibited",
        "invokingEvent": json.dumps({
            "configRuleName": "s3-bucket-public-read-prohibited",
            "complianceType": "NON_COMPLIANT",
            "resourceType": "AWS::S3::Bucket",
            "resourceId": "my-test-bucket",
            "awsRegion": "us-east-1",
        }),
        "resultToken": "test-token",
    }
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2, default=str))

