import json
import os
import re
import urllib.request
import urllib.error
from datetime import datetime
from typing import Any, Dict, List, Optional

# Environment variables
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL', '')
SLACK_CHANNEL = os.environ.get('SLACK_CHANNEL', '#security-alerts')
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'production')

# Severity emoji mapping
SEVERITY_EMOJI = {
    'CRITICAL': ':red_circle:',
    'HIGH': ':large_orange_circle:',
    'MEDIUM': ':large_yellow_circle:',
    'LOW': ':large_blue_circle:',
    'INFORMATIONAL': ':white_circle:'
}

# Severity color mapping
SEVERITY_COLOR = {
    'CRITICAL': '#FF0000',
    'HIGH': '#FF6B00',
    'MEDIUM': '#FFD600',
    'LOW': '#00B8D9',
    'INFORMATIONAL': '#36B37E'
}


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler for Security Hub to Slack notifications.

    Trigger: CloudWatch Event / EventBridge rule
    Input: Security Hub finding event
    Output: Slack webhook POST
    """
    print(f"[INFO] Slack alert Lambda invoked")
    print(f"[INFO] Environment: {ENVIRONMENT}")

    try:
        # Parse incoming event
        detail = event.get('detail', {})
        findings = detail.get('findings', [])

        if not findings:
            print("[INFO] No findings in event")
            return {'statusCode': 200, 'body': json.dumps({'message': 'No findings to process'})}

        # Process each finding
        for finding in findings:
            send_slack_notification(finding)

        print(f"[SUCCESS] Processed {len(findings)} findings")
        return {'statusCode': 200, 'body': json.dumps({'processed': len(findings)})}

    except Exception as e:
        print(f"[ERROR] Failed to process event: {e}")
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}


def send_slack_notification(finding: Dict[str, Any]) -> None:
    """Send formatted Slack notification for a Security Hub finding."""
    if not SLACK_WEBHOOK_URL:
        print("[WARN] SLACK_WEBHOOK_URL not configured, skipping notification")
        return

    severity = finding.get('Severity', {}).get('Label', 'INFORMATIONAL')
    title = finding.get('Title', 'Unknown Security Finding')
    description = finding.get('Description', 'No description available')
    finding_id = finding.get('Id', 'N/A')
    resource_type = finding.get('Resources', [{}])[0].get('Type', 'Unknown')
    resource_id = finding.get('Resources', [{}])[0].get('Id', 'Unknown')

    # Truncate long descriptions
    if len(description) > 300:
        description = description[:297] + "..."

    # Format timestamp
    updated_at = finding.get('UpdatedAt', datetime.utcnow().isoformat())
    try:
        dt = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
        time_str = dt.strftime('%Y-%m-%d %H:%M UTC')
    except:
        time_str = updated_at

    # Slack message payload with Block Kit
    payload = {
        'channel': SLACK_CHANNEL,
        'username': 'Security Bot',
        'icon_emoji': ':shield:',
        'attachments': [
            {
                'color': SEVERITY_COLOR.get(severity, '#808080'),
                'title': f"{SEVERITY_EMOJI.get(severity, ':grey_circle:')} {title}",
                'text': description,
                'fields': [
                    {
                        'title': 'Severity',
                        'value': severity,
                        'short': True
                    },
                    {
                        'title': 'Resource',
                        'value': f"{resource_type}: {resource_id}",
                        'short': False
                    },
                    {
                        'title': 'Environment',
                        'value': ENVIRONMENT.title(),
                        'short': True
                    },
                    {
                        'title': 'Time',
                        'value': time_str,
                        'short': True
                    }
                ],
                'actions': [
                    {
                        'type': 'button',
                        'text': {
                            'type': 'plain_text',
                            'text': 'View in Console'
                        },
                        'url': f"https://{get_region()}.console.aws.amazon.com/securityhub",
                        'style': 'primary' if severity in ['CRITICAL', 'HIGH'] else 'default'
                    },
                    {
                        'type': 'button',
                        'text': {
                            'type': 'plain_text',
                            'text': 'Remediation Runbook'
                        },
                        'url': 'https://github.com/your-org/cloud-security-posture-audit/blob/main/remediation/RUNBOOK.md',
                        'style': 'default'
                    }
                ],
                'footer': f"Finding ID: {finding_id[:8]}...",
                'ts': int(datetime.utcnow().timestamp())
            }
        ]
    }

    # Send to Slack
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            SLACK_WEBHOOK_URL,
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            print(f"[SUCCESS] Slack notification sent: {response.status}")

    except urllib.error.HTTPError as e:
        print(f"[ERROR] Slack webhook failed: {e.code} {e.reason}")
    except Exception as e:
        print(f"[ERROR] Failed to send Slack notification: {e}")


def get_region() -> str:
    """Extract region from Lambda context or environment."""
    # Try to get from Lambda context
    try:
        # In actual Lambda, this comes from the context
        return os.environ.get('AWS_REGION', 'us-east-1')
    except:
        return 'us-east-1'


def send_daily_digest(findings: List[Dict[str, Any]], period_days: int = 1) -> None:
    """
    Send a daily digest of security findings to Slack.
    This is a separate function that can be triggered by CloudWatch Events.
    """
    if not findings or not SLACK_WEBHOOK_URL:
        return

    # Aggregate by severity
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for finding in findings:
        severity = finding.get('Severity', {}).get('Label', 'LOW')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    total = sum(severity_counts.values())

    # Build digest message
    blocks = [
        {
            'type': 'header',
            'text': {
                'type': 'plain_text',
                'text': f':daily security digest: Security findings summary - last {period_days} day(s)'
            }
        },
        {
            'type': 'section',
            'fields': [
                {
                    'type': 'mrkdwn',
                    'text': f'*Total Findings:* {total}'
                },
                {
                    'type': 'mrkdwn',
                    'text': f'*Environment:* {ENVIRONMENT.title()}'
                }
            ]
        },
        {
            'type': 'section',
            'fields': [
                {
                    'type': 'mrkdwn',
                    'text': f':red_circle: *Critical:* {severity_counts.get("CRITICAL", 0)}'
                },
                {
                    'type': 'mrkdwn',
                    'text': f':large_orange_circle: *High:* {severity_counts.get("HIGH", 0)}'
                }
            ]
        },
        {
            'type': 'section',
            'fields': [
                {
                    'type': 'mrkdwn',
                    'text': f':large_yellow_circle: *Medium:* {severity_counts.get("MEDIUM", 0)}'
                },
                {
                    'type': 'mrkdwn',
                    'text': f':large_blue_circle: *Low:* {severity_counts.get("LOW", 0)}'
                }
            ]
        }
    ]

    payload = {
        'channel': SLACK_CHANNEL,
        'blocks': blocks
    }

    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            SLACK_WEBHOOK_URL,
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            print(f"[SUCCESS] Daily digest sent: {response.status}")
    except Exception as e:
        print(f"[ERROR] Failed to send digest: {e}")
