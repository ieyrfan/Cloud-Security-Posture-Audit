# Slack Security Alerting

Serverless Slack alerting for AWS Security Hub findings using Lambda and EventBridge.

## Architecture

```
Security Hub → EventBridge Rule → SNS Topic → Lambda → Slack
              (Filter CRITICAL/HIGH)        (Format & Send)
```

## Setup

### 1. Create Slack Incoming Webhook

1. Go to https://api.slack.com/apps
2. Create new app: "Security Bot"
3. Enable Incoming Webhooks
4. Create webhook for your channel (e.g., #security-alerts)
5. Copy the webhook URL

### 2. Deploy Lambda with Terraform

```hcl
module "slack_security_alerts" {
  source = "./terraform/modules/alerting/slack"

  environment             = "prod"
  slack_webhook_url       = var.slack_webhook_url  # Store in SSM Parameter Store
  slack_channel           = "#security-alerts"
  alert_on_severity       = ["CRITICAL", "HIGH"]
}
```

### 3. Create Slack Alerting ZIP

```bash
cd lambda
pip install -r requirements.txt -t .
zip -r slack_alert.zip slack_alert.py
cd ..
terraform apply
```

## Alert Format

Slack alerts use Block Kit formatting:

```
:red_circle: CRITICAL: S3 Bucket Public Access

S3 bucket allows public read access

Severity: CRITICAL
Resource: AWS::S3::Bucket: audit-vulnerable-data-xxxxx
Environment: Production
Time: 2024-01-15 14:30 UTC

[View in Console] [Remediation Runbook]
```

## Daily Digest

The Lambda also sends a daily digest summarizing all findings:

```
:scroll: Daily security findings summary

Total Findings: 8
Environment: Production

Critical: 1 | High: 3
Medium:  2 | Low: 2
```

## EventBridge Trigger

The rule triggers on:
- Any Security Hub finding import
- Filtered to CRITICAL and HIGH severity
- Excludes INFORMATIONAL findings

## Testing

```bash
# Test Lambda locally
python -m pytest lambda/tests/

# Invoke Lambda with test event
aws lambda invoke \
  --function-name slack-alert-prod \
  --payload '{"detail": {"findings": [{"Title": "Test", "Severity": {"Label": "HIGH"}, "Description": "Test finding"}]}}' \
  response.json
```
