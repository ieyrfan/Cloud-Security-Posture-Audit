terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "archive_file" "slack_alert" {
  type        = "zip"
  source_dir  = "${path.module}/../../../../lambda"
  output_path = "${path.module}/slack_alert.zip"
}

# SNS Topic for security findings
resource "aws_sns_topic" "security_findings" {
  name = "security-findings-${var.environment}"

  tags = merge(var.tags, {
    Name        = "Security Findings Topic"
    Environment = var.environment
  })
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.security_findings.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.slack_alert.arn
}

# Lambda execution role
resource "aws_iam_role" "slack_alert" {
  name = "slack-alert-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name        = "Slack Alert Lambda Role"
    Environment = var.environment
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.slack_alert.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "slack_alert_policy" {
  name = "slack-alert-policy"
  role = aws_iam_role.slack_alert.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:DescribeFindings"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Lambda function
resource "aws_lambda_function" "slack_alert" {
  filename         = data.archive_file.slack_alert.output_path
  function_name    = "slack-alert-${var.environment}"
  role            = aws_iam_role.slack_alert.arn
  handler         = "slack_alert.lambda_handler"
  source_code_hash = data.archive_file.slack_alert.output_base64sha256
  runtime         = var.lambda_runtime
  memory_size     = var.lambda_memory_size
  timeout         = var.lambda_timeout

  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      SLACK_CHANNEL     = var.slack_channel
      ENVIRONMENT       = var.environment
    }
  }

  tags = merge(var.tags, {
    Name        = "Slack Alert Lambda"
    Environment = var.environment
  })
}

resource "aws_lambda_permission" "allow_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_alert.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.security_findings.arn
}

# EventBridge rule for Security Hub findings
resource "aws_cloudwatch_event_rule" "security_hub_findings" {
  name        = "security-hub-findings-${var.environment}"
  description = "Capture Security Hub findings with severity ${join(", ", var.alert_on_severity)}"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = {
            anything-but = ["INFORMATIONAL"]
          }
        }
      }
    }
  })

  tags = merge(var.tags, {
    Name        = "Security Hub Findings Rule"
    Environment = var.environment
  })
}

resource "aws_cloudwatch_event_target" "slack_alert" {
  rule      = aws_cloudwatch_event_rule.security_hub_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_findings.arn
}

# Security Hub insight for CRITICAL finding
resource "aws_securityhub_insight" "critical_findings" {
  filters {
    resource_type {
      comparison = "EQUALS"
      value      = "AwsAccount"
    }
  }

  group_by_attribute = "ResourceType"

  name    = "Critical Findings ${var.environment}"
  query   = "findingverificationstate='UNKNOWN' AND severitylabel='CRITICAL'"
  version = "2020-01-01"

  tags = merge(var.tags, {
    Name        = "Critical Findings Insight"
    Environment = var.environment
  })
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic"
  value       = aws_sns_topic.security_findings.arn
}

output "lambda_function_name" {
  description = "Name of the Slack alert Lambda function"
  value       = aws_lambda_function.slack_alert.function_name
}

output "event_rule_name" {
  description = "Name of the EventBridge rule"
  value       = aws_cloudwatch_event_rule.security_hub_findings.name
}
