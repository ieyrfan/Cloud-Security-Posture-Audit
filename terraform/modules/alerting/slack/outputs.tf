output "sns_topic_arn" {
  description = "ARN of the security findings SNS topic"
  value       = aws_sns_topic.security_findings.arn
}

output "lambda_function_name" {
  description = "Name of the Slack alert Lambda function"
  value       = aws_lambda_function.slack_alert.function_name
}

output "event_rule_arn" {
  description = "ARN of the EventBridge rule"
  value       = aws_cloudwatch_event_rule.security_hub_findings.arn
}

output "slack_integration_status" {
  description = "Status of Slack integration"
  value       = var.slack_webhook_url != "" ? "configured" : "not_configured"
}
