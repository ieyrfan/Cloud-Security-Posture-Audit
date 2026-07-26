# ----------------------------------------------------------------------------------------------------------------------
# Logging Module Outputs
# ----------------------------------------------------------------------------------------------------------------------

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = var.create_cloudtrail ? aws_cloudtrail.this[0].arn : null
}

output "cloudtrail_id" {
  description = "ID of the CloudTrail trail"
  value       = var.create_cloudtrail ? aws_cloudtrail.this[0].id : null
}

output "cloudtrail_home_region" {
  description = "Home region of the CloudTrail trail"
  value       = var.create_cloudtrail ? aws_cloudtrail.this[0].home_region : null
}

output "cloudtrail_bucket_id" {
  description = "S3 bucket ID for CloudTrail logs"
  value       = var.create_cloudtrail_bucket ? aws_s3_bucket.cloudtrail[0].id : var.cloudtrail_bucket_name
}

output "cloudtrail_bucket_arn" {
  description = "S3 bucket ARN for CloudTrail logs"
  value       = var.create_cloudtrail_bucket ? aws_s3_bucket.cloudtrail[0].arn : null
}

output "cloudwatch_log_group_name" {
  description = "CloudWatch Log Group name for CloudTrail"
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "cloudwatch_log_group_arn" {
  description = "CloudWatch Log Group ARN for CloudTrail"
  value       = aws_cloudwatch_log_group.cloudtrail.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for security alerts"
  value       = var.create_sns_topic ? aws_sns_topic.alerts[0].arn : null
}

output "metric_filter_names" {
  description = "List of CIS metric filter names"
  value       = var.create_cis_alarms ? aws_cloudwatch_log_metric_filter.cis_2_10[*].name : []
}
