output "aws_security_hub_url" {
  description = "URL to AWS Security Hub dashboard"
  value       = "https://${var.aws_region}.console.aws.amazon.com/securityhub"
}

output "azure_security_center_url" {
  description = "URL to Azure Security Center dashboard"
  value       = "https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/awssc"
}

output "compliance_report_bucket" {
  description = "S3 bucket storing compliance reports"
  value       = aws_s3_bucket.compliance_reports.arn
}

output "security_findings_topic_arn" {
  description = "SNS topic ARN for security findings"
  value       = aws_sns_topic.security_alerts.arn
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = try(aws_guardduty_detector.main.id, "disabled")
}

output "macie_session_id" {
  description = "Macie session ID"
  value       = try(aws_macie_account.main.id, "disabled")
}

output "waf_web_acl_arn" {
  description = "WAF Web ACL ARN"
  value       = try(aws_wafv2_web_acl.security.arn, "disabled")
}

output "cis_findings_count" {
  description = "Current CIS findings count"
  value = {
    total     = aws_securityhub_insight.critical_findings.filter_count + aws_securityhub_insight.high_findings.filter_count
    critical  = aws_securityhub_insight.critical_findings.filter_count
    high      = aws_securityhub_insight.high_findings.filter_count
  }
}
