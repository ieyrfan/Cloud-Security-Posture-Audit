# ----------------------------------------------------------------------------------------------------------------------
# IAM Module Outputs
# ----------------------------------------------------------------------------------------------------------------------

output "ec2_role_arn" {
  description = "ARN of the EC2 IAM role"
  value       = var.create_ec2_role ? aws_iam_role.ec2[0].arn : null
}

output "ec2_instance_profile_name" {
  description = "Name of the EC2 instance profile"
  value       = var.create_ec2_role ? aws_iam_instance_profile.ec2[0].name : null
}

output "ec2_instance_profile_arn" {
  description = "ARN of the EC2 instance profile"
  value       = var.create_ec2_role ? aws_iam_instance_profile.ec2[0].arn : null
}

output "rds_monitoring_role_arn" {
  description = "ARN of the RDS Enhanced Monitoring role"
  value       = var.create_rds_monitoring_role ? aws_iam_role.rds_monitoring[0].arn : null
}

output "lambda_role_arn" {
  description = "ARN of the Lambda IAM role"
  value       = var.create_lambda_role ? aws_iam_role.lambda[0].arn : null
}

output "lambda_role_name" {
  description = "Name of the Lambda IAM role"
  value       = var.create_lambda_role ? aws_iam_role.lambda[0].name : null
}

output "mfa_policy_arn" {
  description = "ARN of the MFA enforcement policy"
  value       = var.create_mfa_policy ? aws_iam_policy.mfa_enforcement[0].arn : null
}

output "support_role_arn" {
  description = "ARN of the support role"
  value       = var.create_support_role ? aws_iam_role.support[0].arn : null
}

output "password_policy_set" {
  description = "Whether the account password policy has been set"
  value       = true
}
