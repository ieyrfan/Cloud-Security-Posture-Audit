# ----------------------------------------------------------------------------------------------------------------------
# IAM Module Variables
# ----------------------------------------------------------------------------------------------------------------------

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "create_ec2_role" {
  description = "Create IAM role for EC2 instances"
  type        = bool
  default     = true
}

variable "ec2_s3_bucket_arns" {
  description = "List of S3 bucket ARNs for EC2 read-only access"
  type        = list(string)
  default     = []
}

variable "create_rds_monitoring_role" {
  description = "Create IAM role for RDS Enhanced Monitoring"
  type        = bool
  default     = true
}

variable "create_lambda_role" {
  description = "Create IAM role for Lambda functions"
  type        = bool
  default     = true
}

variable "lambda_vpc_access" {
  description = "Grant Lambda role VPC access permissions"
  type        = bool
  default     = false
}

variable "lambda_kms_key_arns" {
  description = "List of KMS key ARNs for Lambda decryption"
  type        = list(string)
  default     = []
}

variable "lambda_secrets_arns" {
  description = "List of Secrets Manager secret ARNs for Lambda access"
  type        = list(string)
  default     = []
}

variable "create_mfa_policy" {
  description = "Create MFA enforcement policy"
  type        = bool
  default     = true
}

variable "create_support_role" {
  description = "Create read-only support role"
  type        = bool
  default     = true
}

variable "support_principal_arns" {
  description = "List of IAM ARNs allowed to assume the support role"
  type        = list(string)
  default     = null
}

variable "tags" {
  description = "Additional tags"
  type        = map(string)
  default     = {}
}
