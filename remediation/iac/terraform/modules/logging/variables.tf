# ----------------------------------------------------------------------------------------------------------------------
# Logging Module Variables
# ----------------------------------------------------------------------------------------------------------------------

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
}

variable "create_cloudtrail" {
  description = "Create CloudTrail trail"
  type        = bool
  default     = true
}

variable "create_cloudtrail_bucket" {
  description = "Create S3 bucket for CloudTrail logs"
  type        = bool
  default     = true
}

variable "cloudtrail_bucket_name" {
  description = "Name of existing S3 bucket for CloudTrail (null creates one)"
  type        = string
  default     = null
}

variable "cloudtrail_s3_key_prefix" {
  description = "S3 key prefix for CloudTrail logs"
  type        = string
  default     = null
}

variable "cloudtrail_log_retention_days" {
  description = "Retention period for CloudTrail logs in days"
  type        = number
  default     = 365
}

variable "cloudtrail_log_s3_data_events" {
  description = "Log S3 data events in CloudTrail"
  type        = bool
  default     = true
}

variable "cloudtrail_log_lambda_data_events" {
  description = "Log Lambda data events in CloudTrail"
  type        = bool
  default     = true
}

variable "cloudtrail_kms_key_id" {
  description = "KMS key ID for CloudTrail log encryption"
  type        = string
  default     = null
}

variable "cloudtrail_logs_kms_key_id" {
  description = "KMS key ID for CloudWatch Logs encryption"
  type        = string
  default     = null
}

variable "create_sns_topic" {
  description = "Create SNS topic for security alerts"
  type        = bool
  default     = true
}

variable "alert_email" {
  description = "Email address for SNS subscription (null to skip)"
  type        = string
  default     = null
}

variable "sns_kms_key_id" {
  description = "KMS key ID for SNS topic encryption"
  type        = string
  default     = null
}

variable "create_cis_alarms" {
  description = "Create CIS Benchmark metric filters and alarms (2.10-2.19)"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags"
  type        = map(string)
  default     = {}
}
