variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "azure_region" {
  description = "Azure region for resources"
  type        = string
  default     = "eastus"
}

variable "allowed_ips" {
  description = "List of allowed IP addresses for administrative access"
  type        = list(string)
  default     = ["10.0.0.0/8", "172.16.0.0/12"]
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
  sensitive   = true
}

variable "cis_benchmark_version" {
  description = "CIS Benchmark version to use"
  type        = string
  default     = "v1.5.0"
}

variable "enable_threat_detection" {
  description = "Enable threat detection services (GuardDuty, Macie)"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Number of days to retain logs"
  type        = number
  default     = 365
}

variable "encryption_config" {
  description = "Encryption configuration"
  type = object({
    kms_key_rotation = bool
    sse_algorithm    = string
  })
  default = {
    kms_key_rotation = true
    sse_algorithm    = "aws:kms"
  }
}

variable "scan_schedule" {
  description = "Schedule for automated security scans (cron format)"
  type        = string
  default     = "cron(0 2 * * ? *)"  # Daily at 2 AM UTC
}
