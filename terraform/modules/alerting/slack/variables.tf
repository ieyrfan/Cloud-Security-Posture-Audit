variable "environment" {
  description = "Environment name"
  type        = string
}

variable "slack_webhook_url" {
  description = "Slack incoming webhook URL"
  type        = string
  sensitive   = true
}

variable "slack_channel" {
  description = "Slack channel for alerts"
  type        = string
  default     = "#security-alerts"
}

variable "alert_on_severity" {
  description = "List of severities to alert on"
  type        = list(string)
  default     = ["CRITICAL", "HIGH"]
}

variable "lambda_runtime" {
  description = "Lambda runtime"
  type        = string
  default     = "python3.11"
}

variable "lambda_memory_size" {
  description = "Lambda memory size in MB"
  type        = number
  default     = 128
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds"
  type        = number
  default     = 30
}

variable "schedule_expression" {
  description = "CloudWatch Event schedule expression"
  type        = string
  default     = "rate(15 minutes)"
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
