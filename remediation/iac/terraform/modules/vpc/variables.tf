# ----------------------------------------------------------------------------------------------------------------------
# VPC Module Variables
# ----------------------------------------------------------------------------------------------------------------------

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.environment))
    error_message = "Environment name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "aws_region" {
  description = "AWS region for VPC endpoints"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "availability_zones" {
  description = "List of availability zones for subnet deployment"
  type        = list(string)

  validation {
    condition     = length(var.availability_zones) >= 2
    error_message = "At least two availability zones are required for high availability."
  }
}

variable "single_nat_gateway" {
  description = "Use a single NAT Gateway for all private subnets (cost savings vs. high availability)"
  type        = bool
  default     = false
}

variable "flow_logs_traffic_type" {
  description = "Type of traffic to log (ALL, ACCEPT, REJECT)"
  type        = string
  default     = "ALL"

  validation {
    condition     = contains(["ALL", "ACCEPT", "REJECT"], var.flow_logs_traffic_type)
    error_message = "Traffic type must be one of: ALL, ACCEPT, REJECT."
  }
}

variable "flow_logs_retention_days" {
  description = "Retention period in days for VPC Flow Logs"
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.flow_logs_retention_days)
    error_message = "Retention days must be a valid CloudWatch Logs retention period."
  }
}

variable "flow_logs_kms_key_id" {
  description = "KMS Key ID for encrypting VPC Flow Logs (null uses CloudWatch default)"
  type        = string
  default     = null
}

variable "dhcp_options_id" {
  description = "DHCP Options Set ID to associate (null uses default)"
  type        = string
  default     = null
}

variable "enable_s3_endpoint" {
  description = "Enable VPC Gateway Endpoint for S3"
  type        = bool
  default     = true
}

variable "enable_dynamodb_endpoint" {
  description = "Enable VPC Gateway Endpoint for DynamoDB"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
