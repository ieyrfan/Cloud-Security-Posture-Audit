# ----------------------------------------------------------------------------------------------------------------------
# RDS Module Variables
# ----------------------------------------------------------------------------------------------------------------------

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
}

variable "db_identifier_suffix" {
  description = "Suffix for the DB identifier (appended after environment)"
  type        = string
  default     = "db"
}

variable "engine" {
  description = "Database engine (mysql, postgres, etc.)"
  type        = string
  default     = "postgres"
}

variable "engine_version" {
  description = "Database engine version"
  type        = string
  default     = "15.4"
}

variable "instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "allocated_storage" {
  description = "Allocated storage size in GB"
  type        = number
  default     = 20
}

variable "max_allocated_storage" {
  description = "Maximum storage size in GB (autoscaling limit, 0 to disable)"
  type        = number
  default     = 100
}

variable "storage_type" {
  description = "Storage type (gp2, gp3, io1, io2)"
  type        = string
  default     = "gp3"
}

variable "db_name" {
  description = "Database name (default db created on instance)"
  type        = string
  default     = null
}

variable "master_username" {
  description = "Master username for the database"
  type        = string
  default     = "admin"
}

variable "master_password" {
  description = "Master password (null auto-generates a random password)"
  type        = string
  default     = null
  sensitive   = true
}

variable "db_port" {
  description = "Database port"
  type        = number
  default     = 5432
}

variable "vpc_id" {
  description = "VPC ID for the security group"
  type        = string
  default     = null
}

variable "subnet_ids" {
  description = "List of subnet IDs for the DB subnet group"
  type        = list(string)
  default     = []
}

variable "vpc_security_group_ids" {
  description = "List of security group IDs (used when create_security_group = false)"
  type        = list(string)
  default     = []
}

variable "allowed_security_group_ids" {
  description = "List of security group IDs allowed to access the database"
  type        = list(string)
  default     = null
}

variable "allowed_cidr_blocks" {
  description = "List of CIDR blocks allowed to access the database"
  type        = list(string)
  default     = null
}

variable "create_security_group" {
  description = "Create a security group for the RDS instance"
  type        = bool
  default     = true
}

variable "create_subnet_group" {
  description = "Create a DB subnet group"
  type        = bool
  default     = true
}

variable "db_subnet_group_name" {
  description = "Existing subnet group name (used when create_subnet_group = false)"
  type        = string
  default     = null
}

variable "multi_az" {
  description = "Enable Multi-AZ deployment for high availability"
  type        = bool
  default     = true
}

variable "backup_retention_period" {
  description = "Backup retention period in days"
  type        = number
  default     = 30

  validation {
    condition     = var.backup_retention_period >= 7 && var.backup_retention_period <= 35
    error_message = "Backup retention period must be between 7 and 35 days."
  }
}

variable "backup_window" {
  description = "Daily backup window (UTC)"
  type        = string
  default     = "03:00-04:00"
}

variable "maintenance_window" {
  description = "Maintenance window (UTC)"
  type        = string
  default     = "sun:05:00-sun:06:00"
}

variable "final_snapshot_identifier" {
  description = "Custom final snapshot identifier (null auto-generates)"
  type        = string
  default     = null
}

variable "create_parameter_group" {
  description = "Create a DB parameter group"
  type        = bool
  default     = true
}

variable "parameter_group_family" {
  description = "DB parameter group family"
  type        = string
  default     = "postgres15"
}

variable "parameter_group_name" {
  description = "Existing parameter group name (used when create_parameter_group = false)"
  type        = string
  default     = null
}

variable "parameters" {
  description = "List of DB parameters to apply"
  type = list(object({
    name         = string
    value        = string
    apply_method = string
  }))
  default = [
    {
      name         = "rds.force_ssl"
      value        = "1"
      apply_method = "pending-reboot"
    },
    {
      name         = "ssl"
      value        = "1"
      apply_method = "pending-reboot"
    }
  ]
}

variable "create_kms_key" {
  description = "Create a KMS key for RDS encryption"
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "Existing KMS key ARN (used when create_kms_key = false)"
  type        = string
  default     = null
}

variable "monitoring_interval" {
  description = "Enhanced monitoring interval in seconds (0 to disable)"
  type        = number
  default     = 60
}

variable "monitoring_role_arn" {
  description = "Existing monitoring role ARN (null auto-creates)"
  type        = string
  default     = null
}

variable "performance_insights_enabled" {
  description = "Enable Performance Insights"
  type        = bool
  default     = true
}

variable "performance_insights_retention_period" {
  description = "Performance Insights retention period in days (7, 731, or two years)"
  type        = number
  default     = 7
}

variable "iam_database_authentication_enabled" {
  description = "Enable IAM database authentication"
  type        = bool
  default     = true
}

variable "auto_minor_version_upgrade" {
  description = "Enable automatic minor version upgrades"
  type        = bool
  default     = true
}

variable "cloudwatch_logs_exports" {
  description = "List of log types to export to CloudWatch"
  type        = list(string)
  default     = ["postgresql", "upgrade"]
}

variable "create_alarms" {
  description = "Create CloudWatch metric alarms for RDS"
  type        = bool
  default     = true
}

variable "max_connections_threshold" {
  description = "Threshold for database connections alarm"
  type        = number
  default     = 100
}

variable "alarm_sns_topics" {
  description = "List of SNS topic ARNs for alarms"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Additional tags to apply"
  type        = map(string)
  default     = {}
}
