# ----------------------------------------------------------------------------------------------------------------------
# RDS Module - Production-grade RDS with encryption, Multi-AZ, backups, and security
# ----------------------------------------------------------------------------------------------------------------------
# Creates an RDS instance with:
# - Encryption at rest (KMS)
# - Multi-AZ deployment option
# - Automated backups with configurable retention
# - Deletion protection enabled
# - Parameter group with SSL/TLS enforcement
# ----------------------------------------------------------------------------------------------------------------------

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
  }
}

# ----------------------------------------------------------------------------------------------------------------------
# Local variables
# ----------------------------------------------------------------------------------------------------------------------
locals {
  db_identifier = format("%s-%s", var.environment, var.db_identifier_suffix)
  
  common_tags = merge(
    var.tags,
    {
      Environment = var.environment
      ManagedBy   = "terraform"
      Module      = "rds"
    }
  )
}

data "aws_partition" "current" {}

# ----------------------------------------------------------------------------------------------------------------------
# Random password for master password if not provided
# ----------------------------------------------------------------------------------------------------------------------
resource "random_password" "master" {
  count = var.master_password == null ? 1 : 0

  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:"
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
}

# ----------------------------------------------------------------------------------------------------------------------
# KMS Key for RDS Encryption (if not using default)
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_kms_key" "rds" {
  count = var.create_kms_key ? 1 : 0

  description             = format("KMS key for RDS %s encryption", local.db_identifier)
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-rds-key", var.environment)
    }
  )
}

resource "aws_kms_alias" "rds" {
  count = var.create_kms_key ? 1 : 0

  name          = format("alias/%s-rds", var.environment)
  target_key_id = aws_kms_key.rds[0].key_id
}

# ----------------------------------------------------------------------------------------------------------------------
# DB Parameter Group with SSL/TLS enforcement
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_db_parameter_group" "this" {
  count = var.create_parameter_group ? 1 : 0

  name        = format("%s-param-group", local.db_identifier)
  family      = var.parameter_group_family
  description = format("Parameter group for %s with SSL enforcement", local.db_identifier)

  dynamic "parameter" {
    for_each = var.parameters
    content {
      name         = parameter.value.name
      value        = parameter.value.value
      apply_method = parameter.value.apply_method
    }
  }

  tags = local.common_tags
}

# ----------------------------------------------------------------------------------------------------------------------
# DB Subnet Group
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_db_subnet_group" "this" {
  count = var.create_subnet_group ? 1 : 0

  name        = format("%s-subnet-group", local.db_identifier)
  description = format("Subnet group for %s", local.db_identifier)
  subnet_ids  = var.subnet_ids

  tags = local.common_tags
}


# ----------------------------------------------------------------------------------------------------------------------
# Security Group for RDS
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_security_group" "this" {
  count = var.create_security_group ? 1 : 0

  name        = format("%s-rds-sg", local.db_identifier)
  description = format("Security group for %s RDS instance", local.db_identifier)
  vpc_id      = var.vpc_id

  # Ingress - allow database port from allowed CIDRs/security groups
  dynamic "ingress" {
    for_each = var.allowed_security_group_ids != null ? [1] : []
    content {
      from_port       = var.db_port
      to_port         = var.db_port
      protocol        = "tcp"
      security_groups = var.allowed_security_group_ids
    }
  }

  dynamic "ingress" {
    for_each = var.allowed_cidr_blocks != null ? var.allowed_cidr_blocks : []
    content {
      from_port   = var.db_port
      to_port     = var.db_port
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-rds-sg", var.environment)
    }
  )
}

# ----------------------------------------------------------------------------------------------------------------------
# RDS Instance
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_db_instance" "this" {
  identifier = local.db_identifier

  # Engine Settings
  engine         = var.engine
  engine_version = var.engine_version
  instance_class = var.instance_class

  # Storage
  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = var.storage_type
  storage_encrypted     = true
  kms_key_id            = var.create_kms_key ? aws_kms_key.rds[0].arn : var.kms_key_arn

  # Database Configuration
  db_name  = var.db_name
  username = var.master_username
  password = var.master_password != null ? var.master_password : random_password.master[0].result
  port     = var.db_port

  # Network
  vpc_security_group_ids = var.create_security_group
    ? [aws_security_group.this[0].id]
    : var.vpc_security_group_ids
  db_subnet_group_name = var.create_subnet_group
    ? aws_db_subnet_group.this[0].name
    : var.db_subnet_group_name
  publicly_accessible = false

  # High Availability
  multi_az = var.multi_az

  # Backup & Maintenance
  backup_retention_period  = var.backup_retention_period
  backup_window            = var.backup_window
  maintenance_window       = var.maintenance_window
  copy_tags_to_snapshot    = true
  delete_automated_backups = false

  # Security
  deletion_protection = true
  skip_final_snapshot = false
  final_snapshot_identifier = var.final_snapshot_identifier != null
    ? var.final_snapshot_identifier
    : format("%s-final-snapshot-%s", local.db_identifier, formatdate("YYYY-MM-DD-hhmmss", timestamp()))

  # Parameter Group
  parameter_group_name = var.create_parameter_group
    ? aws_db_parameter_group.this[0].name
    : var.parameter_group_name

  # Enhanced Monitoring
  monitoring_interval = var.monitoring_interval
  monitoring_role_arn = var.monitoring_interval > 0 ? (
    var.monitoring_role_arn != null
    ? var.monitoring_role_arn
    : aws_iam_role.enhanced_monitoring[0].arn
  ) : null

  # Performance Insights
  performance_insights_enabled          = var.performance_insights_enabled
  performance_insights_retention_period = var.performance_insights_retention_period
  performance_insights_kms_key_id       = var.performance_insights_enabled ? (
    var.create_kms_key ? aws_kms_key.rds[0].arn : var.kms_key_arn
  ) : null

  # IAM Authentication
  iam_database_authentication_enabled = var.iam_database_authentication_enabled

  # Auto Minor Version Upgrade
  auto_minor_version_upgrade = var.auto_minor_version_upgrade

  # Enable CloudWatch Logs Exports
  enabled_cloudwatch_logs_exports = var.cloudwatch_logs_exports

  tags = merge(
    local.common_tags,
    {
      Name = local.db_identifier
    }
  )
}
