# ----------------------------------------------------------------------------------------------------------------------
# S3 Module - Secure S3 bucket with encryption, versioning, logging, and lifecycle rules
# ----------------------------------------------------------------------------------------------------------------------
# Creates a production-grade S3 bucket with:
# - Block Public Access at account and bucket level
# - Default encryption via KMS (SSE-KMS)
# - Versioning enabled
# - Access logging to a separate log bucket
# - Lifecycle policy for transition to IA/Glacier and expiration
# ----------------------------------------------------------------------------------------------------------------------
	erraform {
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
  bucket_name       = var.bucket_name != null ? var.bucket_name : format("%s-%s-%s", var.environment, var.bucket_suffix, data.aws_caller_identity.current.account_id)
  log_bucket_name   = var.log_bucket_name != null ? var.log_bucket_name : format("%s-%s-logs-%s", var.environment, var.bucket_suffix, data.aws_caller_identity.current.account_id)
  common_tags = merge(
    var.tags,
    {
      Environment = var.environment
      ManagedBy   = "terraform"
      Module      = "s3"
    }
  )
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

# ----------------------------------------------------------------------------------------------------------------------
# KMS Key for S3 Default Encryption
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_kms_key" "s3" {
  count = var.create_kms_key ? 1 : 0

  description             = format("KMS key for S3 bucket %s encryption", local.bucket_name)
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = format("arn:%s:iam::%s:root", data.aws_partition.current.partition, data.aws_caller_identity.current.account_id)
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow S3 Service to use the key"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-s3-key", var.environment)
    }
  )
}

resource "aws_kms_alias" "s3" {
  count = var.create_kms_key ? 1 : 0

  name          = format("alias/%s-s3-bucket", var.environment)
  target_key_id = aws_kms_key.s3[0].key_id
}

# ----------------------------------------------------------------------------------------------------------------------
# S3 Bucket ACL Ownership (recommended over canned ACLs)
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}


# ----------------------------------------------------------------------------------------------------------------------
# S3 Bucket - Main Bucket
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_s3_bucket" "this" {
  bucket = local.bucket_name

  tags = merge(
    local.common_tags,
    {
      Name = local.bucket_name
    }
  )
}

# ----------------------------------------------------------------------------------------------------------------------
# Block Public Access (bucket-level)
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ----------------------------------------------------------------------------------------------------------------------
# Default Encryption - SSE-KMS
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.create_kms_key ? aws_kms_key.s3[0].arn : var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

# ----------------------------------------------------------------------------------------------------------------------
# Versioning - Enabled with MFA Delete (optional)
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status     = "Enabled"
    mfa_delete = var.enable_mfa_delete ? "Enabled" : "Disabled"
  }
}

# ----------------------------------------------------------------------------------------------------------------------
# Lifecycle Configuration
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  dynamic "rule" {
    for_each = var.lifecycle_rules
    content {
      id     = rule.value.id
      status = rule.value.enabled ? "Enabled" : "Disabled"

      filter {
        prefix = rule.value.prefix != null ? rule.value.prefix : ""
        tags   = rule.value.tags
      }

      dynamic "transition" {
        for_each = rule.value.transitions != null ? rule.value.transitions : []
        content {
          days          = transition.value.days
          storage_class = transition.value.storage_class
        }
      }

      dynamic "expiration" {
        for_each = rule.value.expiration != null ? [rule.value.expiration] : []
        content {
          days = expiration.value.days
        }
      }

      dynamic "noncurrent_version_transition" {
        for_each = rule.value.noncurrent_version_transitions != null ? rule.value.noncurrent_version_transitions : []
        content {
          noncurrent_days = noncurrent_version_transition.value.days
          storage_class   = noncurrent_version_transition.value.storage_class
        }
      }

      dynamic "noncurrent_version_expiration" {
        for_each = rule.value.noncurrent_version_expiration != null ? [rule.value.noncurrent_version_expiration] : []
        content {
          noncurrent_days = noncurrent_version_expiration.value.days
        }
      }
    }
  }
}


# ----------------------------------------------------------------------------------------------------------------------
# S3 Access Logging Bucket
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_s3_bucket" "log" {
  count = var.enable_access_logging ? 1 : 0

  bucket = local.log_bucket_name

  tags = merge(
    local.common_tags,
    {
      Name = local.log_bucket_name
    }
  )
}

resource "aws_s3_bucket_public_access_block" "log" {
  count = var.enable_access_logging ? 1 : 0

  bucket = aws_s3_bucket.log[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "log" {
  count = var.enable_access_logging ? 1 : 0

  bucket = aws_s3_bucket.log[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log" {
  count = var.enable_access_logging ? 1 : 0

  bucket = aws_s3_bucket.log[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "log" {
  count = var.enable_access_logging ? 1 : 0

  bucket = aws_s3_bucket.log[0].id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    expiration {
      days = var.access_log_expiration_days
    }

    filter {}
  }
}

# Log delivery bucket policy
resource "aws_s3_bucket_policy" "log_delivery" {
  count = var.enable_access_logging ? 1 : 0

  bucket = aws_s3_bucket.log[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "S3ServerAccessLogsDelivery"
        Effect    = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action   = [
          "s3:PutObject"
        ]
        Resource = format("%s/*", aws_s3_bucket.log[0].arn)
        Condition = {
          ArnLike = {
            "aws:SourceArn" = aws_s3_bucket.this.arn
          }
        }
      }
    ]
  })
}

# Enable access logging on the main bucket
resource "aws_s3_bucket_logging" "this" {
  count = var.enable_access_logging ? 1 : 0

  bucket = aws_s3_bucket.this.id

  target_bucket = aws_s3_bucket.log[0].id
  target_prefix = format("access-logs/%s/", var.environment)
}


# ----------------------------------------------------------------------------------------------------------------------
# Bucket Policy - Enforce HTTPS and other security controls
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_s3_bucket_policy" "this" {
  count = var.attach_bucket_policy ? 1 : 0

  bucket = aws_s3_bucket.this.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureConnections"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.this.arn,
          format("%s/*", aws_s3_bucket.this.arn)
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# ----------------------------------------------------------------------------------------------------------------------
# CORS Configuration (optional)
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_s3_bucket_cors_configuration" "this" {
  count = var.enable_cors ? 1 : 0

  bucket = aws_s3_bucket.this.id

  dynamic "cors_rule" {
    for_each = var.cors_rules
    content {
      allowed_headers = cors_rule.value.allowed_headers
      allowed_methods = cors_rule.value.allowed_methods
      allowed_origins = cors_rule.value.allowed_origins
      expose_headers  = cors_rule.value.expose_headers
      max_age_seconds = cors_rule.value.max_age_seconds
    }
  }
}
