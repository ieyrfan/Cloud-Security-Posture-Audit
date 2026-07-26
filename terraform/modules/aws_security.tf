variable "environment" {}
variable "allowed_ips" {}
variable "mfa_enabled" {}
variable "min_password_length" {}
variable "password_reuse_prevention" {}
variable "max_password_age" {}

# IAM Password Policy - CIS 1.5
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length      = var.min_password_length
  require_symbols              = true
  require_numbers              = true
  require_uppercase_characters = true
  require_lowercase_characters = true
  allow_users_to_change_password = true
  expire_passwords            = true
  password_reuse_prevention    = var.password_reuse_prevention
  max_password_age            = var.max_password_age
  hard_expiry                 = false
}

# Account-level security settings
resource "aws_iam_account_alias" "main" {
  account_alias = "security-audit-${var.environment}"
}

# CloudTrail for audit logging - CIS 2.1-2.4
resource "aws_cloudtrail" "audit" {
  name                          = "security-audit-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/"]
    }

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda:*:*:function:*"]
    }
  }

  tags = {
    Name        = "Security Audit Trail"
    Environment = var.environment
    Control     = "CIS 2.1-2.4"
  }
}

# CloudTrail S3 Bucket
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "cloudtrail-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "CloudTrail Logs"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_logging" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  target_bucket = aws_s3_bucket.cloudtrail.id
  target_prefix = "cloudtrail-logs/"
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.security_audit.arn
    }
    bucket_key_enabled = true
  }
}

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "security_audit" {
  description             = "KMS key for security audit data"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "security_audit" {
  name          = "alias/security-audit-${var.environment}"
  target_key_id = aws_kms_key.security_audit.key_id
}

# API Gateway with WAF
resource "aws_api_gateway_rest_api" "secure_api" {
  name        = "security-api-${var.environment}"
  description = "Secured API Gateway with WAF protection"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_wafv2_web_acl_association" "api_gateway" {
  resource_arn = aws_api_gateway_rest_api.secure_api.arn
  web_acl_arn  = aws_wafv2_web_acl.security.arn
}

# Security Group for SSH access
resource "aws_security_group" "secure_ssh" {
  name_prefix = "secure-ssh-${var.environment}-"
  description = "Secure SSH access with IP whitelisting"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ips
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "Secure SSH"
    Environment = var.environment
    Control     = "CIS 5.1"
  }
}

# VPC with no public SGs
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "Security VPC"
    Environment = var.environment
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name        = "Private Subnet ${count.index + 1}"
    Environment = var.environment
    Tier        = "Private"
  }
}

data "aws_availability_zones" "available" {}

# Network ACL for defense in depth
resource "aws_network_acl" "main" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  tags = {
    Name        = "Main Network ACL"
    Environment = var.environment
  }
}

# S3 Block Public Access
resource "aws_s3_bucket_public_access_block" "main" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "ssh_security_group_id" {
  value = aws_security_group.secure_ssh.id
}
