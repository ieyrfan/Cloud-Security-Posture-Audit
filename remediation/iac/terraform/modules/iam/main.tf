# ----------------------------------------------------------------------------------------------------------------------
# IAM Module - Password policy, least-privilege roles, and MFA enforcement
# ----------------------------------------------------------------------------------------------------------------------
# Creates:
# - Account password policy (14 chars, 90-day rotation, prevent reuse)
# - IAM roles for EC2, RDS, Lambda with least-privilege policies
# - MFA enforcement policy for human users
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
  common_tags = merge(
    var.tags,
    {
      Environment = var.environment
      ManagedBy   = "terraform"
      Module      = "iam"
    }
  )
}

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

# ----------------------------------------------------------------------------------------------------------------------
# Account Password Policy
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_iam_account_password_policy" "this" {
  minimum_password_length      = 14
  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers              = true
  require_symbols              = true
  allow_users_to_change_password = true
  hard_expiry                  = false
  max_password_age             = 90
  password_reuse_prevention    = 24
}

# ----------------------------------------------------------------------------------------------------------------------
# IAM Role for EC2 Instances
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_iam_role" "ec2" {
  count = var.create_ec2_role ? 1 : 0

  name        = format("%s-ec2-role", var.environment)
  description = "IAM role for EC2 instances in "

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  max_session_duration = 3600

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-ec2-role", var.environment)
    }
  )
}

resource "aws_iam_instance_profile" "ec2" {
  count = var.create_ec2_role ? 1 : 0

  name = format("%s-ec2-instance-profile", var.environment)
  role = aws_iam_role.ec2[0].name

  tags = local.common_tags
}

# EC2 Least-Privilege Policy
resource "aws_iam_policy" "ec2" {
  count = var.create_ec2_role ? 1 : 0

  name        = format("%s-ec2-policy", var.environment)
  description = "Least-privilege policy for EC2 instances in "

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CloudWatchAgent"
        Effect   = "Allow"
        Action   = [
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricData",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Sid      = "SSMAgent"
        Effect   = "Allow"
        Action   = [
          "ssm:DescribeAssociation",
          "ssm:GetDeployablePatchSnapshotForInstance",
          "ssm:GetDocument",
          "ssm:DescribeDocument",
          "ssm:GetManifest",
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:ListAssociations",
          "ssm:PutInventory",
          "ssm:PutComplianceItems",
          "ssm:PutConfigurePackageResult",
          "ssm:UpdateAssociationStatus",
          "ssm:UpdateInstanceAssociationStatus",
          "ssm:UpdateInstanceInformation"
        ]
        Resource = "*"
      },
      {
        Sid      = "EC2Describe"
        Effect   = "Allow"
        Action   = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Sid      = "S3ReadOnly"
        Effect   = "Allow"
        Action   = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = var.ec2_s3_bucket_arns
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "ec2" {
  count = var.create_ec2_role ? 1 : 0

  role       = aws_iam_role.ec2[0].name
  policy_arn = aws_iam_policy.ec2[0].arn
}


# ----------------------------------------------------------------------------------------------------------------------
# IAM Role for RDS - Enhanced Monitoring (if not created by RDS module)
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_iam_role" "rds_monitoring" {
  count = var.create_rds_monitoring_role ? 1 : 0

  name        = format("%s-rds-monitoring-role", var.environment)
  description = "IAM role for RDS Enhanced Monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = [
    format("arn:%s:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole", data.aws_partition.current.partition)
  ]

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-rds-monitoring-role", var.environment)
    }
  )
}

# ----------------------------------------------------------------------------------------------------------------------
# IAM Role for Lambda Functions
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_iam_role" "lambda" {
  count = var.create_lambda_role ? 1 : 0

  name        = format("%s-lambda-role", var.environment)
  description = "IAM role for Lambda functions in "

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  max_session_duration = 3600

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-lambda-role", var.environment)
    }
  )
}

# Lambda Least-Privilege Policy
resource "aws_iam_policy" "lambda" {
  count = var.create_lambda_role ? 1 : 0

  name        = format("%s-lambda-policy", var.environment)
  description = "Least-privilege policy for Lambda functions in "

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = format("arn:%s:logs:%s:%s:*", data.aws_partition.current.partition, var.aws_region, data.aws_caller_identity.current.account_id)
      },
      {
        Sid      = "XRay"
        Effect   = "Allow"
        Action   = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        Resource = "*"
      },
      {
        Sid      = "VPCManagement"
        Effect   = "Allow"
        Action   = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface",
          "ec2:AssignPrivateIpAddresses",
          "ec2:UnassignPrivateIpAddresses"
        ]
        Resource = "*"
      },
      {
        Sid      = "KMSDecrypt"
        Effect   = "Allow"
        Action   = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = var.lambda_kms_key_arns
      },
      {
        Sid      = "SecretsManager"
        Effect   = "Allow"
        Action   = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = var.lambda_secrets_arns
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  count = var.create_lambda_role ? 1 : 0

  role       = aws_iam_role.lambda[0].name
  policy_arn = format("arn:%s:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole", data.aws_partition.current.partition)
}

resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  count = var.create_lambda_role && var.lambda_vpc_access ? 1 : 0

  role       = aws_iam_role.lambda[0].name
  policy_arn = format("arn:%s:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole", data.aws_partition.current.partition)
}

# ----------------------------------------------------------------------------------------------------------------------
# MFA Enforcement Policy
# ----------------------------------------------------------------------------------------------------------------------
# This policy denies most API actions if the user does not have MFA enabled.
# Attach this policy to groups or users that require MFA.
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_iam_policy" "mfa_enforcement" {
  count = var.create_mfa_policy ? 1 : 0

  name        = format("%s-mfa-enforcement", var.environment)
  description = "Enforces MFA authentication for human users in ${var.environment}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyAllExceptListedIfNoMFA"
        Effect   = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ListUsers",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "iam:ChangePassword",
          "iam:GetAccountPasswordPolicy",
          "iam:GetUser",
          "sts:GetSessionToken"
        ]
        Resource = "*"
        Condition = {
          "BoolIfExists" = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-mfa-policy", var.environment)
    }
  )
}

# ----------------------------------------------------------------------------------------------------------------------
# Support Role (Read-Only) for Break Glass / Support Access
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_iam_role" "support" {
  count = var.create_support_role ? 1 : 0

  name        = format("%s-support-role", var.environment)
  description = "Read-only support role for ${var.environment} with MFA enforcement"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = var.support_principal_arns != null ? var.support_principal_arns : []
        }
        Condition = {
          "Bool" = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  max_session_duration = 28800

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-support-role", var.environment)
    }
  )
}

resource "aws_iam_role_policy_attachment" "support_readonly" {
  count = var.create_support_role ? 1 : 0

  role       = aws_iam_role.support[0].name
  policy_arn = format("arn:%s:iam::aws:policy/ReadOnlyAccess", data.aws_partition.current.partition)
}

