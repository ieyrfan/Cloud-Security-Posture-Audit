terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }

  backend "s3" {
    bucket         = "terraform-state-security-audit"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}

# AWS Provider
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = var.environment
      Project     = "cloud-security-posture-audit"
      ManagedBy   = "Terraform"
      Compliance  = "CIS"
    }
  }
}

# Azure Provider
provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = true
    }
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}

# Security Module - IAM Hardening
module "aws_security" {
  source = "./modules/aws_security"

  environment      = var.environment
  allowed_ips      = var.allowed_ips
  mfa_enabled      = true
将所有密码策略
  min_password_length     = 14
  password_reuse_prevention = 12
  max_password_age        = 90
}

# Compliance Module - CIS Controls
module "compliance" {
  source = "./modules/compliance"

  environment            = var.environment
  cis_benchmark_version = "v1.5.0"
}

# Monitoring Module - CloudWatch/Log Analytics
module "monitoring" {
  source = "./modules/monitoring"

  environment = var.environment
  retention_days = 365
}

# Data Sources
data "aws_caller_identity" "current" {}
data "azurerm_client_config" "current" {}

# Resource Group
resource "aws_resourcegroups_group" "security_audit" {
  name = "security-posture-${var.environment}"

  resource_query {
    query = jsonencode({
      ResourceTypeFilters = ["AWS::AllSupported"]
      TagFilters = [
        {
          Key    = "Environment"
          Values = [var.environment]
        }
      ]
    })
  }
}

# S3 Bucket for reports
resource "aws_s3_bucket" "compliance_reports" {
  bucket = "security-compliance-reports-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "Security Compliance Reports"
    Environment = var.environment
    Purpose     = "Audit Documentation"
  }
}

resource "aws_s3_bucket_versioning" "compliance_reports" {
  bucket = aws_s3_bucket.compliance_reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliance_reports" {
  bucket = aws_s3_bucket.compliance_reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.security_audit.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "compliance_reports" {
  bucket = aws_s3_bucket.compliance_reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# KMS Key for encryption
resource "aws_kms_key" "security_audit" {
  description             = "KMS key for security audit data encryption"
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

  tags = {
    Name        = "security-audit-kms-key"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "security_audit" {
  name          = "alias/security-audit-${var.environment}"
  target_key_id = aws_kms_key.security_audit.key_id
}

# Security Hub for CIS Findings
resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v1.2.0"
}

resource "aws_securityhub_standards_subscription" "pci" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/pci-dss/v3.2.1"
}

# CloudWatch Log Group for security findings
resource "aws_cloudwatch_log_group" "security_findings" {
  name              = "/aws/securityaudit/findings"
  retention_in_days = 365

  kms_key_id = aws_kms_key.security_audit.arn

  tags = {
    Name        = "Security Findings Log Group"
    Environment = var.environment
  }
}

# CloudWatch Dashboard for security posture
resource "aws_cloudwatch_dashboard" "security_posture" {
  dashboard_name = "security-posture-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/SecurityHub", "FindingCount", "StandardArn", aws_securityhub_standards_subscription.cis.standards_arn]
          ]
          view = "singleValue"
          stacked = false
          yAxis = {
            left = {
              min = 0
            }
          }
          title = "CIS Findings Count"
          region = var.aws_region
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/SecurityHub", "FindingCount", "SeverityLabel", "CRITICAL"],
            [".", ".", ".", "HIGH"],
            [".", ".", ".", "MEDIUM"],
            [".", ".", ".", "LOW"]
          ]
          view  = "pie"
          title = "Findings by Severity"
          region = var.aws_region
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 24
        height = 6

        properties = {
          metrics = [
            ["AWS/SecurityHub", "FindingCount"]
          ]
          view    = "timeSeries"
          stacked = false
          title   = "Findings Trends (30 days)"
          region  = var.aws_region
        }
      }
    ]
  })
}

# Config Rules for continuous compliance
resource "aws_config_config_rule" "root_account_mfa" {
  name = "security-posture-root-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = {
    Name        = "Root Account MFA"
    Environment = var.environment
    Control     = "CIS 1.1"
  }
}

resource "aws_config_config_rule" "mfa_enabled_for_iam" {
  name = "security-posture-mfa-enabled-for-iam"

  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = {
    Name        = "MFA for IAM Console"
    Environment = var.environment
    Control     = "CIS 1.2"
  }
}

# Config Configuration Recorder
resource "aws_config_configuration_recorder" "main" {
  name     = "security-posture-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "security-posture-channel"
  s3_bucket_name = aws_s3_bucket.compliance_reports.bucket
  depends_on     = [aws_config_configuration_recorder.main]
}

resource "aws_iam_role" "config_role" {
  name = "config-role-security-audit"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/ConfigRole"
  ]
}

# GuardDuty for threat detection
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    flow_logs {
      enable = true
    }
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
}

# Macie for data classification
resource "aws_macie_account" "main" {}

resource "aws_macie_s3_bucket_association" "compliance_reports" {
  bucket_name = aws_s3_bucket.compliance_reports.id

  classification_type {
    continuous = true
    one_time   = true
  }
}

# WAFv2 for web application protection
resource "aws_wafv2_web_acl" "security" {
  name  = "security-posture-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    action {
      block {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "SecurityPostureWAF"
    sampled_requests_enabled   = true
  }

  tags = {
    Name        = "Security Posture WAF"
    Environment = var.environment
  }
}

# Security Hub Insights
resource "aws_securityhub_insight" "critical_findings" {
  filters {
    resource_type {
      comparison = "EQUALS"
      value      = "AwsAccount"
    }
  }

  group_by_attribute = "ResourceType"

  name    = "Critical Findings"
  query   = "findingverificationstate='UNKNOWN' AND severitylabel='CRITICAL'"
  version = "2020-01-01"
}

resource "aws_securityhub_insight" "high_findings" {
  filters {
    resource_type {
      comparison = "EQUALS"
      value      = "AwsAccount"
    }
  }

  group_by_attribute = "ResourceType"

  name    = "High Findings"
  query   = "findingverificationstate='UNKNOWN' AND severitylabel='HIGH'"
  version = "2020-01-01"
}

# CloudWatch Event Rule for new findings
resource "aws_cloudwatch_event_rule" "security_findings" {
  name        = "security-posture-findings"
  description = "Capture security findings"

  event_pattern = jsonencode({
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Findings - Imported"]
    "detail": {
      "findings": {
        "Severity": {
          "Label": {
            "anything-but": ["INFORMATIONAL"]
          }
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "security_findings" {
  rule     = aws_cloudwatch_event_rule.security_findings.name
  target_id = "SendToSNS"
  arn      = aws_sns_topic.security_alerts.arn
}

resource "aws_sns_topic" "security_alerts" {
  name = "security-alerts-${var.environment}"

  kms_master_key_id = aws_kms_key.security_audit.arn
}

resource "aws_sns_topic_subscription" "security_alerts_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Outputs
output "security_summary" {
  description = "Security posture summary"
  value = {
    environment        = var.environment
    cis_benchmark     = aws_securityhub_standards_subscription.cis.standards_arn
    pci_dss_subscription = aws_securityhub_standards_subscription.pci.standards_arn
    compliance_bucket = aws_s3_bucket.compliance_reports.arn
    kms_key_id        = aws_kms_key.security_audit.key_id
    security_hub_url  = "https://${var.aws_region}.console.aws.amazon.com/securityhub"
  }
}

output "compliance_bucket_arn" {
  description = "ARN of the compliance reports bucket"
  value       = aws_s3_bucket.compliance_reports.arn
}

output "alert_topic_arn" {
  description = "ARN of the security alerts SNS topic"
  value       = aws_sns_topic.security_alerts.arn
}
