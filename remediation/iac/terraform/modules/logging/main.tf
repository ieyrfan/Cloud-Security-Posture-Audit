# ----------------------------------------------------------------------------------------------------------------------
# Logging Module - CloudTrail, CloudWatch Logs, CIS Metric Filters, and SNS Alerts
# ----------------------------------------------------------------------------------------------------------------------
# Creates:
# - CloudTrail multi-region trail with log file validation
# - CloudWatch Logs group for CloudTrail events
# - Metric filters and alarms for CIS AWS Foundations Benchmarks 2.10-2.19
# - SNS topic for security alert notifications
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
  cloudtrail_name = format("%s-trail", var.environment)
  log_group_name  = format("/aws/cloudtrail/%s", var.environment)
  
  common_tags = merge(
    var.tags,
    {
      Environment = var.environment
      ManagedBy   = "terraform"
      Module      = "logging"
    }
  )
}

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ----------------------------------------------------------------------------------------------------------------------
# S3 Bucket for CloudTrail Logs
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_s3_bucket" "cloudtrail" {
  count = var.create_cloudtrail_bucket ? 1 : 0

  bucket = var.cloudtrail_bucket_name != null
    ? var.cloudtrail_bucket_name
    : format("%s-cloudtrail-logs-%s", var.environment, data.aws_caller_identity.current.account_id)

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-cloudtrail-bucket", var.environment)
    }
  )
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count = var.create_cloudtrail_bucket ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  count = var.create_cloudtrail_bucket ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  count = var.create_cloudtrail_bucket ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  count = var.create_cloudtrail_bucket ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    id     = "expire-old-trails"
    status = "Enabled"

    expiration {
      days = var.cloudtrail_log_retention_days
    }

    filter {}
  }
}

# Bucket policy for CloudTrail delivery
resource "aws_s3_bucket_policy" "cloudtrail" {
  count = var.create_cloudtrail_bucket ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail[0].arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = format("arn:%s:cloudtrail:%s:%s:trail/%s",
              data.aws_partition.current.partition,
              data.aws_region.current.name,
              data.aws_caller_identity.current.account_id,
              local.cloudtrail_name)
          }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = format("%s/AWSLogs/%s/*", aws_s3_bucket.cloudtrail[0].arn, data.aws_caller_identity.current.account_id)
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"              = "bucket-owner-full-control"
            "aws:SourceArn" = format("arn:%s:cloudtrail:%s:%s:trail/%s",
              data.aws_partition.current.partition,
              data.aws_region.current.name,
              data.aws_caller_identity.current.account_id,
              local.cloudtrail_name)
          }
        }
      }
    ]
  })
}

# ----------------------------------------------------------------------------------------------------------------------
# CloudWatch Logs Group for CloudTrail
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = local.log_group_name
  retention_in_days = var.cloudtrail_log_retention_days
  kms_key_id        = var.cloudtrail_logs_kms_key_id

  tags = local.common_tags
}

# ----------------------------------------------------------------------------------------------------------------------
# IAM Role for CloudTrail to deliver to CloudWatch Logs
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = format("%s-cloudtrail-cw-role", var.environment)

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = format("%s-cloudtrail-cw-policy", var.environment)
  role = aws_iam_role.cloudtrail_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = format("%s:*", aws_cloudwatch_log_group.cloudtrail.arn)
      }
    ]
  })
}

# ----------------------------------------------------------------------------------------------------------------------
# CloudTrail - Multi-Region Trail with Log File Validation
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_cloudtrail" "this" {
  count = var.create_cloudtrail ? 1 : 0

  name                          = local.cloudtrail_name
  enable_log_file_validation    = true
  enable_logging                = true
  is_multi_region_trail         = true
  include_global_service_events = true
  s3_bucket_name                = var.create_cloudtrail_bucket ? aws_s3_bucket.cloudtrail[0].id : var.cloudtrail_bucket_name
  s3_key_prefix                 = var.cloudtrail_s3_key_prefix
  cloud_watch_logs_group_arn    = format("%s:*", aws_cloudwatch_log_group.cloudtrail.arn)
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch.arn
  kms_key_id                    = var.cloudtrail_kms_key_id

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    dynamic "data_resource" {
      for_each = var.cloudtrail_log_s3_data_events ? [1] : []
      content {
        type   = "AWS::S3::Object"
        values = [format("arn:%s:s3:::", data.aws_partition.current.partition)]
      }
    }

    dynamic "data_resource" {
      for_each = var.cloudtrail_log_lambda_data_events ? [1] : []
      content {
        type   = "AWS::Lambda::Function"
        values = [format("arn:%s:lambda::function:", data.aws_partition.current.partition)]
      }
    }
  }

  insight_selector {
    insight_type = "ApiCallRateInsight"
  }

  insight_selector {
    insight_type = "ApiErrorRateInsight"
  }

  tags = merge(
    local.common_tags,
    {
      Name = local.cloudtrail_name
    }
  )
}

# ----------------------------------------------------------------------------------------------------------------------
# SNS Topic for Security Alerts
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  count = var.create_sns_topic ? 1 : 0

  name              = format("%s-security-alerts", var.environment)
  display_name      = format("[%s] Security Alerts", var.environment)
  kms_master_key_id = var.sns_kms_key_id

  tags = local.common_tags
}

resource "aws_sns_topic_policy" "alerts" {
  count = var.create_sns_topic ? 1 : 0

  arn = aws_sns_topic.alerts[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudWatchAlarms"
        Effect    = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.alerts[0].arn
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "email" {
  count = var.create_sns_topic && var.alert_email != null ? 1 : 0

  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ======================================================================================================================
# CIS AWS Foundations Benchmark Metric Filters and Alarms
# ======================================================================================================================

# ----------------------------------------------------------------------------------------------------------------------
# CIS 2.10 - Ensure CloudTrail log file validation is enabled
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "cis_2_10" {
  count = var.create_cis_alarms ? 1 : 0

  name           = format("%s-cis-2-10-cloudtrail-validation", var.environment)
  pattern        = "{ \$.eventSource = \"cloudtrail.amazonaws.com\" && \$.eventName = \"UpdateTrail\" && \$.requestParameters.enableLogFileValidation = \"false\" }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = format("%s-cis-2-10-cloudtrail-validation", var.environment)
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis_2_10" {
  count = var.create_cis_alarms ? 1 : 0

  alarm_name          = format("%s-cis-2-10-cloudtrail-validation", var.environment)
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.cis_2_10[0].metric_transformation[0].name
  namespace           = "CISBenchmark"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "CIS 2.10: CloudTrail log file validation was disabled. Alert when log file validation is modified or disabled."
  alarm_actions       = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions          = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []

  tags = local.common_tags
}

# ----------------------------------------------------------------------------------------------------------------------
# CIS 2.11 - Ensure S3 bucket CloudTrail logs are encrypted at rest
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "cis_2_11" {
  count = var.create_cis_alarms ? 1 : 0

  name           = format("%s-cis-2-11-cloudtrail-encryption", var.environment)
  pattern        = "{ \$.eventSource = \"cloudtrail.amazonaws.com\" && \$.eventName = \"UpdateTrail\" && \$.requestParameters.s3BucketName = \"*\" }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = format("%s-cis-2-11-cloudtrail-encryption", var.environment)
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis_2_11" {
  count = var.create_cis_alarms ? 1 : 0

  alarm_name          = format("%s-cis-2-11-cloudtrail-encryption", var.environment)
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.cis_2_11[0].metric_transformation[0].name
  namespace           = "CISBenchmark"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "CIS 2.11: CloudTrail bucket encryption was modified. Alert when CloudTrail configuration changes."
  alarm_actions       = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions          = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []

  tags = local.common_tags
}

# ----------------------------------------------------------------------------------------------------------------------
# CIS 2.12 - Ensure no unauthorized API calls
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "cis_2_12" {
  count = var.create_cis_alarms ? 1 : 0

  name           = format("%s-cis-2-12-unauthorized-api", var.environment)
  pattern        = "{ (\$.errorCode = \"*UnauthorizedOperation\") || (\$.errorCode = \"AccessDenied\") }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = format("%s-cis-2-12-unauthorized-api", var.environment)
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis_2_12" {
  count = var.create_cis_alarms ? 1 : 0

  alarm_name          = format("%s-cis-2-12-unauthorized-api", var.environment)
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.cis_2_12[0].metric_transformation[0].name
  namespace           = "CISBenchmark"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "CIS 2.12: Unauthorized API calls detected. Alert when there are unauthorized API operations."
  alarm_actions       = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions          = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []

  tags = local.common_tags
}

# ----------------------------------------------------------------------------------------------------------------------
# CIS 2.13 - Ensure no MFA-disabled root user actions
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "cis_2_13" {
  count = var.create_cis_alarms ? 1 : 0

  name           = format("%s-cis-2-13-root-usage", var.environment)
  pattern        = "{ \$.userIdentity.type = \"Root\" && \$.userIdentity.invokedBy NOT EXISTS && \$.eventType != \"AwsServiceEvent\" }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = format("%s-cis-2-13-root-usage", var.environment)
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis_2_13" {
  count = var.create_cis_alarms ? 1 : 0

  alarm_name          = format("%s-cis-2-13-root-usage", var.environment)
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.cis_2_13[0].metric_transformation[0].name
  namespace           = "CISBenchmark"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "CIS 2.13: Root account usage detected. Alert when the root user performs any action."
  alarm_actions       = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions          = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []

  tags = local.common_tags
}

# ----------------------------------------------------------------------------------------------------------------------
# CIS 2.14 - Ensure IAM policy changes are monitored
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "cis_2_14" {
  count = var.create_cis_alarms ? 1 : 0

  name           = format("%s-cis-2-14-iam-policy-changes", var.environment)
  pattern        = "{ (\$.eventSource = \"iam.amazonaws.com\") && (\$.eventName = \"DeleteGroupPolicy\" || \$.eventName = \"DeleteRolePolicy\" || \$.eventName = \"DeleteUserPolicy\" || \$.eventName = \"PutGroupPolicy\" || \$.eventName = \"PutRolePolicy\" || \$.eventName = \"PutUserPolicy\" || \$.eventName = \"CreatePolicy\" || \$.eventName = \"DeletePolicy\" || \$.eventName = \"CreatePolicyVersion\" || \$.eventName = \"DeletePolicyVersion\" || \$.eventName = \"SetDefaultPolicyVersion\") }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = format("%s-cis-2-14-iam-policy-changes", var.environment)
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis_2_14" {
  count = var.create_cis_alarms ? 1 : 0

  alarm_name          = format("%s-cis-2-14-iam-policy-changes", var.environment)
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.cis_2_14[0].metric_transformation[0].name
  namespace           = "CISBenchmark"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "CIS 2.14: IAM policy changes detected. Alert when IAM policies are modified."
  alarm_actions       = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions          = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []

  tags = local.common_tags
}

# ----------------------------------------------------------------------------------------------------------------------
# CIS 2.15 - Ensure CloudTrail configuration changes are monitored
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "cis_2_15" {
  count = var.create_cis_alarms ? 1 : 0

  name           = format("%s-cis-2-15-cloudtrail-changes", var.environment)
  pattern        = "{ \$.eventSource = \"cloudtrail.amazonaws.com\" && (\$.eventName = \"CreateTrail\" || \$.eventName = \"UpdateTrail\" || \$.eventName = \"DeleteTrail\" || \$.eventName = \"StartLogging\" || \$.eventName = \"StopLogging\") }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = format("%s-cis-2-15-cloudtrail-changes", var.environment)
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis_2_15" {
  count = var.create_cis_alarms ? 1 : 0

  alarm_name          = format("%s-cis-2-15-cloudtrail-changes", var.environment)
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.cis_2_15[0].metric_transformation[0].name
  namespace           = "CISBenchmark"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "CIS 2.15: CloudTrail configuration changes detected. Alert when CloudTrail is modified."
  alarm_actions       = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions          = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []

  tags = local.common_tags
}

# ----------------------------------------------------------------------------------------------------------------------
# CIS 2.16 - Ensure AWS Management Console authentication failures are monitored
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "cis_2_16" {
  count = var.create_cis_alarms ? 1 : 0

  name           = format("%s-cis-2-16-console-signin-failures", var.environment)
  pattern        = "{ \$.eventName = \"ConsoleLogin\" && \$.responseElements.ConsoleLogin = \"Failure\" }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = format("%s-cis-2-16-console-signin-failures", var.environment)
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis_2_16" {
  count = var.create_cis_alarms ? 1 : 0

  alarm_name          = format("%s-cis-2-16-console-signin-failures", var.environment)
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.cis_2_16[0].metric_transformation[0].name
  namespace           = "CISBenchmark"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "CIS 2.16: Console sign-in failures detected. Alert when authentication failures occur."
  alarm_actions       = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions          = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []

  tags = local.common_tags
}

# ----------------------------------------------------------------------------------------------------------------------
# CIS 2.17 - Ensure security group changes are monitored
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "cis_2_17" {
  count = var.create_cis_alarms ? 1 : 0

  name           = format("%s-cis-2-17-security-group-changes", var.environment)
  pattern        = "{ \$.eventName = \"AuthorizeSecurityGroupIngress\" || \$.eventName = \"AuthorizeSecurityGroupEgress\" || \$.eventName = \"RevokeSecurityGroupIngress\" || \$.eventName = \"RevokeSecurityGroupEgress\" || \$.eventName = \"CreateSecurityGroup\" || \$.eventName = \"DeleteSecurityGroup\" }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = format("%s-cis-2-17-security-group-changes", var.environment)
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis_2_17" {
  count = var.create_cis_alarms ? 1 : 0

  alarm_name          = format("%s-cis-2-17-security-group-changes", var.environment)
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.cis_2_17[0].metric_transformation[0].name
  namespace           = "CISBenchmark"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "CIS 2.17: Security group changes detected. Alert when security groups are modified."
  alarm_actions       = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions          = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []

  tags = local.common_tags
}

# ----------------------------------------------------------------------------------------------------------------------
# CIS 2.18 - Ensure Network ACL changes are monitored
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "cis_2_18" {
  count = var.create_cis_alarms ? 1 : 0

  name           = format("%s-cis-2-18-network-acl-changes", var.environment)
  pattern        = "{ \$.eventName = \"CreateNetworkAcl\" || \$.eventName = \"CreateNetworkAclEntry\" || \$.eventName = \"DeleteNetworkAcl\" || \$.eventName = \"DeleteNetworkAclEntry\" || \$.eventName = \"ReplaceNetworkAclEntry\" || \$.eventName = \"ReplaceNetworkAclAssociation\" }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = format("%s-cis-2-18-network-acl-changes", var.environment)
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis_2_18" {
  count = var.create_cis_alarms ? 1 : 0

  alarm_name          = format("%s-cis-2-18-network-acl-changes", var.environment)
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.cis_2_18[0].metric_transformation[0].name
  namespace           = "CISBenchmark"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "CIS 2.18: Network ACL changes detected. Alert when NACLs are modified."
  alarm_actions       = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions          = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []

  tags = local.common_tags
}

# ----------------------------------------------------------------------------------------------------------------------
# CIS 2.19 - Ensure route table changes are monitored
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "cis_2_19" {
  count = var.create_cis_alarms ? 1 : 0

  name           = format("%s-cis-2-19-route-table-changes", var.environment)
  pattern        = "{ \$.eventName = \"CreateRoute\" || \$.eventName = \"DeleteRoute\" || \$.eventName = \"ReplaceRoute\" || \$.eventName = \"ReplaceRouteTableAssociation\" || \$.eventName = \"DisassociateRouteTable\" || \$.eventName = \"CreateRouteTable\" || \$.eventName = \"DeleteRouteTable\" || \$.eventName = \"AssociateRouteTable\" }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = format("%s-cis-2-19-route-table-changes", var.environment)
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis_2_19" {
  count = var.create_cis_alarms ? 1 : 0

  alarm_name          = format("%s-cis-2-19-route-table-changes", var.environment)
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.cis_2_19[0].metric_transformation[0].name
  namespace           = "CISBenchmark"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "CIS 2.19: Route table changes detected. Alert when route tables are modified."
  alarm_actions       = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions          = var.create_sns_topic ? [aws_sns_topic.alerts[0].arn] : []

  tags = local.common_tags
}
