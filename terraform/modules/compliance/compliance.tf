variable "environment" {}
variable "cis_benchmark_version" {}

# AWS Config Rules for CIS Compliance
# CIS AWS Foundations Benchmark v1.2.0

# CIS 1.1 - Root account MFA enabled
resource "aws_iam_account_password_policy" "cis" {
  minimum_password_length      = 14
  require_symbols              = true
  require_numbers              = true
  require_uppercase_characters = true
  require_lowercase_characters = true
  allow_users_to_change_password = true
  password_reuse_prevention    = 12
  max_password_age            = 90
}

# CIS 1.2 - MFA enabled for IAM users
resource "aws_config_config_rule" "mfa_enabled" {
  name = "iam-user-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "IAM User MFA"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "1.2"
  }
}

# CIS 1.3 - Unused credentials
resource "aws_config_config_rule" "credential_unused" {
  name = "iam-user-unused-credentials-check"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
  }

  input_parameters = jsonencode({
    maxCredentialUsageAge = "90"
  })

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "IAM Unused Credentials"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "1.3"
  }
}

# CIS 1.4 - IAM password policy
resource "aws_config_config_rule" "password_policy" {
  name = "iam-password-policy"

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  input_parameters = jsonencode({
    RequireUppercaseCharacters          = "true"
    RequireLowercaseCharacters          = "true"
    RequireSymbols                      = "true"
    RequireNumbers                      = "true"
    MinimumPasswordLength               = "14"
    PasswordReusePrevention             = "12"
    MaxPasswordAge                      = "90"
  })

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "IAM Password Policy"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "1.4"
  }
}

# CIS 1.5 - Root access keys
resource "aws_config_config_rule" "root_account_key" {
  name = "root-account-no-access-keys"

  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCOUNT_KEY_PAIR_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "Root Account Access Key"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "1.5"
  }
}

# CIS 1.6 - Multi-factor authentication
resource "aws_config_config_rule" "mfa_enabled_console" {
  name = "mfa-enabled-for-console"

  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "MFA Console"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "1.6"
  }
}

# CIS 1.7 - No root account usage
resource "aws_config_config_rule" "no_root_account" {
  name = "no-root-account-usage"

  source {
    owner             = "AWS"
    source_identifier = "NO_ROOT_ACCOUNT_ACCESS_KEY_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "No Root Usage"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "1.7"
  }
}

# CIS 1.8 - MFA for root account
resource "aws_config_config_rule" "root_mfa" {
  name = "root-account-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "Root MFA"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "1.8"
  }
}

# CIS 1.9 - Hardware MFA for root
resource "aws_config_config_rule" "root_hardware_mfa" {
  name = "root-account-hardware-mfa"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_HARDWARE_MFA"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "Root Hardware MFA"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "1.9"
  }
}

# CIS 1.10 - No root account console access
resource "aws_config_config_rule" "no_root_console" {
  name = "no-root-account-console-access"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_NO_CONSOLE_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "No Root Console"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "1.10"
  }
}

# Config Setup
resource "aws_s3_bucket" "config" {
  bucket = "config-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "Config Logs"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket = aws_s3_bucket.config.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM Role for Config
resource "aws_iam_role" "config_role" {
  name = "config-role-${var.environment}"

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
}

resource "aws_iam_role_policy_attachment" "config_role" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

resource "aws_config_configuration_recorder" "config" {
  name     = "config-recorder-${var.environment}"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "config" {
  name           = "config-channel"
  s3_bucket_name = aws_s3_bucket.config.bucket
  depends_on     = [aws_config_configuration_recorder.config]
}

# S3 Bucket Public Access Protection
resource "aws_config_config_rule" "s3_public_access" {
  name = "s3-bucket-public-access"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_ACCESS_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "S3 Public Access Block"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "2.1.3"
  }
}

# S3 Encryption
resource "aws_config_config_rule" "s3_encryption" {
  name = "s3-bucket-server-side-encryption"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "S3 Encryption"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "2.1.1"
  }
}

# S3 SSL Only
resource "aws_config_config_rule" "s3_ssl_only" {
  name = "s3-bucket-ssl-requests-only"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "S3 SSL Only"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "2.1.4"
  }
}

# S3 Versioning
resource "aws_config_config_rule" "s3_versioning" {
  name = "s3-bucket-versioning-enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "S3 Versioning"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "2.1.2"
  }
}

# Instance Public IP
resource "aws_config_config_rule" "instance_no_public_ip" {
  name = "ec2-instance-no-public-ip"

  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_NO_PUBLIC_IP"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "No Public IP"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "5.1"
  }
}

# EBS Encryption
resource "aws_config_config_rule" "ebs_encryption" {
  name = "ec2-ebs-encrypted"

  source {
    owner             = "AWS"
    source_identifier = "EC2_EBS_ENCRYPTION"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "EBS Encryption"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "5.2"
  }
}

# RDS Storage Encryption
resource "aws_config_config_rule" "rds_encryption" {
  name = "rds-storage-encrypted"

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "RDS Encryption"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "5.3"
  }
}

# Redshift Encryption
resource "aws_config_config_rule" "redshift_encryption" {
  name = "redshift-cluster-configuration-check"

  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_CLUSTER_CONFIGURATION_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "Redshift Encryption"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "5.4"
  }
}

# CloudTrail enabled
resource "aws_config_config_rule" "cloudtrail_enabled" {
  name = "cloudtrail-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "CloudTrail"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "2.1"
  }
}

# CloudTrail log validation
resource "aws_config_config_rule" "cloudtrail_validation" {
  name = "cloudtrail-log-file-validation"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "CloudTrail Log Validation"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "2.2"
  }
}

# Security group restrictions
resource "aws_config_config_rule" "sg_restricted" {
  name = "security-group-restricted-common-ports"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_COMMON_PORTS"
  }

  input_parameters = jsonencode({
    blockedPort1 = "20"
    blockedPort2 = "21"
    blockedPort3 = "3389"
  })

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "Security Group Port Restrictions"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "5.2"
  }
}

# Lambda Concurrency
resource "aws_config_config_rule" "lambda_concurrency" {
  name = "lambda-function-public-access-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.config]

  tags = {
    Name        = "Lambda Public Access"
    Environment = var.environment
    Benchmark   = "CIS"
    Control     = "5.5"
  }
}

output "config_recorder_name" {
  value = aws_config_configuration_recorder.config.name
}

output "config_compliance_rules" {
  value = [
    aws_config_config_rule.mfa_enabled.name,
    aws_config_config_rule.credential_unused.name,
    aws_config_config_rule.password_policy.name,
    aws_config_config_rule.root_account_key.name,
    aws_config_config_rule.mfa_enabled_console.name,
    aws_config_config_rule.no_root_account.name,
    aws_config_config_rule.root_mfa.name,
    aws_config_config_rule.s3_public_access.name,
    aws_config_config_rule.s3_encryption.name,
    aws_config_config_rule.s3_ssl_only.name,
    aws_config_config_rule.s3_versioning.name,
    aws_config_config_rule.instance_no_public_ip.name,
    aws_config_config_rule.ebs_encryption.name,
    aws_config_config_rule.rds_encryption.name,
    aws_config_config_rule.redshift_encryption.name,
    aws_config_config_rule.cloudtrail_enabled.name,
    aws_config_config_rule.cloudtrail_validation.name,
  ]
}
