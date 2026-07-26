# ----------------------------------------------------------------------------------------------------------------------
# S3 Module Outputs
# ----------------------------------------------------------------------------------------------------------------------

output "bucket_id" {
  description = "The name of the S3 bucket"
  value       = aws_s3_bucket.this.id
}

output "bucket_arn" {
  description = "The ARN of the S3 bucket"
  value       = aws_s3_bucket.this.arn
}

output "bucket_domain_name" {
  description = "The domain name of the S3 bucket"
  value       = aws_s3_bucket.this.bucket_domain_name
}

output "bucket_regional_domain_name" {
  description = "The regional domain name of the S3 bucket"
  value       = aws_s3_bucket.this.bucket_regional_domain_name
}

output "kms_key_arn" {
  description = "The ARN of the KMS key used for S3 encryption"
  value       = var.create_kms_key ? aws_kms_key.s3[0].arn : var.kms_key_arn
}

output "kms_key_id" {
  description = "The ID of the KMS key used for S3 encryption"
  value       = var.create_kms_key ? aws_kms_key.s3[0].key_id : null
}

output "log_bucket_id" {
  description = "The name of the access logging bucket"
  value       = var.enable_access_logging ? aws_s3_bucket.log[0].id : null
}

output "log_bucket_arn" {
  description = "The ARN of the access logging bucket"
  value       = var.enable_access_logging ? aws_s3_bucket.log[0].arn : null
}

output "versioning_enabled" {
  description = "Whether versioning is enabled on the bucket"
  value       = true
}

output "encryption_algorithm" {
  description = "The encryption algorithm used (aws:kms)"
  value       = "aws:kms"
}
