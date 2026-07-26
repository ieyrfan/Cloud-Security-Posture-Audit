# OPA Policies for Terraform Security Gate
# These policies enforce security best practices during deployment

package terraform.security

# Deny any resource that allows public S3 access
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  resource.change.after.acl == "public-read"
  msg := sprintf("S3 bucket '%s' cannot have public-read ACL", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"
  resource.change.after.block_public_acls == false
  msg := sprintf("S3 bucket '%s' must block public ACLs", [resource.address])
}

# Deny unencrypted RDS instances
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_db_instance"
  resource.change.after.storage_encrypted == false
  msg := sprintf("RDS instance '%s' must have encryption at rest enabled", [resource.address])
}

# Deny RDS with public access
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_db_instance"
  resource.change.after.publicly_accessible == true
  msg := sprintf("RDS instance '%s' must not be publicly accessible", [resource.address])
}

# Deny unencrypted EBS volumes
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ebs_volume"
  resource.change.after.encrypted == false
  msg := sprintf("EBS volume '%s' must be encrypted", [resource.address])
}

# Deny security groups allowing SSH from 0.0.0.0/0
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group"
  resource.change.after.ingress[_].cidr_blocks[_] == "0.0.0.0/0"
  resource.change.after.ingress[_].from_port == 22
  msg := sprintf("Security group '%s' cannot allow SSH from 0.0.0.0/0", [resource.address])
}

# Deny IAM policies with wildcard actions on all resources
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_policy"
  document := resource.change.after.policy
  parsed := json.unmarshal(document)
  parsed.Statement[_].Action == "*"
  msg := sprintf("IAM policy '%s' cannot use wildcard action '*'", [resource.address])
}

# Deny IAM policies with wildcard resource
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_policy"
  document := resource.change.after.policy
  parsed := json.unmarshal(document)
  parsed.Statement[_].Resource == "*"
  msg := sprintf("IAM policy '%s' cannot use wildcard resource '*'", [resource.address])
}

# Deny CloudTrail without log file validation
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudtrail"
  resource.change.after.enable_log_file_validation == false
  msg := sprintf("CloudTrail '%s' must have log file validation enabled", [resource.address])
}

# Deny S3 bucket without versioning (for critical buckets)
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_versioning"
  resource.change.after.versioning[_].enabled == false
  msg := sprintf("S3 bucket '%s' must have versioning enabled", [resource.address])
}

# Warn for missing encryption on S3 (warning not deny)
warn[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  not resource.change.after.server_side_encryption_configuration
  msg := sprintf("S3 bucket '%s' should have encryption configured", [resource.address])
}

# Tiered scoring
compliance_score = score {
  all_resources := [r | r := input.resource_changes[_]]
  total := count(all_resources)
  passed := count([r | r := all_resources[_]; not violated(r)])
  score := round((passed / total) * 100)
}

violated(resource) {
  resource.type == "aws_s3_bucket"
  resource.change.after.acl == "public-read"
}

violated(resource) {
  resource.type == "aws_s3_bucket_public_access_block"
  resource.change.after.block_public_acls == false
}

violated(resource) {
  resource.type == "aws_db_instance"
  resource.change.after.storage_encrypted == false
}

violated(resource) {
  resource.type == "aws_db_instance"
  resource.change.after.publicly_accessible == true
}

violated(resource) {
  resource.type == "aws_ebs_volume"
  resource.change.after.encrypted == false
}

violated(resource) {
  resource.type == "aws_cloudtrail"
  resource.change.after.enable_log_file_validation == false
}
