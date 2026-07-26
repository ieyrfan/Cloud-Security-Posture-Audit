# OPA Policy: AWS CIS Controls
# Evaluates AWS resource configurations against CIS AWS Foundations Benchmark

package aws.cis_controls

# CIS Control 1.1: Ensure root account is protected by MFA
deny[msg] {
  input.root_account_mfa_enabled == false
  msg := "CIS 1.1: Root account must have MFA enabled"
}

# CIS Control 1.2: Ensure MFA is enabled for all IAM users
deny[msg] {
  user := input.iam_users[_]
  user.mfa_enabled == false
  msg := sprintf("CIS 1.2: IAM user '%s' must have MFA enabled", [user.name])
}

# CIS Control 1.4: Ensure IAM password policy requires at least 14 characters
deny[msg] {
  input.password_policy.minimum_password_length < 14
  msg := sprintf("CIS 1.4: Password policy must require at least 14 characters (current: %d)", [input.password_policy.minimum_password_length])
}

# CIS Control 1.16: Ensure IAM policies are reviewed for least privilege
deny[msg] {
  policy := input.iam_policies[_]
  policy.has_wildcard_action
  msg := sprintf("CIS 1.16: IAM policy '%s' uses wildcard action", [policy.name])
}

# CIS Control 2.1.1: Ensure CloudTrail is enabled
deny[msg] {
  trail := input.cloudtrails[_]
  not trail.is_logging
  msg := sprintf("CIS 2.1.1: CloudTrail '%s' is not logging", [trail.name])
}

# CIS Control 2.1.2: Ensure CloudTrail log file validation is enabled
deny[msg] {
  trail := input.cloudtrails[_]
  trail.log_file_validation_enabled == false
  msg := sprintf("CIS 2.1.2: CloudTrail '%s' must have log file validation enabled", [trail.name])
}

# CIS Control 3.2: Ensure GuardDuty is enabled
deny[msg] {
  input.guardduty_enabled == false
  msg := "CIS 3.2: GuardDuty must be enabled"
}

# CIS Control 4.1: Ensure VPC Flow Logs are enabled
deny[msg] {
  vpc := input.vpcs[_]
  not vpc.flow_logs_enabled
  msg := sprintf("CIS 4.1: VPC '%s' must have flow logs enabled", [vpc.id])
}

# CIS Control 4.2: Ensure IMDSv2 is enforced
deny[msg] {
  instance := input.ec2_instances[_]
  instance.metadata_options.http_tokens != "required"
  msg := sprintf("CIS 4.2: EC2 instance '%s' must enforce IMDSv2", [instance.id])
}

# CIS Control 5.1: Ensure S3 buckets do not allow public access
deny[msg] {
  bucket := input.s3_buckets[_]
  bucket.public_access_block.block_public_acls == false
  msg := sprintf("CIS 5.1: S3 bucket '%s' must block public ACLs", [bucket.name])
}

# CIS Control 5.2: Ensure S3 buckets have encryption enabled
warn[msg] {
  bucket := input.s3_buckets[_]
  not bucket.encryption_enabled
  msg := sprintf("CIS 5.2: S3 bucket '%s' should have encryption enabled", [bucket.name])
}

# CIS Control 5.3: Ensure EBS volumes are encrypted
deny[msg] {
  volume := input.ebs_volumes[_]
  volume.encrypted == false
  msg := sprintf("CIS 5.3: EBS volume '%s' must be encrypted", [volume.id])
}

# CIS Control 5.4: Ensure RDS instances have encryption at rest
deny[msg] {
  db := input.rds_instances[_]
  db.storage_encrypted == false
  msg := sprintf("CIS 5.4: RDS instance '%s' must have storage encryption enabled", [db.id])
}

# CIS Control 5.5: Ensure RDS instances are not publicly accessible
deny[msg] {
  db := input.rds_instances[_]
  db.publicly_accessible == true
  msg := sprintf("CIS 5.5: RDS instance '%s' must not be publicly accessible", [db.id])
}

# Scoring function
compliance_score = score {
  all_controls := [c | c := input.controls[_]]
  applicable := [c | c := all_controls[_]; c.applicable]
  total := count(applicable)
  passed := count([c | c := applicable[_]; c.status == "PASS"])
  score := round((passed / total) * 100)
}
