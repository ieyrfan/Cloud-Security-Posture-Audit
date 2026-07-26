# Remediation Guide — Cloud Security Posture Audit

**Organization:** CloudSecurityCorp  
**Date:** 2025-01-22  
**Classification:** Internal — Security Sensitive  
**Audience:** Cloud Engineering, DevOps, Security Teams

---

## Overview

This document provides step-by-step remediation procedures for all **51 findings** identified during the Cloud Security Posture Audit conducted on 2025-01-15. Remediations are prioritized by severity, with critical findings addressed first.

### Remediation Summary

| Severity | Count | Remediation Status | Target Completion |
|----------|-------|-------------------|-------------------|
| Critical | 10    | 🟡 In Progress    | 2025-01-29 |
| High     | 15    | 🔴 Not Started    | 2025-02-12 |
| Medium   | 18    | 🔴 Not Started    | 2025-03-12 |
| Low      | 8     | 🔴 Not Started    | 2025-04-12 |

### Critical Remediation Order

1. **FINDING-004:** Enable CloudTrail (foundational for all other audit)
2. **FINDING-001:** Block S3 public access (active data leak)
3. **FINDING-005:** Remove root access keys
4. **FINDING-006:** Enforce MFA
5. **FINDING-003:** Restrict security group SSH access
6. **FINDING-002:** Encrypt RDS instances
7. **FINDING-010:** Encrypt EBS volumes
8. **FINDING-008:** Rotate IAM access keys
9. **FINDING-009:** Apply least-privilege IAM policies
10. **FINDING-007:** Enable VPC Flow Logs

---

## Prerequisites

### Tools & Permissions

- AWS CLI v2.x installed and configured
- IAM permissions: `AdministratorAccess` or equivalent
- jq (JSON processor) installed
- Bash 4.0+ or PowerShell 7+
- AWS Systems Manager Session Manager (preferred over SSH)

### Environment Variables

```bash
export AWS_DEFAULT_REGION=us-east-1
export AWS_PROFILE=prod-admin
export LOG_BUCKET=security-remediation-logs-$(aws sts get-caller-identity --query Account --output text)
export REPO_ROOT=/cloud-security-posture-audit
```

---

## Critical Finding Remediations

---

### 1. FINDING-004: Enable CloudTrail (Multi-Region)

**Priority:** Highest — Audit logging must be enabled before other changes

#### AWS CLI Procedure

```bash
# Step 1: Create S3 bucket for CloudTrail logs
aws s3api create-bucket --bucket prod-cloudtrail-logs-123456789012 \
  --region us-east-1 \
  --create-bucket-configuration LocationConstraint=us-east-1

# Step 2: Attach bucket policy for CloudTrail
cat > cloudtrail-bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::prod-cloudtrail-logs-123456789012"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::prod-cloudtrail-logs-123456789012/AWSLogs/123456789012/*",
      "Condition": {
        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
      }
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket prod-cloudtrail-logs-123456789012 \
  --policy file://cloudtrail-bucket-policy.json

# Step 3: Enable default encryption on S3 bucket
aws s3api put-bucket-encryption \
  --bucket prod-cloudtrail-logs-123456789012 \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# Step 4: Create multi-region CloudTrail trail
aws cloudtrail create-trail \
  --name prod-multi-region-trail \
  --s3-bucket-name prod-cloudtrail-logs-123456789012 \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --include-global-service-events \
  --is-logging

# Step 5: Enable CloudWatch Logs integration
aws cloudtrail put-event-selectors \
  --trail-name prod-multi-region-trail \
  --event-selectors '[{"ReadWriteType": "All","IncludeManagementEvents": true,"DataResources": []}]'

# Step 6: Create CloudWatch Logs log group
aws logs create-log-group --log-group-name aws-cloudtrail-logs-123456789012

aws cloudtrail update-trail \
  --name prod-multi-region-trail \
  --cloud-watch-logs-log-group-arn arn:aws:logs:us-east-1:123456789012:log-group:aws-cloudtrail-logs-123456789012:* \
  --cloud-watch-logs-role-arn arn:aws:iam::123456789012:role/CloudTrail_CloudWatchLogs_Role
```

#### Console Navigation

1. Go to **AWS Console > CloudTrail > Trails > Create trail**
2. Name: `prod-multi-region-trail`
3. Check **Multi-region trail** and **Include global services**
4. Create new S3 bucket or select existing
5. Enable **Log file validation**
6. Enable **CloudWatch Logs** — create or select log group
7. Click **Create**

#### Verification

```bash
aws cloudtrail describe-trails --trail-name-list prod-multi-region-trail
aws cloudtrail get-trail-status --name prod-multi-region-trail
aws cloudtrail get-event-selectors --trail-name prod-multi-region-trail
```

**Expected output:** Trail status shows `IsLogging: true`, trail is `IsMultiRegionTrail: true`

---

### 2. FINDING-001: Block S3 Public Access

**Priority:** Critical — Active data leak in progress

#### Immediate Triage (Emergency)

```bash
# Apply block public access at account level (blocks ALL public access)
aws s3control put-public-access-block \
  --account-id 123456789012 \
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'

# Apply at bucket level for the exposed bucket
aws s3api put-public-access-block \
  --bucket prod-customer-data-2024 \
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'
```

#### Permanent Fix

```bash
# Review current bucket policy
aws s3api get-bucket-policy --bucket prod-customer-data-2024 --query Policy --output json | jq .

# Remove public read policy and apply least-privilege
cat > restricted-bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicRead",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::prod-customer-data-2024/*",
      "Condition": {
        "StringNotEquals": {
          "aws:sourceVpc": "vpc-0a1b2c3d"
        }
      }
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket prod-customer-data-2024 \
  --policy file://restricted-bucket-policy.json

# Enable default encryption
aws s3api put-bucket-encryption \
  --bucket prod-customer-data-2024 \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket prod-customer-data-2024 \
  --versioning-configuration Status=Enabled

# Enable access logging
aws s3api put-bucket-logging \
  --bucket prod-customer-data-2024 \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "prod-s3-access-logs",
      "TargetPrefix": "prod-customer-data-2024/"
    }
  }'
```

#### Verification

```bash
aws s3api get-public-access-block --bucket prod-customer-data-2024
aws s3api get-bucket-policy --bucket prod-customer-data-2024 --query Policy --output json | jq .
aws s3api get-bucket-encryption --bucket prod-customer-data-2024
```

---

### 3. FINDING-005: Remove Root User Access Keys

#### AWS CLI Procedure

```bash
# List root user access keys (requires root credentials)
aws iam list-access-keys --user-name root

# Deactivate the key first
iam update-access-key --user-name root --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive

# After validation, delete the key
aws iam delete-access-key --user-name root --access-key-id AKIAIOSFODNN7EXAMPLE

# Enable MFA on root account
aws iam create-virtual-mfa-device --virtual-mfa-device-name root-mfa --outfile QRCode.png --bootstrap-method QRCodePNG
```

#### Console Navigation

1. Sign in as root user (email + password)
2. Go to **My Security Credentials**
3. Under **Access keys**, click **Delete** for each active key
4. Under **Multi-factor authentication (MFA)**, click **Assign MFA**
5. Choose **Virtual MFA device** and scan QR code
6. Store root credentials in **AWS Secrets Manager** or enterprise PAM

#### Verification

```bash
aws iam list-access-keys --user-name root --output table
# Expected: No access keys listed
```

---

### 4. FINDING-006: Enforce MFA on IAM Users

#### AWS CLI Procedure

```bash
# Step 1: Update password policy
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --allow-users-to-change-password \
  --max-password-age 90 \
  --password-reuse-prevention 24 \
  --hard-expiry

# Step 2: Create MFA enforcement policy
cat > enforce-mfa-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllExceptListedIfNoMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:ListMFADevices",
        "iam:ListUsers",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
EOF

aws iam create-policy \
  --policy-name EnforceMFAPolicy \
  --policy-document file://enforce-mfa-policy.json

# Step 3: Attach to all users/groups
aws iam attach-group-policy \
  --group-name Admins \
  --policy-arn arn:aws:iam::123456789012:policy/EnforceMFAPolicy

aws iam attach-group-policy \
  --group-name Developers \
  --policy-arn arn:aws:iam::123456789012:policy/EnforceMFAPolicy
```

#### Console Procedure for Each User

1. Go to **IAM > Users > [username] > Security credentials**
2. Click **Assign MFA device** > **Virtual MFA device**
3. User scans QR code with authenticator app
4. Enter two consecutive MFA codes
5. User signs out and signs back in with MFA

#### Verification

```bash
# List users without MFA
aws iam list-users --query "Users[*].UserName" --output text | tr "\t" "\n" | while read user; do
  mfa=$(aws iam list-mfa-devices --user-name "$user" --query "MFADevices[0].SerialNumber" --output text)
  if [[ "$mfa" == "None" ]]; then
    echo "NO MFA: $user"
  else
    echo "MFA OK: $user"
  fi
done
```

---

### 5. FINDING-003: Restrict Security Group SSH Access

#### AWS CLI Procedure

```bash
# Find SGs with unrestricted SSH
aws ec2 describe-security-groups \
  --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query 'SecurityGroups[*].[GroupId,GroupName,Description]' \
  --output table

# For each SG, remove the 0.0.0.0/0 SSH rule and replace with corporate CIDR
# Step 1: Remove the permissive rule
aws ec2 revoke-security-group-ingress \
  --group-id sg-0a1b2c3d4e5f6g7h8 \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Step 2: Add restricted CIDR (corporate VPN range)
aws ec2 authorize-security-group-ingress \
  --group-id sg-0a1b2c3d4e5f6g7h8 \
  --protocol tcp \
  --port 22 \
  --cidr 10.0.0.0/8

# Alternative: Restrict to specific security group (jump box)
aws ec2 authorize-security-group-ingress \
  --group-id sg-0a1b2c3d4e5f6g7h8 \
  --protocol tcp \
  --port 22 \
  --source-group sg-jumpbox-sg
```

#### Console Navigation

1. Go to **EC2 > Security Groups**
2. Select the security group
3. Click **Inbound rules > Edit inbound rules**
4. Remove the SSH rule with `0.0.0.0/0`
5. Add rule: **SSH (22)** → **Custom** → `10.0.0.0/8` (corporate CIDR)
6. Click **Save rules**

#### Verification

```bash
aws ec2 describe-security-groups \
  --group-ids sg-0a1b2c3d4e5f6g7h8 \
  --query 'SecurityGroups[*].IpPermissions[?ToPort==`22`].IpRanges[*].CidrIp' \
  --output table
# Expected: No 0.0.0.0/0 entry
```

---

### 6. FINDING-002: Encrypt RDS Instance

#### AWS CLI Procedure

```bash
# Step 1: Create unencrypted snapshot
aws rds create-db-snapshot \
  --db-instance-identifier prod-user-db \
  --db-snapshot-identifier prod-user-db-pre-encryption

# Step 2: Copy snapshot with encryption
aws rds copy-db-snapshot \
  --source-db-snapshot-identifier arn:aws:rds:us-east-1:123456789012:snapshot:prod-user-db-pre-encryption \
  --target-db-snapshot-identifier prod-user-db-encrypted \
  --kms-key-id alias/aws/rds \
  --copy-tags

# Wait for copy to complete
aws rds wait db-snapshot-completed \
  --db-snapshot-identifier prod-user-db-encrypted

# Step 3: Restore encrypted instance
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier prod-user-db-v2 \
  --db-snapshot-identifier prod-user-db-encrypted \
  --db-instance-class db.r5.large \
  --multi-az \
  --publicly-accessible \
  --vpc-security-group-ids sg-0restricted \
  --db-subnet-group-name prod-private

# Wait for instance to be available
aws rds wait db-instance-available --db-instance-identifier prod-user-db-v2

# Step 4: Enable deletion protection
aws rds modify-db-instance \
  --db-instance-identifier prod-user-db-v2 \
  --deletion-protection \
  --backup-retention-period 35 \
  --apply-immediately

# Step 5: Update application connection strings (manual step)
# Update RDS endpoint in application config / Secrets Manager
NEW_ENDPOINT=$(aws rds describe-db-instances \
  --db-instance-identifier prod-user-db-v2 \
  --query 'DBInstances[0].Endpoint.Address' \
  --output text)
echo "New endpoint: $NEW_ENDPOINT"

# Step 6: After cutover, delete old unencrypted instance
aws rds delete-db-instance \
  --db-instance-identifier prod-user-db \
  --skip-final-snapshot \
  --delete-automated-backups
```

#### Verification

```bash
aws rds describe-db-instances \
  --db-instance-identifier prod-user-db-v2 \
  --query 'DBInstances[0].[DBInstanceIdentifier,StorageEncrypted,DeletionProtection,MultiAZ]' \
  --output table
# Expected: StorageEncrypted=true, DeletionProtection=true, MultiAZ=true
```

---

### 7. FINDING-010: Encrypt EBS Volumes

#### AWS CLI Procedure

```bash
# Step 1: Enable EBS default encryption at account level
aws ec2 enable-ebs-encryption-by-default

# Step 2: List unencrypted volumes
aws ec2 describe-volumes \
  --query 'Volumes[?Encrypted==`false`].[VolumeId,Size,State,AvailabilityZone]' \
  --output table

# Step 3: For each volume, create encrypted snapshot and new volume
UNENCRYPTED_VOLUMES=$(aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`].VolumeId' --output text)

for vol in $UNENCRYPTED_VOLUMES; do
  echo "Processing unencrypted volume: $vol"
  
  # Create snapshot
  SNAP_ID=$(aws ec2 create-snapshot \
    --volume-id $vol \
    --description "Pre-encryption snapshot for $vol" \
    --query 'SnapshotId' --output text)
  
  echo "  Created snapshot: $SNAP_ID"
  
  # Wait for snapshot
  aws ec2 wait snapshot-completed --snapshot-ids $SNAP_ID
  
  # Copy with encryption
  ENC_SNAP_ID=$(aws ec2 copy-snapshot \
    --source-region us-east-1 \
    --source-snapshot-id $SNAP_ID \
    --encrypted \
    --kms-key-id alias/ebs-encryption-key \
    --description "Encrypted copy of $vol" \
    --query 'SnapshotId' --output text)
  
  echo "  Created encrypted snapshot: $ENC_SNAP_ID"
    
  # Create encrypted volume from encrypted snapshot
  aws ec2 create-volume \
    --snapshot-id $ENC_SNAP_ID \
    --volume-type gp3 \
    --encrypted \
    --kms-key-id alias/ebs-encryption-key \
    --availability-zone us-east-1a
  
  echo "  Created encrypted volume from $ENC_SNAP_ID"
done

# Step 4: Detach old volumes and attach new encrypted volumes to EC2 instances
# (This requires stopping the EC2 instance)
# aws ec2 stop-instances --instance-ids i-0abc123
# aws ec2 detach-volume --volume-id vol-xxx
# aws ec2 attach-volume --volume-id vol-encrypted --instance-id i-0abc123 --device /dev/xvda
# aws ec2 start-instances --instance-ids i-0abc123
```

#### Verification

```bash
aws ec2 get-ebs-encryption-by-default --region us-east-1
aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`].[VolumeId,Size]' --output table
```

---

### 8. FINDING-008: Rotate IAM Access Keys

#### AWS CLI Procedure

```bash
# List all users with old keys
aws iam list-users --query "Users[*].UserName" --output text | tr "\t" "\n" | while read user; do
  aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[?Status==`Active`].[AccessKeyId,CreateDate]' --output table
done

# For each old key, rotate
# Step 1: Create new access key
aws iam create-access-key --user-name devops-john
# Output includes new AccessKeyId and SecretAccessKey

# Step 2: Update applications with new key (manual coordination)
# echo "AKIAIOSFODNN7EXAMPLE_NEW" | aws secretsmanager put-secret-value --secret-id devops-john-key --secret-string file://-

# Step 3: Deactivate old key
aws iam update-access-key --user-name devops-john --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive

# Step 4: After 7 days, delete old key
aws iam delete-access-key --user-name devops-john --access-key-id AKIAIOSFODNN7EXAMPLE
```

---

### 9. FINDING-009: Apply Least-Privilege IAM Policies

#### AWS CLI Procedure

```bash
# Step 1: Identify over-permissioned users
aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Step 2: Generate credential report to understand usage
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d > credential-report.csv

# Step 3: Use Access Advisor to see actual service usage
aws iam generate-service-last-accessed-details --arn arn:aws:iam::123456789012:user/developer-bob
aws iam get-service-last-accessed-details --job-id <job-id>

# Step 4: Create custom least-privilege policy
cat > developer-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2ReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "ec2:Get*",
        "ec2:List*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3DevBuckets",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::dev-*",
        "arn:aws:s3:::dev-*/*"
      ]
    },
    {
      "Sid": "CloudWatchRead",
      "Effect": "Allow",
      "Action": [
        "logs:Describe*",
        "logs:Get*",
        "logs:FilterLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam create-policy --policy-name DeveloperLeastPrivilege --policy-document file://developer-policy.json

# Step 5: Detach AdminAccess and attach new policy
aws iam detach-user-policy --user-name developer-bob --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam attach-user-policy --user-name developer-bob --policy-arn arn:aws:iam::123456789012:policy/DeveloperLeastPrivilege
```

---

### 10. FINDING-007: Enable VPC Flow Logs

#### AWS CLI Procedure

```bash
# Step 1: Create IAM role for Flow Logs
cat > flow-log-trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role --role-name vpc-flow-logs-role --assume-role-policy-document file://flow-log-trust-policy.json

cat > flow-log-permissions.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam put-role-policy --role-name vpc-flow-logs-role --policy-name flow-logs-policy --policy-document file://flow-log-permissions.json

# Step 2: Enable flow logs on each VPC
for vpc in vpc-0a1b2c3d vpc-4e5f6g7h vpc-8i9j0k1l vpc-2m3n4o5p vpc-6q7r8s9t; do
  aws ec2 create-flow-logs \
    --resource-type VPC \
    --resource-ids $vpc \
    --traffic-type ALL \
    --log-destination-type cloud-watch-logs \
    --log-destination arn:aws:logs:us-east-1:123456789012:log-group:vpc-flow-logs \
    --iam-role-arn arn:aws:iam::123456789012:role/vpc-flow-logs-role \
    --max-aggregation-interval 600
  echo "Flow logs enabled for $vpc"
done
```

#### Verification

```bash
aws ec2 describe-flow-logs --filter Name=resource-id,Values=vpc-0a1b2c3d --query 'FlowLogs[*].[FlowLogId,ResourceId,TrafficType]' --output table
```

---

## High Severity Remediations (Summary)

| ID | Finding | Quick Command |
|----|---------|---------------|
| 011 | S3 default encryption | `aws s3api put-bucket-encryption --bucket \$BUCKET --server-side-encryption-configuration file://encrypt.json` |
| 012 | RDP 0.0.0.0/0 | `aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 3389 --cidr 0.0.0.0/0` |
| 013 | HTTPS 0.0.0.0/0 | Review and restrict if not an ALB |
| 014 | Log validation | `aws cloudtrail update-trail --name dev-trail --enable-log-file-validation` |
| 015 | Password policy | `aws iam update-account-password-policy --minimum-password-length 14 ...` |
| 016 | Unused keys | `aws iam delete-access-key --user-name \$USER --access-key-id \$KEY` |
| 017 | S3 versioning | `aws s3api put-bucket-versioning --bucket \$BUCKET --versioning-configuration Status=Enabled` |
| 018 | RDS public | `aws rds modify-db-instance --db-instance-identifier \$RDS --no-publicly-accessible` |
| 019 | EC2 public IPs | Migrate to private subnets with NAT Gateway |
| 020 | KMS rotation | `aws kms enable-key-rotation --key-id \$KEY` |

---

## Automated Remediation Scripts

All remediation scripts are located in the `remediation/scripts/` directory:

| Script | Purpose |
|--------|---------|
| `fix_s3_buckets.sh` | Block public access, enable encryption, versioning |
| `fix_security_groups.sh` | Remove 0.0.0.0/0 ingress rules |
| `fix_rds_encryption.sh` | Encrypt RDS instances |
| `enable_cloudtrail.sh` | Enable multi-region CloudTrail |
| `fix_iam_policies.sh` | Apply least-privilege IAM policies |

See individual script files for usage: `./scripts/<script_name>.sh --help`

---

## Rollback Procedures

### S3 Rollback
```bash
# Disable block public access (if needed for legitimate use)
aws s3control put-public-access-block --account-id 123456789012 --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
```

### Security Group Rollback
```bash
# Re-add removed ingress rule
aws ec2 authorize-security-group-ingress --group-id sg-xxx --protocol tcp --port 22 --cidr 0.0.0.0/0
```

### RDS Rollback
```bash
# Restore original unencrypted snapshot (emergency only)
aws rds restore-db-instance-from-db-snapshot --db-instance-identifier prod-user-db-restored --db-snapshot-identifier prod-user-db-pre-encryption
```

---

## Appendix: Recommended AWS Config Rules

```json
{
  "s3-bucket-public-read-prohibited": true,
  "s3-bucket-public-write-prohibited": true,
  "s3-bucket-server-side-encryption-enabled": true,
  "restricted-ssh": true,
  "ec2-instance-no-public-ip": true,
  "rds-storage-encrypted": true,
  "cloud-trail-enabled": true,
  "iam-user-mfa-enabled": true,
  "vpc-flow-logs-enabled": true,
  "ebs-encrypted-volumes": true
}
```

---

*End of Remediation Guide*  
*Next review: 2025-02-22*
